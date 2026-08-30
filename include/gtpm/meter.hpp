// SPDX-License-Identifier: MIT
//
// Metering engine: the state the metering thread owns exclusively.
//
// Hot path budget per packet, by design:
//   1 line  TEID -> binding      (flat open-addressing hash)
//   1 line  subscriber counters  (exactly 64 B, one line, no false sharing)
//   1 line  flow entry           (optional, exactly 64 B)
// Cold per-subscriber state (identity, emission bookkeeping, Gy cross-check)
// lives in a parallel array that the packet path only touches when a 5G QFI
// forces a bucket lookup. Nothing here allocates after construction.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "gtpm/clock.hpp"
#include "gtpm/flat_hash.hpp"
#include "gtpm/meter_event.hpp"
#include "gtpm/session.hpp"
#include "gtpm/spsc_ring.hpp"
#include "gtpm/usage_record.hpp"

namespace gtpm {

/// Per-subscriber hot counters. Exactly one cache line, 64-byte aligned so that
/// sharding metering across cores later cannot introduce false sharing.
struct alignas(64) SubscriberCounters {
  uint64_t ul_bytes = 0;
  uint64_t dl_bytes = 0;
  uint64_t ul_packets = 0;
  uint64_t dl_packets = 0;
  uint64_t bucket_bytes[kBucketSlots] = {};
  uint64_t last_seen_ns = 0;

  [[nodiscard]] uint64_t total_bytes() const noexcept { return ul_bytes + dl_bytes; }
  [[nodiscard]] uint64_t total_packets() const noexcept { return ul_packets + dl_packets; }
};

static_assert(sizeof(SubscriberCounters) == 64, "hot counters must be exactly one cache line");

/// Cold per-subscriber state. Same index as SubscriberCounters.
struct SubscriberInfo {
  uint64_t imsi = 0;
  uint64_t first_seen_ns = 0;
  uint64_t interval_start_ns = 0;
  uint64_t emitted_ul_bytes = 0;
  uint64_t emitted_dl_bytes = 0;
  uint64_t emitted_ul_packets = 0;
  uint64_t emitted_dl_packets = 0;
  uint64_t emitted_bucket_bytes[kBucketSlots] = {};
  // Gy cross-check state: what the charging plane says this subscriber used.
  uint64_t gy_reported_octets = 0;
  uint64_t gy_last_ns = 0;
  uint32_t gy_reports = 0;
  uint32_t bucket_ids[kBucketSlots] = {kUnsetBucket, kUnsetBucket, kUnsetBucket};
  uint32_t record_seq = 0;
  uint32_t default_rating_group = 0;
  uint32_t ul_teid = 0;
  uint32_t dl_teid = 0;
  bool active = false;
  bool bucket_aggregated = false;
  bool learned = false;  ///< discovered from traffic rather than installed
};

/// TEID table value. 8 bytes: the whole binding rides in the line the probe
/// already pulled in.
struct TeidBinding {
  uint32_t sub_idx = 0;
  uint8_t dir = static_cast<uint8_t>(Direction::kUnknown);
  uint8_t slot = 0;  ///< pre-resolved accounting slot for this tunnel
  uint16_t _pad = 0;
};

/// Per-flow entry, exactly one cache line.
struct alignas(64) FlowEntry {
  uint64_t key = 0;  ///< 0 marks an empty slot
  uint64_t bytes = 0;
  uint64_t packets = 0;
  uint64_t last_seen_ns = 0;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint32_t sub_idx = 0;
  uint32_t teid = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t proto = 0;
  uint8_t ip_version = 0;
  uint8_t qfi = 0;
  uint8_t dir = 0;
  uint8_t _pad[8] = {};
};

static_assert(sizeof(FlowEntry) == 64, "flow entries must be exactly one cache line");

/// Snapshot-able pipeline counters. POD so it can live behind a seqlock.
struct PipelineStats {
  uint64_t events = 0;
  uint64_t bytes = 0;
  uint64_t ul_bytes = 0;
  uint64_t dl_bytes = 0;
  uint64_t ul_packets = 0;
  uint64_t dl_packets = 0;
  uint64_t control_pdus = 0;
  uint64_t unknown_teid_events = 0;
  uint64_t unknown_teid_bytes = 0;
  uint64_t flows_active = 0;
  uint64_t flow_inserts = 0;
  uint64_t flow_evictions = 0;
  uint64_t records_emitted = 0;
  uint64_t records_dropped = 0;
  uint64_t gy_events = 0;
  uint64_t gy_reported_octets = 0;
  uint64_t subscribers_installed = 0;
  uint64_t subscribers_learned = 0;
  uint64_t sessions_released = 0;
  uint64_t last_event_ns = 0;
};

struct MeterConfig {
  size_t max_subscribers = 1u << 20;      ///< 1M sessions => 64 MB of hot counters
  size_t teid_table_capacity = 1u << 22;  ///< two TEIDs per session, load < 0.5
  size_t flow_table_capacity = 1u << 20;  ///< 64 MB of flow entries
  size_t flow_probe_window = 8;           ///< probes before LRU eviction
  uint64_t report_interval_ns = 10'000'000'000ULL;   ///< 10 s reporting timer
  uint64_t volume_threshold_bytes = 100ULL << 20;    ///< 100 MB triggers a record
  uint64_t sweep_period_ns = 100'000'000ULL;         ///< how often poll() advances
  size_t sweep_fraction = 16;   ///< table slices per full sweep; bounds per-call work
  bool track_flows = true;
  bool learn_unknown_teids = false;  ///< a real UPF meters only installed PDRs
};

/// Owns all metering state. Single-threaded by contract: one instance per
/// metering shard, and shards are partitioned by TEID so no locking is needed.
class MeterEngine {
 public:
  explicit MeterEngine(const MeterConfig& cfg = {})
      : cfg_(cfg),
        counters_(cfg.max_subscribers),
        info_(cfg.max_subscribers),
        teid_map_(cfg.teid_table_capacity),
        flows_(cfg.track_flows ? round_pow2(cfg.flow_table_capacity) : 0),
        flow_mask_(flows_.empty() ? 0 : flows_.size() - 1) {
    imsi_index_.reserve(cfg.max_subscribers / 8 + 1);
  }

  MeterEngine(const MeterEngine&) = delete;
  MeterEngine& operator=(const MeterEngine&) = delete;

  /// Route emitted usage records to `sink`. Not owned; must outlive the engine.
  void set_record_sink(SpscRing<UsageRecord>* sink) noexcept { record_sink_ = sink; }

  // -------------------------------------------------------------------------
  // Control plane (what PFCP would drive)
  // -------------------------------------------------------------------------

  /// Install a session. Returns the subscriber index, or SIZE_MAX if the table
  /// is full or the spec is invalid. `now_ns` opens the first reporting
  /// interval, so a freshly installed session is not immediately overdue.
  size_t install_session(const SessionSpec& spec, uint64_t now_ns) {
    if (!spec.valid()) return SIZE_MAX;

    size_t idx;
    const auto existing = imsi_index_.find(spec.imsi);
    if (existing != imsi_index_.end()) {
      idx = existing->second;
    } else {
      if (next_sub_ >= counters_.size()) return SIZE_MAX;
      idx = next_sub_++;
      imsi_index_.emplace(spec.imsi, idx);
      ++stats_.subscribers_installed;
    }

    SubscriberInfo& info = info_[idx];
    const bool reinstall = info.active;
    if (!reinstall) {
      counters_[idx] = SubscriberCounters{};
      info = SubscriberInfo{};
    }
    info.imsi = spec.imsi;
    info.active = true;
    if (!reinstall) {
      info.first_seen_ns = now_ns;
      info.interval_start_ns = now_ns;
    }
    info.default_rating_group = spec.rating_group;
    info.ul_teid = spec.ul_teid;
    info.dl_teid = spec.dl_teid;

    const uint8_t slot = assign_slot(info, spec.rating_group);
    if (spec.ul_teid != 0) {
      bind_teid(spec.ul_teid, idx, Direction::kUplink, slot);
    }
    if (spec.dl_teid != 0) {
      bind_teid(spec.dl_teid, idx, Direction::kDownlink, slot);
    }
    return idx;
  }

  size_t install_session(const SessionSpec& spec) { return install_session(spec, now_ns()); }

  size_t install_sessions(const std::vector<SessionSpec>& specs, uint64_t now_ns) {
    size_t installed = 0;
    for (const SessionSpec& s : specs) {
      if (install_session(s, now_ns) != SIZE_MAX) ++installed;
    }
    return installed;
  }

  size_t install_sessions(const std::vector<SessionSpec>& specs) {
    return install_sessions(specs, now_ns());
  }

  /// Release a session: emit a final record and drop its TEID bindings.
  bool release_session(uint64_t imsi, uint64_t now_ns) {
    const auto it = imsi_index_.find(imsi);
    if (it == imsi_index_.end()) return false;
    const size_t idx = it->second;
    SubscriberInfo& info = info_[idx];
    if (!info.active) return false;

    emit_record(idx, RecordReason::kRelease, now_ns);
    if (info.ul_teid) (void)teid_map_.erase(info.ul_teid);
    if (info.dl_teid) (void)teid_map_.erase(info.dl_teid);
    info.active = false;
    ++stats_.sessions_released;
    return true;
  }

  // -------------------------------------------------------------------------
  // Data plane
  // -------------------------------------------------------------------------

  /// Apply one metered packet. This is the hot path.
  void apply(const MeterEvent& ev) noexcept {
    ++stats_.events;
    stats_.bytes += ev.bytes;
    stats_.last_event_ns = ev.ts_ns;

    if ((ev.flags & kFlagControlPdu) != 0) {
      ++stats_.control_pdus;
      return;  // Echo / End Marker carry no user payload to charge for
    }

    TeidBinding* binding = teid_map_.find(ev.teid);
    if (binding == nullptr) [[unlikely]] {
      if (!cfg_.learn_unknown_teids) {
        ++stats_.unknown_teid_events;
        stats_.unknown_teid_bytes += ev.bytes;
        return;
      }
      binding = learn_teid(ev);
      if (binding == nullptr) {
        ++stats_.unknown_teid_events;
        stats_.unknown_teid_bytes += ev.bytes;
        return;
      }
    }

    const uint32_t sub = binding->sub_idx;
    SubscriberCounters& c = counters_[sub];

    // Direction comes from which side allocated the TEID, which is what the
    // core actually knows; the parser's guess is only a fallback.
    uint8_t dir = binding->dir;
    if (dir == static_cast<uint8_t>(Direction::kUnknown)) dir = ev.dir;

    if (dir == static_cast<uint8_t>(Direction::kDownlink)) {
      c.dl_bytes += ev.bytes;
      ++c.dl_packets;
      stats_.dl_bytes += ev.bytes;
      ++stats_.dl_packets;
    } else {
      c.ul_bytes += ev.bytes;
      ++c.ul_packets;
      stats_.ul_bytes += ev.bytes;
      ++stats_.ul_packets;
    }
    c.last_seen_ns = ev.ts_ns;

    // 4G: the tunnel's rating group, pre-resolved at install time (free).
    // 5G: the QFI in the PDU Session Container, which needs the cold line.
    uint8_t slot = binding->slot;
    if (ev.has_qfi()) [[unlikely]] {
      slot = resolve_slot(info_[sub], kQfiBucketTag | ev.qfi);
    }
    c.bucket_bytes[slot] += ev.bytes;

    if (!flows_.empty()) update_flow(ev, sub, dir);
  }

  /// Apply one Gy charging event. Off the fast path by construction.
  void apply_gy(const GyEvent& ev) {
    ++stats_.gy_events;
    if (!ev.has_imsi || !ev.has_used) return;
    const auto it = imsi_index_.find(ev.imsi);
    if (it == imsi_index_.end()) return;

    SubscriberInfo& info = info_[it->second];
    info.gy_reported_octets += ev.used_total_octets;
    info.gy_last_ns = ev.ts_ns;
    ++info.gy_reports;
    stats_.gy_reported_octets += ev.used_total_octets;
  }

  /// Advance reporting timers. Sweeps a bounded slice of the subscriber table
  /// per call so the metering thread never stalls behind a full-table scan.
  void poll(uint64_t now_ns) {
    if (now_ns - last_sweep_ns_ < cfg_.sweep_period_ns) return;
    last_sweep_ns_ = now_ns;

    const size_t live = next_sub_;
    if (live == 0) return;
    const size_t chunk = std::max<size_t>(1, live / std::max<size_t>(1, cfg_.sweep_fraction));

    for (size_t n = 0; n < chunk; ++n) {
      if (sweep_cursor_ >= live) sweep_cursor_ = 0;
      const size_t idx = sweep_cursor_++;
      const SubscriberInfo& info = info_[idx];
      if (!info.active) continue;

      const SubscriberCounters& c = counters_[idx];
      const uint64_t pending = (c.ul_bytes - info.emitted_ul_bytes) +
                               (c.dl_bytes - info.emitted_dl_bytes);
      if (pending == 0) continue;

      if (cfg_.volume_threshold_bytes != 0 && pending >= cfg_.volume_threshold_bytes) {
        emit_record(idx, RecordReason::kVolume, now_ns);
      } else if (cfg_.report_interval_ns != 0 &&
                 now_ns - info.interval_start_ns >= cfg_.report_interval_ns) {
        emit_record(idx, RecordReason::kInterval, now_ns);
      }
    }
  }

  /// Emit a final record for every subscriber with unreported usage.
  size_t drain(uint64_t now_ns) {
    size_t emitted = 0;
    for (size_t idx = 0; idx < next_sub_; ++idx) {
      const SubscriberInfo& info = info_[idx];
      if (!info.active) continue;
      const SubscriberCounters& c = counters_[idx];
      if (c.ul_bytes == info.emitted_ul_bytes && c.dl_bytes == info.emitted_dl_bytes) continue;
      emit_record(idx, RecordReason::kShutdown, now_ns);
      ++emitted;
    }
    return emitted;
  }

  // -------------------------------------------------------------------------
  // Read side
  // -------------------------------------------------------------------------

  [[nodiscard]] const PipelineStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const MeterConfig& config() const noexcept { return cfg_; }
  [[nodiscard]] size_t subscriber_count() const noexcept { return next_sub_; }
  [[nodiscard]] const SubscriberCounters& counters(size_t idx) const { return counters_[idx]; }
  [[nodiscard]] const SubscriberInfo& info(size_t idx) const { return info_[idx]; }
  [[nodiscard]] const FlatHashU32<TeidBinding>& teid_map() const noexcept { return teid_map_; }

  [[nodiscard]] size_t find_by_imsi(uint64_t imsi) const {
    const auto it = imsi_index_.find(imsi);
    return it == imsi_index_.end() ? SIZE_MAX : it->second;
  }

  [[nodiscard]] const FlowEntry* find_flow(uint64_t key) const {
    if (flows_.empty()) return nullptr;
    const uint64_t k = key ? key : 1;
    size_t idx = static_cast<size_t>(k ^ (k >> 32)) & flow_mask_;
    for (size_t probe = 0; probe < cfg_.flow_probe_window; ++probe) {
      const FlowEntry& e = flows_[idx];
      if (e.key == k) return &e;
      if (e.key == 0) return nullptr;
      idx = (idx + 1) & flow_mask_;
    }
    return nullptr;
  }

  /// The `n` busiest flows by bytes. Linear scan; reporter-side only.
  [[nodiscard]] std::vector<FlowEntry> top_flows(size_t n) const {
    std::vector<FlowEntry> out;
    if (flows_.empty() || n == 0) return out;
    out.reserve(n + 1);
    for (const FlowEntry& e : flows_) {
      if (e.key == 0) continue;
      if (out.size() < n) {
        out.push_back(e);
        if (out.size() == n) {
          std::sort(out.begin(), out.end(),
                    [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
        }
      } else if (e.bytes > out.back().bytes) {
        out.back() = e;
        for (size_t i = out.size() - 1; i > 0 && out[i].bytes > out[i - 1].bytes; --i) {
          std::swap(out[i], out[i - 1]);
        }
      }
    }
    if (out.size() < n) {
      std::sort(out.begin(), out.end(),
                [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
    }
    return out;
  }

  /// Difference between what we metered and what Gy reported, per subscriber.
  struct GyDelta {
    uint64_t imsi;
    uint64_t metered_octets;
    uint64_t reported_octets;
    int64_t difference;  ///< metered - reported
    uint32_t reports;
  };

  [[nodiscard]] std::vector<GyDelta> gy_crosscheck() const {
    std::vector<GyDelta> out;
    for (size_t idx = 0; idx < next_sub_; ++idx) {
      const SubscriberInfo& info = info_[idx];
      if (!info.active || info.gy_reports == 0) continue;
      const uint64_t metered = counters_[idx].total_bytes();
      out.push_back({info.imsi, metered, info.gy_reported_octets,
                     static_cast<int64_t>(metered) - static_cast<int64_t>(info.gy_reported_octets),
                     info.gy_reports});
    }
    return out;
  }

 private:
  static size_t round_pow2(size_t v) noexcept {
    return v < 2 ? 2 : (std::has_single_bit(v) ? v : std::bit_ceil(v));
  }

  void bind_teid(uint32_t teid, size_t sub_idx, Direction dir, uint8_t slot) {
    TeidBinding b;
    b.sub_idx = static_cast<uint32_t>(sub_idx);
    b.dir = static_cast<uint8_t>(dir);
    b.slot = slot;
    (void)teid_map_.insert(teid, b);
  }

  /// Assign an accounting slot for `bucket_id`, or return the aggregate slot.
  uint8_t assign_slot(SubscriberInfo& info, uint32_t bucket_id) noexcept {
    for (size_t i = 0; i < kBucketSlots; ++i) {
      if (info.bucket_ids[i] == bucket_id) return static_cast<uint8_t>(i);
    }
    for (size_t i = 0; i < kAggregateSlot; ++i) {
      if (info.bucket_ids[i] == kUnsetBucket) {
        info.bucket_ids[i] = bucket_id;
        return static_cast<uint8_t>(i);
      }
    }
    if (info.bucket_ids[kAggregateSlot] == kUnsetBucket) {
      info.bucket_ids[kAggregateSlot] = bucket_id;
    } else if (info.bucket_ids[kAggregateSlot] != bucket_id) {
      info.bucket_aggregated = true;  // slot 2 now mixes rating groups; say so
    }
    return static_cast<uint8_t>(kAggregateSlot);
  }

  uint8_t resolve_slot(SubscriberInfo& info, uint32_t bucket_id) noexcept {
    return assign_slot(info, bucket_id);
  }

  /// Create a subscriber for a TEID seen in traffic but absent from the session
  /// table. Off by default: it is a replay convenience, not core behaviour.
  TeidBinding* learn_teid(const MeterEvent& ev) {
    if (next_sub_ >= counters_.size()) return nullptr;
    const size_t idx = next_sub_++;
    counters_[idx] = SubscriberCounters{};
    SubscriberInfo& info = info_[idx];
    info = SubscriberInfo{};
    info.active = true;
    info.learned = true;
    info.imsi = 0;
    info.first_seen_ns = ev.ts_ns;
    info.interval_start_ns = ev.ts_ns;
    ++stats_.subscribers_learned;

    const uint8_t slot = assign_slot(info, 0);
    const Direction dir = static_cast<Direction>(ev.dir);
    if (dir == Direction::kDownlink) {
      info.dl_teid = ev.teid;
    } else {
      info.ul_teid = ev.teid;
    }
    bind_teid(ev.teid, idx, dir, slot);
    return teid_map_.find(ev.teid);
  }

  void update_flow(const MeterEvent& ev, uint32_t sub, uint8_t dir) noexcept {
    const uint64_t key = ev.flow_key ? ev.flow_key : 1;
    size_t idx = static_cast<size_t>(key ^ (key >> 32)) & flow_mask_;

    FlowEntry* victim = nullptr;
    uint64_t oldest = UINT64_MAX;

    for (size_t probe = 0; probe < cfg_.flow_probe_window; ++probe) {
      FlowEntry& e = flows_[idx];
      if (e.key == key) {
        e.bytes += ev.bytes;
        ++e.packets;
        e.last_seen_ns = ev.ts_ns;
        return;
      }
      if (e.key == 0) {
        init_flow(e, ev, sub, dir, key);
        ++stats_.flow_inserts;
        ++stats_.flows_active;
        return;
      }
      if (e.last_seen_ns < oldest) {
        oldest = e.last_seen_ns;
        victim = &e;
      }
      idx = (idx + 1) & flow_mask_;
    }

    // Probe window exhausted: evict the least recently used entry in it. A
    // bounded window keeps the worst case bounded; the cost of being wrong is
    // an evicted flow record, never a wrong subscriber total.
    ++stats_.flow_evictions;
    init_flow(*victim, ev, sub, dir, key);
  }

  static void init_flow(FlowEntry& e, const MeterEvent& ev, uint32_t sub, uint8_t dir,
                        uint64_t key) noexcept {
    e.key = key;
    e.bytes = ev.bytes;
    e.packets = 1;
    e.last_seen_ns = ev.ts_ns;
    e.src_ip = ev.src_ip;
    e.dst_ip = ev.dst_ip;
    e.sub_idx = sub;
    e.teid = ev.teid;
    e.src_port = ev.src_port;
    e.dst_port = ev.dst_port;
    e.proto = ev.proto;
    e.ip_version = ev.ip_version;
    e.qfi = ev.qfi;
    e.dir = dir;
  }

  void emit_record(size_t idx, RecordReason reason, uint64_t now_ns) {
    const SubscriberCounters& c = counters_[idx];
    SubscriberInfo& info = info_[idx];

    UsageRecord r;
    r.record_wall_ns = wall_ns();
    r.interval_start_ns = info.interval_start_ns;
    r.interval_end_ns = now_ns;
    r.imsi = info.imsi;
    r.ul_bytes = c.ul_bytes - info.emitted_ul_bytes;
    r.dl_bytes = c.dl_bytes - info.emitted_dl_bytes;
    r.ul_packets = c.ul_packets - info.emitted_ul_packets;
    r.dl_packets = c.dl_packets - info.emitted_dl_packets;
    for (size_t i = 0; i < kBucketSlots; ++i) {
      r.bucket_bytes[i] = c.bucket_bytes[i] - info.emitted_bucket_bytes[i];
      r.bucket_ids[i] = info.bucket_ids[i];
    }
    r.subscriber_index = static_cast<uint32_t>(idx);
    r.record_seq = info.record_seq++;
    r.reason = static_cast<uint8_t>(reason);
    r.bucket_aggregated = info.bucket_aggregated;

    info.emitted_ul_bytes = c.ul_bytes;
    info.emitted_dl_bytes = c.dl_bytes;
    info.emitted_ul_packets = c.ul_packets;
    info.emitted_dl_packets = c.dl_packets;
    for (size_t i = 0; i < kBucketSlots; ++i) info.emitted_bucket_bytes[i] = c.bucket_bytes[i];
    info.interval_start_ns = now_ns;

    if (record_sink_ != nullptr && record_sink_->try_push(r)) {
      ++stats_.records_emitted;
    } else if (record_sink_ == nullptr) {
      ++stats_.records_emitted;  // no sink configured: counted, not serialised
    } else {
      ++stats_.records_dropped;  // reporter is behind; never block metering
    }
  }

  MeterConfig cfg_;
  std::vector<SubscriberCounters> counters_;
  std::vector<SubscriberInfo> info_;
  FlatHashU32<TeidBinding> teid_map_;
  std::vector<FlowEntry> flows_;
  size_t flow_mask_ = 0;
  std::unordered_map<uint64_t, size_t> imsi_index_;  ///< control plane only
  SpscRing<UsageRecord>* record_sink_ = nullptr;
  PipelineStats stats_{};
  size_t next_sub_ = 0;
  size_t sweep_cursor_ = 0;
  uint64_t last_sweep_ns_ = 0;
};

}  // namespace gtpm
