// SPDX-License-Identifier: MIT
//
// Runtime implementation: the metering thread, the reporter thread and
// snapshot publication.
//
// The metering thread is the only thread that touches MeterEngine, so no
// locking appears anywhere in this file. It drains the meter ring in batches,
// applies the low-rate Gy control events, advances reporting timers, and
// republishes the snapshot on a timer.
#include "gtpm/runtime.hpp"

#include <algorithm>
#include <cstdio>

#include "gtpm/clock.hpp"

namespace gtpm {

namespace {

/// Busy-wait briefly, then yield. A metering thread that spins hot on an idle
/// pipeline burns a core for nothing; one that sleeps adds latency to the first
/// packet of a burst. This backs off in stages.
inline void idle_backoff(uint64_t consecutive_idle, bool busy_poll) {
  if (consecutive_idle < 64 || busy_poll) {
    cpu_relax();
  } else if (consecutive_idle < 1024) {
    std::this_thread::yield();
  } else {
    std::this_thread::sleep_for(std::chrono::microseconds(50));
  }
}

}  // namespace

Runtime::Runtime(RuntimeConfig cfg)
    : cfg_(std::move(cfg)),
      meter_ring_(cfg_.meter_ring_size),
      gy_ring_(cfg_.gy_ring_size),
      record_ring_(cfg_.record_ring_size),
      engine_(cfg_.meter),
      ingest_(&meter_ring_, &gy_ring_, cfg_.ingest) {
  engine_.set_record_sink(&record_ring_);
}

Runtime::~Runtime() {
  stop();
  if (records_file_ != nullptr) {
    std::fclose(records_file_);
    records_file_ = nullptr;
  }
}

size_t Runtime::install_sessions(const std::vector<SessionSpec>& sessions) {
  return engine_.install_sessions(sessions, now_ns());
}

void Runtime::start() {
  if (running_.exchange(true)) return;
  start_ns_ = now_ns();
  last_publish_ns_ = start_ns_;
  meter_stop_.store(false);
  reporter_stop_.store(false);

  if (!cfg_.records_path.empty()) {
    records_file_ = std::fopen(cfg_.records_path.c_str(), "ab");
    if (records_file_ == nullptr) {
      std::fprintf(stderr, "gtp-meter: cannot open usage record file %s\n",
                   cfg_.records_path.c_str());
    }
  }

  meter_thread_ = std::thread([this] { meter_loop(); });
  reporter_thread_ = std::thread([this] { reporter_loop(); });
  if (cfg_.ingest_cpu >= 0) (void)pin_this_thread(cfg_.ingest_cpu);
}

void Runtime::stop() {
  if (!running_.exchange(false)) return;
  meter_stop_.store(true, std::memory_order_release);
  if (meter_thread_.joinable()) meter_thread_.join();
  reporter_stop_.store(true, std::memory_order_release);
  if (reporter_thread_.joinable()) reporter_thread_.join();
  drain_records();  // anything the reporter did not get to
  if (records_file_ != nullptr) std::fflush(records_file_);
}

void Runtime::meter_loop() {
  if (cfg_.meter_cpu >= 0) (void)pin_this_thread(cfg_.meter_cpu);

  std::vector<MeterEvent> batch(cfg_.meter_batch);
  uint64_t consecutive_idle = 0;

  for (;;) {
    const size_t n = meter_ring_.try_pop_bulk(batch.data(), batch.size());
    if (n != 0) {
      ++meter_batches_;
      consecutive_idle = 0;
      for (size_t i = 0; i < n; ++i) {
        engine_.apply(batch[i]);
        if (cfg_.measure_latency) {
          // Sampled: one clock read per N events keeps the measurement from
          // dominating what is being measured.
          if (++latency_counter_ >= cfg_.latency_sample_every) {
            latency_counter_ = 0;
            const uint64_t now = now_ns();
            if (now > batch[i].ts_ns) latency_.record(now - batch[i].ts_ns);
          }
        }
      }
    } else {
      ++meter_idle_polls_;
      ++consecutive_idle;
    }

    GyEvent gy;
    while (gy_ring_.try_pop(gy)) engine_.apply_gy(gy);

    const uint64_t now = now_ns();
    engine_.poll(now);
    if (now - last_publish_ns_ >= cfg_.publish_interval_ns) publish_locked(now);

    if (n == 0) {
      if (meter_stop_.load(std::memory_order_acquire) && meter_ring_.empty_approx() &&
          gy_ring_.empty_approx()) {
        break;
      }
      idle_backoff(consecutive_idle, cfg_.busy_poll);
    }
  }

  // Final flush: emit records for everything still unreported, then publish a
  // last snapshot so the numbers an operator sees at shutdown are complete.
  const uint64_t now = now_ns();
  (void)engine_.drain(now);
  publish_locked(now);
}

void Runtime::publish_locked(uint64_t now) {
  last_publish_ns_ = now;

  PipelineSnapshot snap;
  snap.meter = engine_.stats();
  snap.ingest = ingest_.stats();
  snap.latency = summarize(latency_);
  snap.publish_wall_ns = wall_ns();
  snap.publish_mono_ns = now;
  snap.uptime_ns = now - start_ns_;
  snap.meter_ring_depth = meter_ring_.size_approx();
  snap.meter_ring_capacity = meter_ring_.capacity();
  snap.gy_ring_depth = gy_ring_.size_approx();
  snap.record_ring_depth = record_ring_.size_approx();
  snap.records_written = records_written_.load(std::memory_order_relaxed);
  snap.record_write_errors = record_write_errors_.load(std::memory_order_relaxed);
  snap.teid_table_size = engine_.teid_map().size();
  snap.teid_table_capacity = engine_.teid_map().capacity();
  snap.teid_load_factor = engine_.teid_map().load_factor();
  snap.teid_probes_per_lookup = engine_.teid_map().lookup_count() == 0
                                    ? 0.0
                                    : static_cast<double>(engine_.teid_map().probe_count()) /
                                          static_cast<double>(engine_.teid_map().lookup_count());
  snap.meter_batches = meter_batches_;
  snap.meter_idle_polls = meter_idle_polls_;
  stats_.store(snap);

  // Only build the per-subscriber/per-flow tables while someone is reading
  // them: scanning a million-entry flow table is real work on the metering
  // thread, and an unobserved pipeline should not pay for it.
  const uint64_t requested = detail_request_ns_.load(std::memory_order_relaxed);
  if (requested != 0 && now - requested <= cfg_.detail_demand_ttl_ns) {
    advance_detail_scan(snap.publish_wall_ns);
  }
}

/// Build the per-subscriber and per-flow tables a slice at a time.
///
/// This runs on the metering thread, so the work per call is bounded by
/// `snapshot_scan_budget`; a full pass spans however many publish ticks it
/// needs and is committed only when complete. The published table is therefore
/// a rolling view: every row is internally consistent, but rows may be up to a
/// full pass apart. That is the right trade for a reporting endpoint, and it
/// keeps a million-entry flow table out of the packet path's tail latency.
void Runtime::advance_detail_scan(uint64_t publish_wall_ns) {
  if (detail_building_ == nullptr) {
    detail_building_ = detail_.begin_write();
    if (detail_building_ == nullptr) return;  // all buffers pinned; try next tick
    detail_building_->subscribers.clear();
    detail_building_->top_flows.clear();
    detail_building_->publish_wall_ns = publish_wall_ns;
    detail_sub_cursor_ = 0;
    detail_flow_cursor_ = 0;
  }

  size_t budget = cfg_.snapshot_scan_budget;
  const size_t sub_count = engine_.subscriber_count();

  while (budget > 0 && detail_sub_cursor_ < sub_count) {
    const size_t idx = detail_sub_cursor_++;
    --budget;
    const SubscriberInfo& info = engine_.info(idx);
    if (!info.active) continue;
    const SubscriberCounters& c = engine_.counters(idx);
    if (c.total_packets() == 0) continue;

    SubscriberSnapshot row;
    row.imsi = info.imsi;
    row.ul_bytes = c.ul_bytes;
    row.dl_bytes = c.dl_bytes;
    row.ul_packets = c.ul_packets;
    row.dl_packets = c.dl_packets;
    row.last_seen_ns = c.last_seen_ns;
    for (size_t b = 0; b < kBucketSlots; ++b) {
      row.bucket_bytes[b] = c.bucket_bytes[b];
      row.bucket_ids[b] = info.bucket_ids[b];
    }
    row.gy_reported_octets = info.gy_reported_octets;
    row.gy_reports = info.gy_reports;
    row.sub_idx = static_cast<uint32_t>(idx);
    row.ul_teid = info.ul_teid;
    row.dl_teid = info.dl_teid;
    row.bucket_aggregated = info.bucket_aggregated;
    detail_building_->subscribers.push_back(row);
  }

  // Busiest flows, kept as a sorted top-N so the scan needs no second pass.
  std::vector<FlowEntry>& top = detail_building_->top_flows;
  const size_t flow_limit = cfg_.snapshot_flow_limit;
  while (budget > 0 && detail_flow_cursor_ < engine_.flow_capacity()) {
    const FlowEntry& f = engine_.flow_at(detail_flow_cursor_++);
    --budget;
    if (f.key == 0) continue;
    if (top.size() < flow_limit) {
      top.push_back(f);
      std::push_heap(top.begin(), top.end(),
                     [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
    } else if (f.bytes > top.front().bytes) {
      std::pop_heap(top.begin(), top.end(),
                    [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
      top.back() = f;
      std::push_heap(top.begin(), top.end(),
                     [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
    }
  }

  if (detail_sub_cursor_ < sub_count || detail_flow_cursor_ < engine_.flow_capacity()) {
    return;  // pass still in progress; keep the previous snapshot published
  }

  const size_t limit = cfg_.snapshot_subscriber_limit;
  std::vector<SubscriberSnapshot>& subs = detail_building_->subscribers;
  if (subs.size() > limit) {
    std::partial_sort(subs.begin(), subs.begin() + static_cast<long>(limit), subs.end(),
                      [](const SubscriberSnapshot& a, const SubscriberSnapshot& b) {
                        return (a.ul_bytes + a.dl_bytes) > (b.ul_bytes + b.dl_bytes);
                      });
    subs.resize(limit);
  }
  std::sort(top.begin(), top.end(),
            [](const FlowEntry& a, const FlowEntry& b) { return a.bytes > b.bytes; });
  detail_building_->total_subscribers = sub_count;
  detail_.commit();
  detail_building_ = nullptr;
}

void Runtime::publish_now() {
  publish_locked(now_ns());
}

PipelineSnapshot Runtime::snapshot() const {
  PipelineSnapshot snap;
  if (!stats_.load(snap)) return PipelineSnapshot{};
  return snap;
}

void Runtime::drain_records() {
  UsageRecord rec;
  while (record_ring_.try_pop(rec)) {
    if (records_file_ == nullptr) {
      records_written_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    const std::string line = to_ndjson(rec);
    if (std::fwrite(line.data(), 1, line.size(), records_file_) != line.size() ||
        std::fputc('\n', records_file_) == EOF) {
      record_write_errors_.fetch_add(1, std::memory_order_relaxed);
    } else {
      records_written_.fetch_add(1, std::memory_order_relaxed);
    }
  }
}

void Runtime::reporter_loop() {
  if (cfg_.reporter_cpu >= 0) (void)pin_this_thread(cfg_.reporter_cpu);

  while (!reporter_stop_.load(std::memory_order_acquire)) {
    drain_records();
    if (records_file_ != nullptr) std::fflush(records_file_);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  drain_records();
  if (records_file_ != nullptr) std::fflush(records_file_);
}

}  // namespace gtpm
