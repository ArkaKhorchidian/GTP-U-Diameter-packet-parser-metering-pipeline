// SPDX-License-Identifier: MIT
//
// Pipeline runtime: rings, threads and the wiring between them.
//
//   ingest thread (caller's)   ->  meter ring  ->  metering thread
//                              ->  gy ring     ->  metering thread
//                                                 -> record ring -> reporter
//
// The ingest thread is the caller's own, so a replay driver or a live capture
// loop stays in control of its core. The metering and reporter threads are
// owned here.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "gtpm/clock.hpp"
#include "gtpm/histogram.hpp"
#include "gtpm/meter.hpp"
#include "gtpm/pipeline.hpp"
#include "gtpm/seqlock.hpp"
#include "gtpm/session.hpp"
#include "gtpm/snapshot.hpp"
#include "gtpm/spsc_ring.hpp"
#include "gtpm/stats.hpp"

namespace gtpm {

struct RuntimeConfig {
  MeterConfig meter{};
  IngestConfig ingest{};
  size_t meter_ring_size = 1u << 16;
  size_t gy_ring_size = 1u << 12;
  size_t record_ring_size = 1u << 14;
  size_t meter_batch = 256;
  int ingest_cpu = -1;  ///< pin the calling thread; -1 leaves it alone
  int meter_cpu = -1;
  int reporter_cpu = -1;
  uint64_t publish_interval_ns = 100'000'000ULL;  ///< 10 Hz snapshot publication
  /// Latency sampling: measure 1 event in N. Reading the clock per event costs
  /// more than the metering work itself, which would distort what it measures.
  uint32_t latency_sample_every = 8;
  bool measure_latency = true;
  /// Spin instead of sleeping when the ring is empty. A metering thread on a
  /// pinned, isolated core should never sleep: the backoff sleep shows up
  /// directly in tail latency for the first packet of a burst. Off by default
  /// so the tool does not burn a core on a shared machine.
  bool busy_poll = false;
  size_t snapshot_subscriber_limit = 4096;  ///< busiest N subscribers published
  size_t snapshot_flow_limit = 64;
  /// Table entries examined per publish tick when building the detail
  /// snapshot. Publishing runs on the metering thread, so an unbounded scan of
  /// a million-entry flow table lands directly in the packet tail latency:
  /// measured at 900 us at p99.9 before this was bounded. The scan spans
  /// several ticks instead, and the published table is a rolling view.
  size_t snapshot_scan_budget = 4096;
  /// How long a reader's interest in the detail tables keeps the scan running.
  /// With no reader, the metering thread does not scan at all — a Prometheus
  /// scrape every 15 s keeps it warm, and an unobserved pipeline pays nothing.
  uint64_t detail_demand_ttl_ns = 30'000'000'000ULL;
  std::string records_path;  ///< NDJSON usage records; empty disables writing
};

/// Owns the metering and reporter threads and everything they touch.
class Runtime {
 public:
  explicit Runtime(RuntimeConfig cfg);
  ~Runtime();

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  /// Install sessions before start(); the metering thread owns the engine once
  /// it is running.
  size_t install_sessions(const std::vector<SessionSpec>& sessions);

  void start();
  /// Stop ingest-side production, let the metering thread drain the rings,
  /// emit final records, and join both threads.
  void stop();
  [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }

  /// The ingest-side object; call from the ingest thread only.
  [[nodiscard]] Ingest& ingest() noexcept { return ingest_; }
  [[nodiscard]] SpscRing<MeterEvent>& meter_ring() noexcept { return meter_ring_; }

  /// Latest published counters. Cheap, wait-free, and may be one interval old.
  [[nodiscard]] PipelineSnapshot snapshot() const;
  /// Latest published per-subscriber and per-flow detail. Reading also
  /// registers interest, which is what makes the metering thread build it.
  [[nodiscard]] SnapshotPublisher<DetailSnapshot>::Handle detail() const {
    request_detail();
    return detail_.read();
  }

  /// Register interest in the detail tables without reading them.
  void request_detail() const noexcept {
    detail_request_ns_.store(now_ns(), std::memory_order_relaxed);
  }

  [[nodiscard]] const RuntimeConfig& config() const noexcept { return cfg_; }
  /// Records actually written to disk by the reporter.
  [[nodiscard]] uint64_t records_written() const noexcept {
    return records_written_.load(std::memory_order_relaxed);
  }

  /// Publish a snapshot immediately. Test hook: avoids sleeping for a tick.
  void publish_now();

 private:
  void meter_loop();
  void reporter_loop();
  void publish_locked(uint64_t now);
  void advance_detail_scan(uint64_t publish_wall_ns);
  void drain_records();

  RuntimeConfig cfg_;
  SpscRing<MeterEvent> meter_ring_;
  SpscRing<GyEvent> gy_ring_;
  SpscRing<UsageRecord> record_ring_;
  MeterEngine engine_;
  Ingest ingest_;
  Histogram latency_;

  Seqlock<PipelineSnapshot> stats_;
  SnapshotPublisher<DetailSnapshot> detail_;

  std::thread meter_thread_;
  std::thread reporter_thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> meter_stop_{false};
  std::atomic<bool> reporter_stop_{false};
  std::atomic<uint64_t> records_written_{0};
  std::atomic<uint64_t> record_write_errors_{0};

  uint64_t start_ns_ = 0;
  uint64_t last_publish_ns_ = 0;
  uint64_t meter_batches_ = 0;
  uint64_t meter_idle_polls_ = 0;
  uint32_t latency_counter_ = 0;
  std::FILE* records_file_ = nullptr;

  // Rolling detail-snapshot build state.
  mutable std::atomic<uint64_t> detail_request_ns_{0};
  DetailSnapshot* detail_building_ = nullptr;
  size_t detail_sub_cursor_ = 0;
  size_t detail_flow_cursor_ = 0;
};

}  // namespace gtpm
