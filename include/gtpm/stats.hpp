// SPDX-License-Identifier: MIT
//
// The published view of the pipeline: everything a reporter, a scrape endpoint
// or an operator needs, in POD form so it can cross a seqlock without locking
// the metering thread.
#pragma once

#include <cstdint>

#include "gtpm/histogram.hpp"
#include "gtpm/meter.hpp"
#include "gtpm/pipeline.hpp"

namespace gtpm {

struct LatencySummary {
  uint64_t count = 0;
  uint64_t min_ns = 0;
  uint64_t p50_ns = 0;
  uint64_t p90_ns = 0;
  uint64_t p99_ns = 0;
  uint64_t p999_ns = 0;
  uint64_t p9999_ns = 0;
  uint64_t max_ns = 0;
  double mean_ns = 0.0;
};

[[nodiscard]] inline LatencySummary summarize(const Histogram& h) {
  LatencySummary s;
  s.count = h.count();
  s.min_ns = h.min();
  s.p50_ns = h.quantile(0.50);
  s.p90_ns = h.quantile(0.90);
  s.p99_ns = h.quantile(0.99);
  s.p999_ns = h.quantile(0.999);
  s.p9999_ns = h.quantile(0.9999);
  s.max_ns = h.max();
  s.mean_ns = h.mean();
  return s;
}

/// Per-subscriber row in the published table.
struct SubscriberSnapshot {
  uint64_t imsi = 0;
  uint64_t ul_bytes = 0;
  uint64_t dl_bytes = 0;
  uint64_t ul_packets = 0;
  uint64_t dl_packets = 0;
  uint64_t last_seen_ns = 0;
  uint64_t bucket_bytes[kBucketSlots] = {};
  uint64_t gy_reported_octets = 0;
  uint32_t bucket_ids[kBucketSlots] = {kUnsetBucket, kUnsetBucket, kUnsetBucket};
  uint32_t sub_idx = 0;
  uint32_t ul_teid = 0;
  uint32_t dl_teid = 0;
  uint32_t gy_reports = 0;
  bool bucket_aggregated = false;
};

/// Global counters, published on a timer behind a seqlock.
struct PipelineSnapshot {
  PipelineStats meter{};
  IngestStats ingest{};
  LatencySummary latency{};
  uint64_t publish_wall_ns = 0;
  uint64_t publish_mono_ns = 0;
  uint64_t uptime_ns = 0;
  uint64_t meter_ring_depth = 0;
  uint64_t meter_ring_capacity = 0;
  uint64_t gy_ring_depth = 0;
  uint64_t record_ring_depth = 0;
  uint64_t records_written = 0;
  uint64_t record_write_errors = 0;
  uint64_t teid_table_size = 0;
  uint64_t teid_table_capacity = 0;
  uint64_t meter_batches = 0;
  uint64_t meter_idle_polls = 0;
  double teid_probes_per_lookup = 0.0;
  double teid_load_factor = 0.0;
};

/// The published per-subscriber and per-flow tables.
struct DetailSnapshot {
  std::vector<SubscriberSnapshot> subscribers;
  std::vector<FlowEntry> top_flows;
  uint64_t publish_wall_ns = 0;
  uint64_t total_subscribers = 0;
};

}  // namespace gtpm
