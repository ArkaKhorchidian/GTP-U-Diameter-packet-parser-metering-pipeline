// SPDX-License-Identifier: MIT
//
// CDR-style usage records: what the metering thread emits and the reporter
// thread serialises to disk.
//
// Records are POD so they cross an SPSC ring to the reporter; the metering
// thread never touches a file descriptor. Counters are deltas since the
// previous record for that subscriber, which is how a UPF reports usage to the
// charging function (each report closes an interval, and the OCS sums them).
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "gtpm/clock.hpp"

namespace gtpm {

/// Number of per-rating-group / per-QFI accounting slots kept per subscriber.
///
/// Three named slots fit the hot counters in exactly one cache line. Slots 0
/// and 1 are assigned first-come to the rating groups a subscriber actually
/// uses; slot 2 aggregates everything beyond that, and its record is flagged
/// so a consumer never mistakes an aggregate for a single rating group.
inline constexpr size_t kBucketSlots = 3;
inline constexpr size_t kAggregateSlot = 2;
/// Bucket ids derived from a 5G QFI are tagged so they cannot collide with a
/// 4G rating group id of the same numeric value.
inline constexpr uint32_t kQfiBucketTag = 0x80000000u;
inline constexpr uint32_t kUnsetBucket = 0xFFFFFFFFu;

enum class RecordReason : uint8_t {
  kInterval = 0,   ///< periodic reporting timer expired
  kVolume = 1,     ///< volume threshold crossed
  kRelease = 2,    ///< session released (PFCP session deletion in a real core)
  kShutdown = 3,   ///< pipeline draining
  kGyTrigger = 4,  ///< a Gy CCR-Update referenced this subscriber
};

[[nodiscard]] constexpr const char* to_string(RecordReason r) noexcept {
  switch (r) {
    case RecordReason::kInterval: return "interval";
    case RecordReason::kVolume: return "volume";
    case RecordReason::kRelease: return "release";
    case RecordReason::kShutdown: return "shutdown";
    case RecordReason::kGyTrigger: return "gy-trigger";
  }
  return "unknown";
}

struct UsageRecord {
  uint64_t record_wall_ns = 0;  ///< wall clock, for the record itself
  uint64_t interval_start_ns = 0;
  uint64_t interval_end_ns = 0;
  uint64_t imsi = 0;
  uint64_t ul_bytes = 0;  ///< delta since the previous record
  uint64_t dl_bytes = 0;
  uint64_t ul_packets = 0;
  uint64_t dl_packets = 0;
  uint64_t bucket_bytes[kBucketSlots] = {};
  uint32_t bucket_ids[kBucketSlots] = {kUnsetBucket, kUnsetBucket, kUnsetBucket};
  uint32_t subscriber_index = 0;
  uint32_t record_seq = 0;  ///< per-subscriber sequence, gap-detectable
  uint8_t reason = 0;
  bool bucket_aggregated = false;  ///< slot 2 holds more than one rating group
  uint8_t _pad[2] = {};

  [[nodiscard]] uint64_t total_bytes() const noexcept { return ul_bytes + dl_bytes; }
};

static_assert(std::is_trivially_copyable_v<UsageRecord>);

/// Render a record as one NDJSON line (no trailing newline).
[[nodiscard]] inline std::string to_ndjson(const UsageRecord& r) {
  std::string out;
  out.reserve(320);
  char buf[512];

  int n = std::snprintf(
      buf, sizeof(buf),
      R"({"ts":"%s","imsi":"%llu","sub":%u,"seq":%u,"reason":"%s",)"
      R"("ul_bytes":%llu,"dl_bytes":%llu,"ul_pkts":%llu,"dl_pkts":%llu,)"
      R"("interval_ns":%llu,"buckets":[)",
      format_rfc3339(r.record_wall_ns).c_str(), static_cast<unsigned long long>(r.imsi),
      r.subscriber_index, r.record_seq, to_string(static_cast<RecordReason>(r.reason)),
      static_cast<unsigned long long>(r.ul_bytes), static_cast<unsigned long long>(r.dl_bytes),
      static_cast<unsigned long long>(r.ul_packets), static_cast<unsigned long long>(r.dl_packets),
      static_cast<unsigned long long>(r.interval_end_ns - r.interval_start_ns));
  out.append(buf, static_cast<size_t>(n));

  bool first = true;
  for (size_t i = 0; i < kBucketSlots; ++i) {
    if (r.bucket_ids[i] == kUnsetBucket && r.bucket_bytes[i] == 0) continue;
    const bool is_qfi = (r.bucket_ids[i] & kQfiBucketTag) != 0;
    n = std::snprintf(buf, sizeof(buf), R"(%s{"kind":"%s","id":%u,"bytes":%llu,"aggregate":%s})",
                      first ? "" : ",", is_qfi ? "qfi" : "rating-group",
                      r.bucket_ids[i] & ~kQfiBucketTag,
                      static_cast<unsigned long long>(r.bucket_bytes[i]),
                      (i == kAggregateSlot && r.bucket_aggregated) ? "true" : "false");
    out.append(buf, static_cast<size_t>(n));
    first = false;
  }
  out.append("]}");
  return out;
}

}  // namespace gtpm
