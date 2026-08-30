// SPDX-License-Identifier: MIT
//
// Fixed-memory latency histogram with HdrHistogram-style logarithmic bucketing:
// constant-time recording, no allocation after construction, and bounded
// relative error across the whole range (1 ns .. ~1 s).
//
// Layout: values are split into 2^k "magnitude" buckets, each with a fixed
// number of linear sub-buckets, so relative precision is uniform per decade.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace gtpm {

class Histogram {
 public:
  /// 2^kSubBucketBits sub-buckets per power of two => ~0.4% relative error.
  static constexpr int kSubBucketBits = 8;
  static constexpr uint32_t kSubBucketCount = 1u << kSubBucketBits;
  static constexpr int kBucketCount = 40;  // covers up to ~2^47 ns

  Histogram() : counts_(static_cast<size_t>(kBucketCount) * kSubBucketCount, 0) {}

  void record(uint64_t value) noexcept {
    const size_t idx = index_for(value);
    ++counts_[idx];
    ++total_;
    sum_ += value;
    min_ = std::min(min_, value);
    max_ = std::max(max_, value);
  }

  void reset() noexcept {
    std::fill(counts_.begin(), counts_.end(), 0);
    total_ = 0;
    sum_ = 0;
    min_ = UINT64_MAX;
    max_ = 0;
  }

  void merge(const Histogram& other) noexcept {
    for (size_t i = 0; i < counts_.size(); ++i) counts_[i] += other.counts_[i];
    total_ += other.total_;
    sum_ += other.sum_;
    min_ = std::min(min_, other.min_);
    max_ = std::max(max_, other.max_);
  }

  [[nodiscard]] uint64_t count() const noexcept { return total_; }
  [[nodiscard]] uint64_t min() const noexcept { return total_ ? min_ : 0; }
  [[nodiscard]] uint64_t max() const noexcept { return max_; }
  [[nodiscard]] double mean() const noexcept {
    return total_ ? static_cast<double>(sum_) / static_cast<double>(total_) : 0.0;
  }

  /// Value at `q` in [0,1]. Returns the upper edge of the containing bucket, so
  /// the report is never optimistic about tail latency.
  [[nodiscard]] uint64_t quantile(double q) const noexcept {
    if (total_ == 0) return 0;
    q = std::clamp(q, 0.0, 1.0);
    const auto target = static_cast<uint64_t>(q * static_cast<double>(total_) + 0.5);
    uint64_t cumulative = 0;
    for (size_t i = 0; i < counts_.size(); ++i) {
      cumulative += counts_[i];
      if (cumulative >= target && counts_[i] != 0) return value_at_upper_edge(i);
    }
    return max_;
  }

  [[nodiscard]] std::string summary(const char* unit = "ns") const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "n=%llu min=%llu p50=%llu p90=%llu p99=%llu p99.9=%llu p99.99=%llu max=%llu "
                  "mean=%.1f %s",
                  static_cast<unsigned long long>(total_), static_cast<unsigned long long>(min()),
                  static_cast<unsigned long long>(quantile(0.50)),
                  static_cast<unsigned long long>(quantile(0.90)),
                  static_cast<unsigned long long>(quantile(0.99)),
                  static_cast<unsigned long long>(quantile(0.999)),
                  static_cast<unsigned long long>(quantile(0.9999)),
                  static_cast<unsigned long long>(max_), mean(), unit);
    return buf;
  }

  /// (value, count) pairs for non-empty buckets — for CSV export and plots.
  [[nodiscard]] std::vector<std::pair<uint64_t, uint64_t>> buckets() const {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    for (size_t i = 0; i < counts_.size(); ++i) {
      if (counts_[i]) out.emplace_back(value_at_upper_edge(i), counts_[i]);
    }
    return out;
  }

 private:
  static size_t index_for(uint64_t value) noexcept {
    if (value < kSubBucketCount) return static_cast<size_t>(value);
    const int msb = 63 - std::countl_zero(value);
    const int bucket = msb - kSubBucketBits + 1;
    const int clamped = std::min(bucket, kBucketCount - 1);
    const uint32_t sub = static_cast<uint32_t>((value >> clamped) & (kSubBucketCount - 1));
    return static_cast<size_t>(clamped) * kSubBucketCount + sub;
  }

  static uint64_t value_at_upper_edge(size_t index) noexcept {
    const auto bucket = static_cast<int>(index / kSubBucketCount);
    const auto sub = static_cast<uint64_t>(index % kSubBucketCount);
    if (bucket == 0) return sub;
    return ((sub + 1) << bucket) - 1;
  }

  std::vector<uint64_t> counts_;
  uint64_t total_ = 0;
  uint64_t sum_ = 0;
  uint64_t min_ = UINT64_MAX;
  uint64_t max_ = 0;
};

}  // namespace gtpm
