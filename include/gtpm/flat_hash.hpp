// SPDX-License-Identifier: MIT
//
// Flat open-addressing hash map for 32-bit keys, built for the TEID lookup that
// happens once per packet.
//
// Why not std::unordered_map: that is a bucket array of pointers to nodes, so a
// hit is at least two dependent loads into unrelated cache lines, and every
// insert allocates. Here keys live in one contiguous power-of-two array and a
// hit is normally a single cache line touch; values are a parallel array so the
// probe sequence only pulls in key bytes.
//
// Deletion uses backward-shift, not tombstones: a metering table that churns
// sessions for months must not degrade into a tombstone swamp.
#pragma once

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <vector>

namespace gtpm {

/// Fibonacci hashing: multiply by 2^32/phi and take the high bits. One imul,
/// and it spreads sequentially allocated TEIDs across the whole table.
[[nodiscard]] inline uint32_t hash_u32(uint32_t key) noexcept {
  uint32_t x = key;
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

template <typename Value>
class FlatHashU32 {
 public:
  /// Reserved key marking an empty slot. A real TEID of this value is stored in
  /// a dedicated side slot rather than being rejected.
  static constexpr uint32_t kEmptyKey = 0xFFFFFFFFu;

  /// `capacity` is rounded up to a power of two; keep the load factor under
  /// ~0.7 by sizing for the expected session count divided by 0.6.
  explicit FlatHashU32(size_t capacity)
      : capacity_(round_up_pow2(capacity < 8 ? 8 : capacity)),
        mask_(capacity_ - 1),
        keys_(capacity_, kEmptyKey),
        values_(capacity_) {}

  [[nodiscard]] size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] size_t size() const noexcept { return size_ + (sentinel_used_ ? 1 : 0); }
  [[nodiscard]] bool empty() const noexcept { return size() == 0; }
  [[nodiscard]] double load_factor() const noexcept {
    return static_cast<double>(size_) / static_cast<double>(capacity_);
  }
  /// Probes performed by find/insert since construction — the number that shows
  /// whether the table is actually behaving like O(1).
  [[nodiscard]] uint64_t probe_count() const noexcept { return probes_; }
  [[nodiscard]] uint64_t lookup_count() const noexcept { return lookups_; }

  /// Returns a pointer to the value, or nullptr. The pointer is invalidated by
  /// any subsequent insert or erase.
  [[nodiscard]] Value* find(uint32_t key) noexcept {
    if (key == kEmptyKey) [[unlikely]] {
      return sentinel_used_ ? &sentinel_value_ : nullptr;
    }
    ++lookups_;
    size_t idx = hash_u32(key) & mask_;
    for (size_t probe = 0; probe <= mask_; ++probe) {
      ++probes_;
      const uint32_t k = keys_[idx];
      if (k == key) return &values_[idx];
      if (k == kEmptyKey) return nullptr;  // linear probing: a gap means absent
      idx = (idx + 1) & mask_;
    }
    return nullptr;
  }

  [[nodiscard]] const Value* find(uint32_t key) const noexcept {
    return const_cast<FlatHashU32*>(this)->find(key);
  }

  [[nodiscard]] bool contains(uint32_t key) const noexcept { return find(key) != nullptr; }

  /// Insert or overwrite. Returns false only when the table is full.
  bool insert(uint32_t key, const Value& value) noexcept {
    if (key == kEmptyKey) [[unlikely]] {
      sentinel_value_ = value;
      sentinel_used_ = true;
      return true;
    }
    if (size_ >= capacity_) return false;  // never let probing become unbounded
    size_t idx = hash_u32(key) & mask_;
    for (size_t probe = 0; probe <= mask_; ++probe) {
      ++probes_;
      const uint32_t k = keys_[idx];
      if (k == kEmptyKey) {
        keys_[idx] = key;
        values_[idx] = value;
        ++size_;
        return true;
      }
      if (k == key) {
        values_[idx] = value;
        return true;
      }
      idx = (idx + 1) & mask_;
    }
    return false;
  }

  bool erase(uint32_t key) noexcept {
    if (key == kEmptyKey) [[unlikely]] {
      const bool had = sentinel_used_;
      sentinel_used_ = false;
      return had;
    }
    size_t idx = hash_u32(key) & mask_;
    for (size_t probe = 0; probe <= mask_; ++probe) {
      const uint32_t k = keys_[idx];
      if (k == kEmptyKey) return false;
      if (k == key) {
        remove_at(idx);
        --size_;
        return true;
      }
      idx = (idx + 1) & mask_;
    }
    return false;
  }

  void clear() noexcept {
    std::fill(keys_.begin(), keys_.end(), kEmptyKey);
    size_ = 0;
    sentinel_used_ = false;
  }

  void reset_stats() noexcept {
    probes_ = 0;
    lookups_ = 0;
  }

  /// Visit every live entry as fn(key, Value&). Order is unspecified.
  template <typename Fn>
  void for_each(Fn&& fn) {
    for (size_t i = 0; i < capacity_; ++i) {
      if (keys_[i] != kEmptyKey) fn(keys_[i], values_[i]);
    }
    if (sentinel_used_) fn(kEmptyKey, sentinel_value_);
  }

 private:
  static size_t round_up_pow2(size_t v) noexcept {
    return std::has_single_bit(v) ? v : std::bit_ceil(v);
  }

  /// Backward-shift deletion (Knuth 6.4 algorithm R): pull up any element whose
  /// probe sequence passes through the hole, so lookups stay correct without
  /// tombstones.
  void remove_at(size_t hole) noexcept {
    size_t next = (hole + 1) & mask_;
    while (keys_[next] != kEmptyKey) {
      const size_t ideal = hash_u32(keys_[next]) & mask_;
      // Is `ideal` cyclically within (hole, next]? If not, the element may move
      // into the hole without breaking its own probe chain.
      const size_t dist_hole = (next - hole) & mask_;
      const size_t dist_ideal = (next - ideal) & mask_;
      if (dist_ideal >= dist_hole) {
        keys_[hole] = keys_[next];
        values_[hole] = values_[next];
        hole = next;
      }
      next = (next + 1) & mask_;
    }
    keys_[hole] = kEmptyKey;
  }

  size_t capacity_;
  size_t mask_;
  std::vector<uint32_t> keys_;
  std::vector<Value> values_;
  size_t size_ = 0;
  uint64_t probes_ = 0;
  uint64_t lookups_ = 0;
  Value sentinel_value_{};
  bool sentinel_used_ = false;
};

}  // namespace gtpm
