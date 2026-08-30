// SPDX-License-Identifier: MIT
//
// Bounded single-producer/single-consumer ring buffer.
//
// One writer and one reader means no CAS on the hot path: publishing is a
// release store of the producer index, consuming is an acquire load. Each index
// sits on its own cache line, and each side caches the other's index so the
// common case touches only lines it already owns — a shared line ping-ponging
// between two cores costs more than the parse it is protecting.
//
// Capacity is a power of two so the wrap is a mask, not a modulo. Indices are
// free-running uint64 counters: at 100 Mpps they wrap in ~5,800 years, so the
// "is it full or empty" ambiguity of wrapping indices never arises.
#pragma once

#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

namespace gtpm {

/// Conservative cache-line size. std::hardware_destructive_interference_size is
/// not universally available and Apple silicon uses 128-byte lines, so pad to
/// the larger value and be right on both.
inline constexpr size_t kCacheLine = 128;

template <typename T>
class SpscRing {
  static_assert(std::is_trivially_copyable_v<T>, "ring elements must be POD-like");

 public:
  /// `capacity` is rounded up to the next power of two, minimum 2.
  explicit SpscRing(size_t capacity)
      : capacity_(round_up_pow2(capacity < 2 ? 2 : capacity)),
        mask_(capacity_ - 1),
        slots_(std::make_unique<T[]>(capacity_)) {}

  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;

  [[nodiscard]] size_t capacity() const noexcept { return capacity_; }

  /// Producer side. Returns false when the ring is full (caller counts the drop
  /// — a data plane must never block the NIC).
  [[nodiscard]] bool try_push(const T& value) noexcept {
    const uint64_t head = head_.value.load(std::memory_order_relaxed);
    if (head - cached_tail_.value >= capacity_) {
      cached_tail_.value = tail_.value.load(std::memory_order_acquire);
      if (head - cached_tail_.value >= capacity_) return false;
    }
    slots_[head & mask_] = value;
    head_.value.store(head + 1, std::memory_order_release);
    return true;
  }

  /// Consumer side. Returns false when empty.
  [[nodiscard]] bool try_pop(T& out) noexcept {
    const uint64_t tail = tail_.value.load(std::memory_order_relaxed);
    if (tail == cached_head_.value) {
      cached_head_.value = head_.value.load(std::memory_order_acquire);
      if (tail == cached_head_.value) return false;
    }
    out = slots_[tail & mask_];
    tail_.value.store(tail + 1, std::memory_order_release);
    return true;
  }

  /// Pop up to `max` elements, amortising the index stores over the batch.
  /// This is what the metering thread uses: one release store per batch.
  [[nodiscard]] size_t try_pop_bulk(T* out, size_t max) noexcept {
    const uint64_t tail = tail_.value.load(std::memory_order_relaxed);
    uint64_t head = cached_head_.value;
    if (tail == head) {
      head = head_.value.load(std::memory_order_acquire);
      cached_head_.value = head;
      if (tail == head) return 0;
    }
    size_t available = static_cast<size_t>(head - tail);
    if (available > max) available = max;
    for (size_t i = 0; i < available; ++i) out[i] = slots_[(tail + i) & mask_];
    tail_.value.store(tail + available, std::memory_order_release);
    return available;
  }

  /// Push up to `count` elements, returning how many were accepted.
  [[nodiscard]] size_t try_push_bulk(const T* in, size_t count) noexcept {
    const uint64_t head = head_.value.load(std::memory_order_relaxed);
    uint64_t tail = cached_tail_.value;
    size_t free_slots = capacity_ - static_cast<size_t>(head - tail);
    if (free_slots < count) {
      tail = tail_.value.load(std::memory_order_acquire);
      cached_tail_.value = tail;
      free_slots = capacity_ - static_cast<size_t>(head - tail);
    }
    const size_t n = free_slots < count ? free_slots : count;
    for (size_t i = 0; i < n; ++i) slots_[(head + i) & mask_] = in[i];
    head_.value.store(head + n, std::memory_order_release);
    return n;
  }

  /// Approximate occupancy. Safe to call from either side; exact only when the
  /// other side is quiescent.
  [[nodiscard]] size_t size_approx() const noexcept {
    const uint64_t head = head_.value.load(std::memory_order_acquire);
    const uint64_t tail = tail_.value.load(std::memory_order_acquire);
    return static_cast<size_t>(head - tail);
  }

  [[nodiscard]] bool empty_approx() const noexcept { return size_approx() == 0; }

  /// Total elements ever published / consumed — used by the pipeline stats.
  [[nodiscard]] uint64_t produced() const noexcept {
    return head_.value.load(std::memory_order_acquire);
  }
  [[nodiscard]] uint64_t consumed() const noexcept {
    return tail_.value.load(std::memory_order_acquire);
  }

 private:
  static size_t round_up_pow2(size_t v) noexcept {
    return std::has_single_bit(v) ? v : std::bit_ceil(v);
  }

  template <typename U>
  struct alignas(kCacheLine) Padded {
    U value{};
  };

  const size_t capacity_;
  const size_t mask_;
  std::unique_ptr<T[]> slots_;

  // Producer-owned line: head plus the producer's stale view of tail.
  Padded<std::atomic<uint64_t>> head_{};
  Padded<uint64_t> cached_tail_{};
  // Consumer-owned line.
  Padded<std::atomic<uint64_t>> tail_{};
  Padded<uint64_t> cached_head_{};
};

}  // namespace gtpm
