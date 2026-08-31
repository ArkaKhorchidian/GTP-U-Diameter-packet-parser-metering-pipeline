// SPDX-License-Identifier: MIT
//
// Lock-free snapshot publication for read-mostly state that is too big for a
// seqlock (the per-subscriber table).
//
// One writer rotates through N pre-allocated buffers; readers pin the current
// buffer with a reference count and release it when done. A writer only ever
// claims a buffer whose refcount it can move from 0 to writer-owned, so a
// reader can never be reading a buffer that is being rewritten — unlike a bare
// double buffer, where a slow reader silently reads torn state.
//
// Buffers are reused, so after warm-up the writer performs no allocation.
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "gtpm/clock.hpp"
#include "gtpm/spsc_ring.hpp"  // kCacheLine

namespace gtpm {

template <typename T, size_t N = 4>
class SnapshotPublisher {
  static_assert(N >= 3, "need at least three buffers to keep a writer unblocked");
  static constexpr uint32_t kWriterOwned = 0x8000'0000u;

 public:
  /// RAII pin on a published buffer.
  class Handle {
   public:
    Handle() = default;
    Handle(const T* value, std::atomic<uint32_t>* refs) : value_(value), refs_(refs) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& o) noexcept : value_(o.value_), refs_(o.refs_) {
      o.value_ = nullptr;
      o.refs_ = nullptr;
    }
    Handle& operator=(Handle&& o) noexcept {
      if (this != &o) {
        release();
        value_ = o.value_;
        refs_ = o.refs_;
        o.value_ = nullptr;
        o.refs_ = nullptr;
      }
      return *this;
    }
    ~Handle() { release(); }

    [[nodiscard]] bool valid() const noexcept { return value_ != nullptr; }
    [[nodiscard]] const T& operator*() const noexcept { return *value_; }
    [[nodiscard]] const T* operator->() const noexcept { return value_; }
    [[nodiscard]] const T* get() const noexcept { return value_; }

   private:
    void release() noexcept {
      if (refs_ != nullptr) refs_->fetch_sub(1, std::memory_order_release);
      refs_ = nullptr;
      value_ = nullptr;
    }
    const T* value_ = nullptr;
    std::atomic<uint32_t>* refs_ = nullptr;
  };

  /// Writer: claim a buffer to fill. Returns nullptr if every buffer is pinned
  /// (only possible with more concurrent readers than buffers).
  [[nodiscard]] T* begin_write() noexcept {
    const int current = current_.load(std::memory_order_relaxed);
    for (size_t attempt = 0; attempt < N; ++attempt) {
      const size_t idx = (write_hint_ + attempt) % N;
      if (static_cast<int>(idx) == current) continue;
      uint32_t expected = 0;
      if (slots_[idx].refs.compare_exchange_strong(
              expected, kWriterOwned, std::memory_order_acquire, std::memory_order_relaxed)) {
        writing_ = static_cast<int>(idx);
        write_hint_ = (idx + 1) % N;
        return &slots_[idx].value;
      }
    }
    return nullptr;
  }

  /// Writer: publish the buffer returned by the last begin_write().
  void commit() noexcept {
    if (writing_ < 0) return;
    const size_t idx = static_cast<size_t>(writing_);
    slots_[idx].refs.store(0, std::memory_order_release);
    current_.store(writing_, std::memory_order_release);
    version_.fetch_add(1, std::memory_order_release);
    writing_ = -1;
  }

  /// Reader: pin the newest published buffer.
  [[nodiscard]] Handle read() const noexcept {
    for (int attempt = 0; attempt < 16; ++attempt) {
      const int idx = current_.load(std::memory_order_acquire);
      if (idx < 0) return Handle{};
      auto& slot = slots_[static_cast<size_t>(idx)];

      uint32_t refs = slot.refs.load(std::memory_order_relaxed);
      bool pinned = false;
      while (refs < kWriterOwned) {
        if (slot.refs.compare_exchange_weak(refs, refs + 1, std::memory_order_acquire,
                                            std::memory_order_relaxed)) {
          pinned = true;
          break;
        }
      }
      if (!pinned) {
        cpu_relax();
        continue;
      }
      // Re-check: if the writer published a newer buffer meanwhile we still
      // hold a valid (slightly older) one, which is fine — it is never being
      // rewritten while pinned.
      return Handle{&slot.value, &slot.refs};
    }
    return Handle{};
  }

  [[nodiscard]] uint64_t version() const noexcept {
    return version_.load(std::memory_order_acquire);
  }
  [[nodiscard]] bool has_data() const noexcept {
    return current_.load(std::memory_order_acquire) >= 0;
  }

 private:
  struct Slot {
    T value{};
    alignas(kCacheLine) mutable std::atomic<uint32_t> refs{0};
  };

  mutable std::array<Slot, N> slots_{};
  std::atomic<int> current_{-1};
  std::atomic<uint64_t> version_{0};
  size_t write_hint_ = 0;
  int writing_ = -1;
};

}  // namespace gtpm
