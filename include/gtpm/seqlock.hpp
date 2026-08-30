// SPDX-License-Identifier: MIT
//
// Single-writer / multi-reader seqlock over a POD payload.
//
// The metering thread must never block on a reporter. A seqlock gives readers a
// consistent snapshot without any writer-side waiting: the writer bumps a
// counter to odd, writes, bumps to even. A reader that observes an odd counter,
// or a changed counter across the read, retries.
//
// Readers race with the writer by construction, so the payload is copied
// through relaxed atomic loads/stores — a torn read is detected and discarded
// by the sequence check, but it must not be a data race in the abstract
// machine. The copy is done a machine word at a time: byte-wise atomics would
// make a 4 KB snapshot 8x slower to read and leave readers starving behind a
// busy writer.
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "gtpm/clock.hpp"
#include "gtpm/spsc_ring.hpp"  // kCacheLine

namespace gtpm {

template <typename T>
class Seqlock {
  static_assert(std::is_trivially_copyable_v<T>, "seqlock payload must be POD-like");

  using Word = uint64_t;
  static constexpr size_t kWordCount = (sizeof(T) + sizeof(Word) - 1) / sizeof(Word);

 public:
  Seqlock() {
    for (size_t i = 0; i < kWordCount; ++i) words_[i].store(0, std::memory_order_relaxed);
  }

  /// Writer side. Only one thread may call this.
  void store(const T& value) noexcept {
    Word staging[kWordCount];
    std::memset(staging, 0, sizeof(staging));
    std::memcpy(staging, &value, sizeof(T));

    const uint32_t seq = seq_.load(std::memory_order_relaxed);
    seq_.store(seq + 1, std::memory_order_relaxed);  // odd: write in progress
    std::atomic_thread_fence(std::memory_order_release);

    for (size_t i = 0; i < kWordCount; ++i) {
      words_[i].store(staging[i], std::memory_order_relaxed);
    }

    std::atomic_thread_fence(std::memory_order_release);
    seq_.store(seq + 2, std::memory_order_relaxed);  // even: readable again
  }

  /// Reader side. Retries until it gets a consistent copy or `max_attempts` is
  /// exhausted; returns false in the latter case so callers can back off rather
  /// than spin forever behind a hot writer.
  [[nodiscard]] bool load(T& out, int max_attempts = 64) const noexcept {
    Word staging[kWordCount];
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
      const uint32_t before = seq_.load(std::memory_order_relaxed);
      if (before & 1u) {  // writer mid-update
        cpu_relax();
        continue;
      }
      std::atomic_thread_fence(std::memory_order_acquire);

      for (size_t i = 0; i < kWordCount; ++i) {
        staging[i] = words_[i].load(std::memory_order_relaxed);
      }

      std::atomic_thread_fence(std::memory_order_acquire);
      if (seq_.load(std::memory_order_relaxed) == before) {
        std::memcpy(&out, staging, sizeof(T));
        return true;
      }
      cpu_relax();
    }
    return false;
  }

  /// Number of completed writes. Readers use it to detect staleness.
  [[nodiscard]] uint32_t version() const noexcept {
    return seq_.load(std::memory_order_acquire) >> 1;
  }

 private:
  alignas(kCacheLine) std::atomic<uint32_t> seq_{0};
  alignas(kCacheLine) std::atomic<Word> words_[kWordCount]{};
};

}  // namespace gtpm
