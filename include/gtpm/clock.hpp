// SPDX-License-Identifier: MIT
//
// Monotonic timestamps and CPU affinity helpers.
//
// The hot path timestamps with CLOCK_MONOTONIC_RAW where the platform has it
// (Linux): it is not slewed by NTP, so latency deltas stay honest. macOS has no
// _RAW, and its CLOCK_MONOTONIC is already an un-slewed uptime clock.
#pragma once

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#elif defined(__APPLE__)
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#endif

namespace gtpm {

#if defined(CLOCK_MONOTONIC_RAW)
inline constexpr clockid_t kMonotonicClock = CLOCK_MONOTONIC_RAW;
#else
inline constexpr clockid_t kMonotonicClock = CLOCK_MONOTONIC;
#endif

/// Nanoseconds from an unspecified but monotonic epoch.
[[nodiscard]] inline uint64_t now_ns() noexcept {
  timespec ts{};
  ::clock_gettime(kMonotonicClock, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

/// Wall-clock nanoseconds since the Unix epoch, for records that leave the box.
[[nodiscard]] inline uint64_t wall_ns() noexcept {
  timespec ts{};
  ::clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

/// Format `wall_ns` as RFC 3339 UTC with millisecond resolution.
[[nodiscard]] inline std::string format_rfc3339(uint64_t ns) {
  const auto secs = static_cast<time_t>(ns / 1'000'000'000ULL);
  const auto millis = static_cast<unsigned>((ns % 1'000'000'000ULL) / 1'000'000ULL);
  tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &secs);
#else
  gmtime_r(&secs, &tm_utc);
#endif
  char buf[40];
  const size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_utc);
  std::string out(buf, n);
  char frac[8];
  std::snprintf(frac, sizeof(frac), ".%03uZ", millis);
  out += frac;
  return out;
}

/// Pin the calling thread to `cpu`. Returns false when unsupported (macOS gives
/// affinity *hints* only) or when the call fails; callers treat it as advisory.
inline bool pin_this_thread(int cpu) noexcept {
  if (cpu < 0) return false;
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(static_cast<size_t>(cpu), &set);
  return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0;
#elif defined(__APPLE__)
  // Darwin has no hard pinning; an affinity tag asks the scheduler to keep
  // threads with the same tag off each other's cores. Best effort by design.
  thread_affinity_policy_data_t policy{cpu + 1};
  const kern_return_t kr =
      thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY,
                        reinterpret_cast<thread_policy_t>(&policy), THREAD_AFFINITY_POLICY_COUNT);
  return kr == KERN_SUCCESS;
#else
  (void)cpu;
  return false;
#endif
}

/// Spin hint for busy-wait loops; keeps SMT siblings and power draw sane.
inline void cpu_relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
  asm volatile("yield" ::: "memory");
#endif
}

}  // namespace gtpm
