// SPDX-License-Identifier: MIT
//
// Shared benchmark scaffolding: CSV output, environment capture, and a
// baseline-versus-ours comparison helper.
//
// Every benchmark prints its environment. A latency number without the CPU,
// the compiler flags and whether the cores were isolated is not a result, it is
// an anecdote.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sched.h>
#include <fstream>
#endif

#include <thread>

#include "gtpm/clock.hpp"
#include "gtpm/histogram.hpp"

namespace gtpm::bench {

using gtpm::Histogram;

[[nodiscard]] inline std::string cpu_model() {
#if defined(__APPLE__)
  char buf[256];
  size_t len = sizeof(buf);
  if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0) {
    return std::string(buf, len > 0 ? len - 1 : 0);
  }
#elif defined(__linux__)
  std::ifstream in("/proc/cpuinfo");
  std::string line;
  while (std::getline(in, line)) {
    const size_t colon = line.find(':');
    if (colon != std::string::npos && line.rfind("model name", 0) == 0) {
      return line.substr(colon + 2);
    }
  }
#endif
  return "unknown";
}

[[nodiscard]] inline std::string compiler_id() {
#if defined(__clang__)
  return "clang " __clang_version__;
#elif defined(__GNUC__)
  return "gcc " __VERSION__;
#else
  return "unknown";
#endif
}

/// Print the environment block that every result table must carry.
inline void print_environment(const char* benchmark) {
  std::printf("# benchmark: %s\n", benchmark);
  std::printf("# cpu: %s\n", cpu_model().c_str());
  std::printf("# cores: %u\n", std::thread::hardware_concurrency());
  std::printf("# compiler: %s\n", compiler_id().c_str());
#if defined(NDEBUG)
  std::printf("# build: release (NDEBUG)\n");
#else
  std::printf("# build: DEBUG - results are not meaningful\n");
#endif
#if defined(__linux__)
  {
    std::ifstream gov("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    std::string value;
    if (gov && std::getline(gov, value)) std::printf("# governor: %s\n", value.c_str());
    std::ifstream iso("/sys/devices/system/cpu/isolated");
    if (iso && std::getline(iso, value)) {
      std::printf("# isolated cpus: %s\n", value.empty() ? "(none)" : value.c_str());
    }
  }
#elif defined(__APPLE__)
  std::printf("# note: macOS gives affinity hints only, and has no isolcpus or\n");
  std::printf("#       performance governor. Tail latency here includes scheduler\n");
  std::printf("#       noise; run on isolated Linux cores for publishable tails.\n");
#endif
  std::printf("# timestamp: %s\n", format_rfc3339(wall_ns()).c_str());
}

inline void print_latency_row(const char* name, const Histogram& h, double ops_per_sec) {
  std::printf("%-28s,%12.0f,%8llu,%8llu,%8llu,%8llu,%8llu,%8llu,%10.1f\n", name, ops_per_sec,
              static_cast<unsigned long long>(h.min()),
              static_cast<unsigned long long>(h.quantile(0.50)),
              static_cast<unsigned long long>(h.quantile(0.99)),
              static_cast<unsigned long long>(h.quantile(0.999)),
              static_cast<unsigned long long>(h.quantile(0.9999)),
              static_cast<unsigned long long>(h.max()), h.mean());
}

inline void print_latency_header() {
  std::printf("%-28s,%12s,%8s,%8s,%8s,%8s,%8s,%8s,%10s\n", "case", "ops/s", "min", "p50", "p99",
              "p99.9", "p99.99", "max", "mean");
}

/// Keep a computed value observable so the optimiser cannot delete the work.
inline volatile uint64_t sink = 0;

}  // namespace gtpm::bench
