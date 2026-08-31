// SPDX-License-Identifier: MIT
//
// TEID table benchmark: lookup cost at load factors 0.3 / 0.5 / 0.7, against
// std::unordered_map as the baseline.
//
// The access pattern matters as much as the structure. A sequential sweep hides
// cache misses that a random TEID stream does not, and real TEIDs arrive in
// essentially random order, so the random column is the one to believe.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <random>
#include <unordered_map>
#include <vector>

#include "bench_common.hpp"
#include "gtpm/flat_hash.hpp"
#include "gtpm/meter.hpp"

using namespace gtpm;

namespace {

struct Timing {
  double ns_per_lookup;
  double probes_per_lookup;
  double hit_rate;
};

std::vector<uint32_t> make_teids(size_t n, std::mt19937& rng, bool sequential) {
  std::vector<uint32_t> keys(n);
  if (sequential) {
    // How a lab generator allocates them: consecutive.
    for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(0x10000 + i * 2);
  } else {
    // How a real core allocates them: sparse and unpredictable.
    for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(rng());
  }
  return keys;
}

Timing bench_flat(const std::vector<uint32_t>& keys, const std::vector<uint32_t>& probe_order,
                  size_t capacity, uint64_t iterations) {
  FlatHashU32<TeidBinding> table(capacity);
  for (size_t i = 0; i < keys.size(); ++i) {
    TeidBinding b;
    b.sub_idx = static_cast<uint32_t>(i);
    (void)table.insert(keys[i], b);
  }
  // Warm the table into cache first: the first case in a run otherwise pays
  // for every cold miss and reads as slower than it is.
  for (const uint32_t key : probe_order) bench::sink += table.find(key) != nullptr;
  table.reset_stats();

  uint64_t hits = 0;
  const uint64_t start = now_ns();
  for (uint64_t it = 0; it < iterations; ++it) {
    for (const uint32_t key : probe_order) {
      const TeidBinding* b = table.find(key);
      if (b != nullptr) {
        hits += b->sub_idx;
      }
    }
  }
  const uint64_t elapsed = now_ns() - start;
  bench::sink += hits;

  const double lookups = static_cast<double>(probe_order.size()) * static_cast<double>(iterations);
  return {static_cast<double>(elapsed) / lookups,
          static_cast<double>(table.probe_count()) / static_cast<double>(table.lookup_count()),
          static_cast<double>(hits != 0)};
}

Timing bench_unordered(const std::vector<uint32_t>& keys, const std::vector<uint32_t>& probe_order,
                       uint64_t iterations) {
  std::unordered_map<uint32_t, TeidBinding> table;
  table.reserve(keys.size());
  for (size_t i = 0; i < keys.size(); ++i) {
    TeidBinding b;
    b.sub_idx = static_cast<uint32_t>(i);
    table.emplace(keys[i], b);
  }

  for (const uint32_t key : probe_order) bench::sink += table.find(key) != table.end();

  uint64_t hits = 0;
  const uint64_t start = now_ns();
  for (uint64_t it = 0; it < iterations; ++it) {
    for (const uint32_t key : probe_order) {
      const auto found = table.find(key);
      if (found != table.end()) hits += found->second.sub_idx;
    }
  }
  const uint64_t elapsed = now_ns() - start;
  bench::sink += hits;

  const double lookups = static_cast<double>(probe_order.size()) * static_cast<double>(iterations);
  return {static_cast<double>(elapsed) / lookups, 0.0, static_cast<double>(hits != 0)};
}

void row(const char* structure, const char* pattern, double load, size_t entries, const Timing& t) {
  std::printf("%-18s,%-12s,%6.2f,%10zu,%12.2f,%12.2f\n", structure, pattern, load, entries,
              t.ns_per_lookup, t.probes_per_lookup);
}

}  // namespace

int main(int argc, char** argv) {
  const uint64_t iterations = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 20;
  bench::print_environment("bench_hash");
  std::printf("# TEID -> subscriber binding lookup, %llu iterations per case\n",
              static_cast<unsigned long long>(iterations));
  std::printf("%-18s,%-12s,%6s,%10s,%12s,%12s\n", "structure", "pattern", "load", "entries",
              "ns/lookup", "probes");

  std::mt19937 rng(0xF10A7);
  constexpr size_t kCapacity = 1u << 20;

  for (const double load : {0.3, 0.5, 0.7}) {
    const size_t entries = static_cast<size_t>(load * static_cast<double>(kCapacity));
    for (const bool sequential : {false, true}) {
      const char* pattern = sequential ? "sequential" : "random";
      std::vector<uint32_t> keys = make_teids(entries, rng, sequential);

      // Probe in an order unrelated to insertion order: a real packet stream
      // does not arrive sorted by TEID.
      std::vector<uint32_t> probe_order(
          keys.begin(), keys.begin() + static_cast<long>(std::min<size_t>(entries, 100'000)));
      std::shuffle(probe_order.begin(), probe_order.end(), rng);

      row("flat_hash", pattern, load, entries,
          bench_flat(keys, probe_order, kCapacity, iterations));
      row("unordered_map", pattern, load, entries, bench_unordered(keys, probe_order, iterations));
    }
  }

  // Miss cost: packets on TEIDs with no installed session must be cheap to
  // reject, since that is what a scanning or misdirected flow looks like.
  std::printf("\n# miss path (no session installed for the TEID)\n");
  std::vector<uint32_t> keys = make_teids(1u << 19, rng, false);
  std::vector<uint32_t> misses(100'000);
  for (size_t i = 0; i < misses.size(); ++i) misses[i] = static_cast<uint32_t>(rng() | 1u);
  row("flat_hash", "miss", 0.5, keys.size(), bench_flat(keys, misses, kCapacity, iterations));
  row("unordered_map", "miss", 0.5, keys.size(), bench_unordered(keys, misses, iterations));

  return bench::sink == UINT64_MAX ? 1 : 0;
}
