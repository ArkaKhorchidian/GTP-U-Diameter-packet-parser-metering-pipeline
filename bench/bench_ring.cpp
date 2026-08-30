// SPDX-License-Identifier: MIT
//
// SPSC ring benchmark: throughput and transit latency across ring sizes, with a
// mutex-guarded std::queue as the baseline.
//
// Transit latency is the number that matters for the pipeline: how long an
// event sits between the producer publishing it and the consumer seeing it.
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "bench_common.hpp"
#include "gtpm/meter_event.hpp"
#include "gtpm/spsc_ring.hpp"

using namespace gtpm;

namespace {

struct Item {
  uint64_t seq;
  uint64_t ts_ns;
  uint64_t payload[6];
};
static_assert(sizeof(Item) == 64);

/// Two-thread run over our SPSC ring. Producer paces itself to `target_pps` so
/// the latency measured is transit latency, not queueing under overload.
void run_spsc(size_t capacity, uint64_t count, uint64_t target_pps, bool measure_latency) {
  SpscRing<Item> ring(capacity);
  bench::Histogram hist;
  std::atomic<bool> consumer_ready{false};

  std::thread consumer([&] {
    Item batch[256];
    uint64_t received = 0;
    consumer_ready.store(true);
    while (received < count) {
      const size_t n = ring.try_pop_bulk(batch, 256);
      if (n == 0) {
        cpu_relax();
        continue;
      }
      const uint64_t now = measure_latency ? now_ns() : 0;
      for (size_t i = 0; i < n; ++i) {
        if (measure_latency && now > batch[i].ts_ns) hist.record(now - batch[i].ts_ns);
        bench::sink += batch[i].seq;
      }
      received += n;
    }
  });

  while (!consumer_ready.load()) cpu_relax();

  const uint64_t start = now_ns();
  for (uint64_t i = 0; i < count; ++i) {
    if (target_pps != 0) {
      const uint64_t deadline = start + i * 1'000'000'000ULL / target_pps;
      while (now_ns() < deadline) cpu_relax();
    }
    Item item{};
    item.seq = i;
    item.ts_ns = measure_latency ? now_ns() : 0;
    while (!ring.try_push(item)) cpu_relax();
  }
  consumer.join();
  const uint64_t elapsed = now_ns() - start;

  char name[64];
  std::snprintf(name, sizeof(name), "spsc_2^%d%s",
                static_cast<int>(std::countr_zero(ring.capacity())),
                target_pps ? "_paced" : "");
  bench::print_latency_row(name, hist,
                           static_cast<double>(count) / (static_cast<double>(elapsed) / 1e9));
}

/// Baseline: the obvious implementation. Mutex plus std::queue, same workload.
void run_mutex_queue(uint64_t count, uint64_t target_pps, bool measure_latency) {
  std::queue<Item> queue;
  std::mutex mu;
  bench::Histogram hist;
  std::atomic<bool> done{false};

  std::thread consumer([&] {
    uint64_t received = 0;
    while (received < count) {
      Item item{};
      bool got = false;
      {
        std::lock_guard<std::mutex> lock(mu);
        if (!queue.empty()) {
          item = queue.front();
          queue.pop();
          got = true;
        }
      }
      if (!got) {
        cpu_relax();
        continue;
      }
      if (measure_latency) {
        const uint64_t now = now_ns();
        if (now > item.ts_ns) hist.record(now - item.ts_ns);
      }
      bench::sink += item.seq;
      ++received;
    }
    done.store(true);
  });

  const uint64_t start = now_ns();
  for (uint64_t i = 0; i < count; ++i) {
    if (target_pps != 0) {
      const uint64_t deadline = start + i * 1'000'000'000ULL / target_pps;
      while (now_ns() < deadline) cpu_relax();
    }
    Item item{};
    item.seq = i;
    item.ts_ns = measure_latency ? now_ns() : 0;
    {
      std::lock_guard<std::mutex> lock(mu);
      queue.push(item);
    }
  }
  consumer.join();
  const uint64_t elapsed = now_ns() - start;
  bench::print_latency_row(target_pps ? "mutex_queue_paced" : "mutex_queue", hist,
                           static_cast<double>(count) / (static_cast<double>(elapsed) / 1e9));
}

/// Single-threaded push+pop pairs: measures the data structure itself with no
/// inter-core traffic at all.
void run_single_thread(size_t capacity, uint64_t count) {
  SpscRing<Item> ring(capacity);
  const uint64_t start = now_ns();
  Item item{};
  for (uint64_t i = 0; i < count; ++i) {
    item.seq = i;
    (void)ring.try_push(item);
    Item out{};
    (void)ring.try_pop(out);
    bench::sink += out.seq;
  }
  const uint64_t elapsed = now_ns() - start;
  char name[64];
  std::snprintf(name, sizeof(name), "spsc_1thread_2^%d",
                static_cast<int>(std::countr_zero(ring.capacity())));
  std::printf("%-28s,%12.0f,%8s,%8.1f ns/op pair\n", name,
              static_cast<double>(count) / (static_cast<double>(elapsed) / 1e9), "-",
              static_cast<double>(elapsed) / static_cast<double>(count));
}

}  // namespace

int main(int argc, char** argv) {
  const uint64_t count = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 4'000'000;
  bench::print_environment("bench_ring");
  std::printf("# elements: %llu, element size: %zu B\n", static_cast<unsigned long long>(count),
              sizeof(Item));
  std::printf("# latency columns are nanoseconds of transit (publish -> consume)\n");

  std::printf("\n## single thread, no contention\n");
  for (int shift = 10; shift <= 20; shift += 2) {
    run_single_thread(size_t{1} << shift, count);
  }

  std::printf("\n## two threads, unpaced (producer runs flat out; latency includes queueing)\n");
  bench::print_latency_header();
  for (int shift = 10; shift <= 20; shift += 2) {
    run_spsc(size_t{1} << shift, count, 0, true);
  }
  run_mutex_queue(count / 4, 0, true);

  std::printf("\n## two threads, paced to 2 Mpps (transit latency, no queueing)\n");
  bench::print_latency_header();
  run_spsc(size_t{1} << 16, count / 4, 2'000'000, true);
  run_mutex_queue(count / 4, 2'000'000, true);

  return bench::sink == UINT64_MAX ? 1 : 0;
}
