// SPDX-License-Identifier: MIT
//
// Seqlock tests. The interesting property is the concurrent one: a reader must
// never observe a half-written payload, and the writer must never block.
#include "gtpm/seqlock.hpp"

#include <atomic>
#include <thread>
#include <vector>

#include "test_harness.hpp"

using namespace gtpm;

namespace {

/// Payload big enough that a torn write is guaranteed to be observable if the
/// sequence check were wrong: every field must always agree with `id`.
struct Snapshot {
  uint64_t id;
  uint64_t fields[15];
};

bool consistent(const Snapshot& s) {
  for (uint64_t f : s.fields) {
    if (f != s.id * 31) return false;
  }
  return true;
}

}  // namespace

TEST("seqlock/store_then_load") {
  Seqlock<Snapshot> lock;
  Snapshot in{};
  in.id = 7;
  for (auto& f : in.fields) f = 7 * 31;
  lock.store(in);

  Snapshot out{};
  REQUIRE(lock.load(out));
  CHECK_EQ(out.id, 7ULL);
  CHECK(consistent(out));
}

TEST("seqlock/version_counts_writes") {
  Seqlock<uint64_t> lock;
  CHECK_EQ(lock.version(), 0u);
  lock.store(1);
  lock.store(2);
  lock.store(3);
  CHECK_EQ(lock.version(), 3u);
  uint64_t v = 0;
  REQUIRE(lock.load(v));
  CHECK_EQ(v, 3ULL);
}

TEST("seqlock/concurrent_reader_never_sees_a_torn_snapshot") {
  // Safety property, tested against the worst case: a writer that never pauses.
  // Readers are allowed to fail here (that is what the retry budget is for);
  // what they must never do is return an inconsistent snapshot.
  Seqlock<Snapshot> lock;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> torn{0};
  std::atomic<uint64_t> reads{0};

  std::thread writer([&] {
    for (uint64_t i = 1; !stop.load(std::memory_order_relaxed); ++i) {
      Snapshot s{};
      s.id = i;
      for (auto& f : s.fields) f = i * 31;
      lock.store(s);
    }
  });

  std::thread reader([&] {
    Snapshot out{};
    for (int i = 0; i < 200000; ++i) {
      if (lock.load(out)) {
        reads.fetch_add(1, std::memory_order_relaxed);
        if (out.id != 0 && !consistent(out)) torn.fetch_add(1, std::memory_order_relaxed);
      }
    }
  });

  reader.join();
  stop.store(true);
  writer.join();

  CHECK_EQ(torn.load(), 0ULL);
}

TEST("seqlock/reader_makes_progress_at_a_realistic_write_rate") {
  // Liveness property. The pipeline publishes a snapshot on a timer (order of
  // 10 Hz), not in a spin loop, so readers should essentially always succeed.
  Seqlock<Snapshot> lock;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> ok{0};
  std::atomic<uint64_t> failed{0};

  std::thread writer([&] {
    for (uint64_t i = 1; !stop.load(std::memory_order_relaxed); ++i) {
      Snapshot s{};
      s.id = i;
      for (auto& f : s.fields) f = i * 31;
      lock.store(s);
      // Simulate real publish spacing without sleeping the test for seconds.
      for (int spin = 0; spin < 2000; ++spin) cpu_relax();
    }
  });

  Snapshot out{};
  for (int i = 0; i < 50000; ++i) {
    if (lock.load(out)) {
      ok.fetch_add(1, std::memory_order_relaxed);
      CHECK(out.id == 0 || consistent(out));
    } else {
      failed.fetch_add(1, std::memory_order_relaxed);
    }
  }
  stop.store(true);
  writer.join();

  CHECK_GT(ok.load(), 49000ULL);
  CHECK_LT(failed.load(), 500ULL);
}

TEST("seqlock/multiple_readers") {
  Seqlock<Snapshot> lock;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> torn{0};

  std::thread writer([&] {
    for (uint64_t i = 1; !stop.load(std::memory_order_relaxed); ++i) {
      Snapshot s{};
      s.id = i;
      for (auto& f : s.fields) f = i * 31;
      lock.store(s);
      for (int spin = 0; spin < 200; ++spin) cpu_relax();
    }
  });

  std::vector<std::thread> readers;
  for (int r = 0; r < 4; ++r) {
    readers.emplace_back([&] {
      Snapshot out{};
      for (int i = 0; i < 50000; ++i) {
        if (lock.load(out) && out.id != 0 && !consistent(out)) {
          torn.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  for (auto& t : readers) t.join();
  stop.store(true);
  writer.join();

  CHECK_EQ(torn.load(), 0ULL);
}

GTPM_TEST_MAIN()
