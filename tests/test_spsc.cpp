// SPDX-License-Identifier: MIT
//
// SPSC ring tests: single-threaded semantics plus a two-thread stress run that
// asserts every element arrives exactly once, in order, with no loss.
#include "gtpm/spsc_ring.hpp"

#include "gtpm/clock.hpp"

#include <atomic>
#include <thread>
#include <vector>

#include "test_harness.hpp"

using namespace gtpm;

TEST("spsc/capacity_rounds_up_to_power_of_two") {
  CHECK_EQ(SpscRing<uint64_t>(1).capacity(), size_t{2});
  CHECK_EQ(SpscRing<uint64_t>(3).capacity(), size_t{4});
  CHECK_EQ(SpscRing<uint64_t>(1000).capacity(), size_t{1024});
  CHECK_EQ(SpscRing<uint64_t>(1024).capacity(), size_t{1024});
}

TEST("spsc/push_pop_fifo_order") {
  SpscRing<uint64_t> ring(8);
  for (uint64_t i = 0; i < 8; ++i) CHECK(ring.try_push(i));
  CHECK(!ring.try_push(99));  // full
  CHECK_EQ(ring.size_approx(), size_t{8});

  for (uint64_t i = 0; i < 8; ++i) {
    uint64_t v = 0;
    REQUIRE(ring.try_pop(v));
    CHECK_EQ(v, i);
  }
  uint64_t v = 0;
  CHECK(!ring.try_pop(v));
  CHECK(ring.empty_approx());
}

TEST("spsc/wraps_around_many_times") {
  SpscRing<uint64_t> ring(4);
  for (uint64_t round = 0; round < 1000; ++round) {
    CHECK(ring.try_push(round));
    uint64_t v = 0;
    REQUIRE(ring.try_pop(v));
    CHECK_EQ(v, round);
  }
  CHECK_EQ(ring.produced(), 1000ULL);
  CHECK_EQ(ring.consumed(), 1000ULL);
}

TEST("spsc/bulk_pop_returns_available_only") {
  SpscRing<uint32_t> ring(64);
  for (uint32_t i = 0; i < 10; ++i) CHECK(ring.try_push(i));

  uint32_t out[32];
  const size_t n = ring.try_pop_bulk(out, 32);
  CHECK_EQ(n, size_t{10});
  for (uint32_t i = 0; i < 10; ++i) CHECK_EQ(out[i], i);
  CHECK_EQ(ring.try_pop_bulk(out, 32), size_t{0});
}

TEST("spsc/bulk_pop_respects_max") {
  SpscRing<uint32_t> ring(64);
  for (uint32_t i = 0; i < 40; ++i) CHECK(ring.try_push(i));
  uint32_t out[8];
  CHECK_EQ(ring.try_pop_bulk(out, 8), size_t{8});
  CHECK_EQ(out[7], 7u);
  CHECK_EQ(ring.size_approx(), size_t{32});
}

TEST("spsc/bulk_push_partial_when_full") {
  SpscRing<uint32_t> ring(8);
  const uint32_t in[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  CHECK_EQ(ring.try_push_bulk(in, 12), size_t{8});
  CHECK_EQ(ring.try_push_bulk(in, 4), size_t{0});
  uint32_t out[8];
  CHECK_EQ(ring.try_pop_bulk(out, 8), size_t{8});
  CHECK_EQ(out[7], 7u);
}

TEST("spsc/two_threads_lose_nothing_and_keep_order") {
  struct Item {
    uint64_t seq;
    uint64_t payload;
  };
  constexpr uint64_t kCount = 2'000'000;
  SpscRing<Item> ring(4096);
  std::atomic<uint64_t> drops{0};

  std::thread producer([&] {
    for (uint64_t i = 0; i < kCount; ++i) {
      Item item{i, i * 2654435761ULL};
      while (!ring.try_push(item)) {
        cpu_relax();  // back-pressure, not loss: this test asserts zero drops
      }
    }
  });

  uint64_t received = 0;
  uint64_t mismatches = 0;
  Item batch[256];
  while (received < kCount) {
    const size_t n = ring.try_pop_bulk(batch, 256);
    for (size_t i = 0; i < n; ++i) {
      if (batch[i].seq != received || batch[i].payload != received * 2654435761ULL) ++mismatches;
      ++received;
    }
    if (n == 0) cpu_relax();
  }
  producer.join();

  CHECK_EQ(received, kCount);
  CHECK_EQ(mismatches, 0ULL);
  CHECK_EQ(drops.load(), 0ULL);
  CHECK_EQ(ring.produced(), kCount);
  CHECK_EQ(ring.consumed(), kCount);
}

TEST("spsc/drops_are_counted_not_blocking") {
  // The pipeline's real policy: a full ring drops and increments a counter
  // rather than stalling ingest.
  SpscRing<uint64_t> ring(16);
  uint64_t dropped = 0;
  for (uint64_t i = 0; i < 100; ++i) {
    if (!ring.try_push(i)) ++dropped;
  }
  CHECK_EQ(dropped, 84ULL);
  CHECK_EQ(ring.size_approx(), size_t{16});
}

GTPM_TEST_MAIN()
