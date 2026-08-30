// SPDX-License-Identifier: MIT
//
// Snapshot publisher tests. The property that matters: a reader holding a
// buffer must never have it rewritten under it, even while the writer keeps
// publishing.
#include "gtpm/snapshot.hpp"

#include <atomic>
#include <numeric>
#include <thread>
#include <vector>

#include "test_harness.hpp"

using namespace gtpm;

namespace {

/// A payload whose internal consistency is checkable: every element equals
/// `generation`, and the vector length equals `generation % 64 + 1`.
struct Payload {
  uint64_t generation = 0;
  std::vector<uint64_t> values;

  [[nodiscard]] bool consistent() const {
    if (generation == 0) return values.empty();
    if (values.size() != generation % 64 + 1) return false;
    for (uint64_t v : values) {
      if (v != generation) return false;
    }
    return true;
  }
};

void fill(Payload& p, uint64_t generation) {
  p.generation = generation;
  p.values.assign(generation % 64 + 1, generation);
}

}  // namespace

TEST("snapshot/no_data_before_first_commit") {
  SnapshotPublisher<Payload> pub;
  CHECK(!pub.has_data());
  CHECK(!pub.read().valid());
  CHECK_EQ(pub.version(), 0ULL);
}

TEST("snapshot/publish_then_read") {
  SnapshotPublisher<Payload> pub;
  Payload* w = pub.begin_write();
  REQUIRE(w != nullptr);
  fill(*w, 7);
  pub.commit();

  auto handle = pub.read();
  REQUIRE(handle.valid());
  CHECK_EQ(handle->generation, 7ULL);
  CHECK(handle->consistent());
  CHECK_EQ(pub.version(), 1ULL);
}

TEST("snapshot/writer_never_reuses_a_pinned_buffer") {
  SnapshotPublisher<Payload, 3> pub;
  for (uint64_t gen = 1; gen <= 2; ++gen) {
    Payload* w = pub.begin_write();
    REQUIRE(w != nullptr);
    fill(*w, gen);
    pub.commit();
  }

  auto pinned = pub.read();
  REQUIRE(pinned.valid());
  const Payload* pinned_ptr = pinned.get();
  CHECK_EQ(pinned->generation, 2ULL);

  // With one buffer pinned and one current, exactly one remains writable.
  Payload* w = pub.begin_write();
  REQUIRE(w != nullptr);
  CHECK(w != pinned_ptr);
  fill(*w, 3);
  pub.commit();

  CHECK_EQ(pinned->generation, 2ULL);  // still intact under the reader
  auto fresh = pub.read();
  CHECK_EQ(fresh->generation, 3ULL);
}

TEST("snapshot/begin_write_fails_rather_than_corrupting") {
  SnapshotPublisher<Payload, 3> pub;
  Payload* first = pub.begin_write();
  REQUIRE(first != nullptr);
  fill(*first, 1);
  pub.commit();

  // Pin every non-current buffer by publishing and holding in turn.
  auto h1 = pub.read();
  Payload* w2 = pub.begin_write();
  REQUIRE(w2 != nullptr);
  fill(*w2, 2);
  pub.commit();
  auto h2 = pub.read();

  // Two pinned (h1, h2 point at different buffers) plus current: no free slot.
  Payload* w3 = pub.begin_write();
  if (w3 != nullptr) {
    fill(*w3, 3);
    pub.commit();
  }
  CHECK(h1.valid());
  CHECK(h2.valid());
  CHECK(h1->consistent());
  CHECK(h2->consistent());
}

TEST("snapshot/reader_sees_only_consistent_payloads_under_a_hot_writer") {
  SnapshotPublisher<Payload> pub;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> inconsistent{0};
  std::atomic<uint64_t> reads{0};

  std::thread writer([&] {
    for (uint64_t gen = 1; !stop.load(std::memory_order_relaxed); ++gen) {
      Payload* w = pub.begin_write();
      if (w == nullptr) {
        cpu_relax();
        continue;
      }
      fill(*w, gen);
      pub.commit();
    }
  });

  std::vector<std::thread> readers;
  for (int r = 0; r < 3; ++r) {
    readers.emplace_back([&] {
      for (int i = 0; i < 50000; ++i) {
        auto h = pub.read();
        if (!h.valid()) continue;
        reads.fetch_add(1, std::memory_order_relaxed);
        // Read it twice with work in between: a buffer rewritten under us
        // would show up as an inconsistent or changing payload.
        const uint64_t gen = h->generation;
        uint64_t sum = 0;
        for (uint64_t v : h->values) sum += v;
        if (!h->consistent() || h->generation != gen || sum != gen * h->values.size()) {
          inconsistent.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  for (auto& t : readers) t.join();
  stop.store(true);
  writer.join();

  CHECK_EQ(inconsistent.load(), 0ULL);
  CHECK_GT(reads.load(), 1000ULL);
}

TEST("snapshot/version_advances_per_commit") {
  SnapshotPublisher<Payload> pub;
  for (uint64_t i = 1; i <= 10; ++i) {
    Payload* w = pub.begin_write();
    REQUIRE(w != nullptr);
    fill(*w, i);
    pub.commit();
    CHECK_EQ(pub.version(), i);
  }
}

GTPM_TEST_MAIN()
