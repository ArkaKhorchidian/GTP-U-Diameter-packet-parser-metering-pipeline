// SPDX-License-Identifier: MIT
//
// Flat hash tests, including a differential run against std::unordered_map and
// erase-heavy churn that would expose a broken backward-shift deletion.
#include "gtpm/flat_hash.hpp"

#include <random>
#include <unordered_map>
#include <vector>

#include "test_harness.hpp"

using namespace gtpm;

TEST("flat_hash/basic_insert_find") {
  FlatHashU32<uint32_t> h(64);
  CHECK(h.empty());
  CHECK(h.insert(42, 100));
  CHECK(h.insert(43, 200));
  CHECK_EQ(h.size(), size_t{2});

  const uint32_t* v = h.find(42);
  REQUIRE(v != nullptr);
  CHECK_EQ(*v, 100u);
  CHECK_EQ(*h.find(43), 200u);
  CHECK(h.find(44) == nullptr);
}

TEST("flat_hash/overwrite_existing_key") {
  FlatHashU32<uint32_t> h(64);
  CHECK(h.insert(7, 1));
  CHECK(h.insert(7, 2));
  CHECK_EQ(h.size(), size_t{1});
  CHECK_EQ(*h.find(7), 2u);
}

TEST("flat_hash/capacity_is_power_of_two") {
  CHECK_EQ(FlatHashU32<uint32_t>(1).capacity(), size_t{8});
  CHECK_EQ(FlatHashU32<uint32_t>(100).capacity(), size_t{128});
  CHECK_EQ(FlatHashU32<uint32_t>(4096).capacity(), size_t{4096});
}

TEST("flat_hash/sentinel_key_is_storable") {
  // 0xFFFFFFFF marks empty slots internally; a TEID with that value must still
  // work rather than silently vanishing.
  FlatHashU32<uint32_t> h(16);
  CHECK(h.insert(FlatHashU32<uint32_t>::kEmptyKey, 777));
  REQUIRE(h.find(FlatHashU32<uint32_t>::kEmptyKey) != nullptr);
  CHECK_EQ(*h.find(FlatHashU32<uint32_t>::kEmptyKey), 777u);
  CHECK_EQ(h.size(), size_t{1});
  CHECK(h.erase(FlatHashU32<uint32_t>::kEmptyKey));
  CHECK(h.find(FlatHashU32<uint32_t>::kEmptyKey) == nullptr);
}

TEST("flat_hash/erase_preserves_probe_chains") {
  // Force a long collision chain by inserting keys that land in the same slot,
  // then erase from the middle: every survivor must remain findable.
  FlatHashU32<uint32_t> h(1024);
  std::vector<uint32_t> keys;
  const size_t cap = h.capacity();
  for (uint32_t k = 1; keys.size() < 32; ++k) {
    if ((hash_u32(k) & (cap - 1)) == (hash_u32(1) & (cap - 1))) keys.push_back(k);
    if (k > 5'000'000) break;  // safety valve
  }
  REQUIRE(keys.size() >= 4);

  for (size_t i = 0; i < keys.size(); ++i) CHECK(h.insert(keys[i], static_cast<uint32_t>(i)));
  CHECK(h.erase(keys[keys.size() / 2]));
  for (size_t i = 0; i < keys.size(); ++i) {
    if (i == keys.size() / 2) {
      CHECK(h.find(keys[i]) == nullptr);
    } else {
      REQUIRE(h.find(keys[i]) != nullptr);
      CHECK_EQ(*h.find(keys[i]), static_cast<uint32_t>(i));
    }
  }
}

TEST("flat_hash/differential_against_unordered_map") {
  FlatHashU32<uint64_t> h(4096);
  std::unordered_map<uint32_t, uint64_t> ref;
  std::mt19937 rng(1234);

  for (int op = 0; op < 200000; ++op) {
    const uint32_t key = rng() % 3000;
    const int action = static_cast<int>(rng() % 10);
    if (action < 6) {
      const uint64_t value = rng();
      if (ref.size() < 2000 || ref.count(key)) {
        CHECK(h.insert(key, value));
        ref[key] = value;
      }
    } else if (action < 8) {
      CHECK_EQ(h.erase(key), ref.erase(key) != 0);
    } else {
      const uint64_t* got = h.find(key);
      const auto it = ref.find(key);
      if (it == ref.end()) {
        CHECK(got == nullptr);
      } else {
        REQUIRE(got != nullptr);
        CHECK_EQ(*got, it->second);
      }
    }
  }
  CHECK_EQ(h.size(), ref.size());

  for (const auto& [k, v] : ref) {
    const uint64_t* got = h.find(k);
    REQUIRE(got != nullptr);
    CHECK_EQ(*got, v);
  }
}

TEST("flat_hash/probe_length_stays_short_at_load_0_7") {
  FlatHashU32<uint32_t> h(1 << 16);
  const size_t target = static_cast<size_t>(0.7 * static_cast<double>(h.capacity()));
  for (uint32_t i = 0; i < target; ++i) CHECK(h.insert(0x10000000u + i * 7u, i));
  CHECK(h.load_factor() > 0.69);
  CHECK(h.load_factor() < 0.71);

  h.reset_stats();
  for (uint32_t i = 0; i < target; ++i) CHECK(h.find(0x10000000u + i * 7u) != nullptr);
  const double probes_per_lookup =
      static_cast<double>(h.probe_count()) / static_cast<double>(h.lookup_count());
  // Theory for linear probing at alpha=0.7 is ~1.7 probes for a successful
  // lookup; anything past 4 means the hash is not spreading.
  CHECK_LT(probes_per_lookup, 4.0);
}

TEST("flat_hash/insert_fails_when_full_instead_of_spinning") {
  FlatHashU32<uint32_t> h(8);
  for (uint32_t i = 0; i < 8; ++i) CHECK(h.insert(i + 1, i));
  CHECK(!h.insert(1000, 0));
  CHECK_EQ(h.size(), size_t{8});
}

TEST("flat_hash/for_each_visits_every_entry") {
  FlatHashU32<uint32_t> h(256);
  for (uint32_t i = 0; i < 50; ++i) CHECK(h.insert(i * 13 + 1, i));
  CHECK(h.insert(FlatHashU32<uint32_t>::kEmptyKey, 999));

  uint64_t sum = 0;
  size_t seen = 0;
  h.for_each([&](uint32_t, uint32_t v) {
    sum += v;
    ++seen;
  });
  CHECK_EQ(seen, size_t{51});
  CHECK_EQ(sum, 49ULL * 50 / 2 + 999);
}

TEST("flat_hash/clear_resets") {
  FlatHashU32<uint32_t> h(64);
  for (uint32_t i = 0; i < 20; ++i) CHECK(h.insert(i + 1, i));
  h.clear();
  CHECK(h.empty());
  CHECK(h.find(1) == nullptr);
  CHECK(h.insert(1, 5));
  CHECK_EQ(*h.find(1), 5u);
}

GTPM_TEST_MAIN()
