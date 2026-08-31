// SPDX-License-Identifier: MIT
//
// Metering engine tests: TEID binding and direction, per-bucket accounting,
// flow table behaviour under eviction pressure, usage-record deltas, Gy
// cross-check, and an end-to-end run from raw frames through the ingest path
// into subscriber counters.
#include "gtpm/meter.hpp"

#include <string>
#include <vector>

#include "gtpm/pipeline.hpp"
#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) {
  return Bytes(b.data(), b.size());
}

MeterConfig small_config() {
  MeterConfig cfg;
  cfg.max_subscribers = 1024;
  cfg.teid_table_capacity = 4096;
  cfg.flow_table_capacity = 1024;
  cfg.report_interval_ns = 1'000'000'000ULL;
  cfg.volume_threshold_bytes = 1u << 20;
  cfg.sweep_period_ns = 0;  // sweep on every poll() in tests
  cfg.sweep_fraction = 1;   // whole table per sweep
  return cfg;
}

SessionSpec session(uint64_t imsi, uint32_t ul, uint32_t dl, uint32_t rg = 10) {
  SessionSpec s;
  s.imsi = imsi;
  s.ul_teid = ul;
  s.dl_teid = dl;
  s.rating_group = rg;
  return s;
}

MeterEvent packet(uint32_t teid, uint32_t bytes, uint64_t ts = 1000, uint64_t flow = 42) {
  MeterEvent ev;
  ev.teid = teid;
  ev.bytes = bytes;
  ev.ts_ns = ts;
  ev.flow_key = flow;
  ev.flags = kFlagInnerParsed;
  return ev;
}

}  // namespace

TEST("meter/install_session_binds_both_teids") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(310150000000001ULL, 100, 200), 0);
  REQUIRE(idx != SIZE_MAX);
  CHECK_EQ(m.find_by_imsi(310150000000001ULL), idx);
  CHECK_EQ(m.teid_map().size(), size_t{2});
  CHECK_EQ(m.stats().subscribers_installed, 1ULL);
}

TEST("meter/session_modification_unbinds_the_old_tunnel") {
  // A PFCP Session Modification moves a tunnel. The old TEID must stop
  // metering to this subscriber, or it keeps billing them with a stale
  // direction long after the network stopped using it.
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200), 0);
  REQUIRE(idx != SIZE_MAX);
  m.apply(packet(100, 500));
  CHECK_EQ(m.counters(idx).ul_bytes, 500ULL);

  const size_t again = m.install_session(session(1, 300, 200), 0);  // uplink moved
  CHECK_EQ(again, idx);
  CHECK_EQ(m.teid_map().size(), size_t{2});

  m.apply(packet(100, 700));  // old uplink TEID
  CHECK_EQ(m.stats().unknown_teid_events, 1ULL);
  CHECK_EQ(m.counters(idx).ul_bytes, 500ULL);  // counters survive the modification

  m.apply(packet(300, 900));  // new uplink TEID
  CHECK_EQ(m.counters(idx).ul_bytes, 1400ULL);
}

TEST("meter/full_teid_table_fails_loudly") {
  MeterConfig cfg = small_config();
  cfg.teid_table_capacity = 8;  // holds 8 TEIDs, i.e. 4 sessions
  MeterEngine m(cfg);

  size_t installed = 0;
  for (uint32_t i = 1; i <= 8; ++i) {
    if (m.install_session(session(i, i * 100, i * 100 + 1), 0) != SIZE_MAX) ++installed;
  }
  CHECK_EQ(installed, size_t{4});
  CHECK_GT(m.stats().teid_bind_failures, 0ULL);
}

TEST("meter/direction_comes_from_the_teid_not_the_packet") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200), 0);

  MeterEvent ul = packet(100, 500);
  ul.dir = static_cast<uint8_t>(Direction::kDownlink);  // deliberately wrong
  m.apply(ul);

  MeterEvent dl = packet(200, 1500);
  dl.dir = static_cast<uint8_t>(Direction::kUplink);  // also wrong
  m.apply(dl);

  const SubscriberCounters& c = m.counters(idx);
  CHECK_EQ(c.ul_bytes, 500ULL);
  CHECK_EQ(c.dl_bytes, 1500ULL);
  CHECK_EQ(c.ul_packets, 1ULL);
  CHECK_EQ(c.dl_packets, 1ULL);
}

TEST("meter/unknown_teid_is_counted_not_metered") {
  MeterEngine m(small_config());
  (void)m.install_session(session(1, 100, 200), 0);
  m.apply(packet(999, 1000));
  CHECK_EQ(m.stats().unknown_teid_events, 1ULL);
  CHECK_EQ(m.stats().unknown_teid_bytes, 1000ULL);
  CHECK_EQ(m.stats().ul_bytes, 0ULL);
  CHECK_EQ(m.subscriber_count(), size_t{1});
}

TEST("meter/learning_mode_creates_subscribers_for_unknown_teids") {
  MeterConfig cfg = small_config();
  cfg.learn_unknown_teids = true;
  MeterEngine m(cfg);
  m.apply(packet(4242, 700));
  CHECK_EQ(m.stats().unknown_teid_events, 0ULL);
  CHECK_EQ(m.stats().subscribers_learned, 1ULL);
  CHECK_EQ(m.subscriber_count(), size_t{1});
  CHECK_EQ(m.counters(0).total_bytes(), 700ULL);
  CHECK(m.info(0).learned);
}

TEST("meter/control_pdus_carry_no_charged_bytes") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200), 0);
  MeterEvent ev = packet(100, 0);
  ev.flags |= kFlagControlPdu;
  ev.msg_type = static_cast<uint8_t>(GtpuMsgType::kEndMarker);
  m.apply(ev);
  CHECK_EQ(m.stats().control_pdus, 1ULL);
  CHECK_EQ(m.counters(idx).total_bytes(), 0ULL);
}

TEST("meter/rating_group_bucket_from_session") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200, 77), 0);
  m.apply(packet(100, 1000));
  CHECK_EQ(m.counters(idx).bucket_bytes[0], 1000ULL);
  CHECK_EQ(m.info(idx).bucket_ids[0], 77u);
}

TEST("meter/qfi_gets_its_own_bucket") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200, 5), 0);

  m.apply(packet(100, 100));  // no QFI: session rating group, slot 0
  MeterEvent q = packet(100, 200);
  q.flags |= kFlagHasQfi;
  q.qfi = 9;
  m.apply(q);

  const SubscriberCounters& c = m.counters(idx);
  CHECK_EQ(c.bucket_bytes[0], 100ULL);
  CHECK_EQ(c.bucket_bytes[1], 200ULL);
  CHECK_EQ(m.info(idx).bucket_ids[0], 5u);
  CHECK_EQ(m.info(idx).bucket_ids[1], kQfiBucketTag | 9u);
}

TEST("meter/bucket_overflow_aggregates_and_is_flagged") {
  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(1, 100, 200, 1), 0);
  for (uint8_t qfi = 1; qfi <= 4; ++qfi) {
    MeterEvent q = packet(100, 10);
    q.flags |= kFlagHasQfi;
    q.qfi = qfi;
    m.apply(q);
  }
  // Slot 0 = rating group 1, slot 1 = QFI 1, slot 2 = QFI 2,3,4 aggregated.
  const SubscriberCounters& c = m.counters(idx);
  CHECK_EQ(c.bucket_bytes[1], 10ULL);
  CHECK_EQ(c.bucket_bytes[kAggregateSlot], 30ULL);
  CHECK(m.info(idx).bucket_aggregated);
}

TEST("meter/flow_table_tracks_five_tuples") {
  MeterEngine m(small_config());
  (void)m.install_session(session(1, 100, 200), 0);
  for (int i = 0; i < 5; ++i) m.apply(packet(100, 100, 1000 + static_cast<uint64_t>(i), 0xABCD));
  m.apply(packet(100, 100, 2000, 0x1234));

  const FlowEntry* f = m.find_flow(0xABCD);
  REQUIRE(f != nullptr);
  CHECK_EQ(f->packets, 5ULL);
  CHECK_EQ(f->bytes, 500ULL);
  CHECK_EQ(m.stats().flow_inserts, 2ULL);
  CHECK_EQ(m.stats().flows_active, 2ULL);
}

TEST("meter/flow_eviction_never_corrupts_subscriber_totals") {
  MeterConfig cfg = small_config();
  cfg.flow_table_capacity = 64;  // deliberately tiny: force evictions
  cfg.flow_probe_window = 4;
  MeterEngine m(cfg);
  const size_t idx = m.install_session(session(1, 100, 200), 0);

  uint64_t expected = 0;
  for (uint64_t i = 0; i < 5000; ++i) {
    m.apply(packet(100, 100, 1000 + i, i * 0x9E3779B97F4A7C15ULL));
    expected += 100;
  }
  CHECK_GT(m.stats().flow_evictions, 0ULL);
  CHECK_EQ(m.counters(idx).ul_bytes, expected);  // eviction loses flows, not bytes
}

TEST("meter/top_flows_ranks_by_bytes") {
  MeterEngine m(small_config());
  (void)m.install_session(session(1, 100, 200), 0);
  for (uint64_t f = 1; f <= 10; ++f) {
    for (uint64_t i = 0; i < f; ++i) m.apply(packet(100, 100, 1000 + i, f * 1000));
  }
  const auto top = m.top_flows(3);
  REQUIRE_EQ(top.size(), size_t{3});
  CHECK_EQ(top[0].bytes, 1000ULL);
  CHECK_EQ(top[1].bytes, 900ULL);
  CHECK_EQ(top[2].bytes, 800ULL);
}

TEST("meter/usage_records_are_deltas_with_a_gapless_sequence") {
  SpscRing<UsageRecord> sink(64);
  MeterConfig cfg = small_config();
  cfg.report_interval_ns = 1000;
  cfg.volume_threshold_bytes = 0;  // interval-driven only
  MeterEngine m(cfg);
  m.set_record_sink(&sink);
  const size_t idx = m.install_session(session(310150000000007ULL, 100, 200), 0);

  m.apply(packet(100, 1000, 500));
  m.poll(2000);
  m.apply(packet(200, 2500, 3000));
  m.poll(4000);

  UsageRecord r1{}, r2{};
  REQUIRE(sink.try_pop(r1));
  REQUIRE(sink.try_pop(r2));
  CHECK_EQ(r1.imsi, 310150000000007ULL);
  CHECK_EQ(r1.ul_bytes, 1000ULL);
  CHECK_EQ(r1.dl_bytes, 0ULL);
  CHECK_EQ(r1.record_seq, 0u);
  CHECK_EQ(r1.reason, static_cast<uint8_t>(RecordReason::kInterval));
  CHECK_EQ(r2.ul_bytes, 0ULL);  // delta, not cumulative
  CHECK_EQ(r2.dl_bytes, 2500ULL);
  CHECK_EQ(r2.record_seq, 1u);
  CHECK_EQ(m.counters(idx).total_bytes(), 3500ULL);
  CHECK_EQ(m.stats().records_emitted, 2ULL);
}

TEST("meter/volume_threshold_emits_before_the_timer") {
  SpscRing<UsageRecord> sink(64);
  MeterConfig cfg = small_config();
  cfg.report_interval_ns = 1'000'000'000'000ULL;  // effectively never
  cfg.volume_threshold_bytes = 10000;
  MeterEngine m(cfg);
  m.set_record_sink(&sink);
  (void)m.install_session(session(1, 100, 200), 0);

  for (int i = 0; i < 20; ++i) m.apply(packet(100, 1000, 1000));
  m.poll(2000);

  UsageRecord r{};
  REQUIRE(sink.try_pop(r));
  CHECK_EQ(r.reason, static_cast<uint8_t>(RecordReason::kVolume));
  CHECK_EQ(r.ul_bytes, 20000ULL);
}

TEST("meter/record_sink_full_counts_drops_instead_of_blocking") {
  SpscRing<UsageRecord> sink(2);
  MeterConfig cfg = small_config();
  cfg.report_interval_ns = 1;
  MeterEngine m(cfg);
  m.set_record_sink(&sink);
  for (uint32_t i = 1; i <= 8; ++i) {
    (void)m.install_session(session(i, 100 + i * 2, 101 + i * 2), 0);
  }
  for (uint32_t i = 1; i <= 8; ++i) m.apply(packet(100 + i * 2, 500, 10));
  m.poll(1'000'000);

  CHECK_EQ(m.stats().records_emitted, 2ULL);
  CHECK_GT(m.stats().records_dropped, 0ULL);
}

TEST("meter/release_emits_a_final_record_and_unbinds") {
  SpscRing<UsageRecord> sink(64);
  MeterEngine m(small_config());
  m.set_record_sink(&sink);
  (void)m.install_session(session(42, 100, 200), 0);
  m.apply(packet(100, 700, 1000));

  CHECK(m.release_session(42, 5000));
  UsageRecord r{};
  REQUIRE(sink.try_pop(r));
  CHECK_EQ(r.reason, static_cast<uint8_t>(RecordReason::kRelease));
  CHECK_EQ(r.ul_bytes, 700ULL);

  m.apply(packet(100, 700, 6000));  // tunnel is gone now
  CHECK_EQ(m.stats().unknown_teid_events, 1ULL);
  CHECK(!m.release_session(42, 6000));
}

TEST("meter/drain_flushes_unreported_usage") {
  SpscRing<UsageRecord> sink(64);
  MeterEngine m(small_config());
  m.set_record_sink(&sink);
  (void)m.install_session(session(1, 100, 200), 0);
  (void)m.install_session(session(2, 300, 400), 0);
  m.apply(packet(100, 111, 10));
  m.apply(packet(300, 222, 20));

  CHECK_EQ(m.drain(1000), size_t{2});
  CHECK_EQ(m.drain(2000), size_t{0});  // nothing left unreported
}

TEST("meter/gy_crosscheck_reports_the_difference") {
  MeterEngine m(small_config());
  (void)m.install_session(session(310150000000123ULL, 100, 200), 0);
  m.apply(packet(100, 4000, 10));
  m.apply(packet(200, 6000, 20));

  GyEvent gy;
  gy.imsi = 310150000000123ULL;
  gy.has_imsi = true;
  gy.has_used = true;
  gy.used_total_octets = 9500;
  gy.rating_group = 10;
  m.apply_gy(gy);

  const auto deltas = m.gy_crosscheck();
  REQUIRE_EQ(deltas.size(), size_t{1});
  CHECK_EQ(deltas[0].metered_octets, 10000ULL);
  CHECK_EQ(deltas[0].reported_octets, 9500ULL);
  CHECK_EQ(deltas[0].difference, 500LL);
  CHECK_EQ(deltas[0].reports, 1u);
  CHECK_EQ(m.stats().gy_events, 1ULL);
}

TEST("meter/gy_for_unknown_imsi_is_ignored_safely") {
  MeterEngine m(small_config());
  GyEvent gy;
  gy.imsi = 999;
  gy.has_imsi = true;
  gy.has_used = true;
  gy.used_total_octets = 100;
  m.apply_gy(gy);
  CHECK_EQ(m.stats().gy_events, 1ULL);
  CHECK(m.gy_crosscheck().empty());
}

TEST("meter/end_to_end_frames_to_counters") {
  // The real path: synthetic frames -> Ingest -> ring -> MeterEngine.
  SpscRing<MeterEvent> ring(1024);
  SpscRing<GyEvent> gy_ring(64);
  Ingest ingest(&ring, &gy_ring);

  MeterEngine m(small_config());
  const size_t idx = m.install_session(session(310150000000042ULL, 0x1111, 0x2222, 8), 0);

  uint64_t expected_ul = 0;
  uint64_t expected_dl = 0;
  for (int i = 0; i < 50; ++i) {
    const Buf payload = synth::filler(100 + static_cast<size_t>(i));
    synth::UdpSpec inner;
    inner.src_ip = synth::ipv4(10, 45, 0, 1);
    inner.dst_ip = synth::ipv4(93, 184, 216, 34);
    const Buf ip = synth::build_ipv4_udp(inner, view(payload));

    synth::GtpuSpec gs;
    const bool uplink = (i % 2) == 0;
    gs.teid = uplink ? 0x1111 : 0x2222;
    const Buf frame = synth::build_gtpu_frame(gs, view(ip));
    CHECK_EQ(ingest.process_frame(view(frame), 1000 + static_cast<uint64_t>(i)),
             FrameOutcome::kMetered);
    (uplink ? expected_ul : expected_dl) += ip.size();
  }

  MeterEvent ev;
  size_t applied = 0;
  while (ring.try_pop(ev)) {
    m.apply(ev);
    ++applied;
  }
  CHECK_EQ(applied, size_t{50});
  CHECK_EQ(m.counters(idx).ul_bytes, expected_ul);
  CHECK_EQ(m.counters(idx).dl_bytes, expected_dl);
  CHECK_EQ(m.counters(idx).ul_packets, 25ULL);
  CHECK_EQ(m.counters(idx).dl_packets, 25ULL);
  CHECK_EQ(m.stats().unknown_teid_events, 0ULL);
  CHECK_EQ(ingest.stats().events_dropped, 0ULL);
}

GTPM_TEST_MAIN()
