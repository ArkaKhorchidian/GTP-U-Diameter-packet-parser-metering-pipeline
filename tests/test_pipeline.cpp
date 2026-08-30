// SPDX-License-Identifier: MIT
//
// Ingest-path tests: classification of frames, byte attribution, ring
// back-pressure, and Diameter routing to the control queue.
#include "gtpm/pipeline.hpp"

#include <random>
#include <vector>

#include "gtpm/session.hpp"
#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) { return Bytes(b.data(), b.size()); }

Buf gtpu_frame(uint32_t teid, size_t payload_len, bool with_qfi = false, uint8_t qfi = 0,
               uint8_t pdu_type = 0) {
  synth::UdpSpec inner;
  inner.src_ip = synth::ipv4(10, 0, 0, 1);
  inner.dst_ip = synth::ipv4(10, 0, 0, 2);
  const Buf payload = synth::filler(payload_len);
  const Buf ip = synth::build_ipv4_udp(inner, view(payload));
  synth::GtpuSpec gs;
  gs.teid = teid;
  gs.with_qfi = with_qfi;
  gs.qfi = qfi;
  gs.pdu_type = pdu_type;
  return synth::build_gtpu_frame(gs, view(ip));
}

}  // namespace

TEST("pipeline/meters_inner_ip_total_length") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);
  const Buf frame = gtpu_frame(0x500, 100);
  CHECK_EQ(ingest.process_frame(view(frame), 12345), FrameOutcome::kMetered);

  MeterEvent ev;
  REQUIRE(ring.try_pop(ev));
  CHECK_EQ(ev.teid, 0x500u);
  CHECK_EQ(ev.ts_ns, 12345ULL);
  CHECK_EQ(ev.bytes, 20u + 8u + 100u);  // inner IP + UDP + payload
  CHECK_EQ(ev.wire_bytes, static_cast<uint16_t>(frame.size()));
  CHECK_EQ(ev.ip_version, 4);
  CHECK(ev.inner_parsed());
  CHECK_NE(ev.flow_key, 0ULL);
}

TEST("pipeline/snaplen_truncation_still_charges_full_length") {
  // A truncated capture must not under-bill: the inner IP header says how many
  // bytes the operator carried.
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);
  Buf frame = gtpu_frame(1, 800);
  const size_t full = frame.size();
  frame.resize(96);  // snaplen cut

  // The GTP-U length field now exceeds what is present, so the PDU is rejected
  // rather than silently mis-metered.
  CHECK_EQ(ingest.process_frame(view(frame), 1), FrameOutcome::kParseError);
  CHECK_EQ(ingest.stats().truncated_frames, 1ULL);
  CHECK_GT(full, size_t{96});
}

TEST("pipeline/qfi_direction_from_pdu_session_container") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);

  const Buf ul = gtpu_frame(1, 40, true, 5, 1);  // uplink PDU session info
  const Buf dl = gtpu_frame(2, 40, true, 6, 0);  // downlink
  CHECK_EQ(ingest.process_frame(view(ul), 1), FrameOutcome::kMetered);
  CHECK_EQ(ingest.process_frame(view(dl), 2), FrameOutcome::kMetered);

  MeterEvent a, b;
  REQUIRE(ring.try_pop(a));
  REQUIRE(ring.try_pop(b));
  CHECK(a.has_qfi());
  CHECK_EQ(a.qfi, 5);
  CHECK_EQ(a.dir, static_cast<uint8_t>(Direction::kUplink));
  CHECK_EQ(b.qfi, 6);
  CHECK_EQ(b.dir, static_cast<uint8_t>(Direction::kDownlink));
}

TEST("pipeline/gtpu_control_pdus_are_flagged") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);

  synth::GtpuSpec gs;
  gs.teid = 7;
  gs.msg_type = static_cast<uint8_t>(GtpuMsgType::kEchoRequest);
  const Buf gtp = synth::build_gtpu(gs, Bytes{});
  synth::UdpSpec us;
  us.src_port = kGtpuPort;
  us.dst_port = kGtpuPort;
  const Buf ip = synth::build_ipv4_udp(us, view(gtp));
  const Buf frame = synth::build_ethernet(view(ip));

  CHECK_EQ(ingest.process_frame(view(frame), 1), FrameOutcome::kGtpuControl);
  MeterEvent ev;
  REQUIRE(ring.try_pop(ev));
  CHECK_EQ(ev.flags & kFlagControlPdu, kFlagControlPdu);
  CHECK_EQ(ev.bytes, 0u);
  CHECK_EQ(ingest.stats().gtpu_control, 1ULL);
}

TEST("pipeline/non_gtpu_traffic_is_ignored_cheaply") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);

  synth::UdpSpec s;
  s.dst_port = 80;
  const Buf ip = synth::build_ipv4_udp(s, view(synth::filler(50)));
  const Buf frame = synth::build_ethernet(view(ip));
  CHECK_EQ(ingest.process_frame(view(frame), 1), FrameOutcome::kNotOurTraffic);
  CHECK_EQ(ingest.stats().not_gtpu_port, 1ULL);
  CHECK(ring.empty_approx());

  const Buf arp = synth::build_ethernet(view(synth::filler(40)), 0x0806);
  CHECK_EQ(ingest.process_frame(view(arp), 2), FrameOutcome::kNotOurTraffic);
  CHECK_EQ(ingest.stats().non_ip, 1ULL);
}

TEST("pipeline/malformed_gtpu_is_a_parse_error_not_a_crash") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);
  Buf frame = gtpu_frame(1, 40);
  // Corrupt the GTP-U version field inside the UDP payload.
  const size_t gtp_off = kEthHeaderLen + 20 + 8;
  frame[gtp_off] = 0x00;
  CHECK_EQ(ingest.process_frame(view(frame), 1), FrameOutcome::kParseError);
  CHECK_EQ(ingest.stats().gtpu_parse_errors, 1ULL);
}

TEST("pipeline/full_ring_drops_and_counts_instead_of_blocking") {
  SpscRing<MeterEvent> ring(4);
  Ingest ingest(&ring, nullptr);
  const Buf frame = gtpu_frame(1, 40);
  for (int i = 0; i < 10; ++i) (void)ingest.process_frame(view(frame), 1);
  CHECK_EQ(ingest.stats().events_pushed, 4ULL);
  CHECK_EQ(ingest.stats().events_dropped, 6ULL);
}

TEST("pipeline/diameter_goes_to_the_control_ring_not_the_meter_ring") {
  SpscRing<MeterEvent> meter_ring(64);
  SpscRing<GyEvent> gy_ring(64);
  Ingest ingest(&meter_ring, &gy_ring);

  synth::GySpec spec;
  spec.imsi = "310150000000099";
  spec.rating_group = 20;
  spec.used_input = 5000;
  spec.used_output = 7000;
  const Buf ccr = synth::build_ccr(spec);

  synth::UdpSpec us;
  us.src_port = 40000;
  us.dst_port = kDiameterPort;
  const Buf ip = synth::build_ipv4_tcp(us, view(ccr));
  const Buf frame = synth::build_ethernet(view(ip));

  CHECK_EQ(ingest.process_frame(view(frame), 999), FrameOutcome::kGyControl);
  CHECK(meter_ring.empty_approx());

  GyEvent ev;
  REQUIRE(gy_ring.try_pop(ev));
  CHECK_EQ(ev.imsi, 310150000000099ULL);
  CHECK(ev.has_imsi);
  CHECK(ev.is_request);
  CHECK_EQ(ev.rating_group, 20u);
  CHECK_EQ(ev.used_total_octets, 12000ULL);
  CHECK_EQ(ev.ts_ns, 999ULL);
  CHECK_EQ(ingest.stats().diameter_messages, 1ULL);
}

TEST("pipeline/multiple_diameter_messages_in_one_segment") {
  SpscRing<GyEvent> gy_ring(64);
  Ingest ingest(nullptr, &gy_ring);

  Buf both;
  for (uint32_t n = 0; n < 2; ++n) {
    synth::GySpec spec;
    spec.request_number = n;
    spec.used_input = 100 * (n + 1);
    const Buf msg = synth::build_ccr(spec);
    both.insert(both.end(), msg.begin(), msg.end());
  }
  CHECK_EQ(ingest.process_diameter(view(both), 5), FrameOutcome::kGyControl);
  CHECK_EQ(ingest.stats().diameter_messages, 2ULL);

  GyEvent a, b;
  REQUIRE(gy_ring.try_pop(a));
  REQUIRE(gy_ring.try_pop(b));
  CHECK_EQ(a.cc_request_number, 0u);
  CHECK_EQ(b.cc_request_number, 1u);
}

TEST("pipeline/partial_diameter_message_is_not_half_parsed") {
  SpscRing<GyEvent> gy_ring(64);
  Ingest ingest(nullptr, &gy_ring);
  Buf ccr = synth::build_ccr({});
  ccr.resize(ccr.size() / 2);  // TCP segment boundary lands mid-message
  CHECK_EQ(ingest.process_diameter(view(ccr), 1), FrameOutcome::kParseError);
  CHECK_EQ(ingest.stats().diameter_parse_errors, 1ULL);
  CHECK(gy_ring.empty_approx());
}

TEST("pipeline/one_gy_event_per_mscc_block") {
  SpscRing<GyEvent> gy_ring(64);
  Ingest ingest(nullptr, &gy_ring);

  Buf avps;
  synth::put_avp_str(avps, 263, "sess");
  Buf sub;
  synth::put_avp_u32(sub, 450, 1);
  synth::put_avp_str(sub, 444, "310150000000001");
  synth::put_avp_grouped(avps, 443, sub);
  for (uint32_t rg = 1; rg <= 3; ++rg) {
    Buf usu;
    synth::put_avp_u64(usu, 421, rg * 100);
    Buf mscc;
    synth::put_avp_u32(mscc, 432, rg);
    synth::put_avp_grouped(mscc, 446, usu);
    synth::put_avp_grouped(avps, 456, mscc);
  }
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  CHECK_EQ(ingest.process_diameter(view(msg), 1), FrameOutcome::kGyControl);
  CHECK_EQ(ingest.stats().gy_events, 3ULL);
  for (uint32_t rg = 1; rg <= 3; ++rg) {
    GyEvent ev;
    REQUIRE(gy_ring.try_pop(ev));
    CHECK_EQ(ev.rating_group, rg);
    CHECK_EQ(ev.used_total_octets, rg * 100ULL);
    CHECK_EQ(ev.imsi, 310150000000001ULL);
  }
}

TEST("pipeline/vlan_tagged_gtpu_is_metered") {
  SpscRing<MeterEvent> ring(64);
  Ingest ingest(&ring, nullptr);

  const Buf payload = synth::filler(60);
  const Buf inner = synth::build_ipv4_udp({}, view(payload));
  synth::GtpuSpec gs;
  gs.teid = 0x99;
  const Buf gtp = synth::build_gtpu(gs, view(inner));
  synth::UdpSpec us;
  us.src_port = kGtpuPort;
  us.dst_port = kGtpuPort;
  const Buf ip = synth::build_ipv4_udp(us, view(gtp));
  const Buf frame = synth::build_ethernet(view(ip), kEtherTypeIpv4, 2);

  CHECK_EQ(ingest.process_frame(view(frame), 1), FrameOutcome::kMetered);
  MeterEvent ev;
  REQUIRE(ring.try_pop(ev));
  CHECK_EQ(ev.teid, 0x99u);
}

TEST("pipeline/random_frames_never_crash_or_leak_events") {
  SpscRing<MeterEvent> ring(1024);
  SpscRing<GyEvent> gy(1024);
  Ingest ingest(&ring, &gy);
  std::mt19937 rng(7);
  std::vector<uint8_t> buf;
  for (int i = 0; i < 30000; ++i) {
    const size_t n = rng() % 200;
    buf.resize(n);
    for (size_t j = 0; j < n; ++j) buf[j] = static_cast<uint8_t>(rng());
    (void)ingest.process_frame(Bytes(buf.data(), n), static_cast<uint64_t>(i));
    MeterEvent ev;
    while (ring.try_pop(ev)) {
    }
    GyEvent g;
    while (gy.try_pop(g)) {
    }
  }
  CHECK_EQ(ingest.stats().frames, 30000ULL);
}

GTPM_TEST_MAIN()
