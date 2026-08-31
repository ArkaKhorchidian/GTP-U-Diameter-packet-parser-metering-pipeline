// SPDX-License-Identifier: MIT
//
// GTP-U parser tests: field extraction, extension-header chains, malformed and
// truncated input, and a brute-force sweep that asserts the parser never reads
// out of bounds for arbitrary byte strings.
#include "gtpm/gtpu.hpp"

#include <random>
#include <vector>

#include "gtpm/net.hpp"
#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) {
  return Bytes(b.data(), b.size());
}

}  // namespace

TEST("gtpu/minimal_gpdu") {
  const Buf inner = synth::build_ipv4_udp({}, view(synth::filler(64)));
  synth::GtpuSpec spec;
  spec.teid = 0xDEADBEEF;
  const Buf pdu = synth::build_gtpu(spec, view(inner));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK_EQ(h.teid, 0xDEADBEEFu);
  CHECK_EQ(h.msg_type, 255);
  CHECK(h.is_gpdu());
  CHECK_EQ(h.header_len, 8);
  CHECK_EQ(h.payload.size(), inner.size());
  CHECK(!h.has_qfi);
  CHECK(!h.has_seq);
  CHECK_EQ(h.declared_len, static_cast<uint16_t>(inner.size()));
}

TEST("gtpu/sequence_number_present") {
  const Buf inner = synth::filler(32);
  synth::GtpuSpec spec;
  spec.with_seq = true;
  spec.seq = 0xABCD;
  const Buf pdu = synth::build_gtpu(spec, view(inner));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK(h.has_seq);
  CHECK_EQ(h.seq, 0xABCD);
  CHECK_EQ(h.header_len, 12);
  CHECK_EQ(h.payload.size(), inner.size());
}

TEST("gtpu/pdu_session_container_qfi") {
  const Buf inner = synth::build_ipv4_udp({}, view(synth::filler(100)));
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  spec.qfi = 9;
  spec.pdu_type = 0;  // downlink
  spec.rqi = true;
  const Buf pdu = synth::build_gtpu(spec, view(inner));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK(h.has_ext);
  CHECK(h.has_qfi);
  CHECK_EQ(h.qfi, 9);
  CHECK_EQ(h.pdu_type, 0);
  CHECK(h.rqi);
  CHECK_EQ(h.ext_count, 1);
  CHECK_EQ(h.payload.size(), inner.size());
}

TEST("gtpu/uplink_container_has_no_rqi") {
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  spec.qfi = 5;
  spec.pdu_type = 1;  // uplink
  spec.rqi = true;    // builder still sets the bit; UL info has no RQI field
  const Buf pdu = synth::build_gtpu(spec, view(synth::filler(16)));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK_EQ(h.qfi, 5);
  CHECK_EQ(h.pdu_type, 1);
  CHECK(!h.rqi);
}

TEST("gtpu/qfi_masks_to_six_bits") {
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  spec.qfi = 0x3F;
  spec.pdu_type = 1;
  const Buf pdu = synth::build_gtpu(spec, view(synth::filler(8)));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK_EQ(h.qfi, 0x3F);
}

TEST("gtpu/multiple_extension_headers") {
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  spec.qfi = 7;
  // A UDP Port ext header (0x40, 2-byte content) ahead of the container.
  spec.extra_ext.push_back({0x40, Buf{0x1F, 0x90}});
  const Buf inner = synth::filler(48);
  const Buf pdu = synth::build_gtpu(spec, view(inner));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK_EQ(h.ext_count, 2);
  CHECK_EQ(h.qfi, 7);
  CHECK_EQ(h.payload.size(), inner.size());
}

TEST("gtpu/ext_chain_depth_cap") {
  synth::GtpuSpec spec;
  for (int i = 0; i < kGtpuMaxExtHeaders + 2; ++i) {
    spec.extra_ext.push_back({0x40, Buf{0x00, 0x00}});
  }
  const Buf pdu = synth::build_gtpu(spec, view(synth::filler(4)));
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kExtChainTooLong);
}

TEST("gtpu/echo_request_is_not_gpdu") {
  synth::GtpuSpec spec;
  spec.msg_type = static_cast<uint8_t>(GtpuMsgType::kEchoRequest);
  const Buf pdu = synth::build_gtpu(spec, Bytes{});
  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK(!h.is_gpdu());
  CHECK_EQ(h.msg_type, 1);
}

TEST("gtpu/end_marker") {
  synth::GtpuSpec spec;
  spec.msg_type = static_cast<uint8_t>(GtpuMsgType::kEndMarker);
  const Buf pdu = synth::build_gtpu(spec, Bytes{});
  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK(h.is_end_marker());
}

TEST("gtpu/rejects_bad_version") {
  Buf pdu = synth::build_gtpu({}, view(synth::filler(8)));
  pdu[0] = static_cast<uint8_t>((pdu[0] & 0x1F) | (2 << 5));  // version 2
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kBadVersion);
}

TEST("gtpu/rejects_gtp_prime") {
  Buf pdu = synth::build_gtpu({}, view(synth::filler(8)));
  pdu[0] = static_cast<uint8_t>(pdu[0] & ~0x10);  // PT = 0
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kNotGtpU);
}

TEST("gtpu/rejects_short_header") {
  const Buf pdu = synth::build_gtpu({}, view(synth::filler(8)));
  for (size_t n = 0; n < kGtpuFixedHeaderLen; ++n) {
    GtpuHeader h;
    CHECK_EQ(parse_gtpu(Bytes(pdu.data(), n), h), GtpuStatus::kTruncated);
  }
}

TEST("gtpu/rejects_truncated_payload") {
  const Buf pdu = synth::build_gtpu({}, view(synth::filler(200)));
  GtpuHeader h;
  // Every prefix shorter than the declared length must be rejected, not read.
  for (size_t n = kGtpuFixedHeaderLen; n < pdu.size(); ++n) {
    CHECK_EQ(parse_gtpu(Bytes(pdu.data(), n), h), GtpuStatus::kTruncated);
  }
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
}

TEST("gtpu/rejects_length_shorter_than_optional_fields") {
  synth::GtpuSpec spec;
  spec.with_seq = true;
  Buf pdu = synth::build_gtpu(spec, view(synth::filler(16)));
  store_be16(pdu.data() + 2, 2);  // declares fewer bytes than the optional block
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(Bytes(pdu.data(), pdu.size()), h), GtpuStatus::kBadLength);
}

TEST("gtpu/rejects_zero_length_ext_header") {
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  spec.qfi = 3;
  Buf pdu = synth::build_gtpu(spec, view(synth::filler(16)));
  pdu[12] = 0;  // first ext header length unit = 0 would loop forever
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kBadExtHeader);
}

TEST("gtpu/rejects_ext_header_overrunning_declared_length") {
  synth::GtpuSpec spec;
  spec.with_qfi = true;
  Buf pdu = synth::build_gtpu(spec, view(synth::filler(16)));
  pdu[12] = 0x40;  // 64 * 4 bytes of extension header that is not there
  GtpuHeader h;
  CHECK_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kTruncated);
}

TEST("gtpu/trailing_ethernet_padding_is_not_payload") {
  const Buf inner = synth::filler(10);
  Buf pdu = synth::build_gtpu({}, view(inner));
  pdu.insert(pdu.end(), 20, 0);  // simulate padding to the 60-byte Ethernet floor
  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  CHECK_EQ(h.payload.size(), inner.size());
}

TEST("gtpu/full_frame_decap_to_inner_five_tuple") {
  synth::UdpSpec inner_spec;
  inner_spec.src_ip = synth::ipv4(10, 45, 0, 7);
  inner_spec.dst_ip = synth::ipv4(8, 8, 8, 8);
  inner_spec.src_port = 43210;
  inner_spec.dst_port = 53;
  const Buf inner = synth::build_ipv4_udp(inner_spec, view(synth::filler(40)));

  synth::GtpuSpec gs;
  gs.teid = 0x00A1B2C3;
  gs.with_qfi = true;
  gs.qfi = 6;
  const Buf frame = synth::build_gtpu_frame(gs, view(inner));

  const EthFrame eth = parse_ethernet(view(frame));
  REQUIRE(eth.valid);
  CHECK_EQ(eth.ethertype, kEtherTypeIpv4);

  const IpPacket outer = parse_ip(eth.payload);
  REQUIRE(outer.valid);
  CHECK_EQ(outer.tuple.dst_port, kGtpuPort);

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(outer.l4_payload, h), GtpuStatus::kOk);
  CHECK_EQ(h.teid, 0x00A1B2C3u);
  CHECK_EQ(h.qfi, 6);

  const IpPacket in = parse_ip(h.payload);
  REQUIRE(in.valid);
  CHECK_EQ(in.tuple.ip_version, 4);
  CHECK_EQ(in.tuple.src_v4(), synth::ipv4(10, 45, 0, 7));
  CHECK_EQ(in.tuple.dst_v4(), synth::ipv4(8, 8, 8, 8));
  CHECK_EQ(in.tuple.src_port, 43210);
  CHECK_EQ(in.tuple.dst_port, 53);
  CHECK_EQ(in.tuple.proto, static_cast<uint8_t>(IpProto::kUdp));
  CHECK(in.tuple.ports_valid);
}

TEST("gtpu/inner_ipv6") {
  synth::Udp6Spec s6;
  s6.src = synth::ipv6_from({0x2001, 0x0db8, 0, 0, 0, 0, 0, 1});
  s6.dst = synth::ipv6_from({0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888});
  s6.src_port = 5555;
  s6.dst_port = 443;
  const Buf inner = synth::build_ipv6_udp(s6, view(synth::filler(64)));

  synth::GtpuSpec gs;
  gs.teid = 0x2222;
  const Buf pdu = synth::build_gtpu(gs, view(inner));

  GtpuHeader h;
  REQUIRE_EQ(parse_gtpu(view(pdu), h), GtpuStatus::kOk);
  const IpPacket in = parse_ip(h.payload);
  REQUIRE(in.valid);
  CHECK_EQ(in.tuple.ip_version, 6);
  CHECK_EQ(in.tuple.src_port, 5555);
  CHECK_EQ(in.tuple.dst_port, 443);
  CHECK(in.tuple.src == s6.src);
}

TEST("gtpu/never_reads_past_the_buffer_on_random_bytes") {
  // Deterministic pseudo-fuzz. Under ASan/UBSan (see CI) any overread here is a
  // hard failure; without sanitizers this still catches hangs and bad status.
  std::mt19937 rng(0xC0FFEE);
  std::vector<uint8_t> buf;
  for (int iter = 0; iter < 20000; ++iter) {
    const size_t n = rng() % 96;
    buf.resize(n);
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rng());
    if (n >= 1) buf[0] = static_cast<uint8_t>(0x30 | (rng() & 0x07));  // steer to valid v1 GTP
    GtpuHeader h;
    const GtpuStatus st = parse_gtpu(Bytes(buf.data(), n), h);
    if (st == GtpuStatus::kOk) {
      // A successful parse must produce a payload fully inside the input.
      CHECK(h.payload.size() <= n);
      CHECK(h.payload.data() >= buf.data());
      CHECK(h.payload.data() + h.payload.size() <= buf.data() + n);
    }
  }
}

GTPM_TEST_MAIN()
