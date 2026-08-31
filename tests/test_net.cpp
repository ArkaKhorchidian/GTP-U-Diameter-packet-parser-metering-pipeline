// SPDX-License-Identifier: MIT
//
// Ethernet / IPv4 / IPv6 / L4 decoding tests, including VLAN stacking,
// fragmentation, IPv6 extension-header chains, and truncation.
#include "gtpm/net.hpp"

#include <random>

#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) {
  return Bytes(b.data(), b.size());
}

}  // namespace

TEST("net/ethernet_plain") {
  const Buf ip = synth::build_ipv4_udp({}, view(synth::filler(20)));
  const Buf frame = synth::build_ethernet(view(ip));
  const EthFrame eth = parse_ethernet(view(frame));
  REQUIRE(eth.valid);
  CHECK_EQ(eth.ethertype, kEtherTypeIpv4);
  CHECK_EQ(eth.vlan_tags, 0);
  CHECK_EQ(eth.payload.size(), ip.size());
}

TEST("net/ethernet_single_and_double_vlan") {
  const Buf ip = synth::build_ipv4_udp({}, view(synth::filler(20)));
  for (int tags = 1; tags <= 2; ++tags) {
    const Buf frame = synth::build_ethernet(view(ip), kEtherTypeIpv4, tags);
    const EthFrame eth = parse_ethernet(view(frame));
    REQUIRE(eth.valid);
    CHECK_EQ(eth.ethertype, kEtherTypeIpv4);
    CHECK_EQ(eth.vlan_tags, tags);
    CHECK_EQ(eth.payload.size(), ip.size());
  }
}

TEST("net/ethernet_too_short") {
  const Buf tiny(10, 0);
  CHECK(!parse_ethernet(view(tiny)).valid);
}

TEST("net/ipv4_udp_five_tuple") {
  synth::UdpSpec s;
  s.src_ip = synth::ipv4(172, 16, 5, 4);
  s.dst_ip = synth::ipv4(1, 1, 1, 1);
  s.src_port = 33333;
  s.dst_port = 853;
  const Buf payload = synth::filler(120);
  const Buf ip = synth::build_ipv4_udp(s, view(payload));

  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK_EQ(p.tuple.ip_version, 4);
  CHECK_EQ(p.tuple.src_v4(), s.src_ip);
  CHECK_EQ(p.tuple.dst_v4(), s.dst_ip);
  CHECK_EQ(p.tuple.src_port, s.src_port);
  CHECK_EQ(p.tuple.dst_port, s.dst_port);
  CHECK_EQ(p.tuple.proto, static_cast<uint8_t>(IpProto::kUdp));
  CHECK_EQ(p.l3_header_len, 20);
  CHECK_EQ(p.l4_header_len, 8);
  CHECK_EQ(p.ip_total_len, 20u + 8u + payload.size());
  CHECK_EQ(p.l4_payload.size(), payload.size());
  CHECK(!p.tuple.fragmented);
}

TEST("net/ipv4_header_checksum_is_valid_in_builder") {
  const Buf ip = synth::build_ipv4_udp({}, view(synth::filler(8)));
  CHECK_EQ(synth::checksum16(ip.data(), 20), 0);  // sum over a valid header is zero
}

TEST("net/ipv4_tcp_options") {
  synth::UdpSpec s;
  s.src_port = 12345;
  s.dst_port = 443;
  Buf ip = synth::build_ipv4_tcp(s, view(synth::filler(60)));
  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK_EQ(p.tuple.proto, static_cast<uint8_t>(IpProto::kTcp));
  CHECK_EQ(p.tuple.src_port, 12345);
  CHECK_EQ(p.tuple.dst_port, 443);
  CHECK_EQ(p.l4_header_len, 20);
}

TEST("net/ipv4_rejects_bad_ihl") {
  Buf ip = synth::build_ipv4_udp({}, view(synth::filler(8)));
  ip[0] = 0x43;  // IHL=3 words = 12 bytes < 20
  CHECK(!parse_ip(view(ip)).valid);
}

TEST("net/ipv4_rejects_total_length_below_header") {
  Buf ip = synth::build_ipv4_udp({}, view(synth::filler(8)));
  store_be16(ip.data() + 2, 10);
  CHECK(!parse_ip(view(ip)).valid);
}

TEST("net/ipv4_non_initial_fragment_has_no_ports") {
  Buf ip = synth::build_ipv4_udp({}, view(synth::filler(64)));
  store_be16(ip.data() + 6, 0x00B9);  // fragment offset 185, MF clear
  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK(p.tuple.fragmented);
  CHECK(!p.tuple.ports_valid);
  CHECK_EQ(p.tuple.src_port, 0);
}

TEST("net/ipv4_first_fragment_keeps_ports") {
  Buf ip = synth::build_ipv4_udp({}, view(synth::filler(64)));
  store_be16(ip.data() + 6, 0x2000);  // MF set, offset 0
  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK(p.tuple.fragmented);
  CHECK(p.tuple.ports_valid);
}

TEST("net/ipv4_snaplen_truncation_is_clamped") {
  const Buf ip = synth::build_ipv4_udp({}, view(synth::filler(500)));
  const IpPacket p = parse_ip(Bytes(ip.data(), 60));  // captured only 60 bytes
  REQUIRE(p.valid);
  CHECK(p.tuple.ports_valid);
  CHECK_EQ(p.l4_payload.size(), size_t{60 - 20 - 8});
  CHECK_EQ(p.ip_total_len, static_cast<uint32_t>(ip.size()));
}

TEST("net/ipv6_udp_five_tuple") {
  synth::Udp6Spec s;
  s.src = synth::ipv6_from({0xfd00, 0, 0, 0, 0, 0, 0, 0x11});
  s.dst = synth::ipv6_from({0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111});
  s.src_port = 40000;
  s.dst_port = 443;
  const Buf ip = synth::build_ipv6_udp(s, view(synth::filler(80)));

  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK_EQ(p.tuple.ip_version, 6);
  CHECK(p.tuple.src == s.src);
  CHECK(p.tuple.dst == s.dst);
  CHECK_EQ(p.tuple.src_port, 40000);
  CHECK_EQ(p.tuple.dst_port, 443);
  CHECK_EQ(p.l3_header_len, 40);
}

TEST("net/ipv6_hop_by_hop_extension_is_skipped") {
  const Buf payload = synth::filler(32);
  // Hand-build: IPv6 -> Hop-by-Hop (8 bytes) -> UDP.
  Buf ip;
  synth::put_be32(ip, 0x60000000);
  synth::put_be16(ip, static_cast<uint16_t>(8 + 8 + payload.size()));
  ip.push_back(static_cast<uint8_t>(IpProto::kHopByHop));
  ip.push_back(64);
  for (int i = 0; i < 32; ++i) ip.push_back(static_cast<uint8_t>(i));  // src+dst
  ip.push_back(static_cast<uint8_t>(IpProto::kUdp));                   // next header
  ip.push_back(0);                                                     // hdr ext len (8 bytes)
  for (int i = 0; i < 6; ++i) ip.push_back(0);                         // options padding
  synth::put_be16(ip, 1234);
  synth::put_be16(ip, 5678);
  synth::put_be16(ip, static_cast<uint16_t>(8 + payload.size()));
  synth::put_be16(ip, 0);
  ip.insert(ip.end(), payload.begin(), payload.end());

  const IpPacket p = parse_ip(view(ip));
  REQUIRE(p.valid);
  CHECK_EQ(p.tuple.proto, static_cast<uint8_t>(IpProto::kUdp));
  CHECK_EQ(p.tuple.src_port, 1234);
  CHECK_EQ(p.tuple.dst_port, 5678);
  CHECK_EQ(p.l3_header_len, 48);
}

TEST("net/flow_key_is_stable_and_direction_sensitive") {
  synth::UdpSpec s;
  const Buf a = synth::build_ipv4_udp(s, view(synth::filler(8)));
  const IpPacket pa = parse_ip(view(a));

  synth::UdpSpec rev;
  rev.src_ip = s.dst_ip;
  rev.dst_ip = s.src_ip;
  rev.src_port = s.dst_port;
  rev.dst_port = s.src_port;
  const Buf b = synth::build_ipv4_udp(rev, view(synth::filler(8)));
  const IpPacket pb = parse_ip(view(b));

  CHECK_EQ(flow_key(pa.tuple), flow_key(pa.tuple));
  CHECK_NE(flow_key(pa.tuple), flow_key(pb.tuple));
}

TEST("net/format_ip") {
  char buf[64];
  IpAddr v4{};
  v4[0] = 10;
  v4[1] = 0;
  v4[2] = 0;
  v4[3] = 255;
  CHECK_EQ(std::string_view(format_ip(v4, 4, buf, sizeof(buf))), std::string_view("10.0.0.255"));
  const IpAddr v6 = synth::ipv6_from({0x2001, 0xdb8, 0, 0, 0, 0, 0, 1});
  CHECK_EQ(std::string_view(format_ip(v6, 6, buf, sizeof(buf))),
           std::string_view("2001:db8:0:0:0:0:0:1"));
}

TEST("net/random_bytes_never_overrun") {
  std::mt19937 rng(0x1234);
  std::vector<uint8_t> buf;
  for (int iter = 0; iter < 20000; ++iter) {
    const size_t n = rng() % 128;
    buf.resize(n);
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rng());
    if (n >= 1) buf[0] = (iter % 2) ? 0x45 : 0x60;
    const IpPacket p = parse_ip(Bytes(buf.data(), n));
    if (p.valid && !p.l4_payload.empty()) {
      CHECK(p.l4_payload.data() >= buf.data());
      CHECK(p.l4_payload.data() + p.l4_payload.size() <= buf.data() + n);
    }
    (void)parse_ethernet(Bytes(buf.data(), n));
  }
}

GTPM_TEST_MAIN()
