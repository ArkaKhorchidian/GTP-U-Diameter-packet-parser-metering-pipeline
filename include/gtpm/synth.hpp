// SPDX-License-Identifier: MIT
//
// Synthetic packet construction: Ethernet/IPv4/IPv6/UDP/TCP frames, GTP-U
// tunnels with extension headers, and Diameter Gy messages.
//
// Shared by the unit tests, the benchmark harness, and the pcap generator so
// that all three agree byte-for-byte on what a well-formed packet looks like.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "gtpm/byte_order.hpp"
#include "gtpm/diameter.hpp"
#include "gtpm/gtpu.hpp"
#include "gtpm/net.hpp"

namespace gtpm::synth {

using Buf = std::vector<uint8_t>;

inline void put_be16(Buf& b, uint16_t v) {
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}
inline void put_be24(Buf& b, uint32_t v) {
  b.push_back(static_cast<uint8_t>(v >> 16));
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}
inline void put_be32(Buf& b, uint32_t v) {
  b.push_back(static_cast<uint8_t>(v >> 24));
  b.push_back(static_cast<uint8_t>(v >> 16));
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}
inline void put_be64(Buf& b, uint64_t v) {
  for (int i = 7; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
inline void put_bytes(Buf& b, Bytes s) {
  b.insert(b.end(), s.begin(), s.end());
}

/// Standard internet checksum (RFC 1071).
[[nodiscard]] inline uint16_t checksum16(const uint8_t* data, size_t len, uint32_t seed = 0) {
  uint32_t sum = seed;
  size_t i = 0;
  for (; i + 1 < len; i += 2) sum += load_be16(data + i);
  if (i < len) sum += static_cast<uint32_t>(data[i]) << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

[[nodiscard]] inline uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
         (static_cast<uint32_t>(c) << 8) | d;
}

// ---------------------------------------------------------------------------
// L3 / L4
// ---------------------------------------------------------------------------

struct UdpSpec {
  uint32_t src_ip = ipv4(10, 0, 0, 1);
  uint32_t dst_ip = ipv4(10, 0, 0, 2);
  uint16_t src_port = 1000;
  uint16_t dst_port = 2000;
  uint8_t ttl = 64;
};

/// IPv4 + UDP carrying `payload`.
[[nodiscard]] inline Buf build_ipv4_udp(const UdpSpec& s, Bytes payload) {
  const uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
  const uint16_t total_len = static_cast<uint16_t>(20 + udp_len);

  Buf ip;
  ip.reserve(total_len);
  ip.push_back(0x45);
  ip.push_back(0x00);
  put_be16(ip, total_len);
  put_be16(ip, 0);       // identification
  put_be16(ip, 0x4000);  // don't fragment
  ip.push_back(s.ttl);
  ip.push_back(static_cast<uint8_t>(IpProto::kUdp));
  put_be16(ip, 0);  // checksum placeholder
  put_be32(ip, s.src_ip);
  put_be32(ip, s.dst_ip);
  const uint16_t ip_csum = checksum16(ip.data(), 20);
  store_be16(ip.data() + 10, ip_csum);

  put_be16(ip, s.src_port);
  put_be16(ip, s.dst_port);
  put_be16(ip, udp_len);
  put_be16(ip, 0);  // UDP checksum: optional over IPv4, left zero
  put_bytes(ip, payload);
  return ip;
}

/// IPv4 + TCP carrying `payload`.
[[nodiscard]] inline Buf build_ipv4_tcp(const UdpSpec& s, Bytes payload, uint32_t seq = 1,
                                        uint8_t tcp_flags = 0x18) {
  const uint16_t tcp_len = static_cast<uint16_t>(20 + payload.size());
  const uint16_t total_len = static_cast<uint16_t>(20 + tcp_len);

  Buf ip;
  ip.reserve(total_len);
  ip.push_back(0x45);
  ip.push_back(0x00);
  put_be16(ip, total_len);
  put_be16(ip, 0);
  put_be16(ip, 0x4000);
  ip.push_back(s.ttl);
  ip.push_back(static_cast<uint8_t>(IpProto::kTcp));
  put_be16(ip, 0);
  put_be32(ip, s.src_ip);
  put_be32(ip, s.dst_ip);
  store_be16(ip.data() + 10, checksum16(ip.data(), 20));

  put_be16(ip, s.src_port);
  put_be16(ip, s.dst_port);
  put_be32(ip, seq);
  put_be32(ip, 0);     // ack
  ip.push_back(0x50);  // data offset 5 words
  ip.push_back(tcp_flags);
  put_be16(ip, 0xFFFF);  // window
  put_be16(ip, 0);       // checksum (not verified by the pipeline)
  put_be16(ip, 0);       // urgent
  put_bytes(ip, payload);
  return ip;
}

struct Udp6Spec {
  IpAddr src{};
  IpAddr dst{};
  uint16_t src_port = 1000;
  uint16_t dst_port = 2000;
  uint8_t hop_limit = 64;
};

[[nodiscard]] inline IpAddr ipv6_from(std::initializer_list<uint16_t> groups) {
  IpAddr a{};
  size_t i = 0;
  for (uint16_t g : groups) {
    if (i + 1 >= a.size()) break;
    store_be16(a.data() + i, g);
    i += 2;
  }
  return a;
}

[[nodiscard]] inline Buf build_ipv6_udp(const Udp6Spec& s, Bytes payload) {
  const uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
  Buf ip;
  ip.reserve(40u + udp_len);
  put_be32(ip, 0x60000000);  // version 6, no traffic class / flow label
  put_be16(ip, udp_len);
  ip.push_back(static_cast<uint8_t>(IpProto::kUdp));
  ip.push_back(s.hop_limit);
  ip.insert(ip.end(), s.src.begin(), s.src.end());
  ip.insert(ip.end(), s.dst.begin(), s.dst.end());
  put_be16(ip, s.src_port);
  put_be16(ip, s.dst_port);
  put_be16(ip, udp_len);
  put_be16(ip, 0);
  put_bytes(ip, payload);
  return ip;
}

/// Wrap an IP packet in an Ethernet header.
[[nodiscard]] inline Buf build_ethernet(Bytes ip_packet, uint16_t ethertype = kEtherTypeIpv4,
                                        int vlan_tags = 0, uint16_t vlan_id = 100) {
  Buf f;
  f.reserve(kEthHeaderLen + ip_packet.size());
  for (int i = 0; i < 6; ++i) f.push_back(static_cast<uint8_t>(0x02 + i));  // dst MAC
  for (int i = 0; i < 6; ++i) f.push_back(static_cast<uint8_t>(0x0A + i));  // src MAC
  for (int i = 0; i < vlan_tags; ++i) {
    put_be16(f, kEtherTypeVlan);
    put_be16(f, vlan_id);
  }
  put_be16(f, ethertype);
  put_bytes(f, ip_packet);
  return f;
}

// ---------------------------------------------------------------------------
// GTP-U
// ---------------------------------------------------------------------------

struct GtpuSpec {
  uint32_t teid = 0x1000;
  uint8_t msg_type = static_cast<uint8_t>(GtpuMsgType::kGpdu);
  bool with_seq = false;
  uint16_t seq = 0;
  bool with_npdu = false;
  uint8_t npdu = 0;
  bool with_qfi = false;
  uint8_t qfi = 0;
  uint8_t pdu_type = 0;  ///< 0 = DL PDU Session Information, 1 = UL
  bool rqi = false;
  /// Extra extension headers appended before the PDU Session Container,
  /// as (type, content) pairs. Content is padded to make the header 4-aligned.
  std::vector<std::pair<uint8_t, Buf>> extra_ext{};
};

/// Build a GTP-U PDU (header + optional fields + ext chain + payload).
[[nodiscard]] inline Buf build_gtpu(const GtpuSpec& s, Bytes payload) {
  // Assemble the extension chain first so we know its length.
  Buf ext;
  uint8_t first_ext_type = static_cast<uint8_t>(GtpuExtType::kNone);
  std::vector<std::pair<uint8_t, Buf>> chain = s.extra_ext;
  if (s.with_qfi) {
    Buf content;
    content.push_back(static_cast<uint8_t>(s.pdu_type << 4));
    content.push_back(static_cast<uint8_t>((s.rqi ? 0x40 : 0x00) | (s.qfi & 0x3F)));
    chain.emplace_back(static_cast<uint8_t>(GtpuExtType::kPduSessionContainer), std::move(content));
  }
  if (!chain.empty()) {
    first_ext_type = chain.front().first;
    for (size_t i = 0; i < chain.size(); ++i) {
      Buf content = chain[i].second;
      // Each header is [len][content][next], total a multiple of 4 bytes.
      while ((content.size() + 2) % 4 != 0) content.push_back(0);
      const size_t total = content.size() + 2;
      ext.push_back(static_cast<uint8_t>(total / 4));
      put_bytes(ext, Bytes(content.data(), content.size()));
      ext.push_back(i + 1 < chain.size() ? chain[i + 1].first
                                         : static_cast<uint8_t>(GtpuExtType::kNone));
    }
  }

  const bool has_optional = s.with_seq || s.with_npdu || !ext.empty();
  uint8_t flags = 0x30;  // version 1, PT=1
  if (!ext.empty()) flags |= 0x04;
  if (s.with_seq) flags |= 0x02;
  if (s.with_npdu) flags |= 0x01;

  const size_t optional_len = has_optional ? kGtpuOptionalFieldsLen : 0;
  const uint16_t length = static_cast<uint16_t>(optional_len + ext.size() + payload.size());

  Buf out;
  out.reserve(kGtpuFixedHeaderLen + length);
  out.push_back(flags);
  out.push_back(s.msg_type);
  put_be16(out, length);
  put_be32(out, s.teid);
  if (has_optional) {
    put_be16(out, s.seq);
    out.push_back(s.npdu);
    out.push_back(first_ext_type);
    put_bytes(out, Bytes(ext.data(), ext.size()));
  }
  put_bytes(out, payload);
  return out;
}

/// Full Ethernet/IPv4/UDP:2152/GTP-U frame around an inner IP packet.
[[nodiscard]] inline Buf build_gtpu_frame(const GtpuSpec& gs, Bytes inner_ip,
                                          uint32_t outer_src = ipv4(192, 168, 1, 1),
                                          uint32_t outer_dst = ipv4(192, 168, 1, 2)) {
  const Buf gtp = build_gtpu(gs, inner_ip);
  UdpSpec us;
  us.src_ip = outer_src;
  us.dst_ip = outer_dst;
  us.src_port = kGtpuPort;
  us.dst_port = kGtpuPort;
  const Buf ip = build_ipv4_udp(us, Bytes(gtp.data(), gtp.size()));
  return build_ethernet(Bytes(ip.data(), ip.size()));
}

/// A payload of `n` deterministic, non-constant bytes.
[[nodiscard]] inline Buf filler(size_t n, uint8_t seed = 0) {
  Buf b(n);
  for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(seed + i * 31u + 7u);
  return b;
}

// ---------------------------------------------------------------------------
// Diameter
// ---------------------------------------------------------------------------

inline constexpr uint8_t kAvpFlagVendor = 0x80;
inline constexpr uint8_t kAvpFlagMandatory = 0x40;

/// Encode one AVP (with 4-byte padding) into `out`.
inline void put_avp(Buf& out, uint32_t code, Bytes data, uint8_t flags = kAvpFlagMandatory,
                    uint32_t vendor_id = 0) {
  const bool vendor = (flags & kAvpFlagVendor) != 0;
  const uint32_t hdr = vendor ? 12u : 8u;
  const uint32_t len = hdr + static_cast<uint32_t>(data.size());
  put_be32(out, code);
  out.push_back(flags);
  put_be24(out, len);
  if (vendor) put_be32(out, vendor_id);
  put_bytes(out, data);
  while ((out.size() % 4) != 0) out.push_back(0);
}

inline void put_avp_u32(Buf& out, uint32_t code, uint32_t value,
                        uint8_t flags = kAvpFlagMandatory) {
  Buf v;
  put_be32(v, value);
  put_avp(out, code, Bytes(v.data(), v.size()), flags);
}

inline void put_avp_u64(Buf& out, uint32_t code, uint64_t value,
                        uint8_t flags = kAvpFlagMandatory) {
  Buf v;
  put_be64(v, value);
  put_avp(out, code, Bytes(v.data(), v.size()), flags);
}

inline void put_avp_str(Buf& out, uint32_t code, std::string_view s,
                        uint8_t flags = kAvpFlagMandatory) {
  put_avp(out, code, Bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size()), flags);
}

/// Wrap already-encoded sub-AVPs in a grouped AVP.
inline void put_avp_grouped(Buf& out, uint32_t code, const Buf& contents,
                            uint8_t flags = kAvpFlagMandatory) {
  put_avp(out, code, Bytes(contents.data(), contents.size()), flags);
}

/// Frame an AVP area as a Diameter message.
[[nodiscard]] inline Buf build_diameter(uint32_t command_code, uint32_t app_id, bool request,
                                        const Buf& avps, uint32_t hop_by_hop = 0x11111111,
                                        uint32_t end_to_end = 0x22222222) {
  Buf out;
  const uint32_t len = static_cast<uint32_t>(kDiameterHeaderLen + avps.size());
  out.push_back(1);
  put_be24(out, len);
  out.push_back(request ? 0x80 : 0x00);
  put_be24(out, command_code);
  put_be32(out, app_id);
  put_be32(out, hop_by_hop);
  put_be32(out, end_to_end);
  put_bytes(out, Bytes(avps.data(), avps.size()));
  return out;
}

struct GySpec {
  std::string session_id = "ocs.example.com;1;1;0";
  std::string origin_host = "pgw.example.com";
  std::string origin_realm = "example.com";
  std::string imsi = "310150123456789";
  uint32_t request_type = static_cast<uint32_t>(CcRequestType::kUpdate);
  uint32_t request_number = 1;
  uint32_t rating_group = 10;
  uint64_t used_input = 0;
  uint64_t used_output = 0;
  uint64_t granted_total = 0;
  bool include_mscc = true;
  uint32_t result_code = kResultSuccess;  ///< answers only
};

/// Credit-Control-Request (Gy).
[[nodiscard]] inline Buf build_ccr(const GySpec& s) {
  Buf avps;
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kSessionId), s.session_id);
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kOriginHost), s.origin_host);
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kOriginRealm), s.origin_realm);
  put_avp_u32(avps, static_cast<uint32_t>(AvpCode::kCcRequestType), s.request_type);
  put_avp_u32(avps, static_cast<uint32_t>(AvpCode::kCcRequestNumber), s.request_number);

  Buf sub;
  put_avp_u32(sub, static_cast<uint32_t>(AvpCode::kSubscriptionIdType),
              static_cast<uint32_t>(SubscriptionIdType::kImsi));
  put_avp_str(sub, static_cast<uint32_t>(AvpCode::kSubscriptionIdData), s.imsi);
  put_avp_grouped(avps, static_cast<uint32_t>(AvpCode::kSubscriptionId), sub);

  if (s.include_mscc) {
    Buf usu;
    put_avp_u64(usu, static_cast<uint32_t>(AvpCode::kCcInputOctets), s.used_input);
    put_avp_u64(usu, static_cast<uint32_t>(AvpCode::kCcOutputOctets), s.used_output);
    put_avp_u64(usu, static_cast<uint32_t>(AvpCode::kCcTotalOctets), s.used_input + s.used_output);

    Buf mscc;
    put_avp_u32(mscc, static_cast<uint32_t>(AvpCode::kRatingGroup), s.rating_group);
    put_avp_grouped(mscc, static_cast<uint32_t>(AvpCode::kUsedServiceUnit), usu);
    put_avp_grouped(avps, static_cast<uint32_t>(AvpCode::kMultipleServicesCreditControl), mscc);
  }

  return build_diameter(static_cast<uint32_t>(DiameterCommand::kCreditControl),
                        static_cast<uint32_t>(DiameterApp::kCreditControl), true, avps);
}

/// Credit-Control-Answer (Gy).
[[nodiscard]] inline Buf build_cca(const GySpec& s) {
  Buf avps;
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kSessionId), s.session_id);
  put_avp_u32(avps, static_cast<uint32_t>(AvpCode::kResultCode), s.result_code);
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kOriginHost), "ocs.example.com");
  put_avp_str(avps, static_cast<uint32_t>(AvpCode::kOriginRealm), s.origin_realm);
  put_avp_u32(avps, static_cast<uint32_t>(AvpCode::kCcRequestType), s.request_type);
  put_avp_u32(avps, static_cast<uint32_t>(AvpCode::kCcRequestNumber), s.request_number);

  if (s.include_mscc) {
    Buf gsu;
    put_avp_u64(gsu, static_cast<uint32_t>(AvpCode::kCcTotalOctets), s.granted_total);
    Buf mscc;
    put_avp_u32(mscc, static_cast<uint32_t>(AvpCode::kRatingGroup), s.rating_group);
    put_avp_grouped(mscc, static_cast<uint32_t>(AvpCode::kGrantedServiceUnit), gsu);
    put_avp_u32(mscc, static_cast<uint32_t>(AvpCode::kResultCode), s.result_code);
    put_avp_grouped(avps, static_cast<uint32_t>(AvpCode::kMultipleServicesCreditControl), mscc);
  }

  return build_diameter(static_cast<uint32_t>(DiameterCommand::kCreditControl),
                        static_cast<uint32_t>(DiameterApp::kCreditControl), false, avps);
}

}  // namespace gtpm::synth
