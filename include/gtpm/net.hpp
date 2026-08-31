// SPDX-License-Identifier: MIT
//
// Ethernet / VLAN / IPv4 / IPv6 / UDP / TCP decoding.
//
// Used twice per packet: once to strip the outer headers on the way to the
// GTP-U tunnel, and once on the encapsulated payload to lift the inner 5-tuple.
// Same code path for both — the inner packet is just another IP packet.
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>

#include "gtpm/byte_order.hpp"

namespace gtpm {

inline constexpr size_t kEthHeaderLen = 14;
inline constexpr size_t kVlanTagLen = 4;
inline constexpr uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr uint16_t kEtherTypeIpv6 = 0x86DD;
inline constexpr uint16_t kEtherTypeVlan = 0x8100;
inline constexpr uint16_t kEtherTypeQinQ = 0x88A8;
inline constexpr int kMaxVlanTags = 2;
inline constexpr int kMaxIpv6ExtHeaders = 8;

enum class IpProto : uint8_t {
  kHopByHop = 0,
  kIcmp = 1,
  kTcp = 6,
  kUdp = 17,
  kIpv6Route = 43,
  kIpv6Frag = 44,
  kEsp = 50,
  kAh = 51,
  kIcmpv6 = 58,
  kIpv6NoNext = 59,
  kIpv6Dest = 60,
  kSctp = 132,
};

using IpAddr = std::array<uint8_t, 16>;

/// Inner 5-tuple plus the metadata metering needs. IPv4 addresses are stored
/// left-aligned in the 16-byte field so one struct covers both families.
struct FiveTuple {
  IpAddr src{};
  IpAddr dst{};
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t proto = 0;
  uint8_t ip_version = 0;  ///< 4, 6, or 0 when the payload was not IP
  bool fragmented = false;
  bool ports_valid = false;

  [[nodiscard]] bool operator==(const FiveTuple& o) const noexcept {
    return src == o.src && dst == o.dst && src_port == o.src_port && dst_port == o.dst_port &&
           proto == o.proto && ip_version == o.ip_version;
  }
  [[nodiscard]] uint32_t src_v4() const noexcept { return load_be32(src.data()); }
  [[nodiscard]] uint32_t dst_v4() const noexcept { return load_be32(dst.data()); }
};

/// Result of decoding one IP packet.
struct IpPacket {
  FiveTuple tuple{};
  Bytes l4_payload{};         ///< bytes after the L4 header (TCP/UDP), empty otherwise
  uint32_t ip_total_len = 0;  ///< IP total length as declared on the wire
  uint16_t l3_header_len = 0;
  uint16_t l4_header_len = 0;
  bool valid = false;
};

/// Result of stripping Ethernet (plus any VLAN tags).
struct EthFrame {
  Bytes payload{};
  uint16_t ethertype = 0;
  uint8_t vlan_tags = 0;
  bool valid = false;
};

[[nodiscard]] inline EthFrame parse_ethernet(Bytes frame) noexcept {
  EthFrame out;
  if (frame.size() < kEthHeaderLen) return out;

  size_t off = 12;
  uint16_t ethertype = load_be16(frame.data() + off);
  off += 2;

  for (int i = 0; i < kMaxVlanTags; ++i) {
    if (ethertype != kEtherTypeVlan && ethertype != kEtherTypeQinQ) break;
    if (off + kVlanTagLen > frame.size()) return out;
    ethertype = load_be16(frame.data() + off + 2);
    off += kVlanTagLen;
    ++out.vlan_tags;
  }

  out.ethertype = ethertype;
  out.payload = frame.subspan(off);
  out.valid = true;
  return out;
}

namespace detail {

inline void parse_l4(Bytes l4, IpPacket& out) noexcept {
  const uint8_t proto = out.tuple.proto;
  if (proto == static_cast<uint8_t>(IpProto::kUdp)) {
    if (l4.size() < 8) return;
    out.tuple.src_port = load_be16(l4.data());
    out.tuple.dst_port = load_be16(l4.data() + 2);
    out.tuple.ports_valid = true;
    out.l4_header_len = 8;
    out.l4_payload = l4.subspan(8);
  } else if (proto == static_cast<uint8_t>(IpProto::kTcp)) {
    if (l4.size() < 20) return;
    out.tuple.src_port = load_be16(l4.data());
    out.tuple.dst_port = load_be16(l4.data() + 2);
    out.tuple.ports_valid = true;
    const size_t doff = static_cast<size_t>(l4[12] >> 4) * 4;
    if (doff < 20 || doff > l4.size()) return;
    out.l4_header_len = static_cast<uint16_t>(doff);
    out.l4_payload = l4.subspan(doff);
  } else if (proto == static_cast<uint8_t>(IpProto::kSctp)) {
    if (l4.size() < 12) return;
    out.tuple.src_port = load_be16(l4.data());
    out.tuple.dst_port = load_be16(l4.data() + 2);
    out.tuple.ports_valid = true;
    out.l4_header_len = 12;
    out.l4_payload = l4.subspan(12);
  }
}

}  // namespace detail

[[nodiscard]] inline IpPacket parse_ipv4(Bytes pkt) noexcept {
  IpPacket out;
  if (pkt.size() < 20) return out;
  if ((pkt[0] >> 4) != 4) return out;

  const size_t ihl = static_cast<size_t>(pkt[0] & 0x0F) * 4;
  if (ihl < 20 || ihl > pkt.size()) return out;

  const uint16_t total_len = load_be16(pkt.data() + 2);
  if (total_len < ihl) return out;

  const uint16_t frag = load_be16(pkt.data() + 6);
  const bool more_frags = (frag & 0x2000) != 0;
  const uint16_t frag_off = static_cast<uint16_t>(frag & 0x1FFF);

  out.tuple.ip_version = 4;
  out.tuple.proto = pkt[9];
  out.tuple.fragmented = more_frags || frag_off != 0;
  std::memcpy(out.tuple.src.data(), pkt.data() + 12, 4);
  std::memcpy(out.tuple.dst.data(), pkt.data() + 16, 4);
  out.l3_header_len = static_cast<uint16_t>(ihl);
  out.ip_total_len = total_len;
  out.valid = true;

  // Clamp to what is really present: captures are often snaplen-truncated.
  const size_t declared_payload = static_cast<size_t>(total_len) - ihl;
  const size_t avail = pkt.size() - ihl;
  const Bytes l4 = pkt.subspan(ihl, declared_payload < avail ? declared_payload : avail);

  // Only the first fragment carries the L4 header.
  if (frag_off == 0) detail::parse_l4(l4, out);
  return out;
}

[[nodiscard]] inline IpPacket parse_ipv6(Bytes pkt) noexcept {
  IpPacket out;
  if (pkt.size() < 40) return out;
  if ((pkt[0] >> 4) != 6) return out;

  const uint16_t payload_len = load_be16(pkt.data() + 4);
  out.tuple.ip_version = 6;
  std::memcpy(out.tuple.src.data(), pkt.data() + 8, 16);
  std::memcpy(out.tuple.dst.data(), pkt.data() + 24, 16);
  out.l3_header_len = 40;
  out.ip_total_len = 40u + payload_len;
  out.valid = true;

  const size_t declared = 40u + payload_len;
  const size_t end = declared < pkt.size() ? declared : pkt.size();
  uint8_t next = pkt[6];
  size_t off = 40;

  for (int i = 0; i < kMaxIpv6ExtHeaders; ++i) {
    const bool is_ext = next == static_cast<uint8_t>(IpProto::kHopByHop) ||
                        next == static_cast<uint8_t>(IpProto::kIpv6Route) ||
                        next == static_cast<uint8_t>(IpProto::kIpv6Dest) ||
                        next == static_cast<uint8_t>(IpProto::kAh) ||
                        next == static_cast<uint8_t>(IpProto::kIpv6Frag);
    if (!is_ext) break;

    if (off + 8 > end) {
      out.tuple.proto = next;
      return out;
    }
    if (next == static_cast<uint8_t>(IpProto::kIpv6Frag)) {
      const uint16_t frag = load_be16(pkt.data() + off + 2);
      out.tuple.fragmented = (frag & 0xFFF9) != 0;
      const bool first_frag = (frag & 0xFFF8) == 0;
      next = pkt[off];
      off += 8;
      if (!first_frag) {
        out.tuple.proto = next;
        out.l3_header_len = static_cast<uint16_t>(off);
        return out;  // non-initial fragment: no L4 header here
      }
      continue;
    }
    // AH length is in 4-byte units minus 2; the others are in 8-byte units.
    const size_t ext_len = next == static_cast<uint8_t>(IpProto::kAh)
                               ? (static_cast<size_t>(pkt[off + 1]) + 2) * 4
                               : (static_cast<size_t>(pkt[off + 1]) + 1) * 8;
    if (off + ext_len > end) {
      out.tuple.proto = next;
      return out;
    }
    next = pkt[off];
    off += ext_len;
  }

  out.tuple.proto = next;
  out.l3_header_len = static_cast<uint16_t>(off);
  if (off <= end) detail::parse_l4(pkt.subspan(off, end - off), out);
  return out;
}

/// Decode an IP packet of either family; dispatches on the version nibble.
[[nodiscard]] inline IpPacket parse_ip(Bytes pkt) noexcept {
  if (pkt.empty()) return IpPacket{};
  const uint8_t version = static_cast<uint8_t>(pkt[0] >> 4);
  if (version == 4) return parse_ipv4(pkt);
  if (version == 6) return parse_ipv6(pkt);
  return IpPacket{};
}

/// 64-bit flow key over the 5-tuple. Direction-sensitive by design: uplink and
/// downlink halves of a connection are metered as separate flows, matching how
/// a UPF accounts for them.
[[nodiscard]] inline uint64_t flow_key(const FiveTuple& t) noexcept {
  // FNV-1a over the tuple bytes; cheap, no table, good enough for a flow table
  // whose collisions cost an eviction, not a correctness bug.
  uint64_t h = 1469598103934665603ULL;
  auto mix = [&h](uint8_t b) noexcept {
    h ^= b;
    h *= 1099511628211ULL;
  };
  const size_t addr_len = t.ip_version == 6 ? 16 : 4;
  for (size_t i = 0; i < addr_len; ++i) mix(t.src[i]);
  for (size_t i = 0; i < addr_len; ++i) mix(t.dst[i]);
  mix(static_cast<uint8_t>(t.src_port >> 8));
  mix(static_cast<uint8_t>(t.src_port));
  mix(static_cast<uint8_t>(t.dst_port >> 8));
  mix(static_cast<uint8_t>(t.dst_port));
  mix(t.proto);
  mix(t.ip_version);
  return h;
}

/// Render an address for logs and usage records. `buf` needs 46 bytes.
inline const char* format_ip(const IpAddr& addr, uint8_t version, char* buf, size_t buf_len) {
  if (version == 4) {
    std::snprintf(buf, buf_len, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
  } else if (version == 6) {
    std::snprintf(
        buf, buf_len, "%x:%x:%x:%x:%x:%x:%x:%x", load_be16(addr.data()), load_be16(addr.data() + 2),
        load_be16(addr.data() + 4), load_be16(addr.data() + 6), load_be16(addr.data() + 8),
        load_be16(addr.data() + 10), load_be16(addr.data() + 12), load_be16(addr.data() + 14));
  } else {
    std::snprintf(buf, buf_len, "-");
  }
  return buf;
}

}  // namespace gtpm
