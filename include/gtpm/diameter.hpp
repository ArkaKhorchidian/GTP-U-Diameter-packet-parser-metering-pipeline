// SPDX-License-Identifier: MIT
//
// Diameter base protocol (RFC 6733) header + AVP decoding, with the Gy
// Credit-Control (RFC 4006) fields the metering pipeline cares about.
//
// Like the GTP-U parser this is zero-copy: AVP values are spans into the
// caller's buffer. Grouped AVPs are walked recursively with a hard depth cap.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "gtpm/byte_order.hpp"

namespace gtpm {

inline constexpr uint16_t kDiameterPort = 3868;
inline constexpr size_t kDiameterHeaderLen = 20;
/// Refuse absurd declared lengths before allocating or buffering anything.
inline constexpr uint32_t kDiameterMaxMsgLen = 1u << 20;
inline constexpr int kAvpMaxDepth = 8;
inline constexpr size_t kMaxMsccPerMessage = 8;

enum class DiameterCommand : uint32_t {
  kCapabilitiesExchange = 257,
  kDeviceWatchdog = 280,
  kDisconnectPeer = 282,
  kReAuth = 258,
  kSessionTermination = 275,
  kCreditControl = 272,
};

enum class DiameterApp : uint32_t {
  kCommon = 0,
  kCreditControl = 4,  ///< Gy
  kGx = 16777238,
};

enum class AvpCode : uint32_t {
  kSessionId = 263,
  kOriginHost = 264,
  kOriginRealm = 296,
  kDestinationHost = 293,
  kDestinationRealm = 283,
  kResultCode = 268,
  kCcRequestType = 416,
  kCcRequestNumber = 415,
  kSubscriptionId = 443,
  kSubscriptionIdType = 450,
  kSubscriptionIdData = 444,
  kMultipleServicesCreditControl = 456,
  kRatingGroup = 432,
  kServiceIdentifier = 439,
  kGrantedServiceUnit = 431,
  kUsedServiceUnit = 446,
  kCcInputOctets = 412,
  kCcOutputOctets = 414,
  kCcTotalOctets = 421,
  kCcTime = 420,
  kEventTimestamp = 55,
  kUserName = 1,
};

enum class CcRequestType : uint32_t {
  kInitial = 1,
  kUpdate = 2,
  kTermination = 3,
  kEvent = 4,
};

enum class SubscriptionIdType : uint32_t {
  kE164 = 0,  ///< MSISDN
  kImsi = 1,
  kSipUri = 2,
  kNai = 3,
  kPrivate = 4,
};

inline constexpr uint32_t kResultSuccess = 2001;

enum class DiameterStatus : uint8_t {
  kOk = 0,
  kTruncated,   ///< fewer bytes than the header or declared length needs
  kBadVersion,  ///< version != 1
  kBadLength,   ///< length field < header, > cap, or not 4-byte aligned
  kBadAvp,      ///< AVP length < header size or overrunning the message
  kAvpTooDeep,  ///< grouped AVP nesting past kAvpMaxDepth
};

[[nodiscard]] constexpr const char* to_string(DiameterStatus s) noexcept {
  switch (s) {
    case DiameterStatus::kOk: return "ok";
    case DiameterStatus::kTruncated: return "truncated";
    case DiameterStatus::kBadVersion: return "bad-version";
    case DiameterStatus::kBadLength: return "bad-length";
    case DiameterStatus::kBadAvp: return "bad-avp";
    case DiameterStatus::kAvpTooDeep: return "avp-too-deep";
  }
  return "unknown";
}

struct DiameterHeader {
  Bytes avps{};  ///< the AVP area, i.e. the message minus the 20-byte header
  uint32_t msg_length = 0;
  uint32_t command_code = 0;
  uint32_t application_id = 0;
  uint32_t hop_by_hop = 0;
  uint32_t end_to_end = 0;
  uint8_t flags = 0;

  [[nodiscard]] bool request() const noexcept { return (flags & 0x80) != 0; }
  [[nodiscard]] bool proxiable() const noexcept { return (flags & 0x40) != 0; }
  [[nodiscard]] bool error() const noexcept { return (flags & 0x20) != 0; }
  [[nodiscard]] bool retransmit() const noexcept { return (flags & 0x10) != 0; }
  [[nodiscard]] bool is_credit_control() const noexcept {
    return command_code == static_cast<uint32_t>(DiameterCommand::kCreditControl);
  }
};

struct Avp {
  Bytes data{};  ///< value bytes, padding excluded
  uint32_t code = 0;
  uint32_t vendor_id = 0;
  uint32_t length = 0;  ///< declared length, header included, padding excluded
  uint8_t flags = 0;

  [[nodiscard]] bool vendor_specific() const noexcept { return (flags & 0x80) != 0; }
  [[nodiscard]] bool mandatory() const noexcept { return (flags & 0x40) != 0; }
  [[nodiscard]] bool protectedf() const noexcept { return (flags & 0x20) != 0; }

  [[nodiscard]] bool as_u32(uint32_t& out) const noexcept {
    if (data.size() != 4) return false;
    out = load_be32(data.data());
    return true;
  }
  [[nodiscard]] bool as_i32(int32_t& out) const noexcept {
    uint32_t v = 0;
    if (!as_u32(v)) return false;
    out = static_cast<int32_t>(v);
    return true;
  }
  /// Unsigned64 or Integer64; also accepts a 4-byte value so that peers that
  /// encode octet counters as Unsigned32 still decode.
  [[nodiscard]] bool as_u64(uint64_t& out) const noexcept {
    if (data.size() == 8) {
      out = load_be64(data.data());
      return true;
    }
    if (data.size() == 4) {
      out = load_be32(data.data());
      return true;
    }
    return false;
  }
  [[nodiscard]] std::string_view as_string() const noexcept {
    return {reinterpret_cast<const char*>(data.data()), data.size()};
  }
};

/// Parse the 20-byte base header. Does not touch the AVP area.
[[nodiscard]] inline DiameterStatus parse_diameter_header(Bytes buf, DiameterHeader& out) noexcept {
  out = DiameterHeader{};
  if (buf.size() < kDiameterHeaderLen) return DiameterStatus::kTruncated;
  if (buf[0] != 1) return DiameterStatus::kBadVersion;

  const uint32_t len = load_be24(buf.data() + 1);
  if (len < kDiameterHeaderLen || len > kDiameterMaxMsgLen) return DiameterStatus::kBadLength;
  if ((len & 3u) != 0) return DiameterStatus::kBadLength;  // RFC 6733: always 4-byte aligned
  if (buf.size() < len) return DiameterStatus::kTruncated;

  out.msg_length = len;
  out.flags = buf[4];
  out.command_code = load_be24(buf.data() + 5);
  out.application_id = load_be32(buf.data() + 8);
  out.hop_by_hop = load_be32(buf.data() + 12);
  out.end_to_end = load_be32(buf.data() + 16);
  out.avps = buf.subspan(kDiameterHeaderLen, len - kDiameterHeaderLen);
  return DiameterStatus::kOk;
}

/// Walk one AVP area, invoking `fn(const Avp&, int depth)`. Returning false
/// from `fn` stops the walk (used to short-circuit searches).
template <typename Fn>
[[nodiscard]] DiameterStatus for_each_avp(Bytes area, Fn&& fn, int depth = 0) noexcept {
  if (depth >= kAvpMaxDepth) return DiameterStatus::kAvpTooDeep;

  size_t off = 0;
  while (off < area.size()) {
    if (area.size() - off < 8) return DiameterStatus::kBadAvp;

    Avp avp;
    avp.code = load_be32(area.data() + off);
    avp.flags = area[off + 4];
    avp.length = load_be24(area.data() + off + 5);

    const size_t hdr = avp.vendor_specific() ? 12u : 8u;
    if (avp.length < hdr) return DiameterStatus::kBadAvp;
    if (avp.length > area.size() - off) return DiameterStatus::kBadAvp;
    if (avp.vendor_specific()) avp.vendor_id = load_be32(area.data() + off + 8);

    avp.data = area.subspan(off + hdr, avp.length - hdr);
    if (!fn(avp, depth)) return DiameterStatus::kOk;

    // Values are padded to a 4-byte boundary; the padding is not in `length`.
    const size_t advance = (avp.length + 3u) & ~size_t{3};
    if (advance == 0 || advance > area.size() - off) return DiameterStatus::kBadAvp;
    off += advance;
  }
  return DiameterStatus::kOk;
}

/// Recurse into a grouped AVP's contents.
template <typename Fn>
[[nodiscard]] DiameterStatus for_each_sub_avp(const Avp& grouped, Fn&& fn, int depth) noexcept {
  return for_each_avp(grouped.data, std::forward<Fn>(fn), depth + 1);
}

// ---------------------------------------------------------------------------
// Gy (RFC 4006) extraction
// ---------------------------------------------------------------------------

/// One Multiple-Services-Credit-Control block.
struct MsccInfo {
  uint64_t used_input_octets = 0;
  uint64_t used_output_octets = 0;
  uint64_t used_total_octets = 0;
  uint64_t granted_total_octets = 0;
  uint32_t rating_group = 0;
  uint32_t service_identifier = 0;
  bool has_rating_group = false;
  bool has_service_identifier = false;
  bool has_used = false;
  bool has_granted = false;
};

/// The fields a metering pipeline lifts out of a CCR/CCA.
struct GyMessage {
  std::string_view session_id{};
  std::string_view origin_host{};
  std::string_view origin_realm{};
  std::string_view msisdn{};
  std::array<MsccInfo, kMaxMsccPerMessage> mscc{};
  uint64_t imsi = 0;  ///< packed decimal, 0 when absent
  uint32_t cc_request_type = 0;
  uint32_t cc_request_number = 0;
  uint32_t result_code = 0;
  size_t mscc_count = 0;
  bool is_request = false;
  bool has_imsi = false;
  bool has_result_code = false;
  bool mscc_overflow = false;  ///< more MSCC blocks than we kept
};

namespace detail {

/// IMSI digits -> uint64. Up to 15 digits fits comfortably; rejects non-digits.
[[nodiscard]] inline bool pack_imsi(std::string_view s, uint64_t& out) noexcept {
  if (s.empty() || s.size() > 19) return false;
  uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  out = v;
  return true;
}

inline void parse_used_service_unit(const Avp& usu, MsccInfo& info, int depth) noexcept {
  info.has_used = true;
  (void)for_each_sub_avp(
      usu,
      [&info](const Avp& a, int) noexcept {
        switch (static_cast<AvpCode>(a.code)) {
          case AvpCode::kCcInputOctets: (void)a.as_u64(info.used_input_octets); break;
          case AvpCode::kCcOutputOctets: (void)a.as_u64(info.used_output_octets); break;
          case AvpCode::kCcTotalOctets: (void)a.as_u64(info.used_total_octets); break;
          default: break;
        }
        return true;
      },
      depth);
  if (info.used_total_octets == 0) {
    info.used_total_octets = info.used_input_octets + info.used_output_octets;
  }
}

inline void parse_mscc(const Avp& mscc_avp, MsccInfo& info, int depth) noexcept {
  (void)for_each_sub_avp(
      mscc_avp,
      [&info, depth](const Avp& a, int) noexcept {
        switch (static_cast<AvpCode>(a.code)) {
          case AvpCode::kRatingGroup: info.has_rating_group = a.as_u32(info.rating_group); break;
          case AvpCode::kServiceIdentifier:
            info.has_service_identifier = a.as_u32(info.service_identifier);
            break;
          case AvpCode::kUsedServiceUnit: parse_used_service_unit(a, info, depth + 1); break;
          case AvpCode::kGrantedServiceUnit:
            info.has_granted = true;
            (void)for_each_sub_avp(
                a,
                [&info](const Avp& g, int) noexcept {
                  if (static_cast<AvpCode>(g.code) == AvpCode::kCcTotalOctets) {
                    (void)g.as_u64(info.granted_total_octets);
                  }
                  return true;
                },
                depth + 2);
            break;
          default: break;
        }
        return true;
      },
      depth);
}

inline void parse_subscription_id(const Avp& sub, GyMessage& out, int depth) noexcept {
  uint32_t type = 0xFFFFFFFF;
  std::string_view data{};
  (void)for_each_sub_avp(
      sub,
      [&type, &data](const Avp& a, int) noexcept {
        if (static_cast<AvpCode>(a.code) == AvpCode::kSubscriptionIdType) {
          (void)a.as_u32(type);
        } else if (static_cast<AvpCode>(a.code) == AvpCode::kSubscriptionIdData) {
          data = a.as_string();
        }
        return true;
      },
      depth);

  if (type == static_cast<uint32_t>(SubscriptionIdType::kImsi)) {
    out.has_imsi = pack_imsi(data, out.imsi);
  } else if (type == static_cast<uint32_t>(SubscriptionIdType::kE164)) {
    out.msisdn = data;
  }
}

}  // namespace detail

/// Extract the Gy fields from an already-parsed Credit-Control message.
[[nodiscard]] inline DiameterStatus parse_gy(const DiameterHeader& hdr, GyMessage& out) noexcept {
  out = GyMessage{};
  out.is_request = hdr.request();

  return for_each_avp(hdr.avps, [&out](const Avp& a, int depth) noexcept {
    switch (static_cast<AvpCode>(a.code)) {
      case AvpCode::kSessionId: out.session_id = a.as_string(); break;
      case AvpCode::kOriginHost: out.origin_host = a.as_string(); break;
      case AvpCode::kOriginRealm: out.origin_realm = a.as_string(); break;
      case AvpCode::kCcRequestType: (void)a.as_u32(out.cc_request_type); break;
      case AvpCode::kCcRequestNumber: (void)a.as_u32(out.cc_request_number); break;
      case AvpCode::kResultCode: out.has_result_code = a.as_u32(out.result_code); break;
      case AvpCode::kSubscriptionId: detail::parse_subscription_id(a, out, depth); break;
      case AvpCode::kMultipleServicesCreditControl:
        if (out.mscc_count < out.mscc.size()) {
          detail::parse_mscc(a, out.mscc[out.mscc_count], depth);
          ++out.mscc_count;
        } else {
          out.mscc_overflow = true;
        }
        break;
      default: break;
    }
    return true;
  });
}

/// Convenience: header + Gy extraction in one call.
[[nodiscard]] inline DiameterStatus parse_diameter_gy(Bytes buf, DiameterHeader& hdr,
                                                      GyMessage& gy) noexcept {
  const DiameterStatus st = parse_diameter_header(buf, hdr);
  if (st != DiameterStatus::kOk) return st;
  if (!hdr.is_credit_control()) return DiameterStatus::kOk;
  return parse_gy(hdr, gy);
}

}  // namespace gtpm
