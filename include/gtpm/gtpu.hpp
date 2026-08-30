// SPDX-License-Identifier: MIT
//
// GTP-U parser (3GPP TS 29.281), including the extension-header chain and the
// 5G PDU Session Container (TS 38.415) that carries the QFI.
//
// The parser is zero-copy and allocation-free: it fills a small POD descriptor
// and returns a `std::span` view of the encapsulated payload. It never trusts a
// length field without checking it against the bytes actually present.
#pragma once

#include <cstdint>

#include "gtpm/byte_order.hpp"

namespace gtpm {

/// UDP port carrying GTP-U on S1-U / N3 (TS 29.281 §4.4.2.0).
inline constexpr uint16_t kGtpuPort = 2152;

/// Mandatory GTP-U header size, before optional fields.
inline constexpr size_t kGtpuFixedHeaderLen = 8;
/// Sequence number + N-PDU number + next-extension-header type.
inline constexpr size_t kGtpuOptionalFieldsLen = 4;
/// Chain depth cap; a conformant packet never comes close.
inline constexpr int kGtpuMaxExtHeaders = 16;

enum class GtpuMsgType : uint8_t {
  kEchoRequest = 1,
  kEchoResponse = 2,
  kErrorIndication = 26,
  kSupportedExtHeadersNotify = 31,
  kEndMarker = 254,
  kGpdu = 255,
};

enum class GtpuExtType : uint8_t {
  kNone = 0x00,
  kLongPdcpPduNumber = 0x03,
  kServiceClassIndicator = 0x20,
  kUdpPort = 0x40,
  kRanContainer = 0x81,
  kLongPdcpPduNumber2 = 0x82,
  kXwRanContainer = 0x83,
  kNrRanContainer = 0x84,
  kPduSessionContainer = 0x85,
  kPdcpPduNumber = 0xC0,
};

/// PDU Session Information type (TS 38.415 §5.5.2).
enum class PduSessionInfoType : uint8_t { kDownlink = 0, kUplink = 1 };

enum class GtpuStatus : uint8_t {
  kOk = 0,
  kTruncated,        ///< fewer bytes present than the header/length demands
  kBadVersion,       ///< version field != 1
  kNotGtpU,          ///< protocol-type bit clear (GTP' / GTPv1-C prime)
  kBadLength,        ///< declared length inconsistent with optional/ext fields
  kBadExtHeader,     ///< extension header with length 0 or overrunning the frame
  kExtChainTooLong,  ///< more than kGtpuMaxExtHeaders links
};

[[nodiscard]] constexpr const char* to_string(GtpuStatus s) noexcept {
  switch (s) {
    case GtpuStatus::kOk: return "ok";
    case GtpuStatus::kTruncated: return "truncated";
    case GtpuStatus::kBadVersion: return "bad-version";
    case GtpuStatus::kNotGtpU: return "not-gtpu";
    case GtpuStatus::kBadLength: return "bad-length";
    case GtpuStatus::kBadExtHeader: return "bad-ext-header";
    case GtpuStatus::kExtChainTooLong: return "ext-chain-too-long";
  }
  return "unknown";
}

/// Decoded GTP-U header. POD, cheap to copy, no owning members.
struct GtpuHeader {
  Bytes payload;              ///< view of the encapsulated packet (inner IP for G-PDU)
  uint32_t teid = 0;          ///< tunnel endpoint identifier — the metering key
  uint16_t seq = 0;           ///< sequence number, valid when has_seq
  uint16_t header_len = 0;    ///< total GTP-U bytes consumed, incl. optional + ext
  uint16_t declared_len = 0;  ///< Length field as it appeared on the wire
  uint8_t msg_type = 0;
  uint8_t npdu = 0;
  uint8_t qfi = 0;       ///< QoS Flow Identifier, valid when has_qfi
  uint8_t pdu_type = 0;  ///< PduSessionInfoType, valid when has_qfi
  uint8_t ext_count = 0;
  bool has_seq = false;
  bool has_npdu = false;
  bool has_ext = false;
  bool has_qfi = false;
  bool rqi = false;  ///< Reflective QoS Indicator (DL PDU Session Information)

  [[nodiscard]] bool is_gpdu() const noexcept {
    return msg_type == static_cast<uint8_t>(GtpuMsgType::kGpdu);
  }
  [[nodiscard]] bool is_end_marker() const noexcept {
    return msg_type == static_cast<uint8_t>(GtpuMsgType::kEndMarker);
  }
};

namespace detail {

/// Walk the extension-header chain starting at `first_type`.
/// `buf` begins at the first extension header. Returns bytes consumed via `consumed`.
[[nodiscard]] inline GtpuStatus parse_ext_chain(Bytes buf, uint8_t first_type, GtpuHeader& out,
                                                size_t& consumed) noexcept {
  consumed = 0;
  uint8_t next = first_type;
  int links = 0;

  while (next != static_cast<uint8_t>(GtpuExtType::kNone)) {
    if (++links > kGtpuMaxExtHeaders) return GtpuStatus::kExtChainTooLong;
    if (consumed >= buf.size()) return GtpuStatus::kTruncated;

    const uint8_t units = buf[consumed];
    if (units == 0) return GtpuStatus::kBadExtHeader;  // zero length would loop forever
    const size_t ext_len = static_cast<size_t>(units) * 4;
    if (consumed + ext_len > buf.size()) return GtpuStatus::kTruncated;

    // Layout: [len][content ... ][next type], content is ext_len - 2 bytes.
    const uint8_t* content = buf.data() + consumed + 1;
    const size_t content_len = ext_len - 2;

    if (next == static_cast<uint8_t>(GtpuExtType::kPduSessionContainer) && content_len >= 2) {
      // TS 38.415 §5.5.2: nibble 0 selects UL/DL info; QFI lives in the low 6
      // bits of the following octet in both directions.
      out.pdu_type = static_cast<uint8_t>(content[0] >> 4);
      out.qfi = static_cast<uint8_t>(content[1] & 0x3F);
      out.rqi = out.pdu_type == static_cast<uint8_t>(PduSessionInfoType::kDownlink) &&
                (content[1] & 0x40) != 0;
      out.has_qfi = true;
    }

    next = buf[consumed + ext_len - 1];
    consumed += ext_len;
  }

  out.ext_count = static_cast<uint8_t>(links);
  return GtpuStatus::kOk;
}

}  // namespace detail

/// Parse a GTP-U PDU. `frame` must start at the GTP-U header (i.e. after the
/// outer Ethernet/IP/UDP headers). On success `out.payload` views the payload.
[[nodiscard]] inline GtpuStatus parse_gtpu(Bytes frame, GtpuHeader& out) noexcept {
  out = GtpuHeader{};

  if (frame.size() < kGtpuFixedHeaderLen) return GtpuStatus::kTruncated;

  const uint8_t flags = frame[0];
  if ((flags >> 5) != 1) return GtpuStatus::kBadVersion;
  if ((flags & 0x10) == 0) return GtpuStatus::kNotGtpU;  // PT=0 is GTP' (charging)

  const bool e_bit = (flags & 0x04) != 0;
  const bool s_bit = (flags & 0x02) != 0;
  const bool pn_bit = (flags & 0x01) != 0;

  out.msg_type = frame[1];
  out.declared_len = load_be16(frame.data() + 2);
  out.teid = load_be32(frame.data() + 4);

  // The Length field counts every byte after the mandatory 8, which includes
  // the optional fields and the whole extension-header chain.
  const size_t declared = out.declared_len;
  if (frame.size() - kGtpuFixedHeaderLen < declared) return GtpuStatus::kTruncated;

  size_t offset = kGtpuFixedHeaderLen;
  size_t optional_and_ext = 0;

  if (e_bit || s_bit || pn_bit) {
    if (declared < kGtpuOptionalFieldsLen) return GtpuStatus::kBadLength;
    out.seq = load_be16(frame.data() + offset);
    out.npdu = frame[offset + 2];
    out.has_seq = s_bit;
    out.has_npdu = pn_bit;
    const uint8_t first_ext = frame[offset + 3];
    offset += kGtpuOptionalFieldsLen;
    optional_and_ext = kGtpuOptionalFieldsLen;

    if (e_bit && first_ext != static_cast<uint8_t>(GtpuExtType::kNone)) {
      out.has_ext = true;
      // Bound the chain walk by the declared payload, not by the whole frame:
      // trailing bytes after the GTP-U PDU (e.g. Ethernet padding) are not ours.
      const Bytes ext_area = frame.subspan(offset, declared - kGtpuOptionalFieldsLen);
      size_t ext_bytes = 0;
      const GtpuStatus st = detail::parse_ext_chain(ext_area, first_ext, out, ext_bytes);
      if (st != GtpuStatus::kOk) return st;
      offset += ext_bytes;
      optional_and_ext += ext_bytes;
    }
  }

  if (declared < optional_and_ext) return GtpuStatus::kBadLength;
  const size_t payload_len = declared - optional_and_ext;

  out.header_len = static_cast<uint16_t>(offset);
  out.payload = frame.subspan(offset, payload_len);
  return GtpuStatus::kOk;
}

}  // namespace gtpm
