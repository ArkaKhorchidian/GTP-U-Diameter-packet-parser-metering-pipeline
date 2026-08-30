// SPDX-License-Identifier: MIT
//
// Ingest-side packet processing: raw frame in, MeterEvent (and optionally a Gy
// control event) out.
//
// This is the code that runs on the parser core. It performs no allocation, no
// I/O and no locking; the only thing it does with the world is push onto the
// rings. Keeping it a pure function of the frame is what makes it testable
// packet-by-packet and reusable from pcap replay, raw sockets and benchmarks.
#pragma once

#include <cstdint>

#include "gtpm/diameter.hpp"
#include "gtpm/gtpu.hpp"
#include "gtpm/meter_event.hpp"
#include "gtpm/net.hpp"
#include "gtpm/spsc_ring.hpp"

namespace gtpm {

/// Per-thread ingest counters. Not shared, so plain integers.
struct IngestStats {
  uint64_t frames = 0;
  uint64_t frames_bytes = 0;
  uint64_t non_ip = 0;
  uint64_t not_gtpu_port = 0;
  uint64_t gtpu_parse_errors = 0;
  uint64_t gtpu_gpdus = 0;
  uint64_t gtpu_control = 0;
  uint64_t inner_parse_errors = 0;
  uint64_t diameter_messages = 0;
  uint64_t diameter_parse_errors = 0;
  uint64_t gy_events = 0;
  uint64_t events_pushed = 0;
  uint64_t events_dropped = 0;  ///< metering ring full: the number that matters
  uint64_t gy_events_dropped = 0;
  uint64_t truncated_frames = 0;
};

enum class FrameOutcome : uint8_t {
  kMetered = 0,       ///< produced a MeterEvent
  kGyControl,         ///< produced one or more Gy control events
  kGtpuControl,       ///< Echo / Error Indication / End Marker
  kNotOurTraffic,     ///< not GTP-U and not Diameter
  kParseError,
  kDropped,           ///< ring full
};

struct IngestConfig {
  uint16_t gtpu_port = kGtpuPort;
  uint16_t diameter_port = kDiameterPort;
  bool parse_diameter = true;
  bool count_wire_bytes = true;
  /// Meter the inner IP total length rather than the captured bytes. This is
  /// what a charging function counts, and it stays correct under snaplen
  /// truncation.
  bool meter_inner_ip_length = true;
};

/// Stateless frame processor. Owns nothing; rings are supplied by the caller.
class Ingest {
 public:
  Ingest(SpscRing<MeterEvent>* meter_ring, SpscRing<GyEvent>* gy_ring, IngestConfig cfg = {})
      : cfg_(cfg), meter_ring_(meter_ring), gy_ring_(gy_ring) {}

  [[nodiscard]] const IngestStats& stats() const noexcept { return stats_; }
  void reset_stats() noexcept { stats_ = IngestStats{}; }

  /// Process one Ethernet frame captured at `ts_ns`.
  FrameOutcome process_frame(Bytes frame, uint64_t ts_ns) noexcept {
    ++stats_.frames;
    stats_.frames_bytes += frame.size();

    const EthFrame eth = parse_ethernet(frame);
    if (!eth.valid) {
      ++stats_.non_ip;
      return FrameOutcome::kNotOurTraffic;
    }
    return process_ip(eth.payload, ts_ns, static_cast<uint16_t>(frame.size()));
  }

  /// Process one IP packet (no Ethernet header), e.g. from a raw IP socket.
  FrameOutcome process_ip(Bytes ip_packet, uint64_t ts_ns, uint16_t wire_bytes) noexcept {
    const IpPacket outer = parse_ip(ip_packet);
    if (!outer.valid) {
      ++stats_.non_ip;
      return FrameOutcome::kNotOurTraffic;
    }

    if (outer.tuple.proto == static_cast<uint8_t>(IpProto::kUdp) &&
        (outer.tuple.dst_port == cfg_.gtpu_port || outer.tuple.src_port == cfg_.gtpu_port)) {
      return process_gtpu(outer.l4_payload, ts_ns, wire_bytes);
    }

    if (cfg_.parse_diameter &&
        (outer.tuple.proto == static_cast<uint8_t>(IpProto::kTcp) ||
         outer.tuple.proto == static_cast<uint8_t>(IpProto::kSctp)) &&
        (outer.tuple.dst_port == cfg_.diameter_port ||
         outer.tuple.src_port == cfg_.diameter_port)) {
      return process_diameter(outer.l4_payload, ts_ns);
    }

    ++stats_.not_gtpu_port;
    return FrameOutcome::kNotOurTraffic;
  }

  /// Process the UDP payload of a GTP-U packet.
  FrameOutcome process_gtpu(Bytes gtpu_pdu, uint64_t ts_ns, uint16_t wire_bytes) noexcept {
    GtpuHeader h;
    const GtpuStatus st = parse_gtpu(gtpu_pdu, h);
    if (st != GtpuStatus::kOk) {
      ++stats_.gtpu_parse_errors;
      if (st == GtpuStatus::kTruncated) ++stats_.truncated_frames;
      return FrameOutcome::kParseError;
    }

    MeterEvent ev;
    ev.ts_ns = ts_ns;
    ev.teid = h.teid;
    ev.msg_type = h.msg_type;
    ev.wire_bytes = cfg_.count_wire_bytes ? wire_bytes : 0;
    if (h.has_qfi) {
      ev.qfi = h.qfi;
      ev.flags |= kFlagHasQfi;
      // TS 38.415 PDU type 1 is uplink information, 0 is downlink.
      ev.dir = static_cast<uint8_t>(h.pdu_type == 1 ? Direction::kUplink : Direction::kDownlink);
    }

    if (!h.is_gpdu()) {
      ++stats_.gtpu_control;
      ev.flags |= kFlagControlPdu;
      ev.bytes = 0;
      return push_event(ev) ? FrameOutcome::kGtpuControl : FrameOutcome::kDropped;
    }

    ++stats_.gtpu_gpdus;
    const IpPacket inner = parse_ip(h.payload);
    if (inner.valid) {
      ev.flags |= kFlagInnerParsed;
      ev.bytes = cfg_.meter_inner_ip_length ? inner.ip_total_len
                                            : static_cast<uint32_t>(h.payload.size());
      ev.ip_version = inner.tuple.ip_version;
      ev.proto = inner.tuple.proto;
      ev.src_port = inner.tuple.src_port;
      ev.dst_port = inner.tuple.dst_port;
      ev.flow_key = flow_key(inner.tuple);
      if (inner.tuple.ip_version == 4) {
        ev.src_ip = inner.tuple.src_v4();
        ev.dst_ip = inner.tuple.dst_v4();
      }
      if (inner.tuple.fragmented) ev.flags |= kFlagFragmented;
    } else {
      // Not IP inside the tunnel (or truncated): still charge the bytes, since
      // the operator carried them, but do not invent a flow.
      ++stats_.inner_parse_errors;
      ev.bytes = static_cast<uint32_t>(h.payload.size());
    }

    return push_event(ev) ? FrameOutcome::kMetered : FrameOutcome::kDropped;
  }

  /// Process a buffer holding one or more complete Diameter messages.
  FrameOutcome process_diameter(Bytes payload, uint64_t ts_ns) noexcept {
    if (payload.empty()) return FrameOutcome::kNotOurTraffic;

    size_t offset = 0;
    bool produced = false;
    while (offset + kDiameterHeaderLen <= payload.size()) {
      DiameterHeader hdr;
      GyMessage gy;
      const Bytes rest = payload.subspan(offset);
      const DiameterStatus st = parse_diameter_gy(rest, hdr, gy);
      if (st != DiameterStatus::kOk) {
        ++stats_.diameter_parse_errors;
        return produced ? FrameOutcome::kGyControl : FrameOutcome::kParseError;
      }
      ++stats_.diameter_messages;
      offset += hdr.msg_length;

      if (hdr.is_credit_control()) {
        produced = emit_gy_events(gy, ts_ns) || produced;
      }
      if (hdr.msg_length == 0) break;  // defensive: parse_diameter rejects this
    }
    return produced ? FrameOutcome::kGyControl : FrameOutcome::kNotOurTraffic;
  }

 private:
  bool push_event(const MeterEvent& ev) noexcept {
    if (meter_ring_ == nullptr) {
      ++stats_.events_pushed;
      return true;
    }
    if (meter_ring_->try_push(ev)) {
      ++stats_.events_pushed;
      return true;
    }
    // A full ring means the metering thread is behind. Drop and count: a data
    // plane that blocks here would push back onto the NIC and lose more.
    ++stats_.events_dropped;
    return false;
  }

  bool emit_gy_events(const GyMessage& gy, uint64_t ts_ns) noexcept {
    bool any = false;
    // One control event per MSCC block, so per-rating-group reports stay
    // separable downstream.
    const size_t blocks = gy.mscc_count == 0 ? 1 : gy.mscc_count;
    for (size_t i = 0; i < blocks; ++i) {
      GyEvent ev;
      ev.ts_ns = ts_ns;
      ev.imsi = gy.imsi;
      ev.has_imsi = gy.has_imsi;
      ev.is_request = gy.is_request;
      ev.cc_request_type = gy.cc_request_type;
      ev.cc_request_number = gy.cc_request_number;
      ev.result_code = gy.result_code;
      if (gy.mscc_count != 0) {
        const MsccInfo& m = gy.mscc[i];
        ev.rating_group = m.rating_group;
        ev.used_input_octets = m.used_input_octets;
        ev.used_output_octets = m.used_output_octets;
        ev.used_total_octets = m.used_total_octets;
        ev.granted_total_octets = m.granted_total_octets;
        ev.has_used = m.has_used;
        ev.has_granted = m.has_granted;
      }
      ++stats_.gy_events;
      if (gy_ring_ == nullptr || gy_ring_->try_push(ev)) {
        any = true;
      } else {
        ++stats_.gy_events_dropped;
      }
    }
    return any;
  }

  IngestConfig cfg_;
  SpscRing<MeterEvent>* meter_ring_ = nullptr;
  SpscRing<GyEvent>* gy_ring_ = nullptr;
  IngestStats stats_{};
};

}  // namespace gtpm
