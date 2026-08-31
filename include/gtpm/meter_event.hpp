// SPDX-License-Identifier: MIT
//
// The POD that crosses the ring from the parser thread to the metering thread.
//
// Exactly one cache line. Everything the metering thread needs to update state
// is here, so it never dereferences back into the packet buffer — which by then
// may have been overwritten by the NIC.
#pragma once

#include <cstdint>

#include "gtpm/spsc_ring.hpp"  // kCacheLine

namespace gtpm {

enum class Direction : uint8_t {
  kUplink = 0,    ///< UE -> network (TEID allocated by the UPF/SGW-U)
  kDownlink = 1,  ///< network -> UE (TEID allocated by the gNB/eNB)
  kUnknown = 2,
};

[[nodiscard]] constexpr const char* to_string(Direction d) noexcept {
  switch (d) {
    case Direction::kUplink: return "uplink";
    case Direction::kDownlink: return "downlink";
    case Direction::kUnknown: return "unknown";
  }
  return "unknown";
}

/// MeterEvent::flags bits.
enum MeterFlags : uint8_t {
  kFlagHasQfi = 1u << 0,
  kFlagFragmented = 1u << 1,
  kFlagInnerParsed = 1u << 2,
  kFlagControlPdu = 1u << 3,  ///< Echo / Error Indication / End Marker
};

struct alignas(64) MeterEvent {
  uint64_t ts_ns = 0;     ///< ingest timestamp; end-to-end latency starts here
  uint64_t flow_key = 0;  ///< hash of the inner 5-tuple, 0 when not IP
  uint32_t teid = 0;      ///< metering key
  uint32_t bytes = 0;     ///< inner IP bytes attributed to the subscriber
  uint32_t src_ip = 0;    ///< inner IPv4 source, 0 for IPv6
  uint32_t dst_ip = 0;    ///< inner IPv4 destination, 0 for IPv6
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t wire_bytes = 0;  ///< captured frame length, for link-rate accounting
  uint8_t proto = 0;
  uint8_t qfi = 0;
  uint8_t dir = static_cast<uint8_t>(Direction::kUnknown);
  uint8_t msg_type = 0;
  uint8_t ip_version = 0;
  uint8_t flags = 0;
  uint8_t _pad[20] = {};

  [[nodiscard]] bool has_qfi() const noexcept { return (flags & kFlagHasQfi) != 0; }
  [[nodiscard]] bool inner_parsed() const noexcept { return (flags & kFlagInnerParsed) != 0; }
};

static_assert(sizeof(MeterEvent) == 64, "MeterEvent must be exactly one cache line");
static_assert(alignof(MeterEvent) == 64, "MeterEvent must be cache-line aligned");

/// Charging control event lifted from a Gy CCR/CCA — one per MSCC block.
///
/// Diameter is deliberately off the fast path: these arrive on a separate,
/// low-rate control ring so a burst of charging traffic can never delay or
/// evict the user-plane metering state.
struct GyEvent {
  uint64_t ts_ns = 0;
  uint64_t imsi = 0;
  uint64_t used_input_octets = 0;
  uint64_t used_output_octets = 0;
  uint64_t used_total_octets = 0;
  uint64_t granted_total_octets = 0;
  uint32_t rating_group = 0;
  uint32_t cc_request_type = 0;
  uint32_t cc_request_number = 0;
  uint32_t result_code = 0;
  bool is_request = false;
  bool has_used = false;
  bool has_granted = false;
  bool has_imsi = false;
};

static_assert(sizeof(GyEvent) <= 128, "GyEvent should stay small enough to copy cheaply");

}  // namespace gtpm
