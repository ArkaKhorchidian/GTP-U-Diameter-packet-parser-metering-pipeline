// SPDX-License-Identifier: MIT
//
// libFuzzer target for the GTP-U parser.
//
// Crash-free on arbitrary bytes is table stakes for a data plane: the input is
// attacker-controlled by definition. Run under ASan+UBSan so a read one byte
// past a span is a failure, not a silent success.
#include <cstddef>
#include <cstdint>

#include "gtpm/gtpu.hpp"
#include "gtpm/net.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const gtpm::Bytes input(data, size);

  gtpm::GtpuHeader header;
  const gtpm::GtpuStatus status = gtpm::parse_gtpu(input, header);
  if (status != gtpm::GtpuStatus::kOk) return 0;

  // Every successful parse must produce a payload view inside the input.
  if (header.payload.data() < data) __builtin_trap();
  if (header.payload.data() + header.payload.size() > data + size) __builtin_trap();
  if (header.header_len > size) __builtin_trap();

  // Then keep going the way the pipeline does: parse the encapsulated packet.
  const gtpm::IpPacket inner = gtpm::parse_ip(header.payload);
  if (inner.valid && !inner.l4_payload.empty()) {
    if (inner.l4_payload.data() < data) __builtin_trap();
    if (inner.l4_payload.data() + inner.l4_payload.size() > data + size) __builtin_trap();
    (void)gtpm::flow_key(inner.tuple);
  }
  return 0;
}
