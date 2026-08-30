// SPDX-License-Identifier: MIT
//
// libFuzzer target for the Diameter base + Gy parsers, including grouped-AVP
// recursion, which is where a length-driven parser is most likely to run away.
#include <cstddef>
#include <cstdint>

#include "gtpm/diameter.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const gtpm::Bytes input(data, size);

  gtpm::DiameterHeader header;
  gtpm::GyMessage gy;
  const gtpm::DiameterStatus status = gtpm::parse_diameter_gy(input, header, gy);
  if (status != gtpm::DiameterStatus::kOk) return 0;

  if (header.msg_length > size) __builtin_trap();
  if (!header.avps.empty()) {
    if (header.avps.data() < data) __builtin_trap();
    if (header.avps.data() + header.avps.size() > data + size) __builtin_trap();
  }

  // Walk the AVPs independently: every value must also stay inside the buffer.
  (void)gtpm::for_each_avp(header.avps, [&](const gtpm::Avp& avp, int) {
    if (!avp.data.empty()) {
      if (avp.data.data() < data) __builtin_trap();
      if (avp.data.data() + avp.data.size() > data + size) __builtin_trap();
    }
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    (void)avp.as_u32(u32);
    (void)avp.as_u64(u64);
    (void)avp.as_string();
    return true;
  });
  return 0;
}
