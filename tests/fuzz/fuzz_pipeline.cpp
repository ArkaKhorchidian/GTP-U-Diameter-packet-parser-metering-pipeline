// SPDX-License-Identifier: MIT
//
// libFuzzer target for the whole ingest path: link layer, outer IP, GTP-U,
// inner IP, Diameter, and the metering engine that consumes the events.
//
// This is the one that matters most — it fuzzes the composition, where a parser
// that is individually safe can still hand a downstream stage something it does
// not expect.
#include <cstddef>
#include <cstdint>
#include <memory>

#include "gtpm/meter.hpp"
#include "gtpm/pipeline.hpp"
#include "gtpm/session.hpp"

namespace {

struct Harness {
  gtpm::SpscRing<gtpm::MeterEvent> meter_ring{4096};
  gtpm::SpscRing<gtpm::GyEvent> gy_ring{1024};
  gtpm::Ingest ingest{&meter_ring, &gy_ring};
  std::unique_ptr<gtpm::MeterEngine> engine;

  Harness() {
    gtpm::MeterConfig cfg;
    cfg.max_subscribers = 512;
    cfg.teid_table_capacity = 2048;
    cfg.flow_table_capacity = 2048;
    cfg.learn_unknown_teids = true;  // exercise the metering state, not just parsing
    engine = std::make_unique<gtpm::MeterEngine>(cfg);

    for (uint64_t i = 0; i < 8; ++i) {
      gtpm::SessionSpec s;
      s.imsi = 310150000000000ULL + i;
      s.ul_teid = static_cast<uint32_t>(0x1000 + i * 2);
      s.dl_teid = static_cast<uint32_t>(0x1001 + i * 2);
      s.rating_group = static_cast<uint32_t>(10 + i);
      (void)engine->install_session(s, 0);
    }
  }
};

Harness& harness() {
  static Harness h;
  return h;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Harness& h = harness();
  (void)h.ingest.process_frame(gtpm::Bytes(data, size), 1'000'000 + size);

  gtpm::MeterEvent ev;
  while (h.meter_ring.try_pop(ev)) h.engine->apply(ev);
  gtpm::GyEvent gy;
  while (h.gy_ring.try_pop(gy)) h.engine->apply_gy(gy);

  h.engine->poll(2'000'000 + size);

  // Also feed the buffer in as a bare IP packet and as a raw Diameter stream,
  // so the fuzzer reaches those entry points without needing valid framing.
  (void)h.ingest.process_ip(gtpm::Bytes(data, size), 3'000'000, static_cast<uint16_t>(size));
  (void)h.ingest.process_diameter(gtpm::Bytes(data, size), 4'000'000);
  while (h.meter_ring.try_pop(ev)) {
  }
  while (h.gy_ring.try_pop(gy)) {
  }
  return 0;
}
