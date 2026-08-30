// SPDX-License-Identifier: MIT
//
// Parse throughput: packets/sec/core for the GTP-U decap path and for Diameter
// Gy messages. Reports CSV on stdout so bench/results can be regenerated with a
// redirect. Timing excludes packet construction; buffers are pre-built.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "gtpm/clock.hpp"
#include "gtpm/diameter.hpp"
#include "gtpm/gtpu.hpp"
#include "gtpm/histogram.hpp"
#include "gtpm/net.hpp"
#include "gtpm/synth.hpp"

using namespace gtpm;

namespace {

/// Keep the optimiser honest: the parsed fields must be observable.
volatile uint64_t g_sink = 0;

struct Result {
  double mpps;
  double gbps;
  double ns_per_pkt;
};

Result run_gtpu(const std::vector<synth::Buf>& frames, int iterations) {
  uint64_t bytes = 0;
  for (const auto& f : frames) bytes += f.size();

  const uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int it = 0; it < iterations; ++it) {
    for (const auto& frame : frames) {
      const EthFrame eth = parse_ethernet(Bytes(frame.data(), frame.size()));
      if (!eth.valid) continue;
      const IpPacket outer = parse_ip(eth.payload);
      if (!outer.valid || outer.tuple.dst_port != kGtpuPort) continue;
      GtpuHeader h;
      if (parse_gtpu(outer.l4_payload, h) != GtpuStatus::kOk) continue;
      const IpPacket inner = parse_ip(h.payload);
      acc += h.teid + inner.tuple.src_port + h.qfi;
    }
  }
  const uint64_t t1 = now_ns();
  g_sink += acc;

  const double elapsed_s = static_cast<double>(t1 - t0) / 1e9;
  const double pkts = static_cast<double>(frames.size()) * iterations;
  const double total_bytes = static_cast<double>(bytes) * iterations;
  return {pkts / elapsed_s / 1e6, total_bytes * 8.0 / elapsed_s / 1e9,
          static_cast<double>(t1 - t0) / pkts};
}

Result run_diameter(const std::vector<synth::Buf>& msgs, int iterations) {
  uint64_t bytes = 0;
  for (const auto& m : msgs) bytes += m.size();

  const uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (int it = 0; it < iterations; ++it) {
    for (const auto& m : msgs) {
      DiameterHeader h;
      GyMessage gy;
      if (parse_diameter_gy(Bytes(m.data(), m.size()), h, gy) != DiameterStatus::kOk) continue;
      acc += gy.imsi + gy.cc_request_number + (gy.mscc_count ? gy.mscc[0].rating_group : 0);
    }
  }
  const uint64_t t1 = now_ns();
  g_sink += acc;

  const double elapsed_s = static_cast<double>(t1 - t0) / 1e9;
  const double n = static_cast<double>(msgs.size()) * iterations;
  return {n / elapsed_s / 1e6, static_cast<double>(bytes) * iterations * 8.0 / elapsed_s / 1e9,
          static_cast<double>(t1 - t0) / n};
}

/// A batch of distinct tunnels so the benchmark is not a single-entry cache hit.
std::vector<synth::Buf> make_gtpu_batch(size_t count, size_t inner_payload, bool with_qfi) {
  std::vector<synth::Buf> out;
  out.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    synth::UdpSpec inner;
    inner.src_ip = synth::ipv4(10, 45, static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i));
    inner.dst_ip = synth::ipv4(93, 184, 216, 34);
    inner.src_port = static_cast<uint16_t>(30000 + i);
    inner.dst_port = 443;
    const synth::Buf payload = synth::filler(inner_payload, static_cast<uint8_t>(i));
    const synth::Buf ip = synth::build_ipv4_udp(inner, Bytes(payload.data(), payload.size()));

    synth::GtpuSpec gs;
    gs.teid = static_cast<uint32_t>(0x10000 + i);
    gs.with_qfi = with_qfi;
    gs.qfi = static_cast<uint8_t>(i % 8 + 1);
    out.push_back(synth::build_gtpu_frame(gs, Bytes(ip.data(), ip.size())));
  }
  return out;
}

void row(const char* name, size_t frame_bytes, const Result& r) {
  std::printf("%-28s,%8zu,%10.2f,%10.3f,%10.1f\n", name, frame_bytes, r.mpps, r.gbps,
              r.ns_per_pkt);
}

}  // namespace

int main(int argc, char** argv) {
  const int iterations = argc > 1 ? std::atoi(argv[1]) : 200;
  const size_t batch = 4096;

  std::printf("# gtp-meter parse benchmark: %d iterations x %zu packets\n", iterations, batch);
  std::printf("%-28s,%8s,%10s,%10s,%10s\n", "case", "bytes", "Mpps", "Gbps", "ns/pkt");

  struct Case {
    const char* name;
    size_t inner;
    bool qfi;
  };
  const Case cases[] = {
      {"gtpu_ipv4_udp_64B", 64, false},
      {"gtpu_ipv4_udp_64B_qfi", 64, true},
      {"gtpu_ipv4_udp_1400B", 1400, false},
      {"gtpu_ipv4_udp_1400B_qfi", 1400, true},
  };

  for (const Case& c : cases) {
    const auto frames = make_gtpu_batch(batch, c.inner, c.qfi);
    (void)run_gtpu(frames, 2);  // warm caches and branch predictors
    row(c.name, frames.front().size(), run_gtpu(frames, iterations));
  }

  std::vector<synth::Buf> ccrs;
  ccrs.reserve(batch);
  for (size_t i = 0; i < batch; ++i) {
    synth::GySpec s;
    s.request_number = static_cast<uint32_t>(i);
    s.used_input = i * 1000;
    s.used_output = i * 500;
    ccrs.push_back(synth::build_ccr(s));
  }
  (void)run_diameter(ccrs, 2);
  row("diameter_gy_ccr", ccrs.front().size(), run_diameter(ccrs, iterations));

  return g_sink == UINT64_MAX ? 1 : 0;  // keep the sink alive
}
