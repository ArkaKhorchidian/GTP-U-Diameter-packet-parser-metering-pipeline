// SPDX-License-Identifier: MIT
//
// End-to-end benchmark: frame in, subscriber counter updated, measured as a
// latency-versus-offered-load curve.
//
// A single latency number for a pipeline is meaningless without the load it was
// taken at: below saturation you measure the pipeline, above it you measure the
// queue. This sweeps the offered rate and reports both, plus the saturation
// point where drops begin, and compares against the obvious implementation
// (mutex-guarded queue, std::unordered_map counters).
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "bench_common.hpp"
#include "gtpm/runtime.hpp"
#include "gtpm/session.hpp"
#include "gtpm/synth.hpp"

using namespace gtpm;

namespace {

constexpr size_t kSubscribers = 512;
constexpr uint32_t kBaseTeid = 0x20000;

struct Corpus {
  std::vector<synth::Buf> frames;
  std::vector<SessionSpec> sessions;
  size_t total_bytes = 0;
};

Corpus build_corpus(size_t frame_count, const std::vector<size_t>& payload_sizes) {
  Corpus corpus;
  corpus.frames.reserve(frame_count);

  for (size_t i = 0; i < kSubscribers; ++i) {
    SessionSpec s;
    s.imsi = 310150000000000ULL + i;
    s.ul_teid = kBaseTeid + static_cast<uint32_t>(i) * 2;
    s.dl_teid = kBaseTeid + static_cast<uint32_t>(i) * 2 + 1;
    s.rating_group = 10 + static_cast<uint32_t>(i % 3);
    corpus.sessions.push_back(s);
  }

  for (size_t i = 0; i < frame_count; ++i) {
    const size_t sub = i % kSubscribers;
    const bool uplink = (i % 3) == 0;
    const size_t payload = payload_sizes[i % payload_sizes.size()];

    synth::UdpSpec inner;
    inner.src_ip = synth::ipv4(10, 45, static_cast<uint8_t>(sub >> 8), static_cast<uint8_t>(sub));
    inner.dst_ip = synth::ipv4(93, 184, 216, 34);
    inner.src_port = static_cast<uint16_t>(30000 + (i % 1024));
    inner.dst_port = 443;
    const synth::Buf body = synth::filler(payload, static_cast<uint8_t>(i));
    const synth::Buf ip = synth::build_ipv4_udp(inner, Bytes(body.data(), body.size()));

    synth::GtpuSpec gs;
    gs.teid = uplink ? corpus.sessions[sub].ul_teid : corpus.sessions[sub].dl_teid;
    gs.with_qfi = (i % 4) == 0;  // a quarter of the traffic is 5G with a QFI
    gs.qfi = static_cast<uint8_t>(1 + (sub % 8));
    gs.pdu_type = uplink ? 1 : 0;
    corpus.frames.push_back(synth::build_gtpu_frame(gs, Bytes(ip.data(), ip.size())));
    corpus.total_bytes += corpus.frames.back().size();
  }
  return corpus;
}

struct RunResult {
  double offered_mpps;
  double achieved_mpps;
  double achieved_gbps;
  uint64_t dropped;
  LatencySummary latency;
  uint64_t metered_bytes;
};

RunResult run_pipeline(const Corpus& corpus, uint64_t target_pps, uint64_t frames_to_send) {
  RuntimeConfig cfg;
  cfg.meter.max_subscribers = 4096;
  cfg.meter.teid_table_capacity = 1u << 14;
  cfg.meter.flow_table_capacity = 1u << 16;
  cfg.meter.report_interval_ns = 60'000'000'000ULL;  // keep record emission out of the way
  cfg.meter.volume_threshold_bytes = 0;
  cfg.meter_ring_size = 1u << 16;
  cfg.busy_poll = true;
  cfg.measure_latency = true;
  cfg.latency_sample_every = 1;  // benchmark wants every sample, not one in eight
  cfg.publish_interval_ns = 1'000'000'000ULL;

  Runtime runtime(cfg);
  (void)runtime.install_sessions(corpus.sessions);
  runtime.start();

  const uint64_t start = now_ns();
  for (uint64_t i = 0; i < frames_to_send; ++i) {
    if (target_pps != 0) {
      const uint64_t deadline = start + i * 1'000'000'000ULL / target_pps;
      while (now_ns() < deadline) cpu_relax();
    }
    const synth::Buf& frame = corpus.frames[i % corpus.frames.size()];
    (void)runtime.ingest().process_frame(Bytes(frame.data(), frame.size()), now_ns());
  }

  // Let the metering thread finish what is in flight before reading counters.
  const uint64_t deadline = now_ns() + 2'000'000'000ULL;
  while (!runtime.meter_ring().empty_approx() && now_ns() < deadline) cpu_relax();
  const uint64_t elapsed = now_ns() - start;
  runtime.stop();

  const PipelineSnapshot snap = runtime.snapshot();
  const double seconds = static_cast<double>(elapsed) / 1e9;
  const double bytes =
      static_cast<double>(snap.ingest.frames_bytes);
  return {target_pps == 0 ? 0.0 : static_cast<double>(target_pps) / 1e6,
          static_cast<double>(frames_to_send) / seconds / 1e6,
          bytes * 8.0 / seconds / 1e9,
          snap.ingest.events_dropped,
          snap.latency,
          snap.meter.bytes};
}

/// The obvious implementation, for contrast: a mutex-guarded queue between the
/// threads and std::unordered_map counters keyed by TEID.
RunResult run_baseline(const Corpus& corpus, uint64_t target_pps, uint64_t frames_to_send) {
  struct Counters {
    uint64_t bytes = 0;
    uint64_t packets = 0;
  };

  std::queue<MeterEvent> queue;
  std::mutex mu;
  std::unordered_map<uint32_t, Counters> counters;
  Histogram hist;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> applied{0};
  uint64_t metered_bytes = 0;

  std::thread meter([&] {
    for (;;) {
      MeterEvent ev;
      bool got = false;
      {
        std::lock_guard<std::mutex> lock(mu);
        if (!queue.empty()) {
          ev = queue.front();
          queue.pop();
          got = true;
        }
      }
      if (!got) {
        if (stop.load(std::memory_order_acquire)) break;
        cpu_relax();
        continue;
      }
      Counters& c = counters[ev.teid];
      c.bytes += ev.bytes;
      ++c.packets;
      metered_bytes += ev.bytes;
      const uint64_t now = now_ns();
      if (now > ev.ts_ns) hist.record(now - ev.ts_ns);
      applied.fetch_add(1, std::memory_order_relaxed);
    }
  });

  SpscRing<MeterEvent> unused_ring(16);
  Ingest ingest(nullptr, nullptr);
  uint64_t bytes_in = 0;

  const uint64_t start = now_ns();
  for (uint64_t i = 0; i < frames_to_send; ++i) {
    if (target_pps != 0) {
      const uint64_t deadline = start + i * 1'000'000'000ULL / target_pps;
      while (now_ns() < deadline) cpu_relax();
    }
    const synth::Buf& frame = corpus.frames[i % corpus.frames.size()];
    bytes_in += frame.size();

    // Parse with the same parser, so the comparison isolates the queue and the
    // hash table rather than re-measuring parsing.
    const EthFrame eth = parse_ethernet(Bytes(frame.data(), frame.size()));
    if (!eth.valid) continue;
    const IpPacket outer = parse_ip(eth.payload);
    if (!outer.valid) continue;
    GtpuHeader h;
    if (parse_gtpu(outer.l4_payload, h) != GtpuStatus::kOk) continue;
    const IpPacket inner = parse_ip(h.payload);

    MeterEvent ev;
    ev.ts_ns = now_ns();
    ev.teid = h.teid;
    ev.bytes = inner.valid ? inner.ip_total_len : static_cast<uint32_t>(h.payload.size());
    {
      std::lock_guard<std::mutex> lock(mu);
      queue.push(ev);
    }
  }

  while (applied.load(std::memory_order_relaxed) < frames_to_send && now_ns() - start < 30'000'000'000ULL) {
    cpu_relax();
  }
  const uint64_t elapsed = now_ns() - start;
  stop.store(true, std::memory_order_release);
  meter.join();

  const double seconds = static_cast<double>(elapsed) / 1e9;
  return {target_pps == 0 ? 0.0 : static_cast<double>(target_pps) / 1e6,
          static_cast<double>(frames_to_send) / seconds / 1e6,
          static_cast<double>(bytes_in) * 8.0 / seconds / 1e9,
          0,
          summarize(hist),
          metered_bytes};
}

void print_row(const char* label, const RunResult& r) {
  char offered[24];
  if (r.offered_mpps == 0.0) {
    std::snprintf(offered, sizeof(offered), "unpaced");
  } else {
    std::snprintf(offered, sizeof(offered), "%.2f", r.offered_mpps);
  }
  std::printf("%-16s,%10s,%10.3f,%10.3f,%9llu,%8llu,%8llu,%8llu,%8llu,%8llu\n", label, offered,
              r.achieved_mpps, r.achieved_gbps, static_cast<unsigned long long>(r.dropped),
              static_cast<unsigned long long>(r.latency.p50_ns),
              static_cast<unsigned long long>(r.latency.p99_ns),
              static_cast<unsigned long long>(r.latency.p999_ns),
              static_cast<unsigned long long>(r.latency.p9999_ns),
              static_cast<unsigned long long>(r.latency.max_ns));
}

}  // namespace

int main(int argc, char** argv) {
  const uint64_t frames = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 2'000'000;
  bench::print_environment("bench_e2e");
  std::printf("# frame -> parse -> ring -> subscriber counter; latency in nanoseconds\n");
  std::printf("# %zu subscribers, mixed 64/512/1400 B payloads, a quarter carrying a 5G QFI\n",
              kSubscribers);

  const Corpus corpus = build_corpus(8192, {64, 512, 1400});
  std::printf("# corpus: %zu distinct frames, %.1f B average\n", corpus.frames.size(),
              static_cast<double>(corpus.total_bytes) / static_cast<double>(corpus.frames.size()));

  std::printf("\n%-16s,%10s,%10s,%10s,%9s,%8s,%8s,%8s,%8s,%8s\n", "pipeline", "offered",
              "achieved", "Gbps", "drops", "p50", "p99", "p99.9", "p99.99", "max");

  for (const uint64_t rate : {500'000ULL, 1'000'000ULL, 2'000'000ULL, 4'000'000ULL,
                              8'000'000ULL}) {
    print_row("gtp-meter", run_pipeline(corpus, rate, frames));
  }
  print_row("gtp-meter", run_pipeline(corpus, 0, frames));

  std::printf("\n# baseline: mutex-guarded std::queue + std::unordered_map counters\n");
  print_row("baseline", run_baseline(corpus, 2'000'000, frames / 4));
  print_row("baseline", run_baseline(corpus, 0, frames / 4));

  return bench::sink == UINT64_MAX ? 1 : 0;
}
