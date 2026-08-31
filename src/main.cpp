// SPDX-License-Identifier: MIT
//
// gtp-meter: parse GTP-U and Diameter from a capture or a live interface,
// meter per subscriber, emit usage records, and expose live counters.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "gtpm/clock.hpp"
#include "gtpm/reporter.hpp"
#include "gtpm/runtime.hpp"
#include "gtpm/session.hpp"
#include "gtpm/source.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) {
  g_stop.store(true, std::memory_order_release);
}

void usage() {
  std::printf(R"(gtp-meter - GTP-U / Diameter metering pipeline

USAGE
  gtp-meter --pcap FILE [options]
  gtp-meter --interface IFACE [options]

INPUT
  --pcap FILE             replay a capture (loaded into memory first)
  --interface IFACE       live capture (needs CAP_NET_RAW / root)
  --loops N               replay the capture N times, 0 = forever (default 1)
  --max-pps N             throttle replay to N packets per second (default: full speed)

SESSIONS
  --sessions FILE         CSV session table: imsi,ul_teid,dl_teid,rating_group,msisdn,apn
  --learn-teids           create a subscriber for any unseen TEID (replay convenience)

OUTPUT
  --records FILE          append NDJSON usage records to FILE
  --http PORT             serve /metrics, /stats, /subscribers, /flows on PORT
  --http-bind ADDR        bind address for --http (default 127.0.0.1)
  --report-interval SEC   usage record interval (default 10)
  --volume-threshold MB   emit a record after this much unreported volume (default 100)
  --quiet                 suppress the periodic progress line

TUNING
  --ring-size N           meter ring entries, rounded to a power of two (default 65536)
  --ingest-cpu N          pin the ingest thread to CPU N
  --meter-cpu N           pin the metering thread to CPU N
  --reporter-cpu N        pin the reporter thread to CPU N
  --no-flows              disable the per-flow table
  --no-latency            disable end-to-end latency sampling
  --busy-poll             metering thread spins instead of sleeping when idle
                          (lower tail latency, burns a core)
  --latency-sample N      sample 1 event in N for latency (default 8)

  -h, --help              this message
)");
}

bool parse_u64_arg(const char* value, uint64_t& out) {
  if (value == nullptr || *value == '\0') return false;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(value, &end, 0);
  if (end == value || (end != nullptr && *end != '\0')) return false;
  out = parsed;
  return true;
}

struct Options {
  std::string pcap_path;
  std::string interface;
  std::string sessions_path;
  std::string records_path;
  std::string http_bind = "127.0.0.1";
  uint64_t loops = 1;
  uint64_t max_pps = 0;
  uint64_t http_port = 0;
  uint64_t report_interval_s = 10;
  uint64_t volume_threshold_mb = 100;
  uint64_t ring_size = 1u << 16;
  uint64_t latency_sample = 8;
  int ingest_cpu = -1;
  int meter_cpu = -1;
  int reporter_cpu = -1;
  bool learn_teids = false;
  bool track_flows = true;
  bool measure_latency = true;
  bool quiet = false;
  bool busy_poll = false;
};

/// Wait until `deadline_ns` with sub-millisecond accuracy. sleep_for alone has
/// millisecond granularity on most platforms, which turns a paced replay into a
/// burst generator and makes the tail latency measure the pacer, not the
/// pipeline.
void wait_until(uint64_t deadline_ns) {
  for (;;) {
    const uint64_t now = gtpm::now_ns();
    if (now >= deadline_ns) return;
    const uint64_t remaining = deadline_ns - now;
    if (remaining > 500'000ULL) {
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    } else {
      gtpm::cpu_relax();
    }
  }
}

void print_progress(const gtpm::PipelineSnapshot& s, double elapsed_s) {
  const double mpps = elapsed_s > 0 ? static_cast<double>(s.ingest.frames) / elapsed_s / 1e6 : 0.0;
  const double gbps =
      elapsed_s > 0 ? static_cast<double>(s.ingest.frames_bytes) * 8.0 / elapsed_s / 1e9 : 0.0;
  std::fprintf(stderr,
               "\r%8.1fs  %7.3f Mpps  %7.3f Gbps  metered=%llu  drops=%llu  unknown-teid=%llu  "
               "p99=%lluns   ",
               elapsed_s, mpps, gbps, static_cast<unsigned long long>(s.meter.events),
               static_cast<unsigned long long>(s.ingest.events_dropped),
               static_cast<unsigned long long>(s.meter.unknown_teid_events),
               static_cast<unsigned long long>(s.latency.p99_ns));
  std::fflush(stderr);
}

void print_summary(const gtpm::PipelineSnapshot& s, double elapsed_s, uint64_t records_written) {
  std::printf("\n");
  std::printf("=== gtp-meter summary ===\n");
  std::printf("  elapsed              %.3f s\n", elapsed_s);
  std::printf("  frames ingested      %llu (%.3f Mpps)\n",
              static_cast<unsigned long long>(s.ingest.frames),
              elapsed_s > 0 ? static_cast<double>(s.ingest.frames) / elapsed_s / 1e6 : 0.0);
  std::printf(
      "  bytes ingested       %llu (%.3f Gbps)\n",
      static_cast<unsigned long long>(s.ingest.frames_bytes),
      elapsed_s > 0 ? static_cast<double>(s.ingest.frames_bytes) * 8.0 / elapsed_s / 1e9 : 0.0);
  std::printf("  GTP-U G-PDUs         %llu\n",
              static_cast<unsigned long long>(s.ingest.gtpu_gpdus));
  std::printf("  GTP-U control        %llu\n",
              static_cast<unsigned long long>(s.ingest.gtpu_control));
  std::printf("  GTP-U parse errors   %llu\n",
              static_cast<unsigned long long>(s.ingest.gtpu_parse_errors));
  std::printf("  Diameter messages    %llu (errors %llu)\n",
              static_cast<unsigned long long>(s.ingest.diameter_messages),
              static_cast<unsigned long long>(s.ingest.diameter_parse_errors));
  std::printf("  not our traffic      %llu\n",
              static_cast<unsigned long long>(s.ingest.not_gtpu_port + s.ingest.non_ip));
  std::printf("  events dropped       %llu\n",
              static_cast<unsigned long long>(s.ingest.events_dropped));
  std::printf("  metered events       %llu\n", static_cast<unsigned long long>(s.meter.events));
  std::printf("  metered bytes        %llu (ul %llu / dl %llu)\n",
              static_cast<unsigned long long>(s.meter.bytes),
              static_cast<unsigned long long>(s.meter.ul_bytes),
              static_cast<unsigned long long>(s.meter.dl_bytes));
  std::printf("  unknown TEID         %llu events, %llu bytes\n",
              static_cast<unsigned long long>(s.meter.unknown_teid_events),
              static_cast<unsigned long long>(s.meter.unknown_teid_bytes));
  std::printf("  flows                %llu active, %llu evictions\n",
              static_cast<unsigned long long>(s.meter.flows_active),
              static_cast<unsigned long long>(s.meter.flow_evictions));
  std::printf("  usage records        %llu emitted, %llu written, %llu dropped\n",
              static_cast<unsigned long long>(s.meter.records_emitted),
              static_cast<unsigned long long>(records_written),
              static_cast<unsigned long long>(s.meter.records_dropped));
  std::printf("  Gy events            %llu (%llu octets reported)\n",
              static_cast<unsigned long long>(s.meter.gy_events),
              static_cast<unsigned long long>(s.meter.gy_reported_octets));
  std::printf("  TEID table           %llu / %llu entries, load %.3f, %.2f probes/lookup\n",
              static_cast<unsigned long long>(s.teid_table_size),
              static_cast<unsigned long long>(s.teid_table_capacity), s.teid_load_factor,
              s.teid_probes_per_lookup);
  if (s.latency.count > 0) {
    std::printf("  e2e latency (ns)     n=%llu p50=%llu p99=%llu p99.9=%llu p99.99=%llu max=%llu\n",
                static_cast<unsigned long long>(s.latency.count),
                static_cast<unsigned long long>(s.latency.p50_ns),
                static_cast<unsigned long long>(s.latency.p99_ns),
                static_cast<unsigned long long>(s.latency.p999_ns),
                static_cast<unsigned long long>(s.latency.p9999_ns),
                static_cast<unsigned long long>(s.latency.max_ns));
  }
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "gtp-meter: %s needs a value\n", name);
        std::exit(2);
      }
      return argv[++i];
    };

    if (arg == "-h" || arg == "--help") {
      usage();
      return 0;
    } else if (arg == "--pcap") {
      opt.pcap_path = next("--pcap");
    } else if (arg == "--interface") {
      opt.interface = next("--interface");
    } else if (arg == "--sessions") {
      opt.sessions_path = next("--sessions");
    } else if (arg == "--records") {
      opt.records_path = next("--records");
    } else if (arg == "--http") {
      if (!parse_u64_arg(next("--http"), opt.http_port)) return 2;
    } else if (arg == "--http-bind") {
      opt.http_bind = next("--http-bind");
    } else if (arg == "--loops") {
      if (!parse_u64_arg(next("--loops"), opt.loops)) return 2;
    } else if (arg == "--max-pps") {
      if (!parse_u64_arg(next("--max-pps"), opt.max_pps)) return 2;
    } else if (arg == "--report-interval") {
      if (!parse_u64_arg(next("--report-interval"), opt.report_interval_s)) return 2;
    } else if (arg == "--volume-threshold") {
      if (!parse_u64_arg(next("--volume-threshold"), opt.volume_threshold_mb)) return 2;
    } else if (arg == "--ring-size") {
      if (!parse_u64_arg(next("--ring-size"), opt.ring_size)) return 2;
    } else if (arg == "--latency-sample") {
      if (!parse_u64_arg(next("--latency-sample"), opt.latency_sample)) return 2;
    } else if (arg == "--ingest-cpu") {
      opt.ingest_cpu = std::atoi(next("--ingest-cpu"));
    } else if (arg == "--meter-cpu") {
      opt.meter_cpu = std::atoi(next("--meter-cpu"));
    } else if (arg == "--reporter-cpu") {
      opt.reporter_cpu = std::atoi(next("--reporter-cpu"));
    } else if (arg == "--learn-teids") {
      opt.learn_teids = true;
    } else if (arg == "--no-flows") {
      opt.track_flows = false;
    } else if (arg == "--no-latency") {
      opt.measure_latency = false;
    } else if (arg == "--busy-poll") {
      opt.busy_poll = true;
    } else if (arg == "--quiet") {
      opt.quiet = true;
    } else {
      std::fprintf(stderr, "gtp-meter: unknown option %s (try --help)\n", arg.c_str());
      return 2;
    }
  }

  if (opt.pcap_path.empty() == opt.interface.empty()) {
    std::fprintf(stderr, "gtp-meter: give exactly one of --pcap or --interface\n");
    usage();
    return 2;
  }

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  // --- source -------------------------------------------------------------
  std::unique_ptr<gtpm::PacketSource> source;
  std::string error;
  if (!opt.pcap_path.empty()) {
    gtpm::PcapReplaySource::Options popt;
    popt.loops = static_cast<uint32_t>(opt.loops);
    auto replay = gtpm::PcapReplaySource::open(opt.pcap_path, popt, error);
    if (replay == nullptr) {
      std::fprintf(stderr, "gtp-meter: %s\n", error.c_str());
      return 1;
    }
    std::fprintf(stderr, "gtp-meter: loaded %zu packets (%zu bytes, link type %u) from %s\n",
                 replay->file().packets().size(), replay->file().total_bytes(), replay->link_type(),
                 opt.pcap_path.c_str());
    source = std::move(replay);
  } else {
    gtpm::LiveCaptureSource::Options lopt;
    lopt.interface = opt.interface;
    auto live = gtpm::LiveCaptureSource::open(lopt, error);
    if (live == nullptr) {
      std::fprintf(stderr, "gtp-meter: %s\n", error.c_str());
      return 1;
    }
    std::fprintf(stderr, "gtp-meter: capturing on %s\n", opt.interface.c_str());
    source = std::move(live);
  }

  // --- runtime ------------------------------------------------------------
  gtpm::RuntimeConfig cfg;
  cfg.meter.report_interval_ns = opt.report_interval_s * 1'000'000'000ULL;
  cfg.meter.volume_threshold_bytes = opt.volume_threshold_mb << 20;
  cfg.meter.learn_unknown_teids = opt.learn_teids;
  cfg.meter.track_flows = opt.track_flows;
  cfg.meter_ring_size = opt.ring_size;
  cfg.records_path = opt.records_path;
  cfg.ingest_cpu = opt.ingest_cpu;
  cfg.meter_cpu = opt.meter_cpu;
  cfg.reporter_cpu = opt.reporter_cpu;
  cfg.measure_latency = opt.measure_latency;
  cfg.busy_poll = opt.busy_poll;
  cfg.latency_sample_every =
      static_cast<uint32_t>(opt.latency_sample == 0 ? 1 : opt.latency_sample);

  gtpm::Runtime runtime(cfg);

  if (!opt.sessions_path.empty()) {
    const gtpm::SessionLoadResult sessions = gtpm::load_sessions_csv(opt.sessions_path);
    if (!sessions.ok()) {
      std::fprintf(stderr, "gtp-meter: %s\n", sessions.error.c_str());
      return 1;
    }
    const size_t installed = runtime.install_sessions(sessions.sessions);
    std::fprintf(stderr, "gtp-meter: installed %zu sessions (%zu malformed rows skipped)\n",
                 installed, sessions.skipped_lines);
  } else if (!opt.learn_teids) {
    std::fprintf(stderr,
                 "gtp-meter: no --sessions given; every TEID will count as unknown. "
                 "Pass --learn-teids to meter them anyway.\n");
  }

  runtime.start();

  std::unique_ptr<gtpm::HttpReporter> http;
  if (opt.http_port != 0) {
    http = std::make_unique<gtpm::HttpReporter>(runtime, static_cast<uint16_t>(opt.http_port),
                                                opt.http_bind);
    if (!http->start(error)) {
      std::fprintf(stderr, "gtp-meter: %s\n", error.c_str());
      runtime.stop();
      return 1;
    }
    std::fprintf(stderr, "gtp-meter: metrics on http://%s:%u/metrics\n", opt.http_bind.c_str(),
                 http->port());
  }

  // --- ingest loop (this thread) ------------------------------------------
  // A paced replay uses a smaller batch: 256 packets released at once is a
  // burst, and a burst measures queueing, not the pipeline.
  const size_t batch_size = opt.max_pps != 0 ? 32 : 256;
  std::vector<gtpm::PcapPacket> batch(batch_size);
  const uint64_t started = gtpm::now_ns();
  uint64_t last_progress = started;
  uint64_t pacing_budget_start = started;
  uint64_t pacing_packets = 0;

  while (!g_stop.load(std::memory_order_acquire)) {
    const size_t n = source->next_batch(batch.data(), batch.size());
    if (n == 0) {
      if (source->exhausted()) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }

    for (size_t i = 0; i < n; ++i) {
      const gtpm::LinkLayer link = gtpm::strip_link_layer(source->link_type(), batch[i].data);
      if (!link.valid) continue;
      // Live capture timestamps come from the kernel; replay restamps with the
      // local clock so end-to-end latency measures this pipeline, not the age
      // of the capture file.
      const uint64_t ts = opt.pcap_path.empty() ? batch[i].ts_ns : gtpm::now_ns();
      if (link.is_ethernet) {
        (void)runtime.ingest().process_frame(link.payload, ts);
      } else {
        (void)runtime.ingest().process_ip(link.payload, ts,
                                          static_cast<uint16_t>(link.payload.size()));
      }
    }

    if (opt.max_pps != 0) {
      pacing_packets += n;
      wait_until(pacing_budget_start + pacing_packets * 1'000'000'000ULL / opt.max_pps);
      if (gtpm::now_ns() - pacing_budget_start > 1'000'000'000ULL) {
        pacing_budget_start = gtpm::now_ns();
        pacing_packets = 0;
      }
    }

    const uint64_t now = gtpm::now_ns();
    if (!opt.quiet && now - last_progress > 500'000'000ULL) {
      last_progress = now;
      print_progress(runtime.snapshot(), static_cast<double>(now - started) / 1e9);
    }
  }

  // Let the metering thread catch up on whatever is still in flight before we
  // read the final numbers.
  const uint64_t drain_deadline = gtpm::now_ns() + 2'000'000'000ULL;
  while (!runtime.meter_ring().empty_approx() && gtpm::now_ns() < drain_deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  const double elapsed_s = static_cast<double>(gtpm::now_ns() - started) / 1e9;
  runtime.stop();
  if (http != nullptr) http->stop();

  print_summary(runtime.snapshot(), elapsed_s, runtime.records_written());
  return 0;
}
