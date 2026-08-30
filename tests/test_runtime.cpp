// SPDX-License-Identifier: MIT
//
// Runtime tests: frames in on one thread, counters and usage records out the
// other side, with the real metering and reporter threads running.
#include "gtpm/runtime.hpp"

#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) { return Bytes(b.data(), b.size()); }

std::string temp_path() {
  char tmpl[] = "/tmp/gtpm-runtime-XXXXXX";
  const int fd = ::mkstemp(tmpl);
  if (fd >= 0) ::close(fd);
  return std::string(tmpl);
}

RuntimeConfig test_config() {
  RuntimeConfig cfg;
  cfg.meter.max_subscribers = 256;
  cfg.meter.teid_table_capacity = 1024;
  cfg.meter.flow_table_capacity = 1024;
  cfg.meter.report_interval_ns = 50'000'000ULL;
  cfg.meter.volume_threshold_bytes = 0;
  cfg.meter.sweep_period_ns = 1'000'000ULL;
  cfg.meter.sweep_fraction = 1;
  cfg.meter_ring_size = 4096;
  cfg.publish_interval_ns = 5'000'000ULL;
  cfg.busy_poll = true;
  cfg.latency_sample_every = 1;
  return cfg;
}

std::vector<SessionSpec> two_sessions() {
  std::vector<SessionSpec> out;
  for (uint64_t i = 0; i < 2; ++i) {
    SessionSpec s;
    s.imsi = 310150000000001ULL + i;
    s.ul_teid = static_cast<uint32_t>(0x1000 + i * 2);
    s.dl_teid = static_cast<uint32_t>(0x1001 + i * 2);
    s.rating_group = 10;
    out.push_back(s);
  }
  return out;
}

Buf frame_for(uint32_t teid, size_t payload) {
  synth::UdpSpec inner;
  inner.src_ip = synth::ipv4(10, 45, 0, 1);
  inner.dst_ip = synth::ipv4(1, 1, 1, 1);
  const Buf body = synth::filler(payload);
  const Buf ip = synth::build_ipv4_udp(inner, view(body));
  synth::GtpuSpec gs;
  gs.teid = teid;
  return synth::build_gtpu_frame(gs, view(ip));
}

/// Wait until `pred` holds or the deadline passes; returns whether it held.
template <typename Pred>
bool wait_for(Pred pred, int timeout_ms = 3000) {
  for (int i = 0; i < timeout_ms; ++i) {
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return pred();
}

}  // namespace

TEST("runtime/frames_reach_subscriber_counters") {
  Runtime rt(test_config());
  CHECK_EQ(rt.install_sessions(two_sessions()), size_t{2});
  rt.start();
  CHECK(rt.running());

  uint64_t expected_bytes = 0;
  for (int i = 0; i < 200; ++i) {
    const Buf f = frame_for(0x1000, 100);
    CHECK_EQ(rt.ingest().process_frame(view(f), now_ns()), FrameOutcome::kMetered);
    expected_bytes += 100 + 20 + 8;  // payload + inner IP + UDP
  }

  CHECK(wait_for([&] { return rt.snapshot().meter.events >= 200; }));
  const PipelineSnapshot snap = rt.snapshot();
  CHECK_EQ(snap.meter.events, 200ULL);
  CHECK_EQ(snap.meter.ul_bytes, expected_bytes);
  CHECK_EQ(snap.meter.unknown_teid_events, 0ULL);
  CHECK_EQ(snap.ingest.events_dropped, 0ULL);
  CHECK_GT(snap.latency.count, 0ULL);
  rt.stop();
  CHECK(!rt.running());
}

TEST("runtime/usage_records_land_in_the_ndjson_file") {
  const std::string path = temp_path();
  RuntimeConfig cfg = test_config();
  cfg.records_path = path;
  Runtime rt(cfg);
  CHECK_EQ(rt.install_sessions(two_sessions()), size_t{2});
  rt.start();

  for (int i = 0; i < 50; ++i) {
    const Buf f = frame_for(0x1000, 200);
    (void)rt.ingest().process_frame(view(f), now_ns());
  }
  CHECK(wait_for([&] { return rt.records_written() > 0; }));
  rt.stop();

  std::ifstream in(path);
  REQUIRE(in.good());
  std::string line;
  size_t lines = 0;
  bool found_imsi = false;
  uint64_t total_ul = 0;
  while (std::getline(in, line)) {
    ++lines;
    if (line.find("\"imsi\":\"310150000000001\"") != std::string::npos) found_imsi = true;
    const size_t key = line.find("\"ul_bytes\":");
    if (key != std::string::npos) {
      total_ul += std::strtoull(line.c_str() + key + 11, nullptr, 10);
    }
    CHECK_EQ(line.front(), '{');
    CHECK_EQ(line.back(), '}');
  }
  std::remove(path.c_str());

  CHECK_GT(lines, size_t{0});
  CHECK(found_imsi);
  CHECK_EQ(total_ul, 50ULL * (200 + 20 + 8));  // records are deltas that sum to the total
}

TEST("runtime/detail_snapshot_publishes_subscribers_and_flows") {
  Runtime rt(test_config());
  (void)rt.install_sessions(two_sessions());
  rt.start();

  for (int i = 0; i < 100; ++i) {
    const Buf ul = frame_for(0x1000, 64);
    const Buf dl = frame_for(0x1003, 512);
    (void)rt.ingest().process_frame(view(ul), now_ns());
    (void)rt.ingest().process_frame(view(dl), now_ns());
  }
  CHECK(wait_for([&] { return rt.snapshot().meter.events >= 200; }));

  // The detail scan is demand-driven: reading registers the interest that makes
  // the metering thread build it.
  rt.request_detail();
  CHECK(wait_for([&] {
    auto d = rt.detail();
    return d.valid() && d->subscribers.size() >= 2;
  }));

  auto detail = rt.detail();
  REQUIRE(detail.valid());
  CHECK_GE(detail->subscribers.size(), size_t{2});
  CHECK_GT(detail->top_flows.size(), size_t{0});

  bool found = false;
  for (const SubscriberSnapshot& row : detail->subscribers) {
    if (row.imsi != 310150000000001ULL) continue;
    found = true;
    CHECK_EQ(row.ul_packets, 100ULL);
    CHECK_EQ(row.ul_bytes, 100ULL * (64 + 20 + 8));
    CHECK_EQ(row.ul_teid, 0x1000u);
  }
  CHECK(found);
  rt.stop();
}

TEST("runtime/gy_events_cross_check_against_metered_bytes") {
  Runtime rt(test_config());
  (void)rt.install_sessions(two_sessions());
  rt.start();

  uint64_t metered = 0;
  for (int i = 0; i < 40; ++i) {
    const Buf f = frame_for(0x1000, 100);
    (void)rt.ingest().process_frame(view(f), now_ns());
    metered += 128;
  }

  synth::GySpec spec;
  spec.imsi = "310150000000001";
  spec.used_input = metered;
  spec.used_output = 0;
  const Buf ccr = synth::build_ccr(spec);
  synth::UdpSpec us;
  us.src_port = 40000;
  us.dst_port = kDiameterPort;
  const Buf ip = synth::build_ipv4_tcp(us, view(ccr));
  const Buf frame = synth::build_ethernet(view(ip));
  CHECK_EQ(rt.ingest().process_frame(view(frame), now_ns()), FrameOutcome::kGyControl);

  CHECK(wait_for([&] { return rt.snapshot().meter.gy_events > 0; }));
  rt.request_detail();
  CHECK(wait_for([&] {
    auto d = rt.detail();
    if (!d.valid()) return false;
    for (const SubscriberSnapshot& row : d->subscribers) {
      if (row.imsi == 310150000000001ULL && row.gy_reports > 0) return true;
    }
    return false;
  }));

  auto detail = rt.detail();
  REQUIRE(detail.valid());
  for (const SubscriberSnapshot& row : detail->subscribers) {
    if (row.imsi != 310150000000001ULL) continue;
    CHECK_EQ(row.gy_reported_octets, metered);
    CHECK_EQ(row.ul_bytes + row.dl_bytes, metered);  // pipeline agrees with Gy
  }
  rt.stop();
}

TEST("runtime/stop_drains_everything_in_flight") {
  Runtime rt(test_config());
  (void)rt.install_sessions(two_sessions());
  rt.start();

  const size_t count = 2000;
  for (size_t i = 0; i < count; ++i) {
    const Buf f = frame_for(0x1000, 64);
    (void)rt.ingest().process_frame(view(f), now_ns());
  }
  rt.stop();  // must not leave events stranded in the ring

  const PipelineSnapshot snap = rt.snapshot();
  CHECK_EQ(snap.meter.events + snap.ingest.events_dropped, count);
  CHECK_EQ(snap.meter_ring_depth, 0ULL);
}

TEST("runtime/unknown_teids_are_reported_not_metered") {
  Runtime rt(test_config());
  rt.start();  // no sessions installed at all
  for (int i = 0; i < 20; ++i) {
    const Buf f = frame_for(0x9999, 100);
    (void)rt.ingest().process_frame(view(f), now_ns());
  }
  CHECK(wait_for([&] { return rt.snapshot().meter.unknown_teid_events >= 20; }));
  const PipelineSnapshot snap = rt.snapshot();
  CHECK_EQ(snap.meter.unknown_teid_events, 20ULL);
  CHECK_EQ(snap.meter.ul_bytes, 0ULL);
  rt.stop();
}

TEST("runtime/restart_is_a_no_op_not_a_second_thread") {
  Runtime rt(test_config());
  (void)rt.install_sessions(two_sessions());
  rt.start();
  rt.start();  // idempotent
  const Buf f = frame_for(0x1000, 64);
  (void)rt.ingest().process_frame(view(f), now_ns());
  CHECK(wait_for([&] { return rt.snapshot().meter.events >= 1; }));
  rt.stop();
  rt.stop();  // also idempotent
  CHECK(!rt.running());
}

GTPM_TEST_MAIN()
