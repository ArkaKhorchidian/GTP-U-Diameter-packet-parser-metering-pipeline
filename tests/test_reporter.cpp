// SPDX-License-Identifier: MIT
//
// Reporter tests: request parsing, routing, and the exposition formats. The
// rendering functions are pure, so most of this needs no socket; one test does
// bind a port to prove the server actually serves.
#include "gtpm/reporter.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <thread>

#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;

namespace {

PipelineSnapshot sample_snapshot() {
  PipelineSnapshot s;
  s.ingest.frames = 1000;
  s.ingest.frames_bytes = 700000;
  s.ingest.gtpu_gpdus = 900;
  s.ingest.events_dropped = 3;
  s.ingest.diameter_messages = 12;
  s.meter.events = 900;
  s.meter.bytes = 650000;
  s.meter.ul_bytes = 250000;
  s.meter.dl_bytes = 400000;
  s.meter.ul_packets = 300;
  s.meter.dl_packets = 600;
  s.meter.unknown_teid_events = 5;
  s.meter.flows_active = 42;
  s.meter.records_emitted = 7;
  s.meter.gy_events = 4;
  s.meter_ring_depth = 16;
  s.meter_ring_capacity = 65536;
  s.teid_load_factor = 0.25;
  s.teid_probes_per_lookup = 1.02;
  s.uptime_ns = 5'000'000'000ULL;
  s.latency.count = 100;
  s.latency.p50_ns = 120;
  s.latency.p99_ns = 900;
  s.latency.p999_ns = 4000;
  s.latency.max_ns = 9000;
  return s;
}

DetailSnapshot sample_detail() {
  DetailSnapshot d;
  d.total_subscribers = 2;
  SubscriberSnapshot a;
  a.imsi = 310150000000001ULL;
  a.sub_idx = 0;
  a.ul_teid = 0x1000;
  a.dl_teid = 0x1001;
  a.ul_bytes = 5000;
  a.dl_bytes = 9000;
  a.ul_packets = 50;
  a.dl_packets = 90;
  a.bucket_ids[0] = 10;
  a.bucket_bytes[0] = 14000;
  a.gy_reported_octets = 13900;
  a.gy_reports = 2;
  d.subscribers.push_back(a);

  SubscriberSnapshot b = a;
  b.imsi = 310150000000002ULL;
  b.sub_idx = 1;
  b.ul_bytes = 100;
  b.dl_bytes = 200;
  b.bucket_ids[0] = kQfiBucketTag | 9;
  b.bucket_bytes[0] = 300;
  d.subscribers.push_back(b);

  FlowEntry f;
  f.key = 1;
  f.teid = 0x1000;
  f.src_ip = synth::ipv4(10, 45, 0, 1);
  f.dst_ip = synth::ipv4(1, 1, 1, 1);
  f.src_port = 40000;
  f.dst_port = 443;
  f.proto = 6;
  f.ip_version = 4;
  f.bytes = 14000;
  f.packets = 140;
  f.dir = static_cast<uint8_t>(Direction::kUplink);
  d.top_flows.push_back(f);
  return d;
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

}  // namespace

TEST("reporter/parses_request_lines") {
  const HttpRequest a = parse_request_line("GET /metrics HTTP/1.1");
  CHECK(a.valid);
  CHECK_EQ(a.method, std::string("GET"));
  CHECK_EQ(a.path, std::string("/metrics"));
  CHECK(a.query.empty());

  const HttpRequest b = parse_request_line("GET /subscribers?limit=5&x=1 HTTP/1.1");
  CHECK(b.valid);
  CHECK_EQ(b.path, std::string("/subscribers"));
  CHECK_EQ(b.query, std::string("limit=5&x=1"));

  CHECK(!parse_request_line("").valid);
  CHECK(!parse_request_line("garbage").valid);
  CHECK(!parse_request_line("GET notapath HTTP/1.1").valid);
}

TEST("reporter/query_params") {
  CHECK_EQ(query_param("limit=5", "limit", 99), 5ULL);
  CHECK_EQ(query_param("a=1&limit=25&b=2", "limit", 99), 25ULL);
  CHECK_EQ(query_param("a=1", "limit", 99), 99ULL);
  CHECK_EQ(query_param("limit=abc", "limit", 99), 99ULL);
  CHECK_EQ(query_param("limit=", "limit", 99), 99ULL);
  CHECK_EQ(query_param("", "limit", 7), 7ULL);
}

TEST("reporter/prometheus_exposition") {
  const std::string text = render_prometheus(sample_snapshot());
  CHECK(contains(text, "# TYPE gtpm_meter_events_total counter"));
  CHECK(contains(text, "gtpm_meter_events_total 900"));
  CHECK(contains(text, "gtpm_meter_direction_bytes_total{direction=\"uplink\"} 250000"));
  CHECK(contains(text, "gtpm_meter_direction_bytes_total{direction=\"downlink\"} 400000"));
  CHECK(contains(text, "gtpm_ingest_events_dropped_total 3"));
  CHECK(contains(text, "gtpm_e2e_latency_ns{quantile=\"0.99\"} 900"));
  CHECK(contains(text, "gtpm_teid_probes_per_lookup 1.02"));
  // Every HELP must be followed by a TYPE: broken exposition breaks scrapes.
  size_t help_count = 0;
  size_t type_count = 0;
  for (size_t pos = 0; (pos = text.find("# HELP ", pos)) != std::string::npos; ++pos) ++help_count;
  for (size_t pos = 0; (pos = text.find("# TYPE ", pos)) != std::string::npos; ++pos) ++type_count;
  CHECK_EQ(help_count, type_count);
}

TEST("reporter/per_subscriber_series_are_opt_in") {
  const DetailSnapshot detail = sample_detail();
  const std::string without = render_prometheus(sample_snapshot(), &detail, 0);
  CHECK(!contains(without, "gtpm_subscriber_bytes_total"));

  const std::string with = render_prometheus(sample_snapshot(), &detail, 1);
  CHECK(contains(with, "gtpm_subscriber_bytes_total{imsi=\"310150000000001\""));
  // Capped at the requested count, not the whole table.
  CHECK(!contains(with, "imsi=\"310150000000002\""));
}

TEST("reporter/stats_json") {
  const std::string json = render_stats_json(sample_snapshot());
  CHECK_EQ(json.front(), '{');
  CHECK_EQ(json.back(), '}');
  CHECK(contains(json, "\"events\":900"));
  CHECK(contains(json, "\"ul_bytes\":250000"));
  CHECK(contains(json, "\"p99\":900"));
  CHECK(contains(json, "\"meter_capacity\":65536"));
}

TEST("reporter/subscribers_json") {
  const DetailSnapshot detail = sample_detail();
  const std::string all = render_subscribers_json(detail, 10);
  CHECK(contains(all, "\"imsi\":\"310150000000001\""));
  CHECK(contains(all, "\"imsi\":\"310150000000002\""));
  CHECK(contains(all, "\"total\":2"));
  CHECK(contains(all, "\"kind\":\"rating-group\",\"id\":10"));
  CHECK(contains(all, "\"kind\":\"qfi\",\"id\":9"));

  const std::string limited = render_subscribers_json(detail, 1);
  CHECK(contains(limited, "\"returned\":1"));
  CHECK(!contains(limited, "310150000000002"));

  const std::string one = render_subscriber_json(detail, 310150000000002ULL);
  CHECK(contains(one, "\"imsi\":\"310150000000002\""));
  CHECK(render_subscriber_json(detail, 999).empty());
}

TEST("reporter/flows_json") {
  const std::string json = render_flows_json(sample_detail(), 10);
  CHECK(contains(json, "\"src\":\"10.45.0.1\""));
  CHECK(contains(json, "\"dst\":\"1.1.1.1\""));
  CHECK(contains(json, "\"dst_port\":443"));
  CHECK(contains(json, "\"direction\":\"uplink\""));
  CHECK(contains(json, "\"bytes\":14000"));
}

TEST("reporter/routes") {
  RuntimeConfig cfg;
  cfg.meter.max_subscribers = 64;
  cfg.meter.teid_table_capacity = 256;
  cfg.meter.flow_table_capacity = 256;
  Runtime rt(cfg);

  CHECK_EQ(route(rt, parse_request_line("GET /healthz HTTP/1.1")).status, 200);
  CHECK_EQ(route(rt, parse_request_line("GET /metrics HTTP/1.1")).status, 200);
  CHECK_EQ(route(rt, parse_request_line("GET /stats HTTP/1.1")).status, 200);
  CHECK_EQ(route(rt, parse_request_line("GET /nope HTTP/1.1")).status, 404);
  CHECK_EQ(route(rt, parse_request_line("POST /metrics HTTP/1.1")).status, 405);
  CHECK_EQ(route(rt, parse_request_line("garbage")).status, 400);
  CHECK_EQ(route(rt, parse_request_line("GET /subscribers/notanimsi HTTP/1.1")).status, 400);
  // No snapshot published yet: say so rather than serving an empty table as
  // though it were the truth.
  CHECK_EQ(route(rt, parse_request_line("GET /subscribers HTTP/1.1")).status, 503);

  const HttpResponse stats = route(rt, parse_request_line("GET /stats HTTP/1.1"));
  CHECK_EQ(stats.content_type, std::string("application/json"));
}

TEST("reporter/serves_over_a_real_socket") {
  RuntimeConfig cfg;
  cfg.meter.max_subscribers = 64;
  cfg.meter.teid_table_capacity = 256;
  cfg.meter.flow_table_capacity = 256;
  cfg.publish_interval_ns = 1'000'000ULL;
  cfg.busy_poll = true;
  Runtime rt(cfg);
  rt.start();

  HttpReporter server(rt, 0);  // port 0: let the OS pick, so tests never collide
  std::string error;
  REQUIRE(server.start(error));
  CHECK(error.empty());
  CHECK_GT(server.port(), 0);

  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server.port());
  REQUIRE_EQ(::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
  REQUIRE_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

  const std::string request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
  CHECK_EQ(::send(fd, request.data(), request.size(), 0), static_cast<ssize_t>(request.size()));

  std::string response;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);
  server.stop();
  rt.stop();

  CHECK(contains(response, "HTTP/1.1 200 OK"));
  CHECK(contains(response, "Content-Type: text/plain"));
  CHECK(contains(response, "gtpm_meter_events_total"));
  CHECK_EQ(server.requests_served(), 1ULL);
}

GTPM_TEST_MAIN()
