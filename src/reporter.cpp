// SPDX-License-Identifier: MIT
#include "gtpm/reporter.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "gtpm/net.hpp"

namespace gtpm {

namespace {

void append(std::string& out, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

void append(std::string& out, const char* fmt, ...) {
  char buf[1024];
  va_list args;
  va_start(args, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  if (n > 0)
    out.append(buf, static_cast<size_t>(
                        n < static_cast<int>(sizeof(buf)) ? n : static_cast<int>(sizeof(buf)) - 1));
}

void counter(std::string& out, const char* name, const char* help, unsigned long long value) {
  append(out, "# HELP %s %s\n# TYPE %s counter\n%s %llu\n", name, help, name, name, value);
}

void gauge(std::string& out, const char* name, const char* help, double value) {
  append(out, "# HELP %s %s\n# TYPE %s gauge\n%s %.6g\n", name, help, name, name, value);
}

std::string ip_string(uint32_t addr, uint8_t version) {
  IpAddr a{};
  store_be32(a.data(), addr);
  char buf[64];
  return format_ip(a, version == 0 ? 4 : version, buf, sizeof(buf));
}

const char* status_text(int status) {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 503: return "Service Unavailable";
    default: return "Unknown";
  }
}

}  // namespace

std::string render_prometheus(const PipelineSnapshot& s, const DetailSnapshot* detail,
                              size_t subscriber_series) {
  std::string out;
  out.reserve(4096);

  counter(out, "gtpm_ingest_frames_total", "Frames handed to the ingest path", s.ingest.frames);
  counter(out, "gtpm_ingest_frame_bytes_total", "Bytes handed to the ingest path",
          s.ingest.frames_bytes);
  counter(out, "gtpm_ingest_gpdus_total", "GTP-U G-PDUs parsed", s.ingest.gtpu_gpdus);
  counter(out, "gtpm_ingest_gtpu_control_total", "GTP-U control PDUs (echo, end marker)",
          s.ingest.gtpu_control);
  counter(out, "gtpm_ingest_parse_errors_total", "GTP-U PDUs rejected by the parser",
          s.ingest.gtpu_parse_errors);
  counter(out, "gtpm_ingest_inner_parse_errors_total", "Tunnelled payloads that were not IP",
          s.ingest.inner_parse_errors);
  counter(out, "gtpm_ingest_not_our_traffic_total", "Frames that were neither GTP-U nor Diameter",
          s.ingest.not_gtpu_port + s.ingest.non_ip);
  counter(out, "gtpm_ingest_events_pushed_total", "Meter events published to the ring",
          s.ingest.events_pushed);
  counter(out, "gtpm_ingest_events_dropped_total",
          "Meter events dropped because the metering ring was full", s.ingest.events_dropped);
  counter(out, "gtpm_diameter_messages_total", "Diameter messages parsed",
          s.ingest.diameter_messages);
  counter(out, "gtpm_diameter_parse_errors_total", "Diameter messages rejected",
          s.ingest.diameter_parse_errors);

  counter(out, "gtpm_meter_events_total", "Events applied by the metering thread", s.meter.events);
  counter(out, "gtpm_meter_bytes_total", "Bytes metered", s.meter.bytes);
  append(out,
         "# HELP gtpm_meter_direction_bytes_total Metered bytes by direction\n"
         "# TYPE gtpm_meter_direction_bytes_total counter\n"
         "gtpm_meter_direction_bytes_total{direction=\"uplink\"} %llu\n"
         "gtpm_meter_direction_bytes_total{direction=\"downlink\"} %llu\n",
         static_cast<unsigned long long>(s.meter.ul_bytes),
         static_cast<unsigned long long>(s.meter.dl_bytes));
  append(out,
         "# HELP gtpm_meter_direction_packets_total Metered packets by direction\n"
         "# TYPE gtpm_meter_direction_packets_total counter\n"
         "gtpm_meter_direction_packets_total{direction=\"uplink\"} %llu\n"
         "gtpm_meter_direction_packets_total{direction=\"downlink\"} %llu\n",
         static_cast<unsigned long long>(s.meter.ul_packets),
         static_cast<unsigned long long>(s.meter.dl_packets));
  counter(out, "gtpm_teid_bind_failures_total",
          "Sessions that could not be bound because the TEID table is full",
          s.meter.teid_bind_failures);
  counter(out, "gtpm_meter_unknown_teid_events_total",
          "Packets on a TEID with no installed session", s.meter.unknown_teid_events);
  counter(out, "gtpm_meter_unknown_teid_bytes_total", "Bytes on a TEID with no installed session",
          s.meter.unknown_teid_bytes);
  counter(out, "gtpm_meter_flow_inserts_total", "Flow table insertions", s.meter.flow_inserts);
  counter(out, "gtpm_meter_flow_evictions_total", "Flow table LRU evictions",
          s.meter.flow_evictions);
  counter(out, "gtpm_usage_records_emitted_total", "Usage records emitted by the meter",
          s.meter.records_emitted);
  counter(out, "gtpm_usage_records_dropped_total",
          "Usage records dropped because the reporter was behind", s.meter.records_dropped);
  counter(out, "gtpm_usage_records_written_total", "Usage records written to disk",
          s.records_written);
  counter(out, "gtpm_gy_events_total", "Gy charging events applied", s.meter.gy_events);
  counter(out, "gtpm_gy_reported_octets_total", "Octets reported by the charging plane",
          s.meter.gy_reported_octets);

  gauge(out, "gtpm_subscribers_active", "Sessions installed in the metering table",
        static_cast<double>(s.meter.subscribers_installed + s.meter.subscribers_learned -
                            s.meter.sessions_released));
  gauge(out, "gtpm_flows_active", "Entries in the flow table",
        static_cast<double>(s.meter.flows_active));
  gauge(out, "gtpm_meter_ring_depth", "Meter ring occupancy",
        static_cast<double>(s.meter_ring_depth));
  gauge(out, "gtpm_meter_ring_capacity", "Meter ring capacity",
        static_cast<double>(s.meter_ring_capacity));
  gauge(out, "gtpm_meter_ring_utilization", "Meter ring occupancy as a fraction of capacity",
        s.meter_ring_capacity == 0
            ? 0.0
            : static_cast<double>(s.meter_ring_depth) / static_cast<double>(s.meter_ring_capacity));
  gauge(out, "gtpm_teid_table_load_factor", "TEID hash table load factor", s.teid_load_factor);
  gauge(out, "gtpm_teid_probes_per_lookup", "Average probes per TEID lookup",
        s.teid_probes_per_lookup);
  gauge(out, "gtpm_uptime_seconds", "Pipeline uptime", static_cast<double>(s.uptime_ns) / 1e9);

  append(out,
         "# HELP gtpm_e2e_latency_ns Ingest-to-counter latency, sampled\n"
         "# TYPE gtpm_e2e_latency_ns summary\n"
         "gtpm_e2e_latency_ns{quantile=\"0.5\"} %llu\n"
         "gtpm_e2e_latency_ns{quantile=\"0.9\"} %llu\n"
         "gtpm_e2e_latency_ns{quantile=\"0.99\"} %llu\n"
         "gtpm_e2e_latency_ns{quantile=\"0.999\"} %llu\n"
         "gtpm_e2e_latency_ns{quantile=\"0.9999\"} %llu\n"
         "gtpm_e2e_latency_ns_max %llu\n"
         "gtpm_e2e_latency_ns_count %llu\n",
         static_cast<unsigned long long>(s.latency.p50_ns),
         static_cast<unsigned long long>(s.latency.p90_ns),
         static_cast<unsigned long long>(s.latency.p99_ns),
         static_cast<unsigned long long>(s.latency.p999_ns),
         static_cast<unsigned long long>(s.latency.p9999_ns),
         static_cast<unsigned long long>(s.latency.max_ns),
         static_cast<unsigned long long>(s.latency.count));

  if (detail != nullptr && subscriber_series > 0) {
    append(out,
           "# HELP gtpm_subscriber_bytes_total Per-subscriber metered bytes (top talkers only)\n"
           "# TYPE gtpm_subscriber_bytes_total counter\n");
    const size_t n = std::min(subscriber_series, detail->subscribers.size());
    for (size_t i = 0; i < n; ++i) {
      const SubscriberSnapshot& row = detail->subscribers[i];
      append(
          out,
          "gtpm_subscriber_bytes_total{imsi=\"%llu\",direction=\"uplink\"} %llu\n"
          "gtpm_subscriber_bytes_total{imsi=\"%llu\",direction=\"downlink\"} %llu\n",
          static_cast<unsigned long long>(row.imsi), static_cast<unsigned long long>(row.ul_bytes),
          static_cast<unsigned long long>(row.imsi), static_cast<unsigned long long>(row.dl_bytes));
    }
  }
  return out;
}

std::string render_stats_json(const PipelineSnapshot& s) {
  std::string out;
  out.reserve(1536);
  append(out,
         "{\"uptime_s\":%.3f,\"published_at\":\"%s\","
         "\"ingest\":{\"frames\":%llu,\"bytes\":%llu,\"gpdus\":%llu,\"control\":%llu,"
         "\"parse_errors\":%llu,\"events_pushed\":%llu,\"events_dropped\":%llu,"
         "\"diameter_messages\":%llu},"
         "\"meter\":{\"events\":%llu,\"bytes\":%llu,\"ul_bytes\":%llu,\"dl_bytes\":%llu,"
         "\"ul_packets\":%llu,\"dl_packets\":%llu,\"unknown_teid_events\":%llu,"
         "\"unknown_teid_bytes\":%llu,\"teid_bind_failures\":%llu,"
         "\"flows_active\":%llu,\"flow_evictions\":%llu,"
         "\"records_emitted\":%llu,\"records_dropped\":%llu,\"records_written\":%llu,"
         "\"gy_events\":%llu},"
         "\"rings\":{\"meter_depth\":%llu,\"meter_capacity\":%llu,\"gy_depth\":%llu,"
         "\"record_depth\":%llu},"
         "\"teid_table\":{\"size\":%llu,\"capacity\":%llu,\"load_factor\":%.4f,"
         "\"probes_per_lookup\":%.4f},"
         "\"latency_ns\":{\"count\":%llu,\"min\":%llu,\"p50\":%llu,\"p90\":%llu,\"p99\":%llu,"
         "\"p999\":%llu,\"p9999\":%llu,\"max\":%llu,\"mean\":%.1f}}",
         static_cast<double>(s.uptime_ns) / 1e9, format_rfc3339(s.publish_wall_ns).c_str(),
         static_cast<unsigned long long>(s.ingest.frames),
         static_cast<unsigned long long>(s.ingest.frames_bytes),
         static_cast<unsigned long long>(s.ingest.gtpu_gpdus),
         static_cast<unsigned long long>(s.ingest.gtpu_control),
         static_cast<unsigned long long>(s.ingest.gtpu_parse_errors),
         static_cast<unsigned long long>(s.ingest.events_pushed),
         static_cast<unsigned long long>(s.ingest.events_dropped),
         static_cast<unsigned long long>(s.ingest.diameter_messages),
         static_cast<unsigned long long>(s.meter.events),
         static_cast<unsigned long long>(s.meter.bytes),
         static_cast<unsigned long long>(s.meter.ul_bytes),
         static_cast<unsigned long long>(s.meter.dl_bytes),
         static_cast<unsigned long long>(s.meter.ul_packets),
         static_cast<unsigned long long>(s.meter.dl_packets),
         static_cast<unsigned long long>(s.meter.unknown_teid_events),
         static_cast<unsigned long long>(s.meter.unknown_teid_bytes),
         static_cast<unsigned long long>(s.meter.teid_bind_failures),
         static_cast<unsigned long long>(s.meter.flows_active),
         static_cast<unsigned long long>(s.meter.flow_evictions),
         static_cast<unsigned long long>(s.meter.records_emitted),
         static_cast<unsigned long long>(s.meter.records_dropped),
         static_cast<unsigned long long>(s.records_written),
         static_cast<unsigned long long>(s.meter.gy_events),
         static_cast<unsigned long long>(s.meter_ring_depth),
         static_cast<unsigned long long>(s.meter_ring_capacity),
         static_cast<unsigned long long>(s.gy_ring_depth),
         static_cast<unsigned long long>(s.record_ring_depth),
         static_cast<unsigned long long>(s.teid_table_size),
         static_cast<unsigned long long>(s.teid_table_capacity), s.teid_load_factor,
         s.teid_probes_per_lookup, static_cast<unsigned long long>(s.latency.count),
         static_cast<unsigned long long>(s.latency.min_ns),
         static_cast<unsigned long long>(s.latency.p50_ns),
         static_cast<unsigned long long>(s.latency.p90_ns),
         static_cast<unsigned long long>(s.latency.p99_ns),
         static_cast<unsigned long long>(s.latency.p999_ns),
         static_cast<unsigned long long>(s.latency.p9999_ns),
         static_cast<unsigned long long>(s.latency.max_ns), s.latency.mean_ns);
  return out;
}

namespace {

void append_subscriber(std::string& out, const SubscriberSnapshot& row) {
  append(out,
         "{\"imsi\":\"%llu\",\"sub\":%u,\"ul_teid\":%u,\"dl_teid\":%u,"
         "\"ul_bytes\":%llu,\"dl_bytes\":%llu,\"ul_packets\":%llu,\"dl_packets\":%llu,"
         "\"gy_reported_octets\":%llu,\"gy_reports\":%u,\"buckets\":[",
         static_cast<unsigned long long>(row.imsi), row.sub_idx, row.ul_teid, row.dl_teid,
         static_cast<unsigned long long>(row.ul_bytes),
         static_cast<unsigned long long>(row.dl_bytes),
         static_cast<unsigned long long>(row.ul_packets),
         static_cast<unsigned long long>(row.dl_packets),
         static_cast<unsigned long long>(row.gy_reported_octets), row.gy_reports);
  bool first = true;
  for (size_t b = 0; b < kBucketSlots; ++b) {
    if (row.bucket_ids[b] == kUnsetBucket && row.bucket_bytes[b] == 0) continue;
    append(out, "%s{\"kind\":\"%s\",\"id\":%u,\"bytes\":%llu}", first ? "" : ",",
           (row.bucket_ids[b] & kQfiBucketTag) ? "qfi" : "rating-group",
           row.bucket_ids[b] & ~kQfiBucketTag,
           static_cast<unsigned long long>(row.bucket_bytes[b]));
    first = false;
  }
  append(out, "],\"bucket_aggregated\":%s}", row.bucket_aggregated ? "true" : "false");
}

}  // namespace

std::string render_subscribers_json(const DetailSnapshot& detail, size_t limit) {
  std::string out = "{\"subscribers\":[";
  const size_t n = std::min(limit, detail.subscribers.size());
  for (size_t i = 0; i < n; ++i) {
    if (i != 0) out += ',';
    append_subscriber(out, detail.subscribers[i]);
  }
  append(out, "],\"returned\":%zu,\"total\":%llu}", n,
         static_cast<unsigned long long>(detail.total_subscribers));
  return out;
}

std::string render_subscriber_json(const DetailSnapshot& detail, uint64_t imsi) {
  for (const SubscriberSnapshot& row : detail.subscribers) {
    if (row.imsi != imsi) continue;
    std::string out;
    append_subscriber(out, row);
    return out;
  }
  return {};
}

std::string render_flows_json(const DetailSnapshot& detail, size_t limit) {
  std::string out = "{\"flows\":[";
  const size_t n = std::min(limit, detail.top_flows.size());
  for (size_t i = 0; i < n; ++i) {
    const FlowEntry& f = detail.top_flows[i];
    if (i != 0) out += ',';
    append(out,
           "{\"teid\":%u,\"sub\":%u,\"src\":\"%s\",\"dst\":\"%s\",\"src_port\":%u,"
           "\"dst_port\":%u,\"proto\":%u,\"qfi\":%u,\"direction\":\"%s\",\"bytes\":%llu,"
           "\"packets\":%llu}",
           f.teid, f.sub_idx, ip_string(f.src_ip, f.ip_version).c_str(),
           ip_string(f.dst_ip, f.ip_version).c_str(), f.src_port, f.dst_port, f.proto, f.qfi,
           to_string(static_cast<Direction>(f.dir)), static_cast<unsigned long long>(f.bytes),
           static_cast<unsigned long long>(f.packets));
  }
  append(out, "],\"returned\":%zu}", n);
  return out;
}

HttpRequest parse_request_line(const std::string& line) {
  HttpRequest req;
  const size_t sp1 = line.find(' ');
  if (sp1 == std::string::npos) return req;
  const size_t sp2 = line.find(' ', sp1 + 1);
  req.method = line.substr(0, sp1);
  const std::string target =
      line.substr(sp1 + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp1 - 1);
  const size_t q = target.find('?');
  if (q == std::string::npos) {
    req.path = target;
  } else {
    req.path = target.substr(0, q);
    req.query = target.substr(q + 1);
  }
  req.valid = !req.method.empty() && !req.path.empty() && req.path[0] == '/';
  return req;
}

uint64_t query_param(const std::string& query, const std::string& key, uint64_t fallback) {
  size_t pos = 0;
  while (pos < query.size()) {
    const size_t amp = query.find('&', pos);
    const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
    const size_t eq = pair.find('=');
    if (eq != std::string::npos && pair.substr(0, eq) == key) {
      const std::string value = pair.substr(eq + 1);
      uint64_t parsed = 0;
      if (value.empty()) return fallback;
      for (const char c : value) {
        if (c < '0' || c > '9') return fallback;
        parsed = parsed * 10 + static_cast<uint64_t>(c - '0');
      }
      return parsed;
    }
    if (amp == std::string::npos) break;
    pos = amp + 1;
  }
  return fallback;
}

HttpResponse route(const Runtime& runtime, const HttpRequest& req) {
  HttpResponse res;
  if (!req.valid) {
    res.status = 400;
    res.body = "bad request\n";
    return res;
  }
  if (req.method != "GET" && req.method != "HEAD") {
    res.status = 405;
    res.body = "method not allowed\n";
    return res;
  }

  const PipelineSnapshot snap = runtime.snapshot();

  if (req.path == "/healthz") {
    res.body = runtime.running() ? "ok\n" : "stopped\n";
    return res;
  }
  if (req.path == "/metrics") {
    const size_t series = static_cast<size_t>(query_param(req.query, "subscribers", 0));
    auto detail = runtime.detail();
    res.body = render_prometheus(snap, detail.valid() ? detail.get() : nullptr, series);
    return res;
  }
  if (req.path == "/stats") {
    res.content_type = "application/json";
    res.body = render_stats_json(snap) + "\n";
    return res;
  }
  if (req.path == "/flows") {
    res.content_type = "application/json";
    auto detail = runtime.detail();
    if (!detail.valid()) {
      res.status = 503;
      res.body = "{\"error\":\"no snapshot published yet\"}\n";
      return res;
    }
    res.body = render_flows_json(*detail, static_cast<size_t>(query_param(req.query, "limit", 20)));
    res.body += '\n';
    return res;
  }
  if (req.path == "/subscribers" || req.path.rfind("/subscribers/", 0) == 0) {
    res.content_type = "application/json";

    // Validate the request before consulting state: a malformed IMSI is a 400
    // whether or not a snapshot happens to have been published yet.
    bool single = req.path != "/subscribers";
    uint64_t imsi = 0;
    if (single) {
      const std::string imsi_str = req.path.substr(std::strlen("/subscribers/"));
      if (imsi_str.empty()) {
        res.status = 400;
        res.body = "{\"error\":\"imsi must be numeric\"}\n";
        return res;
      }
      for (const char c : imsi_str) {
        if (c < '0' || c > '9') {
          res.status = 400;
          res.body = "{\"error\":\"imsi must be numeric\"}\n";
          return res;
        }
        imsi = imsi * 10 + static_cast<uint64_t>(c - '0');
      }
    }

    auto detail = runtime.detail();
    if (!detail.valid()) {
      res.status = 503;
      res.body = "{\"error\":\"no snapshot published yet\"}\n";
      return res;
    }
    if (!single) {
      res.body = render_subscribers_json(*detail,
                                         static_cast<size_t>(query_param(req.query, "limit", 50)));
      res.body += '\n';
      return res;
    }
    const std::string body = render_subscriber_json(*detail, imsi);
    if (body.empty()) {
      res.status = 404;
      res.body = "{\"error\":\"no such subscriber in the current snapshot\"}\n";
      return res;
    }
    res.body = body + "\n";
    return res;
  }

  res.status = 404;
  res.body =
      "gtp-meter\n\n"
      "  /metrics            Prometheus text (?subscribers=N adds top-N series)\n"
      "  /stats              pipeline counters as JSON\n"
      "  /subscribers        top subscribers (?limit=N)\n"
      "  /subscribers/{imsi} one subscriber\n"
      "  /flows              busiest flows (?limit=N)\n"
      "  /healthz            liveness\n";
  return res;
}

HttpReporter::~HttpReporter() {
  stop();
}

bool HttpReporter::start(std::string& error) {
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    error = std::string("socket: ") + std::strerror(errno);
    return false;
  }
  int one = 1;
  (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);
  if (::inet_pton(AF_INET, bind_address_.c_str(), &addr.sin_addr) != 1) {
    error = "invalid bind address: " + bind_address_;
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    error = "bind " + bind_address_ + ":" + std::to_string(port_) + ": " + std::strerror(errno);
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::listen(listen_fd_, 16) < 0) {
    error = std::string("listen: ") + std::strerror(errno);
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }

  sockaddr_in bound{};
  socklen_t len = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
    port_ = ntohs(bound.sin_port);
  }

  stop_.store(false);
  thread_ = std::thread([this] { serve_loop(); });
  return true;
}

void HttpReporter::stop() {
  if (listen_fd_ < 0 && !thread_.joinable()) return;
  stop_.store(true, std::memory_order_release);
  if (thread_.joinable()) thread_.join();
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
}

void HttpReporter::serve_loop() {
  while (!stop_.load(std::memory_order_acquire)) {
    pollfd pfd{listen_fd_, POLLIN, 0};
    const int ready = ::poll(&pfd, 1, 100);
    if (ready <= 0) continue;

    const int fd = ::accept(listen_fd_, nullptr, nullptr);
    if (fd < 0) continue;

    // Bounded read of the request head; anything larger is not a request we
    // serve, and an unbounded read is how a metrics endpoint becomes a DoS.
    std::string request;
    char buf[2048];
    for (int i = 0; i < 4; ++i) {
      pollfd rfd{fd, POLLIN, 0};
      if (::poll(&rfd, 1, 250) <= 0) break;
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) break;
      request.append(buf, static_cast<size_t>(n));
      if (request.find("\r\n\r\n") != std::string::npos || request.size() > 8192) break;
    }

    const size_t eol = request.find("\r\n");
    const HttpRequest req =
        parse_request_line(eol == std::string::npos ? request : request.substr(0, eol));
    const HttpResponse res = route(runtime_, req);
    requests_.fetch_add(1, std::memory_order_relaxed);

    char head[512];
    const int head_len = std::snprintf(
        head, sizeof(head),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        res.status, status_text(res.status), res.content_type.c_str(), res.body.size());
    if (head_len > 0) (void)::send(fd, head, static_cast<size_t>(head_len), 0);
    if (req.method != "HEAD" && !res.body.empty()) {
      (void)::send(fd, res.body.data(), res.body.size(), 0);
    }
    ::close(fd);
  }
}

}  // namespace gtpm
