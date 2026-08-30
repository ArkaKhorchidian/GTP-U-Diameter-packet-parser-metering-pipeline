// SPDX-License-Identifier: MIT
//
// Live counters over HTTP: Prometheus text on /metrics plus small JSON
// endpoints for drilling into a subscriber or a flow.
//
// The rendering functions are pure — snapshot in, string out — so they are unit
// tested without opening a socket. The server itself is deliberately boring:
// one thread, one connection at a time, non-blocking accept with a poll
// timeout so shutdown is prompt. A metrics endpoint that needs an event loop is
// a metrics endpoint that can take the data plane down with it.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#include "gtpm/runtime.hpp"
#include "gtpm/stats.hpp"

namespace gtpm {

/// Prometheus exposition format. Per-subscriber series are opt-in and capped:
/// one series per IMSI is a cardinality bomb in any real deployment.
[[nodiscard]] std::string render_prometheus(const PipelineSnapshot& snap,
                                            const DetailSnapshot* detail = nullptr,
                                            size_t subscriber_series = 0);

[[nodiscard]] std::string render_stats_json(const PipelineSnapshot& snap);
[[nodiscard]] std::string render_subscribers_json(const DetailSnapshot& detail, size_t limit);
/// Empty string when the IMSI is not in the published table.
[[nodiscard]] std::string render_subscriber_json(const DetailSnapshot& detail, uint64_t imsi);
[[nodiscard]] std::string render_flows_json(const DetailSnapshot& detail, size_t limit);

/// Parsed request line: path plus query parameters we care about.
struct HttpRequest {
  std::string method;
  std::string path;
  std::string query;
  bool valid = false;
};

[[nodiscard]] HttpRequest parse_request_line(const std::string& line);
/// Value of `key` in a `a=1&b=2` query string, or `fallback`.
[[nodiscard]] uint64_t query_param(const std::string& query, const std::string& key,
                                   uint64_t fallback);

struct HttpResponse {
  int status = 200;
  std::string content_type = "text/plain; version=0.0.4; charset=utf-8";
  std::string body;
};

/// Route a request against the runtime. Pure: no sockets, fully unit testable.
[[nodiscard]] HttpResponse route(const Runtime& runtime, const HttpRequest& req);

class HttpReporter {
 public:
  HttpReporter(const Runtime& runtime, uint16_t port, std::string bind_address = "127.0.0.1")
      : runtime_(runtime), port_(port), bind_address_(std::move(bind_address)) {}
  ~HttpReporter();

  HttpReporter(const HttpReporter&) = delete;
  HttpReporter& operator=(const HttpReporter&) = delete;

  [[nodiscard]] bool start(std::string& error);
  void stop();
  /// Actual bound port; differs from the requested one when port 0 was asked
  /// for, which the tests use to avoid fixed-port collisions.
  [[nodiscard]] uint16_t port() const noexcept { return port_; }
  [[nodiscard]] uint64_t requests_served() const noexcept {
    return requests_.load(std::memory_order_relaxed);
  }

 private:
  void serve_loop();

  const Runtime& runtime_;
  uint16_t port_;
  std::string bind_address_;
  int listen_fd_ = -1;
  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::atomic<uint64_t> requests_{0};
};

}  // namespace gtpm
