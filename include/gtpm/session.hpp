// SPDX-License-Identifier: MIT
//
// Session table — the static stand-in for PFCP/N4.
//
// In a real UPF the SMF installs PDRs/FARs/URRs over PFCP and the data plane
// learns which TEID belongs to which subscriber, in which direction, and under
// which usage-reporting rule. That signalling plane is out of scope here, so
// sessions are loaded from a CSV that carries exactly the fields PFCP would
// have installed. `docs/pfcp-integration.md` marks where the real thing plugs
// in.
#pragma once

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace gtpm {

/// One PDU session: an IMSI plus its uplink and downlink tunnels.
struct SessionSpec {
  uint64_t imsi = 0;
  uint32_t ul_teid = 0;  ///< UPF-allocated: packets arriving on it are uplink
  uint32_t dl_teid = 0;  ///< gNB/eNB-allocated: packets on it are downlink
  uint32_t rating_group = 0;
  std::string msisdn;
  std::string apn;

  [[nodiscard]] bool valid() const noexcept { return imsi != 0 && (ul_teid != 0 || dl_teid != 0); }
};

struct SessionLoadResult {
  std::vector<SessionSpec> sessions;
  size_t skipped_lines = 0;
  std::string error;  ///< non-empty when the file could not be read at all

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

namespace detail {

[[nodiscard]] inline std::string trim(const std::string& s) {
  size_t b = 0;
  size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
  return s.substr(b, e - b);
}

[[nodiscard]] inline bool parse_u64(const std::string& s, uint64_t& out) {
  if (s.empty()) return false;
  uint64_t v = 0;
  const int base = (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
  for (size_t i = (base == 16 ? 2 : 0); i < s.size(); ++i) {
    const char c = s[i];
    uint64_t digit;
    if (c >= '0' && c <= '9') {
      digit = static_cast<uint64_t>(c - '0');
    } else if (base == 16 && c >= 'a' && c <= 'f') {
      digit = static_cast<uint64_t>(c - 'a' + 10);
    } else if (base == 16 && c >= 'A' && c <= 'F') {
      digit = static_cast<uint64_t>(c - 'A' + 10);
    } else {
      return false;
    }
    v = v * static_cast<uint64_t>(base) + digit;
  }
  out = v;
  return true;
}

}  // namespace detail

/// Load sessions from CSV: `imsi,ul_teid,dl_teid,rating_group,msisdn,apn`.
/// A leading `#` or a header line starting with "imsi" is ignored, as are
/// malformed rows (counted in `skipped_lines`) — a session file with one bad
/// row should not take the pipeline down.
[[nodiscard]] inline SessionLoadResult load_sessions_csv(const std::string& path) {
  SessionLoadResult result;
  std::ifstream in(path);
  if (!in) {
    result.error = "cannot open session file: " + path;
    return result;
  }

  std::string line;
  while (std::getline(in, line)) {
    const std::string trimmed = detail::trim(line);
    if (trimmed.empty() || trimmed[0] == '#') continue;
    if (trimmed.rfind("imsi", 0) == 0) continue;  // header

    std::vector<std::string> cols;
    std::stringstream ss(trimmed);
    std::string cell;
    while (std::getline(ss, cell, ',')) cols.push_back(detail::trim(cell));
    if (cols.size() < 3) {
      ++result.skipped_lines;
      continue;
    }

    SessionSpec s;
    uint64_t ul = 0;
    uint64_t dl = 0;
    uint64_t rg = 0;
    if (!detail::parse_u64(cols[0], s.imsi) || !detail::parse_u64(cols[1], ul) ||
        !detail::parse_u64(cols[2], dl)) {
      ++result.skipped_lines;
      continue;
    }
    if (ul > UINT32_MAX || dl > UINT32_MAX) {
      ++result.skipped_lines;
      continue;
    }
    s.ul_teid = static_cast<uint32_t>(ul);
    s.dl_teid = static_cast<uint32_t>(dl);
    if (cols.size() > 3 && detail::parse_u64(cols[3], rg) && rg <= UINT32_MAX) {
      s.rating_group = static_cast<uint32_t>(rg);
    }
    if (cols.size() > 4) s.msisdn = cols[4];
    if (cols.size() > 5) s.apn = cols[5];

    if (!s.valid()) {
      ++result.skipped_lines;
      continue;
    }
    result.sessions.push_back(std::move(s));
  }
  return result;
}

/// Write sessions back out in the same CSV format (used by the traffic
/// generator so a capture always ships with the session table that explains it).
[[nodiscard]] inline bool write_sessions_csv(const std::string& path,
                                             const std::vector<SessionSpec>& sessions) {
  std::ofstream out(path, std::ios::trunc);
  if (!out) return false;
  out << "imsi,ul_teid,dl_teid,rating_group,msisdn,apn\n";
  for (const SessionSpec& s : sessions) {
    out << s.imsi << ',' << s.ul_teid << ',' << s.dl_teid << ',' << s.rating_group << ','
        << s.msisdn << ',' << s.apn << '\n';
  }
  return static_cast<bool>(out);
}

}  // namespace gtpm
