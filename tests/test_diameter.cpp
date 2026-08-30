// SPDX-License-Identifier: MIT
//
// Diameter base + Gy tests: header fields, AVP padding and boundaries, grouped
// AVP recursion, and malformed input.
#include "gtpm/diameter.hpp"

#include <random>
#include <vector>

#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

Bytes view(const Buf& b) { return Bytes(b.data(), b.size()); }

}  // namespace

TEST("diameter/header_fields") {
  synth::GySpec s;
  const Buf msg = synth::build_ccr(s);

  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
  CHECK_EQ(h.msg_length, static_cast<uint32_t>(msg.size()));
  CHECK_EQ(h.command_code, 272u);
  CHECK_EQ(h.application_id, 4u);
  CHECK(h.request());
  CHECK(!h.error());
  CHECK(h.is_credit_control());
  CHECK_EQ(h.hop_by_hop, 0x11111111u);
  CHECK_EQ(h.end_to_end, 0x22222222u);
  CHECK_EQ(h.avps.size(), msg.size() - kDiameterHeaderLen);
}

TEST("diameter/rejects_bad_version") {
  Buf msg = synth::build_ccr({});
  msg[0] = 2;
  DiameterHeader h;
  CHECK_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kBadVersion);
}

TEST("diameter/rejects_unaligned_length") {
  Buf msg = synth::build_ccr({});
  store_be24(msg.data() + 1, static_cast<uint32_t>(msg.size()) - 1);
  DiameterHeader h;
  CHECK_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kBadLength);
}

TEST("diameter/rejects_length_below_header") {
  Buf msg = synth::build_ccr({});
  store_be24(msg.data() + 1, 16);
  DiameterHeader h;
  CHECK_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kBadLength);
}

TEST("diameter/rejects_absurd_length") {
  Buf msg = synth::build_ccr({});
  store_be24(msg.data() + 1, kDiameterMaxMsgLen + 4);
  DiameterHeader h;
  CHECK_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kBadLength);
}

TEST("diameter/rejects_every_truncation") {
  const Buf msg = synth::build_ccr({});
  DiameterHeader h;
  for (size_t n = 0; n < msg.size(); ++n) {
    CHECK_EQ(parse_diameter_header(Bytes(msg.data(), n), h), DiameterStatus::kTruncated);
  }
  CHECK_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
}

TEST("diameter/avp_iteration_and_padding") {
  Buf avps;
  synth::put_avp_str(avps, 263, "abc");  // 3 bytes -> 1 byte of padding
  synth::put_avp_u32(avps, 416, 2);
  synth::put_avp_str(avps, 264, "seven!!");  // 7 bytes -> 1 byte of padding
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);

  std::vector<uint32_t> codes;
  std::vector<size_t> sizes;
  const DiameterStatus st = for_each_avp(h.avps, [&](const Avp& a, int) {
    codes.push_back(a.code);
    sizes.push_back(a.data.size());
    return true;
  });
  REQUIRE_EQ(st, DiameterStatus::kOk);
  REQUIRE_EQ(codes.size(), size_t{3});
  CHECK_EQ(codes[0], 263u);
  CHECK_EQ(sizes[0], size_t{3});  // padding excluded from the value
  CHECK_EQ(codes[1], 416u);
  CHECK_EQ(sizes[1], size_t{4});
  CHECK_EQ(codes[2], 264u);
  CHECK_EQ(sizes[2], size_t{7});
}

TEST("diameter/vendor_specific_avp") {
  Buf avps;
  Buf v;
  synth::put_be32(v, 42);
  synth::put_avp(avps, 1001, view(v), synth::kAvpFlagVendor | synth::kAvpFlagMandatory, 10415);
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
  int seen = 0;
  (void)for_each_avp(h.avps, [&](const Avp& a, int) {
    ++seen;
    CHECK(a.vendor_specific());
    CHECK_EQ(a.vendor_id, 10415u);
    uint32_t value = 0;
    CHECK(a.as_u32(value));
    CHECK_EQ(value, 42u);
    return true;
  });
  CHECK_EQ(seen, 1);
}

TEST("diameter/rejects_avp_length_below_header") {
  Buf avps;
  synth::put_avp_u32(avps, 416, 1);
  Buf msg = synth::build_diameter(272, 4, true, avps);
  store_be24(msg.data() + kDiameterHeaderLen + 5, 4);  // AVP length 4 < 8-byte header
  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
  CHECK_EQ(for_each_avp(h.avps, [](const Avp&, int) { return true; }), DiameterStatus::kBadAvp);
}

TEST("diameter/rejects_avp_overrunning_message") {
  Buf avps;
  synth::put_avp_str(avps, 263, "session");
  Buf msg = synth::build_diameter(272, 4, true, avps);
  store_be24(msg.data() + kDiameterHeaderLen + 5, 4096);
  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
  CHECK_EQ(for_each_avp(h.avps, [](const Avp&, int) { return true; }), DiameterStatus::kBadAvp);
}

TEST("diameter/rejects_trailing_garbage_avp") {
  Buf avps;
  synth::put_avp_u32(avps, 416, 1);
  avps.push_back(0);  // 1 stray byte: too small to be an AVP header
  avps.push_back(0);
  avps.push_back(0);
  avps.push_back(0);
  const Buf msg = synth::build_diameter(272, 4, true, avps);
  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);
  CHECK_EQ(for_each_avp(h.avps, [](const Avp&, int) { return true; }), DiameterStatus::kBadAvp);
}

TEST("diameter/grouped_avp_recursion") {
  Buf inner;
  synth::put_avp_u32(inner, 450, 1);
  synth::put_avp_str(inner, 444, "310150123456789");
  Buf avps;
  synth::put_avp_grouped(avps, 443, inner);
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);

  int sub_seen = 0;
  (void)for_each_avp(h.avps, [&](const Avp& a, int depth) {
    CHECK_EQ(a.code, 443u);
    CHECK_EQ(depth, 0);
    (void)for_each_sub_avp(
        a,
        [&](const Avp&, int d) {
          ++sub_seen;
          CHECK_EQ(d, 1);
          return true;
        },
        depth);
    return true;
  });
  CHECK_EQ(sub_seen, 2);
}

TEST("diameter/depth_cap_stops_runaway_nesting") {
  Buf level;
  synth::put_avp_u32(level, 416, 1);
  for (int i = 0; i < kAvpMaxDepth + 3; ++i) {
    Buf outer;
    synth::put_avp_grouped(outer, 456, level);
    level = outer;
  }
  const Buf msg = synth::build_diameter(272, 4, true, level);
  DiameterHeader h;
  REQUIRE_EQ(parse_diameter_header(view(msg), h), DiameterStatus::kOk);

  // Recursing manually must hit the cap rather than blowing the stack.
  int max_depth = 0;
  std::function<DiameterStatus(Bytes, int)> walk = [&](Bytes area, int depth) {
    return for_each_avp(
        area,
        [&](const Avp& a, int d) {
          max_depth = d > max_depth ? d : max_depth;
          if (a.code == 456u) (void)walk(a.data, d + 1);
          return true;
        },
        depth);
  };
  CHECK_EQ(walk(h.avps, 0), DiameterStatus::kOk);
  CHECK_LE(max_depth, kAvpMaxDepth);
}

TEST("gy/ccr_update_extraction") {
  synth::GySpec s;
  s.session_id = "ocs.example.com;1;2;3";
  s.imsi = "310150999888777";
  s.request_type = static_cast<uint32_t>(CcRequestType::kUpdate);
  s.request_number = 4;
  s.rating_group = 12;
  s.used_input = 123456;
  s.used_output = 654321;
  const Buf msg = synth::build_ccr(s);

  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  CHECK(gy.is_request);
  CHECK_EQ(gy.session_id, std::string_view("ocs.example.com;1;2;3"));
  CHECK_EQ(gy.origin_host, std::string_view("pgw.example.com"));
  CHECK(gy.has_imsi);
  CHECK_EQ(gy.imsi, 310150999888777ULL);
  CHECK_EQ(gy.cc_request_type, 2u);
  CHECK_EQ(gy.cc_request_number, 4u);
  REQUIRE_EQ(gy.mscc_count, size_t{1});
  CHECK_EQ(gy.mscc[0].rating_group, 12u);
  CHECK(gy.mscc[0].has_rating_group);
  CHECK(gy.mscc[0].has_used);
  CHECK_EQ(gy.mscc[0].used_input_octets, 123456ULL);
  CHECK_EQ(gy.mscc[0].used_output_octets, 654321ULL);
  CHECK_EQ(gy.mscc[0].used_total_octets, 777777ULL);
}

TEST("gy/cca_grant_extraction") {
  synth::GySpec s;
  s.granted_total = 10 * 1024 * 1024;
  s.rating_group = 3;
  const Buf msg = synth::build_cca(s);

  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  CHECK(!gy.is_request);
  CHECK(gy.has_result_code);
  CHECK_EQ(gy.result_code, kResultSuccess);
  REQUIRE_EQ(gy.mscc_count, size_t{1});
  CHECK(gy.mscc[0].has_granted);
  CHECK_EQ(gy.mscc[0].granted_total_octets, 10ULL * 1024 * 1024);
  CHECK_EQ(gy.mscc[0].rating_group, 3u);
}

TEST("gy/used_total_falls_back_to_input_plus_output") {
  Buf usu;
  synth::put_avp_u64(usu, 412, 1000);
  synth::put_avp_u64(usu, 414, 2000);
  Buf mscc;
  synth::put_avp_u32(mscc, 432, 5);
  synth::put_avp_grouped(mscc, 446, usu);
  Buf avps;
  synth::put_avp_str(avps, 263, "s");
  synth::put_avp_grouped(avps, 456, mscc);
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  REQUIRE_EQ(gy.mscc_count, size_t{1});
  CHECK_EQ(gy.mscc[0].used_total_octets, 3000ULL);
}

TEST("gy/multiple_mscc_blocks") {
  Buf avps;
  synth::put_avp_str(avps, 263, "sess");
  for (uint32_t rg = 1; rg <= 3; ++rg) {
    Buf usu;
    synth::put_avp_u64(usu, 421, rg * 1000);
    Buf mscc;
    synth::put_avp_u32(mscc, 432, rg);
    synth::put_avp_grouped(mscc, 446, usu);
    synth::put_avp_grouped(avps, 456, mscc);
  }
  const Buf msg = synth::build_diameter(272, 4, true, avps);

  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  REQUIRE_EQ(gy.mscc_count, size_t{3});
  for (size_t i = 0; i < 3; ++i) {
    CHECK_EQ(gy.mscc[i].rating_group, static_cast<uint32_t>(i + 1));
    CHECK_EQ(gy.mscc[i].used_total_octets, (i + 1) * 1000ULL);
  }
  CHECK(!gy.mscc_overflow);
}

TEST("gy/mscc_overflow_is_flagged_not_overrun") {
  Buf avps;
  synth::put_avp_str(avps, 263, "sess");
  for (uint32_t rg = 0; rg < kMaxMsccPerMessage + 3; ++rg) {
    Buf mscc;
    synth::put_avp_u32(mscc, 432, rg);
    synth::put_avp_grouped(avps, 456, mscc);
  }
  const Buf msg = synth::build_diameter(272, 4, true, avps);
  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  CHECK_EQ(gy.mscc_count, kMaxMsccPerMessage);
  CHECK(gy.mscc_overflow);
}

TEST("gy/non_numeric_imsi_is_rejected") {
  synth::GySpec s;
  s.imsi = "31015012345678X";
  const Buf msg = synth::build_ccr(s);
  DiameterHeader h;
  GyMessage gy;
  REQUIRE_EQ(parse_diameter_gy(view(msg), h, gy), DiameterStatus::kOk);
  CHECK(!gy.has_imsi);
}

TEST("diameter/random_bytes_never_overrun") {
  std::mt19937 rng(0xBEEF);
  std::vector<uint8_t> buf;
  for (int iter = 0; iter < 20000; ++iter) {
    const size_t n = rng() % 128;
    buf.resize(n);
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rng());
    if (n >= 1) buf[0] = 1;  // steer past the version check
    if (n >= 4) {
      const uint32_t len = static_cast<uint32_t>(n & ~size_t{3});
      store_be24(buf.data() + 1, len);
    }
    DiameterHeader h;
    GyMessage gy;
    const DiameterStatus st = parse_diameter_gy(Bytes(buf.data(), n), h, gy);
    if (st == DiameterStatus::kOk && h.msg_length >= kDiameterHeaderLen) {
      CHECK(h.avps.size() <= n);
    }
  }
}

GTPM_TEST_MAIN()
