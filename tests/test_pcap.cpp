// SPDX-License-Identifier: MIT
//
// pcap reader/writer tests: round trip, both endiannesses, both timestamp
// resolutions, truncated captures, and link-layer stripping.
#include "gtpm/pcap.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "gtpm/byte_order.hpp"
#include "gtpm/synth.hpp"
#include "test_harness.hpp"

using namespace gtpm;
using synth::Buf;

namespace {

std::string temp_path() {
  char tmpl[] = "/tmp/gtpm-pcap-XXXXXX";
  const int fd = ::mkstemp(tmpl);
  if (fd >= 0) ::close(fd);
  return std::string(tmpl);
}

Bytes view(const Buf& b) { return Bytes(b.data(), b.size()); }

/// Hand-build a pcap file so the reader is tested against bytes, not against
/// our own writer.
void write_raw(const std::string& path, uint32_t magic, bool big_endian,
               const std::vector<std::vector<uint8_t>>& packets, uint32_t link = 1) {
  std::vector<uint8_t> out(24);
  auto put32 = [&](size_t off, uint32_t v) {
    if (big_endian) {
      store_be32(out.data() + off, v);
    } else {
      store_le32(out.data() + off, v);
    }
  };
  auto put16 = [&](size_t off, uint16_t v) {
    if (big_endian) {
      store_be16(out.data() + off, v);
    } else {
      store_le16(out.data() + off, v);
    }
  };
  store_le32(out.data(), magic);  // magic is written so the reader detects order
  if (big_endian) store_be32(out.data(), magic);
  put16(4, 2);
  put16(6, 4);
  put32(8, 0);
  put32(12, 0);
  put32(16, 65535);
  put32(20, link);

  for (const auto& p : packets) {
    const size_t base = out.size();
    out.resize(base + 16);
    auto rec32 = [&](size_t off, uint32_t v) {
      if (big_endian) {
        store_be32(out.data() + base + off, v);
      } else {
        store_le32(out.data() + base + off, v);
      }
    };
    rec32(0, 1700000000);
    rec32(4, 500000);
    rec32(8, static_cast<uint32_t>(p.size()));
    rec32(12, static_cast<uint32_t>(p.size()));
    out.insert(out.end(), p.begin(), p.end());
  }

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(reinterpret_cast<const char*>(out.data()), static_cast<long>(out.size()));
}

}  // namespace

TEST("pcap/write_then_read_round_trip") {
  const std::string path = temp_path();
  const Buf a = synth::build_ethernet(view(synth::filler(60)));
  const Buf b = synth::build_ethernet(view(synth::filler(1400)));

  {
    PcapWriter w;
    REQUIRE(w.open(path));
    CHECK(w.write(1'700'000'000'123'456'000ULL, view(a)));
    CHECK(w.write(1'700'000'001'000'000'000ULL, view(b)));
  }

  PcapFile file;
  const PcapFile::Result r = PcapFile::load(path, file);
  std::remove(path.c_str());

  REQUIRE(r.ok());
  REQUIRE_EQ(file.packets().size(), size_t{2});
  CHECK_EQ(file.link_type(), 1u);
  CHECK_EQ(file.packets()[0].data.size(), a.size());
  CHECK_EQ(file.packets()[1].data.size(), b.size());
  CHECK_EQ(file.packets()[0].ts_ns / 1000, 1'700'000'000'123'456ULL);
  CHECK_EQ(file.packets()[1].ts_ns, 1'700'000'001'000'000'000ULL);
  CHECK_EQ(file.total_bytes(), a.size() + b.size());
  CHECK(!file.packets()[0].truncated());
}

TEST("pcap/reads_all_four_magic_variants") {
  const std::vector<std::vector<uint8_t>> packets = {{1, 2, 3, 4}, {5, 6, 7, 8, 9}};
  struct Case {
    uint32_t magic;
    bool big_endian;
    bool nanos;
  };
  const Case cases[] = {
      {kPcapMagicMicro, false, false},
      {kPcapMagicMicroSwapped, true, false},
      {kPcapMagicNano, false, true},
      {kPcapMagicNanoSwapped, true, true},
  };

  for (const Case& c : cases) {
    const std::string path = temp_path();
    // A byte-swapped file writes the same magic value with the other byte
    // order, which is exactly what the reader keys off.
    write_raw(path, c.big_endian ? (c.nanos ? kPcapMagicNano : kPcapMagicMicro) : c.magic,
              c.big_endian, packets);
    PcapFile file;
    const PcapFile::Result r = PcapFile::load(path, file);
    std::remove(path.c_str());

    REQUIRE(r.ok());
    REQUIRE_EQ(file.packets().size(), size_t{2});
    CHECK_EQ(file.byte_swapped(), c.big_endian);
    CHECK_EQ(file.packets()[0].data.size(), size_t{4});
    CHECK_EQ(file.packets()[1].data.size(), size_t{5});
    const uint64_t expected_ns =
        1'700'000'000ULL * 1'000'000'000ULL + (c.nanos ? 500'000ULL : 500'000'000ULL);
    CHECK_EQ(file.packets()[0].ts_ns, expected_ns);
  }
}

TEST("pcap/rejects_non_pcap_and_short_files") {
  const std::string path = temp_path();
  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << "this is not a pcap file at all, not even close";
  }
  PcapFile file;
  CHECK(!PcapFile::load(path, file).ok());

  {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << "tiny";
  }
  CHECK(!PcapFile::load(path, file).ok());
  std::remove(path.c_str());

  CHECK(!PcapFile::load("/nonexistent/capture.pcap", file).ok());
}

TEST("pcap/truncated_last_record_costs_one_packet_not_the_file") {
  const std::string path = temp_path();
  write_raw(path, kPcapMagicMicro, false, {{1, 2, 3, 4}, {5, 6, 7, 8}});
  // Chop the file mid-way through the second packet's data.
  {
    std::ifstream in(path, std::ios::binary);
    std::string all((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    all.resize(all.size() - 2);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << all;
  }

  PcapFile file;
  const PcapFile::Result r = PcapFile::load(path, file);
  std::remove(path.c_str());

  REQUIRE(r.ok());
  CHECK_EQ(file.packets().size(), size_t{1});
  CHECK_EQ(r.malformed_records, size_t{1});
}

TEST("pcap/link_layer_stripping") {
  const Buf frame = synth::build_ethernet(view(synth::filler(40)));
  const LinkLayer eth = strip_link_layer(static_cast<uint32_t>(LinkType::kEthernet), view(frame));
  CHECK(eth.valid);
  CHECK(eth.is_ethernet);
  CHECK_EQ(eth.payload.size(), frame.size());

  const Buf ip = synth::build_ipv4_udp({}, view(synth::filler(20)));
  const LinkLayer raw = strip_link_layer(static_cast<uint32_t>(LinkType::kRawIp), view(ip));
  CHECK(raw.valid);
  CHECK(!raw.is_ethernet);
  CHECK_EQ(raw.payload.size(), ip.size());

  Buf sll(16, 0);
  sll.insert(sll.end(), ip.begin(), ip.end());
  const LinkLayer cooked = strip_link_layer(static_cast<uint32_t>(LinkType::kLinuxSll), view(sll));
  CHECK(cooked.valid);
  CHECK(!cooked.is_ethernet);
  CHECK_EQ(cooked.payload.size(), ip.size());

  CHECK(!strip_link_layer(9999, view(frame)).valid);
  CHECK(!strip_link_layer(static_cast<uint32_t>(LinkType::kLinuxSll), Bytes(sll.data(), 8)).valid);
}

TEST("pcap/snaplen_truncated_packet_is_flagged") {
  const std::string path = temp_path();
  {
    PcapWriter w;
    REQUIRE(w.open(path, LinkType::kEthernet, 64));
    const Buf partial = synth::filler(64);
    CHECK(w.write(1'700'000'000'000'000'000ULL, view(partial), 1514));  // orig_len > captured
  }
  PcapFile file;
  const PcapFile::Result r = PcapFile::load(path, file);
  std::remove(path.c_str());

  REQUIRE(r.ok());
  REQUIRE_EQ(file.packets().size(), size_t{1});
  CHECK(file.packets()[0].truncated());
  CHECK_EQ(file.packets()[0].orig_len, 1514u);
  CHECK_EQ(file.snaplen(), 64u);
}

GTPM_TEST_MAIN()
