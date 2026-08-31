// SPDX-License-Identifier: MIT
//
// Classic libpcap file reading and writing, implemented directly.
//
// The format is 24 bytes of header and 16 bytes per packet, so linking libpcap
// to read a file would buy a dependency and nothing else. Doing it here also
// means the replay driver can load the whole capture into memory up front and
// then run with no I/O in the loop, which is what a throughput benchmark needs.
//
// Both endiannesses and both timestamp resolutions (µs and ns) are handled,
// because captures move between machines and tcpdump -w on a big-endian host is
// still a thing you get handed.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "gtpm/byte_order.hpp"

namespace gtpm {

inline constexpr uint32_t kPcapMagicMicro = 0xA1B2C3D4u;
inline constexpr uint32_t kPcapMagicMicroSwapped = 0xD4C3B2A1u;
inline constexpr uint32_t kPcapMagicNano = 0xA1B23C4Du;
inline constexpr uint32_t kPcapMagicNanoSwapped = 0x4D3CB2A1u;
inline constexpr size_t kPcapFileHeaderLen = 24;
inline constexpr size_t kPcapRecordHeaderLen = 16;

/// Link types we know how to hand to the ingest path.
enum class LinkType : uint32_t {
  kEthernet = 1,
  kRawIp = 101,
  kLinuxSll = 113,
  kRawIpv4 = 228,
  kRawIpv6 = 229,
};

struct PcapPacket {
  Bytes data;             ///< captured bytes, a view into the loaded file
  uint64_t ts_ns = 0;     ///< capture timestamp, nanoseconds since the epoch
  uint32_t orig_len = 0;  ///< length on the wire before snaplen truncation

  [[nodiscard]] bool truncated() const noexcept { return data.size() < orig_len; }
};

/// A capture loaded into memory and indexed. Views in `packets()` stay valid as
/// long as the PcapFile does.
class PcapFile {
 public:
  struct Result {
    std::string error;
    size_t malformed_records = 0;
    [[nodiscard]] bool ok() const noexcept { return error.empty(); }
  };

  [[nodiscard]] static Result load(const std::string& path, PcapFile& out) {
    Result r;
    out = PcapFile{};

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
      r.error = "cannot open capture: " + path;
      return r;
    }
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (size < static_cast<long>(kPcapFileHeaderLen)) {
      std::fclose(f);
      r.error = "capture is shorter than a pcap file header: " + path;
      return r;
    }

    out.bytes_.resize(static_cast<size_t>(size));
    const size_t read = std::fread(out.bytes_.data(), 1, out.bytes_.size(), f);
    std::fclose(f);
    if (read != out.bytes_.size()) {
      r.error = "short read on capture: " + path;
      return r;
    }

    const uint32_t magic_le = load_le32(out.bytes_.data());
    bool swapped = false;
    bool nanos = false;
    if (magic_le == kPcapMagicMicro) {
      swapped = false;
    } else if (magic_le == kPcapMagicMicroSwapped) {
      swapped = true;
    } else if (magic_le == kPcapMagicNano) {
      nanos = true;
    } else if (magic_le == kPcapMagicNanoSwapped) {
      swapped = true;
      nanos = true;
    } else {
      r.error = "not a pcap file (bad magic); pcapng is not supported: " + path;
      return r;
    }

    auto u32 = [&](const uint8_t* p) { return swapped ? load_be32(p) : load_le32(p); };
    auto u16 = [&](const uint8_t* p) { return swapped ? load_be16(p) : load_le16(p); };

    out.swapped_ = swapped;
    out.nanosecond_ = nanos;
    out.version_major_ = u16(out.bytes_.data() + 4);
    out.version_minor_ = u16(out.bytes_.data() + 6);
    out.snaplen_ = u32(out.bytes_.data() + 16);
    out.link_type_ = u32(out.bytes_.data() + 20);

    size_t off = kPcapFileHeaderLen;
    while (off + kPcapRecordHeaderLen <= out.bytes_.size()) {
      const uint32_t ts_sec = u32(out.bytes_.data() + off);
      const uint32_t ts_frac = u32(out.bytes_.data() + off + 4);
      const uint32_t incl_len = u32(out.bytes_.data() + off + 8);
      const uint32_t orig_len = u32(out.bytes_.data() + off + 12);
      off += kPcapRecordHeaderLen;

      if (incl_len > out.bytes_.size() - off) {
        // Truncated final record: a capture cut off mid-write is common and
        // should cost you the last packet, not the whole file.
        ++r.malformed_records;
        break;
      }

      PcapPacket p;
      p.data = Bytes(out.bytes_.data() + off, incl_len);
      p.ts_ns =
          static_cast<uint64_t>(ts_sec) * 1'000'000'000ULL + (nanos ? ts_frac : ts_frac * 1000ULL);
      p.orig_len = orig_len;
      out.packets_.push_back(p);
      off += incl_len;
    }
    return r;
  }

  [[nodiscard]] const std::vector<PcapPacket>& packets() const noexcept { return packets_; }
  [[nodiscard]] uint32_t link_type() const noexcept { return link_type_; }
  [[nodiscard]] uint32_t snaplen() const noexcept { return snaplen_; }
  [[nodiscard]] bool nanosecond_resolution() const noexcept { return nanosecond_; }
  [[nodiscard]] bool byte_swapped() const noexcept { return swapped_; }
  [[nodiscard]] uint16_t version_major() const noexcept { return version_major_; }
  [[nodiscard]] uint16_t version_minor() const noexcept { return version_minor_; }
  [[nodiscard]] size_t total_bytes() const noexcept {
    size_t n = 0;
    for (const PcapPacket& p : packets_) n += p.data.size();
    return n;
  }

 private:
  std::vector<uint8_t> bytes_;
  std::vector<PcapPacket> packets_;
  uint32_t link_type_ = static_cast<uint32_t>(LinkType::kEthernet);
  uint32_t snaplen_ = 0;
  uint16_t version_major_ = 2;
  uint16_t version_minor_ = 4;
  bool swapped_ = false;
  bool nanosecond_ = false;
};

/// Minimal pcap writer, host byte order, microsecond timestamps.
class PcapWriter {
 public:
  PcapWriter() = default;
  ~PcapWriter() { close(); }
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;

  [[nodiscard]] bool open(const std::string& path, LinkType link = LinkType::kEthernet,
                          uint32_t snaplen = 262144) {
    close();
    file_ = std::fopen(path.c_str(), "wb");
    if (file_ == nullptr) return false;

    uint8_t header[kPcapFileHeaderLen] = {};
    store_le32(header, kPcapMagicMicro);
    store_le16(header + 4, 2);
    store_le16(header + 6, 4);
    store_le32(header + 8, 0);   // thiszone
    store_le32(header + 12, 0);  // sigfigs
    store_le32(header + 16, snaplen);
    store_le32(header + 20, static_cast<uint32_t>(link));
    return std::fwrite(header, 1, sizeof(header), file_) == sizeof(header);
  }

  [[nodiscard]] bool write(uint64_t ts_ns, Bytes data, uint32_t orig_len = 0) {
    if (file_ == nullptr) return false;
    uint8_t rec[kPcapRecordHeaderLen];
    store_le32(rec, static_cast<uint32_t>(ts_ns / 1'000'000'000ULL));
    store_le32(rec + 4, static_cast<uint32_t>((ts_ns % 1'000'000'000ULL) / 1000ULL));
    store_le32(rec + 8, static_cast<uint32_t>(data.size()));
    store_le32(rec + 12, orig_len ? orig_len : static_cast<uint32_t>(data.size()));
    if (std::fwrite(rec, 1, sizeof(rec), file_) != sizeof(rec)) return false;
    return std::fwrite(data.data(), 1, data.size(), file_) == data.size();
  }

  void close() {
    if (file_ != nullptr) {
      std::fclose(file_);
      file_ = nullptr;
    }
  }

  [[nodiscard]] bool is_open() const noexcept { return file_ != nullptr; }

 private:
  std::FILE* file_ = nullptr;
};

/// Strip a link-layer header so the ingest path sees an IP packet or an
/// Ethernet frame, whichever the capture holds.
struct LinkLayer {
  Bytes payload;
  bool is_ethernet = false;
  bool valid = false;
};

[[nodiscard]] inline LinkLayer strip_link_layer(uint32_t link_type, Bytes frame) noexcept {
  LinkLayer out;
  switch (static_cast<LinkType>(link_type)) {
    case LinkType::kEthernet:
      out.payload = frame;
      out.is_ethernet = true;
      out.valid = true;
      break;
    case LinkType::kRawIp:
    case LinkType::kRawIpv4:
    case LinkType::kRawIpv6:
      out.payload = frame;
      out.valid = true;
      break;
    case LinkType::kLinuxSll:
      // Linux "cooked" capture: 16-byte pseudo-header, then the L3 packet.
      if (frame.size() > 16) {
        out.payload = frame.subspan(16);
        out.valid = true;
      }
      break;
    default: break;
  }
  return out;
}

}  // namespace gtpm
