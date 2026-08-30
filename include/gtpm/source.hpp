// SPDX-License-Identifier: MIT
//
// Packet sources: pcap replay and live capture behind one batch interface.
//
// The interface hands out batches rather than single packets so the one virtual
// call is amortised over hundreds of frames instead of paid per packet.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gtpm/pcap.hpp"

namespace gtpm {

class PacketSource {
 public:
  virtual ~PacketSource() = default;

  /// Fill up to `max` packets. Returns 0 at end of stream or when no packets
  /// were available before the source's internal timeout.
  virtual size_t next_batch(PcapPacket* out, size_t max) = 0;
  /// True once the source will never produce another packet.
  virtual bool exhausted() const = 0;
  virtual uint32_t link_type() const = 0;
  virtual const char* name() const = 0;
  virtual void stop() {}
};

/// Replay a capture from memory. Loading up front keeps I/O out of the loop, so
/// a replay benchmark measures the pipeline rather than the file system.
class PcapReplaySource final : public PacketSource {
 public:
  struct Options {
    uint32_t loops = 1;          ///< 0 means loop forever until stopped
    bool rewrite_timestamps = true;  ///< stamp with capture time on replay
  };

  static std::unique_ptr<PcapReplaySource> open(const std::string& path, Options opt,
                                                std::string& error);

  size_t next_batch(PcapPacket* out, size_t max) override;
  bool exhausted() const override { return exhausted_; }
  uint32_t link_type() const override { return file_.link_type(); }
  const char* name() const override { return "pcap-replay"; }
  void stop() override { stopped_ = true; }

  [[nodiscard]] const PcapFile& file() const noexcept { return file_; }
  [[nodiscard]] uint64_t packets_replayed() const noexcept { return replayed_; }
  [[nodiscard]] uint64_t bytes_replayed() const noexcept { return bytes_; }

 private:
  PcapFile file_;
  Options opt_{};
  size_t cursor_ = 0;
  uint32_t loop_ = 0;
  uint64_t replayed_ = 0;
  uint64_t bytes_ = 0;
  bool exhausted_ = false;
  bool stopped_ = false;
};

/// Live capture from a network interface. AF_PACKET on Linux, BPF on macOS.
/// Requires elevated privileges (CAP_NET_RAW / root).
class LiveCaptureSource final : public PacketSource {
 public:
  struct Options {
    std::string interface;
    bool promiscuous = true;
    uint32_t snaplen = 65535;
    uint32_t poll_timeout_ms = 100;
  };

  static std::unique_ptr<LiveCaptureSource> open(const Options& opt, std::string& error);
  ~LiveCaptureSource() override;

  size_t next_batch(PcapPacket* out, size_t max) override;
  bool exhausted() const override { return stopped_; }
  uint32_t link_type() const override { return link_type_; }
  const char* name() const override { return "live-capture"; }
  void stop() override { stopped_ = true; }

  /// True when this platform has a live-capture backend compiled in.
  [[nodiscard]] static bool supported() noexcept;

 private:
  int fd_ = -1;
  uint32_t link_type_ = static_cast<uint32_t>(LinkType::kEthernet);
  Options opt_{};
  std::vector<uint8_t> buffer_;
  size_t buffer_used_ = 0;
  size_t buffer_offset_ = 0;
  bool stopped_ = false;
};

}  // namespace gtpm
