// SPDX-License-Identifier: MIT
//
// Live capture. AF_PACKET on Linux, /dev/bpf on macOS, and an honest failure
// everywhere else.
//
// Both backends read into a single reusable buffer and hand out spans into it,
// so the capture path allocates nothing per packet. AF_XDP would replace this
// file (and only this file) with a zero-copy UMEM ring; see
// docs/afxdp-design.md for the shape of that work.
#include "gtpm/source.hpp"

#include <cerrno>
#include <cstring>

#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "gtpm/clock.hpp"

namespace gtpm {

bool LiveCaptureSource::supported() noexcept {
#if defined(__linux__) || defined(__APPLE__)
  return true;
#else
  return false;
#endif
}

LiveCaptureSource::~LiveCaptureSource() {
#if defined(__linux__) || defined(__APPLE__)
  if (fd_ >= 0) ::close(fd_);
#endif
}

#if defined(__linux__)

std::unique_ptr<LiveCaptureSource> LiveCaptureSource::open(const Options& opt, std::string& error) {
  auto src = std::unique_ptr<LiveCaptureSource>(new LiveCaptureSource());
  src->opt_ = opt;

  const int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    error = std::string("socket(AF_PACKET): ") + std::strerror(errno) +
            " (live capture needs CAP_NET_RAW or root)";
    return nullptr;
  }
  src->fd_ = fd;

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, opt.interface.c_str(), IFNAMSIZ - 1);
  if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    error = "no such interface: " + opt.interface;
    return nullptr;
  }

  sockaddr_ll addr{};
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = ifr.ifr_ifindex;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    error = std::string("bind: ") + std::strerror(errno);
    return nullptr;
  }

  if (opt.promiscuous) {
    packet_mreq mreq{};
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      error = std::string("promiscuous mode: ") + std::strerror(errno);
      return nullptr;
    }
  }

  src->buffer_.resize(opt.snaplen);
  src->link_type_ = static_cast<uint32_t>(LinkType::kEthernet);
  return src;
}

size_t LiveCaptureSource::next_batch(PcapPacket* out, size_t max) {
  if (stopped_ || fd_ < 0) return 0;
  size_t produced = 0;

  // One packet per read; the buffer is reused, so each batch entry views the
  // bytes read for it. Callers must consume a batch before the next call.
  while (produced < max) {
    pollfd pfd{fd_, POLLIN, 0};
    const int ready = ::poll(&pfd, 1, produced == 0 ? static_cast<int>(opt_.poll_timeout_ms) : 0);
    if (ready <= 0) break;

    const size_t offset = produced * opt_.snaplen;
    if (buffer_.size() < offset + opt_.snaplen) buffer_.resize(offset + opt_.snaplen);
    const ssize_t n = ::recv(fd_, buffer_.data() + offset, opt_.snaplen, MSG_DONTWAIT);
    if (n <= 0) break;

    out[produced].data = Bytes(buffer_.data() + offset, static_cast<size_t>(n));
    out[produced].ts_ns = now_ns();
    out[produced].orig_len = static_cast<uint32_t>(n);
    ++produced;
  }
  return produced;
}

#elif defined(__APPLE__)

std::unique_ptr<LiveCaptureSource> LiveCaptureSource::open(const Options& opt, std::string& error) {
  auto src = std::unique_ptr<LiveCaptureSource>(new LiveCaptureSource());
  src->opt_ = opt;

  int fd = -1;
  char path[32];
  for (int i = 0; i < 256; ++i) {
    std::snprintf(path, sizeof(path), "/dev/bpf%d", i);
    fd = ::open(path, O_RDONLY);
    if (fd >= 0) break;
    if (errno != EBUSY) break;
  }
  if (fd < 0) {
    error = std::string("open /dev/bpf*: ") + std::strerror(errno) +
            " (live capture needs root on macOS)";
    return nullptr;
  }
  src->fd_ = fd;

  unsigned int buf_len = 1 << 20;
  if (::ioctl(fd, BIOCSBLEN, &buf_len) < 0) {
    error = std::string("BIOCSBLEN: ") + std::strerror(errno);
    return nullptr;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, opt.interface.c_str(), IFNAMSIZ - 1);
  if (::ioctl(fd, BIOCSETIF, &ifr) < 0) {
    error = "cannot attach to interface " + opt.interface + ": " + std::strerror(errno);
    return nullptr;
  }

  unsigned int enable = 1;
  (void)::ioctl(fd, BIOCIMMEDIATE, &enable);
  if (opt.promiscuous) (void)::ioctl(fd, BIOCPROMISC, nullptr);

  unsigned int dlt = 0;
  if (::ioctl(fd, BIOCGDLT, &dlt) == 0 && dlt == DLT_RAW) {
    src->link_type_ = static_cast<uint32_t>(LinkType::kRawIp);
  } else {
    src->link_type_ = static_cast<uint32_t>(LinkType::kEthernet);
  }

  src->buffer_.resize(buf_len);
  return src;
}

size_t LiveCaptureSource::next_batch(PcapPacket* out, size_t max) {
  if (stopped_ || fd_ < 0) return 0;

  size_t produced = 0;
  while (produced < max) {
    if (buffer_offset_ >= buffer_used_) {
      pollfd pfd{fd_, POLLIN, 0};
      const int ready = ::poll(&pfd, 1, produced == 0 ? static_cast<int>(opt_.poll_timeout_ms) : 0);
      if (ready <= 0) break;

      const ssize_t n = ::read(fd_, buffer_.data(), buffer_.size());
      if (n <= 0) break;
      buffer_used_ = static_cast<size_t>(n);
      buffer_offset_ = 0;
    }

    // BPF returns a batch of records, each prefixed by a bpf_hdr and aligned
    // to BPF_WORDALIGN.
    if (buffer_offset_ + sizeof(bpf_hdr) > buffer_used_) {
      buffer_offset_ = buffer_used_;
      continue;
    }
    bpf_hdr hdr{};
    std::memcpy(&hdr, buffer_.data() + buffer_offset_, sizeof(hdr));
    const size_t data_off = buffer_offset_ + hdr.bh_hdrlen;
    if (data_off + hdr.bh_caplen > buffer_used_) {
      buffer_offset_ = buffer_used_;
      continue;
    }

    out[produced].data = Bytes(buffer_.data() + data_off, hdr.bh_caplen);
    out[produced].ts_ns = static_cast<uint64_t>(hdr.bh_tstamp.tv_sec) * 1'000'000'000ULL +
                          static_cast<uint64_t>(hdr.bh_tstamp.tv_usec) * 1000ULL;
    out[produced].orig_len = hdr.bh_datalen;
    ++produced;

    buffer_offset_ += BPF_WORDALIGN(hdr.bh_hdrlen + hdr.bh_caplen);
  }
  return produced;
}

#else

std::unique_ptr<LiveCaptureSource> LiveCaptureSource::open(const Options&, std::string& error) {
  error = "live capture is not implemented on this platform; use pcap replay";
  return nullptr;
}

size_t LiveCaptureSource::next_batch(PcapPacket*, size_t) {
  return 0;
}

#endif

}  // namespace gtpm
