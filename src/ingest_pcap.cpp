// SPDX-License-Identifier: MIT
//
// pcap replay source. The capture is loaded once and replayed from memory so a
// throughput run measures the pipeline and not the page cache.
#include "gtpm/source.hpp"

namespace gtpm {

std::unique_ptr<PcapReplaySource> PcapReplaySource::open(const std::string& path, Options opt,
                                                         std::string& error) {
  auto src = std::unique_ptr<PcapReplaySource>(new PcapReplaySource());
  const PcapFile::Result r = PcapFile::load(path, src->file_);
  if (!r.ok()) {
    error = r.error;
    return nullptr;
  }
  if (src->file_.packets().empty()) {
    error = "capture contains no packets: " + path;
    return nullptr;
  }
  src->opt_ = opt;
  return src;
}

size_t PcapReplaySource::next_batch(PcapPacket* out, size_t max) {
  if (exhausted_ || stopped_) return 0;
  const std::vector<PcapPacket>& packets = file_.packets();

  size_t produced = 0;
  while (produced < max) {
    if (cursor_ >= packets.size()) {
      ++loop_;
      if (opt_.loops != 0 && loop_ >= opt_.loops) {
        exhausted_ = true;
        break;
      }
      cursor_ = 0;
    }
    out[produced] = packets[cursor_++];
    bytes_ += out[produced].data.size();
    ++produced;
    ++replayed_;
  }
  return produced;
}

}  // namespace gtpm
