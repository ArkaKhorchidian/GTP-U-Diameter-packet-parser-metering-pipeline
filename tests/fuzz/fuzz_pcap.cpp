// SPDX-License-Identifier: MIT
//
// libFuzzer target for the pcap reader. Capture files come from other people's
// machines and other people's tools; the reader must survive whatever is in
// them.
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "gtpm/pcap.hpp"
#include "gtpm/pipeline.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 1u << 20) return 0;

  // PcapFile::load takes a path, so stage the input in a temp file.
  char path[] = "/tmp/gtpm-fuzz-pcap-XXXXXX";
  const int fd = ::mkstemp(path);
  if (fd < 0) return 0;
  std::FILE* f = ::fdopen(fd, "wb");
  if (f == nullptr) {
    ::close(fd);
    ::remove(path);
    return 0;
  }
  (void)std::fwrite(data, 1, size, f);
  std::fclose(f);

  gtpm::PcapFile file;
  const gtpm::PcapFile::Result result = gtpm::PcapFile::load(path, file);
  ::remove(path);
  if (!result.ok()) return 0;

  gtpm::Ingest ingest(nullptr, nullptr);
  for (const gtpm::PcapPacket& packet : file.packets()) {
    const gtpm::LinkLayer link = gtpm::strip_link_layer(file.link_type(), packet.data);
    if (!link.valid) continue;
    if (link.is_ethernet) {
      (void)ingest.process_frame(link.payload, packet.ts_ns);
    } else {
      (void)ingest.process_ip(link.payload, packet.ts_ns,
                              static_cast<uint16_t>(link.payload.size()));
    }
  }
  return 0;
}
