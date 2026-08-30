// SPDX-License-Identifier: MIT
//
// A main() for the fuzz targets when libFuzzer is not available.
//
// Apple clang ships no libFuzzer, and a fuzz harness that only builds on one
// toolchain stops being run. This driver replays corpus files given on the
// command line and, with no arguments, generates deterministic pseudo-random
// inputs — enough to catch a crash in CI on any compiler, and it keeps the
// harnesses compiling so the real libFuzzer runs never bit-rot.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

int replay_file(const char* path) {
  std::FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    std::fprintf(stderr, "cannot open %s\n", path);
    return 1;
  }
  std::fseek(f, 0, SEEK_END);
  const long size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> buf(size > 0 ? static_cast<size_t>(size) : 0);
  if (!buf.empty()) {
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) {
      std::fclose(f);
      return 1;
    }
  }
  std::fclose(f);
  (void)LLVMFuzzerTestOneInput(buf.data(), buf.size());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::strcmp(argv[1], "--random") != 0) {
    for (int i = 1; i < argc; ++i) {
      if (replay_file(argv[i]) != 0) return 1;
    }
    std::printf("replayed %d corpus file(s)\n", argc - 1);
    return 0;
  }

  const uint64_t iterations =
      argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 50000;
  const uint32_t seed = argc > 3 ? static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10))
                                 : 0x5EED;

  std::mt19937 rng(seed);
  std::vector<uint8_t> buf;
  buf.reserve(2048);

  for (uint64_t i = 0; i < iterations; ++i) {
    const size_t size = rng() % 512;
    buf.resize(size);
    for (size_t j = 0; j < size; ++j) buf[j] = static_cast<uint8_t>(rng());

    // Steer a share of the inputs toward plausible framing so the harness
    // reaches past the first length check instead of only testing rejection.
    if (size > 16) {
      switch (i % 4) {
        case 0: buf[0] = 0x30 | static_cast<uint8_t>(rng() & 0x07); break;  // GTP-U v1
        case 1: buf[0] = 0x45; break;                                       // IPv4
        case 2: buf[0] = 1; break;                                          // Diameter v1
        default: break;
      }
    }
    (void)LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("ran %llu pseudo-random inputs (seed %u) with no crash\n",
              static_cast<unsigned long long>(iterations), seed);
  return 0;
}
