// SPDX-License-Identifier: MIT
//
// Endian-safe scalar loads over a byte span.
//
// Every read is bounds-checked by the caller (parsers validate remaining length
// before calling) and performed via memcpy so the compiler emits a single
// unaligned load plus a byte-swap; no strict-aliasing or alignment UB.
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <span>

namespace gtpm {

using Bytes = std::span<const uint8_t>;

[[nodiscard]] inline uint8_t load_u8(const uint8_t* p) noexcept { return *p; }

[[nodiscard]] inline uint16_t load_be16(const uint8_t* p) noexcept {
  uint16_t v;
  std::memcpy(&v, p, sizeof(v));
  if constexpr (std::endian::native == std::endian::little) {
    v = static_cast<uint16_t>((v >> 8) | (v << 8));
  }
  return v;
}

[[nodiscard]] inline uint32_t load_be24(const uint8_t* p) noexcept {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) |
         static_cast<uint32_t>(p[2]);
}

[[nodiscard]] inline uint32_t load_be32(const uint8_t* p) noexcept {
  uint32_t v;
  std::memcpy(&v, p, sizeof(v));
  if constexpr (std::endian::native == std::endian::little) {
    v = __builtin_bswap32(v);
  }
  return v;
}

[[nodiscard]] inline uint64_t load_be64(const uint8_t* p) noexcept {
  uint64_t v;
  std::memcpy(&v, p, sizeof(v));
  if constexpr (std::endian::native == std::endian::little) {
    v = __builtin_bswap64(v);
  }
  return v;
}

[[nodiscard]] inline uint16_t load_le16(const uint8_t* p) noexcept {
  uint16_t v;
  std::memcpy(&v, p, sizeof(v));
  if constexpr (std::endian::native == std::endian::big) {
    v = static_cast<uint16_t>((v >> 8) | (v << 8));
  }
  return v;
}

[[nodiscard]] inline uint32_t load_le32(const uint8_t* p) noexcept {
  uint32_t v;
  std::memcpy(&v, p, sizeof(v));
  if constexpr (std::endian::native == std::endian::big) {
    v = __builtin_bswap32(v);
  }
  return v;
}

inline void store_be16(uint8_t* p, uint16_t v) noexcept {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

inline void store_be24(uint8_t* p, uint32_t v) noexcept {
  p[0] = static_cast<uint8_t>(v >> 16);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v);
}

inline void store_be32(uint8_t* p, uint32_t v) noexcept {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

inline void store_le16(uint8_t* p, uint16_t v) noexcept {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}

inline void store_le32(uint8_t* p, uint32_t v) noexcept {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

}  // namespace gtpm
