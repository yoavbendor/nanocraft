// SPDX-License-Identifier: Apache-2.0
// nanocraft/checksum.hpp — the Internet checksum (RFC 1071) and its incremental update (RFC 1624).
//
//   std::uint32_t s = nanocraft::csum::sum(bytes);          // ones'-complement partial sum
//   std::uint16_t c = nanocraft::csum::finish(s);           // ~fold(s): the value to store
//   c = nanocraft::csum::update(c, old_words, new_words);   // RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m')
//
// Partial sums are plain 32-bit accumulators that may be added freely (combine with add()) and are
// folded only at the end. A sum over bytes starting at an odd position of the checksummed stream
// must be byte-swapped before it is combined (swap()); sum() of a span always starts at an even
// position. All functions are constexpr and allocation-free; sum() reads 8 bytes per step.
//
// nanom is gaining include/nanom/checksum.hpp with the same primitives; once a nanom release with
// it is pinned, this header becomes a thin forwarding layer.
#ifndef NANOCRAFT_CHECKSUM_HPP_INCLUDED
#define NANOCRAFT_CHECKSUM_HPP_INCLUDED

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace nanocraft::csum {

/// Fold a partial sum to 16 bits (end-around carry), NOT complemented.
constexpr std::uint16_t fold(std::uint64_t s) noexcept {
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  return std::uint16_t(s);
}

/// Ones'-complement addition of two partial sums (result folded to 16 bits).
constexpr std::uint16_t add(std::uint32_t a, std::uint32_t b) noexcept { return fold(std::uint64_t(a) + b); }

/// The byte-swapped sum: what the same bytes contribute when they start at an odd stream position.
constexpr std::uint16_t swap(std::uint32_t s) noexcept {
  const std::uint16_t f = fold(s);
  return std::uint16_t((f << 8) | (f >> 8));
}

/// The value to store in a checksum field for a stream whose partial sum is s.
constexpr std::uint16_t finish(std::uint32_t s) noexcept { return std::uint16_t(~fold(s)); }

/// Partial ones'-complement sum of n bytes as big-endian 16-bit words (a trailing odd byte is the
/// high half of a zero-padded word).
constexpr std::uint32_t sum(const std::byte* p, std::size_t n) noexcept {
  if consteval {
    std::uint64_t s = 0;
    std::size_t i = 0;
    for (; i + 1 < n; i += 2) s += (std::uint32_t(std::uint8_t(p[i])) << 8) | std::uint8_t(p[i + 1]);
    if (i < n) s += std::uint32_t(std::uint8_t(p[i])) << 8;
    return fold(s);
  } else {
    // Native-order accumulation: the ones'-complement sum is byte-order independent, so sum the
    // words as the host sees them and swap once at the end on little-endian hosts.
    std::uint64_t acc = 0;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8) {
      std::uint64_t w;
      std::memcpy(&w, p + i, 8);
      acc += (w & 0xffffffffu) + (w >> 32);
    }
    if (i + 4 <= n) {
      std::uint32_t w;
      std::memcpy(&w, p + i, 4);
      acc += w;
      i += 4;
    }
    if (i + 2 <= n) {
      std::uint16_t w;
      std::memcpy(&w, p + i, 2);
      acc += w;
      i += 2;
    }
    if (i < n) {
      // the odd byte is the high (first) byte of its big-endian word
      if constexpr (std::endian::native == std::endian::little) acc += std::uint8_t(p[i]);
      else acc += std::uint32_t(std::uint8_t(p[i])) << 8;
    }
    std::uint16_t f = fold(acc);
    if constexpr (std::endian::native == std::endian::little) f = std::uint16_t((f << 8) | (f >> 8));
    return f;
  }
}
constexpr std::uint32_t sum(std::span<const std::byte> b) noexcept { return sum(b.data(), b.size()); }

/// RFC 1624 eqn. 3: the stored checksum hc after 16-bit-word content with partial sum `old_sum`
/// became `new_sum`. Never produces the -0 artefact of eqn. 2.
constexpr std::uint16_t update(std::uint16_t hc, std::uint32_t old_sum, std::uint32_t new_sum) noexcept {
  const std::uint32_t s = std::uint32_t(std::uint16_t(~hc)) + std::uint16_t(~fold(old_sum)) + fold(new_sum);
  return std::uint16_t(~fold(s));
}

/// Same update for a field that stores the folded sum itself (not complemented): the pseudo-header
/// seed of a checksum offloaded to the NIC (CHECKSUM_PARTIAL).
constexpr std::uint16_t update_sum(std::uint16_t stored, std::uint32_t old_sum, std::uint32_t new_sum) noexcept {
  return fold(std::uint32_t(stored) + std::uint16_t(~fold(old_sum)) + fold(new_sum));
}

}  // namespace nanocraft::csum

#endif  // NANOCRAFT_CHECKSUM_HPP_INCLUDED
