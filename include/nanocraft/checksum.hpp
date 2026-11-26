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
// Thin forwarding layer over <nanom/checksum.hpp> (nanom::inet::*).
#ifndef NANOCRAFT_CHECKSUM_HPP_INCLUDED
#define NANOCRAFT_CHECKSUM_HPP_INCLUDED

#include <nanom/checksum.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace nanocraft::csum {

/// Fold a partial sum to 16 bits (end-around carry), NOT complemented.
constexpr std::uint16_t fold(std::uint64_t s) noexcept {
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffffffu) + (s >> 32);
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
constexpr std::uint16_t finish(std::uint32_t s) noexcept { return nanom::inet::sum{}.add_folded(fold(s)).checksum(); }

/// Partial ones'-complement sum of n bytes as big-endian 16-bit words (a trailing odd byte is the
/// high half of a zero-padded word).
constexpr std::uint32_t sum(std::span<const std::byte> b) noexcept { return nanom::inet::sum{}.add(b).folded(); }
constexpr std::uint32_t sum(const std::byte* p, std::size_t n) noexcept { return sum(std::span<const std::byte>(p, n)); }

/// RFC 1624 eqn. 3: the stored checksum hc after 16-bit-word content with partial sum `old_sum`
/// became `new_sum`. Never produces the -0 artefact of eqn. 2.
constexpr std::uint16_t update(std::uint16_t hc, std::uint32_t old_sum, std::uint32_t new_sum) noexcept {
  return nanom::inet::update16(hc, fold(old_sum), fold(new_sum));
}

/// Same update for a field that stores the folded sum itself (not complemented): the pseudo-header
/// seed of a checksum offloaded to the NIC (CHECKSUM_PARTIAL).
constexpr std::uint16_t update_sum(std::uint16_t stored, std::uint32_t old_sum, std::uint32_t new_sum) noexcept {
  return std::uint16_t(~nanom::inet::update16(std::uint16_t(~stored), fold(old_sum), fold(new_sum)));
}

}  // namespace nanocraft::csum

#endif  // NANOCRAFT_CHECKSUM_HPP_INCLUDED
