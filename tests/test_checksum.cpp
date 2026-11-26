// SPDX-License-Identifier: Apache-2.0
// nanocraft::csum against the naive RFC 1071 implementation; RFC 1624 incremental updates against
// recomputation from scratch.
#include <nanocraft/checksum.hpp>

#include "check.hpp"
#include "reference.hpp"

namespace cs = nanocraft::csum;

int main() {
  // sum(): every length 0..300 at every alignment 0..7, random contents
  auto big = t::random_bytes(4096);
  for (std::size_t n = 0; n <= 300; ++n)
    for (std::size_t a = 0; a < 8; ++a) {
      std::span<const std::byte> b(big.data() + a, n);
      CHECK_EQ(cs::fold(cs::sum(b)), ref::naive_sum(b));
    }
  // large buffers, including all-0xff (carry-heavy) content
  std::vector<std::byte> ff(70000, std::byte{0xff});
  CHECK_EQ(cs::fold(cs::sum(ff)), ref::naive_sum(ff));
  auto r = t::random_bytes(65537);
  CHECK_EQ(cs::fold(cs::sum(r)), ref::naive_sum(r));
  // constexpr path agrees
  static constexpr std::array<std::byte, 5> k{std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x54},
                                              std::byte{0x12}};
  static_assert(cs::sum(k.data(), k.size()) == 0x5754);
  CHECK_EQ(cs::sum(k.data(), k.size()), cs::sum(std::span<const std::byte>(k)));
  // odd-position sums are byte-swapped sums: sum(x ++ y) == sum(x) + swap(sum(y)) for odd |x|
  for (int it = 0; it < 2000; ++it) {
    auto x = t::random_bytes(t::rnd(0, 40) * 2 + 1), y = t::random_bytes(t::rnd(0, 81));
    std::vector<std::byte> xy = x;
    xy.insert(xy.end(), y.begin(), y.end());
    CHECK_EQ(cs::add(cs::sum(x), cs::swap(cs::sum(y))), ref::naive_sum(xy));
  }
  // RFC 1624 eqn. 3: patch random 16-bit-aligned windows, compare with recomputation
  for (int it = 0; it < 20000; ++it) {
    auto h = t::random_bytes(20);
    h[10] = h[11] = std::byte{0};
    std::uint16_t c = ref::naive_csum(h);
    h[10] = std::byte(c >> 8);
    h[11] = std::byte(c);
    for (int step = 0; step < 4; ++step) {
      std::size_t w = 2 * t::rnd(0, 9);
      if (w == 10) w = 0;
      const std::size_t len = std::min<std::size_t>(2 * t::rnd(1, 3), 20 - w);
      if (w < 12 && w + len > 10) continue;  // never the checksum word itself
      const std::uint32_t old = cs::sum(h.data() + w, len);
      for (std::size_t i = 0; i < len; ++i) h[w + i] = std::byte(t::rnd(0, 255));
      c = cs::update(c, old, cs::sum(h.data() + w, len));
      h[10] = std::byte(c >> 8);
      h[11] = std::byte(c);
    }
    CHECK_EQ(ref::naive_sum(h), 0xffffu);
    auto z = h;
    z[10] = z[11] = std::byte{0};
    CHECK_EQ(unsigned(c), unsigned(ref::naive_csum(z)));
  }
  // the classic RFC 1624 example: HC = 0xdd2f, m = 0x5555 -> m' = 0x3285: HC' = 0x0000
  CHECK_EQ(unsigned(cs::update(0xdd2f, 0x5555, 0x3285)), 0x0000u);
  CHECK_EQ(cs::finish(0xffff), 0u);
  return t::done("test_checksum");
}
