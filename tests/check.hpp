// SPDX-License-Identifier: Apache-2.0
// Minimal test harness: CHECK / CHECK_EQ count failures; main returns non-zero on any failure, 77 to skip.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <span>
#include <string>
#include <vector>

namespace t {
inline int failures = 0;
inline int checks = 0;
inline void fail(const char* file, int line, const std::string& what) {
  ++failures;
  if (failures <= 30) std::fprintf(stderr, "%s:%d: FAILED: %s\n", file, line, what.c_str());
}
inline int done(const char* name) {
  std::printf("%s: %d checks, %d failures\n", name, checks, failures);
  return failures ? 1 : 0;
}
inline std::string hex(std::span<const std::byte> b, std::size_t max = 128) {
  std::string s;
  char tmp[4];
  for (std::size_t i = 0; i < b.size() && i < max; ++i) {
    std::snprintf(tmp, sizeof tmp, "%02x", unsigned(b[i]));
    s += tmp;
    if (i % 16 == 15) s += '\n';
    else s += ' ';
  }
  return s;
}
inline bool same(std::span<const std::byte> a, std::span<const std::byte> b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}
inline std::mt19937_64& rng() {
  static std::mt19937_64 r(0x5eed1234);
  return r;
}
inline std::uint64_t rnd(std::uint64_t lo, std::uint64_t hi) {  // inclusive
  return std::uniform_int_distribution<std::uint64_t>(lo, hi)(rng());
}
inline std::vector<std::byte> random_bytes(std::size_t n) {
  std::vector<std::byte> v(n);
  for (auto& b : v) b = std::byte(rnd(0, 255));
  return v;
}
}  // namespace t

#define CHECK(c)                                                  \
  do {                                                            \
    ++t::checks;                                                  \
    if (!(c)) t::fail(__FILE__, __LINE__, #c);                    \
  } while (0)
#define CHECK_MSG(c, msg)                                               \
  do {                                                                  \
    ++t::checks;                                                        \
    if (!(c)) t::fail(__FILE__, __LINE__, std::string(#c) + ": " + (msg)); \
  } while (0)
#define CHECK_EQ(a, b)                                                                                  \
  do {                                                                                                  \
    ++t::checks;                                                                                        \
    const auto va_ = (a);                                                                               \
    const auto vb_ = (b);                                                                               \
    if (!(va_ == vb_))                                                                                  \
      t::fail(__FILE__, __LINE__,                                                                       \
              std::string(#a " == " #b " (") + std::to_string(va_) + " vs " + std::to_string(vb_) + ")"); \
  } while (0)
#define CHECK_BYTES(a, b)                                                                                 \
  do {                                                                                                    \
    ++t::checks;                                                                                          \
    if (!t::same((a), (b)))                                                                               \
      t::fail(__FILE__, __LINE__, std::string(#a " == " #b "\n got:\n") + t::hex(a) + "\n want:\n" + t::hex(b)); \
  } while (0)
