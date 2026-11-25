// SPDX-License-Identifier: Apache-2.0
// nanocraft/gather.hpp — scatter-gather frame descriptions.
//
// A gather is a frame described as up to four byte ranges that are sent (or written) back to back:
// typically [headers from a template arena][a span of the caller's payload], so segmentation never
// copies payload. A chunk has the exact layout of POSIX `struct iovec` (pointer, length), so a
// gather's chunks can be handed to writev / sendmsg / sendmmsg as they are (see linux_tx.hpp).
//
//   nanocraft::gather g;
//   g.add(hdr.data(), hdr.size());
//   g.add(payload.subspan(off, n));
//   std::size_t len = g.size();             // total bytes
//   g.copy_to(dst);                         // contiguous fallback (dst.size() >= g.size())
#ifndef NANOCRAFT_GATHER_HPP_INCLUDED
#define NANOCRAFT_GATHER_HPP_INCLUDED

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace nanocraft {

/// One contiguous byte range; layout-compatible with struct iovec.
struct chunk {
  const void* base = nullptr;
  std::size_t len = 0;
  std::span<const std::byte> bytes() const noexcept { return {static_cast<const std::byte*>(base), len}; }
};

/// A frame as an ordered list of chunks (at most max_chunks).
struct gather {
  static constexpr std::size_t max_chunks = 4;
  std::array<chunk, max_chunks> chunks{};
  std::uint32_t count = 0;
  std::size_t total = 0;

  void add(const void* p, std::size_t n) noexcept {
    if (n == 0) return;
    assert(count < max_chunks);
    chunks[count++] = chunk{p, n};
    total += n;
  }
  void add(std::span<const std::byte> s) noexcept { add(s.data(), s.size()); }
  std::size_t size() const noexcept { return total; }
  std::span<const chunk> parts() const noexcept { return {chunks.data(), count}; }

  /// Contiguous fallback: copy all chunks to dst. Returns the bytes written (0 if dst is too small).
  std::size_t copy_to(std::span<std::byte> dst) const noexcept {
    if (dst.size() < total) return 0;
    std::byte* w = dst.data();
    for (std::uint32_t i = 0; i < count; ++i) {
      std::memcpy(w, chunks[i].base, chunks[i].len);
      w += chunks[i].len;
    }
    return total;
  }
  /// Copy at most dst.size() bytes (a truncated capture).
  std::size_t copy_prefix(std::span<std::byte> dst) const noexcept {
    std::size_t w = 0;
    for (std::uint32_t i = 0; i < count && w < dst.size(); ++i) {
      const std::size_t n = std::min(chunks[i].len, dst.size() - w);
      std::memcpy(dst.data() + w, chunks[i].base, n);
      w += n;
    }
    return w;
  }
};

}  // namespace nanocraft

#endif  // NANOCRAFT_GATHER_HPP_INCLUDED
