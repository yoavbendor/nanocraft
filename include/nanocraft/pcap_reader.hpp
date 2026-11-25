// SPDX-License-Identifier: Apache-2.0
// nanocraft/pcap_reader.hpp — a strict, zero-copy pcap / pcapng reader (for replay and for tests).
//
//   auto file = nanocraft::mapped_file::open("in.pcapng");     // or any std::span<const std::byte>
//   nanocraft::capture_reader r(file.bytes());
//   nanocraft::packet p;
//   while (r.next(p)) use(p.ts_ns, p.data, p.interface, p.flags, p.comment);
//   if (!r.error().empty()) fail(r.error());
//
// Both byte orders, pcap us/ns magics, pcapng sections / IDBs (if_tsresol decimal and binary) /
// EPBs (epb_flags, opt_comment) / SPBs; unknown blocks are skipped. "Strict" means every framing
// rule is checked and the first violation stops the read with a message: block length >= 12 and a
// multiple of 4, trailing length equal to the leading one, options inside their block, EPB on a
// known interface, caplen <= origlen and inside the block, pcap fraction < 1 s.
#ifndef NANOCRAFT_PCAP_READER_HPP_INCLUDED
#define NANOCRAFT_PCAP_READER_HPP_INCLUDED

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if __has_include(<sys/mman.h>) && __has_include(<fcntl.h>) && __has_include(<unistd.h>)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#define NANOCRAFT_HAS_MMAP 1
#endif

namespace nanocraft {

/// One captured frame (views into the file; valid while the file is).
struct packet {
  std::uint64_t ts_ns = 0;
  std::uint32_t interface = 0;
  std::uint32_t linktype = 0;
  std::uint32_t origlen = 0;
  std::span<const std::byte> data{};
  std::optional<std::uint32_t> flags{};
  std::string_view comment{};
};

struct capture_interface {
  std::uint32_t linktype = 0;
  std::uint32_t snaplen = 0;
  std::uint64_t units_per_sec = 1000000;  ///< timestamp resolution
  std::string_view name{};
};

class capture_reader {
 public:
  enum class format { unknown, pcap, pcapng };

  explicit capture_reader(std::span<const std::byte> file) : f_(file) {
    if (f_.size() < 4) {
      fail("file too small");
      return;
    }
    const std::uint32_t m = rd32le(0);
    if (m == 0x0a0d0d0au) {
      fmt_ = format::pcapng;
      return;
    }
    if (m == 0xa1b2c3d4u || m == 0xa1b23c4du || m == 0xd4c3b2a1u || m == 0x4d3cb2a1u) {
      fmt_ = format::pcap;
      little_ = (m == 0xa1b2c3d4u || m == 0xa1b23c4du);
      if (f_.size() < 24) {
        fail("truncated pcap global header");
        return;
      }
      const bool ns = (m == 0xa1b23c4du || m == 0x4d3cb2a1u);
      if (rd16(4) != 2 || rd16(6) != 4) {
        fail("pcap version is not 2.4");
        return;
      }
      ifaces_.push_back({rd32(20), rd32(16), ns ? 1000000000ull : 1000000ull, {}});
      pos_ = 24;
      return;
    }
    fail("not a pcap or pcapng file");
  }

  format kind() const noexcept { return fmt_; }
  std::string_view error() const noexcept { return err_; }
  std::span<const capture_interface> interfaces() const noexcept { return ifaces_; }
  std::size_t position() const noexcept { return pos_; }

  /// The next frame; false at the end of the file or on the first error (see error()).
  bool next(packet& p) {
    if (!err_.empty()) return false;
    if (fmt_ == format::pcap) return next_pcap(p);
    if (fmt_ == format::pcapng) return next_pcapng(p);
    return false;
  }

 private:
  bool fail(std::string m) {
    if (err_.empty()) err_ = std::move(m) + " (at offset " + std::to_string(pos_) + ")";
    return false;
  }
  std::uint16_t rd16(std::size_t o) const {
    std::uint16_t v;
    std::memcpy(&v, f_.data() + o, 2);
    return (little_ == (std::endian::native == std::endian::little)) ? v : std::uint16_t((v >> 8) | (v << 8));
  }
  std::uint32_t rd32(std::size_t o) const {
    std::uint32_t v;
    std::memcpy(&v, f_.data() + o, 4);
    return (little_ == (std::endian::native == std::endian::little)) ? v : std::byteswap(v);
  }
  std::uint32_t rd32le(std::size_t o) const {
    std::uint32_t v;
    std::memcpy(&v, f_.data() + o, 4);
    return std::endian::native == std::endian::little ? v : std::byteswap(v);
  }

  bool next_pcap(packet& p) {
    if (pos_ == f_.size()) return false;
    if (f_.size() - pos_ < 16) return fail("truncated pcap record header");
    const std::uint32_t sec = rd32(pos_), frac = rd32(pos_ + 4), cap = rd32(pos_ + 8), orig = rd32(pos_ + 12);
    const auto& itf = ifaces_[0];
    if (frac >= itf.units_per_sec) return fail("pcap timestamp fraction >= 1 s");
    if (cap > orig) return fail("pcap caplen > origlen");
    if (cap > f_.size() - pos_ - 16) return fail("truncated pcap record");
    p = packet{};
    p.ts_ns = std::uint64_t(sec) * 1000000000u + std::uint64_t(frac) * (1000000000u / itf.units_per_sec);
    p.linktype = itf.linktype;
    p.origlen = orig;
    p.data = f_.subspan(pos_ + 16, cap);
    pos_ += 16 + cap;
    return true;
  }

  // Options [code u16][len u16][value, padded to 4]... in [b, e). Calls fn(code, value).
  template <class Fn>
  bool options(std::size_t b, std::size_t e, Fn&& fn) {
    while (b < e) {
      if (e - b < 4) return fail("truncated option header");
      const std::uint16_t code = rd16(b), len = rd16(b + 2);
      if (code == 0) return true;  // opt_endofopt
      const std::size_t padded = (std::size_t(len) + 3) & ~std::size_t{3};
      if (padded > e - b - 4) return fail("option overruns its block");
      if (!fn(code, f_.subspan(b + 4, len))) return false;
      b += 4 + padded;
    }
    return true;
  }

  bool next_pcapng(packet& p) {
    for (;;) {
      if (pos_ == f_.size()) return false;
      if (f_.size() - pos_ < 12) return fail("truncated block header");
      const std::uint32_t type_le = rd32le(pos_);
      if (type_le == 0x0a0d0d0au) {  // SHB: learn the section's byte order first
        if (f_.size() - pos_ < 28) return fail("truncated SHB");
        const std::uint32_t bom = rd32le(pos_ + 8);
        if (bom == 0x1a2b3c4du) little_ = true;
        else if (bom == 0x4d3c2b1au) little_ = false;
        else return fail("bad SHB byte-order magic");
      } else if (!seen_shb_) {
        return fail("first block is not an SHB");
      }
      const std::uint32_t type = rd32(pos_), total = rd32(pos_ + 4);
      if (total < 12 || total % 4 != 0) return fail("bad block total length");
      if (total > f_.size() - pos_) return fail("block overruns the file");
      if (rd32(pos_ + total - 4) != total) return fail("trailing block length differs");
      const std::size_t b = pos_, e = pos_ + total - 4;
      pos_ += total;
      switch (type) {
        case 0x0a0d0d0au: {
          if (rd16(b + 12) != 1) return fail("SHB major version is not 1");
          seen_shb_ = true;
          ifaces_.clear();
          if (!options(b + 24, e, [](std::uint16_t, auto) { return true; })) return false;
          break;
        }
        case 1: {
          if (total < 20) return fail("IDB too short");
          capture_interface itf{rd16(b + 8), rd32(b + 12), 1000000, {}};
          bool good = options(b + 16, e, [&](std::uint16_t code, std::span<const std::byte> v) {
            if (code == 9) {
              if (v.size() != 1) return fail("if_tsresol length is not 1");
              const std::uint8_t r = std::uint8_t(v[0]);
              std::uint64_t u = 1;
              if (r & 0x80) {
                if ((r & 0x7f) > 63) return fail("if_tsresol out of range");
                u = std::uint64_t(1) << (r & 0x7f);
              } else {
                if (r > 19) return fail("if_tsresol out of range");
                for (int k = 0; k < r; ++k) u *= 10;
              }
              itf.units_per_sec = u;
            } else if (code == 2) {
              itf.name = {reinterpret_cast<const char*>(v.data()), v.size()};
            }
            return true;
          });
          if (!good) return false;
          ifaces_.push_back(itf);
          break;
        }
        case 6: {
          if (total < 32) return fail("EPB too short");
          const std::uint32_t id = rd32(b + 8), hi = rd32(b + 12), lo = rd32(b + 16), cap = rd32(b + 20),
                              orig = rd32(b + 24);
          if (id >= ifaces_.size()) return fail("EPB on an undeclared interface");
          if (cap > orig) return fail("EPB caplen > origlen");
          const std::size_t dend = b + 28 + ((std::size_t(cap) + 3) & ~std::size_t{3});
          if (dend > e) return fail("EPB data overruns its block");
          const auto& itf = ifaces_[id];
          p = packet{};
          const std::uint64_t ts = (std::uint64_t(hi) << 32) | lo;
          p.ts_ns = to_ns(ts, itf.units_per_sec);
          p.interface = id;
          p.linktype = itf.linktype;
          p.origlen = orig;
          p.data = f_.subspan(b + 28, cap);
          bool good = options(dend, e, [&](std::uint16_t code, std::span<const std::byte> v) {
            if (code == 2) {
              if (v.size() != 4) return fail("epb_flags length is not 4");
              std::uint32_t fl;
              std::memcpy(&fl, v.data(), 4);
              if (little_ != (std::endian::native == std::endian::little)) fl = std::byteswap(fl);
              p.flags = fl;
            } else if (code == 1) {
              p.comment = {reinterpret_cast<const char*>(v.data()), v.size()};
            }
            return true;
          });
          if (!good) return false;
          return true;
        }
        case 3: {
          if (ifaces_.empty()) return fail("SPB without an interface");
          if (total < 16) return fail("SPB too short");
          const std::uint32_t orig = rd32(b + 8);
          const std::size_t room = total - 16;
          const std::size_t cap = std::min<std::size_t>(orig, ifaces_[0].snaplen ? ifaces_[0].snaplen : orig);
          if (cap > room) return fail("SPB data overruns its block");
          p = packet{};
          p.linktype = ifaces_[0].linktype;
          p.origlen = orig;
          p.data = f_.subspan(b + 12, cap);
          return true;
        }
        default: break;  // unknown block: skipped
      }
    }
  }

  static std::uint64_t to_ns(std::uint64_t ts, std::uint64_t ups) {
    if (ups == 1000000000u) return ts;
    if (ups < 1000000000u && 1000000000u % ups == 0) return ts * (1000000000u / ups);
    return std::uint64_t((__uint128_t(ts) * 1000000000u) / ups);
  }

  std::span<const std::byte> f_;
  std::size_t pos_ = 0;
  format fmt_ = format::unknown;
  bool little_ = true;
  bool seen_shb_ = false;
  std::vector<capture_interface> ifaces_;
  std::string err_;
};

#if defined(NANOCRAFT_HAS_MMAP)
/// A read-only memory-mapped file (empty on failure).
class mapped_file {
 public:
  static mapped_file open(const char* path) {
    mapped_file m;
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return m;
    struct stat st{};
    if (::fstat(fd, &st) == 0 && st.st_size > 0) {
      void* p = ::mmap(nullptr, std::size_t(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
      if (p != MAP_FAILED) {
        m.p_ = p;
        m.n_ = std::size_t(st.st_size);
      }
    }
    ::close(fd);
    return m;
  }
  mapped_file() = default;
  mapped_file(mapped_file&& o) noexcept : p_(o.p_), n_(o.n_) { o.p_ = nullptr, o.n_ = 0; }
  mapped_file& operator=(mapped_file&& o) noexcept {
    if (this != &o) {
      reset();
      p_ = o.p_, n_ = o.n_;
      o.p_ = nullptr, o.n_ = 0;
    }
    return *this;
  }
  ~mapped_file() { reset(); }
  std::span<const std::byte> bytes() const noexcept { return {static_cast<const std::byte*>(p_), n_}; }
  explicit operator bool() const noexcept { return p_ != nullptr; }

 private:
  void reset() noexcept {
    if (p_) ::munmap(p_, n_);
    p_ = nullptr;
    n_ = 0;
  }
  void* p_ = nullptr;
  std::size_t n_ = 0;
};
#endif

}  // namespace nanocraft

#endif  // NANOCRAFT_PCAP_READER_HPP_INCLUDED
