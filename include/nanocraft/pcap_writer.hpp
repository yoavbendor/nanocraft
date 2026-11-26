// SPDX-License-Identifier: Apache-2.0
// nanocraft/pcap_writer.hpp — streaming pcap and pcapng writers with large buffered writes.
//
//   auto out = nanocraft::output::file(fp);                // or output::fd(fd), output::buffer(vec)
//   nanocraft::pcap_writer w(out, {.nanosecond = true});
//   w.write(ts_ns, frame_bytes);                           // a contiguous frame
//   w.write(ts_ns, gather);                                // a scatter-gather frame (segmenter output)
//   w.write(ts_ns, tmpl, payload);                         // a template frame crafted IN the buffer
//
//   nanocraft::pcapng_writer png(out);
//   auto if0 = png.add_interface({.linktype = 1, .name = "eth0", .tsresol = 9});
//   png.write(if0, ts_ns, tmpl, payload, {.flags = 1 /*inbound*/, .comment = "fault: bad csum"});
//
// Both writers append record + frame straight into one large buffer (default 1 MiB) and hand it to
// the output in one call when it fills (and on flush() / destruction), so a frame crafted from a
// template is written exactly once, in place. Timestamps are nanoseconds (since the epoch, or any
// origin); the writers convert to the file's resolution. Records use host byte order (the magic
// tells readers which). No allocation after construction except to grow the buffer for a frame
// larger than it.
#ifndef NANOCRAFT_PCAP_WRITER_HPP_INCLUDED
#define NANOCRAFT_PCAP_WRITER_HPP_INCLUDED

#include "gather.hpp"
#include "profile.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#if __has_include(<unistd.h>)
#include <unistd.h>
#define NANOCRAFT_HAS_POSIX_IO 1
#endif

namespace nanocraft {

/// Where a writer's bytes go: a FILE*, a file descriptor or a growing byte vector.
struct output {
  void* ctx = nullptr;
  bool (*fn)(void*, const std::byte*, std::size_t) = nullptr;

  bool write(const std::byte* p, std::size_t n) const { return fn && fn(ctx, p, n); }

  static output file(std::FILE* f) {
    return {f, [](void* c, const std::byte* p, std::size_t n) {
              return std::fwrite(p, 1, n, static_cast<std::FILE*>(c)) == n;
            }};
  }
  static output buffer(std::vector<std::byte>& v) {
    return {&v, [](void* c, const std::byte* p, std::size_t n) {
              auto& vec = *static_cast<std::vector<std::byte>*>(c);
              vec.insert(vec.end(), p, p + n);
              return true;
            }};
  }
#if defined(NANOCRAFT_HAS_POSIX_IO)
  /// A file descriptor (the int is carried in the pointer; partial writes and EINTR are retried).
  static output fd(int fd) {
    return {reinterpret_cast<void*>(static_cast<std::intptr_t>(fd)), [](void* c, const std::byte* p, std::size_t n) {
              const int d = int(reinterpret_cast<std::intptr_t>(c));
              while (n) {
                const ssize_t w = ::write(d, p, n);
                if (w < 0) {
                  if (errno == EINTR) continue;
                  return false;
                }
                if (w == 0) return false;
                p += w;
                n -= std::size_t(w);
              }
              return true;
            }};
  }
#endif
};

namespace detail {

/// The shared buffering: reserve space, fill it, commit; flush in large writes.
class write_buffer {
 public:
  write_buffer(output o, std::size_t cap) : out_(o), buf_(cap ? cap : 4096) {}
  write_buffer(const write_buffer&) = delete;
  write_buffer& operator=(const write_buffer&) = delete;
  ~write_buffer() { flush(); }

  /// Space for n bytes (valid until the next reserve/flush), or null after an output failure.
  std::byte* reserve(std::size_t n) {
    if (!ok_) return nullptr;
    if (n > buf_.size() - used_) {
      if (!flush()) return nullptr;
      if (n > buf_.size()) buf_.resize(n);
    }
    return buf_.data() + used_;
  }
  void commit(std::size_t n) noexcept {
    used_ += n;
    total_ += n;
  }
  void fail() noexcept {
    ok_ = false;
    used_ = 0;
  }
  bool flush() {
    if (!ok_) return false;
    if (used_) {
      NANOCRAFT_PROFILE_SCOPE(pcap_flush);
      ok_ = out_.write(buf_.data(), used_);
      used_ = 0;
    }
    return ok_;
  }
  bool ok() const noexcept { return ok_; }
  std::uint64_t bytes() const noexcept { return total_; }

 private:
  output out_;
  std::vector<std::byte> buf_;
  std::size_t used_ = 0;
  std::uint64_t total_ = 0;
  bool ok_ = true;
};

template <class T>
inline void put(std::byte*& w, T v) noexcept {
  std::memcpy(w, &v, sizeof v);
  w += sizeof v;
}
constexpr std::size_t pad4(std::size_t n) noexcept { return (n + 3) & ~std::size_t{3}; }

/// Frame sources a writer can write: contiguous bytes, a gather, or a template + payload.
template <class F>
concept frame_template_like = requires(F& t, std::span<std::byte> d, std::span<const std::byte> p) {
  { t.frame_size(std::size_t{}) } -> std::convertible_to<std::size_t>;
  { t.write(d, p) } -> std::convertible_to<std::size_t>;
};

}  // namespace detail

// ---------------------------------------------------------------------------------------------
// pcap
// ---------------------------------------------------------------------------------------------

struct pcap_options {
  bool nanosecond = true;           ///< magic a1b23c4d (ns) instead of a1b2c3d4 (us)
  std::uint32_t linktype = 1;       ///< LINKTYPE_ETHERNET
  std::uint32_t snaplen = 262144;   ///< frames are cut to this length (origlen keeps the real size)
  std::size_t buffer_size = 1 << 20;
};

class pcap_writer {
 public:
  explicit pcap_writer(output out, const pcap_options& o = {}) : o_(o), buf_(out, o.buffer_size) {
    std::byte* w = buf_.reserve(24);
    if (!w) return;
    std::byte* p = w;
    detail::put<std::uint32_t>(p, o.nanosecond ? 0xa1b23c4du : 0xa1b2c3d4u);
    detail::put<std::uint16_t>(p, 2);
    detail::put<std::uint16_t>(p, 4);
    detail::put<std::int32_t>(p, 0);
    detail::put<std::uint32_t>(p, 0);
    detail::put<std::uint32_t>(p, o.snaplen);
    detail::put<std::uint32_t>(p, o.linktype);
    buf_.commit(24);
  }

  /// Reserve a record for a frame of up to `len` bytes; fill the returned span, then end().
  std::span<std::byte> begin(std::uint64_t ts_ns, std::size_t len) {
    pending_ = nullptr;
    std::byte* w = buf_.reserve(16 + len);
    if (!w) return {};
    pending_ = w;
    pending_ts_ = ts_ns;
    pending_len_ = len;
    return {w + 16, len};
  }
  /// Finish the record begun with begin(); `len` is the frame's real length (<= reserved).
  bool end(std::size_t len) {
    if (!pending_ || len > pending_len_) {
      pending_ = nullptr;
      return false;
    }
    const std::uint32_t cap = std::uint32_t(std::min<std::size_t>(len, o_.snaplen));
    std::byte* p = pending_;
    const std::uint64_t div = o_.nanosecond ? 1 : 1000;
    detail::put<std::uint32_t>(p, std::uint32_t(pending_ts_ / 1000000000u));
    detail::put<std::uint32_t>(p, std::uint32_t((pending_ts_ % 1000000000u) / div));
    detail::put<std::uint32_t>(p, cap);
    detail::put<std::uint32_t>(p, std::uint32_t(len));
    buf_.commit(16 + cap);
    pending_ = nullptr;
    ++frames_;
    NANOCRAFT_PROFILE_COUNT(pcap_write, 1, 16 + cap);
    return true;
  }
  bool write(std::uint64_t ts_ns, std::span<const std::byte> frame) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    auto s = begin(ts_ns, frame.size());
    if (!s.data()) return false;
    if (!frame.empty()) std::memcpy(s.data(), frame.data(), frame.size());
    return end(frame.size());
  }
  bool write(std::uint64_t ts_ns, const gather& g) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    auto s = begin(ts_ns, g.size());
    if (!s.data()) return false;
    g.copy_to(s);
    return end(g.size());
  }
  /// Craft a template frame directly in the output buffer (no intermediate copy).
  template <detail::frame_template_like T>
  bool write(std::uint64_t ts_ns, T& tmpl, std::span<const std::byte> payload) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    if constexpr (requires { tmpl.ok(); })
      if (!tmpl.ok()) return false;
    auto s = begin(ts_ns, tmpl.frame_size(payload.size()));
    if (!s.data()) return false;
    return end(tmpl.write(s, payload));
  }

  bool flush() {
    pending_ = nullptr;
    return buf_.flush();
  }
  bool ok() const noexcept { return buf_.ok(); }
  std::uint64_t frames() const noexcept { return frames_; }
  std::uint64_t bytes() const noexcept { return buf_.bytes(); }

 private:
  pcap_options o_;
  detail::write_buffer buf_;
  std::byte* pending_ = nullptr;
  std::uint64_t pending_ts_ = 0;
  std::size_t pending_len_ = 0;
  std::uint64_t frames_ = 0;
};

// ---------------------------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------------------------

struct pcapng_interface {
  std::uint16_t linktype = 1;
  std::uint32_t snaplen = 0;         ///< 0: no limit
  std::string_view name{};           ///< if_name
  std::string_view description{};    ///< if_description
  std::uint8_t tsresol = 9;          ///< if_tsresol: decimal exponent (6 = us, 9 = ns)
};

/// Per-packet EPB options.
struct epb_options {
  std::optional<std::uint32_t> flags{};  ///< epb_flags (direction bits 0-1, reception type, FCS length, errors)
  std::string_view comment{};            ///< opt_comment (UTF-8)
};

class pcapng_writer {
 public:
  explicit pcapng_writer(output out, std::size_t buffer_size = 1 << 20, std::string_view userappl = "nanocraft")
      : buf_(out, buffer_size) {
    if (userappl.size() > 0xffffu) {
      buf_.fail();
      return;
    }
    const std::size_t opts = userappl.empty() ? 0 : option_size(userappl.size()) + 4;
    const std::size_t total = 28 + opts;
    std::byte* w = buf_.reserve(total);
    if (!w) return;
    std::byte* p = w;
    detail::put<std::uint32_t>(p, 0x0a0d0d0au);
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    detail::put<std::uint32_t>(p, 0x1a2b3c4du);
    detail::put<std::uint16_t>(p, 1);
    detail::put<std::uint16_t>(p, 0);
    detail::put<std::int64_t>(p, -1);
    if (opts) {
      put_option(p, 4, userappl.data(), userappl.size());  // shb_userappl
      put_end(p);
    }
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    buf_.commit(total);
  }

  /// Add an interface (writes an IDB); returns its id for write() (or ~0u on invalid options/failure).
  std::uint32_t add_interface(const pcapng_interface& i) {
    pending_ = nullptr;
    if (i.tsresol > 9 || i.name.size() > 0xffffu || i.description.size() > 0xffffu) return ~0u;
    std::size_t opts = 0;
    if (!i.name.empty()) opts += option_size(i.name.size());
    if (!i.description.empty()) opts += option_size(i.description.size());
    opts += option_size(1);  // if_tsresol
    opts += 4;               // opt_endofopt
    const std::size_t total = 20 + opts;
    std::byte* w = buf_.reserve(total);
    if (!w) return ~0u;
    std::byte* p = w;
    detail::put<std::uint32_t>(p, 1);
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    detail::put<std::uint16_t>(p, i.linktype);
    detail::put<std::uint16_t>(p, 0);
    detail::put<std::uint32_t>(p, i.snaplen);
    if (!i.name.empty()) put_option(p, 2, i.name.data(), i.name.size());
    if (!i.description.empty()) put_option(p, 3, i.description.data(), i.description.size());
    put_option(p, 9, &i.tsresol, 1);
    put_end(p);
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    buf_.commit(total);
    std::uint64_t div = 1;
    for (int k = i.tsresol; k < 9; ++k) div *= 10;
    ifaces_.push_back({div, i.snaplen});
    return std::uint32_t(ifaces_.size() - 1);
  }

  /// Reserve an EPB for a frame of up to `len` bytes; fill the span, then end(). The options
  /// (copied into the block at end()) must stay valid until then.
  std::span<std::byte> begin(std::uint32_t iface, std::uint64_t ts_ns, std::size_t len, const epb_options& o = {}) {
    pending_ = nullptr;
    if (iface >= ifaces_.size() || o.comment.size() > 0xffffu) return {};
    std::byte* w = buf_.reserve(28 + detail::pad4(len) + options_size(o) + 4);
    if (!w) return {};
    pending_ = w;
    p_iface_ = iface;
    p_ts_ = ts_ns;
    p_len_ = len;
    p_opts_ = o;
    return {w + 28, len};
  }
  bool end(std::size_t len) {
    if (!pending_ || len > p_len_) {
      pending_ = nullptr;
      return false;
    }
    const auto& itf = ifaces_[p_iface_];
    const std::size_t cap = itf.snaplen ? std::min<std::size_t>(len, itf.snaplen) : len;
    const std::size_t opts = options_size(p_opts_);
    const std::size_t total = 28 + detail::pad4(cap) + opts + 4;
    const std::uint64_t ts = p_ts_ / itf.div;
    std::byte* p = pending_;
    detail::put<std::uint32_t>(p, 6);
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    detail::put<std::uint32_t>(p, p_iface_);
    detail::put<std::uint32_t>(p, std::uint32_t(ts >> 32));
    detail::put<std::uint32_t>(p, std::uint32_t(ts));
    detail::put<std::uint32_t>(p, std::uint32_t(cap));
    detail::put<std::uint32_t>(p, std::uint32_t(len));
    p += cap;
    for (std::size_t k = cap; k < detail::pad4(cap); ++k) *p++ = std::byte{0};
    if (opts) {
      if (p_opts_.flags) put_option(p, 2, &*p_opts_.flags, 4);
      if (!p_opts_.comment.empty()) put_option(p, 1, p_opts_.comment.data(), p_opts_.comment.size());
      put_end(p);
    }
    detail::put<std::uint32_t>(p, std::uint32_t(total));
    buf_.commit(total);
    pending_ = nullptr;
    ++frames_;
    NANOCRAFT_PROFILE_COUNT(pcap_write, 1, total);
    return true;
  }

  bool write(std::uint32_t iface, std::uint64_t ts_ns, std::span<const std::byte> frame, const epb_options& o = {}) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    auto s = begin(iface, ts_ns, frame.size(), o);
    if (!s.data()) return false;
    if (!frame.empty()) std::memcpy(s.data(), frame.data(), frame.size());
    return end(frame.size());
  }
  bool write(std::uint32_t iface, std::uint64_t ts_ns, const gather& g, const epb_options& o = {}) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    auto s = begin(iface, ts_ns, g.size(), o);
    if (!s.data()) return false;
    g.copy_to(s);
    return end(g.size());
  }
  template <detail::frame_template_like T>
  bool write(std::uint32_t iface, std::uint64_t ts_ns, T& tmpl, std::span<const std::byte> payload,
             const epb_options& o = {}) {
    NANOCRAFT_PROFILE_SCOPE(pcap_write);
    if constexpr (requires { tmpl.ok(); })
      if (!tmpl.ok()) return false;
    auto s = begin(iface, ts_ns, tmpl.frame_size(payload.size()), o);
    if (!s.data()) return false;
    return end(tmpl.write(s, payload));
  }

  bool flush() {
    pending_ = nullptr;
    return buf_.flush();
  }
  bool ok() const noexcept { return buf_.ok(); }
  std::uint64_t frames() const noexcept { return frames_; }
  std::uint64_t bytes() const noexcept { return buf_.bytes(); }

 private:
  static constexpr std::size_t option_size(std::size_t n) noexcept { return 4 + detail::pad4(n); }
  static std::size_t options_size(const epb_options& o) noexcept {
    std::size_t n = 0;
    if (o.flags) n += option_size(4);
    if (!o.comment.empty()) n += option_size(o.comment.size());
    return n ? n + 4 : 0;
  }
  static void put_option(std::byte*& p, std::uint16_t code, const void* v, std::size_t n) noexcept {
    detail::put<std::uint16_t>(p, code);
    detail::put<std::uint16_t>(p, std::uint16_t(n));
    if (n > 0) std::memcpy(p, v, n);
    p += n;
    for (std::size_t k = n; k < detail::pad4(n); ++k) *p++ = std::byte{0};
  }
  static void put_end(std::byte*& p) noexcept { detail::put<std::uint32_t>(p, 0); }

  struct iface_state {
    std::uint64_t div;
    std::uint32_t snaplen;
  };
  detail::write_buffer buf_;
  std::vector<iface_state> ifaces_;
  std::byte* pending_ = nullptr;
  std::uint32_t p_iface_ = 0;
  std::uint64_t p_ts_ = 0;
  std::size_t p_len_ = 0;
  epb_options p_opts_{};
  std::uint64_t frames_ = 0;
};

}  // namespace nanocraft

#endif  // NANOCRAFT_PCAP_WRITER_HPP_INCLUDED
