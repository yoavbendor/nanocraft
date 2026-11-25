// SPDX-License-Identifier: Apache-2.0
// nanocraft/frame_template.hpp — compiled frame templates: describe a stack once, then craft frames
// by patching a prebuilt byte image instead of re-encoding every layer.
//
//   using namespace nanocraft::proto;                    // or nanowire's layers, later
//   auto t = nanocraft::compile(eth{...} / vlan{...} / ipv4{...} / udp{...} / someip{...});
//
//   t.set<"someip.session_id">(42);                     // compile-time patch point
//   t.set<"ipv4.identification">(7);                    // IPv4 header checksum kept (RFC 1624)
//   std::size_t n = t.write(dst, payload);              // header image + payload; returns frame length
//
//   auto id = t.find("someip.session_id");              // runtime name -> handle
//   t.set(id, 43);
//
// What compile() does, once: links the layers (fills next-protocol fields left at 0), encodes every
// layer with nanom::emit, resolves every described field of every layer to a patch point (byte
// offset, byte span, bit shift and width, byte order), resolves length chains (IPv4 total length,
// UDP length, SOME/IP length, ...) and checksum slots (IPv4 header, UDP with its pseudo header),
// and precomputes, per patch point, which 16-bit checksum windows it touches.
//
// Invariant: the image is always a valid frame with an all-zero payload of payload_size() bytes.
// set() keeps every maintained checksum valid incrementally (RFC 1624: HC' = ~(~HC + ~m + m')), so
// unchanged fields are never re-encoded and no checksum is ever recomputed from scratch on the hot
// path. write(dst, payload) is: resize the length chain if the payload size changed (incremental
// again), memcpy the header image, memcpy the payload, add the payload's ones'-complement sum to
// each L4 checksum (zero payload -> real payload is one more incremental update), pad, faults.
// No allocation anywhere after compile().
//
// Checksum policies (per slot, t.checksum("udp.checksum", policy)):
//   compute  (default) correct value, maintained incrementally
//   zero     store 0 (UDP over IPv4: "no checksum")
//   offload  store the folded pseudo-header sum for NIC checksum offload (CHECKSUM_PARTIAL)
//   keep     store whatever the layer value said; never touched
//
// Fault injection (applied to the written frame only, the image stays correct):
//   t.inject(nanocraft::faults{}.bad_checksum("ipv4.checksum").length_delta("udp.length", +4)
//                               .truncate_by(3).every_nth(100));
// A length fault keeps the checksums consistent with the wrong length (so only the length is wrong);
// a checksum fault flips bits of an otherwise correct checksum; truncation drops trailing bytes.
#ifndef NANOCRAFT_FRAME_TEMPLATE_HPP_INCLUDED
#define NANOCRAFT_FRAME_TEMPLATE_HPP_INCLUDED

#include "checksum.hpp"
#include "layer.hpp"
#include "profile.hpp"

#include <algorithm>
#include <bit>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#if defined(__GNUC__) || defined(__clang__)
#define NANOCRAFT_INLINE [[gnu::always_inline]] inline
#else
#define NANOCRAFT_INLINE inline
#endif

namespace nanocraft {

// ---------------------------------------------------------------------------------------------
// patch points, checksum slots, length chains: the compiled description of a stack
// ---------------------------------------------------------------------------------------------

enum class field_kind : std::uint8_t {
  be,         ///< big-endian unsigned integer (be<>, and plain integers: network order)
  le,         ///< little-endian unsigned integer (le<>)
  bits_msb0,  ///< ubits<N> packed msb-first (network bit order)
  bits_lsb0,  ///< ubits<N, lsb0>
  bytes,      ///< std::array of bytes (MAC / IP address)
};

/// One patch point: where a field lives in the frame and how it is encoded.
struct field_desc {
  std::string_view layer;           ///< layer name ("ipv4")
  std::string_view name;            ///< field name ("identification")
  std::uint16_t layer_index = 0;    ///< position in the stack
  std::uint16_t occurrence = 0;     ///< n-th layer with this name ("vlan[1]")
  std::uint16_t off = 0;            ///< first byte, from the start of the frame
  std::uint16_t len = 0;            ///< bytes spanned
  std::uint8_t shift = 0;           ///< bit fields: lsb position inside the len-byte integer
  std::uint8_t bits = 0;            ///< width in bits (0 for bytes)
  field_kind kind = field_kind::be;
  constexpr std::uint64_t mask() const noexcept { return bits >= 64 ? ~0ull : ((1ull << bits) - 1); }
};

/// A stable handle to a patch point (an index into the stack's field table).
struct field_id {
  std::uint16_t index = 0xffff;
  constexpr bool valid() const noexcept { return index != 0xffff; }
  constexpr explicit operator bool() const noexcept { return valid(); }
  constexpr bool operator==(const field_id&) const = default;
};

enum class csum_policy : std::uint8_t { compute, zero, offload, keep };

struct range16 {
  std::uint16_t begin = 0, end = 0;
};

/// One Internet-checksum field and what it covers.
struct slot_desc {
  std::uint16_t field = 0;        ///< index of the checksum field in the field table
  std::uint16_t off = 0;          ///< byte offset of the 16-bit checksum
  checksum_kind kind = checksum_kind::header;
  range16 pseudo{};               ///< l4: the IP addresses of the pseudo header
  range16 cover{};                ///< header: covered bytes; l4: [layer start, header end)
  std::int32_t alias = -1;        ///< l4: offset of the length field the pseudo header repeats
  std::uint8_t proto = 0;         ///< l4: pseudo-header protocol
  bool zero_ok = false;           ///< l4: a stored 0 means "no checksum"
  bool odd_payload = false;       ///< l4: the payload starts at an odd position of the stream
};

/// One length field of the chain: value = (header_size + payload) - base + add.
struct length_desc {
  std::uint16_t field = 0;
  std::uint32_t base = 0;
  std::int32_t add = 0;
};

/// The 16-bit-aligned window of a checksum slot that a patch point touches.
struct effect {
  std::uint16_t begin = 0, end = 0;
  std::uint8_t slot = 0;
  std::uint8_t mult = 1;  ///< 2 when the field is also repeated by the pseudo header
  bool pseudo = false;    ///< the window lies in the pseudo header
};

namespace detail {

template <class F>
constexpr field_kind kind_of() {
  if constexpr (requires { F::bits; F::order; typename F::value_type; } && !requires(F f) { f.raw; }) {
    static_assert(std::is_unsigned_v<typename F::value_type>, "nanocraft: signed bit fields are not patchable");
    return F::order == nanom::bit_order::msb0 ? field_kind::bits_msb0 : field_kind::bits_lsb0;
  } else if constexpr (requires(F f) { f.raw; F::order; typename F::value_type; }) {
    return F::order == std::endian::big ? field_kind::be : field_kind::le;
  } else if constexpr (nanom::detail::is_std_array_v<F>) {
    static_assert(sizeof(typename F::value_type) == 1, "nanocraft: arrays must be byte arrays");
    return field_kind::bytes;
  } else if constexpr (std::is_integral_v<F>) {
    return field_kind::be;
  } else {
    static_assert(sizeof(F) == 0, "nanocraft: nested structs are not supported as layer fields");
    return field_kind::be;
  }
}

template <class F>
constexpr std::size_t byte_size_of() {
  if constexpr (requires(F f) { f.raw; }) return sizeof(typename F::value_type);
  else return sizeof(F);
}

constexpr std::size_t npos = std::size_t(-1);

// Character loops instead of std::string_view::find / operator==: GCC's sanitizer instrumentation
// makes the library versions non-constant over template-parameter strings.
constexpr bool str_eq(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i)
    if (a[i] != b[i]) return false;
  return true;
}
constexpr std::size_t str_find(std::string_view s, char c) noexcept {
  for (std::size_t i = 0; i < s.size(); ++i)
    if (s[i] == c) return i;
  return npos;
}

template <class... L>
struct stack_meta {
  static constexpr std::size_t nlayers = sizeof...(L);
  static constexpr std::array<std::size_t, nlayers> sizes{nanom::wire_size_v<L>...};
  static constexpr std::array<std::size_t, nlayers> offsets = [] {
    std::array<std::size_t, nlayers> o{};
    std::size_t acc = 0;
    for (std::size_t i = 0; i < nlayers; ++i) {
      o[i] = acc;
      acc += sizes[i];
    }
    return o;
  }();
  static constexpr std::size_t header_size = (std::size_t{0} + ... + nanom::wire_size_v<L>);
  static_assert(header_size < 0xffff, "nanocraft: header image too large");
  static constexpr std::array<std::string_view, nlayers> names{std::string_view(layer_info<L>::name)...};
  static constexpr std::array<bool, nlayers> is_ip{has_pseudo<L>()...};
  static constexpr std::array<pseudo_spec, nlayers> pseudos{pseudo_of<L>()...};
  static constexpr std::size_t nfields = (std::size_t{0} + ... + nanom::detail::field_count_v<L>);

  static constexpr std::array<field_desc, nfields> fields = [] {
    std::array<field_desc, nfields> out{};
    std::size_t k = 0, li = 0;
    (
        [&] {
          using T = L;
          constexpr auto offs = nanom::detail::field_bit_offsets<T>();
          std::uint16_t occ = 0;
          for (std::size_t j = 0; j < li; ++j)
            if (str_eq(names[j], names[li])) ++occ;
          std::size_t fi = 0;
          nanom::detail::for_each_field<T>([&](auto f) {
            using F = nanom::detail::member_t<decltype(f)::mem_ptr>;
            field_desc d{};
            d.layer = names[li];
            d.name = decltype(f)::name.sv();
            d.layer_index = std::uint16_t(li);
            d.occurrence = occ;
            constexpr field_kind K = kind_of<F>();
            d.kind = K;
            const std::size_t bit = offsets[li] * 8 + offs[fi++];
            if constexpr (K == field_kind::bits_msb0 || K == field_kind::bits_lsb0) {
              constexpr unsigned n = F::bits;
              const std::size_t pos = bit % 8;
              d.off = std::uint16_t(bit / 8);
              d.len = std::uint16_t((pos + n + 7) / 8);
              d.bits = std::uint8_t(n);
              d.shift = std::uint8_t(d.kind == field_kind::bits_msb0 ? d.len * 8 - pos - n : pos);
            } else {
              d.off = std::uint16_t(bit / 8);
              d.len = std::uint16_t(byte_size_of<F>());
              d.bits = d.kind == field_kind::bytes ? 0 : std::uint8_t(8 * d.len);
            }
            out[k++] = d;
          });
          ++li;
        }(),
        ...);
    return out;
  }();
  static_assert([] {
    for (const auto& f : fields)
      if (f.kind != field_kind::bytes && f.len > 8) return false;
    return true;
  }(), "nanocraft: a bit field spans more than 8 bytes");

  /// Field index for (layer index, field name), npos when absent.
  static constexpr std::size_t field_in(std::size_t li, std::string_view name) {
    for (std::size_t i = 0; i < nfields; ++i)
      if (fields[i].layer_index == li && str_eq(fields[i].name, name)) return i;
    return npos;
  }

  /// "layer.field" or "layer[k].field" -> field index, npos when absent.
  static constexpr std::size_t find(std::string_view path) {
    const auto dot = str_find(path, '.');
    if (dot == npos) return npos;
    std::string_view lay = path.substr(0, dot), fld = path.substr(dot + 1);
    std::size_t occ = 0;
    if (const auto br = str_find(lay, '['); br != npos) {
      if (lay.back() != ']') return npos;
      occ = 0;
      for (std::size_t i = br + 1; i + 1 < lay.size(); ++i) {
        if (lay[i] < '0' || lay[i] > '9') return npos;
        occ = occ * 10 + std::size_t(lay[i] - '0');
      }
      lay = lay.substr(0, br);
    }
    for (std::size_t i = 0; i < nfields; ++i)
      if (str_eq(fields[i].layer, lay) && fields[i].occurrence == occ && str_eq(fields[i].name, fld)) return i;
    return npos;
  }

  /// Layer index for "name" or "name[k]", npos when absent.
  static constexpr std::size_t layer(std::string_view path) {
    std::size_t occ = 0;
    if (const auto br = str_find(path, '['); br != npos) {
      if (path.back() != ']') return npos;
      for (std::size_t i = br + 1; i + 1 < path.size(); ++i) {
        if (path[i] < '0' || path[i] > '9') return npos;
        occ = occ * 10 + std::size_t(path[i] - '0');
      }
      path = path.substr(0, br);
    }
    for (std::size_t i = 0; i < nlayers; ++i)
      if (str_eq(names[i], path) && occ-- == 0) return i;
    return npos;
  }

  // ---- length chain
  static constexpr std::size_t nlengths = (std::size_t{0} + ... + lengths_of<L>().size());
  static constexpr std::array<length_desc, nlengths> lengths = [] {
    std::array<length_desc, nlengths> out{};
    std::size_t k = 0, li = 0;
    (
        [&] {
          for (const auto& s : lengths_of<L>()) {
            const std::size_t f = field_in(li, s.field);
            if (f == npos) throw "nanocraft: layer_info::lengths names a field the layer does not have";
            out[k++] = length_desc{std::uint16_t(f), std::uint32_t(offsets[li] + s.from), s.add};
          }
          ++li;
        }(),
        ...);
    return out;
  }();

  // ---- checksum slots
  static constexpr std::size_t nslots = (std::size_t{0} + ... + checksums_of<L>().size());
  static_assert(nslots <= 8, "nanocraft: at most 8 checksum slots per stack");
  static constexpr std::array<slot_desc, nslots> slots = [] {
    std::array<slot_desc, nslots> out{};
    std::size_t k = 0, li = 0;
    (
        [&] {
          for (const auto& s : checksums_of<L>()) {
            const std::size_t f = field_in(li, s.field);
            if (f == npos) throw "nanocraft: layer_info::checksums names a field the layer does not have";
            slot_desc d{};
            d.field = std::uint16_t(f);
            d.off = fields[f].off;
            d.kind = s.kind;
            if (s.kind == checksum_kind::header) {
              d.cover = {std::uint16_t(offsets[li]), std::uint16_t(offsets[li] + (s.cover ? s.cover : sizes[li]))};
            } else {
              std::size_t ip = npos;
              for (std::size_t j = li; j-- > 0;)
                if (is_ip[j]) {
                  ip = j;
                  break;
                }
              if (ip == npos) throw "nanocraft: an l4 checksum needs an IP layer below it";
              d.pseudo = {std::uint16_t(offsets[ip] + pseudos[ip].addr_off),
                          std::uint16_t(offsets[ip] + pseudos[ip].addr_off + pseudos[ip].addr_len)};
              d.zero_ok = pseudos[ip].zero_checksum_ok;
              d.cover = {std::uint16_t(offsets[li]), std::uint16_t(header_size)};
              d.proto = s.pseudo_proto;
              if (!s.pseudo_length_field.empty()) {
                const std::size_t a = field_in(li, s.pseudo_length_field);
                if (a == npos) throw "nanocraft: pseudo_length_field names a field the layer does not have";
                d.alias = fields[a].off;
              }
              d.odd_payload = ((header_size - offsets[li]) & 1) != 0;
            }
            out[k++] = d;
          }
          ++li;
        }(),
        ...);
    return out;
  }();

  // ---- per patch point: the checksum windows it touches
  static constexpr std::size_t max_effects = 4;
  struct effects_t {
    std::array<effect, max_effects> e{};
    std::uint8_t n = 0;
  };
  static constexpr std::array<effects_t, nfields> effects = [] {
    std::array<effects_t, nfields> out{};
    for (std::size_t f = 0; f < nfields; ++f) {
      const std::size_t a = fields[f].off, b = a + fields[f].len;
      for (std::size_t s = 0; s < nslots; ++s) {
        const auto& sl = slots[s];
        if (sl.off < b && a < std::size_t(sl.off) + 2) continue;  // the checksum itself: raw write
        auto window = [&](range16 r, bool pseudo) {
          const std::size_t lo = std::max<std::size_t>(a, r.begin), hi = std::min<std::size_t>(b, r.end);
          if (lo >= hi) return;
          effect e{};
          e.begin = std::uint16_t(r.begin + ((lo - r.begin) & ~std::size_t{1}));
          e.end = std::uint16_t(std::min<std::size_t>(r.end, r.begin + ((hi - r.begin + 1) & ~std::size_t{1})));
          e.slot = std::uint8_t(s);
          e.pseudo = pseudo;
          e.mult = (!pseudo && sl.alias >= 0 && std::size_t(sl.alias) >= a && std::size_t(sl.alias) < b) ? 2 : 1;
          if (out[f].n >= max_effects) throw "nanocraft: a field touches too many checksum windows";
          out[f].e[out[f].n++] = e;
        };
        if (sl.kind == checksum_kind::l4) window(sl.pseudo, true);
        window(sl.cover, false);
      }
    }
    return out;
  }();

  // ---- selectors: identity fields compared by matches()
  static constexpr std::size_t nselectors = (std::size_t{0} + ... + selectors_of<L>().size());
  static constexpr std::array<std::uint16_t, nselectors> selectors = [] {
    std::array<std::uint16_t, nselectors> out{};
    std::size_t k = 0, li = 0;
    (
        [&] {
          for (auto s : selectors_of<L>()) {
            const std::size_t f = field_in(li, s);
            if (f == npos) throw "nanocraft: layer_info::selectors names a field the layer does not have";
            out[k++] = std::uint16_t(f);
          }
          ++li;
        }(),
        ...);
    return out;
  }();
};

// ---- byte-level field access

// Loads / stores of 1, 2, 4 or 8 bytes are single memory operations (one memcpy + byteswap), so a
// patch's write and the checksum window read right after it forward through the store buffer.
template <class U>
NANOCRAFT_INLINE U bswap_if(U v, bool big) noexcept {
  if constexpr (sizeof(U) == 1) return v;
  else return (big == (std::endian::native == std::endian::little)) ? std::byteswap(v) : v;
}
NANOCRAFT_INLINE constexpr std::uint64_t load_uint(const std::byte* p, std::size_t n, bool big) noexcept {
  if !consteval {
    switch (n) {
      case 1: return std::uint8_t(p[0]);
      case 2: { std::uint16_t v; std::memcpy(&v, p, 2); return bswap_if(v, big); }
      case 4: { std::uint32_t v; std::memcpy(&v, p, 4); return bswap_if(v, big); }
      case 8: { std::uint64_t v; std::memcpy(&v, p, 8); return bswap_if(v, big); }
      default: break;
    }
  }
  std::uint64_t v = 0;
  if (big)
    for (std::size_t i = 0; i < n; ++i) v = (v << 8) | std::uint8_t(p[i]);
  else
    for (std::size_t i = n; i-- > 0;) v = (v << 8) | std::uint8_t(p[i]);
  return v;
}
NANOCRAFT_INLINE constexpr void store_uint(std::byte* p, std::size_t n, std::uint64_t v, bool big) noexcept {
  if !consteval {
    switch (n) {
      case 1: p[0] = std::byte(v); return;
      case 2: { const auto w = bswap_if(std::uint16_t(v), big); std::memcpy(p, &w, 2); return; }
      case 4: { const auto w = bswap_if(std::uint32_t(v), big); std::memcpy(p, &w, 4); return; }
      case 8: { const auto w = bswap_if(std::uint64_t(v), big); std::memcpy(p, &w, 8); return; }
      default: break;
    }
  }
  if (big)
    for (std::size_t i = n; i-- > 0; v >>= 8) p[i] = std::byte(v);
  else
    for (std::size_t i = 0; i < n; ++i, v >>= 8) p[i] = std::byte(v);
}
NANOCRAFT_INLINE constexpr std::uint16_t load16(const std::byte* p) noexcept { return std::uint16_t(load_uint(p, 2, true)); }
NANOCRAFT_INLINE constexpr void store16(std::byte* p, std::uint16_t v) noexcept { store_uint(p, 2, v, true); }

/// memcpy for the short payloads of sensor / SOME/IP frames without a library call: two possibly
/// overlapping fixed-size copies per size class; long copies go to memcpy.
NANOCRAFT_INLINE void copy_payload(std::byte* d, const std::byte* s, std::size_t n) noexcept {
  if (n <= 16) {
    if (n >= 8) {
      std::memcpy(d, s, 8);
      std::memcpy(d + n - 8, s + n - 8, 8);
    } else if (n >= 4) {
      std::memcpy(d, s, 4);
      std::memcpy(d + n - 4, s + n - 4, 4);
    } else {
      for (std::size_t i = 0; i < n; ++i) d[i] = s[i];
    }
  } else if (n <= 32) {
    std::memcpy(d, s, 16);
    std::memcpy(d + n - 16, s + n - 16, 16);
  } else if (n <= 64) {
    std::memcpy(d, s, 32);
    std::memcpy(d + n - 32, s + n - 32, 32);
  } else {
    std::memcpy(d, s, n);
  }
}

/// Ones'-complement partial sum of a checksum window known at compile time (short windows are a
/// couple of 16-bit loads; the result is < 2^20, fold it with fold32).
template <std::size_t B, std::size_t E>
NANOCRAFT_INLINE std::uint32_t window_sum(const std::byte* f) noexcept {
  constexpr std::size_t n = E - B;
  if constexpr (n == 2) return load16(f + B);
  else if constexpr (n == 4) return std::uint32_t(load16(f + B)) + load16(f + B + 2);
  else if constexpr (n == 6) return std::uint32_t(load16(f + B)) + load16(f + B + 2) + load16(f + B + 4);
  else if constexpr (n == 8) {
    const std::uint64_t v = load_uint(f + B, 8, true);
    return std::uint32_t(v >> 48) + std::uint32_t((v >> 32) & 0xffff) + std::uint32_t((v >> 16) & 0xffff) +
           std::uint32_t(v & 0xffff);
  } else return csum::sum(f + B, n);
}
constexpr std::uint32_t fold32(std::uint32_t s) noexcept {
  s = (s & 0xffff) + (s >> 16);
  return (s & 0xffff) + (s >> 16);
}

NANOCRAFT_INLINE constexpr std::uint64_t read_field(const std::byte* frame, const field_desc& f) noexcept {
  const std::byte* p = frame + f.off;
  switch (f.kind) {
    case field_kind::be: return load_uint(p, f.len, true);
    case field_kind::le: return load_uint(p, f.len, false);
    case field_kind::bits_msb0: return (load_uint(p, f.len, true) >> f.shift) & f.mask();
    case field_kind::bits_lsb0: return (load_uint(p, f.len, false) >> f.shift) & f.mask();
    case field_kind::bytes: return f.len <= 8 ? load_uint(p, f.len, true) : 0;
  }
  return 0;
}
/// Write v (masked to the field's width) at f. Byte arrays of <= 8 bytes take a big-endian integer.
NANOCRAFT_INLINE constexpr void write_field(std::byte* frame, const field_desc& f, std::uint64_t v) noexcept {
  std::byte* p = frame + f.off;
  switch (f.kind) {
    case field_kind::be: store_uint(p, f.len, v, true); return;
    case field_kind::le: store_uint(p, f.len, v, false); return;
    case field_kind::bits_msb0:
    case field_kind::bits_lsb0: {
      const bool big = f.kind == field_kind::bits_msb0;
      const std::uint64_t m = f.mask() << f.shift;
      const std::uint64_t w = (load_uint(p, f.len, big) & ~m) | ((v << f.shift) & m);
      store_uint(p, f.len, w, big);
      return;
    }
    case field_kind::bytes:
      if (f.len <= 8) store_uint(p, f.len, v, true);
      return;
  }
}

/// Per-slot maintenance mode during a patch.
inline constexpr std::uint8_t mode_skip = 0, mode_checksum = 1, mode_sum = 2;

/// Apply `write` to frame and keep every slot whose mode is not skip consistent, incrementally.
template <class W>
inline void patch_with(std::byte* frame, const effect* e, std::size_t ne, const slot_desc* slots,
                       const std::uint8_t* mode, W&& write) noexcept {
  std::uint32_t old[4];
  for (std::size_t i = 0; i < ne; ++i)
    old[i] = mode[e[i].slot] ? csum::sum(frame + e[i].begin, e[i].end - e[i].begin) : 0;
  write();
  for (std::size_t i = 0; i < ne; ++i) {
    const std::uint8_t m = mode[e[i].slot];
    if (!m) continue;
    const std::uint32_t nw = csum::sum(frame + e[i].begin, e[i].end - e[i].begin);
    std::byte* cp = frame + slots[e[i].slot].off;
    std::uint16_t c = load16(cp);
    if (m == mode_checksum) {
      for (std::uint8_t r = 0; r < e[i].mult; ++r) c = csum::update(c, old[i], nw);
    } else {
      const std::uint8_t reps = e[i].pseudo ? 1 : std::uint8_t(e[i].mult - 1);
      for (std::uint8_t r = 0; r < reps; ++r) c = csum::update_sum(c, old[i], nw);
    }
    store16(cp, c);
  }
}

/// Partial sum of an l4 slot's pseudo header (addresses + protocol + length).
constexpr std::uint32_t pseudo_sum(const std::byte* frame, const slot_desc& s, std::uint32_t l4len) noexcept {
  std::uint64_t acc = csum::sum(frame + s.pseudo.begin, std::size_t(s.pseudo.end - s.pseudo.begin));
  acc += s.proto;
  acc += (l4len >> 16) + (l4len & 0xffff);
  return csum::fold(acc);
}

template <class T>
struct is_byte_range : std::false_type {};
template <class E, std::size_t N>
struct is_byte_range<std::array<E, N>> : std::bool_constant<sizeof(E) == 1> {};
template <class E, std::size_t N>
struct is_byte_range<std::span<E, N>> : std::bool_constant<sizeof(E) == 1> {};

}  // namespace detail

// ---------------------------------------------------------------------------------------------
// fault injection
// ---------------------------------------------------------------------------------------------

/// What to break in written frames (names are resolved by frame_template::inject).
struct faults {
  struct length_fault {
    std::string_view field;
    std::int32_t delta = 0;
  };
  std::array<std::string_view, 4> bad_checksums{};
  std::array<length_fault, 4> lengths{};
  std::size_t truncate = 0;
  std::uint32_t period = 1;

  /// Write a wrong value to this checksum field ("ipv4.checksum", "udp.checksum").
  constexpr faults& bad_checksum(std::string_view field) {
    for (auto& s : bad_checksums)
      if (s.empty()) {
        s = field;
        break;
      }
    return *this;
  }
  /// Add delta to this length field (checksums stay consistent with the wrong length).
  constexpr faults& length_delta(std::string_view field, std::int32_t delta) {
    for (auto& l : lengths)
      if (l.field.empty()) {
        l = {field, delta};
        break;
      }
    return *this;
  }
  /// Drop the last n bytes of the frame.
  constexpr faults& truncate_by(std::size_t n) {
    truncate = n;
    return *this;
  }
  /// Apply to every n-th frame only (1 = every frame).
  constexpr faults& every_nth(std::uint32_t n) {
    period = n ? n : 1;
    return *this;
  }
};

/// Options for compile().
struct template_options {
  std::size_t payload_size = 0;  ///< initial payload size (any size can be written later)
  std::size_t min_frame = 0;     ///< pad frames with zeros to this size (60: Ethernet minimum w/o FCS)
};

template <class... L>
class frame_ref;

// ---------------------------------------------------------------------------------------------
// frame_template
// ---------------------------------------------------------------------------------------------

template <class... L>
class frame_template {
 public:
  using meta = detail::stack_meta<L...>;
  static constexpr std::size_t header_size = meta::header_size;
  static constexpr std::size_t field_count = meta::nfields;
  static constexpr std::size_t slot_count = meta::nslots;

  explicit frame_template(const stack<L...>& s, const template_options& o = {}) : opts_(o) {
    auto layers = s.layers;
    detail::link_all(layers);
    [&]<std::size_t... I>(std::index_sequence<I...>) {
      (
          [&] {
            if (!error_.empty()) return;
            auto r = nanom::emit(std::get<I>(layers), std::span<std::byte>(img_.data() + meta::offsets[I], meta::sizes[I]),
                                 {}, std::endian::big);
            if (!r) error_ = r.error().what;
          }(),
          ...);
    }(std::make_index_sequence<sizeof...(L)>{});
    for (std::size_t k = 0; k < slot_count; ++k) {
      user_csum_[k] = detail::load16(img_.data() + meta::slots[k].off);
      policy_[k] = csum_policy::compute;
      mode_[k] = detail::mode_checksum;
    }
    cur_payload_ = o.payload_size;
    for (const auto& l : meta::lengths) detail::write_field(img_.data(), meta::fields[l.field], length_value(l, cur_payload_));
    for (std::size_t k = 0; k < slot_count; ++k) recompute(k);
  }

  /// Empty unless compile() failed (a field value that does not fit its bits).
  std::string_view error() const noexcept { return error_; }
  bool ok() const noexcept { return error_.empty(); }

  // ---- patch points ------------------------------------------------------------------------

  /// The handle of a patch point, resolved at compile time (a typo is a compile error).
  template <nanom::fixed_string Path>
  static constexpr field_id id() noexcept {
    constexpr std::size_t i = meta::find(Path.sv());
    static_assert(i != detail::npos, "nanocraft: no such patch point in this stack");
    return field_id{std::uint16_t(i)};
  }
  /// The handle of a patch point by name ("someip.session_id", "vlan[1].vid"); invalid if absent.
  static constexpr field_id find(std::string_view path) noexcept {
    const std::size_t i = meta::find(path);
    return i == detail::npos ? field_id{} : field_id{std::uint16_t(i)};
  }
  static constexpr const field_desc& describe(field_id id) noexcept { return meta::fields[id.index]; }
  static constexpr std::span<const field_desc> fields() noexcept { return meta::fields; }

  /// Set a field (integers are masked to the field's width; byte arrays take a byte range of the
  /// field's size). Maintained checksums are updated incrementally.
  template <nanom::fixed_string Path, class V>
  NANOCRAFT_INLINE void set(const V& v) noexcept {
    constexpr std::size_t i = id<Path>().index;
    set_index<i>(v);
  }
  /// Patch a frame already written by write() (in a ring slot or capture buffer) instead of the
  /// image: the same compile-time patch with incremental checksums, the frame's L4 checksum
  /// (which covers its payload) included. Cheapest when consecutive frames differ in a few fields:
  /// the image is never re-read after a store. The image itself is not changed.
  template <nanom::fixed_string Path, class V>
  NANOCRAFT_INLINE void patch(std::span<std::byte> frame, const V& v) noexcept {
    constexpr std::size_t I = id<Path>().index;
    static constexpr field_desc f = meta::fields[I];
    assert(frame.size() >= header_size);
    std::byte* fr = frame.data();
    if constexpr (detail::is_byte_range<V>::value) patch_ct<I>(fr, [&] { std::memcpy(fr + f.off, v.data(), f.len); });
    else patch_ct<I>(fr, [&] { detail::write_field(fr, f, std::uint64_t(v)); });
  }

  void set(field_id id, std::uint64_t v) noexcept {
    assert(id.valid());
    const auto& eff = meta::effects[id.index];
    detail::patch_with(img_.data(), eff.e.data(), eff.n, meta::slots.data(), mode_.data(),
                       [&] { detail::write_field(img_.data(), meta::fields[id.index], v); });
  }
  void set(field_id id, std::span<const std::byte> v) noexcept {
    assert(id.valid());
    const auto& f = meta::fields[id.index];
    const auto& eff = meta::effects[id.index];
    detail::patch_with(img_.data(), eff.e.data(), eff.n, meta::slots.data(), mode_.data(),
                       [&] { std::memcpy(img_.data() + f.off, v.data(), std::min<std::size_t>(v.size(), f.len)); });
  }
  template <nanom::fixed_string Path>
  std::uint64_t get() const noexcept {
    return detail::read_field(img_.data(), meta::fields[id<Path>().index]);
  }
  std::uint64_t get(field_id id) const noexcept { return detail::read_field(img_.data(), meta::fields[id.index]); }

  // ---- checksums ---------------------------------------------------------------------------

  /// Choose how a checksum field ("ipv4.checksum", "udp.checksum") is produced. False if the
  /// path is not a checksum field of this stack.
  bool checksum(std::string_view path, csum_policy p) noexcept {
    const std::size_t f = meta::find(path);
    for (std::size_t k = 0; k < slot_count; ++k)
      if (meta::slots[k].field == f) {
        policy_[k] = p;
        mode_[k] = p == csum_policy::compute ? detail::mode_checksum
                   : p == csum_policy::offload && meta::slots[k].kind == checksum_kind::l4 ? detail::mode_sum
                   : p == csum_policy::offload ? detail::mode_checksum
                                               : detail::mode_skip;
        recompute(k);
        return true;
      }
    return false;
  }
  csum_policy checksum_policy(std::size_t slot) const noexcept { return policy_[slot]; }

  // ---- frames ------------------------------------------------------------------------------

  std::size_t payload_size() const noexcept { return cur_payload_; }
  /// Resize the payload: every length field of the chain follows, incrementally.
  NANOCRAFT_INLINE void payload_size(std::size_t n) noexcept {
    if (n == cur_payload_) return;
    for (const auto& l : meta::lengths) set(field_id{l.field}, length_value(l, n));
    cur_payload_ = n;
  }
  /// Does a frame with an n-byte payload fit `room` bytes? (Overflow-safe.)
  bool fits(std::size_t room, std::size_t n) const noexcept {
    return n <= room && room - n >= header_size && room >= opts_.min_frame;
  }
  std::size_t frame_size(std::size_t payload) const noexcept {
    return std::max(header_size + payload, opts_.min_frame);
  }
  /// The header image (lengths and checksums for an all-zero payload of payload_size() bytes).
  std::span<const std::byte, header_size> header() const noexcept { return std::span<const std::byte, header_size>(img_); }

  /// Write the headers for a payload of n bytes into dst and return the payload area, for callers
  /// that produce the payload in place (sensor data serialized straight into the frame). Finish
  /// with commit(dst, n). Empty span if dst is too small.
  NANOCRAFT_INLINE std::span<std::byte> prepare(std::span<std::byte> dst, std::size_t n) noexcept {
    if (!fits(dst.size(), n)) return {};
    payload_size(n);
    std::memcpy(dst.data(), img_.data(), header_size);
    return dst.subspan(header_size, n);
  }
  /// Finish a frame whose payload (n bytes) is in place after prepare(): L4 checksums over the
  /// payload, padding, faults. Returns the frame length.
  NANOCRAFT_INLINE std::size_t commit(std::span<std::byte> dst, std::size_t n) noexcept {
    NANOCRAFT_PROFILE_SCOPE(template_write);
    std::byte* f = dst.data();
    if (n) {
      [&]<std::size_t... K>(std::index_sequence<K...>) {
        (
            [&] {
              constexpr slot_desc s = meta::slots[K];
              if constexpr (s.kind == checksum_kind::l4) {
                if (mode_[K] != detail::mode_checksum) return;
                std::uint32_t ps = csum::sum(f + header_size, n);
                if constexpr (s.odd_payload) ps = csum::swap(ps);
                std::uint16_t c =
                    std::uint16_t(~csum::fold(std::uint32_t(std::uint16_t(~detail::load16(f + s.off))) + ps));
                if (c == 0) c = 0xffff;
                detail::store16(f + s.off, c);
              }
            }(),
            ...);
      }(std::make_index_sequence<slot_count>{});
    }
    std::size_t len = header_size + n;
    if (len < opts_.min_frame) {
      std::memset(f + len, 0, opts_.min_frame - len);
      len = opts_.min_frame;
    }
    if (faults_on_) [[unlikely]]
      len = apply_faults(f, len);
    NANOCRAFT_PROFILE_COUNT(template_write, 1, len);
    return len;
  }
  /// One frame: headers + payload into dst. Returns the frame length (0 if dst is too small).
  NANOCRAFT_INLINE std::size_t write(std::span<std::byte> dst, std::span<const std::byte> payload) noexcept {
    const std::size_t n = payload.size();
    if (!fits(dst.size(), n)) [[unlikely]]
      return 0;
    payload_size(n);
    std::memcpy(dst.data(), img_.data(), header_size);
    detail::copy_payload(dst.data() + header_size, payload.data(), n);
    return commit(dst, n);
  }

  // ---- faults ------------------------------------------------------------------------------

  /// Resolve and arm a fault policy. False (nothing armed) if a name does not resolve.
  bool inject(const faults& fs) noexcept {
    compiled_faults c{};
    for (auto s : fs.bad_checksums) {
      if (s.empty()) continue;
      const std::size_t f = meta::find(s);
      bool found = false;
      for (std::size_t k = 0; k < slot_count; ++k)
        if (meta::slots[k].field == f) {
          c.bad_mask |= 1u << k;
          found = true;
        }
      if (!found) return false;
    }
    for (const auto& l : fs.lengths) {
      if (l.field.empty()) continue;
      const std::size_t f = meta::find(l.field);
      if (f == detail::npos) return false;
      c.len[c.nlen++] = {std::uint16_t(f), l.delta};
    }
    c.truncate = fs.truncate;
    c.period = fs.period ? fs.period : 1;
    faults_ = c;
    faults_on_ = c.bad_mask || c.nlen || c.truncate;
    return true;
  }
  void clear_faults() noexcept {
    faults_ = {};
    faults_on_ = false;
  }

  // ---- other frames ------------------------------------------------------------------------

  /// Does `frame` have this stack's shape (every selector field - ethertypes, IP version and
  /// protocol, ... - equal to this template's value)?
  bool matches(std::span<const std::byte> frame) const noexcept {
    if (frame.size() < header_size) return false;
    for (auto s : meta::selectors) {
      const auto& f = meta::fields[s];
      if (f.kind == field_kind::bytes ? std::memcmp(frame.data() + f.off, img_.data() + f.off, f.len) != 0
                                      : detail::read_field(frame.data(), f) != detail::read_field(img_.data(), f))
        return false;
    }
    return true;
  }

  /// Patch `frame` (laid out like this template) in place with this template's checksum policies,
  /// touching only the slots in slot_mask. For segmenters and fault injection.
  void patch(std::byte* frame, field_id id, std::uint64_t v, std::uint32_t slot_mask = ~0u) const noexcept {
    std::array<std::uint8_t, slot_count ? slot_count : 1> m{};
    for (std::size_t k = 0; k < slot_count; ++k) m[k] = (slot_mask >> k) & 1 ? mode_[k] : detail::mode_skip;
    const auto& eff = meta::effects[id.index];
    detail::patch_with(frame, eff.e.data(), eff.n, meta::slots.data(), m.data(),
                       [&] { detail::write_field(frame, meta::fields[id.index], v); });
  }
  /// The value a length field of the chain takes for a frame whose payload ends `end` bytes after
  /// the start of the frame.
  static constexpr std::uint64_t length_for_end(const length_desc& l, std::size_t end) noexcept {
    return std::uint64_t(std::int64_t(end) - std::int64_t(l.base) + l.add);
  }
  /// Mode of each slot (internal; used by segmenters).
  std::uint8_t slot_mode(std::size_t k) const noexcept { return mode_[k]; }

 private:
  template <std::size_t I, class V>
  NANOCRAFT_INLINE void set_index(const V& v) noexcept {
    static constexpr field_desc f = meta::fields[I];
    std::byte* img = img_.data();
    if constexpr (detail::is_byte_range<V>::value) {
      assert(f.kind == field_kind::bytes && v.size() == f.len);
      patch_ct<I>(img, [&] { std::memcpy(img + f.off, v.data(), f.len); });
    } else {
      static_assert(std::is_integral_v<V> || std::is_enum_v<V>, "nanocraft: set() takes an integer or a byte array");
      patch_ct<I>(img, [&] { detail::write_field(img, f, std::uint64_t(v)); });
    }
  }

  // The compile-time patch: every checksum window, its slot and multiplicity are constants, so
  // this unrolls to a few 16-bit loads, the write, and one RFC 1624 update per touched checksum.
  template <std::size_t I, class W>
  NANOCRAFT_INLINE void patch_ct(std::byte* fr, W&& write) noexcept {
    static constexpr auto eff = meta::effects[I];
    constexpr std::size_t ne = eff.n;
    if constexpr (ne == 0) {
      write();
    } else {
      std::array<std::uint32_t, ne> old{};
      [&]<std::size_t... K>(std::index_sequence<K...>) {
        ((old[K] = detail::window_sum<eff.e[K].begin, eff.e[K].end>(fr)), ...);
      }(std::make_index_sequence<ne>{});
      write();
      [&]<std::size_t... K>(std::index_sequence<K...>) {
        (
            [&] {
              constexpr effect e = eff.e[K];
              const std::uint8_t m = mode_[e.slot];
              if (m == detail::mode_skip) [[unlikely]]
                return;
              const std::uint32_t o = detail::fold32(old[K]), nw = detail::fold32(detail::window_sum<e.begin, e.end>(fr));
              std::byte* cp = fr + meta::slots[e.slot].off;
              const std::uint16_t c = detail::load16(cp);
              if (m == detail::mode_checksum) [[likely]] {
                // ~c + mult * (~o + n)
                const std::uint32_t d = std::uint32_t(std::uint16_t(~o)) + nw;
                std::uint32_t x = std::uint32_t(std::uint16_t(~c)) + d * e.mult;
                detail::store16(cp, std::uint16_t(~detail::fold32(x)));
              } else {
                const std::uint32_t reps = e.pseudo ? 1u : e.mult - 1u;
                const std::uint32_t d = std::uint32_t(std::uint16_t(~o)) + nw;
                detail::store16(cp, std::uint16_t(detail::fold32(c + d * reps)));
              }
            }(),
            ...);
      }(std::make_index_sequence<ne>{});
    }
  }

  std::uint64_t length_value(const length_desc& l, std::size_t payload) const noexcept {
    return length_for_end(l, header_size + payload);
  }

  void recompute(std::size_t k) noexcept {
    const auto& s = meta::slots[k];
    std::byte* p = img_.data();
    detail::store16(p + s.off, 0);
    std::uint16_t v = 0;
    switch (policy_[k]) {
      case csum_policy::keep: v = user_csum_[k]; break;
      case csum_policy::zero: v = 0; break;
      case csum_policy::compute:
      case csum_policy::offload: {
        if (s.kind == checksum_kind::header) {
          v = csum::finish(csum::sum(p + s.cover.begin, s.cover.end - s.cover.begin));
          break;
        }
        const std::uint32_t l4len = s.alias >= 0 ? detail::load16(p + s.alias)
                                                 : std::uint32_t(header_size + cur_payload_ - s.cover.begin);
        const std::uint32_t ps = detail::pseudo_sum(p, s, l4len);
        if (policy_[k] == csum_policy::offload) {
          v = csum::fold(ps);
        } else {
          v = csum::finish(csum::add(ps, csum::sum(p + s.cover.begin, s.cover.end - s.cover.begin)));
          if (v == 0) v = 0xffff;
        }
        break;
      }
    }
    detail::store16(p + s.off, v);
  }

  struct compiled_faults {
    std::uint32_t bad_mask = 0;
    struct lf {
      std::uint16_t field = 0;
      std::int32_t delta = 0;
    };
    std::array<lf, 4> len{};
    std::uint8_t nlen = 0;
    std::size_t truncate = 0;
    std::uint32_t period = 1;
    std::uint32_t counter = 0;
  };

  std::size_t apply_faults(std::byte* f, std::size_t len) noexcept {
    if (++faults_.counter < faults_.period) return len;
    faults_.counter = 0;
    for (std::uint8_t i = 0; i < faults_.nlen; ++i) {
      const field_id id{faults_.len[i].field};
      patch(f, id, detail::read_field(f, meta::fields[id.index]) + std::uint64_t(std::int64_t(faults_.len[i].delta)));
    }
    for (std::size_t k = 0; k < slot_count; ++k)
      if ((faults_.bad_mask >> k) & 1) {
        std::byte* c = f + meta::slots[k].off;
        c[0] ^= std::byte{0x5a};
        c[1] ^= std::byte{0xa5};
      }
    return len - std::min(len, faults_.truncate);
  }

  alignas(64) std::array<std::byte, header_size> img_{};
  std::array<std::uint8_t, slot_count ? slot_count : 1> mode_{};
  std::array<csum_policy, slot_count ? slot_count : 1> policy_{};
  std::array<std::uint16_t, slot_count ? slot_count : 1> user_csum_{};
  std::size_t cur_payload_ = 0;
  template_options opts_{};
  bool faults_on_ = false;
  compiled_faults faults_{};
  std::string_view error_{};
};

/// Compile a stack into a frame template.
template <class... L>
frame_template<L...> compile(const stack<L...>& s, const template_options& o = {}) {
  return frame_template<L...>(s, o);
}
template <class... L>
frame_template<L...> compile(const stack<L...>& s, std::size_t payload_size) {
  return frame_template<L...>(s, template_options{payload_size, 0});
}

// ---------------------------------------------------------------------------------------------
// frame_ref: patch an existing frame (a replayed packet) with the same patch points
// ---------------------------------------------------------------------------------------------

/// A stateless, non-owning patch view over a frame laid out like stack<L...>. Every checksum
/// field stored in the frame is kept correct incrementally (an L4 checksum stored as 0 where 0
/// means "none" - UDP over IPv4 - stays 0). Check the shape first with frame_template::matches().
template <class... L>
class frame_ref {
 public:
  using meta = detail::stack_meta<L...>;
  explicit frame_ref(std::span<std::byte> frame) noexcept : f_(frame) { assert(frame.size() >= meta::header_size); }
  explicit frame_ref(const frame_template<L...>&, std::span<std::byte> frame) noexcept : frame_ref(frame) {}

  template <nanom::fixed_string Path, class V>
  void set(const V& v) noexcept {
    constexpr field_id id = frame_template<L...>::template id<Path>();
    if constexpr (detail::is_byte_range<V>::value) set(id, std::as_bytes(std::span(v)));
    else set(id, std::uint64_t(v));
  }
  void set(field_id id, std::uint64_t v) noexcept {
    apply(id, [&] { detail::write_field(f_.data(), meta::fields[id.index], v); });
  }
  void set(field_id id, std::span<const std::byte> v) noexcept {
    const auto& fd = meta::fields[id.index];
    apply(id, [&] { std::memcpy(f_.data() + fd.off, v.data(), std::min<std::size_t>(v.size(), fd.len)); });
  }
  template <nanom::fixed_string Path>
  std::uint64_t get() const noexcept {
    return detail::read_field(f_.data(), meta::fields[frame_template<L...>::template id<Path>().index]);
  }
  std::span<std::byte> bytes() const noexcept { return f_; }

 private:
  template <class W>
  void apply(field_id id, W&& w) noexcept {
    std::array<std::uint8_t, meta::nslots ? meta::nslots : 1> m{};
    for (std::size_t k = 0; k < meta::nslots; ++k) {
      const auto& s = meta::slots[k];
      m[k] = detail::mode_checksum;
      if (s.kind == checksum_kind::l4 && s.zero_ok && detail::load16(f_.data() + s.off) == 0) m[k] = detail::mode_skip;
    }
    const auto& eff = meta::effects[id.index];
    detail::patch_with(f_.data(), eff.e.data(), eff.n, meta::slots.data(), m.data(), w);
  }
  std::span<std::byte> f_;
};

}  // namespace nanocraft

#endif  // NANOCRAFT_FRAME_TEMPLATE_HPP_INCLUDED
