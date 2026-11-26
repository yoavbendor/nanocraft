// SPDX-License-Identifier: Apache-2.0
// nanocraft/segment.hpp — split a message into segments without copying its payload.
//
// One protocol-independent mechanism covers IPv4 fragmentation, the IPv6 fragment header and
// SOME/IP-TP: everything up to and including layer `after` is replicated per segment (copied from
// the template into a small header arena and patched), everything after it — the rest of the
// template's headers and then the caller's payload — is the data stream that is cut into pieces of
// at most max_data bytes, all but the last a multiple of `unit`. Per segment the engine writes the
// offset field (in units), the "more segments" bit and the length chain of the replicated layers;
// checksums in the replicated headers are kept incrementally, and L4 checksums that live in the data
// stream (UDP under IPv4 fragmentation) are computed once over the whole datagram first.
//
//   auto t = nanocraft::compile(eth{} / ipv4{} / udp{} / someip{} / someip_tp{});
//   nanocraft::segmenter seg(t, nanocraft::proto::someip_tp_segments(1392));
//   seg.run(payload, [&](const nanocraft::gather& g) { writer.write(ts, g); });   // zero copy
//   auto all = seg.segment(payload);       // or: all segments at once (std::span<const gather>)
//
// Each gather is [replicated headers in the arena][slice of template tail][slice of payload]; the
// arena and payload must outlive the gathers (the arena is reused by the next call). Presets for
// nanowire's protocols live in nanocraft/nanowire_layers.hpp (ipv4_fragments, ipv6_fragments,
// someip_tp_segments).
#ifndef NANOCRAFT_SEGMENT_HPP_INCLUDED
#define NANOCRAFT_SEGMENT_HPP_INCLUDED

#include "frame_template.hpp"
#include "gather.hpp"
#include "profile.hpp"

#include <vector>

namespace nanocraft {

/// How to segment (see the header comment). Names are patch-point paths of the template's stack.
struct segment_spec {
  std::string_view after;         ///< layer replicated last ("ipv4", "ipv6_frag", "someip_tp")
  std::string_view offset_field;  ///< receives offset / unit
  std::uint32_t unit = 8;         ///< offset unit; all segments but the last are multiples of it
  std::string_view more_field;    ///< holds the "more segments" flag
  std::uint64_t more_bit = 1;     ///< the flag's value inside more_field
  std::size_t max_data = 1480;    ///< data bytes per segment (rounded down to a multiple of unit)
};

template <class... L>
class segmenter {
  using tmpl = frame_template<L...>;
  using meta = typename tmpl::meta;

 public:
  segmenter(tmpl& t, const segment_spec& s) : t_(&t), spec_(s) {
    if (!t.ok() || s.unit == 0) {
      ok_ = false;
      return;
    }
    const std::size_t li = meta::layer(s.after);
    off_ = tmpl::find(s.offset_field);
    more_ = tmpl::find(s.more_field);
    step_ = (s.max_data / s.unit) * s.unit;
    if (li == detail::npos || !off_ || !more_ || step_ == 0) {
      ok_ = false;
      return;
    }
    rep_ = meta::offsets[li] + meta::sizes[li];
    const auto& od = meta::fields[off_.index];
    const auto& md = meta::fields[more_.index];
    if (std::size_t(od.off) + od.len > rep_ || std::size_t(md.off) + md.len > rep_) {
      ok_ = false;
      return;
    }
    for (std::size_t k = 0; k < meta::nslots; ++k)
      if (meta::slots[k].off < rep_) head_mask_ |= 1u << k;
  }
  bool ok() const noexcept { return ok_; }
  /// Bytes of replicated header per segment.
  std::size_t header_bytes() const noexcept { return rep_; }
  /// Number of segments a payload of n bytes produces.
  std::size_t count(std::size_t n) const noexcept {
    if (!ok_) return 0;
    const std::size_t d = meta::header_size - rep_ + n;
    return d == 0 ? 1 : 1 + (d - 1) / step_;
  }

  /// Segment `payload`; fn(const gather&) is called once per segment, in order. Returns the
  /// number of segments (0 if the spec did not resolve or the offset does not fit its field).
  template <class Fn>
  std::size_t run(std::span<const std::byte> payload, Fn&& fn) {
    if (!ok_) return 0;
    NANOCRAFT_PROFILE_SCOPE(segment);
    tmpl& t = *t_;
    constexpr std::size_t H = meta::header_size;
    const std::size_t n = payload.size();
    const std::size_t total = (H - rep_) + n;
    const std::size_t nseg = count(n);
    const auto& od = meta::fields[off_.index];
    if (od.kind != field_kind::bytes && od.bits < 64 && ((nseg - 1) * step_ / spec_.unit) > od.mask()) return 0;
    // Reject datagrams whose length fields would overflow their wire width.
    const std::size_t max_seg_end = rep_ + std::min(step_, total);
    for (const auto& l : meta::lengths) {
      const auto& fd = meta::fields[l.field];
      const std::size_t end = fd.off < rep_ ? max_seg_end : H + n;
      const std::int64_t lv = std::int64_t(end) - std::int64_t(l.base) + l.add;
      if (lv < 0 || (fd.kind != field_kind::bytes && fd.bits < 64 && std::uint64_t(lv) > fd.mask())) return 0;
    }
    t.payload_size(n);
    std::memcpy(full_.data(), t.header().data(), H);
    // L4 checksums carried in the data stream: complete them over the whole payload once.
    std::uint32_t payload_sum = 0;
    bool have_sum = false;
    for (std::size_t k = 0; k < meta::nslots; ++k) {
      const auto& s = meta::slots[k];
      if (s.kind != checksum_kind::l4 || ((head_mask_ >> k) & 1) || t.slot_mode(k) != detail::mode_checksum || !n)
        continue;
      if (!have_sum) payload_sum = csum::sum(payload.data(), n), have_sum = true;
      add_to(full_.data() + s.off, s.odd_payload ? csum::swap(payload_sum) : payload_sum, s.map_zero_to_ffff);
    }
    const std::span<const std::byte> tail(full_.data() + rep_, H - rep_);
    // L4 checksums in the replicated headers already cover `tail` in t.header(); remove `tail`
    // once here because each segment adds its own data slice (tail slice + payload slice) below.
    if (!tail.empty()) {
      const std::uint32_t tail_sum = csum::sum(tail);
      for (std::size_t s = 0; s < meta::nslots; ++s) {
        const auto& sl = meta::slots[s];
        if (sl.kind != checksum_kind::l4 || !((head_mask_ >> s) & 1) || t.slot_mode(s) != detail::mode_checksum) continue;
        const std::uint32_t ts = ((rep_ - sl.cover.begin) & 1) ? csum::swap(tail_sum) : tail_sum;
        std::uint16_t c = csum::update(detail::load16(full_.data() + sl.off), ts, 0);
        if (sl.map_zero_to_ffff && c == 0) c = 0xffff;
        detail::store16(full_.data() + sl.off, c);
      }
    }
    if (arena_.size() < nseg * rep_) arena_.resize(nseg * rep_);
    for (std::size_t k = 0; k < nseg; ++k) {
      const std::size_t o = k * step_;
      const std::size_t len = std::min(step_, total - o);
      std::byte* h = arena_.data() + k * rep_;
      std::memcpy(h, full_.data(), rep_);
      for (const auto& l : meta::lengths)
        if (meta::fields[l.field].off < rep_) t.patch(h, field_id{l.field}, tmpl::length_for_end(l, rep_ + len), head_mask_);
      // L4 checksums in the replicated headers without a length field (TCP): pseudo-header length
      for (std::size_t s = 0; s < meta::nslots; ++s) {
        const auto& sl = meta::slots[s];
        if (sl.kind != checksum_kind::l4 || sl.alias >= 0 || !((head_mask_ >> s) & 1) || t.slot_mode(s) == detail::mode_skip)
          continue;
        const std::uint32_t a = std::uint32_t(H + n - sl.cover.begin), b = std::uint32_t(rep_ + len - sl.cover.begin);
        const std::uint32_t os = (a >> 16) + (a & 0xffff), ns = (b >> 16) + (b & 0xffff);
        const std::uint16_t c = detail::load16(h + sl.off);
        std::uint16_t nc = t.slot_mode(s) == detail::mode_checksum ? csum::update(c, os, ns) : csum::update_sum(c, os, ns);
        if (t.slot_mode(s) == detail::mode_checksum && sl.map_zero_to_ffff && nc == 0) nc = 0xffff;
        detail::store16(h + sl.off, nc);
      }
      t.patch(h, off_, o / spec_.unit, head_mask_);
      const std::uint64_t mv = detail::read_field(h, meta::fields[more_.index]);
      t.patch(h, more_, k + 1 < nseg ? (mv | spec_.more_bit) : (mv & ~spec_.more_bit), head_mask_);
      gather g;
      g.add(h, rep_);
      // data = tail[o, o+len) ++ payload[...]
      std::span<const std::byte> a, b;
      if (o < tail.size()) a = tail.subspan(o, std::min(len, tail.size() - o));
      if (a.size() < len) {
        const std::size_t bo = o + a.size() - tail.size();  // offset into payload
        b = payload.subspan(bo, len - a.size());
      }
      g.add(a);
      g.add(b);
      // L4 checksums in the replicated headers cover this segment's data
      for (std::size_t s = 0; s < meta::nslots; ++s) {
        const auto& sl = meta::slots[s];
        if (sl.kind != checksum_kind::l4 || !((head_mask_ >> s) & 1) || t.slot_mode(s) != detail::mode_checksum) continue;
        const std::size_t pos = rep_ - sl.cover.begin;  // stream position of the data
        std::uint64_t acc = 0;
        if (!a.empty()) acc += (pos & 1) ? csum::swap(csum::sum(a)) : csum::sum(a);
        if (!b.empty()) acc += ((pos + a.size()) & 1) ? csum::swap(csum::sum(b)) : csum::sum(b);
        if (len) add_to(h + sl.off, csum::fold(acc), sl.map_zero_to_ffff);
      }
      NANOCRAFT_PROFILE_COUNT(segment, 1, g.size());
      fn(std::as_const(g));
    }
    return nseg;
  }

  /// All segments of `payload` at once (valid until the next call).
  std::span<const gather> segment(std::span<const std::byte> payload) {
    gathers_.clear();
    run(payload, [&](const gather& g) { gathers_.push_back(g); });
    return gathers_;
  }

 private:
  static void add_to(std::byte* cp, std::uint32_t s, bool map_zero_to_ffff) noexcept {
    std::uint16_t c = std::uint16_t(~csum::fold(std::uint32_t(std::uint16_t(~detail::load16(cp))) + s));
    if (map_zero_to_ffff && c == 0) c = 0xffff;
    detail::store16(cp, c);
  }

  tmpl* t_;
  segment_spec spec_;
  field_id off_{}, more_{};
  std::size_t rep_ = 0, step_ = 0;
  std::uint32_t head_mask_ = 0;
  bool ok_ = true;
  std::array<std::byte, meta::header_size> full_{};
  std::vector<std::byte> arena_;
  std::vector<gather> gathers_;
};

template <class... L>
segmenter(frame_template<L...>&, const segment_spec&) -> segmenter<L...>;

}  // namespace nanocraft

#endif  // NANOCRAFT_SEGMENT_HPP_INCLUDED
