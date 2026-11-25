// SPDX-License-Identifier: Apache-2.0
// Segmentation: SOME/IP-TP, IPv4 fragments and IPv6 fragment headers. Every segment is checked
// against the spec (offsets, More flag, alignment, sizes, checksums via the independent verifier),
// compared byte for byte with the hand-written reference builder, and a small reference
// reassembler must reproduce the original message. Payload chunks must point into the caller's
// payload (zero copy).
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"
#include "reference.hpp"

#include <map>

using namespace nanocraft::proto;

static ref::bytes flat(const nanocraft::gather& g) {
  ref::bytes f(g.size());
  CHECK_EQ(g.copy_to(f), g.size());
  return f;
}
static bool points_into(const nanocraft::gather& g, std::span<const std::byte> payload) {
  // the last chunk of a segment with payload bytes must alias the caller's buffer
  if (payload.empty() || g.count < 2) return true;
  const auto* b = static_cast<const std::byte*>(g.chunks[g.count - 1].base);
  return b >= payload.data() && b + g.chunks[g.count - 1].len <= payload.data() + payload.size();
}

// ---- reference reassemblers (written from the specs, independent of the segmenter)
struct tp_reassembler {
  std::map<std::uint32_t, ref::bytes> parts;  // offset in bytes -> data
  bool saw_last = false;
  std::uint32_t total = 0;
  bool error = false;
  void add(std::uint32_t off_units, bool more, std::span<const std::byte> data) {
    const std::uint32_t off = off_units * 16;
    if (more && data.size() % 16 != 0) error = true;  // PRS_SOMEIP: all but the last segment
    parts[off] = ref::bytes(data.begin(), data.end());
    if (!more) {
      saw_last = true;
      total = off + std::uint32_t(data.size());
    }
  }
  bool result(ref::bytes& out) const {
    if (error || !saw_last) return false;
    out.assign(total, std::byte{0});
    std::uint32_t next = 0;
    for (const auto& [o, d] : parts) {
      if (o != next) return false;  // gap or overlap
      std::copy(d.begin(), d.end(), out.begin() + o);
      next = o + std::uint32_t(d.size());
    }
    return next == total;
  }
};

static void tp_case(std::size_t n, std::size_t max_payload, bool zero_udp_csum) {
  ref::spec s;
  s.dst = {1, 2, 3, 4, 5, 6};
  s.src = {2, 0, 0, 0, 0, 1};
  s.vlans = {{5, 0, 42}};
  s.src4 = {10, 0, 0, 1};
  s.dst4 = {10, 0, 0, 2};
  s.ident = 0x1234;
  s.sport = s.dport = 30509;
  s.service = 0x4321;
  s.method = 0x8005;
  s.client = 0x0001;
  s.session = 0x0077;
  s.mtype = 0x02;
  s.tp = true;
  if (zero_udp_csum) s.udp_csum = ref::spec::csum_zero;
  auto tm = nanocraft::compile(eth{.dst = s.dst, .src = s.src} / vlan{.pcp = {5}, .vid = {42}} /
                               ipv4{.identification = 0x1234, .src = s.src4, .dst = s.dst4} /
                               udp{.src_port = 30509, .dst_port = 30509} /
                               someip{.service_id = 0x4321, .method_id = 0x8005, .client_id = 1, .session_id = 0x77} /
                               someip_tp{});
  if (zero_udp_csum) tm.checksum("udp.checksum", nanocraft::csum_policy::zero);
  nanocraft::segmenter seg(tm, someip_tp_segments(max_payload));
  CHECK(seg.ok());
  const auto msg = t::random_bytes(n);
  const std::size_t step = (max_payload / 16) * 16;
  tp_reassembler ra;
  std::size_t k = 0, off = 0;
  const std::size_t nseg = seg.run(msg, [&](const nanocraft::gather& g) {
    const auto f = flat(g);
    CHECK(points_into(g, msg));
    const auto v = ref::verify(f);
    CHECK(v.parsed && v.ip_ok && v.lengths_ok);
    CHECK(zero_udp_csum ? v.udp_zero : v.udp_ok);
    const std::size_t sm = 14 + 4 + 20 + 8;  // SOME/IP header
    const std::uint32_t len = ref::get32(f, sm + 4);
    const std::size_t data = f.size() - sm - 20;
    CHECK_EQ(std::size_t(len), 8 + 4 + data);
    CHECK_EQ(unsigned(std::uint8_t(f[sm + 14])), 0x22u);  // TP flag
    CHECK_EQ(ref::get16(f, sm + 10), 0x77u);              // same session for all segments
    const std::uint32_t tpw = ref::get32(f, sm + 16);
    const bool more = tpw & 1;
    CHECK_EQ(std::size_t(tpw >> 4) * 16, off);
    CHECK(data <= step);
    if (more) CHECK_EQ(data, step);
    CHECK_EQ((tpw >> 1) & 7u, 0u);  // reserved bits
    ra.add(tpw >> 4, more, std::span<const std::byte>(f).subspan(sm + 20));
    // byte-identical to the reference builder for this segment
    auto ss = s;
    ss.tp_offset_units = std::uint32_t(off / 16);
    ss.tp_more = more;
    ss.payload.assign(msg.begin() + std::ptrdiff_t(off), msg.begin() + std::ptrdiff_t(off + data));
    CHECK_BYTES(f, ref::build(ss));
    off += data;
    ++k;
  });
  CHECK_EQ(nseg, k);
  CHECK_EQ(nseg, seg.count(n));
  CHECK_EQ(nseg, n == 0 ? std::size_t(1) : (n + step - 1) / step);
  ref::bytes out;
  CHECK(ra.result(out));
  CHECK_BYTES(out, msg);
}

// IPv4 reassembly (RFC 791): by identification, offset in 8-byte units, MF.
struct ip_reassembler {
  std::map<std::size_t, ref::bytes> parts;
  std::size_t total = 0;
  bool last = false, error = false;
  void add(std::size_t off, bool more, std::span<const std::byte> d) {
    if (more && d.size() % 8) error = true;
    parts[off] = ref::bytes(d.begin(), d.end());
    if (!more) last = true, total = off + d.size();
  }
  bool result(ref::bytes& out) const {
    if (error || !last) return false;
    out.clear();
    for (const auto& [o, d] : parts) {
      if (o != out.size()) return false;
      out.insert(out.end(), d.begin(), d.end());
    }
    return out.size() == total;
  }
};

static void ipv4_frag_case(std::size_t n, std::size_t mtu) {
  ref::spec s;
  s.dst = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  s.src = {2, 0, 0, 0, 0, 2};
  s.src4 = {192, 168, 1, 1};
  s.dst4 = {192, 168, 1, 200};
  s.ident = 0xbeef;
  s.ttl = 17;
  s.sport = 1000;
  s.dport = 30490;
  s.service = 0xffff;
  s.method = 0x8100;
  s.session = 9;
  s.payload = t::random_bytes(n);
  auto tm = nanocraft::compile(eth{.dst = s.dst, .src = s.src} /
                               ipv4{.identification = 0xbeef, .ttl = 17, .src = s.src4, .dst = s.dst4} /
                               udp{.src_port = 1000, .dst_port = 30490} /
                               someip{.service_id = 0xffff, .method_id = 0x8100, .session_id = 9});
  nanocraft::segmenter seg(tm, ipv4_fragments(mtu));
  CHECK(seg.ok());
  const std::size_t step = ((mtu - 20) / 8) * 8;
  ip_reassembler ra;
  std::size_t off = 0;
  ref::bytes first_hdr;
  const auto segs = seg.segment(s.payload);
  for (std::size_t k = 0; k < segs.size(); ++k) {
    const auto& g = segs[k];
    const auto f = flat(g);
    CHECK(f.size() <= 14 + mtu);
    CHECK(points_into(g, s.payload) || g.count <= 2);
    CHECK_EQ(unsigned(ref::naive_sum(std::span<const std::byte>(f).subspan(14, 20))), 0xffffu);
    const unsigned tot = ref::get16(f, 16), ff = ref::get16(f, 20);
    CHECK_EQ(std::size_t(tot), f.size() - 14);
    CHECK_EQ(ref::get16(f, 18), 0xbeefu);
    const bool mf = ff & 0x2000;
    CHECK_EQ(std::size_t(ff & 0x1fff) * 8, off);
    CHECK_EQ(mf, k + 1 < segs.size());
    const std::size_t data = tot - 20;
    if (mf) CHECK_EQ(data, step);
    ra.add(off, mf, std::span<const std::byte>(f).subspan(34));
    off += data;
    if (k == 0) first_hdr.assign(f.begin(), f.begin() + 34);
  }
  ref::bytes l4;
  CHECK(ra.result(l4));
  const auto want = ref::build(s);
  CHECK_BYTES(l4, ref::bytes(want.begin() + 34, want.end()));
  // the reassembled datagram passes the independent UDP checksum verification
  ref::bytes dg = first_hdr;
  dg.insert(dg.end(), l4.begin(), l4.end());
  ref::set16(dg, 16, unsigned(20 + l4.size()));
  ref::set16(dg, 20, 0);
  ref::set16(dg, 24, 0);
  ref::set16(dg, 24, ref::naive_csum(std::span<const std::byte>(dg).subspan(14, 20)));
  const auto v = ref::verify(dg);
  CHECK(v.ip_ok && v.udp_ok && v.lengths_ok);
}

static void ipv6_frag_case(std::size_t n, std::size_t mtu) {
  ref::spec s;
  s.v6 = true;
  s.src6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  s.dst6 = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb};
  s.hop = 1;
  s.sport = s.dport = 30490;
  s.service = 0x1111;
  s.session = 3;
  s.payload = t::random_bytes(n);
  auto tm = nanocraft::compile(eth{} / ipv6{.hop_limit = 1, .src = s.src6, .dst = s.dst6} /
                               ipv6_frag{.identification = 0xcafe0001} / udp{.src_port = 30490, .dst_port = 30490} /
                               someip{.service_id = 0x1111, .session_id = 3});
  nanocraft::segmenter seg(tm, ipv6_fragments(mtu));
  CHECK(seg.ok());
  const std::size_t step = ((mtu - 48) / 8) * 8;
  ip_reassembler ra;
  std::size_t off = 0, k = 0;
  const std::size_t nseg = seg.run(s.payload, [&](const nanocraft::gather& g) {
    const auto f = flat(g);
    CHECK(f.size() <= 14 + mtu);
    CHECK_EQ(ref::get16(f, 12), 0x86ddu);
    CHECK_EQ(unsigned(std::uint8_t(f[14 + 6])), 44u);
    CHECK_EQ(std::size_t(ref::get16(f, 14 + 4)), f.size() - 14 - 40);
    const std::size_t fh = 54;
    CHECK_EQ(unsigned(std::uint8_t(f[fh])), 17u);
    CHECK_EQ(ref::get32(f, fh + 4), 0xcafe0001u);
    const unsigned w = ref::get16(f, fh + 2);
    const bool more = w & 1;
    CHECK_EQ(std::size_t(w >> 3) * 8, off);
    const std::size_t data = f.size() - fh - 8;
    if (more) CHECK_EQ(data, step);
    ra.add(off, more, std::span<const std::byte>(f).subspan(fh + 8));
    off += data;
    ++k;
  });
  CHECK_EQ(nseg, k);
  ref::bytes l4;
  CHECK(ra.result(l4));
  const auto want = ref::build(s);  // no fragment header: the UDP checksum is over the same datagram
  CHECK_BYTES(l4, ref::bytes(want.begin() + 54, want.end()));
}

int main() {
  for (std::size_t n : {0, 1, 15, 16, 17, 1391, 1392, 1393, 2784, 5000, 65536})
    for (std::size_t mx : {1392, 1400, 16, 100}) {
      if (mx == 16 && n > 5000) continue;
      tp_case(n, mx, false);
    }
  tp_case(65536, 1392, true);
  for (int i = 0; i < 40; ++i) tp_case(t::rnd(0, 20000), t::rnd(16, 1400), i % 4 == 0);
  for (std::size_t n : {0, 1, 7, 8, 1400, 1448, 1449, 3000, 65000})
    for (std::size_t mtu : {1500, 576, 68}) {
      if (mtu == 68 && n > 3000) continue;
      ipv4_frag_case(n, mtu);
    }
  for (int i = 0; i < 30; ++i) ipv4_frag_case(t::rnd(0, 9000), t::rnd(68, 9000));
  for (std::size_t n : {0, 1, 1400, 1500, 9000, 60000})
    for (std::size_t mtu : {1500, 1280}) ipv6_frag_case(n, mtu);
  for (int i = 0; i < 20; ++i) ipv6_frag_case(t::rnd(0, 9000), t::rnd(1280, 9000));
  // a spec that does not resolve
  auto tm = nanocraft::compile(eth{} / ipv4{} / udp{});
  nanocraft::segmenter bad(tm, someip_tp_segments());
  CHECK(!bad.ok());
  std::array<std::byte, 4> pay{};
  CHECK_EQ(bad.run(pay, [](const nanocraft::gather&) {}), std::size_t(0));
  return t::done("test_segment");
}
