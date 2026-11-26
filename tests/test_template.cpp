// SPDX-License-Identifier: Apache-2.0
// Frame templates vs two builders: the hand-written RFC builder (reference.hpp) and nanowire's own
// builders (nanowire::make_frame); and vs nanowire's reader (packet::parse + views, nw_check.hpp):
// reading and crafting must agree. For many random field values, payload sizes and stacks.
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"
#include "nw_check.hpp"
#include "reference.hpp"

#include <nanowire/build.hpp>

using namespace nanocraft::proto;
namespace nm = nanom;
using nanocraft::csum_policy;

// ---- nanowire oracle: the same protocol definitions' own builders (nanowire::build_frame derives
// every type / length field and computes the IPv4 and UDP checksums itself).
static ref::bytes nanowire_build(const eth& e, const vlan& v, const ipv4& ip, const udp& u, const someip& s,
                                 std::span<const std::byte> pay) {
  auto f = nanowire::make_frame(e, v, ip, u, s, nanowire::raw{pay});
  CHECK(f.has_value());
  return f ? *f : ref::bytes{};
}

template <class A>
static void fill(A& a) {
  for (auto& x : a) x = std::uint8_t(t::rnd(0, 255));
}

static ref::spec random_spec(std::size_t nvlan, bool v6) {
  ref::spec s;
  fill(s.dst);
  fill(s.src);
  for (std::size_t i = 0; i < nvlan; ++i)
    s.vlans.push_back({unsigned(t::rnd(0, 7)), unsigned(t::rnd(0, 1)), unsigned(t::rnd(0, 4095))});
  s.v6 = v6;
  s.dscp = unsigned(t::rnd(0, 63));
  s.ecn = unsigned(t::rnd(0, 3));
  s.ident = unsigned(t::rnd(0, 65535));
  s.flags = unsigned(t::rnd(0, 3));  // DF, MF (the reserved bit: test_patched_vs_reference)
  s.frag = 0;
  s.ttl = unsigned(t::rnd(1, 255));
  fill(s.src4);
  fill(s.dst4);
  s.tclass = unsigned(t::rnd(0, 255));
  s.flow = unsigned(t::rnd(0, 0xfffff));
  s.hop = unsigned(t::rnd(1, 255));
  fill(s.src6);
  fill(s.dst6);
  s.sport = unsigned(t::rnd(0, 65535));
  s.dport = unsigned(t::rnd(0, 65535));
  s.service = unsigned(t::rnd(0, 65535));
  s.method = unsigned(t::rnd(0, 65535));
  s.client = unsigned(t::rnd(0, 65535));
  s.session = unsigned(t::rnd(0, 65535));
  s.pver = unsigned(t::rnd(0, 255));
  s.iver = unsigned(t::rnd(0, 255));
  s.mtype = unsigned(t::rnd(0, 255)) & ~0x20u;
  s.rcode = unsigned(t::rnd(0, 255));
  s.payload = t::random_bytes(t::rnd(0, 3) == 0 ? t::rnd(0, 3) : t::rnd(0, 1400));
  return s;
}

// Stack values from a spec (constructor path).
static eth eth_of(const ref::spec& s) { return eth{.dst = s.dst, .src = s.src}; }
static vlan vlan_of(const ref::vlan_tag& v) {
  return vlan{.vid = std::uint16_t(v.vid), .pcp = std::uint8_t(v.pcp), .dei = v.dei != 0};
}
// nanowire::ipv4 has no field for the reserved ("evil") flag bit: the constructor path uses
// flags & 3, the patched path sets ipv4.reserved too.
static ipv4 ipv4_of(const ref::spec& s) {
  return ipv4{.src = s.src4,
              .dst = s.dst4,
              .ttl = std::uint8_t(s.ttl),
              .dscp = std::uint8_t(s.dscp),
              .ecn = std::uint8_t(s.ecn),
              .id = std::uint16_t(s.ident),
              .df = ((s.flags >> 1) & 1) != 0,
              .mf = (s.flags & 1) != 0};
}
static ipv6 ipv6_of(const ref::spec& s) {
  return ipv6{.src = s.src6,
              .dst = s.dst6,
              .traffic_class = std::uint8_t(s.tclass),
              .flow_label = std::uint32_t(s.flow),
              .hop_limit = std::uint8_t(s.hop)};
}
static udp udp_of(const ref::spec& s) { return udp{.src_port = std::uint16_t(s.sport), .dst_port = std::uint16_t(s.dport)}; }
static someip someip_of(const ref::spec& s) {
  return someip{.service_id = std::uint16_t(s.service),
                .method_id = std::uint16_t(s.method),
                .client_id = std::uint16_t(s.client),
                .session_id = std::uint16_t(s.session),
                .protocol_version = std::uint8_t(s.pver),
                .interface_version = std::uint8_t(s.iver),
                .message_type = std::uint8_t(s.mtype),
                .return_code = std::uint8_t(s.rcode)};
}

template <class T>
static ref::bytes write(T& t, std::span<const std::byte> pay) {
  ref::bytes out(t.frame_size(pay.size()) + 8);
  const std::size_t n = t.write(out, pay);
  out.resize(n);
  return out;
}

// Patch every field of a template to the spec's values through compile-time patch points.
template <class T>
static void patch_common(T& t, const ref::spec& s) {
  t.template set<"eth.dst">(s.dst);
  t.template set<"eth.src">(s.src);
  t.template set<"udp.src_port">(s.sport);
  t.template set<"udp.dst_port">(s.dport);
  t.template set<"someip.service_id">(s.service);
  t.template set<"someip.method_id">(s.method);
  t.template set<"someip.client_id">(s.client);
  t.template set<"someip.session_id">(s.session);
  t.template set<"someip.protocol_version">(s.pver);
  t.template set<"someip.interface_version">(s.iver);
  t.template set<"someip.message_type">(s.mtype);
  t.template set<"someip.return_code">(s.rcode);
}
template <class T>
static void patch_v4(T& t, const ref::spec& s) {
  t.template set<"ipv4.dscp">(s.dscp);
  t.template set<"ipv4.ecn">(s.ecn);
  t.template set<"ipv4.identification">(s.ident);
  t.template set<"ipv4.reserved">(s.flags >> 2);
  t.template set<"ipv4.df">((s.flags >> 1) & 1);
  t.template set<"ipv4.mf">(s.flags & 1);
  t.template set<"ipv4.ttl">(s.ttl);
  t.template set<"ipv4.src">(s.src4);
  t.template set<"ipv4.dst">(s.dst4);
}

static void test_constructed_vs_reference() {
  for (int it = 0; it < 300; ++it) {
    // 0, 1 and 2 VLAN tags; IPv4
    {
      auto s = random_spec(0, false);
      auto tm = nanocraft::compile(eth_of(s) / ipv4_of(s) / udp_of(s) / someip_of(s), s.payload.size());
      CHECK(tm.ok());
      const auto f = write(tm, s.payload);
      CHECK_BYTES(f, ref::build(s));
      nw::check_read(f, s);
    }
    {
      auto s = random_spec(1, false);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / ipv4_of(s) / udp_of(s) / someip_of(s));
      const auto f = write(tm, s.payload);
      CHECK_BYTES(f, ref::build(s));
      // nanowire's own builders agree, and so does nanowire's reader
      CHECK_BYTES(f, nanowire_build(eth_of(s), vlan_of(s.vlans[0]), ipv4_of(s), udp_of(s), someip_of(s), s.payload));
      nw::check_read(f, s);
    }
    {
      auto s = random_spec(2, false);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / vlan_of(s.vlans[1]) / ipv4_of(s) / udp_of(s) /
                                   someip_of(s));
      const auto f = write(tm, s.payload);
      CHECK_BYTES(f, ref::build(s));
      nw::check_read(f, s);
    }
    // IPv6
    {
      auto s = random_spec(1, true);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / ipv6_of(s) / udp_of(s) / someip_of(s));
      const auto f = write(tm, s.payload);
      CHECK_BYTES(f, ref::build(s));
      nw::check_read(f, s);
    }
  }
}

static void test_patched_vs_reference() {
  // One template per stack, patched to new random values every iteration (checksums incremental),
  // payload size changing every iteration (length chain incremental).
  auto t4 = nanocraft::compile(eth{} / vlan{} / ipv4{} / udp{} / someip{});
  auto t6 = nanocraft::compile(eth{} / vlan{} / vlan{} / ipv6{} / udp{} / someip{});
  const auto vid0 = t6.find("vlan[0].vid"), vid1 = t6.find("vlan[1].vid"), pcp1 = t6.find("vlan[1].pcp");
  CHECK(vid0 && vid1 && pcp1 && vid0 != vid1);
  CHECK(!t6.find("vlan[2].vid"));
  CHECK(!t6.find("nope.vid"));
  CHECK(!t6.find("vlan.nope"));
  for (int it = 0; it < 2000; ++it) {
    {
      auto s = random_spec(1, false);
      s.flags = unsigned(t::rnd(0, 7));
      patch_common(t4, s);
      patch_v4(t4, s);
      t4.set<"vlan.pcp">(s.vlans[0].pcp);
      t4.set<"vlan.dei">(s.vlans[0].dei);
      t4.set<"vlan.vid">(s.vlans[0].vid);
      const auto f = write(t4, s.payload);
      CHECK_BYTES(f, ref::build(s));
      nw::check_read(f, s);
      // header() is a valid frame with a zero payload of the current size
      auto z = s;
      z.payload.assign(s.payload.size(), std::byte{0});
      auto h = ref::build(z);
      CHECK_BYTES(std::span<const std::byte>(t4.header()), std::span<const std::byte>(h).first(t4.header_size));
    }
    {
      auto s = random_spec(2, true);
      patch_common(t6, s);
      // runtime handles for the v6 fields
      t6.set(t6.find("ipv6.traffic_class"), s.tclass);
      t6.set(t6.find("ipv6.flow_label"), s.flow);
      t6.set(t6.find("ipv6.hop_limit"), s.hop);
      t6.set(t6.find("ipv6.src"), std::as_bytes(std::span(s.src6)));
      t6.set(t6.find("ipv6.dst"), std::as_bytes(std::span(s.dst6)));
      t6.set(vid0, s.vlans[0].vid);
      t6.set(t6.find("vlan[0].pcp"), s.vlans[0].pcp);
      t6.set(t6.find("vlan[0].dei"), s.vlans[0].dei);
      t6.set(vid1, s.vlans[1].vid);
      t6.set(pcp1, s.vlans[1].pcp);
      t6.set(t6.find("vlan[1].dei"), s.vlans[1].dei);
      const auto f = write(t6, s.payload);
      CHECK_BYTES(f, ref::build(s));
      nw::check_read(f, s);
      CHECK_EQ(t6.get(vid1), s.vlans[1].vid);
      CHECK_EQ(t6.get<"ipv6.flow_label">(), s.flow);
    }
  }
}

static void test_patch_in_frame() {
  // write() the unchanged image, then patch the written frame (payload already in it: the UDP
  // checksum delta must still be right); the image must stay as it was.
  auto base = random_spec(1, false);
  auto tm = nanocraft::compile(eth_of(base) / vlan_of(base.vlans[0]) / ipv4_of(base) / udp_of(base) / someip_of(base));
  for (int it = 0; it < 2000; ++it) {
    auto s = base;
    s.payload = t::random_bytes(t::rnd(0, 700));
    if (it % 7 == 0) {
      tm.checksum("udp.checksum", csum_policy::zero);
      s.udp_csum = ref::spec::csum_zero;
    } else {
      tm.checksum("udp.checksum", csum_policy::compute);
    }
    auto f = write(tm, s.payload);
    auto n = random_spec(1, false);
    s.session = n.session;
    s.ident = n.ident;
    s.dst4 = n.dst4;
    s.sport = n.sport;
    s.vlans[0].pcp = n.vlans[0].pcp;
    s.ttl = n.ttl;
    tm.patch<"someip.session_id">(f, s.session);
    tm.patch<"ipv4.identification">(f, s.ident);
    tm.patch<"ipv4.dst">(f, s.dst4);
    tm.patch<"udp.src_port">(f, s.sport);
    tm.patch<"vlan.pcp">(f, s.vlans[0].pcp);
    tm.patch<"ipv4.ttl">(f, s.ttl);
    CHECK_BYTES(f, ref::build(s));
  }
  tm.checksum("udp.checksum", csum_policy::compute);
  base.payload.clear();
  CHECK_BYTES(write(tm, {}), ref::build(base));
}

static void test_policies() {
  auto s = random_spec(0, false);
  auto tm = nanocraft::compile(eth_of(s) / ipv4_of(s) / udp_of(s) / someip_of(s));
  CHECK(tm.checksum("udp.checksum", csum_policy::zero));
  CHECK(!tm.checksum("udp.length", csum_policy::zero));
  auto z = s;
  z.udp_csum = ref::spec::csum_zero;
  for (int i = 0; i < 50; ++i) {
    s.session = z.session = unsigned(t::rnd(0, 65535));
    s.payload = z.payload = t::random_bytes(t::rnd(0, 300));
    tm.set<"someip.session_id">(s.session);
    CHECK_BYTES(write(tm, z.payload), ref::build(z));
  }
  // offload: the folded pseudo-header sum, not complemented
  CHECK(tm.checksum("udp.checksum", csum_policy::offload));
  for (int i = 0; i < 50; ++i) {
    auto pay = t::random_bytes(t::rnd(0, 300));
    std::array<std::uint8_t, 4> a;
    fill(a);
    tm.set<"ipv4.src">(a);
    auto f = write(tm, pay);
    ref::bytes ps(f.begin() + 26, f.begin() + 34);
    ref::put8(ps, 0);
    ref::put8(ps, 17);
    ref::put16(ps, unsigned(8 + 16 + pay.size()));
    CHECK_EQ(ref::get16(f, 14 + 20 + 6), unsigned(ref::naive_sum(ps)));
    CHECK(ref::verify(f).ip_ok);
  }
  // keep: the layer's own value, untouched by patches (an explicit builder .checksum starts as keep)
  auto u = udp_of(s);
  u.checksum = 0xbeef;
  auto tk = nanocraft::compile(eth_of(s) / ipv4_of(s) / u / someip_of(s));
  CHECK(tk.checksum_policy(1) == csum_policy::keep);
  CHECK(tk.checksum_policy(0) == csum_policy::compute);
  CHECK_EQ(tk.get<"udp.checksum">(), 0xbeefu);
  CHECK(tk.checksum("udp.checksum", csum_policy::keep));
  tk.set<"someip.session_id">(77);
  auto f = write(tk, s.payload);
  CHECK_EQ(ref::get16(f, 14 + 20 + 6), 0xbeefu);
  // back to compute
  CHECK(tk.checksum("udp.checksum", csum_policy::compute));
  s.session = 77;
  CHECK_BYTES(write(tk, s.payload), ref::build(s));
  // ipv4 header checksum zero
  CHECK(tk.checksum("ipv4.checksum", csum_policy::zero));
  f = write(tk, s.payload);
  CHECK_EQ(ref::get16(f, 14 + 10), 0u);
  CHECK(ref::verify(f).udp_ok);
}

static void test_faults() {
  auto s = random_spec(0, false);
  s.payload = t::random_bytes(40);
  auto tm = nanocraft::compile(eth_of(s) / ipv4_of(s) / udp_of(s) / someip_of(s));
  const auto good = ref::build(s);
  CHECK(!tm.inject(nanocraft::faults{}.bad_checksum("udp.length")));
  CHECK(!tm.inject(nanocraft::faults{}.length_delta("nope.x", 1)));
  CHECK(tm.inject(nanocraft::faults{}.bad_checksum("ipv4.checksum")));
  auto f = write(tm, s.payload);
  auto v = ref::verify(f);
  CHECK(!v.ip_ok);
  CHECK(v.udp_ok);
  CHECK(tm.inject(nanocraft::faults{}.bad_checksum("udp.checksum")));
  v = ref::verify(write(tm, s.payload));
  CHECK(v.ip_ok);
  CHECK(!v.udp_ok);
  // a wrong UDP length with checksums consistent with it
  CHECK(tm.inject(nanocraft::faults{}.length_delta("udp.length", -4)));
  f = write(tm, s.payload);
  CHECK_EQ(ref::get16(f, 14 + 20 + 4), unsigned(8 + 16 + 40 - 4));
  {
    ref::bytes ps(f.begin() + 26, f.begin() + 34);
    ref::put8(ps, 0);
    ref::put8(ps, 17);
    ref::put16(ps, ref::get16(f, 14 + 20 + 4));  // the pseudo header repeats the (wrong) field
    ps.insert(ps.end(), f.begin() + 34, f.end());
    CHECK_EQ(unsigned(ref::naive_sum(ps)), 0xffffu);
  }
  CHECK(ref::verify(f).ip_ok);
  // IPv4 total length wrong, header checksum still right
  CHECK(tm.inject(nanocraft::faults{}.length_delta("ipv4.total_length", 6)));
  f = write(tm, s.payload);
  CHECK_EQ(ref::get16(f, 14 + 2), unsigned(20 + 8 + 16 + 40 + 6));
  CHECK_EQ(unsigned(ref::naive_sum(std::span(f).subspan(14, 20))), 0xffffu);
  // truncation, every 3rd frame
  CHECK(tm.inject(nanocraft::faults{}.truncate_by(5).every_nth(3)));
  for (int i = 1; i <= 9; ++i) {
    f = write(tm, s.payload);
    if (i % 3 == 0) {
      CHECK_EQ(f.size(), good.size() - 5);
      CHECK_BYTES(std::span<const std::byte>(f), std::span<const std::byte>(good).first(good.size() - 5));
    } else {
      CHECK_BYTES(f, good);
    }
  }
  tm.clear_faults();
  CHECK_BYTES(write(tm, s.payload), good);
}

static void test_padding_prepare_commit() {
  auto s = random_spec(0, false);
  s.payload = t::random_bytes(4);
  auto tm = nanocraft::compile(eth_of(s) / ipv4_of(s) / udp_of(s) / someip_of(s), {.payload_size = 0, .min_frame = 60});
  CHECK_EQ(tm.frame_size(4), std::size_t(62));
  CHECK_EQ(tm.frame_size(0), std::size_t(60));
  auto f = write(tm, std::span<const std::byte>(s.payload).first(0));
  auto s0 = s;
  s0.payload.clear();
  auto want = ref::build(s0);
  want.resize(60, std::byte{0});
  CHECK_BYTES(f, want);
  // prepare / commit: produce the payload in place
  ref::bytes buf(200);
  auto area = tm.prepare(buf, 100);
  CHECK_EQ(area.size(), std::size_t(100));
  s.payload = t::random_bytes(100);
  std::memcpy(area.data(), s.payload.data(), 100);
  const std::size_t n = tm.commit(buf, 100);
  buf.resize(n);
  CHECK_BYTES(buf, ref::build(s));
  // too small a destination
  ref::bytes tiny(10);
  CHECK_EQ(tm.write(tiny, s.payload), std::size_t(0));
}

static void test_frame_ref_and_matches() {
  auto shape = nanocraft::compile(eth{} / vlan{} / ipv4{} / udp{} / someip{});
  auto shape6 = nanocraft::compile(eth{} / vlan{} / ipv6{} / udp{} / someip{});
  for (int it = 0; it < 500; ++it) {
    auto s = random_spec(1, false);
    if (it % 5 == 0) s.udp_csum = ref::spec::csum_zero;
    auto f = ref::build(s);
    CHECK(shape.matches(f));
    CHECK(!shape6.matches(f));
    nanocraft::frame_ref<eth, vlan, ipv4, udp, someip> r(shape, f);
    auto n = random_spec(1, false);
    s.dst4 = n.dst4;
    s.ttl = n.ttl;
    s.ident = n.ident;
    s.session = n.session;
    s.sport = n.sport;
    s.vlans[0].vid = n.vlans[0].vid;
    r.set<"ipv4.dst">(s.dst4);
    r.set<"ipv4.ttl">(s.ttl);
    r.set<"ipv4.identification">(s.ident);
    r.set<"someip.session_id">(s.session);
    r.set<"udp.src_port">(s.sport);
    r.set<"vlan.vid">(s.vlans[0].vid);
    CHECK_BYTES(f, ref::build(s));
    CHECK_EQ(r.get<"ipv4.ttl">(), std::uint64_t(s.ttl));
  }
  auto s6 = random_spec(1, true);
  auto f6 = ref::build(s6);
  CHECK(shape6.matches(f6));
  CHECK(!shape.matches(f6));
  CHECK(!shape.matches(std::span<const std::byte>(f6).first(20)));
}

// ---- a test-only layer exercising lsb0 bit fields and little-endian fields
struct reg {
  nm::ubits<3, nm::bit_order::lsb0> a{};
  nm::ubits<5, nm::bit_order::lsb0> b{};
  nm::le<std::uint16_t> c{};
  nm::ubits<4> d{};
  nm::ubits<12> e{};
  nm::le<std::uint32_t> f{};
  std::uint8_t g = 0;
  nm::ubits<28> h{};
  nm::ubits<4> i{};
};
NANOM_DESCRIBE(reg, a, b, c, d, e, f, g, h, i);
template <>
struct nanocraft::layer_info<reg> {
  static constexpr std::string_view name = "reg";
};

static void test_generic_field_kinds() {
  auto tm = nanocraft::compile(nanocraft::stack(reg{}));
  for (int it = 0; it < 2000; ++it) {
    reg r{};
    r.a.v = std::uint8_t(t::rnd(0, 7));
    r.b.v = std::uint8_t(t::rnd(0, 31));
    r.c = std::uint16_t(t::rnd(0, 65535));
    r.d.v = std::uint8_t(t::rnd(0, 15));
    r.e.v = std::uint16_t(t::rnd(0, 4095));
    r.f = std::uint32_t(t::rnd(0, 0xffffffff));
    r.g = std::uint8_t(t::rnd(0, 255));
    r.h.v = std::uint32_t(t::rnd(0, (1u << 28) - 1));
    r.i.v = std::uint8_t(t::rnd(0, 15));
    tm.set<"reg.a">(r.a.v);
    tm.set<"reg.b">(r.b.v);
    tm.set<"reg.c">(std::uint16_t(r.c));
    tm.set<"reg.d">(r.d.v);
    tm.set<"reg.e">(r.e.v);
    tm.set<"reg.f">(std::uint32_t(r.f));
    tm.set<"reg.g">(r.g);
    tm.set<"reg.h">(r.h.v);
    tm.set<"reg.i">(r.i.v);
    auto want = nm::to_bytes(r, {}, std::endian::big);
    CHECK(want.has_value());
    CHECK_BYTES(std::span<const std::byte>(tm.header()), std::span<const std::byte>(*want));
    CHECK_EQ(tm.get<"reg.h">(), std::uint64_t(r.h.v));
    CHECK_EQ(tm.get<"reg.c">(), std::uint64_t(std::uint16_t(r.c)));
  }
  // values are masked to the field width
  tm.set<"reg.a">(0xff);
  CHECK_EQ(tm.get<"reg.a">(), 7u);
  CHECK_EQ(tm.get<"reg.b">(), tm.get(tm.find("reg.b")));
  // compile-time resolution
  static_assert(decltype(tm)::id<"reg.h">().index == 7);
  static_assert(decltype(tm)::find("reg.i").index == 8);
  static_assert(!decltype(tm)::find("reg.z").valid());
}

static void test_tp_link() {
  // someip followed by someip_tp: the TP flag is set in message_type by compile()
  auto tm = nanocraft::compile(eth{} / ipv4{} / udp{} / someip{.message_type = 0x02} / someip_tp{});
  CHECK_EQ(tm.get<"someip.message_type">(), 0x22u);
  CHECK_EQ(tm.get<"eth.ethertype">(), 0x0800u);
  CHECK_EQ(tm.get<"ipv4.protocol">(), 17u);
  CHECK_EQ(tm.get<"someip.length">(), 12u);
  // explicit next-protocol values are kept
  auto tx = nanocraft::compile(eth{.type = 0x88b5} / ipv4{.protocol = 253} / udp{} / someip{});
  CHECK_EQ(tx.get<"eth.ethertype">(), 0x88b5u);
  CHECK_EQ(tx.get<"ipv4.protocol">(), 253u);
}

static void test_udp_vs_tcp_zero_checksum() {
  // UDP over IPv4 and IPv6: computed 0x0000 must map to 0xFFFF across EVERY checksum path.
  auto check_udp = [](auto&& tm, std::size_t udp_off) {
    CHECK(tm.ok());
    // 1. set<"udp.src_port"> (patch_ct) hitting 0x0000 -> 0xFFFF
    tm.template set<"udp.src_port">(0);
    tm.template set<"udp.dst_port">(1);
    const std::uint16_t c0 = std::uint16_t(tm.template get<"udp.checksum">());
    CHECK(c0 != 0 && c0 != 0xffff);
    tm.template set<"udp.src_port">(c0);
    CHECK_EQ(tm.template get<"udp.checksum">(), 0xffffu);
    // Subsequent incremental update starting from mapped 0xFFFF must remain exact.
    tm.template set<"udp.src_port">(std::uint16_t(c0 ^ 0x1234));
    {
      ref::bytes f(tm.frame_size(0));
      CHECK_EQ(tm.write(f, {}), tm.header_size);
      // Re-verify by recomputing from scratch via checksum() policy toggle.
      const auto inc = tm.template get<"udp.checksum">();
      CHECK(tm.checksum("udp.checksum", nanocraft::csum_policy::compute));
      CHECK_EQ(inc, tm.template get<"udp.checksum">());
    }
    // 2. runtime set(field_id, ...) (patch_with) hitting 0x0000 -> 0xFFFF
    tm.template set<"udp.src_port">(0);
    const auto sp_id = tm.find("udp.src_port");
    tm.set(sp_id, c0);
    CHECK_EQ(tm.template get<"udp.checksum">(), 0xffffu);
    // 3. recompute() hitting 0x0000 -> 0xFFFF
    CHECK(tm.checksum("udp.checksum", nanocraft::csum_policy::compute));
    CHECK_EQ(tm.template get<"udp.checksum">(), 0xffffu);
    // 4. patch<"udp.src_port">(frame, ...) hitting 0x0000 -> 0xFFFF
    tm.template set<"udp.src_port">(0);
    ref::bytes f(tm.frame_size(0));
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    tm.template patch<"udp.src_port">(f, c0);
    CHECK_EQ(ref::get16(f, udp_off + 6), 0xffffu);
    // 5. frame_ref::set<"udp.src_port"> hitting 0x0000 -> 0xFFFF
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    nanocraft::frame_ref rf(tm, f);
    rf.template set<"udp.src_port">(c0);
    CHECK_EQ(ref::get16(f, udp_off + 6), 0xffffu);
    // 6. commit() with payload hitting 0x0000 -> 0xFFFF
    tm.payload_size(2);
    tm.template set<"udp.src_port">(0);
    const std::uint16_t c2 = std::uint16_t(tm.template get<"udp.checksum">());
    const std::array<std::byte, 2> pay{std::byte(c2 >> 8), std::byte(c2 & 0xff)};
    ref::bytes f2(tm.frame_size(2));
    CHECK_EQ(tm.write(f2, pay), tm.header_size + 2);
    CHECK_EQ(ref::get16(f2, udp_off + 6), 0xffffu);
  };
  check_udp(nanocraft::compile(eth{} / ipv4{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}} / udp{}), 14 + 20);
  check_udp(nanocraft::compile(eth{} / ipv6{.src = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                                            .dst = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}} /
                               udp{}),
            14 + 40);

  // TCP over IPv4 and IPv6: computed 0x0000 MUST stay 0x0000 (NOT mapped to 0xFFFF).
  auto check_tcp = [](auto&& tm, std::size_t tcp_off) {
    CHECK(tm.ok());
    // 1. set<"tcp.src_port"> (patch_ct) hitting 0x0000 stays 0x0000
    tm.template set<"tcp.src_port">(0);
    tm.template set<"tcp.dst_port">(1);
    const std::uint16_t c0 = std::uint16_t(tm.template get<"tcp.checksum">());
    CHECK(c0 != 0 && c0 != 0xffff);
    tm.template set<"tcp.src_port">(c0);
    CHECK_EQ(tm.template get<"tcp.checksum">(), 0x0000u);
    // 2. runtime set(field_id, ...) (patch_with) hitting 0x0000 stays 0x0000
    tm.template set<"tcp.src_port">(0);
    tm.set(tm.find("tcp.src_port"), c0);
    CHECK_EQ(tm.template get<"tcp.checksum">(), 0x0000u);
    // 3. recompute() hitting 0x0000 stays 0x0000
    CHECK(tm.checksum("tcp.checksum", nanocraft::csum_policy::compute));
    CHECK_EQ(tm.template get<"tcp.checksum">(), 0x0000u);
    // 4. patch<"tcp.src_port">(frame, ...) hitting 0x0000 stays 0x0000
    tm.template set<"tcp.src_port">(0);
    ref::bytes f(tm.frame_size(0));
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    tm.template patch<"tcp.src_port">(f, c0);
    CHECK_EQ(ref::get16(f, tcp_off + 16), 0x0000u);
    // 5. frame_ref::set<"tcp.src_port"> hitting 0x0000 stays 0x0000 AND still updates FROM 0x0000
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    nanocraft::frame_ref rf(tm, f);
    rf.template set<"tcp.src_port">(c0);
    CHECK_EQ(ref::get16(f, tcp_off + 16), 0x0000u);
    rf.template set<"tcp.src_port">(0);
    CHECK_EQ(ref::get16(f, tcp_off + 16), unsigned(c0));
    // 6. commit() with payload hitting 0x0000 stays 0x0000
    tm.payload_size(2);
    tm.template set<"tcp.src_port">(0);
    const std::uint16_t c2 = std::uint16_t(tm.template get<"tcp.checksum">());
    const std::array<std::byte, 2> pay{std::byte(c2 >> 8), std::byte(c2 & 0xff)};
    ref::bytes f2(tm.frame_size(2));
    CHECK_EQ(tm.write(f2, pay), tm.header_size + 2);
    CHECK_EQ(ref::get16(f2, tcp_off + 16), 0x0000u);
    // 7. payload_size() incremental update hitting 0x0000 stays 0x0000
    tm.payload_size(0);
    tm.template set<"tcp.src_port">(nanocraft::csum::add(c0, 0xfffbu));  // +4 for payload_size(4) -> hits 0x0000
    tm.payload_size(4);
    CHECK_EQ(tm.template get<"tcp.checksum">(), 0x0000u);
  };
  check_tcp(nanocraft::compile(eth{} / ipv4{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}} / tcp{}), 14 + 20);
  check_tcp(nanocraft::compile(eth{} / ipv6{.src = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                                            .dst = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}} /
                               tcp{}),
            14 + 40);
}

static void test_audit_hardening() {
  // 1. !ok() template rejected by write(), prepare(), commit()
  auto bad = nanocraft::compile(eth{} / ipv4{.total_length = 99} / udp{});
  CHECK(!bad.ok());
  ref::bytes buf(128);
  std::array<std::byte, 8> pay{};
  CHECK(bad.prepare(buf, 8).empty());
  CHECK_EQ(bad.write(buf, pay), std::size_t(0));
  CHECK_EQ(bad.commit(buf, 8), std::size_t(0));

  // 2. bad_checksum fault on UDPv4 never produces 0x0000 ("no checksum")
  {
    auto tm = nanocraft::compile(eth{} / ipv4{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}} / udp{});
    tm.set<"udp.src_port">(0);
    const std::uint16_t c0 = std::uint16_t(tm.get<"udp.checksum">());
    // Set src_port so valid checksum becomes 0x5aa5 (which XOR 0x5aa5 would be 0x0000).
    tm.set<"udp.src_port">(nanocraft::csum::add(c0, 0xa55au));
    CHECK_EQ(tm.get<"udp.checksum">(), 0x5aa5u);
    CHECK(tm.inject(nanocraft::faults{}.bad_checksum("udp.checksum")));
    ref::bytes f(tm.frame_size(0));
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    const std::uint16_t corrupted = ref::get16(f, 14 + 20 + 6);
    CHECK(corrupted != 0x5aa5u);
    CHECK(corrupted != 0x0000u);
    CHECK_EQ(corrupted, 0x0001u);
  }

  // 3. faults overflow and empty field name rejected by inject()
  {
    auto tm = nanocraft::compile(eth{} / ipv4{} / udp{});
    nanocraft::faults f;
    for (int i = 0; i < 9; ++i) f.bad_checksum("ipv4.checksum");
    CHECK(f.overflow);
    CHECK(!tm.inject(f));
    nanocraft::faults f2;
    for (int i = 0; i < 9; ++i) f2.length_delta("udp.length", 1);
    CHECK(f2.overflow);
    CHECK(!tm.inject(f2));
    CHECK(!tm.inject(nanocraft::faults{}.bad_checksum("")));
    CHECK(!tm.inject(nanocraft::faults{}.length_delta("", 1)));
  }

  // 4. Empty brackets [] rejected by find() and layer()
  {
    auto tm = nanocraft::compile(eth{} / vlan{} / ipv4{} / udp{});
    using M = decltype(tm)::meta;
    static_assert(!decltype(tm)::find("vlan[].vid").valid());
    static_assert(M::layer("vlan[]") == nanocraft::detail::npos);
    CHECK(!tm.find("vlan[].vid").valid());
    CHECK_EQ(M::layer("vlan[]"), nanocraft::detail::npos);
  }

  // 5. Dynamic span exact-size matching and zero-length span memcpy guard
  {
    auto tm = nanocraft::compile(eth{} / ipv4{} / udp{});
    std::array<std::byte, 6> mac{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}, std::byte{5}, std::byte{6}};
    std::span<const std::byte> dyn_mac(mac);
    tm.set<"eth.dst">(dyn_mac);
    ref::bytes f(tm.frame_size(0));
    CHECK_EQ(tm.write(f, {}), tm.header_size);
    CHECK_BYTES(std::span<const std::byte>(f).first(6), mac);
    tm.patch<"eth.src">(f, dyn_mac);
    CHECK_BYTES(std::span<const std::byte>(f).subspan(6, 6), mac);
    // Zero-length span with nullptr data must not trigger memcpy UB
    std::span<const std::byte> null_empty(static_cast<const std::byte*>(nullptr), 0);
    tm.set(tm.find("eth.dst"), null_empty);
    nanocraft::frame_ref rf(tm, f);
    rf.set(tm.find("eth.dst"), null_empty);
  }

  // 6. matches() rejects IPv4 non-zero frag_offset and TCP options (data_offset != 5)
  {
    auto udp_shape = nanocraft::compile(eth{} / ipv4{} / udp{});
    ref::bytes f(udp_shape.frame_size(4));
    std::array<std::byte, 4> p{};
    CHECK_EQ(udp_shape.write(f, p), udp_shape.header_size + 4);
    CHECK(udp_shape.matches(f));
    // Set IPv4 frag_offset = 1
    udp_shape.patch<"ipv4.frag_offset">(f, 1);
    CHECK(!udp_shape.matches(f));

    auto tcp_shape = nanocraft::compile(eth{} / ipv4{} / tcp{});
    ref::bytes ft(tcp_shape.frame_size(4));
    CHECK_EQ(tcp_shape.write(ft, p), tcp_shape.header_size + 4);
    CHECK(tcp_shape.matches(ft));
    // Set TCP data_offset = 6 (24-byte TCP header with options)
    tcp_shape.patch<"tcp.data_offset">(ft, 6);
    CHECK(!tcp_shape.matches(ft));
  }
}

int main() {
  test_constructed_vs_reference();
  test_patched_vs_reference();
  test_patch_in_frame();
  test_policies();
  test_faults();
  test_padding_prepare_commit();
  test_frame_ref_and_matches();
  test_generic_field_kinds();
  test_tp_link();
  test_udp_vs_tcp_zero_checksum();
  test_audit_hardening();
  return t::done("test_template");
}
