// SPDX-License-Identifier: Apache-2.0
// Frame templates vs two independent builders: the hand-written RFC builder (reference.hpp) and
// nanom::emit with computed<> fields; for many random field values, payload sizes and stacks.
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"
#include "reference.hpp"

#include <nanom/emit.hpp>

using namespace nanocraft::proto;
namespace nm = nanom;
using nanocraft::csum_policy;

// ---- nanom emit oracle: lengths and the IPv4 checksum via nanom's own computed<> mechanism
template <>
struct nm::computed<ipv4> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_length">([](const ipv4&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h, const nm::emit_ctx&) { return ref::naive_csum(h); })};
};
template <>
struct nm::computed<udp> {
  static constexpr auto fields =
      std::tuple{nm::calc<"length">([](const udp&, const nm::emit_ctx& c) { return 8 + c.payload.size(); })};
};
template <>
struct nm::computed<someip> {
  static constexpr auto fields =
      std::tuple{nm::calc<"length">([](const someip&, const nm::emit_ctx& c) { return 8 + c.payload.size(); })};
};

static ref::bytes nanom_build(const eth& e, const vlan& v, const ipv4& ip, const udp& u, const someip& s,
                              std::span<const std::byte> pay) {
  std::vector<std::byte> buf(2048);
  std::byte* end = buf.data() + buf.size();
  std::byte* p = end - pay.size();
  if (!pay.empty()) std::memcpy(p, pay.data(), pay.size());
  p -= 16;
  (void)nm::emit(s, {p, 16}, nm::emit_ctx{{p + 16, pay.size()}}, std::endian::big);
  p -= 8;
  (void)nm::emit(u, {p, 8}, nm::emit_ctx{{p + 8, std::size_t(end - p - 8)}}, std::endian::big);
  // UDP checksum is not expressible in computed<> (needs the IP pseudo header): compute here.
  {
    ref::bytes ps;
    for (auto b : ip.src) ref::put8(ps, b);
    for (auto b : ip.dst) ref::put8(ps, b);
    ref::put8(ps, 0);
    ref::put8(ps, 17);
    ref::put16(ps, unsigned(end - p));
    ps.insert(ps.end(), p, end);
    unsigned c = ref::naive_csum(ps);
    if (c == 0) c = 0xffff;
    p[6] = std::byte(c >> 8);
    p[7] = std::byte(c);
  }
  p -= 20;
  (void)nm::emit(ip, {p, 20}, nm::emit_ctx{{p + 20, std::size_t(end - p - 20)}}, std::endian::big);
  p -= 4;
  (void)nm::emit(v, {p, 4}, {}, std::endian::big);
  p -= 14;
  (void)nm::emit(e, {p, 14}, {}, std::endian::big);
  return ref::bytes(p, end);
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
  s.flags = unsigned(t::rnd(0, 7));
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
  vlan x{};
  x.pcp.v = std::uint8_t(v.pcp);
  x.dei.v = std::uint8_t(v.dei);
  x.vid.v = std::uint16_t(v.vid);
  return x;
}
static ipv4 ipv4_of(const ref::spec& s) {
  ipv4 x{};
  x.dscp.v = std::uint8_t(s.dscp);
  x.ecn.v = std::uint8_t(s.ecn);
  x.identification = std::uint16_t(s.ident);
  x.flags.v = std::uint8_t(s.flags);
  x.ttl = std::uint8_t(s.ttl);
  x.src = s.src4;
  x.dst = s.dst4;
  return x;
}
static ipv6 ipv6_of(const ref::spec& s) {
  ipv6 x{};
  x.traffic_class.v = std::uint8_t(s.tclass);
  x.flow_label.v = std::uint32_t(s.flow);
  x.hop_limit = std::uint8_t(s.hop);
  x.src = s.src6;
  x.dst = s.dst6;
  return x;
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
  t.template set<"ipv4.flags">(s.flags);
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
      CHECK_BYTES(write(tm, s.payload), ref::build(s));
    }
    {
      auto s = random_spec(1, false);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / ipv4_of(s) / udp_of(s) / someip_of(s));
      CHECK_BYTES(write(tm, s.payload), ref::build(s));
      // the nanom emit oracle agrees too
      auto e = eth_of(s);
      e.ethertype = 0x8100;
      auto v = vlan_of(s.vlans[0]);
      v.ethertype = 0x0800;
      auto ip = ipv4_of(s);
      ip.protocol = 17;
      CHECK_BYTES(write(tm, s.payload), nanom_build(e, v, ip, udp_of(s), someip_of(s), s.payload));
    }
    {
      auto s = random_spec(2, false);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / vlan_of(s.vlans[1]) / ipv4_of(s) / udp_of(s) /
                                   someip_of(s));
      CHECK_BYTES(write(tm, s.payload), ref::build(s));
    }
    // IPv6
    {
      auto s = random_spec(1, true);
      auto tm = nanocraft::compile(eth_of(s) / vlan_of(s.vlans[0]) / ipv6_of(s) / udp_of(s) / someip_of(s));
      CHECK_BYTES(write(tm, s.payload), ref::build(s));
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
      patch_common(t4, s);
      patch_v4(t4, s);
      t4.set<"vlan.pcp">(s.vlans[0].pcp);
      t4.set<"vlan.dei">(s.vlans[0].dei);
      t4.set<"vlan.vid">(s.vlans[0].vid);
      CHECK_BYTES(write(t4, s.payload), ref::build(s));
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
      CHECK_BYTES(write(t6, s.payload), ref::build(s));
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
  // keep: the layer's own value, untouched by patches
  auto u = udp_of(s);
  u.checksum = 0xbeef;
  auto tk = nanocraft::compile(eth_of(s) / ipv4_of(s) / u / someip_of(s));
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
  auto tx = nanocraft::compile(eth{.ethertype = 0x88b5} / ipv4{.protocol = 253} / udp{} / someip{});
  CHECK_EQ(tx.get<"eth.ethertype">(), 0x88b5u);
  CHECK_EQ(tx.get<"ipv4.protocol">(), 253u);
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
  return t::done("test_template");
}
