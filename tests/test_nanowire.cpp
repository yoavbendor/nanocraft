// SPDX-License-Identifier: Apache-2.0
// nanowire's protocols as template layers (nanowire_layers.hpp): every layer nanowire offers that
// templates support, checked three ways — byte for byte against nanowire's own builders
// (nanowire::make_frame), read back with nanowire's views (packet::parse, sd_view, soad_pdus,
// ipdum_pdus), and with checksums verified by nanowire — while fields are patched and payload sizes
// change. Plus the stacking syntax, link rules and the layers compile() refuses.
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"
#include "nw_check.hpp"

#include <nanowire/nanowire.hpp>

#include <cstdio>
#include <string>

namespace nw_ = nanowire;
using nanocraft::csum_policy;

// A sample of the crafted frames, written to nanocraft_nanowire.pcap for the python oracle (scapy
// recomputes every IPv4 / UDP / TCP checksum and length over IPv4 and IPv6).
static std::vector<ref::bytes> g_sample;
static void sample(const ref::bytes& f) {
  if (g_sample.size() < 2000) g_sample.push_back(f);
}

template <class T>
static ref::bytes write(T& t, std::span<const std::byte> pay) {
  ref::bytes out(t.frame_size(pay.size()) + 8);
  out.resize(t.write(out, pay));
  return out;
}
template <class... L>
static ref::bytes nw_frame(const L&... l) {
  auto f = nw_::make_frame(l...);
  CHECK(f.has_value());
  return f ? *f : ref::bytes{};
}

static void test_stacking_syntax() {
  // operator/ on nanowire's own types, no using-directive (ADL)
  auto t = nanocraft::compile(nw_::eth{.dst = nw_::mac("02:00:00:00:00:02")} / nw_::vlan{.vid = 7} /
                              nw_::ipv4{.src = nw_::ip4("10.0.0.1"), .dst = nw_::ip4("10.0.0.2")} /
                              nw_::udp{.src_port = 1, .dst_port = 2} / nw_::someip{.service_id = 0x1234});
  CHECK(t.ok());
  CHECK_EQ(t.get<"eth.ethertype">(), 0x8100u);
  CHECK_EQ(t.get<"vlan.ethertype">(), 0x0800u);
  CHECK_EQ(t.get<"ipv4.protocol">(), 17u);
  // nanocraft::proto names the same types
  static_assert(std::is_same_v<nanocraft::proto::ipv4, nw_::ipv4>);
  static_assert(std::is_same_v<nanocraft::wire_t<nw_::udp>, nw_::wire::udp_hdr>);
  // patch points sit where nanowire's wire structs say
  static_assert(decltype(t)::describe(decltype(t)::id<"someip.session_id">()).off ==
                14 + 4 + 20 + 8 + nw_::field_offset_v<nw_::wire::someip_hdr, "session_id">);
  static_assert(decltype(t)::describe(decltype(t)::id<"ipv4.mf">()).off == 14 + 4 + nw_::field_offset_v<nw_::wire::ipv4_hdr, "mf">);
  // QinQ: S-tag (0x88A8) then C-tag
  auto q = nanocraft::compile(nw_::eth{} / nw_::vlan{.vid = 100, .tpid = nw_::ethertype::qinq} / nw_::vlan{.vid = 7} /
                              nw_::ipv6{} / nw_::udp{});
  CHECK_EQ(q.get<"eth.ethertype">(), 0x88a8u);
  CHECK_EQ(q.get<"vlan[0].ethertype">(), 0x8100u);
  CHECK_EQ(q.get<"vlan[1].ethertype">(), 0x86ddu);
  CHECK_EQ(q.get<"ipv6.next_header">(), 17u);
  const auto pay = t::random_bytes(33);
  const auto f = write(q, pay);
  sample(f);
  CHECK_BYTES(f, nw_frame(nw_::eth{}, nw_::vlan{.vid = 100, .tpid = nw_::ethertype::qinq}, nw_::vlan{.vid = 7},
                          nw_::ipv6{}, nw_::udp{}, nw_::raw{pay}));
  const auto p = nw_::packet::parse(f);
  CHECK_EQ(p.vlan_count(), std::size_t(2));
  CHECK(p.udp().has_value() && nw::l4_ok(p));
  // someip_tp: offset in bytes in the builder, 16-byte units on the wire
  auto tp = nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::udp{} / nw_::someip{} / nw_::someip_tp{.offset = 32, .more = true});
  CHECK(tp.ok());
  CHECK_EQ(tp.get<"someip_tp.offset">(), 2u);
  CHECK_EQ(tp.get<"someip_tp.more">(), 1u);
  CHECK_EQ(tp.get<"someip.message_type">(), 0x22u);
}

static void test_refused() {
  const std::array<std::byte, 4> opt{std::byte{1}, std::byte{1}, std::byte{1}, std::byte{1}};
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{.options = opt} / nw_::udp{}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::tcp{.options = opt}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::udp{} / nw_::someip{.tp = nw_::someip_tp{}}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{.total_length = 99} / nw_::udp{}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv6{.payload_length = 9} / nw_::udp{}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::udp{.length = 9}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::udp{} / nw_::someip{.length = 9}).ok());
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::vlan{.pcp = 9} / nw_::ipv4{}).ok());  // the builder refuses
  CHECK(!nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::udp{} / nw_::someip{} / nw_::someip_tp{.offset = 5}).ok());
  CHECK(!nanocraft::compile(nanocraft::stack(nanocraft::proto::sd_header{}, nw_::sd_entry::subscribe(1, 1, 1, 1))).ok());
  CHECK(!nanocraft::compile(nanocraft::stack(nw_::sd_option::ipv6_endpoint({}, 17, 1))).ok());
  auto e = nanocraft::compile(nw_::eth{} / nw_::ipv4{.total_length = 99} / nw_::udp{});
  CHECK(!e.error().empty());
}

// ---- TCP (fixed 20-byte header): the pseudo-header length follows the payload size
static void test_tcp() {
  for (int v6 = 0; v6 < 2; ++v6) {
    nw_::tcp th{.src_port = 40000, .dst_port = 80, .seq = 1, .ack = 2, .flags = nw_::tcp_flag::ack | nw_::tcp_flag::psh};
    nw_::ipv4 i4{.src = nw_::ip4("192.168.0.1"), .dst = nw_::ip4("192.168.0.2")};
    nw_::ipv6 i6{.src = nw_::ip6("fd00::1"), .dst = nw_::ip6("fd00::2")};
    auto run = [&](auto&& tm, auto&& l3) {
      CHECK(tm.ok());
      CHECK_EQ(tm.template get<"tcp.data_offset">(), 5u);
      for (int it = 0; it < 300; ++it) {
        const auto pay = t::random_bytes(t::rnd(0, 3) == 0 ? t::rnd(0, 3) : t::rnd(0, 1400));
        auto x = th;
        x.seq = std::uint32_t(t::rnd(0, 0xffffffff));
        x.ack = std::uint32_t(t::rnd(0, 0xffffffff));
        x.flags = std::uint16_t(t::rnd(0, 0x1ff));
        x.window = std::uint16_t(t::rnd(0, 0xffff));
        x.urgent = std::uint16_t(t::rnd(0, 0xffff));
        tm.template set<"tcp.seq">(x.seq);
        tm.template set<"tcp.ack">(x.ack);
        tm.template set<"tcp.flags">(x.flags);
        tm.template set<"tcp.window">(x.window);
        tm.template set<"tcp.urgent">(x.urgent);
        const auto f = write(tm, pay);
        if (it % 10 == 0) sample(f);
        CHECK_BYTES(f, nw_frame(nw_::eth{}, l3, x, nw_::raw{pay}));
        const auto p = nw_::packet::parse(f);
        const auto tv = p.tcp();
        CHECK(tv.has_value());
        if (!tv) continue;
        CHECK_EQ(tv->seq(), x.seq);
        CHECK_EQ(tv->ack(), x.ack);
        CHECK_EQ(tv->flags(), x.flags);
        CHECK_EQ(tv->window(), x.window);
        CHECK(nw::l4_ok(p));
        CHECK_BYTES(p.payload(), std::span<const std::byte>(pay));
      }
      // offload: the folded pseudo-header sum follows the payload size too
      CHECK(tm.checksum("tcp.checksum", csum_policy::offload));
      for (int it = 0; it < 50; ++it) {
        const auto pay = t::random_bytes(t::rnd(0, 1400));
        const auto f = write(tm, pay);
        const auto p = nw_::packet::parse(f);
        const std::size_t l4 = p.l4_offset();
        const auto sum = nw_::detail::pseudo_header_sum(p.l3_bytes(), 6, f.size() - l4);
        std::uint64_t s = sum;
        while (s >> 16) s = (s & 0xffff) + (s >> 16);
        CHECK_EQ(unsigned(ref::get16(f, l4 + 16)), unsigned(s));
      }
      CHECK(tm.checksum("tcp.checksum", csum_policy::compute));
      const auto f = write(tm, {});
      CHECK(nw::l4_ok(nw_::packet::parse(f)));
    };
    if (v6) run(nanocraft::compile(nw_::eth{} / i6 / th), i6);
    else run(nanocraft::compile(nw_::eth{} / i4 / th), i4);
  }
  // explicit checksum: kept verbatim
  auto k = nanocraft::compile(nw_::eth{} / nw_::ipv4{} / nw_::tcp{.checksum = 0x1234});
  CHECK(k.checksum_policy(1) == csum_policy::keep);
  const auto f = write(k, t::random_bytes(10));
  CHECK_EQ(ref::get16(f, 14 + 20 + 16), 0x1234u);
}

// ---- segmentation with TCP in the replicated headers (SOME/IP-TP over TCP): per-segment pseudo
// header length; and TCP in the data stream (IPv4 fragments of a TCP segment)
static void test_tcp_segments() {
  using namespace nanocraft::proto;
  auto tm = nanocraft::compile(eth{} / ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")} /
                               tcp{.src_port = 30509, .dst_port = 30509} / someip{.service_id = 0x77} / someip_tp{});
  nanocraft::segmenter seg(tm, someip_tp_segments(1000));
  const auto msg = t::random_bytes(5000);
  std::size_t off = 0, n = 0;
  seg.run(msg, [&](const nanocraft::gather& g) {
    ref::bytes f(g.size());
    g.copy_to(f);
    const auto p = nw_::packet::parse(f);
    CHECK(p.tcp().has_value() && nw::l4_ok(p));
    const auto m = p.someip();
    CHECK(m && m->tp() && m->tp()->offset_bytes() == off && !m->truncated());
    if (m && m->tp()) off += m->tp()->segment().size();
    if (n++ % 2 == 0) sample(f);
  });
  CHECK_EQ(off, msg.size());
  auto tf = nanocraft::compile(eth{} / ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2"), .id = 9} /
                               tcp{.src_port = 1, .dst_port = 2});
  nanocraft::segmenter fr(tf, ipv4_fragments(576));
  nanowire::ipv4_reassembler ra(nw::roomy(nanowire::ip_reassembly_defaults()));
  std::vector<ref::bytes> frames;
  frames.reserve(fr.count(msg.size()));
  bool done = false;
  fr.run(msg, [&](const nanocraft::gather& g) {
    frames.emplace_back(g.size());
    g.copy_to(frames.back());
    const auto r = nanowire::feed(ra, nanowire::packet::parse(frames.back()), 0);
    if (r.complete()) {
      done = true;
      const auto dg = nw::join(r);
      CHECK(nanowire::l4_checksum_ok(std::span<const std::byte>(frames.front()).subspan(14, 20), nanowire::ip_proto::tcp, dg));
      CHECK_BYTES(std::span<const std::byte>(dg).subspan(20), std::span<const std::byte>(msg));
    }
  });
  CHECK(done);
}

// ---- AUTOSAR: PDU-over-IP header + IpduM contained-PDU header
static void test_autosar() {
  const nw_::ipv4 ip{.src = nw_::ip4("10.1.0.1"), .dst = nw_::ip4("10.1.0.2")};
  const nw_::udp u{.src_port = 42000, .dst_port = 42000};
  auto ts = nanocraft::compile(nw_::eth{} / ip / u / nw_::soad_pdu_header{.id = 0x300} / nanocraft::proto::ipdum_short{.id = 0x123});
  auto tl = nanocraft::compile(nw_::eth{} / ip / u / nw_::soad_pdu_header{.id = 0x301} / nanocraft::proto::ipdum_long{.id = 0xabcdef01});
  CHECK(ts.ok() && tl.ok());
  for (int it = 0; it < 300; ++it) {
    const auto data = t::random_bytes(t::rnd(0, 255));
    const auto id = std::uint32_t(t::rnd(1, 0xffffff));
    ts.set<"ipdum.id">(id);
    const auto f = write(ts, data);
    if (it % 10 == 0) sample(f);
    const nw_::pdu contained{id, nw_::bytes(data)};
    const nw_::ipdum_container c{.config = {}, .pdus = std::span(&contained, 1)};
    CHECK_BYTES(f, nw_frame(nw_::eth{}, ip, u, nw_::soad_pdu_header{.id = 0x300}, c));
    const auto p = nw_::packet::parse(f);
    CHECK(nw::l4_ok(p));
    std::size_t n = 0;
    for (auto pd : nw_::soad_pdus(p.payload())) {
      ++n;
      CHECK_EQ(pd.id, 0x300u);
      std::size_t m = 0;
      for (auto cp : nw_::ipdum_pdus(pd.data, {.header = nw_::ipdum_header::short_header})) {
        ++m;
        CHECK_EQ(cp.id, id);
        CHECK_BYTES(cp.data, std::span<const std::byte>(data));
      }
      CHECK_EQ(m, std::size_t(1));
    }
    CHECK_EQ(n, std::size_t(1));
    // long header
    const auto big = t::random_bytes(t::rnd(0, 1300));
    const auto g = write(tl, big);
    const nw_::pdu lc{0xabcdef01, nw_::bytes(big)};
    const nw_::ipdum_container lcont{.config = {.header = nw_::ipdum_header::long_header}, .pdus = std::span(&lc, 1)};
    CHECK_BYTES(g, nw_frame(nw_::eth{}, ip, u, nw_::soad_pdu_header{.id = 0x301}, lcont));
  }
}

// ---- SOME/IP-SD: an OfferService with an IPv4 endpoint; a SubscribeEventgroup with IPv6
static void test_sd() {
  using namespace nanocraft::proto;
  const auto entry = sd_entry::offer_service(0x1234, 0x0001, 1, 0, 3).with_options(0, 1);
  const auto opt = sd_option::ipv4_endpoint(ip4("10.0.0.1"), ip_proto::udp, 30501);
  auto tm = nanocraft::compile(eth{} / ipv4{.src = ip4("10.0.0.1"), .dst = ip4("224.244.224.245")} /
                               udp{.src_port = 30490, .dst_port = 30490} / nw_::someip_sd_header(1) / sd_header{} /
                               entry / sd_options{} / opt);
  CHECK(tm.ok());
  CHECK_EQ(tm.get<"sd.entries_length">(), 16u);
  CHECK_EQ(tm.get<"sd_options.length">(), 12u);
  for (int it = 0; it < 200; ++it) {
    const auto session = std::uint16_t(t::rnd(1, 0xffff));
    const auto ttl = std::uint32_t(t::rnd(0, 0xffffff));
    const auto port = std::uint16_t(t::rnd(1, 0xffff));
    tm.set<"someip.session_id">(session);
    tm.set<"sd_entry.ttl">(ttl);
    tm.set<"sd_option.port">(port);
    const auto f = write(tm, {});
    if (it % 10 == 0) sample(f);
    auto e = entry;
    e.ttl = ttl;
    auto o = opt;
    o.port = port;
    const nw_::someip_sd body{.entries = std::span(&e, 1), .options = std::span(&o, 1)};
    CHECK_BYTES(f, nw_frame(eth{}, ipv4{.src = ip4("10.0.0.1"), .dst = ip4("224.244.224.245")},
                            udp{.src_port = 30490, .dst_port = 30490}, nw_::someip_sd_header(session), body));
    const auto p = nw_::packet::parse(f);
    CHECK(nw::l4_ok(p));
    const auto m = p.someip();
    CHECK(m && m->is_sd() && m->session_id() == session);
    const auto sd = m ? nw_::sd_view::parse(*m) : std::nullopt;
    CHECK(sd.has_value());
    if (!sd) continue;
    CHECK(sd->well_formed());
    CHECK(sd->reboot() && sd->unicast());
    std::size_t n = 0;
    for (auto ev : sd->entries()) {
      ++n;
      CHECK_EQ(ev.type(), nw_::sd_entry_type::offer_service);
      CHECK_EQ(ev.service_id(), 0x1234u);
      CHECK_EQ(ev.ttl(), ttl);
      CHECK_EQ(ev.is_stop(), ttl == 0);
      int found = 0;
      sd->for_each_option(ev, [&](const nw_::sd_option_view& ov, int) {
        const auto ep = ov.endpoint();
        CHECK(ep.has_value());
        if (ep) {
          CHECK(ep->v4 == ip4("10.0.0.1"));
          CHECK_EQ(ep->port, port);
        }
        ++found;
      });
      CHECK_EQ(found, 1);
    }
    CHECK_EQ(n, std::size_t(1));
  }
  // SubscribeEventgroup + IPv6 endpoint; a raw extra option in the payload extends options_length
  const sd_eventgroup_entry sub{sd_entry::subscribe(0x1234, 1, 1, 0x10, 3, 2).with_options(0, 1)};
  const sd_ipv6_option o6{sd_option::ipv6_endpoint(ip6("fd00::5"), ip_proto::udp, 40000)};
  auto t6 = nanocraft::compile(eth{} / ipv6{.src = ip6("fd00::5"), .dst = ip6("fd00::1")} /
                               udp{.src_port = 30490, .dst_port = 30490} / nw_::someip_sd_header(2) /
                               sd_header{.flags = sd_flag::reboot} / sub / sd_options{} / o6);
  CHECK(t6.ok());
  t6.set<"sd_entry.eventgroup_id">(0x22);
  t6.set<"sd_entry.counter">(5);
  const auto lb = sd_option::load_balancing(1, 2);
  std::array<std::byte, 8> extra{};
  CHECK(lb.write(extra.data()));
  const auto f = write(t6, extra);
  sample(f);
  auto s2 = sub;
  s2.eventgroup_id = 0x22;
  s2.counter = 5;
  const std::array<nw_::sd_option, 2> opts{o6, lb};
  const nw_::sd_entry s2e = s2;
  const nw_::someip_sd body{.flags = sd_flag::reboot, .entries = std::span(&s2e, 1), .options = opts};
  CHECK_BYTES(f, nw_frame(eth{}, ipv6{.src = ip6("fd00::5"), .dst = ip6("fd00::1")}, udp{.src_port = 30490, .dst_port = 30490},
                          nw_::someip_sd_header(2), body));
  const auto p = nw_::packet::parse(f);
  CHECK(nw::l4_ok(p));
  const auto sd = nw_::sd_view::parse(*p.someip());
  CHECK(sd && sd->well_formed());
  if (sd) {
    for (auto ev : sd->entries()) {
      CHECK(ev.is_eventgroup());
      CHECK_EQ(ev.eventgroup_id(), 0x22u);
      CHECK_EQ(unsigned(ev.counter()), 5u);
    }
    std::size_t n = 0;
    for (auto ov : sd->options()) {
      (void)ov;
      ++n;
    }
    CHECK_EQ(n, std::size_t(2));
  }
}

int main(int argc, char** argv) {
  test_stacking_syntax();
  test_refused();
  test_tcp();
  test_tcp_segments();
  test_autosar();
  test_sd();
  if (argc > 1) {
    std::vector<std::byte> file;
    {
      nanocraft::pcap_writer w(nanocraft::output::buffer(file));
      std::uint64_t ts = 1'700'000'000'000'000'000ull;
      for (const auto& f : g_sample) CHECK(w.write(ts += 1000, f));
    }
    const std::string path = std::string(argv[1]) + "/nanocraft_nanowire.pcap";
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    CHECK(fp != nullptr);
    if (fp) {
      CHECK_EQ(std::fwrite(file.data(), 1, file.size(), fp), file.size());
      std::fclose(fp);
    }
  }
  return t::done("test_nanowire");
}
