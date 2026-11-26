// SPDX-License-Identifier: Apache-2.0
// tests/ots_craft_emitter.cpp — stream crafted pcap / pcapng test suites to stdout for piping
// straight into off-the-shelf analyzers (`tshark -r -`, `tcpdump -r -`).
//
// Usage:
//   ots_craft_emitter valid_pcap   | tshark -r - -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -o tcp.check_checksum:TRUE
//   ots_craft_emitter valid_pcapng | tshark -r - ...
//   ots_craft_emitter valid_pcap   | tcpdump -nn -vvv -r -
//   ots_craft_emitter faults_pcap  | tshark -r - ...
#include <nanocraft/nanocraft.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

using namespace nanocraft::proto;

namespace {

std::vector<std::byte> make_pattern(std::size_t n, std::uint8_t seed = 0x11) {
  std::vector<std::byte> v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = std::byte(std::uint8_t((seed + i * 37u) & 0xffu));
  return v;
}

// Compute a 16-bit delta to patch a 16-bit field (initially 0) so a checksum initially equal to
// `cur_csum` lands on 0x0000 (before UDP's 0 -> 0xFFFF rule).
std::uint16_t word_for_zero_checksum(std::uint16_t cur_csum) noexcept {
  // Currently ~sum == cur_csum, so sum == ~cur_csum. Adding word = cur_csum gives sum = 0xFFFF -> ~sum = 0x0000.
  return cur_csum;
}

// Emits the full valid test suite through `emit_frame(span, iface_id, ts_ns, comment)`.
template <class EmitFrame, class EmitGather>
bool emit_valid_suite(EmitFrame&& emit_frame, EmitGather&& emit_gather) {
  std::uint64_t ts = 1700000000000000000ull;  // 2023-11-14T22:13:20Z
  auto next_ts = [&] {
    ts += 1000000ull;  // +1 ms
    return ts;
  };
  std::array<std::byte, 2048> buf{};

  auto send_tmpl = [&](auto& tmpl, std::span<const std::byte> pay, std::uint32_t iface = 0,
                       std::string_view comment = {}) -> bool {
    const std::size_t n = tmpl.write(buf, pay);
    if (n == 0) return false;
    return emit_frame(std::span<const std::byte>(buf.data(), n), iface, next_ts(), comment);
  };

  // 1-6. Plain IPv4 / UDP / SOME/IP across edge-case payload sizes (0, odd, padded, near-MTU).
  {
    auto t_pad = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:02"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.1.0.1"), .dst = ip4("10.1.0.2"), .id = 100, .df = true} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x1234, .method_id = 0x0001, .client_id = 0x0100, .session_id = 1},
        nanocraft::template_options{.payload_size = 0, .min_frame = 60});
    if (!t_pad.ok()) return false;
    if (!send_tmpl(t_pad, {}, 0, "ipv4-udp-someip-empty-padded")) return false;
    t_pad.set<"ipv4.identification">(101);
    t_pad.set<"someip.session_id">(2);
    auto p1 = make_pattern(1, 0xA1);
    if (!send_tmpl(t_pad, p1, 0, "ipv4-udp-someip-1b-odd-padded")) return false;

    auto t_nopad = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:02"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.1.0.1"), .dst = ip4("10.1.0.2"), .id = 102, .df = true} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x1234, .method_id = 0x0002, .client_id = 0x0100, .session_id = 3});
    if (!t_nopad.ok()) return false;
    const std::array<std::size_t, 4> sizes{5, 17, 512, 1400};
    for (std::size_t k = 0; k < sizes.size(); ++k) {
      t_nopad.set<"ipv4.identification">(std::uint16_t(102 + k));
      t_nopad.set<"someip.session_id">(std::uint16_t(3 + k));
      auto p = make_pattern(sizes[k], std::uint8_t(0x20 + k));
      if (!send_tmpl(t_nopad, p, 0)) return false;
    }
  }

  // 7. Single 802.1Q VLAN (PCP=5, DEI=1, VID=100) + min_frame=60 padding (49B -> 60B) + odd payload.
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:03"), .src = mac("02:00:00:00:00:01")} /
            vlan{.vid = 100, .pcp = 5, .dei = true, .tpid = ethertype::vlan} /
            ipv4{.src = ip4("10.2.0.1"), .dst = ip4("10.2.0.2"), .id = 200, .df = true} /
            udp{.src_port = 12345, .dst_port = 12346},
        nanocraft::template_options{.payload_size = 3, .min_frame = 60});
    if (!t.ok()) return false;
    auto p = make_pattern(3, 0x33);
    if (!send_tmpl(t, p, 1, "vlan-8021q-padded")) return false;
  }

  // 8. 802.1ad QinQ (S-tag 0x88A8 VID=200 PCP=3 / C-tag 0x8100 VID=100 PCP=6 DEI=1) + min_frame=60 (53B -> 60B).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:04"), .src = mac("02:00:00:00:00:01")} /
            vlan{.vid = 200, .pcp = 3, .dei = false, .tpid = ethertype::qinq} /
            vlan{.vid = 100, .pcp = 6, .dei = true, .tpid = ethertype::vlan} /
            ipv4{.src = ip4("10.3.0.1"), .dst = ip4("10.3.0.2"), .id = 300, .df = true} /
            udp{.src_port = 12345, .dst_port = 12346},
        nanocraft::template_options{.payload_size = 3, .min_frame = 60});
    if (!t.ok()) return false;
    auto p = make_pattern(3, 0x44);
    if (!send_tmpl(t, p, 1, "qinq-8021ad-padded")) return false;
  }

  // 9. Double 802.1Q stacked VLAN (0x8100 VID=300 / 0x8100 VID=101) + IPv4/UDP/SOME/IP (7B odd payload).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:04"), .src = mac("02:00:00:00:00:01")} /
            vlan{.vid = 300, .pcp = 1, .dei = false, .tpid = ethertype::vlan} /
            vlan{.vid = 101, .pcp = 4, .dei = true, .tpid = ethertype::vlan} /
            ipv4{.src = ip4("10.3.1.1"), .dst = ip4("10.3.1.2"), .id = 301, .df = true} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x2002, .method_id = 0x8002, .client_id = 0x0300, .session_id = 20});
    if (!t.ok()) return false;
    auto p = make_pattern(7, 0x45);
    if (!send_tmpl(t, p, 1, "double-8021q")) return false;
  }

  // 10. IPv4/UDP incremental patch hitting 0x0000 -> must emit 0xFFFF (RFC 768).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:05"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.4.0.1"), .dst = ip4("10.4.0.2"), .id = 400} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x3001, .method_id = 0x0001, .client_id = 0x0400, .session_id = 0});
    if (!t.ok()) return false;
    const auto base_csum = std::uint16_t(t.get<"udp.checksum">());
    t.set<"someip.session_id">(word_for_zero_checksum(base_csum));
    if (t.get<"udp.checksum">() != 0xffff) return false;
    if (!send_tmpl(t, {}, 0, "ipv4-udp-ffff-zero-mapped")) return false;
  }

  // 11. IPv4/UDP explicit csum_policy::zero (0x0000 = checksum omitted, valid in IPv4 per RFC 768).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:05"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.4.0.1"), .dst = ip4("10.4.0.2"), .id = 401} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x3002, .method_id = 0x0001, .client_id = 0x0400, .session_id = 1});
    if (!t.ok()) return false;
    t.checksum("udp.checksum", nanocraft::csum_policy::zero);
    auto p = make_pattern(9, 0x55);
    if (!send_tmpl(t, p, 0, "ipv4-udp-zero-omitted")) return false;
  }

  // 12-14. IPv4/TCP: SYN (padded), ACK+PSH (odd payload), and incremental patch hitting TCP checksum 0x0000.
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:06"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.5.0.1"), .dst = ip4("10.5.0.2"), .id = 500, .df = true} /
            tcp{.src_port = 40000, .dst_port = 30502, .seq = 1000, .ack = 0, .flags = tcp_flag::syn, .window = 65535},
        nanocraft::template_options{.payload_size = 0, .min_frame = 60});
    if (!t.ok()) return false;
    if (!send_tmpl(t, {}, 0, "ipv4-tcp-syn-padded")) return false;

    t.set<"ipv4.identification">(501);
    t.set<"tcp.flags">(tcp_flag::ack | tcp_flag::psh);
    t.set<"tcp.seq">(1001);
    t.set<"tcp.ack">(2001);
    auto p = make_pattern(19, 0x66);
    if (!send_tmpl(t, p, 0, "ipv4-tcp-psh-odd")) return false;

    // Force TCP checksum == 0x0000 via incremental patch on urgent pointer (0-byte payload, non-zero window).
    auto t0 = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:06"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.5.0.1"), .dst = ip4("10.5.0.2"), .id = 502, .df = true} /
            tcp{.src_port = 40000,
                .dst_port = 30502,
                .seq = 1020,
                .ack = 2001,
                .flags = tcp_flag::ack,
                .window = 32768,
                .urgent = 0},
        nanocraft::template_options{.payload_size = 0, .min_frame = 60});
    if (!t0.ok()) return false;
    const auto tcp_base = std::uint16_t(t0.get<"tcp.checksum">());
    t0.set<"tcp.urgent">(word_for_zero_checksum(tcp_base));
    if (t0.get<"tcp.checksum">() != 0x0000) return false;
    if (!send_tmpl(t0, {}, 0, "ipv4-tcp-zero-csum")) return false;
  }

  // 15-16. IPv6 / UDP / SOME/IP (empty, and incremental patch hitting 0x0000 -> 0xFFFF per RFC 8200 §8.1).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:07"), .src = mac("02:00:00:00:00:01")} /
            ipv6{.src = ip6("fd00:1::1"), .dst = ip6("fd00:1::2")} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x4001, .method_id = 0x0001, .client_id = 0x0500, .session_id = 0});
    if (!t.ok()) return false;
    if (!send_tmpl(t, {}, 1, "ipv6-udp-someip-empty")) return false;

    const auto v6_base = std::uint16_t(t.get<"udp.checksum">());
    t.set<"someip.session_id">(word_for_zero_checksum(v6_base));
    if (t.get<"udp.checksum">() != 0xffff) return false;
    if (!send_tmpl(t, {}, 1, "ipv6-udp-ffff-rfc8200")) return false;
  }

  // 17. VLAN (VID=42) + IPv6 / TCP (odd payload).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:08"), .src = mac("02:00:00:00:00:01")} /
            vlan{.vid = 42, .pcp = 2, .dei = false} /
            ipv6{.src = ip6("fd00:2::10"), .dst = ip6("fd00:2::20")} /
            tcp{.src_port = 50000,
                .dst_port = 30502,
                .seq = 777,
                .ack = 888,
                .flags = tcp_flag::ack | tcp_flag::psh,
                .window = 16384});
    if (!t.ok()) return false;
    auto p = make_pattern(27, 0x77);
    if (!send_tmpl(t, p, 1, "vlan-ipv6-tcp-odd")) return false;
  }

  // 18. SOME/IP-SD OfferService (0x1234, instance 0x0001) with IPv4 endpoint option on UDP port 30490.
  {
    auto entry = sd_entry::offer_service(0x1234, 0x0001, 1, 0x00000002, 3);
    entry.with_options(0, 1);
    auto opt = sd_option::ipv4_endpoint(ip4("10.1.2.3"), ip_proto::udp, 30501);
    auto t = nanocraft::compile(
        eth{.dst = mac("01:00:5e:00:00:01"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.1.2.3"), .dst = ip4("224.224.224.245"), .ttl = 1, .id = 600} /
            udp{.src_port = 30490, .dst_port = 30490} /
            nanowire::someip_sd_header(1) /
            sd_header{.flags = sd_flag::reboot | sd_flag::unicast, .entries = 1} /
            entry /
            sd_options{} /
            opt);
    if (!t.ok()) return false;
    if (!send_tmpl(t, {}, 0, "someip-sd-offer")) return false;
  }

  // 19-21. IPv4 fragmentation (MTU 500 -> 3 fragments over UDP + SOME/IP).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:09"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.6.0.1"), .dst = ip4("10.6.0.2"), .id = 0x7001, .df = false} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x5001, .method_id = 0x0001, .client_id = 0x0600, .session_id = 1});
    if (!t.ok()) return false;
    nanocraft::segmenter seg(t, ipv4_fragments(500));
    if (!seg.ok()) return false;
    auto pay = make_pattern(1000, 0x88);
    bool ok = true;
    const std::size_t cnt = seg.run(pay, [&](const nanocraft::gather& g) {
      if (!emit_gather(g, 0, next_ts(), "ipv4-frag")) ok = false;
    });
    if (!ok || cnt != 3) return false;
  }

  // 22-24. IPv6 fragmentation (MTU 500 -> 3 fragments over UDP + SOME/IP).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:0a"), .src = mac("02:00:00:00:00:01")} /
            ipv6{.src = ip6("fd00:6::1"), .dst = ip6("fd00:6::2")} /
            ipv6_frag{.offset = 0, .more = false, .id = 0x00060001} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x5002, .method_id = 0x0002, .client_id = 0x0601, .session_id = 2});
    if (!t.ok()) return false;
    nanocraft::segmenter seg(t, ipv6_fragments(500));
    if (!seg.ok()) return false;
    auto pay = make_pattern(1000, 0x99);
    bool ok = true;
    const std::size_t cnt = seg.run(pay, [&](const nanocraft::gather& g) {
      if (!emit_gather(g, 1, next_ts(), "ipv6-frag")) ok = false;
    });
    if (!ok || cnt != 3) return false;
  }

  // 25-27. SOME/IP-TP segmentation (max_payload 64 -> 3 segments over IPv4/UDP/SOME/IP/SOME/IP-TP).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:0b"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.7.0.1"), .dst = ip4("10.7.0.2"), .id = 700, .df = true} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x6001, .method_id = 0x0001, .client_id = 0x0700, .session_id = 42} /
            someip_tp{});
    if (!t.ok()) return false;
    nanocraft::segmenter seg(t, someip_tp_segments(64));
    if (!seg.ok()) return false;
    auto pay = make_pattern(140, 0xAA);
    bool ok = true;
    const std::size_t cnt = seg.run(pay, [&](const nanocraft::gather& g) {
      if (!emit_gather(g, 0, next_ts(), "someip-tp")) ok = false;
    });
    if (!ok || cnt != 3) return false;
  }

  // 28-29. SOME/IP-TP with template tail (soad_pdu_header after someip_tp -> 2 segments; tests L4 checksum with rep_ < H).
  {
    auto t = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:0b"), .src = mac("02:00:00:00:00:01")} /
            ipv4{.src = ip4("10.7.1.1"), .dst = ip4("10.7.1.2"), .id = 710, .df = true} /
            udp{.src_port = 30501, .dst_port = 30501} /
            someip{.service_id = 0x6002, .method_id = 0x0002, .client_id = 0x0701, .session_id = 43} /
            someip_tp{} /
            soad_pdu_header{.id = 0x11223344});
    if (!t.ok()) return false;
    nanocraft::segmenter seg(t, someip_tp_segments(64));
    if (!seg.ok()) return false;
    auto pay = make_pattern(77, 0xAB);  // 8B soad tail + 77B pay = 85B -> 64B + 21B
    bool ok = true;
    const std::size_t cnt = seg.run(pay, [&](const nanocraft::gather& g) {
      if (!emit_gather(g, 0, next_ts(), "someip-tp-soad-tail")) ok = false;
    });
    if (!ok || cnt != 2) return false;
  }

  // 30. Replay + frame_ref rewritten frame (VLAN + IPv4 + UDP + SOME/IP).
  {
    auto shape = nanocraft::compile(
        eth{.dst = mac("02:00:00:00:00:0c"), .src = mac("02:00:00:00:00:01")} /
        vlan{.vid = 111, .pcp = 1} /
        ipv4{.src = ip4("10.8.0.1"), .dst = ip4("10.8.0.2"), .id = 800} /
        udp{.src_port = 30501, .dst_port = 30509} /
        someip{.service_id = 0x7001, .method_id = 0x0001, .client_id = 0x0800, .session_id = 1});
    if (!shape.ok()) return false;
    std::vector<std::byte> mem_pcap;
    {
      nanocraft::pcap_writer w(nanocraft::output::buffer(mem_pcap), {.nanosecond = true});
      auto p = make_pattern(23, 0xBB);
      if (!w.write(next_ts(), shape, p)) return false;
    }
    nanocraft::capture_reader reader(mem_pcap);
    bool emitted = false;
    auto st = nanocraft::replay(
        reader,
        [&](std::span<const std::byte> f, std::uint64_t rts) {
          emitted = emit_frame(f, 0, rts, "replay-rewritten");
          return emitted;
        },
        {.speed = 0.0},
        [&](std::span<std::byte> f, const nanocraft::packet&) {
          if (shape.matches(f)) {
            nanocraft::frame_ref ref(shape, f);
            ref.template set<"vlan.vid">(333);
            ref.template set<"ipv4.dst">(ip4("10.9.9.9"));
            ref.template set<"udp.dst_port">(30501);
            ref.template set<"someip.session_id">(0x4242);
          }
          return true;
        });
    if (!emitted || st.packets != 1 || !st.error.empty()) return false;
  }

  return true;
}

bool emit_faults_pcap(nanocraft::output out) {
  nanocraft::pcap_writer w(out, {.nanosecond = true});
  std::uint64_t ts = 1700000001000000000ull;
  auto next_ts = [&] {
    ts += 1000000ull;
    return ts;
  };
  auto pay = make_pattern(20, 0xCC);

  // 1. Bad IPv4 header checksum
  {
    auto t = nanocraft::compile(
        eth{} / ipv4{.src = ip4("10.9.0.1"), .dst = ip4("10.9.0.2"), .id = 900} /
        udp{.src_port = 30501, .dst_port = 30501} / someip{.service_id = 0x9001});
    if (!t.ok() || !t.inject(nanocraft::faults{}.bad_checksum("ipv4.checksum"))) return false;
    if (!w.write(next_ts(), t, pay)) return false;
  }
  // 2. Bad UDP checksum
  {
    auto t = nanocraft::compile(
        eth{} / ipv4{.src = ip4("10.9.0.1"), .dst = ip4("10.9.0.2"), .id = 901} /
        udp{.src_port = 30501, .dst_port = 30501} / someip{.service_id = 0x9002});
    if (!t.ok() || !t.inject(nanocraft::faults{}.bad_checksum("udp.checksum"))) return false;
    if (!w.write(next_ts(), t, pay)) return false;
  }
  // 3. Bad TCP checksum
  {
    auto t = nanocraft::compile(
        eth{} / ipv4{.src = ip4("10.9.0.1"), .dst = ip4("10.9.0.2"), .id = 902} /
        tcp{.src_port = 40001, .dst_port = 30502, .seq = 1, .ack = 1, .flags = tcp_flag::ack | tcp_flag::psh});
    if (!t.ok() || !t.inject(nanocraft::faults{}.bad_checksum("tcp.checksum"))) return false;
    if (!w.write(next_ts(), t, pay)) return false;
  }
  // 4. UDP length delta (+20 bytes past actual frame)
  {
    auto t = nanocraft::compile(
        eth{} / ipv4{.src = ip4("10.9.0.1"), .dst = ip4("10.9.0.2"), .id = 903} /
        udp{.src_port = 30501, .dst_port = 30501} / someip{.service_id = 0x9004});
    if (!t.ok() || !t.inject(nanocraft::faults{}.length_delta("udp.length", 20))) return false;
    if (!w.write(next_ts(), t, pay)) return false;
  }
  // 5. Truncated frame (-12 bytes)
  {
    auto t = nanocraft::compile(
        eth{} / ipv4{.src = ip4("10.9.0.1"), .dst = ip4("10.9.0.2"), .id = 904} /
        udp{.src_port = 30501, .dst_port = 30501} / someip{.service_id = 0x9005});
    if (!t.ok() || !t.inject(nanocraft::faults{}.truncate_by(12))) return false;
    if (!w.write(next_ts(), t, pay)) return false;
  }

  return w.flush() && w.ok();
}

}  // namespace

int main(int argc, char** argv) {
  const std::string_view mode = argc > 1 ? std::string_view(argv[1]) : "valid_pcap";
  auto out = nanocraft::output::file(stdout);

  if (mode == "valid_pcap") {
    nanocraft::pcap_writer w(out, {.nanosecond = true});
    const bool ok = emit_valid_suite(
        [&](std::span<const std::byte> f, std::uint32_t, std::uint64_t ts, std::string_view) {
          return w.write(ts, f);
        },
        [&](const nanocraft::gather& g, std::uint32_t, std::uint64_t ts, std::string_view) {
          return w.write(ts, g);
        });
    if (!ok || !w.flush() || !w.ok()) {
      std::fprintf(stderr, "ots_craft_emitter: failed writing valid_pcap\n");
      return 1;
    }
    return 0;
  }

  if (mode == "valid_pcapng") {
    nanocraft::pcapng_writer w(out);
    const std::uint32_t if0 = w.add_interface({.linktype = 1, .name = "eth0", .description = "nanocraft v4", .tsresol = 9});
    const std::uint32_t if1 = w.add_interface({.linktype = 1, .name = "eth1", .description = "nanocraft v6/vlan", .tsresol = 9});
    if (if0 == ~0u || if1 == ~0u) {
      std::fprintf(stderr, "ots_craft_emitter: add_interface failed\n");
      return 1;
    }
    const bool ok = emit_valid_suite(
        [&](std::span<const std::byte> f, std::uint32_t iface, std::uint64_t ts, std::string_view comment) {
          nanocraft::epb_options opts{};
          opts.flags = 1u;  // inbound
          opts.comment = comment;
          return w.write(iface == 0 ? if0 : if1, ts, f, opts);
        },
        [&](const nanocraft::gather& g, std::uint32_t iface, std::uint64_t ts, std::string_view comment) {
          nanocraft::epb_options opts{};
          opts.flags = 2u;  // outbound
          opts.comment = comment;
          return w.write(iface == 0 ? if0 : if1, ts, g, opts);
        });
    if (!ok || !w.flush() || !w.ok()) {
      std::fprintf(stderr, "ots_craft_emitter: failed writing valid_pcapng\n");
      return 1;
    }
    return 0;
  }

  if (mode == "faults_pcap") {
    if (!emit_faults_pcap(out)) {
      std::fprintf(stderr, "ots_craft_emitter: failed writing faults_pcap\n");
      return 1;
    }
    return 0;
  }

  std::fprintf(stderr, "usage: %s [valid_pcap|valid_pcapng|faults_pcap]\n", argv[0]);
  return 2;
}
