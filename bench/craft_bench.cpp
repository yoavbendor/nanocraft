// SPDX-License-Identifier: Apache-2.0
// nanocraft benchmarks. Usage: craft_bench [case|all] [frames]
//
//   emit        nanom emit<> per layer, Eth/VLAN/IPv4/UDP/SOME-IP + 32 B payload (the baseline)
//   tmpl1/3/5   compiled template, 1/3/5 patched fields + 32 B payload, UDP checksum zero
//   tmpl3c      same as tmpl3 with the UDP checksum computed (payload summed)
//   tmpl3d      tmpl3, but the 3 fields are patched in the written frame (t.patch<>(frame, v))
//   pcap        tmpl3 crafted straight into a pcap_writer buffer (output discarded)
//   pcapng      the same into a pcapng_writer (EPB)
//   tp64k       SOME/IP-TP: a 64 KiB message -> 1392-byte segments (gathers, UDP checksums)
//   frag64k     IPv4 fragmentation of a 64 000-byte UDP datagram at MTU 1500
//
// Prints ns/frame (best of NANOCRAFT_BENCH_REPS runs, default 5; the machine may be shared, so
// prefer bench/callgrind.sh's instruction counts as the primary metric) and verifies that the
// template frames are byte-identical to the emit baseline.
#include <nanocraft/nanocraft.hpp>

#include <nanom/emit.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace nanocraft::proto;
namespace nm = nanom;
using clk = std::chrono::steady_clock;

static std::uint16_t csum16(std::span<const std::byte> b) { return nanocraft::csum::finish(nanocraft::csum::sum(b)); }
template <>
struct nm::computed<ipv4> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_length">([](const ipv4&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h, const nm::emit_ctx&) { return csum16(h); })};
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

constexpr std::size_t kPay = 32, kFrame = 14 + 4 + 20 + 8 + 16 + kPay;
static int reps() {
  const char* e = std::getenv("NANOCRAFT_BENCH_REPS");
  return e ? std::max(1, std::atoi(e)) : 5;
}
static std::uint64_t fnv(const std::byte* p, std::size_t n, std::uint64_t h) {
  for (std::size_t i = 0; i < n; ++i) h = (h ^ std::uint8_t(p[i])) * 1099511628211ull;
  return h;
}
template <class F>
static double best_ns(long n, F&& f) {
  double best = 1e30;
  for (int r = 0; r < reps(); ++r) {
    const auto t0 = clk::now();
    f(r);
    best = std::min(best, std::chrono::duration<double, std::nano>(clk::now() - t0).count());
  }
  return best / double(n);
}

static const eth kEth{.dst = {1, 0x80, 0xc2, 0, 0, 1}, .src = {2, 0, 0, 0, 0xaa, 1}};
static const vlan kVlan{.pcp = {3}, .vid = {100}};
static const ipv4 kIp{.src = {10, 0, 0, 1}, .dst = {10, 0, 0, 2}};
static const udp kUdp{.src_port = 30501, .dst_port = 30501};
static const someip kSomeip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 1};

static volatile std::uint64_t g_sink;

static void bench_emit(long n, std::uint64_t* hash) {
  std::vector<std::byte> buf(256);
  std::byte pay[kPay];
  const double ns = best_ns(n, [&](int r) {
    std::uint64_t h = 1469598103934665603ull;
    for (long i = 0; i < n; ++i) {
      std::memset(pay, int(i & 0xff), kPay);
      std::byte* end = buf.data() + buf.size();
      std::byte* p = end - kPay;
      std::memcpy(p, pay, kPay);
      someip s = kSomeip;
      s.session_id = std::uint16_t(i);
      p -= 16;
      (void)nm::emit(s, {p, 16}, nm::emit_ctx{{p + 16, kPay}}, std::endian::big);
      udp u = kUdp;
      p -= 8;
      (void)nm::emit(u, {p, 8}, nm::emit_ctx{{p + 8, std::size_t(end - p - 8)}}, std::endian::big);
      ipv4 ip = kIp;
      ip.identification = std::uint16_t(i);
      ip.protocol = 17;
      p -= 20;
      (void)nm::emit(ip, {p, 20}, nm::emit_ctx{{p + 20, std::size_t(end - p - 20)}}, std::endian::big);
      vlan v = kVlan;
      v.ethertype = 0x0800;
      p -= 4;
      (void)nm::emit(v, {p, 4}, {}, std::endian::big);
      eth e = kEth;
      e.ethertype = 0x8100;
      p -= 14;
      (void)nm::emit(e, {p, 14}, {}, std::endian::big);
      if (r == 0 && hash) h = fnv(p, kFrame, h);
      g_sink = g_sink + std::uint8_t(p[30]);
    }
    if (r == 0 && hash) *hash = h;
  });
  std::printf("emit        nanom emit<> per layer          %7.2f ns/frame\n", ns);
}

static void bench_tmpl(long n, int patches, bool udp_csum, std::uint64_t* hash) {
  auto t = nanocraft::compile(kEth / kVlan / kIp / kUdp / kSomeip, kPay);
  if (!udp_csum) t.checksum("udp.checksum", nanocraft::csum_policy::zero);
  std::array<std::byte, 128> fr{};
  std::byte pay[kPay];
  const double ns = best_ns(n, [&](int r) {
    std::uint64_t h = 1469598103934665603ull;
    for (long i = 0; i < n; ++i) {
      std::memset(pay, int(i & 0xff), kPay);
      const auto s = std::uint16_t(i);
      t.set<"someip.session_id">(s);
      if (patches >= 3) {
        t.set<"ipv4.identification">(s);
        t.set<"vlan.pcp">(3);
      }
      if (patches >= 5) {
        t.set<"udp.src_port">(30501);
        t.set<"someip.client_id">(1);
      }
      const std::size_t len = t.write(fr, pay);
      if (r == 0 && hash) h = fnv(fr.data(), len, h);
      g_sink = g_sink + std::uint8_t(fr[30]);
    }
    if (r == 0 && hash) *hash = h;
  });
  std::printf("tmpl%d%s     template, %d patch%s + 32 B%s  %7.2f ns/frame\n", patches, udp_csum ? "c" : " ", patches,
              patches == 1 ? "  " : "es", udp_csum ? ", UDP csum" : "          ", ns);
}

// The same frames, patched in the destination after copying the (unchanged) image.
static void bench_tmpl_dst(long n, std::uint64_t* hash) {
  auto t = nanocraft::compile(kEth / kVlan / kIp / kUdp / kSomeip, kPay);
  t.checksum("udp.checksum", nanocraft::csum_policy::zero);
  std::array<std::byte, 128> fr{};
  std::byte pay[kPay];
  const double ns = best_ns(n, [&](int r) {
    std::uint64_t h = 1469598103934665603ull;
    for (long i = 0; i < n; ++i) {
      std::memset(pay, int(i & 0xff), kPay);
      const auto s = std::uint16_t(i);
      const std::size_t len = t.write(fr, pay);
      t.patch<"someip.session_id">(fr, s);
      t.patch<"ipv4.identification">(fr, s);
      t.patch<"vlan.pcp">(fr, 3);
      if (r == 0 && hash) h = fnv(fr.data(), len, h);
      g_sink = g_sink + std::uint8_t(fr[30]);
    }
    if (r == 0 && hash) *hash = h;
  });
  std::printf("tmpl3d      template, 3 patches in dst + 32 B  %7.2f ns/frame\n", ns);
}

static void bench_pcap(long n, bool ng) {
  auto t = nanocraft::compile(kEth / kVlan / kIp / kUdp / kSomeip, kPay);
  t.checksum("udp.checksum", nanocraft::csum_policy::zero);
  std::uint64_t written = 0;
  nanocraft::output discard{&written, [](void* c, const std::byte*, std::size_t k) {
                              *static_cast<std::uint64_t*>(c) += k;
                              return true;
                            }};
  std::byte pay[kPay];
  std::uint64_t bytes = 0;
  const double ns = best_ns(n, [&](int) {
    auto run = [&](auto& w, auto&& wr) {
      for (long i = 0; i < n; ++i) {
        std::memset(pay, int(i & 0xff), kPay);
        const auto s = std::uint16_t(i);
        t.set<"someip.session_id">(s);
        t.set<"ipv4.identification">(s);
        t.set<"vlan.pcp">(3);
        wr(std::uint64_t(i) * 1000, pay);
      }
      w.flush();
      bytes = w.bytes();
    };
    if (ng) {
      nanocraft::pcapng_writer w(discard, 1 << 20);
      const auto itf = w.add_interface({.name = "eth0"});
      run(w, [&](std::uint64_t ts, std::span<const std::byte> p) { w.write(itf, ts, t, p); });
    } else {
      nanocraft::pcap_writer w(discard, {});
      run(w, [&](std::uint64_t ts, std::span<const std::byte> p) { w.write(ts, t, p); });
    }
  });
  std::printf("%-11s template + %s record (in place)  %7.2f ns/frame  %6.2f GB/s\n", ng ? "pcapng" : "pcap",
              ng ? "pcapng" : "pcap  ", ns, double(bytes) / (ns * double(n)));
}

static void bench_tp(long n) {
  auto t = nanocraft::compile(kEth / kVlan / kIp / kUdp / kSomeip / someip_tp{});
  nanocraft::segmenter seg(t, someip_tp_segments(1392));
  std::vector<std::byte> msg(65536);
  for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = std::byte(i * 7);
  std::size_t segs = 0;
  std::uint64_t bytes = 0;
  const double ns = best_ns(n, [&](int) {
    segs = 0;
    bytes = 0;
    for (long i = 0; i < n; ++i) {
      t.set<"someip.session_id">(std::uint16_t(i));
      segs += seg.run(msg, [&](const nanocraft::gather& g) { bytes += g.size(); });
    }
  });
  std::printf("tp64k       SOME/IP-TP 64 KiB -> %zu segs    %7.0f ns/msg  %7.1f ns/seg  %6.2f GB/s (zero copy)\n",
              segs / std::size_t(n), ns, ns * double(n) / double(segs), double(bytes) / (ns * double(n)));
}

static void bench_frag(long n) {
  auto t = nanocraft::compile(kEth / kVlan / kIp / kUdp / kSomeip);
  nanocraft::segmenter seg(t, ipv4_fragments(1500));
  std::vector<std::byte> msg(64000, std::byte{0x5a});
  std::size_t segs = 0;
  std::uint64_t bytes = 0;
  const double ns = best_ns(n, [&](int) {
    segs = 0;
    bytes = 0;
    for (long i = 0; i < n; ++i) {
      t.set<"ipv4.identification">(std::uint16_t(i));
      segs += seg.run(msg, [&](const nanocraft::gather& g) { bytes += g.size(); });
    }
  });
  std::printf("frag64k     IPv4 fragments 64 000 B -> %zu    %7.0f ns/dgram %6.1f ns/frag %6.2f GB/s (zero copy)\n",
              segs / std::size_t(n), ns, ns * double(n) / double(segs), double(bytes) / (ns * double(n)));
}

int main(int argc, char** argv) {
  const std::string which = argc > 1 ? argv[1] : "all";
  const long n = argc > 2 ? std::atol(argv[2]) : 2'000'000;
  const bool all = which == "all";
  std::uint64_t ha = 0, hb = 0;
  if (all || which == "emit") bench_emit(n, all ? &ha : nullptr);
  if (all || which == "tmpl1") bench_tmpl(n, 1, false, nullptr);
  if (all || which == "tmpl3") bench_tmpl(n, 3, false, all ? &hb : nullptr);
  if (all || which == "tmpl5") bench_tmpl(n, 5, false, nullptr);
  if (all || which == "tmpl3c") bench_tmpl(n, 3, true, nullptr);
  std::uint64_t hd = 0;
  if (all || which == "tmpl3d") bench_tmpl_dst(n, all ? &hd : nullptr);
  if (all)
    std::printf("template frames byte-identical to the nanom emit baseline: %s\n", ha == hb && ha == hd ? "yes" : "NO");
  if (all || which == "pcap") bench_pcap(n, false);
  if (all || which == "pcapng") bench_pcap(n, true);
  const long nm_ = all ? std::max(1L, n / 1000) : n;
  if (all || which == "tp64k") bench_tp(nm_);
  if (all || which == "frag64k") bench_frag(nm_);
  nanocraft::profile::report(stderr);
  return all && (ha != hb || ha != hd) ? 1 : 0;
}
