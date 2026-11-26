// SPDX-License-Identifier: Apache-2.0
// Replay: rewrite fields of captured frames through the template patch points (checksums kept,
// verified by the reference builder), pacing with original / scaled timing, drop and stop.
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"
#include "reference.hpp"

#include <chrono>

using namespace nanocraft::proto;

int main() {
  // a capture: SOME/IP frames (some with UDP checksum 0) and a few non-matching IPv6 frames
  std::vector<ref::spec> specs;
  std::vector<std::byte> file;
  const std::uint64_t t0 = 1'700'000'000'000'000'000ull;
  {
    nanocraft::pcap_writer w(nanocraft::output::buffer(file));
    for (int i = 0; i < 60; ++i) {
      ref::spec s;
      s.vlans = {{1, 0, 10}};
      s.v6 = i % 10 == 9;
      s.src4 = {10, 0, 0, 1};
      s.dst4 = {10, 0, 0, std::uint8_t(i)};
      s.ident = unsigned(i);
      s.sport = 30501;
      s.dport = 30501;
      s.session = unsigned(i);
      s.udp_csum = i % 3 == 0 ? ref::spec::csum_zero : ref::spec::csum_compute;
      s.payload = t::random_bytes(t::rnd(0, 600));
      specs.push_back(s);
      CHECK(w.write(t0 + std::uint64_t(i) * 2'000'000, ref::build(s)));  // 2 ms apart
    }
  }
  auto shape = nanocraft::compile(eth{} / vlan{} / ipv4{} / udp{} / someip{});
  // 1. rewrite as fast as possible
  {
    nanocraft::capture_reader r(file);
    std::size_t k = 0, matched = 0;
    std::vector<std::uint64_t> ts;
    auto st = nanocraft::replay(
        r,
        [&](std::span<const std::byte> f, std::uint64_t t) {
          auto s = specs[k++];
          if (!s.v6) {
            s.dst4 = {192, 168, 0, 9};
            s.session ^= 0x5a5a;
            s.ttl = 3;
          }
          CHECK_BYTES(f, ref::build(s));
          ts.push_back(t);
          return true;
        },
        {.speed = 0},
        [&](std::span<std::byte> pkt, const nanocraft::packet&) {
          if (!shape.matches(pkt)) return true;
          ++matched;
          nanocraft::frame_ref<eth, vlan, ipv4, udp, someip> f(shape, pkt);
          f.set<"ipv4.dst">(ipv4_addr{192, 168, 0, 9});
          f.set<"someip.session_id">(f.get<"someip.session_id">() ^ 0x5a5a);
          f.set<"ipv4.ttl">(3);
          return true;
        });
    CHECK_EQ(st.packets, std::uint64_t(60));
    CHECK_EQ(matched, std::size_t(54));
    CHECK(st.error.empty());
    CHECK_EQ(ts.size(), std::size_t(60));
    if (ts.size() == 60) CHECK_EQ(ts[59], t0 + 59 * 2'000'000ull);
  }
  // 2. drop every other packet, stop after 10 delivered
  {
    nanocraft::capture_reader r(file);
    int n = 0, seen = 0;
    auto st = nanocraft::replay(
        r, [&](std::span<const std::byte>, std::uint64_t) { return ++n < 10; }, {.speed = 0},
        [&](std::span<std::byte>, const nanocraft::packet&) { return ++seen % 2 == 1; });
    CHECK_EQ(n, 10);
    CHECK_EQ(st.packets, std::uint64_t(9));
    CHECK_EQ(st.dropped, std::uint64_t(9));
  }
  // 3. timing: 59 gaps of 2 ms at speed 4 -> ~29.5 ms, timestamps scaled
  {
    nanocraft::capture_reader r(file);
    std::vector<std::uint64_t> ts;
    const auto a = std::chrono::steady_clock::now();
    auto st = nanocraft::replay(r, [&](std::span<const std::byte>, std::uint64_t t) { ts.push_back(t); return true; },
                                {.speed = 4.0});
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - a).count();
    CHECK_EQ(st.packets, std::uint64_t(60));
    CHECK_MSG(ms >= 29.0 && ms < 2000.0, std::to_string(ms));
    if (ts.size() == 60) CHECK_EQ(ts[59], t0 + 59 * 500'000ull);
    std::printf("replay at 4x: %.1f ms for 29.5 ms of scaled capture, max lateness %.1f us\n", ms,
                double(st.max_late_ns) / 1000.0);
  }
  // 4. a malformed capture reports its error (owning std::string survives reader destruction)
  {
    auto bad = file;
    bad.resize(bad.size() - 5);
    nanocraft::replay_stats st;
    {
      nanocraft::capture_reader r(bad);
      st = nanocraft::replay(r, [](std::span<const std::byte>, std::uint64_t) { return true; }, {.speed = 0});
    }
    CHECK_EQ(st.packets, std::uint64_t(59));
    CHECK(!st.error.empty());
    CHECK(st.error.find("truncated") != std::string::npos);
  }
  // 5. invalid / non-finite speeds run unpaced without UB; empty packet with rewrite has no memcpy UB
  {
    std::vector<std::byte> empty_cap;
    {
      nanocraft::pcap_writer w(nanocraft::output::buffer(empty_cap));
      CHECK(w.write(1'000'000'000ull, std::span<const std::byte>{}));
      CHECK(w.write(1'000'000'123ull, std::span<const std::byte>{}));
    }
    for (double spd : {std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::infinity(),
                       -std::numeric_limits<double>::infinity(), -2.0}) {
      nanocraft::capture_reader r(empty_cap);
      auto st = nanocraft::replay(
          r, [](std::span<const std::byte>, std::uint64_t) { return true; }, {.speed = spd},
          [](std::span<std::byte> m, const nanocraft::packet&) { return m.empty(); });
      CHECK_EQ(st.packets, std::uint64_t(2));
      CHECK(st.error.empty());
    }
    // speed == 1.0 exact integer timestamp path (no double precision loss)
    {
      nanocraft::capture_reader r(empty_cap);
      std::vector<std::uint64_t> ts;
      auto st = nanocraft::replay(
          r,
          [&](std::span<const std::byte>, std::uint64_t t) {
            ts.push_back(t);
            return true;
          },
          {.speed = 1.0});
      CHECK_EQ(st.packets, std::uint64_t(2));
      if (ts.size() == 2) CHECK_EQ(ts[1], 1'000'000'123ull);
    }
  }
  return t::done("test_replay");
}
