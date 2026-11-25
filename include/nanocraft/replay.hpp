// SPDX-License-Identifier: Apache-2.0
// nanocraft/replay.hpp — re-emit a capture, optionally rewriting fields, with original or scaled timing.
//
//   auto file = nanocraft::mapped_file::open("in.pcap");
//   nanocraft::capture_reader r(file.bytes());
//   auto shape = nanocraft::compile(eth{} / vlan{} / ipv4{} / udp{} / someip{});   // a stack to match
//   auto stats = nanocraft::replay(r, sink, {.speed = 1.0},
//       [&](std::span<std::byte> pkt, const nanocraft::packet&) {
//         if (shape.matches(pkt)) {
//           nanocraft::frame_ref f(shape, pkt);           // the same patch points as templates
//           f.set<"ipv4.dst">(nanocraft::proto::ip4{10, 0, 0, 9});   // IPv4 + UDP checksums kept
//         }
//         return true;                                     // false drops the packet
//       });
//
// sink(std::span<const std::byte> frame, std::uint64_t ts_ns) -> bool (false stops the replay); any
// writer or sender fits through a lambda. Timing: speed 0 = as fast as possible; otherwise the
// replay sleeps until first_wall + (ts - first_ts) / speed (coarse sleep, then a short spin), and
// the sink gets the scaled timestamp first_ts + (ts - first_ts) / speed. Rewrites work on a copy in
// one reused scratch buffer (the capture stays read-only, e.g. memory-mapped).
#ifndef NANOCRAFT_REPLAY_HPP_INCLUDED
#define NANOCRAFT_REPLAY_HPP_INCLUDED

#include "pcap_reader.hpp"
#include "profile.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <type_traits>
#include <utility>
#include <cstdint>
#include <span>
#include <thread>
#include <vector>

namespace nanocraft {

struct replay_options {
  double speed = 1.0;               ///< 0: no pacing; 1: original timing; 2: twice as fast
  std::uint64_t max_packets = 0;    ///< 0: all
  std::chrono::nanoseconds spin{50000};  ///< busy-wait this close to each deadline
};

struct replay_stats {
  std::uint64_t packets = 0, bytes = 0, dropped = 0;
  std::int64_t max_late_ns = 0;     ///< worst lateness against the schedule
  std::string_view error{};         ///< the reader's error, if the capture was malformed
};

/// Pass-through rewrite.
struct no_rewrite {
  bool operator()(std::span<std::byte>, const packet&) const noexcept { return true; }
};

template <class Sink, class Rewrite = no_rewrite>
replay_stats replay(capture_reader& r, Sink&& sink, const replay_options& o = {}, Rewrite&& rewrite = {}) {
  using clk = std::chrono::steady_clock;
  replay_stats st;
  std::vector<std::byte> scratch;
  packet p;
  bool first = true;
  std::uint64_t ts0 = 0;
  clk::time_point wall0{};
  constexpr bool passthrough = std::is_same_v<std::remove_cvref_t<Rewrite>, no_rewrite>;
  while ((o.max_packets == 0 || st.packets + st.dropped < o.max_packets) && r.next(p)) {
    NANOCRAFT_PROFILE_SCOPE(replay);
    if (first) {
      ts0 = p.ts_ns;
      wall0 = clk::now();
      first = false;
    }
    const std::uint64_t rel = p.ts_ns >= ts0 ? p.ts_ns - ts0 : 0;
    std::uint64_t ts = p.ts_ns;
    if (o.speed > 0) {
      const auto off = std::chrono::nanoseconds(std::int64_t(double(rel) / o.speed));
      ts = ts0 + std::uint64_t(off.count());
      const auto deadline = wall0 + off;
      auto now = clk::now();
      if (deadline - now > o.spin) std::this_thread::sleep_until(deadline - o.spin);
      while ((now = clk::now()) < deadline) {
      }
      st.max_late_ns = std::max<std::int64_t>(st.max_late_ns, (now - deadline).count());
    }
    std::span<const std::byte> out = p.data;
    if constexpr (!passthrough) {
      if (scratch.size() < p.data.size()) scratch.resize(p.data.size());
      std::memcpy(scratch.data(), p.data.data(), p.data.size());
      std::span<std::byte> m(scratch.data(), p.data.size());
      if (!rewrite(m, std::as_const(p))) {
        ++st.dropped;
        continue;
      }
      out = m;
    }
    if (!sink(out, ts)) break;
    ++st.packets;
    st.bytes += out.size();
    NANOCRAFT_PROFILE_COUNT(replay, 1, out.size());
  }
  st.error = r.error();
  return st;
}

}  // namespace nanocraft

#endif  // NANOCRAFT_REPLAY_HPP_INCLUDED
