// SPDX-License-Identifier: Apache-2.0
// nanocraft/profile.hpp — built-in, compiled-out-by-default profiling counters.
//
// Define NANOCRAFT_PROFILE (e.g. -DNANOCRAFT_PROFILE=1, or the CMake option of the same name) and
// every stage of the library counts calls, frames and bytes, and times one call in 64 with the TSC
// (x86) or steady_clock (elsewhere). Without the macro, all hooks expand to nothing.
//
//   nanocraft::profile::reset();
//   ... craft / segment / write ...
//   nanocraft::profile::report(stderr);    // calls, frames, bytes, ns/call per stage
//   const auto& c = nanocraft::profile::local();   // raw counters (thread-local)
//
// Counters are thread-local: each producer thread reports its own stages.
#ifndef NANOCRAFT_PROFILE_HPP_INCLUDED
#define NANOCRAFT_PROFILE_HPP_INCLUDED

#include <chrono>
#include <cstdint>
#include <cstdio>

#if defined(NANOCRAFT_PROFILE) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>
#endif

namespace nanocraft::profile {

enum stage : std::uint8_t { template_write, segment, pcap_write, pcap_flush, tx, replay, n_stages };
inline constexpr const char* stage_names[n_stages] = {"template_write", "segment", "pcap_write",
                                                      "pcap_flush",     "tx",      "replay"};

struct counters {
  std::uint64_t frames[n_stages]{};
  std::uint64_t bytes[n_stages]{};
  std::uint64_t calls[n_stages]{};
  std::uint64_t sampled[n_stages]{};
  std::uint64_t ticks[n_stages]{};
};

#if defined(NANOCRAFT_PROFILE)
inline constexpr bool enabled = true;
inline counters& local() noexcept {
  thread_local counters c;
  return c;
}
inline std::uint64_t now_ticks() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  return __rdtsc();
#else
  return std::uint64_t(std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}
/// Nanoseconds per tick (calibrated once against steady_clock, ~5 ms).
inline double ns_per_tick() noexcept {
  static const double v = [] {
#if defined(__x86_64__) || defined(__i386__)
    using clk = std::chrono::steady_clock;
    const auto t0 = clk::now();
    const std::uint64_t c0 = now_ticks();
    while (clk::now() - t0 < std::chrono::milliseconds(5)) {
    }
    const double ns = double(std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now() - t0).count());
    return ns / double(now_ticks() - c0);
#else
    return double(std::chrono::steady_clock::period::num) * 1e9 / double(std::chrono::steady_clock::period::den);
#endif
  }();
  return v;
}
/// RAII stage timer: counts every call, times one in 64.
class scope {
 public:
  explicit scope(stage s) noexcept : s_(s) {
    on_ = (local().calls[s]++ & 63) == 0;
    if (on_) t0_ = now_ticks();
  }
  ~scope() {
    if (on_) {
      auto& c = local();
      c.ticks[s_] += now_ticks() - t0_;
      ++c.sampled[s_];
    }
  }
  scope(const scope&) = delete;
  scope& operator=(const scope&) = delete;

 private:
  stage s_;
  bool on_ = false;
  std::uint64_t t0_ = 0;
};
inline void count(stage s, std::uint64_t frames, std::uint64_t bytes) noexcept {
  auto& c = local();
  c.frames[s] += frames;
  c.bytes[s] += bytes;
}
inline void reset() noexcept { local() = counters{}; }
inline void report(std::FILE* f) {
  const auto& c = local();
  const double k = ns_per_tick();
  std::fprintf(f, "%-15s %12s %12s %14s %10s\n", "stage", "calls", "frames", "bytes", "ns/call");
  for (int s = 0; s < n_stages; ++s) {
    if (!c.calls[s] && !c.frames[s]) continue;
    const double ns = c.sampled[s] ? double(c.ticks[s]) * k / double(c.sampled[s]) : 0.0;
    std::fprintf(f, "%-15s %12llu %12llu %14llu %10.1f\n", stage_names[s], (unsigned long long)c.calls[s],
                 (unsigned long long)c.frames[s], (unsigned long long)c.bytes[s], ns);
  }
}
#define NANOCRAFT_PROFILE_SCOPE(st) ::nanocraft::profile::scope nanocraft_profile_scope_(::nanocraft::profile::st)
#define NANOCRAFT_PROFILE_COUNT(st, fr, by) ::nanocraft::profile::count(::nanocraft::profile::st, (fr), (by))
#else
inline constexpr bool enabled = false;
inline counters& local() noexcept {
  static counters c;
  return c;
}
inline void reset() noexcept {}
inline void report(std::FILE* f) { std::fprintf(f, "nanocraft: profiling compiled out (define NANOCRAFT_PROFILE)\n"); }
#define NANOCRAFT_PROFILE_SCOPE(st) ((void)0)
#define NANOCRAFT_PROFILE_COUNT(st, fr, by) ((void)0)
#endif

}  // namespace nanocraft::profile

#endif  // NANOCRAFT_PROFILE_HPP_INCLUDED
