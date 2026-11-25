// SPDX-License-Identifier: Apache-2.0
// Quick start: a SOME/IP notification template, 1M frames streamed to a pcapng file.
//   someip_to_pcapng [out.pcapng] [frames]
#include <nanocraft/nanocraft.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>

using namespace nanocraft::proto;

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : "someip.pcapng";
  const long frames = argc > 2 ? std::atol(argv[2]) : 1'000'000;

  // Describe the stack once. Lengths, next-protocol fields and checksums are filled in.
  auto t = nanocraft::compile(
      eth{.dst = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, .src = {0x02, 0, 0, 0, 0, 0x01}} /
      vlan{.pcp = {5}, .vid = {100}} /
      ipv4{.ttl = 8, .src = {10, 0, 0, 1}, .dst = {239, 0, 0, 1}} /
      udp{.src_port = 30501, .dst_port = 30501} /
      someip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 0x0001});

  std::FILE* f = std::fopen(path, "wb");
  if (!f) return 1;
  nanocraft::pcapng_writer w(nanocraft::output::file(f), 4 << 20);
  const auto ifc = w.add_interface({.name = "veth0", .tsresol = 9});

  std::array<std::byte, 32> payload{};  // e.g. a serialized sensor sample
  const auto t0 = std::chrono::steady_clock::now();
  std::uint64_t ts = 1'700'000'000'000'000'000ull;
  for (long i = 0; i < frames; ++i) {
    payload[0] = std::byte(i);
    t.set<"someip.session_id">(std::uint16_t(i % 0xffff + 1));  // checksums follow incrementally
    t.set<"ipv4.identification">(std::uint16_t(i));
    w.write(ifc, ts += 1'000'000, t, payload);                  // crafted in the writer's buffer
  }
  w.flush();
  const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::fclose(f);
  std::printf("%ld frames -> %s in %.3f s (%.1f ns/frame, %.2f GB/s)\n", frames, path, s, s * 1e9 / double(frames),
              double(w.bytes()) / s / 1e9);
}
