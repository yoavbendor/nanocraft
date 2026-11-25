// SPDX-License-Identifier: Apache-2.0
// Live transmit through an AF_PACKET TX ring (needs CAP_NET_RAW): frames are crafted in place in
// the kernel-shared ring, one send() per batch.
//   tx_ring [ifname] [frames]          e.g. sudo ./tx_ring lo 100000
#include <nanocraft/nanocraft.hpp>

#include <cstdio>
#include <cstdlib>

using namespace nanocraft::proto;

int main(int argc, char** argv) {
#if defined(__linux__)
  const char* ifname = argc > 1 ? argv[1] : "lo";
  const long frames = argc > 2 ? std::atol(argv[2]) : 100000;
  auto ring = nanocraft::tx_ring::open(ifname, {.frame_size = 2048, .frame_count = 1024});
  if (!ring) {
    std::fprintf(stderr, "tx_ring: %s\n", ring.error().c_str());
    return 77;
  }
  auto t = nanocraft::compile(eth{.dst = {0x01, 0x00, 0x5e, 0, 0, 1}, .src = {0x02, 0, 0, 0, 0, 1}} /
                              ipv4{.src = {10, 0, 0, 1}, .dst = {239, 0, 0, 1}} /
                              udp{.src_port = 30501, .dst_port = 30501} /
                              someip{.service_id = 0x1234, .method_id = 0x8001});
  std::array<std::byte, 64> payload{};
  for (long i = 0; i < frames; ++i) {
    t.set<"someip.session_id">(std::uint16_t(i % 0xffff + 1));
    while (!ring->write(t, payload)) ring->send(true);  // ring full: kick the kernel, wait
    if (i % 256 == 255) ring->send();                   // kick without waiting
  }
  ring->send(true);
  std::printf("sent %ld frames on %s\n", frames, ifname);
#else
  (void)argc, (void)argv;
  std::printf("Linux only\n");
#endif
}
