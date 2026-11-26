// SPDX-License-Identifier: Apache-2.0
// Linux TX: the TPACKET_V2 ring protocol over plain memory (always), then live on the loopback
// interface when AF_PACKET is permitted (CAP_NET_RAW): TX ring, sendmmsg with gathers, SO_TXTIME.
// Live frames are captured by an independent AF_PACKET receive socket and compared byte for byte.
// GCC 13 reports a bogus -Wstringop-overread inside std::set<std::vector<std::byte>>'s operator<.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wstringop-overread"
#endif
#include <nanocraft/nanocraft.hpp>

#include "check.hpp"

#if defined(__linux__)
#include <poll.h>

#include <set>

using namespace nanocraft::proto;

static constexpr std::uint16_t kMarker = 0x88b5;  // IEEE local experimental ethertype

static void test_ring_view() {
  constexpr std::size_t fs = 2048, n = 8;
  std::vector<std::byte> mem(fs * n + 64);
  auto* base = reinterpret_cast<std::byte*>((reinterpret_cast<std::uintptr_t>(mem.data()) + 63) & ~std::uintptr_t(63));
  nanocraft::tx_ring_view ring(base, fs, n);
  CHECK_EQ(nanocraft::tx_ring_view::data_offset, std::size_t(32));
  CHECK_EQ(ring.max_frame(), fs - 32);
  auto tm = nanocraft::compile(eth{.dst = {2, 0, 0, 0, 0, 1}, .src = {2, 0, 0, 0, 0, 2}} / ipv4{.src = {1, 1, 1, 1}} /
                               udp{.dst_port = 9} / someip{});
  std::vector<std::vector<std::byte>> sent;
  for (std::size_t i = 0; i < n; ++i) {
    tm.set<"someip.session_id">(i);
    auto pay = t::random_bytes(10 + i * 100);
    std::vector<std::byte> f(tm.frame_size(pay.size()));
    f.resize(tm.write(f, pay));
    CHECK(ring.write(tm, pay));
    sent.push_back(f);
  }
  CHECK(ring.acquire(60).empty());  // full
  CHECK(!ring.write(sent[0]));
  CHECK_EQ(ring.take_pending(), n);
  for (std::size_t i = 0; i < n; ++i) {
    auto* h = reinterpret_cast<tpacket2_hdr*>(ring.slot(i));
    CHECK_EQ(ring.status(i), std::uint32_t(TP_STATUS_SEND_REQUEST));
    CHECK_EQ(std::size_t(h->tp_len), sent[i].size());
    CHECK_BYTES(std::span<const std::byte>(ring.slot(i) + 32, h->tp_len), sent[i]);
  }
  // the "kernel" releases slot 0 (sent) and slot 1 (wrong format): the ring wraps to slot 0 only
  reinterpret_cast<tpacket2_hdr*>(ring.slot(0))->tp_status = TP_STATUS_AVAILABLE;
  reinterpret_cast<tpacket2_hdr*>(ring.slot(1))->tp_status = TP_STATUS_WRONG_FORMAT;
  nanocraft::gather g;
  g.add(sent[2]);
  CHECK(ring.write(g));
  CHECK_BYTES(std::span<const std::byte>(ring.slot(0) + 32, sent[2].size()), sent[2]);
  CHECK(ring.write(sent[3]));
  CHECK_EQ(ring.cursor(), std::size_t(2));
  CHECK(!ring.write(sent[3]));
  // oversized
  reinterpret_cast<tpacket2_hdr*>(ring.slot(2))->tp_status = TP_STATUS_AVAILABLE;
  CHECK(ring.acquire(fs).empty());
}

// An independent receiver on lo: every frame carrying kMarker.
struct rx {
  int fd = -1;
  explicit rx(int ifindex) {
    fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) return;
    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof sll) < 0) {
      ::close(fd);
      fd = -1;
    }
    int big = 8 << 20;
    if (fd >= 0) ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
  }
  ~rx() {
    if (fd >= 0) ::close(fd);
  }
  // Receive until every wanted frame was seen (or timeout); returns how many were seen.
  std::size_t collect(const std::set<std::vector<std::byte>>& want, int timeout_ms = 2000) {
    std::set<std::vector<std::byte>> got;
    std::vector<std::byte> buf(65536);
    while (got.size() < want.size()) {
      pollfd p{fd, POLLIN, 0};
      if (::poll(&p, 1, timeout_ms) <= 0) break;
      const ssize_t r = ::recv(fd, buf.data(), buf.size(), 0);
      if (r < 14) continue;
      if (std::uint8_t(buf[12]) != (kMarker >> 8) || std::uint8_t(buf[13]) != (kMarker & 0xff)) continue;
      std::vector<std::byte> f(buf.begin(), buf.begin() + r);
      if (want.count(f)) got.insert(std::move(f));
    }
    return got.size();
  }
};

static bool live_tests() {
  int idx = 0;
  const int probe = nanocraft::open_packet_socket("lo", &idx);
  if (probe < 0) {
    std::printf("SKIP live TX: AF_PACKET not permitted (%s)\n", std::strerror(-probe));
    return false;
  }
  ::close(probe);
  rx r(idx);
  if (r.fd < 0) {
    std::printf("SKIP live TX: cannot open a receive socket\n");
    return false;
  }
  auto tm = nanocraft::compile(nanocraft::stack(eth{.dst = {2, 0, 0, 0, 0, 1}, .src = {2, 0, 0, 0, 0, 2}, .type = kMarker}));

  // 1. TX ring, frames crafted in place
  {
    auto ring = nanocraft::tx_ring::open("lo", {.frame_size = 2048, .frame_count = 64});
    CHECK_MSG(bool(ring), ring ? "" : ring.error());
    if (ring) {
      std::set<std::vector<std::byte>> sent;
      for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 50; ++i) {
          auto pay = t::random_bytes(46 + t::rnd(0, 1400));
          std::vector<std::byte> f(tm.frame_size(pay.size()));
          f.resize(tm.write(f, pay));
          sent.insert(f);
          while (!ring->write(tm, pay)) CHECK(ring->send(true) >= 0);
        }
        CHECK(ring->send(true) >= 0);
      }
      const std::size_t hit = r.collect(sent);
      CHECK_EQ(hit, sent.size());
      std::printf("TX ring on lo: %zu/%zu frames captured byte-identical\n", hit, sent.size());
    }
  }
  // 2. sendmmsg with gathers (SOME/IP-TP style split header/payload) + SO_TXTIME
  {
    const int fd = nanocraft::open_packet_socket("lo");
    CHECK(fd >= 0);
    nanocraft::mmsg_sender tx(fd, 16);
    std::vector<std::vector<std::byte>> hdrs, pays;
    std::set<std::vector<std::byte>> sent;
    for (int i = 0; i < 40; ++i) {
      hdrs.emplace_back(tm.header().begin(), tm.header().end());
      pays.push_back(t::random_bytes(46 + t::rnd(0, 1000)));
    }
    for (int i = 0; i < 40; ++i) {
      nanocraft::gather g;
      g.add(hdrs[std::size_t(i)]);
      g.add(pays[std::size_t(i)]);
      std::vector<std::byte> f(g.size());
      g.copy_to(f);
      sent.insert(f);
      CHECK(tx.add(g));
    }
    CHECK_EQ(tx.flush(), 40 % 16);
    CHECK_EQ(tx.sent(), std::uint64_t(40));
    const std::size_t hit = r.collect(sent);
    CHECK_EQ(hit, sent.size());
    std::printf("sendmmsg on lo: %zu/%zu gathers captured byte-identical\n", hit, sent.size());
    // SO_TXTIME: launch time "now" on CLOCK_MONOTONIC (no ETF qdisc on lo: sent immediately)
    if (nanocraft::enable_txtime(fd, CLOCK_MONOTONIC)) {
      timespec ts{};
      ::clock_gettime(CLOCK_MONOTONIC, &ts);
      const std::uint64_t now = std::uint64_t(ts.tv_sec) * 1000000000ull + std::uint64_t(ts.tv_nsec);
      auto pay = t::random_bytes(100);
      std::vector<std::byte> f(tm.frame_size(pay.size()));
      f.resize(tm.write(f, pay));
      CHECK(tx.add(f, now + 1000));
      const int sentn = tx.flush();
      if (sentn == 1) {
        CHECK_EQ(r.collect({f}), std::size_t(1));
        std::printf("SO_TXTIME on lo: frame with launch time sent and captured\n");
      } else {
        std::printf("SKIP SO_TXTIME send: %s\n", std::strerror(-sentn));
      }
    } else {
      std::printf("SKIP SO_TXTIME: setsockopt refused (%s)\n", std::strerror(errno));
    }
    ::close(fd);
  }
  return true;
}

static void test_tx_edge_cases() {
  // Default / invalid tx_ring_view guards
  {
    nanocraft::tx_ring_view empty;
    CHECK_EQ(empty.max_frame(), std::size_t(0));
    CHECK(empty.acquire(0).empty());
    CHECK(empty.acquire(10).empty());
    std::array<std::byte, 4> d{};
    CHECK(!empty.write(d));

    std::array<std::byte, 64> small_mem{};
    nanocraft::tx_ring_view tiny(small_mem.data(), 16, 4);
    CHECK_EQ(tiny.max_frame(), std::size_t(0));
    CHECK(tiny.acquire(0).empty());

    nanocraft::tx_ring_view zero_n(small_mem.data(), 2048, 0);
    CHECK_EQ(zero_n.max_frame(), std::size_t(0));
    CHECK(zero_n.acquire(0).empty());
  }
  // tx_ring_view::write(tmpl, pay) rejects !tmpl.ok() without committing
  {
    constexpr std::size_t fs = 2048, n = 4;
    std::vector<std::byte> mem(fs * n + 64);
    auto* base = reinterpret_cast<std::byte*>((reinterpret_cast<std::uintptr_t>(mem.data()) + 63) & ~std::uintptr_t(63));
    nanocraft::tx_ring_view ring(base, fs, n);
    auto bad = nanocraft::compile(eth{} / ipv4{.total_length = 99} / udp{});
    CHECK(!bad.ok());
    std::array<std::byte, 8> pay{};
    CHECK(!ring.write(bad, pay));
    CHECK_EQ(ring.cursor(), std::size_t(0));
    CHECK_EQ(ring.take_pending(), std::size_t(0));
    // Empty span with nullptr data writes cleanly without memcpy UB
    CHECK(ring.write(std::span<const std::byte>(static_cast<const std::byte*>(nullptr), 0)));
    CHECK_EQ(ring.cursor(), std::size_t(1));
  }
  // tx_ring::open validates options before touching socket
  {
    auto r1 = nanocraft::tx_ring::open("lo", {.frame_size = 16, .frame_count = 4});
    CHECK(!r1);
    CHECK_EQ(r1.err, EINVAL);
    auto r2 = nanocraft::tx_ring::open("lo", {.frame_size = 2048, .frame_count = 0});
    CHECK(!r2);
    CHECK_EQ(r2.err, EINVAL);
    auto r3 = nanocraft::tx_ring::open("lo", {.frame_size = std::size_t(1) << 33, .frame_count = 4});
    CHECK(!r3);
    CHECK_EQ(r3.err, EINVAL);
  }
  // mmsg_sender: non-copyable/non-movable, clamped dst_len, aligned cmsg, empty gather, error flush
  {
    static_assert(!std::is_copy_constructible_v<nanocraft::mmsg_sender>);
    static_assert(!std::is_move_constructible_v<nanocraft::mmsg_sender>);
    nanocraft::mmsg_sender tx(-1, 4);
    tx.set_destination(nullptr, 100);
    sockaddr_storage ss{};
    tx.set_destination(&ss, socklen_t(sizeof(ss) + 64));  // clamped safely
    nanocraft::gather empty_g;
    CHECK(tx.add(empty_g));  // 0 chunks -> no memcpy UB
    std::array<std::byte, 8> frame{};
    CHECK(tx.add(frame, std::uint64_t{123456789}));  // exercises alignas(cmsghdr) cmsg_slot under UBSan
    CHECK_EQ(tx.queued(), std::size_t(2));
    CHECK(tx.flush() < 0);  // EBADF on fd = -1
    CHECK_EQ(tx.queued(), std::size_t(0));
    CHECK_EQ(tx.sent(), std::uint64_t(0));
  }
}

int main() {
  test_ring_view();
  test_tx_edge_cases();
  live_tests();
  return t::done("test_linux_tx");
}
#else
int main() {
  std::printf("SKIP: not Linux\n");
  return 77;
}
#endif
