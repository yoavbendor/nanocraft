// SPDX-License-Identifier: Apache-2.0
// nanocraft/linux_tx.hpp — live transmit on Linux: AF_PACKET TX ring (zero copy), sendmmsg batches,
// SO_TXTIME pacing. Needs CAP_NET_RAW for packet sockets. Compiles to nothing off Linux.
//
// TX ring (TPACKET_V2): frames are crafted IN the kernel-shared ring, then one send() kicks the
// kernel to transmit every frame marked ready:
//
//   auto ring = nanocraft::tx_ring::open("eth0", {.frame_size = 2048, .frame_count = 1024});
//   if (!ring) fail(ring.error());
//   for (...) {
//     tmpl.set<"someip.session_id">(i);
//     while (!ring->write(tmpl, payload)) ring->send();   // ring full: kick and retry
//   }
//   ring->send(true);                                     // kick and wait until sent
//
// tx_ring_view is the ring protocol over any memory (slot headers, status hand-off with
// release/acquire ordering) — unit-testable without a socket.
//
// sendmmsg batches gathers (each chunk is an iovec: no flattening), optionally with a per-message
// SCM_TXTIME launch time after enable_txtime() (pair with an ETF qdisc for hardware pacing):
//
//   int fd = nanocraft::open_packet_socket("eth0");            // or any UDP / raw socket
//   nanocraft::mmsg_sender tx(fd, 64);
//   tx.set_destination(&sll, sizeof sll);                       // optional (unbound sockets)
//   for (const auto& g : seg.segment(msg)) tx.add(g);           // flushes every 64 messages
//   tx.flush();
#ifndef NANOCRAFT_LINUX_TX_HPP_INCLUDED
#define NANOCRAFT_LINUX_TX_HPP_INCLUDED

#include "gather.hpp"
#include "profile.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <arpa/inet.h>
#include <cerrno>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_TXTIME
#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME
#endif

namespace nanocraft {

static_assert(sizeof(chunk) == sizeof(iovec) && offsetof(chunk, base) == offsetof(iovec, iov_base) &&
                  offsetof(chunk, len) == offsetof(iovec, iov_len),
              "nanocraft::chunk must be layout-compatible with iovec");

// ---------------------------------------------------------------------------------------------
// TX ring protocol over any memory
// ---------------------------------------------------------------------------------------------

/// The TPACKET_V2 TX ring protocol over a memory block of frame_count slots of frame_size bytes.
class tx_ring_view {
 public:
  /// Offset of frame data inside a slot (the kernel's default for TPACKET_V2 without TX_HAS_OFF).
  static constexpr std::size_t data_offset = TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

  tx_ring_view() = default;
  tx_ring_view(std::byte* mem, std::size_t frame_size, std::size_t frame_count) noexcept
      : mem_(mem), fsz_(frame_size), n_(frame_count) {}

  std::size_t frame_size() const noexcept { return fsz_; }
  std::size_t frame_count() const noexcept { return n_; }
  std::size_t max_frame() const noexcept { return (!mem_ || n_ == 0 || fsz_ <= data_offset) ? 0 : fsz_ - data_offset; }
  std::size_t cursor() const noexcept { return cur_; }

  /// The data area (len bytes) of the next free slot, or empty if the ring is full there.
  std::span<std::byte> acquire(std::size_t len) noexcept {
    if (!mem_ || n_ == 0 || fsz_ <= data_offset || len > fsz_ - data_offset) return {};
    const std::uint32_t s = status(cur_);
    if (s != TP_STATUS_AVAILABLE && s != TP_STATUS_WRONG_FORMAT) return {};
    return {slot(cur_) + data_offset, len};
  }
  /// Hand the acquired slot to the kernel with the frame's real length; advance.
  void commit(std::size_t len) noexcept {
    auto* h = reinterpret_cast<tpacket2_hdr*>(slot(cur_));
    h->tp_len = std::uint32_t(len);
    h->tp_snaplen = std::uint32_t(len);
    std::atomic_ref<std::uint32_t>(h->tp_status).store(TP_STATUS_SEND_REQUEST, std::memory_order_release);
    cur_ = cur_ + 1 == n_ ? 0 : cur_ + 1;
    ++pending_;
  }
  bool write(std::span<const std::byte> frame) noexcept {
    auto s = acquire(frame.size());
    if (!s.data()) return false;
    if (!frame.empty()) std::memcpy(s.data(), frame.data(), frame.size());
    commit(frame.size());
    return true;
  }
  bool write(const gather& g) noexcept {
    auto s = acquire(g.size());
    if (!s.data()) return false;
    g.copy_to(s);
    commit(g.size());
    return true;
  }
  /// Craft a template frame in place in the ring slot.
  template <class T>
  bool write(T& tmpl, std::span<const std::byte> payload) noexcept {
    auto s = acquire(tmpl.frame_size(payload.size()));
    if (!s.data()) return false;
    const std::size_t len = tmpl.write(s, payload);
    if (len == 0) return false;
    commit(len);
    return true;
  }

  std::uint32_t status(std::size_t i) const noexcept {
    auto* h = reinterpret_cast<tpacket2_hdr*>(slot(i));
    return std::atomic_ref<std::uint32_t>(h->tp_status).load(std::memory_order_acquire);
  }
  std::byte* slot(std::size_t i) const noexcept { return mem_ + i * fsz_; }
  /// Frames committed since the last take_pending().
  std::size_t take_pending() noexcept { return std::exchange(pending_, 0); }

 private:
  std::byte* mem_ = nullptr;
  std::size_t fsz_ = 0, n_ = 0, cur_ = 0, pending_ = 0;
};

// ---------------------------------------------------------------------------------------------
// sockets
// ---------------------------------------------------------------------------------------------

/// An AF_PACKET SOCK_RAW socket bound to ifname (all protocols); -errno on failure.
inline int open_packet_socket(const char* ifname, int* ifindex_out = nullptr) {
  const int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  const unsigned idx = ::if_nametoindex(ifname);
  if (idx == 0) {
    const int e = errno;
    ::close(fd);
    return -e;
  }
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = 0;  // transmit only: receive nothing
  sll.sll_ifindex = int(idx);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof sll) < 0) {
    const int e = errno;
    ::close(fd);
    return -e;
  }
  if (ifindex_out) *ifindex_out = int(idx);
  return fd;
}

/// Enable SO_TXTIME on fd (launch times via SCM_TXTIME; CLOCK_TAI for the ETF qdisc).
inline bool enable_txtime(int fd, clockid_t clock = CLOCK_TAI, bool deadline_mode = false, bool report_errors = false) {
  sock_txtime t{};
  t.clockid = clock;
  t.flags = (deadline_mode ? SOF_TXTIME_DEADLINE_MODE : 0) | (report_errors ? SOF_TXTIME_REPORT_ERRORS : 0);
  return ::setsockopt(fd, SOL_SOCKET, SO_TXTIME, &t, sizeof t) == 0;
}

struct tx_ring_options {
  std::size_t frame_size = 2048;   ///< power of two >= TPACKET_ALIGNMENT, divides block_size
  std::size_t frame_count = 512;
  std::size_t block_size = 1 << 16;
  bool qdisc_bypass = false;       ///< PACKET_QDISC_BYPASS: straight to the driver
};

/// An AF_PACKET socket with a mapped TPACKET_V2 TX ring.
class tx_ring {
 public:
  struct result;
  static result open(const char* ifname, const tx_ring_options& o = {});

  tx_ring(tx_ring&& o) noexcept { *this = std::move(o); }
  tx_ring& operator=(tx_ring&& o) noexcept {
    if (this != &o) {
      close();
      fd_ = std::exchange(o.fd_, -1);
      map_ = std::exchange(o.map_, nullptr);
      map_len_ = std::exchange(o.map_len_, 0);
      view_ = std::exchange(o.view_, {});
    }
    return *this;
  }
  ~tx_ring() { close(); }

  int fd() const noexcept { return fd_; }
  tx_ring_view& view() noexcept { return view_; }
  std::span<std::byte> acquire(std::size_t len) noexcept { return view_.acquire(len); }
  void commit(std::size_t len) noexcept { view_.commit(len); }
  bool write(std::span<const std::byte> f) noexcept { return view_.write(f); }
  bool write(const gather& g) noexcept { return view_.write(g); }
  template <class T>
  bool write(T& tmpl, std::span<const std::byte> payload) noexcept {
    return view_.write(tmpl, payload);
  }
  /// Ask the kernel to transmit all committed frames. wait=false returns at once (MSG_DONTWAIT);
  /// wait=true blocks until the ring is drained. Returns bytes queued or -errno.
  long send(bool wait = false) noexcept {
    NANOCRAFT_PROFILE_SCOPE(tx);
    const std::size_t n = view_.take_pending();
    (void)n;
    NANOCRAFT_PROFILE_COUNT(tx, n, 0);
    for (;;) {
      const ssize_t r = ::send(fd_, nullptr, 0, wait ? 0 : MSG_DONTWAIT);
      if (r >= 0) return long(r);
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == ENOBUFS) return 0;
      return -long(errno);
    }
  }

 private:
  tx_ring() = default;
  void close() noexcept {
    if (map_) ::munmap(map_, map_len_);
    if (fd_ >= 0) ::close(fd_);
    map_ = nullptr;
    map_len_ = 0;
    fd_ = -1;
    view_ = {};
  }
  int fd_ = -1;
  void* map_ = nullptr;
  std::size_t map_len_ = 0;
  tx_ring_view view_{};
};

/// open() result: the ring, or errno + which step failed.
struct tx_ring::result {
  std::optional<tx_ring> ring;
  int err = 0;
  const char* step = "";
  explicit operator bool() const noexcept { return ring.has_value(); }
  tx_ring* operator->() noexcept { return &*ring; }
  tx_ring& operator*() noexcept { return *ring; }
  std::string error() const { return std::string(step) + ": " + std::strerror(err); }
};

inline tx_ring::result tx_ring::open(const char* ifname, const tx_ring_options& o) {
  result r;
  auto failed = [&](const char* step, int e) {
    r.step = step;
    r.err = e;
    return std::move(r);
  };
  if (o.frame_size < tx_ring_view::data_offset || o.frame_count == 0 ||
      o.frame_size > std::numeric_limits<unsigned>::max() ||
      o.block_size > std::numeric_limits<unsigned>::max())
    return failed("tx_ring_options", EINVAL);
  const std::size_t block_size = std::max(o.block_size, o.frame_size);
  const std::size_t per_block = block_size / o.frame_size;
  if (per_block == 0) return failed("tx_ring_options", EINVAL);
  const std::size_t block_nr = (o.frame_count - 1) / per_block + 1;
  if (block_nr > std::numeric_limits<unsigned>::max() ||
      block_nr > std::numeric_limits<unsigned>::max() / per_block ||
      block_nr > std::numeric_limits<std::size_t>::max() / block_size)
    return failed("tx_ring_options", EINVAL);
  tx_ring t;
  int idx = 0;
  t.fd_ = open_packet_socket(ifname, &idx);
  if (t.fd_ < 0) {
    const int e = -t.fd_;
    t.fd_ = -1;
    return failed("socket(AF_PACKET)", e);
  }
  int v = TPACKET_V2;
  if (::setsockopt(t.fd_, SOL_PACKET, PACKET_VERSION, &v, sizeof v) < 0) return failed("PACKET_VERSION", errno);
  if (o.qdisc_bypass) {
    int one = 1;
    (void)::setsockopt(t.fd_, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof one);
  }
  tpacket_req req{};
  req.tp_frame_size = unsigned(o.frame_size);
  req.tp_block_size = unsigned(block_size);
  req.tp_block_nr = unsigned(block_nr);
  req.tp_frame_nr = unsigned(block_nr * per_block);
  if (::setsockopt(t.fd_, SOL_PACKET, PACKET_TX_RING, &req, sizeof req) < 0) return failed("PACKET_TX_RING", errno);
  t.map_len_ = std::size_t(req.tp_block_size) * req.tp_block_nr;
  void* m = ::mmap(nullptr, t.map_len_, PROT_READ | PROT_WRITE, MAP_SHARED, t.fd_, 0);
  if (m == MAP_FAILED) return failed("mmap", errno);
  t.map_ = m;
  t.view_ = tx_ring_view(static_cast<std::byte*>(m), req.tp_frame_size, req.tp_frame_nr);
  r.ring.emplace(std::move(t));
  return r;
}

// ---------------------------------------------------------------------------------------------
// sendmmsg batches
// ---------------------------------------------------------------------------------------------

/// Batches gathers into one sendmmsg() call per `batch` messages.
class mmsg_sender {
 public:
  explicit mmsg_sender(int fd, std::size_t batch = 64)
      : fd_(fd), n_(batch ? batch : 1), msgs_(n_), iov_(n_ * gather::max_chunks), ctl_(n_) {}
  mmsg_sender(const mmsg_sender&) = delete;
  mmsg_sender& operator=(const mmsg_sender&) = delete;
  mmsg_sender(mmsg_sender&&) = delete;
  mmsg_sender& operator=(mmsg_sender&&) = delete;

  /// Destination for unconnected sockets (copied).
  void set_destination(const void* addr, socklen_t len) {
    if (!addr || len == 0) {
      dst_len_ = 0;
      return;
    }
    dst_len_ = std::min<socklen_t>(len, sizeof dst_);
    std::memcpy(&dst_, addr, dst_len_);
  }

  /// Queue a frame (its chunks must stay valid until flush). txtime_ns: SCM_TXTIME launch time.
  bool add(const gather& g, std::optional<std::uint64_t> txtime_ns = {}) {
    if (used_ == n_ && flush() < 0) return false;
    mmsghdr& m = msgs_[used_];
    m = mmsghdr{};
    iovec* iv = &iov_[used_ * gather::max_chunks];
    if (g.count > 0) std::memcpy(iv, g.chunks.data(), sizeof(iovec) * g.count);
    m.msg_hdr.msg_iov = iv;
    m.msg_hdr.msg_iovlen = g.count;
    if (dst_len_) {
      m.msg_hdr.msg_name = &dst_;
      m.msg_hdr.msg_namelen = dst_len_;
    }
    if (txtime_ns) {
      char* c = ctl_[used_].bytes;
      std::memset(c, 0, CMSG_SPACE(sizeof(std::uint64_t)));
      m.msg_hdr.msg_control = c;
      m.msg_hdr.msg_controllen = CMSG_SPACE(sizeof(std::uint64_t));
      cmsghdr* cm = CMSG_FIRSTHDR(&m.msg_hdr);
      cm->cmsg_level = SOL_SOCKET;
      cm->cmsg_type = SCM_TXTIME;
      cm->cmsg_len = CMSG_LEN(sizeof(std::uint64_t));
      const std::uint64_t t = *txtime_ns;
      std::memcpy(CMSG_DATA(cm), &t, sizeof t);
    }
    ++used_;
    return true;
  }
  bool add(std::span<const std::byte> frame, std::optional<std::uint64_t> txtime_ns = {}) {
    gather g;
    g.add(frame);
    return add(g, txtime_ns);
  }
  /// Send everything queued. Returns messages sent or -errno (unsent messages are dropped).
  int flush() {
    NANOCRAFT_PROFILE_SCOPE(tx);
    std::size_t off = 0;
    while (off < used_) {
      const int r = ::sendmmsg(fd_, msgs_.data() + off, unsigned(used_ - off), 0);
      if (r < 0) {
        if (errno == EINTR) continue;
        const int e = errno;
        NANOCRAFT_PROFILE_COUNT(tx, off, 0);
        sent_ += off;
        used_ = 0;
        return -e;
      }
      if (r == 0) break;
      off += std::size_t(r);
    }
    NANOCRAFT_PROFILE_COUNT(tx, off, 0);
    used_ = 0;
    sent_ += off;
    return int(off);
  }
  std::size_t queued() const noexcept { return used_; }
  std::uint64_t sent() const noexcept { return sent_; }

 private:
  struct alignas(cmsghdr) cmsg_slot {
    char bytes[CMSG_SPACE(sizeof(std::uint64_t))];
  };
  int fd_;
  std::size_t n_;
  std::vector<mmsghdr> msgs_;
  std::vector<iovec> iov_;
  std::vector<cmsg_slot> ctl_;
  sockaddr_storage dst_{};
  socklen_t dst_len_ = 0;
  std::size_t used_ = 0;
  std::uint64_t sent_ = 0;
};

}  // namespace nanocraft

#endif  // __linux__

#endif  // NANOCRAFT_LINUX_TX_HPP_INCLUDED
