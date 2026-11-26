// SPDX-License-Identifier: Apache-2.0
// Independent oracles for the tests: a naive RFC 1071 checksum, a hand-written byte-by-byte frame
// builder that follows the RFCs / PRS_SOMEIP directly (shares no code with nanocraft or nanom), and
// checksum verifiers that parse a frame from scratch.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ref {

using bytes = std::vector<std::byte>;

/// RFC 1071, the obvious way: big-endian 16-bit words, 32-bit accumulator, fold at the end.
inline std::uint16_t naive_sum(std::span<const std::byte> b, std::uint32_t seed = 0) {
  std::uint32_t s = seed;
  for (std::size_t i = 0; i < b.size(); i += 2) {
    std::uint32_t w = std::uint32_t(std::uint8_t(b[i])) << 8;
    if (i + 1 < b.size()) w |= std::uint8_t(b[i + 1]);
    s += w;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
  }
  return std::uint16_t(s);
}
inline std::uint16_t naive_csum(std::span<const std::byte> b, std::uint32_t seed = 0) {
  return std::uint16_t(~naive_sum(b, seed));
}

inline void put8(bytes& v, unsigned x) { v.push_back(std::byte(x)); }
inline void put16(bytes& v, unsigned x) {
  put8(v, (x >> 8) & 0xff);
  put8(v, x & 0xff);
}
inline void put32(bytes& v, std::uint32_t x) {
  put16(v, x >> 16);
  put16(v, x & 0xffff);
}
inline unsigned get16(std::span<const std::byte> b, std::size_t o) {
  return (unsigned(std::uint8_t(b[o])) << 8) | std::uint8_t(b[o + 1]);
}
inline std::uint32_t get32(std::span<const std::byte> b, std::size_t o) {
  return (std::uint32_t(get16(b, o)) << 16) | get16(b, o + 2);
}
inline void set16(bytes& v, std::size_t o, unsigned x) {
  v[o] = std::byte((x >> 8) & 0xff);
  v[o + 1] = std::byte(x & 0xff);
}

struct vlan_tag {
  unsigned pcp = 0, dei = 0, vid = 0;
};

struct spec {
  std::array<std::uint8_t, 6> dst{}, src{};
  std::vector<vlan_tag> vlans;
  bool v6 = false;
  // IPv4
  unsigned dscp = 0, ecn = 0, ident = 0, flags = 0, frag = 0, ttl = 64;
  std::array<std::uint8_t, 4> src4{}, dst4{};
  // IPv6
  unsigned tclass = 0, flow = 0, hop = 64;
  std::array<std::uint8_t, 16> src6{}, dst6{};
  // UDP
  unsigned sport = 0, dport = 0;
  enum { csum_compute, csum_zero } udp_csum = csum_compute;
  // SOME/IP (+TP)
  bool someip = true;
  unsigned service = 0, method = 0, client = 0, session = 0, pver = 1, iver = 1, mtype = 2, rcode = 0;
  bool tp = false;
  std::uint32_t tp_offset_units = 0;
  bool tp_more = false;
  bytes payload;
};

/// Build the frame from the spec, from first principles.
inline bytes build(const spec& s) {
  bytes l4;  // UDP header + data
  bytes udp_data;
  if (s.someip) {
    const std::uint32_t len = 8 + (s.tp ? 4u : 0u) + std::uint32_t(s.payload.size());
    put16(udp_data, s.service);
    put16(udp_data, s.method);
    put32(udp_data, len);
    put16(udp_data, s.client);
    put16(udp_data, s.session);
    put8(udp_data, s.pver);
    put8(udp_data, s.iver);
    put8(udp_data, s.mtype | (s.tp ? 0x20u : 0u));
    put8(udp_data, s.rcode);
    if (s.tp) put32(udp_data, (s.tp_offset_units << 4) | (s.tp_more ? 1u : 0u));
  }
  udp_data.insert(udp_data.end(), s.payload.begin(), s.payload.end());
  const unsigned ulen = 8 + unsigned(udp_data.size());
  put16(l4, s.sport);
  put16(l4, s.dport);
  put16(l4, ulen);
  put16(l4, 0);
  l4.insert(l4.end(), udp_data.begin(), udp_data.end());
  // pseudo header
  bytes pseudo;
  if (!s.v6) {
    for (auto b : s.src4) put8(pseudo, b);
    for (auto b : s.dst4) put8(pseudo, b);
    put8(pseudo, 0);
    put8(pseudo, 17);
    put16(pseudo, ulen);
  } else {
    for (auto b : s.src6) put8(pseudo, b);
    for (auto b : s.dst6) put8(pseudo, b);
    put32(pseudo, ulen);
    put16(pseudo, 0);
    put8(pseudo, 0);
    put8(pseudo, 17);
  }
  if (s.udp_csum == spec::csum_compute) {
    bytes all = pseudo;
    all.insert(all.end(), l4.begin(), l4.end());
    unsigned c = naive_csum(all);
    if (c == 0) c = 0xffff;
    set16(l4, 6, c);
  }
  bytes ip;
  if (!s.v6) {
    put8(ip, 0x45);
    put8(ip, (s.dscp << 2) | s.ecn);
    put16(ip, 20 + unsigned(l4.size()));
    put16(ip, s.ident);
    put16(ip, (s.flags << 13) | s.frag);
    put8(ip, s.ttl);
    put8(ip, 17);
    put16(ip, 0);
    for (auto b : s.src4) put8(ip, b);
    for (auto b : s.dst4) put8(ip, b);
    set16(ip, 10, naive_csum(ip));
  } else {
    put32(ip, (6u << 28) | (s.tclass << 20) | s.flow);
    put16(ip, unsigned(l4.size()));
    put8(ip, 17);
    put8(ip, s.hop);
    for (auto b : s.src6) put8(ip, b);
    for (auto b : s.dst6) put8(ip, b);
  }
  bytes f;
  for (auto b : s.dst) put8(f, b);
  for (auto b : s.src) put8(f, b);
  for (const auto& v : s.vlans) {
    put16(f, 0x8100);
    put16(f, (v.pcp << 13) | (v.dei << 12) | v.vid);
  }
  put16(f, s.v6 ? 0x86dd : 0x0800);
  f.insert(f.end(), ip.begin(), ip.end());
  f.insert(f.end(), l4.begin(), l4.end());
  return f;
}

/// Parse an Ethernet frame from scratch and verify the IPv4 header checksum and the UDP checksum
/// (over the whole IP payload, which must be complete: no fragments). Returns false on mismatch.
struct verdict {
  bool parsed = false, ip_ok = false, udp_ok = false, udp_zero = false, lengths_ok = false;
};
inline verdict verify(std::span<const std::byte> f) {
  verdict v;
  std::size_t o = 12;
  if (f.size() < 14) return v;
  unsigned et = get16(f, o);
  o += 2;
  while (et == 0x8100 || et == 0x88a8) {
    if (f.size() < o + 4) return v;
    et = get16(f, o + 2);
    o += 4;
  }
  bytes pseudo;
  std::size_t l4 = 0, l4len = 0;
  if (et == 0x0800) {
    if (f.size() < o + 20) return v;
    const std::size_t ihl = (std::uint8_t(f[o]) & 0xf) * 4;
    const std::size_t tot = get16(f, o + 2);
    if (f.size() < o + tot || tot < ihl) return v;
    v.ip_ok = naive_sum(f.subspan(o, ihl)) == 0xffff;
    if (std::uint8_t(f[o + 9]) != 17) return v;
    for (int i = 12; i < 20; ++i) pseudo.push_back(f[o + i]);
    put8(pseudo, 0);
    put8(pseudo, 17);
    l4 = o + ihl;
    l4len = tot - ihl;
    put16(pseudo, unsigned(l4len));
  } else if (et == 0x86dd) {
    if (f.size() < o + 40) return v;
    v.ip_ok = true;
    const std::size_t plen = get16(f, o + 4);
    unsigned nh = std::uint8_t(f[o + 6]);
    l4 = o + 40;
    l4len = plen;
    if (nh == 44) {
      nh = std::uint8_t(f[l4]);
      l4 += 8;
      l4len -= 8;
    }
    if (nh != 17 || f.size() < l4 + l4len) return v;
    for (int i = 8; i < 40; ++i) pseudo.push_back(f[o + i]);
    put32(pseudo, std::uint32_t(l4len));
    put16(pseudo, 0);
    put8(pseudo, 0);
    put8(pseudo, 17);
  } else {
    return v;
  }
  v.parsed = true;
  const unsigned ulen = get16(f, l4 + 4);
  v.lengths_ok = ulen == l4len;
  if (get16(f, l4 + 6) == 0) {
    v.udp_zero = true;
    return v;
  }
  bytes all = pseudo;
  all.insert(all.end(), f.begin() + std::ptrdiff_t(l4), f.begin() + std::ptrdiff_t(l4 + l4len));
  v.udp_ok = naive_sum(all) == 0xffff;
  return v;
}

}  // namespace ref
