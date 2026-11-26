// SPDX-License-Identifier: Apache-2.0
// Reading and crafting must agree: read a crafted frame back with nanowire's reader (packet::parse
// + views, the same protocol definitions nanocraft's layers come from) and compare every field
// with what the test meant (a ref::spec), plus nanowire's own checksum verification.
#pragma once

#include "check.hpp"
#include "reference.hpp"

#include <nanowire/nanowire.hpp>

#include <algorithm>

namespace nw {

/// The UDP / TCP checksum of a parsed (unfragmented) packet, verified by nanowire.
inline bool l4_ok(const nanowire::packet& p) {
  const auto l3 = p.l3_bytes();
  const std::size_t l4 = p.l4_offset() - p.l3_offset();
  if (l4 > l3.size()) return false;
  return nanowire::l4_checksum_ok(l3, p.ip_protocol(), l3.subspan(l4));
}

/// Every field of `f` as nanowire reads it == the spec (an unfragmented SOME/IP-over-UDP frame).
inline void check_read(std::span<const std::byte> f, const ref::spec& s) {
  const auto p = nanowire::packet::parse(f);
  CHECK(p.eth().has_value());
  if (!p.eth()) return;
  CHECK(p.eth()->dst() == s.dst);
  CHECK(p.eth()->src() == s.src);
  CHECK_EQ(p.vlan_count(), s.vlans.size());
  for (std::size_t i = 0; i < std::min(p.vlan_count(), s.vlans.size()); ++i) {
    CHECK_EQ(unsigned(p.vlan(i).pcp()), s.vlans[i].pcp);
    CHECK_EQ(unsigned(p.vlan(i).dei()), s.vlans[i].dei);
    CHECK_EQ(unsigned(p.vlan(i).vid()), s.vlans[i].vid);
  }
  CHECK(!p.is_malformed());
  if (!s.v6) {
    const auto ip = p.ipv4();
    CHECK(ip.has_value());
    if (!ip) return;
    CHECK(ip->checksum_ok());
    CHECK_EQ(unsigned(ip->dscp()), s.dscp);
    CHECK_EQ(unsigned(ip->ecn()), s.ecn);
    CHECK_EQ(unsigned(ip->identification()), s.ident);
    CHECK_EQ(unsigned(ip->df()), (s.flags >> 1) & 1);
    CHECK_EQ(unsigned(ip->mf()), s.flags & 1);
    CHECK_EQ(unsigned(ip->frag_offset()), s.frag);
    CHECK_EQ(unsigned(ip->ttl()), s.ttl);
    CHECK(ip->src() == s.src4);
    CHECK(ip->dst() == s.dst4);
    CHECK_EQ(std::size_t(ip->total_length()), f.size() - p.l3_offset());
  } else {
    const auto ip = p.ipv6();
    CHECK(ip.has_value());
    if (!ip) return;
    CHECK_EQ(unsigned(ip->traffic_class()), s.tclass);
    CHECK_EQ(unsigned(ip->flow_label()), s.flow);
    CHECK_EQ(unsigned(ip->hop_limit()), s.hop);
    CHECK(ip->src() == s.src6);
    CHECK(ip->dst() == s.dst6);
    CHECK_EQ(std::size_t(ip->payload_length()) + 40, f.size() - p.l3_offset());
  }
  const auto u = p.udp();
  CHECK(u.has_value());
  if (!u) return;
  CHECK_EQ(unsigned(u->src_port()), s.sport);
  CHECK_EQ(unsigned(u->dst_port()), s.dport);
  CHECK_EQ(std::size_t(u->length()), f.size() - p.l4_offset());
  if (s.udp_csum == ref::spec::csum_zero) CHECK_EQ(unsigned(u->checksum()), 0u);
  else CHECK(l4_ok(p));
  if (!s.someip) {
    CHECK_BYTES(p.payload(), std::span<const std::byte>(s.payload));
    return;
  }
  const auto m = p.someip();
  CHECK(m.has_value());
  if (!m) return;
  CHECK_EQ(unsigned(m->service_id()), s.service);
  CHECK_EQ(unsigned(m->method_id()), s.method);
  CHECK_EQ(unsigned(m->client_id()), s.client);
  CHECK_EQ(unsigned(m->session_id()), s.session);
  CHECK_EQ(unsigned(m->protocol_version()), s.pver);
  CHECK_EQ(unsigned(m->interface_version()), s.iver);
  CHECK_EQ(unsigned(m->message_type_base()), s.mtype & ~0x20u);
  CHECK_EQ(m->is_tp(), s.tp);
  CHECK_EQ(unsigned(m->return_code()), s.rcode);
  CHECK(!m->truncated());
  CHECK_EQ(m->message_size(), p.payload().size());
  auto body = m->payload();
  if (s.tp) {
    const auto tp = m->tp();
    CHECK(tp.has_value());
    if (!tp) return;
    CHECK_EQ(tp->offset_units(), s.tp_offset_units);
    CHECK_EQ(tp->more(), s.tp_more);
    body = tp->segment();
  }
  CHECK_BYTES(body, std::span<const std::byte>(s.payload));
}

/// The bytes of a completed nanowire reassembly, concatenated.
template <class Result>
inline ref::bytes join(const Result& r) {
  ref::bytes out;
  for (auto p : r.part_list) out.insert(out.end(), p.begin(), p.end());
  return out;
}

inline nanowire::reassembly_config roomy(nanowire::reassembly_config c) {
  c.max_fragments = 8192;
  c.max_datagram = 1u << 20;
  return c;
}

/// A reassembled UDP datagram (UDP header + data) read by nanowire: ports, length, the checksum
/// against the pseudo header of `l3` (an IP header of the datagram), SOME/IP fields and payload.
inline void check_datagram(std::span<const std::byte> l3, std::span<const std::byte> dg, const ref::spec& s) {
  const auto u = nanowire::udp_view::parse(dg);
  CHECK(u.has_value());
  if (!u) return;
  CHECK_EQ(unsigned(u->src_port()), s.sport);
  CHECK_EQ(unsigned(u->dst_port()), s.dport);
  CHECK_EQ(std::size_t(u->length()), dg.size());
  CHECK(nanowire::l4_checksum_ok(l3, nanowire::ip_proto::udp, dg));
  const auto m = nanowire::someip_view::parse(dg.subspan(8));
  CHECK(m.has_value());
  if (!m) return;
  CHECK_EQ(unsigned(m->service_id()), s.service);
  CHECK_EQ(unsigned(m->method_id()), s.method);
  CHECK_EQ(unsigned(m->session_id()), s.session);
  CHECK_EQ(m->message_size(), dg.size() - 8);
  CHECK_BYTES(m->payload(), std::span<const std::byte>(s.payload));
}

}  // namespace nw
