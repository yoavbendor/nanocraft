// SPDX-License-Identifier: Apache-2.0
// nanocraft/detail/proto_stub.hpp — MINIMAL LAYER DESCRIPTIONS, TO BE REPLACED BY NANOWIRE'S BUILDERS.
//
// =================================================================================================
//  TO BE REPLACED BY nanowire's per-protocol builders. This is the ONLY file in nanocraft that knows
//  any protocol. It exists so the protocol-independent engine (frame_template.hpp, segment.hpp,
//  the sinks) is usable and testable today. The seam is nanocraft::layer_info<L> (layer.hpp): once
//  nanowire provides described header structs + layer_info specializations for its builders, this
//  header is deleted and nanocraft/nanocraft.hpp includes nanowire's instead. Field names here
//  follow nanom_shark's (service_id, session_id, total_length, ...) so patch paths should survive.
// =================================================================================================
//
// Layers (namespace nanocraft::proto), each a NANOM_DESCRIBE'd wire struct with sensible defaults:
//   eth        dst, src, ethertype                                   ethertype linked from the next layer
//   vlan       pcp, dei, vid, ethertype                              802.1Q tag (TPID 0x8100 in the layer below)
//   ipv4       version..dst (no options)                             total_length + header checksum maintained
//   ipv6       version..dst                                          payload_length maintained
//   ipv6_frag  next_header, reserved, offset, res, more, identification   (RFC 8200 fragment header)
//   udp        src_port, dst_port, length, checksum                  length + pseudo-header checksum maintained
//   someip     service_id, method_id, length, client_id, session_id,
//              protocol_version, interface_version, message_type, return_code   length maintained
//   someip_tp  offset (28 bit, 16-byte units), reserved, more        TP flag 0x20 set in message_type
// Next-protocol fields (ethertype, protocol, next_header) left at 0 are filled by compile().
//
// Segmentation presets: ipv4_fragments(mtu), ipv6_fragments(mtu), someip_tp_segments(max_payload).
#ifndef NANOCRAFT_DETAIL_PROTO_STUB_HPP_INCLUDED
#define NANOCRAFT_DETAIL_PROTO_STUB_HPP_INCLUDED

#include "../layer.hpp"
#include "../segment.hpp"

#include <array>
#include <cstdint>

namespace nanocraft::proto {

namespace nm = nanom;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using nanocraft::operator/;

using mac = std::array<u8, 6>;
using ip4 = std::array<u8, 4>;
using ip6 = std::array<u8, 16>;

struct eth {
  mac dst{};
  mac src{};
  nm::be<u16> ethertype{};
};
struct vlan {
  nm::ubits<3> pcp{};
  nm::ubits<1> dei{};
  nm::ubits<12> vid{};
  nm::be<u16> ethertype{};
};
struct ipv4 {
  nm::ubits<4> version{4};
  nm::ubits<4> ihl{5};
  nm::ubits<6> dscp{};
  nm::ubits<2> ecn{};
  nm::be<u16> total_length{};
  nm::be<u16> identification{};
  nm::ubits<3> flags{};
  nm::ubits<13> frag_offset{};
  u8 ttl = 64;
  u8 protocol = 0;
  nm::be<u16> checksum{};
  ip4 src{};
  ip4 dst{};
};
struct ipv6 {
  nm::ubits<4> version{6};
  nm::ubits<8> traffic_class{};
  nm::ubits<20> flow_label{};
  nm::be<u16> payload_length{};
  u8 next_header = 0;
  u8 hop_limit = 64;
  ip6 src{};
  ip6 dst{};
};
struct ipv6_frag {
  u8 next_header = 0;
  u8 reserved = 0;
  nm::ubits<13> offset{};
  nm::ubits<2> res{};
  nm::ubits<1> more{};
  nm::be<u32> identification{};
};
struct udp {
  nm::be<u16> src_port{};
  nm::be<u16> dst_port{};
  nm::be<u16> length{};
  nm::be<u16> checksum{};
};
struct someip {
  nm::be<u16> service_id{};
  nm::be<u16> method_id{};
  nm::be<u32> length{};
  nm::be<u16> client_id{};
  nm::be<u16> session_id{};
  u8 protocol_version = 1;
  u8 interface_version = 1;
  u8 message_type = 2;  // NOTIFICATION
  u8 return_code = 0;
};
struct someip_tp {
  nm::ubits<28> offset{};
  nm::ubits<3> reserved{};
  nm::ubits<1> more{};
};

inline constexpr u8 someip_tp_flag = 0x20;

}  // namespace nanocraft::proto

NANOM_DESCRIBE(nanocraft::proto::eth, dst, src, ethertype);
NANOM_DESCRIBE(nanocraft::proto::vlan, pcp, dei, vid, ethertype);
NANOM_DESCRIBE(nanocraft::proto::ipv4, version, ihl, dscp, ecn, total_length, identification, flags, frag_offset, ttl,
               protocol, checksum, src, dst);
NANOM_DESCRIBE(nanocraft::proto::ipv6, version, traffic_class, flow_label, payload_length, next_header, hop_limit, src,
               dst);
NANOM_DESCRIBE(nanocraft::proto::ipv6_frag, next_header, reserved, offset, res, more, identification);
NANOM_DESCRIBE(nanocraft::proto::udp, src_port, dst_port, length, checksum);
NANOM_DESCRIBE(nanocraft::proto::someip, service_id, method_id, length, client_id, session_id, protocol_version,
               interface_version, message_type, return_code);
NANOM_DESCRIBE(nanocraft::proto::someip_tp, offset, reserved, more);

namespace nanocraft {

namespace proto::detail {
template <class N>
constexpr u16 ethertype_of() {
  if constexpr (requires { layer_info<N>::ethertype; }) return layer_info<N>::ethertype;
  else return 0;
}
template <class N>
constexpr u8 ip_proto_of() {
  if constexpr (requires { layer_info<N>::ip_proto; }) return layer_info<N>::ip_proto;
  else return 0;
}
template <class Self, class N>
constexpr void link_ethertype(Self& s, const N&) {
  if (s.ethertype.get() == 0 && ethertype_of<N>() != 0) s.ethertype.set(ethertype_of<N>());
}
template <class N>
constexpr void link_proto(u8& field, const N&) {
  if (field == 0 && ip_proto_of<N>() != 0) field = ip_proto_of<N>();
}
}  // namespace proto::detail

template <>
struct layer_info<proto::eth> {
  static constexpr std::string_view name = "eth";
  static constexpr std::array<std::string_view, 1> selectors{"ethertype"};
  template <class N> static constexpr void link(proto::eth& s, const N& n) { proto::detail::link_ethertype(s, n); }
};
template <>
struct layer_info<proto::vlan> {
  static constexpr std::string_view name = "vlan";
  static constexpr std::uint16_t ethertype = 0x8100;
  static constexpr std::array<std::string_view, 1> selectors{"ethertype"};
  template <class N> static constexpr void link(proto::vlan& s, const N& n) { proto::detail::link_ethertype(s, n); }
};
template <>
struct layer_info<proto::ipv4> {
  static constexpr std::string_view name = "ipv4";
  static constexpr std::uint16_t ethertype = 0x0800;
  static constexpr std::array lengths{length_spec{"total_length", 0, 0}};
  static constexpr std::array checksums{checksum_spec{"checksum", checksum_kind::header, 20}};
  static constexpr pseudo_spec pseudo{12, 8, true};
  static constexpr std::array<std::string_view, 3> selectors{"version", "ihl", "protocol"};
  template <class N> static constexpr void link(proto::ipv4& s, const N& n) { proto::detail::link_proto(s.protocol, n); }
};
template <>
struct layer_info<proto::ipv6> {
  static constexpr std::string_view name = "ipv6";
  static constexpr std::uint16_t ethertype = 0x86dd;
  static constexpr std::array lengths{length_spec{"payload_length", 40, 0}};
  static constexpr pseudo_spec pseudo{8, 32, false};
  static constexpr std::array<std::string_view, 2> selectors{"version", "next_header"};
  template <class N> static constexpr void link(proto::ipv6& s, const N& n) { proto::detail::link_proto(s.next_header, n); }
};
template <>
struct layer_info<proto::ipv6_frag> {
  static constexpr std::string_view name = "ipv6_frag";
  static constexpr std::uint8_t ip_proto = 44;
  static constexpr std::array<std::string_view, 1> selectors{"next_header"};
  template <class N> static constexpr void link(proto::ipv6_frag& s, const N& n) { proto::detail::link_proto(s.next_header, n); }
};
template <>
struct layer_info<proto::udp> {
  static constexpr std::string_view name = "udp";
  static constexpr std::uint8_t ip_proto = 17;
  static constexpr std::array lengths{length_spec{"length", 0, 0}};
  static constexpr std::array checksums{checksum_spec{"checksum", checksum_kind::l4, 0, 17, "length"}};
};
template <>
struct layer_info<proto::someip> {
  static constexpr std::string_view name = "someip";
  static constexpr std::array lengths{length_spec{"length", 8, 0}};
  template <class N>
  static constexpr void link(proto::someip& s, const N&) {
    if constexpr (std::is_same_v<N, proto::someip_tp>) s.message_type |= proto::someip_tp_flag;
  }
};
template <>
struct layer_info<proto::someip_tp> {
  static constexpr std::string_view name = "someip_tp";
};

namespace proto {

/// IPv4 fragmentation for a link MTU (IP header + data), DF must be clear in the template.
constexpr segment_spec ipv4_fragments(std::size_t mtu = 1500) {
  return segment_spec{"ipv4", "ipv4.frag_offset", 8, "ipv4.flags", 1, mtu > 20 ? mtu - 20 : 0};
}
/// IPv6 fragmentation (the stack must contain an ipv6_frag layer right after ipv6).
constexpr segment_spec ipv6_fragments(std::size_t mtu = 1500) {
  return segment_spec{"ipv6_frag", "ipv6_frag.offset", 8, "ipv6_frag.more", 1, mtu > 48 ? mtu - 48 : 0};
}
/// SOME/IP-TP (PRS_SOMEIP_00720ff.): segments of at most max_payload bytes (rounded down to a
/// multiple of 16), offset in 16-byte units, More flag in the last bit. The stack must end with
/// someip / someip_tp.
constexpr segment_spec someip_tp_segments(std::size_t max_payload = 1392) {
  return segment_spec{"someip_tp", "someip_tp.offset", 16, "someip_tp.more", 1, max_payload};
}

}  // namespace proto

}  // namespace nanocraft

#endif  // NANOCRAFT_DETAIL_PROTO_STUB_HPP_INCLUDED
