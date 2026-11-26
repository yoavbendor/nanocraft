// SPDX-License-Identifier: Apache-2.0
// nanocraft/nanowire_layers.hpp — nanowire's protocols as nanocraft template layers.
//
// nanowire (https://github.com/yoavbendor/nanowire) defines every protocol header once, as a
// NANOM_DESCRIBE'd wire struct in nanowire::wire, with zero-copy views (the read edge) and value
// builders (eth{}, ipv4{}, udp{}, someip{}, ...). This header plugs those definitions into the
// template engine through nanocraft::layer_info<>: the builder writes the header image (so a
// template frame is byte-for-byte what nanowire::build_frame writes), the wire struct supplies the
// patch points (field names = nanowire's wire field names), and the tables below tell the engine
// which fields are lengths, checksums and identity selectors. nanocraft depends on nanowire, never
// the reverse.
//
//   using namespace nanocraft::proto;            // nanowire's builders + nanocraft's extra layers
//   auto t = nanocraft::compile(eth{.dst = mac("02:00:00:00:00:02")} / vlan{.vid = 100} /
//                               ipv4{.src = ip4("10.0.0.1"), .dst = ip4("10.0.0.2")} /
//                               udp{.src_port = 30501, .dst_port = 30501} /
//                               someip{.service_id = 0x1234, .method_id = 0x8001});
//   t.set<"ipv4.identification">(7);             // patch paths: <layer>.<wire field>
//
// Layers (value type -> patch path prefix, wire struct):
//   nanowire::eth              eth         wire::eth_hdr          ethertype from the next layer
//   nanowire::vlan             vlan        wire::vlan_tag         QinQ: vlan{.tpid = 0x88A8} / vlan{}
//   nanowire::ipv4             ipv4        wire::ipv4_hdr         total_length + header checksum kept
//   nanowire::ipv6             ipv6        wire::ipv6_hdr         payload_length kept
//   nanowire::ipv6_frag        ipv6_frag   wire::ipv6_frag_hdr
//   nanowire::udp              udp         wire::udp_hdr          length + pseudo-header checksum kept
//   nanowire::tcp              tcp         wire::tcp_hdr          20-byte header (no options); checksum kept
//   nanowire::someip           someip      wire::someip_hdr       length kept; TP flag set before someip_tp
//   nanowire::someip_tp        someip_tp   wire::someip_tp_hdr    offset in BYTES (multiple of 16)
//   nanowire::soad_pdu_header  soad        wire::soad_pdu_hdr     length = everything after it
//   proto::ipdum_short / _long ipdum       wire::ipdum_short_hdr / ipdum_long_hdr (big endian), dlc kept
//   proto::sd_header           sd          wire::sd_header        entries_length = 16 * .entries
//   nanowire::sd_entry         sd_entry    wire::sd_service_entry (service entry types 0x00 / 0x01)
//   proto::sd_eventgroup_entry sd_entry    wire::sd_eventgroup_entry (types 0x06 / 0x07)
//   proto::sd_options          sd_options  proto::sd_options_hdr  options_length = everything after it
//   nanowire::sd_option        sd_option   wire::sd_ipv4_option   (IPv4 endpoint / multicast / SD endpoint)
//   proto::sd_ipv6_option      sd_option   wire::sd_ipv6_option
//
// Templates need fixed-size layers: IPv4 / TCP options, someip{.tp = ...} (use / someip_tp{}) and
// length overrides (.total_length, .length, .payload_length: the template maintains every length;
// use faults::length_delta for malformed lengths) are refused by compile() with an error().
// A builder's explicit .checksum (ipv4, udp, tcp) starts that slot with csum_policy::keep.
//
// Segmentation presets: ipv4_fragments(mtu), ipv6_fragments(mtu), someip_tp_segments(max_payload).
#ifndef NANOCRAFT_NANOWIRE_LAYERS_HPP_INCLUDED
#define NANOCRAFT_NANOWIRE_LAYERS_HPP_INCLUDED

#include "layer.hpp"
#include "segment.hpp"

#include <nanowire/autosar_pdu.hpp>
#include <nanowire/ethernet.hpp>
#include <nanowire/ip.hpp>
#include <nanowire/someip.hpp>
#include <nanowire/someip_sd.hpp>
#include <nanowire/transport.hpp>

#include <array>
#include <cstdint>
#include <string_view>

// ---------------------------------------------------------------------------------------------
// nanocraft-side layers for nanowire wire structs that have no fixed-size builder (yet)
// ---------------------------------------------------------------------------------------------
namespace nanocraft::proto {
/// The options-array length word of an SD message. nanowire has no wire struct for it (yet).
struct sd_options_hdr {
  nanom::be<std::uint32_t> length;
};
}  // namespace nanocraft::proto

NANOM_DESCRIBE(nanocraft::proto::sd_options_hdr, length);

namespace nanocraft::proto {

/// AUTOSAR IpduM contained-PDU short header [ID:24][DLC:8] (big endian); dlc = the bytes after it
/// (a template payload of more than 255 bytes wraps: keep contained PDUs short).
struct ipdum_short {
  std::uint32_t id = 0;
  static constexpr std::size_t size() noexcept { return 4; }
  constexpr bool write(std::byte* p, const nanowire::build_ctx& c) const noexcept {
    if (id > 0xFFFFFF) return false;
    return nanowire::emit_wire(nanowire::wire::ipdum_short_hdr{{id}, std::uint8_t(c.after)}, p) == 4;
  }
};
/// AUTOSAR IpduM contained-PDU long header [ID:32][DLC:32] (big endian); dlc = the bytes after it.
struct ipdum_long {
  std::uint32_t id = 0;
  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p, const nanowire::build_ctx& c) const noexcept {
    return nanowire::emit_wire(nanowire::wire::ipdum_long_hdr{id, std::uint32_t(c.after)}, p) == 8;
  }
};

/// The SOME/IP-SD header [flags:8][reserved:24][entries_length:32]; `entries` sd_entry layers
/// follow it (entries_length = 16 * entries).
struct sd_header {
  std::uint8_t flags = nanowire::sd_flag::reboot | nanowire::sd_flag::unicast;
  std::uint32_t entries = 1;
  static constexpr std::size_t size() noexcept { return 8; }
  constexpr bool write(std::byte* p) const noexcept {
    return entries <= 0x0FFFFFFF && nanowire::emit_wire(nanowire::wire::sd_header{flags, {0, 0, 0}, entries * 16}, p) == 8;
  }
};

/// An eventgroup entry (SubscribeEventgroup / Ack: types 0x06 / 0x07):
/// sd_eventgroup_entry{nanowire::sd_entry::subscribe(svc, inst, major, eventgroup)}.
struct sd_eventgroup_entry : nanowire::sd_entry {};

/// The options-array length word; options_length covers every byte after it (the option layers,
/// then the template payload: extra raw options).
struct sd_options {
  static constexpr std::size_t size() noexcept { return 4; }
  constexpr bool write(std::byte* p, const nanowire::build_ctx& c) const noexcept {
    return c.after <= 0xFFFFFFFFu && nanowire::emit_wire(sd_options_hdr{std::uint32_t(c.after)}, p) == 4;
  }
};

/// An IPv6 endpoint / multicast / SD-endpoint option:
/// sd_ipv6_option{nanowire::sd_option::ipv6_endpoint(addr, proto, port)}.
struct sd_ipv6_option : nanowire::sd_option {};

}  // namespace nanocraft::proto

namespace nanocraft {

namespace nwl {
inline constexpr std::string_view length_override =
    "nanocraft: templates maintain every length field; drop the length override (use faults::length_delta)";
}

// ---- L2

template <>
struct layer_info<nanowire::eth> {
  static constexpr std::string_view name = "eth";
  using wire = nanowire::wire::eth_hdr;
  static constexpr std::array<std::string_view, 1> selectors{"ethertype"};
};
template <>
struct layer_info<nanowire::vlan> {
  static constexpr std::string_view name = "vlan";
  using wire = nanowire::wire::vlan_tag;
  static constexpr std::array<std::string_view, 1> selectors{"ethertype"};
};

// ---- L3

template <>
struct layer_info<nanowire::ipv4> {
  static constexpr std::string_view name = "ipv4";
  using wire = nanowire::wire::ipv4_hdr;
  static constexpr std::array lengths{length_spec{"total_length", 0, 0}};
  static constexpr std::array checksums{checksum_spec{"checksum", checksum_kind::header, 20}};
  static constexpr pseudo_spec pseudo{12, 8, true};
  static constexpr std::array<std::string_view, 3> selectors{"version", "ihl", "protocol"};
  static constexpr std::string_view check(const nanowire::ipv4& l) { return l.total_length ? nwl::length_override : ""; }
  static constexpr bool keep_checksum(const nanowire::ipv4& l) { return l.checksum.has_value(); }
};
template <>
struct layer_info<nanowire::ipv6> {
  static constexpr std::string_view name = "ipv6";
  using wire = nanowire::wire::ipv6_hdr;
  static constexpr std::array lengths{length_spec{"payload_length", 40, 0}};
  static constexpr pseudo_spec pseudo{8, 32, false};
  static constexpr std::array<std::string_view, 2> selectors{"version", "next_header"};
  static constexpr std::string_view check(const nanowire::ipv6& l) { return l.payload_length ? nwl::length_override : ""; }
};
template <>
struct layer_info<nanowire::ipv6_frag> {
  static constexpr std::string_view name = "ipv6_frag";
  using wire = nanowire::wire::ipv6_frag_hdr;
  static constexpr std::array<std::string_view, 1> selectors{"next_header"};
};

// ---- L4

template <>
struct layer_info<nanowire::udp> {
  static constexpr std::string_view name = "udp";
  using wire = nanowire::wire::udp_hdr;
  static constexpr std::array lengths{length_spec{"length", 0, 0}};
  static constexpr std::array checksums{checksum_spec{"checksum", checksum_kind::l4, 0, 17, "length"}};
  static constexpr std::string_view check(const nanowire::udp& l) { return l.length ? nwl::length_override : ""; }
  static constexpr bool keep_checksum(const nanowire::udp& l) { return l.checksum.has_value(); }
};
template <>
struct layer_info<nanowire::tcp> {
  static constexpr std::string_view name = "tcp";
  using wire = nanowire::wire::tcp_hdr;
  // No length field: the pseudo header's TCP length follows the payload size (frame_template).
  static constexpr std::array checksums{checksum_spec{"checksum", checksum_kind::l4, 0, 6, {}}};
  static constexpr bool keep_checksum(const nanowire::tcp& l) { return l.checksum.has_value(); }
};

// ---- SOME/IP

template <>
struct layer_info<nanowire::someip> {
  static constexpr std::string_view name = "someip";
  using wire = nanowire::wire::someip_hdr;
  static constexpr std::array lengths{length_spec{"length", 8, 0}};
  static constexpr std::string_view check(const nanowire::someip& l) { return l.length ? nwl::length_override : ""; }
  template <class N>
  static constexpr void link(nanowire::someip& s, const N&) {
    if constexpr (std::is_same_v<N, nanowire::someip_tp>) s.message_type |= nanowire::someip_type::tp_flag;
  }
};
template <>
struct layer_info<nanowire::someip_tp> {
  static constexpr std::string_view name = "someip_tp";
  using wire = nanowire::wire::someip_tp_hdr;
  static constexpr bool write(const nanowire::someip_tp& l, std::byte* p, const nanowire::build_ctx&) {
    if (l.offset % 16 != 0) return false;
    return nanowire::emit_wire(nanowire::wire::someip_tp_hdr{{l.offset / 16}, {0}, {std::uint8_t(l.more)}}, p) == 4;
  }
};

// ---- SOME/IP-SD (fixed-size blocks)

template <>
struct layer_info<proto::sd_header> {
  static constexpr std::string_view name = "sd";
  using wire = nanowire::wire::sd_header;
};
template <>
struct layer_info<nanowire::sd_entry> {
  static constexpr std::string_view name = "sd_entry";
  using wire = nanowire::wire::sd_service_entry;
  static constexpr std::string_view check(const nanowire::sd_entry& e) {
    return e.type <= nanowire::sd_entry_type::offer_service
               ? ""
               : "nanocraft: eventgroup entries (types 6 / 7) are proto::sd_eventgroup_entry layers";
  }
};
template <>
struct layer_info<proto::sd_eventgroup_entry> {
  static constexpr std::string_view name = "sd_entry";
  using wire = nanowire::wire::sd_eventgroup_entry;
  static constexpr std::string_view check(const proto::sd_eventgroup_entry& e) {
    return e.type == nanowire::sd_entry_type::subscribe_eventgroup ||
                   e.type == nanowire::sd_entry_type::subscribe_eventgroup_ack
               ? ""
               : "nanocraft: service entries (types 0 / 1) are nanowire::sd_entry layers";
  }
};
template <>
struct layer_info<proto::sd_options> {
  static constexpr std::string_view name = "sd_options";
  using wire = proto::sd_options_hdr;
  static constexpr std::array lengths{length_spec{"length", 4, 0}};
};
template <>
struct layer_info<nanowire::sd_option> {
  static constexpr std::string_view name = "sd_option";
  using wire = nanowire::wire::sd_ipv4_option;
  static constexpr std::string_view check(const nanowire::sd_option& o) {
    return o.is_v4() ? "" : "nanocraft: only IPv4 options are nanowire::sd_option layers (IPv6: proto::sd_ipv6_option)";
  }
};
template <>
struct layer_info<proto::sd_ipv6_option> {
  static constexpr std::string_view name = "sd_option";
  using wire = nanowire::wire::sd_ipv6_option;
  static constexpr std::string_view check(const proto::sd_ipv6_option& o) {
    return o.is_v6() ? "" : "nanocraft: proto::sd_ipv6_option holds an IPv6 option";
  }
};

// ---- AUTOSAR PDUs

template <>
struct layer_info<nanowire::soad_pdu_header> {
  static constexpr std::string_view name = "soad";
  using wire = nanowire::wire::soad_pdu_hdr;
  static constexpr std::array lengths{length_spec{"length", 8, 0}};
};
template <>
struct layer_info<proto::ipdum_short> {
  static constexpr std::string_view name = "ipdum";
  using wire = nanowire::wire::ipdum_short_hdr;
  static constexpr std::array lengths{length_spec{"dlc", 4, 0}};
};
template <>
struct layer_info<proto::ipdum_long> {
  static constexpr std::string_view name = "ipdum";
  using wire = nanowire::wire::ipdum_long_hdr;
  static constexpr std::array lengths{length_spec{"dlc", 8, 0}};
};

// ---------------------------------------------------------------------------------------------
// user-facing names: nanocraft::proto
// ---------------------------------------------------------------------------------------------
namespace proto {

using nanocraft::operator/;

using nanowire::eth;
using nanowire::ipv4;
using nanowire::ipv6;
using nanowire::ipv6_frag;
using nanowire::sd_entry;
using nanowire::sd_option;
using nanowire::soad_pdu_header;
using nanowire::someip;
using nanowire::someip_tp;
using nanowire::tcp;
using nanowire::udp;
using nanowire::vlan;

using nanowire::ip4;
using nanowire::ip6;
using nanowire::ipv4_addr;
using nanowire::ipv6_addr;
using nanowire::mac;
using nanowire::mac_addr;

namespace ethertype = nanowire::ethertype;
namespace ip_proto = nanowire::ip_proto;
namespace tcp_flag = nanowire::tcp_flag;
namespace someip_type = nanowire::someip_type;
namespace someip_rc = nanowire::someip_rc;
namespace sd_flag = nanowire::sd_flag;
namespace sd_entry_type = nanowire::sd_entry_type;
namespace sd_option_type = nanowire::sd_option_type;

inline constexpr std::uint8_t someip_tp_flag = nanowire::someip_type::tp_flag;

/// IPv4 fragmentation for a link MTU (IP header + data); DF must be clear in the template.
constexpr segment_spec ipv4_fragments(std::size_t mtu = 1500) {
  return segment_spec{"ipv4", "ipv4.frag_offset", 8, "ipv4.mf", 1, mtu > 20 ? mtu - 20 : 0};
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

// `nanowire::eth{} / nanowire::ipv4{}` without a using-directive: make the stacking operator
// visible to argument-dependent lookup on nanowire's builder types. (Declared here, in nanocraft;
// nanowire itself knows nothing about nanocraft.)
namespace nanowire {
using nanocraft::operator/;
}

#endif  // NANOCRAFT_NANOWIRE_LAYERS_HPP_INCLUDED
