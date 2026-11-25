// SPDX-License-Identifier: Apache-2.0
// nanocraft/nanocraft.hpp — umbrella header: everything, plus the stub protocol layers.
//
//   checksum.hpp        Internet checksum + RFC 1624 incremental update
//   layer.hpp           the protocol seam (layer_info<L>, stack, operator/)
//   frame_template.hpp  compile(): templates, patch points, length chains, checksum policies, faults
//   gather.hpp          scatter-gather frame descriptions (iovec-compatible)
//   segment.hpp         zero-copy segmentation (IPv4/IPv6 fragments, SOME/IP-TP)
//   pcap_writer.hpp     pcap / pcapng streaming writers
//   pcap_reader.hpp     strict zero-copy pcap / pcapng reader, mapped_file
//   replay.hpp          replay a capture with rewriting and original / scaled timing
//   linux_tx.hpp        AF_PACKET TX ring, sendmmsg, SO_TXTIME (Linux only)
//   profile.hpp         NANOCRAFT_PROFILE counters
//   detail/proto_stub.hpp  eth/vlan/ipv4/ipv6/ipv6_frag/udp/someip/someip_tp (to be replaced by nanowire)
#ifndef NANOCRAFT_NANOCRAFT_HPP_INCLUDED
#define NANOCRAFT_NANOCRAFT_HPP_INCLUDED

#include "checksum.hpp"
#include "frame_template.hpp"
#include "gather.hpp"
#include "layer.hpp"
#include "linux_tx.hpp"
#include "pcap_reader.hpp"
#include "pcap_writer.hpp"
#include "profile.hpp"
#include "replay.hpp"
#include "segment.hpp"

#include "detail/proto_stub.hpp"

#define NANOCRAFT_VERSION_MAJOR 0
#define NANOCRAFT_VERSION_MINOR 1
#define NANOCRAFT_VERSION_PATCH 0

#endif  // NANOCRAFT_NANOCRAFT_HPP_INCLUDED
