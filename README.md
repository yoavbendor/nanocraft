# nanocraft

Realtime packet crafting for C++23. You describe a protocol stack once. nanocraft compiles it into a
byte image plus a table of patch points. After that, each frame is a `memcpy` and a few field
patches, with lengths and Internet checksums kept up to date incrementally (RFC 1624). Frames go to
pcap/pcapng files, to an AF_PACKET TX ring (crafted in place, no copy), or to `sendmmsg` batches.
Segmentation (IPv4/IPv6 fragments, SOME/IP-TP) never copies the payload.

The library is header-only. Its protocols come from [nanowire](https://github.com/yoavbendor/nanowire),
the shared protocol core: every header is defined once there (a `NANOM_DESCRIBE`'d wire struct, a
zero-copy view, a builder), and the same definition is used to read frames (nanowire / nanoshark)
and to craft them (nanocraft). nanowire in turn sits on [nanom](https://github.com/yoavbendor/nanom)
(struct description, parser, encoder). nanocraft is built for automotive Ethernet (SOME/IP,
SOME/IP-TP, SOME/IP-SD, AUTOSAR PDUs) and sensor-data streaming, where the frame rate is what
matters.

```
Eth/VLAN/IPv4/UDP/SOME-IP + 32 B payload (94 B frame), g++-13 -O3, shared 4-core x86-64 VM

                                         ns/frame   instr/frame (callgrind)
nanowire::build_frame (builders, per frame) ~85         1621
template, 3 patched fields, write()        ~7.8           84
template, write() then 3 patches in place  ~3.5           87
  + UDP checksum computed over payload     ~10.5         158
template -> pcap record, in place          ~9.1          146     ~12 GB/s
template -> pcapng EPB, in place           ~12           205     ~10 GB/s
SOME/IP-TP 64 KiB -> 48 segments           ~112 / seg            ~13 GB/s, zero copy
IPv4 fragments of 64 000 B -> 44           ~79 / frag            ~19 GB/s, zero copy
```

Each frame is byte-identical to what nanowire's own builders write (`nanowire::build_frame`) and to
an independent reference builder, and nanowire's reader (`packet::parse` + views) reads back every
field the template meant.

## Quick start: a SOME/IP notification, 1M frames to pcapng

```cpp
#include <nanocraft/nanocraft.hpp>
using namespace nanocraft::proto;   // nanowire's builders (nanowire::eth, ...) + nanocraft extras

auto t = nanocraft::compile(
    eth{.dst = mac("01:00:5e:00:00:01"), .src = mac("02:00:00:00:00:01")} /
    vlan{.vid = 100, .pcp = 5} /
    ipv4{.src = ip4("10.0.0.1"), .dst = ip4("239.0.0.1"), .ttl = 8} /
    udp{.src_port = 30501, .dst_port = 30501} /
    someip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 1});
// ethertypes, IP protocol, lengths and checksums are filled in
// (`nanowire::eth{} / nanowire::ipv4{} / ...` works too, without the using-directive)

std::FILE* f = std::fopen("someip.pcapng", "wb");
nanocraft::pcapng_writer w(nanocraft::output::file(f), 4 << 20);
auto ifc = w.add_interface({.name = "veth0", .tsresol = 9});

std::array<std::byte, 32> sample{};
std::uint64_t ts = 1'700'000'000'000'000'000;
for (long i = 0; i < 1'000'000; ++i) {
  t.set<"someip.session_id">(i % 0xffff + 1);   // compile-time patch point; checksums follow
  t.set<"ipv4.identification">(i);
  w.write(ifc, ts += 1'000'000, t, sample);      // crafted directly in the writer's buffer
}
```

(`examples/someip_to_pcapng.cpp`: about 55 ns/frame end to end, including the file write.)

## Live transmit: AF_PACKET TX ring

```cpp
auto ring = nanocraft::tx_ring::open("eth0", {.frame_size = 2048, .frame_count = 1024});
if (!ring) die(ring.error());                     // needs CAP_NET_RAW
for (...) {
  t.set<"someip.session_id">(s);
  while (!ring->write(t, payload)) ring->send(true);   // the frame is built inside the ring slot
}
ring->send(true);
```

`mmsg_sender` sends batches of scatter-gather frames with `sendmmsg`. Each chunk is passed to the
kernel as an iovec. The sender can also attach per-frame `SO_TXTIME` launch times; pair them with
the ETF qdisc for paced output. See `examples/tx_ring.cpp`.

## Concepts

**Patch points.** Every field of every layer is a patch point, named `"layer.field"`, where
`field` is the field name of the layer's nanowire wire struct (`nanowire::wire::ipv4_hdr` ...: see
the table below). For a repeated layer, write `"vlan[1].vid"`. A patch point records the byte offset, the span, the bit
shift and width, and the byte order.
- `t.set<"path">(v)` resolves the path at compile time. A typo is a compile error.
- `t.find("path")` returns a runtime handle; pass it to `t.set(handle, v)`.
- Integers are masked to the field width. Address fields take `std::array`s or byte spans.

**Two hot-path styles.**
- `t.set<>(v)` then `t.write(dst, payload)`: patches the image, which persists across frames.
- `t.write(dst, payload)` then `t.patch<"path">(dst, v)`: patches the frame that was just written.
  This is fastest when every frame changes a few fields, because the image is never re-read right
  after a store (store-forwarding stalls). It costs about 3.3 ns for three fields.

Either way, the hot path does no allocation and never re-encodes a field that did not change.
`prepare(dst, n)` / `commit(dst, n)` let you serialize the payload straight into the frame.

**Length chains.** Some layers declare length fields (IPv4 total length, UDP length, IPv6 payload
length, SOME/IP length, SoAd PDU length, IpduM DLC, SD options length). When the payload size
changes, those fields change with it, and the checksums are updated incrementally (TCP, which has
no length field, gets its pseudo-header length updated the same way).

**Checksums.** Each checksum field has a policy, set with
`t.checksum("udp.checksum", csum_policy::...)`:
- `compute` (the default): RFC 1624 incremental update on every patch. The image stays a valid frame
  with an all-zero payload, so writing the real payload is one more incremental update: its
  ones'-complement sum is added.
- `zero`: the UDP "no checksum" value.
- `offload`: the folded pseudo-header sum, for NIC checksum offload.
- `keep`: whatever the layer's own value says. A builder given an explicit checksum
  (`udp{.checksum = 0}`, `ipv4{.checksum = ...}`, `tcp{.checksum = ...}`) starts with `keep`.

**Fault injection.** For example:

```cpp
t.inject(nanocraft::faults{}.bad_checksum("ipv4.checksum").length_delta("udp.length", +4)
                            .truncate_by(3).every_nth(100));
```

A length fault keeps the checksums consistent with the wrong length, so only the length is wrong.

**Segmentation, zero copy.** `segmenter seg(t, spec)` replicates the headers up to a given layer and
cuts everything after it into pieces. Each piece is a `gather`: header bytes from a small arena plus
spans of your payload. The arena is reused on the next call. Presets:
- `ipv4_fragments(mtu)` (DF clear; offset in `ipv4.frag_offset`, More in `ipv4.mf`)
- `ipv6_fragments(mtu)` (requires an `ipv6_frag` layer in the stack)
- `someip_tp_segments(max)` (requires a `someip_tp` layer): segments of at most `max` bytes, all but
  the last a multiple of 16, the offset in 16-byte units, the More flag, and the TP flag in the
  message type.

Run it with `seg.run(payload, fn)`, or `seg.segment(payload)` to get a span of gathers. If a sink
cannot take gathers, `gather::copy_to` produces a contiguous frame.

**Sinks.**
- `pcap_writer`: microsecond or nanosecond resolution, snaplen.
- `pcapng_writer`: SHB, multiple IDBs with `if_tsresol`, `if_name`, `if_description`; EPBs with
  `epb_flags` and `opt_comment`.

Both write to a `FILE*`, a file descriptor, or a byte vector, through one large buffer. Templates
are crafted inside that buffer.
- `capture_reader` is a strict, zero-copy pcap/pcapng reader. `mapped_file` memory-maps a file for
  it.
- `replay(reader, sink, {.speed = s}, rewrite)` re-emits a capture with its original timing, scaled
  timing, or no pacing. Rewrites use the same patch points: `frame_ref` patches any frame laid out
  like a stack, and `t.matches(frame)` checks that layout.

**Profiling.** Build with `-DNANOCRAFT_PROFILE=ON` to compile in counters for each stage (calls,
frames, bytes, and ns/call sampled with the TSC). Print them with `nanocraft::profile::report()`.
Without the option, the counters compile to nothing.

## Headers

| header | what |
|---|---|
| `nanocraft/nanocraft.hpp` | umbrella (everything + nanowire's layers) |
| `nanocraft/frame_template.hpp` | `compile`, `frame_template`, `frame_ref`, policies, faults |
| `nanocraft/segment.hpp`, `gather.hpp` | segmentation, scatter-gather frames |
| `nanocraft/pcap_writer.hpp`, `pcap_reader.hpp`, `replay.hpp` | capture sinks, reader, replay |
| `nanocraft/linux_tx.hpp` | `tx_ring` / `tx_ring_view`, `mmsg_sender`, `enable_txtime` (Linux) |
| `nanocraft/checksum.hpp` | RFC 1071 sum, RFC 1624 update |
| `nanocraft/layer.hpp` | the protocol seam: `layer_info<L>`, `stack`, `operator/` |
| `nanocraft/nanowire_layers.hpp` | `layer_info` for nanowire's protocols, `nanocraft::proto`, segmentation presets |
| `nanocraft/profile.hpp` | `NANOCRAFT_PROFILE` counters |

## Protocols: one definition for reading and crafting

The engine knows no protocol. A layer is a fixed-size header with a `NANOM_DESCRIBE`'d wire layout
plus a `nanocraft::layer_info<L>` specialization that declares (see `layer.hpp`) its name, its
length fields, its checksum fields (header kind or L4-with-pseudo-header kind), its pseudo-header
address range (IP layers), its selector fields, and optional `link()` / `check()` /
`keep_checksum()` hooks. A layer value is either a described struct itself, or a builder whose
`layer_info<L>::wire` names the described struct.

`nanowire_layers.hpp` provides these for nanowire: the **builder writes the header image** (so a
template frame is exactly what `nanowire::build_frame` writes) and the **wire struct supplies the
patch points** (so patch paths are nanowire's field names, at the offsets nanowire's views read).
nanocraft depends on nanowire, never the reverse.

| value (`nanocraft::proto::` / `nanowire::`) | path | wire struct | maintained |
|---|---|---|---|
| `eth{.dst, .src, .type}` | `eth` | `wire::eth_hdr` | ethertype from the next layer |
| `vlan{.vid, .pcp, .dei, .tpid, .type}` | `vlan` | `wire::vlan_tag` | QinQ: `vlan{.tpid = 0x88A8} / vlan{}` |
| `ipv4{.src, .dst, .ttl, .dscp, .ecn, .id, .df, .mf, .frag_offset, .protocol}` | `ipv4` | `wire::ipv4_hdr` | total_length, header checksum, protocol |
| `ipv6{.src, .dst, .traffic_class, .flow_label, .hop_limit}` | `ipv6` | `wire::ipv6_hdr` | payload_length, next_header |
| `ipv6_frag{.offset, .more, .id}` | `ipv6_frag` | `wire::ipv6_frag_hdr` | next_header |
| `udp{.src_port, .dst_port}` | `udp` | `wire::udp_hdr` | length, pseudo-header checksum |
| `tcp{.src_port, .dst_port, .seq, .ack, .flags, .window, .urgent}` | `tcp` | `wire::tcp_hdr` | pseudo-header checksum (20-byte header, no options) |
| `someip{...}` | `someip` | `wire::someip_hdr` | length; TP flag before `someip_tp` |
| `someip_tp{.offset /* bytes */, .more}` | `someip_tp` | `wire::someip_tp_hdr` | |
| `soad_pdu_header{.id}` | `soad` | `wire::soad_pdu_hdr` | length |
| `proto::ipdum_short{.id}` / `ipdum_long{.id}` | `ipdum` | `wire::ipdum_short_hdr` / `ipdum_long_hdr` | dlc |
| `proto::sd_header{.flags, .entries}` | `sd` | `wire::sd_header` | entries_length = 16 x entries |
| `sd_entry::offer_service(...)` (types 0/1) | `sd_entry` | `wire::sd_service_entry` | |
| `proto::sd_eventgroup_entry{sd_entry::subscribe(...)}` | `sd_entry` | `wire::sd_eventgroup_entry` | |
| `proto::sd_options{}` | `sd_options` | `proto::sd_options_hdr` | length (options + payload) |
| `sd_option::ipv4_endpoint(...)` / `proto::sd_ipv6_option{...}` | `sd_option` | `wire::sd_ipv4_option` / `sd_ipv6_option` | |

An SD OfferService template: `eth{} / ipv4{...} / udp{...} / nanowire::someip_sd_header(1) /
sd_header{} / sd_entry::offer_service(0x1234, 1, 1, 0).with_options(0, 1) / sd_options{} /
sd_option::ipv4_endpoint(ip4("10.0.0.1"), ip_proto::udp, 30501)`; patch `sd_entry.ttl`,
`sd_option.port`, ... per frame.

Templates need fixed-size layers. `compile()` refuses (`t.ok() == false`, `t.error()` says why)
IPv4 / TCP options, `someip{.tp = ...}` (write `someip{} / someip_tp{}`), length overrides
(`.total_length`, `.length`, `.payload_length`: templates maintain every length; use
`faults::length_delta` for malformed lengths) and field values the builder refuses.

**Migrating from v0.1's interim layers** (`detail/proto_stub.hpp`, removed): patch paths are
unchanged except `ipv4.flags` (3 bits), which is now `ipv4.reserved`, `ipv4.df` and `ipv4.mf`
(`ipv4_fragments()` uses `ipv4.mf`). Builder value fields follow nanowire: `eth{.type}` (was
`.ethertype`), `vlan{.vid, .pcp, .dei}` (plain integers, in that order; `.type` for the inner
EtherType), `ipv4{.id}` (was `.identification`; fields in nanowire's declaration order: `.src,
.dst, .ttl, ...`), `ipv6_frag{.id}`, `someip_tp{.offset}` in bytes. `ip4` / `ip6` / `mac` are
nanowire's literal parsers (`ip4("10.0.0.1")`); the array types are `ipv4_addr` / `ipv6_addr` /
`mac_addr`. Defaults follow nanowire's builders: `eth{}` is broadcast from 02:00:00:00:00:01,
`someip{}` has session_id 1.

**nanocraft templates or `nanom::craft`?** Both write the same bytes from the same definitions.
nanom's `craft` combinators (`|` sequencing, `+` composition) are general serialization: any
message shape, variable-length content, one-off frames, encoders composed in code. nanocraft is
the template path (`/` stacks, scapy's convention): one fixed header stack, compiled once into an
image + patch points, then millions of frames that differ in a few fields, with lengths and
checksums maintained incrementally, segmentation and fault injection, written straight into pcap
buffers or TX rings. Use nanowire's `build_frame` / `nanom::craft` when the frame shape changes
per frame; use a nanocraft template when the rate matters.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release        # fetches nanowire + nanom (pinned commits)
cmake --build build -j && ctest --test-dir build
bench/callgrind.sh build/bench/craft_bench             # instructions/frame per case
```

- Use the target `nanocraft::nanocraft`.
- Options: `NANOCRAFT_BUILD_TESTS`, `NANOCRAFT_BUILD_BENCH`, `NANOCRAFT_BUILD_EXAMPLES`,
  `NANOCRAFT_PROFILE`, `NANOCRAFT_SANITIZER=address,undefined`, `NANOCRAFT_WERROR`.
- To build against local checkouts: `-DFETCHCONTENT_SOURCE_DIR_NANOWIRE=/path/to/nanowire`
  and/or `-DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom`. nanowire fetches nanom under the same
  FetchContent name; nanocraft makes nanom available first, so only one nanom is configured (keep
  `NANOCRAFT_NANOM_GIT_TAG` equal to nanowire's pin). A parent project that already defines
  `nanom::nanom` / `nanowire::nanowire` wins.
- Requires CMake 3.25+, GCC 13+ or Clang 18+.

**Tests.** The independent oracles are:
- a hand-written RFC/PRS byte builder;
- nanowire's builders (`nanowire::make_frame`): byte-identical frames;
- nanowire's reader (`packet::parse`, views, `sd_view`, `soad_pdus`, `ipdum_pdus`) and its
  IPv4 / IPv6 / SOME/IP-TP reassemblers over every crafted frame and segment: reading and crafting
  agree field by field, checksums verified by nanowire;
  `test_nanowire` covers every nanowire layer (TCP, QinQ, IPv6, SOME/IP-SD, SoAd / IpduM,
  SOME/IP-TP over TCP, fragments of TCP segments) and the layers `compile()` refuses;
- a naive RFC 1071 checksum;
- reference reassemblers for SOME/IP-TP and IPv4/IPv6 fragments;
- nanocraft's strict reader and nanom_shark's block scanner;
- python `dpkt` and `scapy` (`pip install dpkt scapy`; the test is skipped without them): every
  IPv4 / UDP / TCP checksum and length over IPv4 and IPv6 recomputed by scapy.

The live AF_PACKET tests on `lo` are skipped when the process lacks CAP_NET_RAW.

## License

Apache-2.0
