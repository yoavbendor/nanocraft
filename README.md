# nanocraft

Realtime packet crafting for C++23. You describe a protocol stack once. nanocraft compiles it into a
byte image plus a table of patch points. After that, each frame is a `memcpy` and a few field
patches, with lengths and Internet checksums kept up to date incrementally (RFC 1624). Frames go to
pcap/pcapng files, to an AF_PACKET TX ring (crafted in place, no copy), or to `sendmmsg` batches.
Segmentation (IPv4/IPv6 fragments, SOME/IP-TP) never copies the payload.

The library is header-only and has one dependency, [nanom](https://github.com/yoavbendor/nanom),
which supplies struct description and the encoder. It is built for automotive Ethernet (SOME/IP,
SOME/IP-TP, AUTOSAR PDUs) and sensor-data streaming, where the frame rate is what matters.

```
Eth/VLAN/IPv4/UDP/SOME-IP + 32 B payload (94 B frame), g++-13 -O2, shared x86-64 box

                                         ns/frame   instr/frame (callgrind)
nanom emit<> per layer                     ~67          1283
template, 3 patched fields, write()        ~7.5           85
template, write() then 3 patches in place  ~3.3           87
  + UDP checksum computed over payload     ~10.5         157
template -> pcap record, in place          ~8.6          146     ~12 GB/s
template -> pcapng EPB, in place           ~11.7         205     ~10 GB/s
SOME/IP-TP 64 KiB -> 48 segments           ~107 / seg            ~13 GB/s, zero copy
IPv4 fragments of 64 000 B -> 44           ~78 / frag            ~19 GB/s, zero copy
```

Each frame is byte-identical to the output of nanom's per-layer `emit` and of an independent
reference builder.

## Quick start: a SOME/IP notification, 1M frames to pcapng

```cpp
#include <nanocraft/nanocraft.hpp>
using namespace nanocraft::proto;   // stub layers; nanowire's builders later

auto t = nanocraft::compile(
    eth{.dst = {0x01, 0x00, 0x5e, 0, 0, 1}, .src = {0x02, 0, 0, 0, 0, 1}} /
    vlan{.pcp = {5}, .vid = {100}} /
    ipv4{.ttl = 8, .src = {10, 0, 0, 1}, .dst = {239, 0, 0, 1}} /
    udp{.src_port = 30501, .dst_port = 30501} /
    someip{.service_id = 0x1234, .method_id = 0x8001, .client_id = 1});
// ethertypes, IP protocol, lengths and checksums are filled in

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

**Patch points.** Every field of every layer is a patch point, named `"layer.field"`. For a
repeated layer, write `"vlan[1].vid"`. A patch point records the byte offset, the span, the bit
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
length, SOME/IP length). When the payload size changes, those fields change with it, and the
checksums are updated incrementally.

**Checksums.** Each checksum field has a policy, set with
`t.checksum("udp.checksum", csum_policy::...)`:
- `compute` (the default): RFC 1624 incremental update on every patch. The image stays a valid frame
  with an all-zero payload, so writing the real payload is one more incremental update: its
  ones'-complement sum is added.
- `zero`: the UDP "no checksum" value.
- `offload`: the folded pseudo-header sum, for NIC checksum offload.
- `keep`: whatever the layer's own value says.

**Fault injection.** For example:

```cpp
t.inject(nanocraft::faults{}.bad_checksum("ipv4.checksum").length_delta("udp.length", +4)
                            .truncate_by(3).every_nth(100));
```

A length fault keeps the checksums consistent with the wrong length, so only the length is wrong.

**Segmentation, zero copy.** `segmenter seg(t, spec)` replicates the headers up to a given layer and
cuts everything after it into pieces. Each piece is a `gather`: header bytes from a small arena plus
spans of your payload. The arena is reused on the next call. Presets:
- `ipv4_fragments(mtu)`
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
| `nanocraft/nanocraft.hpp` | umbrella (everything + stub layers) |
| `nanocraft/frame_template.hpp` | `compile`, `frame_template`, `frame_ref`, policies, faults |
| `nanocraft/segment.hpp`, `gather.hpp` | segmentation, scatter-gather frames |
| `nanocraft/pcap_writer.hpp`, `pcap_reader.hpp`, `replay.hpp` | capture sinks, reader, replay |
| `nanocraft/linux_tx.hpp` | `tx_ring` / `tx_ring_view`, `mmsg_sender`, `enable_txtime` (Linux) |
| `nanocraft/checksum.hpp` | RFC 1071 sum, RFC 1624 update |
| `nanocraft/layer.hpp` | the protocol seam: `layer_info<L>`, `stack`, `operator/` |
| `nanocraft/profile.hpp` | `NANOCRAFT_PROFILE` counters |
| `nanocraft/detail/proto_stub.hpp` | eth, vlan, ipv4, ipv6, ipv6_frag, udp, someip, someip_tp |

## Protocols and nanowire

The engine knows no protocol. Each layer is a struct registered with `NANOM_DESCRIBE`, plus a
`nanocraft::layer_info<L>` specialization that declares the following (see `layer.hpp`):
- its name
- its length fields
- its checksum fields (header kind or L4-with-pseudo-header kind)
- its pseudo-header address range, for IP layers
- its selector fields
- an optional `link()` that fills next-protocol fields

`detail/proto_stub.hpp` is the only file that knows any protocol. It will be replaced by
nanowire's per-protocol builders, which will provide the
same `layer_info` specializations.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release        # fetches nanom (pinned commit)
cmake --build build -j && ctest --test-dir build
bench/callgrind.sh build/bench/craft_bench             # instructions/frame per case
```

- Use the target `nanocraft::nanocraft`.
- Options: `NANOCRAFT_BUILD_TESTS`, `NANOCRAFT_BUILD_BENCH`, `NANOCRAFT_BUILD_EXAMPLES`,
  `NANOCRAFT_PROFILE`, `NANOCRAFT_SANITIZER=address,undefined`, `NANOCRAFT_WERROR`.
- To build against a local nanom checkout: `-DFETCHCONTENT_SOURCE_DIR_NANOM=/path/to/nanom`.
- Requires GCC 13+ or Clang 18+.

**Tests.** The independent oracles are:
- a hand-written RFC/PRS byte builder;
- nanom `emit` with `computed<>` fields;
- a naive RFC 1071 checksum;
- reference reassemblers for SOME/IP-TP and IPv4/IPv6 fragments;
- nanocraft's strict reader and nanom_shark's block scanner;
- python `dpkt` and `scapy` (`pip install dpkt scapy`; the test is skipped without them).

The live AF_PACKET tests on `lo` are skipped when the process lacks CAP_NET_RAW.

## License

Apache-2.0
