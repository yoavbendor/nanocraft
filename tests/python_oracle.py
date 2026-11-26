#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent third-party readers over the captures test_pcap and test_nanowire write.

dpkt reads every pcap / pcapng file and counts frames; scapy parses Ether/Dot1Q/IP/UDP, recomputes
the IPv4 and UDP checksums from scratch and compares, and checks the SOME/IP length field. Over
nanocraft_nanowire.pcap (templates of nanowire's layers: TCP, IPv6, QinQ, SOME/IP-SD, SoAd / IpduM)
scapy recomputes every IPv4 / UDP / TCP checksum and length over IPv4 and IPv6. Exits 77 (ctest
SKIP) when dpkt or scapy is not installed.
"""
import os
import struct
import sys

# scapy only needs `cryptography` for TLS/IPsec layers; a broken system install of it (seen in the
# wild as a pyo3 panic) must not take the oracle down, so hide it: scapy handles the ImportError.
sys.modules.setdefault("cryptography", None)

try:
    import dpkt
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Dot1Q, raw  # noqa: F401
    from scapy.utils import rdpcap
except BaseException as e:  # pragma: no cover
    print("python oracle skipped:", e)
    sys.exit(77)

d = sys.argv[1] if len(sys.argv) > 1 else "."
manifest = {}
with open(os.path.join(d, "nanocraft_manifest.txt")) as f:
    for line in f:
        k, v = line.split()
        manifest[k] = int(v)

failures = 0


def fail(msg):
    global failures
    failures += 1
    print("FAIL:", msg)


def dpkt_count(path):
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        r = dpkt.pcapng.Reader(f) if head == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        return sum(1 for _ in r)


def check_frames(path):
    n = 0
    for p in rdpcap(path):
        n += 1
        if IP not in p or UDP not in p:
            fail(f"{path}: frame {n} is not IP/UDP")
            continue
        ip, udp = p[IP], p[UDP]
        if ip.flags.MF or ip.frag:
            continue
        got_ip, got_udp = ip.chksum, udp.chksum
        q = p.copy()
        del q[IP].chksum
        del q[UDP].chksum
        q = Ether(raw(q))
        if q[IP].chksum != got_ip:
            fail(f"{path}: frame {n} IPv4 checksum {got_ip:#06x} != scapy {q[IP].chksum:#06x}")
        if got_udp != 0 and q[UDP].chksum != got_udp:
            fail(f"{path}: frame {n} UDP checksum {got_udp:#06x} != scapy {q[UDP].chksum:#06x}")
        if ip.len != len(raw(ip)) - len(ip.payload) + len(raw(ip.payload)):
            fail(f"{path}: frame {n} IPv4 total length")
        if udp.len != len(raw(udp)):
            fail(f"{path}: frame {n} UDP length {udp.len} != {len(raw(udp))}")
        body = raw(udp.payload)
        if len(body) >= 16:
            (slen,) = struct.unpack("!I", body[4:8])
            if slen != len(body) - 8:
                fail(f"{path}: frame {n} SOME/IP length {slen} != {len(body) - 8}")
    return n


def check_nanowire_frames(path):
    n = 0
    for p in rdpcap(path):
        n += 1
        l3 = IP if IP in p else IPv6 if IPv6 in p else None
        l4 = UDP if UDP in p else TCP if TCP in p else None
        if l3 is None or l4 is None:
            fail(f"{path}: frame {n} is not IP(v6)/UDP|TCP")
            continue
        got = p[l4].chksum
        q = p.copy()
        if l3 is IP:
            del q[IP].chksum
            del q[IP].len
        else:
            del q[IPv6].plen
        del q[l4].chksum
        if l4 is UDP:
            del q[UDP].len
        q = Ether(raw(q))
        if raw(q) != raw(p):
            what = "IPv4 checksum / lengths" if q[l4].chksum == got else f"{l4.__name__} checksum"
            fail(f"{path}: frame {n}: scapy rebuilds different bytes ({what})")
    return n


if len(manifest) != 4:
    fail(f"manifest lists {len(manifest)} files, expected 4")
for name, frames in manifest.items():
    path = os.path.join(d, name)
    c = dpkt_count(path)
    if c != frames:
        fail(f"{name}: dpkt read {c} frames, expected {frames}")
    s = check_frames(path)
    if s != frames:
        fail(f"{name}: scapy read {s} frames, expected {frames}")
nw_path = os.path.join(d, "nanocraft_nanowire.pcap")
nw_frames = 0
if os.path.exists(nw_path):
    nw_frames = check_nanowire_frames(nw_path)
    if nw_frames == 0 or dpkt_count(nw_path) != nw_frames:
        fail(f"nanocraft_nanowire.pcap: {nw_frames} frames")
else:
    fail("nanocraft_nanowire.pcap missing (test_nanowire writes it)")
if failures:
    print(f"python oracle: {failures} failures")
    sys.exit(1)
print("python oracle: dpkt + scapy read " + ", ".join(f"{k}={v}" for k, v in manifest.items()) +
      f", nanocraft_nanowire.pcap={nw_frames} frames; every IPv4/UDP/TCP checksum and IPv4/IPv6/UDP/SOME-IP"
      " length re-verified by scapy")
