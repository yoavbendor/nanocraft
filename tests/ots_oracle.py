#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Off-the-shelf analyzer oracle: pipes `ots_craft_emitter` directly into `tshark -r -`
(with strict checksum, reassembly, VLAN/802.1ad, SOME/IP, SOME/IP-SD, SOME/IP-TP and
expert-error verifiers enabled) and `tcpdump -nn -vvv -e -r -`.

Exits 77 (CTest SKIP) when neither tshark nor tcpdump is installed.
"""
import os
import re
import shutil
import subprocess
import sys

if len(sys.argv) < 2:
    print("usage: ots_oracle.py <path-to-ots_craft_emitter>")
    sys.exit(2)

EMITTER = sys.argv[1]
TSHARK = shutil.which("tshark")
TCPDUMP = shutil.which("tcpdump")
REQUIRE_OTS = os.environ.get("NANOCRAFT_REQUIRE_OTS", "") in ("1", "true", "TRUE", "yes")

if REQUIRE_OTS:
    missing = [name for name, path in (("tshark", TSHARK), ("tcpdump", TCPDUMP)) if not path]
    if missing:
        print(f"FAIL: NANOCRAFT_REQUIRE_OTS=1 set, but missing required tool(s): {', '.join(missing)}")
        sys.exit(1)
elif not TSHARK and not TCPDUMP:
    print("ots_oracle skipped: neither tshark nor tcpdump found in PATH")
    sys.exit(77)

EXPECTED_VALID_FRAMES = 30  # 18 single + 3 IPv4 frags + 3 IPv6 frags + 3 SOME/IP-TP + 2 SOME/IP-TP(SoAd) + 1 replay
EXPECTED_FAULT_FRAMES = 5

failures = 0


def fail(msg):
    global failures
    failures += 1
    print("FAIL:", msg)


def ws_bool(val):
    """TShark 4.x prints 'True'/'False'; older versions print '1'/'0'."""
    return val in ("1", "True", "true")


def run_pipe(mode, consumer_cmd):
    """Stream `EMITTER <mode> | consumer_cmd` over an OS pipe without temporary files."""
    p_emit = subprocess.Popen([EMITTER, mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p_cons = subprocess.Popen(consumer_cmd, stdin=p_emit.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p_emit.stdout.close()  # allow SIGPIPE if consumer exits early
    cons_out, cons_err = p_cons.communicate()
    emit_err = p_emit.stderr.read()
    p_emit.wait()
    if p_emit.returncode != 0:
        fail(f"emitter({mode}) exited {p_emit.returncode}: {emit_err.decode(errors='replace')}")
    return p_cons.returncode, cons_out.decode(errors="replace"), cons_err.decode(errors="replace")


TSHARK_BASE = [
    "-n",
    "-r", "-",
    "-o", "ip.check_checksum:TRUE",
    "-o", "udp.check_checksum:TRUE",
    "-o", "tcp.check_checksum:TRUE",
    "-o", "ip.defragment:TRUE",
    "-o", "ipv6.defragment:TRUE",
    "-o", "someip.reassemble_tp:TRUE",
    "-d", "udp.port==30490,someip",
    "-d", "udp.port==30501,someip",
    "-d", "tcp.port==30502,someip",
]

TSHARK_FIELDS = [
    "frame.number",
    "frame.len",
    "eth.type",
    "eth.padding",
    "ieee8021ad.id",
    "ieee8021ad.priority",
    "ieee8021ad.dei",
    "vlan.id",
    "vlan.priority",
    "vlan.dei",
    "ip.len",
    "ip.checksum.status",
    "ip.flags.mf",
    "ip.frag_offset",
    "ipv6.plen",
    "udp.length",
    "udp.checksum",
    "udp.checksum.status",
    "tcp.checksum",
    "tcp.checksum.status",
    "someip.length",
    "someip.tp",
    "someip.tp.offset",
    "someipsd.entry.serviceid",
    "someipsd.option.ipv4address",
    "someipsd.option.port",
    "frame.interface_name",
    "frame.comment",
    "_ws.malformed",
    "_ws.expert.severity",
    "_ws.expert.message",
]


def tshark_rows(mode):
    cmd = [TSHARK] + TSHARK_BASE + ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    rc, out, err = run_pipe(mode, cmd)
    if rc != 0:
        fail(f"tshark({mode}) exited {rc}: {err}")
        return []
    rows = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < len(TSHARK_FIELDS):
            cols += [""] * (len(TSHARK_FIELDS) - len(cols))
        rows.append(dict(zip(TSHARK_FIELDS, cols)))
    return rows


def check_tshark_valid(mode, expect_pcapng=False):
    rows = tshark_rows(mode)
    if len(rows) != EXPECTED_VALID_FRAMES:
        fail(f"tshark({mode}): got {len(rows)} frames, expected {EXPECTED_VALID_FRAMES}")
        return

    # Global verifier checks across every frame in the valid suite
    for r in rows:
        fn = int(r["frame.number"])
        if r["_ws.malformed"]:
            fail(f"tshark({mode}) frame {fn}: _ws.malformed set ({r['_ws.expert.message']})")
        # Wireshark expert severity: 8388608 = PI_ERROR
        for sev in filter(None, r["_ws.expert.severity"].split(",")):
            if int(sev) >= 8388608:
                fail(f"tshark({mode}) frame {fn}: expert error severity={sev} ({r['_ws.expert.message']})")

        # IPv4 checksum status: 1 = Good
        if r["ip.checksum.status"] and r["ip.checksum.status"] != "1":
            fail(f"tshark({mode}) frame {fn}: bad IPv4 checksum status={r['ip.checksum.status']}")

        # UDP checksum status: 1 = Good, except frame 11 (intentional IPv4 csum_policy::zero -> unverified)
        if r["udp.checksum.status"]:
            if fn == 11:
                if r["udp.checksum"] != "0x0000" or r["udp.checksum.status"] == "0":
                    fail(f"tshark({mode}) frame 11: expected IPv4 UDP 0x0000 unverified, got csum={r['udp.checksum']} status={r['udp.checksum.status']}")
            elif r["udp.checksum.status"] != "1":
                fail(f"tshark({mode}) frame {fn}: bad UDP checksum csum={r['udp.checksum']} status={r['udp.checksum.status']}")

        # TCP checksum status: 1 = Good (including frame 14 where TCP checksum is 0x0000)
        if r["tcp.checksum.status"] and r["tcp.checksum.status"] != "1":
            fail(f"tshark({mode}) frame {fn}: bad TCP checksum csum={r['tcp.checksum']} status={r['tcp.checksum.status']}")

    def row(n):
        return rows[n - 1]

    # Packet size & Ethernet min-frame padding checks (frames 1, 2, 6)
    if int(row(1)["frame.len"]) != 60 or not row(1)["eth.padding"] or row(1)["ip.len"] != "44" or row(1)["udp.length"] != "24" or row(1)["someip.length"] != "8":
        fail(f"tshark({mode}) frame 1 size/padding mismatch: {row(1)}")
    if int(row(2)["frame.len"]) != 60 or not row(2)["eth.padding"] or row(2)["ip.len"] != "45" or row(2)["udp.length"] != "25" or row(2)["someip.length"] != "9":
        fail(f"tshark({mode}) frame 2 size/padding mismatch: {row(2)}")
    if int(row(6)["frame.len"]) != 1458 or row(6)["ip.len"] != "1444" or row(6)["udp.length"] != "1424" or row(6)["someip.length"] != "1408":
        fail(f"tshark({mode}) frame 6 near-MTU size mismatch: {row(6)}")

    # 802.1Q VLAN + Ethernet min_frame padding (frame 7: 49B -> 60B)
    r7 = row(7)
    if (r7["eth.type"] != "0x8100" or r7["vlan.id"] != "100" or r7["vlan.priority"] != "5"
            or not ws_bool(r7["vlan.dei"]) or int(r7["frame.len"]) != 60 or not r7["eth.padding"]
            or r7["ip.len"] != "31" or r7["udp.length"] != "11"):
        fail(f"tshark({mode}) frame 7 802.1Q padded VLAN mismatch: {r7}")

    # 802.1ad QinQ + Ethernet min_frame padding (frame 8: 53B -> 60B)
    r8 = row(8)
    if (r8["eth.type"] != "0x88a8"
            or r8["ieee8021ad.id"] != "200" or r8["ieee8021ad.priority"] != "3" or ws_bool(r8["ieee8021ad.dei"])
            or r8["vlan.id"] != "100" or r8["vlan.priority"] != "6" or not ws_bool(r8["vlan.dei"])
            or int(r8["frame.len"]) != 60 or not r8["eth.padding"]
            or r8["ip.len"] != "31" or r8["udp.length"] != "11"):
        fail(f"tshark({mode}) frame 8 802.1ad QinQ padded mismatch: {r8}")

    # Double 802.1Q stacked VLAN (frame 9: 0x8100 VID=300 / 0x8100 VID=101)
    r9 = row(9)
    deis = [ws_bool(x) for x in r9["vlan.dei"].split(",")]
    if (r9["eth.type"] != "0x8100" or r9["vlan.id"] != "300,101" or r9["vlan.priority"] != "1,4"
            or deis != [False, True] or r9["someip.length"] != "15"):
        fail(f"tshark({mode}) frame 9 double-802.1Q mismatch: {r9}")

    # RFC 768 UDP 0x0000 -> 0xFFFF incremental update (frame 10)
    if row(10)["udp.checksum"] != "0xffff" or row(10)["udp.checksum.status"] != "1":
        fail(f"tshark({mode}) frame 10 expected UDP 0xffff Good, got {row(10)['udp.checksum']} status={row(10)['udp.checksum.status']}")

    # TCP 0x0000 checksum preserved and verified Good (frame 14)
    if row(14)["tcp.checksum"] != "0x0000" or row(14)["tcp.checksum.status"] != "1":
        fail(f"tshark({mode}) frame 14 expected TCP 0x0000 Good, got {row(14)['tcp.checksum']} status={row(14)['tcp.checksum.status']}")

    # IPv6 + RFC 8200 UDP 0x0000 -> 0xFFFF (frames 15-16)
    if row(15)["ipv6.plen"] != "24" or row(15)["udp.checksum.status"] != "1":
        fail(f"tshark({mode}) frame 15 IPv6 UDP mismatch: {row(15)}")
    if row(16)["udp.checksum"] != "0xffff" or row(16)["udp.checksum.status"] != "1":
        fail(f"tshark({mode}) frame 16 expected IPv6 UDP 0xffff Good, got {row(16)['udp.checksum']} status={row(16)['udp.checksum.status']}")

    # VLAN + IPv6/TCP (frame 17)
    if row(17)["vlan.id"] != "42" or row(17)["tcp.checksum.status"] != "1":
        fail(f"tshark({mode}) frame 17 VLAN+IPv6/TCP mismatch: {row(17)}")

    # SOME/IP-SD OfferService (frame 18)
    r18 = row(18)
    if r18["someipsd.entry.serviceid"] != "0x1234" or r18["someipsd.option.ipv4address"] != "10.1.2.3" or r18["someipsd.option.port"] != "30501":
        fail(f"tshark({mode}) frame 18 SOME/IP-SD mismatch: {r18}")

    # IPv4 fragmentation reassembly (frames 19-21; frame 21 carries reassembled UDP + SOME/IP)
    if not ws_bool(row(19)["ip.flags.mf"]) or not ws_bool(row(20)["ip.flags.mf"]) or ws_bool(row(21)["ip.flags.mf"]):
        fail(f"tshark({mode}) frames 19-21 IPv4 MF flags mismatch: {[row(i)['ip.flags.mf'] for i in (19, 20, 21)]}")
    if row(21)["udp.checksum.status"] != "1" or row(21)["someip.length"] != "1008":
        fail(f"tshark({mode}) frame 21 IPv4 reassembled UDP/SOME/IP mismatch: {row(21)}")

    # IPv6 fragmentation reassembly (frames 22-24; frame 24 carries reassembled UDP + SOME/IP)
    if row(24)["udp.checksum.status"] != "1" or row(24)["someip.length"] != "1008":
        fail(f"tshark({mode}) frame 24 IPv6 reassembled UDP/SOME/IP mismatch: {row(24)}")

    # SOME/IP-TP segments (frames 25-27; offsets 0, 64, 128)
    for idx, exp_off in ((25, "0"), (26, "64"), (27, "128")):
        rt = row(idx)
        if rt["udp.checksum.status"] != "1" or not rt["someip.tp"] or rt["someip.tp.offset"] != exp_off:
            fail(f"tshark({mode}) frame {idx} SOME/IP-TP mismatch: {rt}")

    # SOME/IP-TP with SoAd PDU template tail (frames 28-29; offsets 0, 64; both UDP checksums Good)
    for idx, exp_off in ((28, "0"), (29, "64")):
        rt = row(idx)
        if rt["udp.checksum.status"] != "1" or not rt["someip.tp"] or rt["someip.tp.offset"] != exp_off:
            fail(f"tshark({mode}) frame {idx} SOME/IP-TP+SoAd mismatch: {rt}")

    # Replay + frame_ref rewritten frame (frame 30)
    r30 = row(30)
    if r30["vlan.id"] != "333" or r30["ip.checksum.status"] != "1" or r30["udp.checksum.status"] != "1" or r30["someip.length"] != "31":
        fail(f"tshark({mode}) frame 30 replay rewrite mismatch: {r30}")

    # PCAPNG-specific checks: multi-interface names + EPB comments
    if expect_pcapng:
        if row(1)["frame.interface_name"] != "eth0" or row(7)["frame.interface_name"] != "eth1":
            fail(f"tshark({mode}): PCAPNG interface names mismatch ({row(1)['frame.interface_name']}, {row(7)['frame.interface_name']})")
        if row(1)["frame.comment"] != "ipv4-udp-someip-empty-padded" or row(30)["frame.comment"] != "replay-rewritten":
            fail(f"tshark({mode}): PCAPNG EPB comments mismatch ({row(1)['frame.comment']!r}, {row(30)['frame.comment']!r})")


def check_tshark_faults():
    """Verify tshark's verifiers actually catch every intentionally injected fault."""
    rows = tshark_rows("faults_pcap")
    if len(rows) != EXPECTED_FAULT_FRAMES:
        fail(f"tshark(faults_pcap): got {len(rows)} frames, expected {EXPECTED_FAULT_FRAMES}")
        return
    if rows[0]["ip.checksum.status"] != "0":
        fail(f"tshark(faults_pcap) frame 1: expected bad IPv4 checksum (status 0), got {rows[0]['ip.checksum.status']!r}")
    if rows[1]["udp.checksum.status"] != "0":
        fail(f"tshark(faults_pcap) frame 2: expected bad UDP checksum (status 0), got {rows[1]['udp.checksum.status']!r}")
    if rows[2]["tcp.checksum.status"] != "0":
        fail(f"tshark(faults_pcap) frame 3: expected bad TCP checksum (status 0), got {rows[2]['tcp.checksum.status']!r}")
    if not rows[3]["_ws.malformed"] and not rows[3]["_ws.expert.severity"]:
        fail(f"tshark(faults_pcap) frame 4: expected malformed/expert diagnostic for +20 udp.length fault")
    if not rows[4]["_ws.malformed"] and not rows[4]["_ws.expert.severity"]:
        fail(f"tshark(faults_pcap) frame 5: expected malformed/expert diagnostic for truncated frame")


def check_tcpdump_valid(mode):
    rc, out, err = run_pipe(mode, [TCPDUMP, "-nn", "-vvv", "-e", "-r", "-"])
    if rc != 0:
        fail(f"tcpdump({mode}) exited {rc}: {err}")
        return
    pkt_lines = [ln for ln in out.splitlines() if re.match(r"^\d{2}:\d{2}:\d{2}\.", ln)]
    if len(pkt_lines) != EXPECTED_VALID_FRAMES:
        fail(f"tcpdump({mode}): read {len(pkt_lines)} frames, expected {EXPECTED_VALID_FRAMES}\n{out}")
    lower = out.lower()
    for bad in ("bad cksum", "incorrect", "truncated", "malformed", "bad-len"):
        if bad in lower:
            fail(f"tcpdump({mode}): unexpected diagnostic {bad!r} in valid stream:\n{out}")
    for expected in ("vlan 100", "0x88a8", "vlan 200", "vlan 300", "vlan 101", "vlan 333", "10.9.9.9.30501", "fd00:1::2"):
        if expected not in out:
            fail(f"tcpdump({mode}): missing expected token {expected!r}")


def check_tcpdump_faults():
    rc, out, err = run_pipe("faults_pcap", [TCPDUMP, "-nn", "-vvv", "-r", "-"])
    if rc != 0:
        fail(f"tcpdump(faults_pcap) exited {rc}: {err}")
        return
    lower = out.lower()
    if "bad cksum" not in lower and "incorrect" not in lower:
        fail(f"tcpdump(faults_pcap): did not flag injected bad checksums:\n{out}")


if TSHARK:
    check_tshark_valid("valid_pcap", expect_pcapng=False)
    check_tshark_valid("valid_pcapng", expect_pcapng=True)
    check_tshark_faults()
    print(f"tshark verifier: checked {EXPECTED_VALID_FRAMES} valid pcap + {EXPECTED_VALID_FRAMES} valid pcapng + {EXPECTED_FAULT_FRAMES} fault frames")

if TCPDUMP:
    check_tcpdump_valid("valid_pcap")
    check_tcpdump_valid("valid_pcapng")
    check_tcpdump_faults()
    print(f"tcpdump verifier: checked {EXPECTED_VALID_FRAMES} valid pcap + {EXPECTED_VALID_FRAMES} valid pcapng + {EXPECTED_FAULT_FRAMES} fault frames")

if failures:
    print(f"ots_oracle: {failures} failure(s)")
    sys.exit(1)
print("ots_oracle: OK")
