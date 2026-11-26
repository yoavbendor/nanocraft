#!/usr/bin/env bash
# Instructions per frame (the primary, noise-free metric) for each bench case: two callgrind runs
# with N and 2N frames, so start-up and set-up cancel out: Ir/frame = (Ir(2N) - Ir(N)) / N.
#   bench/callgrind.sh path/to/craft_bench [N]
set -euo pipefail
bin=${1:?usage: callgrind.sh path/to/craft_bench [N]}
n=${2:-100000}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%-10s %12s\n' case instr/frame
for c in emit tmpl1 tmpl3 tmpl5 tmpl3c tmpl3d pcap pcapng tp64k frag64k; do
  m=$n
  case $c in tp64k|frag64k) m=$(( n / 1000 > 0 ? n / 1000 : 1 )) ;; esac
  ir() {
    NANOCRAFT_BENCH_REPS=1 valgrind --tool=callgrind --callgrind-out-file="$tmp/cg" "$bin" "$c" "$1" >/dev/null 2>&1
    awk '/^summary:/ {print $2}' "$tmp/cg"
  }
  a=$(ir "$m"); b=$(ir $(( 2 * m )))
  unit=frame; case $c in tp64k) unit=msg ;; frag64k) unit=datagram ;; esac
  printf '%-10s %12s  (per %s)\n' "$c" $(( (b - a) / m )) "$unit"
done
