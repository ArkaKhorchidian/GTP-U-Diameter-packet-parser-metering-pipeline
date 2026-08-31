#!/usr/bin/env bash
# Cross-check gtp-meter's per-TEID byte totals against tshark.
#
# The generator-based golden test proves the pipeline agrees with our own idea
# of the traffic. This proves it agrees with someone else's dissector, which is
# what catches a shared misreading of the spec — and unlike the golden test it
# works on real captures, where there is no ground-truth file.
#
# Usage: tools/verify_with_tshark.sh <capture.pcap> <sessions.csv> [gtp-meter]
set -euo pipefail

PCAP="${1:?usage: verify_with_tshark.sh <capture.pcap> <sessions.csv> [gtp-meter]}"
SESSIONS="${2:?usage: verify_with_tshark.sh <capture.pcap> <sessions.csv> [gtp-meter]}"
BINARY="${3:-build/bin/gtp-meter}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v tshark >/dev/null || { echo "tshark is not installed" >&2; exit 2; }
[[ -x "$BINARY" ]] || { echo "no gtp-meter binary at $BINARY" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# One row per G-PDU: the layer stack, the TEID, and every IP length in the
# frame. frame.protocols is what says which layer sits inside the tunnel —
# field presence alone cannot distinguish GTP-over-IPv6-carrying-IPv4 from
# GTP-over-IPv4-carrying-IPv6, and charging the outer header would be wrong.
echo "==> reading $PCAP with tshark"
tshark -r "$PCAP" -Y 'gtp.message == 255' -T fields \
       -e frame.protocols -e gtp.teid -e ip.len -e ipv6.plen \
       -E separator='|' -E occurrence=a 2>/dev/null \
  | python3 "$HERE/tshark_totals.py" > "$WORK/tshark.txt"

echo "==> replaying $PCAP through gtp-meter"
"$BINARY" --pcap "$PCAP" --sessions "$SESSIONS" --records "$WORK/records.ndjson" \
          --report-interval 0 --quiet > "$WORK/summary.txt"

python3 "$HERE/tshark_totals.py" --records "$SESSIONS" "$WORK/records.ndjson" \
  > "$WORK/ours.txt"

echo "==> comparing per-TEID totals"
if diff -u "$WORK/tshark.txt" "$WORK/ours.txt" > "$WORK/diff.txt"; then
  echo "MATCH: $(wc -l < "$WORK/ours.txt" | tr -d ' ') TEIDs agree with tshark to the byte"
  exit 0
fi

echo "MISMATCH between tshark and gtp-meter:" >&2
head -40 "$WORK/diff.txt" >&2
echo >&2
echo "(left = tshark, right = gtp-meter; lines are 'teid bytes')" >&2
exit 1
