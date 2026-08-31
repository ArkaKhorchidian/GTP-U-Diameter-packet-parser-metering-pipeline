#!/usr/bin/env python3
"""Per-TEID byte totals, from either tshark output or gtp-meter usage records.

Two modes, both printing `<teid> <bytes>` sorted by TEID so the two can be
diffed directly:

  tshark ... | tshark_totals.py
      Aggregates tshark's `gtp.teid|ip.len|ipv6.plen` rows.

  tshark_totals.py --records sessions.csv records.ndjson
      Aggregates gtp-meter's NDJSON usage records, mapping each subscriber's
      uplink and downlink deltas back onto its TEIDs via the session table.

Kept in Python rather than awk on purpose: parsing hex TEIDs portably needs
gawk's strtonum, and Ubuntu ships mawk.
"""

from __future__ import annotations

import argparse
import json
import sys


def parse_teid(text: str) -> int | None:
    text = text.strip()
    if not text:
        return None
    # tshark renders TEIDs as 0x-prefixed hex, but has printed plain decimal in
    # older releases; accept both rather than depending on the version.
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def totals_from_tshark(stream) -> dict[int, int]:
    totals: dict[int, int] = {}
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("|")
        while len(parts) < 3:
            parts.append("")
        teid = parse_teid(parts[0])
        if teid is None:
            continue
        if parts[1].strip():
            length = int(parts[1].strip())          # inner IPv4 total length
        elif parts[2].strip():
            length = 40 + int(parts[2].strip())     # IPv6: header + payload
        else:
            continue
        totals[teid] = totals.get(teid, 0) + length
    return totals


def totals_from_records(sessions_path: str, records_path: str) -> dict[int, int]:
    sessions: dict[str, tuple[int, int]] = {}
    with open(sessions_path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("imsi,"):
                continue
            cols = line.split(",")
            if len(cols) < 3:
                continue
            sessions[cols[0]] = (int(cols[1], 0), int(cols[2], 0))

    totals: dict[int, int] = {}
    with open(records_path) as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            binding = sessions.get(rec["imsi"])
            if binding is None:
                continue
            ul_teid, dl_teid = binding
            totals[ul_teid] = totals.get(ul_teid, 0) + rec["ul_bytes"]
            totals[dl_teid] = totals.get(dl_teid, 0) + rec["dl_bytes"]
    return totals


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--records", nargs=2, metavar=("SESSIONS_CSV", "RECORDS_NDJSON"))
    args = ap.parse_args()

    if args.records:
        totals = totals_from_records(args.records[0], args.records[1])
    else:
        totals = totals_from_tshark(sys.stdin)

    for teid in sorted(totals):
        if totals[teid]:
            print(f"{teid} {totals[teid]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
