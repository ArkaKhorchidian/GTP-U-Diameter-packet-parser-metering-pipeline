#!/usr/bin/env python3
"""Per-TEID byte totals, from either tshark output or gtp-meter usage records.

Two modes, both printing `<teid> <bytes>` sorted by TEID so the two can be
diffed directly:

  tshark ... | tshark_totals.py
      Aggregates tshark's `frame.protocols|gtp.teid|ip.len|ipv6.plen` rows.

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


def inner_l3(protocols: str) -> str | None:
    """Return "ip", "ipv6", or None for the layer directly inside the tunnel.

    tshark's frame.protocols reads like `eth:ethertype:ip:udp:gtp:ip:udp:data`.
    The layer after the last `gtp` is the encapsulated one. Guessing from field
    presence instead does not work: a GTP-U-over-IPv6 capture carrying inner
    IPv4 has exactly one occurrence of each, same as the reverse.
    """
    layers = [layer for layer in protocols.split(":") if layer]
    for index in range(len(layers) - 1, -1, -1):
        if layers[index].startswith("gtp"):
            if index + 1 < len(layers):
                return layers[index + 1]
            return None
    return None


def totals_from_tshark(stream) -> dict[int, int]:
    totals: dict[int, int] = {}
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("|")
        while len(parts) < 4:
            parts.append("")
        protocols, teid_text, ip_lens, ipv6_plens = parts[0], parts[1], parts[2], parts[3]

        teid = parse_teid(teid_text)
        if teid is None:
            continue

        layer = inner_l3(protocols)
        if layer == "ip":
            values = [v for v in ip_lens.split(",") if v.strip()]
            if not values:
                continue
            length = int(values[-1])            # innermost IPv4 total length
        elif layer == "ipv6":
            values = [v for v in ipv6_plens.split(",") if v.strip()]
            if not values:
                continue
            length = 40 + int(values[-1])       # IPv6 header + payload length
        else:
            continue                            # not IP inside the tunnel
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
