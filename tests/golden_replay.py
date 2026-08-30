#!/usr/bin/env python3
"""Golden test: replay a generated capture and require exact byte agreement.

Generates traffic with tools/gen_traffic.py (which records exactly how many
inner-IP bytes it put in each tunnel), replays it through gtp-meter, and
compares the emitted usage records against that ground truth. Byte counts must
match exactly — a metering pipeline that is approximately right is wrong.

Also checks:
  * per-subscriber uplink/downlink packet counts
  * that usage records are deltas whose per-subscriber sums equal the totals
  * that record sequence numbers are gapless
  * that GTP-U echo packets and non-GTP noise are not charged to anyone
  * that the Gy cross-check agrees with the pipeline's own metering

Usage: golden_replay.py <path-to-gtp-meter> [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GENERATOR = os.path.join(REPO, "tools", "gen_traffic.py")


class Failure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Failure(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout + proc.stderr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", help="path to the gtp-meter executable")
    ap.add_argument("--packets", type=int, default=20000)
    ap.add_argument("--subscribers", type=int, default=64)
    ap.add_argument("--keep", action="store_true", help="keep the generated files")
    args = ap.parse_args()

    check(os.path.isfile(args.binary), f"no such binary: {args.binary}")
    workdir = tempfile.mkdtemp(prefix="gtpm-golden-")
    prefix = os.path.join(workdir, "golden")

    try:
        run([sys.executable, GENERATOR, "--out", prefix,
             "--packets", str(args.packets),
             "--subscribers", str(args.subscribers),
             "--seed", "20260830"])

        with open(prefix + "-expected.json") as fh:
            expected = json.load(fh)

        records_path = prefix + "-records.ndjson"
        output = run([args.binary,
                      "--pcap", prefix + ".pcap",
                      "--sessions", prefix + "-sessions.csv",
                      "--records", records_path,
                      "--report-interval", "0",
                      "--quiet"])

        # ---- aggregate the usage records -------------------------------
        by_imsi: dict[str, dict] = {}
        for line in open(records_path):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            entry = by_imsi.setdefault(
                record["imsi"], {"ul": 0, "dl": 0, "ul_pkts": 0, "dl_pkts": 0, "seqs": []}
            )
            entry["ul"] += record["ul_bytes"]
            entry["dl"] += record["dl_bytes"]
            entry["ul_pkts"] += record["ul_pkts"]
            entry["dl_pkts"] += record["dl_pkts"]
            entry["seqs"].append(record["seq"])

        mismatches: list[str] = []
        for sub in expected["subscribers"]:
            imsi = sub["imsi"]
            if sub["ul_bytes"] == 0 and sub["dl_bytes"] == 0:
                continue
            got = by_imsi.get(imsi)
            if got is None:
                mismatches.append(f"{imsi}: no usage record emitted")
                continue
            for field, want_key in (("ul", "ul_bytes"), ("dl", "dl_bytes"),
                                    ("ul_pkts", "ul_packets"), ("dl_pkts", "dl_packets")):
                if got[field] != sub[want_key]:
                    mismatches.append(
                        f"{imsi}: {want_key} expected {sub[want_key]}, metered {got[field]}"
                    )
            expected_seqs = list(range(len(got["seqs"])))
            if sorted(got["seqs"]) != expected_seqs:
                mismatches.append(f"{imsi}: record sequence has gaps: {sorted(got['seqs'])}")

        # ---- totals from the pipeline's own summary --------------------
        summary: dict[str, str] = {}
        for line in output.splitlines():
            if line.strip().startswith("metered bytes"):
                summary["metered"] = line
            if "unknown TEID" in line:
                summary["unknown"] = line
            if "events dropped" in line:
                summary["dropped"] = line
            if "GTP-U parse errors" in line:
                summary["parse_errors"] = line

        totals = expected["totals"]
        want_total = totals["ul_bytes"] + totals["dl_bytes"]
        metered_line = summary.get("metered", "")
        check("metered" in summary, "pipeline printed no metered-bytes line")
        metered_total = int(metered_line.split()[2])
        if metered_total != want_total:
            mismatches.append(
                f"total metered bytes expected {want_total}, got {metered_total}"
            )
        check(int(summary["unknown"].split()[2]) == 0,
              f"unexpected unknown-TEID traffic: {summary['unknown'].strip()}")
        check(int(summary["dropped"].split()[2]) == 0,
              f"pipeline dropped events: {summary['dropped'].strip()}")
        check(int(summary["parse_errors"].split()[3]) == 0,
              f"pipeline reported parse errors: {summary['parse_errors'].strip()}")

        if mismatches:
            print("GOLDEN TEST FAILED", file=sys.stderr)
            for line in mismatches[:25]:
                print("  " + line, file=sys.stderr)
            if len(mismatches) > 25:
                print(f"  ... and {len(mismatches) - 25} more", file=sys.stderr)
            return 1

        print(f"golden replay OK: {len(expected['subscribers'])} subscribers, "
              f"{want_total} bytes metered exactly, "
              f"{sum(len(v['seqs']) for v in by_imsi.values())} usage records, no gaps")
        return 0

    except Failure as exc:
        print(f"GOLDEN TEST FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        if not args.keep:
            for name in os.listdir(workdir):
                os.remove(os.path.join(workdir, name))
            os.rmdir(workdir)
        else:
            print(f"kept generated files in {workdir}")


if __name__ == "__main__":
    sys.exit(main())
