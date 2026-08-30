#!/usr/bin/env python3
"""Plot the latency-versus-throughput curve from bench_e2e output as an SVG.

Hand-rolled SVG rather than matplotlib: the benchmark suite should regenerate
its own plots on a bare build machine, and a plotting dependency that is not
installed is a plot that never gets refreshed.

Usage: plot_latency.py e2e.csv out.svg
"""

from __future__ import annotations

import math
import sys

W, H = 760, 460
PAD_L, PAD_R, PAD_T, PAD_B = 78, 150, 42, 58

SERIES = [
    ("p50", "#2563eb"),
    ("p99", "#0891b2"),
    ("p99.9", "#d97706"),
    ("p99.99", "#dc2626"),
]


def parse(path: str):
    """Return {pipeline: [(achieved_mpps, {quantile: ns})]}."""
    rows: dict[str, list] = {}
    header: list[str] | None = None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cells = [c.strip() for c in line.split(",")]
            if cells[0] == "pipeline":
                header = cells
                continue
            if header is None or len(cells) != len(header):
                continue
            record = dict(zip(header, cells))
            try:
                achieved = float(record["achieved"])
                point = (achieved, {q: float(record[q]) for q, _ in SERIES})
            except (KeyError, ValueError):
                continue
            rows.setdefault(record["pipeline"], []).append(point)
    for points in rows.values():
        points.sort(key=lambda p: p[0])
    return rows


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    data = parse(sys.argv[1])
    if not data:
        print(f"no usable rows in {sys.argv[1]}", file=sys.stderr)
        return 1

    xs = [p[0] for pts in data.values() for p in pts]
    ys = [v for pts in data.values() for p in pts for v in p[1].values() if v > 0]
    x_max = max(xs) * 1.08
    y_min, y_max = max(min(ys), 1.0), max(ys) * 1.5

    def sx(v: float) -> float:
        return PAD_L + (v / x_max) * (W - PAD_L - PAD_R)

    def sy(v: float) -> float:
        v = max(v, y_min)
        lo, hi = math.log10(y_min), math.log10(y_max)
        return H - PAD_B - ((math.log10(v) - lo) / (hi - lo)) * (H - PAD_T - PAD_B)

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="ui-sans-serif,system-ui,sans-serif">',
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{PAD_L}" y="24" font-size="15" font-weight="600" fill="#111827">'
        f"End-to-end latency vs. achieved throughput</text>",
        f'<text x="{PAD_L}" y="40" font-size="11" fill="#6b7280">'
        f"frame in → subscriber counter updated; log-scale latency</text>",
    ]

    # Log-decade gridlines.
    decade = 10 ** math.floor(math.log10(y_min))
    while decade <= y_max:
        for mult in (1, 2, 5):
            value = decade * mult
            if not (y_min <= value <= y_max):
                continue
            y = sy(value)
            out.append(
                f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{W-PAD_R}" y2="{y:.1f}" '
                f'stroke="#e5e7eb" stroke-width="1"/>'
            )
            label = f"{value/1000:g} µs" if value >= 1000 else f"{value:g} ns"
            out.append(
                f'<text x="{PAD_L-8}" y="{y+4:.1f}" font-size="10" fill="#6b7280" '
                f'text-anchor="end">{label}</text>'
            )
        decade *= 10

    for i in range(0, 6):
        v = x_max * i / 5
        x = sx(v)
        out.append(
            f'<line x1="{x:.1f}" y1="{PAD_T}" x2="{x:.1f}" y2="{H-PAD_B}" '
            f'stroke="#f3f4f6" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x:.1f}" y="{H-PAD_B+18}" font-size="10" fill="#6b7280" '
            f'text-anchor="middle">{v:.1f}</text>'
        )
    out.append(
        f'<text x="{(PAD_L+W-PAD_R)/2:.0f}" y="{H-14}" font-size="11" fill="#374151" '
        f'text-anchor="middle">achieved throughput (Mpps, single core)</text>'
    )

    legend_y = PAD_T + 6
    for pipeline, points in sorted(data.items()):
        dashed = pipeline != "gtp-meter"
        for quantile, color in SERIES:
            path = " ".join(
                f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(p[quantile]):.1f}"
                for i, (x, p) in enumerate(points)
            )
            dash = ' stroke-dasharray="4,3"' if dashed else ""
            out.append(
                f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2"{dash}/>'
            )
            for x, p in points:
                out.append(
                    f'<circle cx="{sx(x):.1f}" cy="{sy(p[quantile]):.1f}" r="2.6" '
                    f'fill="{color}"/>'
                )
        out.append(
            f'<text x="{W-PAD_R+14}" y="{legend_y}" font-size="11" font-weight="600" '
            f'fill="#111827">{pipeline}</text>'
        )
        legend_y += 16
        for quantile, color in SERIES:
            out.append(
                f'<line x1="{W-PAD_R+14}" y1="{legend_y-4}" x2="{W-PAD_R+34}" '
                f'y2="{legend_y-4}" stroke="{color}" stroke-width="2"'
                + (' stroke-dasharray="4,3"' if dashed else "")
                + "/>"
            )
            out.append(
                f'<text x="{W-PAD_R+40}" y="{legend_y}" font-size="10" fill="#374151">'
                f"{quantile}</text>"
            )
            legend_y += 15
        legend_y += 10

    out.append(
        f'<line x1="{PAD_L}" y1="{H-PAD_B}" x2="{W-PAD_R}" y2="{H-PAD_B}" '
        f'stroke="#9ca3af" stroke-width="1"/>'
    )
    out.append(
        f'<line x1="{PAD_L}" y1="{PAD_T}" x2="{PAD_L}" y2="{H-PAD_B}" '
        f'stroke="#9ca3af" stroke-width="1"/>'
    )
    out.append("</svg>")

    with open(sys.argv[2], "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"wrote {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
