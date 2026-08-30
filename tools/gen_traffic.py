#!/usr/bin/env python3
"""Generate synthetic GTP-U + Diameter Gy captures for the metering pipeline.

Writes three files that belong together:

  <out>.pcap          the capture
  <out>-sessions.csv  the session table (what PFCP would have installed)
  <out>-expected.json ground truth: per-subscriber and per-TEID byte totals

The expected-totals file is what makes the golden test possible without
tshark: the generator knows exactly how many inner-IP bytes it put in each
tunnel, so `tests/golden_replay.py` can assert the pipeline agrees to the byte.
For real captures, `tools/verify_with_tshark.sh` cross-checks against tshark
instead.

Deliberately dependency-free. scapy builds nicer packets, but requiring it to
regenerate test data means the test data cannot be regenerated on a machine
that does not have it. The byte layouts here are the same ones the C++ parser
is tested against.
"""

from __future__ import annotations

import argparse
import json
import random
import struct
import sys
from dataclasses import dataclass, field

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
IPPROTO_TCP = 6
IPPROTO_UDP = 17
GTPU_PORT = 2152
DIAMETER_PORT = 3868
LINKTYPE_ETHERNET = 1


# --------------------------------------------------------------------------
# Packet construction
# --------------------------------------------------------------------------
def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(a: int, b: int, c: int, d: int) -> int:
    return (a << 24) | (b << 16) | (c << 8) | d


def build_ipv4(src: int, dst: int, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBHII", 0x45, 0, total_len, 0, 0x4000, 64, proto, 0, src, dst
    )
    header = header[:10] + struct.pack(">H", checksum16(header)) + header[12:]
    return header + payload


def build_ipv6(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    header = struct.pack(">IHBB", 0x60000000, len(payload), proto, 64) + src + dst
    return header + payload


def build_udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_tcp(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    return (
        struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x18, 0xFFFF, 0, 0)
        + payload
    )


def build_ethernet(payload: bytes, ethertype: int = ETH_P_IPV4) -> bytes:
    return b"\x02\x03\x04\x05\x06\x07" + b"\x0a\x0b\x0c\x0d\x0e\x0f" + struct.pack(
        ">H", ethertype
    ) + payload


def build_gtpu(teid: int, payload: bytes, qfi: int | None = None,
               pdu_type: int = 0, msg_type: int = 255, seq: int | None = None) -> bytes:
    """GTP-U header per TS 29.281, optionally with a PDU Session Container."""
    ext = b""
    first_ext = 0x00
    if qfi is not None:
        # [len=1][pdu type<<4][flags|qfi][next=0] -> 4 bytes
        ext = bytes([1, (pdu_type & 0x0F) << 4, qfi & 0x3F, 0x00])
        first_ext = 0x85

    flags = 0x30  # version 1, PT=1
    if ext:
        flags |= 0x04
    if seq is not None:
        flags |= 0x02
    has_optional = bool(ext) or seq is not None

    optional = b""
    if has_optional:
        optional = struct.pack(">HBB", seq or 0, 0, first_ext) + ext

    length = len(optional) + len(payload)
    return struct.pack(">BBHI", flags, msg_type, length, teid) + optional + payload


# --------------------------------------------------------------------------
# Diameter
# --------------------------------------------------------------------------
def avp(code: int, data: bytes, flags: int = 0x40, vendor: int | None = None) -> bytes:
    if vendor is not None:
        flags |= 0x80
        header = struct.pack(">IBBH", code, flags, 0, 12 + len(data))[:5]
        out = struct.pack(">I", code) + bytes([flags]) + (12 + len(data)).to_bytes(3, "big")
        out += struct.pack(">I", vendor) + data
    else:
        out = struct.pack(">I", code) + bytes([flags]) + (8 + len(data)).to_bytes(3, "big")
        out += data
    while len(out) % 4:
        out += b"\x00"
    return out


def avp_u32(code: int, value: int) -> bytes:
    return avp(code, struct.pack(">I", value))


def avp_u64(code: int, value: int) -> bytes:
    return avp(code, struct.pack(">Q", value))


def avp_str(code: int, value: str) -> bytes:
    return avp(code, value.encode())


def build_diameter(command: int, app_id: int, request: bool, avps: bytes,
                   hbh: int = 0x11111111, e2e: int = 0x22222222) -> bytes:
    length = 20 + len(avps)
    header = (
        bytes([1])
        + length.to_bytes(3, "big")
        + bytes([0x80 if request else 0x00])
        + command.to_bytes(3, "big")
        + struct.pack(">III", app_id, hbh, e2e)
    )
    return header + avps


def build_ccr(session_id: str, imsi: str, request_type: int, request_number: int,
              rating_group: int, used_input: int, used_output: int) -> bytes:
    avps = avp_str(263, session_id)
    avps += avp_str(264, "pgw.example.com")
    avps += avp_str(296, "example.com")
    avps += avp_u32(416, request_type)
    avps += avp_u32(415, request_number)
    avps += avp(443, avp_u32(450, 1) + avp_str(444, imsi))
    usu = avp_u64(412, used_input) + avp_u64(414, used_output) + avp_u64(
        421, used_input + used_output
    )
    avps += avp(456, avp_u32(432, rating_group) + avp(446, usu))
    return build_diameter(272, 4, True, avps)


def build_cca(session_id: str, request_type: int, request_number: int,
              rating_group: int, granted: int) -> bytes:
    avps = avp_str(263, session_id)
    avps += avp_u32(268, 2001)
    avps += avp_str(264, "ocs.example.com")
    avps += avp_str(296, "example.com")
    avps += avp_u32(416, request_type)
    avps += avp_u32(415, request_number)
    avps += avp(456, avp_u32(432, rating_group) + avp(431, avp_u64(421, granted)))
    return build_diameter(272, 4, False, avps)


# --------------------------------------------------------------------------
# pcap writer
# --------------------------------------------------------------------------
class PcapWriter:
    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts_ns: int, data: bytes) -> None:
        self.fh.write(
            struct.pack("<IIII", ts_ns // 1_000_000_000,
                        (ts_ns % 1_000_000_000) // 1000, len(data), len(data))
        )
        self.fh.write(data)

    def close(self) -> None:
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# --------------------------------------------------------------------------
# Scenario
# --------------------------------------------------------------------------
@dataclass
class Subscriber:
    imsi: str
    ul_teid: int
    dl_teid: int
    rating_group: int
    ue_ip: int
    msisdn: str
    qfi: int | None
    ul_bytes: int = 0
    dl_bytes: int = 0
    ul_packets: int = 0
    dl_packets: int = 0
    bytes_by_teid: dict[int, int] = field(default_factory=dict)


def generate(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)
    subs: list[Subscriber] = []
    for i in range(args.subscribers):
        subs.append(
            Subscriber(
                imsi=f"3101500{i:08d}",
                ul_teid=args.base_teid + i * 2,
                dl_teid=args.base_teid + i * 2 + 1,
                rating_group=rng.choice([10, 20, 30]),
                ue_ip=ipv4(10, 45, (i >> 8) & 0xFF, i & 0xFF),
                msisdn=f"1555{i:07d}",
                qfi=rng.choice([None, 1, 5, 9]) if args.five_g else None,
            )
        )

    servers = [ipv4(93, 184, 216, 34), ipv4(142, 250, 74, 46), ipv4(1, 1, 1, 1)]
    outer_gnb = ipv4(192, 168, 100, 1)
    outer_upf = ipv4(192, 168, 100, 2)

    ts = 1_700_000_000 * 1_000_000_000
    step = int(1e9 / max(args.pps, 1))

    with PcapWriter(args.out + ".pcap") as pcap:
        for n in range(args.packets):
            sub = subs[rng.randrange(len(subs))]
            uplink = rng.random() < args.uplink_ratio
            payload_len = rng.choice(args.sizes)
            server = servers[rng.randrange(len(servers))]

            if uplink:
                inner_src, inner_dst = sub.ue_ip, server
                sport, dport = rng.randrange(20000, 60000), rng.choice([80, 443, 53])
                teid, pdu_type = sub.ul_teid, 1
                outer_src, outer_dst = outer_gnb, outer_upf
            else:
                inner_src, inner_dst = server, sub.ue_ip
                sport, dport = rng.choice([80, 443, 53]), rng.randrange(20000, 60000)
                teid, pdu_type = sub.dl_teid, 0
                outer_src, outer_dst = outer_upf, outer_gnb

            body = bytes((i * 31 + 7) & 0xFF for i in range(payload_len))
            if dport == 53 or sport == 53:
                l4 = build_udp(sport, dport, body)
                inner = build_ipv4(inner_src, inner_dst, IPPROTO_UDP, l4)
            else:
                l4 = build_tcp(sport, dport, n + 1, body)
                inner = build_ipv4(inner_src, inner_dst, IPPROTO_TCP, l4)

            gtp = build_gtpu(teid, inner, qfi=sub.qfi, pdu_type=pdu_type)
            outer = build_ipv4(outer_src, outer_dst, IPPROTO_UDP,
                               build_udp(GTPU_PORT, GTPU_PORT, gtp))
            pcap.write(ts, build_ethernet(outer))
            ts += step

            # Ground truth: the pipeline meters the inner IP total length.
            if uplink:
                sub.ul_bytes += len(inner)
                sub.ul_packets += 1
            else:
                sub.dl_bytes += len(inner)
                sub.dl_packets += 1
            sub.bytes_by_teid[teid] = sub.bytes_by_teid.get(teid, 0) + len(inner)

        # A GTP-U echo request/response pair: control PDUs must not be charged.
        if args.echo:
            for msg_type in (1, 2):
                gtp = build_gtpu(0, b"", msg_type=msg_type, seq=1)
                outer = build_ipv4(outer_gnb, outer_upf, IPPROTO_UDP,
                                   build_udp(GTPU_PORT, GTPU_PORT, gtp))
                pcap.write(ts, build_ethernet(outer))
                ts += step

        # Gy charging: report exactly what each subscriber actually used, so a
        # correct pipeline cross-checks to zero difference.
        if args.diameter:
            for i, sub in enumerate(subs):
                session_id = f"ocs.example.com;1;{i};0"
                ccr = build_ccr(session_id, sub.imsi, 2, 1, sub.rating_group,
                                sub.ul_bytes, sub.dl_bytes)
                outer = build_ipv4(outer_upf, ipv4(192, 168, 200, 1), IPPROTO_TCP,
                                   build_tcp(50000 + i, DIAMETER_PORT, 1, ccr))
                pcap.write(ts, build_ethernet(outer))
                ts += step

                cca = build_cca(session_id, 2, 1, sub.rating_group, 100 << 20)
                outer = build_ipv4(ipv4(192, 168, 200, 1), outer_upf, IPPROTO_TCP,
                                   build_tcp(DIAMETER_PORT, 50000 + i, 1, cca))
                pcap.write(ts, build_ethernet(outer))
                ts += step

        # Background traffic the pipeline must ignore without counting it.
        if args.noise:
            for _ in range(args.noise):
                body = bytes(rng.randrange(256) for _ in range(64))
                outer = build_ipv4(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), IPPROTO_UDP,
                                   build_udp(12345, 80, body))
                pcap.write(ts, build_ethernet(outer))
                ts += step

    with open(args.out + "-sessions.csv", "w") as fh:
        fh.write("imsi,ul_teid,dl_teid,rating_group,msisdn,apn\n")
        for sub in subs:
            fh.write(
                f"{sub.imsi},{sub.ul_teid},{sub.dl_teid},{sub.rating_group},"
                f"{sub.msisdn},internet\n"
            )

    expected = {
        "generator": "tools/gen_traffic.py",
        "seed": args.seed,
        "packets": args.packets,
        "totals": {
            "ul_bytes": sum(s.ul_bytes for s in subs),
            "dl_bytes": sum(s.dl_bytes for s in subs),
            "ul_packets": sum(s.ul_packets for s in subs),
            "dl_packets": sum(s.dl_packets for s in subs),
        },
        "subscribers": [
            {
                "imsi": s.imsi,
                "ul_teid": s.ul_teid,
                "dl_teid": s.dl_teid,
                "rating_group": s.rating_group,
                "qfi": s.qfi,
                "ul_bytes": s.ul_bytes,
                "dl_bytes": s.dl_bytes,
                "ul_packets": s.ul_packets,
                "dl_packets": s.dl_packets,
                "bytes_by_teid": {str(k): v for k, v in sorted(s.bytes_by_teid.items())},
            }
            for s in subs
        ],
    }
    with open(args.out + "-expected.json", "w") as fh:
        json.dump(expected, fh, indent=2)
        fh.write("\n")

    print(f"wrote {args.out}.pcap ({args.packets} user-plane packets)")
    print(f"wrote {args.out}-sessions.csv ({len(subs)} sessions)")
    print(f"wrote {args.out}-expected.json")
    print(f"  uplink   {expected['totals']['ul_bytes']:>12} bytes "
          f"/ {expected['totals']['ul_packets']} packets")
    print(f"  downlink {expected['totals']['dl_bytes']:>12} bytes "
          f"/ {expected['totals']['dl_packets']} packets")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="traffic", help="output prefix (default: traffic)")
    p.add_argument("--packets", type=int, default=10000, help="user-plane packets")
    p.add_argument("--subscribers", type=int, default=50)
    p.add_argument("--base-teid", type=int, default=0x10000)
    p.add_argument("--pps", type=int, default=100000, help="timestamp spacing")
    p.add_argument("--uplink-ratio", type=float, default=0.35)
    p.add_argument("--sizes", type=int, nargs="+", default=[64, 128, 512, 1400])
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--noise", type=int, default=100, help="non-GTP packets to mix in")
    p.add_argument("--five-g", action="store_true", default=True,
                   help="include 5G PDU Session Containers (QFI)")
    p.add_argument("--no-five-g", dest="five_g", action="store_false")
    p.add_argument("--diameter", action="store_true", default=True,
                   help="append Gy CCR/CCA pairs")
    p.add_argument("--no-diameter", dest="diameter", action="store_false")
    p.add_argument("--echo", action="store_true", default=True,
                   help="include GTP-U echo request/response")
    p.add_argument("--no-echo", dest="echo", action="store_false")
    return generate(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
