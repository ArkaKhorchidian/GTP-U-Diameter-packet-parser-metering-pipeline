# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org).

## 1.0.0

First complete release: a working GTP-U / Diameter metering pipeline with
measured performance and a byte-exact correctness proof.

### Pipeline

- GTP-U parsing (TS 29.281): mandatory header, optional sequence/N-PDU fields,
  bounded extension-header chain, and the 5G PDU Session Container (TS 38.415)
  carrying QFI and RQI.
- Inner packet decode: IPv4 with fragmentation and snaplen clamping, IPv6 with
  extension-header chain, TCP/UDP/SCTP, Ethernet with stacked VLAN tags, and a
  direction-sensitive 64-bit flow key.
- Diameter (RFC 6733) base header and AVP iterator with correct padding and
  depth-capped grouped-AVP recursion; Gy (RFC 4006) extraction of Session-Id,
  Subscription-Id, MSCC, Used- and Granted-Service-Unit and Result-Code.
- Metering engine: TEID-keyed subscriber counters in exactly one cache line
  each, per-rating-group and per-QFI accounting slots, a bounded-LRU flow table,
  CDR-style usage records with per-subscriber deltas and gapless sequence
  numbers, and a Gy cross-check against the pipeline's own totals.
- Lock-free SPSC rings between ingest, metering and reporting; a seqlock for
  global counters and a refcounted N-buffer publisher for the large tables.
- Static CSV session table standing in for PFCP/N4, with session install,
  modification and release.
- pcap replay and live capture (AF_PACKET on Linux, BPF on macOS), pcap file
  reading and writing implemented directly with no libpcap dependency.
- HTTP reporter: `/metrics` (Prometheus), `/stats`, `/subscribers`,
  `/subscribers/{imsi}`, `/flows`, `/healthz`.
- `gtp-meter` CLI with replay pacing, CPU pinning, busy-poll mode and NDJSON
  usage-record output.

### Measured

On an Apple M5, single core, with the caveats in the README:

- 79-154 Mpps parse throughput for full GTP-U decap.
- 125 ns p50 end-to-end latency, flat from 0.5 to 8 Mpps.
- Saturation at 15 Mpps / 88 Gbps with zero drops.
- 14x lower p50 and 29x lower p99 than a mutex + `std::unordered_map` baseline.

### Verification

- 18 test binaries covering parsers, lock-free structures, the metering engine,
  the reporter and the full runtime with real threads.
- Golden replay requiring byte-exact agreement with generated ground truth.
- tshark cross-check against Wireshark's dissector for real captures.
- Four fuzz targets, building with libFuzzer where available and a standalone
  driver where not; ~90M executions under ASan+UBSan with no findings.
- CI across gcc and clang, Release and Debug, Linux and macOS, with ASan+UBSan
  and TSan builds and a pinned clang-format gate.

### Fixed during development

- Snapshot publication scanned the whole flow table on the metering thread,
  putting 900 µs into p99.9 packet latency. The scan is now bounded per tick and
  runs only while a reader is asking for the data.
- Replay pacing used `sleep_for`, whose millisecond granularity turned a paced
  replay into a burst generator and measured the pacer rather than the pipeline.
- A session re-install with a moved TEID left the old tunnel bound, metering
  traffic to the subscriber with a stale direction.
- A full TEID table dropped bindings silently; it now fails the install and
  exports `gtpm_teid_bind_failures_total`.
- The seqlock copied its payload a byte at a time, which starved readers behind
  a busy writer; it now copies machine words.
