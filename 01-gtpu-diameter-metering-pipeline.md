# Project 1 — GTP-U / Diameter Parser + Line-Rate Metering Pipeline (C++)

**Goal:** Parse mobile-core user-plane and charging traffic at line rate, produce per-subscriber usage records, and expose live counters — with measured tail latency. Structurally the same problem as an ITCH 5.0 market-data feed handler, transplanted into a 4G/5G packet core.

**Why this project for Minute:** Every carrier core has exactly this component. It sits on the N3/S1-U interface (GTP-U) and the Gy/Gx interfaces (Diameter). Showing you can build it — and benchmark it — demonstrates you can work inside the data plane of a cloud-native core, which is what Minute inherited from Mobi.

---

## 1. Scope

### In scope
- GTP-U (3GPP TS 29.281) header parsing, including extension headers (PDU Session Container for 5G QFI).
- Inner IPv4/IPv6 + TCP/UDP 5-tuple extraction from the encapsulated payload.
- Diameter (RFC 6733) base header + AVP parsing, focused on the Gy Credit-Control application (CCR/CCA).
- TEID → subscriber mapping table (simulating what PFCP/N4 would install).
- Per-subscriber byte/packet counters, uplink/downlink, per rating group / QFI.
- Lock-free SPSC ring buffer between parser thread and metering thread.
- Periodic usage-record emission (CDR-style) and a live counters endpoint.
- Benchmark harness: throughput and latency percentiles.

### Out of scope (mention as future work)
- Actual PFCP session establishment (fake it with a static session table).
- Full 3GPP charging logic (rating, tariffs, quota exhaustion).
- DPDK — design for it, but ship with AF_XDP or raw sockets + pcap replay.

---

## 2. Protocol Reference (what you're parsing)

### 2.1 GTP-U (UDP port 2152)

Mandatory 8-byte header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Flags: Version (3 bits, =1), PT (1, =1 for GTP), Reserved (1), E, S, PN |
| 1 | 1 | Message Type (255 = G-PDU, i.e. carries user data; 1 = Echo Req, 2 = Echo Resp, 26 = Error Ind, 31 = End Marker) |
| 2 | 2 | Length (payload length after the mandatory 8 bytes, network order) |
| 4 | 4 | TEID — Tunnel Endpoint Identifier (the key for everything) |

If any of E / S / PN is set, 4 more bytes follow: Sequence Number (2), N-PDU Number (1), Next Extension Header Type (1).

Extension headers are chained: each is `[length in 4-byte units][content][next type]`. The important one:
- **0x85 PDU Session Container** (5G N3): first byte has PDU type in top nibble; for DL PDU Session Information the QFI (6 bits) is in the second byte. This is how you attribute bytes to a QoS flow in 5G.
- 0x00 terminates the chain.

After the GTP header: the inner IP packet. Parse IPv4 (IHL, protocol, src/dst) or IPv6 (next header, src/dst), then TCP/UDP ports. Uplink vs downlink is determined by which direction the TEID belongs to (UL TEID is allocated by the UPF/SGW, DL TEID by the gNB/eNB).

### 2.2 Diameter (RFC 6733, TCP/SCTP port 3868)

20-byte header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Version (=1) |
| 1 | 3 | Message Length (including header) |
| 4 | 1 | Command Flags: R (request), P (proxiable), E (error), T (retransmit) |
| 5 | 3 | Command Code (272 = Credit-Control) |
| 8 | 4 | Application-ID (4 = Diameter Credit Control / Gy) |
| 12 | 4 | Hop-by-Hop Identifier |
| 16 | 4 | End-to-End Identifier |

AVP format: Code (4), Flags (1: V, M, P), Length (3), optional Vendor-ID (4 if V set), Data, padded to 4-byte boundary. AVPs can be grouped (nested).

AVPs that matter for metering (Gy):
- 263 Session-Id
- 264 Origin-Host, 296 Origin-Realm
- 416 CC-Request-Type (1 INITIAL, 2 UPDATE, 3 TERMINATION, 4 EVENT)
- 415 CC-Request-Number
- 443 Subscription-Id (grouped) → 450 Subscription-Id-Type (1 = IMSI), 444 Subscription-Id-Data
- 456 Multiple-Services-Credit-Control (grouped) → 432 Rating-Group, 431 Granted-Service-Unit, 446 Used-Service-Unit → 412 CC-Input-Octets, 414 CC-Output-Octets, 421 CC-Total-Octets
- 268 Result-Code (2001 = success)

The pipeline uses Gy messages to (a) learn IMSI ↔ session ↔ rating-group associations and (b) cross-check its own byte counts against reported Used-Service-Unit values.

---

## 3. Architecture

```
                ┌──────────────────────────────────────────────────────────┐
                │                       Core 0 (pinned)                    │
  NIC / pcap ──▶│  Ingest: AF_XDP or raw socket or pcap replay             │
                │     └─▶ GTP-U parser (zero-copy views over the frame)    │
                │     └─▶ Diameter parser (TCP reassembly, AVP walk)       │
                │              │                                           │
                │              ▼  MeterEvent (32–64 B, POD, cache-aligned) │
                └──────────────┼───────────────────────────────────────────┘
                               │
                    Lock-free SPSC ring (power-of-2, padded head/tail)
                               │
                ┌──────────────┼───────────────────────────────────────────┐
                │              ▼        Core 1 (pinned)                    │
                │  Metering thread                                         │
                │    TEID → SubscriberIdx   (open-addressing hash, flat)   │
                │    Subscriber[] counters  (64-B aligned, UL/DL, per RG)  │
                │    Flow table (5-tuple → flow stats), LRU eviction       │
                │    Usage record emitter (every N seconds or M bytes)     │
                └──────────────┬───────────────────────────────────────────┘
                               │
                   Shared-memory snapshot (double-buffered, seqlock)
                               │
                ┌──────────────▼───────────────────────────────────────────┐
                │  Reporter thread (not latency-critical)                  │
                │    /metrics (Prometheus text) · /subscribers/{imsi}      │
                │    usage-records.ndjson (append-only)                    │
                └──────────────────────────────────────────────────────────┘
```

### Key design decisions (and why — these are your talking points)

1. **Zero-copy parsing.** Parsers return `std::span<const uint8_t>` views and small POD structs; no allocation on the hot path, ever. Same as the ITCH handler.
2. **SPSC ring between parse and meter.** Decouples I/O jitter from state mutation, single writer/single reader so no CAS on the hot path — just acquire/release loads on padded indices. Reuse your existing SPSC queue; add a benchmark showing throughput vs. ring size.
3. **Flat hash for TEID lookup.** 32-bit key, open addressing, linear probing, power-of-2 capacity, keep load factor < 0.7. This is one L1/L2 touch in the common case. No `std::unordered_map` (pointer chasing).
4. **Counters are 64-byte aligned per subscriber.** Prevents false sharing when you later scale to multiple metering threads sharded by TEID.
5. **Seqlock snapshot for readers.** Reporter reads a consistent copy without ever blocking the metering thread.
6. **Diameter is off the fast path.** Charging messages are low volume; parse them on the ingest thread but route them to a control queue, not the metering ring.

---

## 4. Data Structures

```cpp
struct alignas(64) MeterEvent {          // what crosses the ring
  uint64_t ts_ns;
  uint32_t teid;
  uint32_t bytes;
  uint32_t src_ip, dst_ip;               // inner IPv4 (extend to v6 with a variant)
  uint16_t src_port, dst_port;
  uint8_t  proto;
  uint8_t  qfi;                          // from PDU Session Container, 0 if absent
  uint8_t  dir;                          // 0 = UL, 1 = DL
  uint8_t  msg_type;                     // 255 G-PDU, else control
  uint8_t  _pad[30];
};
static_assert(sizeof(MeterEvent) == 64);

struct alignas(64) SubscriberCounters {
  uint64_t ul_bytes, dl_bytes, ul_pkts, dl_pkts;
  uint64_t rg_bytes[4];                   // per rating group / QFI buckets
  uint64_t last_seen_ns;
  uint32_t imsi_idx;                      // index into IMSI table
  uint32_t _pad;
};
```

Subscriber table: `std::vector<SubscriberCounters>` sized at startup (e.g. 1M entries = 64 MB). TEID → index via flat hash. IMSI stored as packed `uint64_t` (15 decimal digits fit in 50 bits).

---

## 5. Implementation Plan

| Week | Deliverable |
|---|---|
| 1 | GTP-U parser with full unit tests (fixed-header, ext headers, malformed input fuzzing). Synthetic pcap generator using scapy (`GTP_U_Header`, `GTPPDUSessionContainer`). |
| 1 | Diameter parser: header, AVP iterator, grouped AVP recursion, Gy CCR/CCA extraction. Test against scapy-generated Diameter and public pcaps. |
| 2 | SPSC ring integration, metering thread, TEID table, counters, usage-record emitter. |
| 2 | pcap replay driver at max speed; raw-socket live capture; optional AF_XDP path. |
| 3 | Benchmark harness + report. Reporter thread with `/metrics`. README with results and architecture diagram. |
| 3+ | Stretch: DPDK ingest, multi-shard metering, quota thresholds → simulated Gy CCR-Update trigger. |

### Testing
- Unit: every header field, boundary conditions, truncated packets, ext-header chains, AVP padding.
- Fuzz: libFuzzer on both parsers (crash-free on arbitrary bytes is table stakes for a data plane).
- Golden: replay a pcap, compare pipeline byte counts to tshark's per-TEID totals. Must match exactly.
- Cross-check: Diameter Used-Service-Unit vs. own metered totals per session.

---

## 6. Benchmark Harness (the part that sells it)

Report all of these, on stated hardware, with the exact command line:

- **Parse throughput**: packets/sec/core for GTP-U with inner IPv4/UDP, 64-B and 1400-B payloads.
- **End-to-end latency**: timestamp at ingest → counter updated, p50 / p99 / p99.9 / p99.99 / max. Use `rdtsc` or `clock_gettime(CLOCK_MONOTONIC_RAW)`. HdrHistogram for percentiles.
- **Ring buffer**: ops/sec and per-op latency at sizes 2^10 .. 2^20.
- **Hash table**: lookup latency at load factors 0.3 / 0.5 / 0.7.
- **Baselines**: same pipeline with `std::unordered_map` and a mutex-guarded `std::queue`. Show the delta.

Environment notes to include: CPU model, isolated cores (`isolcpus`), governor set to performance, huge pages on/off, compiler + flags (`-O3 -march=native`), and whether it was a cloud VM (Mobi's core runs on AWS — running on a c7i or similar and stating that is relevant).

Present as a table plus a latency-vs-throughput curve.

---

## 7. Mapping to Prior Work

| ITCH 5.0 / market data | This project |
|---|---|
| Fixed binary header, message-type dispatch | GTP-U 8-byte header, message-type dispatch |
| Per-symbol order book state | Per-TEID subscriber counters |
| UDP multicast feed ingest | UDP GTP-U ingest on port 2152 |
| SPSC queue between feed handler and book | SPSC ring between parser and meter |
| Latency benchmarking harness | Same harness, different payload |

Say this explicitly in the README. It shows the transfer is deliberate.

---

## 8. Talking Points for Ludvig

- "This is the metering function of a UPF/SGW-U, minus PFCP. Here's where PFCP would plug in."
- "It's single-threaded per shard by design; scaling is shard-by-TEID, not locks."
- "Here's the p99.9 on one core, and here's what changes with DPDK."
- The honest framing: user-visible latency in a mobile network is dominated by the radio and backhaul; this component's job is to never be the bottleneck and never drop a byte. Correctness and zero-loss matter more than nanoseconds here — which is why the golden test against tshark is in the repo.
- Cloud-native angle: runs in a container with CPU pinning; show it on an AWS instance since that's Mobi's actual deployment model.

---

## 9. Repo Layout

```
gtp-meter/
├── README.md               # results table, architecture, how to run
├── CMakeLists.txt
├── include/
│   ├── gtpu.hpp            # header/ext-header parsing
│   ├── diameter.hpp        # header + AVP iterator
│   ├── spsc_ring.hpp       # from your existing queue work
│   ├── flat_hash.hpp
│   └── meter.hpp
├── src/
│   ├── ingest_pcap.cpp
│   ├── ingest_rawsock.cpp
│   ├── ingest_afxdp.cpp    # optional
│   ├── meter_thread.cpp
│   └── reporter.cpp
├── bench/
│   ├── bench_parse.cpp
│   ├── bench_ring.cpp
│   ├── bench_e2e.cpp
│   └── results/            # committed CSVs + plots
├── tests/
│   ├── test_gtpu.cpp
│   ├── test_diameter.cpp
│   └── fuzz/
└── tools/
    └── gen_pcap.py         # scapy synthetic traffic
```
