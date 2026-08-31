# Architecture

How the pieces fit, and why each boundary is where it is.

## Threads and ownership

Three threads, and exactly one owner for every piece of mutable state.

| Thread | Owns | Never does |
|---|---|---|
| Ingest | packet buffers, `IngestStats` | allocate, lock, touch metering state |
| Metering | `MeterEngine` — counters, TEID table, flow table, emission bookkeeping | allocate, lock, do I/O |
| Reporter | the NDJSON file, the HTTP socket | touch metering state directly |

Nothing is shared mutable. The only cross-thread communication is through three
SPSC rings and two snapshot mechanisms, all of which are one-writer structures.
That is the property that makes the whole thing lock-free without any clever
locking: there is nothing to lock.

```
ingest ──MeterEvent──▶ meter ring ──▶ metering ──UsageRecord──▶ record ring ──▶ reporter
   └────GyEvent──────▶ gy ring ─────▶ metering
                                       │
                              seqlock (PipelineSnapshot)  ─────▶ reporter, HTTP
                              N-buffer (DetailSnapshot)   ─────▶ reporter, HTTP
```

## The per-packet budget

On the metering thread, one packet touches:

1. **TEID table line.** `hash_u32(teid) & mask` into a flat array; the 8-byte
   binding (subscriber index, direction, accounting slot) rides in the same line
   as the key. ~1.05 probes at load factor 0.7.
2. **Subscriber counter line.** Exactly 64 bytes, 64-byte aligned. Direction,
   byte and packet counters, the three accounting slots and `last_seen_ns` all
   live here.
3. **Flow entry line** (optional, `--no-flows` disables it). Exactly 64 bytes.

A 5G packet carrying a QFI additionally touches the cold `SubscriberInfo` line
to resolve which accounting slot that QFI maps to. Everything else — identity,
emission bookkeeping, Gy cross-check state — is in that cold array and is never
touched by the packet path.

## Why the split between hot and cold

`SubscriberCounters` has to be exactly one cache line, so the fields that change
per packet are the only fields in it. The obvious layout (IMSI, first-seen,
emitted-so-far counters, and the live counters together) is 2-3 cache lines and
touches all of them on every packet, for data that changes once every ten
seconds. The split costs an extra indirection at reporting time and saves a
cache line per packet.

The same logic decides what crosses the ring: `MeterEvent` is a copy, not a
pointer into the frame, because by the time the metering thread gets to it the
NIC may have reused that buffer. Copying 64 bytes is cheaper than the
lifetime-management scheme that would let it be a reference.

## Back-pressure policy

Every queue in the pipeline drops rather than blocks, and every drop is counted
and exported:

- **Meter ring full** → `gtpm_ingest_events_dropped_total`. Blocking here would
  push back on the NIC, where the loss is invisible and larger.
- **Record ring full** → `gtpm_usage_records_dropped_total`. The reporter being
  slow must never stall metering.
- **Flow table probe window full** → LRU eviction within the window,
  `gtpm_meter_flow_evictions_total`. Losing a flow record is acceptable; losing
  a subscriber byte is not — the subscriber counters are updated before the flow
  table is consulted, so an eviction storm cannot corrupt billing.

The ring size sets how much burst you can absorb before dropping. It does not
set how fast the ring is: transit latency is flat from 2^10 to 2^20 entries.

## Snapshot publication

Two mechanisms, because the two kinds of state have different sizes:

**Global counters** (`PipelineSnapshot`, a few hundred bytes) go through a
seqlock. The writer bumps a sequence to odd, writes, bumps to even. Readers
retry on an odd or changed sequence. The writer never waits.

**Per-subscriber and per-flow tables** (megabytes) go through an N-buffer
publisher with per-buffer reference counts. A writer only claims a buffer it can
CAS from refcount 0 to writer-owned, so a reader holding a buffer can never have
it rewritten. A bare double buffer would let a slow reader read torn state; a
mutex would let a slow reader block the data plane.

The detail tables are built **incrementally and on demand**. Publishing them
used to scan the whole flow table on the metering thread, which put 900 µs into
p99.9 packet latency. Now the scan is bounded per publish tick, spans however
many ticks it needs, and only runs while a reader has asked for the tables
within the demand TTL. An unobserved pipeline pays nothing for reporting it is
not doing.

The consequence, stated plainly: the published detail table is a rolling view.
Each row is internally consistent, but rows may be up to one full scan apart.
For a metrics endpoint that is the right trade. The global counters, which are
what billing reconciliation actually uses, are consistent as of a single instant.

## Sharding (designed for, not implemented)

`MeterEngine` is single-threaded by contract and holds no locks, so scaling is
by shard, not by lock:

```
                 ┌─ hash(TEID) % N ─┬─▶ ring 0 ─▶ MeterEngine 0 (core 2)
  ingest ────────┤                  ├─▶ ring 1 ─▶ MeterEngine 1 (core 3)
                 └──────────────────┴─▶ ring N ─▶ MeterEngine N (core N+2)
```

Both TEIDs of a session hash independently, so a subscriber's uplink and
downlink can land on different shards. Two options: hash on the subscriber index
instead (requires a shared TEID→subscriber map, read-mostly, installed at
session setup), or let the shards each hold partial totals and sum them at
record-emission time. The second is what the counter alignment is for — 64-byte
alignment means two shards updating adjacent subscribers never share a line.

What is missing is the fan-out itself and the record merge. Nothing in the
current design has to change to add them.
