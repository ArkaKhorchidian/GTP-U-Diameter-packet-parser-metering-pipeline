# Kernel-bypass ingest: AF_XDP and DPDK

The pipeline ships with pcap replay and ordinary socket capture. This is the
design for the ingest path that would replace them, and what does *not* have to
change to get there.

## Why the current path is the bottleneck, not the pipeline

The measured numbers separate the two cleanly:

- Parse throughput, from memory: **79-154 Mpps** on one core.
- End-to-end through the metering thread: saturates at **15 Mpps / 88 Gbps**.
- `AF_PACKET` with one `recv()` per packet: roughly **1-2 Mpps** before the
  syscall and copy costs dominate.

So the socket path costs an order of magnitude more than the work it delivers.
That is the standard result, and it is why every production UPF uses DPDK,
AF_XDP, or vendor SmartNIC offload.

## What stays the same

`PacketSource` is a batch interface:

```cpp
virtual size_t next_batch(PcapPacket* out, size_t max) = 0;
```

A batch amortises the one virtual call over hundreds of frames, and `PcapPacket`
is already a view (`std::span`) plus a timestamp — it never owns the bytes. An
AF_XDP source fills that array with spans into UMEM frames instead of spans into
a loaded file. **Nothing downstream changes**: not the parsers, not the ring,
not the metering engine, not the reporter.

The one contract that matters is lifetime: the ingest loop must finish
processing a batch before requesting the next one, because the source may reuse
its buffers. The current sources already work this way, and `MeterEvent` is a
copy precisely so the metering thread is not exposed to that lifetime at all.

## AF_XDP shape

```
NIC ──▶ RX queue ──▶ XDP program ──▶ XSKMAP ──▶ AF_XDP socket ──▶ UMEM frames
                          │
                          └─ XDP_PASS for everything that is not UDP:2152
```

1. **UMEM.** One large mmap'd region, huge-page backed, split into fixed frames
   (2048 B is the usual choice). Four rings: FILL and COMPLETION (userspace →
   kernel), RX and TX (kernel → userspace).
2. **A small XDP program** that redirects only GTP-U to the socket and lets
   everything else follow the normal stack path. Filtering in XDP means the
   pipeline never sees traffic it would immediately discard — the
   `not_our_traffic` counter should go to near zero on a real deployment.
3. **Zero-copy mode** (`XDP_ZEROCOPY`) where the driver supports it: the NIC
   DMAs directly into UMEM and userspace gets a descriptor. Otherwise copy mode,
   which is still far cheaper than a syscall per packet.
4. **`next_batch` becomes**: consume up to `max` descriptors from the RX ring,
   hand out spans into UMEM, and return frames to the FILL ring on the next
   call. Batch the ring index updates; that is the same discipline as the SPSC
   ring's bulk operations.
5. **Busy-poll mode** (`SO_BUSY_POLL` / `XDP_USE_NEED_WAKEUP`) to avoid the
   softirq wakeup on a dedicated core. The runtime already has `--busy-poll` for
   the metering thread; the ingest side would gain the same.

Estimated cost: ~50-100 ns/packet for the AF_XDP path in zero-copy mode against
~500-1000 ns for `AF_PACKET`, which would put ingest and metering within the
same order of magnitude and make the metering thread the bottleneck again — the
right place for it to be.

## DPDK shape

DPDK goes further: the NIC is unbound from the kernel driver entirely, and
`rte_eth_rx_burst()` returns an array of `rte_mbuf`. The changes are the same
shape.

- `next_batch` wraps `rte_eth_rx_burst`, handing out spans over
  `rte_pktmbuf_mtod`.
- Timestamping moves to the NIC where available (`RTE_ETH_RX_OFFLOAD_TIMESTAMP`),
  which removes a `clock_gettime` from the hot path and gives a timestamp taken
  before software ever touched the packet — a strictly better measurement.
- RSS on the outer 5-tuple gives multiple RX queues; combined with the sharded
  metering design in [architecture.md](architecture.md), that is the path to
  scaling past one core. Note that RSS on the *outer* header hashes all traffic
  between one gNB and one UPF to a single queue, which is exactly the wrong
  distribution — production deployments either use a NIC that can hash on the
  inner header, or redistribute in software by TEID after parsing.
- Huge pages and `--socket-mem` so UMEM/mempool memory is NUMA-local to the
  core running ingest.

The reason DPDK is not shipped here is that it needs a bound NIC, huge pages,
and root — which makes the project unrunnable on a laptop and unverifiable in
CI. The pcap replay path measures the same pipeline with the same code, and the
numbers in the README say what happens when the ingest cost is removed.

## What would need re-measuring

Everything downstream of ingest is unaffected, but three numbers would change:

1. **Timestamp origin.** NIC timestamps move the start of the latency
   measurement earlier, so end-to-end latency will *increase* — because it is
   finally measuring the whole path. That is a better number, not a worse one.
2. **Cache behaviour.** UMEM frames are recycled, so the packet data is more
   likely to be cache-warm than a replayed file that streams through memory.
3. **The `not_our_traffic` path.** XDP filtering removes it entirely, so the
   per-packet average improves in a way that has nothing to do with the parser.

Any of those changing the headline numbers is expected; the benchmark harness
prints its environment for exactly this reason.
