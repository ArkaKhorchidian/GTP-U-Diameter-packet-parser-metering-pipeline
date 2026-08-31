# Benchmarking methodology

What the numbers in the README mean, how they were taken, and how to take them
properly on hardware that deserves it.

## Running the suite

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./bench/run_all.sh build 1      # quick;  4 for publishable
```

Results land in `bench/results/` as CSV, each file carrying an environment
header. The latency-versus-throughput plot is regenerated from `e2e.csv`.

## The four benchmarks

| Benchmark | Measures | Isolates |
|---|---|---|
| `bench_parse` | packets/sec/core through the decap path, from memory | the parsers alone: no ring, no state |
| `bench_ring` | SPSC throughput and transit latency across sizes | the hand-off, against a mutex + `std::queue` |
| `bench_hash` | TEID lookup at load factors 0.3/0.5/0.7 | the table, against `std::unordered_map` |
| `bench_e2e` | frame in → subscriber counter updated | the whole pipeline as shipped |

## Rules the harness follows

**Report latency against offered load.** A single latency figure for a pipeline
is not a result. Below saturation you measure the pipeline; above it you measure
the queue. `bench_e2e` sweeps 0.5-8 Mpps plus an unpaced run and reports both
the achieved rate and the drops at each point.

**Pace precisely.** `sleep_for` has millisecond granularity on most platforms,
which turns a paced replay into a burst generator: the tail then measures the
pacer. The harness spins for the last 500 µs of every gap. This was a real bug —
before the fix, 1 Mpps showed a *worse* tail than 5 Mpps.

**Warm up, then measure.** Every case runs the workload before timing it, so the
first case in a run is not paying for cold caches on behalf of the rest.

**Keep the sink alive.** Parsed fields accumulate into a `volatile` so the
optimiser cannot delete the work being measured.

**Sample the clock, do not saturate it.** In the shipped runtime, latency is
sampled one event in eight by default: `clock_gettime` costs more than the
metering work it would be measuring. `bench_e2e` sets the sample rate to 1 and
accepts the overhead, which is why its numbers are conservative relative to
what the pipeline does when it is not being watched.

**Compare against the obvious implementation.** Every structural claim gets a
baseline: mutex + `std::queue` for the ring, `std::unordered_map` for the table,
both for the end-to-end run. A number without a baseline says nothing about
whether the complexity was worth it.

## Environment matters more than the code

Every benchmark prints CPU, core count, compiler, build type, and — on Linux —
the scaling governor and the isolated CPU set. For numbers worth quoting:

```bash
# Isolate cores from the scheduler (kernel command line, then reboot)
isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3

# Performance governor, no turbo variance
sudo cpupower frequency-set -g performance
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Huge pages for the counter and flow tables
echo 512 | sudo tee /proc/sys/vm/nr_hugepages

# Then pin explicitly
./build/bin/gtp-meter --pcap capture.pcap --sessions sessions.csv \
    --ingest-cpu 2 --meter-cpu 3 --busy-poll
```

The committed results were taken on an Apple M5 laptop, which has **none** of
that: macOS offers affinity hints rather than pinning, has no `isolcpus`, and
schedules across performance and efficiency cores at its own discretion. Medians
and p99 are stable there; p99.9 and beyond vary by an order of magnitude between
identical runs. Those columns are published anyway, with the caveat attached,
because hiding a noisy tail is worse than explaining one.

## Cloud VMs

Mobi's core runs on AWS, so a cloud number is the relevant one. On a `c7i` or
similar:

- Pin to cores on the same NUMA node and leave core 0 to the OS.
- Expect worse tails than bare metal regardless of pinning: the hypervisor
  steals time and will not tell you when.
- Report the instance type and whether it is a dedicated host. `c7i.2xlarge`
  and `c7i.metal` are not the same measurement.
- Check `/proc/stat` steal time before and after a run; a run with non-zero
  steal is a run to discard.

## Interpreting the tail

The end-to-end tail has three separable contributors, and it is worth knowing
which one a given number is:

1. **Queueing** — the ring depth times the metering service time. Dominant above
   saturation. Visible as latency that scales with ring size.
2. **Periodic work on the metering thread** — reporting sweeps and snapshot
   publication. Bounded by design; the detail scan is demand-driven precisely
   because it was contributing 900 µs at p99.9.
3. **Scheduler noise** — the thread being descheduled. On an unisolated laptop
   this dominates everything past p99.9 and is not a property of the code.

If a tail number looks wrong, the first diagnostic is `--no-flows` (removes
contributor 2's largest term) and the second is running at a lower offered rate
(removes contributor 1).
