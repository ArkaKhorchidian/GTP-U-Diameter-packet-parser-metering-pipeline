# Contributing

## Getting a build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`make help` lists the shortcuts. There are no third-party dependencies, and
adding one needs a good reason: the ability to build and self-verify on a bare
toolchain with no network is a feature of this repo, not an accident.

## Before opening a pull request

```bash
make test          # all 18 test binaries
make asan          # AddressSanitizer + UBSan
make tsan          # ThreadSanitizer — required for anything touching threads
make golden        # byte-exact replay against generated ground truth
make fmt-check     # clang-format 21.1.2 (pinned: pip install clang-format==21.1.2)
```

CI additionally builds with gcc and clang, Release and Debug, on Linux and
macOS, all with warnings as errors, and runs a 60-second libFuzzer campaign per
target. Building clean under one compiler is not evidence; `-Wconversion` and
`-Wshorten-64-to-32` disagree between toolchains, and gcc catches patterns clang
does not.

## What the code expects of you

**Nothing allocates on the packet path.** Not the parsers, not the metering
engine, not the ingest path. If a change needs memory per packet, it needs a
different design.

**Parsers stay zero-copy.** Return `std::span` views and POD descriptors. Never
trust a length field without checking it against the bytes actually present.

**Structures that must fit a cache line have a `static_assert` saying so.**
`MeterEvent`, `SubscriberCounters` and `FlowEntry` are exactly 64 bytes. If your
change grows one, the build fails, and the right response is usually to move the
field to the cold array rather than to raise the limit.

**One owner per piece of mutable state.** The metering thread owns
`MeterEngine`; nothing else touches it. Cross-thread communication goes through
the SPSC rings or the snapshot publishers. If you find yourself wanting a mutex
on the data path, the design has gone wrong somewhere upstairs.

**Queues drop and count; they never block.** Every drop must land in a counter
that reaches `/metrics`.

## Testing expectations

New parsing code needs, at minimum:

- field extraction from a well-formed packet,
- a truncation sweep (every prefix must be rejected, not partially read),
- the malformed cases that would loop, overrun, or recurse without a bound.

New concurrent code needs a test that actually runs threads and asserts the
property (no loss, no tearing, no starvation), and it must pass under TSan.

Anything that changes metering arithmetic needs the golden test to still pass
byte-exactly. If it legitimately changes what gets counted, say so in the commit
message and explain why the new number is the right one.

## Benchmarks

Performance claims need a measurement and a baseline. `bench/run_all.sh`
refreshes `bench/results/`; commit the regenerated files with the change, and
note the machine. Results from different machines must not be mixed in one file
— each carries an environment header for that reason.

If a change is meant to be faster, show the before and after. If it is meant to
be clearer at some cost, say what the cost measured out to.

## Commit style

Present-tense summary under ~72 characters, then a body explaining *why*. The
diff already says what changed. Commits that fix something should say what was
wrong and how it was found — a measured 900 µs in a tail is more useful to the
next reader than "improve performance".
