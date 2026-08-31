# Convenience wrapper around CMake. Everything here is a one-liner you would
# otherwise have to remember; the build itself is plain CMake.

BUILD_DIR ?= build
BUILD_TYPE ?= Release
JOBS ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4))
CMAKE_FLAGS ?=
# Pin the formatter: clang-format's output changes between major versions, so
# an unpinned one reformats a clean tree. Install with:
#   pip install clang-format==21.1.2
CLANG_FORMAT ?= clang-format

.PHONY: all build test bench fmt fmt-check tidy asan tsan fuzz golden traffic run clean help

all: build

help:
	@echo "make build       configure and build ($(BUILD_TYPE) in $(BUILD_DIR))"
	@echo "make test        build and run the full test suite"
	@echo "make bench       run the benchmark suite and refresh bench/results"
	@echo "make asan        build and test with AddressSanitizer + UBSan"
	@echo "make tsan        build and test with ThreadSanitizer"
	@echo "make fuzz        build the fuzz targets and run a short campaign"
	@echo "make golden      replay generated traffic and check byte-exact totals"
	@echo "make traffic     generate a sample capture in ./traffic.pcap"
	@echo "make run         replay ./traffic.pcap with metrics on :9109"
	@echo "make fmt         apply clang-format; fmt-check verifies without writing"
	@echo "make clean       remove build directories"

build:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(CMAKE_FLAGS)
	cmake --build $(BUILD_DIR) -j$(JOBS)

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

bench: build
	./bench/run_all.sh $(BUILD_DIR) $(or $(SCALE),1)

asan:
	cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DGTPM_ASAN=ON -DGTPM_UBSAN=ON -DGTPM_NATIVE_ARCH=OFF -DGTPM_BUILD_BENCH=OFF
	cmake --build build-asan -j$(JOBS)
	ctest --test-dir build-asan --output-on-failure

tsan:
	cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DGTPM_TSAN=ON -DGTPM_NATIVE_ARCH=OFF -DGTPM_BUILD_BENCH=OFF
	cmake --build build-tsan -j$(JOBS)
	ctest --test-dir build-tsan --output-on-failure

fuzz:
	cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DGTPM_BUILD_FUZZ=ON -DGTPM_BUILD_BENCH=OFF -DGTPM_NATIVE_ARCH=OFF
	cmake --build build-fuzz -j$(JOBS)
	ctest --test-dir build-fuzz --output-on-failure -L fuzz

golden: build
	python3 tests/golden_replay.py $(BUILD_DIR)/bin/gtp-meter

traffic:
	python3 tools/gen_traffic.py --out traffic --packets 200000 --subscribers 500

run: build traffic
	$(BUILD_DIR)/bin/gtp-meter --pcap traffic.pcap --sessions traffic-sessions.csv \
		--records usage-records.ndjson --http 9109 --loops 0 --max-pps 500000

fmt:
	@find include src tests bench \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
		| xargs -0 $(CLANG_FORMAT) -i
	@echo "formatted with $$($(CLANG_FORMAT) --version)"

fmt-check:
	@find include src tests bench \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
		| xargs -0 $(CLANG_FORMAT) --dry-run --Werror

tidy: build
	@find include src -name '*.cpp' -o -name '*.hpp' \
		| xargs clang-tidy -p $(BUILD_DIR) --quiet

clean:
	rm -rf build build-asan build-tsan build-fuzz traffic.pcap traffic-sessions.csv \
		traffic-expected.json usage-records.ndjson
