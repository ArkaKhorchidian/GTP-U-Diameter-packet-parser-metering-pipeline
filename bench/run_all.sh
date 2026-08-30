#!/usr/bin/env bash
# Run the full benchmark suite and refresh bench/results/.
#
# Usage: bench/run_all.sh [build-dir] [scale]
#   build-dir  defaults to ./build
#   scale      1 = quick (default), 4 = publishable
#
# Results are committed to the repo so a reader can see numbers without a
# machine. Each file carries its own environment header; do not mix results
# from different machines in one file.
set -euo pipefail

BUILD_DIR="${1:-build}"
SCALE="${2:-1}"
RESULTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results"
BIN="${BUILD_DIR}/bin"

if [[ ! -x "${BIN}/bench_parse" ]]; then
  echo "error: ${BIN}/bench_parse not found. Build first:" >&2
  echo "  cmake -S . -B ${BUILD_DIR} -DCMAKE_BUILD_TYPE=Release && cmake --build ${BUILD_DIR} -j" >&2
  exit 1
fi

mkdir -p "${RESULTS_DIR}"

echo "==> bench_parse"
"${BIN}/bench_parse" $((200 * SCALE))   > "${RESULTS_DIR}/parse.csv"
echo "==> bench_ring"
"${BIN}/bench_ring" $((2000000 * SCALE)) > "${RESULTS_DIR}/ring.csv"
echo "==> bench_hash"
"${BIN}/bench_hash" $((10 * SCALE))      > "${RESULTS_DIR}/hash.csv"
echo "==> bench_e2e"
"${BIN}/bench_e2e" $((1000000 * SCALE))  > "${RESULTS_DIR}/e2e.csv"

echo "==> latency-vs-throughput plot"
python3 "$(dirname "${RESULTS_DIR}")/plot_latency.py" \
  "${RESULTS_DIR}/e2e.csv" "${RESULTS_DIR}/latency-vs-throughput.svg"

echo
echo "results written to ${RESULTS_DIR}:"
ls -1 "${RESULTS_DIR}"
