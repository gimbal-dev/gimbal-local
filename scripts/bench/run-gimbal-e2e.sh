#!/usr/bin/env bash
# run-gimbal-e2e.sh — drive the gimbal side of the M32.2 benchmark via the
# PTY-based integration test (`microvm_xz_benchmark`), which boots a snapshot,
# runs the same xz workload the Docker side runs, and writes a results JSON.
#
# This is the "no bench-snapshot needed" path: the workload is inlined over the
# guest console, so it runs against the stock demo snapshot (which has xz +
# coreutils). Each trial runs in a fresh session (boot -> one workload ->
# teardown), matching Docker's per-run model.
#
#   BENCH_TRIALS=3 BENCH_N=16000000 \
#   CHM_E2E_SNAPSHOT=snapshots/ch-arm-v2m-demo scripts/bench/run-gimbal-e2e.sh
#
# Then compare with the Docker side:
#   python3 scripts/bench/report.py \
#     scripts/bench/results/docker-xz.json scripts/bench/results/gimbal-xz.json

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$REPO_ROOT"

: "${CHM_E2E_SNAPSHOT:?set CHM_E2E_SNAPSHOT to an HVF-compatible snapshot dir}"
export BENCH_TRIALS="${BENCH_TRIALS:-3}"
export BENCH_N="${BENCH_N:-16000000}"
export BENCH_OUT="${BENCH_OUT:-$HERE/results/gimbal-xz.json}"

echo "==> gimbal xz benchmark: snapshot=$CHM_E2E_SNAPSHOT trials=$BENCH_TRIALS n=$BENCH_N" >&2
exec cargo test -p gimbal-local --test e2e_microvm_loop microvm_xz_benchmark -- \
    --ignored --nocapture
