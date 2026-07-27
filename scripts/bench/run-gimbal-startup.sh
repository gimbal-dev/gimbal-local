#!/usr/bin/env bash
# run-gimbal-startup.sh — start-to-ready latency for a disposable sandbox (#79).
#
# The I/O and CPU runners report `host_envelope_s`, which folds in harness cost
# (per-trial codesign, prompt nudging, transcript drain). That is fine for
# comparing in-guest work, but it cannot answer "how fast does a sandbox start".
# This runner measures the four phases that matter for a disposable sandbox:
#
#   vmm_ready_s   spawn -> guest released to run (from the CHM_TRACE_TIMING stamp)
#   shell_ready_s spawn -> usable shell prompt
#   teardown_s    graceful quit -> process gone
#   total_s       spawn -> gone
#
#   BENCH_TRIALS=5 CHM_E2E_SNAPSHOT=snapshots/ch-arm-stock-its-net \
#     scripts/bench/run-gimbal-startup.sh
#
# Writes `results/gimbal-startup.json` in the same shape as the other runners.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$REPO_ROOT"

: "${CHM_E2E_SNAPSHOT:?set CHM_E2E_SNAPSHOT to an HVF-compatible snapshot dir}"

export BENCH_TRIALS="${BENCH_TRIALS:-5}"
export BENCH_OUT="${BENCH_OUT:-$HERE/results/gimbal-startup.json}"
# The vmm_ready_s phase is read from the `[startup] … (VMM ready)` stamp, so the
# trace must be on. It prints to stderr and is filtered out of the guest console.
export CHM_TRACE_TIMING=1
# Stock ITS/LPI snapshots need the userspace GIC to deliver virtio interrupts.
export CHM_USERSPACE_GIC="${CHM_USERSPACE_GIC:-1}"

echo "==> gimbal startup: snapshot=$CHM_E2E_SNAPSHOT trials=$BENCH_TRIALS" >&2
exec cargo test -p gimbal-local --test e2e_microvm_loop microvm_startup_benchmark -- \
    --ignored --nocapture
