#!/usr/bin/env bash
# run-gimbal-io.sh — the gimbal side of the M32.3 I/O + network benchmark.
#
# Sources the shared inner command from `workloads/commands.sh` and hands it to
# the PTY-driven integration test, so the guest executes the byte-identical
# string the container executes. Each trial is a fresh resume -> one workload ->
# teardown, matching Docker's per-run model.
#
#   BENCH_TRIALS=5 CHM_E2E_SNAPSHOT=snapshots/ch-arm-stock-its-net \
#     scripts/bench/run-gimbal-io.sh diskwrite
#
#   BENCH_TRIALS=5 CHM_E2E_SNAPSHOT=snapshots/ch-arm-stock-its-net \
#     BENCH_URL=http://192.168.1.64:8199/payload.bin \
#     scripts/bench/run-gimbal-io.sh netget
#
# The net-enabled stock snapshot needs the userspace GIC, and reaching a server
# on the host means crossing the M31.1 reserved-address guard, so both are
# enabled here explicitly rather than silently.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=./workloads/commands.sh
. "$HERE/workloads/commands.sh"
cd "$REPO_ROOT"

: "${CHM_E2E_SNAPSHOT:?set CHM_E2E_SNAPSHOT to an HVF-compatible snapshot dir}"
WORKLOAD="${1:-diskwrite}"

BENCH_CMD="$(bench_command "$WORKLOAD")"
export BENCH_CMD
export BENCH_WORKLOAD="$WORKLOAD"
export BENCH_TRIALS="${BENCH_TRIALS:-${2:-3}}"
export BENCH_OUT="${BENCH_OUT:-$HERE/results/gimbal-${WORKLOAD}.json}"

# Stock ITS/LPI snapshots need the userspace GIC to deliver virtio interrupts.
export CHM_USERSPACE_GIC="${CHM_USERSPACE_GIC:-1}"
# The payload server lives on the host, whose address is in a reserved range the
# M31.1 guard denies by default. The benchmark opts in explicitly; this is a
# measurement configuration, not the shipping default.
if [ "$WORKLOAD" = "netget" ]; then
    export CHM_ALLOW_LOCAL_EGRESS=1
fi

echo "==> gimbal $WORKLOAD: snapshot=$CHM_E2E_SNAPSHOT trials=$BENCH_TRIALS" >&2
echo "==> inner command: $BENCH_CMD" >&2
exec cargo test -p gimbal-local --test e2e_microvm_loop microvm_xz_benchmark -- \
    --ignored --nocapture
