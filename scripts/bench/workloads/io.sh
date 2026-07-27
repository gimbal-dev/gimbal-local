#!/usr/bin/env bash
# io.sh — the Docker-side wrapper for the M32.2 I/O + network workloads.
#
# It does not define any work itself: it asks `commands.sh` for the canonical
# inner command and times exactly that, so the container runs the same string
# the gimbal guest runs. It prints one machine-readable line the harness parses:
#
#   BENCH_RESULT workload=<name> wall_s=<float> nproc=<int> ok=<0|1>
#
# Usage:  BENCH_WORKLOAD=diskwrite ./io.sh
#         BENCH_WORKLOAD=netget BENCH_URL=http://<host>:8199/payload.bin ./io.sh

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./commands.sh
. "$HERE/commands.sh"

WORKLOAD="${BENCH_WORKLOAD:-diskwrite}"
JOBS="$(nproc 2>/dev/null || echo 1)"

CMD="$(bench_command "$WORKLOAD")" || {
    echo "BENCH_RESULT workload=$WORKLOAD wall_s=0 nproc=$JOBS ok=0 error=no-command"
    exit 1
}

start="$(date +%s.%N)"
if eval "$CMD" >/dev/null 2>&1; then
    ok=1
else
    ok=0
fi
end="$(date +%s.%N)"

wall="$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.3f", b - a }')"
echo "BENCH_RESULT workload=$WORKLOAD wall_s=$wall nproc=$JOBS ok=$ok"
[ "$ok" = "1" ]
