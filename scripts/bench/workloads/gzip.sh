#!/usr/bin/env bash
# gzip.sh — a deterministic, toolchain-free compression workload (M32.2).
#
# gzip is present in every minimal Linux userland -- including Docker Desktop
# containers, the gimbal demo guest, AND Docker Sandboxes (`sbx`) microVMs, which
# lack xz. So this is the common single-threaded CPU workload for the three-way
# comparison. The payload is a deterministic `seq` stream piped straight into
# `gzip -9` (max compression = most CPU), output discarded -- byte-identical work
# everywhere, no temp file, no network.
#
#   BENCH_RESULT workload=gzip wall_s=<float> nproc=<int> ok=<0|1>

set -u

N="${BENCH_N:-80000000}"
LEVEL="${BENCH_GZIP_LEVEL:--9}"
JOBS="$(nproc 2>/dev/null || echo 1)"

if ! command -v gzip >/dev/null 2>&1; then
    echo "BENCH_RESULT workload=gzip wall_s=0 nproc=$JOBS ok=0 error=no-gzip"
    exit 1
fi

start="$(date +%s.%N)"
if seq 1 "$N" | gzip "$LEVEL" -c >/dev/null 2>&1; then
    ok=1
else
    ok=0
fi
end="$(date +%s.%N)"

wall="$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.3f", b - a }')"
echo "BENCH_RESULT workload=gzip wall_s=$wall nproc=$JOBS ok=$ok level=$LEVEL n=$N"
[ "$ok" = "1" ]
