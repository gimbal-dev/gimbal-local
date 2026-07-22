#!/usr/bin/env bash
# redis.sh — the inner build workload (M32.2).
#
# This is the EXACT script that runs inside both runtimes (a Docker container and
# a gimbal microVM guest), so the only variable between the two runs is the
# runtime, not the workload. It assumes the Redis source is already unpacked at
# $BENCH_SRC (baked into the Docker image / the gimbal snapshot when it was
# provisioned) — so the timed section is a pure CPU+I/O compile, never a network
# fetch.
#
# It prints a single machine-readable line the harness greps for:
#   BENCH_RESULT workload=redis wall_s=<float> nproc=<int> ok=<0|1>
#
# Keep this script dependency-free (POSIX sh + coreutils + the toolchain) so it
# runs identically on a minimal guest and a minimal container.

set -u

SRC="${BENCH_SRC:-/opt/bench/redis}"
JOBS="$(nproc 2>/dev/null || echo 1)"

if [ ! -d "$SRC" ]; then
    echo "BENCH_RESULT workload=redis wall_s=0 nproc=$JOBS ok=0 error=no-source-at-$SRC"
    exit 1
fi

cd "$SRC" || {
    echo "BENCH_RESULT workload=redis wall_s=0 nproc=$JOBS ok=0 error=cd-failed"
    exit 1
}

# Start from a clean tree so every trial builds the same amount of work.
make distclean >/dev/null 2>&1 || true

start="$(date +%s.%N)"
if make -j"$JOBS" >/tmp/bench-build.log 2>&1; then
    ok=1
else
    ok=0
fi
end="$(date +%s.%N)"

# awk for the subtraction so we do not depend on `bc` being installed.
wall="$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.3f", b - a }')"
echo "BENCH_RESULT workload=redis wall_s=$wall nproc=$JOBS ok=$ok"
[ "$ok" = "1" ]
