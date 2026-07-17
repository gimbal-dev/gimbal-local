#!/usr/bin/env bash
# xz.sh — a deterministic, toolchain-free compression workload (M32.2).
#
# Why this workload: the default gimbal demo guest has no C toolchain, but a
# compression pass is CPU heavy, is a real part of build/CI pipelines (artifact
# packaging), and runs identically on any minimal Linux userland (xz +
# coreutils). The payload is a deterministic `seq` stream piped straight into
# `xz` -- byte-identical work in the guest and the Docker baseline, with no large
# temp file (so no tmpfs RAM pressure and no disk-overlay dependence); the only
# variable is the runtime, not the data.
#
# It prints one machine-readable line the harness parses:
#   BENCH_RESULT workload=xz wall_s=<float> nproc=<int> ok=<0|1>
#
# Tunables (env): BENCH_N (seq upper bound -> work size), BENCH_XZ_PRESET.

set -u

N="${BENCH_N:-16000000}"          # seq 1..N piped into xz
PRESET="${BENCH_XZ_PRESET:--6}"   # -6 keeps the compressor's memory ~94 MiB
JOBS="$(nproc 2>/dev/null || echo 1)"

if ! command -v xz >/dev/null 2>&1; then
    echo "BENCH_RESULT workload=xz wall_s=0 nproc=$JOBS ok=0 error=no-xz"
    exit 1
fi

# Timed section: generate the deterministic stream and compress it,
# single-threaded, discarding the output (pure CPU, no file materialised).
start="$(date +%s.%N)"
if seq 1 "$N" | xz "$PRESET" -T1 -c >/dev/null 2>&1; then
    ok=1
else
    ok=0
fi
end="$(date +%s.%N)"

wall="$(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.3f", b - a }')"
echo "BENCH_RESULT workload=xz wall_s=$wall nproc=$JOBS ok=$ok preset=$PRESET n=$N"
[ "$ok" = "1" ]
