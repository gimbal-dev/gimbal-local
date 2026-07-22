#!/usr/bin/env bash
# run-gimbal.sh — the gimbal (Cloud Hypervisor on HVF) side of the M32.2 build
# benchmark. Symmetric with run-docker.sh: it runs the SAME inner workload
# (workloads/<workload>.sh) inside a gimbal microVM guest N times, parses the
# `BENCH_RESULT` line off the guest serial console, and writes a results JSON the
# aggregator (report.py) consumes.
#
#   TRIALS=5 BENCH_SNAPSHOT=/path/to/bench-snapshot ./run-gimbal.sh redis \
#       results/gimbal-redis.json
#
# --- Snapshot contract (what BENCH_SNAPSHOT must be) ---------------------------
# gimbal only rehydrates a snapshot (there is no boot-from-scratch), so the guest
# is prepared ONCE and captured (see docs/aws-byo-setup.md + scripts/hvf/ for the
# KVM capture path; overlaps M32.1 / #76). A "bench snapshot" is a normal
# HVF-compatible snapshot whose guest, on resume, automatically:
#   1. has the workload's source baked in at $BENCH_SRC (e.g. /opt/bench/redis)
#      and the matching workloads/<workload>.sh at /opt/bench/<workload>.sh;
#   2. runs that script on resume (e.g. a oneshot systemd unit or an rc.local
#      line) and prints its `BENCH_RESULT ...` line to the serial console;
#   3. then powers off (so the trial ends cleanly and the next resume is fresh).
#
# The harness measures wall_s from the guest's own BENCH_RESULT (the in-guest
# compile time, directly comparable to Docker's) and separately measures
# rehydrate/cold-start as the host wall-clock from `chm` launch to the first
# guest console byte.
#
# Until such a snapshot exists this script fails closed with an explanatory
# message rather than inventing numbers.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
WORKLOAD="${1:-redis}"
OUT="${2:-$HERE/results/gimbal-${WORKLOAD}.json}"
TRIALS="${TRIALS:-5}"
CHM="${CHM:-$REPO_ROOT/target/debug/chm}"

if [ -z "${BENCH_SNAPSHOT:-}" ]; then
    cat >&2 <<'MSG'
BENCH_SNAPSHOT is not set. The gimbal side needs a bench-enabled snapshot whose
guest builds the workload on resume and prints a BENCH_RESULT line to the serial
console (see the "Snapshot contract" comment at the top of this script and
scripts/bench/README.md). Provisioning one is the M32.1 step (#76) and needs a
KVM capture host — the Mac can only run snapshots, not capture them.
MSG
    exit 2
fi
[ -d "$BENCH_SNAPSHOT" ] || { echo "BENCH_SNAPSHOT '$BENCH_SNAPSHOT' is not a directory" >&2; exit 1; }
[ -x "$CHM" ] || { echo "chm not found/executable at '$CHM' (run scripts/build-chm.sh)" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
ncpu="$(sysctl -n hw.ncpu 2>/dev/null || echo 0)"
memb="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"

trials_json=""
for i in $(seq 1 "$TRIALS"); do
    echo "==> gimbal trial $i/$TRIALS" >&2
    log="$(mktemp -t gimbal-bench.XXXXXX)"

    host_start="$(date +%s.%N)"
    # Resume the bench snapshot; the guest runs the workload and powers off. A
    # generous idle-exit/max-seconds guards against a wedged guest. `chm` streams
    # the guest serial console to stdout, which we capture and parse.
    "$CHM" resume "$BENCH_SNAPSHOT" --idle-exit 30 --max-seconds 1800 --quiet \
        >"$log" 2>&1 || true
    host_end="$(date +%s.%N)"

    line="$(grep '^BENCH_RESULT' "$log" | tail -1 || true)"
    wall="$(printf '%s' "$line" | sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p')"
    ok="$(printf '%s' "$line" | sed -n 's/.*ok=\([01]\).*/\1/p')"
    wall="${wall:-0}"; ok="${ok:-0}"
    # Host-side envelope (rehydrate + build + shutdown); the pure in-guest compile
    # is wall_s above. Their difference approximates rehydrate + teardown.
    envelope="$(awk -v a="$host_start" -v b="$host_end" 'BEGIN { printf "%.3f", b - a }')"

    sep=""; [ -n "$trials_json" ] && sep=","
    trials_json="${trials_json}${sep}{\"wall_s\":${wall},\"host_envelope_s\":${envelope},\"ok\":${ok}}"
    rm -f "$log"
done

cat > "$OUT" <<EOF
{
  "runtime": "gimbal",
  "workload": "${WORKLOAD}",
  "host": {"ncpu": ${ncpu}, "mem_bytes": ${memb}, "snapshot": "$(basename "$BENCH_SNAPSHOT")"},
  "trials": [${trials_json}]
}
EOF
echo "==> wrote $OUT" >&2
