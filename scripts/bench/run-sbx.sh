#!/usr/bin/env bash
# run-sbx.sh — the Docker Sandboxes (`sbx`) side of the M32.2 benchmark.
#
# Docker Sandboxes run each agent in its OWN local microVM (a real per-sandbox VM,
# not Docker Desktop's shared Linux VM), which is the closest peer to gimbal. This
# runner:
#   1. measures microVM startup by timing `docker sandbox create` with the
#      template image already cached (a cold create-from-image, boot included);
#   2. runs the SAME inline gzip workload N times via `docker sandbox exec` and
#      parses the BENCH_RESULT line;
# then writes a report.py-compatible results JSON.
#
#   TRIALS=3 BENCH_N=80000000 ./run-sbx.sh gzip results/sbx-gzip.json
#
# Requires the `docker sandbox` CLI (docker/sandbox plugin) and a working `sbx`
# server. gzip is present in the stock `shell` sandbox template; xz is not.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD="${1:-gzip}"
OUT="${2:-$HERE/results/sbx-${WORKLOAD}.json}"
TRIALS="${TRIALS:-3}"
N="${BENCH_N:-80000000}"
NAME="gimbalbench-sbx"

if ! docker sandbox ls >/dev/null 2>&1; then
    echo "docker sandbox CLI not available / server not running." >&2
    exit 2
fi

WS="$(mktemp -d /tmp/sbx-bench.XXXXXX)"
cleanup() {
    docker sandbox rm "$NAME" "${NAME}-warm" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap cleanup EXIT

# --- microVM startup: time a create with the template image already cached ---
# Warm the template cache first (untimed), then measure a fresh create.
docker sandbox create --name "${NAME}-warm" shell "$WS" >/dev/null 2>&1 || true
docker sandbox rm "${NAME}-warm" >/dev/null 2>&1 || true

boot_start="$(date +%s.%N)"
docker sandbox create --name "$NAME" shell "$WS" >/dev/null 2>&1
boot_end="$(date +%s.%N)"
boot="$(awk -v a="$boot_start" -v b="$boot_end" 'BEGIN { printf "%.3f", b - a }')"
echo "==> sbx microVM create (image cached): ${boot}s" >&2

ncpu="$(docker sandbox exec "$NAME" sh -c 'nproc' 2>/dev/null | tr -dc '0-9' || echo 0)"
memmb="$(docker sandbox exec "$NAME" sh -c 'free -m 2>/dev/null | awk "/Mem:/{print \$2}"' 2>/dev/null | tr -dc '0-9' || echo 0)"

# --- workload: run the inline gzip pipe N times via exec ---------------------
mkdir -p "$(dirname "$OUT")"
trials_json=""
for i in $(seq 1 "$TRIALS"); do
    echo "==> sbx trial $i/$TRIALS" >&2
    line="$(docker sandbox exec "$NAME" sh -c \
        "S=\$(date +%s.%N); if seq 1 $N | gzip -9 -c >/dev/null 2>&1; then OK=1; else OK=0; fi; E=\$(date +%s.%N); W=\$(awk -v a=\$S -v b=\$E 'BEGIN{printf \"%.3f\", b-a}'); echo BENCH_RESULT workload=gzip wall_s=\$W ok=\$OK" \
        2>/dev/null | grep '^BENCH_RESULT' || true)"
    wall="$(printf '%s' "$line" | sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p')"
    ok="$(printf '%s' "$line" | sed -n 's/.*ok=\([01]\).*/\1/p')"
    wall="${wall:-0}"; ok="${ok:-0}"
    sep=""; [ -n "$trials_json" ] && sep=","
    trials_json="${trials_json}${sep}{\"wall_s\":${wall},\"cold_start_s\":${boot},\"ok\":${ok}}"
done

cat > "$OUT" <<EOF
{
  "runtime": "sbx",
  "workload": "${WORKLOAD}",
  "microvm": {"ncpu": ${ncpu:-0}, "mem_mb": ${memmb:-0}, "create_s": ${boot}},
  "trials": [${trials_json}]
}
EOF
echo "==> wrote $OUT" >&2
