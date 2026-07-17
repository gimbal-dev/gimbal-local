#!/usr/bin/env bash
# run-docker.sh — the Docker side of the M32.2 build benchmark.
#
# Builds the workload image once (untimed provisioning), then runs the container
# N times, parsing the `BENCH_RESULT` line the inner workload prints. Also
# measures per-trial container cold-start (docker run of a trivial command) so we
# can compare startup latency, not just build throughput. Writes a results JSON
# the aggregator (report.py) consumes.
#
#   TRIALS=5 ./run-docker.sh redis results/docker-redis.json
#
# Honest scope: this measures Docker Desktop's Linux VM on this Mac. It needs the
# Docker daemon running (Docker Desktop unpaused). It fabricates nothing — if a
# build fails, the trial is recorded as ok=0.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD="${1:-redis}"
OUT="${2:-$HERE/results/docker-${WORKLOAD}.json}"
TRIALS="${TRIALS:-5}"
IMAGE="gimbal-bench-${WORKLOAD}"

dockerfile="$HERE/Dockerfile.${WORKLOAD}"
[ -f "$dockerfile" ] || { echo "no Dockerfile for workload '$WORKLOAD' ($dockerfile)" >&2; exit 1; }

if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon not reachable (is Docker Desktop running/unpaused?)." >&2
    exit 1
fi

echo "==> building workload image (untimed provisioning): $IMAGE" >&2
docker build -q -t "$IMAGE" -f "$dockerfile" "$HERE" >&2

ncpu="$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 0)"
memb="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
server="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || echo unknown)"

# Constrain the container to match a gimbal guest's shape for a fair comparison.
# Defaults match the demo snapshot (1 vCPU / ~1 GiB); override with DOCKER_CPUS /
# DOCKER_MEMORY, or set them empty to run unconstrained.
DOCKER_CPUS="${DOCKER_CPUS-1}"
DOCKER_MEMORY="${DOCKER_MEMORY-1g}"
limit_args=()
[ -n "$DOCKER_CPUS" ] && limit_args+=(--cpus "$DOCKER_CPUS")
[ -n "$DOCKER_MEMORY" ] && limit_args+=(--memory "$DOCKER_MEMORY")
echo "==> container limits: ${limit_args[*]:-none}" >&2

mkdir -p "$(dirname "$OUT")"
trials_json=""
for i in $(seq 1 "$TRIALS"); do
    echo "==> docker trial $i/$TRIALS" >&2

    # Cold-start: time a container that does nothing but start + exit.
    cs_start="$(date +%s.%N)"
    docker run --rm "${limit_args[@]}" "$IMAGE" true >/dev/null 2>&1 || true
    cs_end="$(date +%s.%N)"
    cold="$(awk -v a="$cs_start" -v b="$cs_end" 'BEGIN { printf "%.3f", b - a }')"

    # The build trial: parse the BENCH_RESULT line the workload prints.
    line="$(docker run --rm "${limit_args[@]}" "$IMAGE" 2>/dev/null | grep '^BENCH_RESULT' || true)"
    wall="$(printf '%s' "$line" | sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p')"
    ok="$(printf '%s' "$line" | sed -n 's/.*ok=\([01]\).*/\1/p')"
    wall="${wall:-0}"; ok="${ok:-0}"

    sep=""; [ -n "$trials_json" ] && sep=","
    trials_json="${trials_json}${sep}{\"wall_s\":${wall},\"cold_start_s\":${cold},\"ok\":${ok}}"
done

cat > "$OUT" <<EOF
{
  "runtime": "docker",
  "workload": "${WORKLOAD}",
  "limits": {"cpus": "${DOCKER_CPUS:-unbounded}", "memory": "${DOCKER_MEMORY:-unbounded}"},
  "host": {"ncpu": ${ncpu}, "mem_bytes": ${memb}, "server_version": "${server}"},
  "trials": [${trials_json}]
}
EOF
echo "==> wrote $OUT" >&2
