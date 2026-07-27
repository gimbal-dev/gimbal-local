#!/usr/bin/env bash
# run-docker-io.sh — the Docker side of the M32.3 I/O + network benchmark.
#
# Builds the io image once (untimed), then runs the container N times with the
# requested workload, parsing the `BENCH_RESULT` line. The inner command comes
# from `workloads/commands.sh`, so it is byte-identical to what the gimbal guest
# runs.
#
#   TRIALS=5 ./run-docker-io.sh diskwrite
#   TRIALS=5 BENCH_URL=http://192.168.1.64:8199/payload.bin ./run-docker-io.sh netget
#
# Fabricates nothing: a failed trial is recorded as ok=0.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD="${1:-diskwrite}"
OUT="${2:-$HERE/results/docker-${WORKLOAD}.json}"
TRIALS="${TRIALS:-5}"
IMAGE="gimbal-bench-io"

if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon not reachable (is Docker Desktop running/unpaused?)." >&2
    exit 1
fi

echo "==> building io image (untimed provisioning): $IMAGE" >&2
docker build -q -t "$IMAGE" -f "$HERE/Dockerfile.io" "$HERE" >&2

ncpu="$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 0)"
memb="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
server="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || echo unknown)"

# Match the gimbal guest's shape (1 vCPU / 1 GiB) so the comparison is per-core.
DOCKER_CPUS="${DOCKER_CPUS-1}"
DOCKER_MEMORY="${DOCKER_MEMORY-1g}"
limit_args=()
[ -n "$DOCKER_CPUS" ] && limit_args+=(--cpus "$DOCKER_CPUS")
[ -n "$DOCKER_MEMORY" ] && limit_args+=(--memory "$DOCKER_MEMORY")

env_args=(-e "BENCH_WORKLOAD=$WORKLOAD")
[ -n "${BENCH_URL:-}" ] && env_args+=(-e "BENCH_URL=$BENCH_URL")
[ -n "${BENCH_DISK_MB:-}" ] && env_args+=(-e "BENCH_DISK_MB=$BENCH_DISK_MB")
echo "==> workload=$WORKLOAD limits=${limit_args[*]:-none}" >&2

mkdir -p "$(dirname "$OUT")"
trials_json=""
for i in $(seq 1 "$TRIALS"); do
    echo "==> docker $WORKLOAD trial $i/$TRIALS" >&2
    line="$(docker run --rm "${limit_args[@]}" "${env_args[@]}" "$IMAGE" 2>/dev/null | grep '^BENCH_RESULT' || true)"
    wall="$(printf '%s' "$line" | sed -n 's/.*wall_s=\([0-9.]*\).*/\1/p')"
    ok="$(printf '%s' "$line" | sed -n 's/.*ok=\([01]\).*/\1/p')"
    wall="${wall:-0}"; ok="${ok:-0}"
    echo "    wall_s=$wall ok=$ok" >&2
    sep=""; [ -n "$trials_json" ] && sep=","
    trials_json="${trials_json}${sep}{\"wall_s\":${wall},\"ok\":${ok}}"
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
