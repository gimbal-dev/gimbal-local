# Build benchmark: gimbal microVM vs Docker (M32.2, #76)

A reproducible harness that runs the **same build workload** inside (a) a Docker
Desktop container and (b) a gimbal microVM on the **same Mac**, and reports
wall-clock build time, cold start, and (for gimbal) the rehydrate envelope. Both
runtimes execute the *identical* inner script, so the only variable is the
runtime, not the workload.

> **Status: harness ready, no numbers yet.** The Docker side runs today (needs
> Docker Desktop running). The gimbal side needs a **bench-enabled snapshot** with
> a build toolchain baked in (the M32.1 provisioning step, #76) — the Mac can only
> *run* snapshots, not capture them, so that snapshot is produced on a KVM host.
> This directory deliberately ships **no results**; run it yourself to produce
> real numbers. Nothing here is fabricated.

## Why an existing-style workload

We use a real, pinned software build (Redis by default) rather than a synthetic
micro-benchmark, because a compile is the workload that actually matters for
agent/CI use and stresses CPU + disk I/O the way a real job does. The design also
accommodates the standard **Phoronix Test Suite** timed builds
(`pts/build-linux-kernel`, `pts/build-llvm`, `build-gcc`) — drop in a
`Dockerfile.<name>` + `workloads/<name>.sh` pair and pass the name through.

## Methodology

- **Identical inner workload.** `workloads/<name>.sh` runs inside both runtimes and
  prints one machine-readable line: `BENCH_RESULT workload=<n> wall_s=<f> ...`.
  The source is baked in during provisioning, so the **timed section is a pure
  compile** (no network fetch).
- **N trials, mean +/- stddev.** Default 5 (`TRIALS` env). `make distclean` before
  each trial so every run builds the same amount of work. Failed trials (`ok=0`)
  are excluded and counted.
- **Metrics.**
  - *Build wall-clock* — the in-runtime compile time; directly comparable.
  - *Cold start* (Docker) — `docker run` of a trivial command.
  - *Host envelope* (gimbal) — host wall-clock from `chm` launch to guest power-off
    (rehydrate + build + teardown); the rehydrate portion is the envelope minus
    the in-guest `wall_s`.
- **Same host, pinned inputs.** Run both on the same Mac, back to back; pin the
  base image and the software version (ideally by digest) so re-runs measure the
  same work.

## Honest expectations (prior art)

Firecracker / Kata microVMs run about **92-97% of Docker's throughput** on
CPU-bound builds (i.e. gimbal ~1.03-1.09x Docker wall-clock), with a larger hit
(~17-20%) on IO/network-heavy multi-stage builds, and cold start ~100-300ms vs
Docker's <100ms. If gimbal lands far outside that band, look at the CoW-overlay
I/O path and the userspace-NAT throughput before concluding "microVMs are slower."

**Gimbal's angle to measure:** the snapshot model can rehydrate a guest **already
warm** (deps loaded, caches primed, sitting right before the build) instantly and
repeatably, whereas a container starts cold each run. That warm-rehydrate is a
potential gimbal advantage, not just setup cost.

## Running it

```sh
# Docker side (needs Docker Desktop running/unpaused):
TRIALS=5 scripts/bench/run-docker.sh redis results/docker-redis.json

# Gimbal side (needs a bench-enabled snapshot; see the contract below):
TRIALS=5 BENCH_SNAPSHOT=/path/to/bench-snapshot \
    scripts/bench/run-gimbal.sh redis results/gimbal-redis.json

# Report (mean +/- stddev + ratio):
python3 scripts/bench/report.py results/docker-redis.json results/gimbal-redis.json
```

## The bench-snapshot contract (gimbal side)

`BENCH_SNAPSHOT` is a normal HVF-compatible snapshot whose guest, on resume:

1. has the workload source baked in at `$BENCH_SRC` (default `/opt/bench/redis`)
   and the matching `workloads/<name>.sh` at `/opt/bench/<name>.sh`;
2. runs that script on resume (a oneshot systemd unit or an `rc.local` line) and
   prints its `BENCH_RESULT ...` line to the serial console;
3. powers off, so the trial ends cleanly and the next resume is fresh.

Provisioning it is the M32.1 task (#76): build a guest with the toolchain +
source (mirroring `Dockerfile.redis`), then capture it on a KVM host (see
`docs/aws-byo-setup.md` and `scripts/hvf/`). Bake the inputs in so the build runs
**offline** — that decouples the benchmark from the net-enabled-snapshot gap
(#52).

## Files

| File | Role |
| --- | --- |
| `workloads/redis.sh` | The identical inner build (prints `BENCH_RESULT`). |
| `Dockerfile.redis` | Provisions the Docker image (pinned source + toolchain). |
| `run-docker.sh` | Runs the Docker side, N trials -> results JSON. |
| `run-gimbal.sh` | Runs the gimbal side, N trials -> results JSON. |
| `report.py` | Aggregates results -> markdown (mean +/- stddev + ratio). |
| `test_report.py` | Unit test for the aggregation logic. |
