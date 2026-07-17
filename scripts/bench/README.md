# Build benchmark: gimbal microVM vs Docker vs Docker Sandbox (M32.2, #76)

A reproducible harness that runs the **same workload** inside (a) a Docker
Desktop container, (b) a gimbal microVM, and (c) a Docker Sandbox per-sandbox
microVM (`docker sandbox`) on the **same Mac**, and reports wall-clock compute
time, startup/create time, and (for gimbal) the rehydrate envelope. All three
runtimes execute the *identical* inner script, so the only variable is the
runtime, not the workload.

> **Status: harness ready, 3-way result recorded.** All three runtimes run
> today. The gimbal side runs the same workload inside the stock demo snapshot
> via a PTY-driven integration test (no bench snapshot needed) — see
> `run-gimbal-e2e.sh`. Measured numbers are in [`RESULTS.md`](RESULTS.md): on an
> M3, gimbal is at **parity** with Docker Desktop and within ~7% of a Docker
> Sandbox microVM on a matched single-core `gzip` compression; the real split is
> startup (gimbal warm resume ~5s vs Docker Sandbox microVM create ~12.7s, see
> #79). Raw per-run JSON under `results/` is gitignored; reproduce locally.
> Nothing is fabricated.

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

The **3-way `gzip` comparison** in `RESULTS.md` is reproduced with:

```sh
# Docker Desktop (constrain to the snapshot shape):
TRIALS=3 BENCH_N=80000000 DOCKER_CPUS=1 DOCKER_MEMORY=1g \
    scripts/bench/run-docker.sh gzip scripts/bench/results/docker-gzip.json

# gimbal microVM (PTY-driven, runs inside the stock demo snapshot):
BENCH_TRIALS=5 BENCH_N=80000000 BENCH_PIPE="gzip -9 -c" BENCH_WORKLOAD=gzip \
    CHM_E2E_SNAPSHOT="$PWD/snapshots/ch-arm-v2m-demo" \
    cargo test -p gimbal-local --test e2e_microvm_loop microvm_xz_benchmark \
    -- --ignored --nocapture   # writes results/gimbal-gzip.json

# Docker Sandbox microVM (needs `docker sandbox` / sbx installed):
TRIALS=3 BENCH_N=80000000 \
    scripts/bench/run-sbx.sh gzip scripts/bench/results/sbx-gzip.json

# 3-way report (mean +/- stddev + ratio):
python3 scripts/bench/report.py \
    scripts/bench/results/docker-gzip.json \
    scripts/bench/results/gimbal-gzip.json \
    scripts/bench/results/sbx-gzip.json
```

`gzip` is the common workload because it is the only single-threaded compressor
present in all three images (the Docker Sandbox `shell` image lacks `xz`/`zstd`).
Swap `gzip` -> `redis`/`xz` (with the matching `BENCH_PIPE`) for a 2-way
Docker-vs-gimbal run.

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
| `workloads/gzip.sh` | Common 3-way inner workload (`seq \| gzip -9`, prints `BENCH_RESULT`). |
| `workloads/xz.sh` / `workloads/redis.sh` | Alternate 2-way workloads (xz / a real Redis build). |
| `Dockerfile.gzip` / `Dockerfile.xz` / `Dockerfile.redis` | Provision the Docker image per workload. |
| `run-docker.sh` | Docker Desktop side, N trials -> results JSON (`DOCKER_CPUS`/`DOCKER_MEMORY` constrain shape). |
| `run-gimbal-e2e.sh` | Convenience wrapper for the PTY-driven gimbal run. |
| `run-sbx.sh` | Docker Sandbox side: times `docker sandbox create` (microVM boot) + N trials via `exec`. |
| `report.py` | Aggregates N result JSONs -> markdown (mean +/- stddev + ratio). |
| `test_report.py` | Unit test for the aggregation logic. |
