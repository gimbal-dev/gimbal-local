# Benchmark results: gimbal microVM vs Docker (M32.2)

First real run of the `scripts/bench/` harness. These are actual measured numbers
from a matched, reproducible comparison on one machine -- not estimates. Re-run
the harness (see `README.md`) to reproduce; raw per-run JSON under `results/` is
gitignored, so this file is the committed record.

## Setup

| | |
| --- | --- |
| Host | Apple M3, 8 cores, 24 GB RAM, macOS 26.5.2 |
| Docker | Docker Desktop 29.5.2 (Linux VM on the same Mac, aarch64) |
| gimbal | `chm` on Apple Hypervisor.framework, snapshot `ch-arm-v2m-demo` (Ubuntu 24.04 guest) |
| Shape (both) | **1 vCPU / 1 GiB** -- Docker constrained with `--cpus 1 --memory 1g` to match the single-vCPU snapshot |
| Workload | `seq 1 16000000 \| xz -6 -T1` -- a deterministic, single-threaded compression; byte-identical work in both runtimes, no temp file, no network |
| Trials | 3 each; mean +/- stddev over successful trials |

## Result (2026-07-17)

| Metric | Docker (1 CPU/1GB) | gimbal microVM (1 vCPU/1GB) |
| --- | --- | --- |
| **Compression wall-clock (s)** | **23.17 +/- 0.83** | **23.67 +/- 0.82** |
| Cold start (s) | 0.23 +/- 0.02 | ~5 (resume envelope, below) |
| Host envelope: resume + build + teardown (s) | - | 28.96 +/- 0.89 |

**Headline: gimbal is 1.02x Docker -- 2.2% slower on the compute itself, which is
within the run-to-run noise (the stddev bands overlap).** That is at or better
than the published microVM band (Firecracker/Kata ~1.03-1.09x Docker on CPU-bound
work). For a genuinely hardware-isolated VM to match a shared-kernel container on
CPU throughput is the expected-but-worth-proving result.

The gimbal "host envelope" (~29s) minus the in-guest compress (~24s) implies the
golden-checkpoint **resume + login + teardown costs only ~5s** -- notably, this
is a *warm rehydrate* (the guest resumes already booted and logged in), not a
cold boot. Docker's cold start is ~0.23s, but that starts an empty container; the
gimbal number restores a fully-booted OS. A like-for-like "time to a ready,
warmed environment" comparison would be a follow-up (and is a place the snapshot
model can shine).

## Honest caveats

- **Single vCPU only.** The demo snapshot is 1 vCPU, so this measures
  single-core throughput. A multi-vCPU snapshot + a parallel build (`xz -T0`,
  `make -j`) would test how gimbal's SMP + I/O paths scale -- not yet measured.
- **Compression, not a compile.** The stock demo guest has **no C toolchain**
  (see findings), so we used a toolchain-free CPU workload present in both
  runtimes. A real `docker build` / `make` comparison needs a toolchain-provisioned
  snapshot (M32.1).
- **CPU-bound by design.** This deliberately avoids heavy disk/network so the
  number is a clean CPU comparison. gimbal's virtio-blk CoW overlay and userspace
  NAT are *not* exercised here; an IO/network-heavy workload (where microVMs
  historically lose ~17-20%) is the more interesting stress and is future work.

## Findings surfaced by this run

1. **The default image needs build tooling (M32.1).** `microvm_probe_toolchain`
   showed the demo guest has `python3, xz, zstd, gzip, openssl, git, tar` but
   **no `cc`/`gcc`/`make`**. A benchmark/agent snapshot must bake in a toolchain.
2. **Post-CPU-burst input wedge.** In a single session, the *first* workload runs
   fine but a *second* command issued after a long silent CPU burst does not wake
   the parked vCPU (the console/serial input path stalls) -- a cousin of the
   earlier WFI console-freeze class. The benchmark works around it by running each
   trial in a fresh session; the underlying wedge is tracked separately as a bug.
