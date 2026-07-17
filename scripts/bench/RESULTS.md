# Benchmark results: gimbal microVM vs Docker vs Docker Sandbox (M32.2)

Real measured numbers from the `scripts/bench/` harness on one machine -- not
estimates. Re-run the harness (see `README.md`) to reproduce; raw per-run JSON
under `results/` is gitignored, so this file is the committed record.

## Setup

| | |
| --- | --- |
| Host | Apple M3, 8 cores, 24 GB RAM, macOS 26.5.2 |
| Docker Desktop | 29.5.2 (shared Linux VM on the Mac, aarch64) |
| Docker Sandbox (`sbx`) | `docker sandbox` v0.21.0 -- a **per-sandbox microVM** (Ubuntu 26.04, kernel 6.12-linuxkit), 8 vCPU / 3.9 GB |
| gimbal | `chm` on Apple Hypervisor.framework, snapshot `ch-arm-v2m-demo` (Ubuntu 24.04), 1 vCPU / 1 GiB |

The three runtimes are different isolation models: Docker Desktop is a
shared-kernel container in one big VM; Docker Sandbox gives each sandbox its own
microVM; gimbal rehydrates a snapshot into a per-session Hypervisor.framework VM.

## 3-way result -- gzip (2026-07-17)

Common workload present in **all three** runtimes:
`seq 1 80000000 | gzip -9 -c` -- deterministic, **single-threaded**, no temp
file, no network. Single-threaded keeps it a fair per-core comparison regardless
of how many vCPUs each runtime exposes. Docker Desktop constrained to
`--cpus 1 --memory 1g` to match the gimbal snapshot shape.

| Metric | Docker Desktop (1 CPU) | gimbal microVM (1 vCPU) | Docker Sandbox (8 vCPU) |
| --- | --- | --- | --- |
| **Compute wall-clock (s)** | **20.92 +/- 0.36** (n=3) | **20.92 +/- 1.38** (n=5) | **19.52 +/- 0.58** (n=3) |
| Startup / create (s) | 0.27 +/- 0.03 | ~5 (warm resume, below) | **12.73** (microVM create) |
| Host envelope: start+run+teardown (s) | - | 26.11 +/- 1.29 | - |

**Headline: gimbal is at parity with Docker Desktop on the compute itself
(20.92s vs 20.92s, 1.00x).** Docker Sandbox's microVM is ~7% faster per-core
(19.52s) -- a newer guest kernel/userland on the same silicon, not a
parallelism win (the workload is single-threaded, so the extra 7 vCPUs are
idle). All three land inside the published microVM band (~1.03-1.09x Docker on
CPU-bound work); a hardware-isolated VM matching a shared-kernel container on CPU
throughput is the expected-but-worth-proving result.

### Startup is the real differentiator (and where #79 bites)

The interesting split is **not** compute -- it is time-to-ready:

- **Docker Desktop**: ~0.27s to start a container (but the shared VM is already
  running; it is not an isolated microVM).
- **Docker Sandbox**: **12.73s** to create its per-sandbox microVM (cached image;
  cold/first create with an image pull was ~106s). This is a real per-sandbox
  microVM boot, the closest apples-to-apples to gimbal.
- **gimbal**: the host envelope (~26s) minus the in-guest compress (~21s) implies
  **warm resume + login + teardown costs only ~5s**. gimbal resumes a snapshot
  that is *already booted and logged in*, so it beats Docker Sandbox's ~12.7s
  cold microVM create -- but gimbal has **no cold boot-from-image path at all**
  (it only rehydrates snapshots). That asymmetry, plus the ~5s still being slow
  for a warm resume, is tracked in **#79** (microVM startup time).

So on this hardware: gimbal's warm-resume start (~5s) < Docker Sandbox's cold
microVM create (~12.7s), while both do real per-instance VM isolation that
Docker Desktop's shared-kernel container does not.

## Prior 2-way result -- xz (2026-07-17)

Earlier run before Docker Sandbox was added, using `seq | xz -6 -T1` (xz is not
present in the Docker Sandbox `shell` image, hence the switch to gzip for the
3-way). Docker and gimbal at 1 vCPU / 1 GiB, N=16M:

| Metric | Docker (1 CPU/1GB) | gimbal microVM (1 vCPU/1GB) |
| --- | --- | --- |
| **Compression wall-clock (s)** | **23.17 +/- 0.83** | **23.67 +/- 0.82** |
| Host envelope: resume + build + teardown (s) | - | 28.96 +/- 0.89 |

gimbal 1.02x Docker -- within run-to-run noise (stddev bands overlap).

## Honest caveats

- **Single vCPU / single-threaded by design.** This measures single-core
  throughput. A multi-vCPU snapshot + a parallel build (`-T0`, `make -j`) would
  test how gimbal's SMP + I/O paths scale -- not yet measured. It also means
  Docker Sandbox's 8 vCPUs give it no parallelism advantage here.
- **Compression, not a compile.** The stock demo guest and the Docker Sandbox
  `shell` image both lack a full C toolchain, so we used a toolchain-free CPU
  workload present everywhere. A real `docker build` / `make` comparison needs a
  toolchain-provisioned snapshot (M32.1).
- **CPU-bound by design.** Deliberately avoids heavy disk/network so the number
  is a clean CPU comparison. gimbal's virtio-blk CoW overlay and userspace NAT
  are *not* exercised here; an IO/network-heavy workload (where microVMs
  historically lose ~17-20%) is the more interesting stress and is future work.
- **Different guests.** Docker Sandbox runs Ubuntu 26.04 / kernel 6.12-linuxkit;
  gimbal runs the Ubuntu 24.04 demo snapshot. The ~7% per-core gap is partly
  guest/kernel, not purely hypervisor overhead.

## Findings surfaced by these runs

1. **The default image needs build tooling (M32.1).** `microvm_probe_toolchain`
   showed the demo guest has `python3, xz, zstd, gzip, openssl, git, tar` but
   **no `cc`/`gcc`/`make`**. A benchmark/agent snapshot must bake in a toolchain.
2. **Post-CPU-burst input wedge (#78).** In a single session, the *first*
   workload runs fine but a *second* command issued after a long silent CPU burst
   does not wake the parked vCPU -- a cousin of the earlier WFI console-freeze
   class. The benchmark works around it by running each trial in a fresh session.
3. **Startup latency is the weak spot (#79).** ~5s warm resume beats Docker
   Sandbox's ~12.7s microVM create, but is still slow versus Firecracker-class
   (~200ms) cold boot, and gimbal has no cold boot-from-image path at all.
