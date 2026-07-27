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

---

# I/O and network vs Docker Desktop (2026-07-28, Apple M3)

The compute comparison above deliberately avoided disk and network, and named
that as the more interesting stress. With networking shipped (#91) it became
testable, so this is that run.

Matched 1 vCPU / 1 GiB on both sides, median of five trials, inner command
byte-identical across runners (`scripts/bench/workloads/commands.sh`).

| Workload | Docker | gimbal before | gimbal after | after / Docker |
| --- | --- | --- | --- | --- |
| `fsyncsmall` — 200 x 4 KiB `O_DSYNC` | 0.120s | 6.23s | **0.175s** | 1.5x |
| `diskwrite` — 256 MiB `conv=fsync` | 0.266s | 1.74s | **1.528s** | 5.7x |
| `netget` — 64 MiB over HTTP | 0.155s | 1.93s | 1.982s | 12.8x |

`fsyncsmall` improved 36x. The other two are characterised below rather than
claimed as wins.

## What was actually wrong

**`fsync` was a hardware barrier.** Rust's `File::sync_data()` maps to
`fcntl(F_FULLFSYNC)` on macOS, which asks the SSD to flush its write cache to
physical media. A host micro-benchmark measured plain `fsync(2)` at 0.05ms
against roughly 5ms for the barrier. We were paying that on every guest flush,
and comparing ourselves against Docker Desktop and QEMU `cache=writeback`, which
do not take it. Default is now plain `fsync(2)`; `CHM_FULL_BARRIER=1` restores
the barrier.

Durability, stated plainly: plain `fsync(2)` survives a guest, VMM or host OS
crash, but not host power loss. For the per-run copy-on-write overlay that is
the right trade, because durable state is captured by the checkpoint path.

**The bitmap sidecar was rewritten whole on every flush** — 2 MiB for an 8 GiB
disk — and reopened each time. Now incremental over 4 KiB chunks, with the
handle cached.

**A blocking `EventFd`.** `fcntl(F_SETFL, O_NONBLOCK | O_CLOEXEC)` mixed a
descriptor flag into a file-status call, so the whole request failed and
`O_NONBLOCK` was never applied. Any waiter that reached `drain_pipe()` wedged.

**`WRITE_ZEROES` was silently corrupting data.** Acknowledged without being
performed, which is safe on a zero overlay but not on a copy-on-write one, where
an unwritten sector reads through to the base image. Not hit by these workloads
(3 discards, 36 KiB) but a real latent risk.

## Where I was wrong

Recorded because the wrong turns were more instructive than the fixes.

1. **The WFI park was not the bottleneck.** I was confident enough to change it
   first. Instrumenting the exits showed 195 WFI exits in 24s. The change was
   kept because it is the correct primitive, not because it bought anything.
2. **"The bitmap is a red herring at 0.7ms" was a bad measurement.** Isolated,
   the page cache absorbed a 2 MiB write with nothing competing. Interleaved
   with a real guest fsync workload the same write cost 11.87ms. Micro-benchmarks
   of one component of a contended path are worth very little.
3. **"Only 35.7 MiB of 256 MiB reached the backend" was a mid-stream artefact,**
   not a bug. Two theories were chased and eliminated before it was settled by
   writing the data, dropping caches, and comparing an `md5sum` against a
   host-computed hash. It matched exactly.

## The remaining gaps, honestly

**`diskwrite` (5.7x) is mostly not the device model.** Instrumenting the
transport showed the entire run spends about 120ms inside virtio. Running the
identical command three times in one session gives 1.615s, then 0.634s, then
0.391s — so the bulk of the cold cost is allocating blocks in the freshly
created sparse overlay, which every run gets by design. Worth fixing, but it is
an allocation cost rather than a per-request one.

The comparison also flatters Docker here: without a forced flush its 256 MiB
never leaves the page cache (2.7 GB/s), whereas our guest has 1 GiB of RAM and
begins writing back part way through. Same command, different amount of actual
disk work.

**`netget` (12.8x) is untouched.** `NAT_MTU` is 1500 with no offloads
negotiated, so 64 MiB is roughly 45k packets, each a userspace round trip.
Raising the MTU and negotiating checksum/GSO offloads is the fix and is not
attempted here.

## Caveats

- Single vCPU throughout. Neither side is doing parallel I/O.
- Different guests and kernels, as with the compute run above.
- `netget` needs `--allow-local-egress`, because the host is on RFC1918 and the
  reserved-address guard (M31.1) otherwise refuses it. Benchmark-only.
- gimbal's ~10s per-trial host envelope is startup, excluded from the numbers
  above and tracked separately in #79.
