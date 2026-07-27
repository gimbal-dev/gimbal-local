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
attempted here. (Taken up in #94 below — where the suggested fix turned out to
be unavailable, and the real cost turned out to be somewhere else entirely.)

## Caveats

- Single vCPU throughout. Neither side is doing parallel I/O.
- Different guests and kernels, as with the compute run above.
- `netget` needs `--allow-local-egress`, because the host is on RFC1918 and the
  reserved-address guard (M31.1) otherwise refuses it. Benchmark-only.
- gimbal's ~10s per-trial host envelope is startup, excluded from the numbers
  above and tracked separately in #79.

## `netget` — receive coalescing (2026-07-28, #94)

Same harness, same host, same snapshot. Baseline re-measured on the day rather
than quoted from the table above, so the two numbers come from one sitting.

| | median of 5 | range |
| --- | --- | --- |
| before | 1.966s | 1.942 – 2.056 |
| after | **1.213s** | 1.187 – 1.294 |

1.62x. Docker remains 0.155s, so the gap is 7.8x rather than 12.8x.

### The suggested fix was not available

#94 proposed negotiating `MRG_RXBUF` and GSO. A rehydrated snapshot cannot:
the guest bound its feature set at capture time, and `devmgr` restores
`acked_features` from `state.json`. This snapshot negotiated `0x120427faf` —
`GUEST_CSUM`, `GUEST_TSO4/6`, `GUEST_UFO`, but **not** `MRG_RXBUF`. The guest's
link MTU cannot be raised either: `VIRTIO_NET_F_MTU` with `config.mtu = 1500`
pins `dev->max_mtu`, and TCP MSS clamping caps the segments regardless.

What that feature set does give us is Linux's "big packets" receive mode:
without `MRG_RXBUF` but with GSO, `virtio_net` posts multi-page receive chains.
Measured, the guest was posting 73,708-byte chains and we were putting 1,478
bytes in each. Coalescing on receive is the only route to larger frames, and it
is what a hardware LRO NIC does.

### What was actually wrong

**The vCPU was running the network stack.** `NatResponder::handle` ran the whole
smoltcp pass synchronously inside the MMIO exit for a guest transmit. Measured:
764ms of every second was spent stopped inside `notify_net`. A transmit now only
enqueues the frame and wakes the service thread.

**The checksum was 80% of the remaining cost.** Once the vCPU was free, the
transfer got *slower*. Nested timers narrowed it to `flush_rx` (894ms/s), then
`pop_rx` (721ms), then `checksum_in_place` (710ms) — a byte-at-a-time RFC-1071
loop over a merged ~3 KB payload, roughly 75µs per packet in a debug build.
`GUEST_CSUM` is negotiated, so we stamp `VIRTIO_NET_HDR_F_DATA_VALID` and skip
the TCP checksum entirely. The claim is truthful: the NAT terminates every flow
and generates the segment itself. The IP header checksum is still computed —
Linux verifies that one unconditionally.

**Coalescing needs a backlog to coalesce.** With the above fixed, the merge
ratio sat at exactly 2.0 with no frame ever hitting the size limit: smoltcp
emits about 1.5 frames per poll, and draining after every pass meant there was
never anything to merge. Servicing in a bounded burst — accumulate until one
receive chain's worth of bytes, at most 32 passes, stop early on an idle pass —
took the ratio to 29x (45,223 segments into 1,547 frames) and cut interrupts
from 6,977/s to 1,035/s.

**The service thread slept while the host had data queued.** It waited on the
kick condvar after *every* pass, including passes that had just delivered
frames — so a bulk transfer was capped at one chain per 2ms fallback whenever
guest transmits were sparse. Now a pass that reached the guest goes straight
round again; only an idle pass waits. This is self-reinforcing with the
coalescing above: the better the merging, the fewer guest ACKs, the fewer wakes.

### Where I was wrong

1. **LRO on its own was a regression** — 3.22s against a 2.08s baseline. The
   mechanism was right and the measurement said no. Deferring the stack off the
   vCPU is what made it pay; neither change is worth anything alone.
2. **Deferring with a busy service loop was much worse** — 5.567s, because the
   thread burned a core spinning. The answer to a latency problem was not a
   tighter loop.
3. **I assumed the wire was the cost.** It was the checksum, and only nested
   timers found it. Worth stating that these runs are debug builds, so an
   unoptimised inner loop is disproportionately expensive — the baseline is
   debug too, so the comparison is fair, but the absolute figure is not.
4. **I measured "one poll per pass instead of two"** on the theory the leading
   `iface.poll` was redundant. It is not: 1.459 / 1.613 / 2.551s, with poll time
   rising from 553ms to 1,646ms. Reverted.
5. **Three trials hid a real bug.** A 3-trial run gave 1.49 / 1.33 / 1.41 and I
   nearly stopped there. Five trials gave 10.09 / 36.22 / 8.42 / 2.09 / 1.19 —
   the sleeping-service-thread stall above. The fast reading was luck. The fix
   took the spread to 1.187–1.294 across two independent runs of five.

### What is left

`iface.poll` (smoltcp) is now the largest remaining cost at roughly 550ms of a
second. How much of that is the debug build is untested.

## `diskwrite` — guest-RAM first touch (2026-07-28, #95)

`diskwrite` writes 256 MiB inside the guest and fsyncs. Same-sitting baseline,
median of 5: **1.601s** against Docker's 0.266s.

| workload | before | after | vs before | Docker |
| --- | --- | --- | --- | --- |
| diskwrite | 1.601s | **0.496s** | 3.23x | 0.266s |
| fsyncsmall | 0.224s | **0.103s** | 2.17x | 0.120s |
| netget | 1.269s | **1.153s** | 1.10x | 0.155s |

Interleaved A/B (alternating trials of the shipped default and
`CHM_NO_RAM_WILLNEED=1`) because the host was busy; interleaving cancels drift
that a block-of-5-then-block-of-5 comparison would attribute to the change.

### The issue's premise was wrong

#95 said the cost was "first-write allocation in the fresh sparse CoW overlay"
and proposed `F_PREALLOCATE`. I implemented that hypothesis first, as written.
It bought **1.979s -> 1.696s (~14%)** while costing **8 GiB of real disk per
sandbox** and **100-772ms of startup**. Rejected — but the more useful result is
what the small win *proved*: if allocation were the dominant cost, fully
preallocating the file would have collapsed the number. It did not.

Instrumenting the whole host block path (timers on notify, process, write_at,
the `pwrite` syscall, the `mark_written` loop, `seed_sector`, `flush`,
`persist_bitmap`, dumped at 1 Hz) put **the entire host block path at ~230ms of
a 1.9s wall clock** — 69ms of `pwrite` for ~96 MiB, and 10,065 requests batched
into just 129 notifies, so the device model was already fine.

The decisive measurement was to delete the disk from the experiment: the same
256 MiB write to **tmpfs** (`BENCH_DISK_PATH=/dev/shm/gb.dat`) — no block
device, no overlay, no `pwrite`, no host fsync — still took **1.449s**. So the
overlay accounted for ~0.5s of the 1.98s and **~1.45s was guest-side RAM first
touch**. Confirmed independently: four back-to-back 256 MiB tmpfs writes in one
session cost 1.522s *total* versus 1.449s for one, i.e. iterations 2-4 were
essentially free. A ~60x first-touch penalty, with no disk involved.

### The cause was #79's own fix

Guest RAM is a file-backed `MAP_PRIVATE` mmap of the snapshot's `memory-ranges`
— the "160x faster resume" change from #79, which replaced a 622ms eager read
with a 34µs mmap. Every first touch of a guest page is then a synchronous host
fault. The A/B switch that shipped with that change proves it: `CHM_EAGER_RAM=1`
gave **0.588s vs 1.979s (3.4x)**, and the whole-run host envelope *dropped* from
~12.2s to ~10.9s.

**#79 traded a 622ms eager read for ~1.4s of scattered synchronous faults, and
its resume-only micro-metric could not see it.** This is a global rehydration
cost — it is why `fsyncsmall` and `netget` improve too, and neither is a disk
benchmark.

### Mechanism bake-off

Reverting to eager reads would undo #79. Four alternatives were measured:

| mechanism | diskwrite | fsyncsmall | mmap step |
| --- | --- | --- | --- |
| lazy (before) | 1.601s | 0.224s | ~2ms |
| eager read (`CHM_EAGER_RAM`) | 0.588s | — | 622ms |
| background thread reading the mapping | 0.482s | **1.254s** | ~2ms |
| `fcntl(F_RDADVISE)` | 1.643s | — | 318ms |
| `madvise(MADV_WILLNEED)` inline | 0.534s | 0.094s | **665ms** |
| `madvise(MADV_WILLNEED)` on a thread | **0.542s** | **0.091s** | **1.5ms** |

Shipped: the last row. `Drop` joins the thread before `munmap`, so it can never
touch a torn-down mapping. `CHM_NO_RAM_WILLNEED=1` opts out.

### Where I was wrong

1. **I believed the issue.** I spent the first pass implementing its
   `F_PREALLOCATE` hypothesis. The measurement that mattered was the one that
   removed the disk entirely, and I should have reached for it first — the
   issue's own note that "virtio is only ~120ms of the run" was already telling
   me the device model was not the problem.
2. **`madvise(MADV_WILLNEED)` is not advisory on macOS.** I shipped it inline
   with a doc comment stating it was "advisory and non-blocking" — the Linux
   semantics. `CHM_TRACE_TIMING` showed the mmap step going **2.05ms ->
   702.9ms**: it re-paid almost exactly the cost #79 removed. The workload
   numbers were still good, so nothing failed; the claim in the comment was
   simply false, and only a timing A/B caught it.
3. **`F_RDADVISE` looked like the obvious fix and does nothing.** It is macOS's
   genuinely-asynchronous file readahead, so it seemed strictly better. It
   warms the *file's* page cache, not the *mapping*, and moved the workload by
   0 (1.643s vs a 1.68s baseline). The cost is not reading bytes off disk, it
   is the fault itself.
4. **The background-thread prefault looked like the winner.** Best diskwrite
   number of the lot (0.482s) — and it regressed `fsyncsmall` from 0.176s to
   **1.254s**, because a tiny 200 x 4 KiB workload just contends with a thread
   hammering 1 GiB. Caught only because I checked a second workload, which is
   the same lesson #94 taught. `madvise` on a thread does not have this problem:
   it is one kernel call, not a userspace read loop.
5. **I trusted a block-of-5 A/B on a busy host.** A run that gave a 29.33s
   outlier and a 4.08s median looked like a real regression; the host was at
   load average 41 with 65 MB free. Interleaving the variants made both
   agree to within noise.
