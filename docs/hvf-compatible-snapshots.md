# HVF-compatible snapshots for Gimbal Local

This note is for the cloud agent/control-plane side of Gimbal. It captures the
current macOS Hypervisor.framework compatibility boundary and the snapshot shape
the cloud side should produce for local Mac rehydration.

> **Status: 2026-07-28. This document previously recommended `CH_GIC_V2M=1` and a
> patched fork binary as the production capture path, and described the userspace
> GIC as "experimental, single-vCPU, serial-only". Both statements are now out of
> date and the recommendation has flipped.** A **vanilla, unmodified upstream
> arm64 Cloud Hypervisor capture** is the preferred shape, and as of V2.1 it
> runs through **both** `chm run` and `chm serve` with no flag at all.

## Which capture mode should I produce?

**Capture vanilla.** No fork, no patched binary, no `CH_GIC_V2M`. A stock
upstream `cloud-hypervisor` on Graviton, routing virtio completions through the
GIC ITS as LPIs the way it does by default, is the shape we want:

```text
architecture       = aarch64
hypervisor_capture = kvm
gic_mode           = its-lpi          # stock/vanilla — this is the target shape
ships_disks        = true
```

Gimbal Local runs these on a **userspace GICv3**: a software
distributor/redistributor/ITS plus a trapped CPU interface, with HVF still
executing the vCPUs. That delivers the LPIs Apple's managed GIC cannot. You do
not ask for it — `chm` reads the capture and routes there itself.

| capability on a vanilla ITS/LPI capture | state |
| --- | --- |
| rehydrate + execute | ✅ hardware-proven |
| interactive shell over serial | ✅ hardware-proven |
| virtio **disk** completions | ✅ hardware-proven |
| virtio **net** completions (+ NAT egress) | ✅ hardware-proven |
| SMP (multi-vCPU, cross-core IPIs, SPI affinity) | ✅ hardware-proven |
| checkpoint / suspend / resume | ✅ shipped |
| `chm run` | ✅ supported |
| **`chm serve` (daemon / app path)** | ✅ supported |

Reproduce all of the above on an Apple Silicon Mac:

```sh
CH_SNAPSHOT_DIR=<stock-its-snapshot> \
  cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
  --test hvf_boot -- --ignored --exact --nocapture \
  hvf_rehydrate_stock_its_snapshot_usgic_interactive_shell
```

## No flag required

Both entry points read the capture and pick the backend themselves: if its
virtio completions route as LPIs, it goes to the userspace GICv3, because that
is the only path that can deliver them.

```console
$ chm run <vanilla-graviton-snapshot>      # no environment variables
$ chm ctl start <name>                     # same decision inside the daemon
```

This only ever redirects bundles the managed GIC would have refused outright,
so a capture that runs today keeps taking the same path.

`chm serve` was the last asymmetry ([#102](https://github.com/gimbal-dev/gimbal-local/issues/102)) and is closed: CLI and daemon now
share one engine, including checkpoint capture and resume, and checkpoints
written by either are resumable by the other.

Two things worth knowing about the daemon specifically:

- **A resumed guest emits nothing until it is typed at.** Zero console bytes is
  not evidence of a hang. Send `chm ctl input` (bare = a newline) and read the
  console again. `chm ctl input <text>` sends the text as-is with no trailing
  newline, so finish a command with `chm ctl input '\n'` — or a bare
  `chm ctl input` — to press Enter.
- **Checkpoints cover SMP.** Stop writes a checkpoint for a multi-vCPU guest as
  well as a single-vCPU one: each vCPU's state is captured on its owning thread
  (Hypervisor.framework binds a vCPU to the thread that created it) and the
  whole set is written as one checkpoint. A checkpoint is only resumed onto a
  guest with the same vCPU count; anything else cold-boots and says so.
- **Disk writes need a checkpoint to be safe.** Guest RAM is restored from the
  snapshot on every run, so a run that changes the disk but does *not* end in a
  checkpoint comes back with a filesystem the kernel's cached view no longer
  matches — the files are on the overlay, but the resumed kernel cannot see
  them. Let the run end cleanly (`--checkpoint`, or Stop under the daemon) and
  RAM and disk are captured together.

## Do not confuse the two environment variables

Neither is needed on the supported path. Both are diagnostics.

| variable | what it does |
| --- | --- |
| `CHM_USERSPACE_GIC=1` | **Forces** the software GICv3 even for a capture that would have gone to the managed GIC. Useful for A/B-ing the two backends; not required for vanilla captures, which route there anyway. |
| `CHM_ALLOW_ITS_LPI=1` | **Forces the opposite, and is almost never what you want.** It pushes an ITS/LPI capture onto the *managed* GIC, which cannot deliver LPIs, so the guest restores and then stalls on its first disk or net I/O. It exists to reproduce that failure deliberately, and it warns. |

Anything describing `CHM_ALLOW_ITS_LPI=1` as "the USGIC path" is wrong; it is the
opposite, and it will look like a hang.

## Counter frequency: a capture-host property you cannot fix on restore

Interrupt routing is not the only thing a snapshot inherits from its capture
host. The guest also caches its **counter frequency** (`CNTFRQ_EL0`) as
`arch_timer_rate` the first time it boots, and never re-reads it.

| host | `CNTFRQ_EL0` |
| --- | --- |
| Apple silicon under Hypervisor.framework | 24 000 000 Hz (fixed — no API changes it) |
| AWS Graviton2 (Neoverse-N1) | 121 875 000 Hz |

A Graviton capture resumed on a Mac therefore runs every sleep, timeout,
scheduler tick and wall-clock reading **5.078× slow**. This is measured, not
predicted — see [graviton-acid-test-results.md](graviton-acid-test-results.md).
The guest is not corrupted; it stays internally consistent, which is exactly
what makes it dangerous. It presents as a sluggish VM, not as a wrong clock.

**`chm` corrects this automatically.** A capture taken by a cloud-hypervisor
build including upstream `69637dde6` records the frequency of the host it was
taken on, so nothing has to be guessed or configured: the counter is
rate-corrected on load and the guest keeps correct time.

| variable | what it does |
| --- | --- |
| *(unset — the default)* | The capture's own recorded frequency is used and the dilation is corrected. `chm` prints a note saying so. A capture that records no frequency cannot be corrected, and `chm` says that instead of guessing. |
| `CHM_GUEST_CNTFRQ=<Hz>` | Overrides the recorded value, or supplies one for a capture predating `69637dde6`. A Graviton2 capture is `121875000`. |
| `CHM_GUEST_CNTFRQ=0` | **Declines the correction** and accepts the dilated clock, trading a wrong clock for ~2.8% of wall time. |
| `CHM_STRICT_CNTFRQ=1` | Refuses to start on an *uncorrectable* mismatch, matching the KVM path's `CntfrqMismatch` rejection. |

### How the correction works

Apple exposes `hv_vcpu_set_vtimer_offset`, which is an *offset*, not a rate — but
the offset is ours to move. A VM-global clock holds one offset shared by every
vCPU and steps it forward periodically, so the guest's counter advances at the
rate the guest already believes it has. Measured effect: **5.081× dilation →
1.000×** — `sleep 20` inside a 2-vCPU Graviton2 guest takes 20.01 s of host wall
clock, and `/proc/uptime` advances 20.02 guest-seconds over it.

#### One offset, shared, moved by a stop-the-world barrier

The offset is shared rather than per-vCPU, and that is the whole design. Linux
treats `CNTVCT_EL0` as a single system-wide clocksource and reads it on whichever
core it happens to be running, so two vCPUs must return the same value — not
merely close values. `arch_sys_counter` is a **56-bit** clocksource and
`clocksource_delta()` computes `(now - last) & mask`, so a read even *one tick*
behind its predecessor is latched as `2^56` ticks ≈ **18.7 guest-years** forward.
Bounded skew is therefore not an acceptable target; exact equality is.

Since two vCPUs hold equal offsets only if the offset never changes while either
is running, the stepper forces every vCPU out of `hv_vcpu_run`, publishes the new
offset, and lets them back in. If it cannot get them all out in time it
**abandons the step** — the guest stays coherent and merely runs slow for another
window. Slow-but-correct beats fast-but-corrupt.

#### The cost, measured

The period trades barrier overhead against how far the guest's clock is allowed
to lag before being caught up. Measured on a 2-vCPU Graviton2 capture:

| `CHM_VTIMER_STEP_MS` | wall time stopped | worst-case guest clock error |
| --- | --- | --- |
| 5 | 26.9% | 4 ms |
| 10 | 10.1% | 8 ms |
| **20 (default)** | **2.8%** | **16 ms** |
| 50 | 0.8% | 40 ms |

20 ms is the knee: below it the barrier cost climbs steeply as vCPUs spend their
time bouncing in and out of the guest; above it the saving is small and the clock
gets lumpy. `CHM_TRACE_VTIMER=1` reports the live duty cycle.

#### This also fixed the *uncorrected* path

The per-vCPU offsets were seeded independently, on each vCPU's own thread at its
own `mach_absolute_time()`, so they differed permanently even with no rate
correction at all. Measured inside a 2-vCPU guest with a pinned two-thread
ping-pong test that establishes a strict happens-before chain between reads:
**19,992 of 40,000 strictly-ordered samples went backwards**, and the guest's
`date` read **July 2101**. It is now 0 of 40,000, on both the corrected and
uncorrected paths.

## Legacy path: GICv2M / message-SPI

Before the userspace GIC, the only runnable shape was virtio completions routed
as normal GIC SPIs:

```text
gic_mode = gicv2m-message-spi
```

produced by launching **this repository's patched** Cloud Hypervisor binary with
`CH_GIC_V2M=1`. It still works and is still regression-tested every change
(`snapshots/ch-arm-v2m-demo` boots to a login prompt on the managed GIC).

**It is no longer the recommended production shape**, because it requires a
forked capture engine — the exact coupling the vanilla path removes. Keep it as
a fallback and as the managed-GIC regression fixture.

## Why the managed GIC cannot do this

The limitation is not a Gimbal bug; it matches the prior art:

- QEMU's arm64 `virt` machine rejects ITS when HVF uses the hardware vGIC:
  `ITS not supported on HVF when using the hardware vGIC.`
- QEMU defaults HVF hardware-vGIC MSI routing to GICv2M/message-SPIs, not ITS.
- VirtualBox's Darwin ARM GIC backend uses SPI injection with no full MSI/ITS
  send path.
- Apple exports `hv_gic_set_spi` and `hv_gic_send_msi`, but no public ITS/LPI API
  has been found.

Running a software GIC alongside hardware CPU virtualisation is the same
architecture used by libkrun, QEMU (`kernel-irqchip=off`), and RexPlayer on
Apple Silicon.

## Known caveat: live ITS reprogramming

`GITS_*` MMIO is deliberately not implemented. It is not exercised on the resume
path — a rehydrated guest inherits an already-programmed ITS — but a guest that
**re-programs its ITS while running** (hotplug, a driver rebind) is untested.
None of the fixtures do this. Worth knowing before assuming an arbitrary vanilla
image is safe.

## Classification note

Older Cloud Hypervisor names the serialized GIC node `gic-v3-its` even when the
ITS is disabled. **Do not classify compatibility from the node name alone.**
Check the routing mode or the nested GIC state: `GITS_CTLR.Enabled` clear with
MSI-X data values in the normal SPI range is the GICv2M/message-SPI path.

## Disk requirement (ship the guest disks)

A Cloud Hypervisor snapshot restores guest **RAM** (registers, devices, and the
page cache) but only **references** its disks by host path — it does not embed
their contents. Gimbal Local therefore needs the real disk images alongside the
snapshot, or the guest hits ext4 checksum failures and `Input/output error`
(EIO) the moment it reads any block that was not already cached in the restored
RAM.

Ship each disk under the snapshot bundle as:

```text
<snapshot>/
  state.json
  snapshot/{config.json,memory-ranges,state.json}
  disks/<device-id>.raw     # e.g. disks/_disk0.raw, disks/_disk1.raw
```

The file name must be the snapshot's **device-node id** (`_disk0`, `_disk1`, …),
which is what `chm` resolves via `shipped_backing()`. The capture scripts derive
these names from `config.json` automatically.

### Copy-on-write rehydration (why the base stays immutable)

`chm` opens each shipped disk as an **immutable base** and redirects every guest
write to a fresh, per-run copy-on-write overlay under `<snapshot>/.chm-overlays/`
(`<device-id>-cow.raw`). This is required for correctness, not just tidiness:

- Restore pairs snapshot-era RAM with the snapshot-era disk. If guest writes
  leaked into the base image, the next resume would pair the *old* RAM with a
  *drifted* disk, and ext4 would reject its own metadata (`deleted inode
  referenced`, checksum failures, EIO).
- With COW, the base is never mutated, so every resume is consistent and
  **repeatable** — you can rehydrate the same snapshot any number of times and
  each run starts clean. Writes persist for the life of a run and are discarded
  when overlays are cleared (`rm -rf <snapshot>/.chm-overlays/*`).

Disks must be captured while the guest is **paused** (the capture scripts pause
before snapshotting and export the disks before resuming), so the exported
image matches the memory image instant-for-instant.

## Capture requirement

For the **vanilla path** there is no capture requirement beyond a stock upstream
aarch64 `cloud-hypervisor` on a KVM host, plus the disk-shipping rule above.
That is the point of it.

For the **legacy GICv2M path**, `CH_GIC_V2M=1` only works with this fork's
patched binary; it does nothing to an upstream release binary. The capture worker
must either build `cloud-hypervisor` and `ch-remote` from this repository, or
receive prebuilt aarch64 Linux binaries produced from it.

The local `scripts/hvf/capture-on-mac.sh` path (Lima nested KVM on M3+ Macs)
exports the guest disks into `disks/` automatically, so a bundle captured that
way is self-contained. Both it and `capture-arm-snapshot.sh` now default to
`CH_GIC_V2M=0` — vanilla. Pass `CH_GIC_V2M=1` (plus `CH_BIN`/`CHREMOTE_BIN`
pointing at this fork's binaries) only for a legacy capture. The
`snapshots/ch-arm-stock-its*` fixtures are vanilla.

For a capture on real cloud hardware, the exact spec is
[`graviton-capture-request.md`](graviton-capture-request.md).
