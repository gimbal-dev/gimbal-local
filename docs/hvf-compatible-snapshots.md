# HVF-compatible snapshots for Gimbal Local

This note is for the cloud agent/control-plane side of Gimbal. It captures the
current macOS Hypervisor.framework compatibility boundary and the snapshot shape
the cloud side should produce for local Mac rehydration.

## Required interrupt mode

Gimbal Local can run arm64 Cloud Hypervisor snapshots on Apple Silicon when
virtio completion interrupts are routed as normal GIC SPIs:

```text
gic_mode = gicv2m-message-spi
```

The capture host should set:

```sh
CH_GIC_V2M=1
```

when launching the patched Cloud Hypervisor binary from this repository.

## Stock ITS/LPI mode — two paths

Stock arm64 Cloud Hypervisor snapshots usually route virtio MSI/MSI-X
completions through the GIC ITS as LPIs:

```text
virtio device -> MSI/MSI-X -> GIC ITS -> LPI
```

Apple's *managed* Hypervisor.framework GIC does not expose a deliverable ITS/LPI
path. On the **default managed-GIC path**, if a snapshot contains enabled
`gic-v3-its` state plus MSI-wired virtio devices, `chm` rejects it early rather
than restoring a guest that would hang on its first disk or network completion
interrupt.

**There is now a second path.** Setting `CHM_USERSPACE_GIC=1` runs the snapshot
on a **userspace GICv3** instead of the managed GIC — a software
distributor/redistributor + a trapped CPU interface that delivers LPIs the
managed GIC cannot. This rehydrates a *stock* ITS/LPI snapshot and boots it to an
interactive shell:

```sh
CHM_USERSPACE_GIC=1 chm run <stock-its-snapshot>
#   backend:   Apple Hypervisor.framework (userspace GICv3)
#   ubuntu@ch-snap:~$
```

This is experimental and currently single-vCPU; serial input works (the shell is
fully usable), while virtio disk/net *completion* routing through the userspace
ITS, `GITS_*` MMIO, and SMP are the remaining scope (tracked as M-USGIC / #81).
For production captures today, the managed-GIC `CH_GIC_V2M=1` contract below is
still the recommended path.

## Why this is not just a local-runner bug

The limitation matches the prior art:

- QEMU's arm64 `virt` machine explicitly rejects ITS when HVF is using the
  hardware vGIC: `ITS not supported on HVF when using the hardware vGIC.`
- QEMU defaults HVF hardware-vGIC MSI routing to GICv2M/message-SPIs, not ITS.
- VirtualBox's Darwin ARM GIC backend uses SPI injection and does not expose a
  full MSI/ITS send path.
- Apple's Hypervisor.framework exports SPI/MSI-doorbell style GIC entry points
  such as `hv_gic_set_spi` and `hv_gic_send_msi`, but no public full ITS/LPI
  API has been found.

Gimbal implements a userspace GICv3 (CPU interface + distributor/redistributor +
ITS) while still using HVF for CPU execution. **This now works end to end on
hardware** (Apple M3): a stock ITS/LPI snapshot rehydrates onto the software GIC
and boots to an interactive Ubuntu shell — see
`hypervisor/tests/hvf_boot.rs::hvf_rehydrate_stock_its_snapshot_usgic_interactive_shell`
and run it yourself with `CHM_USERSPACE_GIC=1 chm run <snapshot>`. With no managed
GIC, `ICC_*_EL1` accesses trap to the VMM as `EC=0x18`; the software GIC delivers
SPIs, PPIs, SGIs, and **LPIs** (INTID >= 8192 — the class the managed GIC cannot
deliver); the virtual timer is self-managed across WFI so the guest keeps
ticking. The same architecture ships in libkrun, QEMU (`kernel-irqchip=off`), and
RexPlayer on Apple Silicon.

What remains to make this the *default* path (rather than the `CHM_USERSPACE_GIC`
opt-in) is scope, not feasibility: routing virtio disk/net **completions** through
the userspace ITS (serial already works, so the shell is usable now), `GITS_*`
MMIO for guests that re-program the ITS live, SMP, and per-access trap
performance. Until that lands, the capture-side `CH_GIC_V2M=1` contract below
remains the recommended production path.

## Cloud agent contract

For every snapshot intended to be runnable by Gimbal Local, persist a manifest
field equivalent to:

```text
architecture = aarch64
hypervisor_capture = kvm
gic_mode = gicv2m-message-spi
compatibility_status = runnable-hvf
ships_disks = true
gimbal_local_commit = <commit that built the capture binary>
```

Do not present `its-lpi` snapshots as runnable on the **default managed-GIC**
path — they are refused there. They ARE runnable on the userspace-GICv3 path
(`CHM_USERSPACE_GIC=1`, experimental), and remain useful for Linux/KVM restore.
Label them `its-lpi` and note the managed-GIC mismatch + the userspace-GIC
opt-in, rather than a flat "incompatible".

Implementation note: older Cloud Hypervisor code names the serialized GIC
snapshot node `gic-v3-its` even when the actual ITS is disabled. Do not classify
compatibility from the snapshot-node name alone. Check the captured routing mode
or the nested GIC state: `GITS_CTLR.Enabled` clear with MSI-X data values in the
normal SPI range is the deliverable GICv2M/message-SPI path.

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

`CH_GIC_V2M=1` only works with this fork's patched Cloud Hypervisor binary. It
does not change the behavior of an upstream release binary. The capture worker
must either:

1. build `cloud-hypervisor` and `ch-remote` from this repository, or
2. receive prebuilt aarch64 Linux binaries produced from this repository.

The local `scripts/hvf/capture-on-mac.sh` path now follows the same rule for
M3+ Macs with Lima nested KVM, and exports the guest disks into `disks/`
automatically so the resulting bundle is self-contained.
