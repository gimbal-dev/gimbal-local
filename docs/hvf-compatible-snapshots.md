# HVF-compatible snapshots for Gimbal Local

This note is for the cloud agent/control-plane side of Gimbal. It captures the
current macOS Hypervisor.framework compatibility boundary and the snapshot shape
the cloud side should produce for local Mac rehydration.

> **Status: 2026-07-28. This document previously recommended `CH_GIC_V2M=1` and a
> patched fork binary as the production capture path, and described the userspace
> GIC as "experimental, single-vCPU, serial-only". Both statements are now out of
> date and the recommendation has flipped.** A **vanilla, unmodified upstream
> arm64 Cloud Hypervisor capture** is the preferred shape. See "Which capture
> mode should I produce?" below for the one real caveat (`chm serve`).

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

Gimbal Local runs these on a **userspace GICv3** (`CHM_USERSPACE_GIC=1`): a
software distributor/redistributor/ITS plus a trapped CPU interface, with HVF
still executing the vCPUs. That delivers the LPIs Apple's managed GIC cannot.

| capability on a vanilla ITS/LPI capture | state |
| --- | --- |
| rehydrate + execute | ✅ hardware-proven |
| interactive shell over serial | ✅ hardware-proven |
| virtio **disk** completions | ✅ hardware-proven |
| virtio **net** completions (+ NAT egress) | ✅ hardware-proven |
| SMP (multi-vCPU, cross-core IPIs, SPI affinity) | ✅ hardware-proven |
| checkpoint / suspend / resume | ✅ shipped |
| `chm run` | ✅ supported |
| **`chm serve` (daemon / app path)** | ❌ **not yet — see below** |

Reproduce all of the above on an Apple Silicon Mac:

```sh
CH_SNAPSHOT_DIR=<stock-its-snapshot> \
  cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
  --test hvf_boot -- --ignored --exact --nocapture \
  hvf_rehydrate_stock_its_snapshot_usgic_interactive_shell
```

## The one real gap: `chm serve`

`chm run` honours `CHM_USERSPACE_GIC=1`. **`chm serve` does not.** The daemon
calls `its_lpi_guard` unconditionally and only has the managed-GIC path wired, so
a vanilla ITS/LPI bundle is *rejected* there even though the same bundle runs
fine under `chm run`.

That matters because `chm serve` is what the macOS app drives, and is the likely
integration point for a control plane. Until it is wired:

- **`chm run` + vanilla capture** — works today, fully.
- **`chm serve` + vanilla capture** — refused. Needs either the legacy
  GICv2M capture below, or the userspace-GIC path ported into the daemon.

Tracked as [#102](https://github.com/gimbal-dev/gimbal-local/issues/102). It is wiring, not feasibility — the whole userspace-GIC
stack it needs is already shipped and proven under `chm run`.

## Do not confuse the two environment variables

| variable | what it does |
| --- | --- |
| `CHM_USERSPACE_GIC=1` | **The supported path.** Rehydrates onto the software GICv3, which delivers LPIs. This is what makes vanilla captures work. |
| `CHM_ALLOW_ITS_LPI=1` | **A debugging bypass. Do not use.** Silences the guard on the *managed* GIC and changes nothing about delivery — the guest restores and then stalls on its first disk or net I/O. |

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

`chm` checks this at load and says so:

| variable | what it does |
| --- | --- |
| *(unset — the default)* | Warns loudly and **still runs**. A dilated guest is genuinely useful, and refusing would mean no cloud snapshot ever starts on a Mac. |
| `CHM_STRICT_CNTFRQ=1` | Refuses to start on a mismatch, matching the KVM path's `CntfrqMismatch` rejection. Use it when a wrong clock would be worse than no run at all. |

A capture taken by a cloud-hypervisor build predating upstream `69637dde6`
records no counter frequency at all, so `chm` cannot verify it and says that
instead of guessing.

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
forked capture engine — the exact coupling the vanilla path removes. Keep it for
`chm serve` until the daemon is wired, and as a fallback.

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
