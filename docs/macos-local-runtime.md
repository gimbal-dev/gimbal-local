# Cloud Hypervisor on macOS Hypervisor.framework

This document explains how this fork resumes a Cloud Hypervisor `arm64` cloud
snapshot on Apple Silicon. It is the in-repo companion to the milestone history
and is aimed at someone reading the `hypervisor/src/hvf/` code for the first
time.

## The dream, concretely

A VM runs in the cloud on a Linux/KVM `aarch64` host. You snapshot it with
`ch-remote snapshot` and copy the resulting directory to your Mac. You then run:

```sh
chm run ./ch-snapshot
```

and the **same** guest — its RAM, its vCPU register file, its interrupt
controller state, its virtual-timer deadline — comes back to life on Apple's
Hypervisor.framework and keeps executing from exactly where it was frozen.

The difficulty is that KVM and HVF are different hypervisors with different
register encodings, a different interrupt-controller programming model, and a
different notion of time. The `hvf` backend bridges that gap.

## The snapshot

A Cloud Hypervisor snapshot directory contains:

- `state.json` — VM configuration plus the serialized device/vCPU state,
  including each vCPU's `arm64` core and system registers as captured from KVM.
- `snapshot/memory-ranges` — the raw guest RAM, as one or more ranges mapped at
  their guest physical addresses.

`hypervisor/src/hvf/rehydrate.rs` parses `state.json` into a `Snapshot`
(`Snapshot::from_state_json`) and maps the memory ranges into a fresh HVF VM.

## The rehydration pipeline

`rehydrate(hv, &snapshot, &memory_ranges, &vm_ops)` rebuilds a live VM in the
same order Cloud Hypervisor itself restores one:

1. **Create the VM** and **map guest RAM** at the snapshot's guest physical
   addresses (`hv_vm_map`).
2. **Create the managed GICv3** (`hypervisor/src/hvf/gic.rs`) with the
   distributor/redistributor bases from the snapshot, and restore the
   distributor state.
3. **Create the vCPUs.** For each, restore its full register file — which sets
   `MPIDR_EL1` and the `ICC_*` CPU-interface registers — then restore its
   redistributor frame.
4. Hand back a `RehydratedVm` whose vCPUs can be `run()` immediately.

Field/drop order in `RehydratedVm` matters: HVF requires every vCPU to be
destroyed before the VM, so the `vm` handle is declared last.

## KVM → HVF register translation

`hypervisor/src/hvf/translate.rs` is the bijection between a KVM snapshot's
register list and HVF's register encodings. Core registers (X0–X30, SP, PC,
PSTATE) and system registers (the `S<op0>_<op1>_<crn>_<crm>_<op2>` space) are
routed to the correct HVF setter. The module's tests assert the mapping is an
exact round-trip (`lower_then_raise_is_identity`,
`sysreg_encoding_is_a_bijection`) and ingests a real captured snapshot.

## Interrupt controller (GIC)

Apple's HVF provides a *managed* GICv3: the host configures distributor and
redistributor bases, and HVF emulates the controller. The backend restores
distributor and per-redistributor state out of the snapshot and delivers SPIs
and PPIs (including the virtual-timer PPI 27). Integration tests cover injected
SPIs, the virtual timer, and a WFI woken by a cross-thread IRQ.

## Time: the virtual-timer continuity fix

This was the subtle one. The snapshot carries:

- `CNTVCT_EL0` — the guest's virtual counter value at snapshot time,
- `CNTV_CVAL_EL0` — the timer comparator,
- `CNTV_CTL_EL0` — the timer control (enabled).

A fresh HVF VM restarts its virtual counter near zero. If you restore the
comparator verbatim, it now sits ~2³² ticks in the *future*, so the guest's
scheduler tick never fires: it parks in `WFI` forever and eventually trips its
own soft-lockup watchdog. That is what "boots but then idles" looked like.

HVF defines `CNTVCT_EL0 = mach_absolute_time() - vtimer_offset`. The fix
(`HvfVcpu::restore_vtimer_offset`) pulls `CNTVCT_EL0` out of the restored
register list (it is **read-only**, so it must not be written as a sysreg) and
sets the offset to `mach_absolute_time() - snapshot_cntvct`, so the guest's
virtual counter resumes where it left off and the armed comparator fires
promptly. With timekeeping continuous, the rehydrated guest boots on into real
systemd userspace.

## Idle and stop

When the guest executes `WFI`/`WFE`, HVF returns the exit to the host rather
than blocking in-kernel. The backend implements the idle by parking the vCPU
thread on a wake fd (`kick`) with a bounded poll, so an interrupt asserted from
another thread wakes it promptly and a missed kick can never wedge it.

A guest that is *busy* (a CPU-bound spin with no traps) never returns from
`hv_vcpu_run` on its own. To stop such a guest from another thread,
`Vcpu::exit_signal` returns a thread-safe handle that calls `hv_vcpus_exit`;
the interrupted run returns `HV_EXIT_REASON_CANCELED`, which the run loop treats
as a benign exit. This is what makes the daemon's `ctl stop` reliable.

## Devices

`hypervisor/src/hvf/devices.rs` provides an `MmioBus` (implementing the
backend's `VmOps` MMIO hooks) and a faithful `Pl011` UART at `0x0900_0000` —
the base Cloud Hypervisor's `arm64` machine uses. The bus is the seam every
future device plugs into. Today that is the serial console; Phase 3 adds the
virtio devices (block/net/console over PCI) a guest needs to run open-endedly.

## `chm` and `chm serve`

`chm/` is the standalone executable.

- `chm run <dir>` loads a snapshot, wires the PL011, rehydrates, and runs vCPU0,
  streaming the serial console to stdout.
- `chm serve <library>` is a daemon: it hosts a directory of snapshots behind a
  Unix socket, runs one guest at a time on a worker thread, buffers its console
  into a capped ring, and serves `list` / `start` / `console` / `status` /
  `stop` / `shutdown` to `chm ctl` clients. It is the control plane a desktop
  GUI will drive.

The Hypervisor.framework dependency is target-gated to
`cfg(all(target_os = "macos", target_arch = "aarch64"))`, so the crate still
compiles to a small stub on a Linux workspace build.

## What works, and what does not (yet)

Works, hardware-verified on Apple Silicon: VM creation, RAM mapping, vCPU
register restore, KVM→HVF translation, managed GICv3 with SPI/PPI delivery,
virtual-timer continuity, WFI idle with cross-thread wakeup, end-to-end
rehydration of a real cloud snapshot booting into systemd userspace, the
standalone `chm` binary, and the `chm serve` daemon with forced stop.

Not yet: the virtio device model over PCI (so a resumed guest currently goes
quiet at the first unmodelled device), host I/O on `kqueue`, SMP secondary-core
bring-up (`PSCI CPU_ON`), and the desktop GUI. These are the next milestones.
