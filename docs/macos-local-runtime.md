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
thread on a wake fd (`kick`), so an interrupt asserted from another thread wakes
it promptly and a missed kick can never wedge it.

The park duration is the guest's own virtual-timer deadline, not a flat poll.
While a vCPU is parked it sits *outside* `hv_vcpu_run`, so HVF's native
virtual-timer delivery is suspended and the guest can only take its next
scheduler tick when the host re-enters the guest. Parking a flat interval would
therefore clamp an idle guest's effective tick rate to the poll rate — starving
idle-heavy phases (cloud-init's final stage, a `serial-getty` restart) so they
crawl or look wedged. Instead the backend reads `CNTV_CVAL_EL0`/`CNTV_CTL_EL0`,
converts the remaining ticks to milliseconds via `mach_timebase_info`, and wakes
exactly when the timer is due; re-entering `hv_vcpu_run` at that point lets the
managed GIC deliver PPI 27 on time. A disabled/masked timer falls back to a
100 ms cap (only a device IRQ, which also kicks the wake fd, can wake it).

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

The PL011 presents a live virtual carrier: its flag register ties the
modem-status lines (DCD/DSR/CTS) high. A guest `agetty` that opens `ttyAMA0`
without `CLOCAL` blocks in `open()` until Data Carrier Detect is seen, so a
resumed snapshot whose cloud-init restarts `serial-getty@ttyAMA0` needs the
carrier asserted or the reopened getty hangs before printing its login prompt.

## `chm` and `chm serve`

`chm/` is the standalone executable.

- `chm run <dir>` loads a snapshot, wires the PL011 and native virtio devices,
  rehydrates, and runs the snapshot's vCPUs, streaming the serial console to
  stdout.
- `chm serve <library>` is a daemon: it hosts a directory of snapshots behind a
  Unix socket, runs one guest at a time on a worker thread, buffers its console
  into a capped ring, and serves `list` / `start` / `console` / `status` /
  `stop` / `shutdown` to `chm ctl` clients. It also exposes
  `chm ctl list --json` and `chm ctl status --json`, which are the first
  machine-readable app-facing state surfaces for a desktop shell.
- `chm cloud <command> aws` is the local-managed BYO AWS loop. `init` persists
  profile/region/bucket defaults locally, `preflight` checks identity/quota/
  bucket safety, `capture` can run an SSH capture command then rsync/import the
  snapshot and upload it to S3, `pull` retrieves a snapshot bundle, `push`
  uploads return artifacts, and `cleanup` wraps the tag-scoped destructive
  cleanup script.

## chm runner: driving snapshots through the control plane

`chm runner` makes `chm` a *runner* for a `gimbal-cloud-control` (`gctl`)
control plane instead of a one-off local launcher. The plane is the source of
truth for leases, cost, cleanup, snapshot provenance, the `gic_mode` gate, and
audit; `chm` never sources a snapshot out of band, never overrides the gate, and
never owns cloud lifecycle.

- `chm runner register` announces this Mac to the plane: `POST /runners` with
  `arch: arm64`, the chm version, and an honest capabilities object
  (`supports_gic_v2m`, `supports_resume`).
- `chm runner run <snapshot-id>` performs the full runner protocol against the
  plane: register → create a sandbox → `assign-run` → pull the assigned bundle
  from its `download_uri` → **verify the bytes against `manifest.checksum_tree`**
  → `mark-local-copy {verified:true}` → report `running-local` → execute the
  plane's `chm_command` (branching on `kind`: `cold` → `chm run`, `resume` →
  `chm resume`) → report `stopped` or `error` → idempotent `push-artifacts`. A
  background thread heartbeats well within the plane's 90s window.
- The API base is `GCTL_API` (default `http://127.0.0.1:8080`), overridable with
  `--api`; `--owner` sets the sandbox owner; `--sandbox <id>` continues an
  existing plane sandbox (the cross-substrate resume path); `--skip-run`
  exercises the protocol through `mark-local-copy` without executing.

**Content-addressed cache.** The bundle is materialized into a per-snapshot cache
whose files are stored in a shared content-addressed store (`.cas`, keyed by
sha256) and hard-linked in. A base layer shared across snapshots — e.g. a
checkpoint and its parent's multi-GiB disk, or the two identical `state.json`
copies inside one bundle — is fetched, verified, and stored **once**; a repeat
pull is served entirely from the CAS (no re-copy). The `download_uri` may be a
local `file://` object store (a copy) or a networked `http(s)://` one (streamed
via curl, with an optional bearer token); each object is fetched from
`<download_uri>/<relpath>` and verified before it enters the CAS.

**Cross-substrate resume.** A checkpoint whose `manifest.origin_substrate` is
`linux-kvm` (it ran on a cloud runner) resumes here on `apple-hvf`: the runner
advertises `capabilities.substrate = "apple-hvf"`, re-verifies the `gic_mode`
gate locally (only `gicv2m-message-spi` is HVF-restorable), reads the mid-flight
marker (`gimbal-marker.json` / `GIMBLMK1` frame) to prove continuity, and
`chm resume`s past the point the cloud session reached.

**Hard rule — the `gic_mode` gate.** If `assign-run` returns HTTP 422, `chm`
surfaces the plane's refusal and stops. It never retries as-is and never
self-declares a rejected snapshot runnable.

The runner re-verifies the mode locally too (defence in depth), and accepts
**both** proven shapes: `gicv2m-message-spi` (managed GIC) and `its-lpi` — the
vanilla, stock-upstream shape, which restores on the userspace GICv3. For an
`its-lpi` assignment the runner sets `CHM_USERSPACE_GIC=1` on the `chm`
subprocess so the software GIC path is selected. Note the plane's own gate may
still be stricter than this; that mismatch is tracked as V3.1 in
[`roadmap.md`](roadmap.md).

The client is a thin `curl` + `serde_json` wrapper (matching `chm cloud`'s
shell-out-to-`aws`/`ssh` convention) rather than a heavyweight async HTTP stack,
so it stays dependency-light and easy to audit. See the normative contract in
`gimbal-cloud-control:docs/runner-contract.md`.



`app/GimbalLocal` is the M23 native macOS app. It deliberately stays outside the
Rust runtime and treats `chm` as the local worker contract:

- launches `chm serve <library> --socket <path>`;
- reads local state with `chm ctl list --json` and `chm ctl status --json`;
- starts/stops selected snapshots through `chm ctl start/stop`;
- attaches to the live serial console through `chm ctl console`;
- optionally points at `gimbal-cloud-control` and reads `/healthz`, `/runners`,
  `/snapshots`, `/sandboxes`, and `/cost/running`.

That makes the split explicit: the desktop app manages local sandboxes and
reports control-plane readiness, while `gimbal-cloud-control` remains the source
of truth for leases, resources, artifacts, cleanup, and audit once the hosted
path is enabled.

The Hypervisor.framework dependency is target-gated to
`cfg(all(target_os = "macos", target_arch = "aarch64"))`, so the crate still
compiles to a small stub on a Linux workspace build.

## What works, and what does not (yet)

Works, hardware-verified on Apple Silicon: VM creation, RAM mapping, vCPU
register restore, KVM→HVF translation, managed GICv3 with SPI/PPI delivery,
virtual-timer continuity, WFI idle with cross-thread wakeup, end-to-end
rehydration of a real cloud snapshot booting into systemd userspace, native
virtio block/rng/net, interactive serial console, multi-vCPU snapshot resume,
the PSCI `CPU_ON` path for parked secondaries, the standalone `chm` binary, and
the `chm serve` daemon with forced stop.

Still bounded: stock arm64 cloud snapshots that route virtio completions through
ITS/LPIs cannot be delivered by Apple's managed GIC; use GICv2M/message-SPI
captures. HVF also accepts affinity-routed message SPIs but leaves them pending
instead of forwarding them, so `chm` intentionally re-routes message SPIs as
1-of-N before delivery. Remote capture validation is currently blocked on real
arm64 KVM capacity: AWS bare-metal quota is pending, OCI Ampere capacity is not
available in the tested region, and the available Raspberry Pi hardware is not
strong enough. The local-managed BYO cloud loop is now scriptable through
`chm cloud init/preflight/capture/pull/push/cleanup aws`, and the desktop shell
can manage local sandboxes through `chm serve`; the remote proof still waits for
real arm64 KVM capacity. See [`aws-byo-setup.md`](aws-byo-setup.md).

Future UX: "Create from container image" should be a hidden snapshot factory,
not direct container execution. The user enters an OCI image reference; Gimbal
pulls/unpacks it, builds a bootable arm64 sandbox disk or initramfs, boots it on
a KVM-capable capture host, captures an HVF-compatible GICv2M/message-SPI
snapshot, imports that into the local library, and starts it through the same
`chm serve` path. The app should hide those mechanics unless the user opens
details.
