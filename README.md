# Cloud Hypervisor for macOS

> Rehydrate Cloud Hypervisor cloud snapshots on Apple Silicon.

This is a macOS-focused fork of [Cloud Hypervisor](https://www.cloudhypervisor.org/)
that brings the VMM's `arm64` guests to Apple's **Hypervisor.framework (HVF)**.
The goal is a local runtime: take a snapshot of a running cloud VM (captured on
a Linux/KVM host with `ch-remote snapshot`) and **resume it on your Mac** —
same guest RAM, vCPU state, GIC, and virtual timer — then watch it boot on into
userspace.

It ships as a single, standalone, code-signed executable: **`chm`**.

```console
$ chm run /path/to/ch-snapshot
chm — Cloud Hypervisor for macOS (Apple Silicon)
  snapshot:  /path/to/ch-snapshot
  memory:    /path/to/ch-snapshot/snapshot/memory-ranges (1024 MiB)
  vCPUs:     1
  backend:   Apple Hypervisor.framework (managed GICv3)
chm: guest resumed — serial console follows.

         Starting systemd-user-sessions.service - Permit User Sessions...
[  OK  ] Started dbus.service - D-Bus System Message Bus.
[  ...  ] cloud-init[754]: Cloud-init v. 26.1 running 'modules:config' ...
```

> **Status: real, and honestly bounded.** A captured `arm64` KVM snapshot
> rehydrates onto HVF and boots into real Linux userspace (systemd, D-Bus,
> cloud-init). It runs vCPU0 until it needs a device this build does not yet
> model (virtio block/net/console over PCI), then goes quiet. Closing that gap
> is the device-model work tracked below. There are no stubbed VMs or fake
> consoles here — everything streamed above is the guest actually executing.

---

## Requirements

- Apple Silicon Mac (`macOS`, `aarch64`).
- A Rust toolchain (edition 2024; see `rust-toolchain.toml` / `Cargo.toml`).
- The binary must be **code-signed with the `com.apple.security.hypervisor`
  entitlement** before it can create a VM. `scripts/build-chm.sh` does this for
  you.
- A Cloud Hypervisor **`arm64` snapshot directory** (`state.json` +
  `snapshot/memory-ranges`), produced by `ch-remote --api-socket … snapshot`
  on the source host.

## Build & run

```sh
# Build and code-sign chm; prints the path to the signed binary.
BIN=$(./scripts/build-chm.sh)

# Resume a snapshot, streaming its serial console to your terminal.
"$BIN" run /path/to/ch-snapshot

# Or via make:
make chm                     # build + sign
make chm-run DIR=/path/to/ch-snapshot
```

Useful flags: `--max-seconds N` (wall-clock cap), `--idle-exit N` (stop after N
seconds of console silence; default 10, `0` disables), `--quiet`. Run
`chm --help` for the full surface.

## Run it as a service (`chm serve`)

`chm` can also run as a long-lived daemon hosting a **snapshot library** behind
a Unix socket — the control plane a desktop app talks to:

```sh
# Host a library (a ch-snapshot dir, or a directory of them).
"$BIN" serve /path/to/library &

"$BIN" ctl list                 # enumerate snapshots
"$BIN" ctl start <name>         # resume one
"$BIN" ctl console              # stream its live console
"$BIN" ctl status               # running / stopped + console bytes
"$BIN" ctl stop                 # stop the guest (forced, ~instant)
"$BIN" ctl shutdown             # stop + exit the daemon
```

One guest runs at a time (HVF is one-VM-per-process today). This daemon is the
foundation for a Docker-Desktop-style GUI — see the roadmap.

## How it works

`chm` is a thin front end over the in-tree `hypervisor` crate's `hvf` backend.
The hard part — translating a KVM snapshot's CPU/GIC/timer state into HVF and
re-executing it — lives in `hypervisor/src/hvf/`. A full architecture writeup is
in **[`docs/macos-local-runtime.md`](docs/macos-local-runtime.md)**.

| Area            | Where                                   |
| --------------- | --------------------------------------- |
| HVF backend     | `hypervisor/src/hvf/`                   |
| KVM→HVF xlate   | `hypervisor/src/hvf/translate.rs`       |
| Rehydration     | `hypervisor/src/hvf/rehydrate.rs`       |
| Device bus + PL011 | `hypervisor/src/hvf/devices.rs`      |
| `chm` CLI/daemon | `chm/`                                 |

## Roadmap

Milestones completed (all hardware-verified on Apple Silicon):

| Milestone | What landed |
| --------- | ----------- |
| M1–M2 | Real in-tree HVF backend: vCPU, MMIO traps, managed GICv3, interrupt delivery, virtual timer, WFI idle + cross-thread wakeup. |
| M3 | KVM→HVF register translation (the snapshot's `arm64` sys-regs ⇄ HVF). |
| M4 | End-to-end rehydration of a real cloud snapshot. |
| M5 | First real device: PL011 serial console on an MMIO bus. |
| M6 | Virtual-timer continuity — rehydrated guest resumes into userspace. |
| M7 | **`chm`**: standalone, signed, runnable executable. |
| M8 | **`chm serve`**: daemon + control socket; forced stop via `hv_vcpus_exit`. |
| M9 | Repo refocused as a standalone macOS local-runtime project. |

Next:

- **Device model (Phase 3):** virtio block/net/console over PCI so a guest runs
  open-endedly instead of going quiet at the first unmodelled device; host I/O
  on `kqueue` (the macOS analogue of `epoll`/`EventFd`). This is the gating work
  for everything below.
- **SMP:** secondary-core bring-up via PSCI `CPU_ON` (today `chm` resumes vCPU0
  only).
- **Desktop app:** a SwiftUI/menu-bar (or Tauri) shell over `chm serve` —
  library view, Start/Stop, console/terminal — plus lifecycle (graceful PSCI
  shutdown, pause/resume, re-snapshot).

## Relationship to upstream Cloud Hypervisor

This repository is a fork and is **not** tracking upstream for merge-back; it is
its own project focused on the macOS local runtime. The upstream crates
(`vmm`, `virtio-devices`, `vhost_*`, `pci`, …) are kept in the tree because the
`hypervisor` crate depends on them and they are the device-model substrate the
Phase 3 work will draw from.

The original upstream project README — covering the general KVM/MSHV VMM, its
device model, and full documentation under [`docs/`](docs/) — is preserved
verbatim at **[`README.upstream.md`](README.upstream.md)**.

## License

Unchanged from upstream: dual-licensed under **Apache-2.0** and
**BSD-3-Clause** (see [`LICENSES/`](LICENSES/)). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution and commit conventions
(including the `Assisted-by:` disclosure trailer used for AI-assisted changes).
