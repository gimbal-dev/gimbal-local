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

> **Status: real, and honestly bounded.** Captured `arm64` KVM snapshots
> rehydrate onto HVF, run multi-vCPU Linux guests, service native virtio
> block/rng/net, and expose an interactive serial console. Stock ITS/LPI-routed
> snapshots remain blocked by Apple's managed-GIC limits; supported captures use
> GICv2M/message-SPIs. There are no stubbed VMs or fake consoles here —
> everything streamed above is the guest actually executing.

---

## Requirements

- Apple Silicon Mac (`macOS`, `aarch64`).
- A Rust toolchain (edition 2024; Rust 1.89.0 or later — see the
  `package.rust-version` in `Cargo.toml`).
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
"$BIN" ctl list --json          # machine-readable library state for an app
"$BIN" ctl start <name>         # resume one
"$BIN" ctl console              # stream its live console
"$BIN" ctl status               # running / stopped + console bytes
"$BIN" ctl status --json        # machine-readable VM state for an app
"$BIN" ctl stop                 # stop the guest (forced, ~instant)
"$BIN" ctl shutdown             # stop + exit the daemon
```

One guest runs at a time (HVF is one-VM-per-process today). This daemon is the
foundation for a Docker-Desktop-style GUI — see the roadmap.

## Run the desktop app (`Gimbal Local`)

M23 adds a native macOS SwiftUI app over the daemon: **Gimbal Local**. It is a
Docker Desktop-style dashboard for local sandboxes, with an optional
`gimbal-cloud-control` status panel.

```sh
# Build the signed chm binary and a clickable app bundle.
APP=$(./scripts/build-gimbal-local-app.sh)
open "$APP"
```

The app can start/shutdown `chm serve`, list snapshots, start/stop a selected
sandbox, attach to the serial console, show daemon state, and display control
plane health/count/cost signals when `gctl server` is running. Source and app
notes live in [`app/GimbalLocal/`](app/GimbalLocal/).

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
| M10–M20 | Native virtio block/rng/net, interactive serial console, bidirectional net, and multi-vCPU snapshot resume. |
| R3 | PSCI `CPU_ON` path hardware-proven; HVF SPI affinity routing remains unsupported, so message-SPI delivery deliberately uses the proven 1-of-N route. |
| M23 | **Gimbal Local** native macOS app: local sandbox dashboard, daemon controls, console view, and optional gimbal-cloud-control health/cost panel. |

Next:

- **Remote capture validation:** blocked on real arm64 KVM capacity. Raspberry
  Pi/OCI options were checked; AWS bare-metal quota is the current route back.
- **BYO-subscription loop:** first local-managed AWS helper commands are now
  available: `init`, `preflight`, `capture`, `pull`, `push`, and `cleanup`.
  They let the Mac manage a user's AWS profile, S3 handoff bucket, and existing
  SSH capture host without a hosted control plane.
- **Desktop app:** native SwiftUI shell is stood up in `app/GimbalLocal`, backed
  by `chm serve` / `chm ctl` plus the optional `gimbal-cloud-control` API.
- **Create from container image:** future app action that accepts an OCI/Docker
  image reference, hides the pull/rootfs/disk/capture process, produces an
  HVF-compatible snapshot in the local library, and then starts it like any
  other sandbox.

AWS setup notes for the later cloud round-trip live in
[`docs/aws-byo-setup.md`](docs/aws-byo-setup.md).

## Relationship to upstream Cloud Hypervisor

This repository is a fork and is **not** tracking upstream for merge-back; it is
its own project focused on the macOS local runtime.

The macOS product is small and self-contained: `chm` depends only on the
`hypervisor` crate (built with `--features hvf,kvm-snapshot`), which in turn has
**no** local-crate dependencies. None of the upstream VMM crates (`vmm`,
`virtio-devices`, `vhost_*`, `pci`, …) are compiled into `chm` or the app.

Those upstream crates are kept in the tree for one reason: they build the
patched Linux `cloud-hypervisor` binary used to **capture** HVF-compatible
snapshots (the `CH_GIC_V2M` message-SPI patch; see
[`scripts/hvf/`](scripts/hvf/)). If you are here for the macOS port, you only
need `chm/`, `hypervisor/src/hvf/`, and `app/GimbalLocal/`.

## License

Unchanged from upstream: dual-licensed under **Apache-2.0** and
**BSD-3-Clause** (see [`LICENSES/`](LICENSES/)). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution and commit conventions
(including the `Assisted-by:` disclosure trailer used for AI-assisted changes).
