# Gimbal Local

> Rehydrate Cloud Hypervisor cloud snapshots on your Mac.

**Gimbal Local** is a macOS (Apple Silicon) runtime that brings the `arm64`
guests of [Cloud Hypervisor](https://www.cloudhypervisor.org/) to Apple's
**Hypervisor.framework (HVF)**. Take a snapshot of a running cloud VM (captured
on a Linux/KVM host with `ch-remote snapshot`) and **resume it on your Mac** —
same guest RAM, vCPU state, GIC, and virtual timer — then watch it boot on into
userspace.

Under the hood it is a single, standalone, code-signed engine CLI — **`chm`** —
built as a macOS-focused fork of Cloud Hypervisor, with a native SwiftUI desktop
app (**Gimbal Local**) on top. `chm run` prints the engine banner shown below.

```console
$ chm run /path/to/ch-snapshot
chm — Gimbal Local (Cloud Hypervisor on Apple Silicon)
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
> block/rng/net, and expose an interactive serial console. The default
> **A vanilla upstream ITS/LPI-routed snapshot — the kind Apple's managed GIC
> cannot run at all — boots to an interactive shell with no flags**: `chm` routes
> it onto a userspace GICv3 automatically, from both `chm run` and `chm serve`.
> The legacy managed-GIC path still takes GICv2M/message-SPI captures. See
> [`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md).
> There are no stubbed VMs or fake consoles here — everything streamed above is
> the guest actually executing.

---

## Install

> **This repository is private, so the download needs access to it.** A browser
> or a plain `curl` gets a 9-byte file containing `Not Found`, not a build. If
> you can read this page you almost certainly have that access — use the `gh`
> command below rather than clicking through, because an unauthenticated fetch
> fails in a way that looks like a corrupt download.

Download the latest `GimbalLocal-<version>.zip` from
[Releases](https://github.com/gimbal-dev/gimbal-local/releases), unzip it,
and drag **Gimbal Local** to `/Applications`. The app is signed with a
Developer ID certificate and notarized by Apple, so it opens without a
Gatekeeper warning.

```sh
gh release download --repo gimbal-dev/gimbal-local --pattern '*.zip'
unzip GimbalLocal-*.zip
mv GimbalLocal.app /Applications/
```

(Finder shows it as **Gimbal Local**; the bundle on disk is `GimbalLocal.app`.)

**What you need**

- An Apple Silicon Mac (M1 or later).
- macOS 14 or newer.
- Read access to this repository, until the release is published somewhere
  public.

**What you do not need** — worth stating plainly, because every comparable tool
asks for at least one of them:

- No Linux host and no KVM machine. The Mac is the hypervisor.
- No control plane, no account, no network connection. Everything is local.
- No Rust toolchain, no Xcode, no source checkout. `chm` ships inside the app.

To use the engine from a terminal, it is inside the bundle:

```sh
/Applications/GimbalLocal.app/Contents/MacOS/chm --help
```

Snapshots live in `~/gimbal-snapshots` and cold-boot images in
`~/gimbal-images`; the app creates both on first launch. You need a Cloud
Hypervisor **`arm64` snapshot** (`state.json` + `snapshot/memory-ranges`, from
`ch-remote … snapshot` on a Linux host) to rehydrate — or nothing at all to
cold-boot a stock kernel.

## Requirements (building from source)

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
| M25 | Live local lifecycle: suspend/resume live checkpoints, per-revision disk overlays, fork, and a durable single-slot session registry. |
| M26/M27 | Faithful cloud rehydration through the control-plane runner; branchable image/checkpoint/sandbox lineage (`chm push`/`pull`/`revisions`/`rollback`). |
| M28 | Consistent sandbox controls: userspace-NAT egress firewall (default-deny allow-list, `chm firewall`) enforced locally at DNS resolve + TCP connect. |
| M29 | Durable per-sandbox audit trail (`audit.jsonl`: session start/stop, denied egress, bundle-verify), readable via `chm audit show`. |
| M30 | Security hardening for untrusted snapshots + hostile guest agents: bundle/overlay confinement, daemon socket auth, no host-FS passthrough, resource + NAT limits, per-NIC fail-closed egress, CAS digest hardening, and Ed25519 signed-manifest verification. See [`docs/security-model.md`](docs/security-model.md). |
| M31 | Network host-isolation: a reserved-address guard blocks the guest from reaching host loopback / private LAN / link-local metadata (`169.254.169.254`) regardless of policy (closing DNS rebinding), and new sandboxes default to firewall-on default-deny. |
| M-USGIC | **Userspace GICv3:** a vanilla upstream ITS/LPI-routed snapshot — the kind Apple's managed GIC can't run — rehydrates onto a software GICv3 (distributor/redistributor + trapped CPU interface delivering SPIs/PPIs/SGIs/**LPIs**, live ITS, self-managed vtimer) and boots to an interactive Ubuntu shell. Both `chm run` and `chm serve` route such a capture there **automatically, with no flag**. Multi-vCPU, virtio disk/net and checkpoint/resume all work on this path. See [`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md). |

Next:

- **Living Workspaces:** bake a Git-transparent, content-addressed workspace
  plane into Gimbal Local + Cloud so source, untracked work, and safely
  classified build artifacts fork and rehydrate with the VM, without changing
  vanilla Cloud Hypervisor snapshots. See
  [`docs/living-workspaces.md`](docs/living-workspaces.md).
- **Snapshot signing trust root (M30.4):** `chm` verifies Ed25519-signed
  manifests today; the remaining half is the control plane producing + signing
  production manifests (cross-repo with `gimbal-cloud-control`).
- **Live in-guest firewall demo:** enforcement ships; the end-to-end demo is
  blocked only on a net-enabled capture snapshot.
- **Remote capture validation:** needs real arm64 KVM capacity (a Lima
  nested-KVM guest, or AWS Graviton bare metal); the Mac only *runs* snapshots.
- **BYO-subscription loop:** local-managed AWS helpers (`init`, `preflight`,
  `capture`, `pull`, `push`, `cleanup`) let the Mac drive a user's AWS profile,
  S3 handoff bucket, and SSH capture host without a hosted control plane.
- **Create from container image:** a future app action that accepts an OCI/Docker
  image reference, hides the pull/rootfs/disk/capture process, and produces an
  HVF-compatible snapshot in the local library.

AWS setup notes for the later cloud round-trip live in
[`docs/aws-byo-setup.md`](docs/aws-byo-setup.md).

## Reports

| Date | Report | Summary |
| --- | --- | --- |
| 2026-07-30 | [Snapshot portability and security audit](reports/snapshot-portability-security/) | Three Graviton captures resume live, but secure coding-agent readiness is blocked by provenance, image, networking, and CI gaps |

## Relationship to upstream Cloud Hypervisor

This repository is a fork and is **not** tracking upstream for merge-back; it is
its own project focused on the macOS local runtime.

The macOS product is small and self-contained: `chm` depends only on the
`hypervisor` crate (built with `--features hvf,kvm-snapshot`), which in turn has
**no** local-crate dependencies. None of the upstream VMM crates (`vmm`,
`virtio-devices`, `vhost_*`, `pci`, …) are compiled into `chm` or the app.

Those upstream crates are kept in the tree for one reason: they build the
patched Linux `cloud-hypervisor` binary used to capture **legacy** GICv2M
snapshots (the `CH_GIC_V2M` message-SPI patch; see
[`scripts/hvf/`](scripts/hvf/)). Note that the recommended capture shape is now
**vanilla** — stock upstream, no fork — which needs none of them; see
[`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md). If you
are here for the macOS port, you only need `chm/`, `hypervisor/src/hvf/`, and
`app/GimbalLocal/`.

## License

Unchanged from upstream: dual-licensed under **Apache-2.0** and
**BSD-3-Clause** (see [`LICENSES/`](LICENSES/)). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution and commit conventions
(including the `Assisted-by:` disclosure trailer used for AI-assisted changes).
