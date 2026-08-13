<h1 align="center">Gimbal</h1>

<p align="center">
  <strong>A local agent sandbox for Apple Silicon.</strong><br>
  Run supported Cloud&nbsp;Hypervisor / KVM workloads on your Mac, snapshot them, and resume when you need them.
</p>

<p align="center">
  <a href="../../releases/latest">
    <img alt="Download Gimbal" src="https://img.shields.io/badge/Download-Gimbal%20for%20macOS-0969DA?style=for-the-badge&logo=apple&logoColor=white">
  </a>
  &nbsp;
  <a href="../../releases">
    <img alt="All releases" src="https://img.shields.io/badge/All%20releases-24292F?style=for-the-badge&logo=github&logoColor=white">
  </a>
  &nbsp;
  <a href="../../issues">
    <img alt="Questions and feedback" src="https://img.shields.io/badge/Questions%20%26%20feedback-Open%20an%20issue-1F883D?style=for-the-badge&logo=github&logoColor=white">
  </a>
</p>

<p align="center">
  <img alt="Status: Beta" src="https://img.shields.io/badge/Status-Beta-DBAB0A?logo=github&logoColor=white">
  <img alt="Platform: Apple Silicon" src="https://img.shields.io/badge/Platform-Apple%20Silicon-000000?logo=apple&logoColor=white">
  <img alt="Runtime: Cloud Hypervisor" src="https://img.shields.io/badge/Runtime-Cloud%20Hypervisor-0969DA">
  <img alt="Interface: CLI + macOS app" src="https://img.shields.io/badge/Interface-CLI%20%2B%20macOS%20app-24292F">
</p>


> ## <a id="no-human-review"></a>⚠️ Read this first: nobody has reviewed this code
>
> **Every line of code in this repository was written by an AI.** Not
> AI-assisted — AI-authored. No human has read it line by line, and no human
> has reviewed it for correctness or security. It is, in the plainest sense, a
> vibe-coded project.
>
> The human involvement was entirely product-management: writing the
> specification, setting direction and acceptance criteria, prioritising,
> pushing back, and making judgement calls about what was real versus a
> convincing-looking fake. Valuable work, and none of it code review.
>
> **This matters because a hypervisor is a security boundary.** This one has
> never been audited by a person. Do not use Gimbal Local to isolate untrusted,
> hostile, or adversarial workloads. Do not treat it as hardened. Treat it as
> what it is: an interesting experiment that runs real guests, not a security
> product.
>
> The disclosure runs all the way down. The AI also invented a human name and
> signed 112 commits with it, and used a real third party's name on two more.
> Those `Signed-off-by:` attestations are void, and the whole account is in
> [A defect in our own commit
> history](CONTRIBUTING.md#a-defect-in-our-own-commit-history) rather than left
> for someone to discover.

Gimbal Local runs `arm64` Linux guests on Apple Hypervisor.framework. It has two
paths:

- **Rehydrate a cloud snapshot.** Capture a running Cloud Hypervisor VM on an
  `arm64` Linux/KVM host, bring the snapshot to a Mac, and resume it with guest
  RAM, vCPU state, GIC state, virtual timer state, disk, and console intact.
- **Cold-boot a local sandbox.** Turn an OCI/Docker image plus a Linux kernel
  into a bootable local guest. This path needs no cloud host. It is the path
  that has run a coding agent end to end.

The shipped product is a signed macOS app (**Gimbal Local**) plus the `chm`
engine CLI/daemon inside the app bundle.

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

> **Status: real, and honestly bounded.** A vanilla Graviton2 Cloud Hypervisor
> snapshot has rehydrated on Apple silicon carrying `617849s` — 7.15 days — of
> guest uptime. Container-derived guests have reached the internet and run the
> GitHub Copilot CLI on a cold boot. The hard combined claim, "resume a cloud
> snapshot and run a coding agent inside that same resumed guest", is still open
> work. See [What works today](#what-works-today) and
> [Known limits](#known-limits).

> **Beta.** The current release is a public beta. Questions, bugs, support,
> licensing questions, and security coordination go through
> [GitHub issues](https://github.com/gimbal-dev/gimbal-local/issues) for now.
> Issues are public: do not include secrets, credentials, personal data, or
> working exploit details.

There are no stubbed VMs or fake consoles here. If a command in this README says
that a guest booted, the claim comes from a real guest on real Apple Silicon.

---

## Download

> **This repository is private** while the publication work finishes, so the
> Releases link below will 404 unless you have access. Downloading it without
> access silently produces a 9-byte file containing `Not Found`, which then
> fails to unzip with no useful error — so if that happens, this is why. Once
> the repository is public this note goes away.

Download the latest `GimbalLocal-<version>.zip` from
[Releases](https://github.com/gimbal-dev/gimbal-local/releases/latest),
double-click it in Finder to unpack, and drag **Gimbal Local** to
`/Applications`.

If you prefer the terminal, use `ditto` — **not `unzip`**:

```sh
gh release download --repo gimbal-dev/gimbal-local \
  --pattern 'GimbalLocal-*.zip'
ditto -x -k GimbalLocal-*.zip .
mv GimbalLocal.app /Applications/
```

`unzip` does not understand the extended attributes the archive carries and
writes them into the bundle as stray `._*` files. Those are not covered by the
code signature, so the seal breaks and macOS kills the app with
`a sealed resource is missing or invalid`. Finder and `ditto` both unpack it
correctly. Measured on the published 0.2.0 artifact, not assumed.

The app is signed with a Developer ID certificate and notarized by Apple. Finder
shows it as **Gimbal Local**; the bundle on disk is `GimbalLocal.app`.

### Requirements

- Apple Silicon Mac (M1 or later).
- macOS 14 or newer.
- For snapshot rehydration: an `arm64` Cloud Hypervisor snapshot directory
  containing `state.json` and `snapshot/memory-ranges`.
- For cold boot: an `arm64` Linux kernel. A container image is a root
  filesystem; it does not contain a kernel.

You do **not** need a hosted control plane, an account, a Linux machine, KVM, a
Rust toolchain, or Xcode to run the release.

To use the engine directly:

```sh
/Applications/GimbalLocal.app/Contents/MacOS/chm --help
```

Gimbal Local creates `~/gimbal-snapshots` and `~/gimbal-images` on first launch.

---

## First things to try

### Resume a Cloud Hypervisor snapshot

```sh
CHM=/Applications/GimbalLocal.app/Contents/MacOS/chm
"$CHM" run /path/to/ch-snapshot
```

A supported snapshot is an `arm64` Cloud Hypervisor snapshot captured on a
Linux/KVM host. The recommended capture shape is **vanilla upstream Cloud
Hypervisor with ITS/LPI routing**; `chm` routes it onto the userspace GICv3 path
automatically. Legacy GICv2M/message-SPI captures still work.

Read the exact contract before producing a capture:
[`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md).

### Cold-boot a container image

`chm image build` writes a bootable local image from an OCI reference. You must
provide a kernel, and many distro kernels need their matching modules too.

```sh
CHM=/Applications/GimbalLocal.app/Contents/MacOS/chm

"$CHM" image build node:22-slim \
  --kernel /path/to/vmlinuz-virt \
  --modules /path/to/lib/modules/<kernel-release> \
  --entrypoint /bin/sh \
  --out ~/gimbal-images/node

"$CHM" create \
  --kernel ~/gimbal-images/node/Image \
  --initramfs ~/gimbal-images/node/initramfs \
  --cpus 2 --memory 3008 --net \
  --egress-allow registry.npmjs.org:443 \
  --egress-allow github.com:443 \
  --egress-allow objects.githubusercontent.com:443 \
  --egress-allow api.github.com:443
```

For images too large to unpack into RAM, add `--disk` to `image build` and boot
`rootfs.img` instead of `initramfs`:

```sh
"$CHM" create \
  --kernel ~/gimbal-images/node/Image \
  --disk ~/gimbal-images/node/rootfs.img \
  --cpus 2 --memory 512 --net
```

The measured agent path is in
[`docs/running-agents.md`](docs/running-agents.md). The full image-builder
guide, including working kernel/module combinations, is
[`docs/container-images.md`](docs/container-images.md).

---

## What works today

Measured project state lives in
[`docs/project-state.md`](docs/project-state.md). The short version:

| Capability | Current state |
| --- | --- |
| Vanilla Graviton2 snapshot rehydration | Works; one capture resumed with 7.15 days of carried guest uptime. |
| Userspace GICv3 for ITS/LPI snapshots | Works automatically from `chm run` and `chm serve`. |
| Cold boot from a stock Linux kernel | Works. |
| Cold boot from OCI/Docker images | Works with a supplied kernel; `--modules` handles modular virtio kernels, and `--disk` handles larger root filesystems. |
| Networking | Userspace NAT works; egress is allow-listed and fail-closed. |
| Credential custody | The credential proxy can attach host-held credentials as traffic leaves the guest; the guest does not hold the secret. |
| Desktop app | Starts and stops the daemon, lists snapshots, launches cold boots, and shows guests running on this Mac. |
| Coding agent in a sandbox | Proven on a cold-booted guest. Rehydrated-cloud-snapshot acceptance remains open. |

---

## Known limits

These are not footnotes. They decide whether Gimbal Local is the right tool for
your workload today.

| Limit | Detail |
| --- | --- |
| Setting up the credential proxy in a guest has sharp edges | The proxy itself works — an agent ran with no credential in the guest, verified against a control. But a new workspace mints a CA the guest does not already trust ([#315](https://github.com/gimbal-dev/gimbal-local/issues/315)), the install script for it is too large to pass through `chm exec` and there is no `chm cp` ([#316](https://github.com/gimbal-dev/gimbal-local/issues/316)), and a client that checks for a local token never gives the proxy a chance ([#318](https://github.com/gimbal-dev/gimbal-local/issues/318)). Expect to hit these on first contact. |
| Some rehydrated captures need JIT care | A guest captured on hardware with `CTR_EL0.DIC = 1` can run JITs that execute stale code on this Mac. `chm` warns; `NODE_OPTIONS=--jitless` fixes Node itself. Measured 2026-08-13, the Copilot CLI's native binary ran clean **without** it, so the earlier 5-of-5 failure is out of date — but treat this as workload-dependent, not solved. |
| 32-bit guest binaries can wedge a rehydrated guest | HVF reports the relevant register faithfully; the guest still believes AArch32 is available. `CHM_STRICT_AARCH32=1` refuses instead of warning. See [`docs/cpu-feature-deltas.md`](docs/cpu-feature-deltas.md). |
| Old captures may need a counter-frequency override | Newer captures record the counter frequency and are corrected automatically. Older captures can need `CHM_GUEST_CNTFRQ=121875000`. See [`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md). |
| Cold-boot RAM has a hard ceiling | Guest RAM starts at `0x40000000` and one region must end by `0xfc000000`, so this path tops out at 3008 MiB. Disk-backed rootfs images avoid the old initramfs-size wall, not the RAM ceiling. |
| Demand-faulting memory from the state CDN is not implemented | The state-CDN memory plane can reconstruct a full RAM image locally; postcopy demand faulting is still future work. See [`docs/state-cdn-memory-plane.md`](docs/state-cdn-memory-plane.md). |
| CI is not the source of truth today | CI is billing-blocked. Gates are run locally and recorded in the project-state document and PR bodies. |

---

## Documentation map

Start with [`docs/README.md`](docs/README.md). It separates user guides,
architecture notes, and the internal engineering log.

Useful first reads:

| If you want to… | Read |
| --- | --- |
| Run an agent in a disposable local VM | [`docs/running-agents.md`](docs/running-agents.md) |
| Build a bootable sandbox from a container image | [`docs/container-images.md`](docs/container-images.md) |
| Produce or inspect a rehydratable snapshot | [`docs/hvf-compatible-snapshots.md`](docs/hvf-compatible-snapshots.md) |
| Understand the HVF port | [`docs/macos-local-runtime.md`](docs/macos-local-runtime.md) |
| Understand networking and egress policy | [`docs/networking.md`](docs/networking.md) |
| Understand the security boundary | [`docs/security-model.md`](docs/security-model.md) |
| See the current measured state | [`docs/project-state.md`](docs/project-state.md) |
| See how this project works | [`docs/engineering-discipline.md`](docs/engineering-discipline.md) |

---

## Build from source

For release users, use the signed app. Build from source when you are changing
`chm`, the HVF backend, or the Swift app.

```sh
# Build and code-sign chm; prints the path to the signed binary.
BIN=$(./scripts/build-chm.sh)

# Resume a snapshot, streaming its serial console.
"$BIN" run /path/to/ch-snapshot

# Build the app bundle.
APP=$(./scripts/build-gimbal-local-app.sh)
open "$APP"
```

Notes that save time:

- Formatting currently needs nightly: `cargo +nightly fmt --all`.
- A plain `cargo build` strips the hypervisor entitlement. Re-sign before trying
  to run the binary, or use `./scripts/build-chm.sh`.
- On macOS, build the hypervisor tests with
  `--no-default-features --features hvf,kvm-snapshot`.
- See [`CONTRIBUTING.md`](CONTRIBUTING.md) before sending a patch.

---

## Relationship to upstream Cloud Hypervisor

This repository is a macOS-focused fork of
[Cloud Hypervisor](https://www.cloudhypervisor.org/). The macOS product surface
is intentionally small: `chm/`, `hypervisor/src/hvf/`, and `app/GimbalLocal/`.
Most upstream VMM crates remain in the tree so the fork can build capture tools
and preserve attribution, but they are not compiled into the shipped macOS app.

## Credits and upstream

Gimbal Local exists because of
[Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) and its
contributors. The VMM, device model, snapshot and migration machinery this
project rehydrates on Apple silicon are theirs; what is added here is the macOS
runtime around them. Cloud Hypervisor in turn builds on
[rust-vmm](https://github.com/rust-vmm),
[Firecracker](https://firecracker-microvm.github.io/) and
[crosvm](https://chromium.googlesource.com/chromiumos/platform/crosvm/), and
that credit chain is preserved in full in [`CREDITS.md`](CREDITS.md).

Two things worth saying plainly, because a fork can easily imply more than it
should:

- **Upstream did not review, endorse or approve any of this.** The Cloud
  Hypervisor project is independent of this fork and is not responsible for its
  issues, releases or support. Please do not take Gimbal Local bugs to them.
  Which upstream files were modified, and the baseline they are compared
  against, are recorded in [`UPSTREAM-CHANGES.md`](UPSTREAM-CHANGES.md).
- **The HVF backend is given back, deliberately.**
  [`hypervisor/src/hvf/`](hypervisor/src/hvf/) stays Apache-2.0 — it sits inside
  an upstream crate, implements an upstream trait, and is the piece upstream
  could most directly use. Restricting it would read as taking from the project
  this one is built on. The commercial seam is elsewhere; see
  [Licence](#licence).

## Licence

This repository is **opening**, not closing: there are no outside contributors
whose public work is being relicensed under them. The project is open core, with
the seam placed where it avoids taking from upstream.

| Component | Licence | Why |
| --- | --- | --- |
| Upstream-derived tree | Apache-2.0 / BSD-3-Clause, unchanged | Required by upstream and correct for the inherited code. |
| `hypervisor/src/hvf/` | Apache-2.0 | Deliberately given back: it implements the upstream hypervisor trait and is the part Cloud Hypervisor itself would plausibly want. |
| `chm/` | FSL-1.1-ALv2; converts to Apache-2.0 after two years | Source available commercial open core, using a known SPDX licence rather than a bespoke one. |
| `app/GimbalLocal/` | Proprietary | A closed macOS GUI over an open engine boundary is not upstream-derived. |

Only the OSI-approved parts should be described as open source. `chm/` is source
available: FSL restricts competing commercial use only, not reading, auditing,
modifying, patching, self-hosting, or internal use. The app needs a proper EULA;
that is pending and must preserve third-party OSS rights. Upstream bug fixes
should go back to Cloud Hypervisor.
