# Project state

A single honest snapshot of where Gimbal Local actually is. If you are new — or
you are an agent starting a task — read this, then
[`engineering-discipline.md`](engineering-discipline.md), then the domain guide
for the area you are touching.

**Last verified:** 2026-08-07, against `main` at `c78890e61`.

Everything in this document was measured on this machine. Where something is
believed but not measured, it says so.

---

## What this is, in one paragraph

Gimbal Local rehydrates **vanilla** Cloud Hypervisor arm64/KVM snapshots — taken
on real cloud hardware — onto Apple's Hypervisor.framework, so a sandbox that
was running in the cloud can be brought down and resumed on a Mac. It also cold
boots stock Linux kernels with no snapshot in the path, including guests built
from ordinary OCI/Docker images. It ships as a macOS app plus a `chm` CLI and
daemon.

"Vanilla" is load-bearing: we restore snapshots from **stock upstream**
cloud-hypervisor, not from a patched fork. That constraint is what makes the
whole thing useful rather than a demo.

---

## Does it work? Yes, and here is the evidence

The strongest single result: a vanilla Graviton2 KVM snapshot captured on AWS
rehydrates on Apple silicon **carrying `617849s` — 7.15 days — of guest
uptime**. A cold boot cannot fabricate that number. The guest genuinely
continued rather than restarted.

Verified from a **completely clean machine** on 2026-08-06 — every trace of
gimbal wiped, the release installed the way a stranger downloads it, tested
three ways:

| What was tested | Result |
| --- | --- |
| Vanilla Graviton2 snapshot rehydrated | Booted, carrying 7.15 days of prior guest uptime |
| Container image pulled from Docker Hub, cold-booted | Worked on a *different* kernel — proving the two paths share nothing |
| The app cold-booting a guest from its own emitted command | Worked, RTC correct at boot |
| A container-derived guest reaching the internet | `alpine:3.20` → `wget https://registry.npmjs.org/` rc 0; `debian:12-slim` → TCP to `deb.debian.org:443`, both with virtio bundled by `chm image build --modules` |

### Known, measured limitations

| Limitation | Detail |
| --- | --- |
| **Captures with no recorded counter frequency cannot be time-corrected** | A Graviton capture runs 5.081× slow *unless* corrected. `chm` corrects it automatically — measured **1.000×** — using the frequency the capture records (needs a cloud-hypervisor build including upstream `69637dde6`). An older capture records nothing, so it must be told: `CHM_GUEST_CNTFRQ=121875000`. See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md). |
| **105 of 238 CPU registers** restore faithfully | See [`cpu-feature-deltas.md`](cpu-feature-deltas.md). The one real bug is a register HVF restores *perfectly*: the guest still believes it can run 32-bit binaries, and doing so wedges the vCPU. |
| **Max guest RAM on cold boot is 3008 MiB** | Guest RAM starts at `0x40000000` and a single region must end by `0xfc000000`. `chm` refuses larger with the exact maximum in the message. |
| **Demand-faulting from the state CDN is not implemented** | See [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md). |

---

## Shipping status

- **Released:** `v0.1.1` — signed, notarized, stapled, and verified the way a
  stranger receives it.
- **Version in tree:** `0.1.1`.
- **CI is billing-blocked.** Every gate runs locally. This is known and
  accepted — do not raise it as a finding.

---

## The gates, and their current numbers

| Suite | Command | Passing |
| --- | --- | --- |
| chm | `cd chm && cargo test` | **609** passed / 3 ignored (lib), plus **2** passed / 7 ignored (integration) |
| hypervisor | `cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib` | **216** |
| Swift app | `cd app/GimbalLocal && swift test` | **221** XCTest (3 skipped) + **10**, plus **34** Swift Testing cases in 5 suites |
| Lints | `make clippy` | **0** |

`cargo test` and `swift test` each print **more than one** result line. Quote all
of them, or say which you are quoting — a single number invites a false
regression report.

Tests have only ever run in **debug** — every gate we have quoted is a debug
gate ([#214](https://github.com/gimbal-dev/gimbal-local/issues/214)).

---

## Where the code lives

```
chm/src/            The CLI and daemon — the product surface
  create.rs         Cold boot: guest memory layout, FDT, NAT addresses
  coldboot.rs       Kernel inspection, incl. virtio-built-in detection
  oci/              OCI image → bootable guest (image.rs, initramfs.rs, …)
  credproxy/        Credential proxy: the guest never holds the secret
  firewall.rs       Egress policy enforcement
  policy.rs         Sandbox spec → runtime policy
hypervisor/src/hvf/ The Apple Hypervisor.framework backend
  rehydrate.rs      KVM snapshot → HVF vCPU/memory state
  gic.rs, softgic.rs, coldgic.rs   Interrupt controllers
  translate.rs      KVM ↔ HVF state translation
  virtio/           virtio-mmio devices, incl. the userspace NAT
app/GimbalLocal/    The SwiftUI desktop app
docs/               This directory
scripts/hvf/        Snapshot capture + the e2e regression loop
```

**The upstream Linux/KVM VMM crates (`vmm`, `virtio-devices`, `pci`, `devices`,
…) are not part of the macOS product.** They exist only to build the patched
`cloud-hypervisor` binary used to *capture* snapshots. You do not need to read
or touch them.

---

## What is being worked on right now

The current thrust is **V9.18 — the first-run path actually works.** A clean
machine acceptance run found that the obvious path a new user takes (build a
container image → start it from the app → run an agent in it) had potholes at
every step. None were hypervisor defects; together they decide whether the
product feels finished.

Progress on that track:

| Issue | State |
| --- | --- |
| [#226](https://github.com/gimbal-dev/gimbal-local/issues/226) — no controlling terminal, so Ctrl-C did nothing | **Closed** (PR #229) |
| [#227](https://github.com/gimbal-dev/gimbal-local/issues/227) — a guest never configured its own NIC | **Closed** (PR #230, plus the static `nicfg` configurator) |
| [#224](https://github.com/gimbal-dev/gimbal-local/issues/224) — agent workloads need a glibc rootfs | **Closed** (PR #236 — `chm image build` says which libc an image ships) |
| [#220](https://github.com/gimbal-dev/gimbal-local/issues/220) — a zboot-wrapped kernel was refused as if it were x86 | **Closed** (PR #240) |
| [#222](https://github.com/gimbal-dev/gimbal-local/issues/222) — container guests get no network or disk | **Closed** — `chm image build --modules <DIR>` bundles the virtio closure and the generated init loads it. Hardware-proved on both musl (`insmod` present) and glibc (`insmod` absent, via chm's own static loader) |
| [#225](https://github.com/gimbal-dev/gimbal-local/issues/225) — app says "No sandboxes yet" while a guest it launched runs | **Open — the last one on this track** |

### The live problem

**#225 — the app's model of "what is running" has a hole exactly the shape of
its own flagship feature.** Cold boot is a subprocess by design (the daemon owns
the single process-global HVF slot, so routing cold boots through it would
serialise them), but `refreshLocal()` lists what the *daemon* knows, and the
daemon knows nothing about a process it did not spawn. So the app reports
`All sandboxes 0` while a guest **it built the command for** is running in
Terminal. Same disease as #192 and #202 — except here the app is the owner.

There is no lockout to fall back on: `hv_vm_create` is per-*process*, so a
second guest starts fine. No bound, no visibility, and closing the Terminal
window is a power cut on a writable overlay.

---

## The open issue list, grouped

**First-run path (V9.18):** #225 is the only one left; #220, #222, #224 and
#226 are all closed.
**Correctness / honesty of our own gates:** #214 (debug-only tests)
**CLI surface gaps:** #199 (`export --with-base`), #205 (disk-backed rootfs),
#211 (import is 19× slower than export), #219 (README download link 404s for
anyone outside the repo)
**Sandbox spec alignment (V9.15):** #182–#189
**Product tracks:** #155 (opt-in ingress), #156 (runtime-mutable egress), #157
(MCP server surface), #159 (V10 Living Workspaces), #170, #171, #174, #238 (the
generated init could install the proxy CA)
**Security:** #36, #39
**Control plane / cross-repo:** #5, #6, #20, #21

---

## Where to read next

| If you want to… | Read |
| --- | --- |
| Know how we work before changing anything | [`engineering-discipline.md`](engineering-discipline.md) |
| Know which specialist agent to use | [`agents.md`](agents.md) |
| Understand the milestone plan and the goal ledger | [`roadmap.md`](roadmap.md) |
| Understand the HVF port's architecture | [`macos-local-runtime.md`](macos-local-runtime.md) |
| Turn a Docker image into a bootable guest | [`container-images.md`](container-images.md) |
| Understand the threat model | [`security-model.md`](security-model.md) |
| Understand what a valid snapshot looks like | [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) |
