# Project state

A single honest snapshot of where Gimbal Local actually is. If you are new — or
you are an agent starting a task — read this, then
[`engineering-discipline.md`](engineering-discipline.md), then the domain guide
for the area you are touching.

**Last measured sweep:** 2026-08-20, on the branch that becomes
[#371](https://github.com/gimbal-dev/gimbal-local/pull/371). The gate numbers
below include the changes merging with it, so they are true at the commit that
introduces this line and not before.
**Issue-state refresh:** 2026-08-20, swept from `gh issue list --state open`
rather than transcribed by hand — the previous list was assembled by hand and
every issue on it had closed
([#368](https://github.com/gimbal-dev/gimbal-local/issues/368)).

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
| A coding agent working inside a guest | GitHub Copilot CLI wrote and ran code holding no credential — on a cold-booted guest (V7.1) **and, on 2026-08-13, inside a rehydrated Graviton2 capture across two suspend/resume cycles** (#286). |
| **An agent resuming its own work after a suspend** | The whole product in one line: the agent wrote `fizz.py`, the guest was suspended and resumed, and the agent then **read back its own file and extended it**. Three agent runs, two cycles, exit 0 each time; guest uptime continuous at 14.09 days across all of it. |

### Known, measured limitations

| Limitation | Detail |
| --- | --- |
| **Captures with no recorded counter frequency cannot be time-corrected** | A Graviton capture runs 5.081× slow *unless* corrected. `chm` corrects it automatically — measured **1.000×** — using the frequency the capture records (needs a cloud-hypervisor build including upstream `69637dde6`). An older capture records nothing, so it must be told: `CHM_GUEST_CNTFRQ=121875000`. See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md). |
| **105 of 238 CPU registers** restore faithfully | See [`cpu-feature-deltas.md`](cpu-feature-deltas.md). The one real bug is a register HVF restores *perfectly*: the guest still believes it can run 32-bit binaries, and doing so wedges the vCPU. |
| **Max guest RAM on cold boot is 3008 MiB** | Guest RAM starts at `0x40000000` and a single region must end by `0xfc000000`. `chm` refuses larger with the exact maximum in the message. |
| **Demand-faulting from the state CDN is not implemented** | See [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md). |
| **`chm state-cdn serve` served files from outside its cache — fixed in v0.2.2** | Unauthenticated file disclosure. `sanitize()` folded `/` to `_` but kept `.`, so `ref=..` survived as a path segment and `GET /state-cdn/chunk?ref=..&key=NAME` returned any `[A-Za-z0-9.-]+`-named file *beside* the cache dir. Measured end-to-end: `HTTP 200` with the decoy's contents before, `404` after. Present in **every release up to and including v0.2.1**; fixed and published in **v0.2.2**. Bounded by: explicit opt-in (nothing starts the server), loopback default, one directory level, and that charset — but peer caching exists to be LAN-bound, so the default is weak mitigation for anyone actually using it. |
| **The end-user licence has not been reviewed by a lawyer** | [`EULA.md`](../app/GimbalLocal/EULA.md) was written by the maintainer, not by counsel, and ships that way deliberately — the alternative was distributing with no written terms at all. The document says so in its own opening notice rather than implying a review it never had. `scripts/build-gimbal-local-app.sh` refuses release builds while that text is marked an unreviewed *draft*; the gate was cleared by accepting the terms as-authored, not by obtaining review. |

---

## Shipping status

- **Released:** `v0.2.2` — signed, notarized, stapled, and verified the way a
  stranger receives it. It carries two fixes that matter to anyone running the
  preview: `chm state-cdn serve` no longer serves files from outside its cache
  directory (see the limitations table), and the documented kernel download is
  now fetched over HTTPS against a pinned SHA-256 rather than plain HTTP with
  no integrity check at all.
- **Version in tree:** `0.2.2`.
- **CI is billing-blocked.** Every gate runs locally. This is known and
  accepted — do not raise it as a finding.

---

## The gates, and their current numbers

| Suite | Command | Measured result |
| --- | --- | --- |
| chm | `cd chm && cargo test` | **901** passed / 4 ignored (lib), plus **2** passed / 7 ignored (integration) |
| hypervisor | `cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib` | **276** passed — also run by `make test-hvf` |
| Swift app | `cd app/GimbalLocal && swift test` | **263** XCTest (3 skipped), plus **34** Swift Testing cases in 5 suites |
| Lints | `make clippy` | **0** |
| HVF gate | `make test-hvf` | **41** passed / 3 ignored (signed `hvf_boot`), then **276** passed (hypervisor lib). [#334](https://github.com/gimbal-dev/gimbal-local/issues/334) is fixed and merged |

`cargo test` and `swift test` each print **more than one** result line. Quote all
of them, or say which you are quoting — a single number invites a false
regression report.

The release gate now runs the suite in the configuration it is about to ship
([#214](https://github.com/gimbal-dev/gimbal-local/issues/214), closed) —
`scripts/release-macos.sh` runs `cargo test --release` and `swift test -c
release` **before** it builds anything. That guard exists because a suite that
has only ever run in one build configuration reports safety it does not provide
for any other: the `fcntl` variadic bug passed every debug test and hung every
release binary. Day-to-day gates above are still debug; the release is not.

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

**V11 — the browser sandbox** is the newest shipped capability and the first
workload built *on* this stack rather than into it: an agent gets a browser and
nothing else, reachable over CDP from the host and nothing more. See
[`browser-sandbox.md`](browser-sandbox.md) for how to build and drive one, and
what its acceptance gate actually proves.

**Originating a lineage locally** closed with
[#341](https://github.com/gimbal-dev/gimbal-local/issues/341): before it, a cold
boot could never produce the first snapshot, so every lineage on this machine
had to begin in the cloud. A Mac can now originate one.

### The live problem

The four pillars stand up together in one guest — on 2026-08-13 an agent worked
inside a rehydrated Graviton2 capture and, after a suspend and resume, read back
its own file and extended it.

What is unproven is the **return leg**. Nothing has yet shown upstream
cloud-hypervisor accepting a snapshot this project originated
([#372](https://github.com/gimbal-dev/gimbal-local/issues/372)), and an
Apple-originated snapshot is expected to hard-fail on a non-PAC host, which
cannot be measured on this hardware at all
([#373](https://github.com/gimbal-dev/gimbal-local/issues/373)). Both are
recorded as unmeasured rather than believed. Until the return leg is
demonstrated, "cloud to Mac" is proved and "Mac back to cloud" is not.

Two rehydration warts remain visible to a user:
[#310](https://github.com/gimbal-dev/gimbal-local/issues/310) (a resumed guest
reports an RCU stall the detector classifies as benign, and the presentation
still does not explain the difference) and
[#366](https://github.com/gimbal-dev/gimbal-local/issues/366)
(`update-initramfs` segfaults about half the time in a rehydrated capture).

---

## The open issue list, grouped

Swept from `gh issue list --state open` on 2026-08-20. Six issues close with the
PR introducing this section — #317, #341, #365, #369, #374 and #368 itself — so
**31 remain open**, and every one of them is named below. Issue numbers are
written individually rather than as ranges, so a checker can verify the list
against `gh` without expanding anything.

**Credential-proxy first contact:** [#315](https://github.com/gimbal-dev/gimbal-local/issues/315)
(a workspace mints a CA the guest does not trust),
[#316](https://github.com/gimbal-dev/gimbal-local/issues/316) (the CA install
script is too large for `chm exec`, and there is no `chm cp`),
[#318](https://github.com/gimbal-dev/gimbal-local/issues/318) (a client that
gates on local auth never lets the proxy inject)

**Rehydration fidelity:** [#279](https://github.com/gimbal-dev/gimbal-local/issues/279)
(cure the ASID-width delta at capture time),
[#287](https://github.com/gimbal-dev/gimbal-local/issues/287) (re-patch the
guest kernel's elided `ic ivau` instead of working around DIC=0),
[#310](https://github.com/gimbal-dev/gimbal-local/issues/310),
[#366](https://github.com/gimbal-dev/gimbal-local/issues/366)

**The return leg, unmeasured:** [#372](https://github.com/gimbal-dev/gimbal-local/issues/372),
[#373](https://github.com/gimbal-dev/gimbal-local/issues/373)

**Sandbox / browser defects:** [#360](https://github.com/gimbal-dev/gimbal-local/issues/360)
(the app never stops the daemon it started),
[#361](https://github.com/gimbal-dev/gimbal-local/issues/361) (a browser guest
can be warm-resumable or keep its own sandbox, but not both),
[#363](https://github.com/gimbal-dev/gimbal-local/issues/363) (`chm posture`
reports only what chm does to a guest, never what the guest can do)

**Sandbox spec alignment:** [#182](https://github.com/gimbal-dev/gimbal-local/issues/182)
(umbrella), [#183](https://github.com/gimbal-dev/gimbal-local/issues/183)
(extensions), [#184](https://github.com/gimbal-dev/gimbal-local/issues/184)
(securityModules), [#185](https://github.com/gimbal-dev/gimbal-local/issues/185)
(dataPolicy), [#186](https://github.com/gimbal-dev/gimbal-local/issues/186)
(toolPolicy), [#187](https://github.com/gimbal-dev/gimbal-local/issues/187)
(identity), [#188](https://github.com/gimbal-dev/gimbal-local/issues/188)
(observability), [#189](https://github.com/gimbal-dev/gimbal-local/issues/189)
(lifecycle hooks)

**Product tracks:** [#155](https://github.com/gimbal-dev/gimbal-local/issues/155)
(name guest ingress in the spec — the `--expose` mechanism ships, the spec
surface does not), [#156](https://github.com/gimbal-dev/gimbal-local/issues/156)
(change egress policy without restarting),
[#157](https://github.com/gimbal-dev/gimbal-local/issues/157) (drive a sandbox
as an MCP server), [#159](https://github.com/gimbal-dev/gimbal-local/issues/159)
(V10 Living Workspaces),
[#171](https://github.com/gimbal-dev/gimbal-local/issues/171) (measure vCPU WFI
residency instead of console silence)

**Security:** [#36](https://github.com/gimbal-dev/gimbal-local/issues/36)
(signed snapshot manifest), [#39](https://github.com/gimbal-dev/gimbal-local/issues/39)
(threat model + hardening checklist)

**Docs:** [#368](https://github.com/gimbal-dev/gimbal-local/issues/368) — this
section's own defect, closed by the change that introduced this list

**Control plane / cross-repo:** [#5](https://github.com/gimbal-dev/gimbal-local/issues/5),
[#6](https://github.com/gimbal-dev/gimbal-local/issues/6),
[#20](https://github.com/gimbal-dev/gimbal-local/issues/20),
[#21](https://github.com/gimbal-dev/gimbal-local/issues/21)

---

## Where to read next

| If you want to… | Read |
| --- | --- |
| Know how we work before changing anything | [`engineering-discipline.md`](engineering-discipline.md) |
| Know which specialist agent to use | [`agents.md`](agents.md) |
| Understand the milestone plan | [`roadmap.md`](roadmap.md) is the public engineering plan; planned work is not a shipped commitment. |
| Understand the HVF port's architecture | [`macos-local-runtime.md`](macos-local-runtime.md) |
| Turn a Docker image into a bootable guest | [`container-images.md`](container-images.md) |
| Understand the threat model | [`security-model.md`](security-model.md) |
| Understand what a valid snapshot looks like | [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) |
