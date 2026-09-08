# Project state

A single honest snapshot of where Gimbal Local actually is. If you are new — or
you are an agent starting a task — read this, then
[`engineering-discipline.md`](engineering-discipline.md), then the domain guide
for the area you are touching.

**Last measured sweep:** 2026-09-08, at commit `ded833183`. Every gate number
below was produced by running the command in its own row on that commit, not
carried forward from a previous sweep.
**Issue-state refresh:** 2026-09-08, swept with
[`../scripts/check-docs.sh`](../scripts/check-docs.sh) rather than transcribed
by hand. Run that script before trusting the grouped list at the bottom of this
page; it compares the page against GitHub and exits non-zero on drift. It
exists because this list has now rotted twice — once as
[#368](https://github.com/gimbal-dev/gimbal-local/issues/368), and again in the
refresh that closed #368, which was measured 42% wrong (12 of the 31 issues it
named had closed, and one open issue was missing). Both times the page was
internally consistent, so only leaving the repo and asking could catch it.

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
| chm | `cd chm && cargo test` | **1115** passed / 4 ignored (lib), plus **2** passed / 7 ignored (integration) |
| hypervisor | `cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib` | **343** passed — also run by `make test-hvf` |
| Swift app | `cd app/GimbalLocal && swift test` | **273** XCTest (3 skipped), plus **34** Swift Testing cases in 5 suites |
| Lints | `make clippy` | **0** |
| HVF gate | `make test-hvf` | **41** passed / 3 ignored (signed `hvf_boot`), then **343** passed (hypervisor lib) |
| Harness | `make check-harness` | **62** cases pass across the three hook rule tables |
| Docs | `./scripts/check-docs.sh` | **0** drift — the grouped issue list below matches GitHub |

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

**This is now the only substantial engineering problem left in the local
product.** The defect backlog is empty: the last four defects
([#437](https://github.com/gimbal-dev/gimbal-local/issues/437),
[#438](https://github.com/gimbal-dev/gimbal-local/issues/438),
[#439](https://github.com/gimbal-dev/gimbal-local/issues/439),
[#440](https://github.com/gimbal-dev/gimbal-local/issues/440)) closed on
2026-09-08. What remains open is vision work, the parked sandbox-spec family,
two security umbrellas, one packaging gap
([#410](https://github.com/gimbal-dev/gimbal-local/issues/410)), and four
limitations that need hardware this machine does not have.

One rehydration wart remains visible to a user:
[#366](https://github.com/gimbal-dev/gimbal-local/issues/366)
(`update-initramfs` segfaults about half the time in a rehydrated capture).

---

## The open issue list, grouped

Swept with [`../scripts/check-docs.sh`](../scripts/check-docs.sh) on 2026-09-08,
so **23 remain open** and every one of them is named below. Issue numbers are
written individually rather than as ranges, so the checker can compare this
list against `gh` without expanding anything. If you change this list, re-run
that script before you commit — it is the only thing standing between this page
and its third rot.

**Three of the items below are defects**, all filed on 2026-09-08 after the
backlog had closed out; they are grouped first. Everything after them is vision
work, parked spec work, a security umbrella, a packaging gap, or a limitation
that needs hardware this machine does not have.

**Filed after the backlog closed:**
[#445](https://github.com/gimbal-dev/gimbal-local/issues/445) (CA install
reports rejected trust when the guest only lacks openssl),
[#446](https://github.com/gimbal-dev/gimbal-local/issues/446) (the agent
quickstart lacks account-specific Copilot endpoint setup),
[#447](https://github.com/gimbal-dev/gimbal-local/issues/447) (no bounded stop
wait, so stop/start automation is unreliable)

**Rehydration fidelity:** [#279](https://github.com/gimbal-dev/gimbal-local/issues/279)
(cure the ASID-width delta at capture time, or refuse the capture),
[#366](https://github.com/gimbal-dev/gimbal-local/issues/366)
(`update-initramfs` segfaults about half the time in a rehydrated capture)

**The return leg, unmeasured:** [#372](https://github.com/gimbal-dev/gimbal-local/issues/372)
(nothing has shown upstream cloud-hypervisor accepting a chm-originated
snapshot), [#373](https://github.com/gimbal-dev/gimbal-local/issues/373) (an
Apple-originated snapshot will hard-fail on a non-PAC host, and that is
unmeasurable here)

**Sandbox spec alignment** — parked as a family, not being worked:
[#182](https://github.com/gimbal-dev/gimbal-local/issues/182) (umbrella),
[#183](https://github.com/gimbal-dev/gimbal-local/issues/183) (extensions),
[#184](https://github.com/gimbal-dev/gimbal-local/issues/184) (securityModules),
[#185](https://github.com/gimbal-dev/gimbal-local/issues/185) (dataPolicy),
[#186](https://github.com/gimbal-dev/gimbal-local/issues/186) (toolPolicy),
[#187](https://github.com/gimbal-dev/gimbal-local/issues/187) (identity),
[#188](https://github.com/gimbal-dev/gimbal-local/issues/188) (observability),
[#189](https://github.com/gimbal-dev/gimbal-local/issues/189) (lifecycle hooks)

**Packaging:** [#410](https://github.com/gimbal-dev/gimbal-local/issues/410)
(the app has no update channel, and the gap lost its tracker when #391 closed)

**Product vision:** [#159](https://github.com/gimbal-dev/gimbal-local/issues/159)
(V10 Living Workspaces — the workspace becomes part of the session)

**Security:** [#36](https://github.com/gimbal-dev/gimbal-local/issues/36)
(signed snapshot manifest + verification),
[#39](https://github.com/gimbal-dev/gimbal-local/issues/39) (threat model +
hardening checklist, umbrella)

**Control plane / cross-repo:** [#5](https://github.com/gimbal-dev/gimbal-local/issues/5)
(postcopy memory from the state CDN),
[#6](https://github.com/gimbal-dev/gimbal-local/issues/6) (fork + CoW overlays +
wake-on-traffic), [#20](https://github.com/gimbal-dev/gimbal-local/issues/20)
(consistent filesystem + network policy enforced on the Mac),
[#21](https://github.com/gimbal-dev/gimbal-local/issues/21) (V0 vision: the four
capability pillars)

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
