# Gimbal Local — roadmap & milestones

Gimbal Local rehydrates Cloud Hypervisor arm64 / KVM snapshots onto Apple
Hypervisor.framework (HVF), so a workload captured in the cloud can be brought
down and run — or resumed *past where it left off* — on an Apple-silicon Mac.
This doc is the tidy map: the vision it serves, what is shipped and proven, and
what remains.

It is a companion to [`macos-local-runtime.md`](macos-local-runtime.md) (the
architecture) — read that for *how* the port works; read this for *where the
product is going*.

---

## The vision: four capability pillars (V0)

The end state, shared with the control plane
([Gimbal Cloud](https://github.com/gimbal-dev/gimbal-cloud-control)), is four
capabilities:

1. **Run either side, restart either side.** Start a session in the cloud, resume
   it on the Mac *past the point it reached*, and back. Local vs remote is an
   implementation detail.
2. **Snapshots as a branching filesystem, with lazy rehydration.** Content-
   addressed revisions that fork/branch like git, and a resume that demand-faults
   only the working set instead of copying whole images.
3. **Consistent filesystem + network (firewall) policy.** A per-sandbox policy —
   what it can *reach* and what it can *touch* — authored once in the plane and
   enforced identically wherever the sandbox runs.
4. **Unified logging, insights & cost.** One place for what a session cost, did,
   and reached, regardless of where it ran.

**The one rule that ties it together:** the control plane (`gctl`) is the single
source of truth; `chm`-on-HVF (Mac) and cloud-hypervisor-on-KVM (cloud) are
**symmetric workers** speaking the same
[runner contract](https://github.com/gimbal-dev/gimbal-cloud-control/blob/main/docs/runner-contract.md).
A capability that only works on one substrate is not done.

---

## The line: what Gimbal Local owns

Gimbal Local owns everything on the Mac — the **app** (`app/GimbalLocal`), the
**engine + daemon** (`chm`, `hypervisor/src/hvf/`), and the thin **runner client**
that calls the plane when one exists. The control plane owns the server on the
far side of the runner contract: leases, cost, cleanup, snapshot provenance, the
`gic_mode` compatibility gate, and audit. The Mac is a *worker*, not a second
source of truth.

---

## Milestones to date (shipped & proven)

The port was built as a long series of hardware-proven milestones (`M1`–`M24`),
then the cloud-integration work that followed. Grouped by theme:

### The in-tree HVF port — hardware-proven

| Area | Milestones | Result |
| --- | --- | --- |
| CPU & backend | M1, M3, M20 | Real in-tree HVF backend; KVM→HVF register/system-register translation; SMP resume runs every vCPU of a multi-core snapshot concurrently. |
| Interrupts & GIC | M2, M10–M14 | Host→guest interrupt delivery; a user-space ITS translation engine; message-based SPI (GICv2M) delivery, with live virtio completion routed as message-SPIs. |
| Devices | M5, M17, M18 | PL011 serial console (interactive login), virtio-blk with copy-on-write overlays, and virtio-net with a real host datapath. |
| Snapshots | M15, M16 | A real SPI-routed cloud snapshot rehydrates on HVF and services real virtio I/O, resuming a settled guest to a usable login prompt. |
| Guard rails | M13, M19 | A load-time guard rejects ITS/LPI snapshots the managed GIC cannot deliver (boundary **R1**). The managed GIC limit is real, but a userspace-GICv3 path that *can* deliver LPIs is now proven (M-USGIC / #81), so R1 is a current-default, not a permanent platform limit. |

### Tooling & app

| Milestone | Result |
| --- | --- |
| M7, M8 | The standalone `chm` binary and the `chm serve` daemon + `chm ctl` client (machine-readable local state). |
| M22 | The bring-your-own-AWS capture loop (`chm cloud …`) — local-managed slice. |
| M23 | **Gimbal Local**, the native SwiftUI desktop app over `chm serve`/`ctl`. |

### Live local lifecycle primitives (M25) ✅

- **Suspend / resume** — `chm resume` restores a live checkpoint; a suspend
  captures a memory + device + fs checkpoint on idle and on graceful stop
  (checkpoint-everywhere).
- **Fork lineage** — `chm fork` branches a revision (Image → Revision → Sandbox,
  where *suspend = commit* and *fork = branch*); see
  [`gimbal-local-fork-model.md`](gimbal-local-fork-model.md).
- **Revision store + rollback** — `.chm-revisions/` keeps the lineage (RAM-pruned
  to the newest N); `chm revisions` / `chm rollback`, surfaced as a Revision
  history card in the app.
- **Per-sandbox workspaces** — `chm workspace <image> <ws>` shares an image's
  read-only base but isolates each sandbox's overlays + checkpoints.

### The control-plane runner + M26 — faithful cloud rehydration ✅

`chm runner` makes the Mac a **runner** for the plane, and milestone **M26
(complete)** delivers the whole cloud→local loop:

| # | What | Status |
| --- | --- | --- |
| #15 | Cloud Snapshots tab — browse the plane, bring one down | ✅ |
| #16 | Unified local/cloud sandboxes (origin is an implementation detail) | ✅ |
| #17 | Runner fetches from a `file://` **or** `http(s)://` object store | ✅ |
| #3 | Provenance surfaced + content-addressed cache dedup | ✅ |
| #18 | Real-snapshot fidelity on HVF — booted Ubuntu 24.04 | ✅ **proven** |
| #19 | **Cross-substrate session mobility (the hero loop)** | ✅ **proven** |

The headline proof (**Pillar ①**): a session that ran on `linux-kvm` in the
cloud, was checkpointed, and **resumed on `apple-hvf` past its mid-flight
marker** — booting to an interactive login prompt, with the 1 GiB RAM + 8 GiB
disk + device/vCPU state restored, the `gic_mode` gate re-verified locally, and
the runner cache deduping repeat pulls content-addressed (a 9 GB re-pull served
from cache in 0.077 s).

---

## Where we actually are (2026-07-29)

**The dream sentence is true.** A **vanilla** — stock upstream, unforked — arm64
Cloud Hypervisor KVM snapshot **captured on an AWS Graviton2 host** rehydrates on
Apple silicon and runs an interactive login shell, **with no code changes, no
flags and no environment variables**, through **all three** entry points: the
`chm run` CLI, the `chm serve` daemon, and the Gimbal Local SwiftUI app.

That works because of the **userspace GICv3** (M-USGIC): a software
distributor/redistributor/ITS and a trapped CPU interface, delivering the LPIs
Apple's managed GIC cannot, while HVF still executes the vCPUs. It is a real
interrupt controller, not a compatibility shim.

Locally captured fixtures additionally demonstrate virtio disk, virtio net + NAT
egress, SMP and checkpoint/resume, at **247 ms** start-to-ready against Docker
Sandbox's **12.73 s** on the same host.

**Every problem that blocked the crossing is now closed:**

1. ~~**We have never rehydrated a real cloud snapshot.**~~ **Done, 2026-07-28.**
   Three vanilla Graviton2 captures restored and ran an interactive shell. Full
   evidence in [`graviton-acid-test-results.md`](graviton-acid-test-results.md).
2. ~~**The guest's clock runs 5.08× slow across the cloud→Mac boundary** (#104,
   #108).~~ **Fixed, and measured at 1.000×.** Graviton2 presents `CNTFRQ_EL0 =
   121 875 000 Hz` against Apple silicon's `24 000 000 Hz`, and a Linux guest
   caches the rate at boot. Apple exposes a vtimer *offset*, never a *rate* — but
   the offset is ours to move, so re-stepping it onto `base + (now - base_host) ×
   guest_hz / host_hz` at every guest entry synthesizes the rate. `325/64` reduces
   exactly, so u128 math drifts zero.
3. ~~**`chm serve` rejects vanilla** (#102).~~ **Fixed in V2.1**, and V2.2 took it
   the rest of the way into the app.

**What remains is no longer about making it work — it is about making it a
product.** The open work is the cloud contract (V3), security defaults (V4), and
a cold create-from-image path (#101). See the spine below.

---

## Milestones remaining — the vanilla-first spine

Re-cut 2026-07-28 against the original vision: *snapshots just work → cloud
integration → UI → security with sane defaults*. Everything is ordered by what
makes a **vanilla cloud snapshot run everywhere in the product**.

| | Milestone | Pillar | Status | Issues |
| --- | --- | --- | --- | --- |
| **V1** | **Make a real cloud snapshot run** | ① | ✅ **complete** — acid test passed, clock fixed | ~~#104~~, ~~#105~~, ~~#108~~ |
| **V2** | **Vanilla everywhere in the product** | ①③ | ✅ **complete** — CLI, daemon and app all run vanilla flagless | ~~#102~~ |
| **V3** | **Cloud control plane on the vanilla contract** | ②④ | **the current thrust**; partly blocked cross-repo | #21, #36, #5 |
| **V4** | **Security with sane defaults** | ③ | substantially shipped; needs the umbrella | #39, #20 |

### V1 · Make a real cloud snapshot run ✅

The milestone that proves the vision. **V1.5 passed on 2026-07-28** — see
[`graviton-acid-test-results.md`](graviton-acid-test-results.md). V1.1 was
answered as a side effect, and V1.3 — the hard problem — is now solved: **V1 is complete.**

| | Task | Status / blocked on |
| --- | --- | --- |
| V1.1 | Establish what `CNTFRQ_EL0` an HVF guest actually sees. | ✅ **Done.** No bare-metal payload needed after all: the guest's own dmesg in the RAM image states it. Mac/HVF = **24 000 000 Hz**; Graviton2 = **121 875 000 Hz**. Confirmed three independent ways (boot log, a measured 5.080× dilation vs 5.078125 predicted, and `CNTVCT`÷rate cross-checked against cloud-init's timestamps). |
| V1.2 | Guard the HVF rehydrate path against a frequency mismatch: parse the clock block, compare against the host, say so loudly. (#104) | ✅ **Done.** Ships on both the CLI and daemon paths. Warns by default and still runs — deliberately diverging from KVM, because a dilated guest is genuinely useful and refusing would mean no cloud snapshot ever starts on a Mac. `CHM_STRICT_CNTFRQ=1` opts in to the KVM rejection. A capture predating `69637dde6` carries no clock block, so the guard reports that it cannot verify rather than guessing. |
| V1.3 | **Fix the 5.08&times; dilation.** (#108) Apple exposes `hv_vcpu_set_vtimer_offset` — an *offset*, never a *rate* — but the offset is ours to move. Holding `CNTVCT_guest = base + (now - base_host) * guest_hz / host_hz` and re-stepping the offset onto that curve at every guest entry synthesizes the rate. `121875000/24000000` reduces to exactly `325/64`, so u128 integer math accumulates **zero drift**. Enabled explicitly with `CHM_GUEST_CNTFRQ=<Hz>`. | ✅ **Done — measured 1.000&times;, down from 5.081&times;.** Guest `sleep 5` takes 5.00 s of host wall clock (was 25.40 s); three consecutive runs at 1.001 / 1.000 / 1.000. Boot-to-shell also halved, 2.19 s &rarr; 1.09 s. Instrument: `scripts/hvf/measure-clock-dilation.py`, validated by first reproducing the known 5.08&times; baseline. |
| V1.4 | Audit the rest of the bug class: MPIDR/affinity layout, `ID_AA64*` feature registers, cache topology, GIC `IIDR` — anywhere a guest probed the *capture* host and cached the answer. | ✅ **Done 2026-07-29 — and it found a new bug.** 238 captured registers replayed against a real HVF vCPU: 105 restored, 133 refused, 0 clamped. Every `ID_AA64*`/`MIDR`/`MPIDR` restores exactly, which is *why* a Graviton guest runs here at all. The bug is the inverse of the one we went looking for: `ID_AA64PFR0_EL1.EL0 = 2` (AArch32 at EL0) is restored **faithfully**, so the guest still believes it can run 32-bit binaries — and executing one **permanently wedges the vCPU**, verified against a control that the shell survives. Warned at load; `CHM_STRICT_AARCH32=1` refuses. Also: `CTR_EL0.DIC` differs in exactly one bit (latent, stressed without fault) and the `DC ZVA` block size is identical (hazard closed). Instrument: `chm sysregs`. Full report: [`cpu-feature-deltas.md`](cpu-feature-deltas.md). |
| V1.5 | **THE ACID TEST** — rehydrate a genuine vanilla Graviton capture (#105). | ✅ **PASSED 2026-07-28.** Three Graviton2 captures, all restored, all reached an interactive login shell, no code changes. |
| V1.6 | **Round 2 capture.** Round 1 exposed two bugs in our own request: it pinned `CH_VERSION=v52.0`, which predates the clock block entirely, and the captures fired mid-cloud-init so the guest restarts its getty ~113 s after resume. Both fixed in the request. | gimbal cloud |

The capture we need, precisely: [`graviton-capture-request.md`](graviton-capture-request.md).

### V2 · Vanilla everywhere in the product ✅

| | Task | Blocked on |
| --- | --- | --- |
| V2.1 | Wire the userspace GIC into `chm serve` (#102). Factor the ~525-line `run_usgic` engine so CLI and daemon share it, checkpoint/resume included. | ✅ **Done.** `run_usgic_engine(cfg, loaded, supervise)` is shared by both entry points. The daemon reaches an interactive shell on a vanilla Graviton capture (`ubuntu@ch-snap:~$`, `uname -a` → `6.8.0-136-generic aarch64`), Stop → Start round-trips live guest RAM (a bash variable set before the stop echoed back after it), and checkpoints interoperate in both directions with the CLI's. Adds a `chm ctl input` command, because the daemon's console was read-only and a resumed guest emits nothing until typed at. |
| V2.2 | The SwiftUI app opens, runs, stops and resumes a vanilla snapshot end to end. | ✅ **Done (#114).** Two things were in the way and both are fixed: the app's restorability gate still demanded `gicv2m-message-spi`, so it refused snapshots the runner would happily run (it now mirrors `hvf_restorable`, and separates "this Mac can restore it" from "the plane will release it"); and the console was read-only, which is fatal for a vanilla capture because it resumes at a login prompt and emits nothing until typed at. Input now goes through `chm ctl input`. **Hardware evidence:** from the app, no flags, no environment variables, against a vanilla ITS/LPI Graviton capture — logged in as `ubuntu`, `uname -m` → `aarch64`. Stop wrote a real checkpoint (1 GiB `memory-ranges`); resuming it came back already at `ubuntu@ch-snap:~$` with an in-RAM-only marker intact, so live state genuinely survives Stop → Start. |
| V2.3 | ~~Retire `CHM_USERSPACE_GIC=1`~~ **done as auto-routing.** Both `chm run` and `chm serve` ask `routes_completions_as_lpis()` and send ITS/LPI captures to the userspace GICv3 with no flag, so a vanilla Graviton snapshot reaches a shell with zero environment variables. Only bundles the managed GIC would have refused outright change path. **The three vestigial forcing mechanisms are now gone (#115):** `HvfVcpu::new` no longer reads the variable to seed `UserGic::enabled` (a library crate letting a process-global change per-vCPU interrupt semantics — a vCPU could have come up trapping ICC registers with no distributor behind them), and the runner no longer sets it on the child (belt-and-braces that would have hidden an auto-routing regression). It survives only as a genuine A/B override on `chm run`/`chm serve`. **Still open:** whether the userspace GIC should also take *GICv2M* captures, so there is one path rather than a routing decision. | V1.5 |

### V3 · Cloud control plane on the vanilla contract **[the current thrust]**

| | Task | Blocked on |
| --- | --- | --- |
| V3.1 | `gctl` should stop gating on GIC mode entirely: as of V2.1 a vanilla ITS/LPI capture runs under **both** `chm run` and `chm serve`, so an `assign-run` 422 on `gic_mode: its-lpi` now refuses bundles we can run. Our side of the earlier confusion is corrected in `d8511789d`. | gctl |
| V3.2 | One-command `pull → verify → run`, fail-closed. | V3.3 |
| V3.3 | Signed snapshot manifest + verification, unified trust root (#36). | gctl |

### V4 · Security with sane defaults

| | Task | Status |
| --- | --- | --- |
| V4.1 | Threat model + hardening checklist umbrella (#39). A rehydrated snapshot is untrusted code with a device model attached. | ✅ **Done.** [`security-model.md`](security-model.md) carries the threat model, invariants I1–I10 and the checklist; §1a now adds **the default posture** — what is true of a run with no flags, no env and no config — including a written argument for the two controls that are deliberately *not* default-on. Made executable as `chm posture`, which resolves the same sources the run path resolves, reports every control with how it was decided, and exits non-zero if anything is weakened. A checklist in a document says what we intended; a control you believe is on but is not is worse than one you know is off. |
| V4.2 | Make egress allow-list, reserved-address guard and CoW isolation the **default** posture with a documented opt-out (#20). | ✅ **Done.** Audited what was actually on out of the box rather than assuming: the reserved-address guard (I10) and CoW/overlay confinement (I2/I3) were already default-on, but **resource ceilings were not** — an unconfigured workspace resolved to *unbounded*. Now resolves to a `chm` baseline (≤64 vCPU, RAM ≤ host physical, overlay ≤64 GiB, console ≤1 GiB, ≤128 NAT sockets) with `CHM_LIMITS=none` as the documented opt-out. Verified the acid test still passes under the new ceilings. Egress stays open-to-the-internet by design — §1a argues why default-deny would be the worse security outcome. |

### V5 · The coding-agent sandbox — measured gap list

V1–V4 deliver the sentence *"a vanilla Cloud Hypervisor snapshot from the cloud
just works on my Mac, safely."* That sentence is true. It is **not** the same as
*"a developer's coding agent runs in this sandbox"*, and the difference was
measured rather than assumed, inside a live rehydrated `graviton-1` guest on
2026-07-30:

| what a coding agent needs | measured | gap |
| --- | --- | --- |
| 64-bit userspace | `aarch64`, **2382 ELF binaries, 0 of them 32-bit**, no `armhf` multiarch | ✅ none — the V1.4 AArch32 wedge is effectively unreachable |
| **network** | `ip -br link` → **loopback only**, no routes; the capture config says `net = None` | 🔴 **blocker.** No `git clone`, no `npm install`, no API call. We *built* the userspace NAT and egress policy but have never run them against a real cloud capture |
| **CPU / RAM / disk** | 1 vCPU · 953 MiB · 2.4 GB disk, **74 % full, 634 MB free** | 🔴 **blocker.** A demo VM, not a build environment |
| **toolchain** | `git` ✅ `python3` ✅ `curl` ✅ — `gcc` `make` `node` `npm` `go` `cargo` **all missing** | 🟡 an *image* problem, not a hypervisor problem: needs a purpose-built agent image, not stock Ubuntu cloud |
| **developer's code in / out** | no mechanism at all | 🔴 **blocker, and an unmade design decision.** I1 ("no host FS passthrough") is a security invariant we deliberately hold; a local coding sandbox has to get the repo in somehow. Scoped virtio-fs, a git remote loop, or a syncing volume — each trades against I1 differently |
| **fresh sandbox from an image** | every start is a rehydrate | 🟡 #101 |

| | Task | Status |
| --- | --- | --- |
| V5.1 | **Capture with a NIC and 2+ vCPU** and prove the NAT + egress policy on a real cloud snapshot. Highest value: it is the only blocker where the code already exists and only the evidence is missing. | gimbal cloud (folds into V1.6) |
| V5.2 | **Decide how a developer's repo enters the sandbox**, and write the trade against I1 before building. | decision |
| V5.3 | **A purpose-built agent image** (toolchain, sensible disk, agent runtime) rather than a stock cloud image. | image |
| V5.4 | Cold create-from-image (#101) so a fresh sandbox does not require a pre-existing capture. | M |

### Deferred, deliberately

- **#101 · cold create-from-image.** Every start is a full snapshot rehydrate.
  Reframed from a perf problem to a capability/onboarding gap — warm resume is
  247 ms and a cold path would be slower.
- **`GITS_*` MMIO.** Not exercised on the resume path; a guest that re-programs
  its ITS *while running* is untested. No fixture does this.
- **memfd page-sharing (#4/M25 perf ceiling), postcopy (#5), fork/wake-on-traffic (#6).**

---

## Historical milestone detail (M25–M32)

The sections below are the **previous** milestone structure, kept for the shipped
detail and rationale they record. The V1–V4 spine above supersedes them as the
plan; where the two disagree, V1–V4 is current.

### M25 · Live local lifecycle — suspend · resume · fork

The Mac runs, suspends, resumes, and forks microVMs entirely locally. The engine
is complete:

- **Suspend / resume** live checkpoints, and **checkpoint-everywhere** (idle,
  graceful stop, daemon stop).
- **`chm fork`** branches a revision (shared read-only base + copied live state).
- **Local revision store + rollback** — `.chm-revisions/` keeps the suspend /
  fork / rollback lineage (RAM-pruned to the newest N so the graph survives),
  `chm revisions` / `chm rollback`, and a Revision history card in the app.
- **`chm workspace <image> <ws>`** — a per-sandbox workspace that shares an
  image's read-only base but keeps its own overlays + checkpoints, so N sandboxes
  from one image diverge independently.
- The runner advertises `supports_fork` / `supports_cow_overlay`.
- **Per-sandbox workspaces are wired through the app** — each sandbox runs in its
  own workspace (shared read-only base, isolated overlays + checkpoints) via both
  the interactive terminal and the daemon; several run concurrently (one VM per
  process). `chm fork` shares the base RAM read-only (file-level CoW). The runner
  reports `suspended` + pushes a `checkpoint` artifact when a run leaves one.

**Residual (one deferred perf optimisation, not dangling work):**

- **Runtime memory page-sharing (memfd CoW).** Fork already shares the base RAM
  *file* read-only (copy-on-write at the file level) and diverges on the next
  suspend. Sharing live pages between *concurrently running* VMs via a private
  memfd is a deeper HVF memory-management optimisation — a documented perf
  ceiling, tracked for later; correctness and isolation are complete without it.

### M30 · Security hardening — hostile-agent readiness

**The immediate priority — it precedes M27.** Gimbal Local runs *untrusted*
compute (increasingly an autonomous coding agent) from an *untrusted* snapshot
bundle, on a personal Mac. A first security review found real gaps; M30 closes
them. Full model + plan: [`security-model.md`](security-model.md).

- **M30.1 (#33, P0) — shipped.** Bundle file isolation: reject symlinked disk
  bases + overlays, `O_NOFOLLOW` opens, a private `0700` overlay dir, and
  manifest relpath confinement in `materialize_bundle`.
- **M30.2 (#34, P0) — shipped.** Daemon socket hardening: private `0700` dir,
  `0600` socket, and a peer-uid (`getpeereid`) check before
  start/stop/console/shutdown. Follow-up #66 shipped: a pre-existing runtime dir
  is rejected unless the current user owns it, and self-owned dirs left too open
  are tightened back to `0700`.
- **M30.3 (#35, P0) — shipped.** App command safety: a pure, single-quoting
  `InteractiveTerminalCommand` builder that rejects control characters (the
  snapshot-name vector was already removed). Follow-up #67 shipped: the command
  is handed to `osascript` as an `argv` parameter, dropping the AppleScript
  string-literal escaping layer.
- **M30.4 (#36, P1) — verification shipped.** Ed25519 signed-manifest
  verification in `chm` (trust store via `CHM_TRUST_STORE`, key ids + rotation),
  fail-closed when configured, plus a `chm manifest keygen|sign|verify` reference
  signer. gctl producing + signing production manifests is the remaining
  cross-repo half (#36).
- **M30.5 (#37, P1) — shipped.** The **no host-FS-passthrough** invariant is
  explicit: a behavioural test proves virtio-fs/9p classify as `Unsupported`,
  and `make security-check` fails if host-FS wiring appears without review.
- **M30.6 (#38, P2) — shipped.** Per-sandbox resource limits: a launch
  gate (vCPU/mem ceiling) + a run-loop monitor that stops a runaway on disk
  overlay / console / wall-clock caps, plus NAT `max_connections` /
  `max_bandwidth_kbps` caps enforced on the egress datapath (over-limit SYN
  refused + audited; bandwidth throttled via token-bucket backpressure).
  Authored with `chm limits` and applied to new sandboxes by the app's sane
  global defaults.
- **M30.7 (#39)** — the threat model + hardening checklist (this doc set).
- **M30.8 (P0) — shipped.** CAS digest hardening: a manifest checksum is
  validated as a canonical sha256 hex digest before it is used as a
  content-store path, and every CAS object (including cache hits) is re-hashed
  before linking, so a tampered manifest cannot select or expose a host file.
- **M30.9 (P0) — shipped.** Egress enforced on **every** NIC (not just the
  first) and fail-closed: a governed session whose policy cannot be resolved
  denies all egress rather than booting open.

M30 is the *trust + isolation* layer beneath the feature pillars: even with **no**
policy, a bundle must not escape the host and the daemon must not be hijackable.
Its network item converges with M28's firewall enforcement (same datapath); its
signing item makes M26's displayed provenance cryptographically verified.

### M31 · Network host-isolation — the reserved-address boundary

**The new critical priority** (2026-07-16 adversarial review). M28/M30.9 built a
*policy* gate on egress, but the userspace NAT still relays a permitted flow
through a real host socket — so a guest can reach the **host's own networks**
(loopback, private LAN, link-local `169.254.169.254` metadata), reachable
**by default** (allow-all when no policy is bound; the app firewall ships off),
and bypassable in allow-list mode via **DNS rebinding**. This is a host-boundary
break even without filesystem access. Full findings + plan:
[`security-model.md`](security-model.md#m31--network-host-isolation--the-reserved-address-boundary).

- **M31.1 (P0, #75)** — reserved-address guard in the NAT: deny loopback / RFC1918 /
  link-local / other special-use ranges independently of the policy, re-check the
  *resolved* IP at connect (closes DNS rebinding), drop DNS answers resolving into
  reserved ranges, with an explicit opt-in for deliberate localhost access.
  **Shipped.**
- **M31.2 (P1)** — safe default posture: the app ships the firewall on in
  default-deny (allow-list) mode, so a new sandbox has no public egress until
  allow-listed (host/LAN always blocked by M31.1). **Shipped.**
- **M31.3 (P1)** — correct the overstated network docs to match enforcement.
- **M31.4 (P2)** — document the cloud/KVM path + external capture-harness
  boundary (security-model § "Out of scope" + the BYO capture runbook).
  **Shipped.**
- **M31.5 (P1)** — signing fail-closed default + digest recompute enforcement
  (folds into #36). **Posture shipped** (`CHM_REQUIRE_SIGNED`); gctl-signed
  production manifests are the remaining half.



Pillar ②'s deep, plane-coupled half:

- **`chm commit` / `push` / `pull`** (#7) — **shipped (core loop).** `chm push`
  commits a local checkpoint as a content-addressed revision on a branch (the
  plane dedups it into its CAS and advances the head); `chm pull` rehydrates a
  branch head (or explicit revision) back to a local resume. Proven live on the
  `:8080` dev plane: a re-commit of already-present content stored **0 bytes**.
- **Branch review + merge** (#7) — **shipped.** `chm branches review`/`merge`
  drive the plane's review gate (an unapproved source into a review-required
  target is refused; approve → merge); the app's Branches section has a review
  picker + a merge menu. Proven live: gate refused then merged after approval.
- **Page-range ACL honoring** (#7) — **shipped.** A scoped pull's out-of-scope
  chunk 403s; `chm state-cdn reconstruct` skips those pages (least-privilege
  image) rather than failing. Proven live: a page-0-only token → 1 fetched, 3
  ACL-denied.
- **Peer cache** (#7) — **shipped.** `chm state-cdn serve` runs a peer-cache HTTP
  server over the reconstructed (ciphertext) chunks and `register-peer` advertises
  it; the plane routes same-locality pullers here. Proven live: a peer served
  byte-identical chunks and a different locality fell back to origin. A peer
  serves opaque ciphertext without a token check, so ACL-restricted refs are
  sourced from origin (where the scope is enforced); peer scope-enforcement is a
  documented follow-up.
- **Postcopy memory plane** (#5) — **consumer shipped; demand-fault deferred.**
  `chm state-cdn reconstruct` pulls a checkpoint's encrypted, content-addressed
  RAM chunks from the state CDN, decrypts them (AES-256-GCM per-tenant), and
  reassembles the memory image — proven live decrypting real tenant chunks. It
  advertises `supports_offload_daemon`. True *demand-fault* postcopy (fetch only
  the touched working set) needs HVF stage-2 fault interception (no `userfaultfd`
  on macOS) and is the tracked next step — see
  [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md).
- **Disk plane**: lazy blocks over the same content-addressed store.

Back-compat means Gimbal Local always degrades to the M25 file-backed path, so it
is never *stuck* — just not yet demand-faulting the working set.

### M28 · Consistent sandbox controls — filesystem + network/firewall

Pillar ③ (#20) — **the product must-have, now planned:
[`network-policy-plan.md`](network-policy-plan.md).** The plane authors a
per-sandbox `SandboxPolicy` (egress allow/deny + fs read/write scopes + mounts),
content-addressed so it teleports *with* the session; every `assign-run`/resume
carries the compiled `enforcement.chm_profile` + `policy_digest`. Gimbal Local is
**one of the two enforcers**.

**The key realisation:** `chm` already mediates 100% of the guest's network (one
`NetResponder` seam; no tap/bridge/host route). Replacing the current echo stub
with a **userspace NAT** — a TCP/IP stack that relays the guest's flows through
host sockets `chm` opens — makes networking *real* **and** makes enforcement
*authoritative* in one stroke: because `chm` is the process that dials,
default-deny is literally "don't open the socket," and the guest has no path
around us. Same model as gVisor/slirp/passt.

Staged: **M28.1** policy plumbing + digest teleport (#49, no datapath change,
shipped) → **M28.2** userspace egress NAT (#50, the hard engine work — shipped:
real IPv4 TCP + DNS through a smoltcp NAT, proven by an in-CI relay test) →
**M28.3** the allow-list gate at DNS + TCP-connect (#51, shipped: the verified
`chm_profile` teleports through `CHM_EGRESS_POLICY` into the NAT, which refuses
unlisted DNS names and TCP connects and logs each denial) → **M28.4** the demo +
teleport proof (#52, shipped: two scripted hardware proofs — a default-deny
allow-list refused at BOTH the DNS gate and, for a hardcoded IP, the TCP-connect
gate; and `chm policy bind` bringing a plane-authored policy down so the cloud's
digest governs a local sandbox and names every audited denial) → **M28.5** fs scopes (#53, shipped: requested host mounts
are refused loudly — no host-FS passthrough — and reported to the plane). The
demo it must land: the plane sets *allow-list only for sandbox N*, it follows the
sandbox down, and the guest **provably can't get out** except to the allow-list.
**That demo now runs, on real hardware, from a script.** The net-enabled capture
that used to block it exists (`GUEST_NET=1` in the capture harness), so
`scripts/hvf/egress-allowlist-demo.sh` and `scripts/hvf/policy-teleport-demo.sh`
prove enforcement and the digest teleport end-to-end on a rehydrated stock ITS
snapshot. See [`networking.md`](networking.md) for the runbook.

### M29 · Observability & cost — logging, insights, both sides

Pillar ④. **Local audit trail shipped:** every sandbox writes a durable,
append-only `audit.jsonl` (session start/stop with shape + outcome, denied
egress flows, and bundle-verify decisions), readable with `chm audit show`, so an
operator can review what a sandbox did independent of the guest-floodable
console. The remaining half is the shared telemetry/cost contract: local
sandboxes emit the **same** structured usage events (cpu-seconds, wall-time,
memory, bytes faulted) through the runner's report-state / push-artifacts path,
so insights and cost accounting are uniform regardless of where a session ran.
The app already reads the plane's read-only cost/health panel; the rest waits on
the gctl telemetry/cost event contract.

### M32 · Agent workloads + benchmark vs Docker (#76)

With the local runtime and host-isolation complete, the next thrust is putting
**real agents/workloads to work inside gimbal microVMs** and measuring how the
platform compares to the incumbent (Docker Desktop's Linux VM) on the same Mac.

- **M32.1 — agent workload readiness.** Prove a representative dev/agent loop runs
  end to end inside a gimbal sandbox: clone a repo, install deps, build, run
  tests, and (nested) `docker build` inside the guest. Shake out anything the
  guest image lacks (container runtime, disk headroom, DNS/egress allow-list for
  package registries under the new default-deny). This is the "actually put an
  agent to work" proof.
- **M32.2 — benchmark vs Docker sandboxes. Harness shipped + first result
  recorded (`scripts/bench/`, `RESULTS.md`).** A reproducible harness runs the
  **same** inner workload inside a Docker Desktop container and a gimbal microVM
  on the same Mac, N trials, and aggregates to markdown with mean ± stddev + a
  gimbal/Docker ratio. The gimbal side runs the workload inside the stock demo
  snapshot via a PTY-driven integration test (`microvm_xz_benchmark`), so it
  needs no special snapshot. **First real result (Apple M3, matched 1 vCPU / 1
  GiB, single-threaded `xz` compression):** gimbal 23.67 ± 0.82 s vs Docker
  23.17 ± 0.83 s — **gimbal is 1.02x Docker (~2% slower, within noise)**, at or
  better than the ~1.03–1.09x microVM prior-art band. Warm-checkpoint resume +
  teardown adds only ~5 s.
  - *Two findings surfaced:* the stock demo guest has **no C toolchain** (so a
    real compile benchmark needs a toolchain-provisioned snapshot, M32.1), and a
    **post-CPU-burst input wedge** where a second command after a long silent
    compute does not wake the parked vCPU (filed as #78; the benchmark runs each
    trial in a fresh session to sidestep it).
  - *Still future:* multi-vCPU / parallel builds, and IO/network-heavy workloads
    (where microVMs historically lose ~17–20%) to exercise the CoW overlay + NAT.

**On the "snapshot dependency":** gimbal only *rehydrates a snapshot* — there is
no boot-from-scratch path — so the microVM you build in **is** a snapshot; it is a
one-time "provision a Docker/toolchain guest, then capture it" step (local-doable
on a KVM host), not an external blocker. If the build inputs are **baked into the
guest image**, the build runs **offline** and needs no network / net-enabled
snapshot (#52); network is only needed for realistic pull-at-build-time runs.

Both parts are local-doable and do not depend on the control plane. They also
stress the security posture (egress allow-list vs. registries; disk/console caps
vs. real builds), so they double as end-to-end validation of M30/M31.

---

## Standing platform boundaries

- **R1 — ITS/LPI is no longer a wall; it is a solved problem with one gap.**
  Apple's *managed* GIC (`hv_gic`) delivers message-based SPIs only, with no
  ITS/LPI path. The **userspace GICv3** (M-USGIC) removes that limit: a stock
  ITS/LPI capture rehydrates onto a software GIC that delivers LPIs, with disk,
  net, SMP and checkpoint/resume all hardware-proven. **Vanilla is now the
  recommended capture shape.** The remaining gap is that `chm serve` has not been
  wired to it yet (#102), so the daemon still requires a `gicv2m-message-spi`
  capture. See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md).
- **Counter frequency is a hard, unfixable-at-restore part of the compatibility
  contract.** A guest caches `CNTFRQ_EL0` at boot and never re-reads it. Apple
  presents HVF guests **24 000 000 Hz** and offers no way to change it —
  `hv_vcpu_set_vtimer_offset` sets an *offset*, never a *rate*. **Measured
  2026-07-28:** an AWS Graviton2 guest (`121 875 000 Hz`) resumed on Apple silicon
  runs **5.08× slow** in wall-clock terms — correct, self-consistent, and living
  in dilated time. It presents as sluggishness, not as a clock fault, which makes
  it the most dangerous failure mode we have. The HVF path does not yet check
  (#104). See [`graviton-acid-test-results.md`](graviton-acid-test-results.md) §4
  for every mitigation considered and why each one is or is not available.
- **arm64 KVM capacity.** Producing real snapshots needs a genuine arm64 `/dev/kvm`
  host (a Lima nested-KVM guest for $0, or Graviton bare metal); the Mac itself
  can only *run* snapshots, never capture them.

---

## How this is tracked

Progress lives in the
[GitHub issues](https://github.com/gimbal-dev/gimbal-local/issues), mapped to the
V1–V4 spine:

| Milestone | Issues |
| --- | --- |
| V1.2 counter-frequency guard | ~~#104~~ shipped |
| V1.3 counter-rate synthesis | ~~#108~~ shipped |
| V1.5 the acid test | ~~#105~~ passed |
| V2.1 `chm serve` + userspace GIC | ~~#102~~ shipped |
| V2.2 the app on vanilla | ~~#114~~ shipped |
| V2.3 retire the forcing env var | ~~#115~~ shipped |
| V3 cloud contract / signing / postcopy | #21, #36, #5 |
| V4 security umbrella / defaults | #39, #20 |
| Deferred | #101 (cold create), #4, #6 |

The four pillars remain the capability contract (#21); a pillar is only "done"
when it holds for a **vanilla** snapshot on both substrates.

### What comes next (2026-07-29)

**V1 and V2 are both complete.** The acid test passed, the frequency question is
answered and fixed, and a vanilla capture now runs through the CLI, the daemon
*and* the app with no flags and no environment variables. The engineering
problem that defined this project — *can a cloud snapshot cross to a Mac at all*
— is answered yes, on hardware, three times over.

**The centre of gravity therefore moves from the hypervisor to the product.**

1. **V3 is the thrust, and V3.1 is the gate.** `gctl` still 422s an `assign-run`
   on `gic_mode: its-lpi`, which now refuses bundles we demonstrably run. Until
   that changes, the cloud→Mac loop is only closed by hand. This is cross-repo
   and is the single highest-leverage unblock available.
2. **#101 — there is no cold create-from-image path.** Every start is a full
   snapshot rehydrate. That is fine for the rehydrate story and wrong for a
   product: a user with an image and no snapshot cannot start anything. Needs a
   shape decision before it needs code.
3. **V4.1/V4.2 — the security umbrella (#39, #20).** Most of the mechanism is
   already shipped (egress allow-list, reserved-address guard, CoW isolation,
   limits, signing). What is missing is the threat model that says which of them
   are *on by default* and why. A rehydrated snapshot is untrusted code with a
   device model attached.
4. **V1.6 — round-2 capture.** Blocked on gimbal cloud. Needs the corrected
   version pin (`69637dde6` or later, for the clock block), capture *after*
   cloud-init finishes (round 1 fires mid-cloud-init, so the guest restarts its
   getty ~113 s after resume and swallows input in that window), `CNTFRQ_EL0`
   reported per instance type (Graviton3/4 unverified), and capture **B**
   (2 vCPU + net), which round 1 did not produce.
