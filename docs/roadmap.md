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
| Guard rails | M13, M19 | A load-time guard rejects ITS/LPI snapshots HVF cannot deliver (boundary **R1**); stock ITS/LPI routing was researched and confirmed a hard platform limit. |

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

## Milestones remaining (against the vision)

| Milestone | Pillar | Status | Issues |
| --- | --- | --- | --- |
| **M25 · Live local lifecycle** | ① | **Complete** (one perf ceiling: runtime memfd page-sharing) | #4, #6 |
| **M30 · Security hardening** | trust/isolation | **P0s + no-FS guard shipped** (#33–#35, #37; CAS digest M30.8 + multi-NIC fail-closed M30.9); signing (#36) + limits (#38) next | #33–#39 |
| **M27 · Plane-native edge** | ② | **push/pull shipped** (#7 core); postcopy memory + disk plane next (#5) | #5, #7 |
| **M28 · Consistent controls** | ③ | **M28.1–M28.3 + M28.5 shipped** (policy plumbing + digest teleport; userspace egress NAT; allow-list gate at DNS + TCP-connect; fs mount refusal); enforced on every NIC + fail-closed (M30.9). Live demo (#52) blocked only on a net-enabled snapshot. | #20, #52 |
| **M29 · Observability & cost** | ④ | Waits on the gctl telemetry contract | — |

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
- **M31.2 (P1)** — safe default posture (guard-on floor; app default-deny for
  untrusted sessions).
- **M31.3 (P1)** — correct the overstated network docs to match enforcement.
- **M31.4 (P2)** — document the cloud/KVM path + external capture-harness boundary.
- **M31.5 (P1)** — signing fail-closed default + digest recompute enforcement
  (folds into #36).



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
teleport proof (#52) → **M28.5** fs scopes (#53, shipped: requested host mounts
are refused loudly — no host-FS passthrough — and reported to the plane). The
demo it must land: the plane sets *allow-list only for sandbox N*, it follows the
sandbox down, and the guest **provably can't get out** except to the allow-list.
**Remaining before the live demo: a net-enabled snapshot** — every capture in the
corpus was taken without `--net`, so the capture path needs a virtio-net device
before guest egress can be exercised end-to-end on real HVF.

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

---

## Standing platform boundaries

- **R1 — ITS/LPI (permanent).** Apple's managed GIC (`hv_gic`) delivers
  message-based SPIs only, with no ITS/LPI path. A snapshot is only restorable on
  HVF if it was captured `gicv2m-message-spi` (`CH_GIC_V2M=1`); stock ITS/LPI
  snapshots are refused, at load time locally and at the `assign-run` 422 gate.
  See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md).
- **arm64 KVM capacity.** Producing real snapshots needs a genuine arm64 `/dev/kvm`
  host (a Lima nested-KVM guest for $0, or Graviton bare metal); the Mac itself
  can only *run* snapshots, never capture them.

---

## How this is tracked

Progress lives in the
[GitHub milestones](https://github.com/gimbal-dev/gimbal-local/milestones)
`M25`–`M30`, one per remaining capability, with the cross-repo handoff issues
above. **M30 (security hardening) is the immediate priority and precedes M27.**
The four pillars are the V0 capability contract (issue #21); each pillar is
only "done" when it is enforced identically on both substrates.

### What comes next (crisp view, 2026-07-16)

- **Security — the new #1 (M31.1, P0):** a **reserved-address egress guard**. The
  NAT relays through host sockets, so a guest can currently reach loopback / LAN /
  `169.254.169.254` by default — a host-boundary break found by the 2026-07-16
  review. Deny special-use ranges independently of policy, re-check resolved IPs
  (closes DNS rebinding), and fix the overstated network docs. This precedes
  further feature work.
- **Security (also open):** M30.4 signed manifest + trust root (#36, P1) —
  `chm` verification ships; gctl signing + a fail-closed default (M31.5) is the
  remaining half. Distribution notarisation is still unchecked.
- **Demo gap:** the live in-guest firewall demo (#52) is blocked only on a
  net-enabled snapshot; authoring + enforcement already ship. A cloud-side
  capture-capability request is filed (`gimbal-cloud-control#4`).
- **Cross-repo (CP) handoffs:** #4/#5/#6 (checkpoint/postcopy/fork phases),
  #20 (policy plane), #21 (V0 pillar alignment).
- **Recently shipped + closed:** interactive console freeze (#60), CAS digest
  hardening (#64) + per-NIC fail-closed egress (#65), disk-overlay rollback (#62)
  + live engine/revision UI (#61/#69), durable session registry (#71), resource
  limits + NAT caps (#38), the #66/#67 security follow-ups, and the M29 audit
  trail.
