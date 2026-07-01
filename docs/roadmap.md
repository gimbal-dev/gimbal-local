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

### Live local lifecycle primitives

- **Suspend / resume** — `chm resume` restores a live checkpoint; a suspend
  captures a memory + device + fs checkpoint on idle and on graceful stop
  (checkpoint-everywhere).
- **Fork lineage** — `chm fork` branches a revision (Image → Revision → Sandbox,
  where *suspend = commit* and *fork = branch*); see
  [`gimbal-local-fork-model.md`](gimbal-local-fork-model.md).

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
| **M25 · Live local lifecycle** | ① | Core shipped; app/engine polish advanceable now | #4, #6 |
| **M27 · Plane-native edge** | ② | Waits on gctl (memory plane shipped; disk plane + fork/commit building) | #5, #7 |
| **M28 · Consistent controls** | ③ | Waits on the gctl policy contract | #20 |
| **M29 · Observability & cost** | ④ | Waits on the gctl telemetry contract | — |

### M25 · Live local lifecycle — suspend · resume · fork

The Mac runs, suspends, resumes, and forks microVMs entirely locally. The
primitives are shipped (see above); the remaining work is product polish, all
advanceable **now with zero plane changes**:

- Per-sandbox workspaces so **N concurrent forks** run truly isolated.
- The **fork-tree / lineage view** in the app (the model exists; the UI does not).
- A local **revision store + rollback** (history under `.chm-revisions/`).
- A private **memfd overlay** for true copy-on-write base RAM.
- Drive `suspended` / `resuming` states and push `kind:"checkpoint"` artifacts;
  advertise `supports_fork` / `supports_cow_overlay`.

### M27 · Plane-native edge — branching filesystem + lazy load

Pillar ②'s deep, plane-coupled half:

- **Postcopy memory plane** (#5): run the offload daemon beside `chm`, launch with
  shared-memfd + `memory_mode=postcopy` on resume, demand-fault memory pages from
  the state CDN (the control-plane side is shipped).
- **Disk plane**: lazy blocks over the same content-addressed store.
- **`chm commit` / `push` / `pull`** (#7): a local overlay becomes a new content-
  addressed revision/branch pushed to the CDN, plus peer-cache serving.

Back-compat means Gimbal Local always degrades to the M25 file-backed path, so it
is never *stuck* — just not yet demand-faulting or pushing revisions.

### M28 · Consistent sandbox controls — filesystem + network/firewall

Pillar ③ (#20). The plane authors a per-sandbox `SandboxPolicy` (egress
allow/deny + filesystem read/write scopes + declared mounts), versioned and
content-addressed so it teleports *with* the session; every `assign-run` / resume
carries `policy` + `policy_digest`. Gimbal Local is **one of the two enforcers**:
it applies egress and fs-scoping on the Mac network + block path and reports
allowed/denied decisions as audit events. MVP is deliberately small — a
destination allow/deny list and read-only vs read-write path scopes — not full
role management or per-page ACLs. This needs the canonical policy contract from
gctl before it can be built.

### M29 · Observability & cost — logging, insights, both sides

Pillar ④. Local sandboxes emit the **same** structured logs + usage events
(cpu-seconds, wall-time, memory, bytes faulted) through the runner's
report-state / push-artifacts path, so insights and cost accounting are uniform
regardless of where a session ran. The app already reads the plane's read-only
cost/health panel; the rest waits on the gctl telemetry/cost event contract.

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
`M25`–`M29`, one per remaining capability, with the cross-repo handoff issues
above. The four pillars are the V0 capability contract (issue #21); each pillar is
only "done" when it is enforced identically on both substrates.
