# Gimbal Local: snapshots, checkpoints, and the fork model

**Status:** Design spec (living) · **Date:** 2026-06-30

This spec defines how Gimbal Local models the relationship between images,
live checkpoints, and running sandboxes — and how that model grows into a
**fork-based, branchable lineage** of live compute, the local edge of the
control plane's revision graph.

It pairs two inputs:

- **gimbal-cloud-control** phases — Phase 1 *suspend/resume* (live checkpoints,
  `kind: checkpoint`, `parent_snapshot_id` lineage), Phase 3 *fork + CoW
  overlays + wake-on-traffic*, Phase 4 *commit/push/pull revisions* (see the
  cross-repo handoff issues #4, #6, #7).
- **The Mesa/Drives model** — a versioned object graph with parent pointers,
  cheap branches for parallel agents, durable-on-death state, and sparse
  materialization. "Git for live compute": a snapshot is a commit; a fork is a
  branch.

The throughline: **a microVM's state is a value in a content-addressed history,
not a mutable blob.** Stopping a sandbox doesn't destroy it — it commits a
revision. Forking it is branching. The local Mac is an edge node of that graph.

---

## 1. Object model

Three entities. Today the UI conflates the first two; this spec separates them.

### Image (a base)
An immutable base filesystem + boot state — a `ch-snapshot` directory captured
from a cloud VM or built from a container (`source_kind = container`, Phase 0).
It is the **root of a lineage**. Identified today by name; in future by content
digest so identical bases dedupe across the cache.

> Code today: `SnapshotSummary` (`name`, `path`, `vcpus`, `ramMib`).

### Revision (a checkpoint / commit)
An immutable, point-in-time **live state** — guest RAM + vCPU + interrupt
(GIC) + device + filesystem delta — captured by suspending a sandbox. A
revision is **restored, not cold-booted**. Every revision has:

- `id` — stable identifier (content-addressed in the limit; a ULID today);
- `parent` — the Image *or* Revision it descends from (the lineage edge);
- `created_at`, `origin_sandbox`, optional `label`/`message`;
- the payload: `checkpoint.json` (vCPU + GIC state) + `memory-ranges` (RAM dump)
  + the CoW disk overlay delta.

Revisions form a **DAG** (a tree in the common case): a chain when a sandbox is
suspended repeatedly, a branch when several children fork from one parent.

> Code today: the `.chm-checkpoint/` directory produced by `chm --checkpoint`.
> This spec adds the lineage header (`id`/`parent`/`created_at`).

### Sandbox (an instance)
A **running or suspended instance** bound to a `base` (an Image or a Revision)
and a `location` (local HVF guest, or remote via the control plane — an
implementation detail). A sandbox *produces* revisions when it suspends and
*consumes* a revision when it resumes or is forked.

> Code today: `Sandbox` / `StoredSandbox`.

---

## 2. Lineage: suspend is commit, fork is branch

```
Image  ubuntu-24.04 ──┬─ rev A (boot+apt) ──┬─ rev A1 ── rev A2     [sandbox "build"]
                       │                     └─ rev A3              [sandbox "experiment" — forked from A]
                       └─ rev B (cuda)         …
```

- **Suspend** a sandbox → append a child Revision whose `parent` is the
  sandbox's current base (its last revision, or the Image on first stop). The
  sandbox's history is the chain of its revisions.
- **Resume** a sandbox → start from its latest Revision (restore, not boot).
- **Fork** a Revision (or a live sandbox's current state) → start a **new**
  sandbox whose `base` is that Revision, sharing the parent's RAM + disk via
  copy-on-write so children diverge cheaply. This is the branch point in the
  DAG — `N` children, one shared parent (Phase 3 `POST /sandboxes/{id}/fork`).

The **fork is the general case; single-session resume is the N=1 fork.** Build
the model fork-first so resume is just a fork that reuses its own lineage.

---

## 3. Checkpoint everywhere

A revision is committed on **every clean stop, from every surface** — there is
no "throwaway stop." Concretely, all of these capture a checkpoint:

- the interactive `chm connect`/`chm resume` session ending (window close,
  Ctrl-A x, idle, max-seconds) — **done**;
- the daemon (`chm serve`) stopping a sandbox on request (the app's **Stop**
  button) — **this change**;
- a future explicit `chm commit` / app "Save revision" (Phase 4).

A guest-initiated power-off or a crash does **not** commit (the box is done);
it clears the checkpoint so the next start cold-boots. Suspend-on-idle (commit
when the box goes quiet) is the natural extension.

---

## 4. On-disk format (with lineage)

A revision lives in the parent snapshot directory so it is co-located with the
base it deltas:

```
<image_dir>/
  state.json                 base device + memory layout (carried unchanged)
  snapshot/memory-ranges      base RAM (cold-boot source)
  .chm-overlays/              live CoW disk overlays (+ .bitmap) per sandbox
  .chm-revisions/
    <revision-id>/
      manifest.json           { id, parent, created_at, origin, label, state_ref }
      checkpoint.json         vCPU + GIC live state (hypervisor CheckpointState)
      memory-ranges           live RAM dump (parent's region layout)
      disks/                  the CoW overlay delta for this revision
    HEAD                      the current revision id per sandbox
```

Today's single `.chm-checkpoint/` is the **N=1, HEAD-only** case of this layout.
Step one is to give checkpoints a `manifest.json` lineage header; step two is to
key them by revision id under `.chm-revisions/` so history and forks coexist.

> Memory is the expensive part (a full RAM dump per revision). The same sparse/
> CoW direction the control plane takes (Phase 2 CDN memory plane, Phase 3
> private memfd overlay) applies locally: future revisions store only touched
> pages over a shared base, not a fresh 1 GB each. The lineage header is the
> hook that makes that dedup addressable.

---

## 5. UI: the lineage view

Gimbal Local gains a **lineage** surface that makes the graph first-class:

- **Snapshots page** already lists Images. Each Image expands to its **revision
  tree** — revisions as nodes, parent→child as edges, branches where a revision
  has multiple children. The current `HEAD` of each sandbox is highlighted.
- A revision node shows: label, age, origin sandbox, size, and actions —
  **Resume here**, **Fork**, **Make HEAD** (rollback), **Delete**.
- A sandbox shows its **base** (which Image/Revision it runs from) and, when
  suspended, its **latest revision**.
- Local vs remote stays a small badge; the graph is identical for both.

This view is built now even though forks aren't user-creatable yet: with one
revision per sandbox it renders a simple Image→Revision chain, and it is ready
to render branches the moment fork lands. Prepping the surface early means the
fork feature is a data change, not a UI rebuild.

---

## 6. Alignment with the control plane

| Gimbal Local | Control plane (gimbal-cloud-control) |
|---|---|
| Image | snapshot `kind: full` (+ `source_image` provenance, Phase 0) |
| Revision | snapshot `kind: checkpoint` + `parent_snapshot_id` (Phase 1) |
| Suspend → commit revision | `POST /sandboxes/{id}/suspend` → checkpoint artifact |
| Resume from revision | `assign-run kind: resume` + `checkpoint_ref` |
| Fork a revision | `POST /sandboxes/{id}/fork` → child revision (Phase 3) |
| Lineage DAG (this doc) | revision graph + `parent_snapshot_id` lineage |
| `chm commit`/push (future) | revision commit/push/pull + branches (Phase 4) |

A local revision is byte-compatible with what the plane would push/pull, so the
Mac is a real edge of the same graph — suspend locally, resume in the cloud (or
on another Mac), fork either side.

---

## 7. Phased implementation

1. **Checkpoint everywhere + lineage header** *(this change)* — daemon Stop
   commits a revision; every checkpoint carries `{ id, parent, created_at,
   origin }`. UI lineage view renders the Image→Revision chain.
2. **Revision store** — key revisions by id under `.chm-revisions/`, keep
   history (not just HEAD), add Resume-here / rollback (Make HEAD).
3. **Fork** *(landed: data layer + UI)* — `chm fork <SRC> <DST>` / the app's
   "Fork this revision" button create a new snapshot that shares the parent's
   immutable base (symlinked) and diverges from a copy of its live checkpoint +
   disk overlays, re-parented in the lineage; the graph branches. (Phase 3
   parity.) Next: per-sandbox workspaces so N forks of one image coexist without
   colliding on the shared `.chm-checkpoint`/`.chm-overlays`, and running forks
   concurrently.
4. **Sparse revisions** — store only touched memory pages + disk blocks per
   revision over a shared base; wire the offload daemon / memfd overlay so a
   revision is cheap. (Phase 2/3 parity.)
5. **Commit/push/pull** — name revisions, push to / pull from the control
   plane; the Mac becomes a CDN edge. (Phase 4 parity.)

The boundary stays sharp: **the revision graph is durable live-compute state;
Git stays the source of truth for code.** A revision can pin the repo SHA that
produced it, and vice-versa — one coherent, reproducible workspace.
