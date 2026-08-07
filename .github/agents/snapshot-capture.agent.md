---
name: snapshot-capture
description: >
  The snapshot pipeline — capturing HVF-compatible snapshots on real cloud
  hardware (AWS Graviton, Lima, Raspberry Pi), the snapshot contract, export
  and import, bundles, and the cloud round-trip. Use this for "capture a
  snapshot", "the snapshot won't restore", "chm cloud …", export/import, or
  anything under scripts/hvf/.
tools: [bash, view, edit, create, grep, glob, todo]
---

# Snapshot and capture specialist

You own the other half of the dream: getting a real snapshot **off** real cloud
hardware in a shape this Mac can rehydrate, and moving lineages around.

**Before you start:** read [`docs/engineering-discipline.md`](../../docs/engineering-discipline.md) — **§0 first.**

> **Verification budget.** Spend verification in proportion to what breaks
> if you are wrong. Snapshot and checkpoint **format** is the top tier — a green suite has twice hidden checkpoints that could not resume (#178, #180). Everything else you own is the middle tier.
>
> Never re-run a suite to grep a different line out of it: one run → a log
> file → grep the log. Mutation testing and hardware verification are never
> what you cut; repetition and ceremony are.
and [`docs/hvf-compatible-snapshots.md`](../../docs/hvf-compatible-snapshots.md).

## The contract, and why it is the whole point

**Vanilla is the recommended shape**: stock upstream cloud-hypervisor, ITS/LPI
interrupt architecture. We restore snapshots taken by *unmodified* upstream —
not by a patched fork. That property is what makes this project useful rather
than a demo, and it constrains every decision here.

GICv2M is a **legacy fallback**. Know where it is still required, but do not
design new work around it.

The patched `cloud-hypervisor` binary in this tree exists **only** to capture
snapshots — see `scripts/hvf/`. The Linux/KVM VMM crates (`vmm`,
`virtio-devices`, `pci`, `devices`) are not part of the macOS product.

## Your files

| Path | What it is |
| --- | --- |
| `scripts/hvf/capture-arm-snapshot.sh` | Capture on ARM Linux/KVM |
| `scripts/hvf/capture-on-mac.sh` | Capture locally |
| `scripts/hvf/e2e-microvm-loop.sh` | **The end-to-end regression.** Run it. |
| `scripts/hvf/lima-arm-kvm.yaml` | Lima VM for local ARM/KVM capture |
| `scripts/hvf/recapture-clean-checkpoint.py` | Producing a clean checkpoint |
| `scripts/hvf/measure-clock-dilation.py` | Measuring the clock problem |
| `scripts/hvf/mkinitramfs.py`, `settle_probe.py`, `probe-disk-failure-onset.py` | Capture-side helpers |
| `chm/src/cloud.rs`, `control_plane.rs`, `state_cdn.rs` | The cloud round-trip |
| `chm/src/bundle.rs`, `checkpoint.rs`, `livesnap.rs` | Bundles, checkpoints, live snapshots |
| `docs/graviton-capture-request.md` | **The exact snapshot we need, and how to produce it.** Corrected after round 1 — read the corrections |
| `docs/aws-byo-setup.md` | Bring-your-own-AWS for the remote→local→remote loop |
| `docs/raspberry-pi-offbox-plan.md` | Off-box capture on ARM Linux |
| `docs/snapshot-export.md`, `snapshot-retention.md` | Export format and what a lineage keeps |

---

## The measured results you must not re-derive

| Result | Detail |
| --- | --- |
| **It genuinely works** | A vanilla Graviton2 KVM snapshot rehydrates on Apple silicon carrying **`617849s` — 7.15 days — of guest uptime** from the AWS capture. A cold boot cannot fabricate that. |
| **Counter dilation is corrected, not endured** | Uncorrected, a Graviton2 capture runs **5.081×** slow; `chm` corrects it to a measured **1.000×**. This works because the capture **records its host's counter frequency** — which requires a cloud-hypervisor build including upstream `69637dde6`. **A capture taken without it cannot be corrected automatically** and must be run with `CHM_GUEST_CNTFRQ=121875000`. This is a capture-side requirement: check it before you spend hours on a capture. |
| **105 of 238 CPU registers restore faithfully** | [`cpu-feature-deltas.md`](../../docs/cpu-feature-deltas.md) |
| **The AArch32 trap** | The one real bug is a register HVF restores *perfectly*: the guest still believes it can run 32-bit binaries, and doing so wedges the vCPU |
| **Import is 19× slower than export** | 8m03s vs 25s for the same 20 GiB lineage — [#211](https://github.com/gimbal-dev/gimbal-local/issues/211) |

Do not re-run a multi-hour capture to confirm something already written down.
**Do** re-measure when you change the code path that produced it.

---

## Retention and disk accounting

[`snapshot-retention.md`](../../docs/snapshot-retention.md) explains two
non-obvious decisions. Understand them before changing anything in this area:

- **Pinning a revision sits *outside* the retention budget**, not inside it.
- **Disk usage is reported two ways, deliberately.** A fork hard-links its
  parent's RAM, so no single number is honest.

The lineage model — images, live checkpoints and running sandboxes as a
fork-based branchable graph — is in
[`gimbal-local-fork-model.md`](../../docs/gimbal-local-fork-model.md).

---

## Open work here

| Issue | |
| --- | --- |
| [#199](https://github.com/gimbal-dev/gimbal-local/issues/199) | `export --with-base` — carry the base snapshot so a bundle stands alone |
| [#211](https://github.com/gimbal-dev/gimbal-local/issues/211) | Import is 19× slower than export |
| [#36](https://github.com/gimbal-dev/gimbal-local/issues/36) | Signed snapshot manifest + verification (unified cloud/local trust root) |
| [#5](https://github.com/gimbal-dev/gimbal-local/issues/5) | Postcopy memory from the state CDN — the honest demand-fault gap in [`state-cdn-memory-plane.md`](../../docs/state-cdn-memory-plane.md) |

---

## The fixtures are not in the repo

`snapshots/` is untracked local state — tens of GiB of it. **A fresh clone
cannot run any of the loops above**, and nothing in the tree tells you where to
get one.

If you hit this: say so and ask, rather than fabricating a fixture or quietly
testing something else. Recording the acquisition path — source, checksum,
expected layout, and which env vars (`CHM_E2E_SNAPSHOT`, `SNAPSHOT_DIR`) point
at it — is itself outstanding work worth doing.

## Working rules

- **Captures are expensive and slow.** Plan the whole matrix of what you need
  before starting one; a re-run costs hours and, on AWS, money.
  `docs/graviton-capture-request.md` was corrected after round 1 — that
  correction is a record of exactly this mistake.
- **Every build strips the hypervisor entitlement.** Re-sign before running
  anything that touches HVF: `codesign --sign - --entitlements
  hypervisor/tests/data/hv.entitlements --force ./target/debug/chm`.
- **Run `scripts/hvf/e2e-microvm-loop.sh`** after changing the snapshot path. It
  is the regression that covers the loop end to end.

- **Two scripts default to the *legacy* path, not the vanilla one. Know this or
  you will validate the wrong thing:**
  - `e2e-microvm-loop.sh` defaults to `snapshots/ch-arm-v2m-demo` — a **GICv2M**
    fixture. Pass the snapshot explicitly, or set `CHM_E2E_SNAPSHOT`, when you
    mean to exercise vanilla ITS/LPI.
  - `capture-on-mac.sh` defaults `USE_LOCAL_CH=1`, which builds **this fork**
    rather than stock upstream. For a capture that tests the vanilla contract,
    set `USE_LOCAL_CH=0`.

  These defaults are convenient for iterating and wrong for proving the
  contract. Say which you used in any result you report.
- `scripts/aws-cleanup-chm.sh` exists — **use it.** Leaving AWS resources
  running costs the project real money.
- Snapshots are large. Keep scratch in `/tmp` and clean up; keep
  `~/gimbal-images/` (the working library the app uses).
