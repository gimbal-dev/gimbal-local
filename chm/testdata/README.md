# Frozen on-disk fixtures

These are **real artifacts**, copied verbatim off a working machine. Nothing in
this build can rewrite them.

They exist because every other checkpoint test writes its input with the same
code that reads it back. The pair agrees *by construction*, so a change to the
on-disk **format** moves both sides at once and is invisible to the suite.

That blind spot is not hypothetical. A change that stopped fingerprinting
`.bitmap` sidecars shipped with a green suite and made **every checkpoint
already on disk** refuse to resume, each one reporting an error that blamed the
user's disk.

| File | What it is | What it guards |
| --- | --- | --- |
| `manifest-v1-usgic-smp.json` | A real 2-vCPU userspace-GIC checkpoint manifest | A field added to `Revision` without `#[serde(default)]` stops this parsing |
| `manifest-v1-pre-smp.json` | The pre-SMP state shape: no `host_realtime_ns`, `usgic` or `usgic_cpus` | Those additive fields keeping their defaults |
| `overlay-fingerprint-pre-v9.6` | A real fingerprint carrying a `.bitmap` line | The exact format that #178 could no longer read |
| `checkpoint-dir-shape-v1` | The directory listing of a real checkpoint, and of a real pruned revision | The set of files a checkpoint *is* — a sidecar added, or `overlay.fingerprint` dropped |
| `vanilla-state-2cpu-net.json` | A **vanilla upstream Cloud Hypervisor** `state.json`, captured on AWS Graviton2: 2 vCPU, a NIC, 11 devices | That `chm` can write one back that upstream still understands |
| `vanilla-state-graviton-{1,2,3,1cpu}.json` | Four more real captures, 1 vCPU, no NIC | The same, across machine shapes we cannot produce here |

## The vanilla captures are an oracle, not a sample

These five are the sharpest fixtures in this directory, and for a reason the
others cannot claim: they were authored by **upstream Cloud Hypervisor on
hardware this project does not have**. A Mac cannot capture one — that needs
KVM — so no bug in this tree can have influenced their contents.

That matters because `chm` is about to start *writing* `state.json` rather than
only reading it (#353, #341), and a writer built beside a reader is exactly the
by-construction agreement described above. Round-tripping a document nobody
here wrote is the one check with independent authority.

They are **committed** rather than swept out of a scratch directory. An earlier
draft read them from `/tmp`, which meant the gate silently narrowed to a single
document on any machine that had been rebooted — coverage that disappears
without saying so is worse than coverage you never claimed.
`the_oracle_is_not_quietly_missing` pins the count for that reason.

Audited before committing: across all five, the only strings are PCI addresses,
device names, memory-region kinds and two disk filenames. No hostnames, no
paths, no credentials.

## Why a shape fixture, when the writer is already shared

`write_test_checkpoint` calls `commit_checkpoint`, the same function the
product calls, so the test writer can no longer **drift** from the real one.
That is necessary and it is not sufficient: sharing means a layout change moves
**both** sides in one commit, and the suite stays green while every checkpoint
on a user's disk stops being understood.

Measured rather than assumed — adding a single sidecar file to `write_checkpoint`
left **all 514 tests passing**. `checkpoint-dir-shape-v1` is the outside opinion
that catches it, because no code in this build produced it.

The two guards cover different things and neither subsumes the other:
re-mirroring the test writer produces identical file names, so the shape fixture
stays green — that one is caught by `the_test_writer_shares_the_product_writer`,
which reads the source rather than an outcome.

**Do not regenerate these to make a test pass.** A failure here means *"this
change breaks checkpoints that already exist"*. If the format genuinely must
change, the answer is a migration and a `REVISION_MANIFEST_VERSION` bump, plus a
*new* fixture beside the old one — never an edit to the old one.
