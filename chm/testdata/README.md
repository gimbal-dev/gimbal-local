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
