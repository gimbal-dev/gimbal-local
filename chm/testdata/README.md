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

**Do not regenerate these to make a test pass.** A failure here means *"this
change breaks checkpoints that already exist"*. If the format genuinely must
change, the answer is a migration and a `REVISION_MANIFEST_VERSION` bump, plus a
*new* fixture beside the old one — never an edit to the old one.
