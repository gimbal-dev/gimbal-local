# Snapshot retention — what is kept, what is reclaimed, and what it costs

Every resumable checkpoint carries a **complete guest-RAM image** — you can
resume any of them without consulting its neighbours. What it *costs* is a
different question, and since V9.1a the answer is much smaller than the size:
each dump is written as a clone of the previous one with only the 64 KiB chunks
that changed rewritten, so consecutive revisions share almost all their extents.
On the images this project runs a full image is 2.8 GiB, but the **incremental**
cost of one more revision is a measured 2–13 MiB.

That changes the arithmetic, not the need for a bound. Shared extents are only
freed when the last revision referencing them goes, so a long lineage still
grows — and `chm revisions <dir> --usage` reports what deleting a revision would
*actually* reclaim rather than what its parts add up to, because those two
numbers are now very different. On a real ten-revision lineage:

```
$ chm revisions ~/agent-workspace --usage
revisions     0 B to reclaim
  50.0 GiB of their 50.0 GiB is shared and costs nothing extra
```

Every revision reports 10 GiB of parts and **0 B reclaimable**, because each
one's extents are shared with its neighbours. Naive accounting would have told
you to delete one for 10 GiB back and given you nothing.

`chm` bounds the store by age: the newest `CHM_MAX_RESUMABLE_REVISIONS`
revisions (default 5) keep their RAM, and older ones are reduced to their
manifest — the lineage graph survives, the ability to resume that exact point
does not.

Age is the right default and the wrong rule for the one revision you care
about. The point worth keeping is usually *not* the most recent one: it is the
commit that worked, taken before an afternoon of checkpoints that did not.

## Pinning

```
chm revisions <SNAPSHOT_DIR> pin   <REVISION_ID>
chm revisions <SNAPSHOT_DIR> unpin <REVISION_ID>
```

A pinned revision is a **retention root**: age-based pruning will not reclaim
its RAM, however many checkpoints follow it. `chm revisions` marks it
`[pinned]`.

**Pins sit outside the retention budget rather than inside it.** Counting a pin
against `CHM_MAX_RESUMABLE_REVISIONS` would mean that marking a point as
important silently shortened the window of recent history — the opposite of
what pinning is for. Measured on a real 25 GiB lineage with the budget set to 2:

| | resumable after a prune |
| --- | --- |
| no pins | HEAD + 1 archived = **2** |
| oldest archived revision pinned | HEAD + 1 archived + **the pin** = **3** |

The unpinned survivor count is identical in both runs, so the pin *added* a
retained revision rather than displacing one.

The pin is recorded as a marker file inside the revision directory, not as a
field in its manifest: pinning must not rewrite a manifest that a digest may
cover, and creating or removing a file is atomic, so a pin cannot be half
applied.

## What a lineage costs

```
chm revisions <SNAPSHOT_DIR> --usage
```

```
revisions     50.0 GiB
live overlays 8.0 GiB  (working state, in no revision)
total         58.0 GiB
  rev-…-40d2    10.0 GiB [pinned]
  rev-…-5394    10.0 GiB
  …
```

Two figures are reported for the revisions because one number cannot be honest
on its own. `chm fork` **hard-links** the parent's write-once RAM dump, so the
same bytes appear under several revisions. Summing the per-revision figures
therefore reports disk that does not exist, while reporting only the
deduplicated total hides that a fork was nearly free. Both are shown, and the
difference between them is exactly the saving from sharing.

`revisions` and the per-revision figures below it cover the same set, so they
are comparable. The **live overlays** — the working disk state of the running
guest — belong to no revision, so they are reported on their own line and added
into `total` rather than folded into either.

> A deduplicating count can never exceed the sum it deduplicates. An early
> version of this command reported 58 GiB on disk against 50 GiB of parts,
> because it folded the live overlays into the deduplicated figure while no
> revision owned them. The invariant `on_disk <= apparent` is now asserted by a
> test.

## Related

- [`docs/environment-variables.md`](environment-variables.md) —
  `CHM_MAX_RESUMABLE_REVISIONS`.
- [`docs/living-workspaces.md`](living-workspaces.md) — why retention roots are
  a prerequisite for continuous checkpointing rather than a follow-up to it: a
  cadence-driven timeline built on purely age-based pruning is only ever five
  points deep, and everything behind it is a headstone.
