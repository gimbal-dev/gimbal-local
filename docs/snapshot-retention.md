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

## Reclaiming: delete, gc

Retention roots decide what age-based pruning *keeps*. This half is what you do
deliberately.

### `chm revisions <dir> delete <id>`

Removes one revision, and reports exactly what that gave back.

**Its descendants keep working, and this is the point worth understanding.** It
is tempting to assume a revision built as a delta against its parent must
depend on that parent — and if it did, deleting anything but the newest
revision would have to be refused, which would make the command useless, since
every revision except the newest has a descendant.

It does not depend on it. `dump_guest_ram_delta` *clones* the parent's dump and
overwrites only the 64 KiB chunks that changed, so a child shares **extents**
with its parent, never **dependency**: the clone is a separate inode holding a
logically complete image. Nothing on the restore path reads `parent` at all.

Measured, rather than argued:

| Check | Result |
| --- | --- |
| Child's RAM dump, sha256 before and after its parent was deleted | identical |
| A 2 vCPU guest resumed from a revision whose parent was deleted | login shell, `aarch64/2/ch-snap`, live filesystem |
| Bytes the command reported reclaiming | 1.4 GiB |
| Bytes the volume's own free-space counter gave back | 1452 MiB |

What *does* change is the graph: the descendants' manifests go on naming an id
that is gone. They are left exactly as they were — a manifest is the record of
what was captured, and rewriting one to say it descended from something else
would falsify that record to tidy a display. `chm revisions` reports the
reference for what it is:

```
rev-1785770906759-5394  1d ago  connect  parent=rev-1785770605785-40d2 (deleted)  resumable
```

**Two refusals, both naming their remedy:**

- **HEAD** — the state this snapshot resumes from. It is live state, not
  history; deleting it would silently turn the next start into a cold boot.
  Roll back, or take a newer checkpoint, to make it history first.
- **A pinned revision** — the remedy named is `unpin`, deliberately, rather
  than a `--force` flag. The whole point of a pin is that removing it is a
  separate decision, and `--force` invites reflex.

`--dry-run` runs the same planner the real command runs, so what it promises is
what a real one does.

> **A reclaim of `0 B` is a real answer, not a failure.** The figure counts
> extents no other file shares, so a revision whose content is entirely shared
> with a fork — or with an APFS clone of the whole workspace — costs nothing
> and returns nothing. The command says which it is rather than printing a bare
> zero. It also means the figures are **not additive**: deleting one revision
> can raise what the next one would reclaim, because extents that were shared
> become private.

### `chm revisions <dir> gc`

Reclaims state that no reader can reach. Both classes hold a whole RAM dump
while being invisible to `chm revisions`, so without this, reclaiming them
means knowing they exist and nothing ever tells you:

| Collected | Why it is there |
| --- | --- |
| `<snapshot>/.chm-checkpoint.tmp` | `write_checkpoint` stages a checkpoint here and renames it into place. An interrupted suspend leaves the staging directory behind, and only the *next* checkpoint of that snapshot clears it — so without `gc`, reclaiming it means running a guest. |
| A revision directory whose manifest will not parse | `list_revisions` skips it, so it is unreachable by resume, rollback, prune and usage alike, while still holding its dump. |

Deliberately **snapshot-scoped**. The pull cache in `control_plane` is a shared
content-addressed store keyed by digest; collecting it from here would let one
snapshot's cleanup delete blobs another snapshot is about to reuse.

`--dry-run` lists without removing. Running it twice is a no-op.

## Naming a point: `chm revisions <dir> label <id> <text>`

A timeline of timestamps tells you when, never why. A label is what makes a
point findable a month later, and it pairs with a pin: the two questions are
*keep this* and *keep this **because***.

```
rev-1785770906759-5394  1d ago  connect  parent=…  resumable  "node installed, before the npm crash"
```

Stored as a sidecar file, for the same reasons as the pin marker plus one that
is decisive: the manifest embeds the entire captured hardware state. Rewriting
that file to edit one string would round-trip a **resumable checkpoint** through
serde to change something serde never needed to see, and any asymmetry there
costs the checkpoint rather than the label. Control characters and labels over
120 characters are refused, because a label is echoed back into the listing
someone is reading to decide what to delete. `--clear` removes one.

## Related

- [`docs/environment-variables.md`](environment-variables.md) —
  `CHM_MAX_RESUMABLE_REVISIONS`.
- [`docs/living-workspaces.md`](living-workspaces.md) — why retention roots are
  a prerequisite for continuous checkpointing rather than a follow-up to it: a
  cadence-driven timeline built on purely age-based pruning is only ever five
  points deep, and everything behind it is a headstone.
