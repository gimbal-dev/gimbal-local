# Moving revisions between machines

`chm revisions <DIR> export` writes a bundle. `chm revisions <DIR> import`
reads one back into another copy of the same snapshot. Between them a
lineage — the checkpoints a sandbox accumulated as it ran — can be handed to
another Mac, archived, or restored after a mistake.

```
chm revisions ~/agent export --all /tmp/agent-bundle
tar -czf agent-bundle.tgz -C /tmp agent-bundle      # one file, if you want one

chm revisions ~/agent-copy import /tmp/agent-bundle --dry-run
chm revisions ~/agent-copy import /tmp/agent-bundle
```

## What a bundle is

```
gimbal-export.json      the envelope: what is here, and what it came from
chunks/<aa>/<sha256>    every distinct 64 KiB of content, stored once
```

The envelope names each revision, each file in it, and the ordered list of
chunk hashes that reassemble that file. Nothing else. Display information —
when a revision was taken, what its parent was, what hardware it captured —
comes from the `checkpoint.json` carried inside the revision itself, so the
envelope and the manifest cannot drift apart by having two copies of one fact.

The envelope is written **last** and renamed into place. Until it exists the
directory is a pile of anonymous chunks, so an export killed halfway can never
be mistaken for a complete bundle.

## What a bundle deliberately does not contain

### The base snapshot

A bundle carries revisions. It does not carry the vanilla Cloud Hypervisor
snapshot they descend from, and it never rewrites it.

That is constraint **C1**: *a vanilla snapshot stays vanilla*. The way to
honour it is not to be careful when modifying the base — it is never to touch
the base at all. So the envelope records only the sha256 of the base's
`state.json`, and import refuses a target whose digest differs:

```
this bundle was exported from base snapshot `agent` (e406a0b62fb0…), but
/tmp/other is a different machine (a36e3188cfa0…). A revision's captured RAM
matches the memory layout and device wiring in its own base's state.json;
restoring it onto another would be the RAM/disk mismatch resume exists to
refuse. Import it into a copy of the snapshot it came from.
```

Get the base the same way you got it the first time, then import into that.

### Pins

A pin says *"this revision must survive pruning on this machine"*. That is a
statement about one machine's retention budget, and importing it would spend a
budget the receiving operator never agreed to. Pins are reported instead:

```
rev-1785771527264-81c2   (pinned at source)
```

Re-pin the ones that matter to you, with `chm revisions <DIR> pin <ID>`.

### Metadata-only revisions

A revision that has been pruned down to a headstone — manifest, no RAM — is
refused by `export <ID>` and skipped with a named reason by `export --all`.
Carrying one would produce a bundle that imports "successfully" into something
nobody can resume.

## Why the sharing survives the round trip

A lineage is enormous on paper and small in practice. The real workspace this
was measured against reports **50.0 GiB apparent** and occupies **2.7 GiB**,
because `dump_guest_ram_delta` clones the parent's RAM dump and overwrites only
the 64 KiB chunks that changed, and APFS shares every extent neither revision
has touched.

A bundle has to preserve that in **both** directions, and it took three
measured attempts to get there:

| | written to disk on import |
| --- | --- |
| write each revision out in full | ~50 GiB |
| clone the previous revision, patch the differing chunks | 10.4 GiB |
| …and leave the overlay's holes as holes | **2.9 GiB** |

Against 2.7 GiB at the source. Three things make that work.

**The chunk size is 64 KiB because the delta writer's grid is 64 KiB.** This
is load-bearing, not a tuning parameter. Hashing on the same grid means an
unchanged region hashes identically in every revision that contains it. A
different or unaligned size would put a chunk boundary through the middle of
every change, and two near-identical RAM dumps would share almost nothing. A
test asserts the constant against the delta writer's own.

**Import clones the previous revision and patches it.** The donor is the
revision written immediately before, in the same import; its chunk hashes are
already in the envelope, so the differing indices are known without reading a
single byte back from the destination. Verification is not weakened by this:
the donor was verified chunk-by-chunk when *it* was written, minutes earlier,
in the same run.

**All-zero chunks are left as holes.** A CoW overlay is mostly hole — measured,
a revision's `_disk0-cow.raw` is 8 GiB long and 858 MiB allocated, because the
blocks the guest never wrote are not there at all. Writing those out as literal
zeros reproduces the file's *contents* perfectly and its *shape* not at all,
which is where 7.3 GiB per revision went before this was fixed. A hole reads
back as zeros, so skipping one is invisible to every reader except the disk.

The clone path is the exception: a chunk that is zero *here* and non-zero in
the donor is a difference to apply, not an absence to skip, so those are
written.

## What import checks

Every one of these refuses rather than warns, and each has been proved to fire
by deliberately breaking it.

| Check | Why |
| --- | --- |
| every chunk's content hashes to its own name | corruption is caught at import, not at resume |
| chunk names are canonical sha256 hex | a name is a path component; it must not be arbitrary |
| no path escapes the revision directory | a bundle is untrusted input |
| reassembled length matches the envelope | a truncated chunk list would otherwise pass silently |
| the base `state.json` digest matches | C1, above |
| the revision id is not already present | see below |
| the carried manifest's id matches the envelope's | otherwise `revisions` and `rollback` disagree about a directory |
| the overlays match the fingerprint captured with them | see below |

### The id-collision policy is refuse-by-default

Ids carry a timestamp *and* a random suffix, so a collision means two different
captures wearing one name. There is no safe automatic answer: overwriting
destroys state nobody asked to lose, and silently keeping the existing one
means the import reports success for a revision it did not import.
`--skip-existing` imports the rest and says which it left alone.

### The overlay fingerprint check is the one with independent power

`overlay.fingerprint` records each overlay as `name:len:mtime`, and a revision
ships it beside the files it describes. It was written on the **source**
machine at capture time — so unlike every other check here, it is not the
import being compared against the export.

That matters because a writer and a reader that agree by construction agree
about a bug too. This project has two records of what that costs, and this
milestone very nearly produced a third: an import that wrote every byte
faithfully and let the clock stamp the result produced a revision whose own
fingerprint contradicted its own files. It verified. It deduplicated
beautifully. And it could not be started — on the *receiving* machine, at
resume, with an error blaming their disk for something the transfer had done.

So modification times are carried in the envelope and restored on import.
Reproducing the timestamp is faithful reproduction of the artifact, not a
weakening of the guard: the RAM and the disk were consistent when they were
captured, both halves travel together, and anything that touches the overlays
*after* the import still moves the mtime and still fires.

## Import never moves HEAD

HEAD is where *this* machine would resume. Moving it has its own command. An
import that silently changed which state `Start` resumes would be the same
class of surprise as a checkpoint written over a good one.

```
HEAD is unchanged; `chm rollback <DIR> <REVISION_ID>` to move there
```

## Interruptions

Revisions are assembled in `<snapshot>/.chm-import.tmp/<id>` — **outside** the
revision store. Staging inside it would put a directory holding a valid
`checkpoint.json` exactly where `list_revisions` scans, so a half-written
import would be listed as a revision that `rollback` could not resolve.

A killed import leaves that directory behind, and `gc` collects it:

```
$ chm revisions ~/agent gc --dry-run
would remove ~/agent/.chm-import.tmp (interrupted import, 4.4 GiB)
```

## Measured, on a real 25 GiB lineage

Ten revisions of `graviton-agent4`, five of them resumable, exported and
imported into a fresh copy of the same base:

- export: **50.0 GiB apparent → 2.7 GiB stored**, 43,669 chunks, 44 s
- import: **2.9 GiB written**, and the volume's own free space fell by 3,359 MiB
- an imported revision **resumed to a live 2-vCPU shell** —
  `V95C_IMPORTED=aarch64/2/ch-snap`, filesystem readable, clean suspend
  afterwards

That last line is the one that matters. A bundle that verifies and imports and
produces something nobody can start is not a feature.
