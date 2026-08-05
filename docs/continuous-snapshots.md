# Continuous snapshots

> A session that ends badly should not be a session whose work is gone.

`chm` can checkpoint a **running** guest on a cadence. Nothing is stopped, no
command is issued inside the guest, and the guest keeps running afterwards. Turn
it on with an interval:

```console
$ CHM_SNAPSHOT_INTERVAL_SECS=60 chm resume ~/my-sandbox
chm: continuous snapshots every 60s; roughly the last 5m stays resumable
     (raise CHM_MAX_RESUMABLE_REVISIONS, or pin a revision, to keep more)
...
chm: live snapshot 1 written (froze 2.92s, barrier 163ms)
```

It is **off by default**, and that is deliberate: a checkpoint costs a real
freeze, so switching it on is a trade the operator makes rather than one made
for them.

## What it costs

The guest does not run while its RAM is being written. That is the whole cost of
the feature, so `chm` reports the measured freeze every time rather than a
nominal one — the number you need to choose an interval is the one your hardware
actually produced, not ours.

Measured on an M-series Mac against a real 2 GiB / 25 GiB-on-disk Ubuntu guest:

| | freeze | of which barrier |
| --- | --- | --- |
| busy guest (writing + `sync` in a loop) | 2.6–4.5 s | 0.16–0.97 s |
| idle guest | 1.5–2.3 s | 0.30–0.88 s |

The *barrier* is the time spent getting every vCPU and host-side writer to a safe
point. The remainder is writing the RAM image. So the freeze is dominated by
guest size, not by vCPU count or how busy the guest is.

An idle guest is the cheaper case, which is what you want: the moments worth
checkpointing are often the quiet ones.

## What "safe point" means

A checkpoint has to capture RAM, devices and the disk overlay as one consistent
instant. Anything still writing into guest memory while that dump runs can leave
a ring buffer describing a request that was never finished — which resumes into
a guest that hangs on the first touch.

Three classes of writer exist, and only one of them needs stopping:

| Writer | Paused? | Why |
| --- | --- | --- |
| **vCPUs** | **Yes** | They are the guest. |
| **virtio-block** | No | Requests are drained, processed and published **synchronously on the vCPU thread** that took the MMIO/PCI trap. A vCPU parked at the barrier provably has no half-finished request. This is structural, not luck. |
| **virtio-net** (`chm-net-service`) | **Yes** | A separate thread writing received frames into the guest's RX ring, concurrent with any RAM dump. |
| **console** (`stdin_pump`) | No | Holds a PL011 FIFO, not guest memory. A keystroke mid-dump is device state, never a torn ring. |

Host-side writers are paused **before** the vCPUs, not after. The other order
leaves the net service free to publish into the ring of a guest whose vCPUs are
already parked — exactly the tear being avoided.

An unconsumed entry sitting in an avail ring is fine: that is ordinary suspended
state, drained by the notify handler on resume. Only a *half*-processed chain is
corruption.

### Waking a parked vCPU

Two signals are sent, every time. `hv_vcpus_exit` moves a vCPU that is inside the
guest; a wake fd moves one parked in the host-side WFI idle halt, which has
already left the guest and would otherwise sit there until its poll timeout.
Since an idle VM is exactly when a checkpoint is cheapest, it must not be the
slow case.

### If the world will not stop

The attempt is **abandoned** and reported as skipped:

```
chm: live snapshot skipped: timed out waiting for vCPUs
chm: live snapshots: 4 written, 1 skipped
```

A missed checkpoint is a recoverable disappointment. A torn one is a guest that
resumes into corruption, which is worse than not having the checkpoint at all.

## Where the points go

Each live checkpoint becomes a revision in the snapshot's lineage, exactly like a
deliberate suspend, so the existing tools work on them unchanged:

```console
$ chm revisions ~/my-sandbox
rev-1785771527264-81c2       1d ago  connect       parent=…  resumable
rev-1785917936959-5418       1m ago  connect-auto  parent=…  resumable
rev-1785917961613-5418      51s ago  connect-auto  parent=…  resumable
```

An **`-auto`** origin marks a point the cadence took rather than one you asked
for. The age column is what makes the list navigable once there are dozens of
points rather than a handful of suspends you remember making.

Travel back with `chm rollback <dir> <id>`, which restores that revision's RAM
**and** the disk overlays captured with it — the pairing matters, and is why you
cannot simply resume an older point against today's disk.

### How far back you can actually go

The cadence is the visible knob, but **retention is the binding one**. Only the
newest `CHM_MAX_RESUMABLE_REVISIONS` (default 5) keep their RAM; older revisions
are pruned to metadata so the lineage graph survives but they can no longer be
resumed. So at a 30-second cadence, "continuous snapshots" buys about two and a
half minutes of reachable history — which is not what the phrase suggests, and is
why `chm` prints the real window at startup instead of leaving you to infer it
from two environment variables.

To keep more, either raise the budget or mark specific points as retention roots:

```console
$ chm revisions ~/my-sandbox pin rev-1785917936959-5418
```

Pinned revisions sit **outside** the budget, so pinning one does not shorten the
window of recent history.

## When a session ends badly

This is the case the feature exists for.

If the guest powers itself off, or a vCPU errors, `chm` no longer discards the
current checkpoint. A checkpoint written by the cadence is a point captured
earlier from a *healthy* guest, and throwing it away because the run later died
would defeat the entire purpose. Instead it is filed into the lineage and you are
told how to get it back:

```
chm: kept the last live snapshot as rev-1785917961613-5418;
     recover it with `chm rollback /Users/me/my-sandbox rev-1785917961613-5418`
```

It is filed rather than left in place because the live disk overlays have moved on
since it was taken. Resuming it directly would pair remembered RAM with a
filesystem that changed underneath it — the exact mismatch the overlay drift guard
refuses. `chm rollback` restores both halves together, which is the only
consistent way back.

## Limits

- **The freeze is real and scales with guest RAM.** There is no dirty-page
  tracking or iterative pre-copy: every checkpoint writes a full RAM image. A
  larger guest means a longer freeze, linearly.
- **Retention is age-based**, plus explicit pins. There is no policy that keeps,
  say, one point per hour as history ages.
- **The cadence is a plain timer.** It does not yet trigger on meaningful guest
  events.
