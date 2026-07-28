# The Graviton acid test — results

**Date:** 2026-07-28
**Artifacts:** `gimbal-vanilla-graviton-snapshot-{1,2,3}.tar.zst`, produced by the
gimbal cloud team against [`graviton-capture-request.md`](./graviton-capture-request.md).

---

## TL;DR

**A vanilla Cloud Hypervisor snapshot captured on real AWS Graviton2 hardware
rehydrates on Apple Hypervisor.framework and runs an interactive login shell.**
This is milestone **V1.5**, and it passed on the first attempt with no code
changes.

It also surfaced the failure we had been predicting but could never observe with
our own fixtures — and it is **much larger than we guessed**:

| | `CNTFRQ_EL0` | how we know |
| --- | --- | --- |
| AWS Graviton2 (Neoverse-N1) | **121 875 000 Hz** | the guest's own boot log |
| Apple silicon under HVF | **24 000 000 Hz** | our fixture's boot log |
| **ratio** | **5.078125&times;** (exactly `325/64`) | |

The resumed guest runs correctly but **5.08&times; slow in wall-clock terms**. Measured,
not asserted: **5.080&times;**, within 0.04 % of the predicted ratio.

---

## 1. What we received

Three archives, 636 MiB compressed / 9.66 GiB each. All three are the same
shape — capture **A** (`graviton-vanilla-1cpu`, the acid test) run three times.
Capture **B** (2 vCPU + net) was not produced.

The layout matched the request **exactly**, including both details §3 flagged as
easy to get wrong:

```
snapshot/{state.json,config.json,memory-ranges}   1 GiB RAM image
disks/_disk0.raw  (8 GiB)                         named by DEVICE-NODE id,
disks/_disk1.raw  (366 KiB, cloud-init seed)      not by source filename
state.json
```

`disks/` was present and correctly named, so none of the `EXT4-fs error:
Directory block failed checksum` class of failure occurred.

### They are genuinely vanilla

| check | value | reading |
| --- | --- | --- |
| `its_ctlr` | `0x80000001` | bit 0 **Enabled** &rarr; real ITS/LPI routing |
| `its_cwriter` / `its_creadr` | `608` / `608` | command queue drained, quiescent |
| `its_baser[0..1]` | populated | device + collection tables live |
| `MIDR_EL1` | `0x413fd0c1` | ARM **Neoverse-N1** &rarr; **Graviton2** |
| `payload.firmware` | `CLOUDHV_EFI.fd` | EFI boot, ACPI guest |
| guest | Ubuntu 24.04.4, `6.8.0-136-generic` | |

Identical across all three. Note the device node is called `gic-v3-its` in both
shapes — the classification must come from `its_ctlr & 1`, never the node name.

Two independent fingerprints confirm the binary was **stock upstream v52.0** and
not our fork: the top-level `snapshot_data.state` is `{}` (see §3), and
`cpus` carries no `profile` field.

---

## 2. The acid test

```
$ CHM_USERSPACE_GIC=1 chm run snapshots/graviton-1
  memory:    1024 MiB
  vCPUs:     1
  backend:   Apple Hypervisor.framework (userspace GICv3)

chm: virtio device model restored:
chm:   - virtio-blk _disk1 (732 sectors) @ BAR 0x10000000
chm:   - virtio-blk _disk0 (16777216 sectors) @ BAR 0x10080000
chm:   - virtio-rng __rng @ BAR 0x200000000

Ubuntu 24.04.4 LTS ch-snap ttyAMA0
ch-snap login: ubuntu
Password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-136-generic aarch64)
ubuntu@ch-snap:~$
```

All three snapshots restored, reached a login prompt, accepted credentials and
gave a working shell. Every `\n` sent produced a fresh prompt, so this is live
execution — not a console replay.

Worth stating plainly: **no code changes were required.** The GICv3 + ITS/LPI
restore, the virtio-blk/rng device model, the redistributor reassembly and the
vtimer reseed all worked first time against a capture from a different CPU
vendor, a different hypervisor (KVM), and a different kernel build than any
fixture we have (`6.8.0-136` vs our `6.8.0-124`).

---

## 3. The counter-frequency mismatch (#104)

### It is real, and it is 5&times;

The guest tells us itself, from the RAM image:

```
arch_timer: cp15 timer(s) running at 121.87MHz (virt).      # graviton-1
arch_timer: cp15 timer(s) running at  24.00MHz (virt).      # our Mac fixture
```

A Linux guest reads `CNTFRQ_EL0` **once at boot**, caches it as
`arch_timer_rate`, and never re-reads it — not on resume, not ever. So the
resumed guest still believes its counter runs at 121.875 MHz while it is in fact
ticking at 24 MHz.

### Measured

Logged into `graviton-2` and timed a `sleep 5` from both sides:

```
guest: 1785233384.520157200  →  1785233389.521793189    Δ = 5.0016 s
host:  +36.53 s              →  +61.94 s                Δ = 25.41 s
```

**Measured dilation 5.080&times;. Predicted 121.875/24 = 5.078125&times;. Error 0.04 %.**

And from inside the running guest, on Apple silicon:

```
ubuntu@ch-snap:~$ sudo dmesg | grep -m1 'cp15 timer'
[    0.000000] arch_timer: cp15 timer(s) running at 121.87MHz (virt).
```

### Confirmed a third way

The snapshots' own `CNTVCT_EL0` divided by 121.875 MHz gives guest uptimes of
139.33 s, 141.35 s and 139.38 s. Those land neatly between cloud-init's own
`modules:config` (130.34 s) and `modules:final` (163.16 s) log timestamps. At
24 MHz the same counter would imply 707 s of uptime, which those timestamps
rule out.

So: the boot log, the live measurement, and the counter/uptime cross-check all
agree.

### What it actually feels like

The guest is **not corrupted** — it is internally self-consistent, just living in
dilated time. CPU-bound work runs at full native speed (we execute natively);
anything timer-bound stretches by 5.08&times;. Sleeps, timeouts, scheduler ticks, TCP
retransmit timers, watchdogs and the wall clock all run slow.

That combination is the trap: it presents as *"the VM feels sluggish"*, not as
*"the clock is wrong"*. Login took 30 s. It would be very easy to spend a day
profiling I/O.

### Why our own fixtures could never have caught this

Every fixture we own was captured under Lima **on this Mac**, so all four record
`cntfrq = 24000000` and restore onto a 24 MHz host. The mismatch path was not
merely untested — it was **unreachable**. This is exactly why V1.5 had to be a
real cloud capture.

---

## 4. Can it be fixed?

Short version: **not at restore time, and not with any API Apple exposes.**
Ruled out by inspection, in order of how much we wanted each one to work:

| approach | verdict |
| --- | --- |
| Rescale the counter via Hypervisor.framework | ❌ The API is `hv_vcpu_{get,set}_vtimer_offset` — an **offset**, never a rate. There is no counter-frequency control on the ARM side. |
| DT `clock-frequency` override on the timer node | ❌ Available in the binding, but these guests boot **EFI → ACPI**, and GTDT has no frequency field. Also `create_timer_node()` in `arch/src/aarch64/fdt.rs` does not emit it. (The `clock-frequency = 24000000` at line 717 is the **APB PCLK** for the UART — same number, unrelated register.) |
| Have KVM present a different `CNTFRQ` at capture | ❌ KVM exposes the host's physical counter rate. This is precisely why upstream KVM *rejects* a mismatch instead of trying to paper over it. |
| Make the guest re-read the rate on resume | ❌ `arch_timer_rate` is baked into the clocksource `mult`/`shift` and every clockevent at boot. There is no supported runtime path. |
| Guest agent that steps the clock on resume | ⚠️ Fixes the **wall clock** only. Does nothing about the 5.08&times; dilation of sleeps and timeouts. |
| Synthesize the rate by driving `CNTVOFF` | 🔬 Real, but research. See below. |
| Capture on a 24 MHz host | ✅ Works today — that is what our Lima fixtures are. Not the dream. |

### The one avenue that is actually open

The guest reads `CNTVCT_EL0 = physical_counter + CNTVOFF`. To make the guest
perceive 121.875 MHz while the hardware ticks at 24 MHz, `CNTVOFF` must advance
at the difference, 97.875 MHz. We *can* write `CNTVOFF` via
`hv_vcpu_set_vtimer_offset`.

The problems are real but bounded:

- HVF requires `hv_vcpu_*` calls on the vCPU's **own thread**, so updates can only
  happen at VM exits. Between exits the guest's perceived counter advances at the
  raw 24 MHz and then jumps at the exit — piecewise, jittery, though still
  monotonic.
- At a ~4 ms exit cadence the worst-case error is ~3.2 ms of guest time. Tolerable
  for some workloads, not for others.
- Forcing extra exits to tighten that costs throughput.

One encouraging detail: the ratio is **exactly `325/64`**. A fixed-point
correction is therefore exact and accumulates **no drift**, which removes the
usual objection to this technique.

### What we should do next, in order

1. **Detect and report** (V1.2). Turn a silent 5&times; slowdown into a one-line
   diagnosis. This is unambiguously worth doing and is not blocked.
2. **Prototype the `CNTVOFF` rate synthesis** (V1.3) behind a flag, and measure
   the jitter honestly rather than guessing.
3. Keep "capture on a 24 MHz host" as the supported path meanwhile, and say so
   out loud rather than letting people discover it.

---

## 5. Two bugs in *our* capture request

Both are ours, not the cloud team's — they followed the spec exactly.

### 5.1 We pinned a version that cannot record the clock

The request says `CH_VERSION=v52.0`. The top-level `snapshot_data.state` in all
three captures is `{}` — no clock block, so **no `cntfrq`, no `cntvct`, no
`host_realtime_ns`**.

That block comes from upstream commit `69637dde6` (*"hypervisor: aarch64:
capture the guest counter for snapshot/restore"*, Atish Patra, Meta, Jun 2026),
which landed **after v52.0**. So a v52.0 capture can never self-describe its
counter frequency — the single most important number in this whole exercise.

We got the number anyway, out of the guest's dmesg, but that is forensics, not a
contract. **The request must ask for a build that includes `69637dde6`.**

Two mitigating facts:

- `reference_cntvct()` reads vCPU0's captured `CNTVCT_EL0` **sysreg**, not the
  clock block, so counter *synchronisation* on resume was unaffected. That is why
  the restore worked at all.
- The missing block also means no wall-clock advance on resume, which is why the
  guest came up ~1 h 40 m behind.

### 5.2 The capture fired before cloud-init finished

Derived uptimes (139.33 / 141.35 / 139.38 s) sit between `modules:config`
(130.34 s) and `modules:final` (163.16 s). So cloud-init was still running when
the snapshot was taken.

The consequence is visible on resume: cloud-init completes, then **restarts
`serial-getty@ttyAMA0`**, which kills any console session — roughly 113 s of real
time after resume, in the middle of our first measurement attempt.

This is the exact hazard `capture-arm-snapshot.sh` already warns about: wait for
the authoritative `Cloud-init v.* finished` banner, not a `Reached target` line.
Something in the capture path is still returning early, and the request should
say explicitly how to verify the guest is quiescent before pausing.

---

## 6. Scorecard

| | status |
| --- | --- |
| Vanilla ITS/LPI capture accepted | ✅ |
| Real cloud hardware (Graviton2 / KVM) | ✅ |
| Different kernel build than any fixture | ✅ `6.8.0-136` vs our `6.8.0-124` |
| Restores on HVF, no code changes | ✅ |
| Interactive login shell | ✅ |
| Disk I/O correct (no ext4 checksum errors) | ✅ |
| Reproducible across three captures | ✅ |
| **Guest keeps correct time** | ❌ **5.08&times; slow — §3** |
| Snapshot self-describes its counter rate | ❌ needs CH > v52.0 — §5.1 |
| Guest quiescent at capture | ❌ mid-cloud-init — §5.2 |
| 2 vCPU + networking capture | ⬜ not produced |
