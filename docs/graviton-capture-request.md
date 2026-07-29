# The Graviton capture request

> ### ⚠️ Round 1 is complete — read the results first
>
> Three round-1 captures were produced against this document and **the acid test
> passed**: a vanilla Graviton2 snapshot rehydrates on Apple Hypervisor.framework
> and runs an interactive login shell. See
> [`graviton-acid-test-results.md`](./graviton-acid-test-results.md).
>
> It also exposed **two bugs in this document**, both ours — the capture team
> followed the spec exactly. They are fixed below and marked **`[fixed after
> round 1]`**:
>
> 1. **`CH_VERSION` was pinned to `v52.0`, which cannot record the counter
>    frequency at all.** The number this whole document leads with was therefore
>    absent from every artifact. See [§2](#2-the-binaries--stock-upstream-nothing-of-ours).
> 2. **The captures fired before cloud-init had finished**, so the guest restarts
>    its serial getty ~113 s after resume and kills any console session. See
>    [§3](#3-the-captures).
>
> Round 2 should re-run **A** and **B** with the corrected version pin and the
> quiescence check.

**What this is:** the exact snapshot Gimbal Local needs from AWS, and exactly how
to produce it. This is the one thing blocking **V1.5 — the acid test**
([#105](https://github.com/gimbal-dev/gimbal-local/issues/105)): rehydrating a
snapshot captured on *real cloud hardware* on an Apple-silicon Mac.

**Why it matters:** every fixture we own today was captured under Lima **on a
Mac** and restored on the Mac it came from. The engine is hardware-proven — stock
upstream captures boot to an interactive shell with disk, net, SMP and
checkpoint/resume — but the cloud→Mac boundary is *structurally untested*. This
capture is the difference between "works on my captures" and the actual product
claim.

For the AWS account, quota, bucket, key-pair and AMI plumbing, follow
[`aws-byo-setup.md`](aws-byo-setup.md). This document only specifies **the
capture itself**.

---

## TL;DR

Two snapshots, from **one** Graviton bare-metal host, in **one** session, using
**stock upstream cloud-hypervisor** — no fork, no patches, `CH_GIC_V2M=0`:

| | Shape | Purpose |
| --- | --- | --- |
| **A** — `graviton-vanilla-1cpu` | 1 vCPU, 1 GiB, 2 disks, no net | **The acid test.** Minimal, so a failure has one cause. |
| **B** — `graviton-vanilla-2cpu-net` | 2 vCPU, 2 GiB, 2 disks, virtio-net | Full stack: SMP + net + NAT in one artifact. |

Both must ship their **disk images**, and both must come back with a short
**metadata block** — `CNTFRQ_EL0` first (see [§4](#4-the-metadata-we-need)).

If you can only do one, do **A**.

---

## 1. The host

| Requirement | Value | Why |
| --- | --- | --- |
| Instance type | `c7g.metal` (or any Graviton `*.metal`) | Needs a real `/dev/kvm`. Not a nested/virtualised host — the point is that this is *genuinely different hardware from a Mac*. |
| AMI | Ubuntu 24.04 LTS **arm64** | Matches what the capture script expects. |
| Packages | `qemu-utils cloud-image-utils curl zstd python3` | The script installs these itself if missing. |
| Disk | ≥ 60 GiB root volume | Guest image + RAM dump + tarballs. |

Confirm before doing anything else:

```bash
uname -m                 # expect: aarch64
ls -l /dev/kvm           # must exist
```

If `/dev/kvm` is absent you are not on bare metal and nothing below will work.

---

## 2. The binaries — stock upstream, nothing of ours

This is the single most important instruction, because it is the one our own
docs previously got wrong.

**Use the stock upstream cloud-hypervisor release binaries.** Do **not** build
our fork, do **not** apply any patch, and do **not** set `CH_BIN` /
`CHREMOTE_BIN`.

```bash
# [fixed after round 1] v52.0 is NOT usable. It predates upstream commit
# 69637dde6 ("hypervisor: aarch64: capture the guest counter for
# snapshot/restore", Atish Patra, Jun 2026), which is what writes the clock
# block holding cntfrq / cntvct / host_realtime_ns.
#
# Every round-1 capture came back with a top-level snapshot_data.state of {} --
# no counter frequency at all. We recovered the number by grepping the guest's
# dmesg out of the RAM image, but that is forensics, not a contract.
#
# Use a build that CONTAINS 69637dde6: the latest release that includes it, or
# upstream main. Please report the exact tag/commit in the metadata block.
CH_VERSION=<a release containing 69637dde6, or main>
```

To check a candidate binary before you spend an hour on a capture:

```bash
# after any snapshot, this must NOT be empty
jq -r '.snapshot_data.state' snapshot/state.json
# want: {"clock":{"cntvct":...,"host_realtime_ns":...,"cntfrq":...}}
# v52.0 gives: {}
```

The capture script downloads these itself:

- `cloud-hypervisor-static-aarch64`
- `ch-remote-static-aarch64`

**Set `CH_GIC_V2M=0`.** That means: leave interrupt routing exactly as upstream
does it — MSI-X through the GIC ITS as LPIs. That is the *vanilla* shape and it
is what we now want. Our userspace GICv3 delivers those LPIs on HVF.

> **Do not set `CHM_ALLOW_ITS_LPI=1` anywhere.** That is a debugging bypass on a
> different (managed-GIC) code path: it forces a vanilla capture onto the GIC
> that cannot deliver its completions, so the guest restores and then stalls on
> its first I/O. Running vanilla needs no flag at all — the Mac side reads the
> capture and picks the right backend itself.

---

## 3. The captures

Clone this repo on the capture host (or copy `scripts/hvf/capture-arm-snapshot.sh`
across — it is self-contained).

### A — `graviton-vanilla-1cpu` (the acid test)

```bash
env -u CH_BIN -u CHREMOTE_BIN \
  CH_VERSION=<see §2 — NOT v52.0> \
  CH_GIC_V2M=0 \
  GUEST_CPUS=1 \
  GUEST_MEM_MB=1024 \
  GUEST_NET=0 \
  OUT_DIR="$PWD/graviton-vanilla-1cpu" \
  bash scripts/hvf/capture-arm-snapshot.sh
```

### B — `graviton-vanilla-2cpu-net`

```bash
env -u CH_BIN -u CHREMOTE_BIN \
  CH_VERSION=<see §2 — NOT v52.0> \
  CH_GIC_V2M=0 \
  GUEST_CPUS=2 \
  GUEST_MEM_MB=2048 \
  GUEST_NET=1 \
  OUT_DIR="$PWD/graviton-vanilla-2cpu-net" \
  bash scripts/hvf/capture-arm-snapshot.sh
```

Run both on the **same host, same session**, so the only difference between them
is the guest shape.

### Before you pause: check the guest is actually quiescent `[fixed after round 1]`

All three round-1 captures were taken at ~139–141 s of guest uptime, which is
**between** cloud-init's `modules:config` (130 s) and `modules:final` (163 s).
So cloud-init was still running when the snapshot was taken.

That is not cosmetic. On resume, cloud-init picks up where it left off, finishes,
and **restarts `serial-getty@ttyAMA0`** — which kills the console session roughly
113 s of real time after resume. It killed ours, mid-measurement.

So before pausing, confirm all three of these in the guest:

```bash
cloud-init status --wait          # must print: status: done
systemctl is-system-running       # want: running  (degraded is OK, starting is NOT)
systemd-analyze time              # startup should be finished
```

Then give it ~10 s of genuine idle before `ch-remote pause`. If the script's own
wait returned earlier than this, please say so — that is a bug in the script's
banner matching and we want to fix it rather than have you work around it.

### What the script does (so you can sanity-check it)

Boots a throwaway Ubuntu 24.04 arm64 cloud image under cloud-hypervisor, waits
for the authoritative `Cloud-init v.* finished` banner (**not** a "Reached
target" line — that fires before `runcmd` and can catch the guest mid
getty-restart), then `pause`s and `snapshot`s it, exports the disks **while
still paused** so they match the memory image instant-for-instant, and packages
the result.

It should print, near the end:

```
GITS_CTLR.Enabled is set ✓ — vanilla (stock upstream) ITS/LPI routing
  run this on the Mac with: chm run <dir>
```

If instead it says `GITS_CTLR.Enabled is clear`, the capture came out in the
**legacy** GICv2M shape — check that `CH_GIC_V2M=0` and that `CH_BIN` is unset.

> `CH_GIC_V2M` now **defaults to `0`** (vanilla). The explicit `CH_GIC_V2M=0`
> above is belt-and-braces; older copies of the script defaulted to `1`.

### The output layout

```
graviton-vanilla-1cpu/
├── state.json                    # the small fixture, copied out for convenience
├── snapshot/
│   ├── config.json
│   ├── state.json                # vCPU + GIC + device state
│   └── memory-ranges             # the guest RAM image (1–2 GiB)
├── disks/
│   ├── _disk0.raw                # named by DEVICE NODE ID, not filename
│   └── _disk1.raw
└── ch-arm-snapshot.tar.zst       # the whole thing, for handoff
```

Two things that are easy to get wrong:

1. **`disks/` is mandatory.** A CH snapshot references its disks by host *path*
   and does not embed them. Without the real disk content, any post-resume read
   of an uncached block returns zeros and the guest throws
   `EXT4-fs error: Directory block failed checksum`. We open these read-only
   through a per-run copy-on-write overlay, so the base stays pristine.
2. **The disk filenames must be the device-node ids** (`_disk0.raw`,
   `_disk1.raw`), not the source filenames (`guest.raw`, `seed.img`). The script
   does this correctly; just don't rename them afterwards.

Ship the whole directory, or the `.tar.zst`. Sparse-copy where you can
(`cp --sparse=always`, `aws s3 cp` is fine) — `_disk0.raw` is nominally 8 GiB but
mostly holes.

---

## 4. The metadata we need

Please return this block with each capture. **The first line is the important
one** — it is the specific thing we expect to break.

```bash
# 1. THE ONE WE MOST NEED — the capture host's counter frequency.
cat > /tmp/cntfrq.c <<'EOF'
#include <stdio.h>
int main(void) {
    unsigned long f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    printf("CNTFRQ_EL0 = %lu Hz\n", f);
    return 0;
}
EOF
cc -o /tmp/cntfrq /tmp/cntfrq.c && /tmp/cntfrq

# 2. Cross-check: the value actually baked into the snapshot.
python3 -c "
import json,sys
r=json.load(open(sys.argv[1]))
print('snapshot cntfrq =', json.loads(r['snapshot_data']['state'])['clock'])
" graviton-vanilla-1cpu/state.json

# 3. The rest.
uname -a                                    # kernel version + arch
./cloud-hypervisor --version                # CH version
cat /etc/os-release | head -2               # guest+host distro
curl -s http://169.254.169.254/latest/meta-data/instance-type
nproc; free -g
```

Report it as:

| Field | Example | Why we need it |
| --- | --- | --- |
| **`CNTFRQ_EL0` (host, EL0)** | round 1: **121875000** | **The landmine — confirmed.** See §5. Re-confirm per instance type. |
| **`cntfrq` in `state.json`** | `?` | Should equal the above. If it doesn't, that itself is a finding. |
| Kernel version | `6.8.0-xx-generic` | Determines where the guest caches `arch_timer_rate`. |
| CH version + commit | *(must contain `69637dde6`)* | Snapshot format **and** whether the clock block is recorded — see §2. |
| Instance type | round 1 was **Graviton2 / Neoverse-N1** (`MIDR 0x413fd0c1`) | Which Graviton generation — the counter rate may differ on G3/G4, so please report it. |
| vCPUs / RAM | `1 / 1 GiB` | Cross-check against the manifest. |
| Guest distro | `Ubuntu 24.04.x` | Matches our fixtures. |

---

## 5. Why `CNTFRQ_EL0` is the headline — **answered, and it's bad**

> **Round 1 settled this.** Full evidence in
> [`graviton-acid-test-results.md`](./graviton-acid-test-results.md); the short
> version is below. Please still return the number — round 1 could not record it
> (§2), so we had to recover it forensically from the guest's dmesg.

| | `CNTFRQ_EL0` |
| --- | --- |
| AWS Graviton2 (Neoverse-N1) | **121 875 000 Hz** |
| Apple silicon under HVF | **24 000 000 Hz** |
| **ratio** | **5.078125×** (exactly `325/64`) |

A Linux guest reads `CNTFRQ_EL0` **once at boot**, caches it as
`arch_timer_rate`, and never re-reads it on resume. So a Graviton guest resumed
on a Mac still believes its counter runs at 121.875 MHz while it actually ticks
at 24 MHz. **Everything timer-bound therefore takes 5.08× longer.** We measured
5.080× on real hardware — a `sleep 5` in the guest took 25.41 s of wall clock.

The guest is not corrupted; it is internally consistent, just living in dilated
time. Which is exactly what makes it dangerous: it presents as *"this VM feels
sluggish"*, not as *"the clock is wrong"*.

A cloud-hypervisor snapshot stores the capture-time value in the top-level
`snapshot_data.state`:

```json
{"clock":{"cntvct":4426757347,"host_realtime_ns":1784730066918609199,"cntfrq":24000000}}
```

Our KVM path **explicitly rejects a mismatch**, with this reasoning in
`hypervisor/src/kvm/mod.rs`:

> KVM does not rescale the counter frequency across hosts (unlike x86 TSC) …
> Reject rather than corrupt the guest clock.

**Our HVF path does not check at all** — `Snapshot::from_state_json` never even
parses the clock block. Apple gives us `hv_vcpu_set_vtimer_offset`, an *offset*
and never a *rate*, so there is no restore-time fix available.

That is why §2 now insists on a build that records the clock block: with it, we
can turn a silent 5× slowdown into a one-line diagnosis
([#104](https://github.com/gimbal-dev/gimbal-local/issues/104)) instead of
someone losing a day to it.

---

## 6. The third capture is no longer needed

This section used to ask for a legacy GICv2M / message-SPI capture, because
`chm serve` — the daemon the macOS app drives — only accepted that shape.

**That is fixed.** [#102](https://github.com/gimbal-dev/gimbal-local/issues/102)
shipped in V2.1: the daemon routes a vanilla ITS/LPI capture to the userspace
GICv3 on its own, with no flag. V2.2 then drove a vanilla Graviton capture from
the app itself to an interactive login shell. Both entry points take vanilla.

So: **please do not produce a GICv2M capture.** It needs this fork's patched
binary on the capture host, and nothing depends on it any more. The legacy
fixtures already in `snapshots/` are enough to keep the managed-GIC path under
regression test. Vanilla is the contract.

---

## 7. What we will do with it

1. Check the reported `CNTFRQ_EL0` against what an HVF guest sees.
2. `chm run graviton-vanilla-1cpu` — expect an interactive Ubuntu shell.
3. Same for B, plus `nproc` = 2, a real disk write, and `curl` through the
   userspace NAT.
4. Checkpoint and resume it, to prove live state survives on a foreign
   substrate.
5. Report back honestly, including the failures.

We will publish exactly what happened — including the counter-frequency result —
whichever way it goes.

---

## 8. One honest caveat, on networking

Capture **B** pins the guest to a static address matching our userspace NAT's
contract (guest `192.168.249.2/24`, gateway and DNS `192.168.249.1`, gateway MAC
`02:00:00:00:00:01`). That is baked in at capture time by the script's
cloud-init.

So for **networking specifically**, "vanilla" currently means "stock
cloud-hypervisor with an ITS", not "any guest network configuration". A guest
that got its address from cloud DHCP will come up on our NAT with the wrong
address and no route. Disk, CPU, SMP, interrupts and checkpoint/resume have no
such constraint.

That gap is ours to close, and we are not going to pretend otherwise. It does
not affect capture **A**, which is the acid test.
