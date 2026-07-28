# The Graviton capture request

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
# v52.0 is what our existing fixtures use. Pinning it for the first capture
# removes a variable; once A passes we want a newer release too.
CH_VERSION=v52.0
```

The capture script downloads these itself:

- `cloud-hypervisor-static-aarch64` (v52.0)
- `ch-remote-static-aarch64` (v52.0)

**Set `CH_GIC_V2M=0`.** That means: leave interrupt routing exactly as upstream
does it — MSI-X through the GIC ITS as LPIs. That is the *vanilla* shape and it
is what we now want. Our userspace GICv3 delivers those LPIs on HVF.

> **Do not set `CHM_ALLOW_ITS_LPI=1` anywhere.** That is a debugging bypass on a
> different (managed-GIC) code path. It silences a guard without changing
> delivery, so the guest restores and then stalls on its first I/O. It is not
> the flag for running vanilla — `CHM_USERSPACE_GIC=1` is, and that is a *run*
> time flag on the Mac, not a capture-time one.

---

## 3. The captures

Clone this repo on the capture host (or copy `scripts/hvf/capture-arm-snapshot.sh`
across — it is self-contained).

### A — `graviton-vanilla-1cpu` (the acid test)

```bash
env -u CH_BIN -u CHREMOTE_BIN \
  CH_VERSION=v52.0 \
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
  CH_VERSION=v52.0 \
  CH_GIC_V2M=0 \
  GUEST_CPUS=2 \
  GUEST_MEM_MB=2048 \
  GUEST_NET=1 \
  OUT_DIR="$PWD/graviton-vanilla-2cpu-net" \
  bash scripts/hvf/capture-arm-snapshot.sh
```

Run both on the **same host, same session**, so the only difference between them
is the guest shape.

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
  run this on the Mac with: CHM_USERSPACE_GIC=1 chm run <dir>
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
| **`CNTFRQ_EL0` (host, EL0)** | `?` | **The landmine.** See §5. |
| **`cntfrq` in `state.json`** | `?` | Should equal the above. If it doesn't, that itself is a finding. |
| Kernel version | `6.8.0-xx-generic` | Determines where the guest caches `arch_timer_rate`. |
| CH version + commit | `v52.0` | Snapshot format compatibility. |
| Instance type | `c7g.metal` | Which Graviton generation. |
| vCPUs / RAM | `1 / 1 GiB` | Cross-check against the manifest. |
| Guest distro | `Ubuntu 24.04.x` | Matches our fixtures. |

---

## 5. Why `CNTFRQ_EL0` is the headline

A Linux guest reads `CNTFRQ_EL0` **once at boot**, caches it as
`arch_timer_rate`, and never re-reads it on resume. A cloud-hypervisor snapshot
stores the value it was captured with, in the top-level `snapshot_data.state`:

```json
{"clock":{"cntvct":4426757347,"host_realtime_ns":1784730066918609199,"cntfrq":24000000}}
```

Our KVM path **explicitly rejects a mismatch**, with this reasoning in
`hypervisor/src/kvm/mod.rs`:

> KVM does not rescale the counter frequency across hosts (unlike x86 TSC) …
> Reject rather than corrupt the guest clock.

**Our HVF path does not check at all** — `Snapshot::from_state_json` never even
parses the clock block. And Apple presents HVF guests a fixed counter frequency
we cannot change.

Every fixture we own reports `cntfrq = 24000000` **because they were all
captured on a Mac**. So this failure mode has never executed, and *cannot* with
the fixtures we have. If Graviton's frequency differs, the first real snapshot
gets a guest clock wrong by exactly that ratio — and it will not announce
itself. It will look like a hang, or like time moving at the wrong speed.

**So: if you send us nothing else, send us that number.** It tells us whether
V1.5 is a formality or a research problem, before we spend a day debugging the
wrong thing. It costs one `mrs` instruction.

We are shipping a loud guard for this either way
([#104](https://github.com/gimbal-dev/gimbal-local/issues/104)).

---

## 6. The optional third capture — keep the app working

Until [#102](https://github.com/gimbal-dev/gimbal-local/issues/102) lands,
`chm serve` (the daemon the macOS app drives) still only accepts a **GICv2M /
message-SPI** capture. If you want the app path to keep working against
Graviton artifacts in the meantime, one legacy capture would help:

```bash
# C — legacy. This one DOES need our fork's patched binary, because
# CH_GIC_V2M is our patch and upstream will ignore it.
CH_BIN=/path/to/forked/cloud-hypervisor \
CHREMOTE_BIN=/path/to/forked/ch-remote \
  CH_GIC_V2M=1 GUEST_CPUS=1 GUEST_MEM_MB=1024 GUEST_NET=0 \
  OUT_DIR="$PWD/graviton-gicv2m-1cpu" \
  bash scripts/hvf/capture-arm-snapshot.sh
```

This is **strictly a stopgap**, not the direction. Vanilla is the contract.
If producing our fork on the capture host is inconvenient, skip C — it only
costs us the app demo path, and #102 removes the need entirely.

---

## 7. What we will do with it

1. Check the reported `CNTFRQ_EL0` against what an HVF guest sees.
2. `CHM_USERSPACE_GIC=1 chm run graviton-vanilla-1cpu` — expect an interactive
   Ubuntu shell.
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
