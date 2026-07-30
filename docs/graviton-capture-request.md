# The Graviton capture request

> ### ✅ Round 2 delivered — and round 3 is now open
>
> gimbal cloud produced `graviton-vanilla-1cpu` and `graviton-vanilla-2cpu-net`
> on 2026-07-31, against the corrected spec below. Both bugs in round 1 were
> fixed: the build was **cloud-hypervisor v54.0.0 @ `9ea9019d29af`** (post
> `69637dde6`, so the clock block is real — `cntfrq: 121875000` is recorded in
> *both* captures), and the pause happened **after cloud-init finished**.
>
> **Capture B is the one that mattered.** It is the first capture we have ever
> held with a NIC, and the first with 2 vCPU. On Apple Hypervisor.framework it
> rehydrates with `ens3 UP 192.168.249.2/24`, and from inside the guest
> `curl https://api.github.com/zen` returns `HTTP 200` and `git clone` over
> HTTPS succeeds. That closes V5.1.
>
> It also earned its keep by breaking something: 2 vCPU + `CHM_GUEST_CNTFRQ`
> exposed a counter-coherence bug that a 1-vCPU capture structurally cannot
> show. See `roadmap.md` §V5.5.
>
> The rest of this document is kept as the record of what was asked for and why.

> ### 📋 Round 3 is now the live ask — the minimal agent image
>
> Round 2 answered *"does a real cloud capture run on a Mac"*. Yes, network and
> all. Round 3 asks a different question: **is this an image worth running?**
>
> The round-2 guest is 74% full with 633 MB of headroom and 663 packages of
> general-purpose cloud VM. A toolchain does not fit in it. **See [§9–§12](#9-why-the-current-image-is-the-wrong-shape)
> at the end of this document** for the full spec.
>
> Fastest unblock by far is **[§8b](#8b-the-cheapest-ask-in-this-whole-document--graviton-vanilla-1cpu-net)** — a 1-vCPU capture *with* a NIC, which is a one-line
> change and lets us build the agent image ourselves with no code changes.
>
> The one thing to read if you read nothing else: **do not reuse a Firecracker
> kernel.** Their aarch64 CI kernel sets `# CONFIG_PCI is not set`; Cloud
> Hypervisor puts virtio on PCI, so that kernel boots to no disk and no network.
> Their *rootfs* is a good starting point; their *kernel* is not.

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

---

# Round 3 — the minimal agent image (V5.3)

Round 2 closed the question "does a real cloud capture run on a Mac". It does,
including the network: from inside the rehydrated guest we get `HTTP 200` from
`api.github.com` and a working `git clone` over HTTPS.

This round asks for something different. Not "does it run" but **"is this an
image worth running"** — a purpose-built sandbox for a coding agent, rather than
a stock Ubuntu cloud image that happens to boot.

## 8b. The cheapest ask in this whole document — `graviton-vanilla-1cpu-net`

**If you only do one thing from round 3, do this one.** It is a one-line change
and it unblocks more than the rest of the round combined.

**Capture A's config, with capture B's NIC. 1 vCPU, one virtio-net device.**

Why it matters so much: our checkpoint capture is single-vCPU only
(`want_capture = want_checkpoint && n == 1 && id == 0`), so the two captures we
hold split the requirements exactly wrong.

| Capture | vCPUs | NIC | Can install a toolchain | Can save the result |
| --- | --- | --- | --- | --- |
| `graviton-vanilla-1cpu` | 1 | ❌ | ❌ no network | ✅ |
| `graviton-vanilla-2cpu-net` | 2 | ✅ | ✅ proved | ❌ |
| **`graviton-vanilla-1cpu-net`** | **1** | **✅** | **✅** | **✅** |

We have already proved on capture B that we can grow the disk and install a full
toolchain from inside the guest (`cc 13.3.0`, compiles and runs). We simply
cannot *persist* it, because that guest has two vCPUs. A 1-vCPU capture with a
NIC lets us build the agent image ourselves, today, with no code changes on
either side — and then §9–§12 below becomes a clean-up exercise rather than a
blocker.

Everything else identical to capture B: same host, same CH build, GICv3 + ITS,
same static address contract (§8), quiescent before pause, same metadata block.

---

## 9. Why the current image is the wrong shape

Measured on `graviton-vanilla-2cpu-net`, from inside the running guest:

```
$ df -h /
/dev/vda1       2.4G  1.8G  633M  74% /

$ dpkg -l | grep -c '^ii'
663
```

And on the host side, of the artifact itself:

| | |
| --- | --- |
| ext4 actually used | **1.82 GiB** |
| root partition | 2.50 GiB |
| GPT describes | 3.50 GiB |
| **`_disk0.raw` on disk** | **8.00 GiB** — 4.5 GiB lies beyond the partition table, pure zeros |
| `snapshot/memory-ranges` | 2.00 GiB |
| **materialised per capture** | **10 GiB** (~700 MB compressed) |

Three problems, in order of how much they hurt:

1. **The root filesystem is 74% full.** There is 633 MB of headroom. Installing
   a compiler, a language runtime and a package cache into that does not fit.
   The image cannot grow into an agent environment; it has to be built as one.
2. **663 packages of general-purpose cloud VM** — `cloud-init`, `snapd`,
   `landscape`, a full `apt` world — almost none of which an agent sandbox uses,
   all of which is attack surface and restore-time cost.
3. **10 GiB materialised for 1.82 GiB of payload.** Memory dominates the wire
   cost for `chm state-cdn reconstruct`, and 4.5 GiB of the disk file is
   literally zeros past the end of the partition table.

For comparison, the Firecracker CI rootfs for the same architecture
(`firecracker-ci/v1.12/aarch64/ubuntu-24.04.squashfs`) is **76.5 MB** and
**192 packages**. That is the right order of magnitude. It is 24× smaller than
what we are carrying, and it is still a real Ubuntu 24.04 userspace.

## 10. What we want

A capture named **`graviton-agent-min`**, built from a minimal rootfs rather
than a cloud image.

### 10.1 The kernel — this is the part that will bite

**Cloud Hypervisor puts virtio on PCI.** Our rehydrated guest enumerates
`00:03.0 Ethernet controller: Red Hat Virtio 1.0 network device [1af4:1041]`
and the device sits at `BAR 0x200080000`. A kernel without PCI boots fine and
then sees no disk and no network.

This is not hypothetical. **Do not reuse a Firecracker kernel.** We checked
`firecracker-ci/v1.12/aarch64/vmlinux-6.1.128.config` directly:

```
# CONFIG_PCI is not set
CONFIG_VIRTIO_MMIO=y
```

Firecracker is virtio-MMIO and compiles the whole PCI subsystem out. Under
Cloud Hypervisor that kernel is a brick. Their *rootfs* is reusable; their
*kernel* is not.

The known-good reference is the kernel already in capture B,
**`6.8.0-136-generic`**, which has exactly what we need:

```
CONFIG_PCI=y
CONFIG_PCI_HOST_GENERIC=y
CONFIG_PCI_MSI=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_ARM_GIC_V3=y
CONFIG_ARM_GIC_V3_ITS=y
```

**Simplest path: keep the stock Ubuntu kernel and change only the userspace.**
A custom slim kernel is welcome but is not what we are asking for, and if you
build one, those nine options are the contract. `ARM_GIC_V3_ITS` matters as much
as the PCI ones — the ITS is how MSIs reach the guest, and our restore path
expects it.

### 10.2 The rootfs

Start from a minimal Ubuntu 24.04 base (`debootstrap --variant=minbase`, or the
Ubuntu base tarball) rather than the cloud image. Target the Firecracker CI
rootfs's ~192-package shape, then add only what an agent genuinely needs.

**Remove / never install:** `cloud-init`, `snapd`, `landscape-common`,
`ubuntu-advantage-tools`, `unattended-upgrades`, documentation and locales.

> ⚠️ **`cloud-init` is load-bearing for the network today.** See §8 — capture B's
> static address is applied by cloud-init at capture time. If you drop
> `cloud-init`, configure the same addressing statically some other way
> (`systemd-networkd` unit, or `/etc/network/interfaces`), and keep the contract
> identical: guest `192.168.249.2/24`, gateway and DNS `192.168.249.1`, gateway
> MAC `02:00:00:00:00:01`. Dropping cloud-init *and* the static address gives us
> a guest with no route, which fails the whole point of the round.

**Install:** `git`, `curl`, `ca-certificates`, `openssh-client`,
`build-essential` (or at minimum `gcc`, `g++`, `make`, `binutils`, `libc6-dev`),
`python3`, `pkg-config`, `unzip`, `xz-utils`.

One language runtime beyond Python is worth having. Node LTS is the most useful
single choice for agent workloads; if that is contentious, ship without it and
we will say so rather than guess.

Also please **`apt clean`** and drop `/var/lib/apt/lists` before the capture, and
**zero the free space** (`fstrim -av`, or `dd if=/dev/zero of=/zero; sync; rm
/zero`) so the memory and disk images compress properly.

### 10.3 Sizing

| Knob | Round 2 | **Round 3 ask** | Why |
| --- | --- | --- | --- |
| vCPUs | 2 | **2** | Keep it — it is what found the SMP counter bug, and we want that surface. |
| RAM | 2 GiB | **1 GiB** | Memory dominates the wire cost. Do not go to 512 MiB — a compiler needs room, and we would rather have a working image than a record-breaking one. |
| root partition | 2.5 GiB | **4 GiB** | *Larger* than today on purpose: the goal is low **used**, with headroom to install into. 74% full is what makes the current image a dead end. |
| disk file | 8 GiB | **≤ 4 GiB** | Do not hand us 4.5 GiB of zeros past the end of the GPT. Size the file to the partition table. |
| **target used** | 1.82 GiB | **≤ 1 GiB** | ~76 MB base + toolchain. If it lands at 1.2 GiB that is still a win; tell us the number. |

### 10.4 Everything else stays exactly as round 2

Same host, same CH build (v54.0.0 @ `9ea9019d29af` or newer — it must contain
`69637dde6`), GICv3 with ITS enabled, one virtio-net NIC, and the same pause
discipline: **the guest must be quiescent before you pause** (§3). Same metadata
block, `CNTFRQ_EL0` first.

## 11. Acceptance checks for round 3

Run these **inside the guest, before you pause**, and paste the output. Each one
is a failure we have actually hit.

```bash
# 1. PCI is alive and virtio is on it — the Firecracker-kernel trap.
lspci -nn | grep -i virtio          # expect 1af4:1041 (net) and 1af4:1042 (blk)

# 2. The NIC is up and on OUR contract, not cloud DHCP.
ip -br addr                          # expect 192.168.249.2/24
ip route                             # expect default via 192.168.249.1

# 3. The toolchain is real.
git --version && cc --version && make --version && python3 -V

# 4. It can actually build and fetch.
git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw
printf 'int main(void){return 0;}' > /tmp/t.c && cc /tmp/t.c -o /tmp/t && echo BUILD_OK

# 5. The size claim, so we can check it against the artifact.
df -h / && dpkg -l | grep -c '^ii'

# 6. Quiescent (§3) — no cloud-init or apt still running.
systemctl is-system-running          # expect running or degraded, NOT starting
```

Check 1 is the one that decides the round. If `lspci` is empty, the kernel lacks
PCI and nothing else matters.

## 12. What we will do with it

Rehydrate it on Apple silicon and use it as the default sandbox image for a
coding agent: `chm workspace` it, run an agent inside, and let that agent clone,
build and test through the credential-injecting egress proxy — which has been
built and host-tested but has still never had a real agent workload behind it.

A read-only base is a **feature** for us, not a limitation. We already do
copy-on-write at the block layer: a live session's overlay on capture B measured
**4.3 MB**. A small immutable base plus per-sandbox COW is the architecture we
want, and the smaller the base, the more sandboxes we can hold and ship.
