# The first resume of a real cloud capture

A snapshot captured on a cloud host arrives describing the machine it was
captured from, not the machine you want. A few things stand between a freshly
rehydrated capture and installing a package, and none of them is a hypervisor
defect. They are recorded here because each one cost a debugging cycle to find
and each one is a single command to fix.

Measured on the two round-2 vanilla Cloud Hypervisor captures taken on an AWS
Graviton2 host, `graviton-vanilla-2cpu-net` and `graviton-vanilla-1cpu`. Where
the two disagree, that is said explicitly — **it is the most useful fact on the
page**, because a wall that appears on one capture and not the other is an
accident of the moment that capture was taken, not something rehydration does
to you.

| § | Wall | Present on |
| --- | --- | --- |
| 1 | Root filesystem has no room | both |
| 2 | DNS is dead | **neither** — see the section for what this used to be |
| 3 | Package database arrives half-applied | **`2cpu-net` only** |
| 4 | Chromium's sandbox cannot start | both |
| 5 | JIT code executes stale instructions | workload-dependent |
| 6 | The guest reports an RCU stall right after resume | **`2cpu-net` only** |

> If you cold-booted from a container image or a BYO kernel, none of this
> applies: nothing was captured, so nothing arrived stale.

## 1. The root filesystem may have no room — **chm detects this**

```
/dev/vda1       2.4G  2.3G   56M  98% /
```

The partition was sized for the cloud instance's original volume. The disk the
snapshot declares is much bigger, and the space past the last partition is
simply unclaimed.

`chm` reads the capture's GPT and the device size it declares, so it says so on
resume:

```
chm: note: this capture's partition table leaves 5.6 GiB of its 8.0 GiB disk
unused, so the guest's root filesystem is smaller than the disk it sits on ...
```

Fix it once, inside the guest:

```sh
sudo sgdisk -e /dev/vda && sudo growpart /dev/vda 1 \
  && sudo partx -u /dev/vda && sudo resize2fs /dev/vda1
```

`sgdisk -e` is first and is the step nobody guesses: the backup GPT header is no
longer at the end of a device that grew, and `growpart` refuses until it is
moved there.

**`partx -u` comes after `growpart`, not before**, and that ordering is the
whole difference between this working and silently doing nothing. `growpart`
rewrites the table on disk; `partx -u` is the only step that carries a new table
into a kernel that is already running. Put it first and it publishes the
geometry you are trying to leave behind, `growpart` then changes the GPT with
nothing left to announce it, and `resize2fs` grows the filesystem to fill the
kernel's unchanged view -- reporting `Nothing to do!` while being entirely
correct. All four commands exit 0 and the disk is still full. This is
[#284](https://github.com/gimbal-dev/gimbal-local/issues/284).

**Why `chm` does not do this for you.** Growing the partition means rewriting the
partition table and resizing a *mounted* ext4 filesystem underneath a kernel
whose RAM was restored describing the old geometry. Changing a filesystem behind
a restored kernel's back is precisely the metadata-mismatch hazard the
copy-on-write overlay model exists to prevent (see `docs/project-state.md`). The
guest has to do it, from inside, while it is running.

The notice goes quiet once the guest has rewritten its own partition table, so a
capture you already grew will not nag you.

## 2. DNS is dead while the network is fine — **withdrawn, and worth reading anyway**

This section used to lead the page, and it described a capture whose
`systemd-resolved` had not survived capture and restore. A genuinely dead
resolver looks like this:

```
$ getent hosts nodejs.org; echo $?
2
$ systemctl is-active systemd-resolved
Failed to retrieve unit state: Connection timed out
$ ip -br a
ens3   UP   192.168.249.2/24
```

**Neither round-2 capture behaves that way.** Measured directly:

| Reading | `2cpu-net` | `1cpu` |
| --- | --- | --- |
| `getent hosts ports.ubuntu.com` | `rc=0` | no NIC, not applicable |
| `systemctl is-active systemd-resolved` | — | **`active`** |
| `/etc/resolv.conf` | — | `nameserver 127.0.0.53` |

So the `127.0.0.53` half of the old diagnosis is right and the load-bearing half
is wrong: the stub resolver is up, and lookups through it succeed. **Do not
overwrite `/etc/resolv.conf`.** On these captures that replaces a working
configuration with a hand-rolled one, and you will not find out until something
needs a search domain.

**What this most likely was.** Round-1 captures were taken *mid-`cloud-init`* —
that is the documented defect in our own capture request, corrected for round 2
(`docs/graviton-capture-request.md`). A snapshot that lands while `cloud-init` is
still bringing units up is exactly how you capture a `systemd-resolved` that
never finishes starting. The section is kept rather than deleted because that
class of capture still exists and the symptom is genuinely misleading: every
download fails with `Could not resolve host`, which reads like "there is no
network" while the network is completely fine.

**Check before you change anything:**

```sh
systemctl is-active systemd-resolved   # expect: active
getent hosts ports.ubuntu.com; echo $? # expect: 0
```

Only if the resolver is genuinely dead, point the guest at the gateway:

```sh
echo "nameserver 192.168.249.1" | sudo tee /etc/resolv.conf
```

`192.168.249.1` is `chm`'s own address on the guest network; it answers DNS
directly, under whatever egress policy the sandbox is running with.

**Why this is not detected.** It is a fact about a process inside the guest.
From the host, a guest whose resolver is dead and a guest that has simply not
looked anything up yet are indistinguishable — neither sends a query. Warning on
that would mean warning on every healthy idle guest, and a notice that fires
when nothing is wrong stops being read. See #259.

## 3. One capture arrives with a half-applied package database — **not detected**

```
E: Unmet dependencies. Try 'apt --fix-broken install'
```

Measured on `graviton-vanilla-2cpu-net`: the very first `apt-get install` of
anything exits **100**, and the message blames your package list.

**The cloud instance was mid-`dpkg` transaction when it was snapshotted**, so a
half-applied package state was captured along with everything else. That
sentence is the one part of this section that has always been right.

**The cure is one command, and you may have to run it twice:**

```sh
sudo apt --fix-broken install -y
```

Measured returning `rc=0` and clearing the state completely — `dpkg -l | grep -v
'^ii'` and `sudo dpkg --audit` both silent afterwards, and still silent after an
intervening suspend and resume. The retry advice is not superstition: repairing
this state runs `update-initramfs`, and `update-initramfs` was measured
segfaulting **3 times in 6 consecutive runs** on a rehydrated capture (#366). A
single failure means run it again, not that the cure does not work.

**It is capture-specific, not something rehydration does to you.** The other
round-2 capture, `graviton-vanilla-1cpu`, comes up with `dpkg -l | grep -v '^ii'`
and `sudo dpkg --audit` both **empty** — a completely clean package database from
the same capture pipeline. One capture caught a transaction in flight; the other
did not.

**The broken state is in the captured RAM, not on the disk.** Reading the raw
disk image host-side shows `initramfs-tools` as `Status: install ok installed`,
and the string `half-configured` appears **zero** times across the whole 8 GiB
image — while the live guest calls that exact package `iF`. The divergence runs
in both directions, which is the signature of an interrupted `dpkg --configure
-a`. This is the project's own *"RAM and disk must be captured together"* hazard
arriving from the cloud side.

**Why this is not detected**, correctly, but not for the reason previously given
here. The old text said reading the state would mean mounting the guest's ext4
from the host. That is not true — `grep -a -b -o` on the raw image finds dpkg
stanzas directly. The real reasons are worse:

- the disk is **clean**, so a host-side scan reads a healthy package database and
  reports nothing; and
- once the guest repairs itself, every write lands in the copy-on-write overlay
  while the base image still says what it always said — so a scan of the base
  would nag forever about a problem that has been fixed.

**The durable fix is at capture time.** Ask whoever produces your captures to
take them from a settled instance: after `cloud-init`, after any unattended
upgrade, with `sudo dpkg --audit` silent. A capture is only as clean as the
moment it was taken, and this is now a stated requirement in
`docs/graviton-capture-request.md`.

## 4. Chromium's own sandbox cannot start — **not detected**

```
$ sysctl kernel.apparmor_restrict_unprivileged_userns
kernel.apparmor_restrict_unprivileged_userns = 1
$ unshare --user --map-root-user true
unshare: write failed /proc/self/uid_map: Operation not permitted
```

Measured **identically on both round-2 captures**, so unlike §3 this one is a
property of Ubuntu 24.04 rather than of a single snapshot. Ubuntu 24.04 restricts
unprivileged user namespaces by default, and Chromium's layer-1 sandbox needs
one. Without it the browser exits with `FATAL: ... No usable sandbox!`, which
from the outside looks like the browser simply never came up — you only see the
real reason if you read its stderr.

Allow unprivileged user namespaces:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

`--no-sandbox` also gets the browser running and is **the weaker answer**: it
removes the browser's own privilege separation, so a renderer compromise is no
longer contained by anything except the VM boundary. Prefer the sysctl, and treat
`--no-sandbox` as a fallback for when you cannot set it.

> This does **not** contradict the container-image measurement recorded for the
> browser sandbox image, where Chromium keeps its own sandbox running as an
> unprivileged uid. A container rootfs built by `chm image build` carries no
> AppArmor policy at all, so the restriction is simply not present there. The
> difference is the rootfs, not the hypervisor. See #344.

## 5. JIT code, and why the `--jitless` advice is no longer the first answer

Not a first-resume wall so much as the next one, and the part of this page that
has moved the most.

**The old advice was `NODE_OPTIONS=--jitless`, and the figures behind it are
stale.** They were measured before the instruction-cache stride bug was found and
fixed: a rehydrated Graviton guest was telling userspace the i-cache line was
4096 bytes against a real granule of 64, so every maintenance loop in the guest
invalidated one line in 64. `chm` now sets `SCTLR_EL1.UCT` at restore, which
sends those reads to the hardware. Across that fix, on one binary and one
revision with only an environment variable changed, `npm --version` went from
**5 of 20** to **20 of 20**.

A later acceptance run installed the GitHub Copilot CLI on a capture carrying 12
days of AWS uptime and had it write and run a program — **without `--jitless`**.

**So treat this as workload-dependent rather than solved.** Reach for
`--jitless` when you actually see a `SIGILL`, not pre-emptively:

```sh
sudo env NODE_OPTIONS=--jitless npm i -g <package>
```

That form matters: `sudo` strips `NODE_OPTIONS` from the environment, so
`export`ing it and then running `sudo npm` silently drops it.

`chm` warns about the remaining hazard on every affected resume, and the full
measurement is in `docs/cpu-feature-deltas.md`.

### What is still genuinely exposed

The fix corrects the stride userspace uses for its own cache maintenance. It does
not restore the maintenance the guest kernel elided at boot on the assumption
that its i-cache snooped. On the path where a program maps a page writable, writes
code into it, then flips it executable with `mprotect(PROT_READ|PROT_EXEC)`, a
rehydrated guest still reads stale instructions **998 times out of 1000**. See
[#287](https://github.com/gimbal-dev/gimbal-local/issues/287).

Node and npm do not take that path. A package that ships its own compiled binary
and execs it may.

**A cold-booted guest is immune to all of this by construction** — it reads this
Mac's own `CTR_EL0` and keeps the maintenance its kernel would otherwise have
elided. That is a real property to reach for if you are choosing between the two,
but it is no longer the recommendation for running an agent, because a rehydrated
capture has now done it.

## 6. The guest reports an RCU stall right after resume — **chm classifies this**

The first thing a rehydrated guest may print is its own kernel accusing itself:

```
rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks: { 1-.... }
```

That line is alarming and, immediately after a resume, usually means nothing is
wrong. The guest was frozen between two ticks; from inside, the interval that
elapsed while it was suspended looks exactly like a tick that never arrived, and
its stall detector fires on a gap it has *already come out of*.

**chm tells the two apart, and the tag is the answer.** Immediately below the
kernel's line you will see one of two things:

```
[stall] vcpu 0 the guest reported a stall it has already recovered from -- nothing is stuck
[stall] vcpu 0   the next tick is 272us away, no INTID is stuck active and the timer is
                 live (trigger=guest-reported-stall); expected after a resume, see
                 docs/first-resume.md
```

`[stall]` means chm looked and found nothing stuck: the virtual timer is enabled,
no interrupt is jammed in the active stack, and the next tick is microseconds
out. The guest's complaint is behind it. **Nothing to do.**

```
[wedge] vcpu 0 trigger=guest-reported-stall verdict=gic-model: an INTID is stuck active ...
```

`[wedge]` is the opposite: chm looked and something *is* stuck. The verdict names
the owner. Report that one --
[open an issue](https://github.com/gimbal-dev/gimbal-local/issues) with the four
`[wedge]` lines, which carry everything needed to classify it.

The kernel's own stall line is left alone deliberately. Suppressing a real
message from the guest to make our own output tidier would be lying about
something we did not observe; chm can say what it found, and it should not say
what the guest found on its behalf.

**Only the `2cpu-net` capture has produced this**, and only in the first seconds
after a resume. Why the guest reports a stall on a resume where nothing is stuck
is not explained -- forcing a large counter advance
(`CHM_FORCE_RESUME_ADVANCE_S=3600`) produced **zero** stalls, which argues
against the obvious "the clock jumped" answer. The classification is honest
about that: it reports what it can see, and what it can see is that nothing is
stuck.

## In short

```sh
sudo sgdisk -e /dev/vda && sudo growpart /dev/vda 1 \
  && sudo partx -u /dev/vda && sudo resize2fs /dev/vda1
sudo apt --fix-broken install -y      # only if apt exits 100; retry if it dies
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # only for Chromium
```

The first line is the only one every capture needs. The second is for a capture
that was taken mid-transaction, and the third only if you are running a browser.
Do **not** overwrite `/etc/resolv.conf` and do **not** set `NODE_OPTIONS`
pre-emptively — both were once standard advice on this page and both now make a
working configuration worse. Reach for them only against the symptoms described
in §2 and §5.
