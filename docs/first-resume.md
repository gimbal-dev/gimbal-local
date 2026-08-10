# The first resume of a real cloud capture

A snapshot captured on a cloud host arrives describing the machine it was
captured from, not the machine you want. Three things stand between a freshly
rehydrated capture and installing a package, and none of them is a hypervisor
defect. They are recorded here because each one cost a debugging cycle to find
and each one is a single command to fix.

Measured on `graviton-vanilla-2cpu-net` — a vanilla Cloud Hypervisor capture
taken on an AWS Graviton2 host.

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
sudo sgdisk -e /dev/vda && sudo partx -u /dev/vda \
  && sudo growpart /dev/vda 1 && sudo resize2fs /dev/vda1
```

`sgdisk -e` is first and is the step nobody guesses: the backup GPT header is no
longer at the end of a device that grew, and `growpart` refuses until it is
moved there.

**Why `chm` does not do this for you.** Growing the partition means rewriting the
partition table and resizing a *mounted* ext4 filesystem underneath a kernel
whose RAM was restored describing the old geometry. Changing a filesystem behind
a restored kernel's back is precisely the metadata-mismatch hazard the
copy-on-write overlay model exists to prevent (see `docs/project-state.md`). The
guest has to do it, from inside, while it is running.

The notice goes quiet once the guest has rewritten its own partition table, so a
capture you already grew will not nag you.

## 2. DNS is dead while the network is fine — **not detected**

This is the worst of the three, because the symptom actively misleads.

```
$ getent hosts nodejs.org; echo $?
2
$ systemctl is-active systemd-resolved
Failed to retrieve unit state: Connection timed out
$ ip -br a
ens3   UP   192.168.249.2/24
```

`/etc/resolv.conf` points at `127.0.0.53`, the `systemd-resolved` stub, and
`systemd-resolved` does not survive capture and restore. Every download then
fails with `Could not resolve host`, which reads like "there is no network" —
and the network is completely fine. Users conclude that networking is broken and
file a bug against the part that works.

Point the guest at the gateway instead:

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

## 3. The capture may arrive with a broken package database — **not detected**

```
 linux-tools-6.8.0-137-generic : Depends: linux-tools-6.8.0-137 but it is not
                                 going to be installed
E: Unmet dependencies. Try 'apt --fix-broken install'
```

The cloud instance was mid-upgrade when it was snapshotted, so its half-applied
package state was captured along with everything else. `apt --fix-broken
install` does not clear it, and removing the offending package fails on its own
unmet dependency.

This is inherited from the capture. `chm` cannot repair someone else's package
state, and cannot see it either — reading it would mean mounting the guest's ext4
filesystem from the host, which is the same hazard as §1.

The reliable way past it is to bypass `apt` for the thing you actually need. For
Node, the upstream tarball works:

```sh
curl -fsSLO https://nodejs.org/dist/v22.11.0/node-v22.11.0-linux-arm64.tar.xz
sudo tar -xJf node-v22.11.0-linux-arm64.tar.xz -C /usr/local --strip-components=1
```

Better: ask whoever produces your captures to take them from a settled instance,
after `cloud-init` and any unattended upgrade have finished. A capture is only as
clean as the moment it was taken.

## 4. And then: turn the JIT off

Not a first-resume wall so much as the next one. A guest captured on Graviton
carries a kernel that elides instruction-cache maintenance this Mac needs, so
JIT compilers execute stale code. `npm --version` failed **10 times out of 10**
on a rehydrated capture, and succeeded **5 of 5** with:

```sh
echo 'export NODE_OPTIONS=--jitless' | sudo tee /etc/profile.d/jitless.sh
```

`chm` warns about this on every affected resume. The full measurement is in
`docs/cpu-feature-deltas.md`; a cold-booted guest is immune.

## In short

```sh
sudo sgdisk -e /dev/vda && sudo partx -u /dev/vda \
  && sudo growpart /dev/vda 1 && sudo resize2fs /dev/vda1
echo "nameserver 192.168.249.1" | sudo tee /etc/resolv.conf
echo 'export NODE_OPTIONS=--jitless' | sudo tee /etc/profile.d/jitless.sh
```

Three lines, once, and a rehydrated cloud capture behaves like a machine you can
work in.
