# Container images as bootable sandboxes

`chm image build` turns an OCI/Docker image into something that cold-boots on
Apple Hypervisor.framework — no snapshot, no KVM host, nothing captured
anywhere in the path.

```
chm image build alpine:3.20 --out ~/gimbal-images/alpine
chm create --kernel ~/gimbal-images/alpine/Image \
           --initramfs ~/gimbal-images/alpine/initramfs --cpus 2 --memory 512
```

Images written to your local images directory (default `~/gimbal-images`, or
`GIMBAL_IMAGES`) also appear in Gimbal Local under
**New sandbox → Cold boot from a local image**.

## Read this before you start

One limit will bite you in the first ten minutes if you do not know about it,
and two that used to are now handled for you. All were measured on real
hardware; none is a hypervisor defect.

### 1. You must bring your own kernel, and most of them need their modules too

A container image is a **rootfs**. It contains no kernel, so `--kernel` is
required.

The trap is what happens next. Cold boot presents its devices on
**virtio-mmio**, and many arm64 distro kernels build the whole virtio stack as
*modules*:

```
$ grep -E "^CONFIG_VIRTIO_(MMIO|NET|BLK)=" config-6.6.142-0-virt
CONFIG_VIRTIO_BLK=m
CONFIG_VIRTIO_NET=m
CONFIG_VIRTIO_MMIO=m      <-- the transport itself
```

A container rootfs ships no `/lib/modules`, so on its own the driver and its bus
can never meet: the guest boots to a shell perfectly and then

```
ip: can't find device 'eth0'
```

**Point `--modules` at the kernel's module tree and chm handles the rest.**

```
chm image build alpine:3.20 --out ~/gimbal-images/alpine \
    --kernel /path/to/Image --modules /path/to/lib/modules/6.6.142-0-virt
```

chm reads the release banner out of the kernel itself, checks each module's
`vermagic` against it, resolves the virtio dependency closure, installs it, and
generates an init that loads it **before** configuring the interface. On Alpine
`linux-virt` that is 5 modules and 238 KiB out of 916 in the tree:

```
bundled 5 virtio modules (238.2 KiB) from lib/modules/6.6.142-0-virt
  virtio_mmio, failover, net_failover, virtio_net, virtio_blk
```

Three things it does for you that are easy to get wrong by hand:

- **Order.** Loading `virtio_net` alone returns success and still leaves no NIC,
  because the *transport* is what was missing. `virtio_mmio` goes first.
- **No `insmod` required.** `debian:12-slim` ships neither `insmod` nor
  `modprobe`; chm falls back to a small static loader that calls
  `finit_module` directly.
- **Waiting.** virtio_mmio probes devices on a workqueue, so `eth0` appears
  *after* the load call returns. The generated init waits for the interface
  rather than racing it.

`--modules` requires `--kernel` and is refused without it, before anything is
pulled — the release to match against comes from the kernel's own banner.

Where to get a matched pair: Alpine's `linux-virt` apk ships **both** the kernel
and its modules in one download, already siblings, so chm finds the tree
automatically if you pass a kernel from inside the extracted apk. An apk is
concatenated gzip members, so extract with `gunzip -c linux-virt.apk | tar -xf -`.

### Which kernels actually work

Measured on this project, booting a stock `alpine:3.20` rootfs:

| kernel | virtio built in? | result |
| --- | --- | --- |
| **Ubuntu `linux-image-*-generic` arm64** | yes | ✅ `eth0` with no modules at all |
| Alpine `linux-virt` / `linux-lts` | no (`=m`) | ✅ with `--modules`; no NIC and no disk without it |
| Firecracker CI `vmlinux-*` aarch64 | yes | ❌ **no console** — see below |

Either of the first two is fine. Ubuntu `generic` is the same family as a
Graviton snapshot and needs no module tree:

```
curl -O http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-image-unsigned-6.8.0-71-generic_6.8.0-71.71_arm64.deb
ar x linux-image-*.deb && tar -xf data.tar
```

Hand `chm` the `boot/vmlinuz-*` directly — it unwraps gzip and EFI zboot itself
(see §2).

**Firecracker's CI kernels look ideal and are not.** They are mmio-only, so
virtio is built in — but they are compiled with `CONFIG_SERIAL_8250` and **no
`CONFIG_SERIAL_AMBA_PL011`**, while chm presents a PL011. The guest boots and
emits nothing at all, which is indistinguishable from a hang.

### 2. Compressed kernels are unwrapped for you

Alpine's `vmlinuz-virt` is an **EFI zboot** wrapper (`MZ` at 0, `zimg` at 4),
not a raw `Image`, and Ubuntu ships a plain gzip stream. Both used to be
refused, and the zboot refusal named *x86*, which was actively misleading.

`chm` now reads the container header, decompresses the payload and verifies
`ARM\x64` at offset `0x38` of the result, so you can hand it the file the distro
actually ships. It says which form it found.

### 3. The rootfs unpacks into guest RAM — unless you pass `--disk`

By default the rootfs ships as a **cpio initramfs**. That has a genuine upside:
the kernel needs no `root=`, so the whole PARTUUID-mismatch failure class
disappears. But it means the image is unpacked into RAM at boot, and is
therefore resident roughly twice at the peak.

`image.json` records a measured `ram_mib` for this reason, and the app uses it.
A large image needs a large `--memory`, and there is a ceiling of **3008 MiB**
for a cold boot (guest RAM starts at `0x40000000` and one region must end by
`0xfc000000`). chm states this exactly when you exceed it.

For images too large to unpack into RAM, `--disk` writes the rootfs as an
**ext2 image** the guest mounts instead:

```
chm image build node:22-slim --kernel ./Image --disk --out ~/gimbal-images/node
chm create --kernel ~/gimbal-images/node/Image \
           --disk ~/gimbal-images/node/rootfs.img --cpus 2 --memory 512
```

Guest RAM is then sized for the workload rather than for the image, and writes
persist across boots.

Two things worth knowing before you choose it:

- **The kernel must have `virtio_blk` built in**, or the disk is accepted and
  the guest sees nothing. `chm image build` already checks the kernel you pass
  and says so. An Ubuntu `generic` arm64 kernel has it; Alpine's `virt` does
  not.
- **A disk that has been written to is a workspace, not an image.** The build is
  reproducible from the image digest, but the moment a guest writes to
  `rootfs.img` that copy has diverged and rebuilding will not reproduce it. Copy
  the file per sandbox if you want the original back.

There is no `mkfs.ext4` on macOS, `hdiutil` only produces HFS/APFS, and building
the filesystem inside a short-lived guest does not work either — the Alpine
initramfs we boot carries exactly one `mkfs`, `mkfs.vfat`, and FAT has no
symlinks, no ownership and no executable bit, which a container rootfs needs on
essentially every path. So chm writes the image itself, on the host. That is
tractable because of its scope: it is a one-shot serialiser for a tree that is
already complete, not a filesystem implementation. Every write after the first
boot is performed by Linux's own ext2 driver.

## Choosing a base image

**Use a glibc image for agent workloads.** `node:22-slim`, `debian`, `ubuntu`.

`chm image build` classifies the rootfs it just unpacked and says so, so you
find this out at build time rather than several minutes into a guest:

```
libc:       musl
NOTE: this image uses musl. Prebuilt Node-API addons are linked against
      glibc and fail here with `napi_* has not been loaded` — the GitHub
      Copilot CLI among them.
```

Musl images (`*-alpine`) boot and run general workloads fine. The problem is
specific: the GitHub Copilot CLI downloads a prebuilt `linuxmusl-arm64` runtime
at first use, and that binary fails to load its own Node-API symbols:

```
Node-API symbol napi_create_function has not been loaded
Node-API symbol napi_create_int32 has not been loaded
```

`npm i -g @github/copilot` itself succeeds — the failure is at first run.

Measured as a controlled pair, same kernel, same `chm` build, same egress
allow-list, same node version (v22.23.2), **libc the only variable**:

| base | libc | `npm i -g @github/copilot` | `copilot --version` |
| --- | --- | --- | --- |
| `node:22-slim` | glibc 2.36 | rc=0 | **1.0.78, rc=0** |
| `node:22-alpine` | musl | rc=0 | **`napi_*` unloaded, rc=1** |

An image carrying **both** loaders is reported as `not identified` and draws no
warning. Both readings are real — a Debian image with `musl-dev` runs a glibc
`node` whose addons load, an Alpine image with `gcompat` runs a musl one whose
addons do not — and nothing at build time can tell them apart. A warning that
fires on a working image is worse than a missing one.

Tracking: [#224](https://github.com/gimbal-dev/gimbal-local/issues/224).

## Entrypoints

The image's own entrypoint is used unless you override it. That is often not a
shell — `node:22-alpine` defaults to `docker-entrypoint.sh node`, which drops
you into a Node REPL rather than a prompt, and `node:22-slim` defaults to plain
`node` for the same result. Pass `--entrypoint /bin/sh` (or `/bin/bash` on a
Debian-based image) when you want a shell.

## A working agent sandbox, end to end

Two things must both be true before the GitHub Copilot CLI will run in a
container-image guest, and each one fails differently. The issue that prompted
this ([#224](https://github.com/gimbal-dev/gimbal-local/issues/224)) named only
the first; the second — and a third that has since been fixed outright — were
found by testing the recommendation rather than publishing it.

| requirement | if you skip it |
| --- | --- |
| **glibc rootfs** | `Node-API symbol napi_create_function has not been loaded` at first run |
| **`--entrypoint /bin/sh`** | you land in a Node REPL, not a shell |

A third used to bite here — a kernel with no RTC driver left the guest at the
epoch, and *every* TLS handshake then failed with `certificate is not yet
valid`, an error that names the network for a fault in the clock. `chm` now
passes the host time on the kernel command line in every case, and that is
verified to work on a kernel with **no RTC at all**, so you no longer have to
think about it. See [the clock section](#the-guest-is-told-what-time-it-is).

Kernel and userland are independent, so mixing them is legitimate and is what
the working combination does — the Alpine `virt` kernel for its drivers, a
Debian rootfs for its glibc:

```bash
chm image build node:22-slim \
  --kernel /path/to/vmlinuz-virt \
  --modules /path/to/alpine-modules \
  --entrypoint /bin/sh \
  --out ~/gimbal-images/agent

chm create \
  --kernel ~/gimbal-images/agent/Image \
  --initramfs ~/gimbal-images/agent/initramfs \
  --cpus 2 --memory 3008 --net \
  --egress-allow registry.npmjs.org:443 \
  --egress-allow github.com:443 \
  --egress-allow objects.githubusercontent.com:443 \
  --egress-allow api.github.com:443
```

Then, in the guest:

```
npm i -g @github/copilot && copilot --version
```

Measured on this exact combination, so it can be retested rather than believed:

```
CLOCK=2026-08-07T16:32:34   RTC=/dev/rtc0   NIC=02:00:00:00:00:02
NPM_RC=0
CV_RC=0
CVOUT=GitHub Copilot CLI 1.0.78
```

Versions: Copilot CLI **1.0.78**, node **v22.23.2**, npm **10.9.8**, Alpine
`virt` kernel **6.6.142-0-virt**, `node:22-slim` (glibc 2.36).

The `--egress-allow` list is the minimum for `npm i -g @github/copilot`;
authenticating and running the agent needs more, and the guest names each host
it is refused so you can add them one at a time.

## Platform selection

`--platform os/arch[/variant]` picks a manifest from a multi-arch index. A
platform this host cannot boot is **refused before a byte is fetched** — an
accepted `linux/amd64` would pull real layers, verify real digests and write a
real image directory that could never start.

Layer codecs are detected by magic bytes rather than `mediaType`, because
registries mislabel. gzip and zstd are both read.

## What you get in the guest

The generated init brings the rootfs up and hands over to your entrypoint with
a controlling terminal, so job control works and Ctrl-C interrupts:

```
gimbal: container rootfs up; starting /bin/sh
~ # tty
/dev/ttyAMA0
```

If your image has no `setsid` — it comes from busybox on Alpine and util-linux
on Debian, so nearly everything has one — init falls back to starting the
entrypoint directly. You then get the older behaviour, and it says so:

```
/bin/sh: can't access tty; job control turned off
```

That is a working shell without Ctrl-C, not a failure.

## The guest is told what time it is

`chm` attaches a PL031 real-time clock, but reading it is the guest's half of
the bargain — and a container rootfs ships **no `/lib/modules`**, while Ubuntu's
arm64 generic kernel builds `rtc-pl031` as a module in `linux-modules-extra`. So
`/dev/rtc0` is simply absent and the guest would start at the Unix epoch.

That breaks much more than a timestamp. **Every TLS certificate is "not yet
valid" in 1970**, so `apt`, `pip`, `npm` and `git clone` all fail with errors
that read like a broken network:

```
ERR=CERT_NOT_YET_VALID
```

So `chm create` passes the host's wall clock on the kernel command line as
`gimbal.epoch=<unix seconds>`, and the generated init reads `/proc/cmdline` and
runs `date -s` before anything that could need it — before `/etc/resolv.conf`,
before the NIC, before your entrypoint. `date` ships in coreutils (Debian
Essential) and in busybox, and the init is a shell script, so any image it runs
in has one; verified on GNU coreutils and BusyBox 1.36.1.

You do not need to do anything, and this now holds **however you booted** —
including with an explicit `--cmdline`. To check:

```
date -u        # within a second or two of your Mac
```

> **This was not always true, and the failure was ugly.** Until recently the
> clock was attached only when you did *not* pass `--cmdline` — by analogy with
> `root=`, which genuinely must not be overridden. The analogy is false: `root=`
> is a *choice*, and the wall clock is a *fact about now*. There is no command
> line for which "and therefore the year is 1970" is what the caller meant.
>
> It stayed hidden because the app passes `--cmdline console=ttyAMA0` on every
> cold boot, and Alpine's `virt` kernel has PL031 **builtin** — so the RTC
> covered for the missing argument and the guest's clock was right anyway. Boot
> the same rootfs on Ubuntu's generic kernel, which has no builtin PL031, and
> the clock silently falls back to the epoch. Measured, on identical rootfs:
>
> | kernel | `/dev/rtc0` | guest clock |
> | --- | --- | --- |
> | Alpine `virt` 6.6.142-0-virt | present | correct |
> | Ubuntu generic 6.8 | **absent** | **1970-01-01** |
>
> If you set `gimbal.epoch=` yourself, that is taken at your word and left
> alone.

## Networking, once the drivers are there

The guest sits at `192.168.249.2/24` behind gateway `192.168.249.1` (see
[`networking.md`](networking.md)). A snapshot receives this from capture-side
cloud-init; a container rootfs has neither cloud-init nor a DHCP client, so
**the generated init assigns it**, using `ip` if the image has it and
`ifconfig` otherwise. Both produce the same result, and both are skipped
entirely when you boot without `--net`.

You do not need to configure anything. If you want to check:

```
ip addr show eth0     # inet 192.168.249.2/24
ip route              # default via 192.168.249.1 dev eth0
```

### If the image has neither `ip` nor `ifconfig`

Configuring an interface needs an ioctl, and no shell builtin makes one. Rather
than leave you a silent NIC, `chm` installs a small static `aarch64` helper into
the initramfs and the init falls back to it — so **an image with no networking
tools at all still comes up configured**. `node:22-slim` is the case that
motivated it: it ships neither `ip` nor `ifconfig`, and it needs no intervention.

The order is `ip`, then `ifconfig`, then the bundled helper. Only if all three
fail does the init say so, and it names the addresses you would need:

```
gimbal: eth0 is present but could not be configured: this image
gimbal: has no working 'ip' or 'ifconfig', and chm's own
gimbal: configurator did not run. Configure it yourself with:
gimbal:   <tool> addr add 192.168.249.2/24 dev eth0
gimbal:   <tool> route add default via 192.168.249.1
```

**The guest still boots and you still get a shell** — only the NIC would be
unconfigured.

Kernel-side `ip=` autoconfiguration does **not** rescue this — the Ubuntu
generic kernel is built without `CONFIG_IP_PNP` and prints
`Unknown kernel command line parameters "ip=..."`.

Egress is default-deny on `chm create`. Name what you need with
`--egress-allow host:port`; hosts named in a credential rule imply their own
allowance when the rule and the policy come from the same authority (invariant
I13, see [`credential-proxy.md`](credential-proxy.md)).

Verified end to end on an Ubuntu-kernel `alpine:3.20` guest: `eth0` appeared
with no `modprobe`, came up already carrying `192.168.249.2/24` and its default
route, and reached `registry.npmjs.org` through the NAT and the egress
allow-list.

### TLS from a bare `alpine` rootfs

This used to fail, and the reason was not what it looked like. Busybox `wget`
returned `Connection reset by peer` against `example.com`, `github.com` and
`registry.npmjs.org` alike, while `--no-check-certificate` succeeded — which
reads like busybox's minimal built-in TLS being unable to verify real-world
certificate chains.

**It was the clock.** Every certificate is outside its validity window when the
guest thinks it is 1970, and that is indistinguishable from a chain it cannot
verify. Re-measured on a bare `alpine:3.20` rootfs once the guest is told the
time:

```
CLK=2026-08-07
PLAIN=0     # wget, certificate checking on
NOCHK=0     # --no-check-certificate, for comparison
```

`--no-check-certificate` is still the fastest way to split "the sandbox's
network" from "this guest's TLS" in one command, and it remains worth trying
before going looking. But it should now succeed either way.

If a tool inside the guest must trust the credential proxy, note that **Node
ignores the system trust store** — set `NODE_EXTRA_CA_CERTS` as well as
installing the CA.

## Sandboxes started this way are not yet listed in the app

Cold boot runs as a subprocess with its own Terminal window, deliberately: the
daemon owns a single HVF slot, so routing cold boots through it would serialise
them. The consequence is that the app does not currently list them — it can say
*"No sandboxes yet"* while a guest it launched is running, and offers no Stop
button for it. Closing the Terminal window is a power cut on a running guest.

Tracking: [#225](https://github.com/gimbal-dev/gimbal-local/issues/225).
