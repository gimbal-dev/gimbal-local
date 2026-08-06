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

Three limits will bite you in the first ten minutes if you do not know about
them. All three were measured on the released build; none is a hypervisor
defect, and each has an open issue.

### 1. You must bring your own kernel, and most of them will not have drivers

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

A container rootfs ships no `/lib/modules`, so the modules are not there to
load. The result is a guest that boots to a shell perfectly and then:

```
ip: can't find device 'eth0'
```

`--net` is accepted, chm logs the device, and the guest cannot see it. The same
applies to `--disk`.

**chm now tells you this before you boot.** `chm image build` and
`chm create --net`/`--disk` scan the kernel and warn when the drivers are not
built in. It is a warning rather than a refusal: the image is still perfectly
good for a workload that needs no devices.

### Which kernels actually work

Measured on this project, booting a stock `alpine:3.20` rootfs:

| kernel | virtio built in? | result |
| --- | --- | --- |
| **Ubuntu `linux-image-*-generic` arm64** | yes | ✅ **`eth0` with no `modprobe`, real HTTPS egress** |
| Alpine `linux-virt` / `linux-lts` | no (`=m`) | boots to a shell, no NIC, no disk |
| Firecracker CI `vmlinux-*` aarch64 | yes | ❌ **no console** — see below |

**Use an Ubuntu `generic` arm64 kernel.** It is the same family as a Graviton
snapshot, and it is the pairing verified end to end:

```
curl -O http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-image-unsigned-6.8.0-71-generic_6.8.0-71.71_arm64.deb
ar x linux-image-*.deb && tar -xf data.tar
python3 -c "import gzip,sys; d=open('boot/vmlinuz-6.8.0-71-generic','rb').read(); \
            open('Image','wb').write(gzip.decompress(d[d.find(b'\x1f\x8b\x08'):]))"
```

(Ubuntu ships `vmlinuz` as a gzip stream; the last line unwraps it to the
uncompressed `Image` cold boot needs.)

**Firecracker's CI kernels look ideal and are not.** They are mmio-only, so
virtio is built in — but they are compiled with `CONFIG_SERIAL_8250` and **no
`CONFIG_SERIAL_AMBA_PL011`**, while chm presents a PL011. The guest boots and
emits nothing at all, which is indistinguishable from a hang.

**If you must use a modular kernel**, supply its matching modules and note the
ordering trap: loading `virtio_net` alone silently succeeds and still leaves no
NIC, because the *transport* module is the one that was missing. `virtio_mmio`
must be loaded too. Module version must match the kernel exactly.

Tracking: [#222](https://github.com/gimbal-dev/gimbal-local/issues/222).

### 2. Some distro kernels are not in the format they look like

Alpine's `vmlinuz-virt`, for example, is an **EFI zboot** wrapper (`MZ` magic
followed by `zimg`), not a raw `Image`. `chm image build` currently refuses it
with a message about x86, which is misleading — it is an arm64 kernel in a
container chm does not yet unwrap.

You want an uncompressed arm64 `Image` with `ARM\x64` at offset `0x38`.

Tracking: [#220](https://github.com/gimbal-dev/gimbal-local/issues/220).

### 3. The rootfs unpacks into guest RAM

The rootfs ships as a **cpio initramfs**, which is the only format available
here: macOS has no `mkfs.ext4` and cannot loopback-mount a Linux filesystem.
This is a genuine upside — the kernel needs no `root=`, so the whole
PARTUUID-mismatch failure class disappears — but it means the image is unpacked
into RAM at boot.

`image.json` records a measured `ram_mib` for this reason, and the app uses it.
A large image needs a large `--memory`, and there is a ceiling of **3008 MiB**
for a cold boot (guest RAM starts at `0x40000000` and one region must end by
`0xfc000000`). chm states this exactly when you exceed it.

A disk-backed variant for images too large to unpack into RAM is
[#205](https://github.com/gimbal-dev/gimbal-local/issues/205).

## Choosing a base image

**Use a glibc image for agent workloads.** `node:22-slim`, `debian`, `ubuntu`.

Musl images (`*-alpine`) boot and run general workloads fine, but the GitHub
Copilot CLI downloads a prebuilt `linuxmusl-arm64` runtime at first use and that
binary currently fails to load its own Node-API symbols:

```
Node-API symbol napi_create_function has not been loaded
Failed to load package index: …/linuxmusl-arm64/1.0.78/index.js
```

`npm i -g @github/copilot` itself succeeds — the failure is at first run.
Measured against Copilot CLI 1.0.78; the acceptance run that proved the agent
end-to-end used glibc and 1.0.77.

Tracking: [#224](https://github.com/gimbal-dev/gimbal-local/issues/224).

## Entrypoints

The image's own entrypoint is used unless you override it. That is often not a
shell — `node:22-alpine` defaults to `docker-entrypoint.sh node`, which drops
you into a Node REPL rather than a prompt, and `node:22-slim` defaults to plain
`node` for the same result. Pass `--entrypoint /bin/sh` (or `/bin/bash` on a
Debian-based image) when you want a shell.

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

Configuring an interface needs an ioctl, and no shell builtin makes one — so
if an image ships neither tool there is nothing the init can do, and it says so
rather than leaving you a silent NIC:

```
gimbal: eth0 is present but this image has no working 'ip' or
gimbal: 'ifconfig', so it cannot be configured. Use an image that
gimbal: has iproute2 or busybox, or configure it yourself:
```

**The guest still boots and you still get a shell** — only the NIC is
unconfigured. `node:22-slim` is a real example. This is a chicken-and-egg you
cannot solve from inside: installing `iproute2` needs the network. Either start
from a fuller base image, or bake the tool in before you build.

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

A bare `alpine` image has no `curl` and no `openssl`, so busybox `wget` falls
back to its own minimal built-in TLS. That handshake fails against real-world
certificate chains with `Connection reset by peer` — measured identically
against `example.com`, `github.com` and `registry.npmjs.org`, while
`--no-check-certificate` against the same host succeeds with `rc=0`.

So **this error is not the sandbox's network**, and `--no-check-certificate` is
the one-line way to prove that before you go looking. For real work install
`ca-certificates` and a proper client (`apk add curl`), or start from a fuller
base image.

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
