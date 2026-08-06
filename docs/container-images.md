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
**virtio-mmio**, and every arm64 distro kernel we have checked builds the whole
virtio stack as *modules*:

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

**Note the ordering trap if you do supply modules:** loading `virtio_net` alone
silently succeeds and still leaves no NIC, because the *transport* module has
not been loaded. `virtio_mmio` must be loaded too.

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
you into a Node REPL rather than a prompt. Pass `--entrypoint /bin/sh` when you
want a shell.

## Platform selection

`--platform os/arch[/variant]` picks a manifest from a multi-arch index. A
platform this host cannot boot is **refused before a byte is fetched** — an
accepted `linux/amd64` would pull real layers, verify real digests and write a
real image directory that could never start.

Layer codecs are detected by magic bytes rather than `mediaType`, because
registries mislabel. gzip and zstd are both read.

## What you get in the guest

The generated init brings the rootfs up and starts your entrypoint. You will
currently see:

```
gimbal: container rootfs up; starting /bin/sh
/bin/sh: can't access tty; job control turned off
```

The shell has no controlling terminal, so **Ctrl-C does not interrupt a running
command**. Tracking:
[#226](https://github.com/gimbal-dev/gimbal-local/issues/226).

## Networking, once the drivers are there

The userspace NAT hard-codes the guest at `192.168.249.2/24` with gateway and
nameserver `192.168.249.1` (see [`networking.md`](networking.md)). A snapshot
receives this from capture-side cloud-init; **a container rootfs does not**, so
configure it yourself:

```
ip link set eth0 up
ip addr add 192.168.249.2/24 dev eth0
ip route add default via 192.168.249.1
echo nameserver 192.168.249.1 > /etc/resolv.conf
```

Egress is default-deny on `chm create`. Name what you need with
`--egress-allow host:port`; hosts named in a credential rule imply their own
allowance when the rule and the policy come from the same authority (invariant
I13, see [`credential-proxy.md`](credential-proxy.md)).

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
