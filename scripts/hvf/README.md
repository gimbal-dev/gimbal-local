# Capturing a real arm64 KVM snapshot for the Hypervisor.framework port

The macOS Hypervisor.framework (HVF) backend's KVM→HVF translator
(`hypervisor::hvf::translate`) needs a **real** cloud-hypervisor arm64 snapshot,
taken under KVM, to validate against — both the per-vCPU registers
(`VcpuKvmState`) and the GICv3 state (`Gicv3ItsState { dist, rdist, icc,
gicd_ctlr }`). cloud-hypervisor serializes all of it into the snapshot's
`state.json`.

A snapshot can only be **produced** on a host with real `/dev/kvm` on arm64.
There are now three ways to get one.

## Option A — entirely on an Apple M3+ Mac (recommended)

Apple added hardware **nested virtualization** on M3 (and later) chips, exposed
by Virtualization.framework on macOS 15+. That lets a Linux VM on the Mac expose
`/dev/kvm`, so cloud-hypervisor can run inside it and snapshot a guest — no cloud
box, no cost.

```sh
scripts/hvf/capture-on-mac.sh
```

This:
1. checks you are on an M3+ Mac running macOS 15+,
2. installs [Lima](https://lima-vm.io) via Homebrew if needed,
3. starts `lima-arm-kvm.yaml` (a `vmType: vz` guest with
   `nestedVirtualization: true`) and confirms nested `/dev/kvm`,
4. runs `capture-arm-snapshot.sh` inside it, and
5. copies the snapshot back to `./ch-arm-snapshot` on the Mac.

Set `KEEP_VM=0` to stop the Lima VM afterwards. The Lima VM is reusable; the
downloads are cached.

> Requires Apple **M3 or later**. M1/M2 have no nested virtualization — the
> script detects this and points you at Option B.

## Option B — a Raspberry Pi / local ARM Linux box (off-box proof)

Use this while cloud bare-metal quota is blocked. It proves the snapshot was
captured on a physically separate Linux/KVM arm64 host, but it is not a real
cloud proof.

The hard gate is **KVM VGICv3**, not just `/dev/kvm`. Raspberry Pi 5 is the best
candidate; Raspberry Pi 4 is likely not enough for the current VGICv3-only
capture path. See [`../../docs/raspberry-pi-offbox-plan.md`](../../docs/raspberry-pi-offbox-plan.md).

```sh
# from the Mac:
scp scripts/hvf/capture-arm-snapshot.sh pi@raspberrypi.local:/tmp/
ssh pi@raspberrypi.local \
  'CH_GIC_V2M=1 OUT_DIR=$HOME/ch-arm-snapshot bash /tmp/capture-arm-snapshot.sh'
rsync -avz pi@raspberrypi.local:~/ch-arm-snapshot/snapshot/ ./snapshots/pi-offbox/
```

## Option C — a cloud ARM bare-metal box (fallback)

Use any arm64 host with real `/dev/kvm`: an AWS Graviton `c7g.metal` /
`m7g.metal`, an Oracle `BM.Standard.A1.160`, or any ARM `*.metal`. Regular ARM
cloud *VMs* (Graviton non-metal, Azure Dpsv5, GCP T2A, Hetzner CAX, …) do **not**
expose `/dev/kvm` and will not work.

```sh
# on the bare-metal ARM host:
scp scripts/hvf/capture-arm-snapshot.sh user@host:/tmp/
ssh user@host 'bash /tmp/capture-arm-snapshot.sh'
# then copy ./ch-arm-snapshot/ch-arm-snapshot.tar.zst back
```

A `c7g.metal` spot instance for ~20 minutes costs roughly a dollar, but account
quota/capacity can block this path.

## What you get

```
ch-arm-snapshot/
  snapshot/                 full cloud-hypervisor snapshot
    state.json              vCPU VcpuKvmState + GIC Gicv3ItsState (the fixture)
    config.json             VM config
    memory-ranges …         guest RAM (large; not needed by the translator)
  disks/                    exported guest disk images (the COW base images)
    _disk0.raw              root disk, keyed by the snapshot's device-node id
    _disk1.raw              cloud-init seed, etc.
  state.json                copy of the above, for convenience
  ch-arm-snapshot.tar.zst   packaged, self-contained snapshot (snapshot+disks)
```

`state.json` is the artifact the translator consumes. It is small enough to
commit as a test fixture under `hypervisor/tests/data/` so future iteration is
fully offline on the Mac.

The `disks/` images are what make a snapshot **runnable** (not just
translatable): `chm` opens each as an immutable base and redirects guest writes
to a per-run copy-on-write overlay, so the guest reads/writes its real
filesystem and every resume stays consistent with the restored RAM. See
[`../../docs/hvf-compatible-snapshots.md`](../../docs/hvf-compatible-snapshots.md).

## Verifying the full loop (boot → log in → write a file → ls)

`e2e-microvm-loop.sh` is an automated regression guard for the whole local
sandbox path. It boots a real snapshot under `chm`, logs in over a PTY, writes a
file inside the guest, lists it, reads pre-existing base-disk content back (with
caches dropped), and asserts there are no ext4 / I/O errors:

```sh
scripts/hvf/e2e-microvm-loop.sh [SNAPSHOT_DIR]   # defaults to ./snapshots/ch-arm-v2m-demo
```

It wraps the `#[ignore]`d integration test `chm/tests/e2e_microvm_loop.rs`
(which builds + ad-hoc-signs `chm` itself). A plain `cargo test` never boots a
VM; the loop only runs when invoked this way (or with `CHM_E2E_SNAPSHOT` set and
`-- --ignored`). Set `CHM_E2E_LOG=/path` to dump the guest console transcript.

## Tunables

Both scripts honour environment variables, e.g. `GUEST_CPUS`, `GUEST_MEM_MB`,
`CH_VERSION`, `IMG_URL`, `OUT_DIR`, `BOOT_TIMEOUT`. `CH_GIC_V2M` defaults to
`0`, the vanilla stock-upstream ITS/LPI shape, which is the supported path and
runs on the userspace GICv3 with no flags. Set `CH_GIC_V2M=1` only to produce
the legacy GICv2M/message-SPI shape, which needs this fork's patched binary via
`CH_BIN`/`CHREMOTE_BIN`. See the CONFIG block at the top of
`capture-arm-snapshot.sh`.
