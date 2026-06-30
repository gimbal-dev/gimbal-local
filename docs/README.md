# Documentation

This is a macOS-focused fork of Cloud Hypervisor. The documentation here is in
two groups: a small set written for **this project** (the macOS / Apple
Hypervisor.framework port), and the larger set of **upstream Cloud Hypervisor**
reference docs that are preserved as-is.

## Start here (the macOS port)

If you are working on the macOS local runtime — `chm`, the HVF backend, or the
Gimbal Local app — these are the docs you want:

| Doc | What it covers |
| --- | --- |
| [`macos-local-runtime.md`](macos-local-runtime.md) | Architecture of the HVF port: how a KVM snapshot is translated and rehydrated onto Apple Hypervisor.framework. |
| [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) | The snapshot contract: GICv2M/message-SPI interrupt mode, why ITS/LPI snapshots are unsupported, and the disk + copy-on-write requirement. |
| [`aws-byo-setup.md`](aws-byo-setup.md) | Bring-your-own-AWS setup for the remote→local→remote capture loop (`chm cloud …`). |
| [`raspberry-pi-offbox-plan.md`](raspberry-pi-offbox-plan.md) | Plan for off-box snapshot capture on a Raspberry Pi / ARM Linux host. |

Related, outside this directory:

- [`../README.md`](../README.md) — project overview, build, and run.
- [`../scripts/hvf/README.md`](../scripts/hvf/README.md) — how to capture an
  HVF-compatible snapshot, and the `e2e-microvm-loop.sh` regression test.
- Code: [`../chm/`](../chm/) (CLI/daemon), `../hypervisor/src/hvf/` (the HVF
  backend), and [`../app/GimbalLocal/`](../app/GimbalLocal/) (the desktop app).

## A note on the upstream VMM

This is a fork of Cloud Hypervisor. The Linux/KVM VMM crates (`vmm`,
`virtio-devices`, `pci`, `devices`, …) are not part of the macOS product — they
exist only to build the patched `cloud-hypervisor` binary used to *capture*
HVF-compatible snapshots (see [`../scripts/hvf/`](../scripts/hvf/)). You do not
need to read or touch them to work on the macOS port.
