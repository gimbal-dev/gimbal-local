# Gimbal Local Credits and Upstream Attribution

Gimbal Local is a macOS / Apple Silicon fork of
[Cloud Hypervisor](https://www.cloudhypervisor.org/). The current source tree
contains upstream Cloud Hypervisor history through commit
`1db8858fac037277f6d744db8dbcb637b1295b9b` (2026-06-21,
`virtio-devices: block: Reuse descriptor chain's memory for queue enable`),
which is after upstream `v52.0` and before upstream `v53.0`.

This repository exists because of Cloud Hypervisor and its contributors. Gimbal
Local keeps that upstream tree in place and adds the macOS-specific runtime:
Apple Hypervisor.framework (HVF) support, KVM-to-HVF snapshot rehydration,
userspace GIC and virtio-mmio devices for macOS, the `chm` CLI/daemon, OCI image
cold boot support, and the native Gimbal Local macOS app.

The HVF backend under `hypervisor/src/hvf/` is deliberately given back under
Apache-2.0. It lives inside the upstream-derived hypervisor crate, implements
the upstream backend shape, and is the part Cloud Hypervisor itself could most
directly benefit from. The commercial seam is elsewhere.

The `chm` CLI/daemon is source available under FSL-1.1-ALv2. That licence does
not restrict reading, auditing, modifying, patching, self-hosting, or internal
use; it restricts competing commercial use and converts each release to
Apache-2.0 after two years. The macOS app is proprietary source.

The upstream Cloud Hypervisor project remains independent from this fork. Its
maintainers did not review, endorse, or approve Gimbal Local's AI-authored
macOS additions, and are not responsible for Gimbal Local issues, releases, or
support. Modified upstream files and the baseline used for comparison are
recorded in [`UPSTREAM-CHANGES.md`](UPSTREAM-CHANGES.md).

## Cloud Hypervisor

Cloud Hypervisor is the upstream project from which this repository is derived:

- Project: <https://www.cloudhypervisor.org/>
- Source: <https://github.com/cloud-hypervisor/cloud-hypervisor>
- Licence: `Apache-2.0 AND BSD-3-Clause`, with per-file SPDX headers

Our thanks go first to the Cloud Hypervisor maintainers and contributors for the
VMM, device model, migration, snapshot, and project infrastructure that Gimbal
Local builds on.

That credit does not transfer responsibility. The reviewed upstream project and
this unreviewed fork are separate works with separate maintenance and security
postures.

## Inherited upstream credits

Cloud Hypervisor itself is based on the
[rust-vmm](https://github.com/rust-vmm),
[Firecracker](https://firecracker-microvm.github.io/), and
[crosvm](https://chromium.googlesource.com/chromiumos/platform/crosvm/)
project implementations. Gimbal Local inherits that credit chain and preserves
it here.

### crosvm

- [Zach Reizner](https://github.com/zachreizner) <zachr@chromium.org>
- [Dylan Reid](https://github.com/dgreid) <dgreid@chromium.org>
- [Daniel Verkamp](https://github.com/danielverkamp) <dverkamp@chromium.org>
- [Stephen Barber](https://github.com/smibarber) <smbarber@chromium.org>
- [Chirantan Ekbote](https://github.com/jynnantonix) <chirantan@chromium.org>
- [Jason D. Clinton](https://github.com/jclinton) <jclinton@chromium.org>
- Sonny Rao <sonnyrao@chromium.org>

### Firecracker

See the Firecracker credits in the [Firecracker repository][firecracker].

[firecracker]: https://github.com/firecracker-microvm/firecracker

### rust-vmm

- [Andreea Florescu](https://github.com/andreeaflorescu) <fandree@amazon.com>
- [Paolo Bonzini](https://github.com/zachreizner) <pbonzini@redhat.com>
- [Jiang Liu](https://github.com/jiangliu) <gerry@linux.alibaba.com>
