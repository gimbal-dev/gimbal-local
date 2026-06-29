# Project state handoff

Last updated: 2026-06-29

This is the portable context pack for moving this work into a new private repo
or starting a new agent session without losing the reasoning that made the port
work.

## Product goal

Build a macOS local runtime that can rehydrate `arm64` Cloud Hypervisor
snapshots produced on Linux/KVM hosts, eventually including snapshots captured
from real cloud machines.

The intended architecture is now split:

| Repo / service | Responsibility |
| --- | --- |
| This repo | Local Mac execution plane: parse snapshots, translate KVM state to HVF, run guests through `chm` / `chm serve` |
| Future sister repo | Remote control plane: source of truth, cloud/Pi host orchestration, capture scheduling, artifact movement, cleanup, user/team auth |

Do not let this local runtime grow into the hosted orchestrator. It can keep
local helper scripts and prototype commands, but the long-term control plane
belongs in a separate repo.

## Current technical state

A real Cloud Hypervisor `arm64` KVM snapshot can be parsed, translated, and
rehydrated as a live Hypervisor.framework VM on Apple Silicon.

Hardware-proven capabilities:

| Area | State |
| --- | --- |
| HVF backend through real `Hypervisor` / `Vm` / `Vcpu` traits | Done |
| Managed Apple GICv3 creation and state restore | Done |
| KVM register-list to HVF sysreg/core-reg translation | Done |
| Guest RAM mapping from Cloud Hypervisor snapshot | Done |
| Virtual timer continuity restore | Done |
| WFI/WFE idle and cross-thread wake | Done |
| Standalone signed `chm run` executable | Done |
| `chm serve` daemon and `chm ctl` local control socket | Done |
| Native virtio block/rng/net model over virtio-pci | Done |
| Interactive serial login and host stdin -> guest UART | Done |
| Real bidirectional virtio-net with ARP/ICMP responder | Done |
| Multi-vCPU snapshot resume with already-online cores concurrent | Done |
| PSCI `CPU_ON` for parked secondary vCPUs | Done |

## Most recent commits

```text
4a87c05a6 docs, scripts: add Raspberry Pi off-box plan
3f08c08be docs: correct AWS bare-metal quota guidance
539368d50 docs: add AWS CLI SSO prompt bypass
0c9100065 docs: spell out personal AWS IAM setup
5d66c6ce7 docs: clarify personal AWS account setup
adac0db86 docs: make AWS setup guide beginner safe
253fb37be scripts: add destructive AWS cleanup helper
b5ba37520 docs: note AWS standing cost expectations
b06a970d8 docs: add AWS bring-your-own setup notes
378223981 hypervisor, chm: close PSCI CPU_ON routing gap
b7378c349 hypervisor, chm: SMP resume of multi-vCPU snapshots (M20)
533fcc3e7 hypervisor: add virtio-net device with host responder datapath
1286ddff8 hypervisor: classify virtio devices by PCI Device ID
38bf5bf9b chm: interactive serial console (host stdin -> guest tty)
cbd06aac5 hypervisor: add PL011 receive path and serial-state restore
b30aa29f4 hypervisor: route rehydrated completion SPIs 1-of-N
44eeecc9d hypervisor: enable Group1 SPI forwarding on rehydrate
2915c73f6 hypervisor: re-arm EVENT_IDX notifications across a resume
0453726ae hypervisor, chm: rehydrate and service a real SPI-routed cloud snapshot
f19ece3fd hypervisor: add GICv2M capture mode for SPI-routed snapshots
```

## Honest boundaries

### R1: Stock ITS/LPI snapshots do not work on HVF today

Stock arm64 Cloud Hypervisor routes virtio completions through GIC ITS LPIs.
Apple's managed `hv_gic` cannot deliver LPIs to a normal restored EL1 guest.
This was proven and then re-confirmed against the macOS 26.5 SDK.

Supported capture path today:

```text
GICv2M/message-SPI capture -> HVF message-SPI delivery through hv_gic_send_msi
```

The load-time ITS/LPI guard is intentional. It should fail loudly instead of
letting an unsupported snapshot hang.

### R2: Real cloud round-trip still open

The rehydrated snapshots so far were captured via nested KVM in Lima on this
Mac. AWS Graviton bare-metal quota is being pursued separately, but the
immediate engineering proof has pivoted to Raspberry Pi/off-box Linux KVM.

The Pi proof retires "captured only inside nested Lima on the same Mac" if it
works. It does **not** retire the real-cloud claim.

### R3: PSCI `CPU_ON` closed; SPI affinity routing remains a platform boundary

PSCI `CPU_ON` now works:

- guest HVC `CPU_ON` reaches `VmOps::psci_vcpu_on`;
- `chm` maps target MPIDR to vCPU id;
- stopped vCPUs park on a condvar;
- the secondary starts at the requested entry point with `x0=context`;
- KVM `KVM_MP_STATE_STOPPED` survives KVM -> HVF snapshot translation.

SPI affinity routing was retested. Affinity-routed message SPIs become pending
in the Apple managed-GIC distributor but do not forward to the vCPU CPU
interface. Production therefore deliberately reroutes message SPIs to 1-of-N
with `GICD_IROUTER.IRM` before `hv_gic_send_msi`.

Diagnostic switch:

```bash
CHM_DISABLE_SPI_1_OF_N_FALLBACK=1
```

Use that only to retest future SDK/hardware behavior.

## Key files

| File | Why it matters |
| --- | --- |
| `chm/src/imp.rs` | Local runtime orchestration, ITS/LPI guard, virtio wiring, PSCI CPU_ON coordinator |
| `hypervisor/src/hvf/mod.rs` | HVF vCPU run loop, exit handling, HVC/PSCI handling, vtimer restore |
| `hypervisor/src/hvf/rehydrate.rs` | Snapshot orchestration: RAM, GIC, vCPU state, `RehydratedVm` |
| `hypervisor/src/hvf/translate.rs` | KVM register/GIC state to HVF state translation |
| `hypervisor/src/hvf/gic.rs` | Apple managed-GIC integration, MSI/message-SPI delivery, 1-of-N fallback |
| `hypervisor/src/hvf/virtio/` | Native virtio-pci/block/rng/net model for restored snapshots |
| `hypervisor/src/kvm/aarch64/gic/mod.rs` | KVM capture-side `CH_GIC_V2M=1` path |
| `hypervisor/tests/hvf_boot.rs` | Hardware integration tests, including PSCI CPU_ON proof |
| `scripts/hvf/capture-arm-snapshot.sh` | Linux/KVM capture script; now defaults `CH_GIC_V2M=1` |
| `scripts/hvf/capture-on-mac.sh` | M3+ Mac nested-KVM capture via Lima |
| `scripts/aws-cleanup-chm.sh` | Tag-scoped destructive AWS cleanup helper |
| `docs/macos-local-runtime.md` | Main technical explainer |
| `docs/aws-byo-setup.md` | Beginner-safe AWS setup/runbook |
| `docs/raspberry-pi-offbox-plan.md` | Immediate off-box Linux/KVM proof plan |
| `docs/agent-chat-history.md` | Curated agent/user history archive for repo migration |

## Build and run

Build and sign `chm`:

```bash
bash scripts/build-chm.sh
```

Run a snapshot:

```bash
target/debug/chm run <SNAPSHOT_DIR> --max-seconds 30 --idle-exit 0
```

Clear local overlays before re-running a snapshot:

```bash
rm -rf <SNAPSHOT_DIR>/.chm-overlays/*
```

Library tests:

```bash
cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib
```

Formatting:

```bash
cargo +nightly fmt --all
```

Narrow clippy examples used during the port:

```bash
cargo clippy -p hypervisor --no-default-features --features hvf,kvm-snapshot
cargo clippy -p chm
```

## Capture modes

### M3+ Mac nested-KVM capture

```bash
scripts/hvf/capture-on-mac.sh
```

Uses Lima with Apple Virtualization.framework nested virtualization. Requires
M3 or later and macOS 15+.

### Generic arm64 Linux/KVM capture

```bash
CH_GIC_V2M=1 OUT_DIR=$HOME/ch-arm-snapshot \
  bash scripts/hvf/capture-arm-snapshot.sh
```

`CH_GIC_V2M=1` is the HVF-compatible mode. The script defaults to it now.

### Raspberry Pi off-box proof

See `docs/raspberry-pi-offbox-plan.md`.

Hard gate:

```text
/dev/kvm + KVM VGICv3 support
```

Raspberry Pi 5 is the best candidate. Raspberry Pi 4 is likely a no-go with the
current VGICv3-only KVM capture path.

### AWS cloud proof

See `docs/aws-byo-setup.md`.

Important AWS quota note: EC2 On-Demand Standard quota is in **vCPUs**, not
instances. A default of 5 vCPUs is normal for a new personal account, but it is
not enough for `c7g.metal`, which commonly needs 64 vCPUs. Request at least 64,
or 128 for breathing room.

## Immediate roadmap

### M21a: Raspberry Pi off-box Linux/KVM proof

Goal:

```text
Raspberry Pi Linux/KVM host -> cloud-hypervisor snapshot -> local Mac chm
```

Pass criteria:

- Pi host exposes `/dev/kvm`;
- Pi host can start a KVM guest with `virt,gic-version=3`;
- capture script produces a GICv2M/message-SPI snapshot;
- Mac `chm` accepts the snapshot without the ITS/LPI guard rejecting it;
- restored guest reaches serial output or login.

### M21b: Real cloud round-trip

Return to AWS/Oracle once quota/capacity is available.

Goal:

```text
cloud arm64 KVM host -> snapshot bundle -> local Mac chm -> return artifacts -> cloud
```

### M22: BYO-subscription turnkey loop

Still local-managed in this repo for now:

```text
chm cloud init aws --profile <profile> --bucket <bucket> --region <region>
chm cloud capture aws --name <name>
chm run <downloaded-snapshot>
chm cloud push aws --name <name> --from-local <run-artifacts>
chm cloud cleanup aws --name <name>
```

Longer-term, orchestration moves to the sister control-plane repo.

### M23: Desktop app

GUI over `chm serve`: library view, start/stop, console, lifecycle controls.

## Control-plane sister repo prep

Before creating the repo, write a boundary RFC. Suggested repo name:

```text
cloud-hypervisor-control-plane
```

First document should define:

1. product shape: remote control plane for sandbox lifecycle, local Mac runtime
   as agent/worker;
2. entities: sandbox, snapshot, host, local runner, artifact, lease, run
   session;
3. APIs: create sandbox, request capture, assign local runner, pull snapshot,
   push artifacts, cleanup;
4. local agent contract: what `chm serve` exposes and what the control plane can
   assume;
5. trust model: BYO cloud accounts first, no shared service credentials, explicit
   cost cleanup;
6. MVP: one user, one Mac, one AWS/Pi capture host, one round-trip.

## Private repo migration guidance

Cloud Hypervisor's inherited license posture is permissive:

```text
Apache-2.0 OR BSD-3-Clause
```

Going private is generally allowed, including moving to a new private repo that
is not a GitHub fork, as long as license notices/SPDX headers are preserved and
third-party licenses are tracked. This is not legal advice.

Recommended migration sequence:

1. Commit this handoff pack.
2. Create a new private repo that is not part of the public fork network.
3. Push/import this tree.
4. Keep `LICENSES/`, SPDX headers, upstream attribution, and relevant docs.
5. Start the control-plane repo separately rather than mixing orchestration into
   the local runtime.

