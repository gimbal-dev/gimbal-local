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
| [`roadmap.md`](roadmap.md) | Milestones to date and what remains, on the V1–V4 vanilla-first spine. **Read this first.** |
| [`security-model.md`](security-model.md) | Threat model, security invariants, and the M30 hardening plan — how untrusted snapshots and hostile guest workloads are confined. |
| [`network-policy-plan.md`](network-policy-plan.md) | M28 plan (Pillar ③): how the plane's egress allow-list follows a sandbox to the Mac and is enforced by a userspace NAT — the "provably can't get out" demo. |
| [`networking.md`](networking.md) | User guide: how a rehydrated guest reaches the network through the userspace NAT, and how the control-plane egress allow-list is enforced locally (DNS + TCP connect). |
| [`credential-proxy.md`](credential-proxy.md) | How a sandboxed job authenticates to GitHub, npm or a registry **without ever holding the credential** — the proxy attaches it as the request leaves. Also: the two kinds of secrets, and the honest limits of the approach. |
| [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md) | How `chm` consumes the control plane's content-addressed, encrypted memory plane (Phase 2), and the honest demand-fault gap. |
| [`macos-local-runtime.md`](macos-local-runtime.md) | Architecture of the HVF port: how a KVM snapshot is translated and rehydrated onto Apple Hypervisor.framework. |
| [`gimbal-local-fork-model.md`](gimbal-local-fork-model.md) | How Gimbal Local models images, live checkpoints, and running sandboxes as a fork-based, branchable lineage — the local edge of the control plane's revision graph. |
| [`snapshot-retention.md`](snapshot-retention.md) | What a lineage keeps, what it reclaims, and what it costs. Why pinning a revision sits **outside** the retention budget rather than inside it, and why disk usage is reported two ways — a fork hard-links its parent's RAM, so no single number is honest. |
| [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) | The snapshot contract: **vanilla (stock upstream, ITS/LPI) is the recommended shape**, the legacy GICv2M fallback and where it is still required, and the disk + copy-on-write requirement. |
| [`graviton-capture-request.md`](graviton-capture-request.md) | The exact snapshot we need captured on real cloud hardware, and how to produce it. Corrected after round 1. |
| [`cpu-feature-deltas.md`](cpu-feature-deltas.md) | **Which of a capture's CPU registers this Mac actually reproduces** (V1.4). 105 of 238 restore faithfully — and the one real bug is a register HVF restores *perfectly*: the guest still believes it can run 32-bit binaries, and doing so wedges the vCPU. |
| [`environment-variables.md`](environment-variables.md) | Every `CHM_*` variable: the `CHM_TRACE_*` diagnostic surface (there is no debugger for a guest vCPU), the behavioural overrides for A/B-ing a bug, and the policy bindings. |
| [`graviton-acid-test-results.md`](graviton-acid-test-results.md) | **What happened when we ran it.** A vanilla Graviton2 snapshot boots on Apple silicon — and the guest's clock runs 5.08× slow. The evidence, the numbers, and what can and cannot be fixed. |
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
