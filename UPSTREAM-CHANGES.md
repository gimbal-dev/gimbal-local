# Upstream Baseline and Modification Notice

This repository is a modified fork of
[Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor).

## Baseline

The current Gimbal Local tree includes upstream Cloud Hypervisor history through
commit `1db8858fac037277f6d744db8dbcb637b1295b9b`:

> `virtio-devices: block: Reuse descriptor chain's memory for queue enable`

That upstream commit was committed on 2026-06-21. It is 430 upstream commits
after `v52.0` (`1314ac883c641f1045bbb06dec0de045a3894baa`) and 179 upstream
commits before `v53.0`.

The first HVF backend commit in this fork was
`f67257d46745195d714b6d456f6622c3b9745a4c` (`hypervisor: add Apple
Hypervisor.framework (HVF) backend`), whose parent was upstream commit
`dd3a2f2649b7ace3a2bfe08c8ddbdab6dfa5d46f`. Later merges brought in more
upstream Cloud Hypervisor history through the baseline above.

## Prominent modification notice

Gimbal Local changes Cloud Hypervisor. In particular, this fork adds or changes
support for macOS and Apple Silicon, Apple Hypervisor.framework, KVM-to-HVF
snapshot rehydration, userspace GIC and virtio-mmio devices, the `chm`
CLI/daemon, OCI image cold boot, and the native Gimbal Local app.

Those fork-specific additions were written by an AI agent and have not had human
line-by-line code review. Human involvement has been PM-style: specification,
direction, acceptance criteria, prioritisation, and judgement calls about what
the evidence proves. The upstream Cloud Hypervisor project did not review,
endorse, or approve those additions.

For Apache-2.0 section 4(b), this file is the repository-level modification
manifest for the public source distribution. It identifies the upstream baseline
and the upstream files that differ from that baseline. Newly added source files
also carry SPDX and copyright headers.

## Review provenance and warranty posture

Gimbal Local's own engineering discipline is evidence-heavy: measured claims,
mutation-tested guards, and a refusal to ship fake demos. That evidence is real.
It is not a substitute for human code review of a hypervisor, which is a
security boundary.

The Apache-2.0 and BSD-3-Clause warranty disclaimers therefore matter here in a
very practical way: this fork must not be represented as hardened, audited, or
reviewed by upstream. Any future commercial distribution should make that review
status explicit, and should revisit contributor terms, DCO/CLA posture, support
promises, security response process, and product claims before offering stronger
assurances.

Users should not use Gimbal Local to isolate untrusted or hostile workloads.

## Modified upstream files

Measured with:

```sh
git diff --name-status 1db8858fac037277f6d744db8dbcb637b1295b9b
```

Summary for tracked files at the time this notice was written:

| Status | Count |
| --- | ---: |
| Added by Gimbal Local | 243 |
| Deleted from the upstream baseline | 54 |
| Modified from the upstream baseline | 21 |

The 21 upstream files modified by this fork are:

```text
.gitignore
AGENTS.md
CODEOWNERS
CODE_OF_CONDUCT.md
CONTRIBUTING.md
CREDITS.md
Cargo.lock
Cargo.toml
MAINTAINERS.md
README.md
arch/Cargo.toml
hypervisor/Cargo.toml
hypervisor/src/arch/aarch64/gic.rs
hypervisor/src/cpu.rs
hypervisor/src/kvm/aarch64/gic/mod.rs
hypervisor/src/kvm/mod.rs
hypervisor/src/lib.rs
hypervisor/src/mshv/mod.rs
hypervisor/src/vm.rs
scripts/gitlint/rules/TitleStartsWithComponent.py
vm-migration/src/tls.rs
```
