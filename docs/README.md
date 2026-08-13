# Documentation

This directory is both the public manual and the engineering record for Gimbal
Local. That is deliberate. The public guides should get a new user to a working
sandbox; the engineering notes keep the measured state, scars, and limits
visible instead of hiding them in private lore.

If a document is marked **engineering log**, it may be more detailed, more
dated, and more issue-shaped than a normal user guide. Treat it as useful
evidence, not as polished product copy.

> **Provenance caveat.** Gimbal Local is entirely AI-authored. The code was
> written by an AI agent and has not had human line-by-line code review. Human
> involvement has been specification, direction, acceptance criteria,
> prioritisation, and judgement calls about what is real versus fake. This is a
> hypervisor, so the caveat is material: do not use it to isolate untrusted or
> hostile workloads, and do not treat it as hardened. The evidence in these docs
> is real — measured runs, mutation-tested guards, and explicit refusals — but
> it does not replace human security review.

## Start here

| Goal | Read |
| --- | --- |
| Install and understand the project | [`../README.md`](../README.md) |
| Run a coding agent in a disposable local VM | [`running-agents.md`](running-agents.md) |
| Build a sandbox from an OCI/Docker image | [`container-images.md`](container-images.md) |
| Resume a Cloud Hypervisor snapshot on a Mac | [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) |
| Understand the current measured state | [`project-state.md`](project-state.md) |

## Public guides

These are written for people trying to use or evaluate Gimbal Local.

| Doc | What it covers |
| --- | --- |
| [`running-agents.md`](running-agents.md) | Interactive `chm serve` / `chm ctl console`, headless `chm exec`, and the honest line between proven cold boot and open rehydrated-agent acceptance. |
| [`container-images.md`](container-images.md) | `chm image build`: kernels, modules, initramfs vs `--disk`, networking, libc, and the measured Copilot CLI path. |
| [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md) | The snapshot contract: vanilla upstream ITS/LPI captures are preferred; legacy GICv2M captures still work. |
| [`first-resume.md`](first-resume.md) | What to check on the first resume of a real cloud capture: filesystem growth, DNS, package state, and JIT exposure. |
| [`networking.md`](networking.md) | Userspace NAT, default-deny egress, policy binding, and host-isolation rules. |
| [`credential-proxy.md`](credential-proxy.md) | How host-held credentials are attached to outbound requests without placing the secret in the guest. |
| [`security-model.md`](security-model.md) | Threat model and shipped controls. Read with the provenance caveat above: this is not a hardened, human-reviewed boundary. |
| [`environment-variables.md`](environment-variables.md) | Every `CHM_*` variable, including diagnostics and strictness toggles. |
| [`exec.md`](exec.md) | `chm exec`: running a command in a sandbox and recovering its exit status. |
| [`snapshot-export.md`](snapshot-export.md) | Moving revisions between machines and what a bundle deliberately does not contain. |
| [`snapshot-retention.md`](snapshot-retention.md) | What a lineage keeps, what it reclaims, and how disk usage is reported. |
| [`continuous-snapshots.md`](continuous-snapshots.md) | Periodic local checkpoints for long-running work. |
| [`aws-byo-setup.md`](aws-byo-setup.md) | Bring-your-own-AWS setup for a remote capture loop. |

## Architecture and design notes

These are public, but they assume you want the machinery rather than a quick
start.

| Doc | What it covers |
| --- | --- |
| [`macos-local-runtime.md`](macos-local-runtime.md) | How the KVM snapshot is translated and rehydrated onto Hypervisor.framework. |
| [`cpu-feature-deltas.md`](cpu-feature-deltas.md) | Which captured CPU features this Mac can reproduce, which ones are warned about, and why. |
| [`gimbal-local-fork-model.md`](gimbal-local-fork-model.md) | Images, revisions, checkpoints, and branchable local lineage. |
| [`sandbox-spec.md`](sandbox-spec.md) | The declarative sandbox spec and the fields Gimbal Local refuses rather than silently ignoring. |
| [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md) | The Mac consumer of the content-addressed memory plane; demand faulting is still future work. |
| [`graviton-acid-test-results.md`](graviton-acid-test-results.md) | The measured Graviton2 rehydration result and counter-frequency correction. |
| [`graviton-capture-request.md`](graviton-capture-request.md) | The exact capture shape requested from real cloud hardware. |

## Engineering log

These are intentionally kept public because they explain how the project avoids
fake demos and stale claims. They are not the first thing a release user needs.

| Doc | Why it remains visible |
| --- | --- |
| [`project-state.md`](project-state.md) | The measured state of the world, gate numbers, open limitations, and issue grouping. |
| [`engineering-discipline.md`](engineering-discipline.md) | The project's working rules: measure, mutation-test, fail honestly, and keep build traps written down. |
| [`agents.md`](agents.md) | The specialist agent map. Useful to humans too, but primarily an engineering handoff tool. |
| [`network-policy-plan.md`](network-policy-plan.md) | Planning record for the network/filesystem policy track. The shipped user surface is in `networking.md` and `security-model.md`. |
| [`raspberry-pi-offbox-plan.md`](raspberry-pi-offbox-plan.md) | Off-box capture plan for ARM Linux hardware. Kept as a plan, not a user promise. |

## Internal-only pending scrub

These files are not linked from the public index and should not be published
until the confidentiality/history decision is made.

| File | Reason |
| --- | --- |
| `docs/living-workspaces.md` | Contains detailed architecture for an unshipped workspace capability. The codename it referenced has been scrubbed from HEAD; it remains in git history, which is accepted. |
| `docs/roadmap.md` | Normally this would be a useful public milestone ledger, but it also references the unshipped workspace track. Treat it as internal-only until scrubbed, including history. |

## Outside this directory

- [`../app/GimbalLocal/`](../app/GimbalLocal/) — the SwiftUI desktop app.
- [`../chm/`](../chm/) — the CLI and daemon.
- [`../hypervisor/src/hvf/`](../hypervisor/src/hvf/) — the HVF backend.
- [`../scripts/hvf/README.md`](../scripts/hvf/README.md) — capture scripts and
  the end-to-end microVM loop.
- [`.github/agents/`](../.github/agents/) — the specialist agent definitions.
