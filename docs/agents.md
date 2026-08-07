# The specialist agents

This repo ships a set of specialist agent definitions in
[`.github/agents/`](../.github/agents/). Each one carries the hard-won context
for a single area — the traps, the verification loops, the measured facts — so
that work can be picked up without having to rediscover them.

They are for humans too. If you are new to an area, its agent file is the
fastest honest briefing available.

---

## Which one do I want?

| Agent | Use it for | Owns |
| --- | --- | --- |
| [`guest-boot`](../.github/agents/guest-boot.agent.md) | "My guest has no NIC." "No console output." "Which kernel?" `chm image build`. | `chm/src/oci/`, `chm/src/coldboot.rs`, the generated guest init, `docs/container-images.md` |
| [`hvf-backend`](../.github/agents/hvf-backend.agent.md) | "The guest wedges." "Interrupts aren't delivered." "The snapshot won't restore." `HV_*` errors. | `hypervisor/src/hvf/` — vCPU, GIC, sysregs, translate, virtio + NAT |
| [`chm-cli`](../.github/agents/chm-cli.agent.md) | New commands and flags, error messages, policy, firewall, the credential proxy, the daemon. | `chm/src/` other than `oci/` |
| [`gimbal-app`](../.github/agents/gimbal-app.agent.md) | UI bugs, "the app should show…", Swift test failures, first-run experience. | `app/GimbalLocal/` |
| [`snapshot-capture`](../.github/agents/snapshot-capture.agent.md) | Capturing on real cloud hardware, the snapshot contract, export/import, the cloud round-trip. | `scripts/hvf/`, `chm/src/cloud.rs`, bundles, lineages |
| [`release-engineer`](../.github/agents/release-engineer.agent.md) | Cutting a release, signing, notarization, Gatekeeper, version bumps. | `scripts/release-macos.sh` |
| [`acceptance-tester`](../.github/agents/acceptance-tester.agent.md) | "Does this actually work from clean?" Walking the first-run path as a stranger and filing what hurts. | The whole product, from outside |
| [`doc-steward`](../.github/agents/doc-steward.agent.md) | "Update the roadmap." "Document this." "Is this doc still true?" Filing issues for what a run found. | `docs/`, the roadmap, issue hygiene |

**Rough rule:** if the question is *"why doesn't my guest work"* → `guest-boot`.
If it is *"why doesn't the hypervisor work"* → `hvf-backend`. If it is *"the
product should behave differently"* → `chm-cli` or `gimbal-app`.

---

## What every one of them assumes

All eight are built on [`engineering-discipline.md`](engineering-discipline.md),
and every one of them tells you to read it first. The short version:

1. **Measure, don't assert.** Name the command that produced your claim.
2. **A guard that has never failed is worth nothing.** Mutation-test every new
   test, and put the table in the PR body.
3. **Never restate a constant** — one place reads it from the other.
4. **Fail honestly.** Name the constraint, the number, and the way out.
5. **Don't be a hero — file the issue.** Your familiarity is not a feature the
   user has.
6. **Never `git checkout` to restore a file.** `/tmp` backup, `cp` back,
   `md5 -q` to verify.
7. **Every `cargo build` strips the hypervisor entitlement.** Re-sign.

---

## Keeping them true

**An agent guide that is out of date is worse than none**, because it will be
trusted. When a change invalidates something an agent is told, fix the agent
file **in the same PR**.

The [`doc-steward`](../.github/agents/doc-steward.agent.md) agent owns this, and
[`project-state.md`](project-state.md) is the snapshot they all point at for
"where are we right now".

---

## Adding one

Put it in `.github/agents/<name>.agent.md` with frontmatter:

```yaml
---
name: your-agent
description: >
  What it is for, phrased so someone can tell whether it is the right one —
  including the phrases a person would actually say.
tools: [bash, view, edit, create, grep, glob, todo]
---
```

Then add it to the table above.

> **Agents are discovered when a session starts.** If you have just created or
> edited one, start a new session before expecting it to be available — the file
> being correct on disk is not enough for a session that is already running.
> `name:` must match the filename stem.

**Write it from scars, not from the file tree.** The value of these files is the
things that cost someone hours: the kernel that produces silence rather than
output, the flag that is stripped by every build, the test that passed while
matching a comment instead of the code. A list of directories helps nobody — a
list of ways to waste an afternoon helps everybody.
