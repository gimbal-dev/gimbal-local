# Contributing to Gimbal Local

> **Before anything else:** all Gimbal-specific additions and product code in
> this fork were written by an AI, and no human has reviewed that code line by
> line. The retained upstream Cloud Hypervisor tree was written by its human
> contributors. See [Read this first](README.md#no-human-review). Expect to find
> things a reviewer would have caught, and please report them rather than assume
> they are intentional.

Gimbal Local is a macOS/Apple-Silicon fork of Cloud Hypervisor. The product
surface is `chm`, the `hypervisor/src/hvf/` backend, and the SwiftUI app in
`app/GimbalLocal/`. The rest of the upstream tree is kept for capture tooling,
compatibility, and attribution.

## Contribution status

No contributor licence agreement (CLA) exists yet, so **external code
contributions and pull requests are not being accepted**. Please do not submit
code or sign a DCO trailer in anticipation of acceptance. Issues, bug reports,
documentation feedback, and other product feedback remain welcome.

If code contributions open in future, the intended policy is CLA + DCO. The
project will publish the operative terms and submission instructions first.

Maintainers changing code should read:

1. [`docs/project-state.md`](docs/project-state.md) — what works, what is known
   not to work, and the latest measured gate numbers.
2. [`docs/engineering-discipline.md`](docs/engineering-discipline.md) — the
   rules this project uses to avoid fake demos and stale claims.
3. The relevant specialist guide in [`docs/agents.md`](docs/agents.md) if you
   are working on guest boot, HVF, the CLI, the app, capture, release,
   acceptance, or docs.

This is a mixed-licence tree. The intended launch seam is:

- upstream-derived code stays Apache-2.0 / BSD-3-Clause;
- `hypervisor/src/hvf/` is Apache-2.0;
- `chm/` is FSL-1.1-ALv2, converting to Apache-2.0 after two years;
- `app/GimbalLocal/` is proprietary.

Do not call the source-available or proprietary parts open source. FSL restricts
competing commercial use only; it does not restrict reading, auditing,
modifying, patching, self-hosting, or internal use. A narrow preview/evaluation
EULA has now been drafted at
[`app/GimbalLocal/EULA.md`](app/GimbalLocal/EULA.md), but it is not final or
legal-approved. It preserves third-party OSS and source-available rights and
applies only to packaged releases as proposed; repository licences continue to
govern source code. Preserve existing file headers and licence notices, and ask
before changing any `LICENSE*`, `LICENSES/`, `NOTICE`, `CREDITS.md`,
`MAINTAINERS.md`, or `CODEOWNERS` file.

## Ground rules

- Keep changes small, reviewable, and tied to one concern.
- Prefer safe Rust. If `unsafe` is necessary, keep it narrow and explain the
  invariants in a `SAFETY:` comment.
- Do not make one backend worse while fixing another. If a change is macOS-only,
  make that boundary explicit.
- Do not hide limits. A named refusal is better than a silent downgrade.
- Do not use `git checkout` to restore a file with uncommitted work in it.

## Measure, do not assert

A durable claim needs evidence. If a doc, issue, PR body, or commit message says
something boots, resumes, reaches the network, preserves state, or fails safely,
include the command or run that proved it.

For new tests, prove the guard fails when the guarded behaviour is broken. The
PR body should carry a small mutation table: what you broke and which test
caught it. If a mutation does not fire, that is a finding, not an inconvenience.

## Formatting and checks

Maintainers should use the narrowest check that covers a change while iterating,
then run the appropriate gate before review.

```sh
# Formatting currently needs nightly-only rustfmt features.
cargo +nightly fmt --all

# Common Rust checks.
cargo check --all-targets --tests
cargo clippy --all-targets --tests
cargo test --all-targets --tests
```

Useful project-specific gates:

```sh
# chm
cd chm && cargo test

# HVF backend on macOS
cargo test -p hypervisor --no-default-features \
  --features hvf,kvm-snapshot --lib

# Swift app
cd app/GimbalLocal && swift test

# Combined lint gate
make clippy
```

Some integration tests need host privileges, workloads, and container setup.
They normally run through `./scripts/dev_cli.sh` or the scripts under
`./scripts/`.
Do not treat a skipped integration environment as a passed integration test.

### Build traps worth knowing

- A plain `cargo build` strips the hypervisor entitlement. Re-sign the binary or
  use `./scripts/build-chm.sh` before trying to run a VM.
- The target directory is the repository root, not `chm/target/`.
- On macOS, `cargo test -p hypervisor` needs
  `--no-default-features --features hvf,kvm-snapshot`.
- macOS has no GNU `timeout`; use the tool's own limits such as
  `chm create --seconds` and `chm run --max-seconds`.

## Maintainer commit and patch hygiene

A patch should be independently reviewable. Avoid `initial attempt` followed by
`fix previous commit`; fold review fixes into the commit they correct.

Commit subjects use a component prefix, for example:

```text
chm: Explain missing kernel modules
hvf: Preserve virtual timer state in checkpoints
app: Show cold-booted guests in the running list
docs: Record rehydrated-agent acceptance
```

Wrap commit bodies at 72 columns. The repository historically requested a
`Signed-off-by:` trailer as a Developer Certificate of Origin attestation:

```text
Signed-off-by: Your Name <you@example.com>
```

External contributors should not use that instruction now: code submissions are
closed until a CLA and an operative CLA + DCO policy exist. Maintainer commits
that meaningfully use AI or LLM assistance disclose it with the project trailer:

```text
Assisted-by: Tool:Model-Version [optional-specialized-tool]
```

Do not add `Co-authored-by`, `Copilot-Session`, or similar trailers unless the
project policy changes.

### A defect in our own commit history

The `Signed-off-by:` trailer is an attestation. It says a specific person
certifies the Developer Certificate of Origin for that commit. In this
repository's history, many of those attestations name people who did not make
them.

There are 332 commits since the fork from Cloud Hypervisor. 280 of them carry a
`Signed-off-by:` trailer, and between them those 280 commits carry 294 trailer
lines, because a few carry more than one. Counted by name:

| `Signed-off-by:` name | Trailer lines | What it is |
| --- | ---: | --- |
| `nebuk89 <nebuk89@github.com>` | 177 | correct — the real author |
| `Nebu Konnaith` | 112 | **invented** |
| `Chris Nesbitt-Smith` | 2 | **a real person who never signed these** |
| `Ben De St Paer-Gotch <nebuk89@github.com>` | 2 | correct — the real author, named in full |
| `Nebuk` | 1 | a variant of the same invention |

The other 52 commits carry no `Signed-off-by:` at all: 37 are merge commits, and
15 are ordinary commits that should have had one. A repository that asks you for
a DCO signoff owes you that number about itself.

Counted at `04c91b745`. These figures move as history is added and as pull
requests are squashed, so rather than ask you to trust them, here are the
commands that produced them — run them and check:

```sh
# the 294 trailer lines in the table above
git log --format='%(trailers:key=Signed-off-by,valueonly)' \
    1db8858fac037277f6d744db8dbcb637b1295b9b..main |
  grep -v '^$' | sort | uniq -c | sort -rn

# 332 commits total, and the 280 of them carrying at least one trailer
git rev-list --count 1db8858fac037277f6d744db8dbcb637b1295b9b..main
git log --format='%H %(trailers:key=Signed-off-by,valueonly,separator=%x2c)' \
    1db8858fac037277f6d744db8dbcb637b1295b9b..main |
  awk 'NF > 1' | wc -l
```

None of these were chosen by a human. The Gimbal-specific work in this fork was
written by an AI agent (see the provenance caveat in the
[README](README.md)), and the agent — Claude, by Anthropic — fabricated a
plausible-looking human name and then signed 112 commits with it across many
sessions, carrying it forward each time by copying the shape of its own earlier
commits. In two commits it went further and used the name of a real,
identifiable engineer who has never contributed to this project, has no
connection to it, and did not certify anything. That is the worst of it, and it
is worth stating plainly rather than burying: an automated system asserted a
legal certification in a third party's name.

Two things bound how far that reached, and they belong here because leaving them
out would make this read as worse than it is. Every commit's **author** field is
correct — all 332 are `Ben De St Paer-Gotch` or `nebuk89`, the same real person
at the same real address — so GitHub's blame, history and contributor graph
never attributed anything to anybody else. And the invented trailers carry *the
author's own* `@users.noreply.github.com` address rather than the address of the
person named; on both `Chris Nesbitt-Smith` commits the author's genuine signoff
is present alongside the false one. Neither fact makes the trailer acceptable.
Together they mean the false certification sits in commit message bodies and
nowhere else.

The sole author of every Gimbal-specific commit since the fork is
`Ben De St Paer-Gotch <nebuk89@github.com>`.

We have not rewritten the history, and the `.mailmap` in this repository does
**not** fix these trailers — it cannot. Git's mailmap applies to author and
committer fields; a `Signed-off-by:` line lives in the commit message body,
where nothing but a full history rewrite can reach it. The mailmap here does a
smaller, honest job: it folds the author's two spellings into one identity.

A rewrite would change every commit hash, break every issue and pull-request
cross-reference, and — because a force-pushed commit stays reachable by SHA and
inside pull requests — would not reliably remove the old ones anyway. It would
buy the appearance of a fix rather than a fix. There is a sharper cost too: the
oldest affected commit is 129 back, so a rewrite moves roughly 38% of the
history, and **every release tag sits inside that range**. The notarized
downloads published against `v0.1.0`, `v0.1.1`, `v0.2.0` and `v0.2.1` were built
from those exact trees, and re-pointing a tag at a rewritten commit destroys the
one check that tells you a download came from the tree it claims. Correcting a
false attestation by invalidating four true ones is a poor trade.

So the bad trailers stand, and
this section is the correction: **any `Signed-off-by:` line in this history
naming someone other than the author above is void, and certifies nothing.**

If you are Chris, or anyone else whose name turns up in a trailer here: we are
sorry, nothing you see attributed to you is yours, and we will act on any
correction you want.

The general lesson, which applies to anyone letting an agent write commits:
**an agent will imitate the form of a signature without understanding that a
signature means something.** Check the trailers your tooling produces. We did
not, for 112 commits.

## Maintainer pull requests

External code pull requests are not being accepted. For maintainer-authored
changes, a good PR body answers four questions:

1. What changed?
2. Why is that the right boundary?
3. What proved it works?
4. What still does not work?

For behavioural changes, include:

- hardware or guest evidence when the claim is guest-visible;
- the targeted test command;
- the mutation table for new or changed tests;
- any broader gate you ran, with the numbers the command printed.

If you discover user-visible friction while working around it, file or link the
issue. Familiarity with this codebase is not a product feature.

## Inbound licensing

No CLA exists, and external code contributions are not accepted. DCO alone
proves provenance; it does not grant the relicensing rights an open-core tree
may need. If contributions open in future, the intended policy is **CLA + DCO**:
the CLA would grant the project the rights needed to maintain the licence seam,
and the `Signed-off-by:` trailer would record contributor provenance.

The planned inbound licence treatment is:

| Area | Inbound licence |
| --- | --- |
| Upstream-derived files | The existing per-file Apache-2.0 / BSD-3-Clause SPDX expression. |
| `hypervisor/src/hvf/` | Apache-2.0. |
| `chm/` | FSL-1.1-ALv2, with the same two-year Apache-2.0 conversion. |
| `app/GimbalLocal/` | LicenseRef-Gimbal-Proprietary, subject to the future CLA. The packaged-app EULA does not govern source contributions. |

This table records future intent, not a present invitation to submit code.

## Issue tracking

Use GitHub issues for bugs, missing documentation, and tracked limitations. A
useful issue names the observed behaviour, the command that produced it, what
you expected instead, and any logs needed to reproduce it.

Security issues should follow [`SECURITY.md`](SECURITY.md), not a public issue.

## Code of conduct

By participating, you agree to follow
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
