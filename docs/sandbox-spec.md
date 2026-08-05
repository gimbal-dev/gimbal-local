# The sandbox spec

> Describe a sandbox in a file instead of assembling one on a command line.
>
> Status: **shipped in V9.3** (#150). Partial by design — see
> [What it refuses](#what-it-refuses).

## Why

You could start a sandbox. You could not *describe* one. Everything that made a
sandbox what it is lived in about eleven flags across two entry points plus three
sidecar files, so a sandbox existed only as a command somebody remembered to
type. The app had to assemble the same eleven flags itself, which meant the
knowledge of what a sandbox can be was duplicated in Swift and had to be kept in
step by hand.

A spec is a `sandbox.json` in a workspace. It is committed with the code it runs,
reviewed like the code it runs, and it is the input to the *same* code path the
flags already drive.

```console
$ chm spec init ~/work/agent --name agent-sandbox
$ chm spec show ~/work/agent --explain
$ chm create --spec ~/work/agent
```

## The names are not ours

The field names come from the **agent compute environment spec**
([nebuk89/Dev-spec, `agent-compute-spec`](https://github.com/nebuk89/Dev-spec/tree/agent-compute-spec)),
whose `hostRequirements.hypervisor` enumeration reads:

```json
["firecracker", "cloud-hypervisor", "qemu", "any"]
```

We are one of four named targets. That makes adopting its vocabulary cheaper now
than translating between two forever, so `resourceLimits.memory.ram` rather than
`memory_mib`, `networkPolicy` rather than `network`, `secrets` rather than
`credentials`, camelCase throughout, and unit-suffixed strings (`"4gb"`,
`"30m"`) rather than bare numbers.

The tradeoff is real and worth stating: some names are longer than the ones we
would have picked. A document another tool can read is worth more than a
document that is briefly nicer to type.

### Where we deliberately differ

| Divergence | Why |
| --- | --- |
| `secrets.rulesFile`, not inline values | Credentials are attached at the network edge, so the guest never holds one (invariant I12, `docs/credential-proxy.md`). A spec gets committed; a credential in it would be too. `chm spec validate` refuses `env` keys that look like secrets. |
| `gb` means 1024 MiB | Every other number this tool prints is binary. One field meaning something different would be a worse surprise than the naming inconsistency. |
| `networkPolicy.policyFile` | A `chm` extension. Our policy files predate this spec and stay authoritative for anything a control plane issued. |
| Named tiers (`micro`…`performance`) | Not in the spec at all — a `chm` convenience, labelled as such by `chm spec tiers`. |
| Wildcards (`*.github.com`) refused | In the spec; **not implemented here**. Our matcher takes literal hostnames, so a wildcard would compile to a rule that never fires — permissive-looking and denying everything. Refused rather than silently under-enforced. |

## What it refuses, and why refusing is the feature

Twice this project has shipped a change that silently broke checkpoints on disk
(#178, #180), and both times a green test suite reported success. The lesson is
the design rule here:

> A spec section this build cannot honour is **refused by name, with its issue
> number** — never ignored.

Starting a sandbox that is weaker than the document describing it, with nothing
to tell the operator, is the same failure shape. So `securityModules` does not
become "no seccomp, quietly"; it becomes a refusal that names #184.

```console
$ chm spec validate ./sandbox.json
./sandbox.json: 3 problem(s)
  - `securityModules` is part of the agent compute spec but this build does not
    implement it (seccomp / LSM / capability policy inside the guest). Refusing
    rather than starting a sandbox weaker than this document describes — see #184.
  - toolPolicy.approval: per-tool allow/deny (the `denyList: ["bash"]` case) is
    not enforceable here — nothing in chm sees the agent's tool calls. Refusing,
    because believing a tool is blocked when it is not is worse than knowing it
    is not. See #186.
  - networkPolicy.egress[0]: wildcard `*.github.com` is in the spec but not
    implemented here…
```

A *typo* is reported differently from an *unbuilt section*, because they need
different fixes:

```console
  - unknown field `netwrokPolicy` — not part of the sandbox spec this build understands
```

Everything wrong is reported at once. A validator that makes you re-run it four
times to find four mistakes is one people stop running.

### Not implemented, with issues

| Section | Issue | What it would take |
| --- | --- | --- |
| `extensions` | #183 | The spec's replacement for Dev Container Features, keyed by OCI ref (`ghcr.io/agent-environments/extensions/bash`). Needs a rootfs build stage — #153. |
| `securityModules` | #184 | seccomp / LSM / capability policy *inside* the guest. |
| `dataPolicy` | #185 | Classifying and restricting what leaves. |
| `toolPolicy.approval` | #186 | Per-tool allow/deny. Needs MCP mediation (#157) — nothing in `chm` sees the agent's tool calls. |
| `identity` | #187 | Workload identity and attestation. |
| `observability` | #188 | Structured trace/metric export. |
| `image.oci` | #153 | Building a bootable rootfs from an OCI image. |
| `lifecycle` hooks | #189 | Ten in the spec (`initializeCommand`, `preBootCommand`, `onCreateCommand`, `preTaskCommand`, `postTaskCommand`, `preSnapshotCommand`, `postRestoreCommand`, `preShutdownCommand`, `waitFor`). We implement `postBootCommand` only — the one we have a channel for, and since V9.10 it is genuinely delivered rather than refused. |

Umbrella: **#182**.

`toolPolicy.capabilities` is the one that is *partly* real today. Omitting
`"network"` means no NIC is attached — a verifiable fact about the guest, not a
promise about the agent. `"filesystem"` and `"subprocess"` are refused, because
listing them would imply a control that does not exist.

## `env` and `postBootCommand`: how they actually reach a guest

These two shipped in V9.3 **refused**, and the refusal is the most useful thing
this document records. They parsed, they resolved, they printed in
`--explain` with their origin — and `chm create` had no `--env` and no
entrypoint flag, so nothing carried either across the boundary. A spec setting
`LANG` would have started a guest that had never heard of `LANG`, and every
visible signal would have said it worked. V9.10 (#190) built the delivery.

There is no kernel or `init` in the path. `chm create` cold-boots a **BYO**
image, so it cannot assume a cloud-init, a writable `/etc`, or any particular
init system. What it *can* assume is the thing it already owns: the serial
console, and the shell sitting on it.

**Readiness is proven, not pattern-matched.** Waiting for a `$` or `#` prompt
would be guesswork on an image we did not build — both characters appear in
kernel output, and distros print different banners. Instead `chm` sends a
framed no-op and watches for the answer:

```
__CHM_BEGIN_<nonce>__ ; true ; echo __CHM_END_<nonce>__:$?
```

If the end marker comes back, a shell read that line and ran it. That is not
*evidence* of a shell being ready — it **is** a shell being ready, on any image
that has one. The probe is idempotent, carries a fresh nonce each time so a
late answer cannot be read as the next probe succeeding, and repeats every
500 ms until the readiness deadline (120 s by default).

Then `env` is exported, then `postBootCommand` runs. That order is not
cosmetic: reversed, the two fields would each be individually correct and
jointly useless.

### `env` is not an argv, and that is why it is not one

`export` is a shell builtin. `["sh","-c","export FOO=bar"]` sets a variable in a
subshell that then exits — **exit code 0, nothing set**. It is exactly the shape
of failure this section exists to describe, so the assignments are evaluated by
the console's own shell rather than handed to a new one.

### The scope, stated rather than implied

The console is one tty with one shell session, and `chm connect` and `chm exec`
both attach to it. So an exported variable reaches:

| Reaches | Does not reach |
| --- | --- |
| `postBootCommand` | a **new login** after that shell exits and a getty respawns |
| later `chm exec` calls, and their children | processes started by systemd or any other init |
| an operator's `chm connect` session | anything on a **resumed snapshot** whose RAM predates the export |

Making it survive a getty respawn means writing to `/etc/environment` or a
profile script, which needs a writable rootfs and a known layout — neither of
which a BYO image owes us. Stating the limit is better than a control that
works on the images we happened to test.

### A non-zero exit fails the run

If `postBootCommand` exits non-zero, `chm create` reports it and exits non-zero
too. The guest was described as one that had run that command successfully; it
is not that guest, and a clean shutdown afterwards does not change it. A
delivery failure therefore outranks a tidy guest exit in the run's own status.

### Validation catches what delivery would only discover later

`chm spec validate` refuses an `env` key that is not a POSIX name (`my-var`
cannot be assigned by any shell) and one that looks like a credential
(`GITHUB_TOKEN`) — the second matters *more* now than it did in V9.3, because
before #190 a token in a spec was inert and now it would be exported into a
shell. Use `secrets.rulesFile`; the guest never needs to hold one.

## Precedence: what a sandbox is, versus how this run differs

```
default  <  tier  <  sandbox.json  <  command-line flag
```

A flag wins because a flag is how *this run* differs from what the sandbox is. A
flag you did **not** pass never erases something the spec did say.

`--explain` prints the origin of every value, because a value you cannot trace to
its source is not reviewable:

```console
$ chm spec show ~/work/agent --explain
agent-sandbox
  spec: /Users/me/work/agent/sandbox.json

  FIELD              VALUE                                FROM
  kernel             /images/ubuntu/Image                 sandbox.json
  vcpus              2                                    tier standard
  memory             2gb                                  tier standard
  network            on                                   sandbox.json
  egress             api.github.com:443                   sandbox.json
  idle               10m                                  default
  checkpoint         on                                   sandbox.json
```

## How it stays honest

The spec gets **no private route** into the hypervisor. `--spec` expands to the
argv a person would have typed, which is then parsed by the same parser:

```console
$ chm spec show ~/work/agent --argv
chm create --kernel /images/ubuntu/Image --disk /images/ubuntu/rootfs.img \
  --cpus 2 --memory 2048 --net --egress-allow api.github.com:443 --seconds 1800
```

Placing that expansion *before* your own flags is the whole of the precedence
rule: scalar options are last-wins in the parser, so a flag beats the spec, and
repeatable ones accumulate.

Measured, not asserted — `--dry-run` on both forms of the same sandbox:

```console
$ diff <(chm create --spec /tmp/specboot --dry-run) \
       <(chm create --kernel …/Image --disk …/rootfs.img --cpus 2 --memory 2048 \
                    --seconds 180 --dry-run)
8c8
<   built in   24.5 ms
---
>   built in   9.2 ms
```

Identical but for the build timer.

## Tiers

Named sizes, so the common case is one word rather than four numbers. A tier
sets every field it names; anything explicit lifts it.

| Tier | vCPU | RAM | Disk | For |
| --- | --- | --- | --- | --- |
| `micro` | 1 | 512mb | 2gb | A shell and a script. Too small for a package manager. |
| `dev` | 1 | 1gb | 8gb | The default. A language runtime and an editor session. |
| `standard` | 2 | 2gb | 16gb | An agent that installs dependencies and runs a test suite. |
| `performance` | 4 | 4gb | 32gb | Compiles. The largest that leaves an 8 GiB host usable. |

## In the app

`New sandbox → Describe a sandbox` writes a `sandbox.json` for a discovered
image. Once one exists, the menu says so (`ubuntu-cold · from sandbox.json`) and
cold boot goes through it — because two ways to start the same sandbox is exactly
the duplication this replaces, and the one that is written down wins.

The app does **not** validate specs itself. It shells out to `chm spec validate`
and shows the wording verbatim, the same division of labour as the V8.4
credential rule builder. Two implementations of one rule drift, and the drift
shows up as a sandbox that started differently from the way the UI described it.

A cross-boundary test (`SandboxSpecCrossBoundaryProbe`, skipped unless `CHM_PATH`
is set) proves a spec the app writes is one `chm` accepts, and that the app can
read a spec `chm` wrote. Neither side's unit tests can establish that; both can
be internally consistent and still disagree about a field name.

## Compatibility

`chm/testdata/sandbox-spec-v1.json` is a frozen document covering every field
this build implements. A test parses it and asserts nothing fell through to the
catch-all `extra` map. **If it fails, this change breaks specs that already
exist** — it never means the fixture is stale. Same discipline as the checkpoint
fixtures (#180).

A spec with a *newer* `specVersion` is refused by name. An older one is still
read: compatibility with what is already on disk is the entire point of
versioning a format.
