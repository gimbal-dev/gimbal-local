# Running coding agents in Gimbal Local

This guide shows how to run a coding-agent CLI — GitHub Copilot CLI, Claude
Code, OpenAI Codex, or Gemini CLI — inside a Gimbal Local sandbox.

The most useful first demo is not a benchmark. It is an agent doing real work
inside a disposable local VM while the Mac keeps the credential.

That path is **proven on a cold-booted guest**. It is not yet proven on a
freshly rehydrated cloud snapshot; that acceptance gap is tracked as
[#286](https://github.com/gimbal-dev/gimbal-local/issues/286).

---

## If you already have a sandbox library

Use the daemon path when you have a snapshot library and want to drive the agent
by hand through a real terminal UI.

```sh
chm serve <library> &        # host a snapshot library
chm ctl list                 # list available sandboxes
chm ctl start <sandbox>      # boot the sandbox you want
chm ctl console              # attach to the interactive console
```

Once the console is attached, move into the project and launch the agent:

```sh
cd /workspace/project
copilot        # or: claude | codex | gemini
```

Interactive TUIs belong in `chm ctl console`. It is the path where prompts,
menus, and live output render as the agent expects.

## If you need a local agent image

A container image is a root filesystem; it has no kernel. The known-good local
agent shape is a glibc rootfs with a kernel and matching virtio modules supplied
at image-build time.

Measured on 2026-08-07:

| Piece | Known-good value |
| --- | --- |
| Root filesystem | `node:22-slim` (`glibc`; Alpine's musl build does not run the Copilot CLI) |
| Kernel | Alpine `linux-virt` 6.6.142-0-virt, with matching modules |
| Agent | GitHub Copilot CLI 1.0.78 |

Build the image:

```sh
CHM=/Applications/GimbalLocal.app/Contents/MacOS/chm

"$CHM" image build node:22-slim \
  --kernel /path/to/vmlinuz-virt \
  --modules /path/to/lib/modules/6.6.142-0-virt \
  --entrypoint /bin/sh \
  --out ~/gimbal-images/agent
```

For larger or writable roots, add `--disk`:

```sh
"$CHM" image build node:22-slim \
  --kernel /path/to/vmlinuz-virt \
  --modules /path/to/lib/modules/6.6.142-0-virt \
  --entrypoint /bin/sh \
  --disk \
  --out ~/gimbal-images/agent
```

Boot the default initramfs form:

```sh
"$CHM" create \
  --kernel ~/gimbal-images/agent/Image \
  --initramfs ~/gimbal-images/agent/initramfs \
  --cpus 2 --memory 3008 --net \
  --egress-allow registry.npmjs.org:443 \
  --egress-allow github.com:443 \
  --egress-allow objects.githubusercontent.com:443 \
  --egress-allow api.github.com:443
```

Or boot the disk-backed form:

```sh
"$CHM" create \
  --kernel ~/gimbal-images/agent/Image \
  --disk ~/gimbal-images/agent/rootfs.img \
  --cpus 2 --memory 512 --net \
  --egress-allow registry.npmjs.org:443 \
  --egress-allow github.com:443 \
  --egress-allow objects.githubusercontent.com:443 \
  --egress-allow api.github.com:443
```

Inside the guest:

```sh
npm i -g @github/copilot
copilot --version
```

The measured result on the known-good combination was:

```text
NPM_RC=0
CV_RC=0
CVOUT=GitHub Copilot CLI 1.0.78
```

The image-builder guide explains where to get working kernels and why many
kernels need `--modules`: [`container-images.md`](container-images.md).

---

## Headless: run an agent non-interactively

Use `chm exec` for a single non-interactive command in the guest:

```sh
chm exec [--socket PATH] [--timeout SECS] [--json] -- <command> [args...]
```

`chm exec` talks to the sandbox that `chm serve` is running. It drives the
serial console, so it is the right tool for scripts and headless prompts, not
for full-screen TUIs.

Examples:

```sh
# Claude Code — print mode
chm exec --timeout 1800 -- \
  claude -p "Review this repository and fix the failing tests"

# OpenAI Codex — non-interactive exec subcommand
chm exec --timeout 1800 -- \
  codex exec --sandbox workspace-write \
  "Review this repository and fix the failing tests"

# Gemini CLI — headless prompt
chm exec --timeout 1800 -- \
  gemini -p "Review this repository and fix the failing tests"
```

For automation, add `--json`:

```sh
chm exec --json --timeout 1800 -- \
  gemini -p "Summarize open TODOs in this repository"
```

`chm exec` treats arguments after `--` as an argv, not a shell command line. If
you want shell syntax, ask for it explicitly:

```sh
chm exec -- bash -lc 'make build 2>&1 | tail -20'
```

### Limits of `chm exec`

- The guest must be at a shell prompt.
- One `chm exec` at a time per sandbox.
- stdout and stderr are combined into a single console-text stream.
- Output is not binary-safe.
- The command is capped at 4000 bytes.
- Captured output is capped at 128 KiB.
- Exit code 124 means the guest did not answer before `--timeout`.
- Exit code 125 means `chm` could not run the command at all.
- On timeout, the agent may keep running inside the sandbox; the timeout bounds
  how long `chm exec` waits, not the agent itself.

GitHub Copilot CLI is currently documented here as an interactive command. Check
the official Copilot CLI docs before scripting it headlessly.

## Credentials stay on the host

Do not pass API keys or tokens on the command line, with `chm create --env`, or
inside sandbox images. Those paths leak secrets into command lines, logs, or
image layers.

The safe story is the credential proxy: the guest makes a normal outbound
request, and `chm` attaches a host-held credential as the request leaves the Mac.
The guest never holds the secret.

Start with [`credential-proxy.md`](credential-proxy.md), especially the CA setup
section. Node does not read the system trust store, so the proxy installer also
prints the `NODE_EXTRA_CA_CERTS` setup a Node-based agent needs.

Never paste secrets, tokens, or private data into public GitHub issues.

## Why rehydrated snapshots are different

A cold-booted guest reads this Mac's own `CTR_EL0` and keeps the instruction
cache maintenance this Mac needs. A rehydrated Graviton capture can arrive with
a CPU-feature view that was true in the cloud and false on the Mac. The visible
symptom is JIT code intermittently executing stale instructions.

For Node itself, `NODE_OPTIONS=--jitless` is the current workaround. It does not
cover a tool that launches its own native binary. The first-resume guide has the
current measurements: [`first-resume.md`](first-resume.md).

Until [#286](https://github.com/gimbal-dev/gimbal-local/issues/286) is closed,
use cold boot for agent demos and treat rehydrated-agent runs as an experiment.

## Official agent documentation

- GitHub Copilot CLI — <https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/overview>
- Claude Code CLI reference — <https://code.claude.com/docs/en/cli-reference>
- OpenAI Codex non-interactive mode — <https://learn.chatgpt.com/docs/non-interactive-mode>
- Gemini CLI headless mode — <https://geminicli.com/docs/cli/headless/>
