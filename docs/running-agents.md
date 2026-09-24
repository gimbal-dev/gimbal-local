# Running coding agents in Gimbal Local

This guide shows how to run a coding-agent CLI — GitHub Copilot CLI, Claude
Code, OpenAI Codex, or Gemini CLI — inside a Gimbal Local sandbox.

The most useful first demo is not a benchmark. It is an agent doing real work
inside a disposable local VM while the Mac keeps the credential.

That path is proven **both ways**: on a cold-booted guest, and — since
2026-08-13 — inside a freshly rehydrated cloud snapshot, where the agent also
survived two suspend/resume cycles and carried on with its own earlier work
([#286](https://github.com/gimbal-dev/gimbal-local/issues/286)).

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

The following boot examples allow package installation and GitHub API access,
not authenticated model access. After installation, use the
[account-aware Copilot quickstart](#native-copilot-quickstart) below.

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

## Native Copilot quickstart

**Use the model endpoint selected by your account, not a universal Copilot
host list.** Package installation and `copilot --version` do not check model
discovery. An `ENOTFOUND` error can mean that Gimbal refused DNS under the
sandbox's default-deny policy, not that the token is wrong.

Measured on 2026-09-07 with native Copilot CLI **1.0.83**, Debian 12 and Node
22.23.2: model discovery failed for `api.enterprise.githubcopilot.com`.
The daemon denied that exact host. After the operator changed the destination
and matching credential rule, the native agent completed its tasks
([#446](https://github.com/gimbal-dev/gimbal-local/issues/446)).
That is evidence for one account, not an endpoint selection rule for all
accounts.

This recipe uses a prepared glibc guest in a **local sandbox library**, with
native Copilot installed and a shell prompt available. It needs GNU coreutils
`timeout` inside the guest. No cloud host or host-directory mount is needed.
The September run used a prepared initramfs, then resumed a locally originated
snapshot; it was not a fresh image build or a disk-backed persistence test.
The shorter discovery prompt below is new: its flags match the recorded
`copilot --help`, but this exact prompt was not executed in that run.
This documentation update did not repeat the guest run.

### 1. Keep the credential and initial policy on the Mac

Use a new disposable workspace for these examples. Set these variables in each
host terminal, with your existing library and sandbox name:

```sh
CHM=/Applications/GimbalLocal.app/Contents/MacOS/chm
LIBRARY=/absolute/path/to/local-library
SANDBOX=agent
WS="$LIBRARY/$SANDBOX"
SOCKET=/absolute/path/to/copilot.sock
```

Use the host's `gh` account that has Copilot access on `github.com`. The proxy
runs the credential provider on the Mac. Do not run `gh auth token` yourself
or copy its output. Do not log in inside the guest, copy the host's auth
directory, or pass a real token through `--env`, argv, an image, or a log.

With the sandbox stopped, save this as **host-side**
`$WS/proxy-rules.json`. It contains a provider command, not a credential:

```json
{
  "version": 1,
  "rules": [
    {
      "name": "copilot-github-api",
      "hosts": ["api.github.com"],
      "ports": [443],
      "scheme": "bearer",
      "exec": ["gh", "auth", "token", "--hostname", "github.com"],
      "ttl_secs": 300
    }
  ]
}
```

Start with only the authentication API reachable:

```sh
"$CHM" firewall set "$WS" --default deny --allow api.github.com:443
"$CHM" firewall show "$WS" --json
"$CHM" proxy show "$WS"
```

**`firewall set` replaces the policy; it does not merge entries.** Do not use
this replacement on an existing governed workspace. Preserve its deny rules
and ask its policy owner to approve the exact destination instead.

Both files in this recipe have local authority. A matching credential rule
also implies an allowance for its own host and port, but only across the same
authority; deny rules still win. An environment-bound policy or rules document
can take precedence over these files. Do not remove that binding to bypass a
refusal. See [same-authority widening (I13)](credential-proxy.md#a-rule-makes-its-host-reachable)
and [credential custody (I12)](security-model.md).

In one host terminal, start the daemon and keep its stderr visible:

```sh
"$CHM" serve "$LIBRARY" --socket "$SOCKET"
```

In another host terminal, start the sandbox:

```sh
"$CHM" ctl --socket "$SOCKET" start "$SANDBOX"
"$CHM" ctl --socket "$SOCKET" status --json
"$CHM" ctl --socket "$SOCKET" proxy
```

The last command reads the daemon's configuration, not just the client
terminal's environment. Check that it names the intended workspace and rules.
Wait for the guest shell before you use `chm exec`.

### 2. Install trust, then make a bounded discovery request

Use the [credential-proxy CA guide](credential-proxy.md#the-one-thing-the-guest-must-be-told)
to install the running guest's CA and worthless auth placeholders:

```sh
"$CHM" proxy ca --install --socket "$SOCKET"
```

Resolve any nonzero installer result through the guide's
[minimal-container trust instructions](credential-proxy.md#a-container-guest-has-none-of-the-usual-furniture).
Node trust and system-store trust are separate results. Do not disable TLS
verification. Source `/etc/gimbal/proxy-ca.env` in the shell that starts
Copilot; a previous installer process cannot export into that shell.
The guest must contain only the installer's worthless placeholders, never a
real token.

Check the installed tools before the discovery request:

```sh
"$CHM" exec --socket "$SOCKET" --timeout 30 -- sh -c \
  'copilot --version && copilot --help && timeout --help'
```

The recorded Copilot 1.0.83 help supports the flags below. Check your installed
version rather than assuming a later release has the same flags. Check that
the guest's `timeout` supports `-k` before proceeding.

Run this from the Mac against an otherwise empty disposable guest:

```sh
"$CHM" exec --socket "$SOCKET" --timeout 400 --json -- sh -c '
  . /etc/gimbal/proxy-ca.env &&
  mkdir -p /workspace/copilot-quickstart &&
  cd /workspace/copilot-quickstart &&
  timeout -k 10s 360s copilot \
    --no-auto-update --no-remote --no-remote-export \
    --disable-builtin-mcps --no-custom-instructions --no-ask-user \
    --log-level none --no-color --allow-all-tools \
    -p "Reply with COPILOT_MODEL_OK. Do not use tools, read files or environment variables, or change anything."
'
```

This uses native Copilot's normal model discovery, not a guessed `/models`
HTTP probe. `--allow-all-tools` follows the recorded noninteractive CLI
requirement; use it only in this disposable guest. The prompt is not a
security boundary. Gimbal still controls egress, and the guest has no shared
host filesystem (I1).

The guest's GNU `timeout` sends TERM after 360 seconds and KILL 10 seconds
later if needed. `chm exec --timeout 400` only bounds the daemon's wait for
console completion; it does **not** stop the guest process. These limits
leave room for the inner deadline to finish first. They do not cure a wedged
guest or an unresponsive daemon.

Use the JSON result to distinguish `status: "completed"` with a guest
`exit_code` from `status: "timeout"` at the transport layer. A guest exit of
124 or 137 is not successful discovery. Do not start another agent while a
timed-out command might still run.

### 3. Authorize only the model host the account actually selected

With only `api.github.com` configured, expect the first request to stop at
the unlisted model host. Read the hostname from Copilot's failing URL.
Compare it with the daemon's stderr from the same attempt. The September
run showed:

```text
Error: Failed to load models
Error: error sending request for url (https://api.enterprise.githubcopilot.com/models): client error (Connect): dns error: failed to lookup address information: No address associated with hostname [ENOTFOUND]
Copilot could not retrieve the list of available models.
chm: [egress] DENY dns api.enterprise.githubcopilot.com (default-deny) — sandbox policy local
```

**Do not grant credentials to an arbitrary hostname merely because a guest
prints it.** Check that the requested model host belongs to the intended
Copilot service and is approved for your account. Use only its exact hostname
and HTTPS port 443, not the full URL, an IP workaround, or a wildcard.

Stop the library guest before changing its proxy rules:

```sh
"$CHM" ctl --socket "$SOCKET" stop
"$CHM" ctl --socket "$SOCKET" status --json
```

Repeat the status check until it reports `state: "stopped"`. A response that
says `stop requested` is not completion. If the guest does not stop, stop this
procedure; do not race a new `start` against it.

For the **recorded account only**, change the existing rule's `hosts` array
to `["api.github.com", "api.enterprise.githubcopilot.com"]`. Keep the
provider and port unchanged.

Then set the matching exact egress destination:

```sh
# Replace this with the approved model hostname from YOUR attempt.
COPILOT_MODEL_HOST=api.enterprise.githubcopilot.com
"$CHM" firewall set "$WS" --default deny \
  --allow api.github.com:443 --allow "$COPILOT_MODEL_HOST:443"
"$CHM" firewall show "$WS" --json
"$CHM" proxy show "$WS"
"$CHM" ctl --socket "$SOCKET" start "$SANDBOX"
"$CHM" ctl --socket "$SOCKET" proxy
```

For a different account, replace the example host in **both** the rule and
the command. Do not add individual, business and enterprise endpoints
together. Restarting the guest loads the changed proxy rules; changing live
egress alone does not add credential injection.

Once the guest reaches its shell, repeat the bounded discovery request.
Success means `status: "completed"`, `exit_code: 0`, and the requested
`COPILOT_MODEL_OK` response. `copilot --version` alone is not success.
If another functional endpoint is needed, repeat the same evidence and
approval process rather than widening to a domain suffix.

### Read the failure at the right layer

| Observation | Meaning and next action |
| --- | --- |
| `ENOTFOUND` plus a matching `DENY dns HOST (default-deny)` | Gimbal blocked name resolution for that host. Check the exact destination and the policy's authority before changing auth. |
| `ENOTFOUND` without a matching daemon denial | Not enough evidence to blame policy or auth. Check the daemon, DNS and network path; do not add speculative permissions. |
| TLS/certificate error | Check the running proxy CA and the trust configuration of the failing client. A successful Node request does not prove system-store trust. Never disable certificate checks. |
| HTTP 401/403 after TLS succeeds | Check the matching rule, host credential provider, account entitlement and service policy. A 403 alone does not prove that the token is invalid. |
| A local login/token refusal before any request | Check the installer's worthless placeholders and source its environment file. Do not put a real token in the guest. |
| `status: "timeout"` or a guest deadline exit | No discovery result. Check guest state and completion before retrying. |

For an independent **host-side** auth control with these local rules:

```sh
"$CHM" proxy check --workspace "$WS" --host api.github.com \
  --path /user --control
```

The September control returned HTTP 200 with injection and 401 without it.
This checks the provider and GitHub API auth, not guest DNS, guest trust, or
Copilot model entitlement. See the [proxy control guide](credential-proxy.md#proving-it-works-before-trusting-it-with-anything).

**Telemetry is separate from model access.** Leave telemetry destinations
denied in this quickstart. The September workload succeeded while
`telemetry.enterprise.githubcopilot.com` remained denied; that run also had
an explicit allowance for `copilot-telemetry.githubusercontent.com`, so it
does not prove that every version works with all telemetry blocked.
If telemetry is wanted, review its exact destination as a separate egress
permission. Do not put telemetry, package registries, or unrelated GitHub
hosts in the credential rule. Never use a wildcard to remove these denials.

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

For native GitHub Copilot CLI, use the
[bounded account-aware quickstart](#native-copilot-quickstart) above.

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

For Node itself, `NODE_OPTIONS=--jitless` is the current workaround. Measured
2026-08-13 during [#286](https://github.com/gimbal-dev/gimbal-local/issues/286),
the Copilot CLI's **native** binary ran clean on a rehydrated capture *without*
it, across three separate agent runs — so the older "5 of 5 dead" figure is
stale. Treat this as workload-dependent rather than fixed: if a JIT-heavy tool
dies with `SIGILL`, reach for `--jitless` first. The first-resume guide has the
measurements: [`first-resume.md`](first-resume.md).

Rehydrated agent runs are no longer an experiment. The friction you are most
likely to hit is not the agent — it is getting the credential proxy's CA into
the guest ([#315](https://github.com/gimbal-dev/gimbal-local/issues/315),
[#316](https://github.com/gimbal-dev/gimbal-local/issues/316)) and a client that
refuses to make the request at all unless it already sees a local token
([#318](https://github.com/gimbal-dev/gimbal-local/issues/318)).

## Official agent documentation

- GitHub Copilot CLI — <https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/overview>
- Claude Code CLI reference — <https://code.claude.com/docs/en/cli-reference>
- OpenAI Codex non-interactive mode — <https://learn.chatgpt.com/docs/non-interactive-mode>
- Gemini CLI headless mode — <https://geminicli.com/docs/cli/headless/>
