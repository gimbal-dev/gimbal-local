# The agent harness

This directory turns the rules in `docs/engineering-discipline.md` from advice
into mechanism. The rules were already written down and were still broken,
because a rule an agent has to remember is a rule an agent can forget. A hook
does not forget.

Every refusal below names a defect that actually happened in this repository.
Nothing here is speculative hardening.

## What runs, and when

| Event | Script | What it does |
| --- | --- | --- |
| `sessionStart` | `bin/session_brief.py` | States the working tree, branch, commit, and whether anything is uncommitted, all measured at that moment. Points at the three documents a new session should read. States what the harness will refuse, so a refusal mid-task is not a surprise. |
| `preToolUse` (bash) | `bin/guard_command.py` | Refuses the shell commands that have destroyed work here, and asks before a mutating AWS command. Each refusal explains the safe way round. |
| `postToolUse` (bash) | `bin/relay.py` | Reminds about the traps that cannot be blocked, only remembered. Delivers the rubber-duck request after a compaction or after an interval. Records that a gate command ran. |
| `preCompact` | `bin/pre_compact.py` | Leaves a stamp that `relay.py` turns into a rubber-duck request on the next tool call. |
| `agentStop` | `bin/stop_gate.py` | Refuses one stop when source files changed and no gate command ran all session. |

Wiring is in `gimbal-harness.json`. The Copilot CLI loads every `*.json` in
this directory once the folder is trusted.

## Turning it on

The harness is off until the folder is trusted, and it is silent when it is
off. A new session in a fresh worktree gets no hooks and no warning that it
has none.

In an interactive session, answer yes to the trust prompt the CLI shows the
first time it starts in a directory. That writes the path into
`trustedFolders` in `~/.copilot/config.json`.

Trust cascades to child directories. Measured: with only the worktree parent
in `trustedFolders`, a session inside a child worktree loaded these hooks and
denied `cargo fmt -- --check <path>`, which is a command an agent has no
reason to refuse by itself. So trust the directory that holds the worktrees,
once, and every worktree made later is covered:

```jsonc
// ~/.copilot/config.json
{ "trustedFolders": ["/path/that/holds/your/worktrees"] }
```

That file is JSONC and holds other settings. Edit it, do not overwrite it.

To check whether the harness is live, ask the session to run
`cargo fmt -- --check chm/src/hygiene.rs`, and look for the literal words
`Denied by preToolUse hook` in what comes back. Anything else means the
folder is not trusted and none of this is running.

Do not use `git checkout -- some/file` as that check. It passes for the
wrong reason: the rule is also written in `docs/engineering-discipline.md`,
so an agent refuses it on its own judgement whether or not the hook exists.
Measured, in a worktree with no `.github/hooks` at all, an agent still
refused it. The blind `cargo fmt --check` command discriminates because an
agent has no reason to refuse it: the same worktree ran it without comment.
A check that cannot fail is not a check.

## What it refuses

`bin/guard_command.py --selftest` prints the whole rule table. In summary it
denies `git checkout` of a path, `git restore`, `git reset --hard`,
`git clean -f`, `pkill`, `killall`, and `cargo fmt --check <path>`; and it asks
before a mutating `aws` command.

Two of those deserve their reasons stated here:

- **`git checkout <path>`** has destroyed uncommitted work in this repository
  five or more times. The refusal hands back the safe recipe instead.
- **`cargo fmt -- --check <path>` does not check that path.** It formats the
  package's own targets and ignores the trailing path, so it prints nothing and
  exits 0 on a mangled file. A drift measurement was taken and believed on the
  strength of that zero, and a false claim shipped in a merged pull request.

## The rubber duck

The user asked for a rubber-duck pass on every compaction, and after an
interval. The runtime has a `preCompact` hook but no timer hook, so:

- **On compaction**, `pre_compact.py` writes a stamp and the next `postToolUse`
  turns it into a request. The stamp is used once and then removed.
- **After an interval**, `relay.py` compares wall clock against a stamp it
  keeps per session. The default is 45 minutes. Set
  `GIMBAL_HARNESS_DUCK_MINUTES` to change it, or `0` to switch it off.

Both routes ask for the same thing: run the `rubber-duck` agent against the
current goal, plan, and evidence, and act on what it says.

Requests are worded as repo policy and say which file they come from. That is
not decoration. An unexplained instruction arriving inside a tool result looks
exactly like a prompt injection, and during development an agent correctly
refused a test notice on those grounds. Keep new notices explicit about where
they come from and why.

## The completion gate

`stop_gate.py` refuses a stop when tracked `.rs` or `.swift` files changed and
no gate command ran during the session. It is built so it cannot become the
thing people switch off:

- it blocks **at most once per session**;
- it never blocks a forced continuation (`stop_hook_active`);
- it **fails open**. A malformed payload, a missing git, or any exception at
  all lets the agent stop. A gate that can trap the agent is worse than no gate.

## Testing it

```bash
make check-harness
```

That runs the case table in each script. Every table contains both the inputs
the script must act on and the inputs it must ignore, because a guard that has
never stayed quiet is as untrustworthy as one that has never fired. The
`--dry-run` false positive in `git clean` was caught by exactly that, on the
first run.

To test a change end to end without touching your own configuration, point
`COPILOT_HOME` at a throwaway directory that trusts this repository:

```bash
mkdir -p /tmp/cphome
printf '{ "trustedFolders": ["%s"] }\n' "$(git rev-parse --show-toplevel)" > /tmp/cphome/config.json
COPILOT_HOME=/tmp/cphome GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS=1 \
  copilot -p "Run this shell command: git checkout -- does-not-exist.rs" --allow-all-tools -s
```

Repo hooks load only after folder trust, and in prompt mode only behind
`GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS`.

## Switching it off

Set `disableAllHooks` to `true` in `~/.copilot/config.json` or in
`.github/copilot/settings.json`, or delete `gimbal-harness.json`. The scripts
do nothing on their own.

If a rule here is wrong, fix the rule and its case table together. Do not work
around a refusal: a refusal you routed around is a defect report you threw
away.

## Measured, not assumed

The contract below was measured against Copilot CLI 1.0.74 on macOS by running
real sessions, not read from documentation:

- `preToolUse` receives `toolName` and `toolArgs.command`, and
  `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` blocks the
  command and hands the reason to the agent verbatim.
- `postToolUse` `{"additionalContext": "..."}` reaches the model.
- `agentStop` `{"decision": "block", "reason": "..."}` refuses the stop and
  makes the agent continue.
- `sessionStart` `{"additionalContext": "..."}` is injected into the
  conversation.
- Hook commands run in the session directory, so the scripts are located with
  `git rev-parse --show-toplevel` rather than a relative path.
