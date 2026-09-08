#!/usr/bin/env python3
"""sessionStart hook: open the session with facts, not with a summary.

Two things go wrong at the start of a session here.  The agent works in the
wrong tree, because the environment block it is handed can name a worktree that
was renamed or deleted.  And the agent trusts a number it read in a document,
because the document sounded confident.

So this brief carries only what it measures at the moment it runs -- the tree,
the branch, the commit, whether anything is uncommitted -- and for everything
else it names the command or the document instead of the answer.  Restating a
gate count here would just create one more place for it to rot, which is the
rule docs/engineering-discipline.md sets and the hygiene tests enforce.

It also says what the harness will refuse, because an agent that meets an
unexplained refusal mid-task tends to work around it.

This script must never raise: it prints `{}` on any failure path and exits 0.
"""

import json
import os
import subprocess
import sys


def git(cwd, *args):
    try:
        out = subprocess.run(
            ["git"] + list(args), cwd=cwd, capture_output=True, text=True, timeout=15
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def brief(cwd):
    root = git(cwd, "rev-parse", "--show-toplevel") or cwd
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD") or "(unknown)"
    head = git(root, "rev-parse", "--short", "HEAD") or "(unknown)"
    dirty = [line for line in git(root, "status", "--porcelain").splitlines() if line]
    state = "clean" if not dirty else "%d uncommitted path(s)" % len(dirty)
    lines = [
        "Gimbal harness (.github/hooks) session brief. Measured just now, so "
        "prefer it over any path or branch quoted elsewhere in your context:",
        "  working tree  %s" % root,
        "  branch        %s at %s, %s" % (branch, head, state),
        "",
        "Read before your first change:",
        "  docs/project-state.md          what works, and the evidence for it. "
        "The only place gate counts and the open issue list are allowed to live.",
        "  docs/engineering-discipline.md how we work: measure do not assert, "
        "mutation-test every guard, never restate a constant.",
        "  docs/agents.md                 the specialists in .github/agents. "
        "Read the one that covers your area.",
        "",
        "This harness does more than advise. It refuses `git checkout` of a "
        "path, `git restore`, `git reset --hard`, `git clean -f`, `pkill`, "
        "`killall`, and `cargo fmt --check <path>`, and it asks before a "
        "mutating AWS command. Each refusal names a defect that happened here "
        "and tells you the safe way round. It also asks for a rubber-duck pass "
        "after a compaction, and refuses one stop if you changed source files "
        "and never ran a gate command. Run `python3 "
        ".github/hooks/bin/guard_command.py --selftest` to see the whole rule "
        "table, and read .github/hooks/README.md to switch any of it off.",
    ]
    return "\n".join(lines)


def main():
    try:
        payload = json.load(sys.stdin)
        text = brief(payload.get("cwd") or os.getcwd())
    except Exception:
        text = None
    sys.stdout.write(json.dumps({"additionalContext": text}) if text else "{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
