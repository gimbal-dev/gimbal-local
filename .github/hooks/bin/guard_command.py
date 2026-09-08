#!/usr/bin/env python3
"""preToolUse guard: refuse the shell commands that have cost this repo real work.

Every rule below names a defect that actually happened here.  The rule table is
the single source of truth: `--selftest` runs it against a case table that
contains both commands that must be refused and commands that must be allowed.

Contract (measured against Copilot CLI 1.0.74, not assumed):
  stdin  {"toolName": "bash", "toolArgs": {"command": "...", ...}, ...}
  stdout {} to stay out of the way, or
         {"permissionDecision": "deny"|"ask", "permissionDecisionReason": "..."}

Safety property: a preToolUse hook that errors denies the tool call, so this
script must never raise.  Every failure path prints `{}` and exits 0.
"""

import json
import re
import sys

# (name, pattern, decision, reason).  Patterns are searched against the raw
# command string.  Keep them narrow: a guard that cries wolf gets switched off.
RULES = [
    (
        "git-checkout-path",
        r"\bgit\s+(?:-[^\s]+\s+)*checkout\s+(?:--\s|\.(?:\s|$)|[^\s-][^\s]*\.(?:rs|swift|md|sh|toml|json|yml|yaml)\b)",
        "deny",
        "Refused: `git checkout` of a path discards uncommitted work, and has "
        "destroyed work in this repo five or more times. To restore a file: "
        "`cp <file> /tmp/backup` first, then `git show HEAD:<file> > <file>`, "
        "then `md5 -q` both to check the result. See "
        "docs/engineering-discipline.md.",
    ),
    (
        "git-restore",
        r"\bgit\s+(?:-[^\s]+\s+)*restore\b",
        "deny",
        "Refused: `git restore` discards uncommitted work. Back the file up to "
        "/tmp first, then restore with `git show HEAD:<file> > <file>` and "
        "check with `md5 -q`. See docs/engineering-discipline.md.",
    ),
    (
        "git-reset-hard",
        r"\bgit\s+(?:-[^\s]+\s+)*reset\s+(?:--\S+\s+)*--hard\b",
        "deny",
        "Refused: `git reset --hard` discards uncommitted work. Commit or stash "
        "first, or copy the files you need to /tmp.",
    ),
    (
        "git-clean",
        r"\bgit\s+(?:-[^\s]+\s+)*clean\b(?=.*(?<!-)-[a-zA-Z]*[fdx])",
        "deny",
        "Refused: `git clean` deletes untracked files, which in this worktree "
        "includes captured logs and snapshots that are not reproducible.",
    ),
    (
        "process-kill-by-name",
        r"\b(?:pkill|killall)\b",
        "deny",
        "Refused: `pkill` and `killall` match by name and have killed unrelated "
        "processes on this machine. Find the PID and use `kill <PID>`.",
    ),
    (
        "blind-cargo-fmt-check",
        r"\bcargo\s+(?:\+\S+\s+)?fmt\b(?=.*--check)(?=.*(?:\.rs\b|\bsrc/))",
        "deny",
        "Refused: `cargo fmt -- --check <path>` does not check that path. It "
        "formats the package's own targets and ignores the trailing path, so it "
        "prints nothing and exits 0 on a mangled file. That false zero shipped "
        "in PR #442. Use `rustfmt +nightly --unstable-features --skip-children "
        "--edition 2024 --check` on a copy placed inside the tree, so rustfmt "
        "finds the repo .rustfmt.toml. See docs/engineering-discipline.md, the "
        "section on measuring formatting drift.",
    ),
    (
        "aws-mutation",
        r"\baws\s+(?!\S+\s+(?:describe|list|get|help)\b)\S+\s+"
        r"(?:run|create|start|stop|terminate|delete|modify|put|reboot|attach|detach|import|copy|register|deregister)",
        "ask",
        "This runs a mutating AWS command. The standing rule in this repo is to "
        "ask before touching AWS: the Graviton captures under ~/ch-snapshots are "
        "irreplaceable and instances cost money. Confirm with the user first.",
    ),
]

COMPILED = [(name, re.compile(pat), decision, reason) for name, pat, decision, reason in RULES]


def decide(command):
    """Return (rule_name, decision, reason) for the first matching rule, else None."""
    if not command:
        return None
    for name, pattern, decision, reason in COMPILED:
        if pattern.search(command):
            return (name, decision, reason)
    return None


# (command, expected rule name or None).  Cases expecting None are the negative
# controls: they prove the guard stays quiet on the everyday commands this repo
# runs, which is the half of correctness that a firing test cannot show.
SELFTEST_CASES = [
    # --- must be refused -------------------------------------------------
    ("git checkout -- chm/src/hygiene.rs", "git-checkout-path"),
    ("git checkout chm/src/hygiene.rs", "git-checkout-path"),
    ("git checkout .", "git-checkout-path"),
    ("cd /repo && git checkout -- docs/project-state.md", "git-checkout-path"),
    ("git restore chm/src/main.rs", "git-restore"),
    ("git restore --staged .", "git-restore"),
    ("git reset --hard HEAD~1", "git-reset-hard"),
    ("git clean -fd", "git-clean"),
    ("git clean -xdf", "git-clean"),
    ("pkill -f chm", "process-kill-by-name"),
    ("killall chm", "process-kill-by-name"),
    ("cargo +nightly fmt -- --edition 2024 --check chm/src/hygiene.rs", "blind-cargo-fmt-check"),
    ("cargo fmt --check src/lib.rs", "blind-cargo-fmt-check"),
    ("aws ec2 run-instances --image-id ami-123", "aws-mutation"),
    ("aws ec2 terminate-instances --instance-ids i-123", "aws-mutation"),
    ("aws s3api delete-object --bucket b --key k", "aws-mutation"),
    # --- must be allowed (negative controls) -----------------------------
    ("git checkout -b defects-437-440", None),
    ("git checkout main", None),
    ("git status --short", None),
    ("git show HEAD:chm/src/hygiene.rs > /tmp/base.rs", None),
    ("git commit -q -F msg.txt", None),
    ("git clean --dry-run", None),
    ("kill 4812", None),
    ("cargo +nightly fmt --all", None),
    ("cargo fmt --all -- --check", None),
    ("rustfmt +nightly --unstable-features --skip-children --edition 2024 --check x.rs", None),
    ("cd chm && cargo test --lib", None),
    ("make clippy", None),
    ("aws ec2 describe-instances", None),
    ("aws s3 ls", None),
    ("swift test --package-path app/GimbalLocal", None),
    ("", None),
]


def selftest():
    failures = []
    for command, expected in SELFTEST_CASES:
        got = decide(command)
        actual = got[0] if got else None
        if actual != expected:
            failures.append((command, expected, actual))
    for command, expected, actual in failures:
        sys.stderr.write(
            "FAIL: %r expected %s, got %s\n" % (command, expected, actual)
        )
    total = len(SELFTEST_CASES)
    refused = sum(1 for _, e in SELFTEST_CASES if e is not None)
    if failures:
        sys.stderr.write("%d of %d guard cases failed\n" % (len(failures), total))
        return 1
    sys.stdout.write(
        "guard_command: %d cases pass (%d refused, %d allowed), %d rules\n"
        % (total, refused, total - refused, len(RULES))
    )
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    try:
        payload = json.load(sys.stdin)
        command = payload.get("toolArgs", {}).get("command", "")
        verdict = decide(command)
    except Exception:
        verdict = None
    if verdict is None:
        sys.stdout.write("{}")
        return 0
    _, decision, reason = verdict
    sys.stdout.write(
        json.dumps({"permissionDecision": decision, "permissionDecisionReason": reason})
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
