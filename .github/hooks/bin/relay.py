#!/usr/bin/env python3
"""postToolUse relay: put the repo's expensive lessons in front of the agent.

Three jobs, one process per tool call so the cost stays low:

  1. Command reminders. Some traps here cannot be blocked, only remembered --
     `cargo build` silently strips the hypervisor entitlement, so the next
     `chm` run fails with HV_DENIED and looks like a hypervisor bug.
  2. The compaction rubber-duck. `.github/hooks/bin/pre_compact.sh` leaves a
     stamp when the runtime compacts the conversation. The next tool call picks
     it up and asks for a rubber-duck pass, because compaction is exactly where
     a plan quietly loses the constraints that shaped it.
  3. The elapsed-time rubber-duck. The runtime has no timer hook, so the same
     stamp-file trick stands in for one: after GIMBAL_HARNESS_DUCK_MINUTES of
     wall clock (default 45, 0 disables), ask for the same pass.

Every notice names the harness and says why, because an unexplained
instruction arriving inside a tool result reads like a prompt injection, and a
careful agent is right to refuse it.

Contract (measured against Copilot CLI 1.0.74):
  stdin  {"sessionId": "...", "toolArgs": {"command": "..."}, ...}
  stdout {} or {"additionalContext": "..."}

This script must never raise: it prints `{}` on any failure path and exits 0.
"""

import json
import os
import re
import sys
import time

PREFIX = "Gimbal harness (.github/hooks) notice: "

DUCK_TEXT = (
    "run a rubber-duck pass now. Use the task tool with agent_type "
    '"rubber-duck". Give it the goal you are working towards, the plan you '
    "are following, and the commands whose output backs each claim you have "
    "made. Act on what it finds before you continue. Repo policy is in "
    "docs/engineering-discipline.md: measure, do not assert."
)

# (name, pattern, reminder).  Each names a trap that has cost real hours here.
REMINDERS = [
    (
        "cargo-build-strips-entitlement",
        r"\bcargo\s+(?:\+\S+\s+)?build\b",
        "that build stripped the hypervisor entitlement from the binary. Re-sign "
        "it before you run chm, or the next run fails with HV_DENIED and looks "
        "like a broken hypervisor: `codesign --sign - --entitlements "
        "hypervisor/tests/data/hv.entitlements --force target/debug/chm`.",
    ),
    (
        "pipestatus",
        r"\|\s*(?:tail|head|grep|sed|awk)\b[^\n]*\$\?",
        "`cmd | tail -n 5; echo $?` reports the exit status of `tail`, not of "
        "`cmd`. Use `${PIPESTATUS[0]}` to read the real status.",
    ),
    (
        "cargo-outside-chm",
        r"^\s*cargo\s+(?!\+nightly\s+fmt\b)",
        "cargo commands in this repo run from the chm directory. Prefix with "
        "`cd chm &&`, and run `make clippy` and `make check-docs` from the "
        "repository root.",
    ),
]

COMPILED = [(name, re.compile(pat), text) for name, pat, text in REMINDERS]

# The gate commands this repo runs before it believes a change is safe.  The
# relay records that they ran so `stop_gate.py` can tell a checked change from
# an unchecked one.  postToolUse fires only after a tool call completes, so a
# command that never ran leaves no stamp.
GATE_PATTERN = re.compile(
    r"\b(?:make\s+(?:clippy|check-docs|test-hvf)"
    r"|cargo\s+(?:\+\S+\s+)?(?:test|clippy)"
    r"|swift\s+test)\b"
)


def record_gate(base, command):
    """Leave a stamp when a gate command runs, for stop_gate.py to read."""
    if command and GATE_PATTERN.search(command):
        open(os.path.join(base, "gates-run"), "w").close()
        return True
    return False


def matching_reminders(command):
    """Return the reminder names and texts triggered by `command`."""
    if not command:
        return []
    return [(name, text) for name, pattern, text in COMPILED if pattern.search(command)]


def state_dir(session_id):
    base = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "gimbal-harness", session_id or "nosession"
    )
    os.makedirs(base, exist_ok=True)
    return base


def duck_minutes():
    raw = os.environ.get("GIMBAL_HARNESS_DUCK_MINUTES", "45")
    try:
        value = int(raw)
    except ValueError:
        return 45
    return value if value >= 0 else 45


def compaction_notice(base):
    """Consume the stamp left by pre_compact.sh, if there is one."""
    stamp = os.path.join(base, "compacted")
    if not os.path.exists(stamp):
        return None
    os.remove(stamp)
    return (
        "the conversation was just compacted, so the details behind your current "
        "plan are no longer in front of you. Repo policy is to " + DUCK_TEXT
    )


def elapsed_notice(base, now):
    """Stand in for the timer hook the runtime does not provide."""
    minutes = duck_minutes()
    if minutes == 0:
        return None
    stamp = os.path.join(base, "last-duck")
    try:
        last = os.path.getmtime(stamp)
    except OSError:
        # First tool call of the session: start the clock, do not fire.
        open(stamp, "w").close()
        return None
    if now - last < minutes * 60:
        return None
    os.utime(stamp, (now, now))
    return (
        "%d minutes have passed since the last review point. Repo policy is to "
        % minutes
    ) + DUCK_TEXT


def build_context(command, base, now):
    notices = [text for _, text in matching_reminders(command)]
    for notice in (compaction_notice(base), elapsed_notice(base, now)):
        if notice:
            notices.append(notice)
    if not notices:
        return None
    return "\n".join(PREFIX + notice for notice in notices)


# (command, expected reminder names).  The empty expectations are the negative
# controls: they prove the relay stays quiet on ordinary commands, so its
# notices keep meaning something.
SELFTEST_CASES = [
    ("cd chm && cargo build", ["cargo-build-strips-entitlement"]),
    (
        "cargo +nightly build --release",
        ["cargo-build-strips-entitlement", "cargo-outside-chm"],
    ),
    ("./scripts/check-docs.sh | tail -5; echo $?", ["pipestatus"]),
    ("cargo test --lib", ["cargo-outside-chm"]),
    ("cd chm && cargo test --lib", []),
    ("cargo +nightly fmt --all", []),
    ("make clippy", []),
    ("git status --short", []),
    ("swift test --package-path app/GimbalLocal", []),
    ("./scripts/check-docs.sh", []),
    ("echo hello", []),
    ("", []),
]

# (command, does this count as a gate run).  The False cases matter as much as
# the True ones: if reading a test file counted as running the tests, the
# completion gate would wave through work nobody checked.
GATE_CASES = [
    ("cd chm && cargo test --lib", True),
    ("make clippy", True),
    ("make check-docs", True),
    ("make test-hvf", True),
    ("swift test --package-path app/GimbalLocal", True),
    ("cargo +nightly test", True),
    ("cd chm && cargo build", False),
    ("git status --short", False),
    ("cat chm/src/hygiene.rs", False),
    ("grep -n 'fn test' chm/src/hygiene.rs", False),
    ("", False),
]


def selftest():
    failures = []
    for command, expected in SELFTEST_CASES:
        actual = [name for name, _ in matching_reminders(command)]
        if actual != expected:
            failures.append((command, expected, actual))
    for command, expected in GATE_CASES:
        actual = bool(GATE_PATTERN.search(command))
        if actual != expected:
            failures.append((command, "gate=%s" % expected, "gate=%s" % actual))
    for command, expected, actual in failures:
        sys.stderr.write(
            "FAIL: %r expected %s, got %s\n" % (command, expected, actual)
        )
    total = len(SELFTEST_CASES) + len(GATE_CASES)
    if failures:
        sys.stderr.write("%d of %d relay cases failed\n" % (len(failures), total))
        return 1
    firing = sum(1 for _, e in SELFTEST_CASES if e)
    sys.stdout.write(
        "relay: %d cases pass (%d remind, %d quiet, %d gate), %d reminders\n"
        % (total, firing, len(SELFTEST_CASES) - firing, len(GATE_CASES), len(REMINDERS))
    )
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    try:
        payload = json.load(sys.stdin)
        command = payload.get("toolArgs", {}).get("command", "")
        base = state_dir(payload.get("sessionId", ""))
        record_gate(base, command)
        context = build_context(command, base, time.time())
    except Exception:
        context = None
    sys.stdout.write(json.dumps({"additionalContext": context}) if context else "{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
