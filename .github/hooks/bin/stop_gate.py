#!/usr/bin/env python3
"""agentStop gate: do not let unchecked source changes be called finished.

The runtime lets an agentStop hook refuse the stop and hand a reason back to
the agent, which is the one place a rule can be enforced rather than merely
written down.  This repo's most repeated failure is not a bad change, it is a
change nobody measured, so that is what this gate looks for: source files
edited in the working tree while no gate command ran all session.

`relay.py` leaves the `gates-run` stamp when it sees one, so the two scripts
have to agree on the state directory, and they do by sharing `state_dir`.

Three rules keep the gate from becoming the thing people switch off:

  * It blocks at most once per session.  A second stop always passes.
  * It never blocks a forced continuation (`stop_hook_active`).
  * It fails open.  If git is unavailable, the payload is malformed, or
    anything at all raises, the agent stops.  A gate that can trap the agent
    is worse than no gate.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from relay import state_dir
except Exception:  # pragma: no cover - import guard
    state_dir = None

SOURCE_SUFFIXES = (".rs", ".swift")

REASON = (
    "Gimbal harness gate (.github/hooks): you changed source files that no gate "
    "command has run against this session:\n"
    "%s\n"
    "Repo policy is measure, do not assert, so run what covers the change "
    "before you call it done:\n"
    "  cd chm && cargo test --lib     the chm suite\n"
    "  make clippy                    from the repository root\n"
    "  swift test --package-path app/GimbalLocal\n"
    "  make check-docs                when docs or issue lists moved\n"
    "Read the output, do not just start the command. If a new test guards "
    "something, prove it fails when that thing is broken, and put the mutation "
    "table in the pull request. If you have a reason to stop without running "
    "them, say what it is and stop again: this gate blocks only once."
)


def changed_source_files(cwd):
    """Return the source files git reports as changed, newest listing first."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if out.returncode != 0:
        return []
    files = []
    for line in out.stdout.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path.endswith(SOURCE_SUFFIXES):
            files.append(path)
    return files


def should_block(stop_hook_active, already_blocked, gates_ran, changed):
    """The whole decision, kept separate from the world so it can be tested."""
    if stop_hook_active:
        return False
    if already_blocked:
        return False
    if gates_ran:
        return False
    return bool(changed)


# (stop_hook_active, already_blocked, gates_ran, changed files, expect block).
# The False rows are the ones that keep this gate usable: it has to stay out of
# the way of a question, a docs edit, and a session that already ran its tests.
SELFTEST_CASES = [
    (False, False, False, ["chm/src/hygiene.rs"], True),
    (False, False, False, ["app/GimbalLocal/Sources/App.swift"], True),
    (False, False, True, ["chm/src/hygiene.rs"], False),
    (False, True, False, ["chm/src/hygiene.rs"], False),
    (True, False, False, ["chm/src/hygiene.rs"], False),
    (False, False, False, [], False),
    (True, True, True, [], False),
]


def selftest():
    failures = []
    for active, blocked, gates, changed, expected in SELFTEST_CASES:
        actual = should_block(active, blocked, gates, changed)
        if actual != expected:
            failures.append((active, blocked, gates, changed, expected, actual))
    for case in failures:
        sys.stderr.write("FAIL: %r expected %s, got %s\n" % (case[:4], case[4], case[5]))
    total = len(SELFTEST_CASES)
    if failures:
        sys.stderr.write("%d of %d gate cases failed\n" % (len(failures), total))
        return 1
    blocking = sum(1 for c in SELFTEST_CASES if c[4])
    sys.stdout.write(
        "stop_gate: %d cases pass (%d block, %d allow)\n"
        % (total, blocking, total - blocking)
    )
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    try:
        payload = json.load(sys.stdin)
        base = state_dir(payload.get("sessionId", ""))
        blocked_stamp = os.path.join(base, "stop-blocked")
        changed = changed_source_files(payload.get("cwd") or os.getcwd())
        block = should_block(
            bool(payload.get("stop_hook_active")),
            os.path.exists(blocked_stamp),
            os.path.exists(os.path.join(base, "gates-run")),
            changed,
        )
        if block:
            open(blocked_stamp, "w").close()
            listing = "\n".join("  " + path for path in sorted(changed)[:20])
            sys.stdout.write(
                json.dumps({"decision": "block", "reason": REASON % listing})
            )
            return 0
    except Exception:
        pass
    sys.stdout.write("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
