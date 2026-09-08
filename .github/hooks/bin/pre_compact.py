#!/usr/bin/env python3
"""preCompact hook: leave a stamp so the next tool call asks for a rubber duck.

The runtime runs this before it compacts the conversation.  Whether a
preCompact hook can inject context that survives the compaction is not
something this repo has measured, so it does not rely on that: it writes a
stamp file, and `relay.py` turns that stamp into a request on the next tool
call, through the postToolUse `additionalContext` channel that has been
measured to work.

It shares `state_dir` with relay.py on purpose.  The two must agree on the
path, and the only way to be sure of that is to compute it once.

This script must never raise: the runtime treats a failing lifecycle hook as
noise, but a stack trace on stdout is not valid JSON and helps nobody.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from relay import state_dir
except Exception:  # pragma: no cover - import guard
    state_dir = None


def main():
    try:
        payload = json.load(sys.stdin)
        base = state_dir(payload.get("sessionId", ""))
        open(os.path.join(base, "compacted"), "w").close()
    except Exception:
        pass
    sys.stdout.write("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
