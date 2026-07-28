#!/usr/bin/env python3
"""Measure a rehydrated guest's clock dilation against host wall time.

Drives a snapshot to a login shell over a pty, then times a guest `sleep N`
using the HOST clock. A guest whose cached `arch_timer_rate` disagrees with the
counter it is actually reading takes `N * guest_hz / host_hz` real seconds to
finish a sleep it believes lasted N.

Usage:
  measure-clock-dilation.py <SNAPSHOT_DIR> [--sleep N] [--expect RATIO]

Environment passed through to chm (e.g. CHM_GUEST_CNTFRQ) selects the mode
under test, so the same instrument measures both the dilated and the corrected
run and the two are directly comparable.
"""

import argparse
import os
import pty
import re
import select
import subprocess
import sys
import time

CHM = os.path.join(os.path.dirname(__file__), "..", "..", "target", "debug", "chm")


def drive(snapshot, sleep_secs, boot_budget):
    """Boot, log in, time a guest sleep on the host clock.

    Returns (host_elapsed, boot_elapsed, transcript).
    """
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(
            CHM,
            [CHM, "run", snapshot, "--idle-exit", "0", "--max-seconds",
             str(int(boot_budget + sleep_secs * 8 + 60)), "--quiet"],
        )
        os._exit(1)

    buf = ""
    transcript = []
    started = time.monotonic()
    login_done_at = None
    sleep_started = None
    host_elapsed = None
    stage = "wait-login"
    last_nudge = 0.0

    try:
        while time.monotonic() - started < boot_budget + sleep_secs * 8 + 45:
            r, _, _ = select.select([fd], [], [], 0.25)
            if r:
                try:
                    chunk = os.read(fd, 65536).decode("utf-8", "replace")
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                transcript.append(chunk)

            now = time.monotonic()

            if stage == "wait-login":
                if re.search(r"login:\s*$", buf) or "login:" in buf[-400:]:
                    os.write(fd, b"ubuntu\n")
                    stage = "wait-password"
                    buf = ""
                elif now - last_nudge > 3.0:
                    # Nudge the console so a quiescent getty reprints its prompt.
                    os.write(fd, b"\n")
                    last_nudge = now

            elif stage == "wait-password":
                if "assword" in buf:
                    os.write(fd, b"ubuntu\n")
                    stage = "wait-shell"
                    buf = ""

            elif stage == "wait-shell":
                if "$" in buf and "@" in buf:
                    login_done_at = now
                    # Bracket the sleep with markers we timestamp host-side.
                    os.write(
                        fd,
                        f"echo GO_MARK; sleep {sleep_secs}; echo DONE_MARK\n".encode(),
                    )
                    stage = "wait-go"
                    buf = ""

            elif stage == "wait-go":
                # Ignore the shell's own echo of the command line.
                if "GO_MARK" in buf.replace(f"echo GO_MARK; sleep {sleep_secs}; echo DONE_MARK", ""):
                    sleep_started = time.monotonic()
                    stage = "wait-done"
                    buf = ""

            elif stage == "wait-done":
                if "DONE_MARK" in buf.replace("echo DONE_MARK", ""):
                    host_elapsed = time.monotonic() - sleep_started
                    break
    finally:
        try:
            os.write(fd, b"\x01x")
            time.sleep(1.5)
        except OSError:
            pass
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(fd)

    boot_elapsed = (login_done_at - started) if login_done_at else None
    return host_elapsed, boot_elapsed, "".join(transcript)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot")
    ap.add_argument("--sleep", type=int, default=5)
    ap.add_argument("--boot-budget", type=float, default=90.0)
    args = ap.parse_args()

    host_elapsed, boot_elapsed, transcript = drive(
        args.snapshot, args.sleep, args.boot_budget
    )

    mode = os.environ.get("CHM_GUEST_CNTFRQ")
    print(f"mode:          CHM_GUEST_CNTFRQ={mode or '(unset — no scaling)'}")
    if boot_elapsed is not None:
        print(f"boot to shell: {boot_elapsed:.2f} s host")
    if host_elapsed is None:
        print("RESULT: did not reach a timed sleep", file=sys.stderr)
        sys.stderr.write(transcript[-3000:])
        return 2
    ratio = host_elapsed / args.sleep
    print(f"guest sleep {args.sleep}: {host_elapsed:.2f} s host")
    print(f"dilation:      {ratio:.3f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
