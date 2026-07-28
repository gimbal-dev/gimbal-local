#!/usr/bin/env python3
"""Find the GUEST uptime at which a rehydrated guest starts failing disk reads.

Boots a snapshot, logs in, then polls a guest-side probe that reports its own
uptime alongside an exec of a binary that must come off disk. Records the guest
uptime at which the first `Input/output error` appears.

The point is to compare runs with and without `CHM_GUEST_CNTFRQ` scaling on a
common axis. Host wall time is not comparable between the two (that is the whole
purpose of the scaling), but GUEST uptime is: if both modes fail at the same
guest uptime, the fault is in the guest/disk path and scaling merely reached it
sooner. If only the scaled mode fails, the scaling caused it.
"""

import argparse
import os
import pty
import re
import select
import sys
import time

CHM = os.path.join(os.path.dirname(__file__), "..", "..", "target", "debug", "chm")
PROBE = "while true; do echo PR=$(cut -d' ' -f1 /proc/uptime) $(head -c 12 /usr/bin/id >/dev/null 2>&1 && echo OK || echo READFAIL); sleep 1; done\n"


def run(snapshot, guest_seconds, scaled):
    env = dict(os.environ)
    env["CHM_USERSPACE_GIC"] = "1"
    if scaled:
        env["CHM_GUEST_CNTFRQ"] = "121875000"
    else:
        env.pop("CHM_GUEST_CNTFRQ", None)

    # Host budget: unscaled guest time runs 5.078x slower in real seconds.
    host_budget = guest_seconds * (1.0 if scaled else 5.078125) + 120

    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(env)
        os.execvpe(
            CHM,
            [CHM, "run", snapshot, "--idle-exit", "0",
             "--max-seconds", str(int(host_budget + 60)), "--quiet"],
            env,
        )
        os._exit(1)

    buf = ""
    stage = "wait-login"
    started = time.monotonic()
    last_nudge = 0.0
    samples = []          # (guest_uptime, status)
    first_io_error = None  # (guest_uptime, host_elapsed)
    login_errors = False

    try:
        while time.monotonic() - started < host_budget:
            r, _, _ = select.select([fd], [], [], 0.25)
            if r:
                try:
                    chunk = os.read(fd, 65536).decode("utf-8", "replace")
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            now = time.monotonic()

            for m in re.finditer(r"PR=([0-9.]+) (OK|READFAIL)", buf):
                up, status = float(m.group(1)), m.group(2)
                if not samples or samples[-1][0] != up:
                    samples.append((up, status))
                    if status == "READFAIL" and first_io_error is None:
                        first_io_error = (up, now - started)

            if "Input/output error" in buf or "not known to the underlying" in buf:
                if first_io_error is None and samples:
                    first_io_error = (samples[-1][0], now - started)
                login_errors = True

            if len(buf) > 200000:
                buf = buf[-40000:]

            if stage == "wait-login":
                if "login:" in buf[-500:]:
                    os.write(fd, b"ubuntu\n")
                    stage = "wait-password"
                    buf = ""
                elif now - last_nudge > 3.0:
                    os.write(fd, b"\n")
                    last_nudge = now
            elif stage == "wait-password":
                if "assword" in buf:
                    os.write(fd, b"ubuntu\n")
                    stage = "wait-shell"
                    buf = ""
            elif stage == "wait-shell":
                if "$" in buf and "@" in buf:
                    os.write(fd, PROBE.encode())
                    stage = "probing"
                    buf = ""
            elif stage == "probing":
                if samples and samples[-1][0] >= guest_seconds:
                    break
    finally:
        try:
            os.write(fd, b"\x03\x01x")
            time.sleep(1.5)
        except OSError:
            pass
        for sig in (15, 9):
            try:
                os.kill(pid, sig)
                break
            except ProcessLookupError:
                pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(fd)

    return samples, first_io_error, login_errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot")
    ap.add_argument("--guest-seconds", type=float, default=200.0,
                    help="how far into GUEST uptime to probe")
    ap.add_argument("--scaled", action="store_true")
    args = ap.parse_args()

    samples, first_io_error, login_errors = run(
        args.snapshot, args.guest_seconds, args.scaled
    )
    mode = "SCALED (CHM_GUEST_CNTFRQ=121875000)" if args.scaled else "UNSCALED"
    print(f"mode:              {mode}")
    if samples:
        print(f"guest uptime seen: {samples[0][0]:.1f}s -> {samples[-1][0]:.1f}s "
              f"({len(samples)} samples)")
    else:
        print("guest uptime seen: none (never reached the probe)")
    if first_io_error:
        up, host = first_io_error
        print(f"FIRST DISK FAILURE at guest uptime {up:.1f}s (host +{host:.1f}s)")
    else:
        print("no disk failure observed")
    print(f"login/motd errors: {login_errors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
