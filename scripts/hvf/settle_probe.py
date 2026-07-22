#!/usr/bin/env python3
"""Empirical probe for the #78/#60 mid-cloud-init resume wedge.

Resumes a snapshot, waits for the shell, then does NOTHING for a settle window
(letting cloud-init reach modules:final and restart the getty on its own). After
the window it sends a marker command and reports whether the guest recovered to a
responsive shell. Purpose: determine whether the getty restart hard-wedges the
vCPU or merely drops the console while the guest completes cloud-init.

Usage: settle_probe.py <chm-binary> <snapshot-dir> [settle_secs]
"""
import os, pty, select, subprocess, sys, time

chm, snap = sys.argv[1], sys.argv[2]
settle = int(sys.argv[3]) if len(sys.argv) > 3 else 120

mfd, sfd = pty.openpty()
p = subprocess.Popen(
    [chm, "connect", snap, "--no-stop-daemon", "--idle-exit", "0", "--max-seconds", "900"],
    stdin=sfd, stdout=sfd, stderr=sfd, close_fds=True, preexec_fn=os.setsid,
)
os.close(sfd)
buf = bytearray()

def pump(t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([mfd], [], [], 0.2)
        if r:
            try:
                d = os.read(mfd, 65536)
            except OSError:
                return False
            if not d:
                return False
            buf.extend(d)
    return True

def wait_for(needle, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if needle.encode() in buf:
            return True
        pump(0.3)
    return needle.encode() in buf

def send(s):
    os.write(mfd, s.encode())

PROMPT = "@ch-snap:~$"
print(f"[probe] waiting for shell prompt (resume)...", flush=True)
# Nudge like resume_to_shell does.
got = False
for _ in range(12):
    send("\n")
    if wait_for(PROMPT, 6):
        got = True
        break
print(f"[probe] reached shell: {got}", flush=True)
mark0 = len(buf)

print(f"[probe] settling {settle}s (passive, let cloud-init finish)...", flush=True)
pump(settle)

# What did cloud-init do during the settle?
window = buf[mark0:].decode(errors="replace")
print("[probe] --- console during settle (tail) ---", flush=True)
print("\n".join(window.splitlines()[-25:]), flush=True)
print("[probe] --- end settle window ---", flush=True)

# Now probe responsiveness with the shell-var tag trick.
tag = f"ALIVE_{os.getpid()}_{int(time.time())}"
send(f"\nU={tag}; echo \"live=${{U}}\"\n")
alive = wait_for(f"live={tag}", 25)
print(f"[probe] RESPONSIVE_AFTER_SETTLE={alive}", flush=True)

# Also check cloud-init status if responsive.
if alive:
    send("cloud-init status 2>/dev/null || sudo cloud-init status 2>/dev/null\n")
    pump(8)
    tail = buf[-600:].decode(errors="replace")
    print("[probe] cloud-init status tail:", flush=True)
    print("\n".join(tail.splitlines()[-8:]), flush=True)

# Graceful shutdown (Ctrl-A x).
send("\x01x")
time.sleep(3)
try:
    os.killpg(os.getpgid(p.pid), 15)
except Exception:
    pass
try:
    p.wait(timeout=40)
except Exception:
    try:
        os.killpg(os.getpgid(p.pid), 9)
    except Exception:
        pass
print(f"[probe] done alive={alive}", flush=True)
sys.exit(0 if alive else 2)
