#!/usr/bin/env python3
"""Recapture a quiescent (post-cloud-init) golden checkpoint for a snapshot.

The stock demo snapshot's golden checkpoint was taken mid-cloud-init (Up ~182s),
so every resume replays cloud-init's `modules:final` serial-getty restart, which
wedges the interactive console (#78/#60). This tool resumes once WITH
`--checkpoint`, drives the guest to a confirmed quiescent state (cloud-init
`status: done` + a responsive shell), then clean-stops so `chm` captures a fresh
golden checkpoint at that settled point. Future resumes then start clean.

Usage: recapture-clean-checkpoint.py <chm-binary> <snapshot-dir> [attempts]

Exit 0 on a verified recapture, non-zero otherwise. Back up the existing
`.chm-checkpoint` first (APFS `cp -c -R`); this rewrites it on success.
"""
import json, os, pty, select, subprocess, sys, time

chm, snap = sys.argv[1], sys.argv[2]
attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 3
PROMPT = "@ch-snap:~$"
CKPT = os.path.join(snap, ".chm-checkpoint", "checkpoint.json")


def ckpt_created_ms():
    try:
        with open(CKPT) as f:
            return json.load(f).get("created_at_ms", 0)
    except Exception:
        return 0


def clear_overlays():
    ov = os.path.join(snap, ".chm-overlays")
    if os.path.isdir(ov):
        for e in os.listdir(ov):
            try:
                os.remove(os.path.join(ov, e))
            except OSError:
                pass


class Con:
    def __init__(self, argv):
        self.m, s = pty.openpty()
        self.p = subprocess.Popen(argv, stdin=s, stdout=s, stderr=s,
                                  close_fds=True, preexec_fn=os.setsid)
        os.close(s)
        self.buf = bytearray()

    def pump(self, t):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.m], [], [], 0.2)
            if r:
                try:
                    d = os.read(self.m, 65536)
                except OSError:
                    return False
                if not d:
                    return False
                self.buf.extend(d)
        return True

    def wait_for(self, needle, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if needle.encode() in self.buf:
                return True
            self.pump(0.3)
        return needle.encode() in self.buf

    def send(self, s):
        try:
            os.write(self.m, s.encode())
        except OSError:
            pass

    def close(self):
        self.send("\x01x")  # Ctrl-A x: clean stop (captures checkpoint)
        end = time.time() + 90
        while time.time() < end:
            if self.p.poll() is not None:
                break
            self.pump(0.5)
        if self.p.poll() is None:
            try:
                os.killpg(os.getpgid(self.p.pid), 9)
            except Exception:
                pass
        try:
            self.p.wait(timeout=30)
        except Exception:
            pass


def attempt(i):
    print(f"[recapture] attempt {i+1}/{attempts}", flush=True)
    clear_overlays()
    before = ckpt_created_ms()
    c = Con([chm, "connect", snap, "--checkpoint", "--no-stop-daemon",
             "--idle-exit", "0", "--max-seconds", "900"])
    try:
        # Reach a shell (resume restores it silently; nudge).
        got = False
        for _ in range(20):
            c.send("\n")
            if c.wait_for(PROMPT, 8):
                got = True
                break
        if not got:
            print("[recapture]  never reached a shell", flush=True)
            return False
        # Let cloud-init finish; the guest crawls through the getty restart.
        print("[recapture]  reached shell; waiting for cloud-init to settle...", flush=True)
        c.pump(180)
        # Confirm quiescence: cloud-init done AND a responsive shell, twice.
        ok = True
        for probe in range(2):
            tag = f"Q{os.getpid()}_{int(time.time())}_{probe}"
            c.send(f"\nU={tag}; cloud-init status 2>/dev/null; echo \"q=${{U}}\"\n")
            if not c.wait_for(f"q={tag}", 60):
                print(f"[recapture]  probe {probe}: shell UNRESPONSIVE", flush=True)
                ok = False
                break
            tailtxt = c.buf[-4000:].decode(errors="replace")
            if "status: done" not in tailtxt:
                print(f"[recapture]  probe {probe}: cloud-init not done yet", flush=True)
                ok = False
            time.sleep(5)
            c.pump(1)
        if not ok:
            return False
        # Flush disk, then clean-stop to capture the checkpoint.
        print("[recapture]  quiescent; syncing + capturing checkpoint...", flush=True)
        c.send("sync; sync\n")
        c.pump(4)
    finally:
        c.close()
    after = ckpt_created_ms()
    if after > before:
        print(f"[recapture]  NEW checkpoint captured: created_at_ms {before} -> {after}", flush=True)
        return True
    print(f"[recapture]  no new checkpoint (created_at_ms still {after})", flush=True)
    return False


for i in range(attempts):
    if attempt(i):
        print("[recapture] SUCCESS", flush=True)
        sys.exit(0)
print("[recapture] FAILED after all attempts", flush=True)
sys.exit(2)
