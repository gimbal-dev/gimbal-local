# Copyright © 2026 Ben De St Paer-Gotch
#
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Observe what cdpfwd.bin actually does, on a real Linux kernel.
#
# Driven by `cdpfwd::tests::in_container`, which runs it in a linux/arm64
# container against the *patched* image chm would install. It reports
# `key=value` lines on stdout and the Rust side decides what they mean; nothing
# here asserts anything, so a guard cannot pass because the harness was lenient.
#
# The address and port arrive on argv only so the harness knows where to dial.
# Everything the guards read -- the listening set, whether other ports answer --
# is *observed*, from /proc/net/tcp and from connections that either work or do
# not.

import os
import socket
import subprocess
import sys
import threading
import time

IP = sys.argv[1]
PORT = int(sys.argv[2])
# The argv the forwarder must ignore: a different port, a wildcard address and
# a shell. If any of it meant anything, the observations below would show it.
HOSTILE_ARGV = ["9999", "0.0.0.0", "/bin/sh"]

out = []
live = 0
peak = 0
live_lock = threading.Lock()
# All 96 flows hold their connection open until the last one has arrived, so
# "96 at once" is measured rather than assumed. A forwarder that served them
# one at a time would never reach the barrier.
gate = threading.Barrier(96, timeout=30)


def say(key, value):
    out.append(f"{key}={value}")


def listening():
    """The kernel's own view of what is listening, not the program's."""
    found = set()
    with open("/proc/net/tcp") as fh:
        for line in fh.read().splitlines()[1:]:
            fields = line.split()
            if fields[3] != "0A":  # TCP_LISTEN
                continue
            hexaddr, hexport = fields[1].split(":")
            addr = ".".join(str(b) for b in reversed(bytes.fromhex(hexaddr)))
            found.add(f"{addr}:{int(hexport, 16)}")
    return found


def echo_server(ready):
    """Stands in for Chromium: echoes, and always has one last word."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(256)
    ready.set()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=echo_one, args=(conn,), daemon=True).start()


def echo_one(conn):
    global live, peak
    with live_lock:
        live += 1
        peak = max(peak, live)
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                # The peer will not send again. We still have something to say,
                # and it has to survive: that is the half-close property.
                conn.sendall(b"TAIL")
                conn.shutdown(socket.SHUT_WR)
                conn.close()
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        with live_lock:
            live -= 1


def one_flow(index, results):
    """Each flow sends bytes only it could have sent."""
    try:
        sock = socket.create_connection((IP, PORT), timeout=20)
        payload = ("f%04d" % index).encode() * 64
        sock.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = sock.recv(65536)
            if not chunk:
                break
            got += chunk
        results[index] = True if got == payload else f"flow {index}: {got[:16]!r}"
        if index < 96:
            gate.wait()
        sock.close()
    except Exception as exc:  # noqa: BLE001 - reported, not handled
        results[index] = f"flow {index}: {exc!r}"


def concurrently(count, key):
    results = {}
    threads = [threading.Thread(target=one_flow, args=(i, results)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    ok = sum(1 for v in results.values() if v is True)
    say(key + "_ok", ok)
    bad = [v for v in results.values() if v is not True]
    say(key + "_detail", "; ".join(str(b) for b in bad[:3]) or "none")


def main():
    say("uname", subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip())
    subprocess.run(["ip", "addr", "add", IP + "/24", "dev", "lo"], check=True)
    os.chmod("/w/cdpfwd", 0o755)

    ready = threading.Event()
    threading.Thread(target=echo_server, args=(ready,), daemon=True).start()
    ready.wait(10)
    before = listening()

    proc = subprocess.Popen(["/w/cdpfwd"] + HOSTILE_ARGV, stderr=subprocess.PIPE)
    say("argv", " ".join(HOSTILE_ARGV))
    time.sleep(0.5)
    say("alive", "yes" if proc.poll() is None else "no")
    say("new_listeners", ",".join(sorted(listening() - before)) or "none")

    concurrently(96, "concurrent")
    say("peak_upstream", peak)

    # Half-close: we stop writing, the far side must still be able to answer
    # and its own close must reach us.
    sock = socket.create_connection((IP, PORT), timeout=20)
    sock.settimeout(10)
    sock.sendall(b"hello")
    sock.recv(16)
    sock.shutdown(socket.SHUT_WR)
    tail = b""
    eof = "no"
    while True:
        chunk = sock.recv(16)
        if not chunk:
            eof = "yes"
            break
        tail += chunk
    say("half_close_tail", tail.decode(errors="replace"))
    say("half_close_eof", eof)
    sock.close()

    # Bulk: the only thing that fills a buffer, and so the only thing that
    # exercises the partial write and the rewind.
    blob = bytes(range(256)) * 16384
    sock = socket.create_connection((IP, PORT), timeout=60)
    got = bytearray()

    def sink():
        while len(got) < len(blob):
            chunk = sock.recv(1 << 16)
            if not chunk:
                break
            got.extend(chunk)

    reader = threading.Thread(target=sink)
    reader.start()
    sock.sendall(blob)
    reader.join(120)
    say("bulk_bytes", len(got))
    say("bulk_ok", "yes" if bytes(got) == blob else "no")
    sock.close()

    # A reader that stops reading is the only thing that fills the forwarder's
    # own send queue, and a partial write is the only way its cursor is used.
    # SO_RCVBUF is deliberately tiny and the reads are dripped: a window that
    # opens by less than the queue is what makes sendto return a *partial*
    # count rather than the whole thing or EAGAIN. Measured -- at 2048 the
    # kernel took the queue whole and the partial path was never reached.
    slow = socket.socket()
    slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512)
    slow.connect((IP, PORT))
    slow.settimeout(30)
    chunk_blob = bytes(range(256)) * 4096
    sender = threading.Thread(target=lambda: slow.sendall(chunk_blob))
    sender.start()
    time.sleep(3)  # long enough for every buffer between here and there to fill
    back = bytearray()
    while len(back) < len(chunk_blob):
        try:
            piece = slow.recv(256)
        except socket.timeout:
            break
        if not piece:
            break
        back.extend(piece)
        time.sleep(0.0005)
    sender.join(30)
    say("slow_reader_ok", "yes" if bytes(back) == chunk_blob else "no")
    say("slow_reader_bytes", len(back))
    slow.close()

    # More at once than there are slots. The listener disarms, the backlog
    # holds them, and every one of them still completes.
    global gate
    gate = threading.Barrier(1, timeout=1)  # the 200-flow phase does not gate
    concurrently(200, "over_capacity")

    # A port that is not the one port -- named on argv, so if argv meant
    # anything this would answer.
    try:
        socket.create_connection((IP, int(HOSTILE_ARGV[0])), timeout=5).close()
        say("other_port", "connected")
    except OSError:
        say("other_port", "refused")

    say("listeners_after", ",".join(sorted(listening() - before)) or "none")
    say("still_alive", "yes" if proc.poll() is None else "no")
    proc.kill()
    print("\n".join(out))


main()
