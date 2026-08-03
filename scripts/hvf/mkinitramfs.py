#!/usr/bin/env python3
"""Build a newc cpio initramfs, including device nodes.

macOS `cpio` cannot create character devices without root, and an initramfs
without /dev/console gets init started with no stdin/stdout at all -- which
looks exactly like a silent hang. Writing the archive directly sidesteps
both problems and costs about 40 lines.
"""
import os, sys, stat

TRAILER = "TRAILER!!!"

def hdr(ino, mode, uid, gid, nlink, mtime, size, maj, mnr, rmaj, rmnr, name):
    f = "%08X"
    return ("070701" + "".join(f % v for v in (
        ino, mode, uid, gid, nlink, mtime, size,
        maj, mnr, rmaj, rmnr, len(name) + 1, 0))).encode() + name.encode() + b"\0"

def pad(b, n=4):
    return b + b"\0" * (-len(b) % n)

def build(root, extra_nodes, out):
    entries, ino = [], 721
    for dirpath, dirnames, filenames in os.walk(root):
        for n in sorted(dirnames) + sorted(filenames):
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            data = b"" if stat.S_ISDIR(st.st_mode) else open(p, "rb").read()
            entries.append((rel, st.st_mode, data, 0, 0))
    entries += extra_nodes
    blob = b""
    for name, mode, data, maj, mnr in sorted(entries):
        ino += 1
        blob += pad(hdr(ino, mode, 0, 0, 1, 0, len(data), 8, 1, maj, mnr, name))
        blob += pad(data)
    blob += pad(hdr(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, TRAILER))
    open(out, "wb").write(blob)
    return len(blob)

if __name__ == "__main__":
    nodes = [
        ("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1),
        ("dev/null",    stat.S_IFCHR | 0o666, b"", 1, 3),
        ("dev/tty",     stat.S_IFCHR | 0o666, b"", 5, 0),
        ("dev/ttyAMA0", stat.S_IFCHR | 0o600, b"", 204, 64),
    ]
    print("cpio bytes:", build(sys.argv[1], nodes, sys.argv[2]))
