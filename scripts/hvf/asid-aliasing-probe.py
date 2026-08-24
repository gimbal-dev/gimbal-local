#!/usr/bin/env python3
"""Do this guest's address spaces stay separate from each other?

Run inside a guest. Forks N children, each of which owns a private page it
alone should be able to see, and has every child hammer that page while the
others do the same. Reports two independent failures:

  mismatch  a child read back a value it did not write -- another address
            space reached its page. This is the *data aliasing* an ASID
            collision would produce.
  killed    a child died by signal, broken down by signal number. A child
            that never mismatches can still be killed if a translation goes
            stale under it rather than merely pointing somewhere else.

Why it exists: `ID_AA64MMFR0_EL1.ASIDBits` reads 2 (16-bit) on AWS Graviton2
and 0 (8-bit) on Apple silicon. Hypervisor.framework restores the captured
value faithfully, and Linux latches it in `asids_init()`, an early_initcall --
so a rehydrated Graviton guest sizes its ASID bitmap for 32768 entries while
the TLB it is running on compares only the low 8 bits. Past ~256 concurrently
live address spaces, processes sharing low bits could in principle read and
write each other's pages. `get_cpu_asid_bits()` uses `read_cpuid()`, a raw
MRS, so `idreg-override` cannot correct it from the guest command line.
See docs/cpu-feature-deltas.md and issue #279.

Two design points, each of which a naive probe gets wrong and thereby reports
a false negative:

  * `mmap.mmap(-1, len)` defaults to MAP_SHARED in CPython. A shared page is
    *supposed* to be visible to every child, so a probe that forgets
    MAP_PRIVATE measures nothing and reports a confident positive.
  * A single write-then-read with a long dwell lets the TLB entry evict
    between the two, so the read is served by a fresh, correct walk. The
    tight inner loop is what keeps the translation hot enough to matter.

And one blind spot this closes: a write and a read through the *same*
mapping cannot see a translation that is stale but self-consistent -- both
land on the wrong page and agree with each other. The second channel reads
the same address through /proc/self/mem, which walks the page tables afresh
in the kernel, so the two channels disagree when a single mapping does not.

    CAVEAT, stated because an unfired guard reports safety it does not
    provide: the `skew` channel has been shown to watch the right address
    (400/400 children reported through it in an in-guest control) but has
    never been shown to *fire a positive*, because there is no known way to
    manufacture a stale-but-self-consistent translation on demand. Treat a
    zero `skew` as defence in depth, not as a measurement of the same weight
    as a zero `mismatch`. Where the channel cannot be opened at all -- macOS
    has no /proc/self/mem -- it prints `skew=unavailable`, never `skew=0`,
    so a channel that never opened cannot be misread as one that found
    nothing.

`selftest` is a positive control: it maps the page MAP_SHARED, which
guarantees cross-process visibility, and must report a nonzero mismatch
count. A run that reports zero mismatches is only evidence if the same probe
in the same guest can be made to report a nonzero one -- otherwise it is
indistinguishable from a detector that is not working.

What it has measured so far (2026-08-24), all on one Apple silicon host:

  * Rehydrated Graviton capture, N from 120 to 400: `mismatch=0` across
    roughly 535 million samples, while children died sporadically -- every
    death SIGSEGV, none SIGABRT, and the counts NOT monotone in N. An
    earlier reading of a single sweep suggested a threshold at N=256; a
    second sweep put its largest counts *at* 256 and zeros above it, so
    that threshold is retracted. One run killed the parent harness, so the
    corruption is not confined to forked children.
  * Cold-booted controls at 256 ASID entries -- musl/Alpine 6.6,
    glibc/Alpine 6.6, and glibc/Ubuntu 6.8 -- `killed=0` at every point,
    with `selftest` proven live in each guest first. Those three arms
    remove libc and kernel version as explanations.
  * Positive controls: 11,932,361 selftest mismatches (long form), 40/40
    children (compact form delivered over a console), 4.8-5.0M on the host.

aarch64 oriented; needs no compiler, no network and no root.

Usage:
  asid-aliasing-probe.py N DWELL_SECONDS [selftest]

  N       concurrent child processes, i.e. concurrently live address spaces.
          Sweep it across 256 to probe the 8-bit boundary.
  DWELL   how long each child spins. 2.0 is enough to see deaths; longer
          samples more.
"""
import mmap
import os
import struct
import sys
import time

TAG = 16  # bytes written and read back; must divide the page evenly


def child(page, marker, dwell, second_channel):
    """Spin writing MARKER into PAGE and reading it back.

    Returns (bad, skew, channel_ok). channel_ok is False when the second
    channel could not be opened -- a skew of zero from a channel that never
    opened is not a measurement, and reporting the two identically would be
    the probe claiming coverage it does not have.
    """
    bad = 0
    skew = 0
    fd = -1
    if second_channel:
        try:
            fd = os.open('/proc/self/mem', os.O_RDONLY)
            addr = addr_of(page)
        except OSError:
            fd = -1
    end = time.time() + dwell
    while time.time() < end:
        for _ in range(2000):
            page[0:TAG] = marker
            if bytes(page[0:TAG]) != marker:
                bad += 1
        if fd >= 0:
            try:
                page[0:TAG] = marker
                if os.pread(fd, TAG, addr) != marker:
                    skew += 1
            except OSError:
                pass
    if fd >= 0:
        os.close(fd)
    return bad, skew, fd >= 0 or not second_channel


def addr_of(page):
    """Virtual address of a Python mmap's first byte."""
    import ctypes
    return ctypes.addressof(ctypes.c_char.from_buffer(page))


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__.rsplit('Usage:', 1)[-1])
        return 2
    n = int(argv[1])
    dwell = float(argv[2])
    shared = len(argv) > 3 and argv[3] == 'selftest'

    # MAP_PRIVATE is the whole experiment; see the module docstring.
    flags = mmap.MAP_SHARED if shared else mmap.MAP_PRIVATE
    page = mmap.mmap(-1, 4096, flags=flags)
    page[0:TAG] = b'.' * TAG

    # A child reports its own counts through a pipe rather than an exit
    # status, so a child that is killed by a signal is still distinguishable
    # from one that merely found nothing.
    kids = []
    for i in range(n):
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            bad, skew, ok = child(page, b'%015d.' % i, dwell, not shared)
            os.write(w, struct.pack('<QQQ', bad, skew, 1 if ok else 0))
            os._exit(0)
        os.close(w)
        kids.append((pid, r))

    mismatch = 0
    channel_skew = 0
    channel_seen = 0
    reported = 0
    sigs = {}
    for pid, r in kids:
        buf = os.read(r, 24)
        os.close(r)
        if len(buf) == 24:
            bad, skew, ok = struct.unpack('<QQQ', buf)
            mismatch += bad
            channel_skew += skew
            channel_seen += ok
            reported += 1
        _, status = os.waitpid(pid, 0)
        sig = status & 127
        if sig:
            sigs[sig] = sigs.get(sig, 0) + 1

    # A child killed by a signal reports nothing, so say how many were heard
    # from: `mismatch=0` over 3 surviving children is a much weaker statement
    # than the same zero over 400, and the two must not print identically.
    if shared:
        skew = 'off'
    elif channel_seen == reported and reported:
        skew = str(channel_skew)
    elif channel_seen:
        skew = '%d/%d-children' % (channel_skew, channel_seen)
    else:
        skew = 'unavailable'
    print('N=%d heard=%d mismatch=%d skew=%s killed=%d sigs=%s'
          % (n, reported, mismatch, skew, sum(sigs.values()), sigs))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
