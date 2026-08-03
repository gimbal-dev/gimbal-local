#!/usr/bin/env python3
"""Does this guest's kernel still invalidate the instruction cache?

Run inside a guest. Writes machine code, executes it, and reports how often the
processor fetched the *previous* contents instead — the failure a JIT hits.

Four variants isolate who is responsible:

  A  same page rewritten, no maintenance   - baseline; nonzero on DIC=0 hardware
  B  same page rewritten, explicit ic ivau - proves EL0 maintenance works
  C  mmap(RW), write, mprotect(RX), call   - the JIT path; the kernel's job
  D  as C, plus an explicit ic ivau        - proves C's staleness is the kernel's

C must be 0 on a sound arm64 kernel: it is exactly what __sync_icache_dcache()
exists to make safe. On a guest captured from CTR_EL0.DIC = 1 hardware (AWS
Graviton2) and rehydrated onto DIC = 0 hardware (Apple silicon) it measured
955/1000, because Linux patched `ic ivau` out of caches_clean_inval_pou() at
boot on the capture host. See docs/cpu-feature-deltas.md, Finding 2.

aarch64 only; needs no compiler, no network and no root.
"""
import ctypes, ctypes.util, mmap, struct
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
R, W, X = 1, 2, 4
MAP_PRIVATE, MAP_ANON = 0x02, 0x20
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

# flusher, written once into its own page: dsb ish; ic ivau,x0; dsb ish; isb; ret
fl = mmap.mmap(-1, 4096, prot=R | W | X)
fl.write(struct.pack('<5I', 0xD5033B9F, 0xD50B7520, 0xD5033B9F, 0xD5033FDF, 0xD65F03C0))
flush = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(
    ctypes.addressof(ctypes.c_char.from_buffer(fl)))

def body(imm):
    return struct.pack('<2I', 0xD2800000 | (imm << 5), 0xD65F03C0)

def run_same(n, do_flush):
    pg = mmap.mmap(-1, 4096, prot=R | W | X)
    a = ctypes.addressof(ctypes.c_char.from_buffer(pg))
    fn = ctypes.CFUNCTYPE(ctypes.c_uint64)(a)
    bad = 0
    for k in range(1, n + 1):
        imm = k & 0xffff
        pg.seek(0); pg.write(body(imm))
        if do_flush:
            flush(a)
        if fn() != imm:
            bad += 1
    return bad

def run_fresh(n, do_flush):
    bad = 0
    for k in range(1, n + 1):
        imm = k & 0xffff
        a = libc.mmap(None, 4096, R | W, MAP_PRIVATE | MAP_ANON, -1, 0)
        ctypes.memmove(a, body(imm), 8)
        libc.mprotect(ctypes.c_void_p(a), 4096, R | X)
        if do_flush:
            flush(ctypes.c_void_p(a))
        if ctypes.CFUNCTYPE(ctypes.c_uint64)(a)() != imm:
            bad += 1
        libc.munmap(ctypes.c_void_p(a), 4096)
    return bad

print("A same-page  no-flush : %4d/2000 stale" % run_same(2000, False))
print("B same-page  ic-ivau  : %4d/2000 stale" % run_same(2000, True))
print("C fresh-page no-flush : %4d/1000 stale  (kernel __sync_icache_dcache path)" % run_fresh(1000, False))
print("D fresh-page ic-ivau  : %4d/1000 stale" % run_fresh(1000, True))
