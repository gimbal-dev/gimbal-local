#!/usr/bin/env python3
"""Every `ic ivau` site in a live guest's kernel text, found by opcode.

`dic-alternative-probe.py` answers "is the DIC alternative patched?" for a list
of routines named in its source. That is the right shape for the question it
asks, and the wrong shape for this one: a name list can only report on routines
somebody thought of. If a kernel guards `ic ivau` behind ARM64_HAS_CACHE_DIC
somewhere the list does not name, a name-driven probe reports a clean bill of
health for a routine it never looked at -- understating the defect, which is the
dangerous direction.

So this walks *all* built-in kernel text looking for the instruction itself, and
attributes each hit to its kallsyms symbol. The answer is then complete for the
kernel in front of it rather than complete for a list, and a future capture that
patches a fourth routine shows up without anyone editing this file.

The classification of each routine it finds is *not* reimplemented here --
`classify()` is imported from the probe. Two implementations of one rule
eventually disagree, and the disagreement is invisible until it strands
something.

Run inside the guest:   sudo ./ic-ivau-inventory.py
Positive control:       ./ic-ivau-inventory.py selftest   (needs no guest)

Exit status: 0 clean, 1 every site classified and at least one PATCHED,
2 at least one site could not be classified (see REVIEW REQUIRED).
"""

import importlib.util
import os
import struct
import sys

PROBE = "dic-alternative-probe.py"

# `ic ivau, xN` is 0xD50B7520 | N. Little-endian in memory that is
# [0x20|N, 0x75, 0x0B, 0xD5], so the top three bytes are fixed regardless of Rt
# and can be found with bytes.find -- which runs in C. A pure-Python
# struct.unpack per word over 41 MiB of text does not finish in a console
# session's patience, which is how this started life as a timeout.
NEEDLE = b"\x75\x0b\xd5"
NEEDLE_BYTE_OFFSET = 1  # where NEEDLE sits inside the 4-byte word

CHUNK = 1 << 22
PAGE = 1 << 12

# nVHE hypervisor text is linked into the kernel image and carries its own copy
# of the cache routines, patched by the same alternatives pass. Under HVF the
# guest never runs at EL2, so this text is unreachable -- but it is still
# reported, because silently dropping a patched routine is exactly the
# understatement this tool exists to prevent.
NVHE_PREFIX = "__kvm_nvhe_"


def load_probe():
    """Import the sibling probe, whose filename is not a Python identifier."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), PROBE)
    spec = importlib.util.spec_from_file_location("dic_probe", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load %s -- it must sit beside this script" % PROBE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def text_symbols(path="/proc/kallsyms"):
    """Sorted [(addr, name)] for built-in text only.

    A fourth column is "[module]". Module text lives in the vmalloc region,
    which on arm64 is a long way from the kernel image -- so including it makes
    min(addr)..max(addr) span gigabytes of mostly unmapped address space and the
    scan reads holes until it is killed. `_etext` is not present in kallsyms as
    a t/T symbol on this kernel, so it cannot be used as the bound instead.
    """
    syms = []
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) != 3 or parts[1] not in "tT":
                continue
            addr = int(parts[0], 16)
            if addr:
                syms.append((addr, parts[2]))
    if not syms:
        raise SystemExit(
            "kallsyms exposed no text symbols -- run as root (kptr_restrict)"
        )
    syms.sort()
    return syms


def scan(buf, base, rt_mask, op_word):
    """Byte offsets of every `ic ivau` in `buf`, as absolute addresses.

    The alignment check is load-bearing and not defensive tidiness: NEEDLE is
    three bytes of a four-byte instruction, so it matches just as happily
    straddling two unrelated words -- an operand here, an opcode byte there --
    and every such coincidence would be reported as a maintenance site in a
    routine that has none.
    """
    out = []
    j = buf.find(NEEDLE)
    while j != -1:
        if j % 4 == NEEDLE_BYTE_OFFSET:
            start = j - NEEDLE_BYTE_OFFSET
            word, = struct.unpack_from("<I", buf, start)
            if (word & rt_mask) == op_word:
                out.append(base + start)
        j = buf.find(NEEDLE, j + 1)
    return out


def owner(addr, syms):
    """(name, offset) of the symbol containing `addr`."""
    lo, hi = 0, len(syms)
    while lo < hi:  # rightmost symbol whose address is <= addr
        mid = (lo + hi) // 2
        if syms[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None, None
    base, name = syms[lo - 1]
    return name, addr - base


def find_sites(probe, kc, syms):
    """(stext, etext, {routine: (base, [offsets])}, bytes_skipped).

    A chunk that will not read is *not* silently stepped over. kcore serves
    whole PT_LOAD segments, so a read spanning the end of one fails outright and
    would take up to CHUNK bytes of real text with it -- an inventory quietly
    missing 4 MiB still prints a total and reads as complete. So a failed read
    is retried at finer granularity, and whatever genuinely cannot be read is
    counted and reported.
    """
    stext = syms[0][0]
    etext = syms[-1][0] + 0x1000
    sites = {}
    skipped = 0
    addr = stext
    while addr < etext:
        n = min(CHUNK, etext - addr)
        buf = kc.read(addr, n)
        while buf is None and n > PAGE:
            n //= 2
            buf = kc.read(addr, n)
        if buf is None:
            skipped += n
            addr += n
            continue
        for hit in scan(buf, addr, probe.RT_MASK, probe.IC_IVAU):
            name, off = owner(hit, syms)
            if name is None:
                continue
            base = hit - off
            sites.setdefault(name, (base, []))[1].append(off)
        addr += n
    return stext, etext, sites, skipped


def report(probe, kc, syms, sites, skipped=0, out=sys.stdout):
    """Classify every routine holding an `ic ivau`. Returns an exit status."""
    patched = []
    unknown = []
    other = []

    for name in sorted(sites):
        base, offs = sites[name]
        nwords = probe.routine_extent(base, [a for a, _ in syms])
        words = probe.disassemble(kc, base, nwords)
        if words is None:
            verdict = "UNREADABLE"
        else:
            verdict, _, _ = probe.classify(words, base, probe.ISB, probe.IC_IVAU)

        nvhe = name.startswith(NVHE_PREFIX)
        note = ""
        if verdict == "PATCHED" and nvhe:
            note = "  (nVHE hyp text -- not reached under HVF)"
        elif verdict == "UNKNOWN":
            # An `ic ivau` with no DIC alternative around it is the ordinary
            # shape of the EL0 trap emulation path. It is also the shape of a
            # guard this tool does not understand. Those must not be conflated,
            # so it is reported loudly either way and the caller decides.
            note = "  <-- REVIEW REQUIRED: no DIC alternative recognised here"

        print(
            "  %-36s %#018x  %-16s %s%s"
            % (name, base, verdict, ["+%#x" % o for o in offs], note),
            file=out,
        )

        if verdict == "PATCHED" and not nvhe:
            patched.append(name)
        elif verdict == "UNKNOWN":
            unknown.append(name)
        else:
            other.append(name)

    total = sum(len(v[1]) for v in sites.values())
    print(
        "\n%d site(s) in %d routine(s); %d reachable routine(s) PATCHED, "
        "%d unclassified" % (total, len(sites), len(patched), len(unknown)),
        file=out,
    )

    if unknown:
        print(
            "REVIEW REQUIRED: %s -- this kernel is NOT fully inventoried"
            % ", ".join(unknown),
            file=out,
        )
        return 2
    if skipped:
        # Every site found is still a true finding; what is lost is the claim
        # that they are all of them. Reporting a defect here is right and
        # reporting "clean" would not be, so completeness failure outranks both.
        print(
            "REVIEW REQUIRED: %d KiB of text could not be read -- "
            "this inventory is NOT complete" % (skipped // 1024),
            file=out,
        )
        return 2
    if patched:
        print("DEFECT PRESENT: %s" % ", ".join(patched), file=out)
        return 1
    print("no reachable routine has 'ic ivau' patched out", file=out)
    return 0


class _FakeKcore:
    """Serves one flat buffer, so the scanner can be tested with no guest."""

    def __init__(self, base, buf):
        self.base = base
        self.buf = buf

    def read(self, vaddr, nbytes):
        lo = vaddr - self.base
        if lo < 0 or lo + nbytes > len(self.buf):
            return None
        return self.buf[lo : lo + nbytes]


def _mapped(probe, words):
    """`words` padded out past the scan's end bound, as kcore would map them.

    find_sites walks to the last symbol plus a page, so a fake serving only the
    bytes the symbols cover fails reads for a reason kcore does not have -- and
    the failure would be indistinguishable from the scanner losing text.
    """
    buf = struct.pack("<%dI" % len(words), *words)
    return buf + struct.pack("<I", probe.NOP) * ((2 * PAGE - len(buf)) // 4)


def selftest():
    """Positive control: the scanner must find planted sites and only those."""
    probe = load_probe()
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r, wanted %r" % (name, got, want))

    base = 0xFFFF000000000000

    # 1. an aligned `ic ivau, x0` is found
    buf = struct.pack("<4I", probe.NOP, probe.IC_IVAU, probe.NOP, probe.RET)
    check("aligned x0", scan(buf, base, probe.RT_MASK, probe.IC_IVAU), [base + 4])

    # 2. so is one with a non-zero Rt -- this kernel uses x3, x21 and x22, so a
    #    scanner comparing the whole word finds nothing at all in the routines
    #    that matter while looking like it worked.
    buf = struct.pack("<2I", probe.NOP, probe.IC_IVAU | 21)
    check("aligned x21", scan(buf, base, probe.RT_MASK, probe.IC_IVAU), [base + 4])

    # 3. a `dc cvau` is not an `ic ivau`
    buf = struct.pack("<2I", probe.NOP, probe.DC_CVAU)
    check("dc cvau ignored", scan(buf, base, probe.RT_MASK, probe.IC_IVAU), [])

    # 4. the alignment rule: NEEDLE planted straddling two words is a
    #    coincidence, not a site. Without the check this reports a maintenance
    #    op inside a routine that has none.
    #    The straddle must be one that would ALSO satisfy the Rt mask, or the
    #    mask quietly stands in for the alignment rule and the control proves
    #    nothing about it. Here bytes 1..4 spell `ic ivau, x0` exactly, but
    #    start one byte into a word, so only alignment can reject them.
    buf = b"\x00\x20\x75\x0b" + b"\xd5\x00\x00\x00"
    straddle = struct.unpack("<I", buf[1:5])[0]
    check("the control would pass the mask", straddle & probe.RT_MASK, probe.IC_IVAU)
    check("misaligned coincidence", scan(buf, base, probe.RT_MASK, probe.IC_IVAU), [])

    # 5. attribution picks the containing symbol, not the nearest
    syms = [(base, "first"), (base + 0x40, "second"), (base + 0x80, "third")]
    check("owner inside", owner(base + 0x44, syms), ("second", 4))
    check("owner at start", owner(base + 0x40, syms), ("second", 0))
    check("owner below all", owner(base - 4, syms), (None, None))

    # 6. end to end: the early-return shape must survive the scan *and* the
    #    reused classifier, because that is the form a first-`ret` bound hides.
    words = [probe.BTI_C, probe.ISB, probe.RET] + [probe.NOP] * 5
    words += [probe.IC_IVAU | 3, probe.DSB_ISH, probe.RET]
    syms = [(base, "victim"), (base + len(words) * 4, "next")]
    buf = _mapped(probe, words)
    _, _, sites, skipped = find_sites(probe, _FakeKcore(base, buf), syms)
    check("end to end finds it", sorted(sites), ["victim"])
    if "victim" in sites:
        got, _, _ = probe.classify(words, base, probe.ISB, probe.IC_IVAU)
        check("end to end classifies it", got, "PATCHED")

    # 7. an unclassifiable site must be reported as REVIEW REQUIRED and must
    #    exit non-zero -- a tool that quietly calls "I do not know" benign
    #    reports a completeness it has not established.
    import io  # noqa: E402 -- kept local; the tool itself needs no io

    #    Fully mapped on purpose: an under-served fake makes `skipped` non-zero,
    #    and that rule returns 2 as well -- so the case would pass with the
    #    unknown rule deleted, which is the failure this check exists to catch.
    words = [probe.BTI_C, probe.IC_IVAU | 21, probe.RET]
    buf = _mapped(probe, words)
    syms = [(base, "unguarded"), (base + 12, "next")]
    kc = _FakeKcore(base, buf)
    _, _, sites, skipped = find_sites(probe, kc, syms)
    sink = io.StringIO()
    check("unknown exits 2", report(probe, kc, syms, sites, skipped, out=sink), 2)
    check("unknown is loud", "REVIEW REQUIRED" in sink.getvalue(), True)

    # 8. text that could not be read must also refuse to claim completeness,
    #    including -- especially -- when nothing suspicious was found in the
    #    part that did read. That is the case where a silent skip reads as a
    #    clean bill of health for bytes nobody looked at.
    class _Deaf(_FakeKcore):
        def read(self, vaddr, nbytes):
            return None

    syms = [(base, "unreadable"), (base + CHUNK * 2, "next")]
    kc = _Deaf(base, b"")
    _, _, sites, skipped = find_sites(probe, kc, syms)
    check("unreadable finds nothing", sites, {})
    check("unreadable is counted", skipped > 0, True)
    sink = io.StringIO()
    check("skipped exits 2", report(probe, kc, syms, sites, skipped, out=sink), 2)
    check("skipped is loud", "NOT complete" in sink.getvalue(), True)

    # 9. a patched nVHE copy is reported but must not be counted as needing
    #    repair: it is EL2 hypervisor text and the guest never runs at EL2 under
    #    HVF. Counting it would send a repair pass writing to text nothing
    #    executes, on the strength of a routine name.
    words = [probe.BTI_C, probe.ISB, probe.RET] + [probe.NOP] * 5
    words += [probe.IC_IVAU | 3, probe.DSB_ISH, probe.RET]
    buf = _mapped(probe, words)
    syms = [(base, NVHE_PREFIX + "icache_inval_pou"), (base + len(words) * 4, "next")]
    kc = _FakeKcore(base, buf)
    _, _, sites, skipped = find_sites(probe, kc, syms)
    sink = io.StringIO()
    check("nvhe alone is not a defect", report(probe, kc, syms, sites, skipped, sink), 0)
    check("nvhe is still reported", "PATCHED" in sink.getvalue(), True)
    check("nvhe is annotated", "not reached under HVF" in sink.getvalue(), True)

    for f in fails:
        print("FAIL %s" % f)
    print("selftest: %d checks failed" % len(fails))
    return 1 if fails else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        return selftest()

    probe = load_probe()
    syms = text_symbols()
    kc = probe.Kcore()
    stext, etext, sites, skipped = find_sites(probe, kc, syms)
    print(
        "built-in text %#x .. %#x (%d KiB, %d symbols)"
        % (stext, etext, (etext - stext) // 1024, len(syms))
    )
    print("== every 'ic ivau' in built-in kernel text ==")
    if not sites:
        print("  none -- which no arm64 kernel should report; check the scan")
        return 2
    return report(probe, kc, syms, sites, skipped)


if __name__ == "__main__":
    sys.exit(main())
