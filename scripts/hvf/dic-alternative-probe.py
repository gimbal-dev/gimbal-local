#!/usr/bin/env python3
"""Is `ic ivau` still patched out of this guest kernel's text?

Run inside a guest, as root. Reads the kernel's own instruction-cache
maintenance routines out of `/proc/kcore` and reports, for each one, whether
Linux's boot-time alternatives patching removed the `ic ivau` loop.

Why this exists, when a behavioural probe already does:
`icache-coherency-probe.py` measures the *consequence* and can only ever say
"not observed". It writes at offset 0, does not pin the CPU, and cannot show
that a fresh mapping reused a physically stale page -- so a zero reading from it
is inconclusive, never a cure. `docs/cpu-feature-deltas.md` records that exact
trap: every probe in Finding 2 wrote at offset 0, "which is the single offset in
a 4 KiB page that a 4096-byte stride does cover", and that hid #290 for three
milestones.

This probe reads the *cause* instead. The elision is a decision latched into
kernel text at boot, so the bytes either carry it or they do not, and no host-
side register fix-up (`hypervisor::hvf::ctr_trap_fixup`, the #290 cure) can
alter them. One reading settles it.

Background: a capture taken on a host reporting `CTR_EL0.DIC = 1` has
`ic ivau` alternative-patched out of `caches_clean_inval_pou()`. Apple silicon
reports `DIC = 0`, so the elision is unsound after rehydration and the kernel
performs no instruction-cache maintenance on a machine that requires it.
See issue #287 and `docs/cpu-feature-deltas.md` Finding 2.

Both alternatives are reported, because a capture from a host that also
reported `IDC = 1` has *both* patched. That is not symmetrical: Apple reports
`IDC = 1` too, so eliding `dc cvau` stays correct here and must not be reverted.
Only the DIC pair is the defect.

aarch64 only. Needs root (for `/proc/kcore` and unrestricted `/proc/kallsyms`);
needs no compiler and no network.
"""
import re
import struct
import sys

# Encodings, derived by assembling each mnemonic rather than recalled:
#   printf 'nop\ndsb ishst\n...' | clang -x assembler -c -target arm64-... -
# and cross-checked against the constants already in icache-coherency-probe.py.
NOP = 0xD503201F
DSB_ISHST = 0xD5033A9F
DSB_ISH = 0xD5033B9F
ISB = 0xD5033FDF
RET = 0xD65F03C0
BTI_C = 0xD503245F  # leads every routine here; measured in kcore, checked by assembly

# `ic ivau, Xt` / `dc cvau, Xt` -- Rt is the low 5 bits, so compare the rest.
RT_MASK = 0xFFFFFFE0
IC_IVAU = 0xD50B7520
DC_CVAU = 0xD50B7B20

# Unconditional `b` is 000101 + imm26, sign-extended and scaled by 4.
B_OPC_MASK = 0xFC000000
B_OPC = 0x14000000

# The routines Linux guards with the IDC and DIC alternatives. `icache_inval_all_pou`
# is included because it carries its own DIC alternative: a repair that fixed only
# the range routines would leave it a no-op and could not claim the kernel corrected.
ROUTINES = (
    "caches_clean_inval_pou",
    "caches_clean_inval_user_pou",
    "icache_inval_pou",
    "icache_inval_all_pou",
    "__flush_icache_range",
)

MAX_WORDS = 128  # every one of these routines is far shorter; a bound, not a guess


def decode_b(word, addr):
    """Target of an unconditional `b`, or None if this is not one."""
    if (word & B_OPC_MASK) != B_OPC:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:  # sign-extend the 26-bit immediate
        imm -= 0x04000000
    return addr + imm * 4


def kallsyms():
    """(symbol -> address for the routines we care about, every symbol address).

    The second half is what bounds a routine. Stopping at the first `ret` --
    the obvious choice -- is wrong in exactly the case that matters most: when
    `alternative_if` replaces the *prologue* with `<guard>; ret`, the whole
    body including the maintenance op sits below that return, unreachable and
    invisible. That routine is the most completely elided of all, so a bound
    that hides it understates the defect in the dangerous direction.
    """
    want = set(ROUTINES)
    found = {}
    every = []
    with open("/proc/kallsyms") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr = int(parts[0], 16)
            if not addr:
                continue
            every.append(addr)
            if parts[2] in want:
                found.setdefault(parts[2], addr)
    return found, sorted(set(every))


class Kcore:
    """Just enough ELF64 to turn a kernel virtual address into file bytes."""

    def __init__(self, path="/proc/kcore"):
        self.fh = open(path, "rb")
        hdr = self.fh.read(64)
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
            raise SystemExit("kcore: not an ELF64 image")
        phoff, = struct.unpack_from("<Q", hdr, 32)
        phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
        self.segs = []
        self.fh.seek(phoff)
        for _ in range(phnum):
            ent = self.fh.read(phentsize)
            p_type, = struct.unpack_from("<I", ent, 0)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr = struct.unpack_from("<QQ", ent, 8)
            p_filesz, = struct.unpack_from("<Q", ent, 32)
            self.segs.append((p_vaddr, p_filesz, p_offset))

    def read(self, vaddr, nbytes):
        for base, size, off in self.segs:
            if base <= vaddr and vaddr + nbytes <= base + size:
                self.fh.seek(off + (vaddr - base))
                return self.fh.read(nbytes)
        return None


def routine_extent(addr, every_addr):
    """How many words the routine at `addr` occupies, bounded by the next symbol."""
    for a in every_addr:
        if a > addr:
            return min((a - addr) // 4, MAX_WORDS)
    return MAX_WORDS


def disassemble(kc, addr, nwords=MAX_WORDS):
    """The words of one routine.

    `nwords` comes from the next symbol's address, so code below an early
    `ret` is still read. Falling back to the first `ret` would make the
    fully-elided prologue shape unclassifiable.
    """
    nwords = max(1, min(nwords, MAX_WORDS))
    raw = kc.read(addr, nwords * 4)
    if raw is None or len(raw) < nwords * 4:
        return None
    return list(struct.unpack("<%dI" % nwords, raw))


def classify(words, addr, guard_word, op_word):
    """Is this alternative patched, absent, or something we do not recognise?

    Recognise-or-decline, deliberately. A patched site is not merely a matching
    two-word pair: the `b` must actually branch *over* an occurrence of the
    maintenance op it is supposed to skip. A pair that matches by coincidence
    somewhere else in the routine cannot satisfy that, and a kernel we do not
    understand is reported as UNKNOWN rather than guessed at.
    """
    ops = [i for i, w in enumerate(words) if (w & RT_MASK) == op_word]

    for i in range(len(words) - 1):
        if words[i] != guard_word:
            continue
        target = decode_b(words[i + 1], addr + (i + 1) * 4)
        if target is None:
            continue
        t_idx = (target - addr) // 4
        if not 0 <= t_idx <= len(words):
            continue
        # The branch must skip at least one occurrence of the op it guards.
        if any(i + 1 < o < t_idx for o in ops):
            return "PATCHED", i, t_idx

    # Second patched shape: `alternative_if` replaced the prologue with
    # `<guard>; ret`, so the op below is unreachable rather than branched over.
    # This is the *most* completely elided form -- the entire routine body is
    # dead -- and it is the one a first-`ret` bound cannot see at all.
    for i in range(len(words) - 1):
        if words[i] != guard_word or words[i + 1] != RET:
            continue
        if any(o > i + 1 for o in ops):
            return "PATCHED", i, None

    # Not patched in a form we can prove. The unpatched alternative is a
    # (nop, nop) pair -- but a bare pair is not enough, because these routines
    # are full of padding nops and one of those would report a defective kernel
    # as sound. That is the dangerous direction to be wrong in, so require the
    # *nearest* pair before the op, with nothing unexplained in between: no
    # branch, and no second copy of the guard word. Anything else declines.
    for o in ops:
        for i in range(o - 2, -1, -1):
            if words[i] != NOP or words[i + 1] != NOP:
                continue
            between = words[i + 2 : o]
            if any(w == guard_word for w in between):
                # `break` rather than `continue` is an optimisation, not a rule:
                # `between` only grows as `i` falls, so a guard word here is in
                # every earlier window too. What matters is not returning
                # PRESENT -- reporting a shape we cannot explain as sound is
                # the one direction that hides a defect.
                break
            if any(decode_b(w, 0) is not None for w in between):
                break
            return "PRESENT", i, o
    if not ops:
        return "NO-OP-IN-ROUTINE", None, None
    return "UNKNOWN", None, None


def _synth(idc_patched, dic_patched, dic_branch_skips_nothing=False):
    """A routine of the shape Linux emits, in whichever form is asked for.

    Layout, matching `caches_clean_inval_pou` in arch/arm64/mm/cache.S:
        0..1    the IDC alternative -- `dsb ishst; b` patched, `nop; nop` not
        2..7    the `dc cvau` loop
        8..9    the DIC alternative -- `isb; b` patched, `nop; nop` not
        10..15  the `ic ivau` loop
        16      ret
    """
    def b(frm, to):
        return B_OPC | ((to - frm) & 0x03FFFFFF)

    w = [NOP] * 17
    w[0], w[1] = (DSB_ISHST, b(1, 8)) if idc_patched else (NOP, NOP)
    w[2:8] = [DC_CVAU | 3, DSB_ISH, NOP, NOP, NOP, NOP]
    if dic_patched:
        w[8], w[9] = ISB, b(9, 10 if dic_branch_skips_nothing else 16)
    else:
        w[8], w[9] = NOP, NOP
    w[10:16] = [IC_IVAU | 3, DSB_ISH, ISB, NOP, NOP, NOP]
    w[16] = RET
    return w


def _synth_stray(filler):
    """An unpatched routine with one unexplained word between site and op.

    The alternative pair sits at 6..7 and the guarded op at 10, with `filler`
    at 8. Nothing in Linux emits this; that is the point. If a kernel does not
    have the shape we think it has, the honest answer is to decline rather than
    to report it sound -- so each of the two "nothing unexplained in between"
    checks needs a case that only it can catch.
    """
    w = [NOP] * 17
    w[2:6] = [DC_CVAU | 3, DSB_ISH, NOP, NOP]
    w[8] = filler
    w[10:16] = [IC_IVAU | 3, DSB_ISH, ISB, NOP, NOP, NOP]
    w[16] = RET
    return w


def _synth_far_branch():
    """Unpatched, with an `isb` followed by a branch that leaves the routine.

    The pair at 8..9 looks exactly like a patched DIC alternative until you ask
    where the branch goes: past the end of the routine, as a tail call or a jump
    to a shared epilogue does. Nothing about `isb; b` alone distinguishes the
    two, so the in-range check is the whole of the distinction.

    Wrong in the expensive direction: a repair pass acting on a false PATCHED
    writes two `nop`s over a guard that was never an alternative, corrupting
    kernel text in a routine it had no business touching.
    """

    def b(frm, to):
        return B_OPC | ((to - frm) & 0x03FFFFFF)

    w = [NOP] * 17
    w[2:8] = [DC_CVAU | 3, DSB_ISH, NOP, NOP, NOP, NOP]
    w[8], w[9] = ISB, b(9, 40)  # 40 is well past word 16, the `ret`
    w[10:16] = [IC_IVAU | 3, DSB_ISH, ISB, NOP, NOP, NOP]
    w[16] = RET
    return w


def _synth_isb_in_dc_block():
    """Unpatched, with a legitimate `isb` closing the `dc cvau` block.

    Realistic, not contrived: these routines really do end a block with
    `dsb ish; isb`, and `icache_inval_pou` is `isb; ret`. So an `isb` sitting
    between an *earlier* nop pair and the `ic ivau` block is normal kernel
    text, and the site we want is the pair nearest the op -- not the first one
    in the routine. Searching forwards instead would meet that `isb`, decline,
    and report a sound kernel as unrecognised.
    """
    w = [NOP] * 17
    w[2:8] = [DC_CVAU | 3, DSB_ISH, NOP, ISB, NOP, NOP]
    w[10:16] = [IC_IVAU | 3, DSB_ISH, ISB, NOP, NOP, NOP]
    w[16] = RET
    return w


def _synth_early_return(dic_patched):
    """`icache_inval_pou`'s shape -- the whole body elided by an early `ret`.

    Transcribed from this kernel's own bytes, read out of /proc/kcore:

        +0x000  bti c
        +0x004  isb          <- the DIC alternative; `nop, nop` when unpatched
        +0x008  ret          <- everything below here is dead code
        ...
        +0x028  ic ivau      <- still in text, and never reached
        +0x040  ret

    A bound that stops at the first `ret` sees three words and no `ic ivau`,
    so it reports NO-OP-IN-ROUTINE -- a decline, on the routine whose op is
    *most* thoroughly removed. That is why the extent comes from the next
    symbol instead.
    """
    w = [NOP] * 17
    w[0] = BTI_C
    w[1], w[2] = (ISB, RET) if dic_patched else (NOP, NOP)
    w[10:16] = [IC_IVAU | 3, DSB_ISH, ISB, NOP, NOP, NOP]
    w[16] = RET
    return w


def selftest():
    """Positive and negative controls for the classifier.

    An instrument that has never been shown to distinguish the two states
    cannot be trusted when it reports the benign one. `DEFECT ABSENT` from a
    real guest is only worth reading once this has passed.
    """
    addr = 0xFFFF800008001000
    stray_branch = _synth_stray(B_OPC | 2)
    cases = (
        ("both patched (a DIC=1/IDC=1 capture)", _synth(True, True), "PATCHED", "PATCHED"),
        ("neither patched (a DIC=0 boot)", _synth(False, False), "PRESENT", "PRESENT"),
        ("repaired: DIC reverted, IDC left alone", _synth(True, False), "PRESENT", "PATCHED"),
        ("IDC alone patched", _synth(True, False), "PRESENT", "PATCHED"),
        (
            "negative control: isb+b that skips nothing",
            _synth(False, True, dic_branch_skips_nothing=True),
            "UNKNOWN",
            "PRESENT",
        ),
        ("negative control: stray branch before the op", stray_branch, "UNKNOWN", "PRESENT"),
        ("negative control: stray isb before the op", _synth_stray(ISB), "UNKNOWN", "PRESENT"),
        (
            "unpatched, with a legitimate isb closing the dc block",
            _synth_isb_in_dc_block(),
            "PRESENT",
            "PRESENT",
        ),
        (
            "body elided by an early ret (icache_inval_pou)",
            _synth_early_return(True),
            "PATCHED",
            "NO-OP-IN-ROUTINE",
        ),
        (
            "same routine, unpatched: the early ret is not there",
            _synth_early_return(False),
            "PRESENT",
            "NO-OP-IN-ROUTINE",
        ),
        (
            "negative control: isb+b that leaves the routine",
            _synth_far_branch(),
            "UNKNOWN",
            "PRESENT",
        ),
    )
    bad = 0
    for name, words, want_dic, want_idc in cases:
        got_dic = classify(words, addr, ISB, IC_IVAU)[0]
        got_idc = classify(words, addr, DSB_ISHST, DC_CVAU)[0]
        ok = got_dic == want_dic and got_idc == want_idc
        bad += not ok
        print(
            "%-42s DIC %-9s (want %-9s) IDC %-9s (want %-9s) %s"
            % (name, got_dic, want_dic, got_idc, want_idc, "ok" if ok else "FAIL")
        )
    print()
    if bad:
        raise SystemExit("selftest FAILED in %d of %d cases" % (bad, len(cases)))
    print("selftest passed: the classifier separates a patched kernel from a sound")
    print("one, and declines a shape it does not recognise.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        return selftest()
    if not sys.platform.startswith("linux"):
        raise SystemExit("run this inside the guest (or `selftest` on any host)")
    syms, every = kallsyms()
    if not syms:
        raise SystemExit(
            "no symbols: need root, and /proc/sys/kernel/kptr_restrict = 0"
        )
    kc = Kcore()

    verdict = {}
    for name in ROUTINES:
        addr = syms.get(name)
        if addr is None:
            print("%-28s  (not in this kernel)" % name)
            continue
        words = disassemble(kc, addr, routine_extent(addr, every))
        if words is None:
            print("%-28s  (not readable through kcore)" % name)
            continue
        dic, dic_i, dic_t = classify(words, addr, ISB, IC_IVAU)
        idc, idc_i, idc_t = classify(words, addr, DSB_ISHST, DC_CVAU)
        verdict[name] = dic
        print(
            "%-28s @ %#x  %2d words   DIC/ic-ivau: %-16s IDC/dc-cvau: %s"
            % (name, addr, len(words), dic, idc)
        )
        if dic == "PATCHED":
            if dic_t is None:
                print(
                    "%-28s   ic ivau unreachable: isb at +%#x returns above it"
                    % ("", dic_i * 4)
                )
            else:
                print(
                    "%-28s   ic ivau elided: isb at +%#x branches to +%#x"
                    % ("", dic_i * 4, dic_t * 4)
                )

    print()
    patched = [n for n, v in verdict.items() if v == "PATCHED"]
    present = [n for n, v in verdict.items() if v == "PRESENT"]
    unknown = [n for n, v in verdict.items() if v not in ("PATCHED", "PRESENT")]

    if patched:
        print(
            "DEFECT PRESENT: %d of %d routines have `ic ivau` patched out."
            % (len(patched), len(verdict))
        )
        print("  " + ", ".join(patched))
        print("This is #287, read out of kernel text rather than inferred from a")
        print("failure rate. No host-side register fix-up can change these bytes.")
    elif present and not unknown:
        print(
            "DEFECT ABSENT: all %d routines retain `ic ivau`." % len(present)
        )
    if unknown:
        print("UNRECOGNISED in: " + ", ".join(unknown))
        print("Decline: do not attempt a repair against a kernel not understood.")
    if not verdict:
        raise SystemExit("no routine was readable; nothing was measured")


if __name__ == "__main__":
    main()
