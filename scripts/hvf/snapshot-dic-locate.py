#!/usr/bin/env python3
"""Locate the DIC alternative elision in a *captured* snapshot, with no guest.

`dic-alternative-probe.py` and `ic-ivau-inventory.py` both read `/proc/kcore`
inside a running guest. That is the right instrument for asking "what is this
kernel doing?" and the wrong one for asking "what will this capture do when I
rehydrate it?", because answering the second by running the first means booting
the very guest whose kernel text you suspect. This reads the bytes out of the
capture's RAM dump instead, so the question is answered before a vCPU exists.

Getting from a RAM dump to kernel text is the whole problem. A snapshot is 2 GiB
of physical memory with no symbol table, and a byte pattern found anywhere in it
proves nothing: the same bytes appear in the page cache's copy of `/boot/vmlinuz`,
in a freed page nobody reclaimed, and in the initrd. So this walks the capture's
*own* page tables from the `TTBR1_EL1` it recorded, and scans only pages the
hardware would actually fetch instructions from at EL1 -- `PXN` clear. A hit is
then active kernel text by construction rather than by hope. On the capture this
was built against that is 25.5 MiB of 2048, an 80x reduction, and it is the
difference between a finding and a coincidence.

The second problem is bounding a routine without kallsyms. It turns out not to
need solving: both shapes the alternatives pass leaves are locally decidable.

  S1, the branch elision:   isb ; b <forward>     with an `ic ivau` skipped
      The `isb` is the DIC alternative (`nop, nop` before patching) and the
      branch hops the invalidate loop. That an `ic ivau` lies strictly between
      the branch and its own target is a self-contained fact about three words.

  S2, the early return:     bti c ; isb ; ret     with an `ic ivau` after
      The routine's entire body has been replaced by an `isb`. A function whose
      first act is to return having done nothing but an `isb` is only ever the
      patched-out form of a cache-maintenance routine; the invalidate loop it
      elides is the dead code following, bounded by the next `bti c`.

Both repairs are two `nop`s over the guard word and the instruction after it.

  IMPORTANT: only the DIC pair is a defect. Linux applies the IDC and DIC
  alternatives in the same pass and they look alike -- the IDC early return is
  `bti c ; dsb ishst ; ret`, one word different from S2. Apple silicon reports
  `IDC = 1`, so reverting the IDC pair would be a regression, not a repair.
  Everything here is scoped to the DIC guard word for that reason, and a scan
  that fired on "an alternative was applied" would get this exactly wrong.

Opcodes, the needle and `decode_b` are imported from the two shipped scripts
rather than restated. Two implementations of one encoding eventually disagree,
and the disagreement is invisible until it strands something.

    ./snapshot-dic-locate.py <capture-dir>     # a dir holding state.json + memory-ranges
    ./snapshot-dic-locate.py selftest          # needs no capture

Exit status: 0 no elision present, 1 elision located, 2 the capture could not be
read well enough to answer (see REVIEW REQUIRED).
"""

import importlib.util
import json
import os
import struct
import sys

PROBE = "dic-alternative-probe.py"
INVENTORY = "ic-ivau-inventory.py"

# --- KVM ONE_REG, read from hypervisor/src/hvf/translate.rs, not recalled -----
# A capture stores its system registers as KVM ONE_REG (id, value) pairs. The
# coprocessor field distinguishes the sysreg block from the core-register block,
# and the two collide in their low 16 bits -- masking without checking the
# coprocessor reports core registers as sysregs and finds nothing.
KVM_REG_ARM64_SYSREG = 0x0013_0000
KVM_REG_ARM_COPROC_MASK = 0x0FFF_0000

# Every routine holding one of these routines' opcodes is far shorter than this.
# A bound, not a guess: it exists so a stray `isb` a page away cannot be paired
# with an unrelated `ic ivau`.
LOOKBACK_WORDS = 64


def sysreg_enc(op0, op1, crn, crm, op2):
    """The packed encoding KVM puts in the low 16 bits of a sysreg id."""
    return (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2


# (op0, op1, CRn, CRm, op2) from the Arm ARM. SCTLR_EL1 is here only as a
# self-check: it has an independently measured value on this capture family
# (docs/cpu-feature-deltas.md), so a decode that reproduces it is verified
# rather than merely plausible.
ANCHORS = {
    "SCTLR_EL1": sysreg_enc(3, 0, 1, 0, 0),
    "TTBR1_EL1": sysreg_enc(3, 0, 2, 0, 1),
    "TCR_EL1": sysreg_enc(3, 0, 2, 0, 2),
    "CTR_EL0": sysreg_enc(3, 3, 0, 0, 1),
}

CTR_DIC_BIT = 29  # CTR_EL0.DIC -- 1 means "instruction cache snoops writes"


class Refuse(Exception):
    """The capture could not be read well enough to answer. Exits 2.

    Deliberately NOT a bare SystemExit, which exits 1 -- the code that also
    means "elision present". A caller that cannot tell "I could not answer"
    from "the answer is yes" will act on a verdict nobody produced, and the
    wrong direction here is the expensive one: silence reported as clean.
    """


def load_sibling(filename, modname):
    """Import a sibling script whose filename is not a Python identifier."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise Refuse("cannot load %s -- it must sit beside this script" % filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- reading the capture -----------------------------------------------------


def capture_paths(root):
    """(state.json, memory-ranges) for a capture directory.

    The two files must come from the same capture, so they are required to sit
    beside each other. A workspace holds its own `state.json` at the top level
    *and* the pristine one under `snapshot/`; pairing the outer state with the
    inner RAM would silently read one capture's page tables against another's
    memory, which is the one mistake here that produces plausible garbage
    rather than an error.
    """
    for sub in ("snapshot", ""):
        d = os.path.join(root, sub) if sub else root
        state, ram = os.path.join(d, "state.json"), os.path.join(d, "memory-ranges")
        if os.path.isfile(state) and os.path.isfile(ram):
            return state, ram
    raise Refuse(
        "%s holds no state.json beside a memory-ranges -- point this at a capture "
        "directory or its snapshot/ subdirectory" % root
    )


def read_anchors(state):
    """{name: value} for the anchor registers, requiring every vCPU to agree.

    Disagreement is not averaged or resolved by picking vCPU 0. `TTBR1_EL1` and
    `TCR_EL1` describe one address space that all cores share, so two cores
    reporting different ones means the capture is not understood, and a walk
    driven by a guess would report on an address space that never existed.
    """
    doc = json.load(open(state))
    try:
        cpus = doc["snapshots"]["cpu-manager"]["snapshots"]
    except (KeyError, TypeError):
        raise Refuse("%s has no cpu-manager snapshot -- not a CH capture" % state)

    per_cpu = {}
    for key in sorted(cpus):
        blob = cpus[key]["snapshot_data"]["state"]
        state_doc = json.loads(blob) if isinstance(blob, str) else blob
        try:
            entries = state_doc["Kvm"]["sys_regs"]
        except (KeyError, TypeError):
            raise Refuse(
                "vcpu %s carries no Kvm.sys_regs -- this capture was not taken on "
                "a KVM host, so it has no page tables to walk" % key
            )
        found = {}
        for entry in entries:
            # Each entry is a 16-byte little-endian (u64 id, u64 value) pair,
            # serialised as a list of ints.
            rid, val = struct.unpack("<QQ", bytes(entry))
            if (rid & KVM_REG_ARM_COPROC_MASK) != KVM_REG_ARM64_SYSREG:
                continue
            found[rid & 0xFFFF] = val
        per_cpu[key] = found

    if not per_cpu:
        raise Refuse("%s records no vCPUs" % state)

    out = {}
    for name, enc in ANCHORS.items():
        seen = {}
        for key, regs in per_cpu.items():
            if enc not in regs:
                raise Refuse(
                    "vcpu %s did not capture %s -- this capture cannot be located "
                    "against" % (key, name)
                )
            seen.setdefault(regs[enc], []).append(key)
        if len(seen) != 1:
            detail = ", ".join(
                "%#x on vcpu %s" % (v, "/".join(k)) for v, k in sorted(seen.items())
            )
            raise Refuse(
                "vCPUs disagree on %s (%s) -- refusing to guess "
                "which address space is real" % (name, detail)
            )
        out[name] = next(iter(seen))
    return out, len(per_cpu)


def ram_regions(state):
    """[(gpa, size, file_offset)] for the RAM dump.

    Driven by `guest_ram_mappings` and deliberately not by `arch_mem_regions`,
    which on real captures carries an entry of size 0xffffffffffffffff.
    """
    doc = json.load(open(state))
    blob = doc["snapshots"]["memory-manager"]["snapshot_data"]["state"]
    mm = json.loads(blob) if isinstance(blob, str) else blob
    regions = [
        (m["gpa"], m["size"], m["file_offset"]) for m in mm["guest_ram_mappings"]
    ]
    if not regions:
        raise Refuse("capture declares no guest RAM mappings")
    return sorted(regions)


class Ram:
    """Physical-address reads against a capture's RAM dump."""

    def __init__(self, path, regions):
        self.fh = open(path, "rb")
        self.regions = regions

    def read(self, pa, nbytes):
        """Bytes at a guest physical address, or None if it is not backed."""
        for gpa, size, off in self.regions:
            if gpa <= pa and pa + nbytes <= gpa + size:
                self.fh.seek(off + (pa - gpa))
                buf = self.fh.read(nbytes)
                return buf if len(buf) == nbytes else None
        return None

    def u64(self, pa):
        buf = self.read(pa, 8)
        return None if buf is None else struct.unpack("<Q", buf)[0]


# --- the page-table walk -----------------------------------------------------

# A descriptor's output address is bits [47:12]. Bits 63:48 are attributes
# (including PXN at 53) and bits 11:0 are the type and lower attributes.
OUT_ADDR_MASK = ((1 << 48) - 1) & ~0xFFF
PXN_BIT = 1 << 53  # privileged execute-never: clear means executable at EL1


def decode_tcr(tcr):
    """(va_bits, granule, start_level) for the TTBR1 half of TCR_EL1.

    TG1's encoding is not TG0's -- 1 is 16K, 2 is 4K, 3 is 64K, where TG0 uses
    0 for 4K. Reading TG1 with TG0's table produces a walker that misses on
    every address, which looks like a corrupt capture rather than a bug here.
    """
    t1sz = (tcr >> 16) & 0x3F
    tg1 = (tcr >> 30) & 0x3
    granule = {1: 16384, 2: 4096, 3: 65536}.get(tg1)
    if granule is None:
        raise Refuse("TCR_EL1.TG1=%d is reserved" % tg1)
    va_bits = 64 - t1sz
    if granule != 4096:
        raise Refuse(
            "this capture uses a %d-byte translation granule; "
            "the walk here implements 4 KiB only" % granule
        )
    levels = (va_bits - 12 + 8) // 9
    return va_bits, granule, 4 - levels


def ttbr_base(ttbr):
    """BADDR from TTBR1_EL1. Bit 0 is CnP and bits 63:48 are the ASID."""
    return (ttbr & 0x0000_FFFF_FFFF_FFFE) & ~0xFFF


def translate(ram, root, va, start_level):
    """Physical address for a kernel VA, or None if it is not mapped."""
    table = root
    for lvl in range(start_level, 4):
        shift = 12 + 9 * (3 - lvl)
        desc = ram.u64(table + ((va >> shift) & 0x1FF) * 8)
        if desc is None or (desc & 3) == 0:
            return None
        if (desc & 3) == 1:  # a block, or an invalid page descriptor at L3
            if lvl == 3:
                return None
            size = 1 << shift
            return (desc & OUT_ADDR_MASK & ~(size - 1)) | (va & (size - 1))
        if lvl == 3:
            return (desc & OUT_ADDR_MASK) | (va & 0xFFF)
        table = desc & OUT_ADDR_MASK
    return None


def executable_runs(ram, root, va_bits, start_level):
    """Coalesced [(va, pa, length)] the hardware would fetch from at EL1.

    Executable-at-EL1 is PXN (53) clear, *not* UXN (54): kernel text is
    PXN=0/UXN=1, so testing UXN would return userspace mappings and none of the
    text this is looking for.
    """
    sign = 1 << (va_bits - 1)
    runs = []

    def walk(table, lvl, base):
        if table is None:
            return
        for idx in range(512):
            desc = ram.u64(table + idx * 8)
            if desc is None or (desc & 3) == 0:
                continue
            shift = 12 + 9 * (3 - lvl)
            va = base | (idx << shift)
            leaf = (desc & 3) == 1 or lvl == 3
            if not leaf:
                walk(desc & OUT_ADDR_MASK, lvl + 1, va)
                continue
            if (desc & 3) == 1 and lvl == 3:
                continue  # reserved, not a page
            if desc & PXN_BIT:
                continue
            size = 1 << shift
            pa = desc & OUT_ADDR_MASK & ~(size - 1)
            # TTBR1 addresses are the top half; sign-extend the index back out.
            full = va | ~((1 << va_bits) - 1) if va & sign else va
            full &= (1 << 64) - 1
            if runs and runs[-1][0] + runs[-1][2] == full and runs[-1][1] + runs[-1][2] == pa:
                runs[-1][2] += size
            else:
                runs.append([full, pa, size])

    walk(root, start_level, 0)
    return [tuple(r) for r in runs]


# --- the two signatures ------------------------------------------------------


def find_elisions(probe, inv, words, base_va):
    """(elisions, unexplained) for one contiguous run of instruction words.

    `elisions` is [(repair_word_index, op_word_index, shape)]; `repair` names
    the first of the two words a repair would overwrite with `nop`s.
    """
    ops = [i for i, w in enumerate(words) if (w & probe.RT_MASK) == probe.IC_IVAU]
    elisions, seen = [], set()

    for op in ops:
        lo = max(0, op - LOOKBACK_WORDS)

        # S1 -- the guard word followed by a branch that hops this very op.
        hit = None
        for j in range(op - 1, lo - 1, -1):
            if words[j] != probe.ISB:
                continue
            target = probe.decode_b(words[j + 1], base_va + (j + 1) * 4)
            if target is None:
                continue
            t = (target - base_va) // 4
            # `j + 1 < op` is defence in depth and is NOT independently
            # testable: j stops at op - 1, and at j == op - 1 the word handed
            # to decode_b is the `ic ivau` itself, which is not a `b`, so the
            # loop has already continued. `op < t` is the load-bearing half --
            # it is what requires the branch to jump OVER the op rather than
            # merely somewhere forward -- and a mutation removing it fires.
            if j + 1 < op < t:
                hit = (j, op, "branch")
                break
        if hit is None:
            # S2 -- a routine whose whole body is the guard word and a return.
            for j in range(op - 2, lo - 1, -1):
                if not (
                    words[j] == probe.BTI_C
                    and words[j + 1] == probe.ISB
                    and words[j + 2] == probe.RET
                ):
                    continue
                # The dead loop belongs to this routine only if no later routine
                # has started; the next `bti c` is where the next one does.
                if any(words[k] == probe.BTI_C for k in range(j + 3, op)):
                    break
                hit = (j + 1, op, "early-return")
                break
        if hit is not None:
            elisions.append(hit)
            seen.add(op)

    return elisions, [o for o in ops if o not in seen]


def has_aligned_word(buf, word):
    """Is `word` present at a 4-byte boundary? Presence only, so short-circuit.

    An unaligned byte match is not an instruction -- it is the tail of one word
    meeting the head of the next -- and counting it would answer "yes, this
    kernel has BTI" for a kernel that does not, which is the one direction that
    turns a refusal into a false clean bill of health.
    """
    needle = struct.pack("<I", word)
    j = buf.find(needle)
    while j != -1:
        if j % 4 == 0:
            return True
        j = buf.find(needle, j + 1)
    return False


def scan_run(probe, inv, buf, base_va):
    """Elisions and unexplained ops in one executable run, found by opcode."""
    words = list(struct.unpack("<%dI" % (len(buf) // 4), buf[: (len(buf) // 4) * 4]))
    # bytes.find runs in C; a pure-Python unpack over tens of MiB does not
    # finish in a session's patience. Confirm the needle really is an `ic ivau`
    # rather than trusting three bytes that could straddle two other words.
    hits = []
    j = buf.find(inv.NEEDLE)
    while j != -1:
        if j % 4 == inv.NEEDLE_BYTE_OFFSET:
            hits.append((j - inv.NEEDLE_BYTE_OFFSET) // 4)
        j = buf.find(inv.NEEDLE, j + 1)
    if not hits:
        return [], []
    return find_elisions(probe, inv, words, base_va)


# --- reporting ---------------------------------------------------------------


def report(anchors, ncpus, runs, results, out=sys.stdout):
    """Print the finding. Returns an exit status."""
    dic = (anchors["CTR_EL0"] >> CTR_DIC_BIT) & 1
    total = sum(r[2] for r in runs)
    print(
        "capture: %d vCPU(s) in agreement; SCTLR_EL1=%#x TCR_EL1=%#x\n"
        "         TTBR1_EL1=%#x (ASID %#x)  CTR_EL0=%#x  DIC=%d"
        % (
            ncpus,
            anchors["SCTLR_EL1"],
            anchors["TCR_EL1"],
            anchors["TTBR1_EL1"],
            anchors["TTBR1_EL1"] >> 48,
            anchors["CTR_EL0"],
            dic,
        ),
        file=out,
    )
    print(
        "text:    %d executable-at-EL1 run(s), %.1f MiB"
        % (len(runs), total / (1 << 20)),
        file=out,
    )

    elisions = [(va, kind) for va, _, kind in results["elisions"]]
    for va, op_va, kind in results["elisions"]:
        print(
            "  ELIDED  repair at %#018x  (%s, elides the `ic ivau` at %#018x)"
            % (va, kind, op_va),
            file=out,
        )
    for va in results["unexplained"]:
        # An `ic ivau` with no alternative around it was never guarded, so there
        # is nothing here to revert. Reported rather than dropped: a repair pass
        # walks past this site and should be able to see why it was left alone.
        print(
            "  ---     %#018x  unconditional `ic ivau` -- no alternative here" % va,
            file=out,
        )

    print(
        "\n%d elision(s), %d unconditional site(s)"
        % (len(elisions), len(results["unexplained"])),
        file=out,
    )

    if not total:
        print(
            "REVIEW REQUIRED: the walk found no executable kernel text -- the "
            "capture was not understood, and 'no elision' here would be a "
            "statement about this tool rather than about the kernel",
            file=out,
        )
        return 2
    if elisions and not dic:
        # The elision is applied at boot from the *capture host's* CTR_EL0. A
        # capture reporting DIC=0 that nonetheless carries one is a shape nobody
        # has seen, and calling it understood would be a guess.
        print(
            "REVIEW REQUIRED: %d elision(s) present but this capture reports "
            "DIC=0, which cannot have produced them" % len(elisions),
            file=out,
        )
        return 2
    if elisions:
        print(
            "ELISION PRESENT: %d site(s) will execute stale on a DIC=0 host"
            % len(elisions),
            file=out,
        )
        return 1
    print("no DIC elision in this capture's kernel text", file=out)
    return 0


def locate(root, out=sys.stdout):
    probe = load_sibling(PROBE, "dic_probe")
    inv = load_sibling(INVENTORY, "ic_inventory")

    state, ram_path = capture_paths(root)
    anchors, ncpus = read_anchors(state)
    ram = Ram(ram_path, ram_regions(state))

    va_bits, _granule, start_level = decode_tcr(anchors["TCR_EL1"])
    root_pa = ttbr_base(anchors["TTBR1_EL1"])
    runs = executable_runs(ram, root_pa, va_bits, start_level)

    results = {"elisions": [], "unexplained": []}
    saw_bti = False
    for va, pa, length in runs:
        buf = ram.read(pa, length)
        if buf is None:
            continue
        saw_bti = saw_bti or has_aligned_word(buf, probe.BTI_C)
        el, un = scan_run(probe, inv, buf, va)
        results["elisions"] += [(va + j * 4, va + o * 4, kind) for j, o, kind in el]
        results["unexplained"] += [va + o * 4 for o in un]

    # S2 recognises an early-return elision by the `bti c` that opens the
    # routine and the next `bti c` that bounds it. A kernel built without
    # CONFIG_ARM64_BTI_KERNEL carries neither, so S2 can never match and this
    # tool would report a clean capture by being blind rather than by looking.
    # Refuse: of the two ways to be wrong here, only this one is silent.
    #
    # `runs and` is message quality, not correctness, and is deliberately not
    # asserted anywhere: with no runs at all, report()'s own no-executable-text
    # refusal already returns 2, so this clause only decides which of two exit-2
    # messages a reader gets -- and the specific one ("the capture was not
    # understood") beats "no `bti c` in 0 runs". A mutation removing it is
    # therefore silent by construction, and no test pretends otherwise.
    if runs and not saw_bti:
        raise Refuse(
            "no `bti c` anywhere in %d run(s) of executable text -- this kernel "
            "was built without BTI, so the early-return signature cannot match "
            "and 'no elision' would mean 'not looked for'" % len(runs)
        )

    return report(anchors, ncpus, runs, results, out=out)


# --- selftest ----------------------------------------------------------------
#
# The walker is the half that cannot be exercised by hand-built instruction
# words, so the fixture fabricates a real 4-level table in a bytes buffer. A
# selftest that only checked the signatures would leave the part that decides
# *which bytes are kernel text* -- the part carrying the whole "this is not a
# coincidence" claim -- completely untested.


class FakeRam(Ram):
    def __init__(self, buf, base):
        self.buf, self.base, self.regions = buf, base, [(base, len(buf), 0)]

    def read(self, pa, nbytes):
        off = pa - self.base
        if off < 0 or off + nbytes > len(self.buf):
            return None
        return bytes(self.buf[off : off + nbytes])


def build_fixture(text_words, pxn=False, va=0xFFFF_8000_0000_0000, base=0x4000_0000):
    """A 4-level TTBR1 table mapping one page of `text_words` at `va`."""
    size = 6 * 4096
    buf = bytearray(size)
    tables = [base + i * 4096 for i in range(4)]  # L0..L3
    text_pa = base + 4 * 4096

    def put(pa, idx, val):
        struct.pack_into("<Q", buf, (pa - base) + idx * 8, val)

    for lvl in range(3):
        put(tables[lvl], (va >> (12 + 9 * (3 - lvl))) & 0x1FF, tables[lvl + 1] | 3)
    leaf = text_pa | 3 | (PXN_BIT if pxn else 0)
    put(tables[3], (va >> 12) & 0x1FF, leaf)

    for i, w in enumerate(text_words):
        struct.pack_into("<I", buf, (text_pa - base) + i * 4, w)
    return FakeRam(buf, base), tables[0], va


def selftest(out=sys.stdout):
    probe = load_sibling(PROBE, "dic_probe")
    inv = load_sibling(INVENTORY, "ic_inventory")
    fails = []

    def check(name, got, want):
        ok = got == want
        print("  %-46s %s" % (name, "ok" if ok else "FAIL %r != %r" % (got, want)), file=out)
        if not ok:
            fails.append(name)

    # --- the walk ---
    ram, root, va = build_fixture([probe.NOP] * 8)
    check("4-level walk reaches the mapped page", translate(ram, root, va, 0), 0x4000_0000 + 4 * 4096)
    check("walk resolves the offset within the page", translate(ram, root, va + 0x10, 0), 0x4000_0000 + 4 * 4096 + 0x10)
    check("an unmapped VA translates to nothing", translate(ram, root, va + (1 << 21), 0), None)
    check("the page is enumerated as executable", executable_runs(ram, root, 48, 0), [(va, 0x4000_0000 + 4 * 4096, 4096)])

    ram_pxn, root_pxn, _ = build_fixture([probe.NOP] * 8, pxn=True)
    # PXN set means the hardware will not fetch instructions at EL1, so this
    # page must be invisible -- otherwise a userspace or data page carrying the
    # same bytes would be reported as kernel text.
    check("a PXN page is not executable at EL1", executable_runs(ram_pxn, root_pxn, 48, 0), [])

    # --- TCR ---
    check("TG1=2 is the 4 KiB granule", decode_tcr(0x0000_01F5_B550_3510)[1], 4096)
    check("T1SZ=16 gives 48 VA bits", decode_tcr(0x0000_01F5_B550_3510)[0], 48)
    check("48 VA bits start the walk at level 0", decode_tcr(0x0000_01F5_B550_3510)[2], 0)
    check("TTBR1 BADDR drops CnP and the ASID", ttbr_base(0x036C_0000_987B_1001), 0x987B_1000)

    # --- the signatures ---
    B = 0x1400_0000  # `b .+imm*4`
    V = 0xFFFF_8000_0000_0000

    branch = [probe.BTI_C, probe.DSB_ISHST, probe.ISB, B | 3, probe.NOP, probe.IC_IVAU | 3, probe.RET]
    el, un = find_elisions(probe, inv, branch, V)
    check("S1 finds the branch elision", el, [(2, 5, "branch")])
    check("S1 leaves nothing unexplained", un, [])

    # The `isb` is the DIC alternative; unpatched it is a `nop` pair and the
    # loop runs. Nothing to repair, and reporting one would be a false positive
    # in the one direction that corrupts a kernel.
    unpatched = [probe.BTI_C, probe.NOP, probe.NOP, probe.NOP, probe.IC_IVAU | 3, probe.RET]
    check("an unpatched routine is not an elision", find_elisions(probe, inv, unpatched, V)[0], [])
    check("an unpatched routine's op is unexplained", find_elisions(probe, inv, unpatched, V)[1], [4])

    # A branch that lands *before* the op does not skip it.
    backward = [probe.IC_IVAU | 3, probe.ISB, B | (-1 & 0x03FFFFFF), probe.RET, probe.IC_IVAU | 3]
    check("a branch that does not skip the op is ignored", find_elisions(probe, inv, backward, V)[0], [])

    # A branch stopping short of the op leaves the loop reachable.
    short = [probe.BTI_C, probe.ISB, B | 1, probe.NOP, probe.IC_IVAU | 3]
    check("a branch landing before the op is ignored", find_elisions(probe, inv, short, V)[0], [])

    early = [probe.BTI_C, probe.ISB, probe.RET, probe.NOP, probe.IC_IVAU | 3, probe.RET]
    check("S2 finds the early return", find_elisions(probe, inv, early, V)[0], [(1, 4, "early-return")])

    # The IDC pair is one word different and is NOT a defect -- Apple reports
    # IDC=1, so reverting it would be a regression.
    idc = [probe.BTI_C, probe.DSB_ISHST, probe.RET, probe.NOP, probe.IC_IVAU | 3, probe.RET]
    check("the IDC early return is not a DIC elision", find_elisions(probe, inv, idc, V)[0], [])

    # An `ic ivau` in the *next* routine is not this one's dead code.
    crossed = [probe.BTI_C, probe.ISB, probe.RET, probe.NOP, probe.BTI_C, probe.IC_IVAU | 3]
    check("an op past the next routine's entry is ignored", find_elisions(probe, inv, crossed, V)[0], [])

    # --- the BTI-absent refusal ---
    #
    # A kernel with no `bti c` must be refused, not reported clean. The
    # alignment half is the load-bearing one: a `bti c` straddling two other
    # words is not an instruction, and accepting it would restore exactly the
    # silence this refusal exists to break.
    words_bti = struct.pack("<3I", probe.NOP, probe.BTI_C, probe.NOP)
    check("an aligned `bti c` is found", has_aligned_word(words_bti, probe.BTI_C), True)
    none_bti = struct.pack("<3I", probe.NOP, probe.ISB, probe.RET)
    check("a kernel with no `bti c` is not credited with one", has_aligned_word(none_bti, probe.BTI_C), False)
    straddle = b"\x00" + struct.pack("<I", probe.BTI_C) + b"\x00\x00\x00"
    check("a straddling `bti c` is not an instruction", has_aligned_word(straddle, probe.BTI_C), False)

    # --- end to end, through the walk ---
    ram2, root2, va2 = build_fixture(branch)
    runs = executable_runs(ram2, root2, 48, 0)
    buf = ram2.read(runs[0][1], runs[0][2])
    el, un = scan_run(probe, inv, buf, runs[0][0])
    check("a fabricated capture locates its elision", el, [(2, 5, "branch")])

    print("\n%s" % ("selftest passed" if not fails else "FAIL: %s" % ", ".join(fails)), file=out)
    return 1 if fails else 0


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: %s <capture-dir> | selftest" % os.path.basename(argv[0]), file=sys.stderr)
        return 2
    if argv[1] == "selftest":
        return selftest()
    try:
        return locate(argv[1])
    except Refuse as exc:
        print("REVIEW REQUIRED: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
