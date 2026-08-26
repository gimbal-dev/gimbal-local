// SPDX-License-Identifier: Apache-2.0

//! Reading a capture's cache-identity registers, and deciding what they mean
//! on *this* host.
//!
//! A Graviton2 capture's kernel booted where `CTR_EL0.DIC = 1`, so Linux's
//! boot-time alternatives patching physically branched over the `ic ivau`
//! loops in its cache-maintenance routines and latched that elision into the
//! snapshot's kernel text. Apple silicon reports `DIC = 0`, so the elision is
//! unsound here and freshly written code executes stale.
//!
//! This module lives in `hypervisor` rather than in the CLI because it has two
//! consumers on opposite sides of the crate boundary: the warning an operator
//! reads (`chm`) and the restore-time decision about the guest's own memory
//! (here). Two implementations of one rule eventually disagree, and the
//! disagreement would be a guest that is warned about but not repaired, or
//! repaired without being told.

use std::{error, fmt};

use super::rehydrate::Snapshot;

/// `CTR_EL0` is `S3_3_C0_C0_1`, packed as
/// `(op0<<14)|(op1<<11)|(CRn<<7)|(CRm<<3)|op2`.
pub const CTR_EL0: u16 = 0xd801;
/// `CTR_EL0.DIC` -- instruction cache snoops the data side, so `ic ivau` may
/// be skipped.
pub const CTR_DIC: u64 = 1 << 29;
/// `CTR_EL0.IDC` -- the data cache is coherent to the point of unification, so
/// `dc cvau` may be skipped. The sibling alternative at the same call sites.
pub const CTR_IDC: u64 = 1 << 28;

/// This host's `CTR_EL0`, measured rather than assumed.
///
/// It cannot be read at runtime: macOS traps `mrs ctr_el0` at EL0 with SIGILL
/// and `hv_vcpu_get_sys_reg` refuses the register outright, so the only reader
/// is a guest. `hvf_host_cache_identity_registers` runs exactly that guest and
/// pins the bits this constant is consulted for, so a future part that reports
/// something else fails a test rather than passing this guard silently -- the
/// same arrangement as `HOST_ASID_BITS` and `hvf_host_mmu_feature_register`.
pub const HOST_CTR_EL0: u64 = 0x9444_c004;

/// What a capture says about one system register, read across every vCPU.
///
/// `.iter().any()` collapses three genuinely different situations into one
/// bool: a register no vCPU recorded, vCPUs that recorded *different* values,
/// and a real agreed reading. The first two both mean "this capture cannot
/// answer", and answering them `false` is the one direction that fails
/// silently -- it is indistinguishable from a confident "no hazard here".
///
/// A warning may reasonably treat an unanswerable capture as quiet. A *repair*
/// may not: rewriting kernel text on the strength of a register nobody
/// recorded is acting on a verdict that was never produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Captured {
    /// No vCPU recorded this register.
    Absent,
    /// Two vCPUs recorded different values, so the capture describes no single
    /// machine. Cache identity registers are uniform on real hardware, so a
    /// disagreement means the capture is malformed rather than exotic.
    Disagreed,
    /// Every vCPU that recorded it agrees on this value.
    Agreed(u64),
}

/// Read one system register out of a capture, across all of its vCPUs.
///
/// Deliberately keeps scanning after the first hit: stopping early is what
/// turns a disagreement into whichever vCPU happened to be enumerated first.
pub fn captured_sysreg(snap: &Snapshot, want: u16) -> Captured {
    let mut seen: Option<u64> = None;
    for vcpu in &snap.vcpus {
        for &(reg, val) in &vcpu.sysregs {
            if reg != want {
                continue;
            }
            match seen {
                None => seen = Some(val),
                Some(prev) if prev != val => return Captured::Disagreed,
                Some(_) => {}
            }
        }
    }
    seen.map_or(Captured::Absent, Captured::Agreed)
}

/// Did this capture's kernel boot on a host that let it skip `ic ivau`?
///
/// `CTR_EL0.DIC = 1` promises the instruction cache snoops the data side, so
/// Linux alternative-patches the `ic ivau` out of `caches_clean_inval_pou()` at
/// boot -- and those NOPs travel in the snapshot's kernel text. Apple silicon
/// reports `DIC = 0`, so a guest rehydrated here performs no instruction-cache
/// maintenance on a machine that requires it.
///
/// One predicate, several consumers: the warning the operator reads, the
/// decision to take the maintenance over host-side, and the restore-time
/// repair. Copies of this test would eventually disagree, and the disagreement
/// would be a guest that is warned about but not repaired, or repaired without
/// being told.
///
/// An unreadable capture answers `false` **here and only here**, because the
/// mitigations that consume this bool are best-effort and their absence leaves
/// the guest no worse off than before they existed. Anything that rewrites
/// guest memory must read [`captured_sysreg`] directly and refuse instead --
/// see [`idc_elision_is_sound_here`] for the shape.
pub fn snapshot_elides_ic_ivau(snap: &Snapshot) -> bool {
    matches!(captured_sysreg(snap, CTR_EL0), Captured::Agreed(v) if v & CTR_DIC != 0)
}

/// Why a repair must not touch the `dc cvau` sitting next to every elided
/// `ic ivau`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdcVerdict {
    /// This host is coherent to the point of unification, so the elided
    /// `dc cvau` is sound here for the same reason it was sound on the capture
    /// host. Repair the DIC half and leave the IDC half alone.
    LeaveAlone,
    /// This host is *not* coherent, so the capture's elided `dc cvau` is as
    /// unsound as its elided `ic ivau`. Repairing only the DIC half would
    /// produce a guest that is half-correct and reported as fixed.
    AlsoElidedUnsoundly,
    /// The capture could not be read, so no conclusion is available.
    Unreadable(Captured),
}

/// Decide the IDC half of the repair against the **live host**, not a constant.
///
/// The two alternatives are one word apart -- `bti c; isb; ret` is the DIC
/// early return and `bti c; dsb ishst; ret` is the IDC one -- so a repair that
/// pattern-matches loosely will revert both. Apple silicon reports `IDC = 1`,
/// which means reverting the IDC elision is a *regression*: it reintroduces
/// cache maintenance the hardware does not need.
///
/// That is a fact about this machine, so it is a parameter rather than a
/// constant. `CTR_EL0` cannot be read from the host at all -- macOS traps
/// `mrs ctr_el0` at EL0 and `hv_vcpu_get_sys_reg` refuses it -- so the only
/// way to obtain it is a guest that reads it and hands it back. Keeping this a
/// pure function is what lets all four combinations be tested without one,
/// exactly as [`super::ctr_trap_fixup`] does; the measurement itself is pinned
/// by `hvf_host_cache_identity_registers`.
pub fn idc_elision_is_sound_here(snap: &Snapshot, host_ctr: u64) -> IdcVerdict {
    let captured = captured_sysreg(snap, CTR_EL0);
    let Captured::Agreed(val) = captured else {
        return IdcVerdict::Unreadable(captured);
    };
    // A capture whose own host said `IDC = 0` never elided `dc cvau` in the
    // first place, so there is nothing here to leave alone or to repair.
    if val & CTR_IDC == 0 {
        return IdcVerdict::LeaveAlone;
    }
    if host_ctr & CTR_IDC != 0 {
        IdcVerdict::LeaveAlone
    } else {
        IdcVerdict::AlsoElidedUnsoundly
    }
}

// ===========================================================================
// Phase 3 -- locating the elision in a capture's kernel text and reverting it.
// ===========================================================================

/// Read and write access to a guest's physical address space.
///
/// The restore-time repair runs after guest RAM is mapped and before any vCPU
/// exists, so its reads and writes go through the *host* mapping rather than
/// the capture file. That is also what makes the maintenance afterwards
/// meaningful: the caches are physically indexed, so invalidating our own
/// mapping of a page reaches the guest's view of it -- the argument written out
/// at [`super::icache_wx`].
///
/// A trait rather than a concrete `GuestMemory` because every interesting
/// failure here is far easier to build than to capture: a reserved granule, a
/// descriptor pointing outside RAM, a run straddling two regions, a repair site
/// whose words are not what the locator saw.
pub trait PhysMem {
    /// Guest-physical regions and the host mapping backing each, as
    /// `(guest physical base, host virtual base, length)`.
    fn regions(&self) -> Vec<(u64, usize, usize)>;

    /// Hand `pa..pa + len` to `f`, or answer `false` when that span is not
    /// entirely inside one region.
    fn with_bytes(&self, pa: u64, len: usize, f: &mut dyn FnMut(&[u8])) -> bool;

    /// Overwrite `pa..pa + bytes.len()`. `false` when that span is not entirely
    /// inside one region, in which case nothing was written.
    fn write_bytes(&self, pa: u64, bytes: &[u8]) -> bool;

    /// A little-endian `u64` at a guest physical address.
    fn u64_at(&self, pa: u64) -> Option<u64> {
        let mut out = None;
        self.with_bytes(pa, 8, &mut |b| {
            let mut w = [0u8; 8];
            w.copy_from_slice(b);
            out = Some(u64::from_le_bytes(w));
        });
        out
    }
}

// --- the stage-1 page-table walk -------------------------------------------

/// A descriptor's output address is bits `[47:12]`. Bits `63:48` are the upper
/// attributes (PXN among them) and `11:0` are the type and lower attributes.
const OUT_ADDR_MASK: u64 = ((1 << 48) - 1) & !0xFFF;

/// Privileged execute-never. **Clear** means executable at EL1.
///
/// PXN (53), not UXN (54). Kernel text is `PXN=0`/`UXN=1`, so a walk testing
/// UXN returns userspace mappings and none of the text this is looking for --
/// and it would look like a working walk, because it does return runs.
const PXN_BIT: u64 = 1 << 53;

/// How many translation tables the walk will visit before giving up.
///
/// The offline locator has no bound because it runs against a file with a
/// human watching. This runs inside VM creation, so a walk that takes minutes
/// is a hang at startup rather than a slow tool.
///
/// The axis this bounds is **breadth, not depth**. A cycle cannot hang the
/// walk: the level counter rises on every descent and `lvl == 3` is a leaf, so
/// a table pointing at itself resolves as a page four levels down and stops.
/// That was measured, against the guard test named below, and it is the
/// opposite of what an earlier draft of this comment claimed. What a walk
/// genuinely cannot afford is a fully-populated tree -- 512 level-1 entries
/// each fanning out to 512 level-2 tables is 262,144 visits before a single
/// page is reached. A real 4 KiB-granule kernel mapping needs a few thousand
/// tables, so this is a bound rather than a tuned value: crossing it means the
/// tree is not a kernel's.
///
/// Guarded by `a_tree_too_broad_to_be_a_kernels_is_refused_rather_than_walked`.
const MAX_TABLES: usize = 65_536;

/// How much executable-at-EL1 text the walk will accept before giving up.
///
/// Same reasoning as [`MAX_TABLES`], for the other axis: a tree can be shallow
/// and still describe an absurd amount of text through block descriptors.
const MAX_TEXT_BYTES: u64 = 512 << 20;

/// The TTBR1 translation layout a capture's `TCR_EL1` describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Significant virtual address bits, `64 - T1SZ`.
    pub va_bits: u32,
    /// Translation granule, in bytes.
    pub granule: u64,
    /// The level the walk starts at, `0..=3`.
    pub start_level: u32,
}

/// Decode the TTBR1 half of `TCR_EL1`.
///
/// `TG1`'s encoding is **not** `TG0`'s: 1 is 16 KiB, 2 is 4 KiB and 3 is
/// 64 KiB, where TG0 uses 0 for 4 KiB. Reading TG1 with TG0's table produces a
/// walker that misses on every address, which presents as a corrupt capture
/// rather than as a bug here.
pub fn decode_tcr(tcr: u64) -> Result<Layout, Refusal> {
    let t1sz = ((tcr >> 16) & 0x3F) as u32;
    let granule = match (tcr >> 30) & 0x3 {
        1 => 16384,
        2 => 4096,
        3 => 65536,
        other => return Err(Refusal::ReservedGranule(other)),
    };
    if granule != 4096 {
        return Err(Refusal::UnsupportedGranule(granule));
    }
    let va_bits = 64 - t1sz;
    // A 4 KiB granule resolves 9 bits per level above the 12-bit page offset.
    //
    // The offline locator spells this `(va_bits - 12 + 8) // 9`. For an
    // unsigned numerator that is exactly `div_ceil`, so this is the same
    // arithmetic in the form the language names, not a different rule.
    let levels = (va_bits - 12).div_ceil(9);
    Ok(Layout {
        va_bits,
        granule,
        start_level: 4 - levels,
    })
}

/// `BADDR` from `TTBR1_EL1`. Bit 0 is `CnP` and bits `63:48` are the ASID.
pub fn ttbr_base(ttbr: u64) -> u64 {
    (ttbr & 0x0000_FFFF_FFFF_FFFE) & !0xFFF
}

/// The physical address a kernel VA translates to, or `None` when it is not
/// mapped.
///
/// [`executable_runs`] already reports a physical address for every run, so
/// this is not how the repair finds its sites. It is how the repair *checks*
/// them: translating a site's VA independently and requiring it to agree with
/// the run it came from turns a coalescing bug into a refusal rather than into
/// a write at the wrong physical address.
pub fn translate(mem: &dyn PhysMem, root: u64, va: u64, start_level: u32) -> Option<u64> {
    let mut table = root;
    for lvl in start_level..4 {
        let shift = 12 + 9 * (3 - lvl);
        let desc = mem.u64_at(table + ((va >> shift) & 0x1FF) * 8)?;
        if desc & 3 == 0 {
            return None;
        }
        if desc & 3 == 1 {
            // A block -- or, at level 3, an invalid page descriptor.
            if lvl == 3 {
                return None;
            }
            let size = 1u64 << shift;
            return Some((desc & OUT_ADDR_MASK & !(size - 1)) | (va & (size - 1)));
        }
        if lvl == 3 {
            return Some((desc & OUT_ADDR_MASK) | (va & 0xFFF));
        }
        table = desc & OUT_ADDR_MASK;
    }
    None
}

/// One coalesced stretch of guest memory the hardware would fetch from at EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// Kernel virtual address, sign-extended back into the top half.
    pub va: u64,
    /// Guest physical address.
    pub pa: u64,
    /// Length in bytes.
    pub len: u64,
}

/// Every executable-at-EL1 run under `root`, coalesced where VA *and* PA stay
/// contiguous.
///
/// Coalescing on both is what makes a run safe to read as one buffer: a run
/// whose VAs are contiguous but whose PAs are not would have the locator
/// decoding two unrelated stretches of text as though they were adjacent
/// instructions.
pub fn executable_runs(
    mem: &dyn PhysMem,
    root: u64,
    va_bits: u32,
    start_level: u32,
) -> Result<Vec<Run>, Refusal> {
    /// The walk's invariants and its accumulators, in one place.
    ///
    /// Passing these down as nine separate parameters is what the recursion
    /// wants and not what a reader wants: only `table` and `lvl` change per
    /// call, and the other seven were pure noise at every call site. Splitting
    /// them apart also makes the distinction structural -- `mem`, `sign` and
    /// `va_bits` are fixed for the whole walk, while `runs`, `budget` and
    /// `text` are the state a bound is being enforced against.
    struct Walk<'a> {
        mem: &'a dyn PhysMem,
        sign: u64,
        va_bits: u32,
        runs: Vec<Run>,
        budget: usize,
        text: u64,
    }

    impl Walk<'_> {
        fn descend(&mut self, table: u64, lvl: u32, base: u64) -> Result<(), Refusal> {
            if self.budget == 0 {
                return Err(Refusal::WalkTooLarge);
            }
            self.budget -= 1;
            for idx in 0..512u64 {
                let Some(desc) = self.mem.u64_at(table + idx * 8) else {
                    continue;
                };
                if desc & 3 == 0 {
                    continue;
                }
                let shift = 12 + 9 * (3 - lvl);
                let va = base | (idx << shift);
                let leaf = desc & 3 == 1 || lvl == 3;
                if !leaf {
                    self.descend(desc & OUT_ADDR_MASK, lvl + 1, va)?;
                    continue;
                }
                if desc & 3 == 1 && lvl == 3 {
                    continue; // reserved at level 3, not a page
                }
                if desc & PXN_BIT != 0 {
                    continue;
                }
                let size = 1u64 << shift;
                let pa = desc & OUT_ADDR_MASK & !(size - 1);
                // TTBR1 addresses live in the top half; the walk indexes from
                // zero, so sign-extend the index back out to the address the
                // guest uses.
                let full = if va & self.sign != 0 {
                    va | !((1u64 << self.va_bits) - 1)
                } else {
                    va
                };
                self.text += size;
                if self.text > MAX_TEXT_BYTES {
                    return Err(Refusal::WalkTooLarge);
                }
                match self.runs.last_mut() {
                    Some(last) if last.va + last.len == full && last.pa + last.len == pa => {
                        last.len += size;
                    }
                    _ => self.runs.push(Run {
                        va: full,
                        pa,
                        len: size,
                    }),
                }
            }
            Ok(())
        }
    }

    let mut walk = Walk {
        mem,
        sign: 1u64 << (va_bits - 1),
        va_bits,
        runs: Vec::new(),
        budget: MAX_TABLES,
        text: 0,
    };
    walk.descend(root, start_level, 0)?;
    Ok(walk.runs)
}

// --- the two elision signatures ---------------------------------------------

/// How far back from an `ic ivau` an alternative's guard word may sit.
///
/// Owned by the offline locator, which measured it against five real captures;
/// the widest real gap there is far inside it.
pub const LOOKBACK_WORDS: usize = 64;

/// `nop`. What a reverted alternative's two words become.
pub const NOP: u32 = 0xD503_201F;
/// `isb` -- the word Linux leaves behind when it patches out the **DIC** half.
pub const ISB: u32 = 0xD503_3FDF;
/// `ret`.
pub const RET: u32 = 0xD65F_03C0;
/// `bti c`, which leads every one of the routines involved.
pub const BTI_C: u32 = 0xD503_245F;
/// `ic ivau, Xt` with `Rt` masked off -- `Rt` is the low five bits.
pub const IC_IVAU: u32 = 0xD50B_7520;
/// The mask that drops `Rt` from a cache-maintenance encoding.
pub const RT_MASK: u32 = 0xFFFF_FFE0;
/// `dsb ishst` -- the word the **IDC** half leaves behind. Present here only so
/// that a reader can see it is *not* what the locator matches on: the two
/// alternatives sit one word apart, and reverting the IDC half on this host
/// would reintroduce maintenance the hardware does not need.
pub const DSB_ISHST: u32 = 0xD503_3A9F;

/// Unconditional `b` is `000101` followed by a 26-bit signed word offset.
const B_OPC_MASK: u32 = 0xFC00_0000;
const B_OPC: u32 = 0x1400_0000;

/// The target of an unconditional `b` at `addr`, or `None` if this is not one.
pub fn decode_b(word: u32, addr: u64) -> Option<u64> {
    if word & B_OPC_MASK != B_OPC {
        return None;
    }
    let mut imm = (word & 0x03FF_FFFF) as i64;
    if imm & 0x0200_0000 != 0 {
        imm -= 0x0400_0000; // sign-extend the 26-bit immediate
    }
    Some((addr as i64).wrapping_add(imm * 4) as u64)
}

/// Which of the two shapes Linux's alternatives patching left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The guard word followed by a branch that hops over the maintenance loop.
    Branch,
    /// A routine whose whole body became the guard word and a return, leaving
    /// the maintenance loop below it, unreachable and intact.
    EarlyReturn,
}

/// One located elision, as word indices into the run it was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elision {
    /// The first of the two words a repair overwrites with `nop`s.
    pub repair: usize,
    /// The `ic ivau` this elision skips.
    pub op: usize,
    /// Which signature matched.
    pub shape: Shape,
}

/// Locate every elided `ic ivau` in one contiguous run of instruction words.
///
/// Returns the elisions and, separately, the word indices of `ic ivau`
/// instructions with no alternative around them. Those were never guarded, so
/// there is nothing there to revert -- they are reported rather than dropped
/// so that a repair walking past one can say why it was left alone.
///
/// `base_va` provably cancels out of the arithmetic (`decode_b` adds it and the
/// index conversion subtracts it again), so this is a pure function of the
/// words. It stays in the signature because it is what the offline locator
/// takes and porting it away would be a silent divergence from the
/// specification; `the_locator_does_not_depend_on_where_the_text_is_mapped`
/// pins the cancellation.
pub fn find_elisions(words: &[u32], base_va: u64) -> (Vec<Elision>, Vec<usize>) {
    let ops: Vec<usize> = words
        .iter()
        .enumerate()
        .filter(|(_, w)| **w & RT_MASK == IC_IVAU)
        .map(|(i, _)| i)
        .collect();
    let mut elisions = Vec::new();
    let mut unexplained = Vec::new();

    for &op in &ops {
        let lo = op.saturating_sub(LOOKBACK_WORDS);
        let mut hit = None;

        // S1 -- the guard word, then a branch that hops this very op.
        for j in (lo..op).rev() {
            if words[j] != ISB {
                continue;
            }
            let Some(target) = decode_b(words[j + 1], base_va + (j as u64 + 1) * 4) else {
                continue;
            };
            let t = (target as i64 - base_va as i64) / 4;
            // `j + 1 < op` is defence in depth and is not independently
            // testable: `j` stops at `op - 1`, and there the word handed to
            // `decode_b` is the `ic ivau` itself, which is not a `b`. `op < t`
            // is the load-bearing half -- it is what requires the branch to
            // jump *over* the op rather than merely somewhere forward.
            if (j as i64 + 1) < op as i64 && (op as i64) < t {
                hit = Some(Elision {
                    repair: j,
                    op,
                    shape: Shape::Branch,
                });
                break;
            }
        }

        // S2 -- a routine whose whole body is the guard word and a return.
        if hit.is_none() && op >= 2 {
            for j in (lo..op - 1).rev() {
                if !(words[j] == BTI_C && words[j + 1] == ISB && words[j + 2] == RET) {
                    continue;
                }
                // The dead loop belongs to this routine only while no later
                // routine has started, and the next `bti c` is where one does.
                if words[j + 3..op].contains(&BTI_C) {
                    break;
                }
                hit = Some(Elision {
                    repair: j + 1,
                    op,
                    shape: Shape::EarlyReturn,
                });
                break;
            }
        }

        match hit {
            Some(e) => elisions.push(e),
            None => unexplained.push(op),
        }
    }

    (elisions, unexplained)
}

// --- the transactional repair ------------------------------------------------

/// Why a repair declined to touch this guest's kernel text.
///
/// Every variant means **zero bytes were written**. Declining is not a failure
/// of the restore: it leaves the guest exactly as the capture describes it,
/// which is where every guest was before this existed. The reason is carried
/// rather than flattened to a bool so that the operator is told which of these
/// happened -- "we could not read the capture" and "we read it and found
/// nothing to repair" are very different things to be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `CTR_EL0` is absent from the capture, or its vCPUs disagree.
    UnreadableCacheIdentity(Captured),
    /// `TCR_EL1` is absent from the capture, or its vCPUs disagree.
    UnreadableTranslationControl(Captured),
    /// `TTBR1_EL1` is absent from the capture, or its vCPUs disagree.
    UnreadableTtbr1(Captured),
    /// `TCR_EL1.TG1` names a reserved granule, so the capture describes no
    /// translation regime this or any other walker can follow.
    ReservedGranule(u64),
    /// A granule this walk does not implement.
    UnsupportedGranule(u64),
    /// The walk ran past its bounds, so this tree is not a kernel's.
    WalkTooLarge,
    /// The walk found no executable-at-EL1 memory at all.
    NoKernelText,
    /// The capture says its host elided `ic ivau`, and none of that elision
    /// could be found. Reported loudly: the guest is about to run with kernel
    /// text this host cannot execute safely, and silence would read as repair.
    ElisionNotLocated,
    /// This host would need the `dc cvau` half reverted too, which this repair
    /// does not do. Repairing only the DIC half would produce a guest that is
    /// half-correct and reported as fixed.
    IdcAlsoUnsound,
    /// A site's words were not what the locator saw when the repair came back
    /// to write them, so the two passes disagree about this guest's memory.
    SiteMoved {
        /// The kernel virtual address of the site that disagreed.
        va: u64,
    },
    /// A site's virtual address did not independently translate to the physical
    /// address the run it came from claims.
    SiteDidNotTranslate {
        /// The kernel virtual address of the site that disagreed.
        va: u64,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableCacheIdentity(c) => {
                write!(f, "the capture cannot answer for CTR_EL0 ({c:?})")
            }
            Self::UnreadableTranslationControl(c) => {
                write!(f, "the capture cannot answer for TCR_EL1 ({c:?})")
            }
            Self::UnreadableTtbr1(c) => {
                write!(f, "the capture cannot answer for TTBR1_EL1 ({c:?})")
            }
            Self::ReservedGranule(tg1) => write!(f, "TCR_EL1.TG1={tg1} is reserved"),
            Self::UnsupportedGranule(g) => write!(
                f,
                "this capture uses a {g}-byte translation granule; the walk here implements 4 KiB only"
            ),
            Self::WalkTooLarge => {
                write!(
                    f,
                    "the page tables did not terminate within a kernel's bounds"
                )
            }
            Self::NoKernelText => write!(f, "the walk found no executable-at-EL1 memory"),
            Self::ElisionNotLocated => write!(
                f,
                "the capture reports CTR_EL0.DIC=1 but no elided `ic ivau` could be located"
            ),
            Self::IdcAlsoUnsound => write!(
                f,
                "this host is not coherent to the point of unification, so the `dc cvau` half would need reverting too"
            ),
            Self::SiteMoved { va } => {
                write!(
                    f,
                    "the words at {va:#018x} changed between locating and writing"
                )
            }
            Self::SiteDidNotTranslate { va } => {
                write!(
                    f,
                    "{va:#018x} did not translate to the address its run claims"
                )
            }
        }
    }
}

/// What a repair did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// The capture's own host reported `DIC = 0`, so nothing was ever elided
    /// and there is nothing to revert. A cold-booted guest reaches here too,
    /// by reading this Mac's own register.
    NotElided,
    /// Sites were located and reverted.
    Reverted {
        /// How many elisions were reverted, two words each.
        sites: usize,
        /// How many `ic ivau` instructions were found with no alternative
        /// around them, and so were correctly left alone.
        unconditional: usize,
    },
    /// Declined, with the reason. Zero bytes were written.
    Declined(Refusal),
}

/// A write failed *after* the kernel text had already been modified.
///
/// There is no way back from here. The guest's text is neither what the capture
/// held nor what the repair intended, so starting it would run a kernel
/// assembled by a half-finished edit -- and the failure mode of a half-repaired
/// cache-maintenance routine is silent memory corruption, not a crash that
/// names its cause. The only honest response is to abort VM creation, which is
/// why this is the error half of the result rather than a [`Refusal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TornRepair {
    /// How many sites had already been written when the failure happened.
    pub written: usize,
    /// The physical address the failing write was aimed at.
    pub failed_at: u64,
}

impl error::Error for TornRepair {}

impl fmt::Display for TornRepair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the DIC repair could not finish: {} site(s) were already reverted when the write at {:#018x} failed, so this guest's kernel text is in neither state",
            self.written, self.failed_at
        )
    }
}

/// A located site, resolved all the way to the physical address of its two
/// words, before anything has been written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Site {
    va: u64,
    pa: u64,
    shape: Shape,
}

/// Revert the `CTR_EL0.DIC = 1` elision in a rehydrated guest's kernel text.
///
/// Runs after guest RAM is mapped and before any vCPU exists, so it has the
/// whole address space to itself and no other writer to race.
///
/// **Transactional by construction.** Locating, resolving and verifying happen
/// across the entire address space first; only then does the first byte move.
/// A guest whose sites cannot all be verified is left completely untouched,
/// because a partially reverted cache-maintenance routine is worse than an
/// entirely elided one: the elided one is a known hazard this host already
/// warns about, and the half-reverted one looks repaired.
///
/// The `dc cvau` half is deliberately never touched -- see
/// [`idc_elision_is_sound_here`], and note that the locator matches on [`ISB`]
/// and never on [`DSB_ISHST`], so the IDC alternative is not a candidate even
/// before that verdict is consulted.
pub fn revert_dic_elision(
    mem: &dyn PhysMem,
    snap: &Snapshot,
    host_ctr: u64,
) -> Result<Repair, TornRepair> {
    // --- 1. can this capture be read at all? --------------------------------
    //
    // `snapshot_elides_ic_ivau` is deliberately not used here. It answers
    // `false` for an unreadable capture, which is right for a best-effort
    // warning and wrong for anything that writes to guest memory.
    let ctr = match captured_sysreg(snap, CTR_EL0) {
        Captured::Agreed(v) => v,
        other => {
            return Ok(Repair::Declined(Refusal::UnreadableCacheIdentity(other)));
        }
    };
    if ctr & CTR_DIC == 0 {
        return Ok(Repair::NotElided);
    }
    match idc_elision_is_sound_here(snap, host_ctr) {
        IdcVerdict::LeaveAlone => {}
        IdcVerdict::AlsoElidedUnsoundly => {
            return Ok(Repair::Declined(Refusal::IdcAlsoUnsound));
        }
        IdcVerdict::Unreadable(c) => {
            return Ok(Repair::Declined(Refusal::UnreadableCacheIdentity(c)));
        }
    }

    let tcr = match captured_sysreg(snap, super::ffi::SYSREG_TCR_EL1) {
        Captured::Agreed(v) => v,
        other => {
            return Ok(Repair::Declined(Refusal::UnreadableTranslationControl(
                other,
            )));
        }
    };
    let ttbr1 = match captured_sysreg(snap, super::ffi::SYSREG_TTBR1_EL1) {
        Captured::Agreed(v) => v,
        other => return Ok(Repair::Declined(Refusal::UnreadableTtbr1(other))),
    };

    // --- 2. where is the kernel's executable text? --------------------------
    let layout = match decode_tcr(tcr) {
        Ok(l) => l,
        Err(r) => return Ok(Repair::Declined(r)),
    };
    let root = ttbr_base(ttbr1);
    let runs = match executable_runs(mem, root, layout.va_bits, layout.start_level) {
        Ok(r) => r,
        Err(r) => return Ok(Repair::Declined(r)),
    };
    if runs.is_empty() {
        return Ok(Repair::Declined(Refusal::NoKernelText));
    }

    // --- 3. locate every elision, writing nothing ---------------------------
    let mut sites: Vec<Site> = Vec::new();
    let mut unconditional = 0usize;
    for run in &runs {
        for (chunk_pa, chunk_va, words) in readable_chunks(mem, run) {
            let (found, unguarded) = find_elisions(&words, chunk_va);
            unconditional += unguarded.len();
            for e in found {
                sites.push(Site {
                    va: chunk_va + e.repair as u64 * 4,
                    pa: chunk_pa + e.repair as u64 * 4,
                    shape: e.shape,
                });
            }
        }
    }
    if sites.is_empty() {
        return Ok(Repair::Declined(Refusal::ElisionNotLocated));
    }

    // --- 4. verify every site, still writing nothing ------------------------
    //
    // Two independent checks per site, both of which must hold across the whole
    // set before the first byte moves. The translation check is what turns a
    // coalescing bug into a refusal rather than into a write at a plausible but
    // wrong physical address.
    for site in &sites {
        if translate(mem, root, site.va, layout.start_level) != Some(site.pa) {
            return Ok(Repair::Declined(Refusal::SiteDidNotTranslate {
                va: site.va,
            }));
        }
        let mut ok = false;
        mem.with_bytes(site.pa, 8, &mut |b| {
            let first = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let second = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            ok = match site.shape {
                // The guard word and the branch that hops the loop.
                Shape::Branch => first == ISB && decode_b(second, site.va + 4).is_some(),
                // The guard word and the return that strands the loop below it.
                Shape::EarlyReturn => first == ISB && second == RET,
            };
        });
        if !ok {
            return Ok(Repair::Declined(Refusal::SiteMoved { va: site.va }));
        }
    }

    // --- 5. write, then maintain the caches unconditionally -----------------
    let pair = [NOP, NOP];
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&pair[0].to_le_bytes());
    bytes[4..].copy_from_slice(&pair[1].to_le_bytes());

    let regions = mem.regions();
    let mut done: Vec<u64> = Vec::new();
    let mut torn = None;
    for site in &sites {
        if !mem.write_bytes(site.pa, &bytes) {
            torn = Some(TornRepair {
                written: done.len(),
                failed_at: site.pa,
            });
            break;
        }
        done.push(site.pa);
    }

    // Unconditionally, and before returning either way: this host's caches must
    // not hold the pre-repair words, and that is just as true of a torn repair
    // as of a complete one. The guest has no vCPU yet, so nothing of the
    // guest's has fetched from these pages -- but the *host* just wrote them
    // through a data mapping, and the caches are physically indexed, so this is
    // exactly the maintenance the guest's own patched-out `ic ivau` would have
    // done. Not routed through `GuestMemory::write`'s hook, which is a no-op
    // until `icache_wx` is armed and skipped entirely by `CHM_ICACHE_WX=0`;
    // neither condition may decide whether kernel text we just rewrote is
    // coherent.
    for pa in &done {
        if let Some(host) = host_va_for(&regions, *pa) {
            super::icache_wx::invalidate(host, bytes.len());
        }
    }

    match torn {
        Some(t) => Err(t),
        None => Ok(Repair::Reverted {
            sites: done.len(),
            unconditional,
        }),
    }
}

/// The host address backing a guest physical one, if any region covers it.
fn host_va_for(regions: &[(u64, usize, usize)], pa: u64) -> Option<usize> {
    regions.iter().find_map(|&(gpa, host, size)| {
        (pa >= gpa && pa < gpa + size as u64).then(|| host + (pa - gpa) as usize)
    })
}

/// Split a run into the largest spans that are actually backed, decoding each
/// into instruction words.
///
/// A run is coalesced from page descriptors, so it can legitimately span two
/// guest-RAM regions -- and reading it as one buffer would then fail entirely
/// and drop the whole run in silence. Clamping against the regions that exist
/// is what keeps that from becoming a quiet hole in the scan.
fn readable_chunks(mem: &dyn PhysMem, run: &Run) -> Vec<(u64, u64, Vec<u32>)> {
    let mut out = Vec::new();
    for (gpa, _host, size) in mem.regions() {
        let lo = run.pa.max(gpa);
        let hi = (run.pa + run.len).min(gpa + size as u64);
        if lo >= hi {
            continue;
        }
        let len = ((hi - lo) & !3) as usize;
        if len < 4 {
            continue;
        }
        let mut words = Vec::new();
        let got = mem.with_bytes(lo, len, &mut |b| {
            words = b
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
        });
        if got {
            out.push((lo, run.va + (lo - run.pa), words));
        }
    }
    out
}

/// [`PhysMem`] over the memory view the hypervisor already handed the devices.
///
/// The same host pointers the VM was created with, so a write here is a write
/// the guest will see -- and asking `GuestMemory` rather than reaching into
/// `Arc<dyn Vm>` keeps this on the one view that is already the authority on
/// where guest RAM is, the same argument `icache_regions` makes.
impl PhysMem for super::virtio::GuestMemory {
    fn regions(&self) -> Vec<(u64, usize, usize)> {
        self.icache_regions()
    }

    fn with_bytes(&self, pa: u64, len: usize, f: &mut dyn FnMut(&[u8])) -> bool {
        self.with_slice(pa, len, f).is_ok()
    }

    fn write_bytes(&self, pa: u64, bytes: &[u8]) -> bool {
        self.write(pa, bytes).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BTI_C, CTR_DIC, CTR_EL0, CTR_IDC, Captured, Elision, HOST_CTR_EL0, IC_IVAU, ISB,
        IdcVerdict, NOP, PhysMem, RET, Refusal, Repair, Run, Shape, TornRepair, captured_sysreg,
        decode_tcr, executable_runs, find_elisions, idc_elision_is_sound_here, revert_dic_elision,
        snapshot_elides_ic_ivau, translate, ttbr_base,
    };
    use crate::hvf::VcpuHvfState;
    use crate::hvf::ffi::{SYSREG_TCR_EL1, SYSREG_TTBR1_EL1};
    use crate::hvf::rehydrate::Snapshot;
    use std::cell::{Cell, RefCell};

    /// A capture with vCPUs that recorded no system registers at all.
    fn snap_with_no_sysregs() -> Snapshot {
        Snapshot {
            mem_mappings: Vec::new(),
            vcpus: vec![VcpuHvfState {
                gpr: [0; 31],
                pc: 0,
                cpsr: 0,
                sp_el1: 0,
                sysregs: Vec::new(),
                gic_icc: Vec::new(),
                fp: None,
                mp_state_running: true,
            }],
            gic_dist: Vec::new(),
            gic_rdist: Vec::new(),
            num_irq: 0,
            captured_cntfrq: None,
            captured_realtime_ns: None,
        }
    }

    /// Build a capture with one vCPU per supplied `CTR_EL0` value.
    ///
    /// Takes a slice rather than a scalar because the whole point of
    /// [`captured_sysreg`] is what happens when two vCPUs disagree, and a
    /// single-vCPU helper structurally cannot express that case.
    fn snap_with_ctrs(ctrs: &[u64]) -> Snapshot {
        let mut snap = snap_with_no_sysregs();
        snap.vcpus = ctrs
            .iter()
            .map(|&ctr| VcpuHvfState {
                gpr: [0; 31],
                pc: 0,
                cpsr: 0,
                sp_el1: 0,
                sysregs: vec![(CTR_EL0, ctr)],
                gic_icc: Vec::new(),
                fp: None,
                mp_state_running: true,
            })
            .collect();
        snap
    }

    /// The encoding needs an authority that is not the constant.
    ///
    /// [`snap_with_ctrs`] writes its sysreg id *using* `CTR_EL0`, so every
    /// other test here reads back whatever the constant happens to say and a
    /// wrong encoding is invisible -- the writer and the reader move together,
    /// which is the shape that hid #178 and #180. A capture is written by
    /// something else entirely, so the independent authority is the ARM ARM
    /// tuple `CTR_EL0` is `(op0=3, op1=3, CRn=0, CRm=0, op2=1)` and the packing
    /// `super::rehydrate` reads capture ids with.
    #[test]
    fn the_register_id_is_the_one_a_capture_actually_carries() {
        const fn encode(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> u16 {
            (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
        }
        assert_eq!(
            CTR_EL0,
            encode(3, 3, 0, 0, 1),
            "CTR_EL0 is op0=3 op1=3 CRn=0 CRm=0 op2=1; a capture that carries \
             this register carries it under that id, so reading any other one \
             makes every capture look unreadable"
        );
        // Neighbours that differ in a single field, to catch an off-by-one in
        // any one of the five rather than only in the low bits.
        for (label, other) in [
            ("CTR_EL0 with op2=0", encode(3, 3, 0, 0, 0)),
            ("DCZID_EL0 (op2=7)", encode(3, 3, 0, 0, 7)),
            ("CRm=1", encode(3, 3, 0, 1, 1)),
            ("CRn=1", encode(3, 3, 1, 0, 1)),
            ("op1=0", encode(3, 0, 0, 0, 1)),
        ] {
            assert_ne!(CTR_EL0, other, "{label} is a different register");
        }
    }

    /// The bit position is the whole guard, so pin it against the two measured
    /// values rather than trusting the shift to stay right under edits.
    #[test]
    fn the_predicate_reads_bit_29_and_not_a_neighbour() {
        let elides = |ctr: u64| snapshot_elides_ic_ivau(&snap_with_ctrs(&[ctr]));
        assert!(elides(0xb444_c004), "Graviton2 capture");
        assert!(!elides(0x9444_c004), "Apple silicon");
        // IDC (bit 28) is 1 on both, so a one-off shift would pass everything.
        assert!(elides(0x9444_c004 | (1 << 29)));
        assert!(!elides(0x9444_c004 & !(1 << 28)));
        assert!(!elides(0), "register captured as zero");
    }

    /// The three readings `.iter().any()` used to collapse into one bool.
    ///
    /// `Absent` and `Disagreed` are both "this capture cannot answer", and
    /// telling them apart from a genuine `DIC = 0` is the whole of the gate:
    /// only the last one is a capture that says there is nothing to repair.
    #[test]
    fn a_capture_that_cannot_answer_is_not_a_capture_that_says_no() {
        assert_eq!(
            captured_sysreg(&snap_with_no_sysregs(), CTR_EL0),
            Captured::Absent
        );
        assert_eq!(
            captured_sysreg(&snap_with_ctrs(&[]), CTR_EL0),
            Captured::Absent,
            "a capture with no vCPUs at all records nothing"
        );
        assert_eq!(
            captured_sysreg(&snap_with_ctrs(&[0xb444_c004, 0xb444_c004]), CTR_EL0),
            Captured::Agreed(0xb444_c004),
            "two vCPUs reporting the same value is one reading, not a conflict"
        );
        assert_eq!(
            captured_sysreg(&snap_with_ctrs(&[0xb444_c004, 0x9444_c004]), CTR_EL0),
            Captured::Disagreed,
            "cache identity is uniform on real hardware, so this capture is malformed"
        );
        // The disagreement must be found whichever vCPU is enumerated first,
        // or the verdict depends on capture order.
        assert_eq!(
            captured_sysreg(&snap_with_ctrs(&[0x9444_c004, 0xb444_c004]), CTR_EL0),
            Captured::Disagreed
        );
        // A register that is simply not the one being asked for.
        assert_eq!(
            captured_sysreg(&snap_with_ctrs(&[0xb444_c004]), 0xc038),
            Captured::Absent
        );
    }

    /// A malformed capture must not read as a clean one.
    ///
    /// The warning still answers `false` for both unreadable shapes -- it is a
    /// best-effort mitigation and silence leaves the guest no worse off. The
    /// property that matters is that the *reading* is available to tell them
    /// apart, because a repair cannot afford to guess.
    #[test]
    fn the_warning_stays_quiet_but_the_reading_stays_honest() {
        assert!(snapshot_elides_ic_ivau(&snap_with_ctrs(&[0xb444_c004])));
        assert!(!snapshot_elides_ic_ivau(&snap_with_ctrs(&[0x9444_c004])));

        for unreadable in [
            snap_with_no_sysregs(),
            snap_with_ctrs(&[0xb444_c004, 0x9444_c004]),
        ] {
            assert!(
                !snapshot_elides_ic_ivau(&unreadable),
                "an unanswerable capture must not trigger a mitigation"
            );
            assert!(
                !matches!(captured_sysreg(&unreadable, CTR_EL0), Captured::Agreed(_)),
                "...but it must still be distinguishable from a real DIC = 0"
            );
        }
    }

    /// The IDC half, against all four host/capture combinations.
    ///
    /// `0xb444c004` is the real Graviton2 capture and `0x9444c004` is this
    /// Mac, both measured. They agree on `IDC = 1` and differ only in `DIC`,
    /// which is exactly why the repair must be able to tell the two
    /// alternatives apart: reverting the IDC one on this host reintroduces
    /// maintenance the hardware does not need.
    #[test]
    fn the_idc_alternative_is_judged_against_the_live_host() {
        const GRAVITON: u64 = 0xb444_c004;
        // Read out of production, not retyped: a drift between the guard's idea
        // of this host and the test's would leave both perfectly self-consistent.
        const APPLE: u64 = HOST_CTR_EL0;
        assert_eq!(GRAVITON & CTR_IDC, CTR_IDC, "capture host is IDC coherent");
        assert_eq!(APPLE & CTR_IDC, CTR_IDC, "so is this Mac");
        assert_ne!(GRAVITON & CTR_DIC, APPLE & CTR_DIC, "DIC is the delta");

        // The shipping case: both coherent, so the elided `dc cvau` is sound
        // here for the same reason it was sound there.
        assert_eq!(
            idc_elision_is_sound_here(&snap_with_ctrs(&[GRAVITON]), APPLE),
            IdcVerdict::LeaveAlone
        );
        // A host that is not coherent makes the IDC elision as unsound as the
        // DIC one, and repairing only half would report a fixed guest.
        assert_eq!(
            idc_elision_is_sound_here(&snap_with_ctrs(&[GRAVITON]), APPLE & !CTR_IDC),
            IdcVerdict::AlsoElidedUnsoundly
        );
        // A capture whose own host said IDC = 0 never elided `dc cvau`, so
        // there is nothing there to be unsound -- even on an incoherent host.
        assert_eq!(
            idc_elision_is_sound_here(&snap_with_ctrs(&[GRAVITON & !CTR_IDC]), APPLE & !CTR_IDC),
            IdcVerdict::LeaveAlone
        );
        // Unreadable in both directions, and the reason is carried rather than
        // flattened: a repair that logs "cannot read" should say which.
        assert_eq!(
            idc_elision_is_sound_here(&snap_with_no_sysregs(), APPLE),
            IdcVerdict::Unreadable(Captured::Absent)
        );
        assert_eq!(
            idc_elision_is_sound_here(&snap_with_ctrs(&[GRAVITON, APPLE]), APPLE),
            IdcVerdict::Unreadable(Captured::Disagreed)
        );
    }

    /// The host constant is only as good as the measurement behind it, and the
    /// measurement lives in a hardware test that cannot run in this suite. Pin
    /// the two bits it is consulted for: if a future Mac disagrees,
    /// `hvf_host_cache_identity_registers` fails on hardware and this fails in
    /// the unit suite, rather than the guard quietly judging against fiction.
    #[test]
    fn the_host_constant_carries_the_bits_the_hardware_test_pins() {
        assert_eq!(
            HOST_CTR_EL0 & CTR_DIC,
            0,
            "this host does not snoop instruction fetches, which is the whole hazard"
        );
        assert_eq!(
            HOST_CTR_EL0 & CTR_IDC,
            CTR_IDC,
            "this host is data-coherent, which is why the IDC elision is left alone"
        );
    }

    // --- the repair ---------------------------------------------------------

    /// Rewrite a word once, on the `after`-th read of the address it sits at.
    ///
    /// Both of the repair's passes read the same memory through the same trait,
    /// so a fixture that is merely *wrong* is caught by the locator and never
    /// reaches the second pass at all. Moving the words **between** the passes
    /// is the only way to reach the disagreement the second pass exists to
    /// catch, and a fake that cannot express that cannot test it.
    #[derive(Debug, Clone, Copy)]
    struct Scribble {
        at: u64,
        word: u32,
        after: usize,
    }

    /// Guest RAM, as a handful of real heap buffers.
    ///
    /// The host addresses this hands out are the true addresses of its own
    /// backing buffers. The repair calls `sys_icache_invalidate` over whatever
    /// it is given, so a made-up address would be a real invalid pointer -- and
    /// handing over the truth costs nothing and exercises the real call.
    struct FakeRam {
        regions: Vec<(u64, RefCell<Vec<u8>>)>,
        refuse_write_at: Option<u64>,
        writes: Cell<usize>,
        scribble: Option<Scribble>,
        hits: Cell<usize>,
    }

    impl FakeRam {
        fn new(layout: &[(u64, usize)]) -> Self {
            Self {
                regions: layout
                    .iter()
                    .map(|&(gpa, len)| (gpa, RefCell::new(vec![0u8; len])))
                    .collect(),
                refuse_write_at: None,
                writes: Cell::new(0),
                scribble: None,
                hits: Cell::new(0),
            }
        }

        /// The region covering `pa..pa + len`, and the offset into it.
        fn find(&self, pa: u64, len: usize) -> Option<(usize, usize)> {
            self.regions
                .iter()
                .position(|(gpa, buf)| {
                    let size = buf.borrow().len() as u64;
                    pa >= *gpa && pa + len as u64 <= *gpa + size
                })
                .map(|i| (i, (pa - self.regions[i].0) as usize))
        }

        fn poke_u64(&self, pa: u64, v: u64) {
            let (i, off) = self.find(pa, 8).expect("poke inside a region");
            self.regions[i].1.borrow_mut()[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }

        fn poke_words(&self, pa: u64, words: &[u32]) {
            let (i, off) = self
                .find(pa, words.len() * 4)
                .expect("poke inside a region");
            let mut buf = self.regions[i].1.borrow_mut();
            for (n, w) in words.iter().enumerate() {
                buf[off + n * 4..off + n * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
        }

        fn word_at(&self, pa: u64) -> u32 {
            let (i, off) = self.find(pa, 4).expect("read inside a region");
            let buf = self.regions[i].1.borrow();
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        }
    }

    impl PhysMem for FakeRam {
        fn regions(&self) -> Vec<(u64, usize, usize)> {
            self.regions
                .iter()
                .map(|(gpa, buf)| {
                    let b = buf.borrow();
                    (*gpa, b.as_ptr() as usize, b.len())
                })
                .collect()
        }

        fn with_bytes(&self, pa: u64, len: usize, f: &mut dyn FnMut(&[u8])) -> bool {
            if let Some(s) = self.scribble
                && s.at == pa
            {
                let n = self.hits.get() + 1;
                self.hits.set(n);
                if n > s.after {
                    self.poke_words(s.at, &[s.word]);
                }
            }
            let Some((i, off)) = self.find(pa, len) else {
                return false;
            };
            f(&self.regions[i].1.borrow()[off..off + len]);
            true
        }

        fn write_bytes(&self, pa: u64, bytes: &[u8]) -> bool {
            if self.refuse_write_at == Some(pa) {
                return false;
            }
            let Some((i, off)) = self.find(pa, bytes.len()) else {
                return false;
            };
            self.regions[i].1.borrow_mut()[off..off + bytes.len()].copy_from_slice(bytes);
            self.writes.set(self.writes.get() + 1);
            true
        }
    }

    const R0: u64 = 0x4000_0000;
    const L0: u64 = R0;
    const L1: u64 = R0 + 0x1000;
    const L2: u64 = R0 + 0x2000;
    const L3: u64 = R0 + 0x3000;
    /// Where the fixture's first text page lives.
    const TEXT: u64 = R0 + 0x4000;
    /// `T1SZ = 16`, `TG1 = 2` (4 KiB). Four levels, starting at 0.
    const TCR_48BIT_4K: u64 = (16 << 16) | (2 << 30);
    /// The kernel virtual address the fixture maps its first text page at.
    const KVA: u64 = 0xFFFF_8000_0000_0000;
    /// A capture from a host that elided, derived rather than retyped: the one
    /// bit that differs from this Mac is `DIC`, which is the whole hazard.
    const GRAVITON_CTR: u64 = HOST_CTR_EL0 | CTR_DIC;

    /// A four-level 4 KiB page table mapping `KVA` onwards at `TEXT` onwards.
    ///
    /// Descriptors are written as literals rather than through anything the
    /// walker owns, so the fixture is an independent statement of the encoding
    /// rather than an echo of the code under test.
    ///
    /// `split_at` cuts guest RAM into two regions at that physical address,
    /// which is how a run that legitimately spans two regions is expressed.
    fn fixture(pages: &[bool], split_at: Option<u64>) -> FakeRam {
        let total = 0x4000 + pages.len() * 0x1000;
        let ram = match split_at {
            None => FakeRam::new(&[(R0, total)]),
            Some(at) => {
                let first = (at - R0) as usize;
                FakeRam::new(&[(R0, first), (at, total - first)])
            }
        };
        // Index 256 at level 0 is what puts bit 47 on, and bit 47 is what the
        // walk sign-extends back into the top half. Any other index produces a
        // fixture whose addresses never reach the half TTBR1 describes.
        ram.poke_u64(L0 + 256 * 8, L1 | 0b11);
        ram.poke_u64(L1, L2 | 0b11);
        ram.poke_u64(L2, L3 | 0b11);
        for (i, &executable) in pages.iter().enumerate() {
            let pxn = if executable { 0 } else { 1u64 << 53 };
            ram.poke_u64(L3 + i as u64 * 8, (TEXT + i as u64 * 0x1000) | pxn | 0b11);
        }
        ram
    }

    /// A capture that can be read all the way to a page table.
    ///
    /// The ASID and `CnP` bits are set deliberately: `ttbr_base` has to strip
    /// them, and a fixture that never sets them cannot tell whether it does.
    fn snap_for_repair(ctr: u64, tcr: u64, ttbr1: Option<u64>) -> Snapshot {
        let mut snap = snap_with_no_sysregs();
        let mut regs = vec![(CTR_EL0, ctr), (SYSREG_TCR_EL1, tcr)];
        if let Some(t) = ttbr1 {
            regs.push((SYSREG_TTBR1_EL1, t));
        }
        snap.vcpus[0].sysregs = regs;
        snap
    }

    /// The capture the fixture describes: readable, elided, and pointing at
    /// `L0` through a `TTBR1_EL1` that carries an ASID and `CnP`.
    fn graviton_snap() -> Snapshot {
        snap_for_repair(GRAVITON_CTR, TCR_48BIT_4K, Some((0x25u64 << 48) | L0 | 1))
    }

    /// S1: a guard word, then a branch that hops clean over the `ic ivau`.
    ///
    /// The branch is a literal rather than `B_OPC | 15`, so the encoding's
    /// authority is the ARM ARM rather than the module's own constant.
    fn branch_shape() -> Vec<u32> {
        let mut w = vec![NOP; 32];
        w[10] = ISB;
        w[11] = 0x1400_0000 | 15; // b .+60, from word 11 to word 26
        w[20] = IC_IVAU | 3; // ic ivau, x3 -- the real capture's encoding
        w
    }

    /// S2: a routine whose whole body became the guard word and a return,
    /// stranding the maintenance loop below it.
    fn early_return_shape() -> Vec<u32> {
        let mut w = vec![NOP; 32];
        w[10] = BTI_C;
        w[11] = ISB;
        w[12] = RET;
        w[20] = IC_IVAU | 3;
        w
    }

    /// Run the repair against a fixture holding `words` at its first text page.
    fn repair_over(words: &[u32]) -> (FakeRam, Result<Repair, TornRepair>) {
        let ram = fixture(&[true], None);
        ram.poke_words(TEXT, words);
        let out = revert_dic_elision(&ram, &graviton_snap(), HOST_CTR_EL0);
        (ram, out)
    }

    /// The page table needs an authority that is not the walker.
    ///
    /// Every other walk test here reads back a table [`fixture`] wrote, so a
    /// fixture and a walker that are wrong the same way agree perfectly. This
    /// one asserts that hand-written descriptor bits mean what the ARM ARM says
    /// they mean, which is the only claim the rest of them rest on.
    #[test]
    fn a_hand_built_page_table_translates_to_the_address_it_encodes() {
        let ram = FakeRam::new(&[(R0, 0x6000)]);
        ram.poke_u64(L0 + 256 * 8, L1 | 0b11);
        ram.poke_u64(L1, L2 | 0b11);
        ram.poke_u64(L2, L3 | 0b11);
        ram.poke_u64(L3, TEXT | 0b11);

        let layout = decode_tcr(TCR_48BIT_4K).expect("4 KiB, 48-bit");
        assert_eq!(layout.va_bits, 48);
        assert_eq!(layout.granule, 4096);
        assert_eq!(layout.start_level, 0);

        let root = ttbr_base((0x25u64 << 48) | L0 | 1);
        assert_eq!(
            root, L0,
            "the ASID and CnP bits are not part of the address"
        );

        assert_eq!(translate(&ram, root, KVA, 0), Some(TEXT));
        assert_eq!(translate(&ram, root, KVA + 0x40, 0), Some(TEXT + 0x40));
        assert_eq!(
            translate(&ram, root, KVA + 0x1000, 0),
            None,
            "only one page was mapped"
        );
    }

    #[test]
    fn the_walk_reports_only_pages_that_are_executable_at_el1() {
        let ram = fixture(&[true, false, true], None);
        let runs = executable_runs(&ram, L0, 48, 0).expect("a small tree");
        assert_eq!(
            runs,
            vec![
                Run {
                    va: KVA,
                    pa: TEXT,
                    len: 0x1000
                },
                Run {
                    va: KVA + 0x2000,
                    pa: TEXT + 0x2000,
                    len: 0x1000
                },
            ],
            "a walk testing UXN instead of PXN cannot produce this shape"
        );
    }

    #[test]
    fn adjacent_executable_pages_coalesce_into_one_run() {
        let ram = fixture(&[true, true, true], None);
        assert_eq!(
            executable_runs(&ram, L0, 48, 0).expect("a small tree"),
            vec![Run {
                va: KVA,
                pa: TEXT,
                len: 0x3000
            }]
        );
    }

    #[test]
    fn a_reserved_level_three_descriptor_is_not_a_page() {
        let ram = fixture(&[true], None);
        ram.poke_u64(L3, TEXT | 0b01);
        assert_eq!(translate(&ram, L0, KVA, 0), None);
        assert_eq!(
            executable_runs(&ram, L0, 48, 0).expect("a small tree"),
            vec![]
        );
    }

    /// A cycle is *not* the hazard, and this test says so in both directions.
    ///
    /// The first half is the disproof: the walk's level counter rises on every
    /// descent and `lvl == 3` is a leaf, so a table pointing at itself
    /// terminates as a page rather than spinning. An earlier draft of
    /// [`MAX_TABLES`]'s own comment claimed otherwise, and this is what
    /// corrected it. The second half is the real bound -- breadth. Every
    /// level-1 entry fans out to the same level-2 table and every level-2 entry
    /// to the same level-3 table, which no kernel mapping looks like and which
    /// costs 262,144 visits to walk. The level-3 entries are left invalid so
    /// that no text accumulates and [`MAX_TEXT_BYTES`] cannot fire first,
    /// making this a test of one bound rather than of whichever trips sooner.
    #[test]
    fn a_tree_too_broad_to_be_a_kernels_is_refused_rather_than_walked() {
        let cyclic = FakeRam::new(&[(R0, 0x2000)]);
        cyclic.poke_u64(L0 + 256 * 8, L1 | 0b11);
        cyclic.poke_u64(L1, L1 | 0b11);
        assert_eq!(
            executable_runs(&cyclic, L0, 48, 0),
            Ok(vec![Run {
                va: KVA,
                pa: L1,
                len: 0x1000
            }]),
            "a cycle bottoms out at level 3 rather than spinning"
        );

        let broad = FakeRam::new(&[(R0, 0x4000)]);
        broad.poke_u64(L0 + 256 * 8, L1 | 0b11);
        for i in 0..512u64 {
            broad.poke_u64(L1 + i * 8, L2 | 0b11);
            broad.poke_u64(L2 + i * 8, L3 | 0b11);
            broad.poke_u64(L3 + i * 8, 0);
        }
        assert_eq!(
            executable_runs(&broad, L0, 48, 0),
            Err(Refusal::WalkTooLarge),
            "an unbounded walk here is a hang during VM creation"
        );
    }

    #[test]
    fn the_locator_does_not_depend_on_where_the_text_is_mapped() {
        let words = branch_shape();
        let here = find_elisions(&words, 0);
        assert_eq!(
            here.0,
            vec![Elision {
                repair: 10,
                op: 20,
                shape: Shape::Branch
            }]
        );
        assert_eq!(here, find_elisions(&words, KVA));
        assert_eq!(here, find_elisions(&words, 0xFFFF_FFFF_8000_1000));
    }

    #[test]
    fn both_elision_shapes_are_located() {
        let (found, unexplained) = find_elisions(&branch_shape(), KVA);
        assert_eq!(
            found,
            vec![Elision {
                repair: 10,
                op: 20,
                shape: Shape::Branch
            }]
        );
        assert!(unexplained.is_empty());

        let (found, unexplained) = find_elisions(&early_return_shape(), KVA);
        assert_eq!(
            found,
            vec![Elision {
                repair: 11,
                op: 20,
                shape: Shape::EarlyReturn
            }],
            "S1 must not claim this one: its only ISB is followed by a `ret`"
        );
        assert!(unexplained.is_empty());
    }

    #[test]
    fn an_unconditional_ic_ivau_is_counted_and_does_not_block() {
        let mut words = branch_shape();
        words.resize(256, NOP);
        words[200] = IC_IVAU | 3; // no alternative anywhere within the lookback

        let (found, unexplained) = find_elisions(&words, KVA);
        assert_eq!(found.len(), 1);
        assert_eq!(unexplained, vec![200]);

        let (ram, out) = repair_over(&words);
        assert_eq!(
            out,
            Ok(Repair::Reverted {
                sites: 1,
                unconditional: 1
            }),
            "an `ic ivau` that was never guarded has nothing to revert"
        );
        assert_eq!(
            ram.word_at(TEXT + 200 * 4),
            IC_IVAU | 3,
            "and so must be left exactly where it is"
        );
    }

    #[test]
    fn a_run_that_straddles_two_regions_is_still_scanned_whole() {
        let ram = fixture(&[true; 4], Some(0x4000_6000));
        assert_eq!(
            executable_runs(&ram, L0, 48, 0).expect("a small tree"),
            vec![Run {
                va: KVA,
                pa: TEXT,
                len: 0x4000
            }],
            "the run coalesces across the region boundary"
        );
        // The elision sits in the *second* region. Reading the run as one
        // buffer fails, so without clamping this is a silent hole.
        ram.poke_words(0x4000_6000, &branch_shape());

        let out = revert_dic_elision(&ram, &graviton_snap(), HOST_CTR_EL0);
        assert_eq!(
            out,
            Ok(Repair::Reverted {
                sites: 1,
                unconditional: 0
            })
        );
        assert_eq!(ram.word_at(0x4000_6000 + 40), NOP);
        assert_eq!(ram.word_at(0x4000_6000 + 44), NOP);
    }

    #[test]
    fn a_capture_that_does_not_elide_is_left_alone() {
        let ram = fixture(&[true], None);
        ram.poke_words(TEXT, &branch_shape());
        let snap = snap_for_repair(HOST_CTR_EL0, TCR_48BIT_4K, Some(L0));
        assert_eq!(
            revert_dic_elision(&ram, &snap, HOST_CTR_EL0),
            Ok(Repair::NotElided),
            "a cold-booted guest reaches here by reading this Mac's own register"
        );
        assert_eq!(ram.writes.get(), 0);
        assert_eq!(ram.word_at(TEXT + 40), ISB);
    }

    #[test]
    fn the_repair_writes_two_nops_at_the_guard_word() {
        let (ram, out) = repair_over(&branch_shape());
        assert_eq!(
            out,
            Ok(Repair::Reverted {
                sites: 1,
                unconditional: 0
            })
        );
        assert_eq!(ram.writes.get(), 1);
        assert_eq!(ram.word_at(TEXT + 40), NOP, "the guard word");
        assert_eq!(ram.word_at(TEXT + 44), NOP, "the branch over the loop");
        assert_eq!(
            ram.word_at(TEXT + 80),
            IC_IVAU | 3,
            "the maintenance itself was never patched out of the text"
        );
        assert_eq!(ram.word_at(TEXT + 36), NOP);

        let (ram, out) = repair_over(&early_return_shape());
        assert_eq!(
            out,
            Ok(Repair::Reverted {
                sites: 1,
                unconditional: 0
            })
        );
        assert_eq!(
            ram.word_at(TEXT + 40),
            BTI_C,
            "the landing pad is not part of the pair and must survive"
        );
        assert_eq!(ram.word_at(TEXT + 44), NOP, "the guard word");
        assert_eq!(ram.word_at(TEXT + 48), NOP, "the return that stranded it");
        assert_eq!(ram.word_at(TEXT + 80), IC_IVAU | 3);
    }

    #[test]
    fn a_site_whose_words_moved_is_refused() {
        let ram = fixture(&[true], None);
        ram.poke_words(TEXT, &branch_shape());
        // The locator reads the whole run in one go; only the verifier reads
        // exactly these eight bytes, so this lands between the two passes.
        let ram = FakeRam {
            scribble: Some(Scribble {
                at: TEXT + 40,
                word: NOP,
                after: 0,
            }),
            ..ram
        };

        assert_eq!(
            revert_dic_elision(&ram, &graviton_snap(), HOST_CTR_EL0),
            Ok(Repair::Declined(Refusal::SiteMoved { va: KVA + 40 })),
        );
        assert_eq!(ram.writes.get(), 0);
    }

    #[test]
    fn a_site_that_does_not_translate_where_its_run_claims_is_refused() {
        let ram = fixture(&[true], None);
        ram.poke_words(TEXT, &branch_shape());
        // The walk reads this descriptor once; the verifier's independent
        // translation of the site reads it again. Unmapping it in between is a
        // coalescing bug's shape without having to write one.
        let ram = FakeRam {
            scribble: Some(Scribble {
                at: L3,
                word: 0,
                after: 1,
            }),
            ..ram
        };

        assert_eq!(
            revert_dic_elision(&ram, &graviton_snap(), HOST_CTR_EL0),
            Ok(Repair::Declined(Refusal::SiteDidNotTranslate {
                va: KVA + 40
            })),
        );
        assert_eq!(ram.writes.get(), 0);
    }

    #[test]
    fn a_write_that_fails_midway_reports_a_torn_repair() {
        let ram = fixture(&[true, true], None);
        ram.poke_words(TEXT, &branch_shape());
        ram.poke_words(TEXT + 0x1000, &branch_shape());
        let second = TEXT + 0x1000 + 40;
        let ram = FakeRam {
            refuse_write_at: Some(second),
            ..ram
        };

        assert_eq!(
            revert_dic_elision(&ram, &graviton_snap(), HOST_CTR_EL0),
            Err(TornRepair {
                written: 1,
                failed_at: second
            }),
            "there is no way back from a half-repaired maintenance routine"
        );
        assert_eq!(ram.writes.get(), 1);
        assert_eq!(ram.word_at(TEXT + 40), NOP, "the first site did land");
        assert_eq!(ram.word_at(second), ISB, "and the second did not");
    }

    #[test]
    fn a_reserved_or_unsupported_granule_is_named_rather_than_guessed() {
        assert_eq!(
            decode_tcr(16 << 16),
            Err(Refusal::ReservedGranule(0)),
            "TG1 does not use TG0's encoding, where 0 means 4 KiB"
        );
        assert_eq!(
            decode_tcr((16 << 16) | (1 << 30)),
            Err(Refusal::UnsupportedGranule(16384))
        );
        assert_eq!(
            decode_tcr((16 << 16) | (3 << 30)),
            Err(Refusal::UnsupportedGranule(65536))
        );
    }

    #[test]
    fn every_refusal_writes_nothing() {
        // Each row is a capture or a guest that the repair must decline, and
        // the property under test is the same for all of them: declining is
        // never a partial write. A guest left exactly as its capture describes
        // it is where every guest was before this existed.
        let cases: Vec<(&str, Snapshot, FakeRam, Refusal)> = vec![
            (
                "no vCPU recorded CTR_EL0",
                snap_with_no_sysregs(),
                fixture(&[true], None),
                Refusal::UnreadableCacheIdentity(Captured::Absent),
            ),
            (
                "the vCPUs disagree about CTR_EL0",
                snap_with_ctrs(&[GRAVITON_CTR, HOST_CTR_EL0]),
                fixture(&[true], None),
                Refusal::UnreadableCacheIdentity(Captured::Disagreed),
            ),
            (
                "TCR_EL1 is absent",
                {
                    let mut s = snap_with_no_sysregs();
                    s.vcpus[0].sysregs = vec![(CTR_EL0, GRAVITON_CTR)];
                    s
                },
                fixture(&[true], None),
                Refusal::UnreadableTranslationControl(Captured::Absent),
            ),
            (
                "TTBR1_EL1 is absent",
                snap_for_repair(GRAVITON_CTR, TCR_48BIT_4K, None),
                fixture(&[true], None),
                Refusal::UnreadableTtbr1(Captured::Absent),
            ),
            (
                "TCR_EL1.TG1 is reserved",
                snap_for_repair(GRAVITON_CTR, 16 << 16, Some(L0)),
                fixture(&[true], None),
                Refusal::ReservedGranule(0),
            ),
            (
                "the granule is 64 KiB",
                snap_for_repair(GRAVITON_CTR, (16 << 16) | (3 << 30), Some(L0)),
                fixture(&[true], None),
                Refusal::UnsupportedGranule(65536),
            ),
            (
                "nothing is executable at EL1",
                graviton_snap(),
                fixture(&[false], None),
                Refusal::NoKernelText,
            ),
            (
                "the text holds no elision to revert",
                graviton_snap(),
                fixture(&[true], None),
                Refusal::ElisionNotLocated,
            ),
        ];

        for (why, snap, ram, want) in cases {
            assert_eq!(
                revert_dic_elision(&ram, &snap, HOST_CTR_EL0),
                Ok(Repair::Declined(want)),
                "{why}"
            );
            assert_eq!(ram.writes.get(), 0, "{why}: declining wrote to guest RAM");
        }
    }

    #[test]
    fn a_host_that_is_not_data_coherent_declines_rather_than_half_repairing() {
        let ram = fixture(&[true], None);
        ram.poke_words(TEXT, &branch_shape());
        // A host whose caches are not coherent to the point of unification
        // needs the `dc cvau` half reverted too, and this repair does not do
        // that. Repairing only the DIC half produces a guest that is
        // half-correct and reported as fixed.
        let host = HOST_CTR_EL0 & !CTR_IDC;

        assert_eq!(
            revert_dic_elision(&ram, &graviton_snap(), host),
            Ok(Repair::Declined(Refusal::IdcAlsoUnsound))
        );
        assert_eq!(ram.writes.get(), 0);
    }

    /// Every restore entry point calls the repair, and a new one cannot forget.
    ///
    /// Mutating a function is not mutating its call site, and this repository
    /// has now shipped that mistake ten times: a repair whose call site is
    /// deleted leaves every test in this module green, because they all reach
    /// [`revert_dic_elision`] directly. The stronger half of this guard is the
    /// equality rather than the count -- adding a fourth `prepare_*` entry
    /// point to `rehydrate.rs` without wiring the repair into it fires here,
    /// which is the failure that actually costs a user a broken guest.
    ///
    /// Cold boot is deliberately outside this file: a cold-booted guest reads
    /// this Mac's own `CTR_EL0`, sees `DIC = 0` and keeps its `ic ivau`, so
    /// there is nothing to revert. `prepare_cold_usgic_vm` lives in
    /// `chm/src/create.rs` and is not counted here.
    #[test]
    fn every_restore_entry_point_repairs_before_a_vcpu_exists() {
        let rehydrate = include_str!("rehydrate.rs");
        // Assembled from parts: a needle written whole matches the assertion
        // text that carries it, and then reports safety it does not provide.
        let call = format!("{}(&guest_mem, snap)?;", "repair_dic_elision");
        let entry = format!("pub fn {}_", "prepare");

        let calls = rehydrate.matches(call.as_str()).count();
        let entries = rehydrate.matches(entry.as_str()).count();

        assert!(entries > 0, "the entry points moved out of rehydrate.rs");
        assert_eq!(
            calls, entries,
            "{entries} restore entry point(s) in rehydrate.rs but {calls} call(s) \
             to the DIC repair; a capture that elides `ic ivau` would rehydrate \
             with stale kernel text and no test would notice"
        );
    }

    /// A guard word followed by a branch is not, on its own, an elision.
    ///
    /// The locator's branch shape has two halves and only one of them carries
    /// weight. `j + 1 < op` is defence in depth: `j` stops at `op - 1`, where
    /// the word handed to [`decode_b`] is the `ic ivau` itself and is not a
    /// `b`. **`op < t` is the load-bearing half** -- it is what requires the
    /// branch to jump *over* the maintenance loop rather than merely somewhere
    /// forward, and dropping it left every other test in this module green.
    ///
    /// The direction that matters is the false positive, not the miss. Linux's
    /// cache-maintenance routines are full of `isb` followed by an ordinary
    /// short hop; accepting one of those as an elision writes two `nop`s over
    /// live kernel text at a plausible-looking address. So the third case here
    /// is the important one: a routine with no elision at all must come back
    /// with nothing to repair, not with a site.
    #[test]
    fn a_branch_that_does_not_clear_the_op_is_not_an_elision() {
        // From word 16, `b .+8` lands on word 18 -- forward, but short of the
        // `ic ivau` at word 20, so the loop below it still runs.
        let short_hop = 0x1400_0000 | 2;
        // From word 16, `b .-44` lands on word 5. Backwards, so it cannot
        // reach the op at all; this also exercises `decode_b`'s sign handling
        // through the locator rather than only through its own unit test.
        let backwards = 0x1400_0000 | ((-11i32 as u32) & 0x03FF_FFFF);

        for (name, hop) in [("short forward", short_hop), ("backwards", backwards)] {
            // The decoy sits *nearer* the op than the real elision, so the
            // descending scan reaches it first and a locator missing the
            // `op < t` test stops there.
            let mut words = branch_shape();
            words[15] = ISB;
            words[16] = hop;

            let (found, unexplained) = find_elisions(&words, KVA);
            assert_eq!(
                found,
                vec![Elision {
                    repair: 10,
                    op: 20,
                    shape: Shape::Branch
                }],
                "the {name} decoy at word 15 was taken for the elision at word 10"
            );
            assert!(unexplained.is_empty());

            // And on its own, with no real elision anywhere in the lookback,
            // it must be reported as unexplained rather than repaired.
            let mut alone = vec![NOP; 32];
            alone[15] = ISB;
            alone[16] = hop;
            alone[20] = IC_IVAU | 3;

            let (found, unexplained) = find_elisions(&alone, KVA);
            assert!(
                found.is_empty(),
                "a {name} branch was accepted as an elision, so the repair \
                 would write two `nop`s over live kernel text at word 15"
            );
            assert_eq!(unexplained, vec![20]);

            // The driver must reach the same conclusion, not merely the
            // locator: an unexplained `ic ivau` is counted and written past.
            let (ram, out) = repair_over(&alone);
            assert_eq!(
                out,
                Ok(Repair::Declined(Refusal::ElisionNotLocated)),
                "the {name} case reached the writer"
            );
            for (n, want) in alone.iter().enumerate() {
                assert_eq!(
                    ram.word_at(TEXT + n as u64 * 4),
                    *want,
                    "{name}: word {n} moved under a refusal"
                );
            }
        }
    }
}
