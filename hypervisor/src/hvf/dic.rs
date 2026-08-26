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

#[cfg(test)]
mod tests {
    use super::{
        CTR_DIC, CTR_EL0, CTR_IDC, Captured, HOST_CTR_EL0, IdcVerdict, captured_sysreg,
        idc_elision_is_sound_here, snapshot_elides_ic_ivau,
    };
    use crate::hvf::VcpuHvfState;
    use crate::hvf::rehydrate::Snapshot;

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
}
