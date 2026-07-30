// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Live VM checkpoints: read a running guest's architectural state back out so
//! it can be suspended to disk and later resumed (restored, not cold-booted).
//!
//! This is the symmetric *capture* half of [`super::rehydrate`]'s *restore*. The
//! cold path translates a cloud-hypervisor KVM snapshot into HVF form and writes
//! it into a fresh VM; a checkpoint instead reads the live VM's state directly,
//! in HVF-native form, so resume reuses the same Apple per-register apply path
//! without round-tripping through the KVM dump encoding.
//!
//! What a checkpoint captures (the runtime-mutable state):
//!   * each vCPU's architectural registers ([`super::VcpuHvfState`]) plus a live
//!     `CNTVCT_EL0` read so the virtual timer keeps continuity on resume;
//!   * each vCPU's GIC redistributor (SGI-frame) registers — pending/active/
//!     enabled per-CPU interrupts;
//!   * the global GIC distributor registers — SPI pending/active/enable/route.
//!
//! What it deliberately does NOT capture (invariant after boot, carried from the
//! parent snapshot's `state.json`): virtio queue addresses, negotiated features,
//! MSI-X vectors, and the serial line registers. Guest RAM and the disk overlay
//! are stored as separate files by the `chm` checkpoint writer.
//!
//! All capture/apply that touches a vCPU MUST run on that vCPU's owning host
//! thread — HVF binds a vCPU to its creating thread — exactly like
//! [`super::rehydrate::restore_vcpu_state`].

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::CpuState;
use crate::arch::aarch64::gic::Vgic;
use crate::cpu::Vcpu;
use crate::hvf::ffi::SYSREG_CNTVCT_EL0;
use crate::hvf::gic::HvfGicV3;
use crate::hvf::translate::gic_ingest;
use crate::hvf::{HvfVcpu, VcpuHvfState};

/// The current on-disk checkpoint format version. Bumped on any breaking change
/// to [`CheckpointState`] so a resume can refuse an incompatible checkpoint.
pub const CHECKPOINT_VERSION: u32 = 1;

/// GICD active-interrupt register window (`GICD_ISACTIVER`/`GICD_ICACTIVER`),
/// skipped on apply to match [`super::rehydrate::restore_distributor`].
const GICD_ACTIVE_RANGE: std::ops::Range<u32> = 0x300..0x400;

/// One vCPU's live-captured state: its full architectural register file (with
/// `CNTVCT_EL0` appended) and its SGI-frame redistributor registers as
/// `(offset, value)` pairs ready for `hv_gic_set_redistributor_reg`.
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuCheckpoint {
    pub state: VcpuHvfState,
    pub rdist: Vec<(u32, u64)>,
}

/// A full live VM checkpoint's hardware state. Guest RAM and disk overlays live
/// in sibling files; this is the small, structured part.
///
/// Multi-vCPU aware: [`Self::vcpus`] and [`Self::usgic_cpus`] are both indexed
/// by vCPU id. Use [`Self::usgic_for`] rather than reading the userspace-GIC
/// fields directly, so pre-SMP checkpoints keep resuming.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CheckpointState {
    /// Format version ([`CHECKPOINT_VERSION`]).
    pub version: u32,
    /// Per-vCPU captured state, index == vCPU id.
    pub vcpus: Vec<VcpuCheckpoint>,
    /// Global GIC distributor registers as `(offset, value)` pairs.
    pub gic_dist: Vec<(u32, u64)>,
    /// Interrupt-line width the GIC was built with (carried from the parent
    /// snapshot so the distributor offset walk matches on resume).
    pub num_irq: u32,
    /// Userspace-GIC live state for vCPU 0, when this checkpoint was taken on
    /// the software GICv3 path (M-USGIC). `None` on the managed-GIC path, where
    /// `gic_dist` + the per-vCPU `rdist` carry the interrupt state instead. Kept
    /// `#[serde(default)]` so a managed checkpoint (which never emits it) still
    /// deserializes, and an older reader ignores it.
    ///
    /// Retained alongside [`Self::usgic_cpus`] as the compatibility view: a
    /// checkpoint written before SMP capture existed carries only this field,
    /// and a reader that predates `usgic_cpus` still finds vCPU 0 here. Prefer
    /// [`Self::usgic_for`] over reading either field directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usgic: Option<UsgicCheckpoint>,
    /// Per-vCPU userspace-GIC live state, index == vCPU id.
    ///
    /// [`UsgicCheckpoint`] mixes one VM-global model (the distributor) with
    /// three per-vCPU ones (redistributor, pending, active), so a single
    /// `usgic` can only ever describe a single-vCPU guest. Restoring vCPU 0's
    /// redistributor onto every core would hand each of them the boot CPU's
    /// PPI configuration and its in-flight interrupts.
    ///
    /// Empty on the managed path and on pre-SMP checkpoints, which is what makes
    /// this additive: [`Self::usgic_for`] falls back to `usgic` for vCPU 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usgic_cpus: Vec<UsgicCheckpoint>,
}

/// The live software-GIC state for one userspace-GIC vCPU (M-USGIC). The managed
/// path reads its GIC state back through `hv_gic_*`; the software path instead
/// owns the whole GICv3 model in userspace, so a checkpoint serializes those
/// models directly — losslessly, unlike round-tripping through the MMIO register
/// read view (which cannot observe write-only/derived fields like ICFGR).
#[derive(Clone, Serialize, Deserialize)]
pub struct UsgicCheckpoint {
    /// The VM-global distributor model (SPI enable/priority/group/config/route).
    pub dist: super::softgic::Distributor,
    /// This vCPU's redistributor model (SGI/PPI frame + LPI control registers).
    pub redist: super::softgic::Redistributor,
    /// INTIDs pending delivery at capture (drained FIFO on resume).
    pub pending: Vec<u32>,
    /// The INTID acknowledged but not yet EOId at capture, if any.
    pub active: Option<u32>,
}

impl CheckpointState {
    /// This checkpoint's userspace-GIC state for vCPU `id`, or `None` if it does
    /// not describe that vCPU.
    ///
    /// Prefers the per-vCPU [`Self::usgic_cpus`] and falls back to the legacy
    /// single [`Self::usgic`] for vCPU 0 — which is what lets a checkpoint
    /// written before SMP capture existed still resume, while refusing to hand
    /// vCPU 0's redistributor to a secondary core.
    pub fn usgic_for(&self, id: usize) -> Option<&UsgicCheckpoint> {
        if !self.usgic_cpus.is_empty() {
            return self.usgic_cpus.get(id);
        }
        if id == 0 { self.usgic.as_ref() } else { None }
    }

    /// Whether this is a userspace-GIC checkpoint that fully describes an
    /// `expected`-vCPU guest.
    ///
    /// A checkpoint that covers fewer vCPUs than the snapshot declares cannot be
    /// resumed: [`super::rehydrate::restore_usgic_vcpu`] indexes
    /// [`Self::vcpus`] by id, so a short one would panic. Callers check this
    /// before accepting a checkpoint and cold-boot instead when it fails.
    pub fn covers_usgic_vcpus(&self, expected: usize) -> bool {
        self.vcpus.len() >= expected && (0..expected).all(|id| self.usgic_for(id).is_some())
    }

    /// The shared virtual-counter reference (vCPU0's captured `CNTVCT_EL0`) used
    /// to re-seed every vCPU's timer offset on resume, mirroring
    /// [`super::rehydrate::Snapshot::reference_cntvct`].
    pub fn reference_cntvct(&self) -> Option<u64> {
        self.vcpus
            .first()?
            .state
            .sysregs
            .iter()
            .find(|(id, _)| *id == SYSREG_CNTVCT_EL0)
            .map(|(_, v)| *v)
    }
}

/// Capture one vCPU's live state. MUST run on the vCPU's owning host thread.
pub fn capture_vcpu(vcpu: &mut Box<dyn Vcpu>) -> anyhow::Result<VcpuCheckpoint> {
    let concrete = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .ok_or_else(|| anyhow!("vCPU is not an HVF vCPU"))?;
    concrete
        .capture_checkpoint()
        .map_err(|e| anyhow!("capture vCPU: {e}"))
}

/// Capture a userspace-GIC vCPU: its register file (with `CNTVCT_EL0` and the
/// software CPU-interface bookkeeping folded into `gic_icc`) plus the software
/// distributor/redistributor models and in-flight interrupt state. Unlike
/// [`capture_vcpu`], this does NOT read a managed redistributor (there is none),
/// so it works on the GIC-less software path. MUST run on the vCPU's owning host
/// thread.
pub fn capture_usgic_vcpu(
    vcpu: &mut Box<dyn Vcpu>,
) -> anyhow::Result<(VcpuCheckpoint, UsgicCheckpoint)> {
    let concrete = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .ok_or_else(|| anyhow!("vCPU is not an HVF vCPU"))?;
    concrete
        .capture_usgic_checkpoint()
        .map_err(|e| anyhow!("capture userspace-GIC vCPU: {e}"))
}

/// Capture the global GIC distributor. Safe to call from the orchestrator thread
/// once every vCPU is paused (the distributor is VM-global, not vCPU-bound).
pub fn capture_distributor(
    gic: &Arc<Mutex<dyn Vgic>>,
    num_irq: u32,
) -> anyhow::Result<Vec<(u32, u64)>> {
    let mut guard = gic.lock().unwrap();
    let concrete = guard
        .as_any_concrete_mut()
        .downcast_mut::<HvfGicV3>()
        .ok_or_else(|| anyhow!("GIC is not an HVF GIC"))?;
    let mut out = Vec::new();
    for off in gic_ingest::dist_capture_offsets(num_irq) {
        let val = concrete
            .distributor_reg(off)
            .map_err(|e| anyhow!("get GICD[{off:#x}]: {e}"))?;
        out.push((off, val));
    }
    Ok(out)
}

/// Capture a full checkpoint from a set of paused vCPUs plus the GIC, all on the
/// current thread. This is the single-threaded capture path (the daemon creates
/// and runs its vCPUs on one thread); the SMP interactive path instead captures
/// each vCPU on its own owning thread and assembles the result. Every vCPU MUST
/// be paused before calling.
pub fn capture_all(
    vcpus: &mut [Box<dyn Vcpu>],
    gic: &Arc<Mutex<dyn Vgic>>,
    num_irq: u32,
) -> anyhow::Result<CheckpointState> {
    let mut out = Vec::with_capacity(vcpus.len());
    for vcpu in vcpus.iter_mut() {
        out.push(capture_vcpu(vcpu)?);
    }
    let gic_dist = capture_distributor(gic, num_irq)?;
    Ok(CheckpointState {
        version: CHECKPOINT_VERSION,
        vcpus: out,
        gic_dist,
        num_irq,
        usgic: None,
        usgic_cpus: Vec::new(),
    })
}

/// Apply a captured distributor onto a fresh VM's GIC, skipping the active
/// registers (same as the cold restore — the CPU-interface active-priority
/// state restored via `set_state` performs the EOI priority drop instead).
pub fn apply_distributor(
    gic: &Arc<Mutex<dyn Vgic>>,
    dist: &[(u32, u64)],
) -> anyhow::Result<()> {
    let mut guard = gic.lock().unwrap();
    let concrete = guard
        .as_any_concrete_mut()
        .downcast_mut::<HvfGicV3>()
        .ok_or_else(|| anyhow!("GIC is not an HVF GIC"))?;
    for &(off, val) in dist {
        if GICD_ACTIVE_RANGE.contains(&off) {
            continue;
        }
        concrete
            .set_distributor_reg(off, val)
            .map_err(|e| anyhow!("set GICD[{off:#x}]: {e}"))?;
    }
    Ok(())
}

/// Apply one vCPU's captured state onto a fresh VM's vCPU. MUST run on the
/// vCPU's owning host thread, after the distributor is applied (so the
/// redistributor exists). Mirrors [`super::rehydrate::restore_vcpu_state`].
pub fn apply_vcpu(
    vcpu: &mut Box<dyn Vcpu>,
    cp: &VcpuCheckpoint,
    reference_cntvct: Option<u64>,
) -> anyhow::Result<()> {
    vcpu.set_state(&CpuState::Hvf(cp.state.clone()))
        .map_err(|e| anyhow!("restore vCPU state: {e}"))?;
    let concrete = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .ok_or_else(|| anyhow!("vCPU is not an HVF vCPU"))?;
    for &(off, val) in &cp.rdist {
        concrete
            .set_redistributor_reg(off, val)
            .map_err(|e| anyhow!("set GICR[{off:#x}]: {e}"))?;
    }
    if let Some(reference) = reference_cntvct {
        concrete
            .restore_vtimer_offset(reference)
            .map_err(|e| anyhow!("reseed vtimer offset: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_cntvct_reads_vcpu0_counter() {
        let mut cp = CheckpointState {
            version: CHECKPOINT_VERSION,
            num_irq: 64,
            ..Default::default()
        };
        let mut state = VcpuHvfState::default();
        state.sysregs.push((SYSREG_CNTVCT_EL0, 0x1234_5678));
        cp.vcpus.push(VcpuCheckpoint {
            state,
            rdist: Vec::new(),
        });
        assert_eq!(cp.reference_cntvct(), Some(0x1234_5678));
    }

    #[test]
    fn reference_cntvct_is_none_without_a_counter() {
        let cp = CheckpointState {
            version: CHECKPOINT_VERSION,
            vcpus: vec![VcpuCheckpoint {
                state: VcpuHvfState::default(),
                rdist: Vec::new(),
            }],
            ..Default::default()
        };
        assert_eq!(cp.reference_cntvct(), None);
    }

    /// A [`UsgicCheckpoint`] tagged by its `active` INTID, so a test can tell
    /// which vCPU's state came back out.
    fn usgic_cp(active: u32) -> UsgicCheckpoint {
        UsgicCheckpoint {
            dist: super::super::softgic::Distributor::new(64),
            redist: super::super::softgic::Redistributor::new(),
            pending: vec![active],
            active: Some(active),
        }
    }

    fn state_with(vcpus: usize) -> CheckpointState {
        CheckpointState {
            version: CHECKPOINT_VERSION,
            vcpus: (0..vcpus)
                .map(|_| VcpuCheckpoint {
                    state: VcpuHvfState::default(),
                    rdist: Vec::new(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// A checkpoint written before SMP capture existed carries only the single
    /// `usgic` field. It must still resume as a 1-vCPU guest.
    #[test]
    fn usgic_for_falls_back_to_the_legacy_single_field() {
        let mut cp = state_with(1);
        cp.usgic = Some(usgic_cp(7));

        assert_eq!(cp.usgic_for(0).and_then(|u| u.active), Some(7));
        assert!(cp.covers_usgic_vcpus(1));
    }

    /// …but that fallback must never spread vCPU 0's redistributor and
    /// in-flight interrupts across secondary cores, which is exactly what
    /// resuming a legacy checkpoint on an SMP snapshot used to risk.
    #[test]
    fn legacy_single_field_does_not_cover_secondary_vcpus() {
        let mut cp = state_with(2);
        cp.usgic = Some(usgic_cp(7));

        assert!(cp.usgic_for(1).is_none());
        assert!(!cp.covers_usgic_vcpus(2));
    }

    #[test]
    fn usgic_for_prefers_the_per_vcpu_vector() {
        let mut cp = state_with(2);
        // vCPU 0 mirrored into the legacy field, as `collect_usgic_checkpoint`
        // writes it; the vector is what must actually be read.
        cp.usgic = Some(usgic_cp(7));
        cp.usgic_cpus = vec![usgic_cp(7), usgic_cp(9)];

        assert_eq!(cp.usgic_for(0).and_then(|u| u.active), Some(7));
        assert_eq!(cp.usgic_for(1).and_then(|u| u.active), Some(9));
        assert!(cp.usgic_for(2).is_none());
        assert!(cp.covers_usgic_vcpus(2));
        assert!(!cp.covers_usgic_vcpus(3));
    }

    /// A checkpoint with per-vCPU GIC state but a short `vcpus` list would panic
    /// the restore, which indexes `vcpus[id]`. It must be refused up front.
    #[test]
    fn coverage_requires_a_register_file_per_vcpu_too() {
        let mut cp = state_with(1);
        cp.usgic_cpus = vec![usgic_cp(7), usgic_cp(9)];

        assert!(cp.usgic_for(1).is_some());
        assert!(!cp.covers_usgic_vcpus(2));
    }

    /// A managed-GIC checkpoint carries no userspace-GIC state at all.
    #[test]
    fn managed_checkpoint_covers_no_usgic_vcpus() {
        let cp = state_with(2);
        assert!(cp.usgic_for(0).is_none());
        assert!(!cp.covers_usgic_vcpus(1));
    }

    #[test]
    fn per_vcpu_usgic_survives_json() {
        let mut cp = state_with(2);
        cp.usgic_cpus = vec![usgic_cp(7), usgic_cp(9)];
        let back: CheckpointState =
            serde_json::from_str(&serde_json::to_string(&cp).unwrap()).unwrap();

        assert_eq!(back.usgic_for(1).and_then(|u| u.active), Some(9));
        assert!(back.covers_usgic_vcpus(2));
    }

    /// The new field is additive: a checkpoint serialized without it (an older
    /// writer) still deserializes, rather than failing the whole resume.
    #[test]
    fn json_without_usgic_cpus_still_deserializes() {
        let json = r#"{"version":1,"vcpus":[],"gic_dist":[],"num_irq":64}"#;
        let back: CheckpointState = serde_json::from_str(json).unwrap();
        assert!(back.usgic_cpus.is_empty());
        assert!(back.usgic.is_none());
    }

    #[test]
    fn checkpoint_state_round_trips_through_json() {
        let mut state = VcpuHvfState::default();
        state.gpr[0] = 0xdead_beef;
        state.pc = 0x4000_0000;
        state.sysregs.push((SYSREG_CNTVCT_EL0, 99));
        let cp = CheckpointState {
            version: CHECKPOINT_VERSION,
            vcpus: vec![VcpuCheckpoint {
                state,
                rdist: vec![(0x10100, 0xffff), (0x10400, 0xa0a0_a0a0)],
            }],
            gic_dist: vec![(0x0100, 0x1), (0x6000, 0x8000_0000)],
            num_irq: 64,
            usgic: None,
            usgic_cpus: Vec::new(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: CheckpointState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, CHECKPOINT_VERSION);
        assert_eq!(back.vcpus.len(), 1);
        assert_eq!(back.vcpus[0].state.gpr[0], 0xdead_beef);
        assert_eq!(back.vcpus[0].rdist, vec![(0x10100, 0xffff), (0x10400, 0xa0a0_a0a0)]);
        assert_eq!(back.gic_dist, vec![(0x0100, 0x1), (0x6000, 0x8000_0000)]);
        assert_eq!(back.reference_cntvct(), Some(99));
        assert!(back.usgic.is_none());
    }

    #[test]
    fn usgic_checkpoint_round_trips_losslessly_through_json() {
        // Program some non-default software-GIC state through the MMIO write
        // path, capture it into a UsgicCheckpoint, JSON round-trip, and confirm
        // the model reads back identically — the lossless capture the resume
        // path depends on (the MMIO read view alone cannot observe every field).
        let mut dist = super::super::softgic::Distributor::new(64);
        dist.write(0x0000, 0b11); // GICD_CTLR group enables
        dist.write(0x0100, 0x0000_0002); // ISENABLER0: enable INTID 33 (SPI 1)
        dist.write(0x0104, 0x0000_0001); // ISENABLER1: enable INTID 32? (bit 0 of reg 1 => INTID 32)
        let mut redist = super::super::softgic::Redistributor::new();
        redist.write(0x0000, 0x1); // GICR_CTLR.EnableLPIs
        redist.write(super::super::softgic::GICR_SGI_OFFSET + 0x0100, 1 << 27); // enable PPI 27

        let usgic = UsgicCheckpoint {
            dist: dist.clone(),
            redist: redist.clone(),
            pending: vec![43, 27],
            active: Some(43),
        };
        let cp = CheckpointState {
            version: CHECKPOINT_VERSION,
            vcpus: vec![VcpuCheckpoint {
                state: VcpuHvfState::default(),
                rdist: Vec::new(),
            }],
            gic_dist: Vec::new(),
            num_irq: 64,
            usgic: Some(usgic),
            usgic_cpus: Vec::new(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: CheckpointState = serde_json::from_str(&json).unwrap();
        let u = back.usgic.expect("usgic state present");
        assert_eq!(u.pending, vec![43, 27]);
        assert_eq!(u.active, Some(43));
        // The distributor/redistributor models survive byte-for-byte: compare via
        // the MMIO read view at the programmed registers.
        assert_eq!(u.dist.read(0x0100), dist.read(0x0100), "ISENABLER0 preserved");
        assert_eq!(u.dist.read(0x0104), dist.read(0x0104), "ISENABLER1 preserved");
        assert!(u.redist.lpis_enabled(), "GICR_CTLR.EnableLPIs preserved");
        assert!(u.redist.is_ppi_enabled(27), "PPI 27 enable preserved");
    }

    #[test]
    fn managed_checkpoint_json_without_usgic_field_deserializes() {
        // Back-compat: a checkpoint written before the `usgic` field existed (the
        // managed path never emits it) must still deserialize, with usgic = None.
        let legacy = r#"{"version":1,"vcpus":[],"gic_dist":[],"num_irq":64}"#;
        let cp: CheckpointState = serde_json::from_str(legacy).unwrap();
        assert_eq!(cp.num_irq, 64);
        assert!(cp.usgic.is_none());
        // And a managed capture omits the field entirely (skip_serializing_if).
        let managed = CheckpointState {
            version: CHECKPOINT_VERSION,
            num_irq: 64,
            ..Default::default()
        };
        let json = serde_json::to_string(&managed).unwrap();
        assert!(!json.contains("usgic"), "managed checkpoint must not emit usgic: {json}");
    }
}
