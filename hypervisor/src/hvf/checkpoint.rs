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
}

impl CheckpointState {
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
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: CheckpointState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, CHECKPOINT_VERSION);
        assert_eq!(back.vcpus.len(), 1);
        assert_eq!(back.vcpus[0].state.gpr[0], 0xdead_beef);
        assert_eq!(back.vcpus[0].rdist, vec![(0x10100, 0xffff), (0x10400, 0xa0a0_a0a0)]);
        assert_eq!(back.gic_dist, vec![(0x0100, 0x1), (0x6000, 0x8000_0000)]);
        assert_eq!(back.reference_cntvct(), Some(99));
    }
}
