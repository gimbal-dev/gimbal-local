// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0
//
//! Describing the userspace GIC to a device tree, for cold boot.
//!
//! Every VM this backend has started so far was a *rehydrate*: the guest's
//! device tree was authored by whatever booted it in the cloud, and arrived
//! already sitting in the captured RAM. Nothing on this side ever had to
//! describe a GIC to a kernel, so nothing could.
//!
//! Cold boot inverts that. A kernel starting from an image has never seen a
//! device tree, and will look for its interrupt controller in the one we hand
//! it. `arch::aarch64::configure_system` builds that tree, and to write the
//! `intc` node it needs a [`Vgic`] — a description of where the distributor and
//! redistributors live and what the controller is compatible with.
//!
//! [`HvfGicV3`](super::gic::HvfGicV3) implements `Vgic`, but it is the *managed*
//! GIC: constructing one calls `hv_gic_create`, which must happen before any
//! vCPU exists and which this backend does not use by default. The default is
//! the userspace GIC in [`softgic`](super::softgic), which is a pair of plain
//! data structures with no `Vgic` impl and no opinion about its own MMIO
//! addresses — the rehydrate path gets those from the capture.
//!
//! [`ColdBootGic`] is the missing half: the address map a cold-booted guest
//! should be told about, in a shape the FDT writer accepts.
//!
//! # What this type deliberately refuses to do
//!
//! `Vgic` also carries the save/restore surface — [`Vgic::state`],
//! [`Vgic::set_state`], [`Vgic::save_data_tables`]. A description of an address
//! map cannot serve any of them: it holds no interrupt state, because the
//! interrupt state lives in the `softgic` structures this type does not own.
//!
//! The tempting implementation returns an empty state and `Ok(())`. That would
//! be the ninth bug in this project wearing a tenth hat — a snapshot taken
//! through this path would be byte-valid, restore without complaint, and be
//! missing every pending interrupt in the machine. So those methods return
//! errors that name this type, and the checkpoint path continues to go through
//! `softgic` directly, where the state actually is.

use std::any::Any;

use crate::CpuState;
use crate::arch::aarch64::gic::{Error as GicError, GicState, Result as GicResult, Vgic, VgicConfig};

/// Cloud-hypervisor's canonical aarch64 GIC window, from `arch::aarch64::layout`.
///
/// Duplicated rather than imported because `arch` depends on `hypervisor` and
/// not the other way round. The values are asserted against `arch`'s own
/// constants by a test in `arch/tests/cold_boot_fdt.rs`, so a change on either
/// side fails a build rather than drifting quietly.
pub mod layout {
    /// Below this address is the GIC; at and above it are the MMIO devices.
    pub const MAPPED_IO_START: u64 = 0x0900_0000;
    /// `0x08ff_0000 ~ 0x0900_0000` — the GICv3 distributor.
    pub const GIC_V3_DIST_SIZE: u64 = 0x01_0000;
    /// The distributor sits at the top of the GIC window.
    pub const GIC_V3_DIST_START: u64 = MAPPED_IO_START - GIC_V3_DIST_SIZE;
    /// Per-vCPU redistributor size; redistributors grow *downward* from the
    /// distributor, which is the layout Linux and KVM both expect.
    pub const GIC_V3_REDIST_SIZE: u64 = 0x02_0000;
}

/// The number of interrupt lines a cold-booted guest is given.
///
/// Matches cloud-hypervisor's own default for a fresh arm64 VM. A rehydrated
/// guest instead takes this from its capture, because the number is baked into
/// the distributor state it arrives with.
pub const COLD_BOOT_NR_IRQS: u32 = 256;

/// GICv3 maintenance interrupt, PPI 9 — the value cloud-hypervisor puts in the
/// device tree for every arm64 guest it boots.
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

/// A description of the userspace GIC's address map, for writing a device tree.
///
/// Not an interrupt controller. It answers "where is the GIC and what is it" so
/// [`arch::aarch64::configure_system`] can write the `intc` node; delivery,
/// masking and state all live in [`softgic`](super::softgic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdBootGic {
    vcpu_count: u64,
    dist_addr: u64,
    dist_size: u64,
    redists_addr: u64,
    redists_size: u64,
    nr_irqs: u32,
}

impl ColdBootGic {
    /// Lay out a GIC for `vcpu_count` vCPUs in the canonical arm64 window.
    ///
    /// The distributor sits at the top of the window and the redistributors
    /// grow downward from it — the opposite of the ordering the *managed* GIC
    /// forces on the rehydrate path (`hv_gic_create` returns `HV_BAD_ARGUMENT`
    /// unless the redistributors are above the distributor). Cold boot is free
    /// of that constraint because nothing here calls `hv_gic_create`, so it
    /// uses the layout the kernel expects rather than the one Apple's managed
    /// GIC will accept.
    ///
    /// Returns `None` if the redistributors for that many vCPUs would run below
    /// the GIC window and collide with whatever is beneath it — refusing to
    /// describe a map that overlaps rather than emitting one and letting the
    /// guest find out.
    pub fn new(vcpu_count: u64) -> Option<Self> {
        Self::with_nr_irqs(vcpu_count, COLD_BOOT_NR_IRQS)
    }

    /// As [`ColdBootGic::new`], with an explicit interrupt-line count.
    pub fn with_nr_irqs(vcpu_count: u64, nr_irqs: u32) -> Option<Self> {
        if vcpu_count == 0 {
            return None;
        }
        let redists_size = layout::GIC_V3_REDIST_SIZE.checked_mul(vcpu_count)?;
        let redists_addr = layout::GIC_V3_DIST_START.checked_sub(redists_size)?;

        // The window below the GIC is not ours; UEFI is at 0 and cloud-hypervisor
        // reserves up to 4 MiB for it. Refuse rather than describe an overlap.
        const GIC_WINDOW_FLOOR: u64 = 0x0040_0000;
        if redists_addr < GIC_WINDOW_FLOOR {
            return None;
        }

        Some(Self {
            vcpu_count,
            dist_addr: layout::GIC_V3_DIST_START,
            dist_size: layout::GIC_V3_DIST_SIZE,
            redists_addr,
            redists_size,
            nr_irqs,
        })
    }

    /// The equivalent [`VgicConfig`], for callers that want the plain numbers.
    ///
    /// `msi_addr`/`msi_size` are zero: this GIC advertises no MSI support, so
    /// claiming a doorbell region would describe hardware the guest cannot use.
    pub fn vgic_config(&self) -> VgicConfig {
        VgicConfig {
            vcpu_count: self.vcpu_count,
            dist_addr: self.dist_addr,
            dist_size: self.dist_size,
            redists_addr: self.redists_addr,
            redists_size: self.redists_size,
            msi_addr: 0,
            msi_size: 0,
            nr_irqs: self.nr_irqs,
        }
    }

    /// Number of interrupt lines this GIC is laid out for.
    pub fn nr_irqs(&self) -> u32 {
        self.nr_irqs
    }
}

/// Error returned by the save/restore half of [`Vgic`], which this type cannot
/// serve. Carries the reason rather than a bare failure so a caller that lands
/// here is told where the state actually lives.
fn unsupported(method: &str) -> GicError {
    GicError::Unsupported(format!(
        "ColdBootGic::{method} is not implemented: this type describes the \
         userspace GIC's address map for device-tree generation and holds no \
         interrupt state. The state lives in hvf::softgic; checkpoint and \
         restore go through there. Returning an empty state here would produce \
         a snapshot that restores cleanly with every pending interrupt missing."
    ))
}

impl Vgic for ColdBootGic {
    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn device_properties(&self) -> [u64; 4] {
        [
            self.dist_addr,
            self.dist_size,
            self.redists_addr,
            self.redists_size,
        ]
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn msi_compatible(&self) -> bool {
        // No ITS and no GICv2M frame is created for a cold boot, so MSI is not
        // deliverable. Advertising it would have the guest configure MSI for
        // its virtio devices and then wait forever for completions.
        false
    }

    fn msi_compatibility(&self) -> &str {
        "arm,gic-v3-its"
    }

    fn msi_properties(&self) -> [u64; 2] {
        // Never read: the FDT writer consults `msi_compatible()` first.
        [0, 0]
    }

    fn set_gicr_typers(&mut self, _vcpu_states: &[CpuState]) {
        // GICR_TYPER carries each redistributor's MPIDR affinity, which the
        // userspace GIC derives per-vCPU when it serves the register. Nothing
        // to cache here.
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn state(&self) -> GicResult<GicState> {
        Err(unsupported("state"))
    }

    fn set_state(&mut self, _state: &GicState) -> GicResult<()> {
        Err(unsupported("set_state"))
    }

    fn save_data_tables(&self) -> GicResult<()> {
        Err(unsupported("save_data_tables"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributor_sits_at_the_top_of_the_gic_window() {
        let gic = ColdBootGic::new(1).unwrap();
        let [dist, dist_size, ..] = gic.device_properties();
        assert_eq!(dist + dist_size, layout::MAPPED_IO_START);
    }

    #[test]
    fn redistributors_grow_downward_from_the_distributor() {
        // The opposite of the managed GIC's requirement, and deliberately so:
        // this is the ordering the kernel expects.
        let gic = ColdBootGic::new(4).unwrap();
        let [dist, _, redist, redist_size] = gic.device_properties();
        assert!(redist < dist, "redistributors must be below the distributor");
        assert_eq!(redist + redist_size, dist);
        assert_eq!(redist_size, layout::GIC_V3_REDIST_SIZE * 4);
    }

    #[test]
    fn each_vcpu_gets_its_own_redistributor_frame() {
        for n in 1..=8u64 {
            let gic = ColdBootGic::new(n).unwrap();
            let [_, _, _, redist_size] = gic.device_properties();
            assert_eq!(redist_size, layout::GIC_V3_REDIST_SIZE * n);
            assert_eq!(gic.vcpu_count(), n);
        }
    }

    #[test]
    fn a_vcpu_count_that_would_overlap_is_refused_not_described() {
        // The window between the distributor and the 4 MiB UEFI reservation
        // holds 1119 redistributor frames. Boundary checked from both sides so
        // this stays honest if a layout constant moves: better no map than a
        // wrong one.
        const LAST_THAT_FITS: u64 = 1119;
        let ok = ColdBootGic::new(LAST_THAT_FITS).expect("1119 vCPUs should fit");
        let [_, _, redist, _] = ok.device_properties();
        assert!(redist >= 0x0040_0000);

        assert!(ColdBootGic::new(LAST_THAT_FITS + 1).is_none());
        assert!(ColdBootGic::new(u64::MAX).is_none());
    }

    #[test]
    fn zero_vcpus_is_not_a_machine() {
        assert!(ColdBootGic::new(0).is_none());
    }

    #[test]
    fn msi_is_not_advertised_because_it_is_not_deliverable() {
        let gic = ColdBootGic::new(2).unwrap();
        assert!(!gic.msi_compatible());
    }

    #[test]
    fn save_restore_fails_loudly_rather_than_returning_empty_state() {
        let mut gic = ColdBootGic::new(1).unwrap();
        assert!(gic.save_data_tables().is_err());
        assert!(gic.set_state(&make_unusable_state()).is_err());

        let Err(err) = gic.state() else {
            panic!("state() must not return an empty GicState");
        };

        // The failure must name where the state really is, or the next reader
        // will assume the GIC simply has none.
        let full = format!("{err:#}");
        assert!(full.contains("softgic"), "error should name softgic: {full}");
    }

    /// `set_state` rejects before it inspects its argument, so any `GicState`
    /// serves. Built from the managed GIC's default because `GicState` has no
    /// variant of its own.
    fn make_unusable_state() -> GicState {
        GicState::Hvf(crate::hvf::gic::HvfGicState::default())
    }

    #[test]
    fn vgic_config_matches_the_fdt_description() {
        let gic = ColdBootGic::new(3).unwrap();
        let cfg = gic.vgic_config();
        let [dist, dist_size, redist, redist_size] = gic.device_properties();
        assert_eq!(cfg.dist_addr, dist);
        assert_eq!(cfg.dist_size, dist_size);
        assert_eq!(cfg.redists_addr, redist);
        assert_eq!(cfg.redists_size, redist_size);
        assert_eq!(cfg.nr_irqs, COLD_BOOT_NR_IRQS);
        // No doorbell claimed, matching msi_compatible() == false.
        assert_eq!(cfg.msi_addr, 0);
        assert_eq!(cfg.msi_size, 0);
    }
}
