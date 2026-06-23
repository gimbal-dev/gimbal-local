// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Managed GICv3 (`hv_gic`) support for the Apple Hypervisor.framework backend.
//!
//! Apple's framework provides an in-VM GICv3 distributor + redistributors whose
//! state can be saved and restored as an opaque blob (`hv_gic_state`). This
//! module wires that into the hypervisor-agnostic [`Vgic`] trait, including the
//! interrupt-controller state that snapshot/rehydration depends on.
//!
//! Ordering constraint (enforced by Apple): `hv_gic_create()` must be called
//! after the VM exists but **before** any vCPU is created.

use std::any::Any;
use std::ffi::c_void;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::ffi::*;
use crate::arch::aarch64::gic::{
    Error as GicError, GicState, Result as GicResult, Vgic, VgicConfig,
};
use crate::device::HypervisorDeviceError;
use crate::CpuState;

/// GICv3 maintenance interrupt (PPI), matching the value the VMM advertises.
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

/// `GICD_CTLR` distributor register offset.
pub const GICD_CTLR: u32 = HV_GIC_DIST_REG_GICD_CTLR;
/// `GICD_TYPER` distributor register offset.
pub const GICD_TYPER: u32 = HV_GIC_DIST_REG_GICD_TYPER;

/// Opaque, serializable snapshot of the managed GIC produced by `hv_gic`.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HvfGicState {
    pub data: Vec<u8>,
}

/// A managed GICv3 created through `hv_gic_create`.
pub struct HvfGicV3 {
    dist_addr: u64,
    dist_size: u64,
    redists_addr: u64,
    redists_size: u64,
    msi_addr: u64,
    msi_size: u64,
    /// Lowest INTID configured for message-signalled SPIs (0 if MSI not set up).
    msi_intid_base: u32,
    /// Number of message-signalled SPI INTIDs configured (0 if MSI not set up).
    msi_intid_count: u32,
    vcpu_count: u64,
    gicr_typers: Vec<u64>,
}

/// `HV_GIC_REG_GICM_SET_SPI_NSR` — the doorbell register offset within the MSI
/// region. A 32-bit write of an INTID here pulses that message-based SPI; this
/// is the IPA `hv_gic_send_msi` targets (and the address a guest's MSI-X entry
/// would carry for an MBI-routed device).
pub const GICM_SET_SPI_NSR: u64 = 0x0040;

fn dev_get(op: &'static str, code: i32) -> GicResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(GicError::GetDeviceAttribute(
            HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                "{op} failed: {:#010x}",
                code as u32
            )),
        ))
    }
}

fn dev_set(op: &'static str, code: i32) -> GicResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(GicError::SetDeviceAttribute(
            HypervisorDeviceError::SetDeviceAttribute(anyhow!(
                "{op} failed: {:#010x}",
                code as u32
            )),
        ))
    }
}

impl HvfGicV3 {
    /// Create the managed GIC. Must run before any vCPU is created.
    pub fn new(config: &VgicConfig) -> GicResult<Self> {
        // SAFETY: FFI; the returned object is released below.
        let cfg = unsafe { hv_gic_config_create() };
        if cfg.is_null() {
            return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                anyhow!("hv_gic_config_create returned null"),
            )));
        }

        // Configure the MSI region + interrupt range when the caller reserved a
        // doorbell window (msi_addr/msi_size != 0). This is what makes the
        // managed GIC accept `hv_gic_send_msi`: a message-based SPI delivered
        // through the GICM frame at `msi_addr + GICM_SET_SPI_NSR`. The MSI INTID
        // range is carved from the top of the framework's SPI range so it does
        // not collide with line-based SPIs the snapshot may use.
        let mut msi_intid_base = 0u32;
        let mut msi_intid_count = 0u32;
        if config.msi_addr != 0 && config.msi_size != 0 {
            // SAFETY: FFI; out-params valid for the duration of the calls.
            let geom = unsafe {
                let mut align = 0usize;
                let mut region_size = 0usize;
                let mut spi_base = 0u32;
                let mut spi_count = 0u32;
                let mut rc = hv_gic_get_msi_region_base_alignment(&mut align);
                if rc == 0 {
                    rc = hv_gic_get_msi_region_size(&mut region_size);
                }
                if rc == 0 {
                    rc = hv_gic_get_spi_interrupt_range(&mut spi_base, &mut spi_count);
                }
                (rc, align, region_size, spi_base, spi_count)
            };
            let (rc, align, region_size, spi_base, spi_count) = geom;
            if rc != 0 {
                // SAFETY: release the config before returning.
                unsafe { os_release(cfg) };
                return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                    anyhow!("querying MSI region geometry failed: {:#010x}", rc as u32),
                )));
            }
            let align = align as u64;
            if align != 0 && !config.msi_addr.is_multiple_of(align) {
                // SAFETY: release the config before returning.
                unsafe { os_release(cfg) };
                return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                    anyhow!(
                        "MSI region base {:#x} is not aligned to the required {:#x}",
                        config.msi_addr,
                        align
                    ),
                )));
            }
            if (config.msi_size as usize) < region_size {
                // SAFETY: release the config before returning.
                unsafe { os_release(cfg) };
                return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                    anyhow!(
                        "MSI region size {:#x} is smaller than the required {:#x}",
                        config.msi_size,
                        region_size
                    ),
                )));
            }
            // Make the framework's full SPI range message-capable: any SPI can
            // then be pulsed either by line (`hv_gic_set_spi`) or by message
            // (`hv_gic_send_msi`) through the doorbell. This mirrors how a real
            // VMM exposes MSIs (the whole SPI space is reachable) and keeps the
            // SPI a device's MSI-X entry targets unconstrained.
            msi_intid_base = spi_base;
            msi_intid_count = spi_count;
            // SAFETY: FFI on the valid config object.
            let rc = unsafe {
                let mut rc = hv_gic_config_set_msi_region_base(cfg, config.msi_addr);
                if rc == 0 {
                    rc = hv_gic_config_set_msi_interrupt_range(
                        cfg,
                        msi_intid_base,
                        msi_intid_count,
                    );
                }
                rc
            };
            if rc != 0 {
                // SAFETY: release the config before returning.
                unsafe { os_release(cfg) };
                return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                    anyhow!("configuring MSI region/range failed: {:#010x}", rc as u32),
                )));
            }
        }

        // SAFETY: `cfg` is a valid configuration object for the calls below.
        let result = unsafe {
            let mut rc = hv_gic_config_set_distributor_base(cfg, config.dist_addr);
            if rc == 0 {
                rc = hv_gic_config_set_redistributor_base(cfg, config.redists_addr);
            }
            if rc == 0 {
                rc = hv_gic_create(cfg);
            }
            rc
        };
        // SAFETY: release the configuration object exactly once.
        unsafe { os_release(cfg) };

        if result != 0 {
            return Err(GicError::CreateGic(crate::HypervisorVmError::CreateVgic(
                anyhow!("hv_gic_create failed: {:#010x}", result as u32),
            )));
        }

        Ok(HvfGicV3 {
            dist_addr: config.dist_addr,
            dist_size: config.dist_size,
            redists_addr: config.redists_addr,
            redists_size: config.redists_size,
            msi_addr: config.msi_addr,
            msi_size: config.msi_size,
            msi_intid_base,
            msi_intid_count,
            vcpu_count: config.vcpu_count,
            gicr_typers: vec![0; config.vcpu_count as usize],
        })
    }

    /// Read a distributor register (e.g. `GICD_TYPER`); proves the GIC is live.
    pub fn distributor_reg(&self, reg: u32) -> GicResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI; out-param valid.
        dev_get("hv_gic_get_distributor_reg", unsafe {
            hv_gic_get_distributor_reg(reg, &mut v)
        })?;
        Ok(v)
    }

    /// Write a distributor register by its architectural GICD offset. Used to
    /// rehydrate a KVM snapshot's distributor state field-by-field via the
    /// per-register API (no opaque blob required).
    pub fn set_distributor_reg(&self, reg: u32, value: u64) -> GicResult<()> {
        // SAFETY: FFI.
        dev_set("hv_gic_set_distributor_reg", unsafe {
            hv_gic_set_distributor_reg(reg, value)
        })
    }

    // Per-vCPU redistributor registers are reached through the vCPU's own
    // `hv_vcpu_t` handle (see `HvfVcpu::{redistributor_reg,set_redistributor_reg}`),
    // which the GIC does not own, so no redistributor accessor lives here.

    /// Assert or deassert a shared peripheral interrupt by INTID.
    pub fn set_spi(&self, intid: u32, level: bool) -> GicResult<()> {
        // SAFETY: FFI.
        dev_set("hv_gic_set_spi", unsafe { hv_gic_set_spi(intid, level) })
    }

    /// Deliver a message-signalled interrupt: pulse SPI `intid` via the doorbell
    /// at IPA `address`.
    ///
    /// Deliver a message-signalled interrupt: pulse SPI `intid` via the doorbell
    /// at IPA `address` (the `GICM_SET_SPI_NSR` register in the MSI region).
    ///
    /// This is the managed GIC's ONE supported message-based interrupt path.
    /// Apple's GIC has no ITS, so this delivers a message-based SPI, NOT an LPI:
    /// `intid` must fall within the MSI interrupt range configured at
    /// `hv_gic_create` time (see `msi_intid_range`). A cloud snapshot whose
    /// virtio completions are routed through a GIC ITS as LPIs (INTID >= 8192)
    /// cannot be delivered this way (proven in `hvf_managed_gic_rejects_*`); such
    /// a snapshot must be captured with MBI/message-based-SPI routing instead.
    pub fn send_msi(&self, address: u64, intid: u32) -> GicResult<()> {
        // SAFETY: FFI.
        dev_set("hv_gic_send_msi", unsafe {
            crate::hvf::ffi::hv_gic_send_msi(address, intid)
        })
    }

    /// Deliver a message-based SPI `intid` through this GIC's configured MSI
    /// doorbell (`msi_addr + GICM_SET_SPI_NSR`). Convenience over [`send_msi`]
    /// that knows the doorbell IPA. Errors if MSI was not configured or `intid`
    /// is outside the configured MSI range.
    pub fn deliver_msi(&self, intid: u32) -> GicResult<()> {
        if self.msi_intid_count == 0 {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!(
                    "MSI not configured for this GIC (no doorbell region reserved)"
                )),
            ));
        }
        let lo = self.msi_intid_base;
        let hi = self.msi_intid_base + self.msi_intid_count - 1;
        if intid < lo || intid > hi {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!(
                    "MSI INTID {intid} outside configured range {lo}..={hi}"
                )),
            ));
        }
        self.send_msi(self.msi_addr + GICM_SET_SPI_NSR, intid)
    }

    /// The `[base, count]` of INTIDs reserved for message-based SPIs, or
    /// `[0, 0]` if MSI delivery was not configured.
    pub fn msi_intid_range(&self) -> [u32; 2] {
        [self.msi_intid_base, self.msi_intid_count]
    }

    /// The MSI doorbell IPA (`GICM_SET_SPI_NSR`) a guest's MSI-X entry targets,
    /// or `None` if MSI delivery was not configured.
    pub fn msi_doorbell(&self) -> Option<u64> {
        (self.msi_intid_count != 0).then_some(self.msi_addr + GICM_SET_SPI_NSR)
    }
}

/// A [`MsiSink`](crate::hvf::virtio::pci::MsiSink) backed by the managed GIC: it
/// delivers a virtio completion's target SPI as a message-based SPI through this
/// GIC's MSI doorbell (`hv_gic_send_msi`). This is the live delivery sink the
/// virtio [`MsiSpiInjector`](crate::hvf::virtio::pci::MsiSpiInjector) hands
/// resolved completions to for a deliverable (MBI/message-SPI-routed) snapshot.
///
/// It holds the GIC as the shared `Arc<Mutex<dyn Vgic>>` the rehydrated VM
/// exposes and downcasts to the concrete [`HvfGicV3`] to reach `deliver_msi`,
/// so a device's completion (serviced on the owning vCPU thread inside the MMIO
/// notify path) lands the interrupt directly in Apple's GIC.
pub struct GicMsiSink {
    gic: std::sync::Arc<std::sync::Mutex<dyn Vgic>>,
}

impl GicMsiSink {
    /// Wrap the rehydrated VM's GIC handle as a message-based SPI sink.
    pub fn new(gic: std::sync::Arc<std::sync::Mutex<dyn Vgic>>) -> Self {
        Self { gic }
    }
}

impl crate::hvf::virtio::pci::MsiSink for GicMsiSink {
    fn deliver_spi(&self, intid: u32) {
        if std::env::var_os("CHM_TRACE_MSI").is_some() {
            eprintln!("[gic-msi] delivering virtio completion as SPI {intid}");
        }
        let mut guard = self.gic.lock().unwrap();
        let Some(gic) = guard.as_any_concrete_mut().downcast_mut::<HvfGicV3>() else {
            eprintln!("[gic-msi] GIC is not the HVF managed GIC; dropping SPI {intid}");
            return;
        };
        if let Err(e) = gic.deliver_msi(intid) {
            eprintln!("[gic-msi] deliver SPI {intid} failed: {e:?}");
        }
    }
}

// `hv_gic_ich_reg_t` encodings for the GIC virtualization-control registers.
const HV_GIC_ICH_REG_VTR_EL2: u16 = 0xe659;
const HV_GIC_ICH_REG_ELRSR_EL2: u16 = 0xe65d;
const HV_GIC_ICH_REG_LR0_EL2: u16 = 0xe660;

/// ICH_LR<n>_EL2 field shifts (GICv3, 64-bit List Register).
const LR_STATE_SHIFT: u64 = 62; // [63:62] state (01 = pending)
const LR_GROUP_SHIFT: u64 = 60; // [60] group (1 = Group 1)
const LR_PRIORITY_SHIFT: u64 = 48; // [55:48] priority
const LR_STATE_PENDING: u64 = 0b01;

fn ich_get(vcpu_id: u64, reg: u16) -> GicResult<u64> {
    let mut v = 0u64;
    // SAFETY: FFI on the vCPU's owning thread; out-param valid.
    let rc = unsafe { crate::hvf::ffi::hv_gic_get_ich_reg(vcpu_id, reg, &mut v) };
    dev_get("hv_gic_get_ich_reg", rc)?;
    Ok(v)
}

fn ich_set(vcpu_id: u64, reg: u16, value: u64) -> GicResult<()> {
    // SAFETY: FFI on the vCPU's owning thread.
    dev_set("hv_gic_set_ich_reg", unsafe {
        crate::hvf::ffi::hv_gic_set_ich_reg(vcpu_id, reg, value)
    })
}

/// Attempt to inject an interrupt `intid` (e.g. an LPI, `>= 8192`) directly into
/// a vCPU's virtual CPU interface by programming a free ICH List Register.
///
/// IMPORTANT — hardware-proven boundary (macOS 15/26, Apple Silicon): on the
/// managed GIC the ICH virtualization-control registers are **EL2-gated**.
/// Apple's own header states they exist only "when EL2 is enabled... used by the
/// guest hypervisor for injecting interrupts to its guest" (i.e. nested
/// virtualization). For a normal non-nested EL1 guest EL2 is owned by the
/// framework, so `hv_gic_{get,set}_ich_reg` returns `HV_UNSUPPORTED` and this
/// function returns that error. There is therefore NO VMM-controllable path to
/// deliver an LPI to a non-nested guest's CPU interface: the managed GIC
/// delivers only SPIs (line-based `hv_gic_set_spi` or message-based
/// `hv_gic_send_msi`), and exposes no LPI/ITS/PROPBASER/PENDBASER registers at
/// all. See `hvf_managed_gic_rejects_el1_lpi_injection` and the M11 plan note.
///
/// Retained as a real, correct binding for the nested-guest case (a guest
/// hypervisor injecting into ITS own guest) and as the executable record of the
/// boundary. Must be called on the vCPU's owning thread. Returns `Ok(false)` if
/// every List Register is occupied; `Err(..)` (typically `HV_UNSUPPORTED`) when
/// ICH access is not permitted for this guest.
pub fn inject_lpi_via_lr(
    vcpu_id: u64,
    intid: u32,
    group1: bool,
    priority: u8,
) -> GicResult<bool> {
    // ICH_VTR_EL2.ListRegs[4:0] + 1 = number of implemented List Registers.
    let num_lrs = (ich_get(vcpu_id, HV_GIC_ICH_REG_VTR_EL2)? & 0x1f) as u16 + 1;
    // ELRSR has a set bit per *empty* List Register; prefer it to avoid clobbering.
    let elrsr = ich_get(vcpu_id, HV_GIC_ICH_REG_ELRSR_EL2).unwrap_or(0);

    let mut chosen: Option<u16> = None;
    for n in 0..num_lrs {
        if elrsr != 0 {
            if elrsr & (1 << n) != 0 {
                chosen = Some(n);
                break;
            }
        } else {
            // No ELRSR hint: treat a List Register whose state is Invalid (00) as free.
            let lr = ich_get(vcpu_id, HV_GIC_ICH_REG_LR0_EL2 + n)?;
            if (lr >> LR_STATE_SHIFT) & 0b11 == 0 {
                chosen = Some(n);
                break;
            }
        }
    }
    let Some(n) = chosen else {
        return Ok(false);
    };

    let value = (LR_STATE_PENDING << LR_STATE_SHIFT)
        | ((group1 as u64) << LR_GROUP_SHIFT)
        | ((priority as u64) << LR_PRIORITY_SHIFT)
        | (intid as u64 & 0xffff_ffff);
    ich_set(vcpu_id, HV_GIC_ICH_REG_LR0_EL2 + n, value)?;
    Ok(true)
}

impl Vgic for HvfGicV3 {
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
        // MSI/ITS delivery (irqfd + GSI routing) is not implemented yet, so we
        // do not advertise MSI support even if a region was reserved.
        false
    }

    fn msi_compatibility(&self) -> &str {
        "arm,gic-v3-its"
    }

    fn msi_properties(&self) -> [u64; 2] {
        [self.msi_addr, self.msi_size]
    }

    fn set_gicr_typers(&mut self, vcpu_states: &[CpuState]) {
        // The managed GIC owns redistributor state; we only track the count so
        // FDT generation and snapshot bookkeeping stay consistent.
        self.gicr_typers = vec![0; vcpu_states.len()];
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn state(&self) -> GicResult<GicState> {
        // SAFETY: FFI; the state object is released before returning.
        let state_obj = unsafe { hv_gic_state_create() };
        if state_obj.is_null() {
            return Err(GicError::GetDeviceAttribute(
                HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                    "hv_gic_state_create returned null"
                )),
            ));
        }

        let mut size = 0usize;
        // SAFETY: FFI; out-param valid.
        let rc = unsafe { hv_gic_state_get_size(state_obj, &mut size) };
        if rc != 0 {
            // SAFETY: release before bailing out.
            unsafe { os_release(state_obj) };
            return dev_get("hv_gic_state_get_size", rc).map(|_| unreachable!());
        }
        if size == 0 {
            // SAFETY: release before bailing out.
            unsafe { os_release(state_obj) };
            return Err(GicError::GetDeviceAttribute(
                HypervisorDeviceError::GetDeviceAttribute(anyhow!(
                    "hv_gic_state_get_size reported zero bytes"
                )),
            ));
        }

        let mut data = vec![0u8; size];
        // SAFETY: `data` has room for `size` bytes.
        let rc = unsafe { hv_gic_state_get_data(state_obj, data.as_mut_ptr() as *mut c_void) };
        // SAFETY: release the state object exactly once.
        unsafe { os_release(state_obj) };
        dev_get("hv_gic_state_get_data", rc)?;

        Ok(GicState::Hvf(HvfGicState { data }))
    }

    fn set_state(&mut self, state: &GicState) -> GicResult<()> {
        #[allow(irrefutable_let_patterns)]
        let GicState::Hvf(s) = state else {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!("expected HVF GicState")),
            ));
        };
        if s.data.is_empty() {
            return Err(GicError::SetDeviceAttribute(
                HypervisorDeviceError::SetDeviceAttribute(anyhow!("empty HVF GIC state blob")),
            ));
        }
        // SAFETY: FFI; `s.data` is valid for `s.data.len()` bytes.
        dev_set("hv_gic_set_state", unsafe {
            hv_gic_set_state(s.data.as_ptr() as *const c_void, s.data.len())
        })
    }

    fn save_data_tables(&self) -> GicResult<()> {
        // The managed GIC keeps its tables internally; nothing to flush.
        Ok(())
    }
}

/// Re-arm the virtual timer after an `HV_EXIT_REASON_VTIMER_ACTIVATED` exit.
///
/// With Apple's managed GIC the CNTV output is wired internally to GIC PPI 27
/// (`HV_GIC_INT_EL1_VIRTUAL_TIMER`): when the timer fires the GIC pends INTID 27
/// and the guest takes it directly through the CPU interface. In that
/// configuration this exit reason does not normally occur at all — verified by
/// the `hvf_guest_takes_virtual_timer` integration test, where the guest arms
/// CNTV, takes INTID 27 and powers off without any `VTIMER_ACTIVATED` exit or
/// host injection.
///
/// HVF may still surface the activation and auto-mask the vtimer; the correct
/// response for a managed GIC is simply to unmask so the GIC re-evaluates and
/// delivers PPI 27. We deliberately do NOT assert the raw vCPU IRQ line
/// (`hv_vcpu_set_pending_interrupt`) here: that bypasses the GIC and would
/// deliver a spurious (INTID 1023) interrupt rather than the timer PPI.
pub(super) fn rearm_vtimer(vcpu_id: u64) -> Result<(), i32> {
    // SAFETY: FFI on the owning thread.
    let rc = unsafe { hv_vcpu_set_vtimer_mask(vcpu_id, false) };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(())
    }
}
