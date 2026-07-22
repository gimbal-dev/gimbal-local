// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Apple Hypervisor.framework (HVF) backend for Cloud Hypervisor.
//!
//! This backend implements the hypervisor-agnostic `Hypervisor`, `Vm` and
//! `Vcpu` traits on top of Apple's `Hypervisor.framework` so that arm64 guests
//! (and, ultimately, rehydrated arm64 cloud snapshots) can run natively on
//! Apple Silicon Macs.
//!
//! Scope (milestone M1): boot an arm64 guest through the real trait objects,
//! service MMIO via [`VmOps`], and snapshot/restore vCPU architectural state
//! through the real `state()`/`set_state()`. Interrupt delivery (the managed
//! `hv_gic`), PMU, multi-vCPU threading and dirty-page live migration are
//! tracked as follow-up milestones.
//!
//! HVF has two hard constraints that shape this code:
//!   * one VM per process (`hv_vm_create`/`hv_vm_destroy` are process-global);
//!   * a vCPU must be created and run on the same host thread.

use std::any::Any;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::{Vgic, VgicConfig};
use crate::compat::{EFD_NONBLOCK, EventFd};
use crate::cpu::{HypervisorCpuError, Vcpu, VmExit};
use crate::vm::{DataMatch, HypervisorVmError, InterruptSourceConfig, Vm, VmOps};
use crate::{
    CpuState, HypervisorType, HypervisorVmConfig, IoEventAddress, IrqRoutingEntry, MpState,
    RegList, StandardRegisters, VcpuInit,
};

mod ffi;
use ffi::*;
pub mod gic;
use gic::HvfGicV3;
#[cfg(feature = "kvm-snapshot")]
pub mod devices;
#[cfg(feature = "kvm-snapshot")]
pub mod rehydrate;
pub mod translate;
pub mod checkpoint;

pub mod softgic;
#[cfg(feature = "kvm-snapshot")]
pub mod virtio;

type CpuResult<T> = std::result::Result<T, HypervisorCpuError>;
type VmResult<T> = std::result::Result<T, HypervisorVmError>;

/// Re-evaluation cadence (milliseconds) for a vCPU parked on WFI with no armed
/// virtual-timer deadline. A cross-thread interrupt wakes the vCPU immediately
/// via its wake fd; this bound only caps how long a kick-less wakeup source can
/// wait, and guarantees a parked vCPU can never wedge. When a timer IS armed the
/// park instead wakes at the deadline (see [`HvfVcpu::wfi_park_ms`]).
const WFI_IDLE_POLL_MS: i32 = 100;

/// The host `mach_absolute_time` -> nanoseconds timebase, read once. Converting
/// a virtual-timer deadline (in mach ticks) to a wall-clock park duration needs
/// this ratio; it is constant for the life of the process.
fn mach_timebase() -> ffi::MachTimebaseInfo {
    use std::sync::OnceLock;
    static TB: OnceLock<ffi::MachTimebaseInfo> = OnceLock::new();
    *TB.get_or_init(|| {
        let mut info = ffi::MachTimebaseInfo::default();
        // SAFETY: FFI; out-param is a valid, owned struct.
        let ret = unsafe { ffi::mach_timebase_info(&mut info) };
        if ret != 0 || info.numer == 0 || info.denom == 0 {
            // Fall back to the Apple-Silicon 24 MHz timebase (125/3 ns per tick).
            info = ffi::MachTimebaseInfo { numer: 125, denom: 3 };
        }
        info
    })
}

/// Fill `buf` with cryptographically-strong host entropy for the guest's TRNG
/// firmware calls. Reads `/dev/urandom` (never blocks on modern macOS); on the
/// rare read failure the buffer is left zeroed, which only weakens one TRNG
/// batch and never wedges the guest (Linux treats the TRNG as one of several
/// entropy sources).
fn host_entropy(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    }
}

// ---------------------------------------------------------------------------
// Neutral state payloads carried by the `hypervisor` crate enums.
// ---------------------------------------------------------------------------

/// HVF core registers. Field layout mirrors the MSHV `StandardRegisters`
/// variant so the shared `get_/set_aarch64_reg!` macros work unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfStandardRegisters {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// HVF analogue of `kvm_vcpu_init` — HVF needs no explicit feature negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfVcpuInit {
    pub features: u64,
}

/// HVF register list (system-register ids that participate in snapshot).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HvfRegList {
    pub regs: Vec<u64>,
}

/// HVF MSI/IRQ routing entry placeholder (interrupt routing lands with hv_gic).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct HvfIrqRoutingEntry {
    pub gsi: u32,
    pub address: u64,
    pub data: u32,
}

/// Full architectural vCPU state — the unit of snapshot/restore.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct VcpuHvfState {
    pub gpr: [u64; 31],
    pub pc: u64,
    pub cpsr: u64,
    pub sp_el1: u64,
    pub sysregs: Vec<(u16, u64)>,
    /// Per-vCPU GIC CPU-interface (ICC) registers. Empty when the VM has no
    /// managed GIC. Captured separately from `sysregs` because the managed GIC
    /// owns these and they are not reachable via `hv_vcpu_get_sys_reg`.
    #[serde(default)]
    pub gic_icc: Vec<(u16, u64)>,
    pub mp_state_running: bool,
}

/// EL1 system registers captured on snapshot. This curated set is the analogue
/// of KVM's ONE_REG list and the future home of KVM->HVF state translation.
const SNAPSHOT_SYS_REGS: &[u16] = &[
    SYSREG_MPIDR_EL1,
    SYSREG_MDSCR_EL1,
    SYSREG_SCTLR_EL1,
    SYSREG_CPACR_EL1,
    SYSREG_TTBR0_EL1,
    SYSREG_TTBR1_EL1,
    SYSREG_TCR_EL1,
    SYSREG_SPSR_EL1,
    SYSREG_ELR_EL1,
    SYSREG_SP_EL0,
    SYSREG_ESR_EL1,
    SYSREG_FAR_EL1,
    SYSREG_MAIR_EL1,
    SYSREG_VBAR_EL1,
    SYSREG_TPIDR_EL1,
    SYSREG_TPIDR_EL0,
    SYSREG_TPIDRRO_EL0,
    SYSREG_SP_EL1,
];

// ---------------------------------------------------------------------------
// Hypervisor
// ---------------------------------------------------------------------------

/// The HVF hypervisor handle. Creating one validates that HVF is usable.
pub struct HvfHypervisor;

impl HvfHypervisor {
    /// Create a new HVF hypervisor wrapped in an `Arc<dyn Hypervisor>`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> crate::hypervisor::Result<Arc<dyn crate::Hypervisor>> {
        Ok(Arc::new(HvfHypervisor))
    }

    /// HVF is available on Apple Silicon Macs with the hypervisor entitlement.
    pub fn is_available() -> crate::hypervisor::Result<bool> {
        Ok(cfg!(target_os = "macos"))
    }
}

impl crate::Hypervisor for HvfHypervisor {
    fn hypervisor_type(&self) -> HypervisorType {
        HypervisorType::Hvf
    }

    fn create_vm(&self, _config: HypervisorVmConfig) -> crate::hypervisor::Result<Arc<dyn Vm>> {
        // SAFETY: FFI; NULL config selects HVF defaults. One VM per process.
        let ret = unsafe { hv_vm_create(ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(crate::HypervisorError::VmCreate(anyhow!(
                "hv_vm_create failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(Arc::new(HvfVm {
            mappings: Mutex::new(Vec::new()),
            gic: Mutex::new(None),
            vcpu_created: AtomicBool::new(false),
        }))
    }

    fn get_host_ipa_limit(&self) -> i32 {
        // HVF exposes a wide IPA space; report the common 40-bit limit.
        40
    }

    fn get_max_vcpus(&self) -> u32 {
        // M1 supports a single vCPU; raised once multi-vCPU threading lands.
        1
    }
}

// ---------------------------------------------------------------------------
// Vm
// ---------------------------------------------------------------------------

struct Mapping {
    ipa: u64,
    size: usize,
}

/// One HVF VM. Owns the process-global VM lifetime and the IPA mappings.
pub struct HvfVm {
    mappings: Mutex<Vec<Mapping>>,
    gic: Mutex<Option<Arc<Mutex<HvfGicV3>>>>,
    vcpu_created: AtomicBool,
}

impl Drop for HvfVm {
    fn drop(&mut self) {
        // SAFETY: all vCPUs are destroyed before the VM (enforced by ownership).
        unsafe {
            hv_vm_destroy();
        }
    }
}

impl Vm for HvfVm {
    fn create_irq_chip(&self) -> VmResult<()> {
        // No userspace IRQ chip in M1; the managed hv_gic arrives with M2.
        Ok(())
    }

    fn register_irqfd(&self, _fd: &crate::compat::EventFd, _gsi: u32) -> VmResult<()> {
        Err(HypervisorVmError::RegisterIrqFd(anyhow!(
            "irqfd routing requires hv_gic (not yet implemented)"
        )))
    }

    fn unregister_irqfd(&self, _fd: &crate::compat::EventFd, _gsi: u32) -> VmResult<()> {
        Err(HypervisorVmError::UnregisterIrqFd(anyhow!(
            "irqfd routing requires hv_gic (not yet implemented)"
        )))
    }

    fn create_vcpu(&self, id: u32, vm_ops: Option<Arc<dyn VmOps>>) -> VmResult<Box<dyn Vcpu>> {
        let mut vcpu_id: u64 = 0;
        let mut exit: *mut HvVcpuExit = ptr::null_mut();
        // SAFETY: out-params are valid; must run on the creating thread.
        let ret = unsafe { hv_vcpu_create(&mut vcpu_id, &mut exit, ptr::null_mut()) };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::CreateVcpu(anyhow!(
                "hv_vcpu_create failed: {:#010x}",
                ret as u32
            )));
        }
        self.vcpu_created.store(true, Ordering::SeqCst);
        let kick = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            HypervisorVmError::CreateVcpu(anyhow!("failed to create vCPU wake fd: {e}"))
        })?;
        Ok(Box::new(HvfVcpu {
            id: vcpu_id,
            index: id,
            exit,
            vm_ops,
            kick,
            vtimer_offset: AtomicU64::new(0),
            run_gen: Arc::new(AtomicU64::new(0)),
            usgic: Mutex::new(UserGic {
                enabled: std::env::var_os("CHM_USERSPACE_GIC").is_some(),
                ..UserGic::default()
            }),
            inject_queue: Arc::new(Mutex::new(Vec::new())),
        }))
    }

    fn create_vgic(&self, config: &VgicConfig) -> VmResult<Arc<Mutex<dyn Vgic>>> {
        // hv_gic_create must run after the VM exists but before any vCPU is
        // created; enforce that ordering (and single creation) here rather than
        // relying on HVF to reject a misordered call.
        if self.vcpu_created.load(Ordering::SeqCst) {
            return Err(HypervisorVmError::CreateVgic(anyhow!(
                "hv_gic must be created before any vCPU"
            )));
        }
        let mut slot = self.gic.lock().unwrap();
        if slot.is_some() {
            return Err(HypervisorVmError::CreateVgic(anyhow!(
                "GIC already created for this VM"
            )));
        }
        let gic =
            HvfGicV3::new(config).map_err(|e| HypervisorVmError::CreateVgic(anyhow!("{e}")))?;
        let gic = Arc::new(Mutex::new(gic));
        *slot = Some(gic.clone());
        Ok(gic)
    }

    fn register_ioevent(
        &self,
        _fd: &crate::compat::EventFd,
        _addr: &IoEventAddress,
        _datamatch: Option<DataMatch>,
    ) -> VmResult<()> {
        Err(HypervisorVmError::RegisterIoEvent(anyhow!(
            "ioeventfd requires the device fast-path (not yet implemented)"
        )))
    }

    fn unregister_ioevent(
        &self,
        _fd: &crate::compat::EventFd,
        _addr: &IoEventAddress,
    ) -> VmResult<()> {
        Err(HypervisorVmError::UnregisterIoEvent(anyhow!(
            "ioeventfd requires the device fast-path (not yet implemented)"
        )))
    }

    fn make_routing_entry(&self, gsi: u32, config: &InterruptSourceConfig) -> IrqRoutingEntry {
        let (address, data) = match config {
            InterruptSourceConfig::MsiIrq(cfg) => (
                ((cfg.high_addr as u64) << 32) | cfg.low_addr as u64,
                cfg.data,
            ),
            InterruptSourceConfig::LegacyIrq(_) => (0, 0),
        };
        IrqRoutingEntry::Hvf(HvfIrqRoutingEntry { gsi, address, data })
    }

    fn set_gsi_routing(&self, _entries: &[IrqRoutingEntry]) -> VmResult<()> {
        // No-op until hv_gic MSI routing exists; M1 guests are poll-driven.
        Ok(())
    }

    unsafe fn create_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        userspace_addr: *mut u8,
        readonly: bool,
        _log_dirty_pages: bool,
    ) -> VmResult<()> {
        let mut flags = HV_MEMORY_READ | HV_MEMORY_EXEC;
        if !readonly {
            flags |= HV_MEMORY_WRITE;
        }
        // SAFETY: caller guarantees [userspace_addr, +memory_size) is valid for
        // the lifetime of the mapping (until remove_user_memory_region).
        let ret = unsafe {
            hv_vm_map(
                userspace_addr as *mut c_void,
                guest_phys_addr,
                memory_size,
                flags,
            )
        };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::CreateUserMemory(anyhow!(
                "hv_vm_map failed: {:#010x}",
                ret as u32
            )));
        }
        self.mappings.lock().unwrap().push(Mapping {
            ipa: guest_phys_addr,
            size: memory_size,
        });
        Ok(())
    }

    unsafe fn remove_user_memory_region(
        &self,
        _slot: u32,
        guest_phys_addr: u64,
        memory_size: usize,
        _userspace_addr: *mut u8,
        _readonly: bool,
        _log_dirty_pages: bool,
    ) -> VmResult<()> {
        // SAFETY: unmaps a region previously mapped via create_user_memory_region.
        let ret = unsafe { hv_vm_unmap(guest_phys_addr, memory_size) };
        if ret != HV_SUCCESS {
            return Err(HypervisorVmError::RemoveUserMemory(anyhow!(
                "hv_vm_unmap failed: {:#010x}",
                ret as u32
            )));
        }
        self.mappings
            .lock()
            .unwrap()
            .retain(|m| m.ipa != guest_phys_addr || m.size != memory_size);
        Ok(())
    }

    fn get_preferred_target(&self, _kvi: &mut VcpuInit) -> VmResult<()> {
        Ok(())
    }

    fn start_dirty_log(&self) -> VmResult<()> {
        Err(HypervisorVmError::StartDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn stop_dirty_log(&self) -> VmResult<()> {
        Err(HypervisorVmError::StopDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn get_dirty_log(&self, _slot: u32, _base_gpa: u64, _memory_size: u64) -> VmResult<Vec<u64>> {
        Err(HypervisorVmError::GetDirtyLog(anyhow!(
            "dirty-page logging is not yet implemented for HVF"
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Vcpu
// ---------------------------------------------------------------------------

/// Minimal userspace GICv3 **CPU interface** (experimental, Path A / M-USGIC).
///
/// When Apple's managed GIC is NOT created, guest accesses to the GICv3 CPU
/// interface system registers (`ICC_*_EL1`) trap to the VMM as `EC=0x18`
/// MSR/MRS exceptions (proven on Apple Silicon; also how libkrun, QEMU
/// `kernel-irqchip=off`, and RexPlayer run arm64 guests without `hv_gic`). This
/// struct is the emulated CPU-interface state that services those traps, so the
/// VMM controls exactly which INTID the guest acknowledges — INCLUDING an LPI
/// (`>= 8192`) that the managed GIC can never deliver. Interrupts are asserted
/// into the vCPU with the raw virtual IRQ line
/// (`hv_vcpu_set_pending_interrupt`); the guest then reads `ICC_IAR1_EL1` to
/// learn the INTID (we return it), services it, and writes `ICC_EOIR1_EL1`.
///
/// This is the delivery half that the existing user-space ITS translator
/// ([`crate::hvf::virtio::its`]) has been missing: the ITS resolves a virtio
/// completion to an LPI INTID; this interface hands that INTID to the guest.
#[derive(Default)]
struct UserGic {
    /// Whether the userspace CPU interface is active (no managed GIC; opt-in via
    /// `CHM_USERSPACE_GIC`). When false the `EC=0x18` arm falls through to the
    /// normal unhandled-exception error, preserving default behavior.
    enabled: bool,
    /// Pending INTIDs awaiting acknowledgement (FIFO; priority ordering is a
    /// later refinement). Popped by an `ICC_IAR1_EL1` read.
    pending: Vec<u32>,
    /// The INTID currently between `ICC_IAR1_EL1` (ack) and `ICC_EOIR1_EL1`
    /// (EOI). `None` when the guest is not in an interrupt.
    active: Option<u32>,
    /// Last-written CPU-interface control values (bookkeeping so reads are
    /// coherent; they do not gate the raw-line delivery in this experiment).
    pmr: u64,
    bpr1: u64,
    ctlr: u64,
    igrpen1: u64,
    sre: u64,
    /// The GICv3 distributor model (SPI config + routing). VM-global in the
    /// architecture; kept per-vCPU here for the single-vCPU path (SMP sharing is
    /// a later refinement). Serviced when the guest hits the GICD MMIO frame.
    dist: crate::hvf::softgic::Distributor,
    /// This vCPU's redistributor model (SGI/PPI frame + LPI control registers).
    redist: crate::hvf::softgic::Redistributor,
    /// MMIO base of the distributor frame (`0` = not wired; MMIO falls through to
    /// the device bus). Set on resume from the snapshot's GIC config.
    gicd_base: u64,
    /// MMIO base of this vCPU's redistributor window (`0` = not wired).
    gicr_base: u64,
}

/// GICv3 spurious INTID returned when no interrupt is pending.
const GICV3_INTID_SPURIOUS: u32 = 1023;

/// The EL1 virtual-timer PPI (CNTV → INTID 27), delivered through the software
/// GIC when there is no managed GIC.
const VTIMER_PPI: u32 = 27;

impl UserGic {
    /// Queue an INTID (SPI, PPI, or LPI) for delivery. Priority ordering is a
    /// later refinement; today the pending set is drained FIFO.
    fn push_pending(&mut self, intid: u32) {
        self.pending.push(intid);
    }

    /// Model an `ICC_IAR1_EL1` read (interrupt acknowledge): take the next
    /// pending INTID, mark it active, and return it — or the spurious INTID when
    /// nothing is pending. A read while an interrupt is already active still
    /// acknowledges the next pending one (nested), matching the architecture.
    fn read_iar(&mut self) -> u32 {
        if self.pending.is_empty() {
            return GICV3_INTID_SPURIOUS;
        }
        let intid = self.pending.remove(0);
        self.active = Some(intid);
        intid
    }

    /// Model an `ICC_EOIR1_EL1` write (end of interrupt). With `EOImode=0`
    /// (`ICC_CTLR_EL1.EOImode` clear) this drops priority AND deactivates; with
    /// `EOImode=1` it drops priority only and the guest deactivates later via
    /// `ICC_DIR_EL1`. Keeping `active` set until DIR when `EOImode=1` is what
    /// prevents the next pending interrupt from being delivered while the
    /// current one is still active.
    fn write_eoir(&mut self) {
        let eoimode = (self.ctlr >> 1) & 1 != 0;
        if !eoimode {
            self.active = None;
        }
    }

    /// Model an `ICC_DIR_EL1` write (deactivate interrupt), used with
    /// `EOImode=1` to complete the split priority-drop/deactivate cycle.
    fn write_dir(&mut self) {
        self.active = None;
    }

    /// Whether the raw virtual IRQ line should be asserted before a run entry:
    /// there is pending work and no interrupt is currently active (an active
    /// interrupt keeps the guest in its handler until it EOIs/deactivates).
    fn should_assert(&self) -> bool {
        !self.pending.is_empty() && self.active.is_none()
    }
}

#[cfg(test)]
mod usgic_tests {
    use super::UserGic;

    fn eoimode1() -> UserGic {
        UserGic {
            enabled: true,
            ctlr: 0b10, // EOImode = 1
            ..UserGic::default()
        }
    }

    #[test]
    fn iar_pops_pending_and_marks_active() {
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        g.push_pending(8192);
        g.push_pending(8193);
        assert!(g.should_assert(), "pending + idle should assert the line");
        assert_eq!(g.read_iar(), 8192);
        assert_eq!(g.active, Some(8192));
        // While active, the line must not re-assert for the next pending one.
        assert!(!g.should_assert(), "an active interrupt suppresses re-assert");
    }

    #[test]
    fn spurious_when_empty() {
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        assert_eq!(g.read_iar(), super::GICV3_INTID_SPURIOUS);
        assert_eq!(g.active, None);
    }

    #[test]
    fn eoimode0_eoir_deactivates() {
        let mut g = UserGic {
            enabled: true,
            ctlr: 0, // EOImode = 0
            ..UserGic::default()
        };
        g.push_pending(8192);
        g.push_pending(8193);
        assert_eq!(g.read_iar(), 8192);
        g.write_eoir(); // EOImode=0: drops priority AND deactivates
        assert_eq!(g.active, None);
        // Now the next pending one can be delivered.
        assert!(g.should_assert());
        assert_eq!(g.read_iar(), 8193);
    }

    #[test]
    fn eoimode1_eoir_holds_active_until_dir() {
        let mut g = eoimode1();
        g.push_pending(8192);
        g.push_pending(8193);
        assert_eq!(g.read_iar(), 8192);
        g.write_eoir(); // EOImode=1: priority drop ONLY; stays active
        assert_eq!(g.active, Some(8192), "EOImode=1 EOIR must not deactivate");
        assert!(
            !g.should_assert(),
            "next pending must be held while the first is still active"
        );
        g.write_dir(); // now deactivate
        assert_eq!(g.active, None);
        assert!(g.should_assert(), "after DIR the next pending is deliverable");
        assert_eq!(g.read_iar(), 8193);
    }
}

/// One HVF vCPU. Bound to the host thread that created it.
pub struct HvfVcpu {
    id: u64,
    index: u32,
    exit: *mut HvVcpuExit,
    vm_ops: Option<Arc<dyn VmOps>>,
    /// Wakeup primitive for the WFI idle path. When the guest executes WFI and
    /// no interrupt is yet deliverable, the vCPU thread parks on this fd; a
    /// device/IRQ thread that asserts an interrupt cross-thread calls
    /// `write()` (via a clone from `wake_handle()`) to wake it promptly.
    kick: EventFd,
    /// The virtual-counter offset last programmed via [`Self::restore_vtimer_offset`]
    /// (HVF defines `CNTVCT_EL0 = mach_absolute_time() - offset`). Tracked so a
    /// checkpoint can read the live `CNTVCT_EL0` back — HVF does not expose it
    /// reliably through `hv_vcpu_get_sys_reg` once the vCPU is forced out of
    /// `run()`. Defaults to 0, matching a freshly created vCPU's counter.
    vtimer_offset: AtomicU64,
    /// Monotonic counter bumped once per `run()` iteration. A host-side watchdog
    /// samples it to tell a vCPU that is making progress (returning from
    /// `hv_vcpu_run` for exits) apart from one wedged inside a single
    /// `hv_vcpu_run` call — e.g. blocked in Apple's internal WFI wait
    /// (`wait_for_interrupt`) on a deadline it is not honouring. When the counter
    /// stalls the watchdog forces the vCPU out via [`Self::exit_signal`] so it
    /// re-enters and Apple re-evaluates pending interrupts / the timer deadline.
    run_gen: Arc<AtomicU64>,
    /// Experimental userspace GICv3 CPU interface (see [`UserGic`]). Active only
    /// when no managed GIC is used and `CHM_USERSPACE_GIC` is set.
    usgic: Mutex<UserGic>,
    /// Cross-thread interrupt-injection queue for the userspace GIC. A device or
    /// net-service thread (which does NOT own this vCPU) cannot call
    /// [`hv_vcpu_set_pending_interrupt`] — that is owning-thread only — so it
    /// enqueues the resolved INTID here and wakes the vCPU via [`Self::wake_handle`].
    /// The owning thread drains this queue into `usgic` at the top of every
    /// [`Self::run`] entry, applying the same distributor/redistributor gating a
    /// direct [`Self::usgic_assert_spi`]/[`Self::usgic_inject`] would, then
    /// re-asserts the raw IRQ line. This is how a stock ITS/LPI snapshot's virtio
    /// completions (delivered from the device thread) reach the guest.
    inject_queue: Arc<Mutex<Vec<u32>>>,
}

// SAFETY: HVF requires a vCPU to be created and run on the same thread; the VMM
// upholds this by owning each HvfVcpu on its dedicated vCPU thread. The raw
// `exit` pointer is owned by HVF and only dereferenced by that thread.
unsafe impl Send for HvfVcpu {}
// SAFETY: see the `Send` impl above — access is confined to the owning thread.
unsafe impl Sync for HvfVcpu {}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        // SAFETY: destroy on the owning thread, before the VM is destroyed.
        unsafe {
            hv_vcpu_destroy(self.id);
        }
    }
}

impl HvfVcpu {
    /// Return a clonable handle to this vCPU's WFI wakeup fd. A device/IRQ
    /// thread holds it (alongside the shared GIC) and `write()`s it right after
    /// asserting an interrupt to wake the vCPU from a blocked WFI promptly. Safe
    /// to call cross-thread; the underlying fd/counter is `Arc`-shared.
    pub fn wake_handle(&self) -> EventFd {
        self.kick
            .try_clone()
            .expect("clone of the vCPU wake fd cannot fail")
    }

    /// This vCPU's `hv_vcpu_t` handle. Needed by the user-space ITS to address
    /// per-vCPU GIC virtualization (ICH List Register) injection at the owning
    /// thread.
    pub fn vcpu_id(&self) -> u64 {
        self.id
    }

    fn set_reg(&self, reg: u32, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetRegister(anyhow!(
                "hv_vcpu_set_reg({reg}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    fn get_reg(&self, reg: u32) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_vcpu_get_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetRegister(anyhow!(
                "hv_vcpu_get_reg({reg}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    fn set_sysreg(&self, reg: u16, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_sys_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_vcpu_set_sys_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    fn get_sysreg(&self, reg: u16) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_vcpu_get_sys_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetSysRegister(anyhow!(
                "hv_vcpu_get_sys_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    /// Establish this vCPU's affinity in MPIDR_EL1.
    ///
    /// HVF leaves MPIDR_EL1 reading 0, which lacks the architectural RES1 bit
    /// and — more importantly — leaves Apple's managed GIC unable to associate
    /// the vCPU with its redistributor (the GIC keys redistributors by MPIDR
    /// affinity). Without this, an asserted SPI becomes pending in the
    /// distributor but never forwards to the CPU interface, so the guest never
    /// takes the interrupt. Pack the linear cpu index into the architectural
    /// Aff0[7:0]/Aff1[15:8]/Aff2[23:16]/Aff3[39:32] fields. This is verified for
    /// vCPU0; the exact hv_gic redistributor affinity ordering for multiple
    /// vCPUs remains to be validated when HVF multi-vCPU support lands.
    fn set_mpidr_affinity(&self, cpu_id: u32) -> CpuResult<()> {
        let aff = (u64::from(cpu_id) & 0xff)
            | ((u64::from(cpu_id) >> 8 & 0xff) << 8)
            | ((u64::from(cpu_id) >> 16 & 0xff) << 16)
            | ((u64::from(cpu_id) >> 24 & 0xff) << 32);
        self.set_sysreg(SYSREG_MPIDR_EL1, MPIDR_RES1 | aff)
    }

    /// Read a managed-GIC CPU-interface (ICC) register for this vCPU.
    fn get_icc_reg(&self, reg: u16) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_gic_get_icc_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetSysRegister(anyhow!(
                "hv_gic_get_icc_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    /// Restore virtual-counter continuity from a snapshot's captured
    /// `CNTVCT_EL0`. HVF defines `CNTVCT_EL0 = mach_absolute_time() - offset`,
    /// so seeding the offset with `mach_absolute_time() - snapshot_cntvct` makes
    /// the guest's virtual counter resume at the value it held when snapshotted.
    /// Without this the fresh VM's counter restarts near zero while the guest's
    /// armed `CNTV_CVAL_EL0` comparator sits ~2^32 ticks ahead, so its scheduler
    /// tick never fires and a resumed guest idles in WFI for minutes (and its
    /// soft-lockup watchdog trips on the apparent stall).
    pub fn restore_vtimer_offset(&self, snapshot_cntvct: u64) -> CpuResult<()> {
        // SAFETY: FFI; reads the host monotonic tick.
        let now = unsafe { mach_absolute_time() };
        let offset = now.wrapping_sub(snapshot_cntvct);
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_vcpu_set_vtimer_offset failed: {:#010x}",
                ret as u32
            )));
        }
        // Remember the offset so a later checkpoint can derive the live counter.
        self.vtimer_offset.store(offset, Ordering::Relaxed);
        Ok(())
    }

    /// The guest's current `CNTVCT_EL0`, derived as `mach_absolute_time() -
    /// offset` (HVF's definition) from the offset we last programmed. Used at
    /// checkpoint time because `hv_vcpu_get_sys_reg(CNTVCT_EL0)` is not reliably
    /// readable once the vCPU has been forced out of `run()`.
    pub fn current_cntvct(&self) -> u64 {
        // SAFETY: FFI; reads the host monotonic tick.
        let now = unsafe { mach_absolute_time() };
        now.wrapping_sub(self.vtimer_offset.load(Ordering::Relaxed))
    }

    /// How long (in milliseconds) to park a WFI-idle vCPU on its wake fd before
    /// re-evaluating, derived from the armed virtual-timer deadline.
    ///
    /// While parked the vCPU is outside `hv_vcpu_run`, so HVF's native
    /// virtual-timer delivery is suspended: the guest can only take its next
    /// scheduler tick when we re-enter the guest. A flat poll would therefore
    /// clamp an idle guest's effective tick rate to the poll rate (e.g. 10 Hz
    /// at 100 ms), so an idle-heavy phase like cloud-init or a `serial-getty`
    /// restart crawls or appears wedged. Instead, wake exactly when the guest's
    /// own `CNTV_CVAL_EL0` deadline is due: re-entering `hv_vcpu_run` at that
    /// point lets the managed GIC deliver PPI 27 on time, restoring a
    /// near-native tick rate. When no timer is armed (disabled or masked) we
    /// fall back to the cap, since only a device IRQ (which also kicks the wake
    /// fd) will wake the guest. The result is clamped to `[1, WFI_IDLE_POLL_MS]`.
    fn wfi_park_ms(&self) -> i32 {
        const CNTV_CTL_EL0: u16 = 0xDF19;
        const CNTV_CVAL_EL0: u16 = 0xDF1A;
        let ctl = self.get_sysreg(CNTV_CTL_EL0).unwrap_or(0);
        let enabled = ctl & 1 != 0;
        let masked = ctl & 2 != 0;
        if !enabled || masked {
            return WFI_IDLE_POLL_MS;
        }
        let cval = self.get_sysreg(CNTV_CVAL_EL0).unwrap_or(0);
        let now = self.current_cntvct();
        if cval <= now {
            // Deadline already passed: re-enter immediately so HVF delivers the
            // overdue timer PPI.
            return 0;
        }
        let remaining_ticks = cval - now;
        // Convert mach ticks -> ns -> ms via the host timebase.
        let tb = mach_timebase();
        let remaining_ns = (remaining_ticks as u128) * (tb.numer as u128) / (tb.denom as u128);
        let remaining_ms = (remaining_ns / 1_000_000) as i64;
        remaining_ms.clamp(1, WFI_IDLE_POLL_MS as i64) as i32
    }

    /// After a watchdog-forced exit, unmask the virtual timer (HVF host-side) if
    /// the guest has it enabled, so the managed GIC re-evaluates and delivers
    /// PPI 27 on re-entry. HVF auto-masks the vtimer when it surfaces an
    /// activation, so a guest whose scheduler tick stalled during an idle
    /// transition (e.g. the cloud-init `serial-getty` restart) can sit with the
    /// timer host-masked while Apple's internal WFI wait never redelivers it;
    /// unmasking here breaks that wedge. Idempotent when already unmasked, so it
    /// is safe to call on every forced exit (including a busy compute burst or a
    /// teardown stop). Reads `CNTV_CTL`/`CNTV_CVAL` on the owning thread (valid
    /// here — the vCPU is out of `hv_vcpu_run`) and derives the counter via
    /// [`current_cntvct`] for the diagnostic.
    fn unmask_vtimer_after_cancel(&self) {
        const CNTV_CTL_EL0: u16 = 0xDF19;
        const CNTV_CVAL_EL0: u16 = 0xDF1A;
        let ctl = self.get_sysreg(CNTV_CTL_EL0).unwrap_or(0);
        let enabled = ctl & 1 != 0;
        let guest_masked = ctl & 2 != 0;
        if !enabled || guest_masked {
            return;
        }
        if std::env::var("CHM_TRACE_WATCHDOG").is_ok() {
            let cval = self.get_sysreg(CNTV_CVAL_EL0).unwrap_or(0);
            let now = self.current_cntvct();
            let delta = (cval as i64).wrapping_sub(now as i64);
            eprintln!(
                "[watchdog] vcpu {} forced exit; unmask vtimer CVAL={cval:#x} CNTVCT={now:#x} \
                 cval_minus_cntvct={delta} ({})",
                self.index,
                if delta <= 0 { "OVERDUE" } else { "pending" }
            );
        }
        let _ = gic::rearm_vtimer(self.id);
    }

    // --- Experimental userspace GICv3 CPU interface (Path A / M-USGIC) --------

    /// True when the userspace CPU interface is active for this vCPU.
    fn usgic_enabled(&self) -> bool {
        self.usgic.lock().unwrap().enabled
    }

    /// Enable/disable the experimental userspace CPU interface at runtime (used
    /// by tests; production enables it at creation via `CHM_USERSPACE_GIC`).
    pub fn set_usgic_enabled(&self, on: bool) {
        self.usgic.lock().unwrap().enabled = on;
    }

    /// Re-assert (or clear) the raw virtual IRQ line to match the emulated CPU
    /// interface's pending state before a run entry. Called at the top of
    /// [`Self::run`]. Asserts when an interrupt is pending and none is active;
    /// otherwise leaves the line as-is (an active interrupt keeps the guest in
    /// its handler). No-op unless the userspace GIC is enabled.
    fn usgic_refresh_irq_line(&self) {
        let assert = {
            let g = self.usgic.lock().unwrap();
            if !g.enabled {
                return;
            }
            g.should_assert()
        };
        if assert {
            let _ = self.set_irq_line(true);
        }
    }

    /// Assert or deassert this vCPU's raw virtual IRQ line. Delivery of a queued
    /// interrupt to a guest running the userspace CPU interface is a raw-line
    /// assert; the guest then reads `ICC_IAR1_EL1` (serviced by
    /// [`Self::handle_icc_trap`]) to learn the INTID. Owning-thread only.
    fn set_irq_line(&self, level: bool) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread; sets/clears the virtual IRQ line.
        let rc = unsafe { hv_vcpu_set_pending_interrupt(self.id, HV_INTERRUPT_TYPE_IRQ, level) };
        if rc != HV_SUCCESS {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "hv_vcpu_set_pending_interrupt(irq={level}) failed: {:#010x}",
                rc as u32
            )));
        }
        Ok(())
    }

    /// Inject an interrupt `intid` (SPI, PPI, or an **LPI** `>= 8192`) into this
    /// vCPU through the userspace CPU interface: queue it and assert the raw IRQ
    /// line. This is the delivery path the managed GIC cannot provide for LPIs;
    /// paired with the user-space ITS translator it lets a stock ITS/LPI-routed
    /// snapshot's virtio completions actually reach the guest. Owning-thread
    /// only; a no-op unless the userspace GIC is enabled.
    pub fn usgic_inject(&self, intid: u32) -> CpuResult<()> {
        {
            let mut g = self.usgic.lock().unwrap();
            if !g.enabled {
                return Ok(());
            }
            g.push_pending(intid);
        }
        self.set_irq_line(true)
    }

    /// A clone of this vCPU's cross-thread injection queue. A device/net-service
    /// thread pushes a resolved INTID (an ITS-resolved LPI, a line/message SPI)
    /// here, then wakes the vCPU via [`Self::wake_handle`]; the owning thread
    /// drains it at the next [`Self::run`] entry. This is the only cross-thread-
    /// safe way to inject into the userspace GIC (the raw-line assert itself is
    /// owning-thread only).
    pub fn usgic_inject_queue(&self) -> Arc<Mutex<Vec<u32>>> {
        self.inject_queue.clone()
    }

    /// Drain the cross-thread injection queue into the userspace GIC, applying
    /// the same enable gating as the owning-thread inject paths: an LPI
    /// (`>= 8192`) is always queued (LPI enable rides in the redistributor the
    /// snapshot seeded); a PPI (`< 32`) is gated on the redistributor's per-vCPU
    /// enable; an SPI on the distributor. Called at the top of [`Self::run`].
    /// No-op unless the userspace GIC is enabled.
    fn usgic_drain_injected(&self) {
        let queued: Vec<u32> = {
            let mut q = self.inject_queue.lock().unwrap();
            if q.is_empty() {
                return;
            }
            std::mem::take(&mut *q)
        };
        let mut g = self.usgic.lock().unwrap();
        if !g.enabled {
            return;
        }
        for intid in queued {
            let enabled = if intid >= 8192 {
                true
            } else if intid < 32 {
                g.redist.is_ppi_enabled(intid)
            } else {
                g.dist.assert_spi(intid)
            };
            if enabled {
                g.push_pending(intid);
            }
        }
    }

    /// Wire this vCPU's software distributor/redistributor to their guest MMIO
    /// bases (from the snapshot's GIC config) and size the distributor. After
    /// this, guest accesses to those frames are serviced by the software GIC
    /// instead of faulting to the device bus. `0` bases leave them unwired.
    pub fn usgic_set_gic_bases(&self, gicd_base: u64, gicr_base: u64, num_irqs: u32) {
        let mut g = self.usgic.lock().unwrap();
        g.gicd_base = gicd_base;
        g.gicr_base = gicr_base;
        g.dist = crate::hvf::softgic::Distributor::new(num_irqs);
    }

    /// Seed the software distributor + redistributor from captured KVM GIC state
    /// (the same `(offset, value)` pairs the managed-GIC path restores), so a
    /// resumed guest keeps its interrupt configuration.
    pub fn usgic_seed_gic(&self, dist_regs: &[(u32, u64)], redist_regs: &[(u32, u64)]) {
        let mut g = self.usgic.lock().unwrap();
        g.dist.seed_from_kvm(dist_regs);
        g.redist.seed_from_kvm(redist_regs);
    }

    /// Seed the userspace CPU-interface bookkeeping (PMR, BPR1, CTLR, SRE,
    /// IGRPEN1) from the captured managed-GIC ICC registers. On the userspace-GIC
    /// path there is no managed GIC to write these into via `hv_gic_set_icc_reg`,
    /// so a resumed guest's ICC reads (serviced by [`Self::handle_icc_trap`])
    /// return these seeded values, keeping its CPU-interface view coherent with
    /// what it had at capture. Delivery itself does not gate on them today.
    pub fn usgic_seed_icc(&self, icc: &[(u16, u64)]) {
        let mut g = self.usgic.lock().unwrap();
        for &(reg, v) in icc {
            match reg {
                crate::hvf::ffi::GIC_ICC_PMR_EL1 => g.pmr = v,
                crate::hvf::ffi::GIC_ICC_BPR1_EL1 => g.bpr1 = v,
                crate::hvf::ffi::GIC_ICC_CTLR_EL1 => g.ctlr = v,
                crate::hvf::ffi::GIC_ICC_SRE_EL1 => g.sre = v,
                crate::hvf::ffi::GIC_ICC_IGRPEN1_EL1 => g.igrpen1 = v,
                _ => {}
            }
        }
    }

    /// Service a GICD/GICR MMIO access via the software GIC. Returns `None` if
    /// `ipa` is outside both frames (the caller falls through to the device
    /// bus); `Some(read_value)` when handled (0 for writes).
    fn usgic_mmio(&self, ipa: u64, is_write: bool, write_val: u32) -> Option<u64> {
        let mut g = self.usgic.lock().unwrap();
        if g.gicd_base != 0 && ipa >= g.gicd_base && ipa < g.gicd_base + 0x1_0000 {
            let off = ipa - g.gicd_base;
            if is_write {
                g.dist.write(off, write_val);
                Some(0)
            } else {
                Some(g.dist.read(off) as u64)
            }
        } else if g.gicr_base != 0 && ipa >= g.gicr_base && ipa < g.gicr_base + 0x2_0000 {
            let off = ipa - g.gicr_base;
            if is_write {
                g.redist.write(off, write_val);
                Some(0)
            } else {
                Some(g.redist.read(off) as u64)
            }
        } else {
            None
        }
    }

    /// Assert an SPI (INTID >= 32) or PPI (16..31) into this vCPU: mark it
    /// pending in the distributor/redistributor and, if enabled there, forward it
    /// to the CPU interface and assert the raw IRQ line. This is the delivery
    /// path for line/message SPIs (serial, virtio-INTx) and PPIs (the virtual
    /// timer). Owning-thread only; a no-op unless the userspace GIC is enabled.
    pub fn usgic_assert_spi(&self, intid: u32) -> CpuResult<()> {
        let deliver = {
            let mut g = self.usgic.lock().unwrap();
            if !g.enabled {
                return Ok(());
            }
            // PPIs gate on the redistributor's per-vCPU enable; SPIs on the
            // distributor (which also latches the pending bit).
            let enabled = if intid < 32 {
                g.redist.is_ppi_enabled(intid)
            } else {
                g.dist.assert_spi(intid)
            };
            if enabled {
                g.push_pending(intid);
            }
            enabled
        };
        if deliver {
            self.set_irq_line(true)?;
        }
        Ok(())
    }

    /// Service an `EC=0x18` GICv3 CPU-interface sysreg trap: decode the ISS,
    /// emulate the `ICC_*_EL1` access against [`UserGic`], advance PC past the
    /// trapped instruction. Returns `Ok(true)` when handled, `Ok(false)` for a
    /// sysreg we do not model (caller turns that into an error).
    fn handle_icc_trap(&self, esr: u64) -> CpuResult<bool> {
        let iss = esr & 0x1ff_ffff;
        let is_read = (iss & 1) == 1;
        let crm = ((iss >> 1) & 0xf) as u8;
        let rt = ((iss >> 5) & 0x1f) as u32;
        let crn = ((iss >> 10) & 0xf) as u8;
        let op1 = ((iss >> 14) & 0x7) as u8;
        let op2 = ((iss >> 17) & 0x7) as u8;
        let op0 = ((iss >> 20) & 0x3) as u8;
        // Every GICv3 CPU-interface register is encoded op0=3, op1=0.
        if op0 != 3 || op1 != 0 {
            return Ok(false);
        }
        let trace = std::env::var_os("CHM_TRACE_USGIC").is_some();
        let key = (crn, crm, op2);
        let mut deassert = false;
        let mut set_rt: Option<u64> = None;
        let mut rearm_timer = false;
        let mut sgi_intid: Option<u32> = None;
        let name: &str;
        {
            let mut g = self.usgic.lock().unwrap();
            if is_read {
                let val: u64 = match key {
                    // ICC_IAR1_EL1 / ICC_IAR0_EL1 (interrupt acknowledge).
                    (12, 12, 0) | (12, 8, 0) => {
                        name = "ICC_IAR";
                        g.read_iar() as u64
                    }
                    // ICC_HPPIR1_EL1 (highest pending, no ack).
                    (12, 12, 2) | (12, 8, 2) => {
                        name = "ICC_HPPIR";
                        g.pending.first().copied().unwrap_or(GICV3_INTID_SPURIOUS) as u64
                    }
                    (4, 6, 0) => {
                        name = "ICC_PMR";
                        g.pmr
                    }
                    (12, 12, 3) => {
                        name = "ICC_BPR1";
                        g.bpr1
                    }
                    (12, 12, 4) => {
                        name = "ICC_CTLR";
                        g.ctlr
                    }
                    // Always report SRE=1 so the guest keeps the sysreg interface.
                    (12, 12, 5) => {
                        name = "ICC_SRE";
                        g.sre | 1
                    }
                    (12, 12, 7) => {
                        name = "ICC_IGRPEN1";
                        g.igrpen1
                    }
                    (12, 11, 3) => {
                        name = "ICC_RPR";
                        if g.active.is_some() { 0 } else { 0xff }
                    }
                    _ => {
                        name = "ICC_?rd";
                        0
                    }
                };
                if rt < 31 {
                    set_rt = Some(val);
                }
                deassert = !g.should_assert();
                if trace {
                    eprintln!("[usgic] vcpu {} read  {name} -> {val:#x} (x{rt})", self.index);
                }
            } else {
                let val = if rt == 31 { 0 } else { self.get_reg(rt)? };
                match key {
                    // ICC_EOIR1_EL1 / ICC_EOIR0_EL1 (end of interrupt). With
                    // EOImode=0 (ICC_CTLR_EL1.EOImode clear) this both drops
                    // priority AND deactivates. With EOImode=1 it drops priority
                    // only; the guest deactivates separately via ICC_DIR_EL1.
                    // Keeping `active` set until DIR when EOImode=1 is what stops
                    // a still-active interrupt's slot being reused by the next
                    // pending one (correctness the rubber-duck flagged).
                    (12, 12, 1) | (12, 8, 1) => {
                        name = "ICC_EOIR";
                        let was = g.active;
                        g.write_eoir();
                        // If the virtual-timer PPI just deactivated, re-arm the
                        // HVF vtimer so the guest's next armed deadline fires.
                        if was == Some(VTIMER_PPI) && g.active.is_none() {
                            rearm_timer = true;
                        }
                    }
                    // ICC_DIR_EL1 (deactivate interrupt) — used with EOImode=1.
                    (12, 11, 1) => {
                        name = "ICC_DIR";
                        let was = g.active;
                        g.write_dir();
                        if was == Some(VTIMER_PPI) {
                            rearm_timer = true;
                        }
                    }
                    // ICC_SGI1R_EL1: software-generated interrupt (IPI). The INTID
                    // is bits [27:24]. Single-vCPU delivers to self; multi-target
                    // routing across vCPUs is future SMP work.
                    (12, 11, 5) => {
                        name = "ICC_SGI1R";
                        sgi_intid = Some(((val >> 24) & 0xf) as u32);
                    }
                    (4, 6, 0) => {
                        name = "ICC_PMR";
                        g.pmr = val;
                    }
                    (12, 12, 3) => {
                        name = "ICC_BPR1";
                        g.bpr1 = val;
                    }
                    (12, 12, 4) => {
                        name = "ICC_CTLR";
                        g.ctlr = val;
                    }
                    (12, 12, 5) => {
                        name = "ICC_SRE";
                        g.sre = val | 1;
                    }
                    (12, 12, 7) => {
                        name = "ICC_IGRPEN1";
                        g.igrpen1 = val;
                    }
                    _ => {
                        name = "ICC_?wr";
                    }
                }
                if trace {
                    eprintln!("[usgic] vcpu {} write {name} <- {val:#x} (x{rt})", self.index);
                }
            }
        }
        if let Some(v) = set_rt {
            self.set_reg(rt, v)?;
        }
        if is_read && deassert {
            self.set_irq_line(false)?;
        }
        // The guest EOI'd/deactivated the virtual-timer PPI: unmask the HVF
        // vtimer so its next armed deadline is delivered.
        if rearm_timer {
            let _ = gic::rearm_vtimer(self.id);
        }
        // A software-generated interrupt targets this vCPU: deliver it.
        if let Some(intid) = sgi_intid {
            self.usgic_inject(intid)?;
        }
        // Advance past the trapped MSR/MRS instruction.
        let pc = self.get_reg(HV_REG_PC)?;
        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
        Ok(true)
    }

    fn set_icc_reg(&self, reg: u16, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_gic_set_icc_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_gic_set_icc_reg({reg:#06x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    /// Read a managed-GIC redistributor register for THIS vCPU.
    ///
    /// `reg` is an architectural GICR offset (RD_base or SGI frame); Apple's
    /// `hv_gic_redistributor_reg_t` enum values are those same offsets, so this
    /// is the per-register restore path for the redistributor half of a
    /// translated KVM snapshot (see `hvf::translate::gic_ingest::redist_to_hvf`).
    pub fn redistributor_reg(&self, reg: u32) -> CpuResult<u64> {
        let mut v = 0u64;
        // SAFETY: FFI on the owning thread; out-param valid.
        let ret = unsafe { hv_gic_get_redistributor_reg(self.id, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::GetSysRegister(anyhow!(
                "hv_gic_get_redistributor_reg({reg:#x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(v)
    }

    /// Write a managed-GIC redistributor register for THIS vCPU.
    pub fn set_redistributor_reg(&self, reg: u32, val: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_gic_set_redistributor_reg(self.id, reg, val) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_gic_set_redistributor_reg({reg:#x}) failed: {:#010x}",
                ret as u32
            )));
        }
        Ok(())
    }

    /// Capture this vCPU's live state for a checkpoint. MUST run on the vCPU's
    /// owning host thread. Reads the full architectural register file (via
    /// [`Vcpu::state`]), appends a live `CNTVCT_EL0` read so the virtual timer
    /// keeps continuity on resume (the cold path gets this from the KVM
    /// snapshot), and reads the SGI-frame redistributor registers.
    pub fn capture_checkpoint(&self) -> CpuResult<crate::hvf::checkpoint::VcpuCheckpoint> {
        let CpuState::Hvf(mut state) = <Self as Vcpu>::state(self)?;
        // CNTVCT_EL0 is derived from the tracked vtimer offset (HVF does not let
        // us read it back via hv_vcpu_get_sys_reg here); appending it lets the
        // resume re-seed the offset so the guest's virtual clock stays continuous.
        state
            .sysregs
            .push((SYSREG_CNTVCT_EL0, self.current_cntvct()));
        let mut rdist = Vec::new();
        for off in crate::hvf::translate::gic_ingest::rdist_capture_offsets() {
            rdist.push((off, self.redistributor_reg(off)?));
        }
        Ok(crate::hvf::checkpoint::VcpuCheckpoint { state, rdist })
    }

    /// Service a stage-2 data abort (MMIO) by decoding ESR and calling VmOps.
    fn handle_data_abort(&self, esr: u64, ipa: u64) -> CpuResult<()> {
        let iss = esr & 0x01ff_ffff;
        let isv = (iss >> 24) & 1;
        if isv == 0 {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "MMIO data abort without valid ISS at IPA {ipa:#x} (esr={esr:#x})"
            )));
        }
        let sas = ((iss >> 22) & 0x3) as u32; // 0=B,1=H,2=W,3=D
        let srt = ((iss >> 16) & 0x1f) as u32; // transfer register index
        let is_write = (iss >> 6) & 1 == 1;
        let access = 1usize << sas;

        // Software GIC (userspace path): service GICD/GICR MMIO before falling
        // through to the device bus. A resumed stock ITS/LPI snapshot runs with
        // no managed GIC, so the guest's distributor/redistributor accesses land
        // here as unmapped-IPA data aborts.
        if self.usgic_enabled() {
            let write_val = if is_write && srt != 31 {
                self.get_reg(srt)? as u32
            } else {
                0
            };
            if let Some(read_val) = self.usgic_mmio(ipa, is_write, write_val) {
                if !is_write && srt != 31 {
                    self.set_reg(srt, read_val)?;
                }
                let pc = self.get_reg(HV_REG_PC)?;
                self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
                return Ok(());
            }
        }

        let Some(vm_ops) = self.vm_ops.as_ref() else {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "MMIO at {ipa:#x} but no VmOps registered"
            )));
        };

        if is_write {
            let val = if srt == 31 { 0 } else { self.get_reg(srt)? };
            let bytes = val.to_le_bytes();
            if std::env::var("CHM_TRACE_ABORT").is_ok() {
                eprintln!("[abort] W ipa={ipa:#x} sz={access} val={val:#x}");
            }
            vm_ops
                .mmio_write(ipa, &bytes[..access])
                .map_err(|e| HypervisorCpuError::RunVcpu(e.into()))?;
        } else {
            let mut bytes = [0u8; 8];
            vm_ops
                .mmio_read(ipa, &mut bytes[..access])
                .map_err(|e| HypervisorCpuError::RunVcpu(e.into()))?;
            if std::env::var("CHM_TRACE_ABORT").is_ok() {
                eprintln!(
                    "[abort] R ipa={ipa:#x} sz={access} -> {:#x}",
                    u64::from_le_bytes(bytes)
                );
            }
            if srt != 31 {
                self.set_reg(srt, u64::from_le_bytes(bytes))?;
            }
        }

        // Advance PC past the faulting load/store.
        let pc = self.get_reg(HV_REG_PC)?;
        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
        Ok(())
    }
}

impl Vcpu for HvfVcpu {
    fn create_standard_regs(&self) -> StandardRegisters {
        StandardRegisters::Hvf(HvfStandardRegisters::default())
    }

    fn get_regs(&self) -> CpuResult<StandardRegisters> {
        let mut regs = [0u64; 31];
        for (i, slot) in regs.iter_mut().enumerate() {
            *slot = self.get_reg(i as u32)?;
        }
        Ok(StandardRegisters::Hvf(HvfStandardRegisters {
            regs,
            sp: self.get_sysreg(SYSREG_SP_EL1)?,
            pc: self.get_reg(HV_REG_PC)?,
            pstate: self.get_reg(HV_REG_CPSR)?,
        }))
    }

    fn set_regs(&self, regs: &StandardRegisters) -> CpuResult<()> {
        // Refutable when several backends are compiled in; on an HVF-only build
        // there is a single variant, hence the allow.
        #[allow(irrefutable_let_patterns)]
        let StandardRegisters::Hvf(r) = regs else {
            return Err(HypervisorCpuError::SetStandardRegs(anyhow!(
                "expected HVF StandardRegisters"
            )));
        };
        for (i, v) in r.regs.iter().enumerate() {
            self.set_reg(i as u32, *v)?;
        }
        self.set_reg(HV_REG_PC, r.pc)?;
        self.set_reg(HV_REG_CPSR, r.pstate)?;
        self.set_sysreg(SYSREG_SP_EL1, r.sp)?;
        Ok(())
    }

    fn get_mp_state(&self) -> CpuResult<MpState> {
        Ok(MpState::Hvf)
    }

    fn set_mp_state(&self, _mp_state: MpState) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_init(&self, _kvi: &VcpuInit) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_finalize(&self, _feature: i32) -> CpuResult<()> {
        Ok(())
    }

    fn vcpu_get_finalized_features(&self) -> i32 {
        0
    }

    fn vcpu_set_processor_features(
        &self,
        _vm: &dyn Vm,
        _kvi: &mut VcpuInit,
        _id: u32,
    ) -> CpuResult<()> {
        Ok(())
    }

    fn create_vcpu_init(&self) -> VcpuInit {
        VcpuInit::Hvf(HvfVcpuInit::default())
    }

    fn get_reg_list(&self, reg_list: &mut RegList) -> CpuResult<()> {
        #[allow(irrefutable_let_patterns)]
        if let RegList::Hvf(list) = reg_list {
            list.regs = SNAPSHOT_SYS_REGS.iter().map(|&r| r as u64).collect();
            Ok(())
        } else {
            Err(HypervisorCpuError::GetRegList(anyhow!(
                "expected HVF RegList"
            )))
        }
    }

    fn get_sys_reg(&self, sys_reg: u32) -> CpuResult<u64> {
        self.get_sysreg(sys_reg as u16)
    }

    fn setup_regs(&self, cpu_id: u32, boot_ip: u64, fdt_start: u64) -> CpuResult<()> {
        // EL1h, with DAIF interrupts masked, ready for a cold boot.
        self.set_reg(HV_REG_CPSR, PSTATE_EL1H_DAIF)?;
        self.set_reg(HV_REG_PC, boot_ip)?;
        // Linux/PSCI boot protocol: x0 = device-tree blob address.
        self.set_reg(0, fdt_start)?;
        self.set_mpidr_affinity(cpu_id)?;
        Ok(())
    }

    fn has_pmu_support(&self) -> bool {
        false
    }

    fn init_pmu(&self, _irq: u32) -> CpuResult<()> {
        Err(HypervisorCpuError::InitializePmu(anyhow!(
            "PMU is not yet implemented for HVF"
        )))
    }

    fn state(&self) -> CpuResult<CpuState> {
        let mut gpr = [0u64; 31];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = self.get_reg(i as u32)?;
        }
        let mut sysregs = Vec::with_capacity(SNAPSHOT_SYS_REGS.len());
        for &id in SNAPSHOT_SYS_REGS {
            sysregs.push((id, self.get_sysreg(id)?));
        }
        // Capture the managed-GIC CPU-interface registers. These are absent on a
        // GIC-less VM; in that case the first read fails and we record none.
        let mut gic_icc = Vec::new();
        if self.get_icc_reg(GIC_ICC_SNAPSHOT_REGS[0]).is_ok() {
            for &reg in GIC_ICC_SNAPSHOT_REGS {
                gic_icc.push((reg, self.get_icc_reg(reg)?));
            }
        }
        Ok(CpuState::Hvf(VcpuHvfState {
            gpr,
            pc: self.get_reg(HV_REG_PC)?,
            cpsr: self.get_reg(HV_REG_CPSR)?,
            sp_el1: self.get_sysreg(SYSREG_SP_EL1)?,
            sysregs,
            gic_icc,
            mp_state_running: true,
        }))
    }

    fn set_state(&self, state: &CpuState) -> CpuResult<()> {
        #[allow(irrefutable_let_patterns)]
        let CpuState::Hvf(s) = state else {
            return Err(HypervisorCpuError::SetRegister(anyhow!(
                "expected HVF CpuState"
            )));
        };
        for (i, v) in s.gpr.iter().enumerate() {
            self.set_reg(i as u32, *v)?;
        }
        self.set_reg(HV_REG_PC, s.pc)?;
        self.set_reg(HV_REG_CPSR, s.cpsr)?;
        // Some EL1 system registers may be read-only on a given core; restoring
        // them is best-effort and must not abort the whole restore.
        let _ = self.set_sysreg(SYSREG_SP_EL1, s.sp_el1);
        let mut restored_mpidr = false;
        let mut snapshot_cntvct = None;
        for &(id, v) in &s.sysregs {
            if id == SYSREG_MPIDR_EL1 {
                // MPIDR affinity is load-bearing for GIC interrupt delivery, so
                // it is restored with a hard failure rather than best-effort.
                self.set_sysreg(SYSREG_MPIDR_EL1, v)?;
                restored_mpidr = true;
            } else if id == SYSREG_CNTVCT_EL0 {
                // Read-only: not written as a sysreg. Its value seeds the vtimer
                // offset below so the virtual counter resumes continuously.
                snapshot_cntvct = Some(v);
            } else {
                let _ = self.set_sysreg(id, v);
            }
        }
        if !restored_mpidr {
            // Older snapshots predate capturing MPIDR; synthesize it from this
            // vCPU's index so a restored guest can still take interrupts.
            self.set_mpidr_affinity(self.index)?;
        }
        // Restore virtual-counter continuity if the snapshot carried CNTVCT, so
        // the guest's armed timer fires promptly and time advances on resume.
        if let Some(cntvct) = snapshot_cntvct {
            if std::env::var("CHM_TRACE_VTIMER").is_ok() {
                let cval = self.get_sysreg(0xDF1A).unwrap_or(0);
                let ctl = self.get_sysreg(0xDF19).unwrap_or(0);
                eprintln!(
                    "[vtimer] vcpu {} reseed offset from CNTVCT={cntvct:#x} CVAL={cval:#x} CTL={ctl:#x} (CVAL-CNTVCT={})",
                    self.index,
                    (cval as i64).wrapping_sub(cntvct as i64)
                );
            }
            self.restore_vtimer_offset(cntvct)?;
        } else if std::env::var("CHM_TRACE_VTIMER").is_ok() {
            eprintln!(
                "[vtimer] vcpu {} NO CNTVCT in snapshot -- offset not reseeded",
                self.index
            );
        }
        // Restore the managed-GIC CPU-interface registers (priority mask, group
        // enables, active priorities, ...). These are load-bearing for delivery
        // and live in the GIC, not in the vCPU sysreg file. They are restored
        // after MPIDR so the vCPU is already associated with its redistributor.
        // On the userspace-GIC path there is no managed GIC, so instead seed the
        // emulated CPU interface's bookkeeping from the captured ICC values.
        if self.usgic.lock().unwrap().enabled {
            self.usgic_seed_icc(&s.gic_icc);
        } else {
            for &(reg, v) in &s.gic_icc {
                self.set_icc_reg(reg, v)?;
            }
        }
        Ok(())
    }

    fn exit_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let id = self.id;
        Some(Arc::new(move || {
            let ids = [id];
            // SAFETY: `hv_vcpus_exit` is explicitly safe to call from a thread
            // other than the one running the vCPU; it only needs valid vcpu
            // ids and forces them out of `hv_vcpu_run` (returning CANCELED).
            unsafe {
                let _ = hv_vcpus_exit(ids.as_ptr(), 1);
            }
        }))
    }

    fn wake_signal(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        // A clone of the WFI wake fd the owning vCPU thread parks on. Writing it
        // wakes a vCPU idling in the host-side WFI park (see the `EC_WFX` arm in
        // `run`), so an interrupt asserted cross-thread (a keystroke's serial
        // SPI, a virtio completion) is taken immediately instead of waiting up
        // to `WFI_IDLE_POLL_MS` for the park's re-evaluation poll.
        let fd = self.wake_handle();
        Some(Arc::new(move || {
            let _ = fd.write(1);
        }))
    }

    fn run_progress(&self) -> Option<Arc<AtomicU64>> {
        Some(self.run_gen.clone())
    }

    fn run(&mut self) -> std::result::Result<VmExit, HypervisorCpuError> {
        // Signal forward progress to the host-side run watchdog: each entry into
        // run() bumps this. A vCPU wedged inside a single hv_vcpu_run call (e.g.
        // Apple's internal WFI wait not honouring its deadline) stops bumping it,
        // which the watchdog detects and breaks by forcing an exit.
        self.run_gen.fetch_add(1, Ordering::Relaxed);
        // Drain any cross-thread injections (device/net-service completions) into
        // the userspace GIC before we sample the line — they were enqueued off
        // this vCPU's thread and can only be applied here, on the owning thread.
        self.usgic_drain_injected();
        // Userspace CPU interface: HVF samples the raw virtual IRQ line at run
        // ENTRY (not continuously), so — like QEMU's hvf_inject_interrupts — we
        // must (re)assert it before every entry whenever an interrupt is pending
        // and none is currently active. This is what makes an injected LPI get
        // taken once the guest clears PSTATE.I, regardless of intervening exits.
        self.usgic_refresh_irq_line();
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_run(self.id) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::RunVcpu(anyhow!(
                "hv_vcpu_run failed: {:#010x}",
                ret as u32
            )));
        }
        // SAFETY: `exit` is owned by HVF and valid until the next run() call.
        let exit = unsafe { &*self.exit };
        if std::env::var("CHM_TRACE_EXIT").is_ok() {
            let pc = self.get_reg(HV_REG_PC).unwrap_or(0);
            let ec = if exit.reason == HV_EXIT_REASON_EXCEPTION {
                (exit.exception.syndrome >> 26) & 0x3f
            } else {
                0xff
            };
            eprintln!(
                "[exit] vcpu {} reason={} ec={ec:#x} pc={pc:#x} ipa={:#x}",
                self.index,
                exit.reason,
                if exit.reason == HV_EXIT_REASON_EXCEPTION {
                    exit.exception.physical_address
                } else {
                    0
                }
            );
        }
        match exit.reason {
            HV_EXIT_REASON_EXCEPTION => {
                let esr = exit.exception.syndrome;
                let ipa = exit.exception.physical_address;
                let ec = (esr >> 26) & 0x3f;
                match ec {
                    EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
                        self.handle_data_abort(esr, ipa)?;
                        Ok(VmExit::Ignore)
                    }
                    EC_WFX => {
                        if std::env::var("CHM_TRACE_VTIMER").is_ok() {
                            let cv = self.get_sysreg(SYSREG_CNTVCT_EL0).unwrap_or(0);
                            let cval = self.get_sysreg(0xDF1A).unwrap_or(0);
                            let ctl = self.get_sysreg(0xDF19).unwrap_or(0);
                            eprintln!(
                                "[vtimer] vcpu {} WFI park CNTVCT={cv:#x} CVAL={cval:#x} CTL={ctl:#x}",
                                self.index
                            );
                        }
                        // Trapped WFI/WFE: the guest is idling for an interrupt.
                        // Advance past the instruction so that on re-entry any
                        // interrupt the GIC has since made pending (an asserted
                        // SPI or the virtual timer) is taken. ESR bit0 (TI)
                        // distinguishes WFE from WFI; both are treated the same.
                        //
                        // Apple HVF returns WFx to the host rather than blocking
                        // in-kernel, so we implement the idle here: park the vCPU
                        // thread on its wake fd instead of busy-spinning. A
                        // device/IRQ thread that asserts an interrupt
                        // cross-thread wakes us via `wake_handle().write()`; the
                        // bounded timeout also re-evaluates the GIC periodically
                        // (e.g. for a virtual-timer deadline) so a missing kick
                        // can never wedge the vCPU. On wake we return Ignore and
                        // re-enter the guest, which takes any now-pending IRQ or
                        // re-executes WFI and parks again.
                        let pc = self.get_reg(HV_REG_PC)?;
                        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
                        // Park until kicked or the virtual-timer deadline is due
                        // (see wfi_park_ms); a failed wait just falls through to
                        // a guest re-entry.
                        let _ = self.kick.wait_timeout(self.wfi_park_ms());
                        Ok(VmExit::Ignore)
                    }
                    EC_HVC64 => {
                        // PSCI: x0 carries the function id. PC already points past
                        // the HVC, so do not advance it here.
                        let func = self.get_reg(0)?;
                        if std::env::var("CHM_TRACE_HVC").is_ok() {
                            eprintln!("[hvc] vcpu {} func={func:#x}", self.index);
                        }
                        match func {
                            PSCI_SYSTEM_OFF => Ok(VmExit::Shutdown),
                            PSCI_SYSTEM_RESET => Ok(VmExit::Reset),
                            PSCI_CPU_ON | PSCI_CPU_ON_32 => {
                                let Some(vm_ops) = self.vm_ops.as_ref() else {
                                    self.set_reg(0, SMCCC_NOT_SUPPORTED)?;
                                    return Ok(VmExit::Ignore);
                                };
                                let target_mpidr = self.get_reg(1)?;
                                let entry = self.get_reg(2)?;
                                let context = self.get_reg(3)?;
                                let rc = vm_ops
                                    .psci_vcpu_on(target_mpidr, entry, context)
                                    .map_err(|e| HypervisorCpuError::RunVcpu(e.into()))?;
                                self.set_reg(0, rc as u64)?;
                                Ok(VmExit::Ignore)
                            }
                            TRNG_VERSION => {
                                // Report TRNG firmware interface v1.0
                                // (major in bits[31:16], minor in bits[15:0]).
                                self.set_reg(0, 1u64 << 16)?;
                                Ok(VmExit::Ignore)
                            }
                            TRNG_FEATURES => {
                                let fid = self.get_reg(1)?;
                                let supported = matches!(
                                    fid,
                                    TRNG_VERSION
                                        | TRNG_FEATURES
                                        | TRNG_GET_UUID
                                        | TRNG_RND32
                                        | TRNG_RND64
                                );
                                self.set_reg(
                                    0,
                                    if supported {
                                        SMCCC_SUCCESS
                                    } else {
                                        SMCCC_NOT_SUPPORTED
                                    },
                                )?;
                                Ok(VmExit::Ignore)
                            }
                            TRNG_GET_UUID => {
                                // A stable, non-zero UUID identifying this TRNG.
                                self.set_reg(0, 0x8c2e_b1a0)?;
                                self.set_reg(1, 0x4d8f_11ee)?;
                                self.set_reg(2, 0xa1b2_c3d4)?;
                                self.set_reg(3, 0xe5f6_0718)?;
                                Ok(VmExit::Ignore)
                            }
                            TRNG_RND32 | TRNG_RND64 => {
                                let max_bits = if func == TRNG_RND64 { 192 } else { 96 };
                                let nbits = self.get_reg(1)?;
                                if nbits == 0 || nbits > max_bits {
                                    self.set_reg(0, SMCCC_INVALID_PARAMETER)?;
                                    return Ok(VmExit::Ignore);
                                }
                                // Fill the entropy registers (X3 = least significant,
                                // per SMCCC TRNG) from the host CSPRNG. The guest
                                // masks to nbits; supplying full-width entropy is
                                // both spec-conformant and what Linux's driver reads.
                                let mut bytes = [0u8; 24];
                                host_entropy(&mut bytes);
                                let w = |b: &[u8]| {
                                    let mut a = [0u8; 8];
                                    a.copy_from_slice(b);
                                    u64::from_le_bytes(a)
                                };
                                self.set_reg(1, w(&bytes[0..8]))?;
                                self.set_reg(2, w(&bytes[8..16]))?;
                                self.set_reg(3, w(&bytes[16..24]))?;
                                self.set_reg(0, SMCCC_SUCCESS)?;
                                Ok(VmExit::Ignore)
                            }
                            _ => {
                                // Unknown PSCI/HVC call: report success (0) and
                                // continue so the guest keeps running.
                                self.set_reg(0, 0)?;
                                Ok(VmExit::Ignore)
                            }
                        }
                    }
                    EC_MSR_MRS_64 if self.usgic_enabled() => {
                        // Userspace GICv3 CPU interface: the guest touched an
                        // ICC_*_EL1 register with no managed GIC present, so HVF
                        // trapped it to us. Emulate it (this is what lets us hand
                        // the guest an LPI the managed GIC could never deliver).
                        if self.handle_icc_trap(esr)? {
                            Ok(VmExit::Ignore)
                        } else {
                            Err(HypervisorCpuError::RunVcpu(anyhow!(
                                "usgic: unhandled sysreg trap ESR={esr:#x} (vcpu {})",
                                self.index
                            )))
                        }
                    }
                    _ => Err(HypervisorCpuError::RunVcpu(anyhow!(
                        "unhandled guest exception: EC={ec:#x} ESR={esr:#x} IPA={ipa:#x} (vcpu {})",
                        self.index
                    ))),
                }
            }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                // The virtual timer fired and HVF auto-masked it on exit.
                if self.usgic_enabled() {
                    // No managed GIC: deliver the timer as PPI 27 through the
                    // software GIC (if the guest enabled it in its
                    // redistributor). Leave the HVF vtimer masked until the guest
                    // EOIs the timer interrupt — by then it has re-armed CNTV to a
                    // future deadline, so unmasking on EOI won't immediately
                    // re-fire. The re-arm happens in handle_icc_trap.
                    self.usgic_assert_spi(VTIMER_PPI)?;
                    return Ok(VmExit::Ignore);
                }
                // Managed GIC path: with the managed GIC the timer is normally
                // delivered as GIC PPI 27 without this exit at all (see
                // hvf_guest_takes_virtual_timer); this is the defensive path for
                // when HVF does surface the activation. Re-arm so the GIC
                // re-evaluates and delivers PPI 27 — without asserting the raw IRQ
                // line, which would bypass the GIC and deliver a spurious IRQ.
                if let Err(rc) = gic::rearm_vtimer(self.id) {
                    return Err(HypervisorCpuError::RunVcpu(anyhow!(
                        "failed to re-arm vtimer: {:#010x}",
                        rc as u32
                    )));
                }
                Ok(VmExit::Ignore)
            }
            HV_EXIT_REASON_CANCELED => {
                // A cross-thread `hv_vcpus_exit` forced this return. Two sources:
                // a host-side stop (teardown) or the run watchdog breaking a vCPU
                // wedged inside a single `hv_vcpu_run` — typically Apple's
                // internal WFI wait (`wait_for_interrupt`) failing to honour a due
                // virtual-timer deadline during an idle transition (e.g. the
                // cloud-init `serial-getty` restart). If the timer is enabled,
                // unmasked, and already overdue, re-arm it so the managed GIC
                // redelivers PPI 27 on re-entry and the guest's scheduler tick
                // resumes. Same redelivery as the VTIMER_ACTIVATED path, applied
                // when we (not HVF) surfaced the exit.
                self.unmask_vtimer_after_cancel();
                Ok(VmExit::Ignore)
            }
            other => Err(HypervisorCpuError::RunVcpu(anyhow!(
                "unexpected HVF exit reason: {other}"
            ))),
        }
    }

    fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
        self
    }
}
