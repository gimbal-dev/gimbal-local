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
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;

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
pub mod checkpoint;
#[cfg(feature = "kvm-snapshot")]
pub mod devices;
#[cfg(feature = "kvm-snapshot")]
pub mod rehydrate;
pub mod translate;

/// Which of a capture's system registers this host can actually reproduce.
#[cfg(feature = "kvm-snapshot")]
pub mod sysreg_audit;

pub mod softgic;

/// The address map a cold-booted guest is told about, for device-tree
/// generation. Not needed to rehydrate — a capture brings its own tree.
pub mod coldgic;

#[cfg(feature = "kvm-snapshot")]
pub mod virtio;

/// Host-side instruction-cache maintenance for guests whose kernel had its
/// `ic ivau` alternative-patched out on a `CTR_EL0.DIC = 1` capture host.
pub mod icache_wx;

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
            info = ffi::MachTimebaseInfo {
                numer: 125,
                denom: 3,
            };
        }
        info
    })
}

/// Reduce `a/b` to its lowest terms so a rate scale can be applied as exact
/// integer arithmetic and accumulate no drift. Graviton2's 121_875_000 Hz over
/// Apple silicon's 24_000_000 Hz reduces to exactly 325/64.
fn reduce_ratio(a: u64, b: u64) -> (u64, u64) {
    let (mut x, mut y) = (a, b);
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    let g = x.max(1);
    (a / g, b / g)
}

/// Whether `CHM_DEBUG_VTIMER` asked for per-step virtual-counter tracing.
///
/// One line per accepted offset step — 50/s at the default 20 ms period — naming
/// the host tick, the curve target, and how far the guest's counter jumped.
/// Still cached: this used to sit on the guest-entry path at ~118,000 calls per
/// vCPU per minute, and `env::var_os` allocates.
fn debug_vtimer() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CHM_DEBUG_VTIMER").is_some())
}

/// The guest `CNTVCT_EL0` the scaled curve calls for at host time `now`, given
/// the anchor (`base_host`, `base_guest`) and the reduced rate `num/den`.
///
/// `now.saturating_sub(base_host)` is load-bearing. A `now` behind the anchor
/// means the curve has not started yet, not that ~2^64 ticks have elapsed —
/// wrapping there converts a sub-microsecond thread race into a counter about
/// `2^64 * num/den` ticks ahead, which a guest's monotonic clocksource then
/// latches permanently.
fn scaled_cntvct(base_guest: u64, base_host: u64, now: u64, num: u64, den: u64) -> u64 {
    let elapsed = u128::from(now.saturating_sub(base_host));
    let scaled = elapsed * u128::from(num) / u128::from(den);
    base_guest.wrapping_add(scaled as u64)
}

/// The frequency the host virtual counter actually ticks at, derived from the
/// mach timebase (nanoseconds per tick). Apple silicon reports numer=125,
/// denom=3, i.e. 24 MHz — the value an HVF guest sees in `CNTFRQ_EL0`.
pub fn host_counter_hz() -> u64 {
    let tb = mach_timebase();
    (u64::from(tb.denom) * 1_000_000_000) / u64::from(tb.numer)
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
    // The guest's virtual-timer arming state. CVAL is listed before CTL because
    // `set_state` writes in this order, and arming a deadline before enabling
    // the timer is the safe sequence — the reverse briefly enables a timer
    // against whatever comparator happens to be there.
    //
    // Their absence was #257: a checkpoint that forgets these resumes every vCPU
    // with no tick and no deadline. See `SYSREG_CNTV_CTL_EL0`.
    SYSREG_CNTV_CVAL_EL0,
    SYSREG_CNTV_CTL_EL0,
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

    /// Whether this backend *could* apply to the target it was compiled for.
    ///
    /// This is backend selection in [`crate::new`], not an availability check,
    /// and the distinction is load-bearing: it answers a question about the
    /// **compiler**, so it cannot see the two things that actually stop HVF
    /// working — a missing `com.apple.security.hypervisor` entitlement (which
    /// every `cargo build` strips, making this the most common local failure by
    /// a wide margin) or a host that has no hypervisor device.
    ///
    /// It used to be documented as "available on Apple Silicon Macs with the
    /// hypervisor entitlement" while returning `cfg!(target_os = "macos")`,
    /// which is neither: it was `true` on Intel macOS and `true` for an
    /// unentitled binary that `hv_vm_create` would immediately refuse with
    /// `HV_DENIED`. The arch is now part of the answer; the entitlement cannot
    /// be, because knowing it requires asking the kernel.
    ///
    /// For "will this actually work here", use [`probe_availability`], which
    /// does ask.
    pub fn is_available() -> crate::hypervisor::Result<bool> {
        Ok(cfg!(all(target_os = "macos", target_arch = "aarch64")))
    }
}

/// Ask the kernel whether this process can actually create a VM, by creating
/// one and immediately destroying it.
///
/// The only honest answer to "is HVF available" comes from HVF. Everything
/// cheaper — the target triple, the presence of the framework, a previous
/// success — is a proxy that is wrong in exactly the case that matters most: a
/// freshly `cargo build`-ed binary has lost its entitlement and looks identical
/// to a working one until `hv_vm_create` returns `HV_DENIED`.
///
/// `hv_vm_create` is **process-global**: a process that already has a VM gets
/// `HV_BUSY`, which says nothing about entitlement. A caller that might be
/// hosting a guest must therefore either skip the probe (a running guest is
/// already stronger evidence than any probe) or run it in a child process.
/// `HV_BUSY` is reported as-is rather than folded into a yes or a no.
///
/// Returns the decoded `hv_return_t` description on failure.
pub fn probe_availability() -> Result<(), String> {
    // SAFETY: FFI; NULL config selects HVF defaults, exactly as `create_vm`
    // does. The VM is destroyed before returning, so the process-global slot is
    // left as it was found.
    let ret = unsafe { hv_vm_create(ptr::null_mut()) };
    if ret != HV_SUCCESS {
        return Err(format!("{:#010x} — {}", ret as u32, hv_return_str(ret)));
    }
    // SAFETY: FFI; releases the VM created immediately above.
    let ret = unsafe { ffi::hv_vm_destroy() };
    if ret != HV_SUCCESS {
        return Err(format!(
            "created a VM but could not destroy it: {:#010x} — {}",
            ret as u32,
            hv_return_str(ret)
        ));
    }
    Ok(())
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
                "hv_vm_create failed: {:#010x} — {}",
                ret as u32,
                hv_return_str(ret)
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
            clock: OnceLock::new(),
            programmed_epoch: AtomicU64::new(0),
            cnt_scale_num: AtomicU64::new(0),
            cnt_scale_den: AtomicU64::new(1),
            vtimer_reprogram_failed: AtomicBool::new(false),
            run_gen: Arc::new(AtomicU64::new(0)),
            usgic: Mutex::new(UserGic::default()),
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
/// A 32-bit MMIO register model — the shape both the software GIC's
/// distributor and its redistributor already have.
trait Reg32 {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
}

impl Reg32 for crate::hvf::softgic::Distributor {
    fn read32(&self, offset: u64) -> u32 {
        self.read(offset)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.write(offset, value);
    }
}

impl Reg32 for crate::hvf::softgic::Redistributor {
    fn read32(&self, offset: u64) -> u32 {
        self.read(offset)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.write(offset, value);
    }
}

/// Bridge a guest access of any width onto a 32-bit register model.
///
/// A 64-bit access is split into its two word halves, low first — which is
/// both what the architecture defines for the doubleword registers and what
/// the models already implement (`GICR_TYPER` at `+0x8`/`+0xC`,
/// `GICR_PROPBASER` at `+0x70`/`+0x74`). Narrower accesses go straight
/// through: the models ignore offsets they do not know, and a sub-word access
/// to a GIC register is not something Linux does.
///
/// Returns the value for a read, or 0 for a write.
fn access_32bit_model(
    model: &mut impl Reg32,
    off: u64,
    is_write: bool,
    write_val: u64,
    access: usize,
) -> u64 {
    match (is_write, access) {
        (true, 8) => {
            model.write32(off, write_val as u32);
            model.write32(off + 4, (write_val >> 32) as u32);
            0
        }
        (true, _) => {
            model.write32(off, write_val as u32);
            0
        }
        (false, 8) => u64::from(model.read32(off)) | (u64::from(model.read32(off + 4)) << 32),
        (false, _) => u64::from(model.read32(off)),
    }
}

/// The VM's redistributor frames, one per vCPU, shared by every core.
///
/// A newtype only so `Default` can produce **one** frame rather than none:
/// `UserGic` derives `Default`, and an empty vector would make a single-vCPU
/// guest index out of bounds on its first GICR access.
struct Redists(Arc<Vec<Mutex<crate::hvf::softgic::Redistributor>>>);

impl Default for Redists {
    fn default() -> Self {
        Self(Arc::new(vec![Mutex::new(Default::default())]))
    }
}

impl std::ops::Deref for Redists {
    type Target = Vec<Mutex<crate::hvf::softgic::Redistributor>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Default)]
struct UserGic {
    /// Whether the userspace CPU interface is active for this vCPU. Off unless a
    /// caller turns it on with [`HvfVcpu::set_usgic_enabled`], which
    /// [`crate::hvf::rehydrate::restore_usgic_vcpu`] does for every vCPU it
    /// builds. When false the `EC=0x18` arm falls through to the normal
    /// unhandled-exception error, preserving managed-GIC behaviour.
    enabled: bool,
    /// Pending INTIDs awaiting acknowledgement (FIFO; priority ordering is a
    /// later refinement). Popped by an `ICC_IAR1_EL1` read.
    pending: Vec<u32>,
    /// The INTIDs acknowledged (`ICC_IAR1_EL1`) and not yet deactivated,
    /// innermost last — the architecture's active-priority stack, not a single
    /// slot.
    ///
    /// It has to be a stack because [`HvfVcpu::usgic_assert_spi`] raises the raw
    /// IRQ line whenever a source fires, without consulting [`Self::should_assert`]
    /// — so a device interrupt genuinely can arrive while the guest is inside
    /// another handler, and the guest genuinely does acknowledge it. A single
    /// slot silently forgot the outer INTID, which made
    /// "did the virtual timer just deactivate?" unanswerable exactly when a
    /// busy guest nested anything inside its own timer tick.
    active: Vec<u32>,
    /// How many times a source tried to re-queue an INTID that was already
    /// active *beneath* a nested handler, and was refused.
    ///
    /// This counts the exact save the active stack makes over the single slot
    /// it replaced, and it is the measurement #262 asks for. The dominant
    /// source is [`HvfVcpu::usgic_poll_vtimer`], which runs at every run entry
    /// and re-asserts PPI 27 whenever the guest's armed deadline has passed —
    /// including while the guest is still inside the timer handler it has not
    /// yet answered by writing the next `CNTV_CVAL_EL0`. With a single slot the
    /// dedup compared against the innermost INTID only, so a device interrupt
    /// nesting inside the timer tick made this fail open and delivered PPI 27 a
    /// second time, re-entrantly, desynchronizing the guest's EOI count — the
    /// very thing [`Self::push_pending`] documents itself as preventing.
    ///
    /// A non-zero value on a real workload is therefore evidence that the
    /// #257/#262 wedge had this mechanism available to it; a zero value across
    /// hours of load is evidence that it did not, and that the fix is not the
    /// cure. Reported under `CHM_TRACE_USGIC`.
    nested_requeues_refused: u64,
    /// When this vCPU's armed virtual-timer deadline was first seen overdue with
    /// PPI 27 still not acknowledged, and across how many consecutive run
    /// entries. Cleared the instant the guest acknowledges 27 or re-arms past
    /// `now`, so in health these reset every tick.
    ///
    /// Both halves are required to call it a wedge, and the entry count is the
    /// half that matters: wall-clock alone cannot tell "the guest's tick stopped"
    /// from "this VM was suspended for an hour", because a suspend produces one
    /// run entry with an enormous gap rather than thousands of entries that each
    /// still see the deadline passed. See [`HvfVcpu::usgic_note_vtimer_overdue`].
    ///
    /// The two halves are reached at wildly different times — a wedged vCPU
    /// re-enters in a tight spin, because `wfi_park_ms` returns 0 once the
    /// deadline has passed — so the crossing must be a `>=` latched by
    /// `vtimer_overdue_reported`, never an equality on either counter. An
    /// equality test on the entry count passed every unit test here and could
    /// not fire on hardware even once: entry 200 arrives milliseconds into a
    /// wedge and the dwell has another ten seconds to run.
    vtimer_overdue_since: Option<Instant>,
    vtimer_overdue_entries: u64,
    vtimer_overdue_reported: bool,
    /// How many wedge reports this vCPU has emitted, and the console-triggered
    /// request generation it has already answered. Both exist to bound output:
    /// the condition that produces a report is by definition persistent, so
    /// without a cap it would print on every run entry for the rest of the run.
    wedge_reports: u32,
    wedge_request_seen: u64,
    /// Fault-injection bookkeeping for `CHM_USGIC_LEAK_ACTIVE`; inert otherwise.
    vtimer_deactivations: u64,
    leaked: bool,
    /// Last-written CPU-interface control values (bookkeeping so reads are
    /// coherent; they do not gate the raw-line delivery in this experiment).
    pmr: u64,
    bpr1: u64,
    ctlr: u64,
    igrpen1: u64,
    sre: u64,
    /// The GICv3 distributor model (SPI config + routing). VM-global in the
    /// architecture: behind an `Arc<Mutex<>>` shared across every vCPU of the VM,
    /// so a reprogram (enable/priority/affinity) on any core is visible to all
    /// and an SPI routes to the target vCPU its `GICD_IROUTER` names. Serviced
    /// when the guest hits the GICD MMIO frame. On the single-vCPU path this is
    /// simply that vCPU's own distributor.
    dist: Arc<Mutex<crate::hvf::softgic::Distributor>>,
    /// Every vCPU's redistributor model (SGI/PPI frame + LPI control
    /// registers), indexed by vCPU id and shared by all cores.
    ///
    /// Shared rather than owned because a redistributor frame is *not* private
    /// to its core on real hardware, and Linux relies on that: the boot CPU's
    /// `gic_iterate_rdists` walks every frame in the region reading
    /// `GICR_TYPER` until it finds `Last`. A core that decoded only its own
    /// frame would fault the boot CPU on the second one. A rehydrated guest
    /// discovered its GIC on the KVM host before capture, which is why this
    /// only became load-bearing once something cold-booted.
    ///
    /// Defaults to a single frame so the single-vCPU and restore paths are
    /// unchanged.
    redists: Redists,
    /// Which frame in `redists` belongs to this vCPU.
    redist_index: usize,
    /// MMIO base of the distributor frame (`0` = not wired; MMIO falls through to
    /// the device bus). Set on resume from the snapshot's GIC config.
    gicd_base: u64,
    /// MMIO base of this vCPU's redistributor window (`0` = not wired).
    gicr_base: u64,
    /// SMP: handles to every vCPU's cross-thread injection queue + wake, indexed
    /// by vCPU id, so a software-generated interrupt (SGI / IPI) raised on this
    /// core can be routed to the target core(s). `None` on the single-vCPU path
    /// (an SGI is delivered to self). Set once, after all vCPUs are created.
    cpu_table: Option<Arc<Vec<UsgicCpuHandle>>>,
}

/// One vCPU's cross-thread delivery handles, used to route an SGI (IPI) from any
/// core to this core: push the INTID into its injection queue, then wake its
/// thread so the run-entry drain picks it up.
pub struct UsgicCpuHandle {
    /// This vCPU's cross-thread injection queue ([`HvfVcpu::usgic_inject_queue`]).
    pub inject: Arc<Mutex<Vec<u32>>>,
    /// A wake handle for this vCPU's idle-park fd ([`HvfVcpu::wake_handle`]).
    pub wake: EventFd,
}

/// Cross-thread SPI delivery with affinity routing. A device or console thread
/// (which does not own any vCPU) delivers a line/message SPI here; the router
/// reads the shared distributor's `GICD_IROUTER` for that INTID, resolves the
/// target vCPU, and pushes the INTID into that vCPU's injection queue + wakes
/// it. This is what lets an SPI land on the core its affinity names (e.g. after
/// the guest writes `/proc/irq/<n>/smp_affinity`), instead of always the boot
/// CPU. On the single-vCPU path there is one target, so it is a no-op change.
#[derive(Clone)]
pub struct UsgicSpiRouter {
    dist: Arc<Mutex<crate::hvf::softgic::Distributor>>,
    cpus: Arc<Vec<UsgicCpuHandle>>,
}

impl UsgicSpiRouter {
    /// Build a router over the VM-global distributor and the per-vCPU delivery
    /// table.
    pub fn new(
        dist: Arc<Mutex<crate::hvf::softgic::Distributor>>,
        cpus: Arc<Vec<UsgicCpuHandle>>,
    ) -> Self {
        Self { dist, cpus }
    }

    /// Deliver an SPI to the vCPU its `GICD_IROUTER` targets: resolve the target
    /// (affinity Aff0 == vCPU id in the layout we resume; 1-of-N routes to the
    /// boot CPU), push the INTID into that vCPU's injection queue, and wake it.
    pub fn deliver_spi(&self, intid: u32) {
        let target = {
            let d = self.dist.lock().unwrap();
            resolve_spi_target(d.spi_target_affinity(intid), self.cpus.len())
        };
        if let Some(h) = self.cpus.get(target) {
            h.inject.lock().unwrap().push(intid);
            let _ = h.wake.write(1);
        }
    }
}

/// Resolve an SPI's `GICD_IROUTER` affinity to a target vCPU id. The guests we
/// resume assign `MPIDR.Aff0 == vCPU index` with Aff1..3 == 0 (verified against
/// captured snapshots), so the target is `affinity & 0xff` clamped to the vCPU
/// count. `None` affinity is `GICD_IROUTER.IRM == 1` (1-of-N: any participating
/// PE) — we deliver to the boot CPU (0), a valid choice for 1-of-N. Extracted as
/// a pure function so the routing is unit-testable without a live VM.
fn resolve_spi_target(affinity: Option<u64>, n: usize) -> usize {
    match affinity {
        None => 0,
        Some(aff) => {
            let id = (aff & 0xff) as usize;
            if id < n { id } else { 0 }
        }
    }
}

/// GICv3 spurious INTID returned when no interrupt is pending.
const GICV3_INTID_SPURIOUS: u32 = 1023;

/// The EL1 virtual-timer PPI (CNTV → INTID 27), delivered through the software
/// GIC when there is no managed GIC.
const VTIMER_PPI: u32 = 27;

/// `PSTATE.I` — the EL1 IRQ mask bit in `CPSR`. A guest running with this set
/// cannot take an interrupt no matter how correctly we deliver it, which is why
/// the wedge report reads it before blaming delivery.
const PSTATE_I: u64 = 1 << 7;

/// How long a live virtual-timer deadline must stay passed, and across how many
/// consecutive run entries, before the vCPU is reported as wedged.
///
/// Both are needed and they rule out different things. The dwell is what
/// separates a wedge from an ordinary scheduling hiccup: a healthy guest's
/// deadline is overdue for microseconds, between the deadline passing and the
/// handler arming the next one. The entry count is what separates it from a
/// *suspended* VM, which produces one run entry spanning the whole gap rather
/// than thousands. The existing run watchdog forces an exit every 30 ms, so a
/// running vCPU re-enters at least ~33 times a second and reaches the count in
/// well under the dwell; a resumed one cannot reach it at all.
///
/// Ten seconds is chosen to fire *before* the guest's own RCU stall detector,
/// which needs 60 s — so the state is captured early in the wedge rather than a
/// minute into it.
const WEDGE_OVERDUE_DWELL: std::time::Duration = std::time::Duration::from_secs(10);
const WEDGE_OVERDUE_ENTRIES: u64 = 200;

/// How many wedge reports a single vCPU will emit. The condition is permanent by
/// construction, so this is what stops one wedge printing forever.
const WEDGE_REPORT_LIMIT: u32 = 3;

/// Bumped by [`request_wedge_report`]; each vCPU compares it against its own
/// last-seen value at its next run entry.
static WEDGE_REPORT_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Ask every vCPU to report its interrupt-delivery state at its next run entry.
///
/// Called from the console reader when the *guest kernel* announces that its own
/// tick has stopped (`rcu_preempt kthread starved`, `detected stalls on
/// CPUs/tasks`). Routing it through a request rather than reporting directly is
/// not indirection for its own sake: HVF binds a vCPU to the thread that created
/// it, so a vCPU's registers — the timer deadline, `PC`, `PSTATE` — are readable
/// *only* on that thread, and the console runs on another one.
///
/// This trigger is not redundant with the overdue-dwell one. That one is built
/// on our own counter, so it is structurally blind to the case where our counter
/// is wrong: if we believe the deadline has not arrived, we never assert and
/// never accumulate dwell, no matter how stopped the guest's tick is. The guest
/// kernel is the only observer that can report *that*.
pub fn request_wedge_report() {
    WEDGE_REPORT_REQUESTS.fetch_add(1, Ordering::Relaxed);
    roll_call();
}

/// The largest vCPU index the roll call tracks.
const ROLL_CALL_VCPUS: usize = 64;

/// A vCPU is *silent* once this long has passed with no run entry. Well beyond
/// any legitimate `NO_HZ` nap, which `wfi_park_ms` bounds by the guest's own
/// next deadline, and well inside the 60 s the guest's own detectors need.
const ROLL_CALL_SILENCE: u64 = 5_000;

/// Milliseconds (monotonic) at each vCPU's last run entry, plus a packed
/// snapshot of what its GIC held there. Published by the vCPU, read by anyone.
///
/// This exists because **both wedge triggers require the wedged vCPU to reach a
/// run entry, and the one shape that matters most does not.** The overdue-dwell
/// trigger counts entries; the console trigger is serviced at an entry. A vCPU
/// parked in WFI waiting for a tick that will never arrive makes no entries at
/// all, so it cannot report on itself, and the healthy sibling answering the
/// same request produces a clean bill of health for the wrong CPU. That is
/// exactly what a real wedge looked like: the guest said `Possible timer
/// handling issue on cpu=0` while our own report described vcpu 1.
///
/// Published state is a compromise the platform forces. `CNTV_*`, `PC` and
/// `PSTATE` are readable only on the owning thread, so they cannot appear here —
/// but the load-bearing fact, whether an INTID is stuck active, lives in the
/// GIC and can be.
static ROLL_CALL_SEEN: [AtomicU64; ROLL_CALL_VCPUS] =
    [const { AtomicU64::new(0) }; ROLL_CALL_VCPUS];
static ROLL_CALL_GIC: [AtomicU64; ROLL_CALL_VCPUS] = [const { AtomicU64::new(0) }; ROLL_CALL_VCPUS];

/// Monotonic milliseconds since process start.
fn now_ms() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Pack a vCPU's GIC state into one word so it can be published without a lock.
/// `+1` on the timestamp so a published zero stays distinguishable from "this
/// vCPU has never run", which is the state every unused index is in.
fn pack_gic(vtimer_active: bool, active: usize, pending: usize, depth: usize) -> u64 {
    (u64::from(vtimer_active))
        | ((active.min(0xFF) as u64) << 1)
        | ((pending.min(0xFF) as u64) << 9)
        | ((depth.min(0xFF) as u64) << 17)
}

/// Name every vCPU that has stopped entering the guest, and say what its GIC
/// held when it last did.
///
/// Printed alongside the per-vCPU reports rather than instead of them: a running
/// vCPU can say far more about itself than this can, and a silent one can say
/// nothing at all.
fn roll_call() {
    let now = now_ms();
    for (idx, seen) in ROLL_CALL_SEEN.iter().enumerate() {
        let last = seen.load(Ordering::Relaxed);
        if last == 0 {
            continue; // never ran: not a vCPU of this VM
        }
        let quiet_for = now.saturating_sub(last - 1);
        if quiet_for < ROLL_CALL_SILENCE {
            continue;
        }
        let g = ROLL_CALL_GIC[idx].load(Ordering::Relaxed);
        let vtimer_active = g & 1 != 0;
        let verdict = if vtimer_active {
            "the timer PPI was stuck active at its last entry — it is waiting for \
             a tick that cannot be re-queued (#257/#302 shape)"
        } else {
            "no INTID was stuck; it is parked for another reason"
        };
        eprintln!(
            "[wedge] vcpu {idx} trigger=roll-call: no run entry for {:.1}s — {verdict}",
            quiet_for as f64 / 1000.0,
        );
        eprintln!(
            "[wedge] vcpu {idx}   at its last entry: active={} pending={} depth={} \
             vtimer_active={vtimer_active}",
            (g >> 1) & 0xFF,
            (g >> 9) & 0xFF,
            (g >> 17) & 0xFF,
        );
    }
}

/// What a wedge report observed, as the facts the verdict turns on.
#[derive(Clone, Copy)]
struct WedgeFacts {
    active_empty: bool,
    timer_live: bool,
    /// `CNTVCT - CVAL`, signed: negative means the deadline is still ahead.
    overdue_by: i128,
    /// The guest's own counter frequency, in ticks per second. Only used to give
    /// [`WedgeFacts::overdue_by`] a magnitude: "the deadline is ahead of us" is a
    /// different finding at 273 microseconds than at thirty seconds, and reading
    /// the sign alone conflates them.
    guest_hz: u128,
    irqs_masked: bool,
    vtimer_pending: bool,
}

/// How far ahead the guest's deadline must be, in seconds, before a stall the
/// guest reported is blamed on our counter rather than on the guest simply
/// being between ticks.
///
/// The guest's own detectors need **sixty seconds** of missed ticks before they
/// say anything, so a counter disagreement large enough to explain one of their
/// reports cannot be sub-second. Measured on the benign post-resume stall this
/// separates: the deadline was 33,266 guest ticks out — 273 microseconds —
/// while the guest was complaining about a 60-second gap it had already
/// recovered from.
const WEDGE_CLOCK_SKEW_SECONDS: u128 = 1;

/// Decide who owns a stalled tick, from the state captured at the stall.
///
/// The order of these arms is the argument, not a formatting choice, because
/// several of them can be true at once and only the first is the *cause*:
///
/// 1. A stuck active INTID is checked first because it explains everything
///    downstream — while it is set, [`UserGic::push_pending`] refuses to
///    re-queue, so 27 is legitimately *not* pending and a later arm would
///    misread that absence as a guest fault. Ours; the #262/#302 shape.
/// 2. A timer the guest has disabled or masked is not a delivery failure at
///    all, and must be excluded before anything is blamed for non-delivery.
/// 3. A deadline still in the future, reported as stalled *by the guest*, can
///    only mean our counter and the guest's disagree — but only once it is far
///    enough ahead to explain the sixty seconds of missed ticks the guest needs
///    before it says anything. It has its own arm because folding it into
///    "guest-side" would send a counter-scaling bug down the instruction-cache
///    path — the failure mode that made the sixth reproduction attempt
///    worthless.
/// 4. A deadline only *just* ahead is the opposite finding: nothing is stuck and
///    the next tick is imminent, so the stall the guest reported is behind it.
///    This is the benign post-resume case, and it must not be filed as a clock
///    bug — a diagnostic that names the wrong subsystem costs more than one that
///    says nothing.
/// 5. `PSTATE.I` set is separated from the general guest-side case for the same
///    reason: a guest that has disabled interrupts is not failing to *take* an
///    interrupt, it is refusing one, and only one of those is DIC territory.
fn wedge_verdict(f: WedgeFacts) -> &'static str {
    let skew_floor = -((f.guest_hz * WEDGE_CLOCK_SKEW_SECONDS) as i128);
    if !f.active_empty {
        "gic-model: an INTID is stuck active, so re-queue is refused — ours (#262/#302 shape)"
    } else if !f.timer_live {
        "guest-idle: the guest's own timer is disabled or masked; not a delivery failure"
    } else if f.overdue_by < skew_floor {
        "clock: the guest reports a stopped tick but our counter says its deadline is still far \
         off — counter offset/scale, not the GIC"
    } else if f.overdue_by < 0 {
        "recovered: nothing is stuck and the next tick is imminent — the stall the guest reported \
         is behind it (the benign post-resume case)"
    } else if f.irqs_masked {
        "guest-masked: delivered, but the guest is running with PSTATE.I set"
    } else if f.vtimer_pending {
        "guest-side: delivered with interrupts enabled and not taken — i-cache/DIC territory"
    } else {
        "unclassified: the timer is live and overdue but 27 is neither pending nor active"
    }
}

/// Whether an `ICC_SGI1R_EL1` write targets the core `cand_id`, given the raw
/// register value and the writing core's id. The register encodes the routing
/// mode in bit [40] (1 = all cores except the writer / "broadcast but self") and
/// otherwise an Aff0 target-list in bits [15:0] (bit i selects the core whose
/// MPIDR Aff0 == i — the linear per-core affinity cloud-hypervisor assigns for
/// the small vCPU counts we resume). Extracted as a pure function so the SGI
/// routing is unit-testable without a live VM.
fn sgi_targets_core(sgi: u64, self_id: usize, cand_id: usize) -> bool {
    let irm_all_but_self = (sgi >> 40) & 1 != 0;
    if irm_all_but_self {
        cand_id != self_id
    } else {
        let target_list = (sgi & 0xffff) as u16;
        cand_id < 16 && (target_list >> cand_id) & 1 != 0
    }
}

impl UserGic {
    /// This vCPU's own redistributor frame.
    fn my_redist(&self) -> std::sync::MutexGuard<'_, crate::hvf::softgic::Redistributor> {
        self.redists[self.redist_index].lock().unwrap()
    }

    /// Decode a guest-physical address inside the redistributor *region* into
    /// `(frame index, byte offset within that frame)`.
    ///
    /// The region is contiguous and frame `k` sits at `region + k * 128 KiB`,
    /// so this vCPU's own base minus its own index recovers the region base.
    /// Every core decodes the whole region, not just its own frame: see the
    /// `redists` field docs.
    fn redist_frame(&self, ipa: u64) -> Option<(usize, u64)> {
        const FRAME: u64 = 0x2_0000;
        if self.gicr_base == 0 {
            return None;
        }
        let region = self.gicr_base.checked_sub(self.redist_index as u64 * FRAME)?;
        let span = self.redists.len() as u64 * FRAME;
        if ipa < region || ipa >= region + span {
            return None;
        }
        let off = ipa - region;
        Some(((off / FRAME) as usize, off % FRAME))
    }

    /// Queue an INTID (SPI, PPI, or LPI) for delivery. Priority ordering is a
    /// later refinement; today the pending set is drained FIFO. Deduplicated: an
    /// INTID already pending or currently active is not re-queued, so a source
    /// that can assert the same line from two paths (e.g. the virtual timer via
    /// both the run-entry poll and a residual `VTIMER_ACTIVATED`) delivers it
    /// exactly once — a second copy would desynchronize the guest's EOI count.
    fn push_pending(&mut self, intid: u32) {
        if self.is_active(intid) {
            // Nested: active, but not the handler the guest is running now. A
            // single-slot `active` could not see this and re-queued. Counted so
            // a long run can say whether the case is real. See
            // [`Self::nested_requeues_refused`].
            if self.active_top() != Some(intid) {
                self.nested_requeues_refused += 1;
            }
            return;
        }
        if self.pending.contains(&intid) {
            return;
        }
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
        self.active.push(intid);
        // The guest has taken the tick: whatever overdue dwell was accumulating
        // is answered. Clearing here rather than in the poll is deliberate — the
        // poll only observes what we *offered*, and the wedge is precisely the
        // case where offering and taking come apart.
        if intid == VTIMER_PPI {
            self.vtimer_overdue_since = None;
            self.vtimer_overdue_entries = 0;
            self.vtimer_overdue_reported = false;
        }
        intid
    }

    /// Accumulate one overdue run entry and say whether this is the entry that
    /// crosses into "wedged" for the first time.
    ///
    /// Called only when the guest's timer is live (`ENABLE` set, `IMASK` clear)
    /// and its own armed deadline has passed — so this is not "the vCPU is
    /// quiet", it is "the guest asked for a tick, its deadline came, and it has
    /// still not taken it". That distinction is the whole soundness argument: an
    /// idle guest under `NO_HZ`, an offlined core, or a guest that has migrated
    /// all work to one CPU each arms nothing or arms far ahead, so none of them
    /// reach here at all.
    ///
    /// Two thresholds must both be crossed, and [`WEDGE_OVERDUE_ENTRIES`] is the
    /// one that rules out a suspended VM: a suspend of any length produces a
    /// *single* run entry across the gap, never thousands, so wall-clock alone
    /// would report every resume as a wedge.
    ///
    /// **They are not reached together, and that is the trap.** A wedged vCPU
    /// re-enters in a tight spin, because `wfi_park_ms` returns 0 the moment the
    /// deadline is behind us — so the entry count is satisfied within
    /// milliseconds while the dwell has another ten seconds to run. An equality
    /// test on the entry count is therefore a race that essentially never lands:
    /// it passed every unit test and could not fire once on hardware. Hence
    /// `>=` on both, latched so the report is emitted once per episode.
    ///
    /// Takes `now` rather than reading the clock so the crossing is testable
    /// without a vCPU; the caller on the vCPU thread passes `Instant::now()`.
    fn note_vtimer_overdue(&mut self, now: Instant) -> bool {
        let since = *self.vtimer_overdue_since.get_or_insert(now);
        self.vtimer_overdue_entries = self.vtimer_overdue_entries.saturating_add(1);
        if self.vtimer_overdue_reported {
            return false;
        }
        let crossed = self.vtimer_overdue_entries >= WEDGE_OVERDUE_ENTRIES
            && now.duration_since(since) >= WEDGE_OVERDUE_DWELL;
        self.vtimer_overdue_reported = crossed;
        crossed
    }

    /// Forget any accumulated overdue dwell: the guest's deadline is in the
    /// future again, which it can only be because the tick was taken and the
    /// handler armed the next one.
    fn clear_vtimer_overdue(&mut self) {
        if self.vtimer_overdue_since.is_some() {
            self.vtimer_overdue_since = None;
            self.vtimer_overdue_entries = 0;
            self.vtimer_overdue_reported = false;
        }
    }
    /// Model an `ICC_EOIR1_EL1` write (end of interrupt). With `EOImode=0`
    /// (`ICC_CTLR_EL1.EOImode` clear) this drops priority AND deactivates; with
    /// `EOImode=1` it drops priority only and the guest deactivates later via
    /// `ICC_DIR_EL1`. Keeping `active` set until DIR when `EOImode=1` is what
    /// prevents the next pending interrupt from being delivered while the
    /// current one is still active.
    fn write_eoir(&mut self, intid: u32) {
        let eoimode = (self.ctlr >> 1) & 1 != 0;
        if !eoimode {
            self.deactivate(intid);
        }
    }

    /// Model an `ICC_DIR_EL1` write (deactivate interrupt), used with
    /// `EOImode=1` to complete the split priority-drop/deactivate cycle.
    fn write_dir(&mut self, intid: u32) {
        self.deactivate(intid);
    }

    /// Remove the innermost activation of `intid` from the active stack.
    ///
    /// The guest *names* the INTID in both `ICC_EOIR1_EL1` and `ICC_DIR_EL1`,
    /// and honouring that name — rather than popping whatever happens to be on
    /// top — is what makes an unmatched or out-of-order deactivate safe. Two
    /// distinct failures come from popping the top instead, and the second one
    /// is unrecoverable:
    ///
    /// 1. A deactivate for an INTID this model never made active (a residual
    ///    from before restore, an interrupt HVF delivered on the managed path)
    ///    silently deactivates an *unrelated* interrupt that is still live.
    /// 2. The named INTID stays on the stack **forever**. That is permanent for
    ///    the virtual timer specifically: [`Self::push_pending`] refuses to
    ///    re-queue an INTID that is active at any depth, so once PPI 27 is
    ///    buried, [`HvfVcpu::usgic_poll_vtimer`] asserts it at every single run
    ///    entry and is refused every time. The vCPU's tick never returns, while
    ///    its siblings — which have their own model — stay healthy. See #257.
    ///
    /// Searching from the top removes the innermost activation, which is the
    /// one a correctly-nested guest is completing.
    fn deactivate(&mut self, intid: u32) {
        if self.leak_this_deactivation(intid) {
            return;
        }
        if let Some(pos) = self.active.iter().rposition(|&a| a == intid) {
            self.active.remove(pos);
        }
    }

    /// The innermost acknowledged INTID, or `None` outside any handler.
    fn active_top(&self) -> Option<u32> {
        self.active.last().copied()
    }

    /// Whether `intid` is acknowledged and not yet deactivated at any depth.
    fn is_active(&self, intid: u32) -> bool {
        self.active.contains(&intid)
    }

    /// Whether an EOI/DIR naming `wrote` has just taken the virtual-timer PPI
    /// out of the active stack, i.e. whether HVF's auto-masked vtimer must now
    /// be re-armed.
    ///
    /// Call *after* the write. Both halves matter and neither is redundant:
    /// under `EOImode=1` the EOI drops priority without deactivating, so 27 is
    /// still active and re-arming would storm; and when 27 sits *underneath* a
    /// nested handler, an inner handler's EOI names a different INTID and must
    /// not re-arm it either. Asking the whole stack is what makes the second
    /// case answerable at all.
    ///
    /// `wrote` is the INTID the guest named, not the top of the stack: those
    /// coincide only for a perfectly nested guest, and the whole point of
    /// [`Self::deactivate`] is that we no longer assume they do.
    fn vtimer_just_deactivated(&self, wrote: Option<u32>) -> bool {
        wrote == Some(VTIMER_PPI) && !self.is_active(VTIMER_PPI)
    }

    /// Whether the raw virtual IRQ line should be asserted before a run entry:
    /// there is pending work and no interrupt is currently active (an active
    /// interrupt keeps the guest in its handler until it EOIs/deactivates).
    fn should_assert(&self) -> bool {
        !self.pending.is_empty() && self.active.is_empty()
    }

    /// Fault injection, off unless `CHM_USGIC_LEAK_ACTIVE` is set: drop the
    /// `n`th deactivation of the virtual-timer PPI on the floor, reproducing on
    /// demand the pre-#302 defect where a named INTID stayed active forever.
    ///
    /// This exists so the wedge report has demonstrated power. A detector that
    /// has never fired is an unfalsified guard, and the reproduction hunt for
    /// #257 has already burned seven attempts on experiments that could not
    /// distinguish their own hypotheses. Rather than wait for nature to bury
    /// PPI 27 again, this buries it deliberately, so
    /// [`HvfVcpu::usgic_report_wedge`] can be shown to fire and to classify the
    /// result as ours rather than the guest's.
    ///
    /// Only PPI 27 is leakable, and only once per run: the point is to produce
    /// the one permanent per-vCPU stall this issue describes, not to make the
    /// GIC generally unreliable.
    fn leak_this_deactivation(&mut self, intid: u32) -> bool {
        let Some(target) = leak_active_after() else {
            return false;
        };
        self.leak_at(intid, target)
    }

    /// The injector's decision, with the setting passed in rather than read from
    /// the process environment.
    ///
    /// Split out so the guard can drive the real injector. A test that reaches
    /// the same end state by hand — pushing onto `active` and setting `leaked`
    /// itself — proves the *consequence* of a leak and is structurally blind to
    /// the injector no longer performing one, which is the call-site class this
    /// repo has now banked five times.
    fn leak_at(&mut self, intid: u32, target: u64) -> bool {
        if intid != VTIMER_PPI {
            return false;
        }
        self.vtimer_deactivations += 1;
        if self.vtimer_deactivations != target || self.leaked {
            return false;
        }
        self.leaked = true;
        eprintln!(
            "[usgic] FAULT INJECTION (CHM_USGIC_LEAK_ACTIVE={target}): dropping \
             deactivation #{target} of PPI {VTIMER_PPI}; this vCPU's tick should now stop"
        );
        true
    }
}

/// The `CHM_USGIC_LEAK_ACTIVE` setting: which deactivation of the virtual-timer
/// PPI to drop. Read once — this sits on the interrupt path.
fn leak_active_after() -> Option<u64> {
    static CACHE: OnceLock<Option<u64>> = OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("CHM_USGIC_LEAK_ACTIVE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
    })
}

/// Whether a restore must arm the virtual timer itself.
///
/// True only when the restored register file carries **no** `CNTV_CTL_EL0` at
/// all. A supplied value is always honoured, including `ENABLE = 0`: a vCPU
/// parked by `PSCI CPU_OFF` has its timer genuinely off, and overriding a
/// captured value would invent state rather than restore it.
///
/// The case this exists for is #257. Checkpoints written before the timer pair
/// joined `SNAPSHOT_SYS_REGS` carry no timer state, so the vCPU keeps its reset
/// value — no tick, no deadline — and nothing in the guest re-arms it except
/// code that only runs *because* of an interrupt. Those checkpoints already
/// exist on users' disks and cannot be rewritten, so the restore has to
/// recognise the gap rather than faithfully reproduce it.
fn vtimer_needs_arming(sysregs: &[(u16, u64)]) -> bool {
    !sysregs.iter().any(|&(id, _)| id == SYSREG_CNTV_CTL_EL0)
}

#[cfg(test)]
mod snapshot_sys_reg_tests {
    use super::{
        vtimer_needs_arming, SNAPSHOT_SYS_REGS, SYSREG_CNTV_CTL_EL0, SYSREG_CNTV_CVAL_EL0,
        SYSREG_SCTLR_EL1,
    };

    /// A checkpoint must carry the guest's virtual-timer arming state.
    ///
    /// This is #257. `SNAPSHOT_SYS_REGS` is a *curated* list, so anything absent
    /// from it is silently discarded on suspend and comes back zeroed — and for
    /// these two registers, zeroed means a vCPU with no tick and no deadline.
    /// Nothing in the guest re-arms a timer except code that runs because of an
    /// interrupt, so a vCPU resumed in userspace with nothing else pending never
    /// ticks again while its siblings look perfectly healthy.
    ///
    /// The omission was invisible for months because the *snapshot* path was
    /// fine: a KVM capture arrives with the full ONE_REG set, including these.
    /// Only our own checkpoint dropped them, so the bug needed a suspend/resume
    /// to appear at all.
    #[test]
    fn a_checkpoint_carries_the_virtual_timer_arming_state() {
        assert!(
            SNAPSHOT_SYS_REGS.contains(&SYSREG_CNTV_CVAL_EL0),
            "without CNTV_CVAL a resumed vCPU has no deadline to tick at"
        );
        assert!(
            SNAPSHOT_SYS_REGS.contains(&SYSREG_CNTV_CTL_EL0),
            "without CNTV_CTL a resumed vCPU's timer comes back disabled"
        );
    }

    /// The deadline must be written before the timer is enabled.
    ///
    /// `state()` and `set_state` both walk this list in order, so its order *is*
    /// the write order. Enabling a timer before its comparator is set arms it
    /// against whatever value happens to be in the register.
    #[test]
    fn the_deadline_is_restored_before_the_timer_is_enabled() {
        let cval = SNAPSHOT_SYS_REGS
            .iter()
            .position(|&r| r == SYSREG_CNTV_CVAL_EL0)
            .expect("CVAL is captured");
        let ctl = SNAPSHOT_SYS_REGS
            .iter()
            .position(|&r| r == SYSREG_CNTV_CTL_EL0)
            .expect("CTL is captured");
        assert!(cval < ctl, "arm the deadline, then enable the timer");
    }

    /// A checkpoint predating the timer pair must not resume with a dead timer.
    ///
    /// These already exist on users' disks and cannot be rewritten, so the
    /// restore has to recognise the gap. Arming a deadline just ahead of now
    /// costs one spurious tick, which Linux's `timer_handler` absorbs and
    /// answers by re-arming `CNTV_CVAL` itself.
    #[test]
    fn a_restore_carrying_no_timer_state_arms_the_timer_itself() {
        let old_format = [(SYSREG_SCTLR_EL1, 0x3454_591d)];
        assert!(vtimer_needs_arming(&old_format));
        assert!(vtimer_needs_arming(&[]));
    }

    /// A captured `ENABLE = 0` is guest intent and must be left alone.
    ///
    /// A vCPU parked by `PSCI CPU_OFF` has its timer genuinely off. Overriding
    /// a value the capture supplied would invent state rather than restore it,
    /// and would wake a core the guest deliberately stopped.
    #[test]
    fn a_captured_disabled_timer_is_honoured_rather_than_overridden() {
        assert!(!vtimer_needs_arming(&[(SYSREG_CNTV_CTL_EL0, 0)]));
        assert!(!vtimer_needs_arming(&[
            (SYSREG_CNTV_CVAL_EL0, 0x1234),
            (SYSREG_CNTV_CTL_EL0, 1),
        ]));
    }
}

#[cfg(test)]
mod availability_tests {
    use super::HvfHypervisor;

    /// `is_available` selects a backend; it does not establish availability, and
    /// the difference is the whole reason `probe_availability` exists.
    ///
    /// This used to return `cfg!(target_os = "macos")` under a doc comment that
    /// said "Apple Silicon Macs with the hypervisor entitlement" — so it was
    /// `true` on Intel macOS, and `true` for a binary that `hv_vm_create` would
    /// refuse with `HV_DENIED`, which is what every `cargo build` in this
    /// repository produces. Backend selection believed it.
    #[test]
    fn is_available_answers_about_the_target_and_says_nothing_about_the_host() {
        assert_eq!(
            HvfHypervisor::is_available().unwrap(),
            cfg!(all(target_os = "macos", target_arch = "aarch64")),
            "is_available must track the compiled target, arch included"
        );
    }

    /// The probe is the honest answer, and it is only meaningful because it
    /// costs a real syscall. Running it here would take the process-global VM
    /// slot from anything else in the test binary, so this only checks that a
    /// failure is reported with the detail a human needs — the entitlement fix
    /// is the single most common local failure and a bare code hides it.
    #[test]
    fn a_refused_probe_names_the_entitlement() {
        let msg = super::hv_return_str(super::HV_DENIED);
        assert!(msg.contains("com.apple.security.hypervisor"), "{msg}");
        assert!(msg.contains("codesign"), "{msg}");
    }
}

#[cfg(test)]
mod usgic_redist_tests {
    use super::{Redists, UserGic, access_32bit_model};
    use crate::hvf::softgic::Redistributor;
    use std::sync::{Arc, Mutex};

    const FRAME: u64 = 0x2_0000;
    const REGION: u64 = 0x0800_0000;

    fn gic_with(vcpus: usize, index: usize) -> UserGic {
        let mut g = UserGic::default();
        g.redists = Redists(Arc::new(
            (0..vcpus).map(|_| Mutex::new(Redistributor::default())).collect(),
        ));
        g.redist_index = index;
        g.gicr_base = REGION + index as u64 * FRAME;
        g
    }

    /// The bug this whole path exists for: `gic_iterate_rdists` runs on the
    /// boot CPU and reads `GICR_TYPER` out of *every* frame in the region. A
    /// core that decodes only its own frame data-aborts on the second one.
    #[test]
    fn every_core_decodes_every_frame() {
        for index in 0..4 {
            let g = gic_with(4, index);
            for frame in 0..4u64 {
                assert_eq!(
                    g.redist_frame(REGION + frame * FRAME + 0x8),
                    Some((frame as usize, 0x8)),
                    "cpu{index} could not decode frame {frame}"
                );
            }
        }
    }

    #[test]
    fn an_address_past_the_last_frame_is_not_ours() {
        let g = gic_with(2, 0);
        assert_eq!(g.redist_frame(REGION + 2 * FRAME), None);
    }

    #[test]
    fn an_address_below_the_region_is_not_ours() {
        let g = gic_with(2, 1);
        assert_eq!(g.redist_frame(REGION - 4), None);
    }

    /// The SGI frame sits at +0x10000 inside a frame, so the offset must come
    /// back frame-relative rather than region-relative.
    #[test]
    fn the_sgi_frame_offset_is_frame_relative() {
        let g = gic_with(2, 0);
        assert_eq!(
            g.redist_frame(REGION + FRAME + 0x1_0100),
            Some((1, 0x1_0100))
        );
    }

    /// Before `usgic_set_gic_bases`, nothing is mapped; a zero base must not
    /// be read as "the region starts at 0" and swallow low IPAs.
    #[test]
    fn an_unset_base_decodes_nothing() {
        let mut g = gic_with(2, 0);
        g.gicr_base = 0;
        assert_eq!(g.redist_frame(0x8), None);
    }

    /// A 64-bit read must combine both word halves. `GICR_TYPER`'s upper half
    /// is the affinity Linux matches against `MPIDR_EL1`: fold it onto the low
    /// word and every frame claims affinity 0, so only the boot CPU finds
    /// itself and every secondary hangs in `gic_populate_rdist`.
    #[test]
    fn a_doubleword_read_of_typer_carries_the_affinity() {
        let mut r = Redistributor::default();
        r.set_identity(3, true);
        let v = access_32bit_model(&mut r, 0x8, false, 0, 8);
        assert_eq!(v >> 32, 3, "affinity must be in the upper word");
        assert_eq!(v & 0x1f, 0b1_0001, "PLPIS and Last in the lower word");
    }

    #[test]
    fn a_word_read_sees_only_the_low_half() {
        let mut r = Redistributor::default();
        r.set_identity(3, true);
        assert_eq!(access_32bit_model(&mut r, 0x8, false, 0, 4) >> 32, 0);
    }

    /// `GICR_PROPBASER` is written as one doubleword; splitting it must land
    /// both halves, not just the low one.
    #[test]
    fn a_doubleword_write_lands_both_halves() {
        let mut r = Redistributor::default();
        let val = 0xdead_beef_1234_5678u64;
        assert_eq!(access_32bit_model(&mut r, 0x70, true, val, 8), 0);
        assert_eq!(access_32bit_model(&mut r, 0x70, false, 0, 8), val);
    }
}

#[cfg(test)]
mod counter_scale_tests {
    use super::{reduce_ratio, scaled_cntvct};

    /// The ratio that matters in practice: AWS Graviton2's 121.875 MHz counter
    /// over Apple silicon's 24 MHz. It reduces to exactly 325/64, so the scaled
    /// curve is computable in integers and accumulates no drift at all.
    #[test]
    fn graviton_over_apple_reduces_exactly() {
        assert_eq!(reduce_ratio(121_875_000, 24_000_000), (325, 64));
    }

    #[test]
    fn an_already_reduced_ratio_is_unchanged() {
        assert_eq!(reduce_ratio(325, 64), (325, 64));
    }

    #[test]
    fn a_matching_frequency_reduces_to_unity() {
        assert_eq!(reduce_ratio(24_000_000, 24_000_000), (1, 1));
    }

    /// Integer arithmetic on the reduced fraction must not drift: after a full
    /// simulated hour of host ticks the scaled counter has to land on the exact
    /// value the guest's own frequency implies, to the tick.
    #[test]
    fn the_scaled_curve_accumulates_no_drift_over_an_hour() {
        let (num, den) = reduce_ratio(121_875_000, 24_000_000);
        // One hour of host ticks at 24 MHz.
        let host_ticks: u64 = 24_000_000 * 3600;
        let scaled = (u128::from(host_ticks) * u128::from(num) / u128::from(den)) as u64;
        // One hour of guest ticks at the guest's own 121.875 MHz.
        assert_eq!(scaled, 121_875_000 * 3600);
    }

    /// The park duration converts the other way (guest ticks back to host
    /// ticks), so a guest asking to sleep one of its seconds must park for one
    /// real second rather than 5.08 of them.
    #[test]
    fn a_guest_second_converts_back_to_one_host_second() {
        let (num, den) = reduce_ratio(121_875_000, 24_000_000);
        let guest_ticks: u64 = 121_875_000;
        let host_ticks = (u128::from(guest_ticks) * u128::from(den) / u128::from(num)) as u64;
        assert_eq!(host_ticks, 24_000_000);
    }

    /// A degenerate frequency must not panic or divide by zero. Callers guard
    /// against it before ever reaching here, so this only pins that the
    /// arithmetic itself is total.
    #[test]
    fn a_zero_frequency_does_not_panic() {
        assert_eq!(reduce_ratio(0, 24_000_000), (0, 1));
        assert_eq!(reduce_ratio(24_000_000, 0), (1, 0));
    }

    /// The curve must never be evaluated behind its own anchor. Measured on a
    /// 2-vCPU Graviton2 capture: a secondary vCPU reaching `run()` while
    /// rehydrate was still seeding evaluated the curve from an anchor ahead of
    /// `now`, the subtraction wrapped, and the guest's counter landed on exactly
    /// 2^58 ticks — 2_364_967_189 guest seconds, or ~75 years. Linux's
    /// clocksource is monotonic, so it kept the jump and RCU then reported its
    /// kthreads starved for 2.36e12 jiffies.
    #[test]
    fn a_now_behind_the_anchor_does_not_run_the_counter_75_years_forward() {
        let (num, den) = reduce_ratio(121_875_000, 24_000_000);
        let base_guest: u64 = 7_694_581_610; // capture B's recorded CNTVCT
        let anchor: u64 = 1_000_000;

        // `now` one tick behind the anchor: the curve has not started.
        assert_eq!(
            scaled_cntvct(base_guest, anchor, anchor - 1, num, den),
            base_guest,
            "a now behind the anchor must pin the counter at the guest base"
        );
        // The wrapping form this replaced produced a value ~2^58 ticks out.
        let wrapped = {
            let elapsed = u128::from((anchor - 1u64).wrapping_sub(anchor));
            base_guest.wrapping_add((elapsed * u128::from(num) / u128::from(den)) as u64)
        };
        assert!(
            wrapped / 121_875_000 > 1_000_000_000,
            "the bug this pins should be worth >1e9 guest seconds, was {}",
            wrapped / 121_875_000
        );

        // And an unanchored curve (base_host still zero) must not measure
        // elapsed from host time zero.
        let unanchored = scaled_cntvct(base_guest, 0, 5_000_000_000_000, num, den);
        assert!(
            unanchored > base_guest,
            "sanity: with no anchor the curve does run from zero, which is why \
             VtimerClock captures `base_host` at construction rather than lazily"
        );
    }

    /// Forward progress still works: one host second past the anchor must
    /// advance the guest counter by exactly one guest second.
    #[test]
    fn one_host_second_past_the_anchor_is_one_guest_second() {
        let (num, den) = reduce_ratio(121_875_000, 24_000_000);
        let base_guest: u64 = 7_694_581_610;
        let anchor: u64 = 42_000_000;
        assert_eq!(
            scaled_cntvct(base_guest, anchor, anchor + 24_000_000, num, den),
            base_guest + 121_875_000
        );
    }
}

#[cfg(test)]
mod vtimer_clock_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::VtimerClock;

    const GRAVITON_HZ: u64 = 121_875_000;
    const APPLE_HZ: u64 = 24_000_000;

    /// The defect this type exists to close: every vCPU must read the SAME
    /// offset, because HVF derives `CNTVCT_EL0` from it and the guest treats the
    /// counter as one system-wide clocksource. Seeding per vCPU (the old
    /// behaviour) left a permanent skew — measured at 2,909 ticks on a 2-vCPU
    /// Graviton capture, enough to wrap the guest's 56-bit clocksource.
    #[test]
    fn one_clock_hands_every_vcpu_the_same_offset() {
        let clock = VtimerClock::new(7_694_581_610, 0, APPLE_HZ);
        let first = clock.offset();
        // Anchoring is a one-off at construction; later readers see that value,
        // not one derived from whenever they happened to ask.
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(clock.offset(), first);
        assert_eq!(clock.epoch(), 1);
    }

    /// An unscaled clock never moves, so it needs no stepper and pays no
    /// stop-the-world barrier.
    #[test]
    fn an_unscaled_clock_never_steps() {
        let clock = VtimerClock::new(1_000_000, 0, APPLE_HZ);
        assert!(!clock.scaled());
        let before = clock.offset();
        assert!(!clock.step(&|| {}, Duration::from_millis(1)));
        assert_eq!(
            clock.offset(),
            before,
            "an unscaled offset must be constant"
        );
    }

    /// A scaled clock steps the offset DOWN (HVF: `CNTVCT = now - offset`), so
    /// the guest's counter only ever jumps forward.
    #[test]
    fn a_scaled_clock_steps_the_offset_down() {
        let clock = VtimerClock::new(7_694_581_610, GRAVITON_HZ, APPLE_HZ);
        assert!(clock.scaled());
        assert_eq!(
            clock.scale(),
            (325, 64),
            "121.875/24 MHz must reduce exactly"
        );
        let before = clock.offset();
        std::thread::sleep(Duration::from_millis(5));
        assert!(clock.step(&|| {}, Duration::from_millis(50)));
        assert!(
            clock.offset() < before,
            "offset must decrease so the guest counter advances faster, was {before} now {}",
            clock.offset()
        );
        assert_eq!(clock.epoch(), 2, "a step must publish a new epoch");
    }

    /// The safety property: while ANY vCPU is executing guest code the offset
    /// must not move, because a half-applied change is exactly the cross-core
    /// skew that corrupts the guest's clock. Failing to step is the correct
    /// outcome — the guest simply runs at the host rate for another window.
    #[test]
    fn a_step_is_abandoned_while_a_vcpu_is_in_the_guest() {
        let clock = VtimerClock::new(7_694_581_610, GRAVITON_HZ, APPLE_HZ);
        let before = clock.offset();
        clock.enter();
        std::thread::sleep(Duration::from_millis(5));
        let forced = Arc::new(AtomicBool::new(false));
        let f = forced.clone();
        assert!(
            !clock.step(
                &move || f.store(true, Ordering::SeqCst),
                Duration::from_millis(20)
            ),
            "a step must not publish while a vCPU is in the guest"
        );
        assert!(
            forced.load(Ordering::SeqCst),
            "the step must try to force an exit"
        );
        assert_eq!(clock.offset(), before, "the offset must be untouched");
        // Once the vCPU is out, the same step succeeds.
        clock.leave();
        assert!(clock.step(&|| {}, Duration::from_millis(50)));
        assert!(clock.offset() < before);
    }

    /// A vCPU leaving the guest must let a waiting step complete promptly rather
    /// than making it burn its whole timeout.
    #[test]
    fn leaving_the_guest_wakes_a_waiting_step() {
        let clock = VtimerClock::new(7_694_581_610, GRAVITON_HZ, APPLE_HZ);
        clock.enter();
        let c = clock.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            c.leave();
        });
        let t = std::time::Instant::now();
        assert!(clock.step(&|| {}, Duration::from_secs(5)));
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "step waited {:?}; it should wake on leave(), not time out",
            t.elapsed()
        );
    }

    /// Entering must never block indefinitely on a stepper: proceeding early is
    /// safe (it raises `in_guest`, so the step fails rather than publishing
    /// under a running vCPU), and blocking forever would wedge teardown.
    #[test]
    fn release_unblocks_a_vcpu_waiting_on_a_step() {
        let clock = VtimerClock::new(7_694_581_610, GRAVITON_HZ, APPLE_HZ);
        clock.enter(); // hold one vCPU in, so the step below cannot finish
        let c = clock.clone();
        let stepper = std::thread::spawn(move || {
            c.step(&|| {}, Duration::from_secs(30));
        });
        std::thread::sleep(Duration::from_millis(20));
        clock.release();
        clock.leave();
        assert!(
            stepper.join().is_ok(),
            "release() must let an in-flight step unwind"
        );
    }
}

#[cfg(test)]
mod usgic_tests {
    use std::time::Instant;

    use super::{
        ROLL_CALL_SILENCE, UserGic, WEDGE_OVERDUE_DWELL, WEDGE_OVERDUE_ENTRIES, WedgeFacts,
        pack_gic, wedge_verdict,
    };

    /// The `CNTFRQ_EL0` a Graviton2 capture carries, so a tick count in a test
    /// reads as the duration it really is.
    const GRAVITON_HZ: u128 = 121_875_000;

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
        assert_eq!(g.active_top(), Some(8192));
        // While active, the line must not re-assert for the next pending one.
        assert!(
            !g.should_assert(),
            "an active interrupt suppresses re-assert"
        );
    }

    #[test]
    fn spurious_when_empty() {
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        assert_eq!(g.read_iar(), super::GICV3_INTID_SPURIOUS);
        assert_eq!(g.active_top(), None);
    }

    #[test]
    fn sgi_target_list_selects_named_cores() {
        use super::sgi_targets_core;
        // INTID 0, IRM=0, target list = cores 0 and 2 (bits 0 and 2 set). The
        // writer is core 1; targeting is by the list, independent of the writer.
        let sgi = (0u64 << 24) | 0b101;
        assert!(sgi_targets_core(sgi, 1, 0), "core 0 is in the list");
        assert!(!sgi_targets_core(sgi, 1, 1), "core 1 is not in the list");
        assert!(sgi_targets_core(sgi, 1, 2), "core 2 is in the list");
        assert!(!sgi_targets_core(sgi, 1, 3), "core 3 is not in the list");
    }

    #[test]
    fn sgi_broadcast_targets_all_but_the_writer() {
        use super::sgi_targets_core;
        // IRM (bit 40) = 1: deliver to every core except the writer (core 0).
        let sgi = (1u64 << 40) | (3u64 << 24);
        assert!(!sgi_targets_core(sgi, 0, 0), "the writer is excluded");
        assert!(sgi_targets_core(sgi, 0, 1), "every other core is targeted");
        assert!(sgi_targets_core(sgi, 0, 2), "every other core is targeted");
    }

    #[test]
    fn spi_affinity_resolves_to_the_named_core() {
        use super::resolve_spi_target;
        // Aff0 == vCPU id (verified against captured snapshots): an SPI routed to
        // affinity Aff0=1 targets vCPU 1.
        assert_eq!(resolve_spi_target(Some(0x0000), 2), 0);
        assert_eq!(resolve_spi_target(Some(0x0001), 2), 1);
        // 1-of-N (IRM=1, affinity None) delivers to the boot CPU.
        assert_eq!(resolve_spi_target(None, 2), 0);
        // An out-of-range affinity (e.g. a stale/foreign Aff0) falls back to boot.
        assert_eq!(resolve_spi_target(Some(0x0005), 2), 0);
        // Higher affinity fields are ignored (Aff1..3 are 0 in our layout).
        assert_eq!(resolve_spi_target(Some(0x01_0000_0001), 2), 1);
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
        g.write_eoir(8192); // EOImode=0: drops priority AND deactivates
        assert_eq!(g.active_top(), None);
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
        g.write_eoir(8192); // EOImode=1: priority drop ONLY; stays active
        assert_eq!(g.active_top(), Some(8192), "EOImode=1 EOIR must not deactivate");
        assert!(
            !g.should_assert(),
            "next pending must be held while the first is still active"
        );
        g.write_dir(8192); // now deactivate
        assert_eq!(g.active_top(), None);
        assert!(
            g.should_assert(),
            "after DIR the next pending is deliverable"
        );
        assert_eq!(g.read_iar(), 8193);
    }

    /// The wedge in #262, in the model that produced it.
    ///
    /// `usgic_assert_spi` raises the raw IRQ line whenever an enabled source
    /// fires; it does **not** consult `should_assert`. So a device interrupt
    /// really can arrive while the guest is inside its virtual-timer handler,
    /// and the guest really does acknowledge it. With one `active` slot the
    /// outer PPI 27 was overwritten and then forgotten, so neither EOI could
    /// answer "did the virtual timer just deactivate?" — and the caller only
    /// re-arms HVF's auto-masked vtimer when that answer is yes. The vCPU then
    /// takes no further ticks, which is what
    /// `rcu_preempt kthread timer wakeup didn't happen` reports.
    #[test]
    fn a_nested_interrupt_does_not_lose_the_virtual_timer_underneath_it() {
        const VTIMER_PPI: u32 = 27;
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);

        // A virtio IRQ lands mid-handler and the guest nests it.
        g.push_pending(79);
        assert_eq!(g.read_iar(), 79);
        assert!(
            g.is_active(VTIMER_PPI),
            "the timer is still active underneath the nested handler"
        );

        // Inner EOI: the timer has NOT deactivated, so re-arming here would
        // storm the guest with an activation it cannot yet service.
        g.write_eoir(79);
        assert!(
            !g.vtimer_just_deactivated(Some(79)),
            "the inner EOI must not re-arm the vtimer"
        );

        // Outer EOI: the timer really has gone, and this is the edge that must
        // re-arm. With a single `active` slot `was` was `None` here and the
        // vtimer stayed masked for the life of the guest.
        assert_eq!(
            g.active_top(),
            Some(VTIMER_PPI),
            "the outer INTID must still be known"
        );
        g.write_eoir(VTIMER_PPI);
        assert!(
            g.vtimer_just_deactivated(Some(VTIMER_PPI)),
            "the outer EOI must re-arm the vtimer"
        );
        assert!(g.active.is_empty(), "no interrupt is active any more");
    }

    /// Under `EOImode=1` the EOI drops priority and the guest deactivates later
    /// via `ICC_DIR_EL1`, so the timer PPI is still active when its own EOI is
    /// written. Re-arming HVF's vtimer there would surface a fresh activation
    /// before the guest has left the handler that is meant to advance
    /// `CNTV_CVAL_EL0` -- the storm the masked-until-EOI sequence exists to
    /// avoid. Only the deactivate may re-arm.
    ///
    /// This is the half `a_nested_interrupt_...` cannot reach: there the inner
    /// EOI is refused because the INTID is not the timer at all, so a rule that
    /// looked only at `was` would have passed it.
    #[test]
    fn under_split_eoi_only_the_deactivate_rearms_the_vtimer() {
        const VTIMER_PPI: u32 = 27;
        let mut g = eoimode1();
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);

        g.write_eoir(VTIMER_PPI);
        assert!(
            g.is_active(VTIMER_PPI),
            "EOImode=1 EOIR drops priority without deactivating"
        );
        assert!(
            !g.vtimer_just_deactivated(Some(VTIMER_PPI)),
            "the priority drop must not re-arm the vtimer"
        );

        g.write_dir(VTIMER_PPI);
        assert!(
            g.vtimer_just_deactivated(Some(VTIMER_PPI)),
            "the deactivate must re-arm the vtimer"
        );
    }

    /// Taking the tick is what clears the overdue dwell — not offering it.
    ///
    /// The wedge is precisely the case where offering and taking come apart, so
    /// a dwell cleared anywhere on the *assert* path would reset itself on every
    /// run entry and could never accumulate. Clearing it in `read_iar`, the one
    /// place the guest actually consumes the interrupt, is what makes the
    /// detector able to observe a stall at all.
    #[test]
    fn only_the_guest_acknowledging_the_tick_clears_the_overdue_dwell() {
        const VTIMER_PPI: u32 = 27;
        let mut g = UserGic {
            enabled: true,
            vtimer_overdue_since: Some(Instant::now()),
            vtimer_overdue_entries: 512,
            ..UserGic::default()
        };

        // Offering it again does not clear anything: push_pending is the assert
        // path, and a wedged guest is offered the tick at every single entry.
        g.push_pending(VTIMER_PPI);
        assert_eq!(
            g.vtimer_overdue_entries, 512,
            "merely making the tick pending must not count as the guest taking it"
        );

        // A different INTID being taken is not the timer returning either.
        g.push_pending(79);
        assert_eq!(g.read_iar(), VTIMER_PPI, "27 was queued first");
        assert_eq!(g.vtimer_overdue_entries, 0, "acknowledging 27 clears the dwell");
        assert!(g.vtimer_overdue_since.is_none());
    }

    /// The two thresholds are reached at wildly different times, so the crossing
    /// must not be an equality on the one that arrives first.
    ///
    /// **This is the guard the hardware run bought.** The first implementation
    /// fired on `entries == WEDGE_OVERDUE_ENTRIES && dwell elapsed`, evaluated
    /// at one instant. Every unit test passed. On a real injected wedge the vCPU
    /// spins — `wfi_park_ms` returns 0 once the deadline is behind us — so entry
    /// 200 arrived milliseconds in, the dwell had ten seconds left to run, the
    /// equality never matched again, and the detector could not fire at all.
    #[test]
    fn the_entry_count_arriving_long_before_the_dwell_still_reports_the_wedge() {
        let mut g = UserGic::default();
        let t0 = Instant::now();

        // A wedged vCPU spins: the entry budget is spent in microseconds.
        for _ in 0..WEDGE_OVERDUE_ENTRIES * 4 {
            assert!(
                !g.note_vtimer_overdue(t0),
                "no wedge yet — the dwell has not elapsed"
            );
        }

        // Ten seconds later the same condition is still true, and *that* is the
        // moment it must be reported, long past the entry count's equality.
        assert!(
            g.note_vtimer_overdue(t0 + WEDGE_OVERDUE_DWELL),
            "the dwell elapsed while overdue: this is a wedge"
        );
    }

    /// The report is emitted once per episode, not on every entry of a spin.
    #[test]
    fn a_standing_wedge_is_reported_once_and_a_recovered_tick_re_arms_it() {
        let mut g = UserGic::default();
        let t0 = Instant::now();
        let past = t0 + WEDGE_OVERDUE_DWELL;
        for _ in 0..WEDGE_OVERDUE_ENTRIES {
            g.note_vtimer_overdue(t0);
        }
        assert!(g.note_vtimer_overdue(past), "first crossing reports");
        for _ in 0..1000 {
            assert!(
                !g.note_vtimer_overdue(past),
                "a standing wedge must not print on every entry of a spin"
            );
        }

        // The guest taking a tick ends the episode, so a *later* wedge is a new
        // finding and must be reportable again.
        g.clear_vtimer_overdue();
        let t1 = past;
        for _ in 0..WEDGE_OVERDUE_ENTRIES {
            g.note_vtimer_overdue(t1);
        }
        assert!(
            g.note_vtimer_overdue(t1 + WEDGE_OVERDUE_DWELL),
            "a fresh stall after a recovery is a fresh report"
        );
    }

    /// The roll call's packed word must survive the round trip, because every
    /// field in it is read back by a human diagnosing a wedge.
    ///
    /// The stuck-timer bit is the one that decides the verdict, so it is checked
    /// against neighbouring fields set to values that would corrupt it if the
    /// shifts overlapped.
    #[test]
    fn the_roll_call_snapshot_round_trips_every_field() {
        let g = pack_gic(true, 1, 0, 1);
        assert_eq!(g & 1, 1, "the stuck-timer bit");
        assert_eq!((g >> 1) & 0xFF, 1, "active");
        assert_eq!((g >> 9) & 0xFF, 0, "pending");
        assert_eq!((g >> 17) & 0xFF, 1, "depth");

        // A healthy vCPU: nothing active, one interrupt waiting.
        let h = pack_gic(false, 0, 1, 0);
        assert_eq!(h & 1, 0, "no INTID stuck");
        assert_eq!((h >> 9) & 0xFF, 1, "pending survives a clear timer bit");

        // Saturating rather than wrapping: a large count must not bleed into the
        // neighbouring field and invent a stuck timer.
        let big = pack_gic(false, 9_999, 9_999, 9_999);
        assert_eq!(big & 1, 0, "a huge active count must not set the timer bit");
        assert_eq!((big >> 1) & 0xFF, 0xFF, "active saturates");
        assert_eq!((big >> 9) & 0xFF, 0xFF, "pending saturates");
    }

    /// The silence threshold must sit above any legitimate idle nap and below
    /// the guest's own detectors, or the roll call either cries wolf or arrives
    /// after the evidence is stale.
    #[test]
    fn the_roll_call_silence_window_sits_between_a_nap_and_the_guests_own_verdict() {
        assert!(
            ROLL_CALL_SILENCE > WEDGE_OVERDUE_DWELL.as_millis() as u64 / 4,
            "shorter than a fraction of the dwell would report ordinary scheduling"
        );
        assert!(
            ROLL_CALL_SILENCE < 60_000,
            "the guest needs 60s to report a stall; ours must already be true by then"
        );
    }

    /// A dwell must not be cleared by an unrelated interrupt being taken.
    /// A suspended VM crosses the wall clock without crossing the entry count,
    /// and must not be reported.
    ///
    /// This is the half of the crossing that keeps the trap from calling every
    /// resume a wedge: a suspend of any length produces a *single* run entry
    /// across the gap, so wall-clock alone would fire on all of them. It is
    /// testable at all only because `note_vtimer_overdue` takes `now` — with the
    /// clock read inside, this case needs a real suspend and goes untested.
    #[test]
    fn a_long_suspend_crosses_the_dwell_on_one_entry_and_is_not_a_wedge() {
        let mut g = UserGic::default();
        let t0 = Instant::now();
        assert!(!g.note_vtimer_overdue(t0), "the entry that armed the dwell");
        assert!(
            !g.note_vtimer_overdue(t0 + WEDGE_OVERDUE_DWELL * 6),
            "one entry an hour later is a resumed VM, not a spinning vCPU"
        );
        assert!(
            g.vtimer_overdue_entries < WEDGE_OVERDUE_ENTRIES,
            "the entry count is what rules this out; the dwell alone is crossed"
        );
    }

    #[test]
    fn taking_some_other_interrupt_leaves_the_overdue_dwell_standing() {
        let mut g = UserGic {
            enabled: true,
            vtimer_overdue_since: Some(Instant::now()),
            vtimer_overdue_entries: 300,
            ..UserGic::default()
        };
        g.push_pending(79);
        assert_eq!(g.read_iar(), 79);
        assert_eq!(
            g.vtimer_overdue_entries, 300,
            "a virtio completion is not the timer tick returning"
        );
    }

    /// The fault injector must actually reproduce the pre-#302 defect, or the
    /// wedge report is a guard that has never fired.
    ///
    /// This is the whole reason the injector exists. Seven reproduction attempts
    /// for #257 failed to produce the wedge, and one of them was later shown to
    /// have had no power at all — so shipping a detector on the promise that it
    /// would work when nature next triggered it would repeat exactly that
    /// mistake. Here the burial is deliberate, and its consequence — the tick
    /// being refused for ever after — is asserted rather than assumed.
    #[test]
    fn the_fault_injector_buries_the_timer_ppi_exactly_as_the_old_defect_did() {
        const VTIMER_PPI: u32 = 27;
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };

        // The first tick is ordinary: taken, ended, deactivated.
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);
        assert!(!g.leak_at(VTIMER_PPI, 2), "not the targeted deactivation");
        g.write_eoir(VTIMER_PPI);
        assert!(!g.is_active(VTIMER_PPI), "an unleaked tick deactivates");

        // The second is the one the injector drops. Drive the real thing rather
        // than reproducing its end state by hand: a test that pushes onto
        // `active` itself cannot see the injector stop performing the leak.
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);
        assert!(g.leak_at(VTIMER_PPI, 2), "deactivation #2 is the target");
        // Exactly what `deactivate` does when the injector claims the drop.
        g.write_eoir(VTIMER_PPI);
        g.active.push(VTIMER_PPI);

        assert!(
            g.is_active(VTIMER_PPI),
            "the leaked activation must survive the guest's EOI"
        );
        // One leak only — and structurally, not by a flag: `vtimer_deactivations`
        // only ever counts up, so a fixed target is reached exactly once. That is
        // why the next targeted deactivation is honoured rather than dropped, and
        // why the injector models one lost EOI rather than a permanently broken
        // GIC. (`self.leaked` is belt-and-braces over that argument; removing it
        // changes no behaviour, so no assertion here pretends to test it.)
        assert!(!g.leak_at(VTIMER_PPI, 2), "the target is behind us now");
        // The consequence that makes it permanent rather than transient.
        let before = g.nested_requeues_refused;
        g.push_pending(VTIMER_PPI);
        assert!(
            !g.pending.contains(&VTIMER_PPI),
            "a buried INTID is refused re-queue, so the tick can never be offered again"
        );
        assert_eq!(
            g.nested_requeues_refused,
            before,
            "refusal at the top of the stack is the dedup, not a nested requeue"
        );
        assert!(
            !g.should_assert(),
            "and with 27 active the line is never re-asserted either"
        );
    }

    /// The verdict must name the GIC when an INTID is stuck active, even though
    /// every other symptom of that state also looks like a guest fault.
    ///
    /// This is the ordering that matters most: while 27 is buried,
    /// `push_pending` refuses it, so 27 is legitimately *not* pending. A verdict
    /// that checked "is the timer pending?" first would read that absence as the
    /// guest ignoring us and send the next investigation down the i-cache path
    /// for a bug that is ours.
    #[test]
    fn a_stuck_active_intid_is_blamed_on_the_gic_and_not_on_the_guest() {
        let v = wedge_verdict(WedgeFacts {
            active_empty: false,
            timer_live: true,
            overdue_by: 5_000_000,
            guest_hz: GRAVITON_HZ,
            irqs_masked: false,
            // The buried case: refused re-queue means it is NOT pending.
            vtimer_pending: false,
        });
        assert!(v.starts_with("gic-model:"), "got {v}");
    }

    /// A tick the guest reports as stopped while our own counter says its
    /// deadline is still far off is a clock fault, and must not be filed as a
    /// guest one.
    ///
    /// Only the console trigger can reach this state — a deadline we do not
    /// believe has passed can never raise the overdue trigger — which is why
    /// the two triggers are not redundant.
    #[test]
    fn a_deadline_far_in_our_future_is_blamed_on_the_counter() {
        let v = wedge_verdict(WedgeFacts {
            active_empty: true,
            timer_live: true,
            // Thirty seconds ahead: nothing a healthy tick arms, and comfortably
            // enough disagreement to explain the guest's 60-second stall report.
            overdue_by: -(30 * GRAVITON_HZ as i128),
            guest_hz: GRAVITON_HZ,
            irqs_masked: false,
            vtimer_pending: true,
        });
        assert!(v.starts_with("clock:"), "got {v}");
    }

    /// A deadline only just ahead is the *opposite* finding to a clock fault,
    /// and reading the sign alone conflates them.
    ///
    /// This is the benign post-resume stall, and it is the case the control run
    /// produced: `overdue_by = -33266` at 121.875 MHz — **273 microseconds** —
    /// while the guest complained about a 60-second gap it had already
    /// recovered from. The first version of this classifier called that `clock`,
    /// which would have sent the next reader hunting a counter-scaling bug that
    /// does not exist. A diagnostic that names the wrong subsystem costs more
    /// than one that says nothing.
    #[test]
    fn a_deadline_a_few_microseconds_ahead_is_a_recovered_stall_not_a_clock_fault() {
        let v = wedge_verdict(WedgeFacts {
            active_empty: true,
            timer_live: true,
            overdue_by: -33_266,
            guest_hz: GRAVITON_HZ,
            irqs_masked: false,
            vtimer_pending: false,
        });
        assert!(
            v.starts_with("recovered:"),
            "273us from the next tick is not a clock bug; got {v}"
        );
    }

    /// A guest running with interrupts disabled is refusing the tick, not
    /// failing to take it, and the two have different owners.
    #[test]
    fn interrupts_masked_in_the_guest_is_reported_separately_from_a_delivery_failure() {
        let masked = wedge_verdict(WedgeFacts {
            active_empty: true,
            timer_live: true,
            overdue_by: 1,
            guest_hz: GRAVITON_HZ,
            irqs_masked: true,
            vtimer_pending: true,
        });
        assert!(masked.starts_with("guest-masked:"), "got {masked}");

        let enabled = wedge_verdict(WedgeFacts {
            active_empty: true,
            timer_live: true,
            overdue_by: 1,
            guest_hz: GRAVITON_HZ,
            irqs_masked: false,
            vtimer_pending: true,
        });
        assert!(enabled.starts_with("guest-side:"), "got {enabled}");
    }

    /// A guest that has disabled its own timer is idle, not wedged. Reporting
    /// that as a delivery failure would fire on every `NO_HZ` guest.
    #[test]
    fn a_timer_the_guest_turned_off_is_never_reported_as_a_delivery_failure() {
        let v = wedge_verdict(WedgeFacts {
            active_empty: true,
            timer_live: false,
            overdue_by: 9_999_999,
            guest_hz: GRAVITON_HZ,
            irqs_masked: false,
            vtimer_pending: false,
        });
        assert!(v.starts_with("guest-idle:"), "got {v}");
    }

    /// The #257 wedge, in the model: a deactivate must honour the INTID the
    /// guest named, or the virtual timer can be buried in the active stack
    /// permanently.
    ///
    /// `ICC_DIR_EL1` is written *with* an INTID. Popping the top of the stack
    /// instead deactivates whatever happens to be innermost, so a guest that
    /// completes the timer while a device handler is still active loses both
    /// halves at once: the device IRQ is deactivated behind its handler's back,
    /// and PPI 27 stays active forever. That second half never recovers --
    /// [`UserGic::push_pending`] refuses to re-queue an INTID that is active at
    /// any depth, so `usgic_poll_vtimer` asserts the timer at every run entry
    /// and is refused every time. The vCPU's tick never returns while its
    /// siblings, which have their own model, stay healthy.
    #[test]
    fn a_deactivate_out_of_order_cannot_strand_the_virtual_timer() {
        const VTIMER_PPI: u32 = 27;
        let mut g = eoimode1();

        // The timer is taken, then a device IRQ nests on top of it.
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);
        g.push_pending(79);
        assert_eq!(g.read_iar(), 79);
        assert_eq!(g.active_top(), Some(79));

        // The guest deactivates the *timer* while the nested handler is still
        // active. The INTID it named is the one that must go.
        g.write_dir(VTIMER_PPI);
        assert!(
            !g.is_active(VTIMER_PPI),
            "the named INTID must be the one deactivated"
        );
        assert!(
            g.is_active(79),
            "a nested handler nobody named must stay active"
        );

        // And the property the wedge is actually about: the timer is
        // deliverable again.
        g.push_pending(VTIMER_PPI);
        assert!(
            g.pending.contains(&VTIMER_PPI),
            "the vtimer must be re-queueable once deactivated"
        );
        assert_eq!(
            g.nested_requeues_refused, 0,
            "no assert should have been refused"
        );
    }

    /// The other direction: a deactivate naming an INTID this model never
    /// acknowledged must be a no-op, not a silent deactivate of an unrelated
    /// live interrupt. Residual writes like this are reachable across a
    /// restore, where the guest resumes holding state the model was rebuilt
    /// without.
    #[test]
    fn a_deactivate_naming_an_unknown_intid_leaves_the_stack_alone() {
        const VTIMER_PPI: u32 = 27;
        let mut g = eoimode1();
        g.push_pending(VTIMER_PPI);
        assert_eq!(g.read_iar(), VTIMER_PPI);

        g.write_dir(1022);

        assert!(
            g.is_active(VTIMER_PPI),
            "an unmatched deactivate must not deactivate a live interrupt"
        );
    }

    /// Dedup has to ask the whole stack, not its top. A source re-asserting an
    /// INTID that is active *underneath* a nested handler must not queue a
    /// second copy: the guest EOIs once per acknowledge, so the extra copy
    /// would be acknowledged and then never deactivated, permanently
    /// suppressing `should_assert` — a different route to the same silence.
    #[test]
    fn a_source_cannot_requeue_an_intid_active_beneath_a_nested_handler() {
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        g.push_pending(27);
        g.read_iar();
        g.push_pending(79);
        g.read_iar();
        g.push_pending(27);
        assert!(
            g.pending.is_empty(),
            "27 is active beneath 79 and must not be queued again"
        );
        assert_eq!(
            g.nested_requeues_refused, 1,
            "the refusal is the measurement #262 asks for and must be counted"
        );
    }

    /// The counter measures *nesting*, not every refusal. A source re-asserting
    /// the INTID the guest is servicing right now is the ordinary case (the
    /// run-entry vtimer poll does it on every entry until the handler arms the
    /// next deadline), it was already handled correctly by the single slot, and
    /// counting it would bury the rare case this exists to find under millions
    /// of uninteresting ones.
    #[test]
    fn re_asserting_the_innermost_handlers_own_intid_is_not_counted_as_nesting() {
        let mut g = UserGic {
            enabled: true,
            ..UserGic::default()
        };
        g.push_pending(27);
        g.read_iar();
        g.push_pending(27);
        g.push_pending(27);
        assert!(
            g.pending.is_empty(),
            "27 is active and must not be requeued"
        );
        assert_eq!(
            g.nested_requeues_refused, 0,
            "27 is the innermost handler, not nested beneath one"
        );
    }

    /// A checkpoint written before the stack existed still restores. Its writer
    /// only ever tracked one INTID, so lifting it to a one-deep stack is the
    /// whole of the old truth -- which is why this is additive rather than a
    /// `manifest_version` bump.
    #[test]
    fn a_checkpoint_without_a_stack_restores_its_single_active_intid() {
        use crate::hvf::checkpoint::UsgicCheckpoint;
        let legacy = UsgicCheckpoint {
            dist: Default::default(),
            redist: Default::default(),
            pending: vec![],
            active: Some(43),
            active_stack: Vec::new(),
        };
        assert_eq!(legacy.active_stack(), vec![43]);

        let none = UsgicCheckpoint {
            active: None,
            ..legacy.clone()
        };
        assert!(none.active_stack().is_empty());

        let nested = UsgicCheckpoint {
            active: Some(79),
            active_stack: vec![27, 79],
            ..legacy.clone()
        };
        assert_eq!(nested.active_stack(), vec![27, 79]);
    }
}

/// The single virtual-counter offset that every vCPU in a VM must have
/// programmed, plus the rendezvous that lets it change safely.
///
/// # Why one shared offset is mandatory
///
/// HVF defines `CNTVCT_EL0 = mach_absolute_time() - offset`, and
/// `mach_absolute_time()` is one counter shared by every host core. So two
/// vCPUs read the same `CNTVCT_EL0` **iff** they have the same offset
/// programmed. Linux treats `CNTVCT_EL0` as a single system-wide clocksource
/// and reads it from whichever CPU it happens to be running on, so a
/// per-vCPU offset makes the guest's clock non-monotonic.
///
/// That is not a cosmetic problem. `arch_sys_counter` is a 56-bit clocksource,
/// and `clocksource_delta()` computes `(now - last) & mask`: a read that is
/// even one tick behind the previous one wraps to ~2^56 ticks and is latched
/// into the guest's timekeeping as a ~18.7-year forward jump. Measured on a
/// 2-vCPU Graviton capture before this type existed: 19,992 backwards reads out
/// of 40,000 strictly-ordered cross-vCPU samples, a constant 2,909-tick skew,
/// and a guest that believed the date was 2101.
///
/// # Two sources of skew, both closed here
///
/// 1. **Anchoring.** Each vCPU used to seed its own offset as
///    `mach_absolute_time() - reference` on its own thread, so the offsets
///    differed by however far apart the restore calls landed (~2,909 ticks in
///    practice) — forever. The offset is now computed once, here, and every
///    vCPU programs *this* value.
/// 2. **Rate scaling.** When [`HvfVcpu::set_counter_scale`] is active the
///    offset must keep moving (see that method for why). Moving it while any
///    vCPU is executing guest code re-creates per-vCPU skew, so [`Self::step`]
///    changes it only while every vCPU is out of `hv_vcpu_run`. Guest code
///    therefore never observes a half-applied change.
pub struct VtimerClock {
    /// Reduced rate-scale numerator, or 0 when the guest counter runs at the
    /// host rate — in which case the offset is constant and [`Self::step`] is
    /// never needed.
    num: u64,
    /// Reduced rate-scale denominator. Only meaningful when `num` is non-zero.
    den: u64,
    /// Host tick at which the curve was anchored.
    base_host: u64,
    /// Guest `CNTVCT_EL0` at which the curve was anchored (the snapshot's
    /// shared reference counter).
    base_guest: u64,
    /// The offset every vCPU must program before entering the guest.
    offset: AtomicU64,
    /// Bumped whenever `offset` changes, so a vCPU can skip a redundant
    /// `hv_vcpu_set_vtimer_offset` on the overwhelmingly common path where
    /// nothing moved.
    epoch: AtomicU64,
    gate: Mutex<ClockGate>,
    cv: Condvar,
}

/// Rendezvous state for [`VtimerClock`].
#[derive(Default)]
struct ClockGate {
    /// How many vCPUs are currently inside `hv_vcpu_run`.
    in_guest: usize,
    /// A stepper wants the offset to itself; new entries wait.
    stepping: bool,
}

/// How long a vCPU will wait for an in-progress step before entering the guest
/// anyway. Entering early is *safe* — it raises `in_guest`, which makes the
/// step fail rather than publish under a running vCPU — so this is a liveness
/// valve, not a correctness one.
const CLOCK_ENTER_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

impl VtimerClock {
    /// Anchor the counter at `reference` (the snapshot's shared `CNTVCT_EL0`).
    /// `guest_hz`/`host_hz` enable rate scaling; equal values, or a zero,
    /// leave the counter at the host rate.
    pub fn new(reference: u64, guest_hz: u64, host_hz: u64) -> Arc<Self> {
        // SAFETY: FFI; reads the host monotonic tick.
        let base_host = unsafe { mach_absolute_time() };
        let (num, den) = if guest_hz == 0 || host_hz == 0 || guest_hz == host_hz {
            (0, 1)
        } else {
            reduce_ratio(guest_hz, host_hz)
        };
        Arc::new(Self {
            num,
            den,
            base_host,
            base_guest: reference,
            offset: AtomicU64::new(base_host.wrapping_sub(reference)),
            epoch: AtomicU64::new(1),
            gate: Mutex::new(ClockGate::default()),
            cv: Condvar::new(),
        })
    }

    /// Whether the counter is rate-scaled, and so needs [`Self::step`] to be
    /// driven. An unscaled clock has a constant offset and needs nothing.
    pub fn scaled(&self) -> bool {
        self.num != 0
    }

    /// The rate scale as a reduced `(numerator, denominator)`; `(0, 1)` when the
    /// counter runs at the host rate.
    fn scale(&self) -> (u64, u64) {
        (self.num, self.den)
    }

    /// The offset every vCPU must currently have programmed.
    fn offset(&self) -> u64 {
        self.offset.load(Ordering::Acquire)
    }

    /// The current offset generation.
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Mark this vCPU as entering guest execution. Blocks (briefly) while a
    /// step is in flight so the entry cannot race a publish.
    fn enter(&self) {
        let mut g = self.gate.lock().unwrap();
        if g.stepping {
            let (ng, _) = self.cv.wait_timeout(g, CLOCK_ENTER_WAIT).unwrap();
            g = ng;
        }
        g.in_guest += 1;
    }

    /// Mark this vCPU as having left guest execution.
    fn leave(&self) {
        let mut g = self.gate.lock().unwrap();
        g.in_guest -= 1;
        if g.stepping && g.in_guest == 0 {
            drop(g);
            self.cv.notify_all();
        }
    }

    /// Advance the offset onto the scaled curve, but only while no vCPU is
    /// executing guest code.
    ///
    /// `force_exit` is invoked to push every vCPU out of `hv_vcpu_run`. If they
    /// are not all out within `timeout` the step is **abandoned**: the offset
    /// keeps its previous value, so the guest's counter stays coherent and
    /// merely runs at the host rate for another window. Degrading to "slow but
    /// correct" is the whole point — a partially applied offset would corrupt
    /// the guest's clock permanently.
    ///
    /// Returns whether the offset was advanced.
    pub fn step(&self, force_exit: &dyn Fn(), timeout: std::time::Duration) -> bool {
        if !self.scaled() {
            return false;
        }
        {
            let mut g = self.gate.lock().unwrap();
            if g.stepping {
                return false;
            }
            g.stepping = true;
        }
        force_exit();
        let mut g = self.gate.lock().unwrap();
        let deadline = std::time::Instant::now() + timeout;
        while g.in_guest > 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            let (ng, _) = self.cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
        let advanced = if g.in_guest == 0 {
            // SAFETY: FFI; reads the host monotonic tick.
            let now = unsafe { mach_absolute_time() };
            let target = scaled_cntvct(self.base_guest, self.base_host, now, self.num, self.den);
            let next = now.wrapping_sub(target);
            // The scale ratio is > 1, so the offset only ever decreases and the
            // guest's counter only ever jumps forward. Guard it anyway: a
            // backwards offset move would rewind the guest's clock, which is the
            // exact failure this type exists to prevent.
            let prev = self.offset.load(Ordering::Relaxed);
            if next < prev {
                self.offset.store(next, Ordering::Release);
                self.epoch.fetch_add(1, Ordering::Release);
                if debug_vtimer() {
                    eprintln!(
                        "[vtimer] step now={now} target={target} offset {prev} -> {next} \
                         (guest jumped {} ticks)",
                        prev - next
                    );
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        g.stepping = false;
        drop(g);
        self.cv.notify_all();
        advanced
    }

    /// Release any vCPU blocked in [`Self::enter`], for teardown.
    pub fn release(&self) {
        self.gate.lock().unwrap().stepping = false;
        self.cv.notify_all();
    }
}

/// Marks a vCPU as executing guest code for the guard's lifetime, so
/// [`VtimerClock::step`] can tell when it is safe to move the shared offset.
struct ClockGuard<'a>(Option<&'a VtimerClock>);

impl Drop for ClockGuard<'_> {
    fn drop(&mut self) {
        if let Some(clock) = self.0 {
            clock.leave();
        }
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
    /// The VM-global counter clock. Every vCPU programs the offset this
    /// publishes, which is what makes `CNTVCT_EL0` coherent across cores — see
    /// [`VtimerClock`]. Attached during rehydrate; absent only for a vCPU that
    /// was never restored from a snapshot.
    clock: OnceLock<Arc<VtimerClock>>,
    /// The [`VtimerClock`] epoch this vCPU has actually programmed, so a run
    /// entry can skip a redundant `hv_vcpu_set_vtimer_offset` — the common case,
    /// since an unscaled clock never moves at all.
    programmed_epoch: AtomicU64,
    /// Numerator of the virtual-counter rate scale, or 0 when the counter runs
    /// at the host rate. Mirrored from the clock purely so the WFI idle nap can
    /// convert a guest-tick deadline into a host-tick wait.
    cnt_scale_num: AtomicU64,
    /// Denominator of the virtual-counter rate scale. Only read when
    /// `cnt_scale_num` is non-zero.
    cnt_scale_den: AtomicU64,
    /// Set the first time `hv_vcpu_set_vtimer_offset` refuses a reprogram, so the
    /// warning is emitted once per vCPU rather than on every guest entry.
    vtimer_reprogram_failed: AtomicBool,
    /// Monotonic counter bumped once per `run()` iteration. A host-side watchdog
    /// samples it to tell a vCPU that is making progress (returning from
    /// `hv_vcpu_run` for exits) apart from one wedged inside a single
    /// `hv_vcpu_run` call — e.g. blocked in Apple's internal WFI wait
    /// (`wait_for_interrupt`) on a deadline it is not honouring. When the counter
    /// stalls the watchdog forces the vCPU out via [`Self::exit_signal`] so it
    /// re-enters and Apple re-evaluates pending interrupts / the timer deadline.
    run_gen: Arc<AtomicU64>,
    /// Userspace GICv3 CPU interface (see [`UserGic`]). Active only when no
    /// managed GIC is used, and only once a caller has switched it on.
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

/// What became of one captured system register when replayed onto this host.
///
/// See [`HvfVcpu::probe_sysreg`]. The distinction that matters is between a
/// register this Mac reproduces faithfully and one where the guest will observe
/// something other than what its capture host told it at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysregFate {
    /// HVF took the write and read back exactly the captured value.
    Restored,
    /// HVF took the write but reads back something else — the register is
    /// partly or wholly RES0/RAZ on this core, so only some fields survived.
    Clamped {
        /// What the register actually reads after writing the captured value.
        observed: u64,
        /// This host's own value before the probe, when readable.
        host: Option<u64>,
    },
    /// HVF rejected the write outright. The guest sees `host` instead of what
    /// its capture recorded.
    Refused {
        /// This host's own value, when readable.
        host: Option<u64>,
    },
    /// The write was accepted but the register cannot be read back, so no claim
    /// either way is defensible.
    Unverifiable,
}

impl SysregFate {
    /// Whether the guest will observe something other than its captured value.
    ///
    /// `Unverifiable` is deliberately *not* a divergence: we cannot demonstrate
    /// one, and reporting unprovable deltas would make the audit noise.
    pub fn diverges(&self) -> bool {
        matches!(
            self,
            SysregFate::Clamped { .. } | SysregFate::Refused { .. }
        )
    }
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

/// `SCTLR_EL1.UCT` — when clear, EL0 reads of `CTR_EL0` trap to EL1.
pub const SCTLR_EL1_UCT: u64 = 1 << 15;

/// Let EL0 read this host's real `CTR_EL0`, rather than the capture host's lie.
///
/// Graviton2 is a Neoverse-N1, so Linux applies erratum 1542419 at boot. That
/// workaround clears `SCTLR_EL1.UCT` so every EL0 `mrs ctr_el0` traps into
/// `ctr_read_handler`, which — deliberately, to keep the trap rate down —
/// answers with `IminLine` forced to `PAGE_SHIFT - 2`, i.e. **4096 bytes**,
/// and `DIC` cleared (`arch/arm64/kernel/traps.c`, v6.8).
///
/// That is sound on the capture host: N1 reports `DIC = 1`, so the i-cache is
/// already coherent with data writes and the maintenance userspace performs is
/// belt-and-braces. Covering one 64-byte line in every 4096 costs nothing when
/// covering none would also have been correct.
///
/// It is not sound here. Apple silicon reports `DIC = 0`, so `ic ivau` is
/// genuinely required for every line — and the restored kernel keeps handing
/// userspace a 4096-byte stride, so 63 of every 64 lines are never invalidated.
/// Measured in a rehydrated Graviton capture: a JIT-written page was stale at
/// 199 of 200 attempts at any offset past the first line, and `npm --version`
/// died with SIGILL 15 times in 20.
///
/// Setting `UCT` sends EL0 straight to the hardware, which answers
/// `0x9444c004` — `IminLine = 4` (64 bytes) and `DIC = 0`, both true of this
/// machine. Userspace then strides correctly and clears its own cache. It is
/// strictly *more* maintenance than the trap handler asked for, never less, so
/// it cannot weaken the erratum mitigation this bit belongs to.
///
/// EL1 is unaffected: `UCT` gates EL0 only, so the kernel's own `read_ctr`
/// already reads the host value. The kernel's separate defect — `ic ivau`
/// alternative-patched to a NOP at boot because the capture host advertised
/// `DIC = 1` — lives in kernel text and is untouched by this. It is tracked as
/// its own issue, and measured independently at 998/1000 stale via
/// `mmap(RW) -> write -> mprotect(RX)` after this fix is applied.
///
/// Returns `None` when the capture already lets EL0 read `CTR_EL0`, so a guest
/// that never trapped is never rewritten.
pub fn ctr_trap_fixup(captured_sctlr_el1: u64) -> Option<u64> {
    if captured_sctlr_el1 & SCTLR_EL1_UCT != 0 {
        return None;
    }
    Some(captured_sctlr_el1 | SCTLR_EL1_UCT)
}

/// #297, answered by measurement: **nothing to do.** `UCI` is the sibling of
/// [`SCTLR_EL1_UCT`] — clear it and every EL0 `ic ivau` / `dc cvau` / `dc civac`
/// traps to EL1 to be emulated one line at a time. The worry was that #296 had
/// made that 64x worse: handing EL0 the true 64-byte stride turns one trap per
/// 4 KiB page into sixty-four.
///
/// It never happened, because the erratum-1542419 workaround clears `UCT` and
/// leaves `UCI` alone — Linux sets `UCI` in `INIT_SCTLR_EL1_MMU_ON` and the
/// workaround only ever touches the `CTR_EL0` read. Read out of a real
/// Graviton2 capture, both vCPUs: `SCTLR_EL1 = 0x3454591d`, `UCT` clear and
/// **`UCI` set**. EL0 cache maintenance has been running natively on the
/// hardware the whole time, so there are no traps for a second bit to remove.
///
/// Pinned by `the_captured_guest_already_runs_its_own_cache_maintenance` so the
/// question is not reopened on the strength of the reasoning that opened it —
/// the premise was plausible and simply false, and only the capture could say
/// so. If a future capture ever arrives with `UCI` clear that guard fails, and
/// the trade re-opens with the evidence already attached.
pub const SCTLR_EL1_UCI: u64 = 1 << 26;

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
        // A vCPU bound to a `VtimerClock` takes its offset from the clock and
        // from nowhere else; letting a per-vCPU seed land here would re-open the
        // cross-core skew the clock exists to close.
        if self.clock.get().is_some() {
            return Ok(());
        }
        // SAFETY: FFI; reads the host monotonic tick.
        let now = unsafe { mach_absolute_time() };
        let offset = now.wrapping_sub(snapshot_cntvct);
        self.program_vtimer_offset(offset)
    }

    /// Write `offset` into HVF's virtual-timer offset for this vCPU and record
    /// it, so [`Self::current_cntvct`] can derive the counter later.
    fn program_vtimer_offset(&self, offset: u64) -> CpuResult<()> {
        // SAFETY: FFI on the owning thread.
        let ret = unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) };
        if ret != HV_SUCCESS {
            return Err(HypervisorCpuError::SetSysRegister(anyhow!(
                "hv_vcpu_set_vtimer_offset failed: {:#010x}",
                ret as u32
            )));
        }
        self.vtimer_offset.store(offset, Ordering::Relaxed);
        Ok(())
    }

    /// Bind this vCPU to the VM's shared counter clock and program the offset it
    /// publishes. Must be called on the vCPU's owning thread.
    ///
    /// This is the *only* supported way to set a restored guest's virtual
    /// counter: every vCPU programming one shared offset is what keeps
    /// `CNTVCT_EL0` coherent across cores. See [`VtimerClock`] for the
    /// measurements that make that non-negotiable.
    pub fn attach_clock(&self, clock: Arc<VtimerClock>) -> CpuResult<()> {
        let (num, den) = clock.scale();
        // Mirrored for the WFI nap's guest-ticks-to-host-ticks conversion only.
        self.cnt_scale_den.store(den, Ordering::Relaxed);
        self.cnt_scale_num.store(num, Ordering::Relaxed);
        let _ = self.clock.set(clock);
        self.sync_vtimer_offset()
    }

    /// Program the shared clock's current offset if this vCPU has not already.
    /// A no-op when the epoch has not moved, which is every entry for an
    /// unscaled clock.
    fn sync_vtimer_offset(&self) -> CpuResult<()> {
        let Some(clock) = self.clock.get() else {
            return Ok(());
        };
        let epoch = clock.epoch();
        if self.programmed_epoch.load(Ordering::Relaxed) == epoch {
            return Ok(());
        }
        self.program_vtimer_offset(clock.offset())?;
        self.programmed_epoch.store(epoch, Ordering::Relaxed);
        Ok(())
    }

    /// Program the shared offset before entering the guest, warning once if HVF
    /// refuses.
    ///
    /// A vCPU running on a stale offset has a `CNTVCT_EL0` that disagrees with
    /// its siblings', and the guest assumes one coherent counter — so this is
    /// reported rather than swallowed. It sits in a path that runs ~10^5 times
    /// per minute, hence once per vCPU rather than per call.
    fn sync_vtimer_offset_or_warn(&self) {
        if self.sync_vtimer_offset().is_err()
            && !self.vtimer_reprogram_failed.swap(true, Ordering::Relaxed)
        {
            eprintln!(
                "chm: warning: hv_vcpu_set_vtimer_offset failed on vcpu {}; \
                 guest counter on this vcpu will drift from its siblings'",
                self.id,
            );
        }
    }

    /// The rate scale as a reduced `(numerator, denominator)`, or `None` when
    /// the guest counter runs at the host rate.
    ///
    /// Only the WFI idle nap consumes this: it converts the guest's armed
    /// `CNTV_CVAL_EL0` deadline, expressed in the guest's faster tick rate, into
    /// a host-tick wait. The counter value itself comes from the shared
    /// [`VtimerClock`], never from a per-vCPU curve.
    fn counter_scale(&self) -> Option<(u64, u64)> {
        let num = self.cnt_scale_num.load(Ordering::Relaxed);
        if num == 0 {
            return None;
        }
        Some((num, self.cnt_scale_den.load(Ordering::Relaxed)))
    }

    /// Enter the guest-execution window of the shared counter clock. A no-op
    /// (and a free guard) for a vCPU with no clock attached.
    fn clock_enter(&self) -> ClockGuard<'_> {
        let clock = self.clock.get().map(|c| c.as_ref());
        if let Some(clock) = clock {
            clock.enter();
        }
        ClockGuard(clock)
    }

    /// The guest's current `CNTVCT_EL0`, derived as `mach_absolute_time() -
    /// offset` (HVF's definition) from the offset this vCPU has programmed.
    /// Used at checkpoint time because `hv_vcpu_get_sys_reg(CNTVCT_EL0)` is not
    /// reliably readable once the vCPU has been forced out of `run()`, and by
    /// the WFI nap to compare against the guest's armed deadline.
    ///
    /// This reports what the guest actually reads, not what the scaled curve
    /// aims at: between [`VtimerClock::step`]s the offset is fixed, so the
    /// counter advances at the host rate. Reasoning from the real value is what
    /// keeps the WFI wake-up and the checkpoint's captured counter honest.
    pub fn current_cntvct(&self) -> u64 {
        // SAFETY: FFI; reads the host monotonic tick.
        let now = unsafe { mach_absolute_time() };
        let offset = match self.clock.get() {
            Some(clock) => clock.offset(),
            None => self.vtimer_offset.load(Ordering::Relaxed),
        };
        now.wrapping_sub(offset)
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
        // The deadline is in guest ticks; under a counter scale those elapse
        // faster than host ticks, so convert back to the host rate first.
        let remaining_host_ticks = match self.counter_scale() {
            Some((num, den)) => {
                (u128::from(remaining_ticks) * u128::from(den) / u128::from(num)) as u64
            }
            None => remaining_ticks,
        };
        // Convert mach ticks -> ns -> ms via the host timebase.
        let tb = mach_timebase();
        let remaining_ns = (remaining_host_ticks as u128) * (tb.numer as u128) / (tb.denom as u128);
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

    // --- Userspace GICv3 CPU interface ---------------------------------------

    /// True when the userspace CPU interface is active for this vCPU.
    fn usgic_enabled(&self) -> bool {
        self.usgic.lock().unwrap().enabled
    }

    /// Switch the userspace CPU interface on for this vCPU.
    ///
    /// This is the only way it is ever enabled. On the production path
    /// [`crate::hvf::rehydrate::restore_usgic_vcpu`] calls it for every vCPU it
    /// builds, which is what makes a vanilla ITS/LPI capture run; tests call it
    /// directly. It is deliberately not driven by an environment variable: a
    /// vCPU with the interface on but no seeded distributor would intercept ICC
    /// system registers with nothing behind them.
    pub fn set_usgic_enabled(&self, on: bool) {
        self.usgic.lock().unwrap().enabled = on;
    }

    /// Publish this vCPU's liveness and GIC state for the roll call.
    ///
    /// Called at every run entry, before any early return. Two relaxed atomic
    /// stores and one short lock on a path that already takes that lock several
    /// times per entry.
    fn usgic_publish_liveness(&self) {
        let idx = self.index as usize;
        if idx >= ROLL_CALL_VCPUS {
            return;
        }
        // One line per vCPU at its first entry: the virtual timer as restored.
        // This splits "the checkpoint came back with a dead timer" from "the
        // timer died later", which no amount of reading the code can settle —
        // and it is what root-caused #257, so it is kept behind the same flag as
        // the rest of the vtimer tracing rather than deleted.
        if ROLL_CALL_SEEN[idx].load(Ordering::Relaxed) == 0
            && std::env::var_os("CHM_TRACE_VTIMER").is_some()
        {
            eprintln!(
                "[vtimer] vcpu {idx} first entry: CNTV_CTL={:#x} CNTV_CVAL={:#x} CNTVCT={:#x}",
                self.get_sysreg(0xDF19).unwrap_or(0),
                self.get_sysreg(0xDF1A).unwrap_or(0),
                self.current_cntvct(),
            );
        }
        let (vtimer_active, active, pending, depth) = {
            let g = self.usgic.lock().unwrap();
            (
                g.is_active(VTIMER_PPI),
                g.active.len(),
                g.pending.len(),
                g.active.len(),
            )
        };
        ROLL_CALL_GIC[idx].store(
            pack_gic(vtimer_active, active, pending, depth),
            Ordering::Relaxed,
        );
        // +1 so a live vCPU never publishes 0, which means "never ran".
        ROLL_CALL_SEEN[idx].store(now_ms() + 1, Ordering::Relaxed);
    }

    /// Self-manage the guest's virtual timer on the userspace-GIC path.
    ///
    /// With no managed GIC, HVF surfaces the timer via `HV_EXIT_REASON_VTIMER_
    /// ACTIVATED` and auto-masks it on that exit. Empirically, once that mask/
    /// unmask cycle has run, HVF does NOT reliably re-surface the activation for
    /// the guest's next armed deadline: an idle guest takes one tick, EOIs, arms
    /// its next `CNTV_CVAL`, executes WFI, and then wedges inside `hv_vcpu_run`
    /// with the overdue timer never redelivered. libkrun and QEMU's
    /// `kernel-irqchip=off` avoid this by self-managing the timer instead of
    /// trusting the activation exit.
    ///
    /// So at every run entry we sample the guest's `CNTV_CTL_EL0`/`CNTV_CVAL_EL0`
    /// directly and, if the timer is enabled, not guest-masked, and its deadline
    /// has passed against [`current_cntvct`], assert PPI 27 through the software
    /// GIC ourselves. [`push_pending`] dedups, so a race with a still-delivered
    /// `VTIMER_ACTIVATED` cannot double-inject. The WFI idle park already wakes
    /// at the `CNTV_CVAL` deadline (see [`wfi_park_ms`]), so this poll fires
    /// promptly on the re-entry after an idle park — restoring a steady tick.
    /// No-op unless the userspace GIC is enabled.
    ///
    /// This poll is also the reason [`UserGic::push_pending`]'s dedup has to ask
    /// the whole active stack. It runs at *every* entry, and the guest's armed
    /// deadline stays passed until the handler writes the next `CNTV_CVAL_EL0`
    /// — so throughout the timer handler's own prologue, and throughout anything
    /// that nests inside it, this function is asserting PPI 27 into a guest that
    /// is already servicing PPI 27. Only the dedup stops that becoming a second,
    /// re-entrant delivery. Refusals are counted; see
    /// [`UserGic::nested_requeues_refused`].
    ///
    /// It is a live safety net, not a dormant one: Apple's host-side vtimer mask
    /// is *not* visible in the guest's `CNTV_CTL_EL0`, so the `IMASK` check below
    /// reads guest intent only and this function keeps running while HVF has the
    /// timer masked — which is exactly when it is needed. That is measured by
    /// `hvf_host_vtimer_mask_is_invisible_to_the_guest_control_register`, and it
    /// had been an assumption until then.
    fn usgic_poll_vtimer(&self) {
        const CNTV_CTL_EL0: u16 = 0xDF19;
        const CNTV_CVAL_EL0: u16 = 0xDF1A;
        if !self.usgic_enabled() {
            return;
        }
        let ctl = self.get_sysreg(CNTV_CTL_EL0).unwrap_or(0);
        // ENABLE (bit0) set and IMASK (bit1) clear: the guest wants timer IRQs.
        if ctl & 1 == 0 || ctl & 2 != 0 {
            return;
        }
        let cval = self.get_sysreg(CNTV_CVAL_EL0).unwrap_or(u64::MAX);
        if cval <= self.current_cntvct() {
            let _ = self.usgic_assert_spi(VTIMER_PPI);
            self.usgic_report_nested_requeues();
            if self.usgic_note_vtimer_overdue() {
                self.usgic_report_wedge("overdue-dwell");
            }
        } else {
            self.usgic_clear_vtimer_overdue();
        }
    }

    /// Accumulate overdue dwell and say whether it has crossed the threshold for
    /// the first time. The reasoning lives on
    /// [`UserGic::note_vtimer_overdue`], which is where it is testable.
    fn usgic_note_vtimer_overdue(&self) -> bool {
        self.usgic.lock().unwrap().note_vtimer_overdue(Instant::now())
    }

    /// Forget any accumulated overdue dwell: the guest's deadline is in the
    /// future again, which it can only be because the tick was taken and the
    /// handler armed the next one.
    fn usgic_clear_vtimer_overdue(&self) {
        self.usgic.lock().unwrap().clear_vtimer_overdue();
    }

    /// The guest's counter frequency in ticks per second, derived from the host
    /// timebase and the rate-scaling ratio the shared clock synthesizes.
    ///
    /// Only the wedge report consumes this, and only to give `overdue_by` a
    /// magnitude: the sign alone cannot tell a guest that is 273 microseconds
    /// from its next tick from one whose counter disagrees with ours by half a
    /// minute, and those two findings name different subsystems.
    fn guest_ticks_per_second(&self) -> u128 {
        let tb = mach_timebase();
        if tb.numer == 0 {
            return 0;
        }
        let host_hz = 1_000_000_000u128 * u128::from(tb.denom) / u128::from(tb.numer);
        match self.counter_scale() {
            Some((num, den)) if den != 0 => host_hz * u128::from(num) / u128::from(den),
            _ => host_hz,
        }
    }

    /// Whether a console-side stall report is outstanding for this vCPU.
    fn usgic_wedge_report_requested(&self) -> bool {
        let want = WEDGE_REPORT_REQUESTS.load(Ordering::Relaxed);
        let mut g = self.usgic.lock().unwrap();
        if g.wedge_request_seen == want {
            return false;
        }
        g.wedge_request_seen = want;
        true
    }

    /// Print one report of this vCPU's interrupt-delivery state, and say which
    /// side of the boundary the evidence puts the fault on.
    ///
    /// #257 has been observed twice and reproduced never, and both observations
    /// produced nothing actionable because the state that would have answered it
    /// was never captured. The point of this is that the *next* occurrence is
    /// answerable the first time, from either trigger, without a 1.5M-line trace
    /// running for hours beforehand.
    ///
    /// The classification is the deliverable. Each arm names a different owner:
    ///
    /// * **`gic-model`** — an INTID is still on our active stack, so
    ///   [`UserGic::push_pending`] refuses to re-queue it and
    ///   [`Self::usgic_poll_vtimer`] is refused at every entry. Permanent, and
    ///   ours. This is exactly the shape #262 and #302 fixed.
    /// * **`guest-masked`** — we made the tick available and the guest is
    ///   sitting with `PSTATE.I` set. It cannot take an interrupt it has
    ///   disabled; the fault is above us.
    /// * **`guest-side`** — we delivered and the guest, with interrupts enabled,
    ///   did not take it. That is the instruction-cache/`DIC` territory
    ///   (`docs/cpu-feature-deltas.md` Finding 2), not the GIC's.
    /// * **`clock`** — the guest's kernel says its tick has stopped while *our*
    ///   counter says its deadline has not arrived. Only reachable from the
    ///   console trigger, because a deadline we do not believe has passed can
    ///   never raise the overdue trigger. Recording it as its own arm is what
    ///   stops a counter-scaling bug being misfiled as a guest-side one.
    fn usgic_report_wedge(&self, trigger: &str) {
        const CNTV_CTL_EL0: u16 = 0xDF19;
        const CNTV_CVAL_EL0: u16 = 0xDF1A;
        {
            let mut g = self.usgic.lock().unwrap();
            if g.wedge_reports >= WEDGE_REPORT_LIMIT {
                return;
            }
            g.wedge_reports += 1;
        }
        let ctl = self.get_sysreg(CNTV_CTL_EL0).unwrap_or(0);
        let cval = self.get_sysreg(CNTV_CVAL_EL0).unwrap_or(0);
        let now = self.current_cntvct();
        // Signed: the console trigger can fire while the deadline is still in
        // the future, and that gap is the entire evidence for the `clock` arm.
        let overdue_by = (now as i128) - (cval as i128);
        let pc = self.get_reg(HV_REG_PC).unwrap_or(0);
        let cpsr = self.get_reg(HV_REG_CPSR).unwrap_or(0);
        let irqs_masked = cpsr & PSTATE_I != 0;
        let timer_live = ctl & 1 != 0 && ctl & 2 == 0;

        let (pending, active, refused, asserting, entries) = {
            let g = self.usgic.lock().unwrap();
            (
                g.pending.clone(),
                g.active.clone(),
                g.nested_requeues_refused,
                g.should_assert(),
                g.vtimer_overdue_entries,
            )
        };

        let verdict = wedge_verdict(WedgeFacts {
            active_empty: active.is_empty(),
            timer_live,
            overdue_by,
            guest_hz: self.guest_ticks_per_second(),
            irqs_masked,
            vtimer_pending: pending.contains(&VTIMER_PPI),
        });

        eprintln!(
            "[wedge] vcpu {} trigger={trigger} verdict={verdict}\n\
             [wedge] vcpu {}   pending={pending:?} active={active:?} depth={} \
             asserting={asserting} nested_requeues_refused={refused}\n\
             [wedge] vcpu {}   CNTV_CTL={ctl:#x} (live={timer_live}) CVAL={cval:#x} \
             CNTVCT={now:#x} overdue_by={overdue_by} overdue_entries={entries}\n\
             [wedge] vcpu {}   PC={pc:#x} CPSR={cpsr:#x} (PSTATE.I={})",
            self.index,
            self.index,
            active.len(),
            self.index,
            self.index,
            u8::from(irqs_masked),
        );
    }

    /// Report the nested-requeue count when it crosses a power of two, under
    /// `CHM_TRACE_USGIC`.
    ///
    /// Powers of two rather than a stored watermark: it needs no extra state,
    /// self-limits to ~64 lines over any run, and still shows the shape of the
    /// growth. This sits on a path that runs ~10^5 times a minute, so the env
    /// lookup is behind the counter check, not the other way round.
    fn usgic_report_nested_requeues(&self) {
        let n = self.usgic.lock().unwrap().nested_requeues_refused;
        if n == 0 || n & (n - 1) != 0 {
            return;
        }
        if std::env::var_os("CHM_TRACE_USGIC").is_none() {
            return;
        }
        eprintln!(
            "[usgic] vcpu {}: refused {n} re-queue(s) of an INTID active beneath a \
             nested handler (see #262)",
            self.index,
        );
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

    /// This vCPU's cross-thread delivery handle (its injection queue + a wake fd),
    /// for the SMP SGI routing table. Collected for every vCPU after creation and
    /// handed back to each via [`Self::usgic_set_cpu_table`].
    pub fn usgic_cpu_handle(&self) -> UsgicCpuHandle {
        UsgicCpuHandle {
            inject: self.inject_queue.clone(),
            wake: self.wake_handle(),
        }
    }

    /// Install the SMP cross-vCPU delivery table (every vCPU's inject queue +
    /// wake, indexed by vCPU id). After this, an SGI raised on this core routes
    /// to the target core(s) instead of being delivered only to self. Thread-safe
    /// (guards the `UserGic` mutex), so the orchestrator can set it on every vCPU
    /// from its own thread once all vCPUs exist.
    pub fn usgic_set_cpu_table(&self, table: Arc<Vec<UsgicCpuHandle>>) {
        self.usgic.lock().unwrap().cpu_table = Some(table);
    }

    /// Route a software-generated interrupt (SGI / IPI) decoded from an
    /// `ICC_SGI1R_EL1` write to its target vCPU(s). `sgi` is the raw register
    /// value; the INTID is bits [27:24], the routing mode bit [40] (1 = all cores
    /// except self), and the Aff0 target list bits [15:0] (bit i = the core whose
    /// MPIDR Aff0 == i, the linear layout cloud-hypervisor uses for small vCPU
    /// counts). For each target this pushes the INTID into that core's injection
    /// queue and wakes it; the target's run-entry drain gates it on its own
    /// redistributor SGI-enable and delivers. Falls back to self-delivery when no
    /// cross-vCPU table is installed (single-vCPU path).
    fn usgic_route_sgi(&self, sgi: u64) -> CpuResult<()> {
        let intid = ((sgi >> 24) & 0xf) as u32;
        let table = self.usgic.lock().unwrap().cpu_table.clone();
        let Some(table) = table else {
            // Single-vCPU: deliver to self, preserving prior behaviour.
            return self.usgic_inject(intid);
        };
        let self_id = self.index as usize;
        for id in 0..table.len() {
            if !sgi_targets_core(sgi, self_id, id) {
                continue;
            }
            table[id].inject.lock().unwrap().push(intid);
            // Wake the target's idle-park fd so it drains promptly. A best-effort
            // write; a full pipe already means a wake is pending.
            let _ = table[id].wake.write(1);
        }
        Ok(())
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
                g.my_redist().is_ppi_enabled(intid)
            } else {
                // SPI: latch pending + read enable in the shared distributor.
                g.dist.lock().unwrap().assert_spi(intid)
            };
            if enabled {
                g.push_pending(intid);
            }
        }
    }

    /// Wire this vCPU's software distributor/redistributor to their guest MMIO
    /// bases (from the snapshot's GIC config). After this, guest accesses to those
    /// frames are serviced by the software GIC instead of faulting to the device
    /// bus. `0` bases leave them unwired. The distributor itself (VM-global) is
    /// sized + installed via [`Self::usgic_install_shared_dist`].
    pub fn usgic_set_gic_bases(&self, gicd_base: u64, gicr_base: u64) {
        let mut g = self.usgic.lock().unwrap();
        g.gicd_base = gicd_base;
        g.gicr_base = gicr_base;
    }

    /// Tell this vCPU's redistributor who it belongs to and whether it is the
    /// last in the region.
    ///
    /// Only a guest *discovering* its GIC reads these — `gic_populate_rdist`
    /// matches the affinity against `MPIDR_EL1`, and `gic_iterate_rdists` walks
    /// until it sees `Last`. A rehydrated guest discovered its GIC on the KVM
    /// host before it was captured, which is why this was never needed until
    /// something cold-booted. See `softgic::Redistributor::for_cpu`.
    pub fn usgic_set_redist_identity(&self, cpu_id: u32, last: bool) {
        self.usgic.lock().unwrap().my_redist().set_identity(cpu_id, last);
    }

    /// Install the VM-global distributor shared by every vCPU (so a reprogram on
    /// any core is visible to all and SPIs route by affinity). On the single-vCPU
    /// path this is that vCPU's own freshly-sized distributor.
    pub fn usgic_install_shared_dist(&self, dist: Arc<Mutex<crate::hvf::softgic::Distributor>>) {
        self.usgic.lock().unwrap().dist = dist;
    }

    /// Put this vCPU into the state PSCI defines for a core entered via
    /// `CPU_ON`: the highest implemented non-secure EL, interrupts masked.
    pub fn set_psci_entry_pstate(&self) -> CpuResult<()> {
        self.set_reg(HV_REG_CPSR, PSTATE_EL1H_DAIF)
    }

    /// Install the VM's redistributor frames — one per vCPU, shared by every
    /// core — and tell this vCPU which frame is its own.
    ///
    /// Needed only where a guest *discovers* its GIC. `gic_iterate_rdists`
    /// runs on the boot CPU and reads `GICR_TYPER` from every frame in the
    /// region, so each core has to be able to decode the whole region.
    pub fn usgic_install_shared_redists(
        &self,
        redists: Arc<Vec<Mutex<crate::hvf::softgic::Redistributor>>>,
        index: usize,
    ) {
        let mut g = self.usgic.lock().unwrap();
        g.redists = Redists(redists);
        g.redist_index = index;
    }

    /// A clone of the shared distributor handle, for the SPI router (which reads
    /// `GICD_IROUTER` to pick an SPI's target vCPU).
    pub fn usgic_shared_dist(&self) -> Arc<Mutex<crate::hvf::softgic::Distributor>> {
        self.usgic.lock().unwrap().dist.clone()
    }

    /// Seed the software distributor + redistributor from captured KVM GIC state
    /// (the same `(offset, value)` pairs the managed-GIC path restores), so a
    /// resumed guest keeps its interrupt configuration. The distributor is shared,
    /// so on SMP this seeds identical values under its mutex (idempotent).
    pub fn usgic_seed_gic(&self, dist_regs: &[(u32, u64)], redist_regs: &[(u32, u64)]) {
        let g = self.usgic.lock().unwrap();
        g.dist.lock().unwrap().seed_from_kvm(dist_regs);
        g.my_redist().seed_from_kvm(redist_regs);
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
    ///
    /// `access` is the access width in bytes. The GIC's register models are
    /// 32-bit, but several architectural registers are 64-bit and Linux
    /// touches them as one doubleword — `GICR_TYPER` (whose upper half holds
    /// the affinity a core matches against its own `MPIDR_EL1`),
    /// `GICR_PROPBASER`/`PENDBASER`, and `GICD_IROUTER`. Folding those onto
    /// the low word alone reports affinity 0 for every redistributor, so only
    /// the boot CPU can ever find its own frame.
    fn usgic_mmio(&self, ipa: u64, is_write: bool, write_val: u64, access: usize) -> Option<u64> {
        let g = self.usgic.lock().unwrap();
        if g.gicd_base != 0 && ipa >= g.gicd_base && ipa < g.gicd_base + 0x1_0000 {
            let off = ipa - g.gicd_base;
            // The distributor is VM-global (shared): a GICD write from ANY core
            // (e.g. reprogramming an SPI's enable or IROUTER affinity) updates the
            // one shared model, so it is visible to every core and to the SPI
            // router.
            let mut d = g.dist.lock().unwrap();
            Some(access_32bit_model(
                &mut *d,
                off,
                is_write,
                write_val,
                access,
            ))
        } else if let Some((frame, off)) = g.redist_frame(ipa) {
            if std::env::var_os("CHM_TRACE_REDIST").is_some() {
                eprintln!(
                    "[redist] cpu{} frame={frame} off={off:#x} write={is_write}",
                    g.redist_index
                );
            }
            // Any core may touch any frame — see the `redists` field docs.
            let mut r = g.redists[frame].lock().unwrap();
            Some(access_32bit_model(
                &mut *r,
                off,
                is_write,
                write_val,
                access,
            ))
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
            // shared distributor (which also latches the pending bit).
            let enabled = if intid < 32 {
                g.my_redist().is_ppi_enabled(intid)
            } else {
                g.dist.lock().unwrap().assert_spi(intid)
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
        let mut sgi_intid: Option<u64> = None;
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
                        if g.active.is_empty() { 0xff } else { 0 }
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
                    eprintln!(
                        "[usgic] vcpu {} read  {name} -> {val:#x} (x{rt})",
                        self.index
                    );
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
                        // The INTID lives in bits [23:0]; the rest is RES0.
                        let wrote = (val & 0xff_ffff) as u32;
                        g.write_eoir(wrote);
                        // If the virtual-timer PPI just deactivated, re-arm the
                        // HVF vtimer so the guest's next armed deadline fires.
                        // Asked of the whole active stack, not of a single slot:
                        // under EOImode=1 the EOI drops priority without
                        // deactivating, and a nested handler leaves 27 active
                        // underneath. Re-arming while it is still active would
                        // storm; not re-arming when it has gone is the wedge.
                        if g.vtimer_just_deactivated(Some(wrote)) {
                            rearm_timer = true;
                        }
                    }
                    // ICC_DIR_EL1 (deactivate interrupt) — used with EOImode=1.
                    (12, 11, 1) => {
                        name = "ICC_DIR";
                        let wrote = (val & 0xff_ffff) as u32;
                        g.write_dir(wrote);
                        if g.vtimer_just_deactivated(Some(wrote)) {
                            rearm_timer = true;
                        }
                    }
                    // ICC_SGI1R_EL1: software-generated interrupt (IPI). The INTID
                    // is bits [27:24]; the full register (target list / routing
                    // mode) is decoded by `usgic_route_sgi` so an SMP guest can
                    // IPI another core.
                    (12, 11, 5) => {
                        name = "ICC_SGI1R";
                        sgi_intid = Some(val);
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
                    eprintln!(
                        "[usgic] vcpu {} write {name} <- {val:#x} (x{rt})",
                        self.index
                    );
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
        // A software-generated interrupt was raised: route it to its target
        // core(s) (or self on the single-vCPU path).
        if let Some(sgi) = sgi_intid {
            self.usgic_route_sgi(sgi)?;
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

    /// Replay one captured system register against this host and report what
    /// actually happens to it, without disturbing the vCPU's usable state.
    ///
    /// [`Vcpu::set_state`] restores every non-MPIDR system register
    /// best-effort — `let _ = self.set_sysreg(id, v)` — because a register that
    /// is read-only on this core must not abort an otherwise good restore. That
    /// is the right behaviour, but it is silent: a value the capture host chose
    /// and the guest may have cached at boot can be dropped with no trace. This
    /// is the same bug class as the counter-frequency mismatch, which cost a
    /// 5.08x clock dilation before it was found by accident.
    ///
    /// This probe makes that silence measurable. It is deliberately read-mostly:
    /// the original value is read back and rewritten afterwards, so a probe run
    /// leaves the vCPU as it found it.
    pub fn probe_sysreg(&self, reg: u16, captured: u64) -> SysregFate {
        let host = self.get_sysreg(reg).ok();
        if self.set_sysreg(reg, captured).is_err() {
            return SysregFate::Refused { host };
        }
        let after = self.get_sysreg(reg).ok();
        // Put back whatever was there before, so probing cannot perturb a vCPU.
        if let Some(h) = host {
            let _ = self.set_sysreg(reg, h);
        }
        match after {
            Some(a) if a == captured => SysregFate::Restored,
            Some(a) => SysregFate::Clamped { observed: a, host },
            // Accepted the write but unreadable: treat as restored-but-unverified
            // rather than claiming a delta we cannot actually demonstrate.
            None => SysregFate::Unverifiable,
        }
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

    /// Capture this vCPU's live state for a **userspace-GIC** checkpoint: the
    /// architectural register file (plus a fresh `CNTVCT_EL0`), the software
    /// CPU-interface bookkeeping folded into `gic_icc` so the resume's
    /// [`Self::usgic_seed_icc`] re-seeds it, and the software distributor /
    /// redistributor models with the in-flight interrupt set. No managed
    /// redistributor is read (there is none on this path). Owning-thread only.
    pub fn capture_usgic_checkpoint(
        &self,
    ) -> CpuResult<(
        crate::hvf::checkpoint::VcpuCheckpoint,
        crate::hvf::checkpoint::UsgicCheckpoint,
    )> {
        let CpuState::Hvf(mut state) = <Self as Vcpu>::state(self)?;
        state
            .sysregs
            .push((SYSREG_CNTVCT_EL0, self.current_cntvct()));
        let g = self.usgic.lock().unwrap();
        // On the software path `state()` records no managed ICC (there is none);
        // fold in the values we track so resume restores the CPU-interface view.
        state.gic_icc = vec![
            (crate::hvf::ffi::GIC_ICC_PMR_EL1, g.pmr),
            (crate::hvf::ffi::GIC_ICC_BPR1_EL1, g.bpr1),
            (crate::hvf::ffi::GIC_ICC_CTLR_EL1, g.ctlr),
            (crate::hvf::ffi::GIC_ICC_SRE_EL1, g.sre),
            (crate::hvf::ffi::GIC_ICC_IGRPEN1_EL1, g.igrpen1),
        ];
        let usgic = crate::hvf::checkpoint::UsgicCheckpoint {
            dist: g.dist.lock().unwrap().clone(),
            redist: g.my_redist().clone(),
            pending: g.pending.clone(),
            active: g.active.last().copied(),
            active_stack: g.active.clone(),
        };
        Ok((
            crate::hvf::checkpoint::VcpuCheckpoint {
                state,
                rdist: Vec::new(),
            },
            usgic,
        ))
    }

    /// Restore a captured software-GIC state onto this vCPU's userspace GIC,
    /// overwriting the distributor/redistributor models and the in-flight
    /// interrupt set while leaving `enabled` and the MMIO bases (set by
    /// [`Self::usgic_set_gic_bases`]) intact. Applied on resume after the bases
    /// are wired, in place of the cold [`Self::usgic_seed_gic`].
    pub fn usgic_restore_softgic(&self, cp: &crate::hvf::checkpoint::UsgicCheckpoint) {
        let mut g = self.usgic.lock().unwrap();
        *g.dist.lock().unwrap() = cp.dist.clone();
        *g.my_redist() = cp.redist.clone();
        g.pending = cp.pending.clone();
        g.active = cp.active_stack();
    }

    /// Service a trapped self-hosted-debug system register that Hypervisor.framework
    /// does not implement. Returns `Ok(false)` if this is not one of them, so the
    /// caller still fails loudly on a register nobody has reasoned about.
    ///
    /// **Why this is not a blanket "ignore unknown MSR" catch-all.** Silently
    /// swallowing a system-register write is the most expensive kind of lie a
    /// hypervisor can tell: the guest believes it changed the machine, the
    /// machine did not change, and the divergence surfaces arbitrarily far away.
    /// So every register below is named, and — for the ones that carry state —
    /// only the write that requests the state we *actually* provide is accepted.
    /// A guest asking for something else still gets a hard error naming the
    /// register, which is how we found this path in the first place.
    ///
    /// A rehydrated guest never reaches here, which is why this was missing:
    /// `clear_os_lock()` runs once during `debug_monitors_init` at boot, long
    /// before any snapshot is taken. Cold boot is the first thing to execute it.
    fn handle_debug_sysreg_trap(&self, esr: u64) -> CpuResult<bool> {
        let iss = esr & 0x1ff_ffff;
        let is_read = (iss & 1) == 1;
        let crm = ((iss >> 1) & 0xf) as u8;
        let rt = ((iss >> 5) & 0x1f) as u32;
        let crn = ((iss >> 10) & 0xf) as u8;
        let op1 = ((iss >> 14) & 0x7) as u8;
        let op2 = ((iss >> 17) & 0x7) as u8;
        let op0 = ((iss >> 20) & 0x3) as u8;
        // The whole self-hosted debug register file is op0=2, op1=0.
        if op0 != 2 || op1 != 0 {
            return Ok(false);
        }
        // Value the guest is writing (XZR reads as zero, and Rt=31 means XZR
        // for MSR — not the stack pointer).
        let wval = if is_read || rt == 31 {
            0
        } else {
            self.get_reg(rt)?
        };
        let (name, rval): (&str, Option<u64>) = match (crn, crm, op2) {
            // OSLAR_EL1 (write-only). Writing 0 unlocks the OS lock; the lock is
            // a debugger handshake we do not implement, so it is permanently
            // unlocked and a write of 0 is genuinely a no-op. A write of 1 asks
            // us to lock out debug, which we cannot honour, so it falls through
            // to the hard error rather than being quietly dropped.
            (1, 0, 4) if !is_read && wval & 1 == 0 => ("OSLAR_EL1", None),
            // OSLSR_EL1 (read-only). OSLM = 0b00 in bits [3,0]: OS lock not
            // implemented. OSLK (bit 1) = 0: not locked. Consistent with the
            // OSLAR_EL1 answer above.
            (1, 1, 4) if is_read => ("OSLSR_EL1", Some(0)),
            // OSDLR_EL1. Same argument as OSLAR_EL1: the OS *double* lock is not
            // implemented, so clearing it (DLK=0) is a no-op; setting it is not
            // something we can honour.
            (1, 3, 4) if wval & 1 == 0 => ("OSDLR_EL1", Some(0)),
            // DBGPRCR_EL1. CORENPDRQ=0 means "no powerdown request held", which
            // is the state of a vCPU that has no power controller behind it.
            (1, 4, 4) if wval & 1 == 0 => ("DBGPRCR_EL1", Some(0)),
            _ => return Ok(false),
        };
        if is_read {
            let Some(v) = rval else {
                // A read of a write-only register: architecturally UNDEFINED, so
                // do not invent an answer.
                return Ok(false);
            };
            if rt != 31 {
                self.set_reg(rt, v)?;
            }
        }
        if std::env::var_os("CHM_TRACE_DEBUGREG").is_some() {
            let dir = if is_read { "read" } else { "write" };
            eprintln!(
                "[dbgreg] vcpu {} {dir} {name} val={:#x}",
                self.index,
                if is_read { rval.unwrap_or(0) } else { wval }
            );
        }
        let pc = self.get_reg(HV_REG_PC)?;
        self.set_reg(HV_REG_PC, pc.wrapping_add(4))?;
        Ok(true)
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
                self.get_reg(srt)?
            } else {
                0
            };
            if let Some(read_val) = self.usgic_mmio(ipa, is_write, write_val, access) {
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
            } else if id == SYSREG_SCTLR_EL1 {
                // See `ctr_trap_fixup`: a capture from Neoverse-N1 arrives with
                // EL0 reads of CTR_EL0 trapped to a handler that reports a
                // 4096-byte i-cache stride, which is 64x too coarse here.
                let want = if std::env::var_os("CHM_KEEP_CTR_TRAP").is_some() {
                    v
                } else {
                    ctr_trap_fixup(v).unwrap_or(v)
                };
                let _ = self.set_sysreg(id, want);
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
        // A restore that supplied no `CNTV_CTL_EL0` tells us nothing about the
        // guest's virtual timer, and the safest reading of "nothing" is not
        // "disabled". Checkpoints written before the timer pair joined
        // `SNAPSHOT_SYS_REGS` carry no timer state at all, so honouring the
        // vCPU's reset value would resume every one of them with no tick and no
        // deadline — #257, permanently, for every checkpoint that already
        // exists on a user's disk.
        //
        // So arm a deadline just ahead of now and enable the timer. The guest
        // takes one tick, `timer_handler` sees `ISTATUS`, and Linux re-arms
        // `CNTV_CVAL` itself on the way out — which is precisely how the vCPUs
        // that appeared to recover on their own were recovering, except by luck
        // rather than by design.
        //
        // This deliberately does NOT fire when the state supplied `CNTV_CTL`,
        // even with `ENABLE` clear: a vCPU parked by `PSCI CPU_OFF` has its
        // timer genuinely off, and overriding a captured value would invent
        // state instead of restoring it.
        if vtimer_needs_arming(&s.sysregs) {
            let now = self.get_sysreg(SYSREG_CNTVCT_EL0).unwrap_or(0);
            let _ = self.set_sysreg(SYSREG_CNTV_CVAL_EL0, now.saturating_add(1));
            let _ = self.set_sysreg(SYSREG_CNTV_CTL_EL0, 1);
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

    fn usgic_inject_queue(&self) -> Option<Arc<Mutex<Vec<u32>>>> {
        // Only expose the queue when the userspace GIC is actually in use — a
        // managed-GIC vCPU delivers cross-thread interrupts through the GIC, not
        // this queue.
        if self.usgic.lock().unwrap().enabled {
            Some(self.inject_queue.clone())
        } else {
            None
        }
    }

    fn run(&mut self) -> std::result::Result<VmExit, HypervisorCpuError> {
        // Signal forward progress to the host-side run watchdog: each entry into
        // run() bumps this. A vCPU wedged inside a single hv_vcpu_run call (e.g.
        // Apple's internal WFI wait not honouring its deadline) stops bumping it,
        // which the watchdog detects and breaks by forcing an exit.
        self.run_gen.fetch_add(1, Ordering::Relaxed);
        // Everything from here to `hv_vcpu_run` returning is guest-execution
        // time as far as the shared counter clock is concerned: while this guard
        // is held the clock cannot move the virtual-timer offset, so the guest
        // can never observe a half-applied change. The guard is dropped as soon
        // as the guest exits — deliberately *before* the WFI idle park below,
        // which can nap for up to a second and would otherwise stall the clock.
        let ret = {
            let _guest = self.clock_enter();
            // Adopt the shared offset. A no-op unless the clock stepped, which
            // for an unscaled guest is never.
            self.sync_vtimer_offset_or_warn();
            // Drain any cross-thread injections (device/net-service completions)
            // into the userspace GIC before we sample the line — they were
            // enqueued off this vCPU's thread and can only be applied here, on
            // the owning thread.
            self.usgic_drain_injected();
            // Publish liveness before anything that can return early. A wedged
            // vCPU is defined by not getting here, so this must not sit behind a
            // condition the wedge itself can fail.
            self.usgic_publish_liveness();
            // A stall the guest kernel itself reported (see `request_wedge_report`).
            // Serviced on the owning thread, which is the only thread allowed to
            // read this vCPU's registers — but *outside* `usgic_poll_vtimer`,
            // which returns early when the guest has its timer disabled or
            // masked. A vCPU in that state is precisely the one worth asking
            // about, and while this check sat behind that early return the real
            // wedge was silent while a healthy sibling answered for it. Never
            // gate a report on a condition the fault can itself produce.
            if self.usgic_wedge_report_requested() {
                self.usgic_report_wedge("guest-reported-stall");
            }
            // Self-manage the guest's virtual timer: if its armed CNTV deadline
            // is due, assert PPI 27 now. HVF's own VTIMER_ACTIVATED delivery is
            // unreliable across the mask/unmask cycle and wedges an idle guest,
            // so we poll it here every entry (see usgic_poll_vtimer). The WFI
            // idle park wakes at that deadline, so this fires promptly on the
            // re-entry.
            self.usgic_poll_vtimer();
            // Userspace CPU interface: HVF samples the raw virtual IRQ line at
            // run ENTRY (not continuously), so — like QEMU's
            // hvf_inject_interrupts — we must (re)assert it before every entry
            // whenever an interrupt is pending and none is currently active.
            // This is what makes an injected LPI get taken once the guest clears
            // PSTATE.I, regardless of intervening exits.
            self.usgic_refresh_irq_line();
            // SAFETY: FFI on the owning thread.
            unsafe { hv_vcpu_run(self.id) }
        };
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
                "[exit] t={} vcpu {} reason={} ec={ec:#x} pc={pc:#x} ipa={:#x}",
                self.current_cntvct(),
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
                    EC_INSTR_ABORT_LOWER | EC_INSTR_ABORT_SAME
                        if icache_wx::on_exec_fault(ipa) =>
                    {
                        // The guest fetched from a page we were holding
                        // non-executable so that we could do the instruction-cache
                        // maintenance its own kernel has had patched out. Done
                        // now; re-enter and let the fetch retry.
                        Ok(VmExit::Ignore)
                    }
                    EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME
                        if icache_wx::armed() && icache_wx::on_write_fault(ipa) =>
                    {
                        // A write to a page we had granted execute. Execute has
                        // been withdrawn, so the next fetch faults and we get to
                        // invalidate against the finished contents.
                        Ok(VmExit::Ignore)
                    }
                    EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
                        self.handle_data_abort(esr, ipa)?;
                        Ok(VmExit::Ignore)
                    }
                    EC_WFX => {
                        if std::env::var("CHM_TRACE_VTIMER_WFI").is_ok() {
                            // NOT `get_sysreg(CNTVCT_EL0)`: HVF does not expose the
                            // virtual counter that way and returns 0, which made
                            // this trace read as "the guest counter is stuck at 0".
                            let cv = self.current_cntvct();
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
                        if self.usgic_enabled() {
                            // Halt IN THE HOST until the software GIC has an
                            // interrupt to deliver, then return so hv_vcpu_run
                            // delivers it. Re-entering hv_vcpu_run with nothing
                            // pending lets HVF service the WFI in-kernel and block
                            // on a vtimer deadline it never redelivers (it only
                            // surfaces VTIMER_ACTIVATED *inside* hv_vcpu_run) —
                            // the idle-guest wedge.
                            //
                            // Capture the guest's timer deadline ONCE here, while
                            // the values are fresh from the just-returned
                            // hv_vcpu_run (CNTV_* / CNTVCT read unreliably once the
                            // vCPU is parked out of run), then nap against the
                            // host monotonic counter (current_cntvct, mach-based
                            // and always valid) and self-deliver PPI 27 when the
                            // captured deadline passes. A cross-thread injection
                            // (drained each nap) also breaks the wait. A wall-clock
                            // cap bounds the halt so VM teardown (which stops the
                            // outer run loop) is observed even if nothing becomes
                            // pending — on re-entry the guest simply re-WFIs and we
                            // capture its next deadline.
                            const CNTV_CTL_EL0: u16 = 0xDF19;
                            const CNTV_CVAL_EL0: u16 = 0xDF1A;
                            let ctl = self.get_sysreg(CNTV_CTL_EL0).unwrap_or(0);
                            let timer_live = ctl & 1 != 0 && ctl & 2 == 0;
                            let cval = self.get_sysreg(CNTV_CVAL_EL0).unwrap_or(u64::MAX);
                            let halt_deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(1);
                            loop {
                                if timer_live && self.current_cntvct() >= cval {
                                    let _ = self.usgic_assert_spi(VTIMER_PPI);
                                }
                                self.usgic_drain_injected();
                                if self.usgic.lock().unwrap().should_assert()
                                    || std::time::Instant::now() >= halt_deadline
                                {
                                    break;
                                }
                                let nap_ms = if timer_live {
                                    let now = self.current_cntvct();
                                    if cval > now {
                                        // `cval` and `current_cntvct` are GUEST
                                        // ticks; the mach timebase converts HOST
                                        // ticks. When the counter is scaled those
                                        // are different units, so fold the
                                        // guest->host ratio in first or the nap is
                                        // computed `guest_hz / host_hz` too long.
                                        let (num, den) = self.counter_scale().unwrap_or((1, 1));
                                        let host_ticks =
                                            (cval - now) as u128 * den as u128 / num as u128;
                                        let tb = mach_timebase();
                                        let ns = host_ticks * tb.numer as u128 / tb.denom as u128;
                                        ((ns / 1_000_000) as u64).clamp(1, 10)
                                    } else {
                                        1
                                    }
                                } else {
                                    10
                                };
                                // Wait on the wake fd rather than sleeping blind.
                                // Device threads write this fd immediately after
                                // asserting a completion interrupt, so a guest
                                // parked in WFI on a virtio completion resumes as
                                // soon as the device is done instead of after the
                                // remainder of a 1-10 ms nap. The timeout is the
                                // same nap, so a wakeup source that never kicks
                                // (e.g. the virtual timer, self-delivered above)
                                // behaves exactly as before. `wait_timeout` drains
                                // the fd itself, so a stale count cannot spin here.
                                let _ = self.kick.wait_timeout(nap_ms as i32);
                            }
                        } else {
                            // Managed path: one bounded park; the outer loop
                            // re-enters and the managed GIC redelivers.
                            let _ = self.kick.wait_timeout(self.wfi_park_ms());
                        }
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
                            // The device tree says `arm,psci-0.2`, so the kernel
                            // asks what version it is actually talking to before
                            // it uses anything else. Answering 0 (the old
                            // catch-all) reads as v0.0, which makes the kernel
                            // disable PSCI outright — no secondary CPUs, no
                            // reset. A rehydrated guest never asked, because it
                            // probed PSCI before it was ever captured.
                            PSCI_VERSION => {
                                self.set_reg(0, PSCI_VERSION_1_0)?;
                                Ok(VmExit::Ignore)
                            }
                            PSCI_FEATURES => {
                                let fid = self.get_reg(1)?;
                                let supported = matches!(
                                    fid,
                                    PSCI_VERSION
                                        | PSCI_FEATURES
                                        | PSCI_SYSTEM_OFF
                                        | PSCI_SYSTEM_RESET
                                        | PSCI_CPU_ON
                                        | PSCI_CPU_ON_32
                                );
                                self.set_reg(
                                    0,
                                    if supported {
                                        PSCI_SUCCESS
                                    } else {
                                        PSCI_NOT_SUPPORTED
                                    },
                                )?;
                                Ok(VmExit::Ignore)
                            }
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
                    EC_MSR_MRS_64 => {
                        // Userspace GICv3 CPU interface: the guest touched an
                        // ICC_*_EL1 register with no managed GIC present, so HVF
                        // trapped it to us. Emulate it (this is what lets us hand
                        // the guest an LPI the managed GIC could never deliver).
                        // The debug arm is checked on BOTH GIC paths, because
                        // that trap has nothing to do with the interrupt
                        // controller — it only ever looked that way because the
                        // userspace GIC was the one thing that had claimed an
                        // MSR/MRS exit.
                        let handled = (self.usgic_enabled() && self.handle_icc_trap(esr)?)
                            || self.handle_debug_sysreg_trap(esr)?;
                        if handled {
                            Ok(VmExit::Ignore)
                        } else {
                            Err(HypervisorCpuError::RunVcpu(anyhow!(
                                "unhandled sysreg trap ESR={esr:#x} (vcpu {})",
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
                    // software GIC and leave HVF's vtimer masked until the guest
                    // EOIs it (unmask in handle_icc_trap). This is the libkrun /
                    // QEMU kernel-irqchip=off sequence; unmasking earlier storms
                    // (HVF re-fires the activation before the guest can run its
                    // handler to advance CNTV). The wedge where an idle guest
                    // never gets its NEXT tick — because HVF only delivers
                    // VTIMER_ACTIVATED inside hv_vcpu_run, not while we're parked
                    // in the WFI idle wait — is handled by usgic_poll_vtimer,
                    // which re-raises PPI 27 at the armed CNTV_CVAL deadline on
                    // the run entry after the park wakes.
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
