// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Raw FFI bindings to Apple's `Hypervisor.framework` (arm64) plus the small
//! set of architectural constants the backend decodes. These mirror the public
//! `<Hypervisor/hv*.h>` headers shipped with the macOS SDK.

use std::ffi::c_void;

/// `hv_return_t` success value (`HV_SUCCESS`).
pub const HV_SUCCESS: i32 = 0;

// hv_return_t failure codes (from `<Hypervisor/hv_error.h>`). These are the
// values `hv_vm_create` and friends return so we can turn an opaque failure into
// an actionable diagnostic instead of a bare "operation failed".
pub const HV_ERROR: i32 = 0xfae94001u32 as i32;
pub const HV_BUSY: i32 = 0xfae94002u32 as i32;
pub const HV_BAD_ARGUMENT: i32 = 0xfae94003u32 as i32;
pub const HV_ILLEGAL_GUEST_STATE: i32 = 0xfae94004u32 as i32;
pub const HV_NO_RESOURCES: i32 = 0xfae94005u32 as i32;
pub const HV_NO_DEVICE: i32 = 0xfae94006u32 as i32;
pub const HV_DENIED: i32 = 0xfae94007u32 as i32;
pub const HV_UNSUPPORTED: i32 = 0xfae9400fu32 as i32;

/// A human, actionable description of an `hv_return_t` code. The load-bearing
/// case is [`HV_DENIED`]: on macOS that is what `hv_vm_create` returns when the
/// running binary lacks the `com.apple.security.hypervisor` entitlement — the
/// single most common local-dev failure, and one a bare code makes look like a
/// kernel/VM-slot problem. Naming it directly (with the fix) turns an hour of
/// misdiagnosis into a one-line remedy.
pub fn hv_return_str(code: i32) -> &'static str {
    match code {
        HV_SUCCESS => "HV_SUCCESS",
        HV_ERROR => "HV_ERROR (unexpected internal error)",
        HV_BUSY => "HV_BUSY (another VM already exists in this process; hv_vm_create is process-global)",
        HV_BAD_ARGUMENT => "HV_BAD_ARGUMENT (invalid argument)",
        HV_ILLEGAL_GUEST_STATE => "HV_ILLEGAL_GUEST_STATE (illegal guest state)",
        HV_NO_RESOURCES => "HV_NO_RESOURCES (out of resources; a host reboot may be needed to reclaim leaked VMs)",
        HV_NO_DEVICE => "HV_NO_DEVICE (no hypervisor device; not an Apple-silicon/VM-capable host?)",
        HV_DENIED => {
            "HV_DENIED — the binary is not signed with the \
             'com.apple.security.hypervisor' entitlement (every `cargo build` \
             STRIPS it). Re-sign it: `codesign --sign - --entitlements \
             hypervisor/tests/data/hv.entitlements --force <binary>` (or build \
             chm via scripts/build-chm.sh, which signs)"
        }
        HV_UNSUPPORTED => "HV_UNSUPPORTED (operation not supported on this host)",
        _ => "unknown hv_return_t",
    }
}

// hv_reg_t — general-purpose and special core registers.
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_CPSR: u32 = 34;

// hv_exit_reason_t
pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

// hv_memory_flags_t
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

// ESR_EL2 exception classes (syndrome >> 26).
pub const EC_WFX: u64 = 0x01; // WFI/WFE trapped
pub const EC_MSR_MRS_64: u64 = 0x18; // trapped AArch64 MSR/MRS/system-reg access
pub const EC_HVC64: u64 = 0x16;
pub const EC_DATA_ABORT_LOWER: u64 = 0x24; // from a lower EL (the guest)
pub const EC_DATA_ABORT_SAME: u64 = 0x25; // from the current EL
pub const EC_INSTR_ABORT_LOWER: u64 = 0x20; // instruction fetch fault, lower EL
pub const EC_INSTR_ABORT_SAME: u64 = 0x21; // instruction fetch fault, current EL

// PSTATE for a cold EL1h boot with DAIF (D,A,I,F) masked.
pub const PSTATE_EL1H_DAIF: u64 = 0x3c5;

// PSCI 0.2 function ids issued via HVC.
pub const PSCI_VERSION: u64 = 0x8400_0000;
pub const PSCI_FEATURES: u64 = 0x8400_000a;
pub const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
pub const PSCI_CPU_ON: u64 = 0xc400_0003;
pub const PSCI_CPU_ON_32: u64 = 0x8400_0003;

/// PSCI version reported to the guest: 1.0, encoded major[31:16].minor[15:0].
///
/// The device tree declares `arm,psci-0.2`, which tells the kernel it may call
/// `PSCI_VERSION` — so the value it gets back has to be at least 0.2 or the
/// kernel prints *"PSCIv0.0 detected in firmware"* and *"Conflicting PSCI
/// version detected"* and disables PSCI entirely, taking secondary CPU bringup
/// and system-reset with it.
///
/// This went unnoticed for the whole life of the backend because a *rehydrated*
/// guest has already probed PSCI before it was captured and never asks again.
/// The first cold boot asked on its first millisecond.
pub const PSCI_VERSION_1_0: u64 = 0x0001_0000;

/// `PSCI_FEATURES` return for a supported function.
pub const PSCI_SUCCESS: u64 = 0;
/// `PSCI_FEATURES` / dispatch return for an unimplemented function id.
pub const PSCI_NOT_SUPPORTED: u64 = -1i64 as u64;

// Arm SMCCC TRNG firmware interface (DEN0098). cloud-hypervisor exposes these as
// a firmware service; a resumed guest calls TRNG_RND* during early boot to seed
// its CRNG, so the runtime must honour them or the guest stalls before I/O.
pub const TRNG_VERSION: u64 = 0x8400_0050;
pub const TRNG_FEATURES: u64 = 0x8400_0051;
pub const TRNG_GET_UUID: u64 = 0x8400_0052;
pub const TRNG_RND32: u64 = 0x8400_0053;
pub const TRNG_RND64: u64 = 0xc400_0053;
// SMCCC return codes.
pub const SMCCC_SUCCESS: u64 = 0;
pub const SMCCC_NOT_SUPPORTED: u64 = -1i64 as u64;
pub const SMCCC_INVALID_PARAMETER: u64 = -2i64 as u64;

// hv_sys_reg_t — curated EL1 system-register ids used for snapshot/restore.
pub const SYSREG_MDSCR_EL1: u16 = 0x8012;
pub const SYSREG_SCTLR_EL1: u16 = 0xc080;
pub const SYSREG_CPACR_EL1: u16 = 0xc082;
pub const SYSREG_TTBR0_EL1: u16 = 0xc100;
pub const SYSREG_TTBR1_EL1: u16 = 0xc101;
pub const SYSREG_TCR_EL1: u16 = 0xc102;
pub const SYSREG_SPSR_EL1: u16 = 0xc200;
pub const SYSREG_ELR_EL1: u16 = 0xc201;
pub const SYSREG_SP_EL0: u16 = 0xc208;
pub const SYSREG_ESR_EL1: u16 = 0xc290;
pub const SYSREG_FAR_EL1: u16 = 0xc300;
pub const SYSREG_MAIR_EL1: u16 = 0xc510;
pub const SYSREG_VBAR_EL1: u16 = 0xc600;
pub const SYSREG_TPIDR_EL1: u16 = 0xc684;
pub const SYSREG_TPIDR_EL0: u16 = 0xde82;
pub const SYSREG_TPIDRRO_EL0: u16 = 0xde83;
pub const SYSREG_SP_EL1: u16 = 0xe208;
pub const SYSREG_MPIDR_EL1: u16 = 0xc005;
/// EL0 virtual counter (read-only). Carried in a KVM snapshot's register file;
/// its captured value seeds the HVF vtimer offset on restore so the guest's
/// CNTVCT_EL0 resumes continuously instead of restarting near zero.
pub const SYSREG_CNTVCT_EL0: u16 = 0xdf02;
/// EL0 virtual timer compare value: the counter value at which the guest's next
/// tick is due. Part of the checkpointed state — see [`SYSREG_CNTV_CTL_EL0`].
pub const SYSREG_CNTV_CVAL_EL0: u16 = 0xdf1a;
/// EL0 virtual timer control: `ENABLE` (bit 0), `IMASK` (bit 1), `ISTATUS`
/// (bit 2).
///
/// This and `CNTV_CVAL_EL0` are the guest's entire virtual-timer arming state,
/// and omitting them from a checkpoint is not a lossy nicety — it is #257. A
/// vCPU resumed with `ENABLE = 0` and `CVAL = 0` has no tick, and nothing in the
/// guest will re-arm it except code that only runs *because* of an interrupt. A
/// vCPU that happens to take some other interrupt re-enters the kernel and
/// re-arms, which is why this looked intermittent for months; one resumed while
/// executing userspace with nothing else pending never gets that chance and
/// wedges permanently, while its siblings stay healthy.
pub const SYSREG_CNTV_CTL_EL0: u16 = 0xdf19;
/// MPIDR_EL1 bit[31] is RES1 on AArch64; affinity fields occupy Aff0..Aff3.
pub const MPIDR_RES1: u64 = 1 << 31;

// hv_gic_icc_reg_t — per-vCPU GIC CPU-interface registers (managed by hv_gic).
pub const GIC_ICC_PMR_EL1: u16 = 0xc230;
pub const GIC_ICC_BPR0_EL1: u16 = 0xc643;
pub const GIC_ICC_AP0R0_EL1: u16 = 0xc644;
pub const GIC_ICC_AP1R0_EL1: u16 = 0xc648;
/// Running priority — read-only, captured for diagnostics but never restored.
#[allow(dead_code)]
pub const GIC_ICC_RPR_EL1: u16 = 0xc65b;
pub const GIC_ICC_BPR1_EL1: u16 = 0xc663;
pub const GIC_ICC_CTLR_EL1: u16 = 0xc664;
pub const GIC_ICC_SRE_EL1: u16 = 0xc665;
pub const GIC_ICC_IGRPEN0_EL1: u16 = 0xc666;
pub const GIC_ICC_IGRPEN1_EL1: u16 = 0xc667;

/// Writable CPU-interface registers captured on snapshot, in restore order.
/// RPR_EL1 (running priority) is read-only and so deliberately excluded.
pub const GIC_ICC_SNAPSHOT_REGS: &[u16] = &[
    GIC_ICC_PMR_EL1,
    GIC_ICC_BPR0_EL1,
    GIC_ICC_AP0R0_EL1,
    GIC_ICC_AP1R0_EL1,
    GIC_ICC_BPR1_EL1,
    GIC_ICC_CTLR_EL1,
    GIC_ICC_SRE_EL1,
    GIC_ICC_IGRPEN0_EL1,
    GIC_ICC_IGRPEN1_EL1,
];

// hv_interrupt_type_t. The managed GIC routes interrupts itself (SPIs via
// hv_gic_set_spi, the vtimer via PPI 27), so the raw per-vCPU interrupt-line
// primitive below is not used by this backend; it is retained as the documented
// HVF primitive for a future no-GIC or cross-thread-kick path.
#[allow(dead_code)]
pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;
#[allow(dead_code)]
pub const HV_INTERRUPT_TYPE_FIQ: u32 = 1;

// hv_gic_distributor_reg_t — register offsets within the distributor.
#[allow(dead_code)]
pub const HV_GIC_DIST_REG_GICD_CTLR: u32 = 0x0000;
#[allow(dead_code)]
pub const HV_GIC_DIST_REG_GICD_TYPER: u32 = 0x0004;

/// `hv_vcpu_exit_exception_t`.
#[repr(C)]
pub struct HvVcpuExitException {
    pub syndrome: u64,         // ESR_ELx
    pub virtual_address: u64,  // FAR_ELx
    pub physical_address: u64, // faulting IPA (stage-2)
}

/// `hv_vcpu_exit_t`.
#[repr(C)]
pub struct HvVcpuExit {
    pub reason: u32,
    pub exception: HvVcpuExitException,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_create(config: *mut c_void) -> i32;
    pub fn hv_vm_destroy() -> i32;
    pub fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> i32;
    pub fn hv_vm_unmap(ipa: u64, size: usize) -> i32;
    /// Change stage-2 permissions on an already-mapped IPA range. `ipa` and
    /// `size` must be host-page aligned. Used by `icache_wx` to hold guest RAM
    /// writable-but-not-executable and grant execute one page at a time.
    pub fn hv_vm_protect(ipa: u64, size: usize, flags: u64) -> i32;
    pub fn hv_vcpu_create(vcpu: *mut u64, exit: *mut *mut HvVcpuExit, config: *mut c_void) -> i32;
    pub fn hv_vcpu_destroy(vcpu: u64) -> i32;
    pub fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) -> i32;
    pub fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *mut u64) -> i32;
    pub fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u16, value: u64) -> i32;
    pub fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
    pub fn hv_vcpu_run(vcpu: u64) -> i32;
    // Force the listed vCPUs to return from `hv_vcpu_run` promptly. Safe to call
    // from a thread other than the one running the vCPU; the interrupted run
    // returns with `HV_EXIT_REASON_CANCELED`. Used to interrupt a guest that is
    // executing without trapping (e.g. a CPU-bound spin) so a host-side stop can
    // take effect.
    pub fn hv_vcpus_exit(vcpus: *const u64, vcpu_count: u32) -> i32;
    #[allow(dead_code)]
    pub fn hv_vcpu_set_pending_interrupt(vcpu: u64, ty: u32, pending: bool) -> i32;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: u64, masked: bool) -> i32;
    // VTimer offset: CNTVCT_EL0 = mach_absolute_time() - offset. Restoring the
    // offset from a snapshot's captured CNTVCT makes the guest's virtual counter
    // resume where it left off, so an armed CNTV comparator fires promptly
    // instead of the guest sleeping ~2^32 ticks waiting for a counter that
    // restarted near zero.
    #[allow(dead_code)]
    pub fn hv_vcpu_get_vtimer_offset(vcpu: u64, offset: *mut u64) -> i32;
    pub fn hv_vcpu_set_vtimer_offset(vcpu: u64, offset: u64) -> i32;

    // GIC configuration object (os_object, released with os_release).
    pub fn hv_gic_config_create() -> *mut c_void;
    pub fn hv_gic_config_set_distributor_base(config: *mut c_void, base: u64) -> i32;
    pub fn hv_gic_config_set_redistributor_base(config: *mut c_void, base: u64) -> i32;
    // MSI/ITS region setup — reserved for when irqfd/GSI routing lands.
    pub fn hv_gic_config_set_msi_region_base(config: *mut c_void, base: u64) -> i32;
    pub fn hv_gic_config_set_msi_interrupt_range(config: *mut c_void, base: u32, count: u32)
    -> i32;

    // GIC lifecycle, register access and interrupt injection.
    pub fn hv_gic_create(config: *mut c_void) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_reset() -> i32;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> i32;
    // Message-signalled interrupt delivery. `address` is the doorbell IPA
    // (GICM_SET_SPI_NSR within the configured MSI region) and `intid` the SPI to
    // pulse. NOTE: Apple's managed GIC has NO ITS, so this delivers a
    // message-based SPI — it CANNOT replay an LPI the way a KVM ITS-wired guest
    // expects. Kept for future MBI-style guests and documented in
    // `HvfGicV3::send_msi`.
    pub fn hv_gic_send_msi(address: u64, intid: u32) -> i32;
    pub fn hv_gic_get_distributor_reg(reg: u32, value: *mut u64) -> i32;
    pub fn hv_gic_set_distributor_reg(reg: u32, value: u64) -> i32;
    // Per-vCPU redistributor registers. `reg` is an `hv_gic_redistributor_reg_t`
    // — the architectural GICR offset (e.g. ISENABLER0 = 0x10100 in the SGI
    // frame), exactly the offsets KVM's VGIC redistributor dump uses.
    pub fn hv_gic_get_redistributor_reg(vcpu: u64, reg: u32, value: *mut u64) -> i32;
    pub fn hv_gic_set_redistributor_reg(vcpu: u64, reg: u32, value: u64) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_redistributor_size(size: *mut usize) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_distributor_size(size: *mut usize) -> i32;
    #[allow(dead_code)]
    pub fn hv_gic_get_spi_interrupt_range(base: *mut u32, count: *mut u32) -> i32;
    // MSI region geometry — required to place the doorbell at a framework-
    // approved base/size before `hv_gic_config_set_msi_region_base`.
    pub fn hv_gic_get_msi_region_size(size: *mut usize) -> i32;
    pub fn hv_gic_get_msi_region_base_alignment(alignment: *mut usize) -> i32;

    // Per-vCPU GIC CPU-interface (ICC) registers. The managed GIC owns these
    // (they are not reachable via hv_vcpu_get_sys_reg), so a faithful vCPU
    // snapshot must read/write them through these accessors.
    pub fn hv_gic_get_icc_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
    pub fn hv_gic_set_icc_reg(vcpu: u64, reg: u16, value: u64) -> i32;

    // hv_gic_ich_reg_t — per-vCPU GIC virtualization-control (ICH) registers.
    // The List Registers (LR0..LR15, encodings 0xe660..0xe66f) drive what the
    // guest's virtual CPU interface presents at ICC_IAR1; writing a List
    // Register injects an arbitrary INTID — including an LPI (>= 8192) the
    // managed GIC's redistributor cannot itself deliver. VTR/ELRSR report the
    // implemented List-Register count and which ones are empty.
    pub fn hv_gic_get_ich_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
    pub fn hv_gic_set_ich_reg(vcpu: u64, reg: u16, value: u64) -> i32;

    // GIC state save/restore (os_object state handle).
    pub fn hv_gic_state_create() -> *mut c_void;
    pub fn hv_gic_state_get_size(state: *mut c_void, size: *mut usize) -> i32;
    pub fn hv_gic_state_get_data(state: *mut c_void, data: *mut c_void) -> i32;
    pub fn hv_gic_set_state(data: *const c_void, size: usize) -> i32;
}

unsafe extern "C" {
    /// Release an `os_object` (e.g. an `hv_gic_config_t`/`hv_gic_state_t`).
    pub fn os_release(object: *mut c_void);
}

unsafe extern "C" {
    /// Mach monotonic tick count. The HVF vtimer offset is defined relative to
    /// it: `CNTVCT_EL0 = mach_absolute_time() - offset`.
    pub fn mach_absolute_time() -> u64;
}

/// Ratio converting `mach_absolute_time` ticks to nanoseconds
/// (`ns = ticks * numer / denom`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

unsafe extern "C" {
    /// Fill in the timebase ratio used to convert `mach_absolute_time` ticks to
    /// nanoseconds. Returns `KERN_SUCCESS` (0) on success.
    pub fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hv_denied_names_the_entitlement_and_the_fix() {
        // The load-bearing diagnostic: HV_DENIED means the binary lost its
        // hypervisor entitlement (every cargo build strips it). The message must
        // name the entitlement and how to re-sign, or it reads as a VM-slot leak.
        let msg = hv_return_str(HV_DENIED);
        assert!(msg.contains("com.apple.security.hypervisor"), "got: {msg}");
        assert!(msg.contains("codesign") || msg.contains("scripts/build-chm.sh"), "got: {msg}");
    }

    #[test]
    fn known_codes_have_distinct_descriptions() {
        for code in [HV_ERROR, HV_BUSY, HV_NO_RESOURCES, HV_NO_DEVICE, HV_DENIED] {
            assert_ne!(hv_return_str(code), "unknown hv_return_t", "code {code:#010x}");
        }
        assert_eq!(hv_return_str(0x1234_5678), "unknown hv_return_t");
    }
}
