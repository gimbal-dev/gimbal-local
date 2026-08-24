// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! macOS / Apple-Silicon implementation of the `chm` CLI.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, fs, io, thread};

use crate::bundle;
use crate::checkpoint;
use crate::disktail;
use crate::livesnap;
use crate::kernelimage;
use crate::runs;
use crate::vanilla_export;
use crate::create::create_main;
use crate::oci::image::image_main;
use crate::cloud;
use crate::console::{self, RawConsole};
use crate::console_filter::ConsoleFilter;
use crate::audit;
use crate::capability;
use crate::control_plane;
use crate::credproxy;
use crate::firewall;
use crate::guestcp;
use crate::limits;
use crate::serve;
use crate::spec;
use crate::signing;
use crate::startup;
use crate::posture;
use crate::state_cdn;
use crate::sysregs;

use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::hvf::checkpoint::{self as hvf_checkpoint, CheckpointState};
use hypervisor::hvf::devices::{MmioBus, Pl011};
use hypervisor::hvf::gic::GicMsiSink;
use hypervisor::hvf::rehydrate::{self, Snapshot, snapshot_cntfrq};
use hypervisor::hvf::UsgicCpuHandle;
use hypervisor::hvf::VtimerClock;
use hypervisor::hvf::host_counter_hz;
use hypervisor::hvf::UsgicSpiRouter;
use hypervisor::hvf::virtio::GuestMemory;
use hypervisor::hvf::icache_wx;
use hypervisor::hvf::virtio::nat::{EgressPolicy, NatLimits};
use hypervisor::hvf::virtio::net::NetKick;
use hypervisor::hvf::virtio::pci::{MsiSink, MsiSpiInjector, VirtioPciDevice};
use hypervisor::hvf::virtio::{devmgr, its};
use hypervisor::{HypervisorVmError, StandardRegisters, Vcpu, VmExit, VmOps};

/// cloud-hypervisor's arm64 PL011 lives at the base of the mapped-IO window.
pub(crate) const PL011_BASE: u64 = 0x0900_0000;
pub(crate) const PL011_SIZE: u64 = 0x1000;
const PSCI_SUCCESS: i64 = 0;
const PSCI_NOT_SUPPORTED: i64 = -1;
const PSCI_INVALID_PARAMS: i64 = -2;
const PSCI_ALREADY_ON: i64 = -4;
const PSCI_ON_PENDING: i64 = -5;

/// A snapshot loaded off disk and ready to rehydrate.
pub(crate) struct Loaded {
    pub snap: Snapshot,
    pub mem_ranges: PathBuf,
    pub num_vcpus: u32,
    pub total_ram: u64,
    /// The raw `state.json` text, retained so the virtio device model can be
    /// reconstructed from the device-manager state after rehydration.
    pub state_json: String,
}

/// Read and parse a `ch-snapshot` directory (`state.json` +
/// `snapshot/memory-ranges`). Shared by `chm run` and the `chm serve` daemon.
pub(crate) fn load_snapshot(dir: &Path) -> Result<Loaded, String> {
    let state_path = dir.join("state.json");
    let mem_ranges = dir.join("snapshot").join("memory-ranges");

    if !state_path.exists() {
        return Err(format!(
            "{} not found — is `{}` a Cloud Hypervisor snapshot directory?",
            state_path.display(),
            dir.display()
        ));
    }
    if !mem_ranges.exists() {
        return Err(format!("{} not found", mem_ranges.display()));
    }

    let state_json =
        fs::read_to_string(&state_path).map_err(|e| format!("read state.json: {e}"))?;
    let snap =
        Snapshot::from_state_json(&state_json).map_err(|e| format!("parse snapshot: {e}"))?;
    let num_vcpus = snap.num_vcpus();
    let total_ram: u64 = snap.mem_mappings.iter().map(|m| m.size).sum();

    Ok(Loaded {
        snap,
        mem_ranges,
        num_vcpus,
        total_ram,
        state_json,
    })
}

/// Build the device model: a bus carrying a real PL011 at the guest's serial
/// base. Returns the UART (to drain output) alongside the concrete bus, so the
/// caller can add virtio devices to it after rehydration maps guest RAM.
pub(crate) fn build_vm_ops(state_json: &str) -> (Arc<Pl011>, Arc<MmioBus>) {
    let uart = Arc::new(Pl011::new());
    // Seed the UART's line/interrupt state from the snapshot so the resumed
    // guest's interrupt-driven tty receives host keystrokes (RXIM is programmed
    // pre-snapshot and never re-issued after resume).
    if let Some(s) = devmgr::parse_serial_state(state_json) {
        uart.restore(s.imsc, s.cr, s.lcr_h, s.ibrd, s.fbrd, s.ifls);
    }
    let bus = Arc::new(MmioBus::new());
    bus.add(PL011_BASE, PL011_SIZE, uart.clone());
    (uart, bus)
}

#[derive(Default)]
pub(crate) struct CpuPowerState {
    pub(crate) online: bool,
    pub(crate) cpu_on: Option<(u64, u64)>,
}

pub(crate) type CpuPowerSlot = Arc<(Mutex<CpuPowerState>, Condvar)>;
type VmOpsResult<T> = Result<T, HypervisorVmError>;

#[derive(Default)]
pub(crate) struct PsciCoordinator {
    slots: Vec<CpuPowerSlot>,
}

impl PsciCoordinator {
    /// Power state for a guest that was never captured: vCPU 0 is running
    /// because the boot protocol started it there, and every secondary is off
    /// until the kernel asks for it by `CPU_ON`.
    ///
    /// The mirror of [`from_snapshot`], which reads each core's `mp_state`
    /// out of the capture instead. A cold guest has no such record, and
    /// starting a secondary before the kernel asks would run it from HVF's
    /// reset state with no stack and no page tables.
    ///
    /// [`from_snapshot`]: Self::from_snapshot
    pub(crate) fn cold(vcpus: usize) -> Arc<Self> {
        let slots = (0..vcpus)
            .map(|id| {
                Arc::new((
                    Mutex::new(CpuPowerState {
                        online: id == 0,
                        cpu_on: None,
                    }),
                    Condvar::new(),
                ))
            })
            .collect();
        Arc::new(Self { slots })
    }

    pub(crate) fn slot(&self, id: usize) -> CpuPowerSlot {
        self.slots[id].clone()
    }

    pub(crate) fn wake_all(&self) {
        for slot in &self.slots {
            slot.1.notify_all();
        }
    }

    fn mpidr_to_vcpu_id(mpidr: u64) -> usize {
        let aff0 = mpidr & 0xff;
        let aff1 = (mpidr >> 8) & 0xff;
        let aff2 = (mpidr >> 16) & 0xff;
        let aff3 = (mpidr >> 32) & 0xff;
        (aff0 | (aff1 << 8) | (aff2 << 16) | (aff3 << 24)) as usize
    }

    pub(crate) fn cpu_on(&self, target_mpidr: u64, entry: u64, context: u64) -> i64 {
        let target = Self::mpidr_to_vcpu_id(target_mpidr);
        let Some(slot) = self.slots.get(target) else {
            return PSCI_INVALID_PARAMS;
        };
        let (lock, cv) = &**slot;
        let mut st = lock.lock().unwrap();
        if st.online {
            return PSCI_ALREADY_ON;
        }
        // Defence in depth. `online` and `cpu_on` are set together below, so
        // a pending request always reads as already-on and this arm should be
        // unreachable; it is here so a future change that decouples the two
        // fails closed with the architectural error rather than silently
        // overwriting an entry point the target may already be running from.
        if st.cpu_on.is_some() {
            return PSCI_ON_PENDING;
        }
        st.online = true;
        st.cpu_on = Some((entry, context));
        cv.notify_all();
        PSCI_SUCCESS
    }
}

struct ChmVmOps {
    bus: Arc<MmioBus>,
    psci: Mutex<Option<Arc<PsciCoordinator>>>,
}

impl ChmVmOps {
    fn new(bus: Arc<MmioBus>) -> Self {
        Self {
            bus,
            psci: Mutex::new(None),
        }
    }

}

impl VmOps for ChmVmOps {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> VmOpsResult<usize> {
        self.bus.guest_mem_write(gpa, buf)
    }

    fn guest_mem_read(&self, gpa: u64, buf: &mut [u8]) -> VmOpsResult<usize> {
        self.bus.guest_mem_read(gpa, buf)
    }

    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> VmOpsResult<()> {
        self.bus.mmio_read(gpa, data)
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        self.bus.mmio_write(gpa, data)
    }

    fn psci_vcpu_on(&self, target_mpidr: u64, entry: u64, context: u64) -> VmOpsResult<i64> {
        let Some(psci) = self.psci.lock().unwrap().clone() else {
            return Ok(PSCI_NOT_SUPPORTED);
        };
        Ok(psci.cpu_on(target_mpidr, entry, context))
    }
}

/// The counter frequency an Apple-silicon HVF guest observes, in Hz.
///
/// `hv_vcpu_get_sys_reg(CNTFRQ_EL0)` returns `HV_BAD_ARGUMENT`, so we derive it
/// from the host timebase instead: `mach_absolute_time` counts the same system
/// counter the guest's `CNTVCT_EL0` does, and `mach_timebase_info` gives the
/// ticks->nanoseconds ratio, so the frequency is `1e9 * denom / numer`. On
/// current Apple silicon that is `1e9 * 3 / 125` = 24 MHz, which matches the
/// `arch_timer: cp15 timer(s) running at 24.00MHz` a guest logs at boot.
///
/// Deriving it beats hardcoding 24 MHz: if Apple ever ships a part with a
/// different system counter, this follows it rather than silently lying.
fn hvf_guest_cntfrq() -> Option<u64> {
    // Declared here rather than taken from `libc`, whose `mach_timebase_info`
    // fields are deprecated in favour of a separate `mach2` crate we do not
    // otherwise need. The ABI is two u32s and has been stable for decades.
    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    let mut tb = MachTimebaseInfo { numer: 0, denom: 0 };
    // SAFETY: `mach_timebase_info` writes exactly the two u32 fields of the
    // struct it is handed; `tb` is a live, correctly laid out local.
    let rc = unsafe { mach_timebase_info(&raw mut tb) };
    if rc != 0 || tb.numer == 0 {
        return None;
    }
    Some(1_000_000_000u64 * u64::from(tb.denom) / u64::from(tb.numer))
}

/// Load-time guest-clock-rate guard (#104).
///
/// A Linux guest reads `CNTFRQ_EL0` **once at boot**, caches it as
/// `arch_timer_rate`, and never re-reads it — not on resume, not ever. Apple
/// presents HVF guests a fixed counter frequency and offers no way to change it:
/// `hv_vcpu_set_vtimer_offset` sets an *offset*, never a *rate*. So a snapshot
/// captured on a host with a different frequency resumes into a guest whose
/// every sleep, timeout and scheduler tick is scaled by the ratio.
///
/// Measured on real hardware (2026-07-28): an AWS Graviton2 capture
/// (121_875_000 Hz) resumed on Apple silicon (24_000_000 Hz) runs **5.08x
/// slow** — a `sleep 5` in the guest took 25.41s of wall clock.
///
/// The danger is not corruption; the guest stays internally consistent. The
/// danger is that it presents as *"this VM feels sluggish"* rather than *"the
/// clock is wrong"*, which is a day of profiling the wrong thing. This guard
/// exists to make that diagnosis immediate.
///
/// **A capture that records its frequency is now corrected automatically**, so
/// on those this guard only reports what was done. It still matters for a
/// capture that predates upstream `69637dde6` and therefore cannot state its own
/// frequency: nothing can be inferred, and the dilation has to be named.
/// Whether the operator has explicitly switched rate correction off.
fn cntfrq_correction_disabled() -> bool {
    env::var("CHM_GUEST_CNTFRQ")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        == Some(0)
}

pub(crate) fn cntfrq_guard(state_json: &str) -> Result<(), String> {
    let Some(host) = hvf_guest_cntfrq() else {
        return Ok(());
    };
    let Some(captured) = snapshot_cntfrq(state_json) else {
        // Pre-69637dde6 capture: it cannot tell us, so we cannot check. Say so
        // once rather than implying the clock was verified.
        eprintln!(
            "chm: note: this snapshot records no counter frequency (captured by a \
             cloud-hypervisor build predating upstream 69637dde6), so the guest \
             clock rate cannot be verified. If it was captured on a host whose \
             CNTFRQ_EL0 differs from this Mac's {host} Hz, the guest's clock will \
             run slow or fast by that ratio. See docs/graviton-acid-test-results.md."
        );
        return Ok(());
    };
    if captured == host {
        return Ok(());
    }

    let ratio = captured as f64 / host as f64;
    let (faster_or_slower, factor) = if captured > host {
        ("slow", ratio)
    } else {
        ("fast", 1.0 / ratio)
    };

    // The snapshot stated its own frequency, so the counter is being corrected;
    // say what is happening rather than warning about a problem already solved.
    if !cntfrq_correction_disabled() {
        eprintln!(
            "chm: note: this snapshot was captured at {captured} Hz and an Apple \
             Hypervisor.framework guest sees {host} Hz, so the guest counter is \
             rate-corrected to keep its clock right (it would otherwise run \
             {factor:.3}x {faster_or_slower}). This costs a measured 2.8% of wall \
             time in stop-the-world barriers; set CHM_GUEST_CNTFRQ=0 to turn it \
             off and accept the dilation. See docs/hvf-compatible-snapshots.md."
        );
        return Ok(());
    }

    let detail = format!(
        "guest clock rate mismatch: this snapshot was captured on a host whose \
         counter runs at {captured} Hz, but an Apple Hypervisor.framework guest \
         sees {host} Hz, and rate correction is disabled by CHM_GUEST_CNTFRQ=0.\n\
         \n\
         The guest cached {captured} Hz as its arch_timer_rate when it first \
         booted and never re-reads it, so every sleep, timeout, scheduler tick \
         and wall-clock reading inside it will run {factor:.3}x {faster_or_slower}. \
         The guest is not corrupted — it stays internally consistent — but it \
         will look like a slow machine rather than a wrong clock, which is the \
         easiest way to lose a day to this.\n\
         \n\
         Unset CHM_GUEST_CNTFRQ to restore the correction. See \
         docs/hvf-compatible-snapshots.md."
    );

    if env::var_os("CHM_STRICT_CNTFRQ").is_some() {
        return Err(format!(
            "{detail}\n\
             \n\
             Refusing to start because CHM_STRICT_CNTFRQ is set (this matches the \
             KVM path, which rejects a mismatch rather than corrupt the guest \
             clock). Unset it to run anyway with the warning above."
        ));
    }
    eprintln!("chm: warning: {detail}");
    Ok(())
}

/// Load-time AArch32-at-EL0 guard (V1.4).
///
/// `ID_AA64PFR0_EL1.EL0` (bits 3:0) says which execution states EL0 supports:
/// `1` = AArch64 only, `2` = AArch64 **and AArch32**. Unlike most identity
/// registers, HVF *accepts* a write to `ID_AA64PFR0_EL1`, so a Graviton2
/// capture's value — `0x1100000011111112`, EL0 field `2` — is restored
/// **faithfully**. Apple silicon implements no AArch32 at any exception level.
///
/// So this is the inverse of the usual bug: the guest is not harmed by a
/// register we failed to reproduce, it is harmed by one we reproduced
/// perfectly. It booted on a host that really did support 32-bit userspace,
/// cached that in `ARM64_HAS_32BIT_EL0` at boot, and cannot be told otherwise
/// afterwards — rewriting the register post-resume would change nothing,
/// because the capability was latched during the capture host's boot.
///
/// Measured on real hardware (2026-07-29, Apple M3, Ubuntu 24.04 guest with
/// `CONFIG_COMPAT=y`): executing a 96-byte static AArch32 ELF **permanently
/// wedges the vCPU**. Not the task — the whole guest. Backgrounding it with `&`
/// makes no difference: bash prints the job number, emits one more prompt, and
/// the guest never executes another instruction. A control binary (a malformed
/// ELF the kernel rejects with `Exec format error`) leaves the shell healthy,
/// so the wedge is specific to entering AArch32 state.
///
/// The mechanism is an illegal exception return: the kernel writes
/// `SPSR_EL1.M[4] = 1` to drop to EL0 in AArch32, and on a core with no AArch32
/// that return cannot be architecturally completed.
///
/// Nothing can be fixed at rehydrate time, so this warns rather than refuses:
/// the guest is entirely healthy for the 64-bit workloads that are the whole
/// point, and refusing would block every Graviton capture over a hazard most
/// users will never touch. `CHM_STRICT_AARCH32=1` refuses instead, for anyone
/// running untrusted or unknown workloads.
pub(crate) fn aarch32_guard(snap: &Snapshot) -> Result<(), String> {
    /// `ID_AA64PFR0_EL1` is `S3_0_C0_C4_0`, packed as `(op0<<14)|(CRm<<3)`.
    const ID_AA64PFR0_EL1: u16 = 0xc020;

    let supports_aarch32 = snap.vcpus.iter().any(|v| {
        v.sysregs
            .iter()
            .any(|&(reg, val)| reg == ID_AA64PFR0_EL1 && (val & 0xf) == 2)
    });
    if !supports_aarch32 {
        return Ok(());
    }

    let detail = "this snapshot's guest believes it can run 32-bit binaries, and this Mac \
         cannot.\n\
         \n\
         The capture host advertised AArch32 at EL0 (ID_AA64PFR0_EL1.EL0 = 2) and the \
         guest kernel latched that at boot. Apple silicon implements no AArch32 at any \
         exception level. Measured on hardware: executing a 32-bit binary permanently \
         wedges the vCPU — the entire guest stops, not just that process, and it cannot \
         be recovered.\n\
         \n\
         64-bit workloads are completely unaffected. This only bites if something in the \
         guest execs a 32-bit binary, which a stock arm64 Ubuntu image never does. Set \
         CHM_STRICT_AARCH32=1 to refuse to start instead of warning. See \
         docs/cpu-feature-deltas.md.";

    if env::var_os("CHM_STRICT_AARCH32").is_some() {
        return Err(format!(
            "{detail}\n\nRefusing to start because CHM_STRICT_AARCH32 is set."
        ));
    }
    eprintln!("chm: warning: {detail}");
    Ok(())
}

/// Warn when the capture's kernel elided instruction-cache maintenance that
/// this Mac requires — which silently breaks every JIT in the guest.
///
/// `CTR_EL0.DIC = 1` means "instruction cache invalidation to the point of
/// unification is not required for data-to-instruction coherence". Linux reads
/// it once at boot and, when it is set, **alternative-patches `ic ivau` out of
/// `caches_clean_inval_pou()`** — the routine `__sync_icache_dcache()` calls
/// whenever userspace makes a page executable. AWS Graviton2 (Neoverse-N1)
/// reports `DIC = 1`; Apple silicon reports `DIC = 0`. So a capture taken on
/// Graviton rehydrates a kernel whose cache maintenance has been NOP'd out onto
/// hardware that genuinely needs it.
///
/// Measured in a rehydrated guest, executing freshly written code 1,000 times
/// (`mmap(RW)` → write → `mprotect(RX)` → call — exactly what a JIT does):
/// **955 of 1,000 executions fetched stale instructions**. Adding an explicit
/// `ic ivau` took it to 0/1,000.
///
/// That last number was read for a long time as "only the kernel's elided copy
/// is wrong". It was not — see #290. The explicit `ic ivau` in that test ran at
/// offset 0 of its page, the one offset a 4096-byte stride covers, and the
/// guest was reading `CTR_EL0.IminLine = 4096 B` against a real 64 B granule.
/// Every `ic ivau` loop that honours `IminLine` — libgcc's `__clear_cache`,
/// V8's and JSC's own — invalidated one line in every 4 KiB and left the other
/// 63 stale.
///
/// **That half is fixed**, in [`hypervisor::hvf::ctr_trap_fixup`]: the stride
/// came from a kernel trap handler, not from the hardware, and restore now
/// lets EL0 read this Mac's own `CTR_EL0`. Measured after the fix, all eight
/// offsets return 0/200 and `npm --version` is 20/20.
///
/// What this warning still covers is the kernel's own elided copy (#287),
/// which lives in kernel text and no register can reach. Measured *after* the
/// stride fix, `mmap(RW)` → write → `mprotect(RX)` → call is stale 998 times
/// in 1,000.
///
/// How bad this is in practice was understated for a long time. The figure used
/// to be "roughly one run in seven"; measured on a rehydrated Graviton guest
/// running Node 22.11.0, `npm --version` died with `Illegal instruction (core
/// dumped)` **10 times out of 10**. Under `NODE_OPTIONS=--jitless` the same
/// command succeeded **5 times out of 5**. So for the workload people actually
/// bring — Node tooling — the untreated failure rate is total, and one
/// environment variable is the difference between unusable and working.
///
/// It is not, however, the difference for every *program* Node tooling installs.
/// `NODE_OPTIONS` reaches node; a package that ships a compiled binary and execs
/// it keeps its own JIT and its own exposure. The GitHub Copilot CLI is exactly
/// that shape, and with `--jitless` set its platform binary still died 5 runs out
/// of 5 (#261) — while reporting the crash as a missing platform package, which
/// sends the reader to reinstall something that is already installed. The
/// warning says so, because a mitigation quoted without its limit is the more
/// expensive kind of wrong.
///
/// And it is not confined to JITs at all. `__sync_icache_dcache()` — which
/// `caches_clean_inval_pou()` backs — runs whenever a page becomes executable
/// for userspace, so **every `execve` and every shared-library mapping** takes
/// the same elided path a JIT does. Under page-cache pressure, program text
/// routinely lands on a page something else wrote moments ago, and the process
/// executes whatever the I-cache still holds. Measured on a rehydrated capture
/// under four `dd`/`sync`/`rm` loops plus two spinners: **35 crashes** spread
/// across SIGSEGV (13), stack-smashing aborts (10), SIGABRT (8), SIGBUS (3) and
/// SIGILL (1), in `rm`, `dd` and `sync`. A cold-booted guest under the same
/// load — at roughly *twice* the load average — crashed **zero** times. So the
/// warning no longer claims non-JIT workloads are safe: they are not, and no
/// in-guest environment variable reaches this case.
///
/// The kernel side cannot be fixed at rehydrate time: the NOPs are baked into
/// the kernel text inside the snapshot, and we have no way to write into the
/// guest filesystem from here either, so the mitigation has to be something the
/// user applies. This warns rather than refuses, matching [`aarch32_guard`], and
/// the warning carries the workaround so it is read at the moment the problem
/// is. A cold-booted guest is unaffected: its kernel reads this Mac's real
/// `CTR_EL0` and patches correctly. `CHM_STRICT_ICACHE=1` refuses.
///
/// The comparison is against the capture alone. Every Apple part measured
/// reports `DIC = 0` (`hvf_host_cache_identity_registers` prints the live
/// value); a Mac that reported 1 would make this a false positive.
/// The text of the i-cache warning, split out so the workaround it offers can
/// be asserted. The measured numbers in it are the point of the message, so a
/// test pins them rather than trusting prose to stay true.
pub(crate) fn icache_detail() -> &'static str {
    "this snapshot's guest kernel skips the instruction-cache maintenance this \
         Mac requires, so JIT compilers in the guest will intermittently execute stale \
         code.\n\
         \n\
         The capture host reported CTR_EL0.DIC = 1, and Linux latched that at boot by \
         patching `ic ivau` out of `caches_clean_inval_pou()`. Apple silicon reports \
         DIC = 0, so that elision is unsound here. Measured in a rehydrated guest, \
         executing freshly written code (mmap RW, write, mprotect RX, call — what every \
         JIT does): 955 of 1000 executions fetched stale instructions.\n\
         \n\
         A second defect used to compound this and is now corrected at restore. The \
         capture also arrives with SCTLR_EL1.UCT clear, so EL0 reads of CTR_EL0 \
         trapped to the kernel's erratum-1542419 handler, which answers with \
         IminLine forced to 4096 bytes -- 64x the granule this Mac invalidates. \
         Every JIT strided its own `ic ivau` loops by that and touched one line in \
         every 4 KiB. Restore now sets UCT, so EL0 reads this Mac's real CTR_EL0 \
         and userspace maintenance is correct: measured at eight offsets within a \
         page, 200 rounds each, 0/200 stale everywhere, and `npm --version` \
         succeeded 20 times out of 20 where it had failed 15 of 20 before. Setting \
         CHM_KEEP_CTR_TRAP=1 restores the captured value and the failure with it.\n\
         \n\
         What remains is the kernel's own elided maintenance (#287), which no \
         register can reach because it is patched into the kernel text inside the \
         snapshot. \
         Measured after the UCT fix, mmap RW -> write -> mprotect RX -> call was \
         stale 998 times in 1000. Node and npm do not take that path and now work; \
         a runtime that relies on the kernel to synchronise the caches for it will \
         still fetch stale code.\n\
         \n\
         If a JIT workload does still die with `Illegal instruction (core dumped)`, \
         turn the JIT off:\n\
         \n\
             export NODE_OPTIONS=--jitless\n\
         \n\
         `sudo` does not carry NODE_OPTIONS through -- it is not in env_keep -- so the \
         first command most people run next fails, and neither failure names the \
         variable: without sudo, `npm i -g` dies EACCES; with it, SIGILL. Install with \
         the variable passed explicitly:\n\
         \n\
             sudo env NODE_OPTIONS=--jitless npm i -g <package>\n\
         \n\
         The same command is a reactive remedy, not a default. Do not put the \
         variable in /etc/profile.d/ pre-emptively -- since the stride is \
         corrected at restore, setting it everywhere only disables the JIT of \
         every node process that would have been fine.\n\
         \n\
         That variable reaches node and nothing else, so it does not cover a tool \
         that runs its own compiled binary. The GitHub Copilot CLI installs a \
         174 MiB native platform package and execs it; measured with \
         NODE_OPTIONS=--jitless set, that binary died 5 runs out of 5 (4 SIGILL, \
         1 SIGBUS) and the CLI blamed a missing platform package that was in fact \
         installed. That measurement predates the stride correction above, and it \
         HAS been repeated since: with the correction in place the same native \
         binary ran 20 of 20, and an acceptance run installed the Copilot CLI and \
         had it write and execute a program with no NODE_OPTIONS set at all \
         (#286). Treat the native-binary failure as fixed rather than as the last \
         known state.\n\
         \n\
         This warning covers freshly written code only. It used to also claim the \
         userspace crashes a rehydrated guest suffers under ordinary dd/sync/rm load, \
         and that attribution was measured and found false: performing the guest's \
         instruction-cache maintenance host-side (1,277,598 invalidations over 266 MiB, \
         with the mechanism separately proven guest-visible) changed the crash count by \
         nothing, and removing the block device from the load entirely did not help \
         either. Those crashes are the ASID-width delta, warned about separately.\n\
         \n\
         Set CHM_STRICT_ICACHE=1 to refuse to start instead of warning. See \
         docs/cpu-feature-deltas.md."
}

/// Did this capture's kernel boot on a host that let it skip `ic ivau`?
///
/// `CTR_EL0.DIC = 1` promises the instruction cache snoops the data side, so
/// Linux alternative-patches the `ic ivau` out of `caches_clean_inval_pou()` at
/// boot -- and those NOPs travel in the snapshot's kernel text. Apple silicon
/// reports `DIC = 0`, so a guest rehydrated here performs no instruction-cache
/// maintenance on a machine that requires it.
///
/// One predicate, two consumers: the warning the operator reads
/// ([`icache_dic_guard`]) and the decision to take the maintenance over
/// host-side. Two copies of this test would eventually disagree, and the
/// disagreement would be a guest that is warned about but not repaired, or
/// repaired without being told.
pub(crate) fn snapshot_elides_ic_ivau(snap: &Snapshot) -> bool {
    /// `CTR_EL0` is `S3_3_C0_C0_1`, packed as
    /// `(op0<<14)|(op1<<11)|(CRn<<7)|(CRm<<3)|op2`.
    const CTR_EL0: u16 = 0xd801;
    /// `CTR_EL0.DIC`.
    const DIC: u64 = 1 << 29;

    snap.vcpus.iter().any(|v| {
        v.sysregs
            .iter()
            .any(|&(reg, val)| reg == CTR_EL0 && (val & DIC) != 0)
    })
}

/// The ASID-width hazard, in the words an operator needs.
///
/// Kept separate from [`asid_width_guard`] so the test that this text is what
/// gets printed cannot pass against a second copy of the words.
pub(crate) fn asid_detail() -> &'static str {
    "this snapshot's guest uses more TLB context ids than this Mac can tell \
         apart, so unrelated processes in the guest will silently corrupt each \
         other's memory.\n\
         \n\
         The capture host advertised 16-bit ASIDs (ID_AA64MMFR0_EL1.ASIDBits = 2) \
         and Linux latched that at boot -- the guest's own log says `ASID \
         allocator initialised with 32768 entries`. Apple silicon implements \
         8-bit ASIDs (measured here: ID_AA64MMFR0_EL1 = 0xf100002), so the \
         hardware compares only the low 8 bits of every context id. Once the \
         guest has more than 256 live address spaces, processes whose ASIDs \
         differ only above bit 7 share TLB entries and read and write each \
         other's pages.\n\
         \n\
         Kernel mappings are global and unaffected, which is why the guest stays \
         up while its userspace dies. Measured on a rehydrated Graviton capture \
         under four dd/sync/rm loops plus two spinners: 30 processes killed in 16 \
         minutes -- SIGSEGV, SIGBUS, glibc `stack smashing detected` and \
         `malloc(): unaligned tcache chunk detected` -- in `dd`, `rm` and `sync`. \
         The identical load cold-booted on this host at more than twice the load \
         average killed zero.\n\
         \n\
         Nothing inside the guest can undo it: the ASID width was latched before \
         the snapshot was taken. Keeping the process count low reduces the \
         collision rate but does not remove it. A cold-booted guest reads this \
         Mac's own 8-bit width and is correct by construction.\n\
         \n\
         Set CHM_STRICT_ASID=1 to refuse to start instead of warning. See \
         docs/cpu-feature-deltas.md."
}

/// Does this capture's guest believe it has more ASID bits than this host
/// implements?
///
/// `ID_AA64MMFR0_EL1.ASIDBits` is one of the registers HVF restores faithfully,
/// which is normally the point of the project and here is the whole problem: the
/// guest latched the capture host's width at boot and cannot be told otherwise.
/// Encoding is `0` = 8 bits, `2` = 16 bits.
pub(crate) fn snapshot_asid_bits(snap: &Snapshot) -> Option<u32> {
    /// `ID_AA64MMFR0_EL1` is `S3_0_C0_C7_0`, packed as
    /// `(op0<<14)|(op1<<11)|(CRn<<7)|(CRm<<3)|op2`.
    const ID_AA64MMFR0_EL1: u16 = 0xc038;

    snap.vcpus.iter().find_map(|v| {
        v.sysregs.iter().find_map(|&(reg, val)| {
            (reg == ID_AA64MMFR0_EL1).then_some(if (val >> 4) & 0xf == 0 { 8 } else { 16 })
        })
    })
}

/// The warning this capture deserves, or `None` if its ASID width fits.
///
/// Split out from [`asid_width_guard`] so the decision is observable: the guard
/// itself only warns, so a test that asserts it returns `Ok` passes just as
/// happily when the predicate is broken.
pub(crate) fn asid_warning_for(snap: &Snapshot) -> Option<&'static str> {
    /// Every Apple M-series part implements 8-bit ASIDs; measured on hardware by
    /// `hvf_host_mmu_feature_register`, which fails if that ever changes.
    const HOST_ASID_BITS: u32 = 8;
    (snapshot_asid_bits(snap)? > HOST_ASID_BITS).then(asid_detail)
}

/// Warn when the capture's ASID width exceeds this host's 8 bits.
///
/// Apple silicon's width is not a runtime question -- it is 8 on every M-series
/// part, and the probe that established it lives in
/// `hvf_host_mmu_feature_register` so a future part that changes it fails a test
/// rather than passing this guard silently.
pub(crate) fn asid_width_guard(snap: &Snapshot) -> Result<(), String> {
    let Some(detail) = asid_warning_for(snap) else {
        return Ok(());
    };

    if env::var_os("CHM_STRICT_ASID").is_some() {
        return Err(format!(
            "{detail}\n\nRefusing to start because CHM_STRICT_ASID is set."
        ));
    }
    eprintln!("chm: warning: {detail}");
    Ok(())
}

pub(crate) fn icache_dic_guard(snap: &Snapshot) -> Result<(), String> {
    if !snapshot_elides_ic_ivau(snap) {
        return Ok(());
    }

    let detail = icache_detail();

    if env::var_os("CHM_STRICT_ICACHE").is_some() {
        return Err(format!(
            "{detail}\n\nRefusing to start because CHM_STRICT_ICACHE is set."
        ));
    }
    eprintln!("chm: warning: {detail}");
    Ok(())
}

/// Take instruction-cache maintenance over from a guest kernel that cannot do
/// it, once guest RAM holds its restored contents.
///
/// Deliberately *not* done for every guest. A cold-booted guest read this
/// host's own `CTR_EL0`, saw `DIC = 0`, and kept its `ic ivau`: it is correct
/// already, and arming would buy it nothing but stage-2 faults. Only a capture
/// that elided the maintenance needs us to perform it, which is why this shares
/// [`snapshot_elides_ic_ivau`] with the warning rather than testing again.
///
/// `CHM_ICACHE_WX=0` opts out, for measuring what the maintenance is worth: it
/// restores the behaviour that produced the 35 crashes in #274, so it is a
/// comparison, not a tuning knob.
///
/// A failure here is reported and not fatal. The guest still runs -- exactly as
/// it did before this existed -- and refusing to start a rehydrated snapshot
/// because an optimisation could not be armed would be a worse outcome than the
/// hazard it guards.
fn arm_icache_maintenance(snap: &Snapshot, guest_mem: &GuestMemory) {
    if !snapshot_elides_ic_ivau(snap) {
        return;
    }
    if env::var("CHM_ICACHE_WX").as_deref() == Ok("0") {
        eprintln!(
            "chm: host-side instruction-cache maintenance disabled by CHM_ICACHE_WX=0;              this guest can execute stale instructions (see docs/cpu-feature-deltas.md)"
        );
        return;
    }
    let regions = guest_mem.icache_regions();
    let mapped: usize = regions.iter().map(|&(_, _, n)| n).sum();
    match icache_wx::arm(&regions) {
        Ok(()) => {
            startup::stamp("icache maintenance armed");
            eprintln!(
                "chm: performing this guest's instruction-cache maintenance for it \
                 ({} region(s), {} MiB)",
                regions.len(),
                mapped / (1024 * 1024)
            );
            spawn_icache_reporter();
        }
        Err(e) => eprintln!(
            "chm: warning: could not take over instruction-cache maintenance ({e});              continuing without it"
        ),
    }
}

/// Report what the maintenance is actually doing, every 30 s, under
/// `CHM_TRACE_ICACHE=1`.
///
/// Without this the mechanism is unfalsifiable from a run log: a hook that
/// never fires and a hook that fires and does not help look identical. The
/// counters are the difference between "the fix did not work" and "the fix did
/// not run".
fn spawn_icache_reporter() {
    if env::var("CHM_TRACE_ICACHE").as_deref() != Ok("1") {
        return;
    }
    thread::spawn(|| {
        loop {
            thread::sleep(Duration::from_secs(30));
            let (exec, write, relaxed, dma, bytes) = icache_wx::stats();
            eprintln!(
                "chm: [icache] exec_faults={exec} write_faults={write} \
                 relaxed_pages={relaxed} dma_invalidations={dma} dma_MiB={}",
                bytes / (1024 * 1024)
            );
        }
    });
}

/// Create the per-run overlay directory as a private `0700` dir that `chm`
/// owns, refusing to reuse a symlink shipped in an (untrusted) snapshot bundle.
///
/// Guest disk writes land in copy-on-write overlays under this directory; if a
/// malicious bundle shipped `.chm-overlays` as a symlink to a host location,
/// those overlays (and their bitmaps) would be written there. Reject a
/// pre-existing symlink and create the directory `0700`, so overlays stay
/// confined to a directory the runner created (M30.1, invariant I3).
fn ensure_private_overlay_dir(overlay_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::symlink_metadata(overlay_dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(format!(
                "refusing overlay dir {}: it is a symlink (possible tampered bundle)",
                overlay_dir.display()
            ));
        }
        Ok(_) => return Ok(()),
        Err(_) => {}
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(overlay_dir)
        .map_err(|e| format!("create overlay dir {}: {e}", overlay_dir.display()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn wire_virtio(
    bus: &MmioBus,
    guest_mem: &Arc<GuestMemory>,
    state_json: &str,
    overlay_dir: &Path,
    gic: Option<&Arc<Mutex<dyn Vgic>>>,
    reattach_overlay: bool,
    cli_egress: Option<&Path>,
    net_limits: &NatLimits,
    allow_local_egress: bool,
    lpi_sink_override: Option<Arc<dyn its::LpiSink>>,
    cli_proxy_rules: Option<&Path>,
) -> Result<WiredVirtio, String> {
    let descs =
        devmgr::parse_devices(state_json).map_err(|e| format!("parse virtio devices: {e}"))?;
    if descs.is_empty() {
        return Ok(WiredVirtio::default());
    }
    ensure_private_overlay_dir(overlay_dir)?;

    let mut summary = Vec::with_capacity(descs.len());
    // Net devices carry a userspace NAT that must be polled off the vCPU thread
    // (host sockets deliver asynchronously); collected here so the caller can
    // spawn the net service thread.
    let mut net_devices: Vec<Arc<VirtioPciDevice>> = Vec::new();
    // Devices whose in-flight queues should be drained once on resume (only the
    // deliverable message-SPI path; the logging ITS fallback has nothing to
    // deliver). Drained after the whole tree is wired and the GIC is live.
    let mut drainable: Vec<Arc<VirtioPciDevice>> = Vec::new();
    // An enabled gic-v3-its means completions are LPI-routed. On the managed GIC
    // those resolve through the ITS but cannot be delivered, so they fall back to
    // the logging sink; on the userspace GIC the caller passes a deliverable LPI
    // sink (`lpi_sink_override`) that injects the resolved LPI into the software
    // GIC. Anything else is message-SPI routed and delivered live through the GIC.
    let its_engine = its::Its::from_snapshot_state(state_json)
        .ok()
        .filter(|its| its.enabled())
        .map(Arc::new);
    let lpi_deliverable = lpi_sink_override.is_some();
    let lpi_sink: Arc<dyn its::LpiSink> =
        lpi_sink_override.unwrap_or_else(|| Arc::new(its::LoggingLpiSink::default()));
    let msi_sink: Option<Arc<dyn MsiSink>> =
        gic.map(|g| Arc::new(GicMsiSink::new(g.clone())) as Arc<dyn MsiSink>);

    // The egress policy governing this sandbox's outbound network, if any. It is
    // resolved (in priority order) from the `--egress-policy` flag, the
    // `CHM_EGRESS_POLICY` env binding the runner sets for a cloud assignment
    // (M28.3), or a per-workspace `egress-policy.json` a local user authored with
    // `chm firewall` — the same seam, whether the run is cloud- or self-served.
    // It is enforced by the net device's userspace NAT at DNS resolve + connect.
    //
    // The resolved policy applies to EVERY virtio-net NIC, not just the first: a
    // snapshot with a second NIC must not get a free unrestricted path around the
    // allow-list. If a policy source was specified but could not be honored, the
    // session was meant to be governed, so we fail closed with a deny-all policy
    // rather than booting wide open (M30.9).
    let workspace = overlay_dir.parent().unwrap_or(overlay_dir);
    // Resolved here, ahead of the device loop, because the injection rules feed
    // the egress allow-list (V8.7) that is baked into each NIC below, and the
    // proxy itself cannot start until those NICs exist. One read, two uses.
    let proxy_rules = credproxy::cli::resolve_rules(Some(workspace), cli_proxy_rules)
        .map_err(|e| format!("credential proxy: {e}"))?;

    let enforced_policy: Option<EgressPolicy> = match resolve_egress_policy(overlay_dir, cli_egress)
    {
        EgressResolution::Unrestricted => None,
        EgressResolution::Policy(p, authority) => {
            let mut policy = *p;
            // Naming a host in an injection rule is the intent to reach it. Only
            // when the same authority wrote both halves, and never silently.
            if let Some(resolved) = proxy_rules.as_ref() {
                let implied =
                    credproxy::cli::implied_egress_for(resolved, authority, policy.label());
                policy.allow_implied(&implied, "implied by the credential rules");
            }
            Some(policy)
        }
        EgressResolution::FailClosed(reason) => {
            eprintln!(
                "chm: egress was governed but the policy could not be resolved \
                 ({reason}); failing closed — denying all egress"
            );
            // Deliberately not widened by the injection rules: this branch exists
            // precisely because the session was meant to be governed and we
            // cannot tell by what, so nothing may imply an exception to it.
            Some(EgressPolicy::from_profile("deny", &[], &[], "fail-closed"))
        }
    };

    // Report the posture once, and only when this run actually has a NIC:
    // telling someone about egress on a sandbox with no network is noise that
    // teaches them to skip the line that matters.
    if descs
        .iter()
        .any(|d| matches!(d.backend, devmgr::BackendKind::Net))
    {
        eprintln!("chm: {}", egress_posture_line(enforced_policy.as_ref()));
    }

    for desc in &descs {
        let kind = match &desc.backend {
            devmgr::BackendKind::Block { nsectors, .. } => {
                format!("virtio-blk {} ({} sectors)", desc.name, nsectors)
            }
            devmgr::BackendKind::Net => format!("virtio-net {}", desc.name),
            devmgr::BackendKind::Rng => format!("virtio-rng {}", desc.name),
            devmgr::BackendKind::Unsupported { virtio_type } => {
                format!("virtio type {virtio_type} {}", desc.name)
            }
        };
        let is_net = matches!(desc.backend, devmgr::BackendKind::Net);
        // Clone (not take) so a second NIC is governed by the same policy.
        let policy = if is_net { enforced_policy.clone() } else { None };
        let dev_limits = if is_net { net_limits.clone() } else { NatLimits::default() };
        let (base, size, dev) = devmgr::build_device(
            desc,
            guest_mem.clone(),
            overlay_dir,
            reattach_overlay,
            policy,
            dev_limits,
            allow_local_egress,
        )
        .map_err(|e| format!("build device {}: {e}", desc.name))?;
        if !desc.vector_events.is_empty() {
            if let Some(its) = &its_engine {
                // LPI-routed. Resolve each MSI-X vector to the guest's real LPI
                // through the captured ITS tables and hand it to the LPI sink. On
                // the userspace GIC that sink delivers it (deliverable); on the
                // managed GIC it only logs. Devices with a deliverable sink are
                // drained on resume so pre-snapshot in-flight I/O completes.
                if desc.device_id != 0 {
                    dev.set_injector(Box::new(its::ItsInjector::new(
                        desc.name.clone(),
                        its.clone(),
                        guest_mem.clone(),
                        desc.device_id,
                        desc.vector_events.clone(),
                        lpi_sink.clone(),
                    )));
                    if lpi_deliverable {
                        drainable.push(dev.clone());
                    }
                }
            } else if let Some(sink) = &msi_sink {
                // Deliverable: each MSI-X vector's msg_data is its target SPI
                // INTID; deliver completions live through the managed GIC.
                dev.set_injector(Box::new(MsiSpiInjector::new(
                    desc.name.clone(),
                    desc.vector_events.clone(),
                    sink.clone(),
                )));
                drainable.push(dev.clone());
            }
        }
        bus.add(base, size, dev.clone());
        if matches!(desc.backend, devmgr::BackendKind::Net) {
            net_devices.push(dev);
        }
        summary.push(format!("{kind} @ BAR {base:#x}"));
    }
    // Complete any requests left in-flight at snapshot time and deliver their
    // interrupts, so a resumed guest waiting on pre-snapshot I/O (e.g. a mount
    // reading the boot filesystem) makes progress instead of blocking forever.
    for dev in &drainable {
        dev.drain_on_resume();
    }

    // The credential proxy, if this workspace configures one. Installed after
    // the NICs exist because the hook is per-device, and only when a rule would
    // actually inject: a run with nothing to inject keeps the plain data path.
    let proxy = match proxy_rules
        .as_ref()
        .map(|r| credproxy::cli::start_resolved(workspace, r))
        .transpose()
    {
        Ok(Some(Some((proxy, decider)))) => {
            for dev in &net_devices {
                dev.set_net_intercept(Some(Arc::clone(&decider)));
            }
            Some(proxy)
        }
        Ok(_) => None,
        // Fail closed: a rules file that cannot be honoured must stop the run
        // rather than quietly boot a guest whose calls will go out unsigned.
        Err(e) => return Err(format!("credential proxy: {e}")),
    };

    Ok(WiredVirtio {
        summary,
        net_devices,
        proxy,
    })
}

/// Resolve the egress policy governing a sandbox's outbound network, in priority
/// order:
///
/// 1. `cli_override` — an explicit `--egress-policy <file>` on `chm run`/
///    `resume`/`connect`. Highest, because it is the most specific intent.
/// 2. `CHM_EGRESS_POLICY` env — the binding the runner sets for a cloud
///    assignment (`run_assignment` re-execs `chm run`); preserves cloud parity.
/// 3. `<workspace>/egress-policy.json` — the per-workspace file a local,
///    no-control-plane user authors with `chm firewall`. The workspace is the
///    parent of `overlay_dir` (`<snapshot_dir>/.chm-overlays`), so both `chm run`
///    and the `chm serve` daemon pick it up with no extra plumbing.
///
/// Returns `None` when nothing is configured (the guest then gets unrestricted
/// egress). A malformed policy is logged but must not silently *tighten* or crash
/// the boot: an allow-list you cannot read is treated as "no policy", never as
/// "deny everything".
/// How a run's egress policy resolved, distinguishing "no policy was ever
/// requested" (unrestricted by design) from "a policy source was specified but
/// could not be honored" (must fail closed). Collapsing both to `None` would let
/// a governed session silently run wide open if its policy file went missing or
/// malformed (M30.9).
enum EgressResolution {
    /// No policy source at all — egress is unrestricted.
    Unrestricted,
    /// A resolved, enforceable policy, and which authority supplied it.
    Policy(Box<EgressPolicy>, credproxy::cli::Authority),
    /// A source was specified (flag / env binding / workspace file) but failed to
    /// load or parse. The session was meant to be governed, so fail closed.
    FailClosed(String),
}

/// Resolve a run's egress policy from, in priority order: an explicit
/// `--egress-policy <file>` flag, the `CHM_EGRESS_POLICY` binding the cloud
/// runner sets, then a per-workspace `egress-policy.json` a local user authored
/// with `chm firewall`. A source that is present but unreadable/malformed yields
/// [`EgressResolution::FailClosed`] rather than silently disabling the firewall.
/// The sentence a user reads at session start about what their sandbox can
/// reach.
///
/// `None` — no policy anywhere — is the case this exists for. Resuming a
/// snapshot with no policy file runs with the public internet reachable, which
/// is the right default (a rehydrated guest arrives expecting the network it
/// was captured with, and denying it would train people to switch the firewall
/// off wholesale) but is currently discoverable only by running `chm posture`,
/// i.e. by someone who already knows the answer. So it says so unprompted, and
/// says it is a default rather than something the user chose — and names the
/// flag that changes it, because a warning with no remedy is just a worry.
pub(crate) fn egress_posture_line(policy: Option<&EgressPolicy>) -> String {
    match policy {
        Some(p) => format!("[egress] {} ({})", p.posture_summary(), p.label()),
        None => "[egress] the public internet is reachable — the default when no \
                 policy is set, not a choice this sandbox recorded. The host, this \
                 LAN and cloud metadata stay blocked. Restrict with `chm firewall \
                 set`."
            .to_string(),
    }
}

fn resolve_egress_policy(overlay_dir: &Path, cli_override: Option<&Path>) -> EgressResolution {
    let from_raw = |raw: &str, what: String, who: credproxy::cli::Authority| {
        // An undigested, unlabelled policy still has to say where it came from.
        // The authority is the only thing that knows, so it names the fallback
        // rather than the parser guessing (it used to hardcode "control-plane",
        // which attributed every `chm firewall set` to a cloud that may not
        // exist — and V9.17 now prints that label to the operator).
        let fallback = match who {
            credproxy::cli::Authority::Local => "local",
            credproxy::cli::Authority::ControlPlane => "control-plane",
        };
        match parse_egress_policy_labelled(raw, fallback) {
            Some(p) => EgressResolution::Policy(Box::new(p), who),
            None => EgressResolution::FailClosed(what),
        }
    };
    if let Some(path) = cli_override {
        return match fs::read_to_string(path) {
            Ok(raw) => from_raw(
                &raw,
                format!("--egress-policy {} is malformed", path.display()),
                credproxy::cli::Authority::Local,
            ),
            Err(e) => EgressResolution::FailClosed(format!(
                "--egress-policy {} could not be read: {e}",
                path.display()
            )),
        };
    }
    if let Ok(raw) = env::var("CHM_EGRESS_POLICY") {
        return from_raw(
            &raw,
            "CHM_EGRESS_POLICY is set but malformed".to_string(),
            credproxy::cli::Authority::ControlPlane,
        );
    }
    let workspace = overlay_dir.parent().unwrap_or(overlay_dir);
    let file = workspace.join("egress-policy.json");
    match fs::read_to_string(&file) {
        Ok(raw) => from_raw(
            &raw,
            format!("{} is malformed", file.display()),
            credproxy::cli::Authority::Local,
        ),
        // No workspace file: this run was never asked to be governed.
        Err(_) => EgressResolution::Unrestricted,
    }
}

/// Parse a control-plane policy document into an [`EgressPolicy`], for tests.
///
/// Production reads every document through [`parse_egress_policy_labelled`], so
/// that the label reported by the posture line is the authority that actually
/// wrote the document rather than a hardcoded guess. This wrapper only pins the
/// control-plane fallback, and is `cfg(test)` so it cannot quietly become a
/// second production entry point with a different default.
#[cfg(test)]
fn parse_egress_policy(raw: &str) -> Option<EgressPolicy> {
    parse_egress_policy_labelled(raw, "control-plane")
}

/// Parse a policy document, with the caller naming the label to use when the
/// document carries neither a `digest` nor a `label` of its own.
///
/// Every member is read defensively, because a policy document is hand-edited
/// (`chm firewall set`) and machine-generated (a control plane) by turns. The
/// rule for a member we cannot honour is the direction it would have moved the
/// posture (#269):
///
/// * would have **restricted** traffic — a `deny` entry, or the `default`
///   stance itself — refuse. Running on with a restriction we could not read is
///   a sandbox weaker than its own description, and nothing says so.
/// * would have **permitted** traffic — an `allow` entry — report it and carry
///   on. That direction already fails closed; the only cost is a guest that
///   cannot reach something, and the report is what turns an afternoon of
///   network debugging into a sentence.
///
/// Returning `None` puts the caller on its fail-closed path, which denies all
/// egress and prints why.
fn parse_egress_policy_labelled(raw: &str, fallback: &str) -> Option<EgressPolicy> {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("chm: warning: ignoring malformed egress policy ({e})");
            return None;
        }
    };

    // Absent is a real choice and means allow. Present-but-not-a-string is not:
    // `{"default": false}` used to read as "allow", so a document whose author
    // plainly meant to restrict something produced an unrestricted sandbox in
    // silence. We cannot tell which stance was meant, so we refuse to guess.
    match v.get("default") {
        None | Some(serde_json::Value::Null) => {}
        Some(d) if d.is_string() => {}
        Some(d) => {
            eprintln!(
                "chm: warning: egress policy: `default` is {d}, not \"allow\" or \"deny\" -- \
                 refusing to guess which stance was meant"
            );
            return None;
        }
    }
    let default = v.get("default").and_then(|d| d.as_str()).unwrap_or("allow");

    let mut unreadable_denies = false;
    let mut strings = |key: &str, restricts: bool| -> Vec<String> {
        let complain = |what: String| {
            eprintln!("chm: warning: egress policy: {what}");
        };
        match v.get(key) {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(a)) => {
                let mut out = Vec::new();
                for (i, e) in a.iter().enumerate() {
                    match e.as_str() {
                        Some(t) => out.push(t.to_string()),
                        None => {
                            complain(format!(
                                "`{key}[{i}]` is {e}, not a \"host[:port]\" string -- ignored"
                            ));
                            unreadable_denies |= restricts;
                        }
                    }
                }
                out
            }
            Some(other) => {
                complain(format!(
                    "`{key}` is {other}, not a list of \"host[:port]\" strings -- ignored"
                ));
                unreadable_denies |= restricts;
                Vec::new()
            }
        }
    };
    let allow = strings("allow", false);
    let deny = strings("deny", true);
    if unreadable_denies {
        eprintln!(
            "chm: warning: egress policy: a deny rule could not be read, so honouring \
             this policy would permit traffic its author blocked"
        );
        return None;
    }

    let label = v
        .get("digest")
        .and_then(|d| d.as_str())
        .or_else(|| v.get("label").and_then(|d| d.as_str()))
        .unwrap_or(fallback)
        .to_string();
    Some(EgressPolicy::from_profile(default, &allow, &deny, label))
}

/// The result of wiring the virtio device tree: a human summary plus the net
/// devices whose userspace NAT the caller must service on a background thread.
#[derive(Default)]
pub(crate) struct WiredVirtio {
    pub summary: Vec<String>,
    pub net_devices: Vec<Arc<VirtioPciDevice>>,
    /// The credential proxy, when this run has one. Held only to keep it alive
    /// and stoppable for the life of the VM — nothing else reads it.
    pub proxy: Option<credproxy::server::RunningProxy>,
}

/// How long the net service thread waits for a guest transmit before servicing
/// anyway. A guest transmit wakes it immediately (see [`NetKick`]), so this only
/// bounds how long host-side arrivals — which have no readiness signal we can
/// wait on — can sit unnoticed on an otherwise silent link.
const NET_SERVICE_INTERVAL: Duration = Duration::from_millis(2);

/// Spawn the net service thread: it advances each net device's userspace NAT
/// (relaying host-socket bytes into the guest's RX queue) and nudges the vCPUs
/// out of `hv_vcpu_run` when a frame was delivered, so the guest takes the RX
/// completion promptly.
///
/// This thread does all of the stack work. A guest transmit only enqueues the
/// frame and wakes this thread, so the vCPU returns to the guest immediately
/// instead of running the NAT inside its MMIO exit. Returns `None` when there
/// are no net devices to serve.
fn spawn_net_service(
    net_devices: Vec<Arc<VirtioPciDevice>>,
    running: Arc<AtomicBool>,
    exits: Arc<Mutex<Vec<ExitSignal>>>,
    audit: audit::AuditLog,
    quiesce: Arc<livesnap::Quiesce>,
) -> Option<(thread::JoinHandle<()>, Arc<NetKick>)> {
    if net_devices.is_empty() {
        return None;
    }
    let kick = Arc::new(NetKick::default());
    for dev in &net_devices {
        dev.set_net_kick(kick.clone());
    }
    // This thread writes received frames straight into the guest's RX ring, so
    // a live checkpoint must be able to stop it at a pass boundary. Registered
    // here, before the thread starts, so no checkpoint can ever observe a
    // writer that has not yet declared itself.
    quiesce.register();
    let waker = kick.clone();
    thread::Builder::new()
        .name("chm-net-service".into())
        .spawn(move || {
            // One line per distinct flow, allowed or denied, with the totals
            // written at session end. Recording denials only -- which is what
            // this did until V6.3 -- leaves a sandbox that reached two hundred
            // permitted hosts with an empty trail, indistinguishable from one
            // that never opened a socket.
            let mut tally = audit::EgressTally::default();
            while running.load(Ordering::Acquire) {
                // Pass boundary: the only point at which this thread is provably
                // not partway through publishing a frame into guest memory, and
                // therefore the only safe place to hold it for a RAM dump.
                quiesce.park_if_paused();
                let mut delivered = false;
                for dev in &net_devices {
                    if dev.service_net() {
                        delivered = true;
                    }
                    // Drain egress decisions and audit them. Draining also
                    // bounds the NAT's event buffer over a long session.
                    for ev in dev.drain_egress_events() {
                        if !tally.observe(ev.domain, &ev.target, &ev.rule, ev.allowed) {
                            continue;
                        }
                        if ev.allowed {
                            audit.egress_allow(ev.domain, &ev.target, &ev.rule, &ev.policy);
                        } else {
                            audit.egress_deny(ev.domain, &ev.target, &ev.rule, &ev.policy);
                        }
                    }
                }
                if delivered {
                    // Force any running vCPU to re-enter and take the pending RX
                    // SPI now; an idle (WFI-parked) vCPU picks it up on its own
                    // poll interval.
                    for sig in exits.lock().unwrap().iter() {
                        sig();
                    }
                    // A pass that reached the guest means the host had data
                    // ready, so go straight round again. Waiting here would cap
                    // a bulk transfer at one chain per interval — and the better
                    // our receive coalescing gets, the fewer guest transmits
                    // there are to wake us early.
                    continue;
                }
                kick.wait(NET_SERVICE_INTERVAL);
            }
            // The loop only exits when the run is over, so this is the one place
            // that knows the totals. Written here rather than beside
            // `session_stop` because the tally lives on this thread.
            if tally.saw_anything() {
                audit.egress_summary(&tally);
            }
        })
        .ok()
        .map(|h| (h, waker))
}

/// How long a guest may be silent on the console before chm suspends it.
///
/// This was 10 seconds, and that number was never a judgement about idleness.
/// It dates from a build that could not yet model virtio-block/net/console over
/// PCI: a resumed guest ran until it needed a device that did not exist, went
/// quiet, and would have sat parked in WFI forever. Ten seconds was scaffolding
/// to stop that hanging. The devices landed; the scaffold did not come down.
///
/// Ten seconds of console silence is not idleness. An agent thinking, an `npm
/// install` resolving, a compile — all silent, all working. For comparison
/// Cloudflare's `sleepAfter` defaults to ten minutes.
///
/// Ten minutes is also only defensible because expiry now *suspends* rather
/// than kills (V9.6): being wrong about idleness costs a resume, not the work.
///
/// Console silence is still a proxy, and a poor one for a guest doing silent
/// compute — measuring vCPU WFI residency instead is #171. `--idle-exit 0`
/// disables the timeout entirely, which is what `chm connect` already does,
/// because an interactive session has a human to judge.
///
/// `chm serve` shares this rather than keeping its own copy: the daemon and the
/// CLI had separate constants with the same stale rationale, and two numbers
/// that must agree eventually will not.
pub(crate) const DEFAULT_IDLE_EXIT_SECS: u64 = 600;

struct Args {
    snapshot_dir: PathBuf,
    max_seconds: u64,
    idle_exit_secs: u64,
    quiet: bool,
    /// Optional path to a session-liveness lock file. When set, the interactive
    /// run writes its PID here on start and removes it on its (now always
    /// graceful) teardown, so a supervising app can tell when the session ends —
    /// including when the user simply closes the window. Set by `chm connect
    /// --session-lock`; `None` for a plain `chm run`.
    session_lock: Option<PathBuf>,
    /// Use live checkpoints (suspend/resume): resume from a saved checkpoint in
    /// the snapshot dir if one exists, and capture a fresh checkpoint on a clean
    /// stop so the next start continues where this one left off. Set by `chm
    /// resume` and by `chm connect --checkpoint`; `false` cold-boots.
    checkpoint: bool,
    /// Optional path to a local egress-policy file (`--egress-policy`). When set,
    /// it governs the guest's outbound network for this run, overriding the
    /// `CHM_EGRESS_POLICY` env binding and any per-workspace `egress-policy.json`.
    /// `None` falls back to that resolution order. See [`resolve_egress_policy`].
    egress_policy: Option<PathBuf>,
    /// Checkpoint the *running* guest every N seconds (`--snapshot-every`).
    /// `Some(0)` is a deliberate "off" that outranks the environment, which is
    /// the whole reason this is an `Option<u64>` rather than a `u64`: a caller
    /// that has to be able to say "not for this run" cannot do it with a
    /// sentinel that also means "unset". `None` defers to
    /// `CHM_SNAPSHOT_INTERVAL_SECS`. See [`snapshot_interval`].
    snapshot_every: Option<u64>,
    /// Credential-proxy rules for this run, overriding `CHM_PROXY_RULES` and any
    /// per-workspace `proxy-rules.json`. See [`credproxy::cli::resolve_rules`].
    proxy_rules: Option<PathBuf>,
    /// Optional path to a local resource-limits file (`--limits`). When set, it
    /// bounds this run's resources, overriding the `CHM_LIMITS` env binding and
    /// any per-workspace `limits.json`. See [`limits::resolve_limits`].
    limits_file: Option<PathBuf>,
    /// Opt the guest into reaching reserved / host-internal address ranges
    /// (loopback, private LAN, link-local metadata) through the NAT. Off by
    /// default: the reserved-address guard (M31.1) denies those regardless of
    /// the egress policy. Set by `--allow-local-egress` or `CHM_ALLOW_LOCAL_EGRESS`.
    allow_local_egress: bool,
}

struct ConnectArgs {
    run: Args,
    socket_path: PathBuf,
    no_stop_daemon: bool,
}

pub fn main() -> ExitCode {
    startup::init();
    let raw: Vec<String> = env::args().skip(1).collect();
    match raw.first().map(String::as_str) {
        Some("create") => create_main(&raw[1..]),
        Some("cloud") => cloud::cloud_main(&raw[1..]),
        Some("runner") => control_plane::runner_main(&raw[1..]),
        Some("push") => control_plane::push_main(&raw[1..]),
        Some("pull") => control_plane::pull_main(&raw[1..]),
        Some("branches") => control_plane::branches_main(&raw[1..]),
        Some("policy") => control_plane::policy_main(&raw[1..]),
        Some("firewall") => firewall::firewall_main(&raw[1..]),
        Some("limits") => limits::limits_main(&raw[1..]),
        Some("audit") => audit::audit_main(&raw[1..]),
        Some("posture") => posture::posture_main(&raw[1..]),
        Some("capabilities") => capability::capabilities_main(&raw[1..]),
        // Not in the help: this is the child half of the HVF probe, which has to
        // run in its own process because `hv_vm_create` is process-global.
        Some(capability::PROBE_ARG) => capability::probe_main(),
        Some("proxy") => credproxy::cli::proxy_main(&raw[1..]),
        Some("sysregs") => sysregs::sysregs_main(&raw[1..]),
        Some("manifest") => signing::manifest_main(&raw[1..]),
        Some("state-cdn") => state_cdn::state_cdn_main(&raw[1..]),
        Some("serve") => serve::serve_main(&raw[1..]),
        Some("ctl") => serve::ctl_main(&raw[1..]),
        Some("exec") => serve::exec_main(&raw[1..]),
        Some("cp") => guestcp::cp_main(&raw[1..]),
        Some("ps") => runs::ps_main(&raw[1..]),
        Some("kernel") => kernelimage::kernel_main(&raw[1..]),
        Some("spec") => spec::spec_main(&raw[1..]),
        Some("image") => image_main(&raw[1..]),
        Some("fork") => match fork(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm fork: {e}");
                ExitCode::FAILURE
            }
        },
        Some("vanilla") => match vanilla(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm vanilla: {e}");
                ExitCode::FAILURE
            }
        },
        Some("revisions") => match revisions(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm revisions: {e}");
                ExitCode::FAILURE
            }
        },
        Some("workspace") => match workspace(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm workspace: {e}");
                ExitCode::FAILURE
            }
        },
        Some("rollback") => match rollback_cmd(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm rollback: {e}");
                ExitCode::FAILURE
            }
        },
        Some("connect") => match parse_connect(&raw[1..]) {
            Parsed::Connect(args) => match connect(&args) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("chm connect: {e}");
                    ExitCode::FAILURE
                }
            },
            Parsed::Help => {
                print!("{}", usage());
                ExitCode::SUCCESS
            }
            Parsed::Version => {
                println!("chm {}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            Parsed::Error(msg) => {
                eprintln!("chm connect: {msg}\n");
                eprint!("{}", usage());
                ExitCode::FAILURE
            }
            Parsed::Run(_) => unreachable!("parse_connect never returns Parsed::Run"),
        },
        _ => match parse(&raw) {
            Parsed::Run(args) => match run(&args) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("chm: error: {e}");
                    ExitCode::FAILURE
                }
            },
            Parsed::Connect(_) => unreachable!("parse never returns Parsed::Connect"),
            Parsed::Help => {
                print!("{}", usage());
                ExitCode::SUCCESS
            }
            Parsed::Version => {
                println!("chm {}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            Parsed::Error(msg) => {
                eprintln!("chm: {msg}\n");
                eprint!("{}", usage());
                ExitCode::FAILURE
            }
        },
    }
}

enum Parsed {
    Run(Args),
    Connect(ConnectArgs),
    Help,
    Version,
    Error(String),
}

fn usage() -> String {
    "chm — Gimbal Local (Cloud Hypervisor on Apple Silicon)\n\
     \n\
     Run Linux guests on Hypervisor.framework: cold-boot a kernel with no\n\
     snapshot, or rehydrate a Cloud Hypervisor arm64 snapshot and resume it\n\
     locally. Either way the guest serial console streams to stdout.\n\
     \n\
     USAGE:\n    \
         chm <COMMAND> [OPTIONS]\n\
     \n\
     RUN A GUEST\n    \
         chm create --kernel <Image> [OPTIONS] (cold boot, no snapshot needed)\n    \
         chm run <SNAPSHOT_DIR> [OPTIONS]      (rehydrate a snapshot)\n    \
         chm restore <SNAPSHOT_DIR> [OPTIONS]  (alias for run)\n    \
         chm resume <SNAPSHOT_DIR> [OPTIONS]   (restore a saved checkpoint)\n    \
         chm connect <SNAPSHOT_DIR> [OPTIONS]  (interactive session)\n    \
         chm exec [OPTIONS] -- <CMD> [ARG...]  (run a command in the guest)\n    \
         chm cp <HOST_FILE> <GUEST_PATH>       (put a file into the guest)\n    \
         chm ps [--json]                       (what is running right now)\n    \
         chm spec <COMMAND> [OPTIONS]          (describe a sandbox in a file)\n\
     \n\
     BUILD AN IMAGE\n    \
         chm image build <REF> --kernel <I>    (bootable rootfs from a container)\n    \
         chm kernel probe <PATH> [--json]      (can this host boot this kernel?)\n\
     \n\
     SNAPSHOTS AND LINEAGE\n    \
         chm workspace <IMAGE_DIR> <WS_DIR>    (isolated sandbox workspace)\n    \
         chm fork <SRC_DIR> <DST_DIR>          (branch a saved revision)\n    \
         chm revisions <SNAPSHOT_DIR> [--json] (list the lineage)\n    \
         chm rollback <SNAPSHOT_DIR> <REV_ID>  (roll back to a revision)\n    \
         chm vanilla export <SNAP_DIR> <OUT>   (write a vanilla capture back)\n    \
         chm manifest <COMMAND> [OPTIONS]      (sign / verify a manifest)\n\
     \n\
     SECURITY AND EVIDENCE\n    \
         chm firewall set <WORKSPACE_DIR> ...  (author a local egress policy)\n    \
         chm proxy show [WORKSPACE_DIR]        (credential injection for egress)\n    \
         chm limits <COMMAND> [OPTIONS]        (bound CPU, memory and disk)\n    \
         chm audit show <WORKSPACE_DIR>        (the append-only session trail)\n    \
         chm posture <WORKSPACE_DIR> [--json]  (which security controls are on)\n    \
         chm capabilities [SNAPSHOT_DIR]       (what this build can do, and why)\n    \
         chm sysregs <SNAPSHOT_DIR> [--all]    (CPU registers this Mac reproduces)\n\
     \n\
     DAEMON\n    \
         chm serve <LIBRARY_DIR> [OPTIONS]     (background daemon)\n    \
         chm ctl <COMMAND> [ARG] [--socket P]  (talk to a daemon)\n    \
         chm ctl posture [DIR]                 (the daemon's own posture)\n\
     \n\
     YOUR OWN CLOUD (your AWS account, no control plane)\n    \
         chm cloud <COMMAND> aws [OPTIONS]     (init/preflight/pull/push/capture)\n\
     \n\
     NEEDS A CONTROL PLANE\n    \
         chm push <CHECKPOINT_DIR> --branch N  (commit a revision to the plane)\n    \
         chm pull --branch N --to DIR          (rehydrate a branch head)\n    \
         chm branches [--json] [--owner WHO]   (list + drive revision branches)\n    \
         chm runner <COMMAND> [OPTIONS]        (drive local runs through gctl)\n    \
         chm policy show --sandbox ID          (a sandbox's bound governance)\n    \
         chm state-cdn reconstruct [OPTIONS]   (pull memory from the state CDN)\n\
     \n\
     Every command takes `--help` of its own.\n\
     \n\
     ARGS:\n    \
         <SNAPSHOT_DIR>    Directory holding `state.json` and\n                      \
         `snapshot/memory-ranges` (a `ch-snapshot` directory).\n\
     \n\
     OPTIONS:\n    \
         --max-seconds <N>   Suspend after N seconds of wall-clock run time,\n                        \
         saving a checkpoint you can resume (0 = unlimited; default 0).\n    \
         --idle-exit <N>     Suspend after N seconds with no console output\n                        \
         (0 = disabled; default 600). Console silence is a proxy: a\n                        \
         guest doing silent compute looks idle. Expiry suspends\n                        \
         rather than stops, so being wrong costs a resume.\n    \
         --snapshot-every <N>  Checkpoint the *running* guest every N\n                        \
         seconds without stopping it, so a session that ends badly is\n                        \
         not a session whose work is gone (0 = off; default off). Each\n                        \
         one freezes the guest to capture RAM — 0.9–2.1s for 2 GiB — and\n                        \
         chm prints the freeze it measured, so the interval is a trade\n                        \
         you make on your own numbers. Overrides\n                        \
         `CHM_SNAPSHOT_INTERVAL_SECS`, `0` to turn it off for one run.\n                        \
         Retention bounds how far back this travels (`chm revisions`).\n    \
         --quiet             Suppress the informational banner on stderr.\n    \
         --egress-policy <FILE>  Govern this run's outbound network with a local\n                        \
         egress policy (see `chm firewall`); overrides any per-workspace\n                        \
         `egress-policy.json` and the control-plane binding.\n    \
         --proxy-rules <FILE>  Inject credentials into this run's outbound calls\n                        \
         for the listed destinations, so the guest never holds them (see\n                        \
         `chm proxy`); overrides `CHM_PROXY_RULES` and any per-workspace\n                        \
         `proxy-rules.json`.\n    \
         --allow-local-egress  Let the guest reach reserved / host-internal\n                        \
         address ranges (loopback, private LAN, link-local metadata). OFF by\n                        \
         default: the NAT blocks them regardless of policy (M31.1). Also via\n                        \
         `CHM_ALLOW_LOCAL_EGRESS=1`.\n    \
         --checkpoint         Use live checkpoints: resume from a saved\n                        \
         checkpoint in the snapshot dir if present, and capture a fresh one on\n                        \
         a clean stop so the next start continues where this left off. Implied\n                        \
         by `chm resume`.\n    \
         --socket <PATH>      For `connect`, stop any app/daemon-run VM on this\n                        \
         socket before taking the snapshot over interactively.\n    \
         --no-stop-daemon     For `connect`, do not stop a daemon-run VM first.\n    \
         --session-lock <PATH> For `connect`, maintain a PID lock file at PATH\n                        \
         for the life of the session (a supervising app watches it).\n    \
         -h, --help          Print this help.\n    \
         -V, --version       Print the version.\n\
     \n\
     CLOUD:\n    \
         chm cloud preflight aws --profile P --region R [--bucket B]\n    \
         chm cloud cleanup aws --profile P --region R [--bucket B]\n\
     \n\
     DAEMON:\n    \
         chm serve <LIBRARY_DIR> [--socket PATH] [--idle-exit N]\n                        \
         [--max-seconds N]\n      \
         Host a snapshot library (a `ch-snapshot` dir, or a directory of\n      \
         them) behind a Unix socket (default $TMPDIR/chm.sock).\n    \
         chm ctl list [--json]       List snapshots in the library.\n    \
         chm ctl status [--json]     Show daemon / running-VM status.\n    \
         chm ctl start <name>        Resume a snapshot by name.\n    \
         chm ctl console             Stream the running guest console.\n    \
         chm ctl input [TEXT]        Type TEXT at the guest console. TEXT is\n                                \
         sent as-is, so end it with \\n (or run the\n                                \
         command bare) to press Enter. A resumed\n                                \
         guest is idle until it is typed at.\n    \
         chm ctl stop                Stop the running guest.\n    \
         chm ctl shutdown            Stop the guest and exit the daemon.\n    \
         chm exec [--timeout N] [--json] -- <CMD> [ARG...]\n      \
         Run a command in the running guest and exit with ITS exit\n      \
         status. The arguments after `--` are an argv: nothing in\n      \
         them is interpreted as shell syntax, so ask for a shell\n      \
         explicitly (`chm exec -- bash -lc '...'`) when you want one.\n      \
         124 means the guest did not answer in time and 125 means\n      \
         chm could not run it at all, so a transport failure is\n      \
         never reported as success.\n    \
         chm cp [--timeout N] <HOST_FILE> <GUEST_PATH>\n      \
         Copy a file into the running guest over the same console\n      \
         channel, in chunks small enough to survive a tty, and\n      \
         verify it by comparing a SHA-256 taken here against one\n      \
         the guest reports. This is how a script too long for\n      \
         `chm exec` gets in. An unverifiable copy is a failure,\n      \
         never a success: the guest needs `base64` and\n      \
         `sha256sum`.\n\
     \n\
     NOTE: the binary must be code-signed with the\n      \
     `com.apple.security.hypervisor` entitlement (see scripts/build-chm.sh).\n"
        .to_string()
}

/// Read a boolean opt-in from an environment variable: true for `1`/`true`/`yes`
/// (case-insensitive), false otherwise or when unset.
fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn parse(raw: &[String]) -> Parsed {
    let mut snapshot_dir: Option<PathBuf> = None;
    let mut max_seconds = 0u64;
    let mut idle_exit_secs = DEFAULT_IDLE_EXIT_SECS;
    let mut quiet = false;
    let mut checkpoint = false;
    let mut egress_policy: Option<PathBuf> = None;
    let mut proxy_rules: Option<PathBuf> = None;
    let mut limits_file: Option<PathBuf> = None;
    let mut allow_local_egress = env_flag("CHM_ALLOW_LOCAL_EGRESS");
    let mut snapshot_every: Option<u64> = None;

    let mut i = 0;
    // A leading `run`/`restore` subcommand is accepted but optional; `resume`
    // additionally enables live checkpoints (suspend/resume).
    if i < raw.len() && (raw[i] == "run" || raw[i] == "restore") {
        i += 1;
    } else if i < raw.len() && raw[i] == "resume" {
        checkpoint = true;
        i += 1;
    }

    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--quiet" => quiet = true,
            "--checkpoint" => checkpoint = true,
            "--allow-local-egress" => allow_local_egress = true,
            "--egress-policy" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                egress_policy = Some(PathBuf::from(v));
            }
            "--proxy-rules" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                proxy_rules = Some(PathBuf::from(v));
            }
            "--limits" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                limits_file = Some(PathBuf::from(v));
            }
            "--max-seconds" | "--idle-exit" | "--snapshot-every" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                let Ok(n) = v.parse::<u64>() else {
                    return Parsed::Error(format!("{a}: `{v}` is not a number"));
                };
                match a.as_str() {
                    "--max-seconds" => max_seconds = n,
                    "--idle-exit" => idle_exit_secs = n,
                    _ => snapshot_every = Some(n),
                }
            }
            other if other.starts_with('-') => {
                return Parsed::Error(format!("unknown option `{other}`"));
            }
            _ => {
                if snapshot_dir.is_some() {
                    return Parsed::Error(format!("unexpected extra argument `{a}`"));
                }
                snapshot_dir = Some(PathBuf::from(a));
            }
        }
        i += 1;
    }

    match snapshot_dir {
        Some(snapshot_dir) => Parsed::Run(Args {
            snapshot_dir,
            max_seconds,
            idle_exit_secs,
            quiet,
            session_lock: None,
            checkpoint,
            egress_policy,
            proxy_rules,
            limits_file,
            allow_local_egress,
            snapshot_every,
        }),
        None => Parsed::Error("missing <SNAPSHOT_DIR>".to_string()),
    }
}

fn parse_connect(raw: &[String]) -> Parsed {
    let mut snapshot_dir: Option<PathBuf> = None;
    let mut max_seconds = 0u64;
    let mut idle_exit_secs = 0u64;
    let mut quiet = false;
    let mut socket_path = serve::default_socket();
    let mut no_stop_daemon = false;
    let mut session_lock: Option<PathBuf> = None;
    let mut checkpoint = false;
    let mut egress_policy: Option<PathBuf> = None;
    let mut proxy_rules: Option<PathBuf> = None;
    let mut limits_file: Option<PathBuf> = None;
    let mut allow_local_egress = env_flag("CHM_ALLOW_LOCAL_EGRESS");
    let mut snapshot_every: Option<u64> = None;

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--quiet" => quiet = true,
            "--no-stop-daemon" => no_stop_daemon = true,
            "--checkpoint" => checkpoint = true,
            "--allow-local-egress" => allow_local_egress = true,
            "--socket" | "--max-seconds" | "--idle-exit" | "--session-lock"
            | "--egress-policy" | "--proxy-rules" | "--limits" | "--snapshot-every" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                match a.as_str() {
                    "--socket" => socket_path = PathBuf::from(v),
                    "--session-lock" => session_lock = Some(PathBuf::from(v)),
                    "--egress-policy" => egress_policy = Some(PathBuf::from(v)),
                    "--proxy-rules" => proxy_rules = Some(PathBuf::from(v)),
                    "--limits" => limits_file = Some(PathBuf::from(v)),
                    "--max-seconds" | "--idle-exit" | "--snapshot-every" => {
                        let Ok(n) = v.parse::<u64>() else {
                            return Parsed::Error(format!("{a}: `{v}` is not a number"));
                        };
                        match a.as_str() {
                            "--max-seconds" => max_seconds = n,
                            "--idle-exit" => idle_exit_secs = n,
                            _ => snapshot_every = Some(n),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            other if other.starts_with('-') => {
                return Parsed::Error(format!("unknown option `{other}`"));
            }
            _ => {
                if snapshot_dir.is_some() {
                    return Parsed::Error(format!("unexpected extra argument `{a}`"));
                }
                snapshot_dir = Some(PathBuf::from(a));
            }
        }
        i += 1;
    }

    match snapshot_dir {
        Some(snapshot_dir) => Parsed::Connect(ConnectArgs {
            run: Args {
                snapshot_dir,
                max_seconds,
                idle_exit_secs,
                quiet,
                session_lock,
                checkpoint,
                egress_policy,
                proxy_rules,
                limits_file,
                allow_local_egress,
                snapshot_every,
            },
            socket_path,
            no_stop_daemon,
        }),
        None => Parsed::Error("missing <SNAPSHOT_DIR>".to_string()),
    }
}

/// `chm fork <SRC_SNAPSHOT_DIR> <DST_SNAPSHOT_DIR>` — branch a sandbox.
///
/// Creates DST as an independent fork of SRC's current saved revision: DST
/// references SRC's immutable base read-only and copies SRC's live checkpoint +
/// disk overlays, re-parented in the lineage. `chm resume <DST>` then runs the
/// fork, diverging from SRC. The graph branches here (see
/// `docs/gimbal-local-fork-model.md`).
fn fork(raw: &[String]) -> Result<ExitCode, String> {
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") || positionals.len() != 2 {
        eprintln!(
            "usage: chm fork <SRC_SNAPSHOT_DIR> <DST_SNAPSHOT_DIR>\n\
             \n\
             Branch SRC's current saved revision into a new, independent\n\
             snapshot DST that shares SRC's base but diverges from a copy of\n\
             its live state. Run the fork with `chm resume <DST>`."
        );
        return if positionals.len() == 2 {
            Ok(ExitCode::SUCCESS)
        } else {
            Err("expected exactly two directory arguments".to_string())
        };
    }
    let src = PathBuf::from(positionals[0]);
    let dst = PathBuf::from(positionals[1]);
    checkpoint::fork_into(&src, &dst)?;
    eprintln!(
        "chm: forked {} -> {} (resume the fork with `chm resume {}`)",
        src.display(),
        dst.display(),
        dst.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// `chm workspace <IMAGE_DIR> <WORKSPACE_DIR>` — create an isolated per-sandbox
/// workspace that shares the image's read-only base but keeps its own overlays
/// and checkpoints, so N sandboxes from one image don't clobber each other.
fn workspace(raw: &[String]) -> Result<ExitCode, String> {
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") || positionals.len() != 2 {
        eprintln!(
            "usage: chm workspace <IMAGE_DIR> <WORKSPACE_DIR>\n\
             \n\
             Create an isolated sandbox workspace: it shares IMAGE_DIR's\n\
             read-only base (state.json, snapshot/, disks/ are symlinked) but\n\
             keeps its own disk overlays + checkpoint/revision store, so several\n\
             sandboxes from one image diverge independently. If the image ships\n\
             a golden checkpoint the workspace is seeded from it and resumes\n\
             that settled state (`chm connect <WORKSPACE_DIR> --checkpoint`);\n\
             otherwise `chm run <WORKSPACE_DIR>` rehydrates the base capture.\n\
             Either way a later suspend saves a checkpoint inside the workspace.\n\
             \n\
             IMAGE_DIR must be a captured snapshot, not a `chm image build`\n\
             output: those cold-boot with `chm create` and need no workspace."
        );
        return if positionals.len() == 2 {
            Ok(ExitCode::SUCCESS)
        } else {
            Err("expected an image directory and a workspace directory".to_string())
        };
    }
    let image = PathBuf::from(positionals[0]);
    let ws = PathBuf::from(positionals[1]);
    checkpoint::workspace_from_image(&image, &ws)?;
    eprintln!(
        "chm: created workspace {} from {} (run it with `chm run {}`)",
        ws.display(),
        image.display(),
        ws.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// `chm revisions <SNAPSHOT_DIR> [--json]` — list a snapshot's saved revisions
/// (its suspend/fork/rollback lineage), oldest first.
/// Shared by the parser and its test, so the documented order and the accepted
/// order cannot drift apart.
const VANILLA_USAGE: &str = "usage: chm vanilla export <SNAPSHOT_DIR> <OUT_DIR> [--json]\n\
     \n\
     Write this lineage's current checkpoint back out as a *vanilla* Cloud\n\
     Hypervisor capture -- the same shape upstream writes on a KVM host, and\n\
     the shape `chm run` reads. The register state comes from a live Apple\n\
     Hypervisor.framework vCPU; there is no KVM, no QEMU and no Linux host\n\
     anywhere in the path.\n\
     \n\
     This is what makes the cloud round trip symmetric. Until now a snapshot\n\
     could only travel one way: down from the cloud, run here, and whatever\n\
     the guest did on this Mac stayed on this Mac.\n\
     \n\
     The export rewrites this lineage's own ancestor rather than synthesising\n\
     a document, so every field a Mac did not re-measure is the cloud's own\n\
     bytes. `--json` reports exactly which fields changed, so the claim is\n\
     checkable rather than asserted.\n\
     \n\
     OUT_DIR must not exist. Guest RAM and the disks are APFS clones plus the\n\
     sectors that were written, so an export of a 10 GiB machine costs close\n\
     to what actually changed.";

/// What `chm vanilla` was asked to do.
///
/// Parsing is split out from doing because the dispatch arm hands this
/// function `&raw[1..]` -- the slice *after* `vanilla` -- so the verb is at
/// index 0, not 1. An off-by-one here is invisible to every test that calls
/// the exporter directly, and it makes the command print usage forever
/// instead of exporting anything.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VanillaCmd {
    /// An explicit `-h`/`--help`. Asking for help and getting it is a success.
    Help,
    Export {
        dir: PathBuf,
        out: PathBuf,
        json: bool,
    },
}

/// Parse the argv slice the dispatcher passes for `chm vanilla`.
///
/// `raw[0]` is the sub-verb (`export`), NOT `vanilla`.
pub(crate) fn parse_vanilla(raw: &[String]) -> Result<VanillaCmd, String> {
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(VanillaCmd::Help);
    }
    let json = raw.iter().any(|a| a == "--json");
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();

    match positionals.first().map(|s| s.as_str()) {
        Some("export") if positionals.len() == 3 => Ok(VanillaCmd::Export {
            dir: PathBuf::from(positionals[1]),
            out: PathBuf::from(positionals[2]),
            json,
        }),
        Some("export") => Err(format!(
            "`export` takes a snapshot directory and an output directory, got {}",
            positionals.len() - 1
        )),
        Some(other) => Err(format!("expected `export` after `vanilla`, got `{other}`")),
        None => Err("expected `export <SNAPSHOT_DIR> <OUT_DIR>`".to_string()),
    }
}

/// `chm vanilla export <SNAPSHOT_DIR> <OUT_DIR>` (#353).
fn vanilla(raw: &[String]) -> Result<ExitCode, String> {
    let (dir, out, json) = match parse_vanilla(raw) {
        Ok(VanillaCmd::Help) => {
            println!("{VANILLA_USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
        Ok(VanillaCmd::Export { dir, out, json }) => (dir, out, json),
        Err(e) => {
            eprintln!("{VANILLA_USAGE}");
            return Err(e);
        }
    };
    let dir = dir.as_path();
    let out = out.as_path();
    let report = vanilla_export::export(dir, out)?;

    if json {
        let paths: Vec<serde_json::Value> = report
            .changed_paths
            .iter()
            .map(|p| serde_json::Value::String(p.clone()))
            .collect();
        let warnings: Vec<serde_json::Value> = report
            .warnings
            .iter()
            .map(|w| serde_json::Value::String(w.clone()))
            .collect();
        let disks: Vec<serde_json::Value> = report
            .disks
            .iter()
            .map(|(name, sectors)| {
                serde_json::json!({ "disk": name, "sectors_overlaid": sectors })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "out": out.display().to_string(),
                "vcpus": report.vcpus,
                "ram_bytes": report.ram_bytes,
                "disks": disks,
                "changed_paths": paths,
                "not_carried": warnings,
                "vcpus_exported": report
                    .vcpu_summaries
                    .iter()
                    .map(|l| serde_json::Value::String(l.clone()))
                    .collect::<Vec<serde_json::Value>>(),
            })
        );
        return Ok(ExitCode::SUCCESS);
    }

    println!("vanilla capture written to {}", out.display());
    println!(
        "  {} vCPU register block(s) rewritten, guest RAM {}",
        report.vcpus,
        human_bytes(report.ram_bytes)
    );
    // Where each guest core actually was, read back out of the written
    // document. A zero or wild `pc` is the cheapest visible symptom of an
    // offset or byte-order mistake in the register block.
    for line in &report.vcpu_summaries {
        println!("  {line}");
    }
    for (name, sectors) in &report.disks {
        if *sectors == 0 {
            println!("  {name}: unchanged from the base");
        } else {
            println!(
                "  {name}: {sectors} sector(s) overlaid ({})",
                human_bytes(sectors * 512)
            );
        }
    }
    // The differential IS the evidence: a field outside this list would mean
    // the export had invented something the guest never did.
    println!("  {} field(s) differ from the ancestor:", report.changed_paths.len());
    for p in &report.changed_paths {
        println!("    {p}");
    }
    for w in &report.warnings {
        println!("  not carried: {w}");
    }
    Ok(ExitCode::SUCCESS)
}

const REVISIONS_USAGE: &str = "usage: chm revisions <SNAPSHOT_DIR> [--json] [--usage]\n       \
     chm revisions <SNAPSHOT_DIR> pin    <REVISION_ID>\n       \
     chm revisions <SNAPSHOT_DIR> unpin  <REVISION_ID>\n       \
     chm revisions <SNAPSHOT_DIR> label  <REVISION_ID> <TEXT>|--clear\n       \
     chm revisions <SNAPSHOT_DIR> delete <REVISION_ID> [--dry-run]\n       \
     chm revisions <SNAPSHOT_DIR> gc [--dry-run]\n       \
     chm revisions <SNAPSHOT_DIR> export <REVISION_ID>|--all <BUNDLE_DIR> [--with-base]\n       \
     chm revisions <SNAPSHOT_DIR> import <BUNDLE_DIR> [--dry-run] [--skip-existing]\n\
     \n\
     List the snapshot's saved revisions (its lineage), oldest first, with\n     \
     how long ago each was taken. `resumable` marks revisions whose live\n     \
     RAM is still retained; older ones are pruned to metadata so the\n     \
     lineage graph survives. An `-auto` origin marks a point the\n     \
     continuous-snapshot cadence took rather than one you asked for.\n\
     \n\
     `pin` makes a revision a retention root: age-based pruning will not\n\
     reclaim its RAM, so a point you care about stays resumable however\n\
     many checkpoints follow it. Pins sit outside the retention budget,\n\
     so pinning one does not shorten the window of recent history. With\n     \
     CHM_SNAPSHOT_INTERVAL_SECS set, that budget is what bounds how far\n     \
     back you can actually travel: the reachable window is roughly the\n     \
     interval times CHM_MAX_RESUMABLE_REVISIONS, so pin anything you\n     \
     want to outlive it.\n\
     \n\
     `label` names a revision so a timeline of timestamps becomes a list\n     \
     of reasons. A label is what makes a point findable months later.\n\
     \n\
     `delete` removes one revision. Descendants keep working — a RAM\n     \
     dump is a complete image, so a child shares extents with its parent\n     \
     but never depends on it — and their manifests go on naming the\n     \
     deleted id, which is reported as `(deleted)`. HEAD and pinned\n     \
     revisions are refused.\n\
     \n\
     `gc` reclaims state no reader can reach: a staging directory left\n     \
     by an interrupted checkpoint or import, and revision directories\n     \
     whose manifest will not parse. Both hold a whole RAM dump while\n     \
     being invisible to `chm revisions`.\n\
     \n\
     `export` writes revisions into a portable bundle directory. Its\n     \
     payload is content-addressed on the same 64 KiB grid the delta\n     \
     writer uses, so a lineage whose revisions overlap exports at close\n     \
     to the size of one of them rather than the sum of all. By default\n     \
     the bundle does NOT contain the base snapshot, and it never\n     \
     rewrites it — it\n     \
     records the base's identity so an import can refuse a mismatch.\n\
     \n     \
     --with-base carries the base snapshot's own files too, so the\n     \
     bundle stands alone on a machine that has never held it. The\n     \
     base shares the revisions' chunk store, so it costs only what\n     \
     genuinely differs from them.\n     \
     `tar` the directory if you want a single file.\n\
     \n\
     `import` adds a bundle's revisions to this snapshot's lineage. The\n     \
     target must be the same base snapshot the bundle came from --\n     \
     or, for a bundle exported --with-base, an empty directory, which\n     \
     is where the base is laid down. An existing base is never\n     \
     overwritten. An\n     \
     imported revision never becomes HEAD — use `chm rollback` to move\n     \
     there deliberately. A revision id already present is refused;\n     \
     --skip-existing imports the rest instead.\n\
     \n\
     `--usage` reports what the lineage occupies. A fork hard-links its\n\
     parent's RAM dump, so shared content is counted once for the\n\
     revisions total and once per revision below it; the difference is\n\
     the saving from sharing. Live overlays belong to no revision and\n\
     are reported on their own line.";

/// How many positional arguments each `revisions` verb takes, including the
/// directory and the verb itself. `None` is "not a verb".
fn revisions_arity(verb: &str, clearing: bool, all: bool) -> Option<usize> {
    match verb {
        "pin" | "unpin" | "delete" | "import" => Some(3),
        "gc" => Some(2),
        // `label <ID> <TEXT>`, or `label <ID> --clear` where the flag is not a
        // positional.
        "label" => Some(if clearing { 3 } else { 4 }),
        // `export <ID> <DIR>`, or `export --all <DIR>` where the flag is not a
        // positional.
        "export" => Some(if all { 3 } else { 4 }),
        _ => None,
    }
}

fn revisions(raw: &[String]) -> Result<ExitCode, String> {
    let json = raw.iter().any(|a| a == "--json");
    let usage_only = raw.iter().any(|a| a == "--usage");
    let dry_run = raw.iter().any(|a| a == "--dry-run");
    let clearing = raw.iter().any(|a| a == "--clear");
    let all = raw.iter().any(|a| a == "--all");
    let skip_existing = raw.iter().any(|a| a == "--skip-existing");
    let with_base = raw.iter().any(|a| a == "--with-base");
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();

    // Every verb acts on a revision inside a snapshot, so they follow the
    // directory exactly as `chm rollback <SNAPSHOT_DIR> <REVISION_ID>` does.
    // Every command in this CLI takes SNAPSHOT_DIR immediately after the verb;
    // putting it second here would make the directory's position depend on
    // whether a sub-verb was given.
    let verb = positionals.get(1).map(|s| s.as_str());
    let arity = verb.and_then(|v| revisions_arity(v, clearing, all));
    let expected = arity.unwrap_or(1);

    if raw.iter().any(|a| a == "-h" || a == "--help") || positionals.len() != expected {
        eprintln!("{REVISIONS_USAGE}");
        return if positionals.len() == expected {
            Ok(ExitCode::SUCCESS)
        } else if let (Some(verb), Some(arity)) = (verb, arity) {
            Err(format!(
                "`{verb}` takes {} argument(s) after the directory, got {}",
                arity - 2,
                positionals.len().saturating_sub(2)
            ))
        } else if positionals.len() > 1 {
            Err(format!(
                "expected one of pin, unpin, label, delete, gc, export, import \
                 after the directory, got `{}`",
                positionals[1]
            ))
        } else {
            Err("expected one directory argument".to_string())
        };
    }

    if let Some(verb) = verb {
        let dir = PathBuf::from(positionals[0]);
        let opts = RevisionsOpts {
            dry_run,
            clearing,
            all,
            skip_existing,
            with_base,
        };
        return revisions_verb(&dir, verb, &positionals, &opts);
    }

    let dir = PathBuf::from(positionals[0]);
    let summaries = checkpoint::revision_summaries(&dir);

    if usage_only {
        let usage = checkpoint::snapshot_usage(&dir);
        if json {
            let out = serde_json::to_string(&usage).map_err(|e| format!("serialize usage: {e}"))?;
            println!("{out}");
        } else {
            // Revisions clone rather than copy, so the sum of their sizes is a
            // ceiling that can exceed the real cost by orders of magnitude (a
            // measured lineage: 110 GiB of parts over 41 MiB of disk). Lead
            // with what deleting them gives back, which is the number anyone
            // reading this is about to act on.
            println!("revisions     {} to reclaim", human_bytes(usage.on_disk));
            let shared = usage.apparent.saturating_sub(usage.on_disk);
            if shared > 0 {
                println!(
                    "  {} of their {} is shared and costs nothing extra",
                    human_bytes(shared),
                    human_bytes(usage.apparent)
                );
            }
            if usage.live_overlays > 0 {
                println!(
                    "live overlays {}  (working state, in no revision)",
                    human_bytes(usage.live_overlays)
                );
            }
            println!(
                "total         {}",
                human_bytes(usage.on_disk + usage.live_overlays)
            );
            for r in &summaries {
                let pin = if r.pinned { " [pinned]" } else { "" };
                let kind = if r.resumable { "" } else { "  metadata-only" };
                println!(
                    "  {}  {:>10} to reclaim{pin}{kind}",
                    r.id,
                    human_bytes(r.frees)
                );
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    if json {
        let out =
            serde_json::to_string(&summaries).map_err(|e| format!("serialize revisions: {e}"))?;
        println!("{out}");
    } else if summaries.is_empty() {
        eprintln!(
            "chm: no saved revisions for {} (run and suspend it first)",
            dir.display()
        );
    } else {
        let ids: HashSet<&str> = summaries.iter().map(|r| r.id.as_str()).collect();
        for r in &summaries {
            let head = if r.is_head { " (HEAD)" } else { "" };
            let resumable = if r.resumable { "resumable" } else { "metadata-only" };
            let pin = if r.pinned { "  [pinned]" } else { "" };
            // A parent that no longer resolves is not a broken record, it is the
            // record of a deletion — and saying so is the whole reason `delete`
            // can leave manifests alone. Silently printing the id would look
            // like a revision the reader had somehow missed.
            let parent = match r.parent.as_deref() {
                Some(p) if ids.contains(p) => p.to_string(),
                Some(p) => format!("{p} (deleted)"),
                None => "—".to_string(),
            };
            let label = r.label.as_deref().map_or_else(String::new, |l| format!("  \"{l}\""));
            println!(
                "{}{head}  {:>9}  {}  parent={parent}  {resumable}{pin}{label}",
                r.id,
                relative_age(r.created_at_ms),
                r.origin
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Flags shared by the `revisions` sub-verbs, so adding one does not add a
/// positional parameter to a function four verbs already share.
struct RevisionsOpts {
    dry_run: bool,
    clearing: bool,
    all: bool,
    skip_existing: bool,
    with_base: bool,
}

/// Dispatch a `chm revisions <dir> <verb>` sub-verb.
fn revisions_verb(
    dir: &Path,
    verb: &str,
    positionals: &[&String],
    opts: &RevisionsOpts,
) -> Result<ExitCode, String> {
    let dry_run = opts.dry_run;
    match verb {
        "pin" | "unpin" => {
            let rev = positionals[2];
            let pin = verb == "pin";
            let changed = checkpoint::pin_revision(dir, rev, pin)?;
            let state = if pin { "pinned" } else { "unpinned" };
            if changed {
                println!("{rev} {state}");
            } else {
                println!("{rev} was already {state}");
            }
        }
        "label" => {
            let rev = positionals[2];
            let text = if opts.clearing { None } else { Some(positionals[3].as_str()) };
            match checkpoint::label_revision(dir, rev, text)? {
                Some(stored) => println!("{rev} labelled \"{stored}\""),
                None => println!("{rev} label cleared"),
            }
        }
        "delete" => {
            let rev = positionals[2];
            let plan = if dry_run {
                checkpoint::plan_delete(dir, rev)?
            } else {
                checkpoint::delete_revision(dir, rev)?
            };
            let verbed = if dry_run { "would delete" } else { "deleted" };
            let kind = if plan.resumable { "resumable" } else { "metadata-only" };
            println!("{verbed} {} ({kind})", plan.id);
            // `frees` is exact but can legitimately be zero, when every extent
            // is shared with a fork or a clone elsewhere. Reporting "0 B" with
            // no explanation reads like a failure, so say which it is.
            if plan.frees == 0 {
                println!("  reclaims nothing: its content is shared with another file");
            } else {
                println!("  reclaims {}", human_bytes(plan.frees));
            }
            for id in &plan.orphans {
                println!("  {id} still works; its recorded parent is now shown as deleted");
            }
        }
        "gc" => {
            let (items, errors) = if dry_run {
                (checkpoint::plan_gc(dir), Vec::new())
            } else {
                checkpoint::run_gc(dir)
            };
            if items.is_empty() && errors.is_empty() {
                println!("nothing to collect");
            }
            let verbed = if dry_run { "would remove" } else { "removed" };
            let mut total = 0u64;
            for item in &items {
                total += item.frees;
                println!(
                    "{verbed} {}  ({}, {})",
                    item.path.display(),
                    item.reason,
                    human_bytes(item.frees)
                );
            }
            if items.len() > 1 {
                println!("total {}", human_bytes(total));
            }
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("chm: {e}");
                }
                return Err(format!("{} item(s) could not be removed", errors.len()));
            }
        }
        "export" => {
            // `--all` and an explicit id are the same code path with a
            // different id list, so a bundle written either way is identical.
            let (ids, out) = if opts.all {
                (Vec::new(), positionals[2])
            } else {
                (vec![positionals[2].to_string()], positionals[3])
            };
            let report = bundle::export(dir, &ids, Path::new(out.as_str()), opts.with_base)?;
            println!(
                "exported {} revision(s) to {}",
                report.revisions.len(),
                report.bundle.display()
            );
            for id in &report.revisions {
                println!("  {id}");
            }
            if report.base_files > 0 {
                println!(
                    "  plus the base snapshot: {} file(s), {}",
                    report.base_files,
                    human_bytes(report.base_apparent)
                );
            }
            println!("  {} stored", human_bytes(report.stored));
            let saved = report.apparent.saturating_sub(report.stored);
            if saved > 0 {
                println!(
                    "  {} of their {} is shared between revisions and stored once",
                    human_bytes(saved),
                    human_bytes(report.apparent)
                );
            }
        }
        "import" => {
            let src = Path::new(positionals[2].as_str());
            if dry_run {
                for line in bundle::describe(src)? {
                    println!("{line}");
                }
            }
            let on_collision = if opts.skip_existing {
                bundle::OnCollision::Skip
            } else {
                bundle::OnCollision::Refuse
            };
            let report = bundle::import(src, dir, on_collision, dry_run)?;
            if report.base_written {
                println!("laid down the base snapshot in {}", dir.display());
            }
            let verbed = if dry_run { "would import" } else { "imported" };
            println!(
                "{verbed} {} revision(s) ({}) into {}",
                report.imported.len(),
                human_bytes(report.bytes),
                dir.display()
            );
            for id in &report.imported {
                println!("  {id}");
            }
            // What it cost, not what it looks like. Revisions are cloned from
            // each other on the way in, so the apparent total is a ceiling that
            // can exceed the real one by an order of magnitude.
            if !dry_run && !report.imported.is_empty() {
                println!("  {} written to disk", human_bytes(report.written));
                let shared = report.bytes.saturating_sub(report.written);
                if shared > 0 {
                    println!("  {} of that is shared between them", human_bytes(shared));
                }
            }
            for id in &report.skipped {
                println!("  {id} already here, left alone");
            }
            // A pin is a statement about the *source* machine's retention
            // budget, so it is reported rather than applied -- see
            // `bundle::NOT_CARRIED`.
            for id in &report.pinned_at_source {
                println!("  {id} was pinned at the source; `pin` it here if you agree");
            }
            if !report.imported.is_empty() && !dry_run {
                println!(
                    "HEAD is unchanged; `chm rollback {} <REVISION_ID>` to move there",
                    dir.display()
                );
            }
        }
        _ => return Err(format!("unknown revisions verb `{verb}`")),
    }
    Ok(ExitCode::SUCCESS)
}

/// How long ago a revision was taken, for the `chm revisions` timeline.
///
/// The id already carries the millisecond timestamp, but reading a point in
/// time out of a 13-digit epoch is not something a person does — and with
/// continuous snapshots the list is no longer a handful of deliberate suspends
/// you remember making, it is a timeline you have to navigate. "22m ago" is the
/// column that makes "put me back to before I broke it" answerable.
///
/// Relative rather than absolute deliberately: the question asked of a timeline
/// is nearly always *how far back*, and a clock time makes the reader do the
/// subtraction. Coarse on purpose — a resolution finer than the cadence would
/// imply a precision the cadence does not have.
fn relative_age(created_at_ms: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    // A revision from the future is a clock that moved, not a negative age.
    // Saturating keeps it merely wrong rather than absurd (u64 would wrap).
    let secs = now.saturating_sub(created_at_ms) / 1000;
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

/// A duration at a scale a person plans around. Used for the reachable-history
/// window, where "150s" invites arithmetic and "2m 30s" does not.
fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 if secs.is_multiple_of(60) => format!("{}m", secs / 60),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        _ if secs.is_multiple_of(3600) => format!("{}h", secs / 3600),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

/// Bytes at a scale a person can act on. Disk-usage output exists to answer
/// "what is using 40 GB?", and a 17-digit number does not answer it.
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// `chm rollback <SNAPSHOT_DIR> <REVISION_ID>` — roll a snapshot back to an
/// archived revision (appended as a fresh HEAD; history is preserved).
fn rollback_cmd(raw: &[String]) -> Result<ExitCode, String> {
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") || positionals.len() != 2 {
        eprintln!(
            "usage: chm rollback <SNAPSHOT_DIR> <REVISION_ID>\n\
             \n\
             Roll the snapshot back to an archived revision: it becomes a fresh\n\
             HEAD descending from the target (history is preserved, not rewound).\n\
             The target must still be `resumable`. Then `chm resume <DIR>`."
        );
        return if positionals.len() == 2 {
            Ok(ExitCode::SUCCESS)
        } else {
            Err("expected a snapshot directory and a revision id".to_string())
        };
    }
    let dir = PathBuf::from(positionals[0]);
    let rev_id = positionals[1];
    checkpoint::rollback(&dir, rev_id)?;
    eprintln!(
        "chm: rolled {} back to {rev_id} (resume it with `chm resume {}`)",
        dir.display(),
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn connect(args: &ConnectArgs) -> Result<ExitCode, String> {
    if !args.no_stop_daemon {
        stop_daemon_vm_if_present(&args.socket_path)?;
    }
    run_as(&args.run, runs::Kind::Connect)
}

fn stop_daemon_vm_if_present(socket_path: &Path) -> Result<(), String> {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(stream) => stream,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            return Ok(());
        }
        Err(e) => {
            return Err(format!(
                "connect to daemon socket {}: {e}",
                socket_path.display()
            ));
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set daemon socket timeout: {e}"))?;
    stream
        .write_all(b"stop\n")
        .map_err(|e| format!("send daemon stop: {e}"))?;
    stream.flush().ok();

    let mut reply = String::new();
    match stream.read_to_string(&mut reply) {
        Ok(_) => {}
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
            ) => {}
        Err(e) => return Err(format!("read daemon stop reply: {e}")),
    }
    let trimmed = reply.trim();
    if !trimmed.is_empty() {
        eprintln!("chm connect: {trimmed}");
    }
    Ok(())
}

fn run(args: &Args) -> Result<ExitCode, String> {
    run_as(args, runs::Kind::Run)
}

/// The shared body of `chm run` and `chm connect`.
///
/// `kind` is passed in rather than inferred, because the two differ only in
/// what the caller meant and a guess would show up as a mislabelled row in
/// `chm ps`. Inferring it from `--session-lock` was the obvious shortcut and is
/// wrong: that flag says the app wants to watch the session, not which command
/// was typed.
fn run_as(args: &Args, kind: runs::Kind) -> Result<ExitCode, String> {
    let dir = &args.snapshot_dir;
    let loaded = load_snapshot(dir)?;
    startup::stamp("snapshot parsed");

    // Guest-clock-rate check (#104). Applies to both GIC paths: a frequency
    // mismatch is a property of the capture host, not of interrupt routing.
    cntfrq_guard(&loaded.state_json)?;

    // AArch32-at-EL0 check (V1.4): the capture host advertised 32-bit
    // userspace and this Mac has none, so a 32-bit exec wedges the vCPU.
    aarch32_guard(&loaded.snap)?;
    icache_dic_guard(&loaded.snap)?;
    asid_width_guard(&loaded.snap)?;

    // Room-to-grow check (#259): a capture sized for the cloud instance's
    // original volume arrives with a root filesystem that may have no space to
    // install anything. Never fatal -- the guest still runs, and the fix is the
    // guest's to apply.
    if let Some(n) = disktail::tail_notice(dir, &loaded.state_json) {
        eprintln!("chm: note: {n}");
    }

    // One interrupt path. Apple's managed GIC cannot deliver LPIs (proven on
    // hardware: ICH List Registers are EL2/nested-only, and no
    // PROPBASER/PENDBASER/ITS API exists), so it could never run a stock
    // cloud-hypervisor arm64 capture — every such guest wires its virtio
    // completions through the ITS. It also cannot cold-boot: `hv_gic_create`
    // refuses any layout with the redistributors below the distributor, which
    // is the layout Linux expects. Measured across every capture we hold, the
    // managed path routed nothing.
    //
    // So the product runs one GIC. The hardware evidence for *why* survives
    // as pinned boundary tests against `hypervisor::hvf::gic` (see
    // `hypervisor/tests/hvf_boot.rs`); what is retired is the runtime path,
    // not the proof.
    run_usgic(args, loaded, kind)
}

/// Did **chm** choose the moment this session ended, rather than the user or the
/// guest?
///
/// A deadline or an idle window is chm stopping a guest that was still going.
/// The user picked a *limit*, not this instant, so we owe them the state.
/// Tearing down a writable overlay here is a power cut: measured before this
/// existed, a guest wrote a file, ran `sync`, hit `--max-seconds`, and a later
/// session found nothing — and the run had also cleared the resumable HEAD it
/// started from, so the deadline destroyed more history than it created.
///
/// A guest power-off, a closed console and a Ctrl-C are all somebody choosing
/// deliberately to stop *here*, and nothing is owed. That distinction is the
/// whole rule, and it is why this is not simply "always checkpoint".
///
/// An `Err` is a supervisor failure, not a choice, and does not qualify: the
/// session state is not known to be sound, so the existing clear-or-retire path
/// still runs.
///
/// V9.1a is what makes this affordable. A capture is now a delta against the
/// previous one, so suspending on a deadline costs ~1-2s and a few MiB, rather
/// than the ~4.5s and ~3.4GB it would have cost when this was filed (#154).
fn chm_initiated_stop(coordinator: &Result<Outcome, String>) -> bool {
    matches!(coordinator, Ok(Outcome::MaxSeconds) | Ok(Outcome::Idle(_)))
}

/// The sentence printed beside a teardown checkpoint that replaced an earlier
/// one, naming the revision it displaced and the command that gets back to it.
///
/// #288: a `chm ctl stop` on a guest that had stopped answering wrote a
/// checkpoint of the wedge over the last good state, reported `ok  stopped`,
/// and the next `start` came back still wedged. The state was never actually
/// destroyed — `write_checkpoint` archives the HEAD it supersedes — but nothing
/// at the moment of the mistake said so, and a user with no clone of the
/// workspace had no reason to believe the sandbox was recoverable at all.
///
/// This deliberately does **not** try to decide whether the guest was healthy.
/// The available signal is console silence, and a resumed guest emits nothing
/// until it receives input — documented behaviour of this stack, and §49
/// recorded a whole day lost to reading that silence as death. A heuristic here
/// would refuse legitimate stops and still miss real wedges. State the fact,
/// hand over the remedy, let the reader judge.
pub(crate) fn superseded_note(superseded: Option<&str>, dir: &Path) -> String {
    match superseded {
        // A first checkpoint replaced nothing, so there is no way back to offer
        // and saying so would be noise.
        None => String::new(),
        Some(id) => format!(
            "chm: this replaced revision {id} as the resume point. If the guest was \
             not healthy when it stopped, go back with `chm rollback {} {id}`.\n",
            dir.display()
        ),
    }
}

pub(crate) enum Outcome {
    PoweredOff,
    MaxSeconds,
    Idle(u64),
    ConsoleClosed,
    Interrupted,
    /// A resource limit was hit; the guest was stopped to protect the host. The
    /// string names the limit for the operator.
    LimitExceeded(String),
}

/// An [`MsiSink`] that delivers an SPI/LPI into a userspace-GIC vCPU from another
/// thread. The console (and, later, virtio) threads run OFF the vCPU thread, and
/// the raw IRQ-line assert is owning-thread only — so we enqueue the INTID on the
/// vCPU's injection queue and wake it; the vCPU drains + delivers it through the
/// software GIC at its next `run()` entry.
struct UsgicMsiSink {
    router: Arc<UsgicSpiRouter>,
}

impl MsiSink for UsgicMsiSink {
    fn deliver_spi(&self, intid: u32) {
        // Route the SPI to the vCPU its GICD_IROUTER affinity names (not always
        // the boot CPU), then wake that core. Single-vCPU resolves to vCPU 0.
        self.router.deliver_spi(intid);
    }
}

/// An [`its::LpiSink`] that delivers an ITS-resolved LPI into a userspace-GIC
/// vCPU from a device thread. A virtio completion resolves `(DeviceID, EventID)`
/// through the captured ITS tables into a physical LPI INTID (>= 8192); we
/// enqueue it on the vCPU's injection queue and wake it, and the vCPU drains +
/// delivers it through the software GIC at its next `run()` entry. This is the
/// disk/net-completion path a stock ITS/LPI snapshot needs.
struct UsgicLpiSink {
    queue: Arc<Mutex<Vec<u32>>>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl its::LpiSink for UsgicLpiSink {
    fn deliver(&self, lpi: its::Lpi) {
        self.queue.lock().unwrap().push(lpi.intid);
        (self.wake)();
    }
}

/// `chm run --userspace-gic`: drive the shared engine with an interactive
fn run_usgic(args: &Args, loaded: Loaded, kind: runs::Kind) -> Result<ExitCode, String> {
    // Announce the run for the lifetime of the session (#225). The session lock
    // below answers "is *this sandbox* live?" for a caller that already knows
    // which sandbox it means; this answers "what is running on this machine?"
    // for a caller that does not, which is the question the app could not ask.
    let _registration = runs::register(
        kind,
        &runs::label_for(&args.snapshot_dir),
        &args.snapshot_dir.display().to_string(),
        loaded.num_vcpus,
        loaded.total_ram / (1 << 20),
        // `chm run` and `chm connect` have no `--expose` (#341: cold boot has
        // the networking flags, the snapshot path has the checkpoints, and the
        // two sets are disjoint). No ingress to declare, so declare none.
        &[],
    )
    .unwrap_or_else(|e| {
        eprintln!("chm: warning: could not record this run: {e}");
        None
    });

    // Session-liveness lock, held for the whole interactive session. The app
    // reconciles which sandboxes are live by scanning these files, so it has to
    // be taken on the path the guest actually runs on. Held in a binding rather
    // than dropped immediately so the file survives until the session returns.
    let _session_lock = args.session_lock.as_deref().and_then(|path| {
        match SessionLock::acquire(path) {
            Ok(lock) => Some(lock),
            Err(e) => {
                eprintln!(
                    "chm: warning: could not write session lock {}: {e}",
                    path.display()
                );
                None
            }
        }
    });
    let cfg = UsgicConfig {
        dir: &args.snapshot_dir,
        quiet: args.quiet,
        checkpoint: args.checkpoint,
        egress_policy: args.egress_policy.as_deref(),
        proxy_rules: args.proxy_rules.as_deref(),
        allow_local_egress: args.allow_local_egress,
        limits_file: args.limits_file.as_deref(),
        checkpoint_source: "connect",
        interactive: true,
        snapshot_every: args.snapshot_every,
    };
    let outcome = run_usgic_engine(&cfg, loaded, &mut |s| {
        run_console(s.uart, s.running, args, s.limits, s.overlay_dir)
    })?;
    if !args.quiet {
        match &outcome {
            Outcome::PoweredOff => eprintln!("\nchm: guest powered off."),
            Outcome::Interrupted => eprintln!("chm: session closed; VM shut down."),
            Outcome::ConsoleClosed => eprintln!("chm: console closed; stopping."),
            Outcome::MaxSeconds => eprintln!("chm: reached the maximum session time."),
            Outcome::Idle(secs) => eprintln!("chm: guest idle for {secs}s — stopping."),
            Outcome::LimitExceeded(reason) => eprintln!("chm: resource limit hit ({reason})."),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Everything a userspace-GIC session needs that does not come from the snapshot.
///
/// The engine below is shared by `chm run` and the `chm serve` daemon, which
/// differ only in how they supervise a live guest: the CLI owns a terminal and
/// a keyboard, the daemon owns a console ring and a stop flag. Keeping the
/// difference in this struct (plus the `supervise` callback) means the hard
/// part — multi-threaded vCPU orchestration, the cross-vCPU SGI table, ITS/LPI
/// virtio wiring and checkpoint capture — exists exactly once.
pub(crate) struct UsgicConfig<'a> {
    pub dir: &'a Path,
    /// Suppress the banner and progress chatter (always set for the daemon,
    /// whose stderr is not a user-facing console).
    pub quiet: bool,
    /// Enable live checkpoints (suspend on a clean external stop, resume from a
    /// saved capture on the next start).
    pub checkpoint: bool,
    pub egress_policy: Option<&'a Path>,
    pub proxy_rules: Option<&'a Path>,
    pub allow_local_egress: bool,
    pub limits_file: Option<&'a Path>,
    /// Recorded in the checkpoint so an operator can see which entry point wrote
    /// it (`connect` for the CLI, `daemon` for `chm serve`).
    pub checkpoint_source: &'static str,
    /// Own the terminal: raw mode, signal handlers and a stdin pump into the
    /// guest's PL011. The daemon's console is read-only and its stdin belongs to
    /// the service manager, so it opts out.
    pub interactive: bool,
    /// Live-snapshot cadence in seconds, from `--snapshot-every`. `None` defers
    /// to `CHM_SNAPSHOT_INTERVAL_SECS`; see [`snapshot_interval`].
    pub snapshot_every: Option<u64>,
}

/// The live handles a supervisor needs while the guest runs.
///
/// Handed to the `supervise` callback once every vCPU is released. The callback
/// returns when the session should end; the engine then performs the ordered
/// teardown (stop, kick every vCPU out of `run()`, join, capture) regardless of
/// which supervisor asked for it.
pub(crate) struct UsgicSession<'a> {
    pub uart: &'a Arc<Pl011>,
    pub running: &'a Arc<AtomicBool>,
    pub limits: &'a limits::LimitsDoc,
    pub overlay_dir: &'a Path,
    /// One per vCPU: forces that core out of `hv_vcpu_run` from another thread.
    pub exits: &'a [ExitSignal],
    /// Delivers host bytes to the guest's serial console. The CLI drives this
    /// from stdin; the daemon exposes it as the `input` command.
    pub input: &'a console::ConsoleInput,
}

/// Resume a snapshot onto the **userspace GICv3** (no managed GIC) with an
/// interactive serial console. This is the path for a stock ITS/LPI-routed
/// snapshot — the capture Apple's managed GIC cannot deliver completions for.
///
/// HVF binds a vCPU to the thread that created it, so each vCPU is created + run
/// on its own thread; this function creates the VM + maps RAM on the orchestrator
/// thread, spawns one thread per vCPU (each restores its vCPU and hands its
/// injection queue + wake back), then builds the cross-vCPU SGI table, wires the
/// virtio device model + interactive console, releases the vCPU threads, and
/// drains the console until the session ends. Handles single- and multi-vCPU
/// (SMP) snapshots, including live checkpoint/suspend: each vCPU captures its
/// own state on its owning thread (HVF binds a vCPU to the thread that created
/// it) and the orchestrator assembles them into one checkpoint. The shipping
/// managed-GIC path is untouched.
pub(crate) fn run_usgic_engine(
    cfg: &UsgicConfig<'_>,
    loaded: Loaded,
    supervise: &mut dyn FnMut(&UsgicSession<'_>) -> Result<Outcome, String>,
) -> Result<Outcome, String> {
    let dir = cfg.dir;
    let n = loaded.num_vcpus as usize;
    if n == 0 {
        return Err("snapshot declares no vCPUs".into());
    }

    // Refuse to pair a guest's remembered filesystem with a different one on
    // disk. See `checkpoint::overlay_drift` for the measured failure this
    // prevents: the guest resumes, serves RAM-only work, then wedges the first
    // time it touches the diverged tree -- and the teardown capture then writes
    // that hung kernel over the last good checkpoint.
    let drift = if cfg.checkpoint && checkpoint::has_checkpoint(dir) {
        checkpoint::overlay_drift(dir)
    } else {
        None
    };
    if let Some(drift) = drift {
        if env::var_os("CHM_ALLOW_OVERLAY_DRIFT").is_none() {
            return Err(format!(
                "disk overlays have changed since this checkpoint's RAM was captured \
                 ({} overlay file(s) recorded, {} now). Resuming would hand the guest \
                 kernel a filesystem it does not remember, which wedges it. This happens \
                 when a session writes to disk and exits without --checkpoint.\n  \
                 To resume the consistent RAM+disk pair a revision stored: \
                 chm revisions {} then chm rollback {} <rev-id>\n  \
                 To discard the checkpoint and cold-boot: remove {}\n  \
                 To proceed anyway: CHM_ALLOW_OVERLAY_DRIFT=1",
                drift.recorded_files,
                drift.live_files,
                dir.display(),
                dir.display(),
                checkpoint::checkpoint_dir(dir).display(),
            ));
        }
        eprintln!(
            "chm: warning: resuming despite overlay drift ({} recorded, {} live) \
             because CHM_ALLOW_OVERLAY_DRIFT is set; the guest may wedge",
            drift.recorded_files, drift.live_files
        );
    }

    // Resume from a live checkpoint when one exists and checkpoints are enabled.
    // Accepted only when it describes every vCPU this snapshot declares: the
    // userspace-GIC redistributor, pending set and active INTID are all
    // per-vCPU, so a checkpoint that covers fewer cores cannot be spread across
    // more without handing secondaries the boot CPU's interrupt state.
    let resume_state: Option<Arc<CheckpointState>> = if cfg.checkpoint
        && checkpoint::has_checkpoint(dir)
    {
        match checkpoint::read_checkpoint(dir) {
            Ok(state) if state.covers_usgic_vcpus(n) => Some(Arc::new(state)),
            Ok(state) => {
                let why = if state.usgic.is_none() && state.usgic_cpus.is_empty() {
                    "is not a userspace-GIC capture".to_string()
                } else {
                    let covered = (0..=state.vcpus.len())
                        .take_while(|id| state.usgic_for(*id).is_some())
                        .count();
                    format!("covers {covered} vCPU(s) but this snapshot declares {n}")
                };
                eprintln!("chm: warning: checkpoint {why}; cold-booting");
                checkpoint::clear_checkpoint(dir);
                None
            }
            Err(e) => {
                eprintln!("chm: warning: ignoring checkpoint ({e}); cold-booting");
                checkpoint::clear_checkpoint(dir);
                None
            }
        }
    } else {
        None
    };
    let resuming = resume_state.is_some();

    if !cfg.quiet {
        let shown_ranges = if resuming {
            checkpoint::memory_ranges_path(dir)
        } else {
            loaded.mem_ranges.clone()
        };
        banner(dir, &shown_ranges, loaded.num_vcpus, loaded.total_ram, "userspace GICv3");
        if resuming {
            eprintln!("chm: resuming a userspace-GIC checkpoint (restored, not cold-booted).\n");
        } else {
            eprintln!(
                "chm: userspace GICv3 — rehydrating a {n}-vCPU ITS/LPI snapshot, \
                 the routing Apple's managed GIC cannot deliver.\n"
            );
        }
    }

    // Device model: a bus with a real PL011 at the guest's serial base, its
    // line/interrupt state seeded from the snapshot so host keystrokes deliver.
    let (uart, bus) = build_vm_ops(&loaded.state_json);
    let vm_ops: Arc<dyn VmOps> = Arc::new(ChmVmOps::new(bus.clone()));

    let mem_ranges = if resuming {
        checkpoint::memory_ranges_path(dir)
    } else {
        loaded.mem_ranges.clone()
    };
    let snap = Arc::new(loaded.snap);
    // The orchestrator keeps the memory layout so it can dump guest RAM into a
    // checkpoint on suspend, once, after every vCPU thread has joined.
    let mem_mappings = snap.mem_mappings.clone();
    let snap_num_irq = snap.num_irq;

    // Create the VM + map guest RAM on THIS thread; each vCPU is then created and
    // run on its own thread (HVF binds a vCPU to its creating thread). `hv` and
    // `prepared` (RAM backings + VM) are kept alive for the whole session.
    let hv = hypervisor::new().map_err(|e| {
        format!(
            "hypervisor::new() failed: {e}\n\
             (is the binary code-signed with the hypervisor entitlement? \
             see scripts/build-chm.sh)"
        )
    })?;
    startup::stamp("hypervisor opened");
    let prepared = rehydrate::prepare_usgic_vm(hv.as_ref(), &snap, &mem_ranges)
        .map_err(|e| format!("prepare userspace-GIC VM: {e}"))?;
    startup::stamp("VM created + guest RAM mapped");
    let guest_mem = prepared.guest_mem.clone();
    arm_icache_maintenance(&snap, guest_mem.as_ref());
    let vm = prepared.vm.clone();
    let seed = prepared.seed();
    // ONE virtual-counter clock for the whole VM. Every vCPU programs the offset
    // it publishes, which is what keeps the guest's `CNTVCT_EL0` coherent across
    // cores; when the counter is rate-scaled, `spawn_vtimer_stepper` below is
    // what moves it. See `hypervisor::hvf::VtimerClock`.
    let clock = rehydrate::counter_clock(&snap, resume_state.as_deref())
        .unwrap_or_else(|| VtimerClock::new(0, 0, host_counter_hz()));

    let running = Arc::new(AtomicBool::new(true));
    let outcome: Arc<Mutex<Option<Result<Outcome, String>>>> = Arc::new(Mutex::new(None));

    // Per-vCPU setup handshake: each thread creates + restores its vCPU, then
    // sends back its id and delivery handles. Once every vCPU reports in, the
    // orchestrator builds the cross-vCPU SGI table + wires the device model, then
    // releases each thread through its go channel (which carries the completed
    // SGI table). At suspend each thread returns its own capture on the capture
    // channel, keyed by vCPU id.
    struct CpuSetup {
        id: usize,
        inject: Arc<Mutex<Vec<u32>>>,
        wake: Arc<dyn Fn() + Send + Sync>,
        exit: Arc<dyn Fn() + Send + Sync>,
        /// Run-progress counter, bumped once per `hv_vcpu_run` iteration. Read by
        /// the run watchdog to detect a vCPU wedged inside a single entry.
        progress: Option<Arc<AtomicU64>>,
        handle: UsgicCpuHandle,
    }
    let (setup_tx, setup_rx) = mpsc::channel::<Result<CpuSetup, String>>();
    let (capture_tx, capture_rx) = mpsc::channel::<(usize, UsgicCapture)>();
    let mut go_txs: Vec<mpsc::Sender<Arc<Vec<UsgicCpuHandle>>>> = Vec::with_capacity(n);

    // Whether a vCPU sends its register file at teardown used to be gated on
    // `--checkpoint`, decided here at spawn. But whether the result is worth
    // keeping cannot be known until the run ends — a deadline or an idle window
    // turns an ordinary run into a suspend (V9.6), and by then these threads
    // have exited. The gate therefore made "suspend on a deadline" impossible to
    // implement downstream: there was nothing left to assemble.
    //
    // Every vCPU now captures unconditionally and the orchestrator decides
    // whether to keep it. That is what the comment at the send site already
    // claimed the code did, and it is cheap for the reason given there: a
    // capture is a register file plus this core's software-GIC state, taken on a
    // thread that is exiting anyway. The expensive part of a checkpoint is the
    // guest RAM dump, which happens once, on the orchestrator, and is still
    // gated on actually wanting the checkpoint.

    // The live-checkpoint rendezvous. Present even when continuous snapshots are
    // off: the per-vCPU cost is one relaxed atomic load per `run()` return, and
    // making it conditional would mean two versions of the run loop.
    let gate: Arc<livesnap::CheckpointGate<UsgicCapture>> =
        Arc::new(livesnap::CheckpointGate::new(n));

    let mut threads = Vec::with_capacity(n);
    for id in 0..n {
        let (go_tx, go_rx) = mpsc::channel::<Arc<Vec<UsgicCpuHandle>>>();
        go_txs.push(go_tx);

        let vm = vm.clone();
        let seed = seed.clone();
        let snap = snap.clone();
        let vm_ops = vm_ops.clone();
        let running = running.clone();
        let outcome = outcome.clone();
        let setup_tx = setup_tx.clone();
        let resume = resume_state.clone();
        let clock = clock.clone();
        let capture_tx = capture_tx.clone();
        let gate = gate.clone();

        let t = thread::Builder::new()
            .name(format!("chm-usgic-vcpu{id}"))
            .spawn(move || {
                // Create + restore this vCPU on its own thread.
                let mut vcpu = match rehydrate::restore_usgic_vcpu(
                    &vm,
                    &seed,
                    &snap,
                    resume.as_deref(),
                    id,
                    &vm_ops,
                    &clock,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = setup_tx.send(Err(format!("restore_usgic_vcpu {id}: {e}")));
                        return;
                    }
                };
                let inject = match vcpu.usgic_inject_queue() {
                    Some(q) => q,
                    None => {
                        let _ =
                            setup_tx.send(Err(format!("vCPU {id} exposed no userspace-GIC queue")));
                        return;
                    }
                };
                let wake = vcpu
                    .wake_signal()
                    .unwrap_or_else(|| Arc::new(|| {}) as Arc<dyn Fn() + Send + Sync>);
                let exit = vcpu
                    .exit_signal()
                    .unwrap_or_else(|| Arc::new(|| {}) as Arc<dyn Fn() + Send + Sync>);
                let progress = vcpu.run_progress();
                let handle = match rehydrate::usgic_cpu_handle(&mut vcpu) {
                    Some(h) => h,
                    None => {
                        let _ = setup_tx.send(Err(format!("vCPU {id} is not an HVF vCPU")));
                        return;
                    }
                };
                if setup_tx.send(Ok(CpuSetup { id, inject, wake, exit, progress, handle })).is_err()
                {
                    return;
                }

                // Wait for the completed cross-vCPU SGI table (also the go signal)
                // before entering the guest, so the device model + console + SGI
                // routing are all wired first. A dropped sender means the
                // orchestrator aborted setup; exit cleanly.
                let table = match go_rx.recv() {
                    Ok(t) => t,
                    Err(_) => return,
                };
                rehydrate::usgic_set_cpu_table(&mut vcpu, table);

                // Baseline for the live-checkpoint epoch, read before the
                // snapshotter thread can exist (it is spawned only after every
                // vCPU has been released through this gate). A vCPU that first
                // read the epoch after a request was already in flight would
                // start level with it and never service it.
                let mut my_epoch = gate.epoch();

                // Run the guest until a host-side stop (running=false) or a guest
                // power-off. The run() body handles the software GIC, the self-
                // managed vtimer, the WFI idle halt, and draining cross-thread
                // (including cross-vCPU SGI) injections internally.
                while running.load(Ordering::Acquire) {
                    match vcpu.run() {
                        Ok(VmExit::Ignore) => {}
                        Ok(VmExit::Shutdown | VmExit::Reset) => {
                            *outcome.lock().unwrap() = Some(Ok(Outcome::PoweredOff));
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Ok(other) => {
                            *outcome.lock().unwrap() =
                                Some(Err(format!("vCPU {id} unexpected exit: {other:?}")));
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Err(e) => {
                            *outcome.lock().unwrap() = Some(Err(format!("vCPU {id} run: {e}")));
                            running.store(false, Ordering::Release);
                            break;
                        }
                    }

                    // Live checkpoint rendezvous. One relaxed load when nothing
                    // is pending, which is the overwhelmingly common case.
                    //
                    // This sits *after* the exit is fully serviced, not before,
                    // and that ordering is what makes disk quiescence free:
                    // `DeviceCore::notify` drains and publishes a block request
                    // synchronously on this thread as part of handling the trap,
                    // so a vCPU that reaches here provably has no half-finished
                    // request in guest memory. An unconsumed entry still sitting
                    // in an avail ring is fine -- that is ordinary suspended
                    // state, and the notify handler drains it on resume.
                    let e = gate.epoch();
                    if e != my_epoch {
                        my_epoch = e;
                        let captured = hvf_checkpoint::capture_usgic_vcpu(&mut vcpu)
                            .map_err(|err| format!("capture: {err}"));
                        gate.arrive_and_park(id, e, captured);
                    }
                }

                // Suspend capture. A vCPU's register file and software-GIC models
                // can only be read on the thread that created it (HVF binds a
                // vCPU to its owning thread), so every vCPU captures itself here
                // and sends the result to the orchestrator, which assembles all
                // of them and writes one checkpoint. Guest RAM is deliberately
                // NOT dumped here: the mappings are owned by `prepared` on the
                // orchestrator thread and outlive these threads, so the dump
                // belongs there, once, rather than on the boot CPU.
                //
                // Capture unconditionally rather than checking the run outcome
                // first: whether the checkpoint is worth keeping is the
                // orchestrator's call, and a thread that skipped sending because
                // it raced another vCPU's error would hang the collector. The
                // same reasoning is why this is no longer gated on
                // `--checkpoint` either — see the note at the channel.
                let captured = hvf_checkpoint::capture_usgic_vcpu(&mut vcpu)
                    .map_err(|e| format!("capture: {e}"));
                let _ = capture_tx.send((id, captured));
                // `vcpu` (and its VM ref) drops here, on the owning thread.
            })
            .map_err(|e| format!("spawn userspace-GIC vCPU thread {id}: {e}"))?;
        threads.push(t);
    }
    // Drop the orchestrator's spare senders so the collectors below terminate.
    drop(setup_tx);
    drop(capture_tx);

    // Collect every vCPU's setup, indexed by id. Abort (stop + join) on failure.
    let mut collected: Vec<Option<CpuSetup>> = (0..n).map(|_| None).collect();
    for _ in 0..n {
        match setup_rx.recv() {
            Ok(Ok(s)) => {
                let id = s.id;
                collected[id] = Some(s);
            }
            Ok(Err(e)) => {
                running.store(false, Ordering::Release);
                drop(go_txs); // release any threads still waiting at the gate
                for t in threads {
                    let _ = t.join();
                }
                return Err(e);
            }
            Err(_) => {
                running.store(false, Ordering::Release);
                drop(go_txs);
                for t in threads {
                    let _ = t.join();
                }
                return Err("a userspace-GIC vCPU thread exited before setup".into());
            }
        }
    }
    let setups: Vec<CpuSetup> = collected.into_iter().map(|s| s.expect("all ids present")).collect();
    startup::stamp("vCPUs restored");

    // vCPU 0's handles drive the device sinks (SPIs/LPIs are delivered to the
    // boot CPU) and the serial console; collect every vCPU's exit signal so the
    // stop can force each out of `hv_vcpu_run`. The SGI table takes ownership of
    // each vCPU's delivery handle, indexed by id.
    let inject0 = setups[0].inject.clone();
    let wake0 = setups[0].wake.clone();
    let all_exits: Vec<Arc<dyn Fn() + Send + Sync>> = setups.iter().map(|s| s.exit.clone()).collect();
    // Every vCPU's WFI wake fd. `all_exits` alone is not enough to stop the
    // world for a live checkpoint: `hv_vcpus_exit` forces a vCPU out of
    // `hv_vcpu_run`, but a core idling in the host-side WFI park has already
    // left the guest and would sit there until its poll timeout. An idle VM is
    // exactly when a checkpoint is cheapest and most likely to be wanted, so
    // both signals are needed. (The vtimer stepper only needs `exits` because it
    // merely waits for `in_guest` to reach zero, which a parked vCPU satisfies.)
    let all_wakes: Vec<Arc<dyn Fn() + Send + Sync>> =
        setups.iter().map(|s| s.wake.clone()).collect();
    // Snapshot the run-progress counters alongside the exit signals, before
    // `setups` is consumed into the shared handle table below.
    let all_progress: Vec<Arc<AtomicU64>> =
        setups.iter().filter_map(|s| s.progress.clone()).collect();
    let sgi_table: Arc<Vec<UsgicCpuHandle>> =
        Arc::new(setups.into_iter().map(|s| s.handle).collect());

    let (limits, _src) = limits::resolve_limits(dir, cfg.limits_file);
    // Read the constant, never restate it: `create.rs` computes this same
    // directory when it ships a lineage's disks, and `checkpoint` fingerprints
    // it. Three spellings of one path is how a disk comes to be written where
    // nothing looks for it.
    let overlay_dir = dir.join(checkpoint::live_overlays_dir_name());
    // Durable audit trail (M29): record the session lifecycle and every denied
    // egress flow to a per-workspace append-only log, so an operator can review
    // what the sandbox did independent of the (guest-floodable) console.
    let audit = audit::AuditLog::open(dir);
    let egress_label = match resolve_egress_policy(&overlay_dir, cfg.egress_policy) {
        EgressResolution::Unrestricted => "unrestricted".to_string(),
        EgressResolution::Policy(p, _) => p.label().to_string(),
        EgressResolution::FailClosed(_) => "fail-closed:deny-all".to_string(),
    };
    audit.session_start(
        if resuming { "resume" } else { "cold" },
        n,
        loaded.total_ram / (1024 * 1024),
        &limits.summary(),
        &egress_label,
    );
    let session_started = Instant::now();

    // Wire the virtio device model onto the shared bus, routing each device's
    // completions through the captured ITS to a deliverable LPI sink that injects
    // into vCPU 0's software GIC — so a resumed stock ITS/LPI guest's disk/net I/O
    // actually completes. Net devices additionally need an off-thread NAT service.
    let usgic_lpi_sink: Arc<dyn its::LpiSink> = Arc::new(UsgicLpiSink {
        queue: inject0.clone(),
        wake: wake0.clone(),
    });
    // Held for the whole session and stopped at teardown. The daemon runs many
    // VMs in one process, so an accept loop left running past its VM would leak a
    // thread and hold its port for the life of the daemon.
    let mut running_proxy: Option<credproxy::server::RunningProxy> = None;
    // Host-side writers to guest memory that a live checkpoint must hold still.
    // Created before the device model is wired because the net service registers
    // itself as it starts.
    let quiesce = Arc::new(livesnap::Quiesce::new());
    let net_service = match wire_virtio(
        &bus,
        &guest_mem,
        &loaded.state_json,
        &overlay_dir,
        None, // no managed GIC
        // Reattach the previous run's disk overlay ONLY when we are genuinely
        // resuming that run's checkpoint. This used to be hardcoded `true`,
        // which paired a previous session's disk with this rehydrate's pristine
        // snapshot RAM — the restored page cache described the base image while
        // the disk carried someone else's writes, so the guest saw
        // `Input/output error` on reads it believed were cached (#110).
        resume_state.is_some(),
        cfg.egress_policy,
        &NatLimits {
            max_connections: limits.max_connections.map(|n| n as usize),
            max_bytes_per_sec: limits.max_bandwidth_kbps.map(|kbps| kbps * 125),
        },
        cfg.allow_local_egress,
        Some(usgic_lpi_sink),
        cfg.proxy_rules,
    ) {
        Ok(wired) => {
            if !wired.summary.is_empty() && !cfg.quiet {
                eprintln!("chm: virtio device model restored:");
                for d in &wired.summary {
                    eprintln!("chm:   - {d}");
                }
            }
            running_proxy = wired.proxy;
            let exits: Arc<Mutex<Vec<ExitSignal>>> = Arc::new(Mutex::new(all_exits.clone()));
            spawn_net_service(
                wired.net_devices,
                running.clone(),
                exits,
                audit.clone(),
                quiesce.clone(),
            )
        }
        Err(e) => {
            eprintln!("chm: warning: virtio device model not wired: {e}");
            None
        }
    };

    startup::stamp("virtio device model wired");

    // Interactive console. The serial sink routes a keystroke's line SPI to the
    // vCPU its GICD_IROUTER affinity names (via the shared distributor) and wakes
    // that core — so moving the serial IRQ's affinity (e.g. to CPU1) actually
    // delivers there. Single-vCPU routes to vCPU 0, unchanged.
    let spi_router = Arc::new(prepared.spi_router(sgi_table.clone()));
    let serial_sink: Arc<dyn MsiSink> = Arc::new(UsgicMsiSink {
        router: spi_router,
    });
    let serial_wake: Option<Arc<dyn Fn() + Send + Sync>> = Some(wake0);
    // Resolved once from the capture rather than three times from a constant:
    // three independent reads is three chances for the stdin pump, the reassert
    // thread and the daemon's console input to aim at different interrupts.
    let serial_spi = console::serial_spi_for(&loaded.state_json);
    // Terminal ownership is the CLI's alone. The daemon must not put the
    // service manager's stdin into raw mode, install console signal handlers,
    // or race a stdin pump for bytes it does not own.
    let raw_console = cfg.interactive.then(|| {
        let raw = RawConsole::enable();
        console::install_signal_handlers(raw.handle());
        console::spawn_stdin_pump(
            uart.clone(),
            serial_sink.clone(),
            raw.handle(),
            serial_wake.clone(),
            serial_spi,
        );
        raw
    });
    // Both paths need this: it re-asserts a level-triggered serial IRQ the guest
    // left pending, which is what keeps console output flowing after the guest
    // reopens its tty.
    let serial_reassert = console::spawn_serial_reassert(
        uart.clone(),
        serial_sink.clone(),
        serial_wake.clone(),
        running.clone(),
        serial_spi,
    );
    // Also available to a non-interactive supervisor (the daemon), so a console
    // consumer can type into the guest without owning this process's stdin.
    let console_input =
        console::console_input(uart.clone(), serial_sink, serial_wake, serial_spi);
    if !cfg.quiet {
        eprintln!(
            "chm: interactive console active — close this window or press Ctrl-A x \
             to end the session.\n"
        );
    }

    // Release every vCPU thread now that the device model + console + SGI table
    // are ready: hand each the completed cross-vCPU delivery table.
    for go_tx in &go_txs {
        let _ = go_tx.send(sgi_table.clone());
    }
    startup::stamp("guest released (VMM ready)");
    // Virtual-counter stepper: advances a rate-scaled guest's shared counter
    // offset with every vCPU stopped, so no core ever runs on a stale one. No
    // thread and no barrier when the counter runs at the host rate.
    let vtimer_stepper =
        spawn_vtimer_stepper(clock.clone(), all_exits.clone(), running.clone());

    // Run-progress watchdog: bounds how long any vCPU can stay wedged inside a
    // single `hv_vcpu_run` (#78/#60). Every vCPU publishes a counter it bumps per
    // entry; a counter that does not move for a full interval means that core is
    // stuck, so the watchdog forces it out to re-evaluate. Only armed when every
    // vCPU exposed both a counter and an exit signal, since a partial view would
    // let a stalled core go unwatched while reporting healthy.
    let run_watchdog = if env::var_os("CHM_DISABLE_RUN_WATCHDOG").is_none() {
        (all_progress.len() == all_exits.len() && !all_progress.is_empty())
            .then(|| spawn_run_watchdog(all_progress.clone(), all_exits.clone(), running.clone()))
    } else {
        None
    };

    // Continuous snapshots (#148): checkpoint a *running* guest on a cadence, so
    // a session that ends badly is not a session whose work is gone. Off unless
    // an interval is set, because a checkpoint costs a real freeze.
    let live_taken = Arc::new(AtomicU64::new(0));
    let live_snapshotter = spawn_live_snapshotter(LiveSnapshotter {
        gate: gate.clone(),
        quiesce: quiesce.clone(),
        net_kick: net_service.as_ref().map(|(_, k)| k.clone()),
        exits: all_exits.clone(),
        wakes: all_wakes.clone(),
        running: running.clone(),
        guest_mem: guest_mem.clone(),
        mem_mappings: mem_mappings.clone(),
        dir: dir.to_path_buf(),
        num_irq: snap_num_irq,
        vcpus: n,
        // Its own origin, so a timeline reader can tell a point the operator
        // asked for from one the cadence took. Same vocabulary either way, so
        // the entry point stays visible.
        origin: format!("{}-auto", cfg.checkpoint_source),
        quiet: cfg.quiet,
        every: cfg.snapshot_every,
        taken: live_taken.clone(),
    });

    let coordinator = supervise(&UsgicSession {
        uart: &uart,
        running: &running,
        limits: &limits,
        overlay_dir: &overlay_dir,
        exits: &all_exits,
        input: &console_input,
    });

    // Stop: clear the flag, force every vCPU out of any in-flight run(), join.
    running.store(false, Ordering::Release);
    // Release any vCPU waiting on an in-flight counter step first, so teardown
    // cannot block behind the stepper.
    clock.release();
    for exit in &all_exits {
        exit();
    }
    if let Some(h) = vtimer_stepper {
        let _ = h.join();
    }
    // The watchdog observes `running`, cleared above.
    if let Some(h) = run_watchdog {
        let _ = h.join();
    }
    // Stop accepting new proxied flows; in-flight connections finish on their own.
    if let Some(p) = running_proxy.take() {
        p.stop();
    }
    let _ = serial_reassert.join();
    // Stop the live snapshotter before the writers it holds still: it closes the
    // gate and the latch on its way out, so a vCPU or the net service parked for
    // a checkpoint in progress is released rather than joined-on forever.
    if let Some(h) = live_snapshotter {
        let _ = h.join();
    }
    gate.close();
    quiesce.close();
    if let Some((h, _)) = net_service {
        let _ = h.join();
    }
    for t in threads {
        let _ = t.join();
    }
    drop(raw_console);

    let vcpu_outcome = outcome.lock().unwrap().take();

    let chm_chose_the_moment = chm_initiated_stop(&coordinator);

    // Suspend capture. Every vCPU has sent its own register file + software-GIC
    // state from its owning thread and joined, so assemble them into one
    // checkpoint and dump guest RAM here — `prepared` still owns the RAM
    // mappings at this point and is not dropped until the end of this function.
    //
    // Only a clean external stop checkpoints. A guest power-off or a vCPU error
    // means the box is finished, so any stale checkpoint is cleared instead.
    if cfg.checkpoint || chm_chose_the_moment {
        if vcpu_outcome.is_none() {
            let written = collect_usgic_checkpoint(&capture_rx, snap_num_irq, n).and_then(|state| {
                checkpoint::write_checkpoint(
                    dir,
                    &state,
                    &guest_mem,
                    &mem_mappings,
                    cfg.checkpoint_source,
                )
            });
            match written {
                Ok(superseded) => {
                    if !cfg.quiet {
                        let cores = if n == 1 { "1 vCPU" } else { &format!("{n} vCPUs") };
                        // A user who did not pass --checkpoint has just had one
                        // written for them, so say why rather than leaving them
                        // to infer it from a changed HEAD.
                        if chm_chose_the_moment && !cfg.checkpoint {
                            eprintln!(
                                "\nchm: suspended rather than stopped — the time limit was \
                                 reached while the guest was still running, so its state was \
                                 saved ({cores}). Resume with `chm resume {}`.",
                                dir.display()
                            );
                        } else {
                            eprintln!(
                                "\nchm: suspended — userspace-GIC checkpoint saved ({cores}); \
                                 resume to continue."
                            );
                        }
                        eprint!("{}", superseded_note(superseded.as_deref(), dir));
                    }
                }
                Err(e) => {
                    eprintln!("chm: warning: could not write checkpoint: {e}");
                    retire_or_clear_head(dir, &live_taken, cfg.quiet);
                }
            }
        } else {
            retire_or_clear_head(dir, &live_taken, cfg.quiet);
        }
    } else {
        // Nothing asked for a teardown checkpoint, but the cadence may still
        // have left one as HEAD. Its overlays have moved on since, so leaving it
        // there guarantees the next start meets the #139 drift guard instead of
        // booting. File it and stand down.
        retire_or_clear_head(dir, &live_taken, cfg.quiet);
    }

    let resolved = match vcpu_outcome {
        Some(Ok(o)) => Ok(o),
        Some(Err(e)) => Err(e),
        None => Ok(coordinator.unwrap_or(Outcome::Interrupted)),
    };

    // Close the audit trail before returning, on the error path too: a session
    // that ended because a vCPU failed is precisely the one an operator needs a
    // durable record of, and an unmatched session-start would read as a session
    // that never ended.
    let outcome_label = match &resolved {
        Ok(Outcome::PoweredOff) => "powered-off".to_string(),
        Ok(Outcome::MaxSeconds) => "max-seconds".to_string(),
        Ok(Outcome::Idle(_)) => "idle".to_string(),
        Ok(Outcome::ConsoleClosed) => "console-closed".to_string(),
        Ok(Outcome::Interrupted) => "interrupted".to_string(),
        Ok(Outcome::LimitExceeded(reason)) => format!("limit-exceeded:{reason}"),
        Err(_) => "error".to_string(),
    };
    audit.session_stop(&outcome_label, session_started.elapsed().as_secs());

    let final_outcome = resolved?;

    // `prepared` (guest-RAM backings + VM) and `hv` are dropped here, after every
    // vCPU thread has joined (so every vCPU is destroyed before `hv_vm_destroy`).
    drop(prepared);
    drop(hv);
    Ok(final_outcome)
}



/// RAII guard for the interactive session-liveness lock file. Writes this
/// process's PID on creation and removes the file on drop. Because every
/// interactive exit path now returns through `resume_smp` (the `Ctrl-A x` escape
/// and the terminating-signal handlers request a graceful shutdown rather than
/// calling `process::exit`), this drop reliably runs, so the file's presence is
/// an honest "session is live" signal for a supervising app. Only an uncatchable
/// `SIGKILL` can leak it — which the PID lets the watcher detect as stale.
struct SessionLock {
    path: PathBuf,
}

impl SessionLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        fs::write(path, format!("{}\n", process::id()))?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// How often the virtual-counter stepper advances a rate-scaled clock, and how
/// long it will wait for every vCPU to leave the guest before giving up.
///
/// The period is the whole trade-off, and both sides of it were measured on a
/// 2-vCPU Graviton2 capture rather than reasoned about. Between steps the
/// guest's counter runs at the host rate, so it falls behind and each step jumps
/// it forward; the guest's worst-case error against real time is
/// `period * (1 - host_hz/guest_hz)`, and the barriers cost a share of wall
/// time that rises sharply as the period shrinks:
///
/// | period | stopped | worst-case guest clock error |
/// | ------ | ------- | ---------------------------- |
/// |   5 ms |  26.9%  |    4 ms |
/// |  10 ms |  10.1%  |    8 ms |
/// |  20 ms |   2.8%  |   16 ms |
/// |  50 ms |   0.8%  |   40 ms |
///
/// 20 ms is the knee: below it the barrier cost climbs steeply (vCPUs spend
/// their time bouncing in and out of the guest), above it the gain is small and
/// the clock gets lumpy. Overridable via `CHM_VTIMER_STEP_MS`.
const VTIMER_STEP_INTERVAL: Duration = Duration::from_millis(20);
const VTIMER_STEP_TIMEOUT: Duration = Duration::from_millis(20);

/// Spawn the virtual-counter stepper for a rate-scaled guest.
///
/// A guest captured on a host with a different counter frequency has its cached
/// `arch_timer_rate` baked in, so the only way to give it correct timekeeping is
/// to run its counter at the rate it already believes (see
/// [`hypervisor::hvf::VtimerClock`]). HVF offers an offset, not a rate, so the
/// offset has to keep moving — and moving it per-vCPU at run entry is what made
/// `CNTVCT_EL0` disagree across cores. This thread moves it once, for the whole
/// VM, with every vCPU stopped.
///
/// Returns `None` for an unscaled clock, which never moves and so needs no
/// thread and pays no barrier.
/// Everything the live snapshotter needs. A struct because a dozen positional
/// arguments is how a `guest_mem`/`mem_mappings` pair gets silently swapped.
struct LiveSnapshotter {
    gate: Arc<livesnap::CheckpointGate<UsgicCapture>>,
    quiesce: Arc<livesnap::Quiesce>,
    net_kick: Option<Arc<NetKick>>,
    exits: Vec<Arc<dyn Fn() + Send + Sync>>,
    wakes: Vec<Arc<dyn Fn() + Send + Sync>>,
    running: Arc<AtomicBool>,
    guest_mem: Arc<GuestMemory>,
    mem_mappings: Vec<rehydrate::MemMapping>,
    dir: PathBuf,
    num_irq: u32,
    vcpus: usize,
    origin: String,
    quiet: bool,
    /// The `--snapshot-every` value this run was started with, if any. See
    /// [`snapshot_interval`] for why a flag has to be able to say zero.
    every: Option<u64>,
    /// How many live checkpoints have landed, shared with teardown. Teardown
    /// needs to know whether HEAD is *this run's dying breath* or a point
    /// captured earlier from a healthy guest, because the two deserve opposite
    /// treatment and they are indistinguishable from the directory alone.
    taken: Arc<AtomicU64>,
}

/// How long the whole world may stay stopped for one live checkpoint before the
/// attempt is abandoned. Generous next to the 0.9–2.1 s a 2 GiB guest measures
/// on this hardware (V9.1a; it was 1.5–4.5 s when every dump was a full image),
/// but this is a *ceiling on damage*, not a target: crossing it means something
/// is wrong, and the honest response is a missed checkpoint rather than a torn
/// one. Deliberately not retuned down alongside the delta work — a timeout
/// sized to the common case turns a slow disk into a lost checkpoint.
const LIVE_SNAPSHOT_BARRIER_TIMEOUT: Duration = Duration::from_secs(30);

/// Decide what happens to HEAD when a run ends without writing a fresh
/// checkpoint over it.
///
/// Deleting is right when HEAD is this run's own dying breath. It is wrong when
/// the cadence put a healthy point there, so the two cases are separated by who
/// wrote it rather than by how the run ended.
fn retire_or_clear_head(dir: &Path, live_taken: &Arc<AtomicU64>, quiet: bool) {
    if live_taken.load(Ordering::Acquire) == 0 {
        checkpoint::clear_checkpoint(dir);
        return;
    }
    match checkpoint::retire_checkpoint(dir) {
        Some(id) if !quiet => eprintln!(
            "chm: kept the last live snapshot as {id}; \
             recover it with `chm rollback {} {id}`",
            dir.display()
        ),
        _ => {}
    }
}

/// Resolve the live-snapshot cadence from the flag and the environment.
///
/// The flag wins, including when it says zero, and that is the whole point of
/// the function. `CHM_SNAPSHOT_INTERVAL_SECS` is how a wrapper — a shell
/// profile, a CI job, the app's own environment — turns the cadence on for
/// everything it launches. Without a flag that can say *off*, a caller inside
/// that environment has no way to run one guest without it, and the only
/// remedy would be to unset a variable it does not own.
///
/// So `Some(0)` is a deliberate refusal and returns `None`, while a `None`
/// flag defers. An unparsable or zero environment value is off, because there
/// is no reading of `CHM_SNAPSHOT_INTERVAL_SECS=nonsense` under which freezing
/// someone's guest on an invented cadence is the helpful answer.
fn snapshot_interval(flag: Option<u64>, env_value: Option<String>) -> Option<Duration> {
    let secs = match flag {
        Some(n) => n,
        None => env_value
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0),
    };
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Checkpoint a running guest on a cadence, without stopping it (#148).
///
/// Returns `None` unless `--snapshot-every` or `CHM_SNAPSHOT_INTERVAL_SECS`
/// asks for it. Off by default deliberately: a checkpoint freezes the guest for
/// as long as it takes to dump RAM, so turning it on is a trade the operator
/// makes, not one we make for them.
fn spawn_live_snapshotter(s: LiveSnapshotter) -> Option<thread::JoinHandle<()>> {
    let interval = snapshot_interval(s.every, env::var("CHM_SNAPSHOT_INTERVAL_SECS").ok())?;

    // Say up front how far back this actually lets you travel. The cadence is
    // the visible knob but retention is the binding one: at 30 s and the default
    // budget of 5, "continuous snapshots" buys two and a half minutes of
    // history, which is not what the phrase suggests. An operator who wants more
    // can raise the budget or pin a point, and can only make that choice if the
    // number is in front of them rather than inferred from two env vars.
    if !s.quiet {
        let window = interval * u32::try_from(checkpoint::max_resumable_revisions()).unwrap_or(1);
        eprintln!(
            "chm: continuous snapshots every {}s; roughly the last {} \
             stays resumable (raise CHM_MAX_RESUMABLE_REVISIONS, or pin a \
             revision, to keep more)",
            interval.as_secs(),
            human_duration(window)
        );
    }

    thread::Builder::new()
        .name("chm-live-snapshot".into())
        .spawn(move || {
            let LiveSnapshotter {
                gate,
                quiesce,
                net_kick,
                exits,
                wakes,
                running,
                guest_mem,
                mem_mappings,
                dir,
                num_irq,
                vcpus,
                origin,
                quiet,
                every: _,
                taken: taken_total,
            } = s;

            // Both signals, every time. `hv_vcpus_exit` moves a vCPU that is
            // inside the guest; the wake fd moves one parked in the host-side
            // WFI idle halt, which has already left the guest and would
            // otherwise sit there until its poll timeout. An idle VM is exactly
            // when a checkpoint is cheapest, so it must not be the slow case.
            let kick = move || {
                for e in &exits {
                    e();
                }
                for w in &wakes {
                    w();
                }
            };
            let wake_writers = move || {
                if let Some(k) = &net_kick {
                    k.wake();
                }
            };

            let (mut taken, mut missed) = (0u64, 0u64);
            let mut next = Instant::now() + interval;
            while running.load(Ordering::Acquire) {
                // Poll rather than sleep the whole interval so teardown is
                // observed promptly instead of after a full period.
                thread::sleep(Duration::from_millis(200));
                if Instant::now() < next {
                    continue;
                }
                next = Instant::now() + interval;

                let started = Instant::now();
                // Order matters: hold the host-side writers first, then the
                // vCPUs. The other way round leaves the net service free to
                // publish into the RX ring of a guest whose vCPUs are already
                // parked, which is precisely the torn ring we are avoiding.
                if let Err(e) = quiesce.pause(&wake_writers, LIVE_SNAPSHOT_BARRIER_TIMEOUT) {
                    missed += 1;
                    if !quiet {
                        eprintln!("chm: live snapshot skipped (writers): {e}");
                    }
                    continue;
                }
                let captures = match gate.stop_the_world(&kick, LIVE_SNAPSHOT_BARRIER_TIMEOUT) {
                    Ok(c) => c,
                    Err(e) => {
                        quiesce.resume();
                        missed += 1;
                        if !quiet {
                            eprintln!("chm: live snapshot skipped: {e}");
                        }
                        continue;
                    }
                };
                let frozen_at = started.elapsed();

                // The world is stopped here, and nothing in this block may
                // return early without releasing it.
                let result =
                    assemble_usgic_checkpoint(captures, num_irq, vcpus).and_then(|state| {
                    checkpoint::write_checkpoint(
                        &dir,
                        &state,
                        &guest_mem,
                        &mem_mappings,
                        &origin,
                    )
                });
                let froze = started.elapsed();
                gate.release();
                quiesce.resume();

                match result {
                    // The superseded id is for the teardown path, where a
                    // checkpoint replaces the resume point unasked. A cadence
                    // snapshot supersedes its own predecessor by design, every
                    // interval, so naming it here would be noise (#288).
                    Ok(_superseded) => {
                        taken += 1;
                        taken_total.store(taken, Ordering::Release);
                        if !quiet {
                            // Report the measured freeze, not a nominal one: the
                            // whole cost of this feature is time the guest did
                            // not run, and an operator choosing an interval
                            // needs the real number.
                            eprintln!(
                                "chm: live snapshot {taken} written \
                                 (froze {:.2}s, barrier {:.0}ms)",
                                froze.as_secs_f64(),
                                frozen_at.as_secs_f64() * 1000.0
                            );
                        }
                    }
                    Err(e) => {
                        missed += 1;
                        eprintln!("chm: warning: live snapshot failed: {e}");
                    }
                }
            }
            gate.close();
            quiesce.close();
            if !quiet && (taken > 0 || missed > 0) {
                eprintln!("chm: live snapshots: {taken} written, {missed} skipped");
            }
        })
        .ok()
}

fn spawn_vtimer_stepper(
    clock: Arc<VtimerClock>,
    exits: Vec<ExitSignal>,
    running: Arc<AtomicBool>,
) -> Option<thread::JoinHandle<()>> {
    if !clock.scaled() {
        return None;
    }
    let interval = env::var("CHM_VTIMER_STEP_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(VTIMER_STEP_INTERVAL, Duration::from_millis);
    let handle = thread::Builder::new()
        .name("chm-vtimer-step".into())
        .spawn(move || {
            let trace = env::var("CHM_TRACE_VTIMER").is_ok();
            let force_exit = move || {
                for sig in &exits {
                    sig();
                }
            };
            let (mut stepped, mut skipped) = (0u64, 0u64);
            // Stop-the-world accounting: the whole cost of this design is the
            // time every vCPU spends outside the guest waiting for the barrier,
            // so measure it directly rather than inferring it from guest
            // throughput (which is hostage to whatever else the Mac is doing).
            let (mut barrier_total, mut barrier_max) = (Duration::ZERO, Duration::ZERO);
            let started = Instant::now();
            const REPORT_EVERY: Duration = Duration::from_secs(5);
            let mut last_report = Instant::now();
            let (mut reported, mut reported_total) = (0u64, Duration::ZERO);
            while running.load(Ordering::Relaxed) {
                thread::sleep(interval);
                let t = Instant::now();
                let ok = clock.step(&force_exit, VTIMER_STEP_TIMEOUT);
                let took = t.elapsed();
                barrier_total += took;
                barrier_max = barrier_max.max(took);
                if ok {
                    stepped += 1;
                } else {
                    skipped += 1;
                }
                // Report while the VM is still alive: teardown is not always
                // reached (a harness may kill the process outright).
                if trace && last_report.elapsed() >= REPORT_EVERY {
                    let wall = last_report.elapsed();
                    let n = (stepped + skipped - reported).max(1);
                    eprintln!(
                        "[vtimer] {stepped} stepped {skipped} skipped | barrier \
                         {:.2}% of wall, mean {:.3}ms, max {:.3}ms",
                        (barrier_total - reported_total).as_secs_f64() / wall.as_secs_f64()
                            * 100.0,
                        (barrier_total - reported_total).as_secs_f64() * 1e3 / n as f64,
                        barrier_max.as_secs_f64() * 1e3,
                    );
                    last_report = Instant::now();
                    reported = stepped + skipped;
                    reported_total = barrier_total;
                    barrier_max = Duration::ZERO;
                }
            }
            // Never leave a vCPU blocked waiting on a stepper that has stopped.
            clock.release();
            if trace {
                let wall = started.elapsed();
                let duty = if wall.is_zero() {
                    0.0
                } else {
                    barrier_total.as_secs_f64() / wall.as_secs_f64() * 100.0
                };
                eprintln!(
                    "[vtimer] stepper stopped: {stepped} stepped, {skipped} skipped, \
                     barrier total {:.3}s of {:.3}s wall ({duty:.2}% stopped), \
                     max {:.3}ms, mean {:.3}ms",
                    barrier_total.as_secs_f64(),
                    wall.as_secs_f64(),
                    barrier_max.as_secs_f64() * 1e3,
                    barrier_total.as_secs_f64() * 1e3
                        / (stepped + skipped).max(1) as f64,
                );
            }
        })
        .expect("spawn vtimer stepper");
    Some(handle)
}

/// A boxed closure that forces one vCPU out of `hv_vcpu_run` (its `exit_signal`).
/// Collected per-vCPU so the orchestrator can stop every thread at once.
type ExitSignal = Arc<dyn Fn() + Send + Sync>;

/// Re-evaluation cadence for the run-progress watchdog.
const RUN_WATCHDOG_INTERVAL: Duration = Duration::from_millis(30);

/// Spawn the run-progress watchdog. Every [`RUN_WATCHDOG_INTERVAL`] it samples
/// each vCPU's run-progress counter (bumped once per `hv_vcpu_run` iteration). A
/// counter that has not advanced across a full interval means the vCPU is wedged
/// inside a single, non-returning `hv_vcpu_run` — the failure mode where Apple's
/// internal WFI wait (`wait_for_interrupt`) fails to honour a due virtual-timer
/// deadline during an idle transition (observed as the interactive-console
/// wedge, #78/#60). The watchdog forces that vCPU out via its exit signal, so it
/// re-enters `hv_vcpu_run`; the CANCELED path then unmasks an overdue vtimer and
/// the guest's scheduler tick resumes.
///
/// Forcing a genuinely busy vCPU (a long in-guest compute burst never exits, so
/// its counter is also static) out of the run loop is harmless: `hv_vcpus_exit`
/// preserves register state and the guest resumes exactly where it left off. The
/// bounded ~1 kick/interval overhead is negligible next to the wedge it prevents.
fn spawn_run_watchdog(
    progress: Vec<Arc<AtomicU64>>,
    exits: Vec<ExitSignal>,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("chm-run-watchdog".into())
        .spawn(move || {
            let trace = env::var("CHM_TRACE_WATCHDOG").is_ok();
            let mut last: Vec<u64> = vec![u64::MAX; progress.len()];
            while running.load(Ordering::Relaxed) {
                thread::sleep(RUN_WATCHDOG_INTERVAL);
                for (i, p) in progress.iter().enumerate() {
                    let cur = p.load(Ordering::Relaxed);
                    // A counter unchanged since the previous sample means no
                    // run() iteration happened this interval: the vCPU is stuck
                    // in one hv_vcpu_run. Force it out so it re-evaluates.
                    if cur == last[i] && let Some(sig) = exits.get(i) {
                        if trace {
                            eprintln!("[watchdog] vcpu {i} stalled at gen={cur}; forcing exit");
                        }
                        sig();
                    }
                    last[i] = cur;
                }
            }
        })
        .expect("spawn run watchdog")
}

pub(crate) fn wait_for_cpu_on_request(
    slot: &CpuPowerSlot,
    running: &AtomicBool,
) -> Option<(u64, u64)> {
    let (lock, cv) = &**slot;
    let mut st = lock.lock().unwrap();
    loop {
        if !running.load(Ordering::Acquire) {
            return None;
        }
        if st.online {
            if let Some(req) = st.cpu_on.take() {
                return Some(req);
            }
            // Online without an outstanding CPU_ON request means this vCPU was
            // already runnable at snapshot time; the caller should not be waiting.
            return None;
        }
        let (next, _) = cv.wait_timeout(st, Duration::from_millis(100)).unwrap();
        st = next;
    }
}

pub(crate) fn apply_psci_cpu_on_state(
    vcpu: &mut dyn Vcpu,
    entry: u64,
    context: u64,
) -> Result<(), String> {
    let mut regs = vcpu
        .get_regs()
        .map_err(|e| format!("read regs for CPU_ON: {e}"))?;
    #[allow(irrefutable_let_patterns)]
    let StandardRegisters::Hvf(ref mut hvf) = regs else {
        return Err("CPU_ON: expected HVF register state".into());
    };
    hvf.pc = entry;
    hvf.regs[0] = context;
    vcpu.set_regs(&regs)
        .map_err(|e| format!("write regs for CPU_ON: {e}"))?;
    Ok(())
}

/// One vCPU's userspace-GIC suspend capture: its register file plus its
/// software distributor/redistributor models, or why the capture failed.
pub(crate) type UsgicCapture =
    Result<(hvf_checkpoint::VcpuCheckpoint, hvf_checkpoint::UsgicCheckpoint), String>;

/// Gather the per-vCPU userspace-GIC captures (in id order) into a
/// [`CheckpointState`] ready to persist.
///
/// The software-GIC sibling of [`collect_checkpoint`], and simpler in one
/// respect: there is no managed distributor to read back, because the whole
/// GICv3 model lives in userspace and each vCPU already serialized its view of
/// it. Called at suspend, after every vCPU thread has sent its capture and
/// joined, while the VM (and so guest RAM) is still alive.
pub(crate) fn collect_usgic_checkpoint(
    captured_rx: &mpsc::Receiver<(usize, UsgicCapture)>,
    num_irq: u32,
    n: usize,
) -> Result<CheckpointState, String> {
    let mut slots: Vec<Option<UsgicCapture>> = (0..n).map(|_| None).collect();
    for _ in 0..n {
        let (id, res) = captured_rx
            .recv()
            .map_err(|_| "a vCPU thread exited before sending its capture".to_string())?;
        *slots
            .get_mut(id)
            .ok_or_else(|| format!("captured out-of-range vCPU id {id}"))? = Some(res);
    }
    let ordered = slots
        .into_iter()
        .enumerate()
        .map(|(id, c)| c.ok_or_else(|| format!("missing capture for vCPU {id}")))
        .collect::<Result<Vec<_>, String>>()?;
    assemble_usgic_checkpoint(ordered, num_irq, n)
}

/// Turn per-vCPU captures **already in id order** into a [`CheckpointState`].
///
/// Split out of [`collect_usgic_checkpoint`] so the live-checkpoint path
/// (which gets its captures from the [`livesnap::CheckpointGate`], indexed by
/// id rather than delivered over a channel) builds byte-identical state. Two
/// assemblers would be two chances for the resume side to meet a shape only one
/// of them writes.
fn assemble_usgic_checkpoint(
    captures: Vec<UsgicCapture>,
    num_irq: u32,
    n: usize,
) -> Result<CheckpointState, String> {
    if captures.len() != n {
        return Err(format!(
            "checkpoint covers {} vCPU(s) but this VM has {n}",
            captures.len()
        ));
    }
    let (vcpus, usgic_cpus): (Vec<_>, Vec<_>) = captures
        .into_iter()
        .enumerate()
        .map(|(id, c)| c.map_err(|e| format!("vCPU {id}: {e}")))
        .collect::<Result<Vec<_>, String>>()?
        .into_iter()
        .unzip();

    Ok(CheckpointState {
        version: hvf_checkpoint::CHECKPOINT_VERSION,
        vcpus,
        // The managed distributor dump is empty on this path by construction:
        // there is no managed GIC, and each entry of `usgic_cpus` carries the
        // software distributor instead.
        gic_dist: Vec::new(),
        num_irq,
        // vCPU 0 is also written to the legacy single-`usgic` field so a reader
        // that predates SMP capture still resumes a checkpoint we write. Every
        // vCPU shares one distributor model, so the copies here are identical in
        // that part and differ only in the per-vCPU redistributor and in-flight
        // interrupt state — a few KB of duplication against a multi-GB RAM dump,
        // which is a price worth paying for a format with no cross-references.
        usgic: usgic_cpus.first().cloned(),
        usgic_cpus,
        host_realtime_ns: hvf_checkpoint::now_realtime_ns(),
    })
}

/// The effective wall-clock cap in seconds: the tighter (smaller nonzero) of the
/// `--max-seconds` flag and the limits doc's `max_wall_seconds`. `0`/`None` mean
/// "no cap from that source"; `None` result means unlimited.
fn effective_wall_secs(max_seconds: u64, max_wall: Option<u64>) -> Option<u64> {
    [max_seconds, max_wall.unwrap_or(0)]
        .into_iter()
        .filter(|&s| s > 0)
        .min()
}

/// Total *allocated* size in bytes of the files directly under `dir` (the disk
/// overlays + their bitmaps). Overlays are sparse CoW files whose logical length
/// equals the full disk, so this must count actually-allocated blocks
/// (`st_blocks` x 512), not logical length — otherwise a freshly-cloned sparse
/// overlay would read as its full logical size and trip the cap immediately.
/// Errors (e.g. a missing dir) read as 0 so the cap simply does not trip.
fn dir_size_bytes(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        // st_blocks is in 512-byte units; this is real on-disk allocation, so a
        // sparse hole costs nothing and only genuine writes count.
        .map(|m| m.blocks() * 512)
        .sum()
}

/// The orchestrator-thread console loop: drain the guest's shared PL011 output
/// to stdout and enforce the stop policy — `--max-seconds` / `--idle-exit` and
/// the resource limits (M30.6): wall-clock, total console output, and disk
/// overlay growth. Runs until a vCPU thread clears `running` (power-off / error)
/// or a stop condition fires.
fn run_console(
    uart: &Arc<Pl011>,
    running: &Arc<AtomicBool>,
    args: &Args,
    limits: &limits::LimitsDoc,
    overlay_dir: &Path,
) -> Result<Outcome, String> {
    let start = Instant::now();
    let mut last_output = Instant::now();
    let mut stdout = io::stdout();
    let mut filter = ConsoleFilter::new();

    // The wall-clock cap is the tighter of --max-seconds and the limits doc.
    let wall_secs = effective_wall_secs(args.max_seconds, limits.max_wall_seconds);
    let max = wall_secs.map(Duration::from_secs);
    let idle = (args.idle_exit_secs > 0).then(|| Duration::from_secs(args.idle_exit_secs));

    // Byte budgets for the resource caps.
    let max_console_bytes = limits.max_console_mb.map(|mb| mb * 1024 * 1024);
    let max_disk_bytes = limits.max_disk_mb.map(|mb| mb * 1024 * 1024);
    let mut console_bytes: u64 = 0;
    // Poll the overlay size occasionally (a directory walk is not free), not on
    // every 5 ms loop iteration.
    let mut last_disk_check = Instant::now();
    const DISK_CHECK_INTERVAL: Duration = Duration::from_millis(500);

    while running.load(Ordering::Acquire) {
        // A terminating signal (window close / kill) or the Ctrl-A x escape asks
        // the session to end: return so run() runs the graceful VM teardown.
        if console::shutdown_requested() {
            let tail = filter.flush();
            if !tail.is_empty() {
                let _ = stdout.write_all(&tail).and_then(|()| stdout.flush());
            }
            return Ok(Outcome::Interrupted);
        }
        let raw = uart.take_output();
        if raw.is_empty() {
            thread::sleep(Duration::from_millis(5));
        } else {
            // Drop the one documented cosmetic genirq line from the rendered
            // console (see console_filter); everything else passes through.
            let bytes = filter.feed(&raw);
            if bytes.is_empty() {
                continue;
            }
            match stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
                Ok(()) => last_output = Instant::now(),
                // The console consumer went away (e.g. piped into `head`): stop
                // cleanly rather than treating a closed pipe as a failure.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    return Ok(Outcome::ConsoleClosed);
                }
                Err(e) => return Err(format!("write console: {e}")),
            }
            // Cap total console output: a runaway that floods the console (e.g.
            // `yes` to the tty) is stopped before it can fill logs/pipes.
            console_bytes += bytes.len() as u64;
            if let Some(cap) = max_console_bytes
                && console_bytes >= cap
            {
                return Ok(Outcome::LimitExceeded(format!(
                    "console output exceeded {} MiB",
                    limits.max_console_mb.unwrap_or(0)
                )));
            }
        }

        // Cap disk overlay growth: a runaway that writes to the persistent disk
        // (e.g. `dd if=/dev/zero`) can't fill the host disk — stop it first.
        if let Some(cap) = max_disk_bytes
            && last_disk_check.elapsed() >= DISK_CHECK_INTERVAL
        {
            last_disk_check = Instant::now();
            if dir_size_bytes(overlay_dir) >= cap {
                return Ok(Outcome::LimitExceeded(format!(
                    "disk overlay exceeded {} MiB",
                    limits.max_disk_mb.unwrap_or(0)
                )));
            }
        }

        if let Some(max) = max
            && start.elapsed() >= max
        {
            return Ok(Outcome::MaxSeconds);
        }
        if let Some(idle) = idle
            && last_output.elapsed() >= idle
        {
            return Ok(Outcome::Idle(args.idle_exit_secs));
        }
    }
    // A vCPU thread stopped the run; flush any withheld partial line and surface
    // the recorded outcome.
    let tail = filter.flush();
    if !tail.is_empty() {
        let _ = stdout.write_all(&tail).and_then(|()| stdout.flush());
    }
    Ok(Outcome::PoweredOff)
}

fn banner(dir: &Path, mem_ranges: &Path, num_vcpus: u32, total_ram: u64, backend: &str) {
    let mib = total_ram / (1024 * 1024);
    eprintln!("chm — Gimbal Local (Cloud Hypervisor on Apple Silicon)");
    eprintln!("  snapshot:  {}", dir.display());
    eprintln!("  memory:    {} ({mib} MiB)", mem_ranges.display());
    eprintln!("  vCPUs:     {num_vcpus}");
    eprintln!("  backend:   Apple Hypervisor.framework ({backend})");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_deadline_or_an_idle_window_is_chm_choosing_the_moment() {
        // The rule this pins: chm interrupting work it was asked to time-limit
        // owes the user a resumable point. Anyone else choosing to stop does
        // not. Without this, the only thing standing between a deadline and a
        // power cut is one `||` in a 600-line function.
        assert!(chm_initiated_stop(&Ok(Outcome::MaxSeconds)));
        assert!(chm_initiated_stop(&Ok(Outcome::Idle(600))));

        // The guest decided it was finished.
        assert!(!chm_initiated_stop(&Ok(Outcome::PoweredOff)));
        // The user decided, via Ctrl-C or by closing the console.
        assert!(!chm_initiated_stop(&Ok(Outcome::Interrupted)));
        assert!(!chm_initiated_stop(&Ok(Outcome::ConsoleClosed)));
        // A limit breach is a guest protecting the host from itself; capturing
        // the state that was busy exceeding a limit is not a kindness.
        assert!(!chm_initiated_stop(&Ok(Outcome::LimitExceeded("disk".into()))));
        // Not a choice at all — the session is not known to be sound.
        assert!(!chm_initiated_stop(&Err("supervisor failed".into())));
    }

    /// #288: `chm ctl stop` on a wedged guest wrote a checkpoint of the wedge
    /// over the resume point and said `ok  stopped`. The previous state was
    /// archived and recoverable the whole time; nothing said so, so it read as
    /// destroyed. The remedy has to arrive at the moment of the overwrite.
    #[test]
    fn a_teardown_checkpoint_names_the_revision_it_displaced() {
        let dir = Path::new("/tmp/ws");
        let note = superseded_note(Some("rev-20260810-aaa"), dir);
        assert!(
            note.contains("rev-20260810-aaa"),
            "the displaced revision must be named: {note}"
        );
        assert!(
            note.contains("chm rollback /tmp/ws rev-20260810-aaa"),
            "and the way back must be a command that can be pasted: {note}"
        );
    }

    /// A first checkpoint replaces nothing. Offering a way back to a revision
    /// that does not exist would be worse than silence.
    #[test]
    fn a_first_checkpoint_offers_no_way_back_because_there_is_none() {
        assert_eq!(superseded_note(None, Path::new("/tmp/ws")), "");
    }

    #[test]
    fn the_idle_default_is_not_the_scaffold_it_used_to_be() {
        // 10s was a workaround for a build that could not model virtio devices:
        // the guest went quiet at the first missing device and would have hung.
        // The devices landed years of sessions ago. A default that low kills an
        // agent mid-`npm install`, so this asserts the scaffold is gone rather
        // than trusting a comment to stay true.
        assert!(
            DEFAULT_IDLE_EXIT_SECS >= 60,
            "an idle window under a minute measures console silence, not idleness"
        );
    }

    /// The reachable-history window is the number an operator plans around, so
    /// it must not make them do arithmetic to read it.
    #[test]
    fn human_duration_reads_at_the_scales_a_cadence_produces() {
        let d = |s: u64| human_duration(Duration::from_secs(s));
        assert_eq!(d(45), "45s");
        assert_eq!(d(150), "2m 30s"); // 30s cadence x default budget of 5
        assert_eq!(d(300), "5m");
        assert_eq!(d(3600), "1h");
        assert_eq!(d(5400), "1h 30m");
    }

    /// The timeline column has to stay readable at every scale a session
    /// reaches, and must not turn a clock that went backwards into an absurdity.
    #[test]
    fn relative_age_reads_as_a_timeline_at_every_scale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ago = |secs: u64| relative_age(now - secs * 1000);
        assert_eq!(ago(0), "0s ago");
        assert_eq!(ago(59), "59s ago");
        assert_eq!(ago(60), "1m ago");
        assert_eq!(ago(3599), "59m ago");
        assert_eq!(ago(3600), "1h ago");
        assert_eq!(ago(86_399), "23h ago");
        assert_eq!(ago(86_400), "1d ago");
        // A revision stamped in the future means the host clock moved, not that
        // time ran backwards. Saturating keeps it wrong-but-sane; subtracting
        // would wrap u64 and print ~584 million years.
        assert_eq!(relative_age(now + 60_000), "0s ago");
    }

    /// A `\\` at the end of a line in a Rust string eats the newline *and*
    /// the next line's leading whitespace, so an entry whose predecessor
    /// forgets to write the indent before its backslash silently renders at
    /// column 0. That shipped twice: once in `VANILLA_USAGE`, once on the
    /// `chm spec` line here. Nothing else notices, because every guard we had
    /// asks whether a subcommand is *mentioned*, and a de-indented line
    /// mentions it perfectly.
    #[test]
    fn no_help_entry_loses_its_indentation() {
        let help = usage();
        let stray: Vec<&str> = help
            .lines()
            .skip(1) // the title line is deliberately at column 0
            .filter(|l| l.starts_with("chm "))
            .collect();
        assert!(
            stray.is_empty(),
            "help entries rendered at column 0 (a `\\` ate their indent): {stray:?}"
        );
    }

    /// `--help` is the only place a user can discover what `chm` does, and it
    /// had drifted: seven dispatched subcommands were absent from it, including
    /// `create` — the whole cold-boot path. Listing them once fixes today; this
    /// test fixes the class, by reading the dispatch table out of this file's
    /// own source and requiring every arm to be reachable from the help.
    ///
    /// The extraction is bounded to the dispatch `match` itself, tracked by
    /// brace balance from its head. Scanning the whole file was the first
    /// shape, and it broke the moment a *nested* `match` elsewhere used the
    /// same `Some("...")` arm: `parse_vanilla` dispatches its own sub-verb, and
    /// the guard reported `export` as an undocumented top-level subcommand.
    /// A guard that fires on things it was never meant to see gets weakened to
    /// silence it; bounding it to the table it is guarding keeps its teeth.
    /// This guard had itself stopped running. A later test was inserted at
    /// this function's `fn` header line, which left the doc comment and
    /// `#[test]` above orphaned onto the newcomer and stole the attribute from
    /// this one -- so from that commit until #357 the help was unguarded, and
    /// the suite reported otherwise. Third time in this repo; the tell is a
    /// `duplicated attribute` warning nobody reads. Append at the module's
    /// closing brace instead of splicing at a `fn` line.
    #[test]
    fn every_dispatched_subcommand_appears_in_the_help() {
        let src = include_str!("imp.rs");
        let help = usage();

        const HEAD: &str = "match raw.first().map(String::as_str) {";
        let start = src.find(HEAD).expect("the dispatch match head moved");
        let mut depth = 0i32;
        let mut end = src.len();
        for (i, c) in src[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let table = &src[start..end];

        let mut dispatched: Vec<&str> = table
            .lines()
            .filter_map(|l| l.trim().strip_prefix("Some(\""))
            .filter_map(|r| r.split('"').next())
            .collect();
        dispatched.sort_unstable();
        dispatched.dedup();

        assert!(
            dispatched.len() > 20,
            "extraction found only {} subcommands — the dispatch match moved \
             and this guard is no longer reading it",
            dispatched.len()
        );

        let missing: Vec<&str> = dispatched
            .iter()
            .copied()
            .filter(|c| !help.contains(&format!("chm {c} ")))
            .collect();
        assert!(
            missing.is_empty(),
            "dispatched but absent from `chm --help`: {missing:?}"
        );
    }

    /// The header is the first thing a reader sees, so it must not describe
    /// half the product. Cold boot is a first-class entry point, not a footnote
    /// to snapshot rehydration.
    #[test]
    fn the_help_header_covers_both_entry_points() {
        let help = usage();
        let header = help.split("USAGE:").next().expect("header");
        assert!(header.contains("cold-boot"), "header omits cold boot: {header}");
        assert!(header.contains("snapshot"), "header omits snapshots: {header}");
    }

    /// A local-only install cannot use these, and V8.2 ships exactly that mode.
    /// Grouping them is the difference between "this is broken" and "this needs
    /// something you have not set up".
    #[test]
    fn control_plane_commands_are_grouped_as_such() {
        let help = usage();
        let start = help.find("NEEDS A CONTROL PLANE").expect("group heading");
        let group = &help[start..];
        for c in ["chm push ", "chm pull ", "chm branches ", "chm runner ", "chm policy "] {
            assert!(group.contains(c), "{c} is not under the control-plane heading");
        }
        // `create` is the local cold-boot path and must not be down there.
        assert!(!group.contains("chm create "), "create listed as control-plane");
    }

    /// A cold guest has no captured `mp_state`: the boot protocol started
    /// vCPU 0 and nothing else. Bringing a secondary up before the kernel asks
    /// would run it from HVF's reset state with no stack and no page tables.
    #[test]
    fn a_cold_coordinator_starts_only_the_boot_cpu() {
        let psci = PsciCoordinator::cold(4);
        assert!(psci.slots[0].0.lock().unwrap().online);
        for id in 1..4 {
            assert!(!psci.slots[id].0.lock().unwrap().online, "cpu{id}");
        }
    }

    #[test]
    fn cpu_on_brings_a_parked_core_up_once() {
        let psci = PsciCoordinator::cold(2);
        assert_eq!(psci.cpu_on(1, 0x4200_0000, 7), PSCI_SUCCESS);
        let st = psci.slots[1].0.lock().unwrap();
        assert!(st.online);
        assert_eq!(st.cpu_on, Some((0x4200_0000, 7)));
    }

    /// Linux retries `CPU_ON` on some paths; the second call must be refused
    /// rather than overwrite an entry point the target may already be running
    /// from. Because the coordinator commits a core to `online` at the moment
    /// it accepts the request, that refusal is `ALREADY_ON` — there is no
    /// window in which the request is visible but the core is not yet up.
    #[test]
    fn cpu_on_refuses_a_core_that_is_already_on() {
        let psci = PsciCoordinator::cold(2);
        assert_eq!(psci.cpu_on(1, 0x4200_0000, 0), PSCI_SUCCESS);
        assert_eq!(psci.cpu_on(1, 0x4300_0000, 0), PSCI_ALREADY_ON);
        assert_eq!(psci.slots[1].0.lock().unwrap().cpu_on, Some((0x4200_0000, 0)));
        // vCPU 0 was never off.
        assert_eq!(psci.cpu_on(0, 0x4300_0000, 0), PSCI_ALREADY_ON);
    }

    #[test]
    fn cpu_on_refuses_an_mpidr_with_no_vcpu_behind_it() {
        let psci = PsciCoordinator::cold(2);
        assert_eq!(psci.cpu_on(9, 0x4200_0000, 0), PSCI_INVALID_PARAMS);
    }

    /// The device tree gives each core an `MPIDR` built from affinity fields,
    /// so the mapping back to a vCPU index has to unpack all four.
    #[test]
    fn mpidr_unpacks_every_affinity_level() {
        assert_eq!(PsciCoordinator::mpidr_to_vcpu_id(0x0000_0000_0000_0003), 3);
        assert_eq!(PsciCoordinator::mpidr_to_vcpu_id(0x0000_0000_0000_0201), 0x201);
        assert_eq!(PsciCoordinator::mpidr_to_vcpu_id(0x0000_0001_0000_0000), 1 << 24);
    }

    /// The clock block is a JSON *string* nested under `snapshot_data.state`, so
    /// it has to be parsed twice. Getting that wrong reads as "no clock block"
    /// and silently disables the #104 guard, so pin the shape.
    #[test]
    fn snapshot_cntfrq_parses_the_doubly_encoded_clock_block() {
        let with_clock = r#"{"snapshot_data":{"state":
            "{\"clock\":{\"cntvct\":4426757347,\"host_realtime_ns\":1784730066918609199,\"cntfrq\":24000000}}"}}"#;
        assert_eq!(snapshot_cntfrq(with_clock), Some(24_000_000));

        // A Graviton2 capture, for contrast.
        let graviton = r#"{"snapshot_data":{"state":
            "{\"clock\":{\"cntvct\":16981244116,\"host_realtime_ns\":1,\"cntfrq\":121875000}}"}}"#;
        assert_eq!(snapshot_cntfrq(graviton), Some(121_875_000));
    }

    /// cloud-hypervisor v52.0 predates upstream 69637dde6 and writes `{}` here,
    /// which must read as "cannot tell" rather than as an error or a zero.
    #[test]
    fn snapshot_cntfrq_is_absent_on_pre_clock_block_captures() {
        assert_eq!(snapshot_cntfrq(r#"{"snapshot_data":{"state":"{}"}}"#), None);
        assert_eq!(snapshot_cntfrq(r#"{"snapshots":{}}"#), None);
        assert_eq!(snapshot_cntfrq("not json"), None);
    }

    /// A capture whose `ID_AA64PFR0_EL1.EL0` says "AArch64 and AArch32" is the
    /// dangerous case: HVF restores that register faithfully, so the guest keeps
    /// believing it, and executing a 32-bit binary wedges the vCPU outright.
    #[test]
    fn aarch32_guard_fires_only_when_the_capture_advertises_32_bit_el0() {
        fn snap_with(pfr0: u64) -> Snapshot {
            Snapshot {
                mem_mappings: Vec::new(),
                vcpus: vec![hypervisor::hvf::VcpuHvfState {
                    gpr: [0; 31],
                    pc: 0,
                    cpsr: 0,
                    sp_el1: 0,
                    // 0xc020 is ID_AA64PFR0_EL1 (S3_0_C0_C4_0).
                    sysregs: vec![(0xc020, pfr0)],
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

        // The real Graviton2 value: EL0 field 2 == AArch64 *and* AArch32.
        aarch32_guard(&snap_with(0x1100_0000_1111_1112)).unwrap();
        // EL0 field 1 == AArch64 only: nothing to warn about.
        aarch32_guard(&snap_with(0x1100_0000_1111_1111)).unwrap();
        // A capture with no ID_AA64PFR0_EL1 at all cannot be judged.
        aarch32_guard(&snap_with_no_sysregs()).unwrap();
    }

    /// The real values, from `chm sysregs` against a Graviton2 capture: the
    /// capture records `CTR_EL0 = 0xb444c004` (DIC = 1) and this Mac reports
    /// `0x9444c004` (DIC = 0). Exactly one bit differs, and it is the bit that
    /// decides whether the guest kernel keeps its `ic ivau`.
    #[test]
    fn icache_guard_fires_only_when_the_capture_elided_ic_ivau() {
        fn snap_with_ctr(ctr: u64) -> Snapshot {
            Snapshot {
                mem_mappings: Vec::new(),
                vcpus: vec![hypervisor::hvf::VcpuHvfState {
                    gpr: [0; 31],
                    pc: 0,
                    cpsr: 0,
                    sp_el1: 0,
                    // 0xd801 is CTR_EL0 (S3_3_C0_C0_1).
                    sysregs: vec![(0xd801, ctr)],
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

        // Graviton2: DIC = 1, so the kernel patched `ic ivau` out. Warns.
        icache_dic_guard(&snap_with_ctr(0xb444_c004)).unwrap();
        // A capture from DIC = 0 hardware keeps its maintenance. Silent.
        icache_dic_guard(&snap_with_ctr(0x9444_c004)).unwrap();
        // No CTR_EL0 recorded at all: nothing to judge, so do not guess.
        icache_dic_guard(&snap_with_no_sysregs()).unwrap();
    }

    /// The ASID width is the one CPU-feature delta that corrupts memory rather
    /// than killing a process, so the predicate behind the warning has to be
    /// exact: 16-bit captures must be caught and 8-bit ones must stay silent,
    /// or a user is either frightened for nothing or not warned at all.
    #[test]
    fn asid_guard_fires_only_when_the_capture_has_more_asid_bits_than_this_host() {
        fn snap_with_mmfr0(v: u64) -> Snapshot {
            Snapshot {
                mem_mappings: Vec::new(),
                vcpus: vec![hypervisor::hvf::VcpuHvfState {
                    gpr: [0; 31],
                    pc: 0,
                    cpsr: 0,
                    sp_el1: 0,
                    // 0xc038 is ID_AA64MMFR0_EL1 (S3_0_C0_C7_0).
                    sysregs: vec![(0xc038, v)],
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

        // Graviton2's measured value: ASIDBits = 2 -> 16 bits, wider than the
        // 8 this host implements.
        assert_eq!(snapshot_asid_bits(&snap_with_mmfr0(0x10_1125)), Some(16));
        assert!(
            asid_warning_for(&snap_with_mmfr0(0x10_1125)).is_some(),
            "a 16-bit capture must be warned about on this 8-bit host"
        );
        // This Mac's own measured value: ASIDBits = 0 -> 8 bits. Nothing to say.
        assert_eq!(snapshot_asid_bits(&snap_with_mmfr0(0xf10_0002)), Some(8));
        assert_eq!(
            asid_warning_for(&snap_with_mmfr0(0xf10_0002)),
            None,
            "a capture that already matches this host must stay silent"
        );
        // Nothing recorded: do not guess a width the capture never stated.
        assert_eq!(snapshot_asid_bits(&snap_with_no_sysregs()), None);
        assert_eq!(asid_warning_for(&snap_with_no_sysregs()), None);
    }

    /// A warning nobody can act on is noise, so pin the parts an operator needs:
    /// what was measured, why the guest cannot fix itself, and the escape hatch.
    #[test]
    fn the_asid_warning_carries_its_evidence() {
        let d = asid_detail();
        for needle in [
            "ASID allocator initialised with 32768 entries",
            "0xf100002",
            "256 live address spaces",
            "cold-booted",
            "CHM_STRICT_ASID=1",
        ] {
            assert!(d.contains(needle), "asid_detail() must mention {needle:?}");
        }
    }

    /// #289: the warning names a variable that `sudo` throws away. A reader who
    /// follows it hits `EACCES` without `sudo` and `SIGILL` with it, and neither
    /// message mentions `NODE_OPTIONS`, so the workaround we hand over fails on
    /// the very next command. The form that survives has to be the one printed.
    #[test]
    fn the_icache_warning_gives_a_form_that_survives_sudo() {
        let d = icache_detail();
        let form = format!("sudo env NODE_{}", "OPTIONS=--jitless npm i -g");
        assert!(
            d.contains(&form),
            "the warning must print the sudo-safe install form: {d}"
        );
        assert!(
            d.contains("env_keep"),
            "and say why the plain form does not survive: {d}"
        );
    }

    /// #290: the warning used to end "so only the kernel's copy is wrong",
    /// which sends every reader towards a kernel-side fix. There is a second,
    /// independent error -- the guest strides its `ic ivau` loops by an
    /// advertised 4096 B when the granule that actually invalidates is 64 B --
    /// and a reader who does not learn that will fix the kernel and still get
    /// SIGILL, because the restored loop strides 4096 too.
    #[test]
    fn the_icache_warning_carries_the_stride_that_is_actually_wrong() {
        let d = icache_detail();
        for needle in [
            "IminLine",
            "4096 bytes",
            "SCTLR_EL1.UCT",
            "CHM_KEEP_CTR_TRAP",
            "998",
            "#287",
        ] {
            assert!(
                d.contains(needle),
                "icache_detail() must carry {needle:?}: {d}"
            );
        }
        assert!(
            !d.contains("only the kernel's copy is wrong"),
            "the retracted #290 conclusion must not come back: {d}"
        );
        assert!(
            !d.contains("failed 15 times out of 20"),
            "the stride failure is fixed; the warning must not present it as live: {d}"
        );
    }

    /// The warning exists to change what the user does next, so it has to carry
    /// the workaround and the measured numbers behind it. Both were wrong for a
    /// long time -- the message claimed "1 run in 7" while the measured rate on
    /// a rehydrated Graviton guest was 10 of 10 -- so pin them.
    #[test]
    fn the_icache_warning_hands_over_the_workaround_and_not_just_the_diagnosis() {
        let d = icache_detail();
        // Assembled from parts so this cannot match its own assertion text.
        let opt = format!("NODE_{}", "OPTIONS=--jitless");
        assert!(
            d.contains(&opt),
            "the warning must name the env var that fixes it: {d}"
        );
        assert!(
            d.contains("20 times out of 20"),
            "the measured rate now that the stride is corrected at restore"
        );
        assert!(
            d.contains("998 times in 1000"),
            "the measured residual, which is what still justifies the workaround"
        );
        // #261: the workaround's limit is part of the workaround. A reader who
        // sets NODE_OPTIONS and then watches a native binary SIGILL -- while
        // being told to reinstall a package that is already installed -- is
        // worse off than one who was never given the variable, because the
        // message they get next points away from the real cause.
        assert!(
            d.contains("reaches node and nothing else"),
            "the warning must say what NODE_OPTIONS does not cover: {d}"
        );
        assert!(
            d.contains("SIGILL"),
            "the measured outcome for a native platform binary: {d}"
        );
        assert!(
            !d.contains("1 run in 7"),
            "the old understated figure must not come back"
        );
        assert!(
            d.contains("profile.d"),
            "telling the user how to make it stick is the difference between \
             a one-shot and a fix"
        );
        // Measured 2026-08-10, then re-measured and corrected 2026-08-11. The
        // exec-path claim was the wrong conclusion from a real observation: the
        // 35 crashes under dd/sync/rm load are the ASID-width delta, not this.
        // Performing the maintenance host-side (mechanism separately proven
        // guest-visible) changed the count by nothing, and removing virtio-blk
        // from the load did not help either. A warning that keeps a falsified
        // attribution sends the reader to a workaround that cannot work, so the
        // retraction is pinned here rather than left to prose.
        assert!(
            !d.contains("only cold boot does"),
            "the falsified exec-path attribution must not come back: {d}"
        );
        assert!(
            !d.contains("35 crashes"),
            "those crashes belong to asid_detail(), not here: {d}"
        );
        assert!(
            d.contains("changed the crash count by"),
            "the warning must carry the null result that narrowed its scope: {d}"
        );
        assert!(
            d.contains("ASID-width delta"),
            "a reader whose guest is crashing must be sent to the right warning: {d}"
        );
    }

    /// Asserting on `icache_detail()` says nothing about what the guard actually
    /// prints -- re-inlining the old string would leave the test above perfectly
    /// green and unused. This repo has been bitten by that call-site class four
    /// times, so read the source. The needle is assembled from parts or it
    /// matches its own assertion text.
    #[test]
    fn the_guard_prints_the_text_the_test_above_checks() {
        let src = include_str!("imp.rs");
        let needle = format!("let detail = icache_{}();", "detail");
        assert!(
            src.contains(&needle),
            "icache_dic_guard must emit icache_detail(), not its own literal"
        );
    }

    /// The bit position is the whole guard, so pin it against the two measured
    /// values rather than trusting the shift to stay right under edits.
    #[test]
    fn icache_guard_reads_bit_29_and_not_a_neighbour() {
        fn elides(ctr: u64) -> bool {
            (ctr & (1 << 29)) != 0
        }
        assert!(elides(0xb444_c004), "Graviton2 capture");
        assert!(!elides(0x9444_c004), "Apple silicon");
        // IDC (bit 28) is 1 on both, so a one-off shift would pass everything.
        assert!(elides(0x9444_c004 | (1 << 29)));
        assert!(!elides(0x9444_c004 & !(1 << 28)));
        assert!(!elides(0), "absent register");
    }

    fn snap_with_no_sysregs() -> Snapshot {
        Snapshot {
            mem_mappings: Vec::new(),
            vcpus: Vec::new(),
            gic_dist: Vec::new(),
            gic_rdist: Vec::new(),
            num_irq: 0,
            captured_cntfrq: None,
            captured_realtime_ns: None,
        }
    }

    /// The whole point of the strict mode is that it *refuses*, so pin that the
    /// two EL0 encodings are distinguished rather than both being waved through.
    #[test]
    fn aarch32_strict_mode_refuses_a_32_bit_capable_capture() {
        fn has_aarch32(pfr0: u64) -> bool {
            (pfr0 & 0xf) == 2
        }
        assert!(has_aarch32(0x1100_0000_1111_1112), "Graviton2 capture");
        assert!(!has_aarch32(0x1100_0000_1111_1111), "AArch64-only host");
        assert!(!has_aarch32(0), "absent register");
    }

    /// Derived from the host timebase rather than hardcoded, so assert the
    /// property (a plausible ARM system counter) rather than one machine's value.
    #[test]
    fn hvf_guest_cntfrq_is_derived_from_the_host_timebase() {
        let f = hvf_guest_cntfrq().expect("mach_timebase_info should succeed");
        assert!(
            (1_000_000..=1_000_000_000).contains(&f),
            "implausible counter frequency {f} Hz"
        );
    }

    /// A matching capture must be silent, and an unreadable one must not block a
    /// run — the guard is a diagnosis aid, not a gate (unless asked to be one).
    #[test]
    fn cntfrq_guard_admits_matching_and_unknown_captures() {
        let host = hvf_guest_cntfrq().unwrap();
        let matching =
            format!(r#"{{"snapshot_data":{{"state":"{{\"clock\":{{\"cntfrq\":{host}}}}}"}}}}"#);
        cntfrq_guard(&matching).unwrap();
        cntfrq_guard(r#"{"snapshot_data":{"state":"{}"}}"#).unwrap();
    }

    /// The Graviton2 case, which is the one that actually happened: warn by
    /// default so the guest still runs, and name the dilation factor so it is
    /// diagnosed rather than mistaken for a slow machine.
    #[test]
    fn cntfrq_guard_warns_but_admits_a_mismatched_capture() {
        let graviton =
            r#"{"snapshot_data":{"state":"{\"clock\":{\"cntfrq\":121875000}}"}}"#;
        assert!(
            cntfrq_guard(graviton).is_ok(),
            "a mismatch must not block the run by default -- refusing would mean \
             no cloud snapshot ever starts on a Mac"
        );
    }

    #[test]
    fn effective_wall_secs_takes_the_tighter_cap() {
        // Flag only, limit only, both (tighter wins), neither.
        assert_eq!(effective_wall_secs(30, None), Some(30));
        assert_eq!(effective_wall_secs(0, Some(60)), Some(60));
        assert_eq!(effective_wall_secs(30, Some(60)), Some(30));
        assert_eq!(effective_wall_secs(90, Some(60)), Some(60));
        assert_eq!(effective_wall_secs(0, None), None);
        assert_eq!(effective_wall_secs(0, Some(0)), None);
    }

    #[test]
    fn dir_size_bytes_counts_allocation_not_logical_length() {
        let dir = std::env::temp_dir().join(format!("chm-dsz-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // Missing dir reads as 0 (the cap simply never trips).
        assert_eq!(dir_size_bytes(&dir), 0);
        fs::create_dir_all(&dir).unwrap();

        // A sparse file: 8 GiB logical length, but no data written -> ~no blocks.
        let sparse = fs::File::create(dir.join("sparse.raw")).unwrap();
        sparse.set_len(8 * 1024 * 1024 * 1024).unwrap();
        drop(sparse);
        // A real 1 MiB write.
        fs::write(dir.join("real.raw"), vec![7u8; 1024 * 1024]).unwrap();
        fs::create_dir_all(dir.join("nested")).unwrap(); // ignored (not a file)

        let sz = dir_size_bytes(&dir);
        assert!(sz >= 1024 * 1024, "the real 1 MiB write is counted: {sz}");
        assert!(
            sz < 64 * 1024 * 1024,
            "the 8 GiB sparse file must NOT count as its logical length: {sz}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_egress_policy_builds_a_restrictive_allow_list() {
        let raw = r#"{"digest":"sha256:abc","default":"deny",
            "allow":["api.github.com:443"],"deny":["blocked.test"]}"#;
        let p = parse_egress_policy(raw).expect("parse");
        assert!(p.is_restrictive());
        assert_eq!(p.label(), "sha256:abc");
        assert!(p.decide_dns("api.github.com").is_allow());
        assert!(!p.decide_dns("evil.test").is_allow(), "unlisted name denied");
        assert!(!p.decide_dns("blocked.test").is_allow(), "deny rule wins");
    }

    #[test]
    fn parse_egress_policy_defaults_to_allow_when_unspecified() {
        let p = parse_egress_policy(r#"{"digest":"sha256:x"}"#).expect("parse");
        assert!(!p.is_restrictive(), "no default/deny => allow-all");
        assert!(p.decide_dns("anything.test").is_allow());
    }

    /// #269. The direction a member would have moved the posture decides what
    /// happens to it: a restriction we cannot read is refused, a permission we
    /// cannot read is dropped and reported. Both directions pinned here,
    /// because a rule that only ever refuses is indistinguishable from a parser
    /// that refuses everything.
    #[test]
    fn an_unreadable_restriction_is_refused_and_an_unreadable_permission_is_not() {
        // Permission we cannot read: tighter than written, so carry on. The
        // readable entries must survive -- dropping the whole list would be a
        // silent tightening of its own.
        let p = parse_egress_policy(
            r#"{"default":"deny","allow":["api.github.com:443",{"host":"b.test"},7]}"#,
        )
        .expect("a dropped allow entry must not fail the policy");
        assert!(
            p.decide_dns("api.github.com").is_allow(),
            "readable entry kept"
        );
        assert!(
            !p.decide_dns("b.test").is_allow(),
            "unreadable entry not honoured"
        );

        // `allow` that is not a list at all: same direction, same treatment.
        assert!(
            parse_egress_policy(r#"{"default":"deny","allow":"api.github.com:443"}"#).is_some(),
            "a mistyped allow list is still only a tightening"
        );

        // Restriction we cannot read: honouring the policy would permit traffic
        // its author blocked, so refuse and let the caller fail closed.
        assert!(
            parse_egress_policy(r#"{"default":"allow","deny":[{"host":"evil.test"}]}"#).is_none(),
            "an unreadable deny entry must not be quietly skipped"
        );
        assert!(
            parse_egress_policy(r#"{"default":"allow","deny":"evil.test"}"#).is_none(),
            "a mistyped deny list is a restriction we cannot honour"
        );

        // The stance itself. `{"default": false}` used to read as "allow", so a
        // document that plainly meant to restrict produced an open sandbox.
        assert!(
            parse_egress_policy(r#"{"default":false,"allow":["a.test:443"]}"#).is_none(),
            "a non-string stance must not silently become allow-all"
        );
        // Absent still means allow -- that is a real choice, not a typo.
        assert!(
            !parse_egress_policy(r#"{"allow":["a.test:443"]}"#)
                .expect("absent default is fine")
                .is_restrictive()
        );
    }

    #[test]
    fn parse_egress_policy_rejects_malformed_json() {
        assert!(parse_egress_policy("not json").is_none());
    }

    #[test]
    fn an_unlabelled_local_policy_is_not_attributed_to_a_control_plane() {
        // `chm firewall set` writes a document with no digest and no label. The
        // posture line (V9.17) prints whatever label it resolves to, so a
        // hardcoded fallback would tell a Mac-only user their own policy came
        // from a cloud they have never contacted.
        let ws = std::env::temp_dir().join(format!("chm-lbl-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");
        fs::write(
            ws.join("egress-policy.json"),
            r#"{"default":"deny","allow":["api.github.com:443"]}"#,
        )
        .expect("write");
        let p = resolved_policy(&overlay, None).expect("a policy");
        assert_eq!(p.label(), "local", "a workspace file is the operator's");
        assert!(
            !egress_posture_line(Some(&p)).contains("control-plane"),
            "the line the operator reads must not name a control plane"
        );
        // A document that *does* carry a digest still wins over the fallback.
        fs::write(
            ws.join("egress-policy.json"),
            r#"{"digest":"sha256:pinned","default":"deny","allow":["a.test:443"]}"#,
        )
        .expect("write");
        assert_eq!(
            resolved_policy(&overlay, None).expect("a policy").label(),
            "sha256:pinned"
        );
        let _ = fs::remove_dir_all(&ws);
    }

    /// Test helper: resolve and return the enforceable policy, or None for an
    /// unrestricted resolution. Panics if the resolution fails closed.
    fn resolved_policy(overlay: &Path, cli: Option<&Path>) -> Option<EgressPolicy> {
        match resolve_egress_policy(overlay, cli) {
            EgressResolution::Unrestricted => None,
            EgressResolution::Policy(p, _) => Some(*p),
            EgressResolution::FailClosed(r) => panic!("unexpected fail-closed: {r}"),
        }
    }

    /// Every entry point that attaches a NIC must actually emit the posture.
    ///
    /// Reads the sources, because the other tests here assert on what
    /// `egress_posture_line` *returns* and an assertion about a return value
    /// structurally cannot see a call that is no longer made. Proved necessary:
    /// replacing the resume path's condition with `false` left all 673 tests
    /// green. Sixth time this class has appeared in this repo — see V9.5c,
    /// V9.11a M4, #222, #242.
    #[test]
    fn both_entry_points_still_report_the_posture() {
        // Assembled from parts so the needle cannot match this assertion itself.
        let call = format!("{}_posture_line(", "egress");
        for (what, src) in [
            ("the resume path", include_str!("imp.rs")),
            ("the cold-boot path", include_str!("create.rs")),
        ] {
            assert!(
                src.matches(call.as_str()).count() > if what == "the resume path" { 3 } else { 0 },
                "{what} no longer reports the egress posture at session start"
            );
        }
    }

    #[test]
    fn an_ungoverned_session_says_so_unprompted_and_names_the_remedy() {
        // The whole of #170: resuming a snapshot with no policy runs with the
        // public internet reachable, and today the only way to find that out is
        // to run a command you would only run if you already knew.
        let line = egress_posture_line(None);
        assert!(line.contains("the public internet is reachable"), "{line}");
        // It is a default, not a choice — otherwise the reader assumes someone
        // decided this for them and stops asking.
        assert!(line.contains("not a choice"), "{line}");
        // A warning with no remedy is a worry.
        assert!(line.contains("chm firewall set"), "{line}");
        // And it must not overstate: M31.1 still holds here.
        assert!(line.contains("stay blocked"), "{line}");
    }

    #[test]
    fn a_governed_session_is_described_by_the_policy_and_not_by_the_caller() {
        // Rendered through `posture_summary`, so this cannot drift from what the
        // NAT actually enforces. Restating it here would be the defect the
        // devmgr line had: a plausible sentence about a different sandbox.
        let allow = vec!["api.github.com:443".to_string()];
        let p = EgressPolicy::from_profile("deny", &allow, &[], "sha256:abc");
        let line = egress_posture_line(Some(&p));
        assert_eq!(
            line,
            format!("[egress] {} (sha256:abc)", p.posture_summary())
        );
        assert!(line.contains("api.github.com:443"), "{line}");
        assert!(!line.contains("not a choice"), "{line}");
    }

    #[test]
    fn resolve_egress_policy_reads_the_per_workspace_file() {
        // A local user's `chm firewall set` writes <workspace>/egress-policy.json;
        // a run whose overlay dir is <workspace>/.chm-overlays must pick it up.
        let ws = std::env::temp_dir().join(format!("chm-egress-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");
        fs::write(
            ws.join("egress-policy.json"),
            r#"{"default":"deny","allow":["api.github.com:443"],"label":"local"}"#,
        )
        .expect("write policy");

        let p = resolved_policy(&overlay, None).expect("policy resolved from workspace file");
        assert!(p.is_restrictive());
        assert_eq!(p.label(), "local");
        assert!(p.decide_dns("api.github.com").is_allow());
        assert!(!p.decide_dns("evil.test").is_allow());

        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn resolve_egress_policy_cli_override_beats_the_workspace_file() {
        // `--egress-policy <file>` is the most specific intent and must win over a
        // per-workspace file.
        let ws = std::env::temp_dir().join(format!("chm-egress-cli-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");
        fs::write(
            ws.join("egress-policy.json"),
            r#"{"default":"deny","allow":["only-workspace.test:443"]}"#,
        )
        .expect("write ws policy");
        let override_path = ws.join("override.json");
        fs::write(
            &override_path,
            r#"{"default":"deny","allow":["override.test:443"],"label":"flag"}"#,
        )
        .expect("write override");

        let p = resolved_policy(&overlay, Some(&override_path)).expect("override resolved");
        assert_eq!(p.label(), "flag");
        assert!(p.decide_dns("override.test").is_allow());
        assert!(
            !p.decide_dns("only-workspace.test").is_allow(),
            "the workspace file must not apply when the flag is set"
        );

        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn resolve_egress_policy_fails_closed_on_a_bad_source() {
        // A source that was specified but cannot be honored must fail closed
        // (deny-all), never silently run unrestricted (M30.9).
        let ws = std::env::temp_dir().join(format!("chm-egress-fc-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");

        // (a) an explicit flag pointing at a missing file.
        let missing = ws.join("nope.json");
        assert!(
            matches!(
                resolve_egress_policy(&overlay, Some(&missing)),
                EgressResolution::FailClosed(_)
            ),
            "a missing --egress-policy file must fail closed"
        );

        // (b) a malformed per-workspace file.
        fs::write(ws.join("egress-policy.json"), b"{ not json").expect("write bad");
        assert!(
            matches!(
                resolve_egress_policy(&overlay, None),
                EgressResolution::FailClosed(_)
            ),
            "a malformed workspace policy must fail closed"
        );

        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn resolve_egress_policy_is_unrestricted_without_any_source() {
        let ws = std::env::temp_dir().join(format!("chm-egress-none-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");
        // No env binding is set in this test process and no workspace file exists.
        assert!(matches!(
            resolve_egress_policy(&overlay, None),
            EgressResolution::Unrestricted
        ));
        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn egress_policy_applies_to_every_nic_via_clone() {
        // The wiring hands each virtio-net NIC a clone of the resolved policy, so
        // a snapshot with a second NIC cannot slip past the allow-list on an
        // ungoverned interface (M30.9). Model that: a restrictive policy cloned
        // for a second NIC still enforces.
        let p = EgressPolicy::from_profile("deny", &["api.github.com:443".to_string()], &[], "t");
        let nic1 = Some(p);
        let nic2 = nic1.clone(); // exactly what the wiring loop does for NIC #2
        // The literal `Some` is the subject here, not an oversight: the wiring
        // holds an `Option<EgressPolicy>` and hands NIC #2 a clone of it.
        #[expect(clippy::unnecessary_literal_unwrap)]
        let nic1 = nic1.unwrap();
        let nic2 = nic2.expect("second NIC must receive the policy, not None");
        assert!(nic1.decide_dns("api.github.com").is_allow());
        assert!(
            !nic2.decide_dns("evil.test").is_allow(),
            "a second NIC must enforce the same deny, not run unrestricted"
        );
        assert!(nic2.decide_dns("api.github.com").is_allow());
    }

    #[test]
    fn fail_closed_builds_a_deny_all_policy() {
        // The fail-closed branch of the wiring builds this policy; it must deny
        // every destination so a governed-but-unresolved session is not open.
        let deny_all = EgressPolicy::from_profile("deny", &[], &[], "fail-closed");
        assert!(deny_all.is_restrictive());
        assert!(!deny_all.decide_dns("anything.test").is_allow());
        assert!(!deny_all.decide_dns("api.github.com").is_allow());
    }

    #[test]
    fn parse_connect_accepts_session_lock() {
        let raw: Vec<String> = ["snap", "--session-lock", "/tmp/chm-test.lock"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match parse_connect(&raw) {
            Parsed::Connect(args) => {
                assert_eq!(
                    args.run.session_lock.as_deref(),
                    Some(Path::new("/tmp/chm-test.lock"))
                );
                assert_eq!(args.run.snapshot_dir, PathBuf::from("snap"));
            }
            _ => panic!("expected Parsed::Connect with a session lock"),
        }
    }

    /// The flag has to be able to say *off*, or a caller inside an environment
    /// that sets `CHM_SNAPSHOT_INTERVAL_SECS` cannot run one guest without the
    /// cadence except by unsetting a variable it does not own.
    #[test]
    fn a_flag_can_turn_the_cadence_off_even_when_the_environment_turns_it_on() {
        let env_on = Some("60".to_string());

        assert_eq!(
            snapshot_interval(None, env_on.clone()),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            snapshot_interval(Some(15), env_on.clone()),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            snapshot_interval(Some(0), env_on),
            None,
            "--snapshot-every 0 must beat the environment"
        );
        assert_eq!(snapshot_interval(None, None), None);
    }

    /// There is no reading of `CHM_SNAPSHOT_INTERVAL_SECS=nonsense` under which
    /// freezing someone's guest on an invented cadence is the helpful answer.
    #[test]
    fn an_unusable_environment_value_leaves_the_cadence_off() {
        for bad in ["nonsense", "", "  ", "-5", "12s", "0"] {
            assert_eq!(
                snapshot_interval(None, Some(bad.to_string())),
                None,
                "`{bad}` should not start a cadence"
            );
        }
        assert_eq!(
            snapshot_interval(Some(30), Some("nonsense".to_string())),
            Some(Duration::from_secs(30)),
            "a usable flag should not be spoiled by an unusable environment"
        );
    }

    #[test]
    fn both_entry_points_take_snapshot_every() {
        let argv = |extra: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = vec!["snap".to_string()];
            v.extend(extra.iter().map(|s| (*s).to_string()));
            v
        };

        match parse(&argv(&["--snapshot-every", "45"])) {
            Parsed::Run(a) => assert_eq!(a.snapshot_every, Some(45)),
            _ => panic!("run: expected Parsed::Run"),
        }
        match parse(&argv(&[])) {
            Parsed::Run(a) => assert_eq!(
                a.snapshot_every, None,
                "absent means defer to the environment"
            ),
            _ => panic!("run: expected Parsed::Run"),
        }
        match parse_connect(&argv(&["--snapshot-every", "0"])) {
            Parsed::Connect(a) => assert_eq!(
                a.run.snapshot_every,
                Some(0),
                "zero must survive parsing as a value, not vanish"
            ),
            _ => panic!("connect: expected Parsed::Connect"),
        }
        assert!(
            matches!(
                parse(&argv(&["--snapshot-every", "soon"])),
                Parsed::Error(_)
            ),
            "a non-number should be refused rather than read as off"
        );
    }

    /// `chm connect` had a `--proxy-rules` arm the outer guard never routed to,
    /// so the flag that carries credential-injection rules — and, since #163,
    /// the egress allowance that goes with them — was refused as unknown on the
    /// one entry point the app uses.
    #[test]
    fn connect_accepts_the_proxy_rules_flag_it_has_an_arm_for() {
        let raw: Vec<String> = ["snap", "--proxy-rules", "/tmp/rules.json"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        match parse_connect(&raw) {
            Parsed::Connect(a) => assert_eq!(
                a.run.proxy_rules.as_deref(),
                Some(Path::new("/tmp/rules.json"))
            ),
            _ => panic!("expected Parsed::Connect"),
        }
    }

    /// A flag that parses and is never read is the failure this repo has now
    /// been caught by five times, and every assertion above stays green through
    /// it. So read the source and require that the cadence resolver is actually
    /// asked for the run's own value.
    ///
    /// The needle is assembled from parts because a literal here would match
    /// this test's own text (#241).
    #[test]
    fn the_snapshotter_asks_the_run_for_its_cadence() {
        let src = include_str!("imp.rs");
        let call = format!("snapshot_interval(s.{}, env::var(", "every");
        assert!(
            src.contains(&call),
            "spawn_live_snapshotter must pass the run's --snapshot-every to the resolver"
        );
        let wiring = format!("every: cfg.{},", "snapshot_every");
        assert!(
            src.contains(&wiring),
            "the LiveSnapshotter must be built with the config's cadence"
        );
    }

    #[test]
    fn session_lock_writes_pid_and_removes_on_drop() {
        let path =
            env::temp_dir().join(format!("chm-session-lock-test-{}.lock", process::id()));
        let _ = fs::remove_file(&path);
        {
            let _lock = SessionLock::acquire(&path).expect("acquire session lock");
            let body = fs::read_to_string(&path).expect("read session lock");
            assert_eq!(body.trim(), process::id().to_string());
        }
        assert!(!path.exists(), "lock file must be removed when the guard drops");
    }
}

#[cfg(test)]
mod revisions_args_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The bug this locks out was found by *using* the command, not by the unit
    /// tests: they called `pin_revision` directly and never crossed the arg
    /// parser, which had wanted the verb before the directory. Every other
    /// command here — `rollback` most closely — takes SNAPSHOT_DIR immediately
    /// after the verb, so that is the order.
    #[test]
    fn pin_takes_the_directory_first_like_every_other_command() {
        let dir = std::env::temp_dir().join(format!("chm-revargs-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Directory first is accepted: it gets far enough to reject the id on
        // its merits rather than complaining about the shape of the command.
        let err = revisions(&args(&[dir.to_str().unwrap(), "pin", "rev-absent"]))
            .expect_err("an unknown revision must be refused");
        assert!(
            err.contains("rev-absent"),
            "the parser should have reached revision lookup, got: {err}"
        );

        // Verb first — the order the help used to document — is refused, and
        // the message says what to do rather than restating the usage line.
        let err = revisions(&args(&["pin", dir.to_str().unwrap(), "rev-absent"]))
            .expect_err("verb-first must be refused");
        assert!(
            err.contains("after the directory"),
            "the error should name the correct order, got: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The usage text is the only place a user learns the order, so drift
    /// between it and the parser is the defect itself, not a cosmetic one.
    /// Reading the same constant the parser prints makes them one thing.
    #[test]
    fn the_usage_text_documents_the_order_the_parser_accepts() {
        for verb in ["pin", "unpin", "label", "delete", "gc", "export", "import"] {
            assert!(
                REVISIONS_USAGE.contains(&format!("<SNAPSHOT_DIR> {verb}")),
                "help must show `{verb}` after the directory, got:\n{REVISIONS_USAGE}"
            );
            assert!(
                !REVISIONS_USAGE.contains(&format!("revisions {verb} ")),
                "help must not document verb-first, which the parser refuses"
            );
            assert!(
                revisions_arity(verb, false, false).is_some(),
                "`{verb}` is documented but the parser does not dispatch it"
            );
        }
    }

    /// The verbs take different numbers of arguments, so one shared arity would
    /// either reject `gc` (which takes none) or wave through a `delete` with no
    /// revision id — and a delete that guessed its target would be the worst
    /// possible defect in this command.
    #[test]
    fn each_verb_checks_its_own_arity() {
        let dir = std::env::temp_dir().join(format!("chm-revarity-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();

        // Too few: a delete with no id must not be interpreted as anything.
        let err = revisions(&args(&[d, "delete"])).expect_err("delete needs an id");
        assert!(err.contains("delete"), "{err}");
        // Too many: `gc` takes none, so an id is a mistake worth naming.
        let err = revisions(&args(&[d, "gc", "rev-1"])).expect_err("gc takes no id");
        assert!(err.contains("gc"), "{err}");
        // `label` needs its text, unless --clear says there is none.
        assert!(revisions(&args(&[d, "label", "rev-absent"])).is_err());
        let err = revisions(&args(&[d, "label", "rev-absent", "--clear"]))
            .expect_err("an unknown id must still be refused");
        assert!(
            err.contains("rev-absent"),
            "--clear should reach revision lookup, got: {err}"
        );
        // An unknown verb names the ones that exist rather than the usage line.
        let err = revisions(&args(&[d, "purge", "rev-1"])).expect_err("unknown verb");
        assert!(err.contains("delete"), "the error should list real verbs: {err}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// `--with-base` is parsed, stored and threaded through, and every
    /// assertion about what a bundle contains still passes if the flag is
    /// dropped on the way to `export` -- a test that asserts an outcome
    /// structurally cannot see a path that is no longer taken. This repo has
    /// now banked that eight times, so the guard reads the call itself.
    ///
    /// The needle is assembled from parts because a guard whose needle appears
    /// in its own assertion text matches itself and can never fail.
    #[test]
    fn the_with_base_flag_reaches_export_rather_than_being_parsed_and_dropped() {
        let src = include_str!("imp.rs");
        let field = format!("opts.{}_base", "with");
        let call = format!("bundle::export(dir, &ids, Path::new(out.as_str()), {field})");
        assert!(
            src.contains(&call),
            "export must be handed the flag the user typed; found instead: {:?}",
            src.lines()
                .find(|l| l.contains("bundle::export("))
                .unwrap_or("<no call at all>")
        );
        let parse = format!("--{}-base", "with");
        assert!(
            src.contains(&parse),
            "and the flag must still be recognised on the command line"
        );
    }
}

#[cfg(test)]
mod vanilla_args_tests {
    use super::*;

    /// The dispatch arm hands `vanilla()` the slice *after* `vanilla`, so the
    /// sub-verb is at index 0. This shipped indexing it at 1, which made
    /// `chm vanilla export A B` print usage and refuse forever -- the command
    /// could never do its job. Every unit test called the exporter directly,
    /// so none of them crossed the parser.
    #[test]
    fn export_parses_at_the_slice_the_dispatcher_actually_passes() {
        let argv: Vec<String> = ["export", "/snap", "/out"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        match parse_vanilla(&argv) {
            Ok(VanillaCmd::Export { dir, out, json }) => {
                assert_eq!(dir, PathBuf::from("/snap"));
                assert_eq!(out, PathBuf::from("/out"));
                assert!(!json);
            }
            other => panic!("expected an Export, got {other:?}"),
        }
    }

    /// The parse tests above are only meaningful if the dispatcher really does
    /// strip one element. Mutating a function is not mutating its call site,
    /// so pin the call site itself.
    #[test]
    fn the_vanilla_dispatch_arm_strips_only_the_subcommand_name() {
        let src = include_str!("imp.rs");
        let needle = format!("Some(\"vanilla\") => match {}(&raw[1..])", "vanilla");
        assert!(
            src.contains(&needle),
            "the vanilla dispatch arm no longer passes `&raw[1..]`; \
             parse_vanilla indexes the sub-verb at 0 and would be off by one"
        );
    }

    #[test]
    fn a_json_flag_is_not_mistaken_for_a_positional() {
        let argv: Vec<String> = ["export", "/snap", "/out", "--json"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        match parse_vanilla(&argv) {
            Ok(VanillaCmd::Export { json, dir, .. }) => {
                assert!(json, "--json was dropped");
                assert_eq!(dir, PathBuf::from("/snap"));
            }
            other => panic!("expected an Export, got {other:?}"),
        }
    }

    /// An explicit help request is a success, and it must win over an
    /// otherwise-invalid argument list rather than being reported as an error.
    #[test]
    fn an_explicit_help_request_is_not_an_error() {
        for flag in ["-h", "--help"] {
            let argv = vec![flag.to_string()];
            assert_eq!(parse_vanilla(&argv), Ok(VanillaCmd::Help), "{flag}");
        }
        let argv: Vec<String> = ["export", "--help"].iter().map(|s| (*s).to_string()).collect();
        assert_eq!(parse_vanilla(&argv), Ok(VanillaCmd::Help));
    }

    /// Each refusal has to name what was actually wrong; a single generic
    /// message would send a reader to the wrong half of the command line.
    #[test]
    fn each_way_of_getting_it_wrong_is_refused_by_name() {
        let call = |args: &[&str]| {
            parse_vanilla(&args.iter().map(|s| (*s).to_string()).collect::<Vec<String>>())
                .expect_err("should have been refused")
        };
        assert!(call(&[]).contains("expected `export <SNAPSHOT_DIR> <OUT_DIR>`"));
        assert!(call(&["frobnicate", "a", "b"]).contains("frobnicate"));
        let short = call(&["export", "/snap"]);
        assert!(short.contains("got 1"), "{short}");
        let long = call(&["export", "/snap", "/out", "/extra"]);
        assert!(long.contains("got 3"), "{long}");
    }

    /// The usage text is printed straight to a terminal, so a continuation
    /// that keeps its source indentation renders as a ragged five-space step.
    #[test]
    fn the_usage_text_carries_no_accidental_indentation() {
        for (n, line) in VANILLA_USAGE.lines().enumerate() {
            assert!(
                !line.starts_with(' '),
                "VANILLA_USAGE line {n} is indented: {line:?}"
            );
        }
    }
}
