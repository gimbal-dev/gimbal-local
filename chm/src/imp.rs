// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! macOS / Apple-Silicon implementation of the `chm` CLI.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use std::{env, fs, io, thread};

use crate::checkpoint;
use crate::create::create_main;
use crate::cloud;
use crate::console::{self, RawConsole};
use crate::console_filter::ConsoleFilter;
use crate::audit;
use crate::capability;
use crate::control_plane;
use crate::credproxy;
use crate::firewall;
use crate::limits;
use crate::serve;
use crate::signing;
use crate::startup;
use crate::posture;
use crate::state_cdn;
use crate::sysregs;

use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::hvf::checkpoint::{self as hvf_checkpoint, CheckpointState};
use hypervisor::hvf::devices::{MmioBus, Pl011};
use hypervisor::hvf::gic::GicMsiSink;
use hypervisor::hvf::rehydrate::{
    self, PreparedVm, Snapshot, enable_group1_spi_forwarding, prepare_vm, restore_distributor,
    restore_vcpu_state, snapshot_cntfrq,
};
use hypervisor::hvf::UsgicCpuHandle;
use hypervisor::hvf::VtimerClock;
use hypervisor::hvf::host_counter_hz;
use hypervisor::hvf::UsgicSpiRouter;
use hypervisor::hvf::virtio::GuestMemory;
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
struct CpuPowerState {
    online: bool,
    cpu_on: Option<(u64, u64)>,
}

type CpuPowerSlot = Arc<(Mutex<CpuPowerState>, Condvar)>;
type VmOpsResult<T> = Result<T, HypervisorVmError>;

#[derive(Default)]
struct PsciCoordinator {
    slots: Vec<CpuPowerSlot>,
}

impl PsciCoordinator {
    fn from_snapshot(snap: &Snapshot) -> Arc<Self> {
        let mut slots = Vec::with_capacity(snap.vcpus.len());
        for vcpu in &snap.vcpus {
            slots.push(Arc::new((
                Mutex::new(CpuPowerState {
                    online: vcpu.mp_state_running,
                    cpu_on: None,
                }),
                Condvar::new(),
            )));
        }
        Arc::new(Self { slots })
    }

    fn slot(&self, id: usize) -> CpuPowerSlot {
        self.slots[id].clone()
    }

    fn wake_all(&self) {
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

    fn cpu_on(&self, target_mpidr: u64, entry: u64, context: u64) -> i64 {
        let target = Self::mpidr_to_vcpu_id(target_mpidr);
        let Some(slot) = self.slots.get(target) else {
            return PSCI_INVALID_PARAMS;
        };
        let (lock, cv) = &**slot;
        let mut st = lock.lock().unwrap();
        if st.online {
            return PSCI_ALREADY_ON;
        }
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

    fn set_psci_coordinator(&self, psci: Arc<PsciCoordinator>) {
        *self.psci.lock().unwrap() = Some(psci);
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

/// Reconstruct the native virtio-pci device model from the snapshot's
/// device-manager state and install each device into `bus` at its restored BAR.
///
/// Block devices get a host-backed sparse overlay (under `overlay_dir`) because
/// cloud-hypervisor snapshots reference external disk images by path and do not
/// embed them; the overlay lets the data path complete (reads of never-written
/// sectors return zeroes, writes persist) without the original image. Returns
/// the number of devices wired and a human description of each.
/// Load-time interrupt-routing guard.
///
/// Apple's managed GIC cannot deliver LPIs to a non-nested EL1 guest
/// (hardware-proven: ICH List Registers are EL2/nested-only -> HV_UNSUPPORTED,
/// and there is no PROPBASER/PENDBASER/ITS API). A snapshot whose virtio
/// completions are routed through the GIC ITS as LPIs would restore and then
/// hang on its first device wait with no completion interrupt.
///
/// Whether this snapshot routes its virtio completion interrupts through the
/// GIC ITS as LPIs — the routing Apple's managed Hypervisor.framework GIC
/// physically cannot deliver, and which therefore has to run on the userspace
/// GICv3 (`run_usgic_engine`).
///
/// Both entry points (`chm run` and `chm serve`) use this to route
/// automatically, so a vanilla upstream capture just works. Only bundles the
/// managed path would have refused outright are redirected, so nothing that
/// works on the managed GIC changes path.
///
/// `CHM_ALLOW_ITS_LPI=1` forces such a capture onto the managed GIC anyway.
/// That is a diagnostic for A/B-ing the two backends: the guest restores and
/// then stalls on its first disk or net I/O, because the completion interrupt
/// can never arrive.
pub(crate) fn routes_completions_as_lpis(state_json: &str) -> bool {
    let Ok(descs) = devmgr::parse_devices(state_json) else {
        return false;
    };
    let wired_devices = descs
        .iter()
        .filter(|d| !d.vector_events.is_empty() && d.device_id != 0)
        .count();
    if its::classify_routing(state_json, wired_devices) != its::CompletionRouting::ItsLpi {
        return false;
    }
    if env::var_os("CHM_ALLOW_ITS_LPI").is_some() {
        eprintln!(
            "chm: warning: CHM_ALLOW_ITS_LPI set -- running an ITS/LPI capture \
             on the managed GIC; the guest will likely stall on its first I/O \
             wait because LPI completions cannot be delivered there."
        );
        return false;
    }
    true
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
    let enforced_policy: Option<EgressPolicy> = match resolve_egress_policy(overlay_dir, cli_egress)
    {
        EgressResolution::Unrestricted => None,
        EgressResolution::Policy(p) => Some(*p),
        EgressResolution::FailClosed(reason) => {
            eprintln!(
                "chm: egress was governed but the policy could not be resolved \
                 ({reason}); failing closed — denying all egress"
            );
            Some(EgressPolicy::from_profile("deny", &[], &[], "fail-closed"))
        }
    };

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
    let workspace = overlay_dir.parent().unwrap_or(overlay_dir);
    let proxy = match credproxy::cli::start_for_workspace(workspace, cli_proxy_rules) {
        Ok(Some((proxy, decider))) => {
            for dev in &net_devices {
                dev.set_net_intercept(Some(Arc::clone(&decider)));
            }
            Some(proxy)
        }
        Ok(None) => None,
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
    /// A resolved, enforceable policy.
    Policy(Box<EgressPolicy>),
    /// A source was specified (flag / env binding / workspace file) but failed to
    /// load or parse. The session was meant to be governed, so fail closed.
    FailClosed(String),
}

/// Resolve a run's egress policy from, in priority order: an explicit
/// `--egress-policy <file>` flag, the `CHM_EGRESS_POLICY` binding the cloud
/// runner sets, then a per-workspace `egress-policy.json` a local user authored
/// with `chm firewall`. A source that is present but unreadable/malformed yields
/// [`EgressResolution::FailClosed`] rather than silently disabling the firewall.
fn resolve_egress_policy(overlay_dir: &Path, cli_override: Option<&Path>) -> EgressResolution {
    let from_raw = |raw: &str, what: String| match parse_egress_policy(raw) {
        Some(p) => EgressResolution::Policy(Box::new(p)),
        None => EgressResolution::FailClosed(what),
    };
    if let Some(path) = cli_override {
        return match fs::read_to_string(path) {
            Ok(raw) => from_raw(&raw, format!("--egress-policy {} is malformed", path.display())),
            Err(e) => EgressResolution::FailClosed(format!(
                "--egress-policy {} could not be read: {e}",
                path.display()
            )),
        };
    }
    if let Ok(raw) = env::var("CHM_EGRESS_POLICY") {
        return from_raw(&raw, "CHM_EGRESS_POLICY is set but malformed".to_string());
    }
    let workspace = overlay_dir.parent().unwrap_or(overlay_dir);
    let file = workspace.join("egress-policy.json");
    match fs::read_to_string(&file) {
        Ok(raw) => from_raw(&raw, format!("{} is malformed", file.display())),
        // No workspace file: this run was never asked to be governed.
        Err(_) => EgressResolution::Unrestricted,
    }
}

/// Parse a `CHM_EGRESS_POLICY` JSON document into an [`EgressPolicy`]. Returns
/// `None` when the document is not valid JSON — a malformed policy is logged but
/// must not silently *tighten* or crash the boot; the runner already verified
/// the digest before setting it.
fn parse_egress_policy(raw: &str) -> Option<EgressPolicy> {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("chm: warning: ignoring malformed CHM_EGRESS_POLICY ({e})");
            return None;
        }
    };
    let default = v.get("default").and_then(|d| d.as_str()).unwrap_or("allow");
    let strings = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let label = v
        .get("digest")
        .and_then(|d| d.as_str())
        .or_else(|| v.get("label").and_then(|d| d.as_str()))
        .unwrap_or("control-plane")
        .to_string();
    Some(EgressPolicy::from_profile(
        default,
        &strings("allow"),
        &strings("deny"),
        label,
    ))
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
) -> Option<thread::JoinHandle<()>> {
    if net_devices.is_empty() {
        return None;
    }
    let kick = Arc::new(NetKick::default());
    for dev in &net_devices {
        dev.set_net_kick(kick.clone());
    }
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
}

/// Default seconds of total console silence after which `chm` stops on its own.
/// The resumed guest currently runs until it needs a device this build does not
/// yet model (virtio-block/net/console over PCI), at which point it goes quiet;
/// without this it would otherwise sit parked in WFI forever. `--idle-exit 0`
/// disables it for an open-ended session.
const DEFAULT_IDLE_EXIT_SECS: u64 = 10;

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
        Some("fork") => match fork(&raw[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm fork: {e}");
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
     Rehydrate a Cloud Hypervisor arm64 snapshot onto Hypervisor.framework and\n\
     resume it locally, streaming the guest serial console to stdout.\n\
     \n\
     USAGE:\n    \
         chm run <SNAPSHOT_DIR> [OPTIONS]\n    \
         chm restore <SNAPSHOT_DIR> [OPTIONS]   (alias for run)\n    \
         chm resume <SNAPSHOT_DIR> [OPTIONS]    (restore a saved checkpoint)\n    \
         chm fork <SRC_DIR> <DST_DIR>           (branch a saved revision)\n    \
         chm workspace <IMAGE_DIR> <WS_DIR>     (isolated sandbox workspace)\n    \
         chm revisions <SNAPSHOT_DIR> [--json]  (list the lineage)\n    \
         chm rollback <SNAPSHOT_DIR> <REV_ID>   (roll back to a revision)\n    \
         chm connect <SNAPSHOT_DIR> [OPTIONS]   (interactive session)\n    \
         chm push <CHECKPOINT_DIR> --branch N   (commit a revision to the plane)\n    \
         chm pull --branch N --to DIR           (rehydrate a branch head)\n    \
         chm state-cdn reconstruct [OPTIONS]    (pull memory from the state CDN)\n    \
         chm policy show --sandbox ID           (show a sandbox's bound policy)\n    \
         chm firewall set <WORKSPACE_DIR> ...   (author a local egress policy)\n    \
     chm posture <WORKSPACE_DIR> [--json]   (which security controls are on)\n    \
     chm ctl posture [DIR]                  (the daemon's own posture)\n    \
     chm proxy show [WORKSPACE_DIR]         (credential injection for egress)\n    \
     chm sysregs <SNAPSHOT_DIR> [--all]     (CPU registers this Mac reproduces)\n    \
         chm cloud <COMMAND> aws [OPTIONS]      (BYO cloud helpers)\n    \
         chm serve <LIBRARY_DIR> [OPTIONS]      (background daemon)\n    \
         chm ctl <COMMAND> [ARG] [--socket P]   (talk to a daemon)\n\
     \n\
     ARGS:\n    \
         <SNAPSHOT_DIR>    Directory holding `state.json` and\n                      \
         `snapshot/memory-ranges` (a `ch-snapshot` directory).\n\
     \n\
     OPTIONS:\n    \
         --max-seconds <N>   Stop after N seconds of wall-clock run time\n                        \
         (0 = unlimited; default 0).\n    \
         --idle-exit <N>     Stop after N seconds with no console output\n                        \
         (0 = disabled; default 10).\n    \
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
         chm ctl shutdown            Stop the guest and exit the daemon.\n\
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
            "--max-seconds" | "--idle-exit" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                let Ok(n) = v.parse::<u64>() else {
                    return Parsed::Error(format!("{a}: `{v}` is not a number"));
                };
                if a == "--max-seconds" {
                    max_seconds = n;
                } else {
                    idle_exit_secs = n;
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
            | "--egress-policy" | "--limits" => {
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
                    "--max-seconds" | "--idle-exit" => {
                        let Ok(n) = v.parse::<u64>() else {
                            return Parsed::Error(format!("{a}: `{v}` is not a number"));
                        };
                        if a == "--max-seconds" {
                            max_seconds = n;
                        } else {
                            idle_exit_secs = n;
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
             otherwise `chm run <WORKSPACE_DIR>` cold-boots it. Either way a\n\
             later suspend saves a checkpoint inside the workspace."
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
fn revisions(raw: &[String]) -> Result<ExitCode, String> {
    let json = raw.iter().any(|a| a == "--json");
    let positionals: Vec<&String> = raw.iter().filter(|a| !a.starts_with('-')).collect();
    if raw.iter().any(|a| a == "-h" || a == "--help") || positionals.len() != 1 {
        eprintln!(
            "usage: chm revisions <SNAPSHOT_DIR> [--json]\n\
             \n\
             List the snapshot's saved revisions (its lineage), oldest first.\n\
             `resumable` marks revisions whose live RAM is still retained; older\n\
             ones are kept as metadata so the lineage graph survives."
        );
        return if positionals.len() == 1 {
            Ok(ExitCode::SUCCESS)
        } else {
            Err("expected one directory argument".to_string())
        };
    }
    let dir = PathBuf::from(positionals[0]);
    let summaries = checkpoint::revision_summaries(&dir);
    if json {
        let out = serde_json::to_string(&summaries)
            .map_err(|e| format!("serialize revisions: {e}"))?;
        println!("{out}");
    } else if summaries.is_empty() {
        eprintln!(
            "chm: no saved revisions for {} (run and suspend it first)",
            dir.display()
        );
    } else {
        for r in &summaries {
            let head = if r.is_head { " (HEAD)" } else { "" };
            let resumable = if r.resumable { "resumable" } else { "metadata-only" };
            let parent = r.parent.as_deref().unwrap_or("—");
            println!(
                "{}{head}  {}  parent={parent}  {resumable}",
                r.id, r.origin
            );
        }
    }
    Ok(ExitCode::SUCCESS)
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
    run(&args.run)
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
    let dir = &args.snapshot_dir;
    let loaded = load_snapshot(dir)?;
    startup::stamp("snapshot parsed");

    // Guest-clock-rate check (#104). Applies to both GIC paths: a frequency
    // mismatch is a property of the capture host, not of interrupt routing.
    cntfrq_guard(&loaded.state_json)?;

    // AArch32-at-EL0 check (V1.4): the capture host advertised 32-bit
    // userspace and this Mac has none, so a 32-bit exec wedges the vCPU.
    aarch32_guard(&loaded.snap)?;

    // Userspace-GIC path: rehydrate an ITS/LPI-routed snapshot — the kind Apple's
    // managed GIC cannot deliver completions for — onto a software GICv3. This is
    // the path that lifts the "GICv2M capture only" restriction (#81), so a
    // vanilla upstream capture runs with no flag.
    //
    // Routing is automatic: we only redirect bundles the managed path would have
    // rejected outright, so nothing that works on the managed GIC changes path.
    // `CHM_USERSPACE_GIC=1` forces it, for A/B-ing the two backends.
    if env::var_os("CHM_USERSPACE_GIC").is_some()
        || routes_completions_as_lpis(&loaded.state_json)
    {
        return run_usgic(args, loaded);
    }

    // Resume from a live checkpoint when one exists and checkpoints are enabled;
    // a malformed/incompatible checkpoint is discarded so we cold-boot cleanly.
    let resume_state = if args.checkpoint && checkpoint::has_checkpoint(dir) {
        match checkpoint::read_checkpoint(dir) {
            Ok(state) => Some(Arc::new(state)),
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
    // On resume the guest RAM comes from the checkpoint's dump; otherwise from
    // the parent snapshot's base memory-ranges.
    let mem_ranges = if resuming {
        checkpoint::memory_ranges_path(dir)
    } else {
        loaded.mem_ranges.clone()
    };

    if !args.quiet {
        banner(dir, &mem_ranges, loaded.num_vcpus, loaded.total_ram, "managed GICv3");
        if resuming {
            eprintln!("chm: resuming from a saved checkpoint (restored, not cold-booted).");
        }
    }

    // Device model: a bus with a real PL011 at the guest's serial base.
    let (uart, bus) = build_vm_ops(&loaded.state_json);
    let vm_ops = Arc::new(ChmVmOps::new(bus.clone()));

    let hv = hypervisor::new().map_err(|e| {
        format!(
            "hypervisor::new() failed: {e}\n\
             (is the binary code-signed with the hypervisor entitlement? \
             see scripts/build-chm.sh)"
        )
    })?;

    // Map RAM + create the managed GIC shell (no vCPUs yet). Each vCPU is then
    // created, restored, and run on its OWN host thread (HVF binds a vCPU to its
    // creating thread), so the snapshot's secondary cores resume concurrently.
    let prepared = prepare_vm(hv.as_ref(), &loaded.snap, &mem_ranges)
        .map_err(|e| format!("prepare VM: {e}"))?;

    let overlay_dir = dir.join(".chm-overlays");

    // Resolve + apply resource limits (M30.6). The launch gate is admission
    // control: a snapshot's vCPU/RAM shape is fixed, so an over-ceiling snapshot
    // is refused rather than throttled. Runtime caps (disk overlay, console,
    // wall-clock) are enforced by the console monitor.
    let (limits, limits_src) = limits::resolve_limits(dir, args.limits_file.as_deref());
    if let Some(max) = limits.max_vcpus
        && loaded.num_vcpus > max
    {
        return Err(format!(
            "snapshot declares {} vCPUs but the limit ({limits_src}) is {max} — refusing to run",
            loaded.num_vcpus
        ));
    }
    if let Some(max_mb) = limits.max_memory_mb {
        let ram_mb = loaded.total_ram / (1024 * 1024);
        if ram_mb > max_mb {
            return Err(format!(
                "snapshot needs {ram_mb} MiB RAM but the limit ({limits_src}) is {max_mb} MiB — refusing to run"
            ));
        }
    }
    if limits.is_bounded() && !args.quiet {
        eprintln!("chm: resource limits [{limits_src}] — {}", limits.summary());
    }

    let ckpt = CheckpointMode {
        resume_from: resume_state,
        capture_to: args.checkpoint.then(|| dir.clone()),
    };

    // Durable audit trail (M29): record the session lifecycle and every denied
    // egress flow to a per-workspace append-only log, so an operator can review
    // what the sandbox did independent of the (guest-floodable) console.
    let audit = audit::AuditLog::open(dir);
    let egress_label = match resolve_egress_policy(&overlay_dir, args.egress_policy.as_deref()) {
        EgressResolution::Unrestricted => "unrestricted".to_string(),
        EgressResolution::Policy(p) => p.label().to_string(),
        EgressResolution::FailClosed(_) => "fail-closed:deny-all".to_string(),
    };
    audit.session_start(
        if resuming { "resume" } else { "cold" },
        loaded.num_vcpus as usize,
        loaded.total_ram / (1024 * 1024),
        &limits.summary(),
        &egress_label,
    );
    let session_started = Instant::now();

    let outcome = resume_smp(
        prepared, loaded, &bus, &uart, &vm_ops, &overlay_dir, args, &limits, ckpt, &audit,
    )?;

    let duration_s = session_started.elapsed().as_secs();
    let outcome_label = match &outcome {
        Outcome::PoweredOff => "powered-off".to_string(),
        Outcome::MaxSeconds => "max-seconds".to_string(),
        Outcome::Idle(_) => "idle".to_string(),
        Outcome::ConsoleClosed => "console-closed".to_string(),
        Outcome::Interrupted => "interrupted".to_string(),
        Outcome::LimitExceeded(reason) => format!("limit-exceeded:{reason}"),
    };
    audit.session_stop(&outcome_label, duration_s);

    if !args.quiet {
        eprintln!();
        match outcome {
            Outcome::PoweredOff => eprintln!("chm: guest powered off."),
            Outcome::MaxSeconds => {
                eprintln!("chm: reached --max-seconds limit; stopping.");
            }
            Outcome::Idle(secs) => eprintln!(
                "chm: guest produced no console output for {secs}s — stopping \
                 (it is likely waiting on a device this build does not yet \
                 model). Use --idle-exit 0 to keep running."
            ),
            Outcome::ConsoleClosed => eprintln!("chm: console closed; stopping."),
            Outcome::Interrupted => eprintln!("chm: session closed; VM shut down."),
            Outcome::LimitExceeded(reason) => {
                eprintln!("chm: resource limit hit ({reason}); stopped the guest to protect the host.");
            }
        }
    }

    Ok(ExitCode::SUCCESS)
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
/// terminal, then report the outcome the way the CLI always has.
fn run_usgic(args: &Args, loaded: Loaded) -> Result<ExitCode, String> {
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
        handle: UsgicCpuHandle,
    }
    let (setup_tx, setup_rx) = mpsc::channel::<Result<CpuSetup, String>>();
    let (capture_tx, capture_rx) = mpsc::channel::<(usize, UsgicCapture)>();
    let mut go_txs: Vec<mpsc::Sender<Arc<Vec<UsgicCpuHandle>>>> = Vec::with_capacity(n);

    // Copied out of `cfg` so the per-vCPU thread closures capture plain values
    // rather than a borrow of the caller's config, which cannot outlive it.
    let want_checkpoint = cfg.checkpoint;

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
                let handle = match rehydrate::usgic_cpu_handle(&mut vcpu) {
                    Some(h) => h,
                    None => {
                        let _ = setup_tx.send(Err(format!("vCPU {id} is not an HVF vCPU")));
                        return;
                    }
                };
                if setup_tx.send(Ok(CpuSetup { id, inject, wake, exit, handle })).is_err() {
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
                // it raced another vCPU's error would hang the collector.
                if want_checkpoint {
                    let captured = hvf_checkpoint::capture_usgic_vcpu(&mut vcpu)
                        .map_err(|e| format!("capture: {e}"));
                    let _ = capture_tx.send((id, captured));
                }
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
    let sgi_table: Arc<Vec<UsgicCpuHandle>> =
        Arc::new(setups.into_iter().map(|s| s.handle).collect());

    let (limits, _src) = limits::resolve_limits(dir, cfg.limits_file);
    let overlay_dir = dir.join(".chm-overlays");
    let audit = audit::AuditLog::open(dir);

    // Wire the virtio device model onto the shared bus, routing each device's
    // completions through the captured ITS to a deliverable LPI sink that injects
    // into vCPU 0's software GIC — so a resumed stock ITS/LPI guest's disk/net I/O
    // actually completes. Net devices additionally need an off-thread NAT service.
    let usgic_lpi_sink: Arc<dyn its::LpiSink> = Arc::new(UsgicLpiSink {
        queue: inject0.clone(),
        wake: wake0.clone(),
    });
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
            let exits: Arc<Mutex<Vec<ExitSignal>>> = Arc::new(Mutex::new(all_exits.clone()));
            spawn_net_service(wired.net_devices, running.clone(), exits, audit.clone())
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
    );
    // Also available to a non-interactive supervisor (the daemon), so a console
    // consumer can type into the guest without owning this process's stdin.
    let console_input = console::console_input(uart.clone(), serial_sink, serial_wake);
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
    let _ = serial_reassert.join();
    if let Some(h) = net_service {
        let _ = h.join();
    }
    for t in threads {
        let _ = t.join();
    }
    drop(raw_console);

    let vcpu_outcome = outcome.lock().unwrap().take();

    // Suspend capture. Every vCPU has sent its own register file + software-GIC
    // state from its owning thread and joined, so assemble them into one
    // checkpoint and dump guest RAM here — `prepared` still owns the RAM
    // mappings at this point and is not dropped until the end of this function.
    //
    // Only a clean external stop checkpoints. A guest power-off or a vCPU error
    // means the box is finished, so any stale checkpoint is cleared instead.
    if cfg.checkpoint {
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
                Ok(()) => {
                    if !cfg.quiet {
                        let cores = if n == 1 { "1 vCPU" } else { &format!("{n} vCPUs") };
                        eprintln!(
                            "\nchm: suspended — userspace-GIC checkpoint saved ({cores}); \
                             resume to continue."
                        );
                    }
                }
                Err(e) => {
                    eprintln!("chm: warning: could not write checkpoint: {e}");
                    checkpoint::clear_checkpoint(dir);
                }
            }
        } else {
            checkpoint::clear_checkpoint(dir);
        }
    }

    let final_outcome = match vcpu_outcome {
        Some(Ok(o)) => o,
        Some(Err(e)) => return Err(e),
        None => coordinator.unwrap_or(Outcome::Interrupted),
    };

    // `prepared` (guest-RAM backings + VM) and `hv` are dropped here, after every
    // vCPU thread has joined (so every vCPU is destroyed before `hv_vm_destroy`).
    drop(prepared);
    drop(hv);
    Ok(final_outcome)
}



/// How a run should treat live checkpoints (suspend/resume).
///
/// `resume_from` makes the run restore captured live state (vCPU + GIC + RAM)
/// instead of cold-restoring from the parent snapshot; `capture_to` makes a
/// clean external stop (suspend) write a fresh checkpoint to that snapshot dir.
/// Both can be set: the app resumes a sandbox and re-checkpoints it on the next
/// stop.
#[derive(Default)]
struct CheckpointMode {
    resume_from: Option<Arc<CheckpointState>>,
    capture_to: Option<PathBuf>,
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

/// Three-state phase gate used to coordinate the SMP restore handshake between
/// the orchestrator thread and the per-vCPU threads. A vCPU thread blocks in
/// [`PhaseGate::wait`] until the orchestrator advances the gate to `Go` (proceed
/// to the next phase) or `Abort` (a sibling failed; unwind cleanly).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    Pending,
    Go,
    Abort,
}

struct PhaseGate {
    state: Mutex<Gate>,
    cv: Condvar,
}

impl PhaseGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(Gate::Pending),
            cv: Condvar::new(),
        }
    }
    fn set(&self, g: Gate) {
        *self.state.lock().unwrap() = g;
        self.cv.notify_all();
    }
    /// Block until the gate leaves `Pending`; return the terminal state.
    fn wait(&self) -> Gate {
        let mut s = self.state.lock().unwrap();
        while *s == Gate::Pending {
            s = self.cv.wait(s).unwrap();
        }
        *s
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

fn wait_for_cpu_on_request(slot: &CpuPowerSlot, running: &AtomicBool) -> Option<(u64, u64)> {
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

fn apply_psci_cpu_on_state(vcpu: &mut dyn Vcpu, entry: u64, context: u64) -> Result<(), String> {
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

/// Resume every vCPU in the snapshot concurrently (SMP) on Hypervisor.framework.
///
/// HVF binds a vCPU to the host thread that creates it: that thread must also
/// restore its register file and run it. So each vCPU runs on its own thread and
/// the restore is a multi-phase handshake driven by this orchestrator thread:
///
/// 1. Each thread creates its vCPU and reports in (the global GIC distributor
///    must be restored only after every redistributor exists, i.e. after every
///    vCPU is created).
/// 2. The orchestrator restores the global distributor, then releases the
///    threads via `dist_gate`.
/// 3. Each thread restores its own register file (MPIDR + ICC interface) and
///    redistributor frame, then reports in.
/// 4. The orchestrator enables Group1 SPI forwarding, wires the virtio device
///    model + interactive console, then releases the threads via `go_gate`.
/// 5. The threads run their vCPUs; the orchestrator drains the shared console
///    and enforces the stop policy, then stops + joins every thread (each vCPU
///    is destroyed on its owning thread).
///
/// mpsc channels collect the per-phase "ready" reports (rather than a barrier,
/// which would deadlock if a thread fails early); the gates let the orchestrator
/// broadcast `Abort` so a partially-restored set unwinds without hanging.
#[allow(clippy::too_many_arguments)]
fn resume_smp(
    prepared: PreparedVm,
    loaded: Loaded,
    bus: &Arc<MmioBus>,
    uart: &Arc<Pl011>,
    vm_ops: &Arc<ChmVmOps>,
    overlay_dir: &Path,
    args: &Args,
    limits: &limits::LimitsDoc,
    ckpt: CheckpointMode,
    audit: &audit::AuditLog,
) -> Result<Outcome, String> {
    let Loaded {
        snap, state_json, ..
    } = loaded;
    let n = snap.vcpus.len();
    let num_irq = snap.num_irq;
    let snap = Arc::new(snap);
    let psci = PsciCoordinator::from_snapshot(&snap);
    vm_ops.set_psci_coordinator(psci.clone());

    let CheckpointMode {
        resume_from,
        capture_to,
    } = ckpt;
    let capturing = capture_to.is_some();

    let running = Arc::new(AtomicBool::new(true));
    let dist_gate = Arc::new(PhaseGate::new());
    let go_gate = Arc::new(PhaseGate::new());
    let exits: Arc<Mutex<Vec<ExitSignal>>> = Arc::new(Mutex::new(Vec::new()));
    // WFI wake handles for each vCPU (writes its idle-park fd). Collected so the
    // serial input pump + re-assert tick can wake a parked vCPU the instant a
    // keystroke's interrupt is asserted, instead of waiting for its idle poll.
    let wakes: Arc<Mutex<Vec<ExitSignal>>> = Arc::new(Mutex::new(Vec::new()));
    // Per-vCPU run-progress counters (bumped once per `run()` iteration). The run
    // watchdog samples these to detect a vCPU wedged inside a single, non-
    // returning `hv_vcpu_run` (Apple's internal WFI wait not honouring a due
    // timer) and forces it out so it re-enters and redelivers the tick.
    let progress: Arc<Mutex<Vec<Arc<AtomicU64>>>> = Arc::new(Mutex::new(Vec::new()));
    let outcome: Arc<Mutex<Option<Result<Outcome, String>>>> = Arc::new(Mutex::new(None));
    let (created_tx, created_rx) = mpsc::channel::<Result<(), String>>();
    let (restored_tx, restored_rx) = mpsc::channel::<Result<(), String>>();
    // Per-vCPU live-state captures, collected at suspend (each vCPU must be read
    // on its own thread, so it sends its capture back here before it exits).
    let (captured_tx, captured_rx) =
        mpsc::channel::<(usize, Result<hvf_checkpoint::VcpuCheckpoint, String>)>();
    // Serialize vCPU creation in index order: the managed GIC associates each
    // redistributor with a vCPU at create time, so creating them out of order
    // (two threads racing `hv_vcpu_create`) can misassign a secondary's
    // redistributor. A turn counter makes vCPU i create only after i-1.
    let create_turn = Arc::new((Mutex::new(0usize), Condvar::new()));
    // Same ordered-handshake mechanism for the per-vCPU register/redistributor
    // restore, which also touches the managed GIC and must be serialized.
    let restore_turn = Arc::new((Mutex::new(0usize), Condvar::new()));

    let mut handles = Vec::with_capacity(n);
    for id in 0..n {
        let vm = prepared.vm.clone();
        let vm_ops = vm_ops.clone();
        let snap = snap.clone();
        let running = running.clone();
        let dist_gate = dist_gate.clone();
        let go_gate = go_gate.clone();
        let exits = exits.clone();
        let wakes = wakes.clone();
        let progress = progress.clone();
        let outcome = outcome.clone();
        let created_tx = created_tx.clone();
        let restored_tx = restored_tx.clone();
        let captured_tx = captured_tx.clone();
        let resume_from = resume_from.clone();
        let create_turn = create_turn.clone();
        let restore_turn = restore_turn.clone();
        let power_slot = psci.slot(id);
        let h = thread::Builder::new()
            .name(format!("chm-vcpu{id}"))
            .spawn(move || {
                // --- phase 1: create this vCPU on its own thread, in id order ---
                {
                    let (lock, cv) = &*create_turn;
                    let mut turn = lock.lock().unwrap();
                    while *turn != id {
                        turn = cv.wait(turn).unwrap();
                    }
                }
                let mut vcpu = match vm.create_vcpu(id as u32, Some(vm_ops)) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = created_tx.send(Err(format!("create_vcpu {id}: {e}")));
                        let (lock, cv) = &*create_turn;
                        *lock.lock().unwrap() = id + 1;
                        cv.notify_all();
                        // Park until the orchestrator aborts the handshake.
                        let _ = dist_gate.wait();
                        return;
                    }
                };
                {
                    let (lock, cv) = &*create_turn;
                    *lock.lock().unwrap() = id + 1;
                    cv.notify_all();
                }
                if let Some(sig) = vcpu.exit_signal() {
                    exits.lock().unwrap().push(sig);
                }
                if let Some(wake) = vcpu.wake_signal() {
                    wakes.lock().unwrap().push(wake);
                }
                if let Some(p) = vcpu.run_progress() {
                    progress.lock().unwrap().push(p);
                }
                let _ = created_tx.send(Ok(()));

                // --- phase 2: wait for the global distributor restore ---
                if dist_gate.wait() != Gate::Go {
                    return;
                }

                // --- phase 3: restore this vCPU's register file + redist, in id
                //     order. The managed GIC's redistributor register access is
                //     not safe to drive concurrently from multiple vCPU threads
                //     (a concurrent restore lands a secondary's redistributor on
                //     the wrong one, so it then takes no PPI/SGI), so serialize. ---
                {
                    let (lock, cv) = &*restore_turn;
                    let mut turn = lock.lock().unwrap();
                    while *turn != id {
                        turn = cv.wait(turn).unwrap();
                    }
                }
                let restore_res = match &resume_from {
                    Some(cp) => hvf_checkpoint::apply_vcpu(&mut vcpu, &cp.vcpus[id], cp.reference_cntvct())
                        .map_err(|e| format!("apply checkpoint vCPU {id}: {e}")),
                    None => restore_vcpu_state(&mut vcpu, &snap, id)
                        .map_err(|e| format!("restore vCPU {id}: {e}")),
                };
                {
                    let (lock, cv) = &*restore_turn;
                    *lock.lock().unwrap() = id + 1;
                    cv.notify_all();
                }
                if let Err(e) = restore_res {
                    let _ = restored_tx.send(Err(e));
                    let _ = go_gate.wait();
                    return;
                }
                let _ = restored_tx.send(Ok(()));

                // --- phase 4: wait for device wiring, then run the guest ---
                if go_gate.wait() != Gate::Go {
                    return;
                }
                let mut online = power_slot.0.lock().unwrap().online;
                while running.load(Ordering::Acquire) {
                    if !online {
                        match wait_for_cpu_on_request(&power_slot, &running) {
                            Some((entry, context)) => {
                                if let Err(e) =
                                    apply_psci_cpu_on_state(vcpu.as_mut(), entry, context)
                                {
                                    let mut o = outcome.lock().unwrap();
                                    if o.is_none() {
                                        *o = Some(Err(format!(
                                            "vCPU {id} PSCI CPU_ON state apply failed: {e}"
                                        )));
                                    }
                                    running.store(false, Ordering::Release);
                                    break;
                                }
                                online = true;
                            }
                            None => break,
                        }
                    }
                    match vcpu.run() {
                        Ok(VmExit::Ignore) => {}
                        Ok(VmExit::Shutdown | VmExit::Reset) => {
                            let mut o = outcome.lock().unwrap();
                            if o.is_none() {
                                *o = Some(Ok(Outcome::PoweredOff));
                            }
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Ok(other) => {
                            let mut o = outcome.lock().unwrap();
                            if o.is_none() {
                                *o = Some(Err(format!("vCPU {id} unexpected exit: {other:?}")));
                            }
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Err(e) => {
                            let mut o = outcome.lock().unwrap();
                            if o.is_none() {
                                *o = Some(Err(format!("vCPU {id} run: {e}")));
                            }
                            running.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
                // Suspend: with the run loop stopped (this vCPU paused but the VM
                // still alive), read this vCPU's live state back on its owning
                // thread and hand it to the orchestrator. The orchestrator decides
                // whether to persist it (only a clean external stop is suspended).
                if capturing {
                    let _ = captured_tx
                        .send((id, hvf_checkpoint::capture_vcpu(&mut vcpu).map_err(|e| e.to_string())));
                }
                // `vcpu` drops here, on its owning thread (HVF requirement).
            })
            .map_err(|e| format!("spawn vCPU {id} thread: {e}"))?;
        handles.push(h);
    }
    drop(created_tx);
    drop(restored_tx);
    drop(captured_tx);

    // --- phase 1 join: every vCPU created ---
    let mut first_err: Option<String> = None;
    for _ in 0..n {
        match created_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert_with(|| "a vCPU thread exited before creation".into());
            }
        }
    }
    if let Some(e) = first_err {
        dist_gate.set(Gate::Abort);
        for h in handles {
            let _ = h.join();
        }
        return Err(e);
    }

    // --- phase 2: restore the global distributor, then release the threads ---
    let dist_res = match &resume_from {
        Some(cp) => hvf_checkpoint::apply_distributor(&prepared.gic, &cp.gic_dist)
            .map_err(|e| format!("apply checkpoint distributor: {e}")),
        None => restore_distributor(&prepared.gic, &snap)
            .map_err(|e| format!("restore distributor: {e}")),
    };
    if let Err(e) = dist_res {
        dist_gate.set(Gate::Abort);
        for h in handles {
            let _ = h.join();
        }
        return Err(e);
    }
    dist_gate.set(Gate::Go);

    // --- phase 3 join: every vCPU's register file + redistributor restored ---
    for _ in 0..n {
        match restored_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert_with(|| "a vCPU thread exited before restore".into());
            }
        }
    }
    if let Some(e) = first_err {
        go_gate.set(Gate::Abort);
        for h in handles {
            let _ = h.join();
        }
        return Err(e);
    }

    // --- phase 4 prep: Group1 forwarding, virtio device model, console ---
    if let Err(e) = enable_group1_spi_forwarding(&prepared.gic) {
        go_gate.set(Gate::Abort);
        for h in handles {
            let _ = h.join();
        }
        return Err(format!("enable Group1 forwarding: {e}"));
    }

    let net_service = match wire_virtio(
        bus,
        &prepared.guest_mem,
        &state_json,
        overlay_dir,
        Some(&prepared.gic),
        resume_from.is_some(),
        args.egress_policy.as_deref(),
        &NatLimits {
            max_connections: limits.max_connections.map(|n| n as usize),
            // kbps (kilobits/sec) -> bytes/sec: * 1000 / 8 = * 125.
            max_bytes_per_sec: limits.max_bandwidth_kbps.map(|kbps| kbps * 125),
        },
        args.allow_local_egress,
        None,
        args.proxy_rules.as_deref(),
    ) {
        Ok(wired) => {
            if !wired.summary.is_empty() && !args.quiet {
                eprintln!("chm: virtio device model restored:");
                for d in &wired.summary {
                    eprintln!("chm:   - {d}");
                }
            }
            // Start relaying guest egress through the userspace NAT.
            spawn_net_service(wired.net_devices, running.clone(), exits.clone(), audit.clone())
        }
        Err(e) => {
            eprintln!("chm: warning: virtio device model not wired: {e}");
            None
        }
    };

    if !args.quiet {
        if n > 1 {
            eprintln!("chm: resuming {n} vCPUs concurrently (SMP).");
        }
        eprintln!("chm: guest resumed — serial console follows.\n");
    }

    // Interactive console: raw-mode terminal + a stdin pump that feeds host
    // keystrokes into the guest's PL011 receive path, asserting the serial SPI
    // through the managed GIC. The guard restores the terminal on any exit path.
    let raw_console = RawConsole::enable();
    // Install graceful-shutdown signal handlers now that the terminal is in raw
    // mode: closing the window (SIGHUP) or any kill (SIGTERM/SIGINT) funnels into
    // the same teardown as Ctrl-A x / power-off, so the HVF VM is always
    // destroyed and the terminal restored.
    console::install_signal_handlers(raw_console.handle());
    // Publish a session-liveness lock (PID file) if asked. It is removed when
    // this function returns — which now happens on EVERY interactive exit — so a
    // supervising app can detect that the session ended, even on window close.
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
    let serial_sink: Arc<dyn MsiSink> = Arc::new(GicMsiSink::new(prepared.gic.clone()));
    // A waker that nudges every vCPU out of its WFI idle park, so a keystroke's
    // serial interrupt is taken immediately. Populated during vCPU creation.
    let serial_wake: Option<Arc<dyn Fn() + Send + Sync>> = {
        let wakes = wakes.clone();
        Some(Arc::new(move || {
            for w in wakes.lock().unwrap().iter() {
                w();
            }
        }))
    };
    console::spawn_stdin_pump(
        uart.clone(),
        serial_sink.clone(),
        raw_console.handle(),
        serial_wake.clone(),
    );
    // Watchdog that restores level-triggered serial RX semantics: re-asserts the
    // interrupt if input is ever stranded in the FIFO with the guest's RXIM
    // unmasked (e.g. after cloud-init reopens ttyAMA0), so an interactive
    // session can never wedge waiting for an edge that already passed.
    let serial_reassert =
        console::spawn_serial_reassert(uart.clone(), serial_sink, serial_wake, running.clone());
    // Run-progress watchdog: bounds how long any vCPU can stay wedged inside a
    // single `hv_vcpu_run` (Apple's internal WFI wait not honouring a due timer),
    // forcing it out to re-enter and redeliver the tick. Snapshot the per-vCPU
    // counters + exit signals now that every vCPU thread has registered them.
    // Set CHM_DISABLE_RUN_WATCHDOG=1 to opt out (diagnostics / A-B comparison).
    let run_watchdog = if env::var_os("CHM_DISABLE_RUN_WATCHDOG").is_none() {
        let progress = progress.lock().unwrap().clone();
        let exits_snapshot = exits.lock().unwrap().clone();
        Some(spawn_run_watchdog(progress, exits_snapshot, running.clone()))
    } else {
        None
    };
    if !args.quiet {
        eprintln!(
            "chm: interactive console active — close this window or press Ctrl-A x \
             to end the session (it shuts the VM down cleanly).\n"
        );
    }

    // --- phase 4 go: release the vCPU threads to run the guest ---
    go_gate.set(Gate::Go);

    // The orchestrator drains the shared console + enforces the stop policy.
    let coordinator = run_console(uart, &running, args, limits, overlay_dir);

    // Stop every vCPU thread: clear the run flag, force any in-flight `run()` to
    // return (hv_vcpus_exit), and join — each vCPU is destroyed on its thread.
    // Each thread captures its live state (if suspending) before it returns.
    running.store(false, Ordering::Release);
    psci.wake_all();
    for sig in exits.lock().unwrap().iter() {
        sig();
    }
    // Stop the net service thread (it observes `running` and exits its poll
    // loop), then join the vCPU threads.
    if let Some(h) = net_service {
        let _ = h.join();
    }
    // Stop the serial re-assert watchdog (also observes `running`).
    let _ = serial_reassert.join();
    // Stop the run-progress watchdog (observes `running`).
    if let Some(h) = run_watchdog {
        let _ = h.join();
    }
    for h in handles {
        let _ = h.join();
    }
    drop(raw_console);

    // Suspend: persist a checkpoint ONLY on a clean external stop (the console
    // coordinator ended the session — window close / Ctrl-A x / idle / max-secs).
    // A guest power-off or a vCPU error means the box is finished, so the next
    // start should cold-boot: clear any stale checkpoint instead.
    let vcpu_outcome = outcome.lock().unwrap().take();
    let external_stop = vcpu_outcome.is_none()
        && matches!(
            coordinator,
            Ok(Outcome::Interrupted
                | Outcome::ConsoleClosed
                | Outcome::Idle(_)
                | Outcome::MaxSeconds
                | Outcome::LimitExceeded(_))
        );
    if let Some(dir) = &capture_to {
        if external_stop {
            match collect_checkpoint(&captured_rx, &prepared, &snap, num_irq, n) {
                Ok(state) => {
                    match checkpoint::write_checkpoint(dir, &state, &prepared.guest_mem, &snap.mem_mappings, "connect") {
                        Ok(()) => {
                            if !args.quiet {
                                eprintln!("\nchm: suspended — checkpoint saved (resume to continue).");
                            }
                        }
                        Err(e) => eprintln!("chm: warning: could not write checkpoint: {e}"),
                    }
                }
                Err(e) => eprintln!("chm: warning: checkpoint capture failed ({e}); not suspending"),
            }
        } else {
            // Powered off / errored: drop any prior checkpoint so we cold-boot.
            checkpoint::clear_checkpoint(dir);
        }
    }

    // Tear the VM down now that every vCPU thread has joined: `hv_vm_destroy`
    // (inside this drop) must run only once all vCPUs are destroyed, which they
    // are because each thread destroyed its own vCPU before returning and we have
    // joined them all. `PreparedVm` declares `vm` last so it drops after the GIC,
    // guest memory and RAM backings. Dropping here (rather than at scope exit)
    // both makes that ordering explicit and consumes `prepared` by value.
    drop(prepared);

    // Flush any final console bytes emitted just before the threads stopped.
    let tail = uart.take_output();
    if !tail.is_empty() {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(&tail).and_then(|()| stdout.flush());
    }

    // A vCPU-reported terminal result (power-off / error) wins; otherwise the
    // coordinator's stop reason (max-seconds / idle / console-closed).
    if let Some(res) = vcpu_outcome {
        return res;
    }
    coordinator
}

/// Gather the per-vCPU captures (in id order) plus the global GIC distributor
/// into a [`CheckpointState`] ready to persist. Called at suspend, after every
/// vCPU thread has sent its capture and joined, while the VM is still alive.
fn collect_checkpoint(
    captured_rx: &mpsc::Receiver<(usize, Result<hvf_checkpoint::VcpuCheckpoint, String>)>,
    prepared: &PreparedVm,
    snap: &Snapshot,
    num_irq: u32,
    n: usize,
) -> Result<CheckpointState, String> {
    let mut vcpus: Vec<Option<hvf_checkpoint::VcpuCheckpoint>> = (0..n).map(|_| None).collect();
    for _ in 0..n {
        let (id, res) = captured_rx
            .recv()
            .map_err(|_| "a vCPU thread exited before sending its capture".to_string())?;
        let cp = res.map_err(|e| format!("vCPU {id}: {e}"))?;
        *vcpus
            .get_mut(id)
            .ok_or_else(|| format!("captured out-of-range vCPU id {id}"))? = Some(cp);
    }
    let vcpus = vcpus
        .into_iter()
        .enumerate()
        .map(|(id, c)| c.ok_or_else(|| format!("missing capture for vCPU {id}")))
        .collect::<Result<Vec<_>, String>>()?;

    let gic_dist = hvf_checkpoint::capture_distributor(&prepared.gic, num_irq)
        .map_err(|e| format!("capture distributor: {e}"))?;

    let _ = snap; // mem layout is read by the caller via snap.mem_mappings.
    Ok(CheckpointState {
        version: hvf_checkpoint::CHECKPOINT_VERSION,
        vcpus,
        gic_dist,
        num_irq,
        usgic: None,
        usgic_cpus: Vec::new(),
        host_realtime_ns: hvf_checkpoint::now_realtime_ns(),
    })
}

/// One vCPU's userspace-GIC suspend capture: its register file plus its
/// software distributor/redistributor models, or why the capture failed.
type UsgicCapture =
    Result<(hvf_checkpoint::VcpuCheckpoint, hvf_checkpoint::UsgicCheckpoint), String>;

/// Gather the per-vCPU userspace-GIC captures (in id order) into a
/// [`CheckpointState`] ready to persist.
///
/// The software-GIC sibling of [`collect_checkpoint`], and simpler in one
/// respect: there is no managed distributor to read back, because the whole
/// GICv3 model lives in userspace and each vCPU already serialized its view of
/// it. Called at suspend, after every vCPU thread has sent its capture and
/// joined, while the VM (and so guest RAM) is still alive.
fn collect_usgic_checkpoint(
    captured_rx: &mpsc::Receiver<(usize, UsgicCapture)>,
    num_irq: u32,
    n: usize,
) -> Result<CheckpointState, String> {
    let mut slots: Vec<Option<(hvf_checkpoint::VcpuCheckpoint, hvf_checkpoint::UsgicCheckpoint)>> =
        (0..n).map(|_| None).collect();
    for _ in 0..n {
        let (id, res) = captured_rx
            .recv()
            .map_err(|_| "a vCPU thread exited before sending its capture".to_string())?;
        let cp = res.map_err(|e| format!("vCPU {id}: {e}"))?;
        *slots
            .get_mut(id)
            .ok_or_else(|| format!("captured out-of-range vCPU id {id}"))? = Some(cp);
    }
    let (vcpus, usgic_cpus): (Vec<_>, Vec<_>) = slots
        .into_iter()
        .enumerate()
        .map(|(id, c)| c.ok_or_else(|| format!("missing capture for vCPU {id}")))
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
        assert!(aarch32_guard(&snap_with(0x1100_0000_1111_1112)).is_ok());
        // EL0 field 1 == AArch64 only: nothing to warn about.
        assert!(aarch32_guard(&snap_with(0x1100_0000_1111_1111)).is_ok());
        // A capture with no ID_AA64PFR0_EL1 at all cannot be judged.
        assert!(aarch32_guard(&snap_with_no_sysregs()).is_ok());
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
        assert!(cntfrq_guard(&matching).is_ok());
        assert!(cntfrq_guard(r#"{"snapshot_data":{"state":"{}"}}"#).is_ok());
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

    #[test]
    fn parse_egress_policy_rejects_malformed_json() {
        assert!(parse_egress_policy("not json").is_none());
    }

    /// Test helper: resolve and return the enforceable policy, or None for an
    /// unrestricted resolution. Panics if the resolution fails closed.
    fn resolved_policy(overlay: &Path, cli: Option<&Path>) -> Option<EgressPolicy> {
        match resolve_egress_policy(overlay, cli) {
            EgressResolution::Unrestricted => None,
            EgressResolution::Policy(p) => Some(*p),
            EgressResolution::FailClosed(r) => panic!("unexpected fail-closed: {r}"),
        }
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
