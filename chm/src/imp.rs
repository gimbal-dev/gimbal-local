// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! macOS / Apple-Silicon implementation of the `chm` CLI.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use std::{env, fs, io, thread};

use crate::checkpoint;
use crate::cloud;
use crate::console::{self, RawConsole};
use crate::console_filter::ConsoleFilter;
use crate::control_plane;
use crate::firewall;
use crate::serve;
use crate::state_cdn;

use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::hvf::checkpoint::{self as hvf_checkpoint, CheckpointState};
use hypervisor::hvf::devices::{MmioBus, Pl011};
use hypervisor::hvf::gic::GicMsiSink;
use hypervisor::hvf::rehydrate::{
    PreparedVm, Snapshot, enable_group1_spi_forwarding, prepare_vm, restore_distributor,
    restore_vcpu_state,
};
use hypervisor::hvf::virtio::GuestMemory;
use hypervisor::hvf::virtio::nat::EgressPolicy;
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
/// hang on its first device wait with no completion interrupt. Detect that here
/// and fail loudly with an actionable message instead of a silent I/O stall.
///
/// Returns `Ok(())` when the snapshot is deliverable (SPI-routed, ITS disabled,
/// or no MSI-wired virtio devices), or when `CHM_ALLOW_ITS_LPI` is set to force
/// a run anyway. Returns `Err` with remediation guidance otherwise.
pub(crate) fn its_lpi_guard(state_json: &str) -> Result<(), String> {
    let descs = match devmgr::parse_devices(state_json) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let wired_devices = descs
        .iter()
        .filter(|d| !d.vector_events.is_empty() && d.device_id != 0)
        .count();
    if its::classify_routing(state_json, wired_devices) != its::CompletionRouting::ItsLpi {
        return Ok(());
    }
    if env::var_os("CHM_ALLOW_ITS_LPI").is_some() {
        eprintln!(
            "chm: warning: CHM_ALLOW_ITS_LPI set -- ignoring ITS/LPI routing \
             guard; the guest will likely stall on its first I/O wait because \
             LPI completions cannot be delivered on the managed GIC."
        );
        return Ok(());
    }
    Err(format!(
        "this snapshot routes its virtio completion interrupts through the GIC \
         ITS as LPIs ({wired_devices} MSI-wired device(s) + an enabled \
         gic-v3-its), which Apple's Hypervisor.framework managed GIC cannot \
         deliver. The guest would restore but then hang on its first disk/net \
         I/O with no completion interrupt. Re-capture the snapshot with the \
         guest's virtio MSIs routed as GICv3 message-based SPIs (MBI) or legacy \
         INTx line SPIs rather than through a GIC ITS; the managed GIC delivers \
         those via hv_gic_send_msi / hv_gic_set_spi. Set CHM_ALLOW_ITS_LPI=1 to \
         bypass this guard and run anyway (the guest will likely stall on first \
         I/O)."
    ))
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

pub(crate) fn wire_virtio(
    bus: &MmioBus,
    guest_mem: &Arc<GuestMemory>,
    state_json: &str,
    overlay_dir: &Path,
    gic: Option<&Arc<Mutex<dyn Vgic>>>,
    resume: bool,
    cli_egress: Option<&Path>,
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
    // An enabled gic-v3-its means completions are LPI-routed (only reachable
    // under the CHM_ALLOW_ITS_LPI bypass, since its_lpi_guard otherwise hard
    // fails first). Those resolve through the ITS but cannot be delivered, so
    // they fall back to the logging sink. Anything else is message-SPI routed
    // and delivered live through the GIC.
    let its_engine = its::Its::from_snapshot_state(state_json)
        .ok()
        .filter(|its| its.enabled())
        .map(Arc::new);
    let lpi_sink: Arc<dyn its::LpiSink> = Arc::new(its::LoggingLpiSink::default());
    let msi_sink: Option<Arc<dyn MsiSink>> =
        gic.map(|g| Arc::new(GicMsiSink::new(g.clone())) as Arc<dyn MsiSink>);

    // The egress policy governing this sandbox's outbound network, if any. It is
    // resolved (in priority order) from the `--egress-policy` flag, the
    // `CHM_EGRESS_POLICY` env binding the runner sets for a cloud assignment
    // (M28.3), or a per-workspace `egress-policy.json` a local user authored with
    // `chm firewall` — the same seam, whether the run is cloud- or self-served.
    // It is enforced by the net device's userspace NAT at DNS resolve + connect.
    let mut net_policy = load_egress_policy(overlay_dir, cli_egress);

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
        let policy = if is_net { net_policy.take() } else { None };
        let (base, size, dev) =
            devmgr::build_device(desc, guest_mem.clone(), overlay_dir, resume, policy)
                .map_err(|e| format!("build device {}: {e}", desc.name))?;
        if !desc.vector_events.is_empty() {
            if let Some(its) = &its_engine {
                // LPI-routed (bypass mode): resolve to the guest's real LPI and
                // log it -- undeliverable on the managed GIC.
                if desc.device_id != 0 {
                    dev.set_injector(Box::new(its::ItsInjector::new(
                        desc.name.clone(),
                        its.clone(),
                        guest_mem.clone(),
                        desc.device_id,
                        desc.vector_events.clone(),
                        lpi_sink.clone(),
                    )));
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
    Ok(WiredVirtio {
        summary,
        net_devices,
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
fn load_egress_policy(overlay_dir: &Path, cli_override: Option<&Path>) -> Option<EgressPolicy> {
    if let Some(path) = cli_override {
        match fs::read_to_string(path) {
            Ok(raw) => return parse_egress_policy(&raw),
            Err(e) => {
                eprintln!(
                    "chm: warning: ignoring --egress-policy {}: {e}",
                    path.display()
                );
                return None;
            }
        }
    }
    if let Ok(raw) = env::var("CHM_EGRESS_POLICY") {
        return parse_egress_policy(&raw);
    }
    let workspace = overlay_dir.parent().unwrap_or(overlay_dir);
    let file = workspace.join("egress-policy.json");
    match fs::read_to_string(&file) {
        Ok(raw) => parse_egress_policy(&raw),
        Err(_) => None,
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
}

/// How often the net service thread polls each net device's NAT for host-socket
/// activity. 2 ms keeps interactive latency low without busy-spinning; a fully
/// idle guest still re-evaluates its GIC on the vCPU's WFI poll interval, so a
/// delivered frame is never stranded longer than that.
const NET_SERVICE_INTERVAL: Duration = Duration::from_millis(2);

/// Spawn the net service thread: it advances each net device's userspace NAT
/// (relaying host-socket bytes into the guest's RX queue) and nudges the vCPUs
/// out of `hv_vcpu_run` when a frame was delivered, so the guest takes the RX
/// completion promptly. Returns `None` when there are no net devices to serve.
fn spawn_net_service(
    net_devices: Vec<Arc<VirtioPciDevice>>,
    running: Arc<AtomicBool>,
    exits: Arc<Mutex<Vec<ExitSignal>>>,
) -> Option<thread::JoinHandle<()>> {
    if net_devices.is_empty() {
        return None;
    }
    thread::Builder::new()
        .name("chm-net-service".into())
        .spawn(move || {
            while running.load(Ordering::Acquire) {
                let mut delivered = false;
                for dev in &net_devices {
                    if dev.service_net() {
                        delivered = true;
                    }
                }
                if delivered {
                    // Force any running vCPU to re-enter and take the pending RX
                    // SPI now; an idle (WFI-parked) vCPU picks it up on its own
                    // poll interval.
                    for sig in exits.lock().unwrap().iter() {
                        sig();
                    }
                }
                thread::sleep(NET_SERVICE_INTERVAL);
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
    /// `None` falls back to that resolution order. See [`load_egress_policy`].
    egress_policy: Option<PathBuf>,
}

struct ConnectArgs {
    run: Args,
    socket_path: PathBuf,
    no_stop_daemon: bool,
}

pub fn main() -> ExitCode {
    let raw: Vec<String> = env::args().skip(1).collect();
    match raw.first().map(String::as_str) {
        Some("cloud") => cloud::cloud_main(&raw[1..]),
        Some("runner") => control_plane::runner_main(&raw[1..]),
        Some("push") => control_plane::push_main(&raw[1..]),
        Some("pull") => control_plane::pull_main(&raw[1..]),
        Some("branches") => control_plane::branches_main(&raw[1..]),
        Some("policy") => control_plane::policy_main(&raw[1..]),
        Some("firewall") => firewall::firewall_main(&raw[1..]),
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
    "chm — Cloud Hypervisor for macOS (Apple Silicon)\n\
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
         chm ctl stop                Stop the running guest.\n    \
         chm ctl shutdown            Stop the guest and exit the daemon.\n\
     \n\
     NOTE: the binary must be code-signed with the\n      \
     `com.apple.security.hypervisor` entitlement (see scripts/build-chm.sh).\n"
        .to_string()
}

fn parse(raw: &[String]) -> Parsed {
    let mut snapshot_dir: Option<PathBuf> = None;
    let mut max_seconds = 0u64;
    let mut idle_exit_secs = DEFAULT_IDLE_EXIT_SECS;
    let mut quiet = false;
    let mut checkpoint = false;
    let mut egress_policy: Option<PathBuf> = None;

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
            "--egress-policy" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                egress_policy = Some(PathBuf::from(v));
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

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--quiet" => quiet = true,
            "--no-stop-daemon" => no_stop_daemon = true,
            "--checkpoint" => checkpoint = true,
            "--socket" | "--max-seconds" | "--idle-exit" | "--session-lock"
            | "--egress-policy" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Parsed::Error(format!("{a} requires a value"));
                };
                match a.as_str() {
                    "--socket" => socket_path = PathBuf::from(v),
                    "--session-lock" => session_lock = Some(PathBuf::from(v)),
                    "--egress-policy" => egress_policy = Some(PathBuf::from(v)),
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

    its_lpi_guard(&loaded.state_json)?;

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
        banner(dir, &mem_ranges, loaded.num_vcpus, loaded.total_ram);
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
    let ckpt = CheckpointMode {
        resume_from: resume_state,
        capture_to: args.checkpoint.then(|| dir.clone()),
    };
    let outcome = resume_smp(prepared, loaded, &bus, &uart, &vm_ops, &overlay_dir, args, ckpt)?;

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
        }
    }

    Ok(ExitCode::SUCCESS)
}

enum Outcome {
    PoweredOff,
    MaxSeconds,
    Idle(u64),
    ConsoleClosed,
    Interrupted,
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

/// A boxed closure that forces one vCPU out of `hv_vcpu_run` (its `exit_signal`).
/// Collected per-vCPU so the orchestrator can stop every thread at once.
type ExitSignal = Arc<dyn Fn() + Send + Sync>;

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
    ckpt: CheckpointMode,
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
    ) {
        Ok(wired) => {
            if !wired.summary.is_empty() && !args.quiet {
                eprintln!("chm: virtio device model restored:");
                for d in &wired.summary {
                    eprintln!("chm:   - {d}");
                }
            }
            // Start relaying guest egress through the userspace NAT.
            spawn_net_service(wired.net_devices, running.clone(), exits.clone())
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
    if !args.quiet {
        eprintln!(
            "chm: interactive console active — close this window or press Ctrl-A x \
             to end the session (it shuts the VM down cleanly).\n"
        );
    }

    // --- phase 4 go: release the vCPU threads to run the guest ---
    go_gate.set(Gate::Go);

    // The orchestrator drains the shared console + enforces the stop policy.
    let coordinator = run_console(uart, &running, args);

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
            Ok(Outcome::Interrupted | Outcome::ConsoleClosed | Outcome::Idle(_) | Outcome::MaxSeconds)
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
    })
}

/// The orchestrator-thread console loop: drain the guest's shared PL011 output
/// to stdout and enforce the `--max-seconds` / `--idle-exit` stop policy. Runs
/// until a vCPU thread clears `running` (power-off / error) or a stop condition
/// fires.
fn run_console(
    uart: &Arc<Pl011>,
    running: &Arc<AtomicBool>,
    args: &Args,
) -> Result<Outcome, String> {
    let start = Instant::now();
    let mut last_output = Instant::now();
    let mut stdout = io::stdout();
    let mut filter = ConsoleFilter::new();

    let max = (args.max_seconds > 0).then(|| Duration::from_secs(args.max_seconds));
    let idle = (args.idle_exit_secs > 0).then(|| Duration::from_secs(args.idle_exit_secs));

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

fn banner(dir: &Path, mem_ranges: &Path, num_vcpus: u32, total_ram: u64) {
    let mib = total_ram / (1024 * 1024);
    eprintln!("chm — Cloud Hypervisor for macOS (Apple Silicon)");
    eprintln!("  snapshot:  {}", dir.display());
    eprintln!("  memory:    {} ({mib} MiB)", mem_ranges.display());
    eprintln!("  vCPUs:     {num_vcpus}");
    eprintln!("  backend:   Apple Hypervisor.framework (managed GICv3)");
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn load_egress_policy_reads_the_per_workspace_file() {
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

        let p = load_egress_policy(&overlay, None).expect("policy resolved from workspace file");
        assert!(p.is_restrictive());
        assert_eq!(p.label(), "local");
        assert!(p.decide_dns("api.github.com").is_allow());
        assert!(!p.decide_dns("evil.test").is_allow());

        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn load_egress_policy_cli_override_beats_the_workspace_file() {
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

        let p = load_egress_policy(&overlay, Some(&override_path)).expect("override resolved");
        assert_eq!(p.label(), "flag");
        assert!(p.decide_dns("override.test").is_allow());
        assert!(
            !p.decide_dns("only-workspace.test").is_allow(),
            "the workspace file must not apply when the flag is set"
        );

        fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn load_egress_policy_is_none_without_any_source() {
        let ws = std::env::temp_dir().join(format!("chm-egress-none-{}", std::process::id()));
        let overlay = ws.join(".chm-overlays");
        fs::create_dir_all(&overlay).expect("mkdir");
        // No env binding is set in this test process and no workspace file exists.
        assert!(load_egress_policy(&overlay, None).is_none());
        fs::remove_dir_all(&ws).ok();
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
