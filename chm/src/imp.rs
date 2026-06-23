// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! macOS / Apple-Silicon implementation of the `chm` CLI.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, fs, io};

use crate::serve;

use hypervisor::hvf::devices::{MmioBus, Pl011};
use hypervisor::hvf::gic::GicMsiSink;
use hypervisor::hvf::rehydrate::{rehydrate, Snapshot};
use hypervisor::hvf::virtio::pci::{MsiSink, MsiSpiInjector, VirtioPciDevice};
use hypervisor::hvf::virtio::{devmgr, its};
use hypervisor::hvf::virtio::GuestMemory;
use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::{Vcpu, VmExit, VmOps};
use std::sync::Mutex;

/// cloud-hypervisor's arm64 PL011 lives at the base of the mapped-IO window.
pub(crate) const PL011_BASE: u64 = 0x0900_0000;
pub(crate) const PL011_SIZE: u64 = 0x1000;

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
    let snap = Snapshot::from_state_json(&state_json).map_err(|e| format!("parse snapshot: {e}"))?;
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
pub(crate) fn build_vm_ops() -> (Arc<Pl011>, Arc<MmioBus>) {
    let uart = Arc::new(Pl011::new());
    let bus = Arc::new(MmioBus::new());
    bus.add(PL011_BASE, PL011_SIZE, uart.clone());
    (uart, bus)
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

pub(crate) fn wire_virtio(
    bus: &MmioBus,
    guest_mem: &Arc<GuestMemory>,
    state_json: &str,
    overlay_dir: &Path,
    gic: Option<&Arc<Mutex<dyn Vgic>>>,
) -> Result<Vec<String>, String> {
    let descs = devmgr::parse_devices(state_json)
        .map_err(|e| format!("parse virtio devices: {e}"))?;
    if descs.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(overlay_dir)
        .map_err(|e| format!("create overlay dir {}: {e}", overlay_dir.display()))?;

    let mut summary = Vec::with_capacity(descs.len());
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

    for desc in &descs {
        let kind = match &desc.backend {
            devmgr::BackendKind::Block { nsectors, .. } => {
                format!("virtio-blk {} ({} sectors)", desc.name, nsectors)
            }
            devmgr::BackendKind::Rng => format!("virtio-rng {}", desc.name),
        };
        let (base, size, dev) = devmgr::build_device(desc, guest_mem.clone(), overlay_dir)
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
        bus.add(base, size, dev);
        summary.push(format!("{kind} @ BAR {base:#x}"));
    }
    // Complete any requests left in-flight at snapshot time and deliver their
    // interrupts, so a resumed guest waiting on pre-snapshot I/O (e.g. a mount
    // reading the boot filesystem) makes progress instead of blocking forever.
    for dev in &drainable {
        dev.drain_on_resume();
    }
    Ok(summary)
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
}

pub fn main() -> ExitCode {
    let raw: Vec<String> = env::args().skip(1).collect();
    match raw.first().map(String::as_str) {
        Some("serve") => serve::serve_main(&raw[1..]),
        Some("ctl") => serve::ctl_main(&raw[1..]),
        _ => match parse(&raw) {
            Parsed::Run(args) => match run(&args) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("chm: error: {e}");
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
                eprintln!("chm: {msg}\n");
                eprint!("{}", usage());
                ExitCode::FAILURE
            }
        },
    }
}

enum Parsed {
    Run(Args),
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
         -h, --help          Print this help.\n    \
         -V, --version       Print the version.\n\
     \n\
     DAEMON:\n    \
         chm serve <LIBRARY_DIR> [--socket PATH] [--idle-exit N]\n                        \
         [--max-seconds N]\n      \
         Host a snapshot library (a `ch-snapshot` dir, or a directory of\n      \
         them) behind a Unix socket (default $TMPDIR/chm.sock).\n    \
         chm ctl list                List snapshots in the library.\n    \
         chm ctl status              Show daemon / running-VM status.\n    \
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

    let mut i = 0;
    // A leading `run`/`restore` subcommand is accepted but optional.
    if i < raw.len() && (raw[i] == "run" || raw[i] == "restore") {
        i += 1;
    }

    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--quiet" => quiet = true,
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
        }),
        None => Parsed::Error("missing <SNAPSHOT_DIR>".to_string()),
    }
}

fn run(args: &Args) -> Result<ExitCode, String> {
    let dir = &args.snapshot_dir;
    let loaded = load_snapshot(dir)?;

    its_lpi_guard(&loaded.state_json)?;

    if !args.quiet {
        banner(dir, &loaded.mem_ranges, loaded.num_vcpus, loaded.total_ram);
    }

    // Device model: a bus with a real PL011 at the guest's serial base.
    let (uart, bus) = build_vm_ops();
    let vm_ops: Arc<dyn VmOps> = bus.clone();

    let hv = hypervisor::new().map_err(|e| {
        format!(
            "hypervisor::new() failed: {e}\n\
             (is the binary code-signed with the hypervisor entitlement? \
             see scripts/build-chm.sh)"
        )
    })?;

    let mut rvm = rehydrate(hv.as_ref(), &loaded.snap, &loaded.mem_ranges, &vm_ops)
        .map_err(|e| format!("rehydrate: {e}"))?;

    // Reconstruct the virtio device model from the snapshot and install it onto
    // the bus, sharing the just-mapped guest RAM.
    let overlay_dir = dir.join(".chm-overlays");
    match wire_virtio(&bus, &rvm.guest_mem, &loaded.state_json, &overlay_dir, Some(&rvm.gic)) {
        Ok(devs) if !devs.is_empty() => {
            if !args.quiet {
                eprintln!("chm: virtio device model restored:");
                for d in &devs {
                    eprintln!("chm:   - {d}");
                }
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("chm: warning: virtio device model not wired: {e}"),
    }

    if loaded.num_vcpus > 1 && !args.quiet {
        eprintln!(
            "chm: note: snapshot has {} vCPUs; resuming vCPU0 only \
             (SMP secondary-core bring-up via PSCI CPU_ON is not yet wired).",
            loaded.num_vcpus
        );
    }

    if !args.quiet {
        eprintln!("chm: guest resumed — serial console follows.\n");
    }

    let vcpu = rvm.vcpus[0].as_mut();
    let outcome = run_loop(vcpu, &uart, args)?;

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
        }
    }

    Ok(ExitCode::SUCCESS)
}

enum Outcome {
    PoweredOff,
    MaxSeconds,
    Idle(u64),
    ConsoleClosed,
}

fn run_loop(vcpu: &mut dyn Vcpu, uart: &Pl011, args: &Args) -> Result<Outcome, String> {
    let start = Instant::now();
    let mut last_output = Instant::now();
    let mut stdout = io::stdout();

    let max = (args.max_seconds > 0).then(|| Duration::from_secs(args.max_seconds));
    let idle = (args.idle_exit_secs > 0).then(|| Duration::from_secs(args.idle_exit_secs));

    loop {
        match vcpu.run().map_err(|e| format!("vCPU run: {e}"))? {
            VmExit::Ignore => {}
            VmExit::Shutdown | VmExit::Reset => return Ok(Outcome::PoweredOff),
            other => return Err(format!("unexpected guest exit: {other:?}")),
        }

        let bytes = uart.take_output();
        if !bytes.is_empty() {
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
}

fn banner(dir: &Path, mem_ranges: &Path, num_vcpus: u32, total_ram: u64) {
    let mib = total_ram / (1024 * 1024);
    eprintln!("chm — Cloud Hypervisor for macOS (Apple Silicon)");
    eprintln!("  snapshot:  {}", dir.display());
    eprintln!("  memory:    {} ({mib} MiB)", mem_ranges.display());
    eprintln!("  vCPUs:     {num_vcpus}");
    eprintln!("  backend:   Apple Hypervisor.framework (managed GICv3)");
}
