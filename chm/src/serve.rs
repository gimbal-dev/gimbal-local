// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm serve` — a long-lived daemon that hosts a snapshot *library* behind a
//! Unix-domain socket, plus the `chm ctl` client that drives it. This is the
//! control plane a Docker-Desktop-style GUI talks to: list snapshots, start one,
//! attach to its console, stop it.
//!
//! HVF is one-VM-per-process today, so the daemon runs a single guest at a time
//! on a dedicated worker thread, buffering its serial console into a capped ring
//! that `ctl console` clients stream live.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{exit, ExitCode};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use hypervisor::hvf::rehydrate::rehydrate;
use hypervisor::{VmExit, VmOps};

use crate::imp::{build_vm_ops, its_lpi_guard, load_snapshot, wire_virtio};

/// Cap the in-memory console ring so a long-lived guest cannot grow it without
/// bound. Late `ctl console` attachers fast-forward past anything dropped.
const CONSOLE_CAP: usize = 256 * 1024;

/// Default seconds of console silence after which a started guest is stopped.
/// Mirrors `chm run`'s default; the resumed guest currently goes quiet at the
/// first unmodelled device. `--idle-exit 0` keeps it running open-endedly.
const DEFAULT_IDLE_EXIT_SECS: u64 = 10;

/// Where the running guest's state lives, shared between the worker thread that
/// drives the vCPU and the connection handlers that read console / status.
struct VmInner {
    console: Vec<u8>,
    /// Number of console bytes evicted from the front of `console` (so a client
    /// cursor is an absolute byte offset into the whole stream).
    dropped: usize,
    status: RunStatus,
    stop_requested: bool,
    /// Cross-thread handle that forces the vCPU out of `run()` (HVF
    /// `hv_vcpus_exit`). Published by the worker once the VM is built, so a
    /// `stop` can interrupt even a guest that is spinning without trapping.
    kick: Option<Arc<dyn Fn() + Send + Sync>>,
}

enum RunStatus {
    Running,
    Stopped(String),
}

struct Vm {
    name: String,
    started: Instant,
    inner: Arc<Mutex<VmInner>>,
}

struct Entry {
    name: String,
    dir: PathBuf,
    num_vcpus: u32,
    total_ram: u64,
}

struct Daemon {
    library: Vec<Entry>,
    idle_exit_secs: u64,
    max_seconds: u64,
    socket_path: PathBuf,
    current: Mutex<Option<Vm>>,
}

struct ServeArgs {
    library_dir: PathBuf,
    socket_path: PathBuf,
    idle_exit_secs: u64,
    max_seconds: u64,
}

fn default_socket() -> PathBuf {
    env::temp_dir().join("chm.sock")
}

/// Parse the shared `--socket PATH` flag out of an argument list, returning the
/// remaining positional/other tokens.
fn take_socket(raw: &[String]) -> Result<(PathBuf, Vec<String>), String> {
    let mut socket = default_socket();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == "--socket" {
            i += 1;
            let Some(v) = raw.get(i) else {
                return Err("--socket requires a value".to_string());
            };
            socket = PathBuf::from(v);
        } else {
            rest.push(raw[i].clone());
        }
        i += 1;
    }
    Ok((socket, rest))
}

// ---------------------------------------------------------------------------
// Daemon (`chm serve`)
// ---------------------------------------------------------------------------

pub fn serve_main(raw: &[String]) -> ExitCode {
    match serve(raw) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm serve: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_serve(raw: &[String]) -> Result<ServeArgs, String> {
    let mut library_dir: Option<PathBuf> = None;
    let mut socket_path = default_socket();
    let mut idle_exit_secs = DEFAULT_IDLE_EXIT_SECS;
    let mut max_seconds = 0u64;

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "--socket" | "--idle-exit" | "--max-seconds" => {
                i += 1;
                let Some(v) = raw.get(i) else {
                    return Err(format!("{a} requires a value"));
                };
                if a == "--socket" {
                    socket_path = PathBuf::from(v);
                } else {
                    let Ok(n) = v.parse::<u64>() else {
                        return Err(format!("{a}: `{v}` is not a number"));
                    };
                    if a == "--idle-exit" {
                        idle_exit_secs = n;
                    } else {
                        max_seconds = n;
                    }
                }
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`"));
            }
            _ => {
                if library_dir.is_some() {
                    return Err(format!("unexpected extra argument `{a}`"));
                }
                library_dir = Some(PathBuf::from(a));
            }
        }
        i += 1;
    }

    let library_dir = library_dir.ok_or("missing <LIBRARY_DIR>")?;
    Ok(ServeArgs {
        library_dir,
        socket_path,
        idle_exit_secs,
        max_seconds,
    })
}

/// Build the snapshot library from `root`: either `root` itself (if it is a
/// `ch-snapshot` directory) or every immediate subdirectory that looks like one.
fn scan_library(root: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();

    if root.join("state.json").exists() {
        let loaded = load_snapshot(root)?;
        let name = root
            .file_name()
            .map_or_else(|| "snapshot".to_string(), |s| s.to_string_lossy().into_owned());
        entries.push(Entry {
            name,
            dir: root.to_path_buf(),
            num_vcpus: loaded.num_vcpus,
            total_ram: loaded.total_ram,
        });
        return Ok(entries);
    }

    let read = fs::read_dir(root).map_err(|e| format!("read library dir: {e}"))?;
    for ent in read {
        let path = ent.map_err(|e| format!("read library entry: {e}"))?.path();
        if path.is_dir()
            && path.join("state.json").exists()
            && let Ok(loaded) = load_snapshot(&path)
        {
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            entries.push(Entry {
                name,
                dir: path,
                num_vcpus: loaded.num_vcpus,
                total_ram: loaded.total_ram,
            });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn serve(raw: &[String]) -> Result<(), String> {
    let args = parse_serve(raw)?;
    let library = scan_library(&args.library_dir)?;

    // Remove any stale socket from a previous run before binding.
    let _ = fs::remove_file(&args.socket_path);
    let listener = UnixListener::bind(&args.socket_path)
        .map_err(|e| format!("bind {}: {e}", args.socket_path.display()))?;

    let daemon = Arc::new(Daemon {
        library,
        idle_exit_secs: args.idle_exit_secs,
        max_seconds: args.max_seconds,
        socket_path: args.socket_path.clone(),
        current: Mutex::new(None),
    });

    eprintln!(
        "chm serve: listening on {} — {} snapshot(s) in library",
        args.socket_path.display(),
        daemon.library.len()
    );
    for e in &daemon.library {
        eprintln!(
            "  {} ({} vCPU, {} MiB)",
            e.name,
            e.num_vcpus,
            e.total_ram / (1024 * 1024)
        );
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let daemon = Arc::clone(&daemon);
                thread::spawn(move || handle_conn(stream, &daemon));
            }
            Err(e) => eprintln!("chm serve: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_conn(stream: UnixStream, daemon: &Daemon) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut writer = stream;

    let mut parts = line.trim().splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let arg = parts.next().unwrap_or("").trim();

    match cmd {
        "ping" => {
            let _ = writer.write_all(b"pong\n");
        }
        "list" => {
            let mut out = String::new();
            for e in &daemon.library {
                out.push_str(&format!(
                    "{}\t{} vCPU\t{} MiB\n",
                    e.name,
                    e.num_vcpus,
                    e.total_ram / (1024 * 1024)
                ));
            }
            if out.is_empty() {
                out.push_str("(library is empty)\n");
            }
            let _ = writer.write_all(out.as_bytes());
        }
        "status" => {
            let _ = writer.write_all(status_line(daemon).as_bytes());
        }
        "start" => {
            let resp = match start_vm(daemon, arg) {
                Ok(msg) => format!("ok\t{msg}\n"),
                Err(e) => format!("error\t{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "console" => stream_console(&mut writer, daemon),
        "stop" => {
            let resp = match stop_vm(daemon) {
                Ok(msg) => format!("ok\t{msg}\n"),
                Err(e) => format!("error\t{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "shutdown" => {
            let _ = stop_vm(daemon);
            let _ = writer.write_all(b"ok\tdaemon exiting\n");
            let _ = writer.flush();
            let _ = fs::remove_file(&daemon.socket_path);
            exit(0);
        }
        other => {
            let _ = writer.write_all(format!("error\tunknown command `{other}`\n").as_bytes());
        }
    }
}

fn status_line(daemon: &Daemon) -> String {
    let guard = daemon.current.lock().unwrap();
    match guard.as_ref() {
        None => "idle\n".to_string(),
        Some(vm) => {
            let inner = vm.inner.lock().unwrap();
            let bytes = inner.dropped + inner.console.len();
            match &inner.status {
                RunStatus::Running => format!(
                    "running\t{}\t{}s\t{} console bytes\n",
                    vm.name,
                    vm.started.elapsed().as_secs(),
                    bytes
                ),
                RunStatus::Stopped(reason) => {
                    format!("stopped\t{}\t{}\t{} console bytes\n", vm.name, reason, bytes)
                }
            }
        }
    }
}

fn start_vm(daemon: &Daemon, name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("start requires a snapshot name (see `chm ctl list`)".to_string());
    }
    let entry = daemon
        .library
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| format!("no snapshot named `{name}` in the library"))?;

    let mut guard = daemon.current.lock().unwrap();
    if let Some(vm) = guard.as_ref()
        && matches!(vm.inner.lock().unwrap().status, RunStatus::Running)
    {
        return Err(format!(
            "`{}` is already running — stop it first (HVF is one VM per process)",
            vm.name
        ));
    }

    let inner = Arc::new(Mutex::new(VmInner {
        console: Vec::new(),
        dropped: 0,
        status: RunStatus::Running,
        stop_requested: false,
        kick: None,
    }));

    let dir = entry.dir.clone();
    let opts = EngineOpts {
        idle_exit_secs: daemon.idle_exit_secs,
        max_seconds: daemon.max_seconds,
    };
    let worker_inner = Arc::clone(&inner);
    thread::spawn(move || {
        let reason = match run_guest(&dir, &opts, &worker_inner) {
            Ok(reason) => reason,
            Err(e) => format!("error: {e}"),
        };
        worker_inner.lock().unwrap().status = RunStatus::Stopped(reason);
    });

    *guard = Some(Vm {
        name: name.to_string(),
        started: Instant::now(),
        inner,
    });
    Ok(format!("started `{name}`"))
}

fn stop_vm(daemon: &Daemon) -> Result<String, String> {
    let guard = daemon.current.lock().unwrap();
    let vm = guard.as_ref().ok_or("no VM running")?;
    let kick = {
        let mut inner = vm.inner.lock().unwrap();
        if matches!(inner.status, RunStatus::Stopped(_)) {
            return Ok(format!("`{}` already stopped", vm.name));
        }
        inner.stop_requested = true;
        inner.kick.clone()
    };
    // Force the vCPU out of any in-progress `run()` so the worker observes the
    // stop flag immediately, even for a guest that is executing without traps.
    if let Some(kick) = kick {
        kick();
    }
    // Wait briefly for the worker to observe the flag and halt, so `ctl stop`
    // returns only once the guest has actually stopped.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(vm.inner.lock().unwrap().status, RunStatus::Stopped(_)) {
            return Ok(format!("stopped `{}`", vm.name));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(format!("stop requested for `{}`", vm.name))
}

fn stream_console(writer: &mut UnixStream, daemon: &Daemon) {
    // Snapshot the shared console handle so we don't hold the daemon lock while
    // streaming. If nothing is running there is nothing to stream.
    let inner = {
        let guard = daemon.current.lock().unwrap();
        match guard.as_ref() {
            Some(vm) => Arc::clone(&vm.inner),
            None => {
                let _ = writer.write_all(b"(no VM running)\n");
                return;
            }
        }
    };

    let mut cursor = 0usize;
    loop {
        let (chunk, stopped) = {
            let g = inner.lock().unwrap();
            if cursor < g.dropped {
                cursor = g.dropped;
            }
            let end = g.dropped + g.console.len();
            let chunk = if cursor < end {
                g.console[cursor - g.dropped..].to_vec()
            } else {
                Vec::new()
            };
            (chunk, matches!(g.status, RunStatus::Stopped(_)))
        };

        if !chunk.is_empty() {
            if writer.write_all(&chunk).is_err() {
                return;
            }
            cursor += chunk.len();
            continue;
        }
        if stopped {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// VM worker
// ---------------------------------------------------------------------------

struct EngineOpts {
    idle_exit_secs: u64,
    max_seconds: u64,
}

/// Build and run a guest on the current thread, pushing serial output into the
/// shared console ring and honouring the stop flag / idle / max-seconds limits.
/// Returns a human-readable reason for why it stopped.
fn run_guest(dir: &Path, opts: &EngineOpts, inner: &Arc<Mutex<VmInner>>) -> Result<String, String> {
    let loaded = load_snapshot(dir)?;
    its_lpi_guard(&loaded.state_json)?;
    let (uart, bus) = build_vm_ops();
    let vm_ops: Arc<dyn VmOps> = bus.clone();

    let hv = hypervisor::new().map_err(|e| {
        format!(
            "hypervisor::new() failed: {e} \
             (is the daemon code-signed with the hypervisor entitlement?)"
        )
    })?;
    let mut rvm = rehydrate(hv.as_ref(), &loaded.snap, &loaded.mem_ranges, &vm_ops)
        .map_err(|e| format!("rehydrate: {e}"))?;

    // Reconstruct the virtio device model from the snapshot's device-manager
    // state and install it onto the bus, sharing the just-mapped guest RAM.
    let overlay_dir = dir.join(".chm-overlays");
    if let Err(e) = wire_virtio(&bus, &rvm.guest_mem, &loaded.state_json, &overlay_dir)
    {
        eprintln!("chm serve: warning: virtio device model not wired: {e}");
    }

    let start = Instant::now();
    let mut last_output = Instant::now();
    let max = (opts.max_seconds > 0).then(|| Duration::from_secs(opts.max_seconds));
    let idle = (opts.idle_exit_secs > 0).then(|| Duration::from_secs(opts.idle_exit_secs));

    let vcpu = rvm.vcpus[0].as_mut();
    // Publish a cross-thread interrupt handle so `stop` can force the vCPU out
    // of `run()` even if the guest is busy-spinning without trapping.
    inner.lock().unwrap().kick = vcpu.exit_signal();
    loop {
        if inner.lock().unwrap().stop_requested {
            return Ok("stopped by request".to_string());
        }

        match vcpu.run().map_err(|e| format!("vCPU run: {e}"))? {
            VmExit::Ignore => {}
            VmExit::Shutdown | VmExit::Reset => return Ok("guest powered off".to_string()),
            other => return Err(format!("unexpected guest exit: {other:?}")),
        }

        let bytes = uart.take_output();
        if !bytes.is_empty() {
            append_console(inner, &bytes);
            last_output = Instant::now();
        }

        if let Some(max) = max
            && start.elapsed() >= max
        {
            return Ok("reached --max-seconds limit".to_string());
        }
        if let Some(idle) = idle
            && last_output.elapsed() >= idle
        {
            return Ok(format!(
                "no console output for {}s (likely waiting on an unmodelled device)",
                opts.idle_exit_secs
            ));
        }
    }
}

/// Push guest serial output into the shared console ring, evicting from the
/// front (and bumping the dropped counter) when it exceeds the cap.
fn append_console(inner: &Arc<Mutex<VmInner>>, bytes: &[u8]) {
    let mut g = inner.lock().unwrap();
    g.console.extend_from_slice(bytes);
    if g.console.len() > CONSOLE_CAP {
        let overflow = g.console.len() - CONSOLE_CAP;
        g.console.drain(..overflow);
        g.dropped += overflow;
    }
}

// ---------------------------------------------------------------------------
// Client (`chm ctl`)
// ---------------------------------------------------------------------------

pub fn ctl_main(raw: &[String]) -> ExitCode {
    match ctl(raw) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm ctl: {e}");
            ExitCode::FAILURE
        }
    }
}

fn ctl(raw: &[String]) -> Result<(), String> {
    let (socket, rest) = take_socket(raw)?;
    if rest.is_empty() {
        return Err(
            "missing command (list | status | start <name> | console | stop | shutdown)"
                .to_string(),
        );
    }
    let command = rest.join(" ");

    let mut stream = UnixStream::connect(&socket).map_err(|e| {
        format!(
            "cannot connect to daemon at {}: {e} (is `chm serve` running?)",
            socket.display()
        )
    })?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .map_err(|e| format!("send command: {e}"))?;
    stream.flush().ok();

    // Stream the daemon's reply (console takes over the connection and streams
    // raw guest output; everything else is a short text response) to stdout.
    let mut stdout = io::stdout();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => match stdout.write_all(&buf[..n]).and_then(|()| stdout.flush()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
                Err(e) => return Err(format!("write stdout: {e}")),
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("read daemon: {e}")),
        }
    }
    Ok(())
}
