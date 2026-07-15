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
use std::process::{ExitCode, exit};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, mem, ptr, thread};

use hypervisor::hvf::checkpoint as hvf_checkpoint;
use hypervisor::hvf::rehydrate::{rehydrate, rehydrate_resume};
use hypervisor::{VmExit, VmOps};

use crate::checkpoint;
use crate::console_filter::ConsoleFilter;
use crate::imp::{build_vm_ops, its_lpi_guard, load_snapshot, wire_virtio};
use crate::limits;
use hypervisor::hvf::virtio::nat::NatLimits;

/// Set by the daemon's termination-signal handlers so the accept loop exits and
/// tears the running VM down gracefully (checkpoint + `hv_vm_destroy`) instead
/// of the process dying mid-run with the VM leaked. Closing the app (which kills
/// its `chm serve` child), `kill`, or Ctrl-C all funnel through this.
static DAEMON_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long a shutdown waits for the worker to finish capturing its checkpoint
/// and destroying the VM. Longer than the `ctl stop` responsiveness window
/// because a full RAM checkpoint dump can take a few seconds.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(30);

extern "C" fn handle_daemon_signal(_sig: libc::c_int) {
    DAEMON_SHUTDOWN.store(true, Ordering::Release);
}

/// Install graceful-shutdown handlers for the daemon's termination signals.
/// The handler only sets a flag; the accept loop polls it (std's `accept()`
/// retries EINTR internally, so the loop runs the listener non-blocking rather
/// than relying on a signal to interrupt a blocking accept).
fn install_daemon_signal_handlers() {
    for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
        // SAFETY: zero-initialized sigaction is valid; the handler is
        // async-signal-safe (a single atomic store); installed once at startup.
        unsafe {
            let mut action: libc::sigaction = mem::zeroed();
            action.sa_sigaction = handle_daemon_signal as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(sig, &action, ptr::null_mut());
        }
    }
}

fn daemon_shutdown_requested() -> bool {
    DAEMON_SHUTDOWN.load(Ordering::Acquire)
}

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

/// The daemon control socket lives in a private, per-user `0700` runtime
/// directory (created + owner-checked by [`ensure_private_runtime_dir`]) rather
/// than loose in a shared temp dir, and is bound `0600` with a peer-uid check
/// (M30.2). Shared with the `chm ctl`/`connect` client so both agree on the
/// default when no `--socket` is passed.
pub(crate) fn default_socket() -> PathBuf {
    runtime_dir().join("chm.sock")
}

/// The private per-user runtime directory for daemon sockets.
pub(crate) fn runtime_dir() -> PathBuf {
    env::temp_dir().join("gimbal-local")
}

/// Create `dir` as a private `0700` directory the current user owns, refusing to
/// follow a pre-existing symlink planted at that path (M30.2). Returns `Ok` if
/// it already exists as a real directory.
fn ensure_private_runtime_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(format!(
                "refusing runtime dir {}: it is a symlink",
                dir.display()
            ));
        }
        Ok(md) if md.is_dir() => return Ok(()),
        Ok(_) => return Err(format!("runtime dir {} exists but is not a directory", dir.display())),
        Err(_) => {}
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create runtime dir {}: {e}", dir.display()))
}

/// Remove a stale control socket from a prior run before re-binding — but only
/// when the path is actually a socket or a symlink, never a regular file. This
/// avoids clobbering a real file a misconfigured `--socket` points at, and
/// unlinks a planted symlink rather than following it (M30.2).
fn remove_stale_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(md) = fs::symlink_metadata(path) {
        let ft = md.file_type();
        if ft.is_symlink() || ft.is_socket() {
            let _ = fs::remove_file(path);
        }
    }
}

/// The effective uid of the process on the other end of `stream`, via
/// `getpeereid(2)`. Used to reject any client that is not the daemon's own user
/// before honoring a control command (M30.2).
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: `stream` owns a valid, connected socket fd for the duration of the
    // call; getpeereid reads that fd and writes only the two out-params, which
    // are valid local variables. A non-zero return means it wrote nothing.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc == 0 {
        Ok(euid)
    } else {
        Err(io::Error::last_os_error())
    }
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
        let name = root.file_name().map_or_else(
            || "snapshot".to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
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

    // Bind the control socket inside a private 0700 runtime dir, then restrict
    // the socket itself to 0600 so only this user can connect (M30.2). Remove a
    // stale socket only if it is actually a socket/symlink, never a regular file.
    if let Some(parent) = args.socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_private_runtime_dir(parent)?;
    }
    remove_stale_socket(&args.socket_path);
    let listener = UnixListener::bind(&args.socket_path)
        .map_err(|e| format!("bind {}: {e}", args.socket_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&args.socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", args.socket_path.display()))?;
    }

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

    // Tear the running VM down gracefully on a termination signal (the app
    // killing its `chm serve` child, `kill`, or Ctrl-C): stop the VM (which
    // captures a checkpoint) and destroy it, rather than leaking the one HVF
    // slot. Std's blocking `accept()` retries EINTR internally, so a signal
    // alone won't wake it; instead poll the listener non-blocking and check the
    // shutdown flag between polls for a responsive, connection-independent exit.
    install_daemon_signal_handlers();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set listener non-blocking: {e}"))?;

    while !daemon_shutdown_requested() {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Handle this connection in blocking mode.
                let _ = stream.set_nonblocking(false);
                let daemon = Arc::clone(&daemon);
                thread::spawn(move || handle_conn(stream, &daemon));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => eprintln!("chm serve: accept error: {e}"),
        }
    }

    // Graceful shutdown path: stop any running VM (capturing its checkpoint and
    // destroying it) before the process exits, so no HVF slot is leaked.
    eprintln!("chm serve: shutting down — stopping any running sandbox…");
    let _ = stop_vm_blocking(&daemon, SHUTDOWN_DRAIN);
    let _ = fs::remove_file(&daemon.socket_path);
    Ok(())
}

/// Request the running VM to stop and wait up to `timeout` for the worker to
/// finish (its checkpoint capture + `hv_vm_destroy` complete when the worker
/// records `Stopped`). Used by the shutdown paths, which need to wait longer
/// than `ctl stop`'s responsiveness window for a full RAM checkpoint to flush.
fn stop_vm_blocking(daemon: &Daemon, timeout: Duration) -> Result<String, String> {
    let (inner, name) = {
        let guard = daemon.current.lock().unwrap();
        match guard.as_ref() {
            Some(vm) => (Arc::clone(&vm.inner), vm.name.clone()),
            None => return Ok("no VM running".to_string()),
        }
    };
    let kick = {
        let mut g = inner.lock().unwrap();
        if matches!(g.status, RunStatus::Stopped(_)) {
            return Ok(format!("`{name}` already stopped"));
        }
        g.stop_requested = true;
        g.kick.clone()
    };
    if let Some(kick) = kick {
        kick();
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if matches!(inner.lock().unwrap().status, RunStatus::Stopped(_)) {
            return Ok(format!("stopped `{name}`"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(format!("stop requested for `{name}` (still draining)"))
}

fn handle_conn(stream: UnixStream, daemon: &Daemon) {
    // Only accept commands from the daemon's own user: a co-tenant process must
    // not be able to drive start/stop/console/shutdown even if it can reach the
    // socket (M30.2). SAFETY: geteuid() is a pure syscall with no preconditions.
    let me = unsafe { libc::geteuid() };
    match peer_uid(&stream) {
        Ok(uid) if uid == me => {}
        Ok(uid) => {
            eprintln!("chm serve: rejecting connection from uid {uid} (daemon uid {me})");
            return;
        }
        Err(e) => {
            eprintln!("chm serve: cannot verify peer credentials ({e}); rejecting connection");
            return;
        }
    }

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
        "list-json" => {
            let _ = writer.write_all(list_json(daemon).as_bytes());
        }
        "status" => {
            let _ = writer.write_all(status_line(daemon).as_bytes());
        }
        "status-json" => {
            let _ = writer.write_all(status_json(daemon).as_bytes());
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
            // Wait longer than `ctl stop` so a full RAM checkpoint finishes
            // flushing (and the VM is destroyed) before the process exits.
            let _ = stop_vm_blocking(daemon, SHUTDOWN_DRAIN);
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
                    format!(
                        "stopped\t{}\t{}\t{} console bytes\n",
                        vm.name, reason, bytes
                    )
                }
            }
        }
    }
}

fn list_json(daemon: &Daemon) -> String {
    let mut out = String::from("{\"snapshots\":[");
    for (idx, e) in daemon.library.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"path\":\"{}\",\"vcpus\":{},\"ram_mib\":{}}}",
            json_escape(&e.name),
            json_escape(&e.dir.display().to_string()),
            e.num_vcpus,
            e.total_ram / (1024 * 1024)
        ));
    }
    out.push_str("]}\n");
    out
}

fn status_json(daemon: &Daemon) -> String {
    let guard = daemon.current.lock().unwrap();
    match guard.as_ref() {
        None => "{\"state\":\"idle\"}\n".to_string(),
        Some(vm) => {
            let inner = vm.inner.lock().unwrap();
            let bytes = inner.dropped + inner.console.len();
            match &inner.status {
                RunStatus::Running => format!(
                    "{{\"state\":\"running\",\"name\":\"{}\",\"uptime_seconds\":{},\"console_bytes\":{}}}\n",
                    json_escape(&vm.name),
                    vm.started.elapsed().as_secs(),
                    bytes
                ),
                RunStatus::Stopped(reason) => format!(
                    "{{\"state\":\"stopped\",\"name\":\"{}\",\"reason\":\"{}\",\"console_bytes\":{}}}\n",
                    json_escape(&vm.name),
                    json_escape(reason),
                    bytes
                ),
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn start_vm(daemon: &Daemon, name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("start requires a snapshot name (see `chm ctl list`)".to_string());
    }
    // A per-sandbox workspace is started by absolute path (it lives outside the
    // library); a library image is started by name.
    let (display_name, dir) = if name.starts_with('/') {
        let path = PathBuf::from(name);
        if !path.join("state.json").exists() {
            return Err(format!("no snapshot at path `{name}` (missing state.json)"));
        }
        let display = path
            .file_name()
            .map_or_else(|| name.to_string(), |s| s.to_string_lossy().into_owned());
        (display, path)
    } else {
        let entry = daemon
            .library
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| format!("no snapshot named `{name}` in the library"))?;
        (entry.name.clone(), entry.dir.clone())
    };

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
        name: display_name.clone(),
        started: Instant::now(),
        inner,
    });
    Ok(format!("started `{display_name}`"))
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
    let (uart, bus) = build_vm_ops(&loaded.state_json);
    let vm_ops: Arc<dyn VmOps> = bus.clone();

    let hv = hypervisor::new().map_err(|e| {
        format!(
            "hypervisor::new() failed: {e} \
             (is the daemon code-signed with the hypervisor entitlement?)"
        )
    })?;

    // Resume from a saved checkpoint if one exists (restored, not cold-booted),
    // so the app's Stop -> Start round-trips the sandbox's live state. A
    // malformed checkpoint is discarded so we cold-boot cleanly.
    let resume_state = if checkpoint::has_checkpoint(dir) {
        match checkpoint::read_checkpoint(dir) {
            Ok(state) => Some(state),
            Err(e) => {
                eprintln!("chm serve: warning: ignoring checkpoint ({e}); cold-booting");
                checkpoint::clear_checkpoint(dir);
                None
            }
        }
    } else {
        None
    };
    let mem_ranges = if resume_state.is_some() {
        checkpoint::memory_ranges_path(dir)
    } else {
        loaded.mem_ranges.clone()
    };

    let mut rvm = match &resume_state {
        Some(state) => rehydrate_resume(hv.as_ref(), &loaded.snap, &mem_ranges, &vm_ops, state),
        None => rehydrate(hv.as_ref(), &loaded.snap, &mem_ranges, &vm_ops),
    }
    .map_err(|e| format!("rehydrate: {e}"))?;

    // Reconstruct the virtio device model from the snapshot's device-manager
    // state and install it onto the bus, sharing the just-mapped guest RAM. On
    // resume, reattach the disk overlays so writes made before the stop persist.
    let overlay_dir = dir.join(".chm-overlays");
    let (doc, _) = limits::resolve_limits(dir, None);
    let net_limits = NatLimits {
        max_connections: doc.max_connections.map(|n| n as usize),
        max_bytes_per_sec: doc.max_bandwidth_kbps.map(|kbps| kbps * 125),
    };
    if let Err(e) = wire_virtio(
        &bus,
        &rvm.guest_mem,
        &loaded.state_json,
        &overlay_dir,
        Some(&rvm.gic),
        resume_state.is_some(),
        None,
        &net_limits,
    ) {
        eprintln!("chm serve: warning: virtio device model not wired: {e}");
    }

    let start = Instant::now();
    let mut last_output = Instant::now();
    let max = (opts.max_seconds > 0).then(|| Duration::from_secs(opts.max_seconds));
    let idle = (opts.idle_exit_secs > 0).then(|| Duration::from_secs(opts.idle_exit_secs));
    // Drop the one documented cosmetic genirq line from the buffered console so
    // the app's read-only stream matches the interactive session.
    let mut console_filter = ConsoleFilter::new();

    // Run the guest on vCPU0 until a stop condition fires; `outcome` records
    // whether the stop was a clean external one (suspend-worthy) or a guest
    // power-off / error (which should cold-boot next time).
    let (reason, external_stop) = {
        let vcpu = rvm.vcpus[0].as_mut();
        // Publish a cross-thread interrupt handle so `stop` can force the vCPU out
        // of `run()` even if the guest is busy-spinning without trapping.
        inner.lock().unwrap().kick = vcpu.exit_signal();
        loop {
            if inner.lock().unwrap().stop_requested {
                break (Ok("stopped by request".to_string()), true);
            }

            match vcpu.run() {
                Ok(VmExit::Ignore) => {}
                Ok(VmExit::Shutdown | VmExit::Reset) => {
                    break (Ok("guest powered off".to_string()), false);
                }
                Ok(other) => break (Err(format!("unexpected guest exit: {other:?}")), false),
                Err(e) => break (Err(format!("vCPU run: {e}")), false),
            }

            let raw = uart.take_output();
            if !raw.is_empty() {
                let bytes = console_filter.feed(&raw);
                if !bytes.is_empty() {
                    append_console(inner, &bytes);
                    last_output = Instant::now();
                }
            }

            if let Some(max) = max
                && start.elapsed() >= max
            {
                break (Ok("reached --max-seconds limit".to_string()), true);
            }
            if let Some(idle) = idle
                && last_output.elapsed() >= idle
            {
                break (
                    Ok(format!(
                        "no console output for {}s (likely waiting on an unmodelled device)",
                        opts.idle_exit_secs
                    )),
                    true,
                );
            }
        }
    };

    // Suspend on a clean external stop: capture the live state into a checkpoint
    // so the next Start resumes here. A power-off / error clears any checkpoint
    // so the next Start cold-boots. Capture happens here, on this thread, while
    // the VM is still alive (every vCPU was created and is paused on it).
    if external_stop {
        match hvf_checkpoint::capture_all(&mut rvm.vcpus, &rvm.gic, loaded.snap.num_irq) {
            Ok(state) => {
                if let Err(e) = checkpoint::write_checkpoint(
                    dir,
                    &state,
                    &rvm.guest_mem,
                    &loaded.snap.mem_mappings,
                    "daemon",
                ) {
                    eprintln!("chm serve: warning: could not write checkpoint: {e}");
                }
            }
            Err(e) => eprintln!("chm serve: warning: checkpoint capture failed: {e}"),
        }
    } else {
        checkpoint::clear_checkpoint(dir);
    }

    reason
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
            "missing command (list [--json] | status [--json] | start <name> | console | stop | shutdown)"
                .to_string(),
        );
    }
    let command = ctl_command(&rest)?;

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

fn ctl_command(rest: &[String]) -> Result<String, String> {
    match rest {
        [cmd] => Ok(cmd.clone()),
        [cmd, json] if matches!(cmd.as_str(), "list" | "status") && json == "--json" => {
            Ok(format!("{cmd}-json"))
        }
        [cmd, ..] if matches!(cmd.as_str(), "list" | "status") => {
            Err(format!("unexpected argument `{}`", rest[1]))
        }
        _ => Ok(rest.join(" ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn ctl_json_commands_map_to_daemon_protocol() {
        assert_eq!(ctl_command(&s(&["list", "--json"])).unwrap(), "list-json");
        assert_eq!(
            ctl_command(&s(&["status", "--json"])).unwrap(),
            "status-json"
        );
        assert_eq!(ctl_command(&s(&["start", "vm1"])).unwrap(), "start vm1");
    }

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(
            json_escape("vm\"one\\two\n"),
            "vm\\\"one\\\\two\\n".to_string()
        );
    }

    #[test]
    fn default_socket_lives_in_a_private_namespaced_dir() {
        // The default is namespaced under a `gimbal-local` dir (not loose in the
        // shared temp root), so it can be created 0700 (M30.2).
        let sock = default_socket();
        assert_eq!(sock.file_name().unwrap(), "chm.sock");
        assert_eq!(sock.parent().unwrap(), runtime_dir());
        assert_eq!(runtime_dir().file_name().unwrap(), "gimbal-local");
    }

    #[test]
    fn ensure_private_runtime_dir_creates_0700_and_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let base = env::temp_dir().join(format!("chm-rtdir-{}", process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join("run");

        ensure_private_runtime_dir(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "runtime dir must be private 0700");
        // Idempotent on an existing real dir.
        ensure_private_runtime_dir(&dir).unwrap();

        // A symlink planted at the runtime-dir path is refused, not followed.
        let link = base.join("link");
        symlink(&dir, &link).unwrap();
        assert!(ensure_private_runtime_dir(&link).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn remove_stale_socket_spares_regular_files_but_clears_sockets() {
        let base = env::temp_dir().join(format!("chm-stale-{}", process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        // A regular file at the socket path is NOT clobbered (a misconfigured
        // --socket pointing at real data must be surfaced, not deleted).
        let regular = base.join("not-a-socket");
        fs::write(&regular, b"important").unwrap();
        remove_stale_socket(&regular);
        assert!(regular.exists(), "a regular file must be left intact");

        // An actual stale socket IS removed so the daemon can re-bind.
        let sock = base.join("chm.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        drop(listener);
        assert!(sock.exists());
        remove_stale_socket(&sock);
        assert!(!sock.exists(), "a stale socket must be removed before re-bind");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn peer_uid_matches_this_user_over_a_local_socket() {
        // The peer-credential plumbing must report the connecting process's uid,
        // so the daemon can admit its own user and reject others (M30.2).
        let base = env::temp_dir().join(format!("chm-peer-{}", process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let sock = base.join("chm.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let client = UnixStream::connect(&sock).unwrap();
        let (server, _) = listener.accept().unwrap();
        // SAFETY: geteuid() is a pure syscall.
        let me = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&server).unwrap(), me);
        assert_eq!(peer_uid(&client).unwrap(), me);

        let _ = fs::remove_dir_all(&base);
    }
}
