// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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

use crate::audit;
use crate::capability;
use crate::checkpoint;
use crate::console::ConsoleInput;
use crate::disktail;
use crate::credproxy::cli;
use crate::console_filter::ConsoleFilter;
use crate::exec;
use crate::imp::{
    Loaded, Outcome, UsgicConfig, UsgicSession, aarch32_guard, cntfrq_guard, icache_dic_guard,
    load_snapshot,
    run_usgic_engine, superseded_note,
};
use crate::posture;

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

// Default seconds of console silence after which a started guest is suspended.
// Shared with `chm run` rather than duplicated — see its definition for why this
// is ten minutes and not the ten seconds it used to be. Two independent copies
// of the same scaffolding constant is how it stayed wrong in both places.
use crate::imp::DEFAULT_IDLE_EXIT_SECS;

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
    /// Delivers bytes to the guest's serial console. Published by the worker
    /// alongside `kick`; without it the daemon's console is read-only and a
    /// client could watch a guest but never type into it.
    input: Option<ConsoleInput>,
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
    /// The library root this daemon was started on, so `posture` has something
    /// to assess when no VM is running.
    library_dir: PathBuf,
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
/// follow a pre-existing symlink planted at that path (M30.2). If the directory
/// already exists it is only accepted when the current user owns it; a directory
/// owned by another user is rejected (it must not host our control socket), and a
/// self-owned directory left with loose permissions is tightened back to `0700`
/// so group/other can never interpose in the runtime dir (M30.2 follow-up, #66).
fn ensure_private_runtime_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(format!(
                "refusing runtime dir {}: it is a symlink",
                dir.display()
            ));
        }
        Ok(md) if md.is_dir() => {
            // SAFETY: geteuid() takes no arguments, cannot fail, and only reads
            // process credentials.
            let euid = unsafe { libc::geteuid() };
            if md.uid() != euid {
                return Err(format!(
                    "refusing runtime dir {}: it is owned by uid {}, not the \
                     current user (uid {}); a directory planted by another user \
                     must not host the control socket",
                    dir.display(),
                    md.uid(),
                    euid
                ));
            }
            // Owned by us: force private perms (self-heal a dir an older build or
            // a lax umask left too open) so only we can create/interpose entries.
            let mode = md.permissions().mode() & 0o777;
            if mode != 0o700 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    format!("tighten runtime dir {} to 0700: {e}", dir.display())
                })?;
            }
            return Ok(());
        }
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
pub(crate) fn take_socket(raw: &[String]) -> Result<(PathBuf, Vec<String>), String> {
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
        library_dir: args.library_dir.clone(),
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
        "posture-json" => {
            let _ = writer.write_all(posture_json(daemon, arg).as_bytes());
        }
        "proxy-json" => {
            let _ = writer.write_all(proxy_json(daemon, arg).as_bytes());
        }
        "proxy-check-json" => {
            let _ = writer.write_all(proxy_check_json(daemon, arg).as_bytes());
        }
        "proxy-ca-json" => {
            let _ = writer.write_all(proxy_ca_json(daemon, arg).as_bytes());
        }
        "audit-json" => {
            let _ = writer.write_all(audit_json(daemon, arg).as_bytes());
        }
        "capabilities-json" => {
            let _ = writer.write_all(capabilities_json(daemon, arg).as_bytes());
        }
        "exec-json" => {
            let _ = writer.write_all(exec_json(daemon, arg).as_bytes());
        }
        "start" => {
            let resp = match start_vm(daemon, arg) {
                Ok(msg) => format!("ok\t{msg}\n"),
                Err(e) => format!("error\t{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "console" => stream_console(&mut writer, daemon),
        "input" => {
            let resp = match send_input(daemon, arg) {
                Ok(n) => format!("ok\t{n} byte(s)\n"),
                Err(e) => format!("error\t{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
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

/// The daemon's status, as a line for a human.
///
/// Reports `library` alongside the state for the same reason `status_json`
/// does: the directory is fixed at `chm serve <dir>`, so someone reading `chm
/// ctl status` after configuring a different one is looking at a daemon that
/// will never see their snapshots. Kept in step with `status_json` — a text
/// form that omits what the JSON form carries is a second answer waiting to
/// drift.
fn status_line(daemon: &Daemon) -> String {
    let library = daemon.library_dir.display();
    let guard = daemon.current.lock().unwrap();
    match guard.as_ref() {
        None => format!("idle\tlibrary {library}\n"),
        Some(vm) => {
            let inner = vm.inner.lock().unwrap();
            let bytes = inner.dropped + inner.console.len();
            match &inner.status {
                RunStatus::Running => format!(
                    "running\t{}\t{}s\t{} console bytes\tlibrary {}\n",
                    vm.name,
                    vm.started.elapsed().as_secs(),
                    bytes,
                    library
                ),
                RunStatus::Stopped(reason) => {
                    format!(
                        "stopped\t{}\t{}\t{} console bytes\tlibrary {}\n",
                        vm.name, reason, bytes, library
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

/// The daemon's status, as JSON.
///
/// Carries `library` in **every** branch, including idle. The library a
/// daemon serves is fixed at `chm serve <dir>` and cannot be overridden
/// per-request, so a caller configured for a different directory is reading a
/// list that has nothing to do with its own setting — and the idle case is
/// exactly when that is least visible, because there is no running guest to
/// contradict it. Same reasoning as `posture_json`: the process that owns the
/// fact is the one that should report it.
fn status_json(daemon: &Daemon) -> String {
    let library = json_escape(&daemon.library_dir.display().to_string());
    let guard = daemon.current.lock().unwrap();
    match guard.as_ref() {
        None => format!("{{\"state\":\"idle\",\"library\":\"{library}\"}}\n"),
        Some(vm) => {
            let inner = vm.inner.lock().unwrap();
            let bytes = inner.dropped + inner.console.len();
            match &inner.status {
                RunStatus::Running => format!(
                    "{{\"state\":\"running\",\"name\":\"{}\",\"uptime_seconds\":{},\"console_bytes\":{},\"library\":\"{}\"}}\n",
                    json_escape(&vm.name),
                    vm.started.elapsed().as_secs(),
                    bytes,
                    library
                ),
                RunStatus::Stopped(reason) => format!(
                    "{{\"state\":\"stopped\",\"name\":\"{}\",\"reason\":\"{}\",\"console_bytes\":{},\"library\":\"{}\"}}\n",
                    json_escape(&vm.name),
                    json_escape(reason),
                    bytes,
                    library
                ),
            }
        }
    }
}

/// The security posture the **daemon** would apply, as JSON.
///
/// This exists because most of the posture is read from the environment of the
/// process that computes it, and the daemon is the process that runs the guest.
/// A UI that shelled out to its own `chm posture` would report *its* env: attach
/// the app to a `chm serve` someone started with `CHM_ALLOW_LOCAL_EGRESS=1` and
/// the panel would show green over a sandbox that can reach the LAN. Reporting a
/// control as on when it is off is the one failure a security panel must not
/// have, so the answer comes from here.
///
/// `arg` optionally names the workspace to assess; empty means the running VM's
/// directory, falling back to the library root when idle. Emits the same shape
/// as `chm posture --json` plus `source` and `assessed` so the caller can say
/// whose posture it is showing.
fn posture_json(daemon: &Daemon, arg: &str) -> String {
    let (dir, assessed) = if arg.is_empty() {
        match running_vm_dir(daemon) {
            Some(dir) => (dir, "running-vm"),
            None => (daemon.library_dir.clone(), "library-root"),
        }
    } else {
        (PathBuf::from(arg), "requested")
    };

    let (body, _weakened) = posture::assess_json(&dir);
    // Splice the provenance in after the opening brace rather than nesting, so
    // one decoder handles both this and `chm posture --json`.
    let spliced = body.replacen(
        '{',
        &format!("{{\n  \"source\": \"daemon\",\n  \"assessed\": \"{assessed}\","),
        1,
    );
    format!("{spliced}\n")
}

/// The credential-proxy rule set **as the daemon resolves it**.
///
/// Same provenance argument as `posture_json`: credential availability comes
/// from `env::var` in the calling process, and the daemon is the process that
/// injects. A UI asking itself gets an answer about itself.
fn proxy_json(daemon: &Daemon, arg: &str) -> String {
    let (dir, assessed) = if arg.is_empty() {
        match running_vm_dir(daemon) {
            Some(dir) => (dir, "running-vm"),
            None => (daemon.library_dir.clone(), "library-root"),
        }
    } else {
        (PathBuf::from(arg), "requested")
    };

    // Name the directory, not just its kind. "Add proxy-rules.json to the
    // workspace" is unactionable when the reader cannot tell which of the
    // library root and the sandbox folder is meant -- and only the latter is
    // ever a guest's workspace.
    let body = cli::show_json_for_daemon(&dir);
    let scope = json_str(&dir.display().to_string());
    let spliced = body.replacen(
        '{',
        &format!(
            "{{\n  \"source\": \"daemon\",\n  \"assessed\": \"{assessed}\",\n  \
             \"scope_dir\": {scope},"
        ),
        1,
    );
    format!("{spliced}\n")
}

/// The CA the running proxy would actually sign with.
///
/// Answered by the daemon for the same reason the rules are: the fingerprint a
/// UI shows is only worth anything if it is the one the guest will meet, and a
/// CA is per-workspace. Measured on hardware: the app process resolved the
/// library root and got `898b834b…`, while the proxy inside the running guest
/// signed with `79f85a28…`. Installing the former would have made the guest
/// trust a certificate nothing uses -- and because the installer compares what
/// it installed against what it was handed, it would have reported success.
fn proxy_ca_json(daemon: &Daemon, arg: &str) -> String {
    let (dir, assessed) = if arg.is_empty() {
        match running_vm_dir(daemon) {
            Some(dir) => (dir, "running-vm"),
            None => (daemon.library_dir.clone(), "library-root"),
        }
    } else {
        (PathBuf::from(arg), "requested")
    };

    let body = cli::ca_json_for_daemon(&dir);
    let scope = json_str(&dir.display().to_string());
    let spliced = body.replacen(
        '{',
        &format!(
            "{{\"source\":\"daemon\",\"assessed\":\"{assessed}\",\"scope_dir\":{scope},"
        ),
        1,
    );
    format!("{spliced}\n")
}

/// The audit trail for the workspace this daemon is actually running, as JSON.
///
/// Same provenance rule as the rest: the trail that matters is the one the
/// running guest is writing to, not whichever directory the caller happened to
/// resolve. `arg` is `[<dir>] [<tail>]`.
fn audit_json(daemon: &Daemon, arg: &str) -> String {
    let mut parts = arg.split_whitespace();
    let first = parts.next().unwrap_or("");
    let tail: usize = parts
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(DEFAULT_AUDIT_TAIL);

    let (dir, assessed) = if first.is_empty() || first == "-" {
        match running_vm_dir(daemon) {
            Some(dir) => (dir, "running-vm"),
            // No running sandbox means there is no workspace in scope, and the
            // library root is not one -- it will never hold a trail. Reading it
            // would answer "no records" to a question about a sandbox that may
            // have a full history sitting on disk, so say what is actually true
            // instead and name the sandboxes that do have one.
            None => return audit_candidates_json(daemon),
        }
    } else {
        (PathBuf::from(first), "requested")
    };

    let body = audit::trail_json(&dir, tail);
    let scope = json_str(&dir.display().to_string());
    let spliced = body.replacen(
        '{',
        &format!("{{\"source\":\"daemon\",\"assessed\":\"{assessed}\",\"scope_dir\":{scope},"),
        1,
    );
    format!("{spliced}\n")
}

/// What the daemon can say about audit history when nothing is running.
///
/// A trail outlives the process that wrote it -- that is the whole point of
/// making it durable -- so the moment a sandbox stops is exactly when someone
/// sits down to read what it did. Answering "no records" then, because the
/// daemon has no VM in scope, would report the reader's own lack of a selection
/// as a fact about the guest's behaviour.
fn audit_candidates_json(daemon: &Daemon) -> String {
    let mut items: Vec<String> = Vec::new();
    for entry in &daemon.library {
        let path = entry.dir.join("audit.jsonl");
        let Ok(meta) = fs::metadata(&path) else { continue };
        if !meta.is_file() {
            continue;
        }
        items.push(format!(
            "{{\"name\":{},\"dir\":{},\"bytes\":{}}}",
            json_str(&entry.name),
            json_str(&entry.dir.display().to_string()),
            meta.len()
        ));
    }
    format!(
        "{{\"source\":\"daemon\",\"assessed\":\"no-sandbox-in-scope\",\"present\":false,\
         \"total\":0,\"records_allow_egress\":false,\"truncated\":false,\"records\":[],\
         \"candidates\":[{}]}}\n",
        items.join(",")
    )
}

/// How many trailing records `chm ctl audit` returns when not told otherwise.
/// Enough to see a session, small enough not to push a megabyte through the
/// socket for a long-running sandbox.
const DEFAULT_AUDIT_TAIL: usize = 200;

/// Minimal JSON string encoding for a host path.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Run a credential-proxy check **in the daemon's process**.
///
/// `arg` is `<host> <port> <path>`. The control run is always requested: a
/// check without one proves reachability, not injection, and this verb exists
/// for a UI button whose entire job is to answer "did the credential arrive?".
fn proxy_check_json(daemon: &Daemon, arg: &str) -> String {
    let mut parts = arg.splitn(3, ' ');
    let (Some(host), Some(port), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
        return "{\"reachable\":false,\"error\":\"usage: proxy-check-json <host> <port> <path>\"}\n"
            .to_string();
    };
    let Ok(port) = port.parse::<u16>() else {
        return format!("{{\"reachable\":false,\"error\":\"bad port `{port}`\"}}\n");
    };

    let dir = running_vm_dir(daemon).unwrap_or_else(|| daemon.library_dir.clone());
    let body = cli::check_json_for_daemon(&dir, host, port, path);
    let spliced = body.replacen('{', "{\n  \"source\": \"daemon\",", 1);
    format!("{spliced}\n")
}

/// The library directory of the VM the daemon currently has loaded, if any.
/// `None` when idle, or when the running VM is not in the library (which cannot
/// happen today, since `start` resolves through it).
fn running_vm_dir(daemon: &Daemon) -> Option<PathBuf> {
    let guard = daemon.current.lock().unwrap();
    let name = guard.as_ref().map(|vm| vm.name.clone())?;
    drop(guard);
    daemon
        .library
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.dir.clone())
}

/// What this build can do, answered by the process that would do it.
///
/// The app must not compute this itself. A capability list rendered from the
/// app's own constants describes a binary it is not talking to: the daemon may
/// be an older `chm`, or the same source re-signed differently, and the panel
/// would be confidently wrong in exactly the case a user opened it to check.
///
/// The hypervisor question is settled differently depending on what is going
/// on. A running guest is proof, and stronger than any probe; with nothing
/// running the daemon spawns a child to try it for real, because
/// `hv_vm_create` is process-global and a diagnostic must not contend with the
/// thing it is diagnosing.
fn capabilities_json(daemon: &Daemon, arg: &str) -> String {
    let running = daemon.current.lock().unwrap().is_some();
    let evidence = if running {
        capability::HvfEvidence::GuestRunning
    } else {
        capability::HvfEvidence::ProbeAllowed
    };
    let caps = capability::build_report(evidence);

    let arg = arg.trim();
    // `-` means "the daemon chooses"; an empty string would be ambiguous with a
    // caller that meant the current directory, and `.` would resolve against
    // the daemon's cwd rather than the caller's.
    let (dir, assessed) = if arg.is_empty() || arg == "-" {
        match running_vm_dir(daemon) {
            Some(dir) => (Some(dir), "running-vm"),
            None => (None, "no-snapshot-in-scope"),
        }
    } else {
        (Some(PathBuf::from(arg)), "requested")
    };

    let pre = dir.as_deref().map(capability::preflight);
    let body = capability::render_json(&caps, pre.as_ref());
    let scope = match &dir {
        Some(d) => json_str(&d.display().to_string()),
        None => "null".to_string(),
    };
    let spliced = body.replacen(
        '{',
        &format!("{{\"source\":\"daemon\",\"assessed\":\"{assessed}\",\"scope_dir\":{scope},"),
        1,
    );
    format!("{spliced}\n")
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
        input: None,
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
    //
    // Report the worker's own reason rather than a bare "stopped": on this path
    // the teardown has just written a checkpoint over the resume point, and that
    // string is the only place the displaced revision is named (#288). A user
    // who stopped a guest that had gone quiet must not have to already know
    // about `chm rollback` to find out their last good state still exists.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let RunStatus::Stopped(reason) = &vm.inner.lock().unwrap().status {
            return Ok(format!("stopped `{}` — {reason}", vm.name));
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
    cntfrq_guard(&loaded.state_json)?;

    // AArch32-at-EL0 check (V1.4): the capture host advertised 32-bit
    // userspace and this Mac has none, so a 32-bit exec wedges the vCPU.
    aarch32_guard(&loaded.snap)?;
    icache_dic_guard(&loaded.snap)?;

    // Room-to-grow check (#259), same as `chm run`: a daemon-started guest hits
    // the identical wall, and the console is where its operator is looking.
    if let Some(n) = disktail::tail_notice(dir, &loaded.state_json) {
        eprintln!("chm: note: {n}");
    }

    // One interrupt path — see the note in `imp::run`. Apple's managed GIC
    // cannot deliver LPIs and cannot cold-boot, so it could never run a stock
    // cloud-hypervisor capture; the runtime path is retired and the hardware
    // evidence for why lives in `hypervisor/tests/hvf_boot.rs`.
    run_guest_usgic(dir, opts, inner, loaded)
}

/// Deliver bytes from a client into the running guest's serial console.
///
/// Escapes are decoded so a line-oriented protocol can carry control characters:
/// `\n`, `\r`, `\t`, `\0`, `\xNN` and `\\`. A bare command with no argument
/// sends a newline, which is the common case (waking a login prompt).
fn send_input(daemon: &Daemon, arg: &str) -> Result<usize, String> {
    let guard = daemon.current.lock().unwrap();
    let vm = guard.as_ref().ok_or("no VM running")?;
    let input = {
        let inner = vm.inner.lock().unwrap();
        if let RunStatus::Stopped(ref why) = inner.status {
            return Err(format!("`{}` is stopped ({why})", vm.name));
        }
        inner.input.clone()
    };
    let input = input.ok_or("this VM does not expose a console input channel")?;
    let bytes = decode_input(arg);
    input(&bytes);
    Ok(bytes.len())
}

/// Serialises exec requests: two commands typed into one console interleave
/// their characters and both come back wrong. A second caller is refused rather
/// than queued, so a stuck exec cannot silently stall a fleet of them.
static EXEC_BUSY: AtomicBool = AtomicBool::new(false);

/// Clears [`EXEC_BUSY`] however the exec ends, including an early return.
struct ExecSlot;

impl Drop for ExecSlot {
    fn drop(&mut self) {
        EXEC_BUSY.store(false, Ordering::Release);
    }
}

/// Run `argv` in the running guest and report what happened.
///
/// `arg` is `<timeout_secs> <hex-argv…>` (see [`exec::encode_argv`]). The reply
/// is a single JSON object whose `status` field is the contract: `completed` is
/// the *only* value that carries a meaningful `exit_code`, so a caller cannot
/// read a transport failure as a successful command.
fn exec_json(daemon: &Daemon, arg: &str) -> String {
    let started = Instant::now();
    match exec_run(daemon, arg) {
        Ok((outcome, elapsed)) => match outcome {
            exec::ExecOutcome::Completed { code, output } => format!(
                "{{\"status\":\"completed\",\"exit_code\":{code},\"output\":\"{}\",\
                 \"error\":null,\"duration_ms\":{}}}\n",
                json_escape(&output),
                elapsed.as_millis()
            ),
            exec::ExecOutcome::Pending => exec_error_json(
                "timeout",
                "the guest did not report completion before the timeout; \
                 the command may still be running (raise `--timeout`), \
                 the console may have no shell on it yet (still booting, or at a login prompt), \
                 or the guest may have stopped executing \
                 (`chm ctl console` shows which)",
                elapsed,
            ),
            exec::ExecOutcome::Truncated => exec_error_json(
                "truncated",
                "the guest produced more console output than the daemon's ring can hold, \
                 so the command's output was partly evicted before it could be read",
                elapsed,
            ),
            exec::ExecOutcome::Overflowed => exec_error_json(
                "overflowed",
                "the command produced too much output to capture over the console channel; \
                 redirect it to a file in the guest instead",
                elapsed,
            ),
        },
        Err(e) => exec_error_json("error", &e, started.elapsed()),
    }
}

fn exec_error_json(status: &str, message: &str, elapsed: Duration) -> String {
    format!(
        "{{\"status\":\"{status}\",\"exit_code\":null,\"output\":\"\",\
         \"error\":\"{}\",\"duration_ms\":{}}}\n",
        json_escape(message),
        elapsed.as_millis()
    )
}

fn exec_run(daemon: &Daemon, arg: &str) -> Result<(exec::ExecOutcome, Duration), String> {
    let (timeout_str, wire) = arg.split_once(' ').unwrap_or((arg, ""));
    let secs: u64 = timeout_str
        .parse()
        .map_err(|_| "malformed exec request".to_string())?;
    let argv = exec::decode_argv(wire)?;
    let nonce = exec::Nonce::mint();
    let script = exec::script(&nonce, &argv)?;

    if EXEC_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("another exec is already running in this sandbox".to_string());
    }
    let _slot = ExecSlot;

    // Take copies of the shared handles and drop the daemon lock before waiting:
    // an exec can run for minutes and must not block `status`, `console` or
    // `stop` while it does.
    let (inner, input) = {
        let guard = daemon.current.lock().unwrap();
        let vm = guard.as_ref().ok_or("no VM running")?;
        let g = vm.inner.lock().unwrap();
        if let RunStatus::Stopped(ref why) = g.status {
            return Err(format!("`{}` is stopped ({why})", vm.name));
        }
        let input =
            g.input.clone().ok_or("this VM does not expose a console input channel")?;
        (Arc::clone(&vm.inner), input)
    };

    // Absolute stream offset of the first byte that can belong to this exec.
    // Everything before it is prior console traffic and is never parsed.
    let start = {
        let g = inner.lock().unwrap();
        g.dropped + g.console.len()
    };

    // Clear whatever framing state the console was left in before writing the
    // frame (#294). Without this, one truncated write or one abandoned
    // interactive command parks the shell at `PS2` and *every* subsequent exec
    // times out, each retry piling more continuation text onto the same
    // unterminated line. `exec::console_writes` explains why the reset must be a
    // separate write and why ETX is the only state-independent one.
    //
    // `postboot::send_line` justifies the SIGINT by step serialisation; here the
    // argument is `EXEC_BUSY`, which we hold: no other exec can be running, so
    // the signal can only reach something the guest started on its own console
    // --- exactly the state being cleared.
    //
    // The reset lands inside the parse window, which is harmless: `exec::parse`
    // locates the frame by nonce, so any `^C` echo or fresh prompt ahead of it is
    // skipped like any other console noise.
    for write in exec::console_writes(&script) {
        input(&write);
    }

    let began = Instant::now();
    let deadline = began + Duration::from_secs(secs);
    loop {
        let (slice, dropped, stopped) = {
            let g = inner.lock().unwrap();
            (g.console.clone(), g.dropped, matches!(g.status, RunStatus::Stopped(_)))
        };
        // Our window opened at `start`; if eviction has passed it, the bytes we
        // would parse are not the ones we asked for.
        if dropped > start {
            return Ok((exec::ExecOutcome::Truncated, began.elapsed()));
        }
        let since = String::from_utf8_lossy(&slice[start - dropped..]);
        let outcome = exec::parse(&nonce, &since);
        match outcome {
            exec::ExecOutcome::Pending => {}
            done => return Ok((done, began.elapsed())),
        }
        if stopped {
            return Err("the guest stopped before the command completed".to_string());
        }
        if Instant::now() >= deadline {
            return Ok((exec::ExecOutcome::Pending, began.elapsed()));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn decode_input(arg: &str) -> Vec<u8> {
    if arg.is_empty() {
        return vec![b'\n'];
    }
    let mut out = Vec::with_capacity(arg.len());
    let mut it = arg.bytes().peekable();
    while let Some(b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(b't') => out.push(b'\t'),
            Some(b'0') => out.push(0),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                // Two hex digits, or a literal `\x` if malformed.
                let hi = it.peek().copied().and_then(|c| (c as char).to_digit(16));
                let mut ok = false;
                if let Some(hi) = hi {
                    it.next();
                    if let Some(lo) = it.peek().copied().and_then(|c| (c as char).to_digit(16)) {
                        it.next();
                        out.push((hi * 16 + lo) as u8);
                        ok = true;
                    } else {
                        out.push(hi as u8);
                        ok = true;
                    }
                }
                if !ok {
                    out.extend_from_slice(b"\\x");
                }
            }
            Some(other) => {
                out.push(b'\\');
                out.push(other);
            }
            None => out.push(b'\\'),
        }
    }
    out
}

/// Run a stock ITS/LPI capture on the **userspace GICv3** under the daemon.
///
/// Shares `chm run`'s engine (`run_usgic_engine`) so there is exactly one copy
/// of the multi-threaded vCPU orchestration, cross-vCPU SGI table, ITS/LPI
/// virtio wiring and checkpoint capture. All this adds is the daemon's own
/// supervision policy: drain the guest's serial output into the console ring
/// and stop on the stop flag, the idle timeout, or the wall-clock cap.
///
/// Live checkpoints here cover SMP, same as the CLI: the engine captures each
/// vCPU on its owning thread and writes one checkpoint for the whole guest.
fn run_guest_usgic(
    dir: &Path,
    opts: &EngineOpts,
    inner: &Arc<Mutex<VmInner>>,
    loaded: Loaded,
) -> Result<String, String> {
    let allow_local_egress = env::var("CHM_ALLOW_LOCAL_EGRESS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let cfg = UsgicConfig {
        dir,
        // The daemon's stderr is a log, not a console: no banner, no chatter.
        quiet: true,
        // Stop -> Start must round-trip guest state, same as the managed path.
        checkpoint: true,
        egress_policy: None,
        proxy_rules: None,
        allow_local_egress,
        limits_file: None,
        checkpoint_source: "daemon",
        // The daemon does not own a terminal: no raw mode, no stdin pump.
        interactive: false,
        // No flag reaches here: `chm ctl start` names a snapshot, not a run
        // shape. The daemon takes the cadence from its own environment, which
        // is the one an operator sets when starting the service.
        snapshot_every: None,
    };

    let outcome = run_usgic_engine(&cfg, loaded, &mut |s| supervise_daemon(s, opts, inner))?;
    // The daemon runs quiet, so the engine's own suspend message goes to a log
    // nobody is reading. `ctl stop` is where the user finds out a checkpoint was
    // written on their behalf, so the way back has to travel in this string
    // (#288). HEAD's `parent` is exactly the revision this teardown displaced.
    let displaced = checkpoint::read_revision(dir)
        .ok()
        .and_then(|r| r.parent)
        .map_or_else(String::new, |id| {
            format!(" — {}", superseded_note(Some(&id), dir).trim_end())
        });
    Ok(match outcome {
        Outcome::PoweredOff => "guest powered off".to_string(),
        // The daemon always checkpoints, so a limit expiring here suspends the
        // guest rather than cutting its power. Say so: an operator reading
        // "reached --max-seconds limit" has no way to tell which happened, and
        // the difference is whether their work still exists.
        Outcome::MaxSeconds => format!("suspended at the --max-seconds limit{displaced}"),
        Outcome::Idle(secs) => {
            format!("suspended after {secs}s with no console output{displaced}")
        }
        Outcome::LimitExceeded(reason) => format!("resource limit hit ({reason})"),
        Outcome::ConsoleClosed | Outcome::Interrupted => {
            format!("stopped by request{displaced}")
        }
    })
}

/// The daemon's supervision loop for a userspace-GIC guest.
///
/// The vCPUs run on their own threads, so unlike the managed path this only
/// pumps the console and watches for a stop; it returns the reason, and the
/// engine performs the teardown (and the suspend capture) from there.
fn supervise_daemon(
    s: &UsgicSession<'_>,
    opts: &EngineOpts,
    inner: &Arc<Mutex<VmInner>>,
) -> Result<Outcome, String> {
    // Publish a kick that forces *every* vCPU out of `hv_vcpu_run`, so a `stop`
    // interrupts even a guest spinning without traps. The managed path only has
    // one vCPU to kick; here the stop must reach all of them.
    let exits: Vec<Arc<dyn Fn() + Send + Sync>> = s.exits.to_vec();
    {
        let mut g = inner.lock().unwrap();
        g.kick = Some(Arc::new(move || {
            for e in &exits {
                e();
            }
        }));
        g.input = Some(s.input.clone());
    }

    let start = Instant::now();
    let mut last_output = Instant::now();
    let max = (opts.max_seconds > 0).then(|| Duration::from_secs(opts.max_seconds));
    let idle = (opts.idle_exit_secs > 0).then(|| Duration::from_secs(opts.idle_exit_secs));
    let mut console_filter = ConsoleFilter::new();

    while s.running.load(Ordering::Acquire) {
        if inner.lock().unwrap().stop_requested {
            return Ok(Outcome::Interrupted);
        }

        let raw = s.uart.take_output();
        if raw.is_empty() {
            // Nothing to move; yield rather than spin a core against the vCPUs.
            thread::sleep(Duration::from_millis(5));
        } else {
            let bytes = console_filter.feed(&raw);
            if !bytes.is_empty() {
                append_console(inner, &bytes);
                last_output = Instant::now();
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
            return Ok(Outcome::Idle(opts.idle_exit_secs));
        }
    }
    // `running` cleared without the supervisor asking: a vCPU thread powered off
    // or failed, and the engine reports that outcome in preference to this one.
    Ok(Outcome::PoweredOff)
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
            "missing command (list [--json] | status [--json] | start <name> | console | input [text] | stop | shutdown)"
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

/// Map `chm ctl <args>` onto the one-line daemon protocol.
///
/// `posture` and `proxy` are JSON-only. The daemon has no text renderer and
/// adding a second one would give us two things to keep in step; a human who
/// wants the prose form has `chm posture <dir>` / `chm proxy show <dir>`, which
/// is the same assessment run locally. The point of the `ctl` form is *whose*
/// environment answered, not its formatting — both read the environment of the
/// process they run in, and only the daemon's environment describes the guest.
fn ctl_command(rest: &[String]) -> Result<String, String> {
    /// Commands whose answer depends on the answering process's environment.
    fn provenanced(cmd: &str) -> Option<&'static str> {
        match cmd {
            "posture" => Some("posture-json"),
            "proxy" => Some("proxy-json"),
            _ => None,
        }
    }

    // `proxy check --host H [--port P] [--path X]` runs in the daemon too.
    if rest.first().map(String::as_str) == Some("proxy")
        && rest.get(1).map(String::as_str) == Some("check")
    {
        let f = |name: &str| {
            rest.iter()
                .position(|a| a == name)
                .and_then(|i| rest.get(i + 1))
                .cloned()
        };
        let host = f("--host").ok_or_else(|| "proxy check: --host is required".to_string())?;
        let port = f("--port").unwrap_or_else(|| "443".to_string());
        let path = f("--path").unwrap_or_else(|| "/".to_string());
        return Ok(format!("proxy-check-json {host} {port} {path}"));
    }

    // `proxy ca [<dir>]` likewise: the CA is per-workspace, so only the daemon
    // can name the one the running guest will actually meet.
    if rest.first().map(String::as_str) == Some("proxy")
        && rest.get(1).map(String::as_str) == Some("ca")
    {
        let dir = rest.get(2).filter(|a| !a.starts_with('-')).cloned();
        return Ok(match dir {
            Some(d) => format!("proxy-ca-json {d}"),
            None => "proxy-ca-json".to_string(),
        });
    }

    // `capabilities [<dir>]`: what the daemon's own binary can do. Asking the
    // caller's `chm` instead would describe a different file — possibly a
    // different build, and certainly a different signature.
    if rest.first().map(String::as_str) == Some("capabilities") {
        let dir = rest.get(1).filter(|a| !a.starts_with('-')).cloned();
        return Ok(match dir {
            Some(d) => format!("capabilities-json {d}"),
            None => "capabilities-json -".to_string(),
        });
    }

    // `audit [<dir>] [--tail N]`: the trail that matters is the one the running
    // guest is writing to, which only the daemon can name.
    if rest.first().map(String::as_str) == Some("audit") {        let tail = rest
            .iter()
            .position(|a| a == "--tail")
            .and_then(|i| rest.get(i + 1))
            .cloned();
        let dir = rest
            .iter()
            .enumerate()
            .skip(1)
            .find(|(i, a)| {
                !a.starts_with('-')
                    && rest.get(i.wrapping_sub(1)).map(String::as_str) != Some("--tail")
                    // `chm audit show <dir>` reads naturally; accept and skip it.
                    && a.as_str() != "show"
            })
            .map(|(_, a)| a.clone());
        return Ok(match (dir, tail) {
            (Some(d), Some(t)) => format!("audit-json {d} {t}"),
            (Some(d), None) => format!("audit-json {d}"),
            // The tail is the second field, so a tail with no directory still
            // needs a first one. `-` means "you choose" -- passing `.` here
            // would name the caller's cwd as a requested directory and quietly
            // read the wrong trail, which is the whole bug class this pattern
            // exists to avoid.
            (None, Some(t)) => format!("audit-json - {t}"),
            (None, None) => "audit-json".to_string(),
        });
    }

    // A `--json` flag is accepted and dropped: these are JSON either way, and
    // rejecting it would make the ctl form gratuitously different from the
    // local one a user just came from.
    let (head, dir) = match rest {
        [cmd] => (Some(cmd), None),
        [cmd, a] if a == "--json" => (Some(cmd), None),
        [cmd, a] => (Some(cmd), Some(a)),
        [cmd, a, b] if b == "--json" => (Some(cmd), Some(a)),
        _ => (None, None),
    };
    if let Some(verb) = head.and_then(|c| provenanced(c)) {
        return Ok(match dir {
            Some(d) => format!("{verb} {d}"),
            None => verb.to_string(),
        });
    }

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

// ---------------------------------------------------------------------------
// Client (`chm exec`)
// ---------------------------------------------------------------------------

/// Exit status when the guest did not report completion in time.
const EXEC_TIMEOUT_EXIT: u8 = 124;
/// Exit status when `chm` itself could not obtain a verdict.
const EXEC_FAILURE_EXIT: u8 = 125;

/// Default seconds to wait for a command. Long enough for a package install,
/// short enough that a wedged guest is not waited on forever.
const EXEC_DEFAULT_TIMEOUT: u64 = 300;

pub(crate) const EXEC_USAGE: &str = "\
usage: chm exec [--socket PATH] [--timeout SECS] [--json] -- <command> [args...]

Run a command in the sandbox `chm serve` is running and report its exit status.

  --timeout SECS   give up after SECS (default 300)
  --json           print {status, exit_code, output, error, duration_ms}

The arguments after `--` are an argv, not a shell command line: nothing in them
is interpreted as shell syntax. To use a shell, ask for one explicitly:

  chm exec -- bash -lc 'make build 2>&1 | tail -20'

Exit status is the guest command's own, so a failing command fails `chm exec`.
A transport failure never reports success: 124 means the guest did not answer in
time and 125 means chm could not run the command at all. With --json the
`status` field is the contract, and `exit_code` is non-null only when it is
`completed`.

Output is the guest's *console* text with stdout and stderr combined, not a
byte-exact stream: the terminal has already cooked it. For binary output, or to
keep the two streams apart, redirect to a file in the guest and copy it out.";

pub fn exec_main(raw: &[String]) -> ExitCode {
    match exec_client(raw) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("chm exec: {e}");
            ExitCode::from(EXEC_FAILURE_EXIT)
        }
    }
}

fn exec_client(raw: &[String]) -> Result<u8, String> {
    let (socket, rest) = take_socket(raw)?;
    let (timeout, json, argv) = parse_exec_args(&rest)?;

    let reply = exec_once(&socket, timeout, &argv)?;

    if json {
        println!("{reply}");
    }

    let status = reply.get("status").and_then(|v| v.as_str()).unwrap_or("error");
    if status != "completed" {
        let msg = reply.get("error").and_then(|v| v.as_str()).unwrap_or("no detail");
        if !json {
            eprintln!("chm exec: {status}: {msg}");
        }
        return Ok(if status == "timeout" {
            EXEC_TIMEOUT_EXIT
        } else {
            EXEC_FAILURE_EXIT
        });
    }

    if !json && let Some(out) = reply.get("output").and_then(|v| v.as_str()) {
        print!("{out}");
        if !out.is_empty() && !out.ends_with('\n') {
            println!();
        }
    }
    // A guest exit status is 0..=255; anything else means the daemon and this
    // client disagree about the protocol, which is a chm failure, not the
    // command's.
    let code = reply.get("exit_code").and_then(|v| v.as_i64());
    match code {
        Some(c) if (0..=255).contains(&c) => Ok(c as u8),
        _ => Err("daemon reported completion without a usable exit status".to_string()),
    }
}

/// Send one framed command to a running daemon and return its reply.
///
/// Shared rather than reimplemented, because `chm cp` (#316) drives a guest over
/// exactly this protocol and two implementations of one wire format eventually
/// disagree — silently, since both sides would still be *ours*. The reply is
/// returned raw so each caller decides what a non-zero status means to it: for
/// `exec` it is the command's own result and must be passed through, for `cp` it
/// is a transfer failure at a named step.
pub(crate) fn exec_once(
    socket: &Path,
    timeout: u64,
    argv: &[String],
) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot connect to daemon at {}: {e} (is `chm serve` running?)",
            socket.display()
        )
    })?;
    let request = format!("exec-json {timeout} {}\n", exec::encode_argv(argv));
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send command: {e}"))?;
    stream.flush().ok();

    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .map_err(|e| format!("read daemon: {e}"))?;
    serde_json::from_str(body.trim()).map_err(|e| format!("daemon reply: {e} ({body})"))
}

/// Split `chm exec`'s own flags from the guest argv.
///
/// Everything after `--` is the command, verbatim: a guest command's own flags
/// must never be mistaken for ours. Without a `--`, flags are consumed until the
/// first non-flag word, which then starts the command.
fn parse_exec_args(rest: &[String]) -> Result<(u64, bool, Vec<String>), String> {
    let mut timeout = EXEC_DEFAULT_TIMEOUT;
    let mut json = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--json" => json = true,
            "--timeout" => {
                let v = rest.get(i + 1).ok_or("--timeout needs a value in seconds")?;
                timeout = v.parse().map_err(|_| format!("--timeout: `{v}` is not a number"))?;
                if timeout == 0 {
                    return Err("--timeout must be at least 1 second".to_string());
                }
                i += 1;
            }
            "-h" | "--help" => return Err(EXEC_USAGE.to_string()),
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`\n\n{EXEC_USAGE}"));
            }
            _ => break,
        }
        i += 1;
    }
    let argv: Vec<String> = rest[i..].to_vec();
    if argv.is_empty() {
        return Err(format!("no command given\n\n{EXEC_USAGE}"));
    }
    Ok((timeout, json, argv))
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

    /// `posture` is JSON whether or not `--json` is passed, and an optional
    /// directory rides through. Bare `posture` must NOT fall through to the
    /// `[cmd] => cmd` arm, which would send the daemon a verb it does not know.
    #[test]
    fn ctl_posture_is_always_json_and_carries_an_optional_dir() {
        assert_eq!(ctl_command(&s(&["posture"])).unwrap(), "posture-json");
        assert_eq!(
            ctl_command(&s(&["posture", "--json"])).unwrap(),
            "posture-json"
        );
        assert_eq!(
            ctl_command(&s(&["posture", "/tmp/ws"])).unwrap(),
            "posture-json /tmp/ws"
        );
        assert_eq!(
            ctl_command(&s(&["posture", "/tmp/ws", "--json"])).unwrap(),
            "posture-json /tmp/ws"
        );
    }

    /// The daemon splices provenance into the posture body rather than nesting
    /// it, so one decoder handles both this and `chm posture --json`. That
    /// splice is a string edit on `{`, so prove it lands and the result parses.
    #[test]
    fn daemon_posture_json_is_valid_and_carries_provenance() {
        let dir = std::env::temp_dir().join(format!("chm-posture-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };

        let out = posture_json(&daemon, "");
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["source"], "daemon");
        // Idle, and the library has no entries, so it falls back to the root.
        assert_eq!(parsed["assessed"], "library-root");
        assert!(parsed["controls"].is_array(), "controls survived the splice");
        assert!(parsed["weakened"].is_number());

        // An explicit directory is reported as such and is the one assessed.
        let out = posture_json(&daemon, dir.to_str().unwrap());
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["assessed"], "requested");
        assert_eq!(parsed["workspace"], dir.to_str().unwrap());

        let _ = fs::remove_dir_all(&dir);
    }

    /// The library a daemon serves is fixed at `chm serve <dir>`, so a caller
    /// configured for a different one is reading a list that has nothing to do
    /// with its own setting. **Idle is the case that matters**: with no running
    /// guest there is nothing else on screen to contradict a wrong library, and
    /// that is exactly the shape the app hit — a banner predicting an empty
    /// list above a sidebar full of snapshots from somewhere else.
    #[test]
    fn status_reports_the_library_it_serves_even_when_idle() {
        let dir = std::env::temp_dir().join(format!("chm-statuslib-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };

        let parsed: serde_json::Value =
            serde_json::from_str(&status_json(&daemon)).expect("valid JSON");
        assert_eq!(parsed["state"], "idle");
        assert_eq!(parsed["library"], dir.to_str().unwrap());

        // The human form must carry it too. A text answer that omits what the
        // JSON answer has is a second opinion waiting to drift apart.
        let line = status_line(&daemon);
        assert!(line.starts_with("idle\t"), "{line}");
        assert!(line.contains(dir.to_str().unwrap()), "{line}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A library path can contain a character JSON must escape. The field is
    /// interpolated into a hand-built object like every other field here, so
    /// prove the escaping is applied rather than assumed.
    #[test]
    fn status_escapes_a_library_path_that_needs_it() {
        let dir = std::env::temp_dir().join(format!("chm-esc-\"{}", process::id()));
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };

        let out = status_json(&daemon);
        let parsed: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("not valid JSON: {e}: {out}"));
        assert_eq!(parsed["library"], dir.to_str().unwrap());
    }

    #[test]
    fn daemon_proxy_json_names_the_directory_it_assessed() {
        let dir = std::env::temp_dir().join(format!("chm-proxy-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };

        let parsed: serde_json::Value =
            serde_json::from_str(&proxy_json(&daemon, "")).expect("valid JSON");
        assert_eq!(parsed["source"], "daemon");
        assert_eq!(parsed["assessed"], "library-root");
        assert_eq!(parsed["scope_dir"], dir.to_str().unwrap());
        assert_eq!(parsed["configured"], false);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bare_input_sends_a_newline() {
        // The common case: waking a login prompt on a resumed guest, which
        // emits nothing until it is typed at.
        assert_eq!(decode_input(""), b"\n");
    }

    #[test]
    fn input_decodes_escapes_into_raw_control_bytes() {
        assert_eq!(decode_input("ubuntu\\n"), b"ubuntu\n");
        assert_eq!(decode_input("\\r"), b"\r");
        assert_eq!(decode_input("\\t"), b"\t");
        assert_eq!(decode_input("\\x03"), &[3u8]);
        // Ctrl-C then Ctrl-D, the two escapes a console client needs most.
        assert_eq!(decode_input("\\x03\\x04"), &[3u8, 4u8]);
        // A literal backslash survives.
        assert_eq!(decode_input("a\\\\b"), b"a\\b");
    }

    #[test]
    fn input_passes_unknown_escapes_through_verbatim() {
        // Better to deliver what the caller wrote than to silently drop it.
        assert_eq!(decode_input("\\q"), b"\\q");
        assert_eq!(decode_input("\\xzz"), b"\\xzz");
        assert_eq!(decode_input("\\"), b"\\");
    }

    #[test]
    fn input_leaves_plain_text_untouched() {
        assert_eq!(decode_input("ubuntu"), b"ubuntu");
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

        // A self-owned dir left with loose permissions is tightened back to
        // 0700 rather than accepted as-is (#66), so group/other can never
        // interpose in the runtime dir.
        let loose = base.join("loose");
        fs::create_dir_all(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
        ensure_private_runtime_dir(&loose).unwrap();
        let loose_mode = fs::metadata(&loose).unwrap().permissions().mode() & 0o777;
        assert_eq!(loose_mode, 0o700, "a loose self-owned runtime dir must be tightened to 0700");

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
        let base = env::temp_dir().join(format!("chm-peeruid-{}", process::id()));
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

    /// `audit` must reach the daemon, because the trail belongs to the process
    /// running the guest. The `--tail` value must not be mistaken for a
    /// directory, and a tail with no directory must not silently name the
    /// caller's cwd -- that is how a reader ends up looking at the wrong
    /// sandbox and concluding it was quiet.
    #[test]
    fn ctl_audit_reaches_the_daemon_without_inventing_a_directory() {
        assert_eq!(ctl_command(&s(&["audit"])).unwrap(), "audit-json");
        assert_eq!(
            ctl_command(&s(&["audit", "--tail", "50"])).unwrap(),
            "audit-json - 50",
            "`-` means the daemon chooses; `.` would name the caller's cwd"
        );
        assert_eq!(
            ctl_command(&s(&["audit", "/w"])).unwrap(),
            "audit-json /w"
        );
        assert_eq!(
            ctl_command(&s(&["audit", "/w", "--tail", "5"])).unwrap(),
            "audit-json /w 5"
        );
        // `audit show <dir>` reads naturally and must not be taken as the dir.
        assert_eq!(
            ctl_command(&s(&["audit", "show", "/w"])).unwrap(),
            "audit-json /w"
        );
    }

    /// `capabilities` must reach the daemon, because it describes the daemon's
    /// own binary. Answering from the caller's `chm` would describe a different
    /// file -- possibly a different build, and certainly a different signature,
    /// which is exactly the distinction the panel exists to draw.
    #[test]
    fn ctl_capabilities_asks_the_binary_that_would_run_the_guest() {
        assert_eq!(
            ctl_command(&s(&["capabilities"])).unwrap(),
            "capabilities-json -",
            "`-` means the daemon chooses; `.` would name the caller's cwd"
        );
        assert_eq!(
            ctl_command(&s(&["capabilities", "/snap"])).unwrap(),
            "capabilities-json /snap"
        );
        // A flag is not a directory.
        assert_eq!(
            ctl_command(&s(&["capabilities", "--json"])).unwrap(),
            "capabilities-json -"
        );
    }

    // -----------------------------------------------------------------------
    // `chm exec`
    // -----------------------------------------------------------------------

    #[test]
    fn exec_defaults_to_a_bounded_wait_and_text_output() {
        let (timeout, json, argv) = parse_exec_args(&s(&["uname", "-a"])).unwrap();
        assert_eq!(timeout, EXEC_DEFAULT_TIMEOUT);
        assert!(!json);
        assert_eq!(argv, s(&["uname", "-a"]));
    }

    /// The guest's own flags must never be eaten by ours. `--` is the boundary,
    /// and everything past it is data.
    #[test]
    fn exec_does_not_claim_the_guest_commands_flags() {
        let (_, json, argv) =
            parse_exec_args(&s(&["--", "ls", "--json", "--timeout", "5"])).unwrap();
        assert!(!json, "`--json` after `--` belongs to the guest command");
        assert_eq!(argv, s(&["ls", "--json", "--timeout", "5"]));
    }

    #[test]
    fn exec_reads_its_own_flags_before_the_separator() {
        let (timeout, json, argv) =
            parse_exec_args(&s(&["--timeout", "5", "--json", "--", "true"])).unwrap();
        assert_eq!(timeout, 5);
        assert!(json);
        assert_eq!(argv, s(&["true"]));
    }

    #[test]
    fn exec_refuses_an_empty_or_nonsensical_request() {
        assert!(parse_exec_args(&s(&[])).is_err());
        assert!(parse_exec_args(&s(&["--json"])).is_err());
        assert!(parse_exec_args(&s(&["--timeout"])).is_err());
        assert!(parse_exec_args(&s(&["--timeout", "soon", "--", "true"])).is_err());
        // A zero timeout would send the command and give up before the guest
        // could possibly answer, reporting a timeout for work that is running.
        assert!(parse_exec_args(&s(&["--timeout", "0", "--", "true"])).is_err());
        assert!(parse_exec_args(&s(&["--bogus", "--", "true"])).is_err());
    }

    /// With no VM running there is nothing to run a command in, and the reply
    /// must say so in a form no caller can mistake for a successful command.
    #[test]
    fn exec_without_a_running_guest_is_an_error_not_an_exit_status() {
        let dir = std::env::temp_dir().join(format!("chm-exec-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };
        let out = exec_json(&daemon, &format!("30 {}", exec::encode_argv(&s(&["true"]))));
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["status"], "error");
        assert!(parsed["exit_code"].is_null(), "a failure must carry no exit status");
        assert!(
            parsed["error"].as_str().unwrap().contains("no VM running"),
            "{out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A garbled request must not be answered with a plausible-looking success.
    #[test]
    fn exec_refuses_a_malformed_request() {
        let dir = std::env::temp_dir().join(format!("chm-execbad-{}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon {
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: dir.join("chm.sock"),
            current: Mutex::new(None),
        };
        for req in ["", "notanumber ff", "30 zz"] {
            let out = exec_json(&daemon, req);
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
            assert_eq!(parsed["status"], "error", "{req} -> {out}");
            assert!(parsed["exit_code"].is_null(), "{req} -> {out}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// #288 has a call-site failure mode no assertion about a *string* can see:
    /// `superseded_note` can be perfectly correct and simply never consulted,
    /// or `stop_vm` can go back to discarding the worker's reason, and every
    /// test that examines the note's text stays green. This repo has banked
    /// that class four times (V9.5c, V9.11a M4, #222, #242), so read the source.
    ///
    /// The needles are assembled from parts because a literal here would match
    /// its own assertion text -- exactly how the #222 guard was born dead.
    #[test]
    fn the_stop_path_still_carries_the_way_back() {
        let src = include_str!("serve.rs");
        let consulted = format!("{}(Some(&id), dir)", "superseded_note");
        assert!(
            src.contains(&consulted),
            "run_guest_usgic must consult superseded_note, or the daemon's stop \
             message loses the displaced revision"
        );
        let reports = format!("stopped `{{}}` {} {{reason}}", "\u{2014}");
        assert!(
            src.contains(&reports),
            "stop_vm must report the worker's own reason: a bare `stopped` is \
             what #288 printed over a wedged guest"
        );
    }
}
