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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, mem, ptr, thread};

use crate::audit;
use crate::capability;
use crate::checkpoint;
use crate::console::ConsoleInput;
use hypervisor::hvf::virtio::NetIo;
use hypervisor::hvf::virtio::nat::{AmendOutcome, Amendment};
use crate::disktail;
use crate::credproxy::cli;
use crate::console_filter::ConsoleFilter;
use crate::exec;
use crate::imp::{
    IDLE_RESIDENCY_PERCENT, IdleResidency, Loaded, Outcome, UsgicConfig, UsgicSession,
    aarch32_guard, cntfrq_guard, icache_dic_guard, load_snapshot, run_usgic_engine,
    superseded_note,
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

/// Applies one live egress amendment to every NIC a guest has, returning what
/// each device did, paired with the name it reported it under.
///
/// Named rather than written inline because it appears at both the field and
/// the publication site, and the two must not drift: a mismatch there is a
/// compile error only by luck, since both are `Arc<dyn Fn…>` and coercion is
/// what connects them.
pub(crate) type EgressAmender =
    Arc<dyn Fn(&Amendment) -> Vec<(String, AmendOutcome)> + Send + Sync>;

/// Where the running guest's state lives, shared between the worker thread that
/// drives the vCPU and the connection handlers that read console / status.
///
/// `pub(crate)` because `chm create` publishes its cold-booted guest through the
/// same structure (#401). Cold boot builds its VM itself rather than through
/// [`run_guest`], but everything downstream of the console -- `exec`, `input`,
/// `console`, `status` -- reads only this, so sharing it is what lets the whole
/// verb surface serve a cold guest with no second implementation.
pub(crate) struct VmInner {
    pub(crate) console: Vec<u8>,
    /// Number of console bytes evicted from the front of `console` (so a client
    /// cursor is an absolute byte offset into the whole stream).
    pub(crate) dropped: usize,
    pub(crate) status: RunStatus,
    pub(crate) stop_requested: bool,
    /// Cross-thread handle that forces the vCPU out of `run()` (HVF
    /// `hv_vcpus_exit`). Published by the worker once the VM is built, so a
    /// `stop` can interrupt even a guest that is spinning without trapping.
    pub(crate) kick: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Delivers bytes to the guest's serial console. Published by the worker
    /// alongside `kick`; without it the daemon's console is read-only and a
    /// client could watch a guest but never type into it.
    pub(crate) input: Option<ConsoleInput>,
    /// Applies a live egress amendment to every NIC this guest has, reporting
    /// per-NIC what each one did. Published by the worker alongside `input`.
    ///
    /// `None` means this guest exposes no amendable NIC -- either no device
    /// model was wired, or the path that started it does not publish one. That
    /// is reported as such rather than as a silent success, because "your
    /// change did nothing" is the one answer an operator must never have to
    /// infer (#156).
    pub(crate) egress: Option<EgressAmender>,
    /// Per NIC, the effective policy label the *device* reported after the last
    /// amendment, so `posture` can say the policy in force is no longer the one
    /// the workspace configures.
    ///
    /// Recorded rather than recomputed: the label is the NIC's own answer,
    /// carried verbatim. Deriving a second label here from the amendments this
    /// process happens to have sent would be a second rendering of the policy,
    /// and #202/#203 are two records of what that costs.
    pub(crate) egress_live: Vec<(String, String)>,
}

impl VmInner {
    /// An empty ring for a guest that is starting.
    pub(crate) fn new() -> Self {
        Self {
            console: Vec::new(),
            dropped: 0,
            status: RunStatus::Running,
            stop_requested: false,
            kick: None,
            input: None,
            egress: None,
            egress_live: Vec::new(),
        }
    }
}

pub(crate) enum RunStatus {
    Running,
    Stopped(String),
}

struct Vm {
    name: String,
    started: Instant,
    /// The directory this guest's state lives in, when the daemon knows it
    /// without consulting its library. A cold-booted guest has no library entry
    /// to look up, so without this `posture`/`proxy`/`audit` would silently
    /// assess the library root instead and report it as such.
    dir: Option<PathBuf>,
    inner: Arc<Mutex<VmInner>>,
}

struct Entry {
    name: String,
    dir: PathBuf,
    num_vcpus: u32,
    total_ram: u64,
}

/// What kind of endpoint a [`Daemon`] is, so the verbs that only make sense for
/// one of them can be refused by name rather than answered wrongly.
///
/// `chm serve` manages a *library* of snapshots and starts guests out of it on
/// request. `chm create --socket` manages exactly one guest that is already
/// running and has no library at all. Every verb that reads the running guest
/// is identical for both; the four that are not are the whole of the
/// difference, and naming it here is what keeps that difference in one place.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// `chm serve`: a library, and guests started from it.
    Library,
    /// `chm create --socket`: one guest, no library, already running.
    ColdBoot,
}

struct Daemon {
    role: Role,
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

pub(crate) const SERVE_USAGE: &str = "\
usage: chm serve <LIBRARY_DIR> [--socket PATH] [--idle-exit SECS] [--max-seconds SECS]

Run the daemon that owns this process's one HVF slot, serving snapshots out of
LIBRARY_DIR. Drive it with `chm ctl` (see `chm ctl --help`) or `chm exec`.

  <LIBRARY_DIR>        directory of snapshot workspaces to offer
  --socket PATH        where to listen (default: <tmpdir>/gimbal-local/chm.sock)
  --idle-exit SECS     exit after SECS with no guest running (0 disables)
  --max-seconds SECS   suspend the guest and exit after SECS (0 disables)

The socket is created 0600. A deadline suspends and checkpoints the guest
rather than cutting its power, so a resumable point survives.";

pub fn serve_main(raw: &[String]) -> ExitCode {
    // Before `serve()`, because the argument parser's job is to reject unknown
    // options and `--help` would be one of them: a command that answers its own
    // `--help` with "unknown option `--help`" teaches nothing and contradicts
    // what `chm --help` promises about every subcommand.
    if wants_help(raw) {
        println!("{SERVE_USAGE}");
        return ExitCode::SUCCESS;
    }
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

    let library_dir =
        library_dir.ok_or_else(|| format!("missing <LIBRARY_DIR>\n\n{SERVE_USAGE}"))?;
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
        role: Role::Library,
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

/// The console ring of a guest `chm create` is driving, optionally published on
/// a control socket (#401).
///
/// Cold boot builds its own VM rather than going through [`start_vm`], so
/// nothing here starts a guest. What it does is put that guest behind the
/// *same* [`VmInner`] every control verb already reads, which is what lets
/// `exec`, `input`, `console` and `status` serve a cold-booted sandbox without
/// a second implementation of the exec framing, the truncation window or the
/// input path. Those are the pieces that would silently diverge.
/// Counts one accepted connection for the whole time it is being served.
///
/// The increment and the decrement live in one type on purpose. When the
/// `fetch_add` sat at the accept site instead, deleting it left all 1020 tests
/// green -- the call-site class that has caught this repo nine times, and here
/// it would silently restore the very race `finish`'s drain exists to close.
/// As a value it is reachable from a unit test, so the counting is guarded
/// rather than assumed.
///
/// `Drop` gives the count back however the handler leaves, including a panic,
/// so one bad connection cannot hold teardown open for the full drain.
struct Served(Arc<AtomicUsize>);

impl Served {
    fn begin(inflight: &Arc<AtomicUsize>) -> Self {
        inflight.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(inflight))
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long [`ColdControl::finish`] will wait for an in-flight reply to land
/// before dropping the socket anyway.
///
/// A ceiling, not a delay: the reply a `stop` client is waiting for is one small
/// write issued within one 50 ms poll of the status flipping, so the usual cost
/// is milliseconds. It is only reached by a connection that is not waiting for a
/// reply at all -- `ctl console` streams until the socket closes -- and making
/// that case wait two seconds is the price of not truncating everyone else.
const FINISH_DRAIN: Duration = Duration::from_secs(2);

pub(crate) struct ColdControl {
    inner: Arc<Mutex<VmInner>>,
    /// Cleared at teardown to stop the accept loop. `None` when no socket was
    /// asked for, in which case this is only a console ring.
    serving: Option<Arc<AtomicBool>>,
    /// Connections currently being served, so teardown can let a reply finish
    /// rather than racing it. See [`ColdControl::finish`].
    inflight: Option<Arc<AtomicUsize>>,
    socket_path: Option<PathBuf>,
}

impl ColdControl {
    /// A console ring with no socket -- what `--post-boot` needs on its own.
    pub(crate) fn detached() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VmInner::new())),
            serving: None,
            inflight: None,
            socket_path: None,
        }
    }

    /// Bind `socket_path` and serve this guest's control verbs on it.
    ///
    /// Same hygiene as [`serve`]: a private 0700 runtime dir that refuses a
    /// symlink, a 0600 socket, and a peer-uid check on every connection. `dir`
    /// is what `posture`/`proxy`/`audit` assess, since there is no library
    /// entry to look the guest up in.
    pub(crate) fn bound(name: &str, dir: PathBuf, socket_path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = socket_path.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_private_runtime_dir(parent)?;
        }
        remove_stale_socket(&socket_path);
        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| format!("bind {}: {e}", socket_path.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 0600 {}: {e}", socket_path.display()))?;
        }
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set listener non-blocking: {e}"))?;

        let inner = Arc::new(Mutex::new(VmInner::new()));
        let daemon = Arc::new(Daemon {
            role: Role::ColdBoot,
            library: Vec::new(),
            library_dir: dir.clone(),
            idle_exit_secs: 0,
            max_seconds: 0,
            socket_path: socket_path.clone(),
            current: Mutex::new(Some(Vm {
                name: name.to_string(),
                started: Instant::now(),
                dir: Some(dir),
                inner: Arc::clone(&inner),
            })),
        });

        let serving = Arc::new(AtomicBool::new(true));
        let loop_serving = Arc::clone(&serving);
        let inflight = Arc::new(AtomicUsize::new(0));
        let loop_inflight = Arc::clone(&inflight);
        thread::Builder::new()
            .name("cold-control".into())
            .spawn(move || {
                while loop_serving.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            let _ = stream.set_nonblocking(false);
                            let daemon = Arc::clone(&daemon);
                            // Counted before the thread exists, so teardown can
                            // never observe zero for a connection it has already
                            // accepted.
                            let served = Served::begin(&loop_inflight);
                            thread::spawn(move || {
                                let _served = served;
                                handle_conn(stream, &daemon);
                            });
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => eprintln!("chm create: accept error: {e}"),
                    }
                }
            })
            .map_err(|e| format!("spawning the control socket thread: {e}"))?;

        Ok(Self {
            inner,
            serving: Some(serving),
            inflight: Some(inflight),
            socket_path: Some(socket_path),
        })
    }

    /// Publish the channels a control client needs: `input` types into the
    /// guest's console, `kick` forces its vCPUs out of `run()` so a `stop`
    /// lands on a guest that is not trapping, and `egress` amends the live
    /// policy on every NIC it has.
    ///
    /// `egress` is a required argument rather than a later setter, and `None`
    /// has to be passed deliberately. A cold guest reaches the same verb
    /// surface as a daemon-run one, so a path that quietly forgot to publish
    /// this would refuse `chm ctl egress` with "this VM exposes no amendable
    /// network device" on a guest that plainly has one -- true about the
    /// plumbing and useless to the operator reading it. Making the omission a
    /// compile error is the only version of that guard which cannot be skipped.
    pub(crate) fn publish(
        &self,
        input: ConsoleInput,
        kick: Arc<dyn Fn() + Send + Sync>,
        egress: Option<EgressAmender>,
    ) {
        let mut g = self.inner.lock().unwrap();
        g.input = Some(input);
        g.kick = Some(kick);
        g.egress = egress;
    }

    /// Push guest serial output into the ring.
    pub(crate) fn push(&self, bytes: &[u8]) {
        append_console(&self.inner, bytes);
    }

    /// Everything still in the ring.
    ///
    /// Bytes, not text: the ring evicts whole bytes and the UART delivers them
    /// in arbitrary batches, so a multi-byte character can be cut at either end.
    /// Callers mark a position and slice from it later, and decoding first makes
    /// those marks move -- see [`postboot::Console::transcript`], which explains
    /// why that panics rather than merely reading the wrong text.
    pub(crate) fn transcript(&self) -> Vec<u8> {
        self.inner.lock().unwrap().console.clone()
    }

    /// Whether a control client has asked this guest to stop.
    pub(crate) fn stop_requested(&self) -> bool {
        self.inner.lock().unwrap().stop_requested
    }

    /// Record why the guest ended and take the socket down.
    ///
    /// The status matters even though the process is about to exit: a `stop`
    /// waits for [`RunStatus::Stopped`] before replying, so without this the
    /// client that asked would time out on a guest that had already halted.
    pub(crate) fn finish(&self, reason: &str) {
        self.inner.lock().unwrap().status = RunStatus::Stopped(reason.to_string());
        // A `ctl stop` client is blocked polling for exactly the status just
        // published, and the reply is written by a connection thread nothing
        // here joins. Clearing `serving` and unlinking the socket in the same
        // breath races that write, and the client loses: measured 0 bytes of
        // reply, twice, on hardware -- `chm ctl stop` appeared to do nothing
        // while having stopped the guest correctly.
        //
        // So publish first, then let the reply land, then take the socket away.
        // Bounded by FINISH_DRAIN, because a client that never reads must not
        // be able to hold teardown open.
        if let Some(inflight) = &self.inflight {
            let deadline = Instant::now() + FINISH_DRAIN;
            while inflight.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(serving) = &self.serving {
            serving.store(false, Ordering::Release);
        }
        if let Some(path) = &self.socket_path {
            let _ = fs::remove_file(path);
        }
    }
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

/// Why a verb does not apply to a cold-boot control socket, or `None` if it does.
///
/// A pure function so the refusals can be asserted without a socket, a guest or
/// a `Daemon`: the reason each one is refused is the part worth guarding, and it
/// is prose that a test can hold to.
pub(crate) fn cold_boot_refusal(cmd: &str) -> Option<String> {
    let library = |verb: &str| {
        Some(format!(
            "`{verb}` needs a snapshot library and this socket belongs to a \
             cold-booted guest, which was started from a kernel rather than \
             chosen out of one -- run `chm serve <library>` and ask that socket \
             instead"
        ))
    };
    match cmd {
        "list" | "list-json" => library(cmd),
        "start" => Some(
            "`start` needs a snapshot library and this socket belongs to a \
             cold-booted guest, which is already running -- HVF is one VM per \
             process, so this endpoint will never start a second one"
                .to_string(),
        ),
        "shutdown" => Some(
            "`shutdown` exits the daemon, and exiting this process here would \
             skip the teardown that captures `--originate` and releases the HVF \
             slot -- use `stop`, which asks the guest to halt and lets the \
             cold-boot path finish"
                .to_string(),
        ),
        _ => None,
    }
}

/// The prefix the daemon puts on a reply that reports a failure.
///
/// One constant, written by every daemon reply that refuses and read by the one
/// client that classifies replies. A second copy of this string is exactly how
/// `chm ctl` would go back to reporting failures as success: the daemon would
/// carry on saying so and the client would quietly stop hearing it, with
/// nothing failing in between.
pub(crate) const REPLY_ERROR_PREFIX: &str = "error\t";

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

    // Four verbs are about a *library*, and a cold-booted guest has none: this
    // process was handed a kernel, it did not pick a snapshot out of a
    // directory. Answering `list` with "(library is empty)" would be true of
    // this endpoint and read as "you have no snapshots", which is the shape of
    // wrong answer #304 is about -- so say which endpoint this is and where the
    // verb does work. `shutdown` is refused for a different reason: it calls
    // `exit(0)` from this thread, which on the cold path would skip the
    // teardown that captures `--originate` and destroys the VM.
    if daemon.role == Role::ColdBoot
        && let Some(why) = cold_boot_refusal(cmd)
    {
        let _ = writer.write_all(format!("{REPLY_ERROR_PREFIX}{why}\n").as_bytes());
        return;
    }

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
                Err(e) => format!("{REPLY_ERROR_PREFIX}{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "console" => stream_console(&mut writer, daemon),
        "input" => {
            let resp = match send_input(daemon, arg) {
                Ok(n) => format!("ok\t{n} byte(s)\n"),
                Err(e) => format!("{REPLY_ERROR_PREFIX}{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "egress" => {
            let resp = match amend_egress(daemon, arg) {
                Ok(msg) => format!("ok\t{msg}\n"),
                Err(e) => format!("{REPLY_ERROR_PREFIX}{e}\n"),
            };
            let _ = writer.write_all(resp.as_bytes());
        }
        "stop" => {
            let resp = match stop_vm(daemon) {
                Ok(msg) => format!("ok\t{msg}\n"),
                Err(e) => format!("{REPLY_ERROR_PREFIX}{e}\n"),
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
            let _ = writer
                .write_all(format!("{REPLY_ERROR_PREFIX}unknown command `{other}`\n").as_bytes());
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
///
/// # Why `--probe-guest` is opt-in
///
/// The in-guest user-namespace row can only be answered by running a command in
/// the guest, and [`exec_run`] writes **ETX (Ctrl-C)** to the console before its
/// script so it starts from a known prompt. `EXEC_BUSY` serialises two `chm
/// exec`s against each other; it knows nothing about a human's foreground
/// command. So probing on every posture read would interrupt whatever the user
/// was running, to compute a report that sounds read-only.
///
/// Split a `posture-json` request line into "was the guest's consent given?"
/// and "which directory?".
///
/// A pure function rather than two lines inside [`posture_json`] because that
/// function needs a live [`Daemon`], so a guard written against it can only
/// re-implement this parsing -- and a test that re-implements the thing it
/// guards agrees with itself no matter what the product does.
fn posture_request(arg: &str) -> (bool, &str) {
    let probe = arg.split_whitespace().any(|a| a == "--probe-guest");
    let dir = arg
        .split_whitespace()
        .find(|a| !a.starts_with('-'))
        .unwrap_or("");
    (probe, dir)
}

/// Reading a posture must not do anything. The flag is how a caller says it is
/// willing to.
fn posture_json(daemon: &Daemon, arg: &str) -> String {
    let (probe_requested, arg) = posture_request(arg);

    let (dir, assessed) = if arg.is_empty() {
        match running_vm_dir(daemon) {
            Some(dir) => (dir, "running-vm"),
            None => (daemon.library_dir.clone(), "library-root"),
        }
    } else {
        (PathBuf::from(arg), "requested")
    };

    let userns = match guest_userns_plan(probe_requested, running_vm_dir(daemon).is_some()) {
        Err(answer) => answer,
        Ok(secs) => probe_guest_userns(daemon, secs),
    };

    let (body, _weakened) = posture::assess_json(&dir, &userns);
    // Splice the provenance in after the opening brace rather than nesting, so
    // one decoder handles both this and `chm posture --json`.
    let spliced = body.replacen(
        '{',
        &format!(
            "{{\n  \"source\": \"daemon\",\n  \"assessed\": \"{assessed}\",{}",
            live_egress_json(daemon)
        ),
        1,
    );
    format!("{spliced}\n")
}

/// The policy the running guest's NICs are enforcing *now*, when it is no
/// longer the one the workspace configures (#156).
///
/// The rest of the report reads the configured sources -- `CHM_EGRESS_POLICY`,
/// `egress-policy.json` -- and after a live amendment those are still a true
/// description of what the sandbox *started* from and no longer a description
/// of what it enforces. Reporting only them would be the #202/#203 shape: a
/// statement that is accurate about its own source and wrong about the world.
///
/// Empty when nothing has been amended, so an unamended sandbox's report is
/// byte-identical to what it was before this feature existed.
fn live_egress_json(daemon: &Daemon) -> String {
    let guard = daemon.current.lock().unwrap();
    let Some(vm) = guard.as_ref() else {
        return String::new();
    };
    let live = vm.inner.lock().unwrap().egress_live.clone();
    render_live_egress(&live)
}

/// Render the live-policy key, separately from reading it off a running guest.
///
/// Split for the same reason as [`parse_amendment`]: the read needs a live
/// [`Daemon`], and the property that matters -- that an *unamended* report is
/// byte-identical to the one this build produced before #156 -- is a property
/// of the rendering, not of the lock.
fn render_live_egress(live: &[(String, String)]) -> String {
    if live.is_empty() {
        return String::new();
    }
    let nics = live
        .iter()
        .map(|(nic, label)| {
            format!(
                "{{ \"device\": {}, \"policy\": {} }}",
                posture::json_str(nic),
                posture::json_str(label)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("\n  \"egress_live\": [{nics}],")
}

/// How long the guest gets to answer the user-namespace probe.
///
/// Two orders of magnitude below `chm exec`'s 300 s default, and deliberately
/// so: `unshare --user --map-root-user true` either returns immediately or the
/// console is not in a state to run it. A posture read that can block for five
/// minutes is a posture read nobody will wait for, and the honest answer to a
/// console that will not answer in eight seconds is [`GuestUserns::NoAnswer`],
/// which this report can say.
const USERNS_PROBE_SECS: u64 = 8;

/// Decide whether to probe, separately from probing.
///
/// Split out because the effect needs a live guest and a console, and the
/// decision does not -- so every cell of the table is unit-testable without
/// either. Same move as `leak_at` in the GIC model (§54).
///
/// `Err` carries the answer to report without asking; `Ok` carries the deadline
/// to ask within.
fn guest_userns_plan(probe_requested: bool, vm_running: bool) -> Result<u64, posture::GuestUserns> {
    match (probe_requested, vm_running) {
        (false, true) => Err(posture::GuestUserns::NotAsked(
            "reading a posture does not touch the guest; pass --probe-guest to \
             run the check in it (it writes to the console, which interrupts a \
             foreground command)"
                .into(),
        )),
        (false, false) => Err(posture::GuestUserns::NotAsked(
            "no guest is running, and this control is a property of the guest".into(),
        )),
        // Asked, with nothing to ask. Not a failure: an idle daemon is the
        // normal state, and `NoAnswer` would imply something went wrong.
        (true, false) => Err(posture::GuestUserns::NotAsked(
            "--probe-guest was given but no guest is running; start one and ask \
             again"
                .into(),
        )),
        (true, true) => Ok(USERNS_PROBE_SECS),
    }
}

/// Run the probe in the guest and translate what came back.
///
/// Every outcome that is not a completed command becomes
/// [`GuestUserns::NoAnswer`] carrying its own reason. The transport cannot be
/// allowed to look like an answer in either direction: a timeout is not a
/// restriction, and a truncated transcript is not a success.
fn probe_guest_userns(daemon: &Daemon, secs: u64) -> posture::GuestUserns {
    let argv: Vec<String> = posture::USERNS_PROBE_ARGV
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let request = format!("{secs} {}", exec::encode_argv(&argv));

    match exec_run(daemon, &request) {
        Err(why) => posture::GuestUserns::NoAnswer(why),
        Ok((exec::ExecOutcome::Completed { code, output }, _)) => {
            if code == 0 {
                posture::GuestUserns::Available
            } else {
                let said = output.trim();
                let said = said.lines().next_back().unwrap_or("").trim();
                if said.is_empty() {
                    posture::GuestUserns::Restricted(format!("it exited {code} and said nothing"))
                } else {
                    posture::GuestUserns::Restricted(format!("exit {code}: {said}"))
                }
            }
        }
        Ok((exec::ExecOutcome::Pending, _)) => posture::GuestUserns::NoAnswer(format!(
            "the guest console did not answer within {secs}s"
        )),
        Ok((exec::ExecOutcome::Truncated, _)) => posture::GuestUserns::NoAnswer(
            "the guest console overflowed and the reply was lost".into(),
        ),
        Ok((exec::ExecOutcome::Overflowed, _)) => posture::GuestUserns::NoAnswer(
            "the reply was longer than the console buffer could hold".into(),
        ),
    }
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
    let vm = guard.as_ref()?;
    if let Some(dir) = vm.dir.clone() {
        return Some(dir);
    }
    let name = vm.name.clone();
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

    let inner = Arc::new(Mutex::new(VmInner::new()));

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
        // The library is the authority for a daemon-started guest, and
        // `running_vm_dir` looks it up there.
        dir: None,
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

/// Change the running guest's egress policy without restarting it (#156).
///
/// `arg` is `allow <host[:port]>` or `deny <host[:port]>`. The reply names the
/// rule as it was *parsed*, the effective policy label afterwards, anything the
/// change displaced, and how many established flows carry on under the old
/// decision -- because an amendment governs admission, not connections that are
/// already up, and an operator watching a connection survive their `deny` must
/// not be left to work that out for themselves.
fn amend_egress(daemon: &Daemon, arg: &str) -> Result<String, String> {
    let amendment = parse_amendment(arg)?;

    let guard = daemon.current.lock().unwrap();
    let vm = guard.as_ref().ok_or("no VM running")?;
    let amend = {
        let inner = vm.inner.lock().unwrap();
        if let RunStatus::Stopped(ref why) = inner.status {
            return Err(format!("`{}` is stopped ({why})", vm.name));
        }
        inner.egress.clone()
    };
    // Reported as a refusal, never as a quiet success: a guest with no NIC to
    // amend has not had its policy changed, and saying "ok" would be the exact
    // false sell this feature exists to remove.
    let amend = amend.ok_or(
        "this VM exposes no amendable network device, so its egress policy \
         cannot be changed while it runs",
    )?;
    let outcomes = amend(&amendment);
    if !outcomes.is_empty() {
        let mut inner = vm.inner.lock().unwrap();
        inner.egress_live = outcomes
            .iter()
            .map(|(nic, o)| (nic.clone(), o.label.clone()))
            .collect();
    }
    if outcomes.is_empty() {
        return Err(
            "this VM has a network device but it enforces no egress policy, so \
             there is nothing to amend"
                .to_string(),
        );
    }
    Ok(describe_amendments(&outcomes))
}

/// One line per NIC saying what the amendment did there.
///
/// Per NIC rather than once overall because the NICs are amended independently
/// and could in principle disagree; collapsing them to a single sentence would
/// invent an agreement nobody measured.
fn describe_amendments(outcomes: &[(String, AmendOutcome)]) -> String {
    let mut lines = Vec::new();
    for (nic, o) in outcomes {
        let verb = if o.allowed { "allow" } else { "deny" };
        let mut line = format!("{nic}: {verb} {} -- policy now {}", o.rule, o.label);
        if !o.superseded.is_empty() {
            line.push_str(&format!("; superseded {}", o.superseded.join(", ")));
        }
        line.push_str(&format!(
            "; {} established flow(s) continue under the previous decision",
            o.established_retained
        ));
        lines.push(line);
    }
    lines.join("\n\t")
}

/// Read `allow|deny <host[:port]>` out of a request line.
///
/// A pure function rather than four lines inside [`amend_egress`], because that
/// one needs a live [`Daemon`] and a running guest -- so every refusal a user
/// can reach by mistyping would otherwise be testable only through a VM, which
/// means in practice not at all.
fn parse_amendment(arg: &str) -> Result<Amendment, String> {
    let mut parts = arg.split_whitespace();
    let verb = parts.next().unwrap_or("");
    let entry = parts.next().unwrap_or("");
    if let Some(extra) = parts.next() {
        return Err(format!("unexpected argument `{extra}`; {EGRESS_USAGE}"));
    }
    if entry.is_empty() {
        return Err(format!("a host is required; {EGRESS_USAGE}"));
    }
    match verb {
        "allow" => Ok(Amendment::Allow(entry.to_string())),
        "deny" => Ok(Amendment::Deny(entry.to_string())),
        other => Err(format!("unknown action `{other}`; {EGRESS_USAGE}")),
    }
}

/// The shape `chm ctl egress` accepts, quoted verbatim in every refusal so a
/// user who typed it wrong is told the form rather than the category.
///
/// `pub(crate)` for the guard in `hygiene.rs` that holds `docs/networking.md`
/// to this exact string. A doc teaching a form the parser rejects sends a
/// reader to the one place that cannot help them, and a constant retyped in
/// the test would pass happily through exactly that bug.
pub(crate) const EGRESS_USAGE: &str = "usage: chm ctl egress allow|deny <host[:port]>";

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
        // `chm ctl start` names a snapshot, not a run shape, so there is no
        // flag here either. Publishing a guest port is an authorisation the
        // caller gives one run; a daemon serving a whole library has nobody to
        // take it from.
        expose: &[],
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
        // Reach the live NAT the same way `set_net_intercept` already does:
        // every NIC is behind its own mutex, so an amendment from the control
        // thread is synchronous and costs the packet path nothing. See the
        // trait note on `NetIo::amend_net_egress` for why one caller must reach
        // every NIC -- two renderings of one security posture drift.
        let nics: Vec<Arc<dyn NetIo>> = s.nics.to_vec();
        g.egress = (!nics.is_empty()).then(|| {
            Arc::new(move |a: &Amendment| {
                nics.iter()
                    .filter_map(|n| n.amend_net_egress(a).map(|o| (n.name().to_string(), o)))
                    .collect::<Vec<_>>()
            }) as EgressAmender
        });
    }

    let start = Instant::now();
    let mut last_output = Instant::now();
    let max = (opts.max_seconds > 0).then(|| Duration::from_secs(opts.max_seconds));
    let idle = (opts.idle_exit_secs > 0).then(|| Duration::from_secs(opts.idle_exit_secs));
    let mut console_filter = ConsoleFilter::new();
    let mut residency = IdleResidency::new(s.parked);
    // Say why an idle exit was withheld, once per silent window. A user who
    // asked for `--idle-exit` and watched it not fire is otherwise left with the
    // same silence the flag was about.
    let mut withheld = false;

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
                // The guest spoke, so the silent window -- and the residency
                // measured across it -- starts again from here.
                residency.restart();
                withheld = false;
            }
        }

        if let Some(max) = max
            && start.elapsed() >= max
        {
            return Ok(Outcome::MaxSeconds);
        }
        if let Some(idle) = idle {
            let silent_for = last_output.elapsed();
            residency.trace(silent_for);
            if silent_for >= idle {
                match residency.idle_over(silent_for) {
                    // Silent and genuinely parked: the guest is waiting, not working.
                    Some(true) | None => return Ok(Outcome::Idle(opts.idle_exit_secs)),
                    // Silent but running guest code -- a compile, an agent
                    // thinking, a package resolve. Console silence was the only
                    // thing that ever made this look idle.
                    Some(false) => {
                        if !withheld {
                            withheld = true;
                            eprintln!(
                                "[idle] guest silent for {}s but its vCPUs were parked only {}% of \
                                 it (idle needs {}%), so it is working, not idle -- not stopping",
                                silent_for.as_secs(),
                                residency.percent_over(silent_for),
                                IDLE_RESIDENCY_PERCENT,
                            );
                        }
                    }
                }
            }
        }
    }
    // `running` cleared without the supervisor asking: a vCPU thread powered off
    // or failed, and the engine reports that outcome in preference to this one.
    Ok(Outcome::PoweredOff)
}

/// Push guest serial output into the shared console ring, evicting from the
/// front (and bumping the dropped counter) when it exceeds the cap.
pub(crate) fn append_console(inner: &Arc<Mutex<VmInner>>, bytes: &[u8]) {
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

pub(crate) const CTL_USAGE: &str = "\
usage: chm ctl [--socket PATH] <COMMAND> [ARGS...]

Talk to a running `chm serve` daemon.

THE LIBRARY AND ITS GUESTS
  list [--json]                     snapshots this daemon can start
  status [--json]                   what it is running now
  start <NAME>                      start a snapshot from the library
  stop                              stop the guest, saving a checkpoint
  shutdown                          stop the guest and exit the daemon

THE RUNNING GUEST
  console                           stream the serial console (Ctrl-C detaches)
  input [TEXT]                      type into the guest console
  egress allow|deny <HOST[:PORT]>   change its egress policy without a restart

WHAT THE DAEMON'S OWN ENVIRONMENT REPORTS (JSON)
  posture [DIR] [--probe-guest]     which security controls are on
  proxy [DIR]                       credential-injection rules
  proxy check --host H [--port P] [--path X]
  proxy ca [DIR]                    the CA a guest has to trust
  audit [DIR] [--tail N]            the append-only session trail
  capabilities [DIR]                what the daemon's own binary can do

  These five read the *daemon's* environment. `chm posture`, `chm proxy show`
  and `chm audit show` read yours, which is a different answer whenever the
  daemon runs somewhere else -- and only the daemon's describes the guest.

OPTIONS
  --socket PATH   the daemon's socket (default: <tmpdir>/gimbal-local/chm.sock)

A cold-booted guest (`chm create --socket`) serves the same socket but has no
library, so the four library verbs are refused by name rather than answered
misleadingly.";

/// True when the first argument is a request for help.
///
/// First position only, deliberately. `chm ctl input <text>` sends its argument
/// to the guest verbatim, so scanning the whole argument list would make
/// `--help` unsendable -- and a flag that silently changes meaning depending on
/// which verb precedes it is worse than one that only works where it reads
/// naturally.
pub(crate) fn wants_help(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("--help" | "-h" | "help")
    )
}

/// True when the daemon's reply is raw guest output rather than a protocol reply.
///
/// `console` hands the connection over to the guest's serial output, so its
/// bytes are never classified: a guest is entirely free to print a line
/// beginning `error<TAB>`, and that is the guest's text, not our protocol. Every
/// other verb answers with one bounded protocol reply, so every other verb can
/// be judged. Decided from the wire command we sent rather than from the shape
/// of what came back -- only the sender knows which of the two this is.
fn reply_is_guest_bytes(command: &str) -> bool {
    command == "console"
}

/// Pass the daemon's reply on to `out`, or report it as the failure it is.
///
/// A reply that opens with [`REPLY_ERROR_PREFIX`] is the daemon refusing, and
/// the only honest way to hand that to a caller is out of the `Err` channel: it
/// then reaches stderr and a non-zero exit, so `chm ctl start missing` can no
/// longer be mistaken for a start that worked -- by a person, a shell script, or
/// the app, which throws on a non-zero status and so believed every refusal.
///
/// Generic over the reader and writer so the classification is testable without
/// a daemon, a socket or a guest.
fn relay_reply<R: Read, W: Write>(
    reader: &mut R,
    out: &mut W,
    classify: bool,
) -> Result<(), String> {
    let needle = REPLY_ERROR_PREFIX.as_bytes();
    // `None` until enough bytes have arrived to tell. A reply we were told not
    // to classify starts decided, so guest bytes are never inspected at all.
    let mut verdict: Option<bool> = (!classify).then_some(false);
    let mut pending: Vec<u8> = Vec::new();
    let mut failure: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read daemon: {e}")),
        };
        pending.extend_from_slice(&buf[..n]);
        if verdict.is_none() {
            if pending.len() < needle.len() {
                continue;
            }
            verdict = Some(pending.starts_with(needle));
        }
        if verdict == Some(true) {
            failure.append(&mut pending);
            continue;
        }
        match out.write_all(&pending).and_then(|()| out.flush()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(format!("write stdout: {e}")),
        }
        pending.clear();
    }

    // A reply too short to carry the prefix cannot be one, so it is output.
    if verdict.is_none() && !pending.is_empty() {
        out.write_all(&pending)
            .and_then(|()| out.flush())
            .map_err(|e| format!("write stdout: {e}"))?;
    }

    if verdict == Some(true) {
        let text = String::from_utf8_lossy(&failure);
        let text = text.strip_prefix(REPLY_ERROR_PREFIX).unwrap_or(&text);
        return Err(text.trim_end().to_string());
    }
    Ok(())
}

fn ctl(raw: &[String]) -> Result<(), String> {
    let (socket, rest) = take_socket(raw)?;
    // Answered before the connect, because the person who needs this most is
    // the one with no daemon running: replying "cannot connect to daemon" to
    // `chm ctl --help` is true, unrelated to the question, and leaves them with
    // nowhere to go. `chm --help` promises every command takes its own.
    if wants_help(&rest) {
        println!("{CTL_USAGE}");
        return Ok(());
    }
    if rest.is_empty() {
        return Err(format!("missing command\n\n{CTL_USAGE}"));
    }
    // `egress` is the one verb carrying a grammar of its own, so it is the one
    // whose `--help` a reader can plausibly ask for separately. Answered here
    // rather than in `ctl_command` for the same reason as the block above: the
    // question is about the grammar, and the daemon is not part of the answer.
    // Deliberately not generalised to `<verb> --help` for every verb -- `chm ctl
    // input --help` is a line of text bound for the guest's console, and a rule
    // that swallowed it would be a silent data loss dressed as a kindness.
    if rest[0] == "egress" && wants_help(&rest[1..]) {
        println!("{EGRESS_USAGE}");
        return Ok(());
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

    // Hand the daemon's reply on -- to stdout when it is an answer, and out of
    // the `Err` channel when it is a refusal, so a refused command exits
    // non-zero instead of looking exactly like one that worked.
    relay_reply(
        &mut stream,
        &mut io::stdout(),
        !reply_is_guest_bytes(&command),
    )
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

    // `posture [<dir>] [--probe-guest]`: the generic tail below matches only
    // bare `[cmd]`/`[cmd, <dir>]` shapes, so a flag would fall through it and
    // be reported as an unknown command. Its own block, like `audit`.
    if rest.first().map(String::as_str) == Some("posture") {
        let probe = rest.iter().any(|a| a == "--probe-guest");
        let dir = rest.iter().skip(1).find(|a| !a.starts_with('-')).cloned();
        return Ok(match (probe, dir) {
            (true, Some(d)) => format!("posture-json --probe-guest {d}"),
            (true, None) => "posture-json --probe-guest".to_string(),
            (false, Some(d)) => format!("posture-json {d}"),
            (false, None) => "posture-json".to_string(),
        });
    }

    // `audit [<dir>] [--tail N]`: the trail that matters is the one the running
    // guest is writing to, which only the daemon can name.
    if rest.first().map(String::as_str) == Some("audit") {
        let tail = rest
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
    let Some((timeout, json, argv)) = parse_exec_args(&rest)? else {
        print!("{EXEC_USAGE}");
        return Ok(0);
    };

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
    ask_json(
        socket,
        &format!("exec-json {timeout} {}", exec::encode_argv(argv)),
    )
}

/// Send one line to the daemon and parse its whole reply as JSON.
///
/// The transport half of [`exec_once`], shared because the CA install (#376)
/// has to ask the daemon which CA the *running* guest's proxy signs with before
/// it can carry anything in. Resolving that from a workspace path on this side
/// is the measured footgun recorded on `ca_json_for_daemon`: install the wrong
/// one and the guest ends up trusting a CA nothing uses, with every intercepted
/// connection failing a certificate check *after* the installer said it worked.
pub(crate) fn ask_json(socket: &Path, command: &str) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot connect to daemon at {}: {e} (is `chm serve` running?)",
            socket.display()
        )
    })?;
    stream
        .write_all(format!("{command}\n").as_bytes())
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
///
/// `Ok(None)` means the caller asked `chm exec` itself to explain. That answer
/// lives in here rather than in [`exec_main`] because the boundary it depends on
/// lives in here: `chm exec -- mytool --help` is asking *mytool* for help, and
/// any second copy of "where do our flags stop" would eventually disagree with
/// this loop. #417 -- the help page used to leave through the `Err` channel,
/// which printed it to stderr and exited 125.
fn parse_exec_args(rest: &[String]) -> Result<Option<(u64, bool, Vec<String>)>, String> {
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
            "-h" | "--help" => return Ok(None),
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
    Ok(Some((timeout, json, argv)))
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
            role: Role::Library,
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
            role: Role::Library,
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
            role: Role::Library,
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
            role: Role::Library,
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
        let (timeout, json, argv) = parse_exec_args(&s(&["uname", "-a"]))
            .unwrap()
            .expect("a command, not a help request");
        assert_eq!(timeout, EXEC_DEFAULT_TIMEOUT);
        assert!(!json);
        assert_eq!(argv, s(&["uname", "-a"]));
    }

    /// The guest's own flags must never be eaten by ours. `--` is the boundary,
    /// and everything past it is data.
    #[test]
    fn exec_does_not_claim_the_guest_commands_flags() {
        let (_, json, argv) = parse_exec_args(&s(&["--", "ls", "--json", "--timeout", "5"]))
            .unwrap()
            .expect("a command, not a help request");
        assert!(!json, "`--json` after `--` belongs to the guest command");
        assert_eq!(argv, s(&["ls", "--json", "--timeout", "5"]));
    }

    #[test]
    fn exec_reads_its_own_flags_before_the_separator() {
        let (timeout, json, argv) =
            parse_exec_args(&s(&["--timeout", "5", "--json", "--", "true"]))
                .unwrap()
                .expect("a command, not a help request");
        assert_eq!(timeout, 5);
        assert!(json);
        assert_eq!(argv, s(&["true"]));
    }

    /// `chm exec -- mytool --help` is asking *mytool* to explain itself, not
    /// `chm`. #417 moved seven subcommands to a scan-every-argument rule for
    /// help; applying that rule here too would have silently eaten a flag meant
    /// for the guest. So `exec` keeps the question inside this parser, which is
    /// the only code that knows where our flags stop -- the same care `chm ctl
    /// input <text>` needed in #416, for the same reason.
    #[test]
    fn exec_does_not_answer_a_help_flag_meant_for_the_guest() {
        let (_, _, argv) = parse_exec_args(&s(&["--", "mytool", "--help"]))
            .expect("a guest command line is not an error")
            .expect("`--help` after `--` belongs to the guest, not to chm");
        assert_eq!(argv, s(&["mytool", "--help"]));

        // The same word before any separator is ours, and it is a question
        // rather than a failure -- `Ok(None)`, not `Err`.
        assert!(
            parse_exec_args(&s(&["--help"]))
                .expect("asking for help is not an error")
                .is_none(),
            "`chm exec --help` must be read as a request for chm's own help"
        );
        assert!(parse_exec_args(&s(&["-h"])).expect("nor is `-h`").is_none());
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
            role: Role::Library,
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
            role: Role::Library,
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

#[cfg(test)]
mod cold_control_tests {
    use super::{Role, cold_boot_refusal};

    /// The refusals are the whole of #401's contract with a user who points a
    /// library verb at a cold guest. A bare `error` would be true and useless;
    /// #304/#305/#306 are three separate records of a true sentence that leaves
    /// the reader with no next step. So assert the prose, not just the refusal.
    #[test]
    fn a_library_verb_says_where_it_does_work() {
        for verb in ["list", "list-json", "start"] {
            let why = cold_boot_refusal(verb)
                .unwrap_or_else(|| panic!("{verb} needs a library and must be refused here"));
            assert!(
                why.contains(verb),
                "the refusal for {verb} must name the verb: {why}"
            );
            assert!(
                why.contains("library"),
                "the refusal for {verb} must say a library is what is missing, \
                 or it reads as `you have no snapshots`: {why}"
            );
        }
        // Assembled from parts: a literal remedy here would be found by
        // `contains` in this very assertion if the check ever moved to reading
        // the source, and a needle that matches its own test is born dead.
        let remedy = format!("chm serve {}library>", "<");
        for verb in ["list", "list-json"] {
            let why = cold_boot_refusal(verb).unwrap();
            assert!(
                why.contains(&remedy),
                "{verb} must name the socket that does answer it: {why}"
            );
        }
        let start = cold_boot_refusal("start").unwrap();
        assert!(
            start.contains("one VM per process"),
            "`start` is refused for a second reason -- HVF's single slot -- and \
             a reader who fixes only the library half would try again: {start}"
        );
    }

    /// `shutdown` is the one refusal that is not about the library, and the
    /// reason matters: it calls `exit(0)` from the connection thread, so on this
    /// path it would skip `--originate` capture and the HVF release.
    #[test]
    fn shutdown_names_the_teardown_it_would_skip() {
        let why = cold_boot_refusal("shutdown").expect("shutdown must be refused on a cold socket");
        assert!(
            why.contains("--originate"),
            "the refusal must name what would be lost, not just say no: {why}"
        );
        assert!(
            why.contains("`stop`"),
            "and it must name the verb that does the intended thing: {why}"
        );
    }

    /// The far more expensive mistake is refusing a verb that works: every
    /// served verb reads only the running guest, and a cold guest is a running
    /// guest. A refusal here would make `--socket` useless while looking
    /// deliberate.
    #[test]
    fn every_verb_about_the_running_guest_is_served() {
        for verb in [
            "ping",
            "status",
            "status-json",
            "exec-json",
            "input",
            "egress",
            "console",
            "stop",
            "proxy-json",
            "proxy-check-json",
            "proxy-ca-json",
            "posture-json",
            "audit-json",
            "capabilities-json",
        ] {
            assert!(
                cold_boot_refusal(verb).is_none(),
                "{verb} reads only the running guest, so refusing it would make \
                 --socket a socket that answers nothing"
            );
        }
    }

    /// A pure function that nobody calls refuses nothing. This repo has been
    /// caught by the call-site class seven times, so read the source rather than
    /// asserting on a value the production path may no longer compute.
    #[test]
    fn handle_conn_actually_consults_the_refusal() {
        let src = include_str!("serve.rs");
        // Assembled, or this assertion is its own needle (§43).
        let gate = format!("daemon.role == Role::{}", "ColdBoot");
        assert!(
            src.contains(&gate),
            "handle_conn must gate on the role, or a cold socket answers library \
             verbs about a library it does not have"
        );
        let consulted = format!("let Some(why) = {}(cmd)", "cold_boot_refusal");
        assert!(
            src.contains(&consulted),
            "the gate must consult cold_boot_refusal itself: a second copy of \
             the verb list would drift from this one"
        );
        assert!(
            Role::ColdBoot != Role::Library,
            "the two roles must stay distinguishable, or the gate is a no-op"
        );
    }
}

#[cfg(test)]
mod cold_finish_drain_tests {
    use super::{ColdControl, FINISH_DRAIN, RunStatus, VmInner};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn control(inflight: usize) -> (ColdControl, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let n = Arc::new(AtomicUsize::new(inflight));
        let serving = Arc::new(AtomicBool::new(true));
        let c = ColdControl {
            inner: Arc::new(Mutex::new(VmInner::new())),
            serving: Some(Arc::clone(&serving)),
            inflight: Some(Arc::clone(&n)),
            socket_path: None,
        };
        (c, n, serving)
    }

    /// The bug this guards was measured on hardware twice: `chm ctl stop`
    /// stopped the guest correctly and printed *nothing*, because `finish`
    /// published the `Stopped` status the client was polling for and tore the
    /// socket down in the same breath. The client could only lose that race.
    ///
    /// The property is ordering, so hold a connection in flight and prove
    /// `finish` waited for it rather than asserting on a message.
    #[test]
    fn finish_waits_for_an_inflight_reply_before_it_stops_serving() {
        let (c, n, serving) = control(1);
        let releaser = Arc::clone(&n);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            releaser.fetch_sub(1, Ordering::AcqRel);
        });
        let began = Instant::now();
        c.finish("stopped on request");
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(200),
            "finish returned in {waited:?} with a reply still in flight -- that \
             is the race that ate the client's confirmation"
        );
        assert!(
            !serving.load(Ordering::Acquire),
            "it must still stop serving once the reply has landed"
        );
    }

    /// The status has to be published *before* the wait, or the client is
    /// polling for something that only appears after it has been given up on --
    /// a deadlock dressed as a timeout.
    #[test]
    fn the_status_is_published_before_the_drain_begins() {
        let (c, n, _) = control(1);
        let inner = Arc::clone(&c.inner);
        let releaser = Arc::clone(&n);
        std::thread::spawn(move || {
            // Stand in for the connection thread: it only finishes once it can
            // see the status, exactly as `stop_vm_blocking` does.
            for _ in 0..200 {
                if matches!(inner.lock().unwrap().status, RunStatus::Stopped(_)) {
                    releaser.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let began = Instant::now();
        c.finish("stopped on request");
        assert!(
            began.elapsed() < FINISH_DRAIN,
            "the drain hit its ceiling, so the waiter never saw the status -- \
             publishing after the wait cannot work"
        );
        assert!(matches!(
            c.inner.lock().unwrap().status,
            RunStatus::Stopped(_)
        ));
    }

    /// A client that never reads must not be able to hold teardown open --
    /// `ctl console` streams until the socket closes and is never going to
    /// decrement.
    #[test]
    fn a_connection_that_never_finishes_cannot_hold_teardown_open() {
        let (c, _n, serving) = control(1);
        let began = Instant::now();
        c.finish("stopped on request");
        let waited = began.elapsed();
        assert!(
            waited >= FINISH_DRAIN,
            "it should have waited the full ceiling: {waited:?}"
        );
        assert!(
            waited < FINISH_DRAIN + Duration::from_secs(2),
            "but it must be a ceiling, not a wait for a decrement that is never \
             coming: {waited:?}"
        );
        assert!(!serving.load(Ordering::Acquire));
    }

    /// The counting itself, which the tests above take on trust because they
    /// set the counter by hand. Deleting the `fetch_add` used to leave all 1020
    /// tests green (the call-site class); it is a value now so it can fail.
    #[test]
    fn a_served_connection_is_counted_for_exactly_as_long_as_it_is_served() {
        use super::Served;
        let n = Arc::new(AtomicUsize::new(0));
        {
            let _a = Served::begin(&n);
            assert_eq!(
                n.load(Ordering::Acquire),
                1,
                "an accepted connection must be counted before it is handed to a \
                 thread, or teardown can observe zero for a reply already owed"
            );
            let _b = Served::begin(&n);
            assert_eq!(n.load(Ordering::Acquire), 2, "and they must accumulate");
        }
        assert_eq!(
            n.load(Ordering::Acquire),
            0,
            "and be given back on the way out, or the first client to disconnect \
             makes every later teardown pay the full ceiling"
        );
    }

    /// Handlers panic. If that leaked a count, one bad connection would tax
    /// every teardown for the rest of the process's life.
    #[test]
    fn a_panicking_handler_still_gives_its_count_back() {
        use super::Served;
        let n = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&n);
        let _ = std::thread::spawn(move || {
            let _served = Served::begin(&counter);
            panic!("handler exploded");
        })
        .join();
        assert_eq!(n.load(Ordering::Acquire), 0);
    }

    /// A `Served` nobody constructs counts nothing. The accept loop is not
    /// reachable from a unit test -- it needs a bound socket -- so read it.
    #[test]
    fn the_accept_loop_actually_counts_the_connections_it_accepts() {
        let src = include_str!("serve.rs");
        // Assembled from parts, or this assertion is its own needle.
        let needle = format!("let served = {}::begin(&loop_inflight);", "Served");
        assert!(
            src.contains(&needle),
            "the accept loop must count through Served::begin; anything else \
             leaves finish() draining a counter that never rises"
        );
    }

    /// And the common case pays nothing: no client attached, no delay.
    #[test]
    fn an_idle_socket_tears_down_immediately() {
        let (c, _n, _) = control(0);
        let began = Instant::now();
        c.finish("guest ended");
        assert!(
            began.elapsed() < Duration::from_millis(200),
            "a guest that ended on its own must not pay the drain"
        );
    }
}

/// Guards for the in-guest user-namespace probe (#363).
#[cfg(test)]
mod guest_userns_probe_tests {
    use super::*;

    /// All four cells, without a guest or a console.
    ///
    /// The two that matter most are the `false` rows: they are the promise that
    /// reading a posture writes nothing to anyone's console.
    #[test]
    fn the_probe_only_runs_when_it_was_asked_for_and_there_is_something_to_ask() {
        assert!(
            guest_userns_plan(true, true).is_ok(),
            "--probe-guest with a running guest must actually probe"
        );
        for (requested, running) in [(false, true), (false, false), (true, false)] {
            let plan = guest_userns_plan(requested, running);
            assert!(
                plan.is_err(),
                "probed with requested={requested} running={running}; a posture \
                 read wrote to a guest console it was not told it could touch"
            );
        }
    }

    /// Not asking is not the same as asking and getting nothing back, and the
    /// report has to be able to tell a reader which happened.
    #[test]
    fn every_non_probing_cell_says_why_without_claiming_a_failure() {
        for (requested, running) in [(false, true), (false, false), (true, false)] {
            match guest_userns_plan(requested, running) {
                Err(posture::GuestUserns::NotAsked(why)) => {
                    assert!(
                        why.len() > 20,
                        "requested={requested} running={running} gave no reason"
                    );
                }
                other => panic!(
                    "requested={requested} running={running} reported {other:?}; an \
                     unasked question must not read as a failed one"
                ),
            }
        }
    }

    /// A guest that is up but silent must not be reported as either answer.
    #[test]
    fn the_deadline_is_short_enough_that_a_posture_read_returns() {
        assert!(
            USERNS_PROBE_SECS <= 30,
            "a posture read that can block for {USERNS_PROBE_SECS}s is one \
             nobody will wait for"
        );
        assert!(USERNS_PROBE_SECS >= 1);
    }

    /// The call-site class, eight times over in this repo now: a guard that
    /// asserts an outcome structurally cannot see a path that is no longer
    /// taken. `guest_userns_plan` could keep returning `Ok` forever while
    /// `posture_json` stopped consulting it.
    ///
    /// Needles assembled from parts so this test cannot match its own text.
    #[test]
    fn posture_json_consults_the_plan_and_runs_the_probe() {
        let src = include_str!("serve.rs");
        let body = src
            .split_once("fn posture_json(")
            .expect("posture_json is gone")
            .1
            .split_once("\nfn ")
            .expect("posture_json has no end")
            .0;
        for needle in [
            // Both halves of the parsed request must be the ones used. Binding
            // the flag to `_` and hardcoding `false` compiles, passes every
            // outcome assertion, and silently never probes.
            format!("let (probe_requested, arg) = {}(arg);", "posture_request"),
            format!("{}(probe_requested", "guest_userns_plan"),
            format!("{}(daemon, secs)", "probe_guest_userns"),
            format!("&{}", "userns"),
        ] {
            assert!(
                body.contains(&needle),
                "posture_json no longer contains `{needle}`, so the probe it \
                 reports on may never run"
            );
        }
    }

    /// The flag has to survive `ctl_command`, which is where a new flag on an
    /// existing verb silently falls off: the generic tail matches only bare
    /// `[cmd]` and `[cmd, <dir>]`.
    #[test]
    fn ctl_carries_probe_guest_through_to_the_daemon() {
        let wire = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            ctl_command(&owned).expect("ctl_command refused a posture form")
        };
        let flag = format!("--{}", "probe-guest");
        assert_eq!(wire(&["posture"]), "posture-json");
        assert_eq!(wire(&["posture", "/w"]), "posture-json /w");
        assert_eq!(wire(&["posture", &flag]), format!("posture-json {flag}"));
        assert_eq!(
            wire(&["posture", &flag, "/w"]),
            format!("posture-json {flag} /w")
        );
        assert_eq!(
            wire(&["posture", "/w", &flag]),
            format!("posture-json {flag} /w"),
            "flag order changed the request"
        );
    }

    /// And the daemon side has to read it back off the wire. Both halves,
    /// because a flag that arrives and is ignored is the worse failure: it
    /// reports "not asked" while the user believes they asked.
    #[test]
    fn the_daemon_reads_the_flag_and_the_directory_out_of_one_argument() {
        let flag = format!("--{}", "probe-guest");
        assert_eq!(
            posture_request(&format!("{flag} /some/dir")),
            (true, "/some/dir"),
            "the flag arrived and was ignored, or the directory was lost"
        );
        // Order must not matter: the CLI emits flag-first, a human may not.
        assert_eq!(
            posture_request(&format!("/some/dir {flag}")),
            (true, "/some/dir")
        );
        assert_eq!(posture_request("/some/dir"), (false, "/some/dir"));
        assert_eq!(posture_request(""), (false, ""));
        // A near-miss must not be read as consent to write to the console.
        assert!(!posture_request("--probe-guests").0);
    }

    /// Every way of mistyping the verb must name the form, not the category.
    ///
    /// This is the whole reachable surface of `chm ctl egress` for a user who
    /// gets it wrong, and #156 exists because the alternative to amending a
    /// policy is destroying the session -- so a refusal that leaves someone
    /// guessing costs the session anyway.
    #[test]
    fn every_way_of_mistyping_an_amendment_is_told_the_form() {
        for bad in ["", "allow", "deny", "permit foo.com", "allow foo.com extra"] {
            let err = parse_amendment(bad).expect_err("accepted `{bad}`");
            assert!(
                err.contains(EGRESS_USAGE),
                "refusing `{bad}` did not quote the usage: {err}"
            );
        }
    }

    #[test]
    fn a_well_formed_amendment_carries_the_verb_and_the_entry() {
        assert!(matches!(
            parse_amendment("allow api.github.com:443"),
            Ok(Amendment::Allow(ref e)) if e == "api.github.com:443"
        ));
        assert!(matches!(
            parse_amendment("deny  evil.test"),
            Ok(Amendment::Deny(ref e)) if e == "evil.test"
        ));
    }

    /// Retaining established flows is the deliberate choice #156 made -- cutting
    /// them destroys the work the session exists to protect -- so it has to be
    /// *reported*, or a user reasonably reads "deny" as "that connection is
    /// gone now".
    #[test]
    fn a_denial_says_that_established_flows_were_kept() {
        let out = AmendOutcome {
            label: "base+live1".into(),
            rule: "evil.test".into(),
            allowed: false,
            superseded: Vec::new(),
            established_retained: 3,
        };
        let line = describe_amendments(&[("net0".to_string(), out)]);
        assert!(line.contains("net0"), "{line}");
        assert!(line.contains("deny evil.test"), "{line}");
        assert!(line.contains("base+live1"), "{line}");
        assert!(
            line.contains("3 established flow(s) continue"),
            "the retained flows were not reported: {line}"
        );
    }

    /// A superseded rule must be named, because the alternative is silence
    /// about a rule the operator wrote and we then removed.
    #[test]
    fn a_superseded_rule_is_named_in_the_reply() {
        let out = AmendOutcome {
            label: "base+live1".into(),
            rule: "foo.com".into(),
            allowed: true,
            superseded: vec!["deny foo.com".into()],
            established_retained: 0,
        };
        let line = describe_amendments(&[("net0".to_string(), out)]);
        assert!(
            line.contains("superseded") && line.contains("deny foo.com"),
            "the displaced rule was not named: {line}"
        );
    }

    /// A posture report for a guest nobody has amended must be byte-identical
    /// to the one this build produced before #156.
    ///
    /// `posture_json` promises in its own doc comment that one decoder handles
    /// both it and `chm posture --json`; a key that appears unconditionally
    /// would make every existing reader parse a shape it has never seen, to say
    /// nothing new.
    #[test]
    fn an_unamended_guest_adds_nothing_to_the_posture_report() {
        assert_eq!(render_live_egress(&[]), "");
    }

    /// The live label has to reach the report, or `posture` keeps describing
    /// the policy the sandbox *started* from -- true about its own source and
    /// wrong about the world, which is the #202/#203 failure shape.
    #[test]
    fn an_amended_guest_reports_the_label_that_is_actually_enforcing() {
        let out = render_live_egress(&[("net0".into(), "sha256:cafe+live2".into())]);
        assert!(out.contains("\"egress_live\""), "{out}");
        assert!(out.contains("net0") && out.contains("sha256:cafe+live2"), "{out}");
        let body = format!("{{{out}\n  \"controls\": []\n}}");
        serde_json::from_str::<serde_json::Value>(&body)
            .unwrap_or_else(|e| panic!("the spliced report is not parseable: {e}\n{body}"));
    }

    /// `amend_egress` must go through `parse_amendment`, not re-parse inline.
    ///
    /// Every guard above asserts an *outcome*, and an outcome assertion is
    /// structurally blind to a path that is no longer taken -- this repo has
    /// been bitten by that call-site class seven times. The refusals are only
    /// reachable by a user if the verb handler actually consults them.
    #[test]
    fn the_egress_verb_refuses_through_the_parser_it_is_tested_against() {
        let src = include_str!("serve.rs");
        // Assembled, or this assertion is its own needle (§43).
        let call = format!("let amendment = {}(arg)?;", "parse_amendment");
        assert!(
            src.contains(&call),
            "amend_egress must call parse_amendment: an inline re-parse would \
             leave every refusal test asserting about a path nobody reaches"
        );
    }

    /// The same class again, for the other pure function.
    ///
    /// Every test above calls [`render_live_egress`] directly, so a
    /// `posture_json` that stops splicing its result leaves all of them green
    /// -- measured: dropping the call passes the whole suite. And the failure
    /// it hides is the exact one #156 exists to remove: a report that describes
    /// the policy the sandbox *started* from while the guest enforces another.
    #[test]
    fn the_posture_report_actually_splices_the_live_policy() {
        let src = include_str!("serve.rs");
        // Assembled, or this assertion is its own needle (§43).
        let call = format!("            {}(daemon)\n", "live_egress_json");
        assert!(
            src.contains(&call),
            "posture_json must splice live_egress_json into the body it returns, \
             or an amended guest reports the policy it no longer enforces"
        );
    }

    /// A device name is not ours, so it cannot be pasted into JSON unescaped.
    #[test]
    fn a_hostile_device_name_cannot_break_out_of_the_report() {
        let out = render_live_egress(&[("ne\"t0".into(), "lab\\el".into())]);
        let body = format!("{{{out}\n  \"controls\": []\n}}");
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("unescaped name broke the report: {e}\n{body}"));
        assert_eq!(v["egress_live"][0]["device"], "ne\"t0");
        assert_eq!(v["egress_live"][0]["policy"], "lab\\el");
    }
}

#[cfg(test)]
mod ctl_help_tests {
    use super::*;

    /// Every verb the daemon dispatches has to be named in `chm ctl --help`.
    ///
    /// `ctl_command`'s tail arm passes an unrecognised verb straight through, so
    /// the dispatch table -- not the parser -- is the real `ctl` surface, and
    /// the usage text is a hand-written list sitting a thousand lines away from
    /// it. #156 added `egress` to the dispatch and left it out of the list, and
    /// nothing failed: this is the drift V9.4's guard catches one level up, at
    /// `chm --help`, with no equivalent down here.
    ///
    /// Both sides are read as *entries*, never as substrings. A verb also
    /// appears in its own neighbours' descriptions ("stop the guest"), so a
    /// `contains` would keep passing after the entry it guards was deleted --
    /// the shape that defeated #296's first doc guard.
    #[test]
    fn every_dispatched_ctl_verb_is_named_in_the_usage() {
        let src = include_str!("serve.rs");
        // Needles assembled from parts so they cannot match this test's own text.
        let q = '"';
        let start = src
            .find(&format!("        {q}ping{q} => {{"))
            .expect("the dispatch table opens at the ping arm");
        let end = start
            + src[start..]
                .find(&format!("        {} => {{", "other"))
                .expect("the dispatch table closes at its catch-all arm");

        let mut dispatched = Vec::new();
        for line in src[start..end].lines() {
            let t = line.trim_start();
            if line.len() - t.len() != 8 {
                continue;
            }
            let Some(rest) = t.strip_prefix(q) else {
                continue;
            };
            let Some((verb, tail)) = rest.split_once(q) else {
                continue;
            };
            if tail.starts_with(" =>") {
                dispatched.push(verb);
            }
        }
        assert!(
            dispatched.len() >= 15,
            "only {} dispatch arms found -- the anchors have moved: {dispatched:?}",
            dispatched.len()
        );

        // An entry is a two-space-indented lower-case token with a description
        // column after it. Prose wrapped to the same indent has no such column.
        let documented: Vec<&str> = CTL_USAGE
            .lines()
            .filter_map(|l| {
                let body = l.strip_prefix("  ")?;
                if !body.starts_with(|c: char| c.is_ascii_lowercase()) {
                    return None;
                }
                let (head, tail) = body.split_once(' ')?;
                tail.contains("  ").then_some(head)
            })
            .collect();
        assert!(
            documented.contains(&"list"),
            "the usage parser found no entries at all: {documented:?}"
        );

        for verb in dispatched {
            // `ping` is a liveness probe the client sends on its own behalf. The
            // `-json` arms are the wire protocol, reached by the human name
            // `ctl_command` maps onto them -- except `exec-json`, which belongs
            // to top-level `chm exec` and is not a `ctl` verb at all.
            if verb == "ping" || verb.ends_with("-json") {
                continue;
            }
            assert!(
                documented.contains(&verb),
                "`chm ctl {verb}` is dispatched but absent from CTL_USAGE, so the \
                 only list a user can see does not mention it"
            );
        }
    }

    /// `chm ctl --help` must not need a daemon.
    ///
    /// It used to take the socket, hand `--help` to `ctl_command` (whose tail
    /// arm turns anything into a wire command), and die at `UnixStream::connect`
    /// -- so the person least likely to have a daemon running, the one reading
    /// the help, got a connection error instead of an answer.
    #[test]
    fn ctl_answers_help_without_connecting() {
        for form in ["--help", "-h", "help"] {
            let args = vec![
                "--socket".to_string(),
                "/nonexistent/gimbal-ctl-help-guard/chm.sock".to_string(),
                form.to_string(),
            ];
            assert!(
                ctl(&args).is_ok(),
                "`chm ctl {form}` reached the socket instead of answering"
            );
        }
        assert!(!wants_help(&["status".to_string()]));
        // `chm ctl input --help` is a payload, not a question.
        assert!(!wants_help(&["input".to_string(), "--help".to_string()]));

        // The one verb with a grammar of its own answers for that grammar,
        // still without a daemon. A socket that cannot exist is what proves it.
        for form in ["--help", "-h", "help"] {
            let args = vec![
                "--socket".to_string(),
                "/nonexistent/gimbal-ctl-help-guard/chm.sock".to_string(),
                "egress".to_string(),
                form.to_string(),
            ];
            assert!(
                ctl(&args).is_ok(),
                "`chm ctl egress {form}` reached the socket instead of answering"
            );
        }
        // And an actual amendment still travels: it must reach the connect and
        // fail there, not be swallowed as a question.
        let real = vec![
            "--socket".to_string(),
            "/nonexistent/gimbal-ctl-help-guard/chm.sock".to_string(),
            "egress".to_string(),
            "allow".to_string(),
            "example.com:80".to_string(),
        ];
        assert!(
            ctl(&real).is_err(),
            "a real egress amendment was answered as help instead of being sent"
        );
    }

    /// `chm serve` answers `--help` before its argument parser rejects it.
    ///
    /// A call-site guard rather than an outcome one: `serve_main` returns an
    /// `ExitCode`, which cannot be compared, and the bug was purely one of
    /// order -- `parse_serve` refuses every unknown option, `--help` included.
    #[test]
    fn serve_answers_help_before_it_parses() {
        let src = include_str!("serve.rs");
        let body = &src[src
            .find(&format!(
                "pub fn {}(raw: &[String]) -> ExitCode {{",
                "serve_main"
            ))
            .expect("serve_main must be findable")..];
        let asks = body
            .find(&format!("if {}(raw) {{", "wants_help"))
            .expect("serve_main must consult wants_help");
        let acts = body
            .find(&format!("match {}(raw) {{", "serve"))
            .expect("serve_main must call serve");
        assert!(
            asks < acts,
            "serve_main parses its arguments before answering --help"
        );
    }
}

#[cfg(test)]
mod ctl_reply_tests {
    use super::*;

    /// The daemon's own source, so a guard here reads what ships rather than
    /// what a test rebuilt.
    const SRC: &str = include_str!("serve.rs");

    /// The prefix as it appears in Rust source, assembled from parts.
    ///
    /// Written out whole it would appear in this assertion too, and a needle
    /// that matches its own test can never detect the thing it guards going
    /// missing -- banked twice in this repo already.
    fn source_literal() -> String {
        format!("{}{}t", "error", '\\')
    }

    fn relay(reply: &[u8], classify: bool) -> (Result<(), String>, String) {
        let mut out: Vec<u8> = Vec::new();
        let r = relay_reply(&mut &reply[..], &mut out, classify);
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_refusal_leaves_stdout_untouched_and_comes_back_as_an_error() {
        let reply = format!("{REPLY_ERROR_PREFIX}no VM running\n");
        let (r, out) = relay(reply.as_bytes(), true);
        assert_eq!(
            r,
            Err("no VM running".to_string()),
            "the prefix is stripped and the trailing newline trimmed, so \
             ctl_main prints `chm ctl: no VM running`"
        );
        assert!(
            out.is_empty(),
            "a refusal must not be written to stdout, or `chm ctl list --json \
             | jq` is fed the refusal text: got {out:?}"
        );
    }

    #[test]
    fn an_answer_reaches_stdout_verbatim_and_succeeds() {
        let (r, out) = relay(b"idle\tlibrary /x\n", true);
        assert_eq!(r, Ok(()));
        assert_eq!(out, "idle\tlibrary /x\n");
    }

    #[test]
    fn a_reply_shorter_than_the_prefix_is_an_answer_not_a_refusal() {
        // `ping` answers `pong\n` -- five bytes against a six-byte prefix, so
        // the decision is never reached and EOF has to settle it as output.
        assert!(
            "pong\n".len() < REPLY_ERROR_PREFIX.len(),
            "this test only means anything while pong is the shorter of the two"
        );
        let (r, out) = relay(b"pong\n", true);
        assert_eq!(r, Ok(()));
        assert_eq!(out, "pong\n", "a short reply must still reach the caller");
    }

    #[test]
    fn a_refusal_split_across_reads_is_still_recognised() {
        struct Dribble(Vec<Vec<u8>>);
        impl Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let chunk = self.0.remove(0);
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
        }
        let mut src = Dribble(vec![b"err".to_vec(), b"or\tno VM running\n".to_vec()]);
        let mut out: Vec<u8> = Vec::new();
        let r = relay_reply(&mut src, &mut out, true);
        assert_eq!(
            r,
            Err("no VM running".to_string()),
            "the prefix arrives over two reads and must not be judged early"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn guest_bytes_are_never_classified() {
        assert!(
            reply_is_guest_bytes("console"),
            "console hands the connection to raw guest output"
        );
        for verb in ["status", "list", "start", "stop", "input", "egress", "ping"] {
            assert!(
                !reply_is_guest_bytes(verb),
                "{verb} answers with one bounded protocol reply and can be judged"
            );
        }

        // A guest is free to print this. It is the guest's text, not our wire.
        let guest = format!("{REPLY_ERROR_PREFIX}fsck: unable to resolve 'LABEL=x'\n");
        let (r, out) = relay(guest.as_bytes(), false);
        assert_eq!(r, Ok(()), "guest output is never a chm failure");
        assert_eq!(out, guest, "and it reaches the terminal unaltered");
    }

    /// Every daemon reply that refuses has to be written with the shared
    /// constant.
    ///
    /// This is the drift the whole fix rests on. If one site went back to its
    /// own literal and the constant later changed, the daemon would carry on
    /// refusing and `chm ctl` would quietly stop hearing it -- rc back to 0,
    /// nothing failing anywhere in between. An outcome assertion cannot see
    /// that: it would still pass against whichever sites did use the constant.
    #[test]
    fn no_daemon_reply_writes_the_prefix_as_its_own_literal() {
        let bare = source_literal();
        let hits: Vec<&str> = SRC
            .lines()
            .filter(|l| l.contains(&bare))
            .map(str::trim)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "exactly one line in serve.rs may spell the prefix out -- the \
             constant's own declaration. Found: {hits:?}"
        );
        assert!(
            hits[0].contains("REPLY_ERROR_PREFIX"),
            "the one spelling must be the constant, not a reply: {:?}",
            hits[0]
        );
    }

    /// `ctl` has to ask which kind of reply it is expecting.
    ///
    /// Every guard above asserts an *outcome*, and an outcome assertion is
    /// structurally blind to a call site that stopped taking the path -- this
    /// repo has been bitten by exactly that seven times. Hardcoding `false`
    /// here would restore the original bug with every test above still green.
    #[test]
    fn ctl_decides_by_the_verb_it_sent() {
        let needle = format!("!{}(&command)", "reply_is_guest_bytes");
        assert!(
            SRC.contains(&needle),
            "ctl must pass the classification decision to relay_reply, keyed \
             on the wire command it sent"
        );
    }
}
