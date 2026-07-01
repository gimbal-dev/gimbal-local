// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Full-loop regression test for the macOS sandbox: bring a real
//! HVF-compatible snapshot up under `chm`, log in over a pseudo-terminal, write
//! a file inside the guest, `ls` it back, and confirm the file is there — while
//! asserting that **no** ext4 / `Input/output error` shows up on the console.
//!
//! This is the automated guard for the copy-on-write disk fix: if a change ever
//! regresses the shipped-disk rehydration path (the guest falling back to a
//! zero overlay, the base image drifting, etc.) this loop fails because the
//! guest can no longer read/write its real filesystem.
//!
//! It is opt-in because it needs a local, multi-GB, HVF-compatible snapshot and
//! Apple Silicon. Point `CHM_E2E_SNAPSHOT` at a snapshot directory (one holding
//! `state.json` + `snapshot/` + `disks/`) and run it via
//! `scripts/hvf/e2e-microvm-loop.sh`, which builds + signs `chm` first.
//!
//! When `CHM_E2E_SNAPSHOT` is unset the test skips (passes) so `cargo test`
//! stays green on machines without a snapshot. It is also `#[ignore]`d so a
//! plain `cargo test` never spins up a VM; it only runs when explicitly asked.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::env;
use std::fs;
use std::io;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::ptr;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

unsafe extern "C" {
    fn openpty(
        amaster: *mut libc::c_int,
        aslave: *mut libc::c_int,
        name: *mut libc::c_char,
        termp: *const libc::termios,
        winp: *const Winsize,
    ) -> libc::c_int;
}

/// The hypervisor entitlement `chm` must carry to create a VM. Mirrors
/// `hypervisor/tests/data/hv.entitlements`; written to a temp file so the test
/// is self-contained.
const HV_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
"#;

/// Overall wall-clock budget for the whole loop (boot + login + commands).
const OVERALL_BUDGET: Duration = Duration::from_secs(150);

/// Console substrings that mean the guest's disk is broken (the exact failure
/// mode a regressed shipped-disk / zero-overlay path produces). Used both to
/// fail fast during boot and as a final assertion.
const DISK_ERRORS: [&str; 4] = [
    "EXT4-fs error",
    "Input/output error",
    "failed checksum",
    "deleted inode referenced",
];

/// Outcome of [`PtySession::wait_for_or_abort`].
enum WaitOutcome {
    /// One of the wanted needles appeared.
    Found(String),
    /// An abort needle (e.g. a disk error) appeared first.
    Aborted(String),
    /// Neither appeared before the deadline.
    TimedOut,
}

#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/hvf/e2e-microvm-loop.sh"]
fn microvm_boots_logs_in_writes_and_lists_a_file() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!(
            "skipping: set CHM_E2E_SNAPSHOT to a snapshot dir (state.json + snapshot/ + disks/) \
             to run the full microVM loop"
        );
        return;
    };
    assert!(
        snapshot.join("state.json").is_file(),
        "CHM_E2E_SNAPSHOT={} has no state.json",
        snapshot.display()
    );

    // Start each run from clean copy-on-write overlays so the guest disk matches
    // the snapshot instant (the overlay also truncates on open, but clearing
    // keeps stale files from accumulating).
    let overlays = snapshot.join(".chm-overlays");
    if overlays.is_dir() {
        for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }

    let chm = signed_chm_binary();
    let mut session = PtySession::spawn(
        &chm,
        &[
            "connect",
            snapshot.to_str().unwrap(),
            "--no-stop-daemon",
            "--idle-exit",
            "0",
            "--max-seconds",
            "180",
        ],
    );

    let deadline = Instant::now() + OVERALL_BUDGET;

    // --- 1) reach a shell, logging in if a getty prompt is shown ------------- //
    // Fail fast if a disk error shows up while booting — that is the regression
    // this whole test guards against, and it would otherwise just stall to the
    // overall deadline.
    let shell = "@ch-snap:~$";
    match session.wait_for_or_abort(&[shell, "login:"], &DISK_ERRORS, deadline) {
        WaitOutcome::Found(m) if m == "login:" => {
            session.send("ubuntu\n");
            match session.wait_for(&["Password:", shell], deadline) {
                Some(p) if p == "Password:" => {
                    session.send("ubuntu\n");
                    if session.wait_for(&[shell], deadline).is_none() {
                        session.fail("did not reach a shell prompt after entering the password");
                    }
                }
                Some(_) => {}
                None => session.fail("no password prompt or shell after the login name"),
            }
        }
        WaitOutcome::Found(_) => {} // already at a shell (autologin)
        WaitOutcome::Aborted(e) => session.fail(&format!(
            "guest reported a disk error ({e:?}) during boot — the shipped-disk \
             rehydration path has regressed"
        )),
        WaitOutcome::TimedOut => session.fail("guest never reached a login or shell prompt"),
    }

    // Let the brief post-resume driver-init noise (e.g. the genirq irq12 burst)
    // settle before driving commands.
    session.drain_for(Duration::from_secs(2));

    // --- 2) write a file, list it, and read it back ------------------------- //
    // Markers are built so the *typed* command line (which the guest echoes back)
    // never contains the contiguous string we match on — only the executed
    // output does. That makes each assertion unambiguous despite tty echo.
    let uniq = format!("{}_{}", process::id(), nanos());
    let path = format!("/tmp/gimbal_e2e_{uniq}.txt");
    let begin = format!("B1_{uniq}");
    let end = format!("B2_{uniq}");
    let readback = format!("R:GIMBAL_FILE_OK_{uniq}");
    // Pre-existing content that lives on the *base* disk. Reading it back after
    // dropping the page cache is what distinguishes a correctly shipped disk
    // (real content) from a regressed zero overlay (zeros / EIO) — a brand-new
    // /tmp file alone would not, since it lives entirely in the COW overlay.
    let os_marker = "OS:Ubuntu 24.04";

    let command = format!(
        "U={uniq}; F=/tmp/gimbal_e2e_${{U}}.txt; C=GIMBAL_FILE; \
         echo \"${{C}}_OK_${{U}}\" > \"$F\"; sync; \
         sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || true; \
         echo B1_${{U}}; ls -1 \"$F\"; echo \"R:$(cat \"$F\")\"; \
         echo \"OS:$(grep -o 'Ubuntu 24\\.04' /etc/os-release | head -1)\"; \
         echo B2_${{U}}\n"
    );
    session.send(&command);

    if session.wait_for(&[&end], deadline).is_none() {
        session.fail("the write/ls/cat command never finished (no end sentinel)");
    }

    let transcript = session.transcript();

    // --- 3) tear down before asserting, so the VM never lingers ------------- //
    session.shutdown();

    // Optional: dump the full console transcript for inspection/debugging.
    if let Some(log) = env::var_os("CHM_E2E_LOG") {
        let _ = fs::write(&log, &transcript);
    }
    eprintln!(
        "e2e: console captured {} bytes; reached shell, ran write/ls/cat loop",
        transcript.len()
    );

    // --- 4) assertions ------------------------------------------------------- //
    // No disk errors anywhere on the console — this is the core regression guard.
    for needle in DISK_ERRORS {
        assert!(
            !transcript.contains(needle),
            "guest console reported a disk error ({needle:?}) — the shipped-disk \
             rehydration path has regressed.\n--- console tail ---\n{}",
            tail(&transcript)
        );
    }

    assert!(
        transcript.contains(&begin),
        "command did not execute (missing begin sentinel)\n--- console tail ---\n{}",
        tail(&transcript)
    );
    // `ls` listed the file we wrote (the full path appears only as ls output).
    assert!(
        transcript.contains(&path),
        "`ls` did not show the written file {path}\n--- console tail ---\n{}",
        tail(&transcript)
    );
    // `cat` read the file's content back — proves the write actually landed and
    // is readable (not just acknowledged).
    assert!(
        transcript.contains(&readback),
        "did not read the written file content back ({readback})\n--- console tail ---\n{}",
        tail(&transcript)
    );
    // Pre-existing base-disk content read back after dropping caches — the
    // deterministic guard that the guest is reading its *real* shipped disk and
    // not a zero overlay (which would return zeros / EIO here).
    assert!(
        transcript.contains(os_marker),
        "did not read pre-existing base-disk content (/etc/os-release) after dropping caches — \
         the shipped-disk read path has regressed.\n--- console tail ---\n{}",
        tail(&transcript)
    );
}

/// Suspend/resume regression: write a marker that lives ONLY in guest RAM
/// (`/dev/shm`, a tmpfs), suspend the microVM (which captures a live checkpoint),
/// then resume it in a fresh `chm` process and prove the guest came back exactly
/// where it left off — already logged in, with the RAM-only marker intact. A
/// cold boot would show a fresh `login:` and an empty tmpfs, so this fails loudly
/// if resume ever silently degrades into a reboot.
#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/hvf/e2e-microvm-loop.sh"]
fn microvm_suspends_and_resumes_live_state() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to run suspend/resume");
        return;
    };
    assert!(
        snapshot.join("state.json").is_file(),
        "CHM_E2E_SNAPSHOT={} has no state.json",
        snapshot.display()
    );

    // Start clean: no prior checkpoint, fresh overlays, so session 1 cold-boots.
    let _ = fs::remove_dir_all(snapshot.join(".chm-checkpoint"));
    let overlays = snapshot.join(".chm-overlays");
    if overlays.is_dir() {
        for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }

    let shell = "@ch-snap:~$";
    let uniq = format!("{}_{}", process::id(), nanos());
    let marker = format!("GIMBAL_RESUME_OK_{uniq}");
    let shmfile = format!("/dev/shm/gimbal_resume_{uniq}");
    let snap_str = snapshot.to_str().unwrap().to_string();
    let args = [
        "connect",
        &snap_str,
        "--no-stop-daemon",
        "--checkpoint",
        "--idle-exit",
        "0",
        "--max-seconds",
        "180",
    ];

    // --- session 1: cold boot, log in, write a RAM-only marker, suspend ------ //
    let chm = signed_chm_binary();
    let mut s1 = PtySession::spawn(&chm, &args);
    let deadline = Instant::now() + OVERALL_BUDGET;
    login_to_shell(&mut s1, shell, deadline);
    s1.drain_for(Duration::from_secs(2));

    // /dev/shm is tmpfs — pure RAM. A cold reboot wipes it; only a live memory
    // resume brings it back. Build the command so the matched marker appears
    // only in `cat` output, never in the echoed command line.
    let write_cmd = format!(
        "M={marker}; printf '%s\\n' \"$M\" > {shmfile}; sync; echo W1_{uniq}_done\n"
    );
    s1.send(&write_cmd);
    if s1.wait_for(&[&format!("W1_{uniq}_done")], deadline).is_none() {
        s1.fail("session 1: writing the RAM marker never completed");
    }
    // Let the guest settle back to an idle shell (serial output drained, the
    // getty parked in its read) before snapshotting, so the checkpoint captures
    // a quiescent state that resumes deterministically.
    s1.drain_for(Duration::from_secs(2));
    s1.suspend();

    assert!(
        snapshot.join(".chm-checkpoint/checkpoint.json").is_file()
            && snapshot.join(".chm-checkpoint/memory-ranges").is_file(),
        "suspend did not write a checkpoint (checkpoint.json + memory-ranges)"
    );

    // --- session 2: resume; must land logged-in with the marker intact ------- //
    let chm2 = signed_chm_binary();
    let mut s2 = PtySession::spawn(&chm2, &args);
    let deadline2 = Instant::now() + OVERALL_BUDGET;

    // Let the resume settle (mapping the full RAM dump + restoring vCPU/GIC takes
    // a moment) so the prod below isn't sent before the guest is running.
    s2.drain_for(Duration::from_secs(4));

    // Prod the resumed shell. A live resume lands at the logged-in prompt (it
    // doesn't reprint spontaneously, so nudge it with a newline and retry); a
    // cold boot would instead show a fresh `login:` and the kernel boot sequence.
    let mut at_shell = false;
    for _ in 0..12 {
        if Instant::now() >= deadline2 {
            break;
        }
        s2.send("\n");
        match s2.wait_for_or_abort(
            &[shell, "login:"],
            &DISK_ERRORS,
            Instant::now() + Duration::from_secs(5),
        ) {
            WaitOutcome::Found(m) if m == "login:" => s2.fail(
                "resume cold-booted (saw a fresh `login:`) instead of restoring the \
                 logged-in session",
            ),
            WaitOutcome::Found(_) => {
                at_shell = true;
                break;
            }
            WaitOutcome::Aborted(e) => {
                s2.fail(&format!("guest reported a disk error ({e:?}) on resume"))
            }
            WaitOutcome::TimedOut => continue,
        }
    }
    if !at_shell {
        s2.fail("resumed guest never produced a shell prompt");
    }

    let read_cmd = format!("echo R1_{uniq}; cat {shmfile} 2>&1; echo R2_{uniq}\n");
    s2.send(&read_cmd);
    if s2.wait_for(&[&format!("R2_{uniq}")], deadline2).is_none() {
        s2.fail("session 2: reading the RAM marker never completed");
    }
    let transcript = s2.transcript();
    s2.shutdown();

    if let Some(log) = env::var_os("CHM_E2E_LOG") {
        let _ = fs::write(&log, &transcript);
    }
    assert!(
        transcript.contains(&marker),
        "the RAM-only /dev/shm marker did not survive suspend/resume — live guest memory \
         was not restored (a cold boot would clear tmpfs).\n--- console tail ---\n{}",
        tail(&transcript)
    );
    eprintln!("e2e: suspend/resume preserved the logged-in shell and RAM marker {marker}");
}

/// Drive a `chm connect` session from spawn to a shell prompt, logging in with
/// `ubuntu` / `ubuntu` if a getty prompt is shown (autologin is also accepted).
fn login_to_shell(session: &mut PtySession, shell: &str, deadline: Instant) {
    match session.wait_for_or_abort(&[shell, "login:"], &DISK_ERRORS, deadline) {
        WaitOutcome::Found(m) if m == "login:" => {
            session.send("ubuntu\n");
            match session.wait_for(&["Password:", shell], deadline) {
                Some(p) if p == "Password:" => {
                    session.send("ubuntu\n");
                    if session.wait_for(&[shell], deadline).is_none() {
                        session.fail("did not reach a shell prompt after entering the password");
                    }
                }
                Some(_) => {}
                None => session.fail("no password prompt or shell after the login name"),
            }
        }
        WaitOutcome::Found(_) => {}
        WaitOutcome::Aborted(e) => session.fail(&format!(
            "guest reported a disk error ({e:?}) during boot"
        )),
        WaitOutcome::TimedOut => session.fail("guest never reached a login or shell prompt"),
    }
}

fn snapshot_from_env() -> Option<PathBuf> {
    let raw = env::var_os("CHM_E2E_SNAPSHOT")?;
    if raw.is_empty() {
        return None;
    }
    Some(PathBuf::from(raw))
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Copy the cargo-built `chm` to a temp path and ad-hoc code-sign it with the
/// hypervisor entitlement. Working on a copy avoids disturbing (or being blocked
/// by) a `chm` the app/daemon may currently be running from `target/`.
fn signed_chm_binary() -> PathBuf {
    let src = env!("CARGO_BIN_EXE_chm");
    let dst = env::temp_dir().join(format!("chm-e2e-{}", process::id()));
    fs::copy(src, &dst).unwrap_or_else(|e| panic!("copy {src} -> {}: {e}", dst.display()));

    let ent = env::temp_dir().join(format!("chm-e2e-{}.entitlements", process::id()));
    fs::write(&ent, HV_ENTITLEMENTS).expect("write entitlements");

    let status = Command::new("codesign")
        .args(["--sign", "-", "--entitlements"])
        .arg(&ent)
        .args(["--force"])
        .arg(&dst)
        .status()
        .expect("run codesign");
    assert!(status.success(), "codesign failed for {}", dst.display());
    let _ = fs::remove_file(&ent);
    dst
}

fn tail(s: &str) -> String {
    let filtered: String = s
        .lines()
        .filter(|l| !l.contains("Setting trigger mode"))
        .collect::<Vec<_>>()
        .join("\n");
    let chars: Vec<char> = filtered.chars().collect();
    let start = chars.len().saturating_sub(2000);
    chars[start..].iter().collect()
}

/// A `chm` child driven over a pseudo-terminal master fd.
struct PtySession {
    master: RawFd,
    child: Child,
    buf: Vec<u8>,
    binary: PathBuf,
}

impl PtySession {
    fn spawn(binary: &Path, args: &[&str]) -> Self {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let win = Winsize {
            ws_row: 50,
            ws_col: 200,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `master`/`slave` are valid out-pointers to local ints; `name`
        // and `termp` are null (allowed by openpty), and `win` outlives the call.
        let rc = unsafe { openpty(&mut master, &mut slave, ptr::null_mut(), ptr::null(), &win) };
        assert_eq!(rc, 0, "openpty failed: {}", io::Error::last_os_error());

        let slave_fd = slave;
        let mut cmd = Command::new(binary);
        cmd.args(args).env("TERM", "vt100");
        // SAFETY: `dup(slave)` yields fresh owned fds handed to `Stdio`, which
        // takes ownership. The `pre_exec` closure only calls async-signal-safe
        // libc functions (`setsid`, `ioctl`) on the open `slave_fd`.
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(dup(slave)));
            cmd.stdout(Stdio::from_raw_fd(dup(slave)));
            cmd.stderr(Stdio::from_raw_fd(dup(slave)));
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                // Best effort: make the slave our controlling terminal.
                libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn chm");

        // Parent keeps only the master end.
        // SAFETY: `slave` is an open fd we own and no longer use in the parent.
        unsafe { libc::close(slave) };
        set_nonblocking(master);

        Self {
            master,
            child,
            buf: Vec::with_capacity(64 * 1024),
            binary: binary.to_path_buf(),
        }
    }

    /// Pull whatever is currently readable into the buffer. Returns false on EOF.
    fn pump(&mut self) -> bool {
        let mut tmp = [0u8; 8192];
        loop {
            // SAFETY: `self.master` is an open fd; `tmp` is a valid, writable
            // buffer of `tmp.len()` bytes for the duration of the read.
            let n = unsafe {
                libc::read(self.master, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len())
            };
            if n > 0 {
                self.buf.extend_from_slice(&tmp[..n as usize]);
            } else if n == 0 {
                return false;
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) => return true,
                    Some(libc::EINTR) => continue,
                    _ => return false,
                }
            }
        }
    }

    /// Wait until any of `needles` appears, or the deadline passes.
    fn wait_for(&mut self, needles: &[&str], deadline: Instant) -> Option<String> {
        loop {
            self.pump();
            let text = String::from_utf8_lossy(&self.buf);
            for n in needles {
                if text.contains(n) {
                    return Some((*n).to_string());
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(50));
        }
    }

    /// Like [`Self::wait_for`], but also bails out early if any `abort` substring
    /// appears first — used to fail fast on disk errors during boot.
    fn wait_for_or_abort(
        &mut self,
        needles: &[&str],
        abort: &[&str],
        deadline: Instant,
    ) -> WaitOutcome {
        loop {
            self.pump();
            let text = String::from_utf8_lossy(&self.buf);
            for a in abort {
                if text.contains(a) {
                    return WaitOutcome::Aborted((*a).to_string());
                }
            }
            for n in needles {
                if text.contains(n) {
                    return WaitOutcome::Found((*n).to_string());
                }
            }
            if Instant::now() >= deadline {
                return WaitOutcome::TimedOut;
            }
            sleep(Duration::from_millis(50));
        }
    }

    fn drain_for(&mut self, dur: Duration) {
        let end = Instant::now() + dur;
        while Instant::now() < end {
            self.pump();
            sleep(Duration::from_millis(50));
        }
    }

    fn send(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let mut off = 0;
        while off < bytes.len() {
            // SAFETY: `self.master` is an open fd; we read `bytes.len() - off`
            // bytes from a valid slice starting at `bytes[off..]`.
            let n = unsafe {
                libc::write(
                    self.master,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n > 0 {
                off += n as usize;
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) => sleep(Duration::from_millis(5)),
                    Some(libc::EINTR) => {}
                    _ => break,
                }
            }
        }
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.buf).to_string()
    }

    /// Ask `chm` to quit (Ctrl-A x) and wait for it to exit cleanly, then make
    /// sure the child is gone. The grace period is generous because a
    /// `--checkpoint` session captures a full RAM checkpoint on exit (seconds for
    /// a 1 GB guest); a short timeout here would SIGKILL mid-capture, which skips
    /// VM teardown and leaks the one HVF slot. The loop breaks as soon as the
    /// child exits, so a non-checkpointing session still tears down fast.
    fn shutdown(&mut self) {
        self.send("\x01x");
        let until = Instant::now() + Duration::from_secs(45);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            self.pump();
            sleep(Duration::from_millis(50));
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            // Last resort: the graceful quit didn't land. SIGKILL may leak the
            // HVF VM (it skips teardown), so this should effectively never fire.
            eprintln!("e2e: WARNING — chm did not exit gracefully; forcing kill (may leak the HVF slot)");
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = fs::remove_file(&self.binary);
    }

    /// Suspend the session: send the graceful quit escape (Ctrl-A x) and wait
    /// for `chm` to exit, which captures a checkpoint. Unlike `shutdown`, the
    /// signed binary is left in place so a second session can resume from it.
    /// The generous grace matches a full RAM checkpoint capture; a SIGKILL here
    /// would skip teardown and leak the HVF slot (and lose the checkpoint).
    fn suspend(&mut self) {
        self.send("\x01x");
        let until = Instant::now() + Duration::from_secs(45);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            self.pump();
            sleep(Duration::from_millis(50));
        }
        eprintln!("e2e: WARNING — chm did not suspend gracefully; forcing kill (may leak the HVF slot)");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Tear down and fail with the console tail for context.
    fn fail(&mut self, why: &str) -> ! {
        let transcript = self.transcript();
        self.shutdown();
        panic!("{why}\n--- console tail ---\n{}", tail(&transcript));
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // SAFETY: `self.master` is an open fd owned by this session; after Drop
        // nothing else references it.
        unsafe { libc::close(self.master) };
        let _ = fs::remove_file(&self.binary);
    }
}

fn dup(fd: RawFd) -> RawFd {
    // SAFETY: `fd` is an open fd; `dup` returns a new fd or -1, checked below.
    let n = unsafe { libc::dup(fd) };
    assert!(n >= 0, "dup failed: {}", io::Error::last_os_error());
    n
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: `fd` is an open fd; `fcntl` get/set of file status flags is safe
    // to issue on it and has no memory effects.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}
