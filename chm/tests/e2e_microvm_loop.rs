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

/// Hero journey — the fork/delta/rollback lineage end to end:
///
///   1. boot a sandbox and log in,
///   2. create a file, checkpoint it (delta 1),
///   3. create a second file, checkpoint again (delta 2),
///   4. list + cat both files (both present),
///   5. roll back to delta 1, and
///   6. prove the second file is gone while the first remains.
///
/// The tmpfs files (`/dev/shm`) live in pure guest RAM; the persistent-disk
/// files (in `$HOME`, backed by the virtio-blk overlay) exercise disk-overlay
/// rollback. Each checkpoint now captures both the RAM image and the disk
/// overlay, so a rollback reverts a consistent RAM+disk pair — the later delta
/// disappears from tmpfs AND from the persistent disk (#62).
#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/hvf/e2e-microvm-loop.sh"]
fn microvm_delta_rollback_removes_the_later_delta() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to run the rollback journey");
        return;
    };
    assert!(
        snapshot.join("state.json").is_file(),
        "CHM_E2E_SNAPSHOT={} has no state.json",
        snapshot.display()
    );

    // Start clean: no prior checkpoint or archived revisions, fresh overlays.
    let _ = fs::remove_dir_all(snapshot.join(".chm-checkpoint"));
    let _ = fs::remove_dir_all(snapshot.join(".chm-revisions"));
    let overlays = snapshot.join(".chm-overlays");
    if overlays.is_dir() {
        for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }

    let shell = "@ch-snap:~$";
    let uniq = format!("{}_{}", process::id(), nanos());
    let file1 = format!("/dev/shm/gimbal_hero1_{uniq}");
    let file2 = format!("/dev/shm/gimbal_hero2_{uniq}");
    // Persistent-disk counterparts (in $HOME on the virtio-blk overlay), to prove
    // rollback reverts the disk overlay too, not just tmpfs/RAM (#62).
    let dfile1 = format!("$HOME/gimbal_herod1_{uniq}");
    let dfile2 = format!("$HOME/gimbal_herod2_{uniq}");
    let m1 = format!("HERO_ONE_{uniq}");
    let m2 = format!("HERO_TWO_{uniq}");
    let md1 = format!("HERO_DISK_ONE_{uniq}");
    let md2 = format!("HERO_DISK_TWO_{uniq}");
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
    let chm = signed_chm_binary();

    // --- 1) boot, log in, write file 1, checkpoint (delta 1) ----------------- //
    let mut s1 = PtySession::spawn(&chm, &args);
    let deadline = Instant::now() + OVERALL_BUDGET;
    login_to_shell(&mut s1, shell, deadline);
    s1.drain_for(Duration::from_secs(2));
    s1.send(&format!(
        "printf '%s\\n' {m1} > {file1}; printf '%s\\n' {md1} > {dfile1}; sync; echo W1_{uniq}_done\n"
    ));
    if s1.wait_for(&[&format!("W1_{uniq}_done")], deadline).is_none() {
        s1.fail("delta 1: writing file 1 never completed");
    }
    s1.drain_for(Duration::from_secs(2));
    s1.suspend();
    assert!(
        snapshot.join(".chm-checkpoint/checkpoint.json").is_file(),
        "delta 1 did not produce a checkpoint"
    );
    let rev1 = head_revision_id(&snapshot);
    eprintln!("e2e: delta 1 captured as revision {rev1}");

    // --- 2) resume, write file 2, checkpoint (delta 2) ----------------------- //
    let mut s2 = PtySession::spawn(&chm, &args);
    let deadline2 = Instant::now() + OVERALL_BUDGET;
    resume_to_shell(&mut s2, shell, deadline2);
    s2.send(&format!(
        "printf '%s\\n' {m2} > {file2}; printf '%s\\n' {md2} > {dfile2}; sync; echo W2_{uniq}_done\n"
    ));
    if s2.wait_for(&[&format!("W2_{uniq}_done")], deadline2).is_none() {
        s2.fail("delta 2: writing file 2 never completed");
    }
    s2.drain_for(Duration::from_secs(2));
    s2.suspend();
    // Capturing delta 2 archives delta 1 into the revision store so a rollback
    // can reach it.
    assert!(
        snapshot
            .join(format!(".chm-revisions/{rev1}/memory-ranges"))
            .is_file(),
        "delta 1 (revision {rev1}) was not archived with its RAM when delta 2 was captured — \
         rollback would have nothing resumable to return to"
    );

    // --- 3) resume and confirm BOTH files are present ------------------------ //
    let mut s3 = PtySession::spawn(&chm, &args);
    let deadline3 = Instant::now() + OVERALL_BUDGET;
    resume_to_shell(&mut s3, shell, deadline3);
    s3.send(&format!(
        "echo LS_{uniq}; ls -1 {file1} {file2} 2>&1; cat {file1} {file2} {dfile1} {dfile2} 2>&1; echo DONE_{uniq}\n"
    ));
    if s3.wait_for(&[&format!("DONE_{uniq}")], deadline3).is_none() {
        s3.fail("could not list/cat both files after delta 2");
    }
    let seen_both = s3.transcript();
    s3.suspend();
    assert!(
        seen_both.contains(&m1) && seen_both.contains(&m2),
        "after two deltas both tmpfs files must be readable (saw m1={}, m2={})\n--- console tail ---\n{}",
        seen_both.contains(&m1),
        seen_both.contains(&m2),
        tail(&seen_both)
    );
    assert!(
        seen_both.contains(&md1) && seen_both.contains(&md2),
        "after two deltas both persistent-disk files must be readable (saw md1={}, md2={})\n--- console tail ---\n{}",
        seen_both.contains(&md1),
        seen_both.contains(&md2),
        tail(&seen_both)
    );
    eprintln!("e2e: both deltas present after delta 2 (tmpfs + disk)");

    // --- 4) roll back to delta 1 -------------------------------------------- //
    let status = Command::new(&chm)
        .args(["rollback", &snap_str, &rev1])
        .status()
        .expect("run chm rollback");
    assert!(status.success(), "chm rollback to {rev1} failed");

    // --- 5) resume and prove file 2 is GONE, file 1 remains ------------------ //
    let mut s4 = PtySession::spawn(&chm, &args);
    let deadline4 = Instant::now() + OVERALL_BUDGET;
    resume_to_shell(&mut s4, shell, deadline4);
    s4.send(&format!(
        "echo RB_{uniq}; cat {file1} {dfile1} 2>&1; ls {file2} {dfile2} 2>&1; echo DONE_{uniq}\n"
    ));
    if s4.wait_for(&[&format!("DONE_{uniq}")], deadline4).is_none() {
        s4.fail("could not inspect files after rollback");
    }
    let after = s4.transcript();
    s4.shutdown();

    if let Some(log) = env::var_os("CHM_E2E_LOG") {
        let _ = fs::write(&log, &after);
    }
    // Only look at output produced after the rollback prod marker, so earlier
    // sessions' echoes in a shared transcript can't confuse the assertions.
    let post = after
        .rsplit_once(&format!("RB_{uniq}"))
        .map_or(after.as_str(), |(_, tailtext)| tailtext);
    assert!(
        post.contains(&m1),
        "rollback lost the FIRST tmpfs file — it should survive (delta 1 is the target).\n\
         --- console tail ---\n{}",
        tail(&after)
    );
    assert!(
        !post.contains(&m2),
        "rollback did NOT remove the second tmpfs file — the later RAM delta was not reverted.\n\
         --- console tail ---\n{}",
        tail(&after)
    );
    assert!(
        post.contains(&md1),
        "rollback lost the FIRST persistent-disk file — the disk overlay was not restored to \
         delta 1.\n--- console tail ---\n{}",
        tail(&after)
    );
    assert!(
        !post.contains(&md2),
        "rollback did NOT remove the second persistent-disk file — the later disk-overlay delta \
         was not reverted (#62).\n--- console tail ---\n{}",
        tail(&after)
    );
    eprintln!(
        "e2e: rollback to delta 1 kept file 1 and removed file 2 (tmpfs + disk) — lineage verified"
    );
}

/// Probe the guest's toolchain + resources (M32 benchmark prep). Boots the
/// snapshot, logs in, and dumps `which <tool>` for a set of build/CPU tools plus
/// nproc/memory to the console + `CHM_E2E_LOG`, so we can pick a benchmark
/// workload that is present in both the guest and the Docker baseline. Read-only:
/// it runs no build and asserts nothing beyond reaching a shell.
#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/hvf/e2e-microvm-loop.sh"]
fn microvm_probe_toolchain() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to probe the guest toolchain");
        return;
    };
    let overlays = snapshot.join(".chm-overlays");
    if overlays.is_dir() {
        for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
    let chm = signed_chm_binary();
    let mut s = PtySession::spawn(
        &chm,
        &[
            "connect",
            snapshot.to_str().unwrap(),
            "--no-stop-daemon",
            "--idle-exit",
            "0",
            "--max-seconds",
            "120",
        ],
    );
    let shell = "@ch-snap:~$";
    let deadline = Instant::now() + OVERALL_BUDGET;
    login_to_shell(&mut s, shell, deadline);
    s.drain_for(Duration::from_secs(2));

    let uniq = format!("{}_{}", process::id(), nanos());
    // The command line the guest echoes back never contains "PROBE_END" as a
    // contiguous executed-output token, so the sentinel is unambiguous.
    let cmd = format!(
        "echo PB_{uniq}_S; \
         for t in cc gcc g++ make ld python3 gzip xz zstd openssl perl git tar; do \
           printf '%s=' $t; command -v $t || echo none; done; \
         echo NPROC=$(nproc); echo MEMMB=$(free -m 2>/dev/null | awk '/Mem:/{{print $2}}'); \
         echo OSREL=$(. /etc/os-release; echo $VERSION_ID); \
         echo PB_{uniq}_E\n"
    );
    s.send(&cmd);
    s.wait_for(&[&format!("PB_{uniq}_E")], deadline);
    let transcript = s.transcript();
    s.shutdown();

    if let Some(log) = env::var_os("CHM_E2E_LOG") {
        let _ = fs::write(&log, &transcript);
    }
    // Surface the probe block on stderr for the operator.
    for line in transcript.lines() {
        if line.contains('=') || line.starts_with("NPROC") || line.starts_with("MEMMB") {
            eprintln!("probe: {}", line.trim());
        }
    }
    eprintln!("probe: captured {} bytes of console", transcript.len());
}

/// Reliability probe for #78 (interactive wedge after a long silent CPU burst).
///
/// In a single `chm connect` session, runs a long silent CPU burst then a
/// follow-up burst, mirroring the back-to-back-compression case that wedged the
/// benchmark. Because the underlying cause is Apple HVF's internal WFI wait not
/// reliably waking a freshly-resumed guest (an intermittent, hard hypervisor-
/// internals issue — see #78/#60), a single run can wedge by chance. So this
/// retries whole sessions up to `WEDGE_ATTEMPTS` and reports the success rate,
/// passing if the guest completes a back-to-back-burst session at least once
/// (proving the path works) and failing only if EVERY attempt wedges (a true
/// regression). Set `CHM_E2E_LOG` to capture the console of a wedged attempt.
///
/// Config (env): `CHM_E2E_SNAPSHOT` (the guest), `WEDGE_N` (burst seq size,
/// default 16000000 ~ 20s on the 1-vCPU demo), `WEDGE_FOLLOWUPS` (default 2),
/// `WEDGE_ATTEMPTS` (default 3). The run-progress watchdog (default on) bounds a
/// wedge into a recoverable crawl; `CHM_DISABLE_RUN_WATCHDOG=1` compares without.
#[test]
#[ignore = "needs a local HVF-compatible snapshot; reliability probe for #78"]
fn microvm_input_wedge_repro() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to run the wedge repro");
        return;
    };
    let n: u64 = env::var("WEDGE_N").ok().and_then(|v| v.parse().ok()).unwrap_or(16_000_000);
    let followups: usize =
        env::var("WEDGE_FOLLOWUPS").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let attempts: usize =
        env::var("WEDGE_ATTEMPTS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);

    let mut successes = 0usize;
    for attempt in 0..attempts {
        if wedge_session(&snapshot, n, followups, attempt) {
            successes += 1;
        }
    }
    eprintln!("wedge-repro: {successes}/{attempts} sessions completed all bursts cleanly");
    assert!(
        successes > 0,
        "guest wedged on EVERY one of {attempts} attempts running back-to-back \
         CPU bursts in a session -- a real regression of the #78 interactive path"
    );
}

/// Run one wedge-probe session: resume, run a burst, then `followups` more
/// bursts. Returns true iff every burst completed. On a wedge, logs the console
/// tail (and `CHM_E2E_LOG`, if set) for diagnosis.
fn wedge_session(snapshot: &Path, n: u64, followups: usize, attempt: usize) -> bool {
    let shell = "@ch-snap:~$";
    let overlays = snapshot.join(".chm-overlays");
    if overlays.is_dir() {
        for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
    let chm = signed_chm_binary();
    let mut s = PtySession::spawn(
        &chm,
        &[
            "connect",
            snapshot.to_str().unwrap(),
            "--no-stop-daemon",
            "--idle-exit",
            "0",
            "--max-seconds",
            "600",
        ],
    );
    let boot_deadline = Instant::now() + Duration::from_secs(150);
    login_to_shell(&mut s, shell, boot_deadline);
    s.drain_for(Duration::from_secs(2));

    let mut wedged = false;
    // The initial burst plus `followups` more, all back-to-back in one session.
    // The tag is assembled from a shell var so the *echoed* command never
    // contains the contiguous `done=<uniq>` string -- only the executed output.
    for step in 0..=followups {
        let tag = format!("BURST_{}_{}_{attempt}_{step}", process::id(), nanos());
        let cmd = format!(
            "B={tag}; seq 1 {n} | xz -6 -T1 -c >/dev/null 2>&1; echo \"done=${{B}}\"\n"
        );
        s.send(&cmd);
        let ok = s
            .wait_for(&[&format!("done={tag}")], Instant::now() + Duration::from_secs(120))
            .is_some();
        eprintln!("wedge-repro: attempt {} burst {}/{} ok={ok}", attempt + 1, step + 1, followups + 1);
        if !ok {
            if let Some(log) = env::var_os("CHM_E2E_LOG") {
                let _ = fs::write(&log, s.transcript());
            }
            eprintln!("wedge-repro: WEDGED; console tail:\n{}", tail(&s.transcript()));
            wedged = true;
            break;
        }
    }
    s.shutdown();
    !wedged
}

/// M32.2/M32.3 gimbal-side benchmark. Boots the snapshot, logs in, and runs the
/// SAME inner command the Docker baseline runs, timing it with the guest's own
/// clock and parsing the `BENCH_RESULT` line off the console. Writes a results
/// JSON compatible with `scripts/bench/report.py`.
///
/// Config (env): `CHM_E2E_SNAPSHOT` (the guest), `BENCH_TRIALS` (default 3),
/// `BENCH_N` (seq payload size), `BENCH_OUT` (results path), `BENCH_WORKLOAD`
/// (label), and `BENCH_CMD` (the timed inner command). With `BENCH_CMD` unset
/// the workload is the CPU pipeline `seq 1 $BENCH_N | $BENCH_PIPE`, which needs
/// no shared FS or network and so runs against the stock demo guest. The I/O and
/// network workloads set `BENCH_CMD` from
/// `scripts/bench/workloads/commands.sh` -- the same string the container runs.
#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/bench/run-gimbal-e2e.sh"]
fn microvm_xz_benchmark() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to run the xz benchmark");
        return;
    };
    let trials: usize = env::var("BENCH_TRIALS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let n: u64 = env::var("BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(16_000_000);
    // The single-threaded compressor pipe to time; overridable so the same test
    // drives the xz (default) or gzip workload for cross-runtime comparison.
    let pipe = env::var("BENCH_PIPE").unwrap_or_else(|_| "xz -6 -T1 -c".to_string());
    let workload = env::var("BENCH_WORKLOAD").unwrap_or_else(|_| "xz".to_string());
    // The timed inner command. Defaults to the CPU pipeline above, so the
    // published xz/gzip numbers stay byte-for-byte reproducible; the I/O and
    // network workloads (M32.3) override it with the shared command string from
    // `scripts/bench/workloads/commands.sh`, which the Docker side also runs.
    let inner = env::var("BENCH_CMD").unwrap_or_else(|_| format!("seq 1 {n} | {pipe}"));
    let out = env::var("BENCH_OUT")
        .unwrap_or_else(|_| format!("{}/../scripts/bench/results/gimbal-{workload}.json", env!("CARGO_MANIFEST_DIR")));

    let shell = "@ch-snap:~$";
    let ncpu = "1"; // demo snapshot is a single vCPU; recorded for the report.

    // Each trial runs in its OWN fresh `chm connect` session (boot -> one
    // workload -> teardown). This mirrors Docker's per-run model (a fresh
    // container each trial) and sidesteps an observed guest wedge where a second
    // command issued after a long silent CPU burst does not wake the parked vCPU
    // (tracked separately). `host_envelope_s` therefore includes this trial's
    // boot; the in-guest `wall_s` is the directly-comparable compression time.
    let mut trial_walls: Vec<(f64, u8, f64)> = Vec::new(); // (wall_s, ok, host_envelope_s)
    for i in 0..trials {
        let overlays = snapshot.join(".chm-overlays");
        if overlays.is_dir() {
            for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
        let host_start = Instant::now();
        // Fresh signed binary per trial: `shutdown()` deletes the binary it ran,
        // so each per-session trial needs its own copy.
        let chm = signed_chm_binary();
        let mut s = PtySession::spawn(
            &chm,
            &[
                "connect",
                snapshot.to_str().unwrap(),
                "--no-stop-daemon",
                "--idle-exit",
                "0",
                "--max-seconds",
                "300",
            ],
        );
        let boot_deadline = Instant::now() + Duration::from_secs(150);
        bench_reach_shell(&mut s, shell, boot_deadline);
        // Let residual boot chatter settle so the transcript is clean before the
        // command. Short by design: the tagged completion line is what the trial
        // matches on, so this only needs to cover the prompt echo, and every
        // millisecond here lands inside the reported `host_envelope_s` (#79).
        s.drain_for(Duration::from_millis(300));

        let uniq = format!("{}_{}", process::id(), nanos());
        // The same inner command the Docker/sbx sides run ($BENCH_CMD, default a
        // deterministic `seq` stream through a single-threaded compressor with
        // the output discarded). The completion tag is emitted via a shell var
        // ($T) so the *echoed* command line never contains the contiguous
        // `tag=<uniq>` string we wait on -- only the executed output does (same
        // trick as the other tests).
        let cmd = format!(
            "T={uniq}; \
             S=$(date +%s.%N); \
             if {inner} >/dev/null 2>&1; then OK=1; else OK=0; fi; \
             E=$(date +%s.%N); \
             W=$(awk -v a=$S -v b=$E 'BEGIN{{printf \"%.3f\", b-a}}'); \
             echo \"BENCH_RESULT workload={workload} wall_s=$W ok=$OK tag=${{T}}\"\n"
        );
        s.send(&cmd);
        let trial_deadline = Instant::now() + Duration::from_secs(200);
        let found = s.wait_for(&[&format!("tag={uniq}")], trial_deadline).is_some();
        let host_env = host_start.elapsed().as_secs_f64();
        let (wall, ok) = if found {
            parse_bench_result(&s.transcript(), &uniq)
        } else {
            (0.0, 0)
        };
        s.shutdown();
        eprintln!("gimbal {workload} trial {}/{}: wall_s={wall} ok={ok} host_envelope_s={host_env:.3}", i + 1, trials);
        trial_walls.push((wall, ok, host_env));
    }

    // Write the results JSON (same shape run-gimbal.sh emits).
    let mut trials_json = String::new();
    for (idx, (wall, ok, env_s)) in trial_walls.iter().enumerate() {
        if idx > 0 {
            trials_json.push(',');
        }
        trials_json.push_str(&format!(
            "{{\"wall_s\":{wall},\"host_envelope_s\":{env_s:.3},\"ok\":{ok}}}"
        ));
    }
    let doc = format!(
        "{{\n  \"runtime\": \"gimbal\",\n  \"workload\": \"{workload}\",\n  \
         \"host\": {{\"ncpu\": {ncpu}, \"snapshot\": \"{}\"}},\n  \
         \"trials\": [{trials_json}]\n}}\n",
        snapshot.file_name().and_then(|s| s.to_str()).unwrap_or("snapshot")
    );
    if let Some(parent) = Path::new(&out).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&out, doc).unwrap_or_else(|e| panic!("write {out}: {e}"));
    eprintln!("gimbal {workload} benchmark: wrote {out}");

    assert!(
        trial_walls.iter().any(|(_, ok, _)| *ok == 1),
        "no {workload} trial succeeded in the guest"
    );
}

/// Start-to-ready latency benchmark (#79).
///
/// The I/O and CPU benchmarks report `host_envelope_s`, which folds in harness
/// cost (per-trial codesign, prompt nudging, drain) and so cannot answer "how
/// fast does a sandbox start". This measures the four phases that matter for a
/// disposable sandbox, per trial:
///
/// * `vmm_ready_s`  — process spawn until the guest is released to run, read
///   from the `[startup] … guest released (VMM ready)` stamp (`CHM_TRACE_TIMING`).
/// * `shell_ready_s` — process spawn until a usable shell prompt.
/// * `teardown_s`   — graceful quit until the process is gone.
/// * `total_s`      — spawn until gone: the whole disposable-sandbox lifetime.
///
/// The signed binary is prepared *before* the clock starts, because codesigning
/// is a harness artifact (a shipped `chm` is signed once at install), not a
/// startup cost users pay.
#[test]
#[ignore = "needs a local HVF-compatible snapshot; run via scripts/bench/run-gimbal-startup.sh"]
fn microvm_startup_benchmark() {
    let Some(snapshot) = snapshot_from_env() else {
        eprintln!("skipping: set CHM_E2E_SNAPSHOT to a snapshot dir to run the startup benchmark");
        return;
    };
    let trials: usize = env::var("BENCH_TRIALS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let out = env::var("BENCH_OUT").unwrap_or_else(|_| {
        format!(
            "{}/../scripts/bench/results/gimbal-startup.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let shell = "@ch-snap:~$";

    let mut rows: Vec<(f64, f64, f64, f64)> = Vec::new();
    for i in 0..trials {
        let overlays = snapshot.join(".chm-overlays");
        if overlays.is_dir() {
            for entry in fs::read_dir(&overlays).into_iter().flatten().flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
        // Outside the measured window on purpose (see the doc comment).
        let chm = signed_chm_binary();

        let t0 = Instant::now();
        let mut s = PtySession::spawn(
            &chm,
            &[
                "connect",
                snapshot.to_str().unwrap(),
                "--no-stop-daemon",
                "--idle-exit",
                "0",
                "--max-seconds",
                "300",
            ],
        );
        bench_reach_shell(&mut s, shell, Instant::now() + Duration::from_secs(150));
        let shell_ready = t0.elapsed().as_secs_f64();
        let vmm_ready = parse_vmm_ready(&s.transcript()).unwrap_or(f64::NAN);

        let t_down = Instant::now();
        s.shutdown();
        let teardown = t_down.elapsed().as_secs_f64();
        let total = t0.elapsed().as_secs_f64();

        eprintln!(
            "gimbal startup trial {}/{}: vmm_ready_s={vmm_ready:.3} shell_ready_s={shell_ready:.3} \
             teardown_s={teardown:.3} total_s={total:.3}",
            i + 1,
            trials
        );
        rows.push((vmm_ready, shell_ready, teardown, total));
    }

    let mut trials_json = String::new();
    for (idx, (vmm, sh, td, tot)) in rows.iter().enumerate() {
        if idx > 0 {
            trials_json.push(',');
        }
        // A missing stamp serialises as null rather than NaN, which is not JSON.
        let vmm = if vmm.is_nan() {
            "null".to_string()
        } else {
            format!("{vmm:.3}")
        };
        trials_json.push_str(&format!(
            "{{\"vmm_ready_s\":{vmm},\"shell_ready_s\":{sh:.3},\"teardown_s\":{td:.3},\"total_s\":{tot:.3}}}"
        ));
    }
    let doc = format!(
        "{{\n  \"runtime\": \"gimbal\",\n  \"workload\": \"startup\",\n  \
         \"host\": {{\"ncpu\": 1, \"snapshot\": \"{}\"}},\n  \
         \"trials\": [{trials_json}]\n}}\n",
        snapshot
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("snapshot")
    );
    if let Some(parent) = Path::new(&out).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&out, doc).unwrap_or_else(|e| panic!("write {out}: {e}"));
    eprintln!("gimbal startup benchmark: wrote {out}");

    assert!(
        rows.iter().any(|(_, sh, _, _)| *sh > 0.0),
        "no startup trial reached a shell"
    );
}

/// Pull the seconds value out of the `[startup] <elapsed> guest released (VMM
/// ready)` stamp. `chm` formats the elapsed time with `{:?}` on a `Duration`, so
/// the unit varies with magnitude (`25.412ms`, `1.204s`, `812.4µs`); all three
/// are normalised to seconds here. Returns `None` when the stamp is absent
/// (`CHM_TRACE_TIMING` unset, or the guest never got released).
fn parse_vmm_ready(transcript: &str) -> Option<f64> {
    let line = transcript
        .lines()
        .find(|l| l.contains("[startup]") && l.contains("VMM ready"))?;
    let field = line.split_whitespace().nth(1)?;
    let (num, scale) = if let Some(v) = field.strip_suffix("ms") {
        (v, 1e-3)
    } else if let Some(v) = field.strip_suffix("µs") {
        (v, 1e-6)
    } else if let Some(v) = field.strip_suffix("ns") {
        (v, 1e-9)
    } else {
        (field.strip_suffix('s')?, 1.0)
    };
    num.parse::<f64>().ok().map(|v| v * scale)
}

/// Extract `(wall_s, ok)` from the `BENCH_RESULT ... tag=<uniq>` line in a
/// console transcript. Returns `(0.0, 0)` if the tagged line is absent.
fn parse_bench_result(transcript: &str, uniq: &str) -> (f64, u8) {
    let tag = format!("tag={uniq}");
    // Match the executed-output line (starts with BENCH_RESULT), not the echoed
    // command (which contains the format string, never a real wall_s=<number>).
    for line in transcript.lines() {
        if line.contains(&tag) && line.contains("BENCH_RESULT") && line.contains("wall_s=") {
            let wall = line
                .split("wall_s=")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .and_then(|v| v.parse::<f64>().ok());
            let ok = line
                .split("ok=")
                .nth(1)
                .and_then(|r| r.chars().next())
                .and_then(|c| c.to_digit(10))
                .map(|d| d as u8);
            if let (Some(w), Some(o)) = (wall, ok) {
                return (w, o);
            }
        }
    }
    (0.0, 0)
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

/// Drive a benchmark session to a usable shell, tolerating either snapshot
/// style: the demo guest cold-boots to a `login:` getty, while the stock
/// ITS/LPI captures resume straight into an already-logged-in shell whose
/// prompt is restored but never reprinted. Nudging with a newline makes the
/// restored prompt visible; a getty is logged into as usual.
///
/// Deliberately separate from `resume_to_shell`, which asserts a resume did
/// *not* cold-boot -- that assertion is the point of the suspend/resume test and
/// must not be relaxed here.
///
/// The nudge is sent *immediately* and then repeated, rather than after a blind
/// grace period. A resumed snapshot prints nothing at all, so any pre-nudge wait
/// is burned in full on every trial and lands inside the reported
/// `host_envelope_s` -- it measures the harness, not the engine (#79). An early
/// newline is harmless to a cold-booting guest: it is either consumed before
/// getty starts or makes getty reprint its prompt.
fn bench_reach_shell(session: &mut PtySession, shell: &str, deadline: Instant) {
    while Instant::now() < deadline {
        session.send("\n");
        match session.wait_for_or_abort(
            &[shell, "login:"],
            &DISK_ERRORS,
            Instant::now() + Duration::from_millis(500),
        ) {
            WaitOutcome::Found(m) if m == "login:" => return bench_log_in(session, shell, deadline),
            WaitOutcome::Found(_) => return,
            WaitOutcome::Aborted(e) => {
                session.fail(&format!("guest reported a disk error ({e:?}) before the benchmark"))
            }
            WaitOutcome::TimedOut => continue,
        }
    }
    session.fail("guest never produced a shell prompt for the benchmark");
}

/// Complete a `login:` getty prompt with the standard demo credentials.
fn bench_log_in(session: &mut PtySession, shell: &str, deadline: Instant) {
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

fn snapshot_from_env() -> Option<PathBuf> {
    let raw = env::var_os("CHM_E2E_SNAPSHOT")?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    if path.exists() {
        return Some(path);
    }
    // Cargo runs integration tests with the *package* directory as the cwd, so a
    // relative path written from the workspace root (`snapshots/...`, as the
    // bench runners pass) would otherwise resolve under `chm/` and be reported
    // as a missing snapshot. Retry it against the workspace root.
    let from_workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(&path);
    if from_workspace.exists() {
        return Some(from_workspace);
    }
    Some(path)
}

/// Prod a freshly-`chm resume`d session until it lands at a logged-in shell
/// (a live resume restores the prompt but does not reprint it, so nudge with a
/// newline and retry). Fails if it cold-boots (a fresh `login:`) or errors.
fn resume_to_shell(session: &mut PtySession, shell: &str, deadline: Instant) {
    session.drain_for(Duration::from_secs(4));
    for _ in 0..12 {
        if Instant::now() >= deadline {
            break;
        }
        session.send("\n");
        match session.wait_for_or_abort(
            &[shell, "login:"],
            &DISK_ERRORS,
            Instant::now() + Duration::from_secs(5),
        ) {
            WaitOutcome::Found(m) if m == "login:" => {
                session.fail("resume cold-booted (saw `login:`) instead of restoring the session")
            }
            WaitOutcome::Found(_) => return,
            WaitOutcome::Aborted(e) => {
                session.fail(&format!("guest reported a disk error ({e:?}) on resume"))
            }
            WaitOutcome::TimedOut => continue,
        }
    }
    session.fail("resumed guest never produced a shell prompt");
}

/// Read the current HEAD revision id from a snapshot's live checkpoint manifest
/// (`.chm-checkpoint/checkpoint.json`). Minimal string extraction so the test
/// stays dependency-free.
fn head_revision_id(snapshot: &Path) -> String {
    let manifest = snapshot.join(".chm-checkpoint/checkpoint.json");
    let body = fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
    let key = "\"id\":\"";
    let start = body
        .find(key)
        .unwrap_or_else(|| panic!("no `id` field in {}", manifest.display()))
        + key.len();
    let rest = &body[start..];
    let end = rest.find('"').expect("unterminated id string");
    rest[..end].to_string()
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
///
/// The freshly-signed binary is then executed once, cheaply, to pay macOS's
/// first-exec code-signature validation here rather than inside a measured
/// window. That validation costs ~0.3s for a debug `chm` and ~0.01s on every
/// subsequent exec, so a benchmark that skipped this would attribute an
/// install-time cost (a shipped `chm` is signed and validated once) to startup
/// latency on every trial -- which is exactly the error #79's premise came from.
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
    // Warm the signature (see the doc comment). `--version` neither creates a VM
    // nor touches a snapshot, so this is a pure exec.
    let _ = Command::new(&dst).arg("--version").output();
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

#[cfg(test)]
mod startup_parse_tests {
    use super::parse_vmm_ready;

    /// `Duration`'s `{:?}` switches unit with magnitude, so a parser that
    /// assumes seconds silently reports a 25 ms startup as 25 seconds.
    #[test]
    fn parses_every_duration_unit_debug_emits() {
        let cases = [
            (
                "[startup]    25.412ms guest released (VMM ready)",
                0.025_412,
            ),
            ("[startup]     1.204s guest released (VMM ready)", 1.204),
            (
                "[startup]    812.4µs guest released (VMM ready)",
                0.000_812_4,
            ),
            (
                "[startup]      900ns guest released (VMM ready)",
                0.000_000_9,
            ),
        ];
        for (line, want) in cases {
            let got = parse_vmm_ready(line).unwrap_or_else(|| panic!("no parse for {line}"));
            assert!((got - want).abs() < 1e-9, "{line}: got {got}, want {want}");
        }
    }

    #[test]
    fn absent_or_unrelated_stamps_yield_none() {
        assert!(parse_vmm_ready("ubuntu@ch-snap:~$ ls\n").is_none());
        // A different phase must not be mistaken for the ready stamp.
        assert!(parse_vmm_ready("[startup]    3.100ms snapshot parsed\n").is_none());
    }
}
