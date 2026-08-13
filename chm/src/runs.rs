// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! A registry of running guests, so anything can ask what this machine is
//! running (#225).
//!
//! Every entry point that creates an HVF VM is its own process — `hv_vm_create`
//! is process-global, so that is a platform constraint rather than a choice.
//! The consequence is that no single process is in a position to answer *"what
//! is running?"*: the daemon knows only its own guest, the app knows only the
//! ones it happens to have spawned in this launch, and a `chm create` started
//! from a terminal is invisible to both. The app's own cold-boot feature fell
//! straight into that hole — it launched a guest and then told the user they
//! had no sandboxes.
//!
//! So the fact is recorded by the only process in a position to know it: the
//! one running the guest. Each writes a record into a well-known directory and
//! removes it on the way out. Anything that wants the answer reads the
//! directory.
//!
//! # Liveness is a lock, not a PID
//!
//! The obvious design is to record a PID and have readers check it with
//! `kill(pid, 0)`. That is what `chm connect`'s session lock does and it has a
//! real flaw: a record left behind by a `SIGKILL`ed process names a PID the
//! kernel is free to hand to something else, and then the registry reports a
//! guest that is really somebody's text editor. Here that would put a Stop
//! button in front of a user and point it at an unrelated process.
//!
//! Instead the writer holds an exclusive `flock` on its own record for the
//! lifetime of the run. The kernel releases it when the process dies **however**
//! it dies, so there is no stale-lock window and no PID-reuse hazard: a record
//! that can be locked is a record whose writer is gone.
//!
//! Readers test with a *shared* lock rather than an exclusive one, and that
//! detail is load-bearing. Two readers taking `LOCK_EX` in turn would each
//! momentarily hold the file, so one would see the other's lock and report a
//! dead run as live. Shared locks do not exclude each other, and they still
//! conflict with the writer's exclusive one, so concurrent readers agree.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

/// What kind of guest a record describes.
///
/// Recorded rather than inferred because the entry points are not
/// interchangeable to a reader: a cold boot has no snapshot to go back to, and
/// a `connect` session is attached to a sandbox the daemon also knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `chm create` — a cold boot from a kernel and an image directory.
    Cold,
    /// `chm run` — a snapshot rehydrated directly, not through the daemon.
    Run,
    /// `chm connect` — an interactive session against a daemon-managed sandbox.
    Connect,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Run => "run",
            Self::Connect => "connect",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "cold" => Some(Self::Cold),
            "run" => Some(Self::Run),
            "connect" => Some(Self::Connect),
            _ => None,
        }
    }
}

/// One running guest, as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub pid: u32,
    pub kind: Kind,
    /// A short name for the guest — the image or snapshot directory's own name.
    pub label: String,
    /// Where it came from, in full, so a reader can tell two runs of similarly
    /// named images apart.
    pub source: String,
    pub started_at_ms: u64,
    pub vcpus: u32,
    pub memory_mib: u64,
}

impl Record {
    /// Serialize as JSON.
    ///
    /// Hand-rolled to match the rest of `chm`, which carries no serde dependency
    /// in its own crate. Every string is escaped through [`json_escape`] rather
    /// than interpolated, because a path is user input and an image called
    /// `my"image` would otherwise emit a document nothing can parse.
    fn to_json(&self) -> String {
        format!(
            "{{\"pid\":{},\"kind\":\"{}\",\"label\":\"{}\",\"source\":\"{}\",\
             \"started_at_ms\":{},\"vcpus\":{},\"memory_mib\":{}}}",
            self.pid,
            self.kind.as_str(),
            json_escape(&self.label),
            json_escape(&self.source),
            self.started_at_ms,
            self.vcpus,
            self.memory_mib,
        )
    }

    /// Read a record back.
    ///
    /// Deliberately tolerant of unknown fields and strict about the ones it
    /// needs: a newer `chm` may add a field, and an older reader dropping the
    /// whole record for that would report a running guest as absent — which is
    /// the exact failure this module exists to remove.
    fn from_json(s: &str) -> Option<Self> {
        Some(Self {
            pid: json_number(s, "pid")? as u32,
            kind: Kind::parse(&json_string(s, "kind")?)?,
            label: json_string(s, "label")?,
            source: json_string(s, "source")?,
            started_at_ms: json_number(s, "started_at_ms")?,
            vcpus: json_number(s, "vcpus").unwrap_or(0) as u32,
            memory_mib: json_number(s, "memory_mib").unwrap_or(0),
        })
    }
}

/// The registry directory.
///
/// `CHM_RUN_DIR` exists so a second install, or a harness driving real guests,
/// can keep its own registry. It is read once at the CLI boundary; everything
/// below takes the directory as an argument, so the tests never touch a
/// process-global.
pub fn registry_dir() -> PathBuf {
    if let Some(v) = env::var_os("CHM_RUN_DIR") {
        return PathBuf::from(v);
    }
    let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".gimbal").join("runs")
}

/// A registration held for the lifetime of a running guest.
///
/// Dropping it removes the record. The `flock` makes that removal
/// belt-and-braces rather than load-bearing: a process that is killed outright
/// never runs `Drop`, and the lock still goes away.
pub struct Registration {
    path: PathBuf,
    // Kept alive purely to hold the lock. The kernel drops it with the fd.
    _file: File,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Announce a running guest.
///
/// Returns `Ok(None)` when the registry cannot be written — a read-only home,
/// say. Failing to register must never stop a guest from running: the registry
/// is how a user *sees* their sandboxes, not how they get one, and refusing to
/// boot because a bookkeeping file could not be created would trade a real
/// capability for a cosmetic one.
pub fn register(
    kind: Kind,
    label: &str,
    source: &str,
    vcpus: u32,
    memory_mib: u64,
) -> io::Result<Option<Registration>> {
    register_in(&registry_dir(), kind, label, source, vcpus, memory_mib)
}

/// [`register`], against a named directory.
///
/// The directory is a parameter rather than read from the environment because
/// the environment is process-global: two tests setting `CHM_RUN_DIR` in
/// parallel threads see each other's registry, and the failure looks like a bug
/// in the locking rather than in the harness. Injecting it also makes the
/// reaping behaviour testable without a real guest.
pub fn register_in(
    dir: &Path,
    kind: Kind,
    label: &str,
    source: &str,
    vcpus: u32,
    memory_mib: u64,
) -> io::Result<Option<Registration>> {
    fs::create_dir_all(dir)?;
    let pid = process::id();
    let path = dir.join(format!("run-{pid}.json"));

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)?;

    // Exclusive and non-blocking: if something else genuinely holds this
    // filename's lock we are looking at a live PID collision, which cannot
    // happen for our own PID, so treat it as a registry we should not touch.
    if !take_lock(&file, libc::LOCK_EX) {
        return Ok(None);
    }

    let record = Record {
        pid,
        kind,
        label: label.to_string(),
        source: source.to_string(),
        started_at_ms: now_ms(),
        vcpus,
        memory_mib,
    };
    let mut f = &file;
    f.write_all(record.to_json().as_bytes())?;
    f.flush()?;

    Ok(Some(Registration { path, _file: file }))
}

/// Every guest running on this machine, newest last.
///
/// Reaps records whose writer is gone as it goes, so the directory does not
/// accumulate. Reaping on read rather than on a timer means the cleanup happens
/// exactly when somebody cares about the answer.
pub fn list() -> Vec<Record> {
    list_in(&registry_dir())
}

/// [`list`], against a named directory.
pub fn list_in(dir: &Path) -> Vec<Record> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut live = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_record = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("run-") && n.ends_with(".json"));
        if !is_record {
            continue;
        }

        match read_if_live(&path) {
            Some(record) => live.push(record),
            // Writer gone. Removing it here is what keeps a machine that has
            // been rebooted, or a guest that was SIGKILLed, from reporting
            // guests that do not exist.
            None => {
                let _ = fs::remove_file(&path);
            }
        }
    }

    live.sort_by_key(|r| (r.started_at_ms, r.pid));
    live
}

/// Read a record if — and only if — its writer is still alive.
///
/// A shared lock is the liveness test: it conflicts with the writer's exclusive
/// lock but not with another reader's, so two readers running at once agree
/// rather than each reporting the other's probe as a live guest.
fn read_if_live(path: &Path) -> Option<Record> {
    let file = File::open(path).ok()?;
    if take_lock(&file, libc::LOCK_SH) {
        // We got the lock, so nobody is holding it: the writer has gone.
        unlock(&file);
        return None;
    }
    let mut body = String::new();
    let mut f = File::open(path).ok()?;
    f.read_to_string(&mut body).ok()?;
    Record::from_json(&body)
}

fn take_lock(file: &File, op: i32) -> bool {
    // SAFETY: `file` owns a valid open descriptor for the duration of the call,
    // and `flock` only reads it.
    unsafe { libc::flock(file.as_raw_fd(), op | libc::LOCK_NB) == 0 }
}

fn unlock(file: &File) {
    // SAFETY: as above.
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The last path component, for a label. Falls back to the whole string so a
/// label is never empty — an unnamed row in a list is worse than an ugly one.
pub fn label_for(source: &Path) -> String {
    source
        .file_name()
        .and_then(|n| n.to_str())
        .map_or_else(|| source.display().to_string(), str::to_string)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Pull a string field out of a flat JSON object, honouring the escapes
/// [`json_escape`] emits. Only has to handle documents this module writes.
fn json_string(s: &str, key: &str) -> Option<String> {
    let at = s.find(&format!("\"{key}\":\""))? + key.len() + 4;
    let mut out = String::new();
    let mut chars = s[at..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let n = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(n)?);
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

fn json_number(s: &str, key: &str) -> Option<u64> {
    let at = s.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = &s[at..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// `chm ps` — say what is running.
pub fn ps_main(raw: &[String]) -> process::ExitCode {
    let mut json = false;
    for a in raw {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage());
                return process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("chm ps: unknown option {other}\n\n{}", usage());
                return process::ExitCode::FAILURE;
            }
        }
    }

    let runs = list();

    if json {
        let body: Vec<String> = runs.iter().map(Record::to_json).collect();
        println!("{{\"runs\":[{}]}}", body.join(","));
        return process::ExitCode::SUCCESS;
    }

    if runs.is_empty() {
        println!("No guests running.");
        println!("A guest started by `chm serve` is reported by `chm ctl status`.");
        return process::ExitCode::SUCCESS;
    }

    println!(
        "{:<8} {:<8} {:<24} {:<10} STARTED",
        "PID", "KIND", "NAME", "SIZE"
    );
    for r in &runs {
        println!(
            "{:<8} {:<8} {:<24} {:<10} {}",
            r.pid,
            r.kind.as_str(),
            truncate(&r.label, 24),
            format!("{}c/{}M", r.vcpus, r.memory_mib),
            relative(r.started_at_ms),
        );
    }
    println!("\nStop one with `kill <PID>`; a guest with a writable disk is better");
    println!("stopped from its own console, because a signal is a power cut.");
    process::ExitCode::SUCCESS
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

fn relative(then_ms: u64) -> String {
    let secs = now_ms().saturating_sub(then_ms) / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

pub fn usage() -> String {
    "chm ps — what is running on this machine\n\
     \n\
     USAGE:\n    \
         chm ps [--json]\n\
     \n\
     Every guest is its own process, because Hypervisor.framework allows one VM\n\
     per process. So no single process can answer this on its own: each one\n\
     records itself while it runs, and this reads those records back. A record\n\
     whose process has gone is removed as it is read, so what you see is what is\n\
     running now.\n\
     \n\
     A guest started by `chm serve` is the daemon's own, and is reported by\n\
     `chm ctl status` instead.\n\
     \n\
     OPTIONS:\n    \
         --json   Machine-readable, for the app.\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private registry directory per test.
    ///
    /// Named for the test rather than shared, because these run in parallel
    /// threads of one process and a shared directory would have them reaping
    /// each other's records.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("chm-runs-{}-{}", name, process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn list(&self) -> Vec<Record> {
            list_in(&self.dir)
        }

        fn register(&self, kind: Kind, label: &str) -> Registration {
            register_in(&self.dir, kind, label, &format!("/src/{label}"), 2, 512)
                .unwrap()
                .expect("registration")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_registered_run_is_listed_and_disappears_when_it_ends() {
        let s = Scratch::new("lifecycle");
        assert!(s.list().is_empty(), "registry did not start empty");

        let reg = s.register(Kind::Cold, "alpine");
        let runs = s.list();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].kind, Kind::Cold);
        assert_eq!(runs[0].label, "alpine");
        assert_eq!(runs[0].source, "/src/alpine");
        assert_eq!(runs[0].vcpus, 2);
        assert_eq!(runs[0].memory_mib, 512);
        assert_eq!(runs[0].pid, process::id());

        drop(reg);
        assert!(s.list().is_empty(), "record outlived its run");
    }

    /// The whole point of the lock: a process that dies without running `Drop`
    /// still stops being reported. Simulated by writing a record by hand — no
    /// lock is ever taken on it, which is exactly the state a `SIGKILL` leaves.
    #[test]
    fn a_record_nobody_holds_is_reaped_rather_than_reported() {
        let s = Scratch::new("orphan");
        let orphan = s.dir.join("run-999999.json");
        fs::write(
            &orphan,
            "{\"pid\":999999,\"kind\":\"cold\",\"label\":\"ghost\",\"source\":\"/x\",\
             \"started_at_ms\":1,\"vcpus\":1,\"memory_mib\":1}",
        )
        .unwrap();

        assert!(
            s.list().is_empty(),
            "an unheld record was reported as running"
        );
        assert!(!orphan.exists(), "an unheld record was left on disk");
    }

    /// A stale record naming a PID the kernel has since reused would pass a
    /// `kill(pid, 0)` liveness check and report a guest that is really some
    /// other program. The lock cannot be fooled that way, and this is the test
    /// that says so: PID 1 is always alive and never ours.
    #[test]
    fn a_reused_pid_does_not_resurrect_a_dead_record() {
        let s = Scratch::new("pidreuse");
        let stale = s.dir.join("run-1.json");
        fs::write(
            &stale,
            "{\"pid\":1,\"kind\":\"cold\",\"label\":\"launchd\",\"source\":\"/x\",\
             \"started_at_ms\":1,\"vcpus\":1,\"memory_mib\":1}",
        )
        .unwrap();
        // A PID-based liveness check would call this record live. `kill(1, 0)`
        // returns EPERM rather than 0 for a process we do not own, which is
        // exactly why the app's own check reads `== 0 || errno == EPERM`.
        let pid_check_says_alive =
            unsafe { libc::kill(1, 0) == 0 || *libc::__error() == libc::EPERM };
        assert!(
            pid_check_says_alive,
            "PID 1 should look alive to a PID check"
        );

        assert!(
            s.list().is_empty(),
            "a record naming a live but unrelated PID was reported as a guest"
        );
    }

    /// Reading must not itself look like a run. If the liveness probe took an
    /// exclusive lock, a second reader arriving during the first one's probe
    /// would find the file locked and report a dead run as live.
    #[test]
    fn two_readers_at_once_agree_that_a_dead_run_is_dead() {
        let s = Scratch::new("readers");
        let orphan = s.dir.join("run-424242.json");
        let body = "{\"pid\":424242,\"kind\":\"run\",\"label\":\"g\",\"source\":\"/x\",\
                    \"started_at_ms\":1,\"vcpus\":1,\"memory_mib\":1}";

        // Hold a reader's shared lock open across a second reader's probe,
        // which is the race an exclusive probe would lose.
        fs::write(&orphan, body).unwrap();
        let first = File::open(&orphan).unwrap();
        assert!(
            take_lock(&first, libc::LOCK_SH),
            "first reader could not probe"
        );
        assert!(
            read_if_live(&orphan).is_none(),
            "a second reader saw the first reader's probe as a live guest"
        );
        unlock(&first);
    }

    #[test]
    fn a_live_run_is_not_reaped_by_a_reader() {
        let s = Scratch::new("survive");
        let reg = s.register(Kind::Connect, "graviton-2");
        for _ in 0..3 {
            assert_eq!(s.list().len(), 1, "a reader reaped a live run");
        }
        assert_eq!(
            fs::read_dir(&s.dir).unwrap().count(),
            1,
            "a reader deleted a live run's record"
        );
        drop(reg);
    }

    /// A path is user input. An image directory called `my"image` would emit a
    /// document nothing could parse, and the run would vanish from the app.
    #[test]
    fn a_hostile_label_survives_a_round_trip() {
        let hostile = "we\"ird\\path\nwith\ttabs";
        let r = Record {
            pid: 7,
            kind: Kind::Cold,
            label: hostile.to_string(),
            source: "/a/b\"c".to_string(),
            started_at_ms: 42,
            vcpus: 1,
            memory_mib: 8,
        };
        let back = Record::from_json(&r.to_json()).expect("round trip");
        assert_eq!(back, r);
    }

    /// Every command that starts a guest registers it.
    ///
    /// The three lifecycle tests above assert an *outcome*, and an outcome test
    /// structurally cannot see a call site that no longer exists: delete the
    /// binding in `create.rs` and every one of them stays green while `chm ps`
    /// goes blind. That has cost this repo real time three times (V9.5c, V9.11a,
    /// #222), so the call sites are read from the source directly.
    ///
    /// The needles are assembled from parts because a literal needle matches its
    /// own assertion text — the exact way the #222 guard was written and failed
    /// to fire.
    #[test]
    fn every_command_that_starts_a_guest_registers_the_run() {
        let call = format!("_{} = ", "registration");
        for (what, src) in [
            ("chm create", include_str!("create.rs")),
            ("chm run and chm connect", include_str!("imp.rs")),
        ] {
            assert!(
                src.contains(&call),
                "{what} no longer registers its run, so it is invisible to chm ps"
            );
        }
        // The binding must outlive the guest: dropping it at the end of the
        // statement removes the record while the guest is still running.
        assert!(
            !include_str!("create.rs").contains(&format!("_ = {}::register(", "runs")),
            "chm create drops its registration immediately, so the run vanishes at once"
        );
    }

    /// A label cannot impersonate a later field.
    ///
    /// The reader finds a key by scanning for the *first* `"key":`, and `label`
    /// is written before `source`, `vcpus` and `memory_mib` — so on the face of
    /// it a directory named to look like JSON could shadow all three. It cannot,
    /// and the reason is worth an assertion rather than a comment: escaping `"`
    /// as `\"` means the closing quote of a fake key is never a bare `"`, so the
    /// needle can never match inside a value. That is a property of the escaper,
    /// so it is asserted where a change to the escaper will break it. A label is
    /// derived from a directory name, which an image we did not build supplies.
    #[test]
    fn a_label_shaped_like_json_cannot_shadow_a_later_field() {
        let r = Record {
            pid: 9,
            kind: Kind::Cold,
            label: "a\",\"source\":\"/etc/passwd\",\"vcpus\":99,\"memory_mib\":1".to_string(),
            source: "/real".to_string(),
            started_at_ms: 3,
            vcpus: 2,
            memory_mib: 512,
        };
        let back = Record::from_json(&r.to_json()).expect("round trip");
        assert_eq!(back.source, "/real", "a label impersonated the source");
        assert_eq!(back.vcpus, 2, "a label impersonated the vcpu count");
        assert_eq!(back.memory_mib, 512, "a label impersonated the memory size");
        assert_eq!(back.label, r.label, "the label itself did not survive");
    }

    /// An older reader meeting a newer writer must keep the run visible. Losing
    /// the record over an unrecognised field would reintroduce exactly the bug
    /// this module removes.
    #[test]
    fn an_unknown_field_does_not_hide_a_run() {
        let forward = "{\"pid\":5,\"kind\":\"cold\",\"label\":\"a\",\"source\":\"/s\",\
                       \"started_at_ms\":9,\"vcpus\":2,\"memory_mib\":64,\"future\":\"x\"}";
        let r = Record::from_json(forward).expect("tolerant of unknown fields");
        assert_eq!(r.label, "a");
        assert_eq!(r.vcpus, 2);
    }

    /// A kind we do not understand is a run we cannot describe, so it is
    /// refused rather than shown as something it is not.
    #[test]
    fn an_unknown_kind_is_refused_rather_than_guessed() {
        let odd = "{\"pid\":5,\"kind\":\"teleport\",\"label\":\"a\",\"source\":\"/s\",\
                   \"started_at_ms\":9,\"vcpus\":1,\"memory_mib\":1}";
        assert!(Record::from_json(odd).is_none());
    }

    /// Oldest first, so a list read twice does not reorder itself under the
    /// reader. `read_dir` has no defined order, so this has to be imposed.
    #[test]
    fn runs_are_listed_oldest_first() {
        let mut rs = vec![
            rec(101, 3000, "c"),
            rec(102, 1000, "a"),
            rec(103, 2000, "b"),
        ];
        rs.sort_by_key(|r| (r.started_at_ms, r.pid));
        let order: Vec<&str> = rs.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(order, ["a", "b", "c"]);
    }

    fn rec(pid: u32, at: u64, label: &str) -> Record {
        Record {
            pid,
            kind: Kind::Cold,
            label: label.to_string(),
            source: format!("/{label}"),
            started_at_ms: at,
            vcpus: 1,
            memory_mib: 1,
        }
    }

    #[test]
    fn label_is_the_directory_name() {
        assert_eq!(label_for(Path::new("/a/b/alpine")), "alpine");
        assert_eq!(label_for(Path::new("alpine")), "alpine");
    }

    #[test]
    fn ps_help_names_the_daemon_as_the_one_thing_it_does_not_cover() {
        let u = usage();
        assert!(
            u.contains("chm ctl status"),
            "help does not point at the daemon"
        );
        assert!(u.contains("--json"));
    }
}
