// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Per-sandbox resource limits (M30.6).
//!
//! A declarative limits document, authored and resolved the same way the egress
//! firewall is: an explicit `--limits <file>` flag, the `CHM_LIMITS` env binding
//! the cloud runner can set, then a per-workspace `limits.json`. This module
//! *authors, inspects, and resolves* that document; enforcement lives in the run
//! loop (`imp`):
//!
//! - a **launch gate** refuses a snapshot whose vCPU / RAM shape exceeds the
//!   ceiling (a snapshot's shape is fixed, so this is admission control);
//! - a **monitor** stops the guest cleanly when its disk overlay or console
//!   output grows past the cap, so a runaway guest cannot exhaust host disk or
//!   flood the console;
//! - the **wall-clock** cap folds onto the existing max-seconds stop.
//!
//! ```text
//! chm limits show  <WORKSPACE_DIR> [--json]      inspect the effective limits
//! chm limits set   <WORKSPACE_DIR> [--max-vcpus N] [--max-memory-mb N]
//!                                  [--max-disk-mb N] [--max-wall-seconds N]
//!                                  [--max-console-mb N] [--label TEXT]
//! chm limits clear <WORKSPACE_DIR>               remove the limits (unbounded)
//! chm limits validate <FILE>                     lint a limits file
//! ```

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::{Deserialize, Serialize};

/// The per-workspace file `chm` reads to bound a sandbox's resources.
pub(crate) const LIMITS_FILE: &str = "limits.json";

/// The on-disk shape of a resource-limits document. Every field is optional; an
/// unset field means "no limit". Kept byte-compatible with the `CHM_LIMITS` env
/// document, so the same resolver consumes a flag, an env binding, or a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LimitsDoc {
    /// Maximum vCPUs the snapshot may declare (admission control).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vcpus: Option<u32>,
    /// Maximum guest RAM in MiB (admission control).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u64>,
    /// Maximum total disk-overlay growth in MiB before the guest is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_disk_mb: Option<u64>,
    /// Maximum wall-clock runtime in seconds before the guest is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_seconds: Option<u64>,
    /// Maximum console output in MiB before the guest is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_console_mb: Option<u64>,
    /// Maximum concurrent outbound NAT connections (host sockets) the guest may
    /// hold open. A runaway guest cannot exhaust host file descriptors (M30.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Maximum sustained outbound NAT throughput in kilobits per second. The NAT
    /// throttles (via TCP backpressure) rather than dropping, bounding the
    /// bandwidth a single sandbox can consume (M30.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bandwidth_kbps: Option<u64>,
    /// Optional human label (provenance of the limits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl LimitsDoc {
    /// The ceilings that apply when nothing else is configured (V4.2).
    ///
    /// A rehydrated snapshot is untrusted code, so "no configuration" must not
    /// mean "no bound". These are chosen to sit far above anything a legitimate
    /// workload does while still stopping a runaway: a guest cannot fill the
    /// host disk through its overlay, flood the host with console output, or
    /// exhaust the process file-descriptor table with NAT sockets.
    ///
    /// Deliberately **not** bounded here: wall-clock runtime (a sandbox you
    /// leave running overnight is a normal thing to want) and bandwidth
    /// (throttling by default would make the network mysteriously slow rather
    /// than visibly refused). Both remain available to configure.
    ///
    /// `CHM_LIMITS=none` opts out entirely.
    pub fn baseline() -> Self {
        Self {
            max_vcpus: Some(64),
            max_memory_mb: Some(host_ram_mb()),
            max_disk_mb: Some(64 * 1024),
            max_wall_seconds: None,
            max_console_mb: Some(1024),
            max_connections: Some(128),
            max_bandwidth_kbps: None,
            label: Some("chm baseline".to_string()),
        }
    }

    /// Whether any limit is set (an all-`None` document bounds nothing).
    pub fn is_bounded(&self) -> bool {
        self.max_vcpus.is_some()
            || self.max_memory_mb.is_some()
            || self.max_disk_mb.is_some()
            || self.max_wall_seconds.is_some()
            || self.max_console_mb.is_some()
            || self.max_connections.is_some()
            || self.max_bandwidth_kbps.is_some()
    }

    /// Reject nonsensical values (a limit of 0 would stop the guest instantly and
    /// is almost certainly a mistake; reject it so limits fail loudly on author).
    pub fn validate(&self) -> Result<(), String> {
        let checks = [
            ("max_vcpus", self.max_vcpus.map(u64::from)),
            ("max_memory_mb", self.max_memory_mb),
            ("max_disk_mb", self.max_disk_mb),
            ("max_wall_seconds", self.max_wall_seconds),
            ("max_console_mb", self.max_console_mb),
            ("max_connections", self.max_connections.map(u64::from)),
            ("max_bandwidth_kbps", self.max_bandwidth_kbps),
        ];
        for (name, value) in checks {
            if value == Some(0) {
                return Err(format!("{name} must be greater than 0 (or omitted for no limit)"));
            }
        }
        Ok(())
    }

    /// A one-line human summary for `chm limits show`.
    pub fn summary(&self) -> String {
        if !self.is_bounded() {
            return "no limits — unbounded".to_string();
        }
        let mut parts = Vec::new();
        if let Some(v) = self.max_vcpus {
            parts.push(format!("vCPUs<={v}"));
        }
        if let Some(v) = self.max_memory_mb {
            parts.push(format!("mem<={v}MiB"));
        }
        if let Some(v) = self.max_disk_mb {
            parts.push(format!("disk<={v}MiB"));
        }
        if let Some(v) = self.max_wall_seconds {
            parts.push(format!("wall<={v}s"));
        }
        if let Some(v) = self.max_console_mb {
            parts.push(format!("console<={v}MiB"));
        }
        if let Some(v) = self.max_connections {
            parts.push(format!("conns<={v}"));
        }
        if let Some(v) = self.max_bandwidth_kbps {
            parts.push(format!("bw<={v}kbps"));
        }
        parts.join(" · ")
    }

    fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Interpret a `CHM_LIMITS` value. Split out from [`resolve_limits`] so the
/// opt-out can be tested without mutating a process-global environment variable
/// that every other test in this binary reads concurrently.
fn from_env_value(raw: &str) -> (LimitsDoc, &'static str) {
    if raw.trim().eq_ignore_ascii_case("none") {
        return (LimitsDoc::default(), "opt-out");
    }
    match serde_json::from_str::<LimitsDoc>(raw) {
        Ok(doc) => (doc, "env"),
        Err(_) => (LimitsDoc::default(), "env"),
    }
}

/// Physical RAM on this host, in MiB, as the admission ceiling for guest RAM.
///
/// A snapshot needing more RAM than the host physically has cannot be mapped
/// anyway; refusing it up front turns an opaque mid-restore failure into a
/// sentence. Falls back to a permissive value if `sysctl` is unavailable, since
/// this is a guard rail, not a security boundary in its own right.
fn host_ram_mb() -> u64 {
    let out = match Command::new("/usr/sbin/sysctl").arg("-n").arg("hw.memsize").output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return 1024 * 1024,
    };
    match String::from_utf8_lossy(&out).trim().parse::<u64>() {
        Ok(bytes) if bytes > 0 => bytes / (1024 * 1024),
        _ => 1024 * 1024,
    }
}

/// The per-workspace limits file path.
fn limits_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(LIMITS_FILE)
}

/// Resolve the limits governing a run, in priority order: an explicit
/// `--limits <file>`, the `CHM_LIMITS` env binding, then the per-workspace
/// `limits.json`. Returns `(doc, source)`.
///
/// **Configuring nothing yields [`LimitsDoc::baseline`], not "unbounded"** — a
/// rehydrated snapshot is untrusted code, so the safe posture is the default
/// (V4.2). `CHM_LIMITS=none` is the documented opt-out and is the only way to
/// get a genuinely unbounded sandbox.
pub(crate) fn resolve_limits(workspace_dir: &Path, cli_override: Option<&Path>) -> (LimitsDoc, &'static str) {
    if let Some(path) = cli_override {
        if let Ok(raw) = fs::read_to_string(path)
            && let Ok(doc) = serde_json::from_str::<LimitsDoc>(&raw)
        {
            return (doc, "flag");
        }
        return (LimitsDoc::default(), "flag");
    }
    if let Ok(raw) = env::var("CHM_LIMITS") {
        return from_env_value(&raw);
    }
    match fs::read_to_string(limits_path(workspace_dir)) {
        Ok(raw) => match serde_json::from_str::<LimitsDoc>(&raw) {
            Ok(doc) => (doc, "workspace"),
            Err(_) => (LimitsDoc::default(), "workspace"),
        },
        Err(_) => (LimitsDoc::baseline(), "baseline"),
    }
}

pub(crate) fn limits_main(raw: &[String]) -> ExitCode {
    let result = match raw.first().map(String::as_str) {
        Some("show") => show(&raw[1..]),
        Some("set") => set(&raw[1..]),
        Some("clear") => clear(&raw[1..]),
        Some("validate") => validate(&raw[1..]),
        Some("-h") | Some("--help") | None => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown subcommand `{other}`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm limits: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage: chm limits <command>\n\
     \n\
     Bound a sandbox's resources so a runaway guest cannot exhaust the host.\n\
     Resolved (in priority order) from --limits <file>, the CHM_LIMITS env\n\
     binding, then a per-workspace limits.json.\n\
     \n\
     commands:\n    \
       show  <WORKSPACE_DIR> [--json]\n    \
       set   <WORKSPACE_DIR> [--max-vcpus N] [--max-memory-mb N] [--max-disk-mb N]\n                          \
        [--max-wall-seconds N] [--max-console-mb N] [--max-connections N]\n                          \
        [--max-bandwidth-kbps N] [--label TEXT]\n    \
       clear <WORKSPACE_DIR>\n    \
       validate <FILE>\n"
        .to_string()
}

fn positional(raw: &[String]) -> Option<PathBuf> {
    let mut skip_value = false;
    for a in raw {
        if skip_value {
            skip_value = false;
            continue;
        }
        if a.starts_with('-') {
            // Every limits flag takes a value except the bare help flags.
            skip_value = a != "-h" && a != "--help" && a != "--json";
            continue;
        }
        return Some(PathBuf::from(a));
    }
    None
}

fn opt_u64(raw: &[String], name: &str) -> Result<Option<u64>, String> {
    match raw.iter().position(|a| a == name) {
        Some(i) => {
            let v = raw
                .get(i + 1)
                .ok_or_else(|| format!("{name} requires a value"))?;
            let n = v
                .parse::<u64>()
                .map_err(|_| format!("{name} value {v:?} is not a non-negative integer"))?;
            Ok(Some(n))
        }
        None => Ok(None),
    }
}

fn opt_str<'a>(raw: &'a [String], name: &str) -> Option<&'a str> {
    raw.iter()
        .position(|a| a == name)
        .and_then(|i| raw.get(i + 1))
        .map(String::as_str)
}

fn show(raw: &[String]) -> Result<(), String> {
    let json = raw.iter().any(|a| a == "--json");
    let dir = positional(raw).ok_or("usage: chm limits show <WORKSPACE_DIR> [--json]")?;
    let (doc, source) = resolve_limits(&dir, None);
    if json {
        println!("{}", doc.to_json());
    } else {
        println!("{} [{}]  {}", dir.display(), source, doc.summary());
    }
    Ok(())
}

fn set(raw: &[String]) -> Result<(), String> {
    let dir = positional(raw).ok_or(
        "usage: chm limits set <WORKSPACE_DIR> [--max-vcpus N] [--max-memory-mb N] \
         [--max-disk-mb N] [--max-wall-seconds N] [--max-console-mb N] \
         [--max-connections N] [--max-bandwidth-kbps N] [--label TEXT]",
    )?;
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let doc = LimitsDoc {
        max_vcpus: opt_u64(raw, "--max-vcpus")?.map(|n| n as u32),
        max_memory_mb: opt_u64(raw, "--max-memory-mb")?,
        max_disk_mb: opt_u64(raw, "--max-disk-mb")?,
        max_wall_seconds: opt_u64(raw, "--max-wall-seconds")?,
        max_console_mb: opt_u64(raw, "--max-console-mb")?,
        max_connections: opt_u64(raw, "--max-connections")?.map(|n| n as u32),
        max_bandwidth_kbps: opt_u64(raw, "--max-bandwidth-kbps")?,
        label: opt_str(raw, "--label")
            .map(str::to_string)
            .or_else(|| Some("local".to_string())),
    };
    doc.validate()?;
    let path = limits_path(&dir);
    fs::write(&path, doc.to_json()).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!("wrote {} — {}", path.display(), doc.summary());
    Ok(())
}

fn clear(raw: &[String]) -> Result<(), String> {
    let dir = positional(raw).ok_or("usage: chm limits clear <WORKSPACE_DIR>")?;
    let path = limits_path(&dir);
    match fs::remove_file(&path) {
        Ok(()) => println!("cleared {} — resources are now unbounded", path.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!("{}: no limits set — already unbounded", dir.display());
        }
        Err(e) => return Err(format!("remove {}: {e}", path.display())),
    }
    Ok(())
}

fn validate(raw: &[String]) -> Result<(), String> {
    let file = positional(raw).ok_or("usage: chm limits validate <FILE>")?;
    let rawtext = fs::read_to_string(&file).map_err(|e| format!("read {}: {e}", file.display()))?;
    let doc: LimitsDoc =
        serde_json::from_str(&rawtext).map_err(|e| format!("{} is not a valid limits file: {e}", file.display()))?;
    doc.validate()?;
    println!("{} is valid — {}", file.display(), doc.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn is_bounded_reflects_any_limit() {
        assert!(!LimitsDoc::default().is_bounded());
        let d = LimitsDoc {
            max_disk_mb: Some(100),
            ..Default::default()
        };
        assert!(d.is_bounded());
    }

    #[test]
    fn validate_rejects_zero_limits() {
        let d = LimitsDoc {
            max_console_mb: Some(0),
            ..Default::default()
        };
        d.validate().expect_err("a zero limit must be rejected");
        let ok = LimitsDoc {
            max_console_mb: Some(16),
            ..Default::default()
        };
        ok.validate().expect("a positive limit is valid");
    }

    #[test]
    fn summary_lists_the_set_limits() {
        let d = LimitsDoc {
            max_vcpus: Some(4),
            max_disk_mb: Some(2048),
            ..Default::default()
        };
        let s = d.summary();
        assert!(s.contains("vCPUs<=4"), "{s}");
        assert!(s.contains("disk<=2048MiB"), "{s}");
        assert_eq!(LimitsDoc::default().summary(), "no limits — unbounded");
    }

    #[test]
    fn resolve_reads_the_workspace_file() {
        let ws = env::temp_dir().join(format!("chm-limits-{}", process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();
        fs::write(
            limits_path(&ws),
            r#"{"max_disk_mb":4096,"max_console_mb":16,"label":"local"}"#,
        )
        .unwrap();
        let (doc, source) = resolve_limits(&ws, None);
        assert_eq!(source, "workspace");
        assert_eq!(doc.max_disk_mb, Some(4096));
        assert_eq!(doc.max_console_mb, Some(16));
        let _ = fs::remove_dir_all(&ws);
    }

    /// V4.2: configuring nothing must not mean bounding nothing. A rehydrated
    /// snapshot is untrusted code, so the safe posture has to be what you get
    /// when you type `chm run <dir>` and nothing else.
    #[test]
    fn resolve_falls_back_to_the_baseline_not_to_unbounded() {
        let ws = env::temp_dir().join(format!("chm-limits-none-{}", process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();
        let (doc, source) = resolve_limits(&ws, None);
        assert_eq!(source, "baseline");
        assert!(doc.is_bounded(), "an unconfigured workspace must still be bounded");
        let _ = fs::remove_dir_all(&ws);
    }

    /// The baseline has to be a ceiling, not a policy: it must not refuse any
    /// snapshot we actually ship, or it would break the thing it protects.
    #[test]
    fn baseline_admits_a_real_capture_and_bounds_a_runaway() {
        let b = LimitsDoc::baseline();
        b.validate().expect("baseline must be self-consistent");
        assert!(b.max_vcpus.unwrap() >= 8, "would refuse an ordinary SMP snapshot");
        assert!(b.max_memory_mb.unwrap() >= 1024, "would refuse a 1 GiB guest");
        assert!(b.max_disk_mb.is_some(), "overlay growth must be bounded");
        assert!(b.max_console_mb.is_some(), "console flooding must be bounded");
        assert!(b.max_connections.is_some(), "socket exhaustion must be bounded");
        // Deliberately unset: bounding these by default would degrade rather
        // than protect. See LimitsDoc::baseline.
        assert!(b.max_wall_seconds.is_none());
        assert!(b.max_bandwidth_kbps.is_none());
    }

    #[test]
    fn chm_limits_none_is_the_documented_opt_out() {
        for raw in ["none", "None", "  NONE  "] {
            let (doc, source) = from_env_value(raw);
            assert_eq!(source, "opt-out", "{raw:?} should opt out");
            assert!(!doc.is_bounded());
        }
        let (doc, source) = from_env_value(r#"{"max_console_mb":8}"#);
        assert_eq!(source, "env");
        assert_eq!(doc.max_console_mb, Some(8));
        // Malformed must not silently become the opt-out.
        let (_, source) = from_env_value("{not json");
        assert_eq!(source, "env");
    }

    #[test]
    fn json_document_roundtrips() {
        let d = LimitsDoc {
            max_vcpus: Some(8),
            max_memory_mb: Some(8192),
            max_disk_mb: Some(4096),
            max_wall_seconds: Some(3600),
            max_console_mb: Some(16),
            max_connections: Some(256),
            max_bandwidth_kbps: Some(10_000),
            label: Some("default".into()),
        };
        let back: LimitsDoc = serde_json::from_str(&d.to_json()).unwrap();
        assert_eq!(back, d);
    }
}
