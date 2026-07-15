// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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
use std::process::ExitCode;

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
    /// Optional human label (provenance of the limits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl LimitsDoc {
    /// Whether any limit is set (an all-`None` document bounds nothing).
    pub fn is_bounded(&self) -> bool {
        self.max_vcpus.is_some()
            || self.max_memory_mb.is_some()
            || self.max_disk_mb.is_some()
            || self.max_wall_seconds.is_some()
            || self.max_console_mb.is_some()
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
        parts.join(" · ")
    }

    fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// The per-workspace limits file path.
fn limits_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(LIMITS_FILE)
}

/// Resolve the limits governing a run, in priority order: an explicit
/// `--limits <file>`, the `CHM_LIMITS` env binding, then the per-workspace
/// `limits.json`. Returns `(doc, source)`. A missing/unreadable source yields an
/// empty (unbounded) document, since limits are opt-in.
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
        if let Ok(doc) = serde_json::from_str::<LimitsDoc>(&raw) {
            return (doc, "env");
        }
        return (LimitsDoc::default(), "env");
    }
    match fs::read_to_string(limits_path(workspace_dir)) {
        Ok(raw) => match serde_json::from_str::<LimitsDoc>(&raw) {
            Ok(doc) => (doc, "workspace"),
            Err(_) => (LimitsDoc::default(), "workspace"),
        },
        Err(_) => (LimitsDoc::default(), "none"),
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
        [--max-wall-seconds N] [--max-console-mb N] [--label TEXT]\n    \
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
         [--max-disk-mb N] [--max-wall-seconds N] [--max-console-mb N] [--label TEXT]",
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

    #[test]
    fn resolve_is_unbounded_without_any_source() {
        let ws = env::temp_dir().join(format!("chm-limits-none-{}", process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();
        let (doc, source) = resolve_limits(&ws, None);
        assert_eq!(source, "none");
        assert!(!doc.is_bounded());
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn json_document_roundtrips() {
        let d = LimitsDoc {
            max_vcpus: Some(8),
            max_memory_mb: Some(8192),
            max_disk_mb: Some(4096),
            max_wall_seconds: Some(3600),
            max_console_mb: Some(16),
            label: Some("default".into()),
        };
        let back: LimitsDoc = serde_json::from_str(&d.to_json()).unwrap();
        assert_eq!(back, d);
    }
}
