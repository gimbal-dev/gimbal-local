// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Durable, append-only audit trail (M29).
//!
//! A sandbox's security-relevant lifecycle — when it started and stopped, and
//! every outbound flow the egress policy *denied* — is recorded to a per-workspace
//! `audit.jsonl` so an operator can answer "what did this sandbox try to do?"
//! after the fact, independent of the console scrollback (which the guest can
//! flood). Each line is a self-contained JSON object:
//!
//! ```text
//! {"event":"session-start","ts":"2026-07-16T…Z","ts_ms":…,"mode":"resume",…}
//! {"event":"egress-deny","ts":"…","domain":"tcp","target":"1.2.3.4:443",…}
//! {"event":"session-stop","ts":"…","outcome":"powered-off","duration_s":12}
//! ```
//!
//! The log is append-only and best-effort: an audit write must never crash or
//! stall the run, so a failure is warned once and the session continues. Writes
//! use `O_APPEND`, so concurrent records from the vCPU thread and the net-service
//! thread interleave safely without a shared lock.
//!
//! ```text
//! chm audit show <WORKSPACE_DIR> [--json]   read the trail back
//! ```

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

/// The per-workspace audit file.
pub(crate) const AUDIT_FILE: &str = "audit.jsonl";

/// A handle to a workspace's audit trail. Cheap to clone (shares one inner), so
/// it can be handed to the net-service thread as well as the main run loop. A
/// `disabled()` handle drops every record (used where no workspace exists).
#[derive(Clone)]
pub(crate) struct AuditLog {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    path: PathBuf,
    /// Set once we have warned about a write failure, so a broken audit sink does
    /// not spam the console every record.
    warned: AtomicBool,
}

impl AuditLog {
    /// Open (or lazily create on first write) the audit trail for `workspace_dir`.
    pub(crate) fn open(workspace_dir: &Path) -> Self {
        Self {
            inner: Some(Arc::new(Inner {
                path: workspace_dir.join(AUDIT_FILE),
                warned: AtomicBool::new(false),
            })),
        }
    }

    /// A no-op handle that records nothing.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self { inner: None }
    }

    /// Append one record: `event` plus its `fields`, stamped with the wall-clock
    /// time. Best-effort; a write error is warned at most once.
    fn record(&self, event: &str, mut fields: Map<String, Value>) {
        let Some(inner) = &self.inner else {
            return;
        };
        let ms = now_ms();
        // Insert in a fixed leading order; serde_json::Map keeps keys sorted, so
        // the exact on-disk order is deterministic regardless.
        fields.insert("event".into(), json!(event));
        fields.insert("ts".into(), json!(utc_rfc3339(ms)));
        fields.insert("ts_ms".into(), json!(ms));
        let mut line = Value::Object(fields).to_string();
        line.push('\n');
        match OpenOptions::new().create(true).append(true).open(&inner.path) {
            Ok(mut f) => {
                if f.write_all(line.as_bytes()).is_err() && !inner.warned.swap(true, Ordering::Relaxed)
                {
                    eprintln!("chm: warning: audit write to {} failed", inner.path.display());
                }
            }
            Err(_) => {
                if !inner.warned.swap(true, Ordering::Relaxed) {
                    eprintln!("chm: warning: cannot open audit log {}", inner.path.display());
                }
            }
        }
    }

    /// Record the start of a session.
    pub(crate) fn session_start(
        &self,
        mode: &str,
        vcpus: usize,
        ram_mb: u64,
        limits_summary: &str,
        egress_label: &str,
    ) {
        let mut m = Map::new();
        m.insert("mode".into(), json!(mode));
        m.insert("vcpus".into(), json!(vcpus));
        m.insert("ram_mb".into(), json!(ram_mb));
        m.insert("limits".into(), json!(limits_summary));
        m.insert("egress".into(), json!(egress_label));
        self.record("session-start", m);
    }

    /// Record the end of a session and how long it ran.
    pub(crate) fn session_stop(&self, outcome: &str, duration_s: u64) {
        let mut m = Map::new();
        m.insert("outcome".into(), json!(outcome));
        m.insert("duration_s".into(), json!(duration_s));
        self.record("session-stop", m);
    }

    /// Record a denied outbound flow (the security-relevant egress signal).
    pub(crate) fn egress_deny(&self, domain: &str, target: &str, rule: &str, policy: &str) {
        let mut m = Map::new();
        m.insert("domain".into(), json!(domain));
        m.insert("target".into(), json!(target));
        m.insert("rule".into(), json!(rule));
        m.insert("policy".into(), json!(policy));
        self.record("egress-deny", m);
    }

    /// Record a bundle-verification decision (signature / checksum), pass or fail.
    pub(crate) fn verify(&self, subject: &str, ok: bool, detail: &str) {
        let mut m = Map::new();
        m.insert("subject".into(), json!(subject));
        m.insert("result".into(), json!(if ok { "ok" } else { "fail" }));
        m.insert("detail".into(), json!(detail));
        self.record("verify", m);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format a unix-epoch-millis instant as a UTC RFC 3339 string, without pulling
/// in a date library. Uses Howard Hinnant's `civil_from_days` algorithm.
fn utc_rfc3339(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

pub(crate) fn audit_main(raw: &[String]) -> ExitCode {
    let result = match raw.first().map(String::as_str) {
        Some("show") => show(&raw[1..]),
        Some("-h") | Some("--help") | None => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown subcommand `{other}`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm audit: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage: chm audit show <WORKSPACE_DIR> [--json]\n\
     \n\
     Read a sandbox's append-only audit trail (session start/stop, denied\n\
     egress, and bundle-verification decisions). With --json, print the raw\n\
     JSON lines; otherwise print a compact one-line-per-record summary.\n"
        .to_string()
}

fn show(raw: &[String]) -> Result<(), String> {
    let json = raw.iter().any(|a| a == "--json");
    let dir = raw
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .ok_or("usage: chm audit show <WORKSPACE_DIR> [--json]")?;
    let path = dir.join(AUDIT_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!("{}: no audit trail yet", dir.display());
            return Ok(());
        }
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if json {
            println!("{line}");
        } else {
            println!("{}", summarize(line));
        }
    }
    Ok(())
}

/// Render one JSON record as a compact human line for `chm audit show`.
fn summarize(line: &str) -> String {
    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };
    let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let ts = s("ts");
    match m.get("event").and_then(Value::as_str).unwrap_or("") {
        "session-start" => format!(
            "{ts}  session-start   mode={} vcpus={} ram={}MiB limits=[{}] egress=[{}]",
            s("mode"),
            m.get("vcpus").and_then(Value::as_u64).unwrap_or(0),
            m.get("ram_mb").and_then(Value::as_u64).unwrap_or(0),
            s("limits"),
            s("egress"),
        ),
        "session-stop" => format!(
            "{ts}  session-stop    outcome={} duration={}s",
            s("outcome"),
            m.get("duration_s").and_then(Value::as_u64).unwrap_or(0),
        ),
        "egress-deny" => format!(
            "{ts}  egress-DENY     {} {} ({}) policy={}",
            s("domain"),
            s("target"),
            s("rule"),
            s("policy"),
        ),
        "verify" => format!(
            "{ts}  verify          {} {} — {}",
            s("subject"),
            s("result"),
            s("detail"),
        ),
        other => format!("{ts}  {other}  {line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::process;

    #[test]
    fn utc_rfc3339_formats_known_instants() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00.000Z");
        // 2026-07-16T09:00:00.000Z = 1_784_192_400_000 ms.
        assert_eq!(utc_rfc3339(1_784_192_400_000), "2026-07-16T09:00:00.000Z");
        // Millisecond component is preserved.
        assert_eq!(utc_rfc3339(1_500), "1970-01-01T00:00:01.500Z");
    }

    #[test]
    fn records_are_appended_as_jsonl_and_read_back() {
        let ws = env::temp_dir().join(format!("chm-audit-{}", process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();

        let audit = AuditLog::open(&ws);
        audit.session_start("resume", 2, 2048, "disk<=8192MiB", "allow-all");
        audit.egress_deny("tcp", "1.2.3.4:443", "connection-limit", "deny:sha256");
        audit.session_stop("powered-off", 12);

        let text = fs::read_to_string(ws.join(AUDIT_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "one JSON line per record");
        // Each line is a valid JSON object carrying its event + timestamp.
        for line in &lines {
            let v: Value = serde_json::from_str(line).expect("valid JSON line");
            assert!(v.get("event").is_some());
            assert!(v.get("ts").is_some());
            assert!(v.get("ts_ms").is_some());
        }
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "session-start");
        assert_eq!(first["vcpus"], 2);
        let deny: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(deny["event"], "egress-deny");
        assert_eq!(deny["target"], "1.2.3.4:443");

        // A disabled handle records nothing.
        let none = AuditLog::disabled();
        none.session_stop("x", 0);

        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn summarize_renders_a_compact_line() {
        let line = r#"{"event":"egress-deny","ts":"2026-07-16T09:00:00.000Z","domain":"tcp","target":"1.2.3.4:443","rule":"deny","policy":"p"}"#;
        let s = summarize(line);
        assert!(s.contains("egress-DENY"), "{s}");
        assert!(s.contains("1.2.3.4:443"), "{s}");
    }
}
