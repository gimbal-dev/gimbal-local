// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Durable, append-only audit trail (M29, extended in V6.3).
//!
//! A sandbox's security-relevant lifecycle — when it started and stopped, and
//! every outbound flow the egress policy decided on — is recorded to a
//! per-workspace `audit.jsonl` so an operator can answer "what did this sandbox
//! do?" after the fact, independent of the console scrollback (which the guest
//! can flood). Each line is a self-contained JSON object:
//!
//! ```text
//! {"event":"session-start","ts":"2026-07-16T…Z","ts_ms":…,"mode":"resume",…}
//! {"event":"egress-allow","ts":"…","domain":"tcp","target":"140.82.121.6:443",…}
//! {"event":"egress-deny","ts":"…","domain":"tcp","target":"1.2.3.4:443",…}
//! {"event":"egress-summary","ts":"…","allowed":347,"denied":2,"truncated":false,…}
//! {"event":"session-stop","ts":"…","outcome":"powered-off","duration_s":12}
//! ```
//!
//! ## Why allows are recorded, not just denials
//!
//! Until V6.3 this trail held denials only. That is the more *interesting*
//! half, but it is not the half that answers the question people actually ask,
//! and the asymmetry is dangerous in a specific way: a sandbox that reached two
//! hundred hosts, all permitted, produced an empty trail — indistinguishable
//! from a sandbox that made no outbound connection at all. An empty list reads
//! as "nothing happened", so the record was most misleading exactly when the
//! most had happened.
//!
//! Allows are unbounded where denials are naturally rare, so they are recorded
//! by *distinct flow* rather than per packet, capped at [`MAX_DISTINCT_FLOWS`],
//! and totalled in an `egress-summary` at session end. When the cap is hit the
//! summary says `truncated: true` — an incomplete record that says so is usable,
//! one that silently stops is not.
//!
//! The log is append-only and best-effort: an audit write must never crash or
//! stall the run, so a failure is warned once and the session continues. Writes
//! use `O_APPEND`, so concurrent records from the vCPU thread and the net-service
//! thread interleave safely without a shared lock.
//!
//! ```text
//! chm audit show <WORKSPACE_DIR> [--json]   read the trail back
//! ```

use std::collections::HashSet;
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
/// default (`disabled`) handle drops every record — used where no workspace
/// exists, e.g. a unit test or an ephemeral proxy with nowhere to write.
#[derive(Clone, Default)]
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

    /// Record the first time a distinct outbound flow was *permitted*.
    ///
    /// One line per distinct flow, not per packet — see [`EgressTally`], which
    /// owns the deduplication and the cap. Without this the trail cannot answer
    /// "what did this sandbox reach", only "what was it stopped from reaching",
    /// and those are very different questions.
    pub(crate) fn egress_allow(&self, domain: &str, target: &str, rule: &str, policy: &str) {
        let mut m = Map::new();
        m.insert("domain".into(), json!(domain));
        m.insert("target".into(), json!(target));
        m.insert("rule".into(), json!(rule));
        m.insert("policy".into(), json!(policy));
        self.record("egress-allow", m);
    }

    /// Record the totals for a session's egress, including whether the
    /// per-flow detail above is complete.
    pub(crate) fn egress_summary(&self, tally: &EgressTally) {
        let mut m = Map::new();
        m.insert("allowed".into(), json!(tally.allowed));
        m.insert("denied".into(), json!(tally.denied));
        m.insert("distinct_allowed".into(), json!(tally.distinct_allowed()));
        m.insert("distinct_denied".into(), json!(tally.distinct_denied()));
        m.insert("truncated".into(), json!(tally.truncated));
        self.record("egress-summary", m);
    }

    /// Record a credential-proxy decision: a destination was intercepted and a
    /// header injected, or relayed end-to-end untouched.
    ///
    /// The proxy keeps its own in-memory ring for the live view, but that dies
    /// with the process. Without a durable line, "did this sandbox's request
    /// carry my credential?" becomes unanswerable the moment the guest stops —
    /// which is usually when someone thinks to ask.
    pub(crate) fn proxy_decision(&self, destination: &str, disposition: &str, rule: &str) {
        let mut m = Map::new();
        m.insert("destination".into(), json!(destination));
        m.insert("disposition".into(), json!(disposition));
        m.insert("rule".into(), json!(rule));
        self.record("proxy", m);
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

/// The most distinct flows recorded per session, allowed and denied each.
///
/// A guest can generate distinct destinations without limit — a port scan is
/// 65535 of them — and an audit file that grows without bound is its own denial
/// of service. The cap bounds the file; `truncated` in the summary keeps it
/// honest about having been reached.
pub(crate) const MAX_DISTINCT_FLOWS: usize = 512;

/// Deduplicates egress decisions and counts them, so the trail gets one line
/// per distinct flow plus totals, rather than one line per packet.
///
/// Deliberately not inside [`AuditLog`]: the tally is owned by the single
/// net-service thread that drains decisions, so it needs no lock, while the
/// log itself is shared and append-only.
#[derive(Default)]
pub(crate) struct EgressTally {
    seen_allowed: HashSet<String>,
    seen_denied: HashSet<String>,
    /// Total decisions observed, including repeats of a flow already recorded.
    allowed: u64,
    denied: u64,
    /// Set once either set hit [`MAX_DISTINCT_FLOWS`], so the summary can say
    /// the per-flow detail is incomplete rather than implying it is all there.
    truncated: bool,
}

impl EgressTally {
    /// Count one decision, and return whether it is the first sighting of this
    /// flow — i.e. whether the caller should write a per-flow audit line.
    pub(crate) fn observe(&mut self, domain: &str, target: &str, rule: &str, allowed: bool) -> bool {
        let key = format!("{domain} {target} {rule}");
        let (seen, total) = if allowed {
            (&mut self.seen_allowed, &mut self.allowed)
        } else {
            (&mut self.seen_denied, &mut self.denied)
        };
        *total = total.saturating_add(1);
        if seen.contains(&key) {
            return false;
        }
        if seen.len() >= MAX_DISTINCT_FLOWS {
            self.truncated = true;
            return false;
        }
        seen.insert(key);
        true
    }

    pub(crate) fn distinct_allowed(&self) -> usize {
        self.seen_allowed.len()
    }

    pub(crate) fn distinct_denied(&self) -> usize {
        self.seen_denied.len()
    }

    /// True once any decision was made, so a caller can skip writing a summary
    /// of nothing for a run with no network at all.
    pub(crate) fn saw_anything(&self) -> bool {
        self.allowed > 0 || self.denied > 0
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
    "usage: chm audit show <WORKSPACE_DIR> [--json] [--tail N]\n\
     \n\
     Read a sandbox's append-only audit trail (session start/stop, egress\n\
     decisions allowed and denied, credential-proxy dispositions, and\n\
     bundle-verification results). With --json, print the raw JSON lines;\n\
     otherwise print a compact one-line-per-record summary. --tail N limits\n\
     output to the most recent N records.\n"
        .to_string()
}

fn show(raw: &[String]) -> Result<(), String> {
    let json = raw.iter().any(|a| a == "--json");
    let tail = raw
        .iter()
        .position(|a| a == "--tail")
        .and_then(|i| raw.get(i + 1))
        .and_then(|n| n.parse::<usize>().ok());
    let dir = raw
        .iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with('-') && raw.get(i.wrapping_sub(1)).map(String::as_str) != Some("--tail")
        })
        .map(|(_, a)| PathBuf::from(a))
        .ok_or("usage: chm audit show <WORKSPACE_DIR> [--json] [--tail N]")?;
    let path = dir.join(AUDIT_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!("{}: no audit trail yet", dir.display());
            return Ok(());
        }
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = tail.map_or(0, |n| lines.len().saturating_sub(n));
    for line in &lines[start..] {
        if json {
            println!("{line}");
        } else {
            println!("{}", summarize(line));
        }
    }
    Ok(())
}

/// The trail as one JSON object, for the daemon and the app.
///
/// Carries the records *and* what the trail cannot tell you, because the second
/// part is what stops a short list being read as a quiet sandbox:
///
/// - `records_allow_egress` is false for a trail written before V6.3, when only
///   denials were recorded. A view that does not say so would show "0 allowed"
///   for a sandbox that reached a hundred hosts.
/// - `truncated` is true when a session hit [`MAX_DISTINCT_FLOWS`], so the
///   per-flow detail is known-incomplete.
pub(crate) fn trail_json(workspace: &Path, tail: usize) -> String {
    let path = workspace.join(AUDIT_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return format!(
                "{{\"present\":false,\"path\":{},\"records\":[],\"total\":0,\
                 \"records_allow_egress\":false,\"truncated\":false}}",
                json!(path.to_string_lossy())
            );
        }
        Err(e) => {
            return format!(
                "{{\"present\":false,\"error\":{},\"records\":[],\"total\":0,\
                 \"records_allow_egress\":false,\"truncated\":false}}",
                json!(e.to_string())
            );
        }
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let total = lines.len();
    // A trail that has never recorded an allow either predates V6.3 or belongs
    // to a sandbox that never got out. Those look identical in the records and
    // must not: the first means the log is incomplete, the second is a finding.
    let records_allow_egress = lines
        .iter()
        .any(|l| l.contains("\"egress-allow\"") || l.contains("\"egress-summary\""));
    let truncated = lines
        .iter()
        .any(|l| l.contains("\"truncated\":true"));
    let start = total.saturating_sub(tail);
    let records: Vec<&str> = lines[start..].to_vec();
    format!(
        "{{\"present\":true,\"path\":{},\"total\":{total},\
         \"records_allow_egress\":{records_allow_egress},\"truncated\":{truncated},\
         \"records\":[{}]}}",
        json!(path.to_string_lossy()),
        records.join(",")
    )
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
        "egress-allow" => format!(
            "{ts}  egress-allow    {} {} ({}) policy={}",
            s("domain"),
            s("target"),
            s("rule"),
            s("policy"),
        ),
        "egress-summary" => {
            let n = |k: &str| m.get(k).and_then(Value::as_u64).unwrap_or(0);
            let truncated = m
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            format!(
                "{ts}  egress-summary  {} allowed ({} distinct), {} denied ({} distinct){}",
                n("allowed"),
                n("distinct_allowed"),
                n("denied"),
                n("distinct_denied"),
                if truncated {
                    " — TRUNCATED: more distinct flows than the cap, detail is incomplete"
                } else {
                    ""
                },
            )
        }
        "proxy" => format!(
            "{ts}  proxy           {} {} ({})",
            s("disposition"),
            s("destination"),
            s("rule"),
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

    /// A guest hammering one host must leave one line, not thousands; a guest
    /// touching many must leave a bounded number and be *told* it was bounded.
    #[test]
    fn the_tally_records_each_flow_once_and_admits_when_it_stops() {
        let mut t = EgressTally::default();

        assert!(t.observe("tcp", "a:443", "allow", true), "first sighting");
        assert!(!t.observe("tcp", "a:443", "allow", true), "repeat");
        assert!(!t.observe("tcp", "a:443", "allow", true), "repeat");
        assert_eq!(t.distinct_allowed(), 1);
        assert_eq!(t.allowed, 3, "repeats still count toward the total");

        // Allowed and denied are separate ledgers: the same target both
        // permitted and refused is two facts, not one.
        assert!(t.observe("tcp", "a:443", "deny", false));
        assert_eq!(t.distinct_denied(), 1);
        assert!(!t.truncated);

        // Fill to the cap and past it.
        for i in 0..MAX_DISTINCT_FLOWS {
            t.observe("tcp", &format!("h{i}:443"), "allow", true);
        }
        assert_eq!(t.distinct_allowed(), MAX_DISTINCT_FLOWS);
        assert!(
            t.truncated,
            "hitting the cap must be recorded -- a silently short list reads as a quiet sandbox"
        );
        assert!(
            !t.observe("tcp", "beyond:443", "allow", true),
            "past the cap nothing more is written"
        );
        assert!(t.allowed > MAX_DISTINCT_FLOWS as u64, "totals keep counting");
    }

    /// The trail has to say what it *cannot* tell you. A pre-V6.3 trail recorded
    /// denials only, so "no allows" there means "not recorded", while in a new
    /// trail it means "the sandbox never got out" -- opposite conclusions from
    /// identical-looking records.
    #[test]
    fn the_trail_json_distinguishes_not_recorded_from_nothing_happened() {
        let ws = env::temp_dir().join(format!("chm-trail-{}", process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();

        // Absent: not an error, and explicitly not a claim about egress.
        let v: Value = serde_json::from_str(&trail_json(&ws, 10)).unwrap();
        assert_eq!(v["present"], false);
        assert_eq!(v["records_allow_egress"], false);

        // A legacy trail: denials only.
        let log = AuditLog::open(&ws);
        log.session_start("resume", 1, 1024, "x", "unrestricted");
        log.egress_deny("tcp", "1.2.3.4:443", "deny", "sha256:aa");
        let v: Value = serde_json::from_str(&trail_json(&ws, 10)).unwrap();
        assert_eq!(v["present"], true);
        assert_eq!(
            v["records_allow_egress"], false,
            "a trail with no allow event cannot be read as proof nothing left"
        );
        assert_eq!(v["total"], 2);

        // Once an allow (or a summary) appears, the trail is answering the
        // question rather than declining it.
        log.egress_allow("tcp", "140.82.121.6:443", "allow", "sha256:aa");
        let v: Value = serde_json::from_str(&trail_json(&ws, 10)).unwrap();
        assert_eq!(v["records_allow_egress"], true);
        assert_eq!(v["truncated"], false);

        // Truncation propagates from any session in the file.
        let t = EgressTally {
            truncated: true,
            allowed: 9_000,
            ..Default::default()
        };
        log.egress_summary(&t);
        let v: Value = serde_json::from_str(&trail_json(&ws, 10)).unwrap();
        assert_eq!(v["truncated"], true);

        // The tail is a window on the end, and `total` still counts everything.
        let v: Value = serde_json::from_str(&trail_json(&ws, 2)).unwrap();
        assert_eq!(v["total"], 4);
        assert_eq!(v["records"].as_array().unwrap().len(), 2);
        assert_eq!(v["records"][1]["event"], "egress-summary");

        let _ = fs::remove_dir_all(&ws);
    }

    /// The proxy's dispositions have to reach the durable trail, or "did my
    /// credential go out?" becomes unanswerable the moment the guest stops.
    #[test]
    fn proxy_decisions_are_summarized_for_a_reader() {
        let line = r#"{"event":"proxy","ts":"2026-07-16T09:00:00.000Z","destination":"api.github.com:443","disposition":"inject","rule":"github-api"}"#;
        let s = summarize(line);
        assert!(s.contains("inject"), "{s}");
        assert!(s.contains("api.github.com:443"), "{s}");

        let summary = r#"{"event":"egress-summary","ts":"2026-07-16T09:00:00.000Z","allowed":9000,"denied":2,"distinct_allowed":512,"distinct_denied":2,"truncated":true}"#;
        let s = summarize(summary);
        assert!(s.contains("TRUNCATED"), "an incomplete record must say so: {s}");
    }
}
