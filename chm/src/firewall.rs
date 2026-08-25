// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Local egress firewall authoring (`chm firewall`).
//!
//! A no-control-plane user governs a sandbox's outbound network the same way the
//! control plane governs a cloud run: by writing a per-workspace
//! `egress-policy.json` that `chm run` / `chm resume` / the `chm serve` daemon
//! then enforce through the **same** userspace NAT (`EgressPolicy`) as a
//! plane-bound policy. This module only *authors and inspects* that file; the
//! enforcement seam lives in `imp::load_egress_policy` (which resolves an
//! explicit `--egress-policy` flag, the `CHM_EGRESS_POLICY` cloud binding, and
//! this workspace file, in that order).
//!
//! It is deliberately separate from `chm policy`, which inspects a
//! *control-plane*-bound policy — local authoring never touches the cloud path.
//!
//! ```text
//! chm firewall show  <WORKSPACE_DIR> [--json]     inspect the effective posture
//! chm firewall set   <WORKSPACE_DIR> [--default allow|deny]
//!                                    [--allow HOST[:PORT]]... [--deny HOST[:PORT]]...
//!                                    [--label TEXT]
//! chm firewall clear <WORKSPACE_DIR>              remove the policy (allow-all)
//! chm firewall validate <FILE>                    lint a policy file
//! ```

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::imp::require_workspace_dir;

use serde::{Deserialize, Serialize};

/// The per-workspace policy file `chm` reads to govern a sandbox's egress.
pub(crate) const POLICY_FILE: &str = "egress-policy.json";

/// The on-disk shape of a local egress policy. Kept byte-compatible with the
/// `CHM_EGRESS_POLICY` env document the cloud runner sets, so the same
/// `imp::parse_egress_policy_labelled` consumes both: `default` is `allow`/`deny`, and
/// `allow`/`deny` are `host[:port]` rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EgressPolicyDoc {
    #[serde(default = "default_stance")]
    pub default: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

fn default_stance() -> String {
    "allow".to_string()
}

impl Default for EgressPolicyDoc {
    fn default() -> Self {
        Self {
            default: default_stance(),
            allow: Vec::new(),
            deny: Vec::new(),
            label: None,
        }
    }
}

impl EgressPolicyDoc {
    /// Whether this policy actually restricts anything (default-deny, or any deny
    /// rule). A default-allow policy with no deny rules is a no-op.
    fn is_restrictive(&self) -> bool {
        self.default.eq_ignore_ascii_case("deny") || !self.deny.is_empty()
    }

    /// Validate the document: a well-formed stance and non-empty `host[:port]`
    /// rules. Returns a human-readable error describing the first problem.
    fn validate(&self) -> Result<(), String> {
        if !self.default.eq_ignore_ascii_case("allow") && !self.default.eq_ignore_ascii_case("deny")
        {
            return Err(format!(
                "default must be \"allow\" or \"deny\", got {:?}",
                self.default
            ));
        }
        for (list, name) in [(&self.allow, "allow"), (&self.deny, "deny")] {
            for rule in list {
                validate_rule(rule).map_err(|e| format!("{name} rule {rule:?}: {e}"))?;
            }
        }
        Ok(())
    }

    /// A one-line human summary for `chm firewall show`.
    fn summary(&self) -> String {
        let stance = if self.default.is_empty() {
            "allow"
        } else {
            &self.default
        };
        format!(
            "egress default={stance} · {} allow / {} deny rule(s){}",
            self.allow.len(),
            self.deny.len(),
            if self.is_restrictive() {
                ""
            } else {
                " (unrestricted)"
            }
        )
    }

    fn to_json(&self) -> String {
        // Pretty-printed so a human can hand-edit the file too.
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Validate a single `host[:port]` rule: a non-empty host, and if a port is
/// present it must be a valid `u16`.
fn validate_rule(rule: &str) -> Result<(), String> {
    let (host, port) = match rule.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rule, None),
    };
    if host.trim().is_empty() {
        return Err("empty host".to_string());
    }
    if let Some(p) = port
        && p.parse::<u16>().is_err()
    {
        return Err(format!("invalid port {p:?}"));
    }
    Ok(())
}

/// Where a workspace's policy file lives.
fn policy_path(dir: &Path) -> PathBuf {
    dir.join(POLICY_FILE)
}

pub(crate) fn firewall_main(raw: &[String]) -> ExitCode {
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
            eprintln!("chm firewall: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `chm firewall show <WORKSPACE_DIR> [--json]` — print the effective egress
/// posture, resolved the same way a run resolves it (env binding wins over the
/// workspace file), so the output matches what a launched sandbox would enforce.
fn show(raw: &[String]) -> Result<(), String> {
    let json = raw.iter().any(|a| a == "--json");
    let dir = positional(raw).ok_or("usage: chm firewall show <WORKSPACE_DIR> [--json]")?;
    require_workspace_dir(&dir)?;

    let (doc, source) = effective_policy(&dir)?;
    if json {
        println!("{}", show_json(doc.as_ref(), source, &dir));
    } else {
        match &doc {
            Some(doc) => println!("{} [{}]  {}", dir.display(), source, doc.summary()),
            None => println!("{} [{}]  no policy — unrestricted egress", dir.display(), source),
        }
    }
    Ok(())
}

/// `chm firewall set <WORKSPACE_DIR> [--default allow|deny] [--allow H[:P]]...
/// [--deny H[:P]]... [--label TEXT]` — write the workspace's `egress-policy.json`
/// to exactly the requested state (no merge), so a UI can drive it declaratively.
/// `--default` defaults to `deny` when omitted: a firewall with no stated stance
/// is closed, not open.
fn set(raw: &[String]) -> Result<(), String> {
    let mut dir: Option<PathBuf> = None;
    let mut default: Option<String> = None;
    let mut allow: Vec<String> = Vec::new();
    let mut deny: Vec<String> = Vec::new();
    let mut label: Option<String> = None;

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            raw.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match a.as_str() {
            "--default" => default = Some(take("--default")?),
            "--allow" => allow.push(take("--allow")?),
            "--deny" => deny.push(take("--deny")?),
            "--label" => label = Some(take("--label")?),
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`"));
            }
            _ => {
                if dir.is_some() {
                    return Err(format!("unexpected extra argument `{a}`"));
                }
                dir = Some(PathBuf::from(a));
            }
        }
        i += 1;
    }

    let dir = dir.ok_or(
        "usage: chm firewall set <WORKSPACE_DIR> [--default allow|deny] \
         [--allow H[:P]]... [--deny H[:P]]... [--label TEXT]",
    )?;
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let doc = EgressPolicyDoc {
        default: default.unwrap_or_else(|| "deny".to_string()),
        allow,
        deny,
        label: label.or_else(|| Some("local".to_string())),
    };
    let path = write_policy_doc(&dir, &doc)?;
    println!("wrote {} — {}", path.display(), doc.summary());
    Ok(())
}

/// Validate `doc` and write it as `<dir>/egress-policy.json`, returning the path.
/// Shared by `chm firewall set` (local authoring) and `chm policy bind` (bringing
/// a control-plane policy down), so both land byte-identical documents that the
/// same enforcement seam consumes.
pub(crate) fn write_policy_doc(dir: &Path, doc: &EgressPolicyDoc) -> Result<PathBuf, String> {
    doc.validate()?;
    let path = policy_path(dir);
    fs::write(&path, doc.to_json()).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// `chm firewall clear <WORKSPACE_DIR>` — remove the policy file so the sandbox
/// runs with unrestricted egress (allow-all). Missing file is not an error.
fn clear(raw: &[String]) -> Result<(), String> {
    let dir = positional(raw).ok_or("usage: chm firewall clear <WORKSPACE_DIR>")?;
    let path = policy_path(&dir);
    match fs::remove_file(&path) {
        Ok(()) => println!("cleared {} — egress is now unrestricted", path.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!("{}: no policy set — egress already unrestricted", dir.display());
        }
        Err(e) => return Err(format!("remove {}: {e}", path.display())),
    }
    Ok(())
}

/// `chm firewall validate <FILE>` — lint a policy file without applying it.
fn validate(raw: &[String]) -> Result<(), String> {
    let path = positional(raw).ok_or("usage: chm firewall validate <FILE>")?;
    let doc = read_doc(&path)?;
    doc.validate()?;
    println!("{}: valid — {}", path.display(), doc.summary());
    Ok(())
}

/// The policy that would govern a run started from `dir` right now, and where it
/// came from: the `CHM_EGRESS_POLICY` env binding (cloud) wins over the local
/// workspace file, mirroring `imp::load_egress_policy`.
fn effective_policy(dir: &Path) -> Result<(Option<EgressPolicyDoc>, &'static str), String> {
    if let Ok(raw) = env::var("CHM_EGRESS_POLICY") {
        let doc: EgressPolicyDoc =
            serde_json::from_str(&raw).map_err(|e| format!("parse CHM_EGRESS_POLICY: {e}"))?;
        return Ok((Some(doc), "control-plane"));
    }
    let path = policy_path(dir);
    if path.exists() {
        return Ok((Some(read_doc(&path)?), "local"));
    }
    Ok((None, "none"))
}

fn read_doc(path: &Path) -> Result<EgressPolicyDoc, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// The `--json` machine-readable posture for the app to consume.
fn show_json(doc: Option<&EgressPolicyDoc>, source: &str, dir: &Path) -> String {
    let default = EgressPolicyDoc::default();
    let doc = doc.unwrap_or(&default);
    let out = serde_json::json!({
        "source": source,
        "default": doc.default,
        "allow": doc.allow,
        "deny": doc.deny,
        "label": doc.label,
        "restrictive": doc.is_restrictive(),
        "path": policy_path(dir).display().to_string(),
    });
    serde_json::to_string(&out).unwrap_or_else(|_| "{}".to_string())
}

/// The first non-flag argument.
fn positional(raw: &[String]) -> Option<PathBuf> {
    raw.iter().find(|a| !a.starts_with('-')).map(PathBuf::from)
}

fn usage() -> String {
    "\
chm firewall — author a sandbox's local egress policy (no control plane needed)

USAGE:
    chm firewall show  <WORKSPACE_DIR> [--json]
    chm firewall set   <WORKSPACE_DIR> [--default allow|deny] \\
                       [--allow HOST[:PORT]]... [--deny HOST[:PORT]]... [--label TEXT]
    chm firewall clear <WORKSPACE_DIR>
    chm firewall validate <FILE>

The policy is written to <WORKSPACE_DIR>/egress-policy.json and enforced by the
userspace NAT the next time the sandbox is started (chm run / chm serve). Rules
are host[:port]; a deny rule wins over an allow rule; an unmatched destination
falls to the default stance. `set` writes exactly the flags given (no merge) and
defaults the stance to `deny` when --default is omitted.

A control-plane binding (CHM_EGRESS_POLICY) overrides the local file; `show`
reports which source is in effect.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_bad_stance_and_port() {
        let bad_stance = EgressPolicyDoc {
            default: "maybe".to_string(),
            ..Default::default()
        };
        assert!(bad_stance.validate().is_err());

        let bad_port = EgressPolicyDoc {
            default: "deny".to_string(),
            allow: vec!["github.com:notaport".to_string()],
            ..Default::default()
        };
        assert!(bad_port.validate().is_err());
    }

    #[test]
    fn validate_accepts_host_and_host_port() {
        let doc = EgressPolicyDoc {
            default: "deny".to_string(),
            allow: vec!["github.com".to_string(), "api.github.com:443".to_string()],
            ..Default::default()
        };
        doc.validate().unwrap();
    }

    #[test]
    fn restrictive_reflects_stance_and_deny() {
        assert!(!EgressPolicyDoc::default().is_restrictive());
        assert!(
            EgressPolicyDoc {
                default: "deny".to_string(),
                ..Default::default()
            }
            .is_restrictive()
        );
        assert!(
            EgressPolicyDoc {
                default: "allow".to_string(),
                deny: vec!["evil.example:443".to_string()],
                ..Default::default()
            }
            .is_restrictive()
        );
    }

    #[test]
    fn json_document_is_parseable_by_the_enforcement_shape() {
        // The file `set` writes must round-trip through the same field names the
        // enforcement path (`imp::parse_egress_policy_labelled`) reads.
        let doc = EgressPolicyDoc {
            default: "deny".to_string(),
            allow: vec!["api.github.com:443".to_string()],
            deny: vec![],
            label: Some("local".to_string()),
        };
        let v: serde_json::Value = serde_json::from_str(&doc.to_json()).unwrap();
        assert_eq!(v["default"], "deny");
        assert_eq!(v["allow"][0], "api.github.com:443");
        assert_eq!(v["label"], "local");
    }
}

/// #421 -- the call site, not the helper: `chm firewall show` must consult
/// `require_workspace_dir` itself, or it keeps reporting on a directory that
/// is not there while the helper's own tests stay green.
#[cfg(test)]
mod workspace_arg_tests {
    use super::*;

    fn ghost(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("chm-ws421-fw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        assert!(!p.exists(), "precondition: {} must be absent", p.display());
        p
    }

    #[test]
    fn firewall_show_refuses_a_workspace_that_is_not_there() {
        let d = ghost("fw");
        let e = show(&[d.display().to_string()]).unwrap_err();
        assert!(e.contains("no such workspace directory"), "{e}");
        assert!(e.contains(&d.display().to_string()), "{e}");
    }

    /// The security half: reporting `no policy -- unrestricted egress` for a
    /// workspace nobody has is a reading that was never measured.
    #[test]
    fn firewall_show_json_refuses_it_too() {
        let d = ghost("fwj");
        let e = show(&[d.display().to_string(), "--json".to_string()]).unwrap_err();
        assert!(e.contains("no such workspace directory"), "{e}");
    }
}
