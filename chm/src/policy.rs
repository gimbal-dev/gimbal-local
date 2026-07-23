// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Sandbox policy: consume + verify the control plane's per-sandbox governance
//! (Pillar ③, M28.1).
//!
//! The plane authors a `SandboxPolicy` (egress allow/deny + filesystem scopes +
//! mounts), content-addresses it as a `policy_digest`, and hands each
//! `assign-run` / `resume` / `pull` a compiled `enforcement.chm_profile` — the
//! Mac-native posture `chm` enforces. Because the policy is content-addressed it
//! **teleports with the session**: the same digest that governed a cloud (KVM)
//! run governs the Mac (HVF) resume.
//!
//! This module is the M28.1 slice: parse the enforcement block, **verify the
//! digest teleported intact**, and expose the compiled profile. It does not yet
//! enforce anything on the datapath — that is M28.2 (userspace NAT) + M28.3 (the
//! egress gate). Keeping consumption separate from enforcement means the plumbing
//! ships and is provable on its own, with no risk to the run.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use ring::digest::{digest, SHA256};

/// A compiled per-sandbox posture as the plane renders it for `apple-hvf`
/// (`enforcement.chm_profile`). This is what `chm` will enforce (M28.3+): an
/// egress default + allow/deny host list, and read-only / read-write fs scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct ChmProfile {
    #[serde(default)]
    pub egress: ChmEgress,
    #[serde(default)]
    pub fs: ChmFs,
    #[serde(default)]
    pub mounts: Vec<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct ChmEgress {
    /// `allow` or `deny` — the stance for a destination no rule matches.
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct ChmFs {
    #[serde(default)]
    pub ro: Vec<String>,
    #[serde(default)]
    pub rw: Vec<String>,
}

/// The governance a run is subject to, after the teleport-integrity check.
#[derive(Debug, Clone)]
pub(crate) struct GovernedPolicy {
    pub digest: String,
    pub profile: ChmProfile,
    /// True when `chm` independently recomputed the digest over the normalized
    /// policy and it matched (cryptographic cross-check), in addition to the
    /// reference-agreement integrity check that always holds.
    pub digest_recomputed: bool,
    pub egress_rule_count: usize,
}

impl GovernedPolicy {
    /// A one-line human summary for logs + the app.
    pub fn summary(&self) -> String {
        let stance = if self.profile.egress.default.is_empty() {
            "allow".to_string()
        } else {
            self.profile.egress.default.clone()
        };
        format!(
            "governed by {} · egress default={stance}, {} rule(s) · fs {} ro / {} rw{}",
            self.digest,
            self.egress_rule_count,
            self.profile.fs.ro.len(),
            self.profile.fs.rw.len(),
            if self.digest_recomputed { " · digest verified" } else { "" }
        )
    }

    /// The host mounts the policy requests. `chm` has **no host-filesystem
    /// passthrough** (a deliberate security invariant — no virtiofs/9p/shared
    /// folder), so these cannot be honored and are refused loudly rather than
    /// silently dropped. Returns `(source, target, mode, durable)` per mount.
    pub fn requested_mounts(&self) -> Vec<(String, String, String, bool)> {
        self.profile
            .mounts
            .iter()
            .map(|m| {
                let s = m.get("source").and_then(Value::as_str).unwrap_or("").to_string();
                let t = m.get("target").and_then(Value::as_str).unwrap_or("").to_string();
                let mode = {
                    let md = m.get("mode").and_then(Value::as_str).unwrap_or("");
                    if md.is_empty() { "ro".to_string() } else { md.to_string() }
                };
                let durable = m.get("durable").and_then(Value::as_bool).unwrap_or(false);
                (s, t, mode, durable)
            })
            .collect()
    }
}

/// Parse + verify the policy an assignment carries, if any.
///
/// Returns `Ok(None)` when the sandbox is unbound (no `enforcement` block) —
/// behave exactly as today. Returns `Err` only when a policy IS present but its
/// teleport integrity fails (the digest references disagree or are malformed),
/// which must not be run blindly.
///
/// `strict` is the M31.5 fail-closed posture (`CHM_REQUIRE_SIGNED`): when set,
/// the independent policy-digest recompute is **enforced** — a governed policy
/// whose document does not re-hash to its stated digest (or cannot be
/// recomputed) is refused rather than merely logged as unverified.
pub(crate) fn parse_and_verify(
    assignment: &Value,
    strict: bool,
) -> Result<Option<GovernedPolicy>, String> {
    let Some(enforcement) = assignment.get("enforcement").filter(|e| !e.is_null()) else {
        return Ok(None);
    };

    // The compiled profile chm will enforce, and the digest it is bound to.
    let enf_digest = enforcement
        .get("policy_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let profile: ChmProfile = enforcement
        .get("chm_profile")
        .filter(|p| !p.is_null())
        .map(|p| serde_json::from_value(p.clone()))
        .transpose()
        .map_err(|e| format!("parse chm_profile: {e}"))?
        .unwrap_or_default();

    // Teleport integrity: the top-level policy_digest, the enforcement digest,
    // and (when present) the policy doc's own digest must all agree and be
    // well-formed. A mismatch means the assignment was tampered/garbled — the
    // compiled profile is not the one bound to the stated policy.
    let top_digest = assignment
        .get("policy_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let policy_doc = assignment.get("policy").filter(|p| !p.is_null());
    let doc_digest = policy_doc
        .and_then(|p| p.get("digest"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let authoritative = if enf_digest.is_empty() { &top_digest } else { &enf_digest };
    if !is_wellformed_digest(authoritative) {
        return Err(format!(
            "policy present but its digest is missing/malformed ({authoritative:?}); refusing to run under an unverifiable policy"
        ));
    }
    for (name, d) in [("policy_digest", &top_digest), ("policy.digest", &doc_digest)] {
        if !d.is_empty() && d != authoritative {
            return Err(format!(
                "policy digest mismatch: enforcement={authoritative}, {name}={d} — the policy did not teleport intact"
            ));
        }
    }

    // Cryptographic cross-check: recompute the digest over the normalized policy
    // doc and compare. A match upgrades the log to "verified". Advisory by
    // default (a mismatch is usually chm-side canonicalization drift, not a
    // guest-reachable boundary, so the plane digest stays authoritative); under
    // the fail-closed posture (`strict`, M31.5) the recompute is *enforced* — a
    // present policy doc that does not re-hash to its stated digest is refused.
    let recompute = policy_doc.map(recompute_digest);
    let digest_recomputed = matches!(&recompute, Some(Ok(c)) if c == authoritative);
    if strict {
        match &recompute {
            Some(Ok(c)) if c == authoritative => {}
            Some(Ok(c)) => {
                return Err(format!(
                    "policy digest recompute mismatch (authoritative={authoritative}, \
                     recomputed={c}); the policy did not teleport intact — refusing \
                     to run (fail closed, CHM_REQUIRE_SIGNED)"
                ));
            }
            Some(Err(e)) => {
                return Err(format!(
                    "cannot recompute policy digest to verify it ({e}); refusing to \
                     run under an unverifiable policy (fail closed, CHM_REQUIRE_SIGNED)"
                ));
            }
            None => {}
        }
    }

    let egress_rule_count = profile.egress.allow.len() + profile.egress.deny.len();
    Ok(Some(GovernedPolicy {
        digest: authoritative.clone(),
        profile,
        digest_recomputed,
        egress_rule_count,
    }))
}

/// True for a `sha256:<64 hex>` digest.
fn is_wellformed_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Recompute the plane's `policy_digest` over a received policy document:
/// `sha256:` + hex of the SHA-256 of the **normalized policy's canonical JSON**
/// (the plane computes `sha256(json.Marshal(normalized))` with the `digest`
/// field cleared). Reproduced byte-for-byte in [`canonical_policy_json`].
pub(crate) fn recompute_digest(policy: &Value) -> Result<String, String> {
    let canonical = canonical_policy_json(policy)?;
    let sum = digest(&SHA256, canonical.as_bytes());
    let hex: String = sum.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("sha256:{hex}"))
}

/// Render a policy document as the exact canonical JSON the plane digests: Go's
/// `json.Marshal` of the normalized `SandboxPolicy` with `digest` cleared —
/// compact, fields in struct-declaration order, `omitempty` drops empties, and
/// `<`/`>`/`&` HTML-escaped as Go does. The normalization defaults are applied
/// so a received doc digests identically regardless of which optional fields the
/// plane omitted.
fn canonical_policy_json(policy: &Value) -> Result<String, String> {
    #[derive(Serialize)]
    struct Egress<'a> {
        action: &'a str,
        host: &'a str,
        #[serde(skip_serializing_if = "<[i64]>::is_empty")]
        ports: Vec<i64>,
        #[serde(skip_serializing_if = "str::is_empty")]
        note: &'a str,
    }
    #[derive(Serialize)]
    struct PathScope<'a> {
        path: &'a str,
        mode: &'a str,
    }
    #[derive(Serialize)]
    struct Mount<'a> {
        source: &'a str,
        target: &'a str,
        mode: &'a str,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        durable: bool,
    }
    #[derive(Serialize)]
    struct Canonical<'a> {
        version: i64,
        default_egress: &'a str,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        egress: Vec<Egress<'a>>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        fs: Vec<PathScope<'a>>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        mounts: Vec<Mount<'a>>,
    }

    let str_at = |v: &'_ Value, k: &str| -> String {
        v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
    };

    // Normalize exactly as the plane does before digesting.
    let version = policy.get("version").and_then(Value::as_i64).filter(|&n| n != 0).unwrap_or(1);
    let default_egress = {
        let d = str_at(policy, "default_egress");
        if d.is_empty() { "allow".to_string() } else { d }
    };
    let egress: Vec<(String, String, Vec<i64>, String)> = policy
        .get("egress")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|r| {
                    let action = {
                        let a = str_at(r, "action");
                        if a.is_empty() { "deny".to_string() } else { a }
                    };
                    let host = {
                        let h = str_at(r, "host");
                        if h.is_empty() { "*".to_string() } else { h }
                    };
                    let ports = r
                        .get("ports")
                        .and_then(Value::as_array)
                        .map(|ps| ps.iter().filter_map(Value::as_i64).collect())
                        .unwrap_or_default();
                    (action, host, ports, str_at(r, "note"))
                })
                .collect()
        })
        .unwrap_or_default();
    let fs: Vec<(String, String)> = policy
        .get("fs")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|sc| {
                    let mode = {
                        let m = str_at(sc, "mode");
                        if m.is_empty() { "ro".to_string() } else { m }
                    };
                    (str_at(sc, "path"), mode)
                })
                .collect()
        })
        .unwrap_or_default();
    let mounts: Vec<(String, String, String, bool)> = policy
        .get("mounts")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|m| {
                    let mode = {
                        let md = str_at(m, "mode");
                        if md.is_empty() { "ro".to_string() } else { md }
                    };
                    (
                        str_at(m, "source"),
                        str_at(m, "target"),
                        mode,
                        m.get("durable").and_then(Value::as_bool).unwrap_or(false),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let canonical = Canonical {
        version,
        default_egress: &default_egress,
        egress: egress
            .iter()
            .map(|(a, h, p, n)| Egress { action: a, host: h, ports: p.clone(), note: n })
            .collect(),
        fs: fs.iter().map(|(p, m)| PathScope { path: p, mode: m }).collect(),
        mounts: mounts
            .iter()
            .map(|(s, t, m, d)| Mount { source: s, target: t, mode: m, durable: *d })
            .collect(),
    };
    let json = serde_json::to_string(&canonical).map_err(|e| format!("marshal policy: {e}"))?;
    Ok(go_escape(&json))
}

/// Apply Go `json.Marshal`'s default HTML escaping (`<`, `>`, `&` → `\u003c`
/// etc.) to already-compact JSON, so chm's canonical form matches the plane's
/// byte-for-byte even for hosts/paths containing those characters.
fn go_escape(s: &str) -> String {
    s.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ASSIGNMENT: &str = include_str!("../tests/data/policy_assignment.json");
    const REAL_DIGEST: &str =
        "sha256:147f9297406ccd92c0bc206791e487c27da44ed48eec8015ed58828425256642";

    #[test]
    fn recompute_matches_the_planes_digest_byte_for_byte() {
        // The load-bearing claim: chm reproduces the plane's canonical JSON, so
        // it can independently confirm the policy_digest.
        let assignment: Value = serde_json::from_str(ASSIGNMENT).unwrap();
        let policy = assignment.get("policy").unwrap();
        assert_eq!(recompute_digest(policy).unwrap(), REAL_DIGEST);
    }

    #[test]
    fn parse_and_verify_accepts_the_real_assignment() {
        let assignment: Value = serde_json::from_str(ASSIGNMENT).unwrap();
        let governed = parse_and_verify(&assignment, false).unwrap().expect("policy present");
        assert_eq!(governed.digest, REAL_DIGEST);
        assert!(governed.digest_recomputed, "digest independently verified");
        assert_eq!(governed.profile.egress.default, "deny");
        assert_eq!(governed.profile.egress.allow, vec!["api.github.com:443"]);
        assert_eq!(governed.profile.fs.rw, vec!["/workspace"]);
        assert_eq!(governed.egress_rule_count, 1);
    }

    #[test]
    fn strict_posture_accepts_a_correctly_recomputing_policy() {
        // Under the fail-closed posture the real assignment (whose doc re-hashes
        // to its digest) is still accepted — enforcement must not break valid runs.
        let assignment: Value = serde_json::from_str(ASSIGNMENT).unwrap();
        let governed = parse_and_verify(&assignment, true).unwrap().expect("policy present");
        assert!(governed.digest_recomputed);
    }

    #[test]
    fn strict_posture_rejects_a_policy_doc_that_does_not_recompute() {
        // A policy doc whose contents were altered so it no longer re-hashes to
        // its (matching-everywhere) stated digest: advisory by default, fatal
        // under CHM_REQUIRE_SIGNED.
        let digest = "sha256:".to_string() + &"a".repeat(64);
        let assignment = json!({
            "policy_digest": digest,
            "policy": { "version": 1, "default_egress": "deny", "digest": digest },
            "enforcement": {
                "substrate": "apple-hvf",
                "policy_digest": digest,
                "chm_profile": { "egress": { "default": "deny" } }
            }
        });
        // Advisory: accepted, but flagged unverified.
        let governed = parse_and_verify(&assignment, false).unwrap().expect("policy present");
        assert!(!governed.digest_recomputed, "recompute drift is surfaced");
        // Strict: refused.
        let err = parse_and_verify(&assignment, true).unwrap_err();
        assert!(err.contains("recompute mismatch"), "{err}");
        assert!(err.contains("fail closed"), "{err}");
    }

    #[test]
    fn unbound_sandbox_has_no_policy() {
        let assignment = json!({ "snapshot_id": "snap-x", "download_uri": "file:///x" });
        assert!(parse_and_verify(&assignment, false).unwrap().is_none());
        // An unbound sandbox is unaffected by the strict posture: nothing to verify.
        assert!(parse_and_verify(&assignment, true).unwrap().is_none());
    }

    #[test]
    fn tampered_digest_reference_is_rejected() {
        // The enforcement profile says one digest, the top-level says another —
        // the policy did not teleport intact.
        let assignment = json!({
            "policy_digest": "sha256:".to_string() + &"a".repeat(64),
            "enforcement": {
                "substrate": "apple-hvf",
                "policy_digest": "sha256:".to_string() + &"b".repeat(64),
                "chm_profile": { "egress": { "default": "deny" } }
            }
        });
        let err = parse_and_verify(&assignment, false).unwrap_err();
        assert!(err.contains("did not teleport intact"), "{err}");
    }

    #[test]
    fn malformed_digest_is_refused() {
        let assignment = json!({
            "enforcement": { "substrate": "apple-hvf", "policy_digest": "not-a-digest",
                             "chm_profile": {} }
        });
        assert!(parse_and_verify(&assignment, false).unwrap_err().contains("malformed"));
    }

    #[test]
    fn default_egress_normalizes_when_empty() {
        // An empty policy digests with default_egress defaulted to "allow".
        let empty = json!({});
        // {"version":1,"default_egress":"allow"} — matches the plane's empty-policy digest.
        let d = recompute_digest(&empty).unwrap();
        assert!(is_wellformed_digest(&d));
    }

    #[test]
    fn go_escape_matches_go_html_escaping() {
        assert_eq!(go_escape(r#"{"host":"a&b<c>"}"#), r#"{"host":"a\u0026b\u003cc\u003e"}"#);
    }

    #[test]
    fn requested_mounts_extracts_source_target_mode_durable() {
        let gp = GovernedPolicy {
            digest: "sha256:x".to_string(),
            profile: ChmProfile {
                egress: ChmEgress::default(),
                fs: ChmFs::default(),
                mounts: vec![
                    json!({"source":"/host/data","target":"/mnt/data","mode":"rw","durable":true}),
                    json!({"source":"/host/ro","target":"/mnt/ro"}),
                ],
            },
            digest_recomputed: true,
            egress_rule_count: 0,
        };
        let mounts = gp.requested_mounts();
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            mounts[0],
            ("/host/data".to_string(), "/mnt/data".to_string(), "rw".to_string(), true)
        );
        // Missing mode defaults to "ro"; missing durable defaults to false.
        assert_eq!(
            mounts[1],
            ("/host/ro".to_string(), "/mnt/ro".to_string(), "ro".to_string(), false)
        );
    }

    #[test]
    fn no_mounts_means_nothing_to_refuse() {
        let gp = GovernedPolicy {
            digest: "sha256:x".to_string(),
            profile: ChmProfile::default(),
            digest_recomputed: true,
            egress_rule_count: 0,
        };
        assert!(gp.requested_mounts().is_empty());
    }
}
