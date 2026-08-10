// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm posture` — the security posture that would govern a run, right now.
//!
//! `docs/security-model.md` carries a hardening checklist. A checklist in a
//! document says what we *intended*; it cannot tell you what is actually
//! switched on for the sandbox in front of you, and a security control you
//! believe is on but is not is worse than one you know is off.
//!
//! This command resolves the same sources the run path resolves — flags, the
//! control-plane env bindings, the per-workspace files — and prints, per
//! control, whether it is **active**, how it was **decided**, and (where it is
//! not) what turns it on. It is the executable form of §4 of the security
//! model.
//!
//! ```text
//! chm posture <WORKSPACE_DIR> [--json]
//! ```
//!
//! Exit status is `0` when every control that has a safe default is at that
//! default or stronger, and `1` when something has been deliberately weakened —
//! so it can be used as a gate in a script.
//!
//! # Whose posture is this?
//!
//! Most of what this reports is read from the **environment of the process that
//! calls it**, so the answer is only true of a guest that runs in that same
//! process. `chm serve` runs the guest, so a UI that shells out to `chm posture`
//! on its own would describe *itself*, not the sandbox — and would show green
//! over a daemon someone had started with `CHM_ALLOW_LOCAL_EGRESS=1`. That is
//! precisely the failure this command exists to prevent, so [`assess_json`] is
//! exposed for the daemon to answer for itself over the control socket
//! (`chm ctl posture`).

use std::env;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::credproxy;
use crate::limits;
use crate::signing;

/// Whether a control is on, and how strongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// On, at or above the safe default.
    Active,
    /// On, but deliberately relaxed from the safe default.
    Weakened,
    /// Off, and off is the documented posture (not a weakening).
    NotApplicable,
}

impl State {
    fn mark(self) -> &'static str {
        match self {
            State::Active => "on ",
            State::Weakened => "OFF",
            State::NotApplicable => "n/a",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Weakened => "weakened",
            State::NotApplicable => "not-applicable",
        }
    }
}

/// One row of the posture report.
struct Control {
    /// The security-model invariant this implements, e.g. `I10`.
    invariant: &'static str,
    name: &'static str,
    state: State,
    /// How this was decided — the source, not a restatement of the state.
    detail: String,
}

/// Build the report for `dir`. Pure over its inputs apart from the environment
/// and filesystem it deliberately inspects, so the shape is easy to test.
fn assess(dir: &Path) -> Vec<Control> {
    let mut out = Vec::new();

    // I10 — the reserved-address boundary. Default-on; opting out is the
    // dangerous direction, so it is the one thing that reports as weakened.
    let local_egress = env::var("CHM_ALLOW_LOCAL_EGRESS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    out.push(Control {
        invariant: "I10",
        name: "host-network isolation",
        state: if local_egress { State::Weakened } else { State::Active },
        detail: if local_egress {
            "CHM_ALLOW_LOCAL_EGRESS is set — the guest can reach loopback, your \
             LAN and link-local addresses including 169.254.169.254"
                .to_string()
        } else {
            "loopback, RFC1918, link-local and other special-use ranges denied \
             before policy is consulted"
                .to_string()
        },
    });

    // I12 — credential custody. Absent configuration is the documented posture,
    // not a weakening: a sandbox with no injected credentials is strictly safer
    // than one with them. What *would* be a weakening is a rule attaching a
    // credential over cleartext, so that is the case singled out.
    let (proxy_state, proxy_detail) = match credproxy::cli::resolve_rules(Some(dir), None) {
        Ok(Some(r)) => {
            let patterns = r.rules.intercept_patterns();
            let cleartext: Vec<&str> = r
                .rules
                .rules
                .iter()
                .filter(|rule| rule.allow_cleartext)
                .map(|rule| rule.name.as_str())
                .collect();
            if patterns.is_empty() {
                (
                    State::NotApplicable,
                    format!("{} defines no injecting rules", r.origin),
                )
            } else if cleartext.is_empty() {
                (
                    State::Active,
                    format!(
                        "credentials injected at the proxy for {} — never present in the guest",
                        patterns.join(", ")
                    ),
                )
            } else {
                (
                    State::Weakened,
                    format!(
                        "rule(s) {} allow_cleartext — a credential may go out unencrypted",
                        cleartext.join(", ")
                    ),
                )
            }
        }
        Ok(None) => (
            State::NotApplicable,
            "no proxy rules; the guest holds whatever credentials it was given".to_string(),
        ),
        // A rules file that cannot be parsed would fail the run, so report it as
        // a weakening rather than letting `posture` look clean.
        Err(e) => (State::Weakened, format!("proxy rules unusable: {e}")),
    };
    out.push(Control {
        invariant: "I12",
        name: "credential custody",
        state: proxy_state,
        detail: proxy_detail,
    });

    // I9 — egress policy. Absent policy is *not* a weakening: a sandbox that
    // can reach the internet is the expected product behaviour, and the
    // dangerous half of egress is I10, which is on regardless.
    let (egress_state, egress_detail) = if let Ok(raw) = env::var("CHM_EGRESS_POLICY") {
        (
            State::Active,
            format!("control-plane binding ({} bytes)", raw.len()),
        )
    } else if dir.join("egress-policy.json").exists() {
        (State::Active, "workspace egress-policy.json".to_string())
    } else {
        (
            State::NotApplicable,
            "no allow-list — internet egress permitted (host networks still \
             denied by I10). `chm firewall set` to restrict."
                .to_string(),
        )
    };
    out.push(Control {
        invariant: "I9",
        name: "egress allow-list",
        state: egress_state,
        detail: egress_detail,
    });

    // Resource ceilings (M30.6) — default-on since V4.2.
    let (doc, source) = limits::resolve_limits(dir, None);
    let limits_state = match source {
        "opt-out" => State::Weakened,
        _ if doc.is_bounded() => State::Active,
        _ => State::Weakened,
    };
    out.push(Control {
        invariant: "—",
        name: "resource ceilings",
        state: limits_state,
        detail: if limits_state == State::Weakened {
            "CHM_LIMITS=none — a runaway guest is unbounded".to_string()
        } else {
            format!("[{source}] {}", doc.summary())
        },
    });

    // I6 — provenance. Verification is only possible with a trust root, and
    // gctl does not sign yet (#36), so "no trust store" is the documented
    // posture rather than a weakening.
    let trust = env::var("CHM_TRUST_STORE").ok().filter(|v| !v.is_empty());
    let strict = env::var(signing::REQUIRE_SIGNED_ENV).is_ok();
    out.push(Control {
        invariant: "I6",
        name: "signature verification",
        state: match (&trust, strict) {
            (Some(_), _) => State::Active,
            (None, true) => State::Active,
            (None, false) => State::NotApplicable,
        },
        detail: match (&trust, strict) {
            (Some(p), true) => format!("trust root {p}, fail-closed"),
            (Some(p), false) => format!("trust root {p}, verified when a manifest is present"),
            (None, true) => "CHM_REQUIRE_SIGNED with no trust root — every bundle refused".to_string(),
            (None, false) => "no CHM_TRUST_STORE — bundles are checksum-verified but not \
                              authenticated (gctl signing pending, #36)"
                .to_string(),
        },
    });

    // I1/I2/I3 — structural, not configurable. Reported anyway: a posture report
    // that only lists knobs implies the unlisted things are absent.
    out.push(Control {
        invariant: "I1",
        name: "no host FS passthrough",
        state: State::Active,
        detail: "structural — the device model wires only block/net/rng".to_string(),
    });
    out.push(Control {
        invariant: "I2/I3",
        name: "bundle + overlay confinement",
        state: State::Active,
        detail: "structural — O_NOFOLLOW opens under the bundle root, private 0700 overlay"
            .to_string(),
    });

    // I7 — interrupt routing. Now structural with no override at all: the
    // managed-GIC runtime path is retired, so there is no second backend a
    // capture could be routed onto. `CHM_ALLOW_ITS_LPI` used to select it and
    // now selects nothing.
    out.push(Control {
        invariant: "I7",
        name: "deliverable-interrupt routing",
        state: State::Active,
        detail: "structural — every capture runs on the userspace GICv3, the only \
                 backend that can deliver ITS/LPI completions"
            .to_string(),
    });

    // V1.4 — the AArch32 wedge. Not a security boundary, but it is a
    // guest-reachable unrecoverable hang, which belongs in a posture report.
    let strict_a32 = env::var("CHM_STRICT_AARCH32").is_ok();
    out.push(Control {
        invariant: "V1.4",
        name: "AArch32 refusal",
        state: if strict_a32 { State::Active } else { State::NotApplicable },
        detail: if strict_a32 {
            "CHM_STRICT_AARCH32 — a snapshot advertising 32-bit EL0 is refused".to_string()
        } else {
            "warn-only: a guest that execs a 32-bit binary wedges its vCPU \
             (docs/cpu-feature-deltas.md). CHM_STRICT_AARCH32=1 to refuse."
                .to_string()
        },
    });

    // V6.8 — the elided `ic ivau`. Like the AArch32 wedge this is a
    // correctness hazard rather than a security boundary, but it is
    // guest-reachable and silent, so it belongs in a posture report.
    let strict_ic = env::var("CHM_STRICT_ICACHE").is_ok();
    out.push(Control {
        invariant: "V6.8",
        name: "stale-icache refusal",
        state: if strict_ic {
            State::Active
        } else {
            State::NotApplicable
        },
        detail: if strict_ic {
            "CHM_STRICT_ICACHE — a snapshot whose kernel elided `ic ivau` is refused".to_string()
        } else {
            "warn-only: a capture taken on CTR_EL0.DIC=1 hardware runs JITs that \
             intermittently execute stale code (docs/cpu-feature-deltas.md). \
             CHM_STRICT_ICACHE=1 to refuse."
                .to_string()
        },
    });

    // #274 -- the ASID-width delta. The most severe of the correctness hazards
    // in this group: unlike the AArch32 wedge (which stops the vCPU) and the
    // stale icache (which raises SIGILL), this one lets unrelated processes
    // read and write each other's memory while the guest keeps running.
    let strict_asid = env::var("CHM_STRICT_ASID").is_ok();
    out.push(Control {
        invariant: "#274",
        name: "ASID-width refusal",
        state: if strict_asid {
            State::Active
        } else {
            State::NotApplicable
        },
        detail: if strict_asid {
            "CHM_STRICT_ASID — a snapshot whose guest latched more ASID bits than \
             this host implements is refused"
                .to_string()
        } else {
            "warn-only: a capture from 16-bit-ASID hardware runs on this host's \
             8-bit ASIDs, so past ~256 live address spaces unrelated processes \
             share TLB entries and corrupt each other's memory \
             (docs/cpu-feature-deltas.md). CHM_STRICT_ASID=1 to refuse."
                .to_string()
        },
    });

    // V5.5 — guest counter rate correction. Unlike its three siblings above,
    // this one is on by default and has a real weakened state, because turning
    // the correction off is something a user does deliberately.
    let cntfrq_off = env::var("CHM_GUEST_CNTFRQ")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        == Some(0);
    out.push(Control {
        invariant: "V5.5",
        name: "guest clock rate correction",
        state: if cntfrq_off {
            State::Weakened
        } else {
            State::Active
        },
        detail: if cntfrq_off {
            "CHM_GUEST_CNTFRQ=0 — a capture from a host with a different counter \
             frequency will run its whole clock fast or slow by that ratio. \
             CHM_STRICT_CNTFRQ=1 refuses such a snapshot instead."
                .to_string()
        } else {
            "the guest counter is re-stepped to the captured frequency, at a \
             measured 2.8% of wall time in stop-the-world barriers. Set \
             CHM_GUEST_CNTFRQ=0 to turn it off and accept the dilation, or \
             CHM_STRICT_CNTFRQ=1 to refuse an uncorrectable snapshot outright \
             (docs/hvf-compatible-snapshots.md)."
                .to_string()
        },
    });

    out
}

pub(crate) fn posture_main(raw: &[String]) -> ExitCode {
    if raw.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let json = raw.iter().any(|a| a == "--json");
    let Some(dir) = raw.iter().find(|a| !a.starts_with('-')).map(PathBuf::from) else {
        eprintln!("chm posture: usage: chm posture <WORKSPACE_DIR> [--json]");
        return ExitCode::FAILURE;
    };

    let controls = assess(&dir);
    let weakened = controls.iter().filter(|c| c.state == State::Weakened).count();

    if json {
        println!("{}", render_json(&dir, &controls, weakened));
    } else {
        println!("chm: security posture — {}", dir.display());
        println!();
        for c in &controls {
            println!("  [{}] {:<6} {}", c.state.mark(), c.invariant, c.name);
            for line in wrap(&c.detail, 66) {
                println!("            {line}");
            }
        }
        println!();
        if weakened == 0 {
            println!("  No control is weakened from its default. See docs/security-model.md.");
        } else {
            println!(
                "  {weakened} control(s) deliberately weakened — listed OFF above. \
                 See docs/security-model.md."
            );
        }
    }

    if weakened == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The posture of `dir` as JSON, plus the number of weakened controls, assessed
/// **in the calling process**.
///
/// This is the daemon's entry point: `chm serve` is the process that actually
/// runs the guest, so it is the only process whose environment describes the
/// sandbox. See the module docs.
pub(crate) fn assess_json(dir: &Path) -> (String, usize) {
    let controls = assess(dir);
    let weakened = controls.iter().filter(|c| c.state == State::Weakened).count();
    (render_json(dir, &controls, weakened), weakened)
}

fn render_json(dir: &Path, controls: &[Control], weakened: usize) -> String {
    let rows: Vec<String> = controls
        .iter()
        .map(|c| {
            format!(
                "    {{\"invariant\":{},\"control\":{},\"state\":{},\"detail\":{}}}",
                json_str(c.invariant),
                json_str(c.name),
                json_str(c.state.as_str()),
                json_str(&c.detail)
            )
        })
        .collect();
    format!(
        "{{\n  \"workspace\": {},\n  \"weakened\": {weakened},\n  \"controls\": [\n{}\n  ]\n}}",
        json_str(&dir.display().to_string()),
        rows.join(",\n")
    )
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Greedy word wrap. Whitespace-collapsing, which suits the multi-line string
/// literals the details are written as.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn usage() -> String {
    "usage: chm posture <WORKSPACE_DIR> [--json]\n\
     \n\
     Print the security posture that would govern a run started from this\n\
     workspace right now: every control, whether it is active, and how it was\n\
     decided. The executable form of the hardening checklist in\n\
     docs/security-model.md.\n\
     \n\
     Exits 0 when nothing is weakened from its default and 1 when something\n\
     is, so it can gate a script.\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_workspace_has_no_weakened_controls() {
        // A workspace with no configuration at all must still come up safe:
        // that is the whole point of V4.2. Guard against the env of whoever
        // runs the tests by only asserting on controls that do not read env.
        let controls = assess(Path::new("/nonexistent-workspace"));
        let limits = controls.iter().find(|c| c.name == "resource ceilings").unwrap();
        assert_eq!(
            limits.state,
            State::Active,
            "an unconfigured workspace must still be bounded, got: {}",
            limits.detail
        );
    }

    #[test]
    fn every_control_names_an_invariant_and_a_source() {
        for c in assess(Path::new("/nonexistent-workspace")) {
            assert!(!c.invariant.is_empty(), "{} has no invariant", c.name);
            assert!(
                c.detail.len() > 10,
                "{} says nothing about how it was decided",
                c.name
            );
        }
    }

    #[test]
    fn json_escapes_quotes_and_control_characters() {
        assert_eq!(json_str("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_str("a\nb"), "\"a\\nb\"");
        assert_eq!(json_str("a\u{1}b"), "\"a\\u0001b\"");
    }

    #[test]
    fn wrap_breaks_on_words_and_never_exceeds_width() {
        let long = "the quick brown fox jumps over the lazy dog and keeps going";
        for line in wrap(long, 20) {
            assert!(line.len() <= 20, "over-wide line: {line:?}");
        }
        assert_eq!(wrap("short", 20), vec!["short"]);
    }

    /// Every refusal `chm` can be asked for must appear in the posture report.
    ///
    /// This is the guard that was missing. `CHM_STRICT_ASID` shipped in #278 as
    /// a warning and a refusal, and `chm posture` -- the one command whose whole
    /// job is to answer "what can this sandbox do to me" -- did not mention the
    /// most severe of the four hazards, because nothing required the two to stay
    /// in step. Asserting the *outcome* (three rows exist) would not have caught
    /// it either; the fourth guard has to be discovered from the source that
    /// implements it.
    #[test]
    fn every_strict_refusal_is_reported_by_posture() {
        // Read the guard layer's own source rather than restating a list here:
        // a list would need updating by the same commit that adds a guard, which
        // is exactly the step this test exists to make unnecessary.
        let src = include_str!("imp.rs");
        let needle = format!("env::var_os(\"{}", "CHM_STRICT_");

        let mut vars: Vec<&str> = src
            .match_indices(&needle)
            .map(|(i, _)| {
                let rest = &src[i + needle.len() - "CHM_STRICT_".len()..];
                let end = rest.find('"').expect("unterminated env var name");
                &rest[..end]
            })
            .collect();
        vars.sort_unstable();
        vars.dedup();

        assert!(
            vars.len() >= 4,
            "found only {vars:?} -- the extraction is broken, not the report"
        );

        let controls = assess(Path::new("/nonexistent-workspace"));
        for var in vars {
            assert!(
                controls.iter().any(|c| c.detail.contains(var)),
                "{var} can refuse to start a guest, but `chm posture` never \
                 mentions it. Add a row to assess()."
            );
        }
    }
}
