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

use std::env;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

    // I7 — interrupt routing. Structural, but has a diagnostic override that
    // genuinely produces a broken guest, so it is worth surfacing.
    let allow_its = env::var("CHM_ALLOW_ITS_LPI").is_ok();
    out.push(Control {
        invariant: "I7",
        name: "deliverable-interrupt routing",
        state: if allow_its { State::Weakened } else { State::Active },
        detail: if allow_its {
            "CHM_ALLOW_ITS_LPI is set — an ITS/LPI capture may be run on the \
             managed GIC, which cannot deliver its completions"
                .to_string()
        } else {
            "ITS/LPI captures routed to the userspace GICv3".to_string()
        },
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
}
