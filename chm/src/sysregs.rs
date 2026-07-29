// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm sysregs` — which of a capture's CPU registers this Mac reproduces.
//!
//! A guest probes its host's identity and feature registers once, at boot, and
//! caches the answers. Rehydrating it somewhere else does not re-run those
//! probes, so any register the new host answers differently leaves the guest
//! acting on a stale belief.
//!
//! That is not hypothetical. `CNTFRQ_EL0` reads 121 875 000 Hz on Graviton2 and
//! 24 000 000 Hz on Apple silicon; Linux caches it at boot; the result was a
//! guest whose clock ran 5.08x slow, found by accident months later. This
//! command exists so the next one is found in a second instead.
//!
//! ```text
//! chm sysregs <SNAPSHOT_DIR> [--all] [--json] [--vcpu N]
//! ```
//!
//! By default it prints only registers that **diverge** — where this host
//! refuses or clamps the captured value — because those are the actionable
//! ones. `--all` shows every register including the faithfully restored.

use std::mem;
use std::path::PathBuf;
use std::process::ExitCode;

use hypervisor::hvf::HvfHypervisor;
use hypervisor::hvf::SysregFate;
use hypervisor::hvf::sysreg_audit::{audit_snapshot, SysregFinding};

use crate::imp::load_snapshot;

/// Parsed `chm sysregs` invocation.
struct Args {
    dir: PathBuf,
    /// Show every register, not just the divergent ones.
    all: bool,
    json: bool,
    vcpu: usize,
}

fn usage() -> &'static str {
    "usage: chm sysregs <SNAPSHOT_DIR> [--all] [--json] [--vcpu N]\n\
     \n\
     Replay a capture's CPU system registers against this Mac and report which\n\
     ones it cannot reproduce. A guest caches these at boot, so a register this\n\
     host answers differently leaves the guest acting on a stale belief.\n\
     \n\
     Options:\n\
     \x20 --all      show every register, not just the divergent ones\n\
     \x20 --json     machine-readable output\n\
     \x20 --vcpu N   audit vCPU N (default 0)\n"
}

fn parse(raw: &[String]) -> Result<Args, String> {
    let mut dir = None;
    let mut all = false;
    let mut json = false;
    let mut vcpu = 0usize;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--all" => all = true,
            "--json" => json = true,
            "--vcpu" => {
                i += 1;
                let v = raw.get(i).ok_or("--vcpu needs a number")?;
                vcpu = v.parse().map_err(|_| format!("--vcpu: not a number: {v}"))?;
            }
            "-h" | "--help" => return Err(usage().to_string()),
            s if s.starts_with('-') => return Err(format!("unknown option: {s}")),
            s => dir = Some(PathBuf::from(s)),
        }
        i += 1;
    }
    Ok(Args {
        dir: dir.ok_or("missing SNAPSHOT_DIR")?,
        all,
        json,
        vcpu,
    })
}

/// Render one register's fate as a short human phrase plus the value the guest
/// will actually observe.
fn describe(f: &SysregFinding) -> (String, String) {
    match f.fate {
        SysregFate::Restored => ("restored".into(), format!("{:#x}", f.captured)),
        SysregFate::Unverifiable => ("write-only".into(), "(cannot read back)".into()),
        SysregFate::Refused { host } => (
            "REFUSED".into(),
            match host {
                Some(h) => format!("{h:#x}"),
                None => "(unreadable)".into(),
            },
        ),
        SysregFate::Clamped { observed, .. } => ("CLAMPED".into(), format!("{observed:#x}")),
    }
}

pub(crate) fn sysregs_main(raw: &[String]) -> ExitCode {
    let args = match parse(raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let loaded = match load_snapshot(&args.dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("chm: {e}");
            return ExitCode::FAILURE;
        }
    };

    let hv = match HvfHypervisor::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("chm: Hypervisor.framework unavailable: {e}");
            return ExitCode::FAILURE;
        }
    };

    let findings = match audit_snapshot(hv.as_ref(), &loaded.snap, args.vcpu) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("chm: sysreg audit failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let divergent: Vec<&SysregFinding> = findings.iter().filter(|f| f.fate.diverges()).collect();
    let identity_divergent: Vec<&&SysregFinding> =
        divergent.iter().filter(|f| f.is_identity()).collect();

    if args.json {
        let rows: Vec<serde_json::Value> = findings
            .iter()
            .filter(|f| args.all || f.fate.diverges())
            .map(|f| {
                let (fate, observed) = describe(f);
                serde_json::json!({
                    "register": f.name(),
                    "encoding": format!("{:#06x}", f.reg),
                    "captured": format!("{:#x}", f.captured),
                    "fate": fate,
                    "guest_observes": observed,
                    "identity": f.is_identity(),
                    "note": f.note(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "snapshot": args.dir.display().to_string(),
            "vcpu": args.vcpu,
            "total": findings.len(),
            "divergent": divergent.len(),
            "identity_divergent": identity_divergent.len(),
            "registers": rows,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        return ExitCode::SUCCESS;
    }

    println!(
        "chm: system-register audit — {} ({} vCPU{}, auditing vCPU {})",
        args.dir.display(),
        loaded.num_vcpus,
        if loaded.num_vcpus == 1 { "" } else { "s" },
        args.vcpu
    );
    println!(
        "     {} registers captured, {} reproduced faithfully, {} divergent ({} of them host-identity)\n",
        findings.len(),
        findings.len() - divergent.len(),
        divergent.len(),
        identity_divergent.len()
    );

    let shown: Vec<&SysregFinding> = if args.all {
        findings.iter().collect()
    } else {
        divergent.clone()
    };

    if shown.is_empty() {
        println!("     No divergence: this Mac reproduces every captured register.");
        return ExitCode::SUCCESS;
    }

    println!(
        "  {:<18} {:<8} {:<20} {:<10} GUEST OBSERVES",
        "REGISTER", "ENCODING", "CAPTURED", "FATE"
    );
    for f in &shown {
        let (fate, observed) = describe(f);
        let mark = if f.is_identity() { "*" } else { " " };
        println!(
            "{mark} {:<18} {:#06x}   {:<20} {:<10} {}",
            f.name(),
            f.reg,
            format!("{:#x}", f.captured),
            fate,
            observed
        );
    }

    if !identity_divergent.is_empty() {
        println!(
            "\n  * marks a host-identity register — the class a guest reads once at boot\n\
             \x20   and caches. These are where a silent behaviour change comes from."
        );
    }

    // The list is data; these are the answers. Computed over *all* findings, not
    // just the divergent ones, because the most dangerous register we have found
    // is one this Mac restores perfectly (ID_AA64PFR0_EL1's AArch32 bit).
    let annotated: Vec<(&SysregFinding, &'static str)> = findings
        .iter()
        .filter_map(|f| f.note().map(|n| (f, n)))
        .collect();
    if !annotated.is_empty() {
        println!("\n  What these mean (measured on this hardware):\n");
        for (f, note) in annotated {
            println!("  {}:", f.name());
            for line in wrap(note, 72) {
                println!("      {line}");
            }
            println!();
        }
        println!("  Full analysis: docs/cpu-feature-deltas.md");
    }
    ExitCode::SUCCESS
}

/// Wrap `text` to `width` columns on word boundaries.
///
/// Hand-rolled rather than pulled in as a dependency: this is the only place in
/// `chm` that needs it, and a wrapping crate is not worth a supply-chain entry.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_on_word_boundaries_without_splitting_words() {
        let lines = wrap("the quick brown fox jumps over the lazy dog", 12);
        assert!(lines.iter().all(|l| l.len() <= 12), "{lines:?}");
        assert_eq!(lines.join(" "), "the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn wrapping_a_short_string_leaves_it_on_one_line() {
        assert_eq!(wrap("short", 72), vec!["short".to_string()]);
        assert!(wrap("", 72).is_empty());
    }

    #[test]
    fn parses_the_flags_that_change_what_is_reported() {
        let a = parse(&[
            "snap".into(),
            "--all".into(),
            "--json".into(),
            "--vcpu".into(),
            "2".into(),
        ])
        .expect("parse");
        assert_eq!(a.dir, PathBuf::from("snap"));
        assert!(a.all && a.json);
        assert_eq!(a.vcpu, 2);
    }

    #[test]
    fn refuses_an_invocation_with_no_snapshot() {
        assert!(parse(&["--all".into()]).is_err());
        assert!(parse(&["snap".into(), "--vcpu".into()]).is_err());
        assert!(parse(&["snap".into(), "--nonsense".into()]).is_err());
    }
}
