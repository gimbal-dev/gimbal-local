// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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

    /// #290: the CTR_EL0 note used to say cache line sizes were "bit-identical,
    /// so cache maintenance strides stay correct". Measured from inside a
    /// running guest, `IminLine` reads 4096 B while the granule that actually
    /// invalidates is 64 B, so the strides are precisely the part that is
    /// wrong, and every JIT under-invalidates by 64x.
    ///
    /// The claim was never measurable by this command: HVF refuses CTR_EL0 and
    /// reports no host value, which is why the report prints `(unreadable)`
    /// next to it. A note that a tool cannot check is exactly the kind that
    /// needs pinning. This guard lives here rather than beside `note()` because
    /// the `hypervisor` crate's own tests cannot compile on macOS -- `kvm-ioctls`
    /// is Linux-only -- so a test next to the code would never run.
    #[test]
    fn the_ctr_note_names_the_stride_and_not_just_dic() {
        let note = SysregFinding {
            reg: 0xd801,
            captured: 0xb444_c004,
            fate: SysregFate::Refused { host: None },
        }
        .note()
        .expect("a refused CTR_EL0 diverges, so it must carry its note");
        for needle in ["IminLine", "4096", "64 B"] {
            assert!(
                note.contains(needle),
                "the CTR_EL0 note must carry {needle:?}: {note}"
            );
        }
        assert!(
            !note.contains("strides stay correct"),
            "the retracted #290 claim must not come back: {note}"
        );
    }

    /// The code retracted the #290 claim before the reference doc did, and the
    /// doc is what the code's own warning tells a reader to go and consult --
    /// so for one release the product pointed at a page still asserting the
    /// thing it had just corrected. That is the failure this repo keeps
    /// re-learning: a fact you established by hard work feels permanently
    /// verified, and the renewal lives in the file, not in memory.
    ///
    /// This pins the retraction rather than the prose around it. Finding 2's
    /// four-row table was measured entirely at offset 0 -- the one offset a
    /// 4096-byte stride covers -- so it may keep its numbers, but it may not
    /// keep the conclusion it drew from them.
    ///
    /// The guard cannot tell an assertion from a verbatim quotation of one, and
    /// it fired on the retraction's own first draft, which quoted the sentence
    /// it was withdrawing. The doc paraphrases instead. That is the right way
    /// round: a reader following a link to a retracted claim should find the
    /// correction, not the original wording sitting there to be skim-read.
    #[test]
    fn the_delta_doc_no_longer_blames_only_the_kernels_copy() {
        let doc = include_str!("../../docs/cpu-feature-deltas.md");

        // Prose wraps, so the claim can come back split across a line break and
        // a substring search would sail straight past it. The first mutation of
        // this guard did exactly that and the suite stayed green. Collapse
        // runs of whitespace before looking.
        let flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");

        // Assembled from parts: a literal needle here would match this test's
        // own source if the doc ever quoted it, and a guard that matches its
        // own assertion text cannot fail.
        let retracted = format!("only the {} elided copy is wrong", "kernel's");
        assert!(
            !flat.contains(&retracted),
            "docs/cpu-feature-deltas.md still draws the conclusion #290 falsified"
        );

        // The cure has to be here too: this page is where the product's own
        // warning sends a reader, and a page that states the defect without
        // stating the fix reads as an open hazard for as long as it stands.
        //
        // `SCTLR_EL1.UCT` is deliberately NOT one of these needles even though
        // it is the mechanism. The doc names that register while describing the
        // *problem* -- the erratum clears it -- so a needle on it matches
        // whether or not the fix is stated, and a mutation removing the cure
        // sailed straight past it. These two strings cannot appear anywhere but
        // an account of what shipped.
        for needle in [
            "IminLine",
            "offset 64",
            "#290",
            "ctr_trap_fixup",
            "CHM_KEEP_CTR_TRAP",
            "998",
        ] {
            assert!(
                flat.contains(needle),
                "the delta doc must record the stride finding: missing {needle:?}"
            );
        }
    }

    /// A capture that trapped EL0's `CTR_EL0` read must be corrected.
    ///
    /// The measured Graviton2 value is `0x3454599d`, whose bit 15 (`UCT`) is
    /// clear because Linux applied erratum 1542419 at boot. Left alone, EL0
    /// reads a 4096-byte i-cache stride against a real 64-byte granule.
    #[test]
    fn a_trapped_ctr_read_is_handed_back_to_the_hardware() {
        let captured_on_graviton2 = 0x3454_599du64;
        assert_eq!(
            captured_on_graviton2 & hypervisor::hvf::SCTLR_EL1_UCT,
            0,
            "this fixture is only meaningful while it has UCT clear"
        );

        let fixed = hypervisor::hvf::ctr_trap_fixup(captured_on_graviton2)
            .expect("a capture with UCT clear must be corrected");

        assert_eq!(
            fixed & hypervisor::hvf::SCTLR_EL1_UCT,
            hypervisor::hvf::SCTLR_EL1_UCT,
            "EL0 must be allowed to read this host's own CTR_EL0"
        );
        assert_eq!(
            fixed & !hypervisor::hvf::SCTLR_EL1_UCT,
            captured_on_graviton2,
            "no other SCTLR_EL1 bit may move; MMU and cache enables live here"
        );
    }

    /// A guest that never trapped the read is never rewritten.
    #[test]
    fn a_capture_that_already_reads_the_hardware_is_left_alone() {
        let untrapped = 0x3454_599du64 | hypervisor::hvf::SCTLR_EL1_UCT;
        assert!(
            hypervisor::hvf::ctr_trap_fixup(untrapped).is_none(),
            "nothing to correct when EL0 already reaches the hardware"
        );
    }

    /// The bit really is `UCT`, not a neighbour.
    ///
    /// `SCTLR_EL1.UCT` is bit 15. Bit 26 is `UCI`, which gates EL0 *cache
    /// maintenance* rather than the `CTR_EL0` read, so the two are easy to
    /// transpose — and transposing them fixes nothing at all, because the
    /// erratum leaves `UCI` set and EL0 maintenance was never trapped. See
    /// `the_captured_guest_already_runs_its_own_cache_maintenance` (#297).
    #[test]
    fn the_corrected_bit_is_uct_and_not_uci() {
        assert_eq!(hypervisor::hvf::SCTLR_EL1_UCT, 1 << 15);
        assert_ne!(hypervisor::hvf::SCTLR_EL1_UCT, 1 << 26);
    }

    /// The restore path must actually consult the fixup.
    ///
    /// Every other test here asserts an *outcome* of the pure function, and an
    /// outcome assertion structurally cannot see a call site that stopped
    /// calling it -- this repo has lost that bet five times (V9.5c, V9.11a,
    /// #222, #242, #244). So read the restore loop's own source.
    #[test]
    fn the_restore_path_still_corrects_the_captured_sctlr() {
        let src = include_str!("../../hypervisor/src/hvf/mod.rs");
        let needle = format!("{}(v).unwrap_or(v)", "ctr_trap_fixup");
        assert!(
            src.contains(&needle),
            "the SCTLR_EL1 restore arm must call ctr_trap_fixup: missing {needle:?}"
        );
    }

    /// #297, closed by a bit rather than a benchmark.
    ///
    /// The question was whether to set `SCTLR_EL1.UCI` as well, so EL0 cache
    /// maintenance runs natively instead of trapping into the erratum handler
    /// one line at a time -- a cost #296 looked to have multiplied by 64 when
    /// it handed EL0 the true 64-byte stride.
    ///
    /// The premise was false. Erratum 1542419's workaround clears `UCT` and
    /// leaves `UCI` alone, so those traps were never happening and there is no
    /// saving to win. This is the measurement, taken out of a real Graviton2
    /// capture's `state.json` rather than reasoned about: both vCPUs carry
    /// `SCTLR_EL1 = 0x3454591d`.
    ///
    /// Kept as a guard rather than a note because the reasoning that opened
    /// #297 was sound and only the capture could refute it. If a capture ever
    /// arrives with `UCI` clear, this fails and the trade genuinely re-opens.
    #[test]
    fn the_captured_guest_already_runs_its_own_cache_maintenance() {
        // Measured: /private/tmp/rculab-287/state.json, cpu-manager snapshots
        // 0 and 1, sysreg encoding 0xc080.
        let captured_on_graviton2 = 0x3454_591du64;

        assert_eq!(
            captured_on_graviton2 & hypervisor::hvf::SCTLR_EL1_UCI,
            hypervisor::hvf::SCTLR_EL1_UCI,
            "EL0 cache maintenance already runs on the hardware, so there are \
             no traps for #297 to remove"
        );
        assert_eq!(
            captured_on_graviton2 & hypervisor::hvf::SCTLR_EL1_UCT,
            0,
            "...while the CTR_EL0 read really was trapped -- the two bits move \
             independently, which is the whole finding"
        );
        assert_eq!(hypervisor::hvf::SCTLR_EL1_UCI, 1 << 26);
    }
}
