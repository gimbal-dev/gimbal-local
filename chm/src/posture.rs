// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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
use crate::runs;
use crate::signing;
use hypervisor::hvf::virtio::nat::INGRESS_BIND_ADDR;

/// The runtime probe for an unprivileged user namespace, as argv.
///
/// Shared with [`crate::oci::browser::launch_script`], which runs the same
/// command to decide whether Chromium keeps its own sandbox. Two copies would
/// eventually ask two different questions, and a posture row describing a
/// different question than the browser asks is worse than no row: it would
/// report on a capability nothing actually depends on.
///
/// It is a **probe, not a sysctl read**. `kernel.apparmor_restrict_unprivileged_userns`
/// is one distro's route to withholding the capability; seccomp, a different
/// LSM, or a kernel built without `CONFIG_USER_NS` all withhold it too, and a
/// report that read only the sysctl would call those guests capable.
pub(crate) const USERNS_PROBE_ARGV: [&str; 4] = ["unshare", "--user", "--map-root-user", "true"];

/// The sysctl that withholds it on Ubuntu 23.10 and later, and therefore in
/// every rehydrated Ubuntu 24.04 capture.
pub(crate) const APPARMOR_USERNS_SYSCTL: &str = "kernel.apparmor_restrict_unprivileged_userns";

/// Whether a control is on, and how strongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// On, at or above the safe default.
    Active,
    /// On, but deliberately relaxed from the safe default.
    Weakened,
    /// Off, and off is the documented posture (not a weakening).
    NotApplicable,
    /// Nobody established either way, and this report says so.
    ///
    /// The first state that admits ignorance, and it exists because the
    /// alternatives all lie. `NotApplicable` would claim the posture is a
    /// documented off; `Active` would claim a capability nothing checked;
    /// `Weakened` would exit non-zero over an absence of looking. This repo has
    /// banked the same failure seven times — a mechanism reporting safety it
    /// never established — and an unasked question is exactly that shape.
    ///
    /// Deliberately **not** counted in the weakened total, so it cannot change
    /// an exit status. `chm posture && deploy` must not start refusing because
    /// a check was skipped.
    Unmeasured,
}

impl State {
    fn mark(self) -> &'static str {
        match self {
            State::Active => "on ",
            State::Weakened => "OFF",
            State::NotApplicable => "n/a",
            State::Unmeasured => " ? ",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Weakened => "weakened",
            State::NotApplicable => "not-applicable",
            State::Unmeasured => "unmeasured",
        }
    }
}

/// What a running guest answered when asked whether an unprivileged process
/// inside it can obtain a user namespace.
///
/// This is an **injected input**, never something [`assess`] reaches for. Every
/// other row in this report resolves from the host — an env var, a file, a
/// registry — and can be computed by any process. This one can only be answered
/// by a guest, over a console, by writing to it; so the decision to ask belongs
/// to the caller that owns the guest, and `assess` stays pure over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuestUserns {
    /// Nobody asked, and why. The ordinary case: `chm posture` has no guest,
    /// and `chm ctl posture` does not interrupt one without being told to.
    NotAsked(String),
    /// Asked, and the guest did not answer — a timeout, a busy console, a
    /// transport failure. Distinct from [`Self::NotAsked`] because a question
    /// that went unanswered is a different fact from one never put.
    NoAnswer(String),
    /// The probe succeeded: an unprivileged process here gets a user namespace.
    Available,
    /// The probe failed, carrying the guest's own words for why.
    Restricted(String),
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
///
/// `guest_userns` is injected rather than measured here: see [`GuestUserns`].
fn assess(dir: &Path, guest_userns: &GuestUserns) -> Vec<Control> {
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

    // I14 — ingress. Every other row here answers for *this*
    // process's environment or *this* workspace's files. Ingress can do
    // neither: `--expose` is a flag on `chm create`, so it is neither an env
    // binding nor a file, and it has already been consumed by the time a guest
    // is running. The live-run registry is the only thing that records it.
    //
    // That makes this row machine-scoped rather than workspace-scoped, and
    // that is the correct scope rather than a compromise: a published port is
    // bound on host loopback, which every process on this host shares. A door
    // into someone else's sandbox is still a door into this machine, and a
    // posture report that stayed silent about it because a different directory
    // opened it would be reporting the boundary it did not check.
    out.push(ingress_control(&runs::registry_dir()));

    out.push(guest_userns_control(guest_userns));

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

/// The ingress row, over an injected registry directory so it is testable.
///
/// This is the executable form of **I14**, which has been written down since
/// V11.0 with a full evidence column and has never had a posture row. The
/// posture-coupling guard could not have caught that: it requires every
/// `CHM_STRICT_*` env var to appear in a row, and ingress is armed by a CLI
/// flag on `chm create`, not by the environment.
///
/// It is also the one control that escapes the "whose posture is it?" trap by
/// construction. Every other row resolves from the environment of the process
/// computing it, so `chm posture` and `chm ctl posture` can legitimately
/// disagree; a published port is a property of a **live run**, so both read the
/// same machine-wide registry and both answer for the whole Mac.
///
/// Three outcomes, not two. The third is the point:
///
/// * ports published → **weakened**. It is a deliberate weakening and the
///   report exits non-zero, which is what makes `chm posture && deploy` refuse
///   while a door into a sandbox is open.
/// * nothing published → **not applicable**. There is no inbound surface to
///   describe, and calling that "active" would claim a control we do not run.
/// * the registry could not be read → **weakened**, naming the reason. It must
///   not read as "nothing is exposed": that is the shape of failure this repo
///   has banked seven times, a mechanism reporting safety it never established.
fn ingress_control(registry: &Path) -> Control {
    let (state, detail) = match runs::try_list_in(registry) {
        Err(e) => (
            State::Weakened,
            format!(
                "could not read the live-run registry ({}): {e}. This report \
                 cannot say whether a sandbox on this machine publishes a port, \
                 so treat it as if one does.",
                registry.display()
            ),
        ),
        Ok(live) => {
            let mut published: Vec<String> = live
                .iter()
                .filter(|r| !r.exposed.is_empty())
                .map(|r| {
                    let ports: Vec<String> = r.exposed.iter().map(u16::to_string).collect();
                    format!("{} (pid {}) {}", r.label, r.pid, ports.join(","))
                })
                .collect();
            published.sort();
            if published.is_empty() {
                (
                    State::NotApplicable,
                    format!(
                        "no guest running on this machine publishes a port. \
                         `chm create --expose <PORT>` opens one, on \
                         {INGRESS_BIND_ADDR}."
                    ),
                )
            } else {
                (
                    State::Weakened,
                    format!(
                        "reachable from this host on {INGRESS_BIND_ADDR}: {}. \
                         Anything on this machine can dial those, not just the \
                         process that asked for them. `chm ps` lists them; \
                         stopping the guest closes them.",
                        published.join("; ")
                    ),
                )
            }
        }
    };
    Control {
        invariant: "I14",
        name: "guest ingress",
        state,
        detail,
    }
}

/// The in-guest user-namespace row, over an injected answer so it is testable.
///
/// **This is the first row in this report that the host cannot answer.**
/// Everything else describes what chm does *to* a guest; this describes what
/// the guest can do. Two guests on the same hypervisor, the same binary and the
/// same flags differ here: a container rootfs built by `chm image build`
/// carries no AppArmor policy, while a rehydrated Ubuntu 24.04 capture carries
/// `kernel.apparmor_restrict_unprivileged_userns=1` in from the cloud host.
///
/// It escapes the "whose posture is it?" trap the same way [`ingress_control`]
/// does, and for the opposite reason: ingress is a property of a live run on
/// this machine, and this is a property of the guest image. Neither is read
/// from the environment of whoever happens to be computing the report, so
/// `chm posture` and `chm ctl posture` cannot disagree about it — the CLI
/// simply has no guest to ask.
///
/// Four inputs, three states. The mapping is the whole design:
///
/// * [`GuestUserns::Available`] → **active**. Defence in depth: the guest can
///   contain a browser, podman or bubblewrap *inside* the VM boundary.
/// * [`GuestUserns::Restricted`] → **not applicable**, never weakened. A stock
///   Ubuntu default is not a misconfiguration, and grading it as a weakening
///   would make `chm posture && deploy` refuse over every capture we hold.
/// * [`GuestUserns::NotAsked`] / [`GuestUserns::NoAnswer`] → **unmeasured**,
///   each naming its own reason. Reporting an unasked question as "n/a" would
///   claim a measured off; reporting it as "active" would claim a capability.
fn guest_userns_control(answer: &GuestUserns) -> Control {
    let probe = USERNS_PROBE_ARGV.join(" ");
    let (state, detail) = match answer {
        GuestUserns::Available => (
            State::Active,
            format!(
                "`{probe}` succeeded in the running guest, so an unprivileged \
                 process there can contain itself: Chromium keeps its own \
                 sandbox, and podman and bubblewrap work. The VM boundary is \
                 not the only isolation in this guest."
            ),
        ),
        GuestUserns::Restricted(why) => (
            State::NotApplicable,
            format!(
                "`{probe}` was refused in the running guest ({}). The VM \
                 boundary still holds and is the premise of this sandbox, but \
                 it is the only isolation here -- Chromium falls back to \
                 --no-sandbox and podman and bubblewrap will not start. This is \
                 the stock Ubuntu 23.10+ default, not a misconfiguration: \
                 `sudo sysctl -w {APPARMOR_USERNS_SYSCTL}=0` in the guest \
                 restores it (docs/first-resume.md).",
                why.trim()
            ),
        ),
        GuestUserns::NoAnswer(why) => (
            State::Unmeasured,
            format!(
                "the running guest was asked and did not answer ({why}), so \
                 this report cannot say whether an unprivileged process there \
                 gets a user namespace. Do not read that as either answer."
            ),
        ),
        GuestUserns::NotAsked(why) => (
            State::Unmeasured,
            format!(
                "not measured: {why}. This is the one control only the guest \
                 can answer -- `chm ctl posture --probe-guest` runs `{probe}` \
                 in a running guest and reports what it said."
            ),
        ),
    };
    Control {
        invariant: "#363",
        name: "in-guest user namespaces",
        state,
        detail,
    }
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

    // Never probes. This process has no guest -- `chm posture` reads a
    // directory -- and reaching for one would mean opening a control socket
    // from a command documented as describing a workspace.
    let controls = assess(
        &dir,
        &GuestUserns::NotAsked(
            "`chm posture` reads a workspace directory and has no guest to ask".into(),
        ),
    );
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
///
/// `guest_userns` has **no default**, deliberately. The daemon is the only
/// caller that can ask a guest anything, so if this parameter could be omitted
/// the one code path capable of measuring the row would be able to silently
/// stop doing so and every test would stay green. Requiring it makes that a
/// compile error instead of a guard.
pub(crate) fn assess_json(dir: &Path, guest_userns: &GuestUserns) -> (String, usize) {
    let controls = assess(dir, guest_userns);
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

pub(crate) fn json_str(s: &str) -> String {
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

    /// The answer every test that does not care about the guest row passes.
    fn unasked() -> GuestUserns {
        GuestUserns::NotAsked("a test".into())
    }

    #[test]
    fn baseline_workspace_has_no_weakened_controls() {
        // A workspace with no configuration at all must still come up safe:
        // that is the whole point of V4.2. Guard against the env of whoever
        // runs the tests by only asserting on controls that do not read env.
        let controls = assess(Path::new("/nonexistent-workspace"), &unasked());
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
        for c in assess(Path::new("/nonexistent-workspace"), &unasked()) {
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

        let controls = assess(Path::new("/nonexistent-workspace"), &unasked());
        for var in vars {
            assert!(
                controls.iter().any(|c| c.detail.contains(var)),
                "{var} can refuse to start a guest, but `chm posture` never \
                 mentions it. Add a row to assess()."
            );
        }
    }

    /// The registry is the only thing that can answer for ingress.
    ///
    /// `--expose` is a flag on `chm create` — not an env var, not a workspace
    /// file — so `assess`, which reads this process's environment and a
    /// workspace directory, structurally cannot see it. Ingress is a property
    /// of a *live run*, which is what the run registry records.
    ///
    /// The records are made by `register_in` rather than written by hand,
    /// because a hand-written record is *dead*: liveness is an `flock` held by
    /// the writer, so a synthetic file is reaped on the first read and every
    /// assertion below would pass by describing an empty registry. That is
    /// exactly how the first draft of these tests passed while proving nothing.
    fn live_registry(name: &str, exposed: &[u16]) -> (std::path::PathBuf, runs::Registration) {
        let dir = std::env::temp_dir().join(format!(
            "chm-posture-ingress-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let reg = runs::register_in(
            &dir,
            runs::Kind::Cold,
            name,
            &format!("/img/{name}"),
            2,
            2048,
            exposed,
        )
        .expect("registry is writable")
        .expect("registration");
        (dir, reg)
    }

    /// A published port is a weakening, and the report has to say so.
    ///
    /// It is a deliberate one — `--expose` is opt-in and refused without
    /// `--net` — but `chm posture` is a gate (`chm posture && deploy`), so
    /// exiting 0 while a door into a sandbox stands open is the whole failure
    /// this row exists to remove.
    #[test]
    fn a_published_port_is_reported_as_a_weakened_control() {
        let (dir, reg) = live_registry("browser", &[9222]);
        let c = ingress_control(&dir);
        assert_eq!(c.state, State::Weakened, "an open port read as safe");
        assert!(c.detail.contains("9222"), "the port itself is not named");
        assert!(
            c.detail.contains("browser"),
            "the run holding it is not named"
        );
        assert!(
            c.detail.contains(&INGRESS_BIND_ADDR.to_string()),
            "the address the port is bound to is not named"
        );
        drop(reg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing published is not a control we are running, so do not claim one.
    #[test]
    fn no_published_port_is_not_applicable_rather_than_active() {
        let (dir, reg) = live_registry("quiet", &[]);
        let c = ingress_control(&dir);
        assert_eq!(
            c.state,
            State::NotApplicable,
            "a guest with no exposed port was reported as one that has some"
        );
        drop(reg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The branch this row exists for.
    ///
    /// "No run publishes a port" and "I could not find out" are opposite
    /// claims, and reporting the first when the second is true is a mechanism
    /// asserting safety it never established — the shape of failure this repo
    /// has banked seven times.
    #[test]
    fn a_registry_that_cannot_be_read_is_never_reported_as_nothing_exposed() {
        let path = std::env::temp_dir().join(format!("chm-posture-blind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::write(&path, b"not a directory").unwrap();

        let c = ingress_control(&path);
        assert_eq!(
            c.state,
            State::Weakened,
            "an unreadable registry was reported as a machine with no open ports"
        );
        assert!(
            c.detail.contains("could not read"),
            "the report does not say that it failed to find out"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A row nobody adds to the report is a row nobody reads.
    ///
    /// `assess` is where the report is assembled, and an assertion about
    /// `ingress_control`'s return value cannot see a call site that no longer
    /// exists — the class this repo has missed seven times. Needle assembled
    /// from parts so it cannot match its own assertion text.
    #[test]
    fn the_report_actually_carries_the_ingress_row() {
        let needle = format!("{}(&runs::registry_dir())", "ingress_control");
        assert!(
            include_str!("posture.rs").contains(&needle),
            "chm posture no longer reports ingress, so a sandbox can be \
             reachable from this host with nothing saying so"
        );
    }
}

/// Guards for the in-guest user-namespace row (#363).
///
/// The coupling guard in the module's other test block cannot see this row: it
/// requires every `CHM_STRICT_*` behind an `env::var_os` in `imp.rs` to appear
/// in some row, and this control has no env var at all -- like
/// [`ingress_control`], it is a property of a guest rather than of the calling
/// process. So it needs its own.
#[cfg(test)]
mod guest_userns_tests {
    use super::*;

    fn row(answer: &GuestUserns) -> Control {
        guest_userns_control(answer)
    }

    /// The mapping is the design, so it is the thing to pin.
    #[test]
    fn each_answer_maps_to_the_state_that_does_not_overclaim() {
        assert_eq!(
            row(&GuestUserns::Available).state,
            State::Active,
            "a guest that can contain its own processes has the control on"
        );
        assert_eq!(
            row(&GuestUserns::NotAsked("x".into())).state,
            State::Unmeasured,
            "a question never put must not read as an answer"
        );
        assert_eq!(
            row(&GuestUserns::NoAnswer("x".into())).state,
            State::Unmeasured,
            "a question that went unanswered must not read as an answer"
        );
    }

    /// The load-bearing one, and the reason this row exists at all.
    ///
    /// `Restricted` is the *stock* Ubuntu 23.10+ posture and every rehydrated
    /// capture we hold is in it. Grading it `Weakened` would exit 1, so
    /// `chm posture && deploy` would refuse on every one of them -- a check
    /// that always fails is a check people delete.
    #[test]
    fn a_restricted_guest_is_not_a_weakened_one() {
        let c = row(&GuestUserns::Restricted("denied".into()));
        assert_eq!(
            c.state,
            State::NotApplicable,
            "the stock distro default was graded as a misconfiguration"
        );
        assert_ne!(c.state, State::Weakened);
    }

    /// An unmeasured control must not be able to change an exit status.
    ///
    /// Asserted through the same counting expression `posture_main` and
    /// `assess_json` use, rather than over the enum, because the exit code is
    /// what a caller actually gates on.
    #[test]
    fn unmeasured_does_not_count_towards_weakened() {
        for answer in [
            GuestUserns::NotAsked("x".into()),
            GuestUserns::NoAnswer("x".into()),
        ] {
            let controls = [row(&answer)];
            let weakened = controls
                .iter()
                .filter(|c| c.state == State::Weakened)
                .count();
            assert_eq!(weakened, 0, "an unasked question changed the exit code");
        }
    }

    /// A refusal that does not name its cure sends the reader to a search
    /// engine. Needle assembled from parts so it cannot match itself.
    #[test]
    fn a_restricted_guest_is_told_the_one_command_that_fixes_it() {
        let c = row(&GuestUserns::Restricted("Operation not permitted".into()));
        let sysctl = format!("sysctl -w {APPARMOR_USERNS_SYSCTL}=0");
        assert!(
            c.detail.contains(&sysctl),
            "the remedy is not in the detail: {}",
            c.detail
        );
        assert!(
            c.detail.contains("Operation not permitted"),
            "the guest's own words were dropped: {}",
            c.detail
        );
        assert!(
            c.detail.contains("--no-sandbox"),
            "the consequence is not named: {}",
            c.detail
        );
    }

    /// A report that says "not measured" and stops has told the reader nothing
    /// they can act on -- the #304/#305/#306 defect class.
    #[test]
    fn an_unmeasured_row_names_the_command_that_would_measure_it() {
        let c = row(&GuestUserns::NotAsked("no guest".into()));
        let cmd = format!("chm ctl posture --{}", "probe-guest");
        assert!(
            c.detail.contains(&cmd),
            "nothing tells the reader how to get an answer: {}",
            c.detail
        );
    }

    /// `chm posture` has no guest, so it must never claim one answered.
    #[test]
    fn the_cli_reports_this_row_as_unmeasured() {
        let controls = assess(
            Path::new("/nonexistent-workspace"),
            &GuestUserns::NotAsked("no guest".into()),
        );
        let c = controls
            .iter()
            .find(|c| c.invariant == "#363")
            .expect("the row is missing from assess()");
        assert_eq!(c.state, State::Unmeasured);
    }

    /// The wire value the app decodes on. Changing it silently would make the
    /// panel fall back to `weakened` and alarm over a skipped check.
    #[test]
    fn unmeasured_has_a_stable_wire_name_and_a_mark_of_its_own() {
        assert_eq!(State::Unmeasured.as_str(), "unmeasured");
        for other in [State::Active, State::Weakened, State::NotApplicable] {
            assert_ne!(
                State::Unmeasured.mark(),
                other.mark(),
                "unmeasured is indistinguishable from {} in the rendered report",
                other.as_str()
            );
        }
    }

    /// The browser must probe the same thing the report describes.
    ///
    /// If these diverge, `chm posture` answers a question nothing depends on
    /// while the browser silently takes the other branch. Reads both out of the
    /// machine rather than restating either.
    #[test]
    fn the_browser_runs_the_probe_this_row_reports_on() {
        let script = crate::oci::browser::launch_script();
        let probe = USERNS_PROBE_ARGV.join(" ");
        assert!(
            script.contains(&probe),
            "the browser no longer runs `{probe}`, so this row describes a \
             different question than the one it depends on"
        );
        assert!(
            script.contains(APPARMOR_USERNS_SYSCTL),
            "the browser's remedy no longer names {APPARMOR_USERNS_SYSCTL}"
        );
    }
}
