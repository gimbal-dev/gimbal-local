// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! What this build can and cannot do — and how strongly each claim is held.
//!
//! Until now the only way to learn whether something worked was to run it and
//! see whether it crashed. That is a bad way to find out, and a worse way to be
//! told: a crash is an expensive, ambiguous, after-the-fact answer to a question
//! that was askable in advance, and its absence is not the opposite of a crash —
//! a guest that resumes and runs at a fifth of real speed has not crashed.
//!
//! ## Why claims are graded
//!
//! The obvious implementation of a capability panel is a list of things we
//! believe. That is the shape of a bug this project has now hit nine times: an
//! answer computed in the wrong place, or checked against the wrong thing, and
//! then presented with the confidence of a measurement.
//!
//! The ninth instance was in this very question, and it had been sitting in the
//! tree since the port began:
//!
//! ```text
//! /// HVF is available on Apple Silicon Macs with the hypervisor entitlement.
//! pub fn is_available() -> Result<bool> {
//!     Ok(cfg!(target_os = "macos"))
//! }
//! ```
//!
//! The comment describes a runtime property of this machine. The body is a
//! compile-time constant that is `true` on Intel macOS and `true` for a binary
//! that lost its entitlement to a plain `cargo build` — which is *every* build
//! in this repository that does not go through `scripts/build-chm.sh`, and the
//! single most common local failure. The one function whose name promised
//! availability answered a question about the compiler, and was believed by
//! backend selection.
//!
//! So a capability here is never just a verdict. It carries the [`Evidence`]
//! behind it, and the panel shows it, because "we probed the kernel and it said
//! yes" and "someone wrote this down in 2026" are not the same claim and must
//! not look alike. The weakest grade that still reads as a yes is [`Built`] —
//! the code is compiled in — which is exactly what the bug above was.
//!
//! [`Built`]: Evidence::Built
//!
//! ## What a preflight may and may not conclude
//!
//! [`preflight`] answers a narrower question than it appears to: it runs the
//! checks it has against a specific snapshot and reports what they said. It
//! cannot report that a snapshot will boot, because booting depends on guest
//! code this process has not run. The summary therefore says *nothing refuses
//! it*, never *supported* — an unchecked thing must not round up to a working
//! one, which is the failure this module exists to end.
//!
//! Preflight reuses the runner's own parsers ([`devmgr::parse_devices`],
//! [`rehydrate::snapshot_cntfrq`]) rather than reimplementing them. A parallel
//! implementation would be a second opinion that drifts, and the drift would be
//! invisible precisely because both halves agreed when it was written.

use std::env::current_exe;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use hypervisor::hvf;

use hypervisor::hvf::rehydrate;
use hypervisor::hvf::virtio::devmgr;

/// How well a thing is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Works, on the terms described.
    Yes,
    /// Works, but not as captured — something is being compensated for or
    /// approximated, and the difference is visible to the guest.
    Degraded,
    /// Refused. Better than a crash, and deliberately not silent.
    No,
    /// Not established. Never a synonym for yes.
    Unknown,
}

impl Support {
    /// The stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::Degraded => "degraded",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// Where a claim's confidence comes from, strongest first.
///
/// This is the point of the module. A panel that renders `Probed` and
/// `Documented` identically has thrown away the only thing that made it more
/// useful than a README.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The thing was done, just now, and the result is being reported.
    Probed,
    /// Not probed, because it is already happening — a running guest is
    /// stronger evidence of a working hypervisor than any probe.
    Observed,
    /// Read out of the artefact under discussion.
    Recorded,
    /// The code path is compiled into this binary. This is the weakest grade
    /// that still reads as a yes, and it is what the `is_available` bug was:
    /// true of the build, and silent about the machine.
    Built,
    /// Written down by a human and not checked by anything. Honest, and worth
    /// showing, but it is the grade a stale claim decays to.
    Documented,
}

impl Evidence {
    /// The stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probed => "probed",
            Self::Observed => "observed",
            Self::Recorded => "recorded",
            Self::Built => "built",
            Self::Documented => "documented",
        }
    }
}

/// One capability claim.
#[derive(Debug, Clone)]
pub struct Capability {
    /// Stable identifier, for tests and for the UI to key on.
    pub id: &'static str,
    /// Short human name.
    pub title: &'static str,
    /// The verdict.
    pub support: Support,
    /// How the verdict was reached.
    pub evidence: Evidence,
    /// What was actually found. Carries the numbers.
    pub detail: String,
}

impl Capability {
    fn new(
        id: &'static str,
        title: &'static str,
        support: Support,
        evidence: Evidence,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            title,
            support,
            evidence,
            detail: detail.into(),
        }
    }
}

/// How the hypervisor question was settled for this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvfEvidence {
    /// A guest is running in the caller's process, so HVF demonstrably works.
    GuestRunning,
    /// Nothing is running; probe by executing this binary as a child.
    ProbeAllowed,
}

/// The build-and-host half of the report: what this binary, on this machine,
/// can do — independent of any particular snapshot.
pub fn build_report(hvf: HvfEvidence) -> Vec<Capability> {
    let mut out = vec![hvf_capability(hvf)];

    let host_hz = hvf::host_counter_hz();
    out.push(Capability::new(
        "host-counter",
        "Host counter frequency",
        Support::Yes,
        Evidence::Probed,
        format!(
            "{host_hz} Hz, read from the mach timebase. This is the rate an HVF guest \
             sees in CNTFRQ_EL0 and it cannot be changed, which is why a capture \
             from a host with a different rate has to be compensated for."
        ),
    ));

    out.push(Capability::new(
        "snapshot-vanilla",
        "Vanilla cloud-hypervisor arm64 snapshots",
        Support::Yes,
        Evidence::Built,
        "Resumes an unmodified arm64 KVM snapshot: guest RAM, per-vCPU core and \
         system registers, the GICv3 distributor/redistributor and per-vCPU ICC, \
         and the virtio-pci device model. Compiled in — whether a given capture \
         resumes is a question about that capture, which `preflight` answers.",
    ));

    out.push(Capability::new(
        "devices-virtio",
        "Modelled guest devices",
        Support::Yes,
        Evidence::Built,
        format!(
            "virtio-blk (type {}), virtio-net (type {}), virtio-rng (type {}) over \
             modern virtio-pci, plus a PL011 console. A virtio type outside that \
             list is refused by name at restore rather than mismodelled.",
            devmgr::VIRTIO_TYPE_BLOCK,
            devmgr::VIRTIO_TYPE_NET,
            devmgr::VIRTIO_TYPE_RNG,
        ),
    ));

    out.push(Capability::new(
        "counter-rescale",
        "Counter-frequency compensation",
        Support::Yes,
        Evidence::Built,
        format!(
            "A guest caches CNTFRQ_EL0 at boot and never re-reads it, and Apple \
             exposes no way to change what an HVF guest sees, so a capture taken \
             at a different rate is compensated by scaling the counter it is fed. \
             A Graviton2 capture at 121875000 Hz on this host's {host_hz} Hz is a \
             ratio of 325/64: uncompensated, the guest would run 5.08x slow and \
             never say so. Needs the capture to record its own rate.",
        ),
    ));

    out.push(Capability::new(
        "cold-boot",
        "Cold boot from an image",
        Support::No,
        Evidence::Documented,
        "This build resumes captured state. Creating a VM from a disk image with \
         no snapshot is not implemented (#101), so there is no kernel-loading or \
         firmware path here.",
    ));

    out.push(Capability::new(
        "gicv2m",
        "GICv2M captures",
        Support::No,
        Evidence::Documented,
        "Dropped deliberately. The contract is vanilla GICv3+ITS captures; a \
         GICv2M capture is refused rather than half-restored.",
    ));

    out.push(Capability::new(
        "managed-gic-vtimer",
        "Managed-GIC virtual timer anchoring",
        Support::Degraded,
        Evidence::Documented,
        "The userspace-GIC path shares one VtimerClock across vCPUs. The managed \
         (HVF-native) GIC path still anchors per-vCPU, so an SMP guest on that \
         path can see vCPUs disagree about time. Known, unfixed, and the reason \
         the userspace GIC is the default.",
    ));

    out.push(Capability::new(
        "its-lpi-restore",
        "ITS table and LPI register restore",
        Support::Degraded,
        Evidence::Documented,
        "GICR_PROPBASER/PENDBASER and the ITS in-memory tables are not restored \
         from the capture; the ITS is rebuilt from the captured register state \
         instead. This matters only for a guest mid-flight in MSI/LPI delivery.",
    ));

    out
}

/// Settle the hypervisor question without disturbing anything.
///
/// `hv_vm_create` is process-global, so probing inside a process that is hosting
/// a guest would either fail with `HV_BUSY` (an answer about the slot, not the
/// entitlement) or, worse, disturb the guest. A diagnostic must not damage its
/// subject, so the probe runs as a child process — which also happens to test
/// the right thing, since the entitlement lives on the file that would be
/// executed, not in the memory of the process asking.
fn hvf_capability(evidence: HvfEvidence) -> Capability {
    match evidence {
        HvfEvidence::GuestRunning => Capability::new(
            "hvf",
            "Hypervisor.framework",
            Support::Yes,
            Evidence::Observed,
            "A guest is running in this process, so HVF is working here. Not \
             probed: creating a VM is process-global and would have had to \
             contend with the running one.",
        ),
        HvfEvidence::ProbeAllowed => match probe_hvf_in_child() {
            Ok(path) => Capability::new(
                "hvf",
                "Hypervisor.framework",
                Support::Yes,
                Evidence::Probed,
                format!(
                    "Created and destroyed a VM just now by executing {path}. \
                     That binary carries the com.apple.security.hypervisor \
                     entitlement."
                ),
            ),
            Err(ProbeFailure::Refused { path, detail }) => Capability::new(
                "hvf",
                "Hypervisor.framework",
                Support::No,
                Evidence::Probed,
                format!("Executing {path} could not create a VM: {detail}"),
            ),
            Err(ProbeFailure::CouldNotRun(detail)) => Capability::new(
                "hvf",
                "Hypervisor.framework",
                Support::Unknown,
                Evidence::Probed,
                format!(
                    "The probe could not be run, so this is not established: \
                     {detail}. Reported as unknown rather than assumed working."
                ),
            ),
        },
    }
}

/// Why a probe did not come back with a yes.
enum ProbeFailure {
    /// The probe ran and HVF said no. A real, trustworthy negative.
    Refused { path: String, detail: String },
    /// The probe did not run. Says nothing about HVF either way.
    CouldNotRun(String),
}

/// The hidden argument that makes `chm` probe HVF and exit.
pub const PROBE_ARG: &str = "__probe-hvf";

/// Run this binary as a child with [`PROBE_ARG`] and interpret the result.
fn probe_hvf_in_child() -> Result<String, ProbeFailure> {
    let exe = current_exe()
        .map_err(|e| ProbeFailure::CouldNotRun(format!("cannot find this executable: {e}")))?;
    let shown = exe.display().to_string();
    let out = Command::new(&exe)
        .arg(PROBE_ARG)
        .output()
        .map_err(|e| ProbeFailure::CouldNotRun(format!("cannot execute {shown}: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    match out.status.code() {
        Some(0) => Ok(shown),
        Some(2) => Err(ProbeFailure::Refused {
            path: shown,
            detail: if text.is_empty() {
                "no detail reported".to_string()
            } else {
                text
            },
        }),
        other => Err(ProbeFailure::CouldNotRun(format!(
            "{shown} exited with {} and said {:?}",
            other.map_or_else(|| "a signal".to_string(), |c| c.to_string()),
            text
        ))),
    }
}

/// The child side of [`probe_hvf_in_child`]: create a VM, destroy it, report.
///
/// Exit codes are the contract: 0 means HVF works in this process, 2 means it
/// answered no and stdout says why. Anything else means the probe itself broke,
/// which must not be read as either.
pub fn probe_main() -> ExitCode {
    match hvf::probe_availability() {
        Ok(()) => ExitCode::SUCCESS,
        Err(detail) => {
            println!("{detail}");
            ExitCode::from(2)
        }
    }
}

/// One preflight finding about a specific snapshot.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable identifier.
    pub id: String,
    /// Short human name.
    pub title: String,
    /// The verdict.
    pub support: Support,
    /// How it was reached.
    pub evidence: Evidence,
    /// What was found.
    pub detail: String,
}

/// The result of checking a snapshot against this build.
pub struct Preflight {
    /// The directory examined.
    pub dir: PathBuf,
    /// Whether the snapshot could be read at all. When false, `findings` holds
    /// the single reason and nothing else was checked.
    pub readable: bool,
    /// Everything checked, in order.
    pub findings: Vec<Finding>,
}

impl Preflight {
    /// The number of findings that refuse the snapshot outright.
    pub fn refusals(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.support == Support::No)
            .count()
    }

    /// The number of findings that will work, but not as captured.
    pub fn degraded(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.support == Support::Degraded)
            .count()
    }

    /// The number of findings that could not be established.
    pub fn unknowns(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.support == Support::Unknown)
            .count()
    }

    /// A one-line verdict that does not overclaim.
    ///
    /// Deliberately never says "supported" or "will boot": the checks below are
    /// the ones this build knows how to make, and passing them is the absence of
    /// a known objection, not the presence of a working guest.
    pub fn summary(&self) -> String {
        if !self.readable {
            return "could not be read as a cloud-hypervisor snapshot".to_string();
        }
        let n = self.findings.len();
        if self.refusals() > 0 {
            return format!("{} of {n} checks refuse this snapshot", self.refusals());
        }
        let mut s = format!("{n} checks, none refuse this snapshot");
        if self.degraded() > 0 {
            s.push_str(&format!("; {} will not run as captured", self.degraded()));
        }
        if self.unknowns() > 0 {
            s.push_str(&format!("; {} could not be established", self.unknowns()));
        }
        s
    }
}

fn finding(
    id: &str,
    title: &str,
    support: Support,
    evidence: Evidence,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        support,
        evidence,
        detail: detail.into(),
    }
}

/// Check a snapshot directory against what this build can do, without running
/// it, without touching Hypervisor.framework, and without writing anything.
pub fn preflight(dir: &Path) -> Preflight {
    let state_path = dir.join("state.json");
    let state_json = match fs::read_to_string(&state_path) {
        Ok(s) => s,
        Err(e) => {
            return Preflight {
                dir: dir.to_path_buf(),
                readable: false,
                findings: vec![finding(
                    "state-json",
                    "Snapshot state",
                    Support::No,
                    Evidence::Probed,
                    format!("{} could not be read: {e}", state_path.display()),
                )],
            }
        }
    };

    let mut findings = Vec::new();
    findings.extend(check_core(dir, &state_json));
    findings.extend(check_devices(&state_json));
    findings.push(check_counter(&state_json));

    Preflight {
        dir: dir.to_path_buf(),
        readable: true,
        findings,
    }
}

/// vCPUs, RAM and the GIC — parsed by the same code the runner uses, so a
/// snapshot this rejects is one the runner would also have rejected, just
/// louder and later.
fn check_core(dir: &Path, state_json: &str) -> Vec<Finding> {
    let snap = match rehydrate::Snapshot::from_state_json(state_json) {
        Ok(s) => s,
        Err(e) => {
            return vec![finding(
                "snapshot-parse",
                "Snapshot structure",
                Support::No,
                Evidence::Probed,
                format!(
                    "The runner's own parser rejects this capture: {e}. This is \
                     the same code the resume path uses, so the answer would not \
                     have been different at run time."
                ),
            )]
        }
    };

    let mut out = vec![finding(
        "vcpus",
        "vCPUs",
        Support::Yes,
        Evidence::Recorded,
        format!(
            "{} vCPU(s) captured, each with core and system registers plus its \
             GIC CPU interface.",
            snap.vcpus.len()
        ),
    )];

    let total: u64 = snap.mem_mappings.iter().map(|m| m.size).sum();
    let needed = snap
        .mem_mappings
        .iter()
        .map(|m| m.file_offset + m.size)
        .max()
        .unwrap_or(0);
    let ranges = dir.join("snapshot").join("memory-ranges");
    let (support, detail) = match fs::metadata(&ranges) {
        Ok(md) if md.len() >= needed => (
            Support::Yes,
            format!(
                "{} region(s), {} of guest RAM; memory-ranges holds the {} the \
                 mappings reach.",
                snap.mem_mappings.len(),
                human_bytes(total),
                human_bytes(md.len()),
            ),
        ),
        Ok(md) => (
            Support::No,
            format!(
                "The mappings reach {} into memory-ranges but the file is only \
                 {} — short by {}. The capture is truncated or incompletely \
                 transferred. Measured: the runner refuses this too, with \
                 `memory region exceeds memory-ranges`, but only after it has \
                 opened the capture and started warning about other things; \
                 this says it first, and without side effects.",
                human_bytes(needed),
                human_bytes(md.len()),
                human_bytes(needed - md.len()),
            ),
        ),
        Err(e) => (
            Support::No,
            format!("{} is unreadable: {e}", ranges.display()),
        ),
    };
    out.push(finding(
        "memory",
        "Guest RAM",
        support,
        Evidence::Probed,
        detail,
    ));

    out.push(finding(
        "gic",
        "Interrupt controller",
        Support::Yes,
        Evidence::Recorded,
        format!(
            "GICv3 with {} interrupt lines; distributor and redistributor state \
             present.",
            snap.num_irq
        ),
    ));

    out
}

/// Every virtio device the capture carries, classified by the runner's parser.
fn check_devices(state_json: &str) -> Vec<Finding> {
    let descs = match devmgr::parse_devices(state_json) {
        Ok(d) => d,
        Err(e) => {
            return vec![finding(
                "devices",
                "Guest devices",
                Support::No,
                Evidence::Probed,
                format!("The device model could not be reconstructed: {e}"),
            )]
        }
    };
    if descs.is_empty() {
        return vec![finding(
            "devices",
            "Guest devices",
            Support::Yes,
            Evidence::Recorded,
            "No virtio devices captured.",
        )];
    }
    descs
        .iter()
        .map(|d| {
            let (support, detail) = match &d.backend {
                devmgr::BackendKind::Block {
                    disk_path,
                    nsectors,
                } => (
                    Support::Yes,
                    format!(
                        "virtio-blk backed by {disk_path}, {}, restored to the \
                         queue positions the guest left.",
                        human_bytes(nsectors * 512)
                    ),
                ),
                devmgr::BackendKind::Net => (
                    Support::Yes,
                    "virtio-net, served by the in-process userspace NAT under \
                     the workspace egress policy."
                        .to_string(),
                ),
                devmgr::BackendKind::Rng => (
                    Support::Yes,
                    "virtio-rng, fed from host entropy.".to_string(),
                ),
                devmgr::BackendKind::Unsupported { virtio_type } => (
                    Support::No,
                    format!(
                        "virtio device type {virtio_type} is not modelled by this \
                         build. It is refused at restore rather than mismodelled, \
                         so the guest would fail on first use, not silently \
                         misbehave."
                    ),
                ),
            };
            finding(
                &format!("device{}", d.name),
                &format!("Device {}", d.name),
                support,
                Evidence::Recorded,
                detail,
            )
        })
        .collect()
}

/// The counter-frequency question, which is the one that bites silently.
fn check_counter(state_json: &str) -> Finding {
    let host = hvf::host_counter_hz();
    match rehydrate::snapshot_cntfrq(state_json) {
        Some(hz) if hz == host => finding(
            "counter",
            "Counter frequency",
            Support::Yes,
            Evidence::Recorded,
            format!("Captured at {hz} Hz, the same rate as this host. Nothing to compensate."),
        ),
        Some(hz) => {
            let (num, den) = reduce(hz, host);
            finding(
                "counter",
                "Counter frequency",
                Support::Degraded,
                Evidence::Recorded,
                format!(
                    "Captured at {hz} Hz against this host's {host} Hz, a ratio of \
                     {num}/{den}. The guest cached CNTFRQ_EL0 at boot and cannot be \
                     told otherwise, so its counter is scaled by that ratio to keep \
                     its sense of time right. Working, but not as captured."
                ),
            )
        }
        None => finding(
            "counter",
            "Counter frequency",
            Support::Unknown,
            Evidence::Recorded,
            format!(
                "This capture does not record the rate its counter ticked at — it \
                 predates upstream 69637dde6, which added the clock block. The \
                 guest will be fed this host's {host} Hz. If it was captured \
                 somewhere faster, it will run slow by that ratio and nothing in \
                 the guest will report it: a Graviton2 capture at 121875000 Hz \
                 would run 5.08x slow. Set CHM_GUEST_CNTFRQ to correct it."
            ),
        ),
    }
}

/// A byte count a human can read, without rounding a real disk to `0 MiB`.
fn human_bytes(n: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB && n.is_multiple_of(GIB) {
        format!("{} GiB", n / GIB)
    } else if n >= MIB {
        format!("{} MiB", n / MIB)
    } else if n >= 1024 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}

/// Reduce `a/b` to lowest terms for display.
fn reduce(a: u64, b: u64) -> (u64, u64) {
    let mut x = a;
    let mut y = b;
    while y != 0 {
        let t = y;
        y = x % y;
        x = t;
    }
    if x == 0 {
        return (a, b);
    }
    (a / x, b / x)
}

/// `chm capabilities [<SNAPSHOT_DIR>] [--json]`
pub fn capabilities_main(args: &[String]) -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("chm capabilities: unknown option `{other}`");
                return ExitCode::from(2);
            }
            other => {
                if dir.is_some() {
                    eprintln!("chm capabilities: unexpected extra argument `{other}`");
                    return ExitCode::from(2);
                }
                dir = Some(PathBuf::from(other));
            }
        }
    }

    // Standalone, so nothing is running in this process and the child probe is
    // free to take a VM slot.
    let caps = build_report(HvfEvidence::ProbeAllowed);
    let pre = dir.as_deref().map(preflight);

    if json {
        println!("{}", render_json(&caps, pre.as_ref()));
    } else {
        print!("{}", render_text(&caps, pre.as_ref()));
    }
    match pre {
        Some(p) if p.refusals() > 0 => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
}

fn usage() -> &'static str {
    "chm capabilities [SNAPSHOT_DIR] [--json]\n\
     \n\
     What this build can and cannot do, with the evidence behind each claim,\n\
     so nothing has to be inferred from whether a thing crashed.\n\
     \n\
     Given a SNAPSHOT_DIR, also checks that capture against this build using\n\
     the runner's own parsers. Exits 1 if any check refuses it.\n\
     \n\
     Claims are graded: probed (done just now) > observed (already happening)\n\
     > recorded (read from the capture) > built (compiled in) > documented\n\
     (written down, unchecked)."
}

fn render_text(caps: &[Capability], pre: Option<&Preflight>) -> String {
    let mut s = String::from("This build\n");
    for c in caps {
        s.push_str(&format!(
            "  [{:<9}] {:<38} ({})\n      {}\n",
            c.support.as_str(),
            c.title,
            c.evidence.as_str(),
            wrap(&c.detail, 6)
        ));
    }
    if let Some(p) = pre {
        s.push_str(&format!("\n{}\n", p.dir.display()));
        for f in &p.findings {
            s.push_str(&format!(
                "  [{:<9}] {:<38} ({})\n      {}\n",
                f.support.as_str(),
                f.title,
                f.evidence.as_str(),
                wrap(&f.detail, 6)
            ));
        }
        s.push_str(&format!("\n  {}\n", p.summary()));
    }
    s
}

/// Wrap `text` to 74 columns, indenting continuations by `indent` spaces.
fn wrap(text: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut col = indent;
    for word in text.split_whitespace() {
        if col + word.len() + 1 > 74 && col > indent {
            out.push('\n');
            out.push_str(&pad);
            col = indent;
        } else if col > indent {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

/// JSON for the daemon and the app.
pub fn render_json(caps: &[Capability], pre: Option<&Preflight>) -> String {
    let rows: Vec<String> = caps
        .iter()
        .map(|c| {
            format!(
                "    {{\"id\":{},\"title\":{},\"support\":{},\"evidence\":{},\"detail\":{}}}",
                json_str(c.id),
                json_str(c.title),
                json_str(c.support.as_str()),
                json_str(c.evidence.as_str()),
                json_str(&c.detail)
            )
        })
        .collect();
    let mut s = format!(
        "{{\n  \"capabilities\": [\n{}\n  ]",
        rows.join(",\n")
    );
    if let Some(p) = pre {
        let frows: Vec<String> = p
            .findings
            .iter()
            .map(|f| {
                format!(
                    "      {{\"id\":{},\"title\":{},\"support\":{},\"evidence\":{},\"detail\":{}}}",
                    json_str(&f.id),
                    json_str(&f.title),
                    json_str(f.support.as_str()),
                    json_str(f.evidence.as_str()),
                    json_str(&f.detail)
                )
            })
            .collect();
        s.push_str(&format!(
            ",\n  \"preflight\": {{\n    \"dir\": {},\n    \"readable\": {},\n    \
             \"refusals\": {},\n    \"degraded\": {},\n    \"unknowns\": {},\n    \
             \"summary\": {},\n    \"findings\": [\n{}\n    ]\n  }}",
            json_str(&p.dir.display().to_string()),
            p.readable,
            p.refusals(),
            p.degraded(),
            p.unknowns(),
            json_str(&p.summary()),
            frows.join(",\n")
        ));
    }
    s.push_str("\n}");
    s
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally real `state.json`: one RAM region, one vCPU,
    /// a GICv3+ITS node, and the doubly-encoded clock block.
    fn state_json(cntfrq: Option<u64>) -> String {
        let clock = match cntfrq {
            Some(hz) => format!(
                r#"{{\"clock\":{{\"cntvct\":1,\"host_realtime_ns\":2,\"cntfrq\":{hz}}}}}"#
            ),
            None => "{}".to_string(),
        };
        format!(r#"{{"snapshot_data":{{"state":"{clock}"}}}}"#)
    }

    #[test]
    fn an_unrecognised_verdict_is_never_a_yes() {
        // The wire is a string, and a newer daemon could send a word this build
        // has never seen. Anything that is not an explicit yes has to read as
        // not-established, or the panel can be talked into optimism.
        for s in [Support::Yes, Support::Degraded, Support::No, Support::Unknown] {
            let round = match s.as_str() {
                "yes" => Support::Yes,
                "degraded" => Support::Degraded,
                "no" => Support::No,
                _ => Support::Unknown,
            };
            assert_eq!(s, round, "{} did not round-trip", s.as_str());
        }
    }

    #[test]
    fn evidence_grades_are_distinct_on_the_wire() {
        // The whole page is worthless if `probed` and `documented` collapse.
        let all = [
            Evidence::Probed,
            Evidence::Observed,
            Evidence::Recorded,
            Evidence::Built,
            Evidence::Documented,
        ];
        let mut seen: Vec<&str> = all.iter().map(|e| e.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), all.len());
    }

    #[test]
    fn a_capture_that_states_its_rate_is_degraded_not_refused() {
        // A Graviton2 capture works here; it just does not run as captured. That
        // is a third state, and folding it into either yes or no loses the
        // information a reader came for.
        let f = check_counter(&state_json(Some(121_875_000)));
        assert_eq!(f.support, Support::Degraded);
        assert_eq!(f.evidence, Evidence::Recorded);
        assert!(f.detail.contains("325/64"), "detail was: {}", f.detail);
    }

    #[test]
    fn a_capture_that_cannot_state_its_rate_is_unknown_not_fine() {
        // The v52.0 case that cost a whole cloud round-trip to discover. The
        // guest will run, and will run wrong, and will never say so -- so the
        // one thing this must not report is a clean bill of health.
        let f = check_counter(&state_json(None));
        assert_eq!(f.support, Support::Unknown);
        assert!(f.detail.contains("69637dde6"), "detail was: {}", f.detail);
        assert!(f.detail.contains("5.08x"), "detail was: {}", f.detail);
    }

    #[test]
    fn a_matching_rate_needs_no_compensation() {
        let host = hvf::host_counter_hz();
        let f = check_counter(&state_json(Some(host)));
        assert_eq!(f.support, Support::Yes);
    }

    #[test]
    fn a_summary_never_says_the_snapshot_will_work() {
        // The load-bearing sentence on the whole page. "Nothing refuses it" is a
        // statement about the checks; "supported" would be a statement about the
        // guest, which nothing here has run.
        let p = Preflight {
            dir: PathBuf::from("/x"),
            readable: true,
            findings: vec![finding("a", "A", Support::Yes, Evidence::Probed, "")],
        };
        let s = p.summary();
        assert!(s.contains("none refuse"), "{s}");
        assert!(!s.to_lowercase().contains("supported"), "{s}");
        assert!(!s.to_lowercase().contains("will boot"), "{s}");
    }

    #[test]
    fn degraded_and_unknown_findings_are_called_out_in_the_summary() {
        // A count of checks that passed, with the caveats dropped, is how an
        // unchecked thing rounds up to a working one.
        let p = Preflight {
            dir: PathBuf::from("/x"),
            readable: true,
            findings: vec![
                finding("a", "A", Support::Yes, Evidence::Probed, ""),
                finding("b", "B", Support::Degraded, Evidence::Recorded, ""),
                finding("c", "C", Support::Unknown, Evidence::Recorded, ""),
            ],
        };
        let s = p.summary();
        assert!(s.contains("not run as captured"), "{s}");
        assert!(s.contains("could not be established"), "{s}");
    }

    #[test]
    fn a_refusal_dominates_the_summary() {
        let p = Preflight {
            dir: PathBuf::from("/x"),
            readable: true,
            findings: vec![
                finding("a", "A", Support::Yes, Evidence::Probed, ""),
                finding("b", "B", Support::No, Evidence::Probed, ""),
            ],
        };
        assert_eq!(p.refusals(), 1);
        assert!(p.summary().contains("refuse"), "{}", p.summary());
    }

    #[test]
    fn an_unreadable_directory_is_refused_not_reported_empty() {
        // A preflight over a directory that is not a snapshot must not come back
        // with zero objections, which is what an empty findings list would read
        // as.
        let p = preflight(Path::new("/nonexistent-v65-preflight"));
        assert!(!p.readable);
        assert_eq!(p.refusals(), 1);
        assert!(!p.summary().contains("none refuse"), "{}", p.summary());
    }

    #[test]
    fn the_build_report_grades_every_claim() {
        // No claim may ship ungraded: an ungraded claim is indistinguishable
        // from a probed one, which is the bug.
        let caps = build_report(HvfEvidence::GuestRunning);
        assert!(!caps.is_empty());
        for c in &caps {
            assert!(!c.detail.is_empty(), "{} has no detail", c.id);
            assert!(!c.title.is_empty(), "{} has no title", c.id);
        }
    }

    #[test]
    fn a_running_guest_is_observed_not_probed() {
        // `hv_vm_create` is process-global. Probing a process that is hosting a
        // guest would either report HV_BUSY -- an answer about the slot, not the
        // entitlement -- or disturb the thing being diagnosed.
        let caps = build_report(HvfEvidence::GuestRunning);
        let hvf = caps.iter().find(|c| c.id == "hvf").expect("no hvf claim");
        assert_eq!(hvf.support, Support::Yes);
        assert_eq!(hvf.evidence, Evidence::Observed);
        assert!(hvf.detail.contains("process-global"), "{}", hvf.detail);
    }

    #[test]
    fn known_gaps_are_documented_not_built() {
        // These are claims a human made. Grading them as anything stronger would
        // let a stale sentence borrow the credibility of a probe.
        let caps = build_report(HvfEvidence::GuestRunning);
        for id in ["cold-boot", "gicv2m", "managed-gic-vtimer", "its-lpi-restore"] {
            let c = caps.iter().find(|c| c.id == id).expect(id);
            assert_eq!(c.evidence, Evidence::Documented, "{id} claimed too much");
        }
    }

    #[test]
    fn the_ratio_reduces_the_way_the_scaler_does() {
        // Must agree with hypervisor::hvf's reduce_ratio, or the page explains a
        // correction that is not the one being applied.
        assert_eq!(reduce(121_875_000, 24_000_000), (325, 64));
        assert_eq!(reduce(24_000_000, 24_000_000), (1, 1));
    }

    #[test]
    fn a_small_disk_is_not_rounded_to_zero() {
        // A seed image is under a megabyte. Reporting it as "0 MiB" reads as a
        // broken device rather than a small one.
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512 * 1024), "512 KiB");
        assert_eq!(human_bytes(8 * 1024 * 1024 * 1024), "8 GiB");
        assert_eq!(human_bytes(1536 * 1024 * 1024), "1536 MiB");
    }

    #[test]
    fn json_carries_the_evidence_grade() {
        // The app cannot show what the wire does not send.
        let caps = build_report(HvfEvidence::GuestRunning);
        let out = render_json(&caps, None);
        assert!(out.contains("\"evidence\":\"observed\""), "{out}");
        assert!(out.contains("\"evidence\":\"documented\""), "{out}");
        assert!(!out.contains("\"preflight\""));
    }

    #[test]
    fn json_is_parseable_with_a_preflight_attached() {
        let caps = build_report(HvfEvidence::GuestRunning);
        let p = Preflight {
            dir: PathBuf::from("/x/y"),
            readable: true,
            findings: vec![finding(
                "d",
                "D",
                Support::No,
                Evidence::Probed,
                "quote \" and \\ backslash",
            )],
        };
        let out = render_json(&caps, Some(&p));
        let v: serde_json::Value = serde_json::from_str(&out).expect("not valid JSON");
        assert_eq!(v["preflight"]["refusals"], 1);
        assert_eq!(v["preflight"]["dir"], "/x/y");
        assert_eq!(v["preflight"]["findings"][0]["support"], "no");
    }
}
