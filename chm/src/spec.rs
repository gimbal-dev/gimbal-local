// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The declarative sandbox spec (V9.3, #150).
//!
//! # The gap this closes
//!
//! We could start a sandbox. We could not *describe* one. What a sandbox was
//! lived in roughly ten argv flags spread over two entry points (`chm create`,
//! `chm run`) plus three sidecar files, and the app reimplemented the flag
//! assembly in its own command builders. Two places to get it right, and no way
//! to write down the answer.
//!
//! That costs four things. A sandbox is not reproducible — you cannot hand
//! someone "the thing I ran". It is not diffable, so nothing can review a change
//! to a sandbox *before* it runs. The app duplicates assembly the engine already
//! owns. And there is no unit for a control plane to send later, so the
//! local/cloud contract has nothing to be a contract *about*.
//!
//! # Why the field names are not ours
//!
//! There is an existing specification for this exact problem — the **agent
//! compute environment spec** ([`nebuk89/Dev-spec@agent-compute-spec`]) — which
//! describes itself as *"an agent environment configuration for autonomous AI
//! agent compute in microVMs"*. Its `hostRequirements.hypervisor` enum reads:
//!
//! ```json
//! "enum": ["firecracker", "cloud-hypervisor", "qemu", "any"]
//! ```
//!
//! We are one of four named targets. So this module deliberately uses **its**
//! vocabulary — `resourceLimits`, `networkPolicy`, `secrets`, `checkpoint`,
//! `hostRequirements`, `toolPolicy`, camelCase, unit-suffixed values like
//! `"4gb"` and `"30m"` — rather than names of our own invention.
//!
//! Adopting a name is nearly free today and expensive once people have files on
//! disk. Adopting the *whole* spec is not free at all, which is why this
//! implements a deliberate subset (#182 tracks the rest).
//!
//! # The rule that makes a subset safe
//!
//! **A document asking for a control this build cannot apply is refused, not
//! ignored.**
//!
//! Quietly dropping `securityModules` would start a sandbox measurably weaker
//! than its own description says it is, with nothing to tell the operator. That
//! is the same shape as #178 — a green suite hiding broken checkpoints — and it
//! gets the same answer: say it, loudly, at the moment it happens. See
//! [`SandboxSpec::validate`] and [`UNIMPLEMENTED`].
//!
//! # The other trap
//!
//! The obvious way to build a spec is also wrong: invent a second source of
//! truth, and now the flags and the spec drift while the app grows a *third* way
//! to start a guest. So the spec is not a parallel path. It resolves into
//! exactly the values the flags produce, and a flag still wins. [`Resolved`] is
//! the one place "what this sandbox is" becomes concrete.
//!
//! # Deploy-time versus per-start
//!
//! Cloudflare splits container config into deploy-time fields and per-invocation
//! `startOptions`, and the split is worth stealing because it separates *what
//! this sandbox is* from *how this run differs*. For a CLI that is already
//! idiomatic: `sandbox.json` is the thing you commit and review; flags are how
//! tonight's run differs. [`Resolved::explain`] prints the layering, because a
//! value you cannot trace is not reviewable.
//!
//! # Format discipline
//!
//! Every field carries `#[serde(default)]` and there is a frozen fixture in
//! `chm/testdata/` from the day the format shipped rather than after the first
//! regression — see #180 for what that discipline cost to learn.
//!
//! [`nebuk89/Dev-spec@agent-compute-spec`]: https://github.com/nebuk89/Dev-spec/tree/agent-compute-spec

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::imp::DEFAULT_IDLE_EXIT_SECS;
use crate::imp::answer_group_help;
use crate::postboot;
use hypervisor::hvf::virtio::nat::INGRESS_BIND_ADDR;

/// The spec format version.
///
/// Bump only when a reader that does not know about a change would
/// *misunderstand* a document — not merely when a field is added, since additive
/// fields are handled by `#[serde(default)]` and cost no version. A newer
/// document is refused by name rather than silently half-read.
pub const SPEC_VERSION: u32 = 1;

/// The conventional filename inside a workspace.
pub const SPEC_FILENAME: &str = "sandbox.json";

/// Sections of the agent-compute spec this build does not implement, and the
/// issue tracking each.
///
/// This table is the reason a subset is safe. Every entry is a control someone
/// might reasonably write down and expect to be enforced; encountering one is a
/// refusal, never a shrug. The alternative — accept and ignore — produces a
/// sandbox that is weaker than its own description with no way to notice, which
/// is precisely the class of failure this repo has twice shipped and then had to
/// harden against.
pub const UNIMPLEMENTED: &[(&str, u32, &str)] = &[
    (
        "extensions",
        183,
        "installing tools into the image (bash, node, python). `chm image build` \
         produces the image; what is missing is a stage that runs an installer \
         inside it",
    ),
    (
        "securityModules",
        184,
        "seccomp / LSM / capability policy inside the guest",
    ),
    (
        "securityProfile",
        184,
        "in-guest hardening (an older name for securityModules)",
    ),
    (
        "dataPolicy",
        185,
        "workspace isolation model, retention, outbound payload inspection",
    ),
    (
        "identity",
        187,
        "agent identity, delegation, attestation. Note that hardware attestation \
         (SEV-SNP, TDX) has no Hypervisor.framework equivalent and cannot be \
         honoured on this substrate at all",
    ),
    (
        "observability",
        188,
        "structured logging, tamper-evident audit chain, metrics",
    ),
    ("customizations", 182, "tool-specific configuration blocks"),
    (
        "multiAgent",
        182,
        "orchestrating more than one agent in a sandbox",
    ),
    // The spec has ten lifecycle hooks; we have a channel for one
    // (`postBootCommand`, via `chm exec`). The rest are named individually so a
    // document using them is told which hook is unbuilt, rather than being told
    // it made a typo.
    (
        "initializeCommand",
        189,
        "runs on the host before the sandbox exists — a trust decision, not just \
         an unimplemented feature",
    ),
    (
        "preBootCommand",
        189,
        "runs after the image is prepared, before boot",
    ),
    (
        "onCreateCommand",
        189,
        "runs once, the first time a sandbox is created",
    ),
    (
        "preTaskCommand",
        189,
        "runs before each agent task; chm has no notion of a task boundary yet",
    ),
    ("postTaskCommand", 189, "runs after each agent task"),
    (
        "preSnapshotCommand",
        189,
        "runs before a checkpoint is taken, so a workload can quiesce",
    ),
    (
        "postRestoreCommand",
        189,
        "runs after a checkpoint is resumed — the natural place to re-sync a \
         guest whose cached view of the world is from the moment of capture",
    ),
    ("preShutdownCommand", 189, "runs before the guest stops"),
    (
        "waitFor",
        189,
        "names the hook that must finish before the agent gets the machine; \
         needs a real readiness signal, which this build does not have",
    ),
    ("lifecycle", 189, "the lifecycle hook block as a whole"),
];

/// Fields this build *understands* but cannot yet deliver into a guest.
///
/// Kept separate from [`UNIMPLEMENTED`] because these are not unbuilt sections
/// of somebody else's spec — they would be our own gap, found by asking the
/// question a spec is meant to make askable: what actually delivers this?
///
/// **Currently empty, and deliberately kept.** `env` and `postBootCommand` lived
/// here from V9.3 until V9.10 built their delivery (#190). The list stays
/// because the *category* is permanent: this build will keep growing fields it
/// can describe before it can carry, and the honest place for one is a refusal
/// naming its issue rather than a parser that quietly drops it. Emptying the
/// list and deleting the mechanism would mean the next such field arrives with
/// nowhere to be declared, and the cheapest thing to do with it would be
/// nothing.
const UNDELIVERED: &[(&str, u32, &str)] = &[];

/// Is an [`UNDELIVERED`] field actually set in this document?
///
/// A named function rather than an inline `false`, because the list is empty
/// and an empty list refuses nobody: the next field we can describe but not
/// deliver needs somewhere obvious to declare *how its presence is detected*,
/// or it will be added to the table and quietly match nothing — a refusal
/// mechanism that reports safety without providing it, which is the #179
/// failure shape one layer up.
fn undelivered_field_present(spec: &SandboxSpec, name: &str) -> bool {
    let _ = (spec, name);
    // No current entries: every field this build understands, it delivers.
    // A future one adds its arm here.
    false
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// A sandbox, written down.
///
/// Every field is optional. A spec naming only an image is valid and means
/// "everything else as it would have been anyway" — the document states
/// *intent*, and intent you did not express should not become intent you did.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxSpec {
    /// Format version. Written on every save; read on every load.
    #[serde(default = "default_spec_version")]
    pub spec_version: u32,

    /// A display name. Never used to address the sandbox — the workspace path is
    /// the identity — but a diff of two specs is far easier to read when each
    /// says what it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// What this sandbox is for, in prose. Reviewers read this first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// What to boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageSpec>,

    /// How big, and for how long. The spec's name for this is `resourceLimits`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,

    /// What it may reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicy>,

    /// Credentials the sandbox needs. Ours are injected at the network edge, so
    /// the guest never holds one — see `docs/credential-proxy.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsSpec>,

    /// What the agent may do, as opposed to what the VM may reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_policy: Option<ToolPolicy>,

    /// Checkpoint / snapshot behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointSpec>,

    /// What the *host* must provide for this sandbox to be honest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_requirements: Option<HostRequirements>,

    /// Environment variables for the guest.
    ///
    /// A `BTreeMap` so two specs describing the same sandbox serialise
    /// identically regardless of authoring order — a document whose diff depends
    /// on key order is not reviewable.
    ///
    /// **Never put a credential here.** A spec is meant to be committed;
    /// `secrets` is the field that keeps one off the guest entirely.
    /// [`SandboxSpec::validate`] refuses names that look like secrets rather
    /// than trusting a reader to notice.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// The username the agent runs as inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_user: Option<String>,

    /// The workspace folder inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_folder: Option<String>,

    /// What to run once the guest is up, argv-style. The spec's lifecycle model
    /// is richer than this (`onCreateCommand`, `preTaskCommand`,
    /// `preSnapshotCommand` and more); this is the one hook we have a channel
    /// for, via `chm exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_boot_command: Option<Vec<String>>,

    /// Anything this build did not recognise.
    ///
    /// Captured rather than rejected at parse time so [`SandboxSpec::validate`]
    /// can tell "a section of the spec we have not built yet" apart from "a
    /// typo", and give a useful message for each. Both are refusals; only the
    /// wording differs, and the wording is most of the value.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn default_spec_version() -> u32 {
    SPEC_VERSION
}

/// What to boot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSpec {
    /// An OCI image reference, the spec's native way to name a root filesystem.
    ///
    /// Accepted and refused today, and the refusal is a boundary rather than a
    /// gap: a spec expands into `chm create` argv and the same parser runs, so
    /// honouring this field would give a spec a private route to a network pull
    /// and a rootfs build that the flags it expands to do not have. `chm image
    /// build` does that job; name what it wrote here. It is named rather than
    /// omitted so a conforming document gets that sentence instead of "unknown
    /// field".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<String>,

    /// Uncompressed arm64 kernel `Image` for a cold boot. A distro `vmlinuz` is
    /// gzip and must be gunzipped first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<PathBuf>,

    /// initrd/initramfs cpio. Without one a cold boot panics at `VFS: unable to
    /// mount root fs`, which is correct — it has nothing to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs: Option<PathBuf>,

    /// Kernel command line. Omitted means the built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,

    /// Raw disk images attached as virtio-blk. The first becomes `/dev/vda`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<PathBuf>,

    /// A snapshot directory to rehydrate instead of cold-booting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<PathBuf>,
}

/// How big, and for how long.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLimits {
    /// A named tier. Not part of the agent-compute spec — a `chm` convenience on
    /// top of it, because "how much RAM does an agent need?" has no good answer
    /// in the abstract and the honest failure mode of a raw number is that
    /// everyone copies the one in the example. Explicit fields win over it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<TimeoutLimits>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CpuLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryLimits {
    /// Guest RAM, unit-suffixed: `"2gb"`, `"512mb"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ram: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskLimits {
    /// Workspace disk, unit-suffixed: `"16gb"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_size: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeoutLimits {
    /// Wall-clock ceiling: `"4h"`, `"30m"`. Absent means no ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock: Option<String>,
    /// Console silence before chm *suspends* the guest: `"10m"`. `"0s"`
    /// disables it. Expiry suspends rather than kills, so being wrong about
    /// idleness costs a resume, not the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
}

/// What it may reach.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Whether the guest gets a network device at all. `false` is a stronger
    /// statement than an empty allow-list, and is the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// `"deny"` or `"allow"`. Deny is the default everywhere in this tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>,

    /// Egress rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<EgressRule>,

    /// Guest ports to publish on this Mac's loopback.
    ///
    /// The spec's name for this, and its array-of-rules shape, are upstream's;
    /// what a rule may *say* is deliberately much narrower. See [`IngressRule`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<IngressRule>,

    /// A full egress-policy document to use instead of inline `egress` rules.
    /// A `chm` extension: our policy files predate this spec and remain the
    /// authority for anything a control plane issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_file: Option<PathBuf>,

    /// Permit reserved / host-internal ranges (loopback, private LAN, the
    /// link-local metadata address). Off by default and independent of the
    /// allow-list: the reserved-address guard denies those regardless of policy,
    /// so opting in has to be its own deliberate sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_local: Option<bool>,
}

/// One egress rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressRule {
    /// `"allow"` or `"deny"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Hostnames. Wildcards are accepted by the spec but **not** by this build
    /// (see [`SandboxSpec::validate`]) — silently treating `*.github.com` as a
    /// literal hostname would deny everything while looking permissive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// Ports. Empty means 443, which is the only port anything here has ever
    /// wanted by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Why this rule exists. Not enforced; read by whoever reviews the diff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One ingress rule: a guest port to publish on this Mac's loopback.
///
/// # Why this is upstream's name but not upstream's shape
///
/// The agent-compute spec's `networkPolicy.ingress` is an array of *firewall
/// rules* -- `allow` / `deny` / `host` / `port` / `protocol`, "applied in
/// order", where `port` is `oneOf` integer or string so it can carry a range.
/// That models **filtering inbound traffic that would otherwise arrive**.
///
/// Nothing otherwise arrives here. The userspace NAT is strictly outbound and
/// there is no listener at all until `--expose` creates one, so an ordering
/// filter has nothing to order and a `deny` rule has nothing to deny. What this
/// build does is the opposite operation: it **creates** one loopback listener
/// for one guest TCP port.
///
/// So the name and the array shape are upstream's -- a conforming document
/// parses -- and every field that would make this a *wider door than the flag*
/// is refused by name in [`SandboxSpec::validate`] rather than dropped. That
/// direction matters: a spec is meant to be committed and reviewed, and a
/// document whose `host` or port range was silently ignored would describe a
/// sandbox that does not exist.
///
/// The narrowing has precedent in this same file: [`EgressRule::ports`] is
/// `Vec<u16>` where upstream's is `oneOf` integer or string, and
/// [`EgressRule::domains`] refuses the wildcards upstream permits.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IngressRule {
    /// The guest TCP port to publish.
    ///
    /// A JSON number. Typed as a `Value` rather than `u16` on purpose: upstream
    /// permits a string here, and a document written to upstream's schema must
    /// receive [`IngressRule::port_number`]'s sentence explaining that ranges
    /// are named one port at a time -- not a serde type error naming a Rust
    /// integer width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<serde_json::Value>,

    /// Upstream permits `tcp` / `udp` / `icmp` / `any`. Only `tcp` is honoured;
    /// the others are refused by name, because ingress here is a TCP listener
    /// and accepting `any` would promise a UDP path that does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Upstream's host matcher. **Refused**: every listener binds
    /// `INGRESS_BIND_ADDR`, deliberately a constant rather than a flag, and a
    /// spec field naming a host is exactly the accident that constant exists to
    /// prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Upstream's source matcher. **Refused**: a published port is reachable by
    /// anything on this Mac, so there is no source this build could filter on,
    /// and a rule implying otherwise would report protection it does not
    /// provide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<String>,

    /// Upstream's deny rule. **Refused**: with no listener there is nothing to
    /// deny, so honouring it would be a no-op wearing the shape of a control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<String>,

    /// Why this port is published. Not enforced; read by whoever reviews the
    /// diff. Ours, like [`EgressRule::description`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl IngressRule {
    /// The guest port this rule names, or why it names none.
    ///
    /// The single place a rule becomes a port. [`SandboxSpec::validate`] calls
    /// it to report, [`resolve`] calls it to act; two readings of one JSON value
    /// would eventually disagree, and the disagreement would be a sandbox that
    /// validated and then published something else.
    pub fn port_number(&self) -> Result<u16, String> {
        match &self.port {
            None => Err("names no `port`, so it publishes nothing".to_string()),
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(0) => Err(
                    "`port` is 0, which is the OS's word for \"choose one\", not a \
                                port a guest can listen on"
                        .to_string(),
                ),
                Some(p) if p <= u16::MAX as u64 => Ok(p as u16),
                _ => Err(format!("`port` {n} is not a TCP port (1-{})", u16::MAX)),
            },
            Some(serde_json::Value::String(s)) => Err(format!(
                "`port` is the string \"{s}\"; write it as a number. The spec permits a string \
                 so it can carry a range, and this build has no range form -- each published \
                 port is named on its own, because each gets its own host port"
            )),
            Some(other) => Err(format!("`port` must be a number, not {other}")),
        }
    }

    /// Every reason this rule cannot be honoured, in field order.
    ///
    /// [`SandboxSpec::validate`] reports these and [`resolve`] publishes a port
    /// only when this is empty, so a rule that is refused can never also be
    /// acted on. Splitting the two -- reporting here, deciding there -- is how a
    /// document comes to validate as refused and start as honoured, which is
    /// the failure this whole module exists to prevent.
    ///
    /// Duplicate ports are deliberately *not* here: that is a property of the
    /// list, not of a rule, so it belongs to the caller that can see the list.
    pub fn refusals(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Err(e) = self.port_number() {
            out.push(e);
        }
        if let Some(proto) = self.protocol.as_deref()
            && !proto.eq_ignore_ascii_case("tcp")
        {
            out.push(format!(
                ".protocol: `{proto}` is in the spec but this build publishes a TCP listener \
                 and nothing else. Accepting it would promise a path that does not exist; \
                 write `tcp`, or leave it out."
            ));
        }
        if let Some(h) = &self.host {
            out.push(format!(
                ".host: `{h}` cannot be honoured. Every published port binds \
                 {INGRESS_BIND_ADDR}, which is a constant rather than a flag precisely so that \
                 widening it stays a decision somebody takes on purpose. A spec that could name \
                 a host would be a wider door than `--expose` is."
            ));
        }
        if let Some(a) = &self.allow {
            out.push(format!(
                ".allow: `{a}` cannot be honoured. A published port is reachable by anything on \
                 this Mac, so there is no source to filter on, and a rule that reads like one \
                 would report protection this build does not provide."
            ));
        }
        if let Some(d) = &self.deny {
            out.push(format!(
                ".deny: `{d}` cannot be honoured. Nothing reaches a guest until `ingress` \
                 publishes a port, so a deny rule has nothing to deny -- it would be a no-op \
                 wearing the shape of a control. Remove the port instead."
            ));
        }
        out
    }

    /// The port to publish, or `None` when any field refuses the rule.
    pub fn publishable_port(&self) -> Option<u16> {
        if self.refusals().is_empty() {
            self.port_number().ok()
        } else {
            None
        }
    }
}

/// Credentials the sandbox needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsSpec {
    /// Path to a credential-injection rules file (`chm proxy`).
    ///
    /// The agent-compute spec declares secrets inline with `injection: "env"`.
    /// We deliberately do not: injecting at the network edge means the guest
    /// never holds the credential at all, which is a stronger property than any
    /// inline declaration can offer. The rules file is where that lives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_file: Option<PathBuf>,

    /// Where the proxy CA and audit trail live. A CA is a persistent trust root,
    /// so it belongs somewhere the caller chose, never a temporary directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<PathBuf>,
}

/// What the agent may do.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolPolicy {
    /// Capability categories: `"filesystem"`, `"network"`, `"subprocess"`.
    ///
    /// Only `"network"` is enforceable today, and it is enforced properly: its
    /// absence means no NIC is attached, which is a verifiable fact about the
    /// guest rather than a promise about the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Per-tool approval — the `denyList: ["bash"]` case.
    ///
    /// Accepted and refused: enforcing it needs us to sit between the agent and
    /// its tools, and we do not. #186 tracks it, most likely through the MCP
    /// surface (#157). Accepting a deny-list we cannot enforce would be the
    /// worst outcome available — the operator believes the shell is blocked and
    /// it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<serde_json::Value>,
}

/// Checkpoint / snapshot behaviour.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointSpec {
    /// Take checkpoints so the next start continues where this one left off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Cadence for continuous checkpoints: `"5m"`. Absent means only on
    /// suspend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
}

/// What the host must provide.
///
/// Worth having even in a subset, because it is the one section that can turn a
/// confusing runtime failure into a clear refusal at start.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRequirements {
    /// Minimum host CPUs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    /// Minimum host memory: `"8gb"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// Required hypervisor. The spec's enum is `firecracker`,
    /// `cloud-hypervisor`, `qemu`, `any` — we are `cloud-hypervisor`, so a
    /// document demanding `firecracker` is refused rather than run on something
    /// it did not ask for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<String>,
    /// Guest architecture. This build is aarch64 only, so an x86_64 document is
    /// refused up front rather than failing much later and much less clearly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

// ---------------------------------------------------------------------------
// Units
// ---------------------------------------------------------------------------

/// Parse a unit-suffixed size (`"4gb"`, `"512mb"`) into MiB.
///
/// The spec uses decimal-looking suffixes for what are conventionally binary
/// quantities. We treat `gb` as 1024 MiB, because every other number this tool
/// prints is binary and having one field mean something different would be a
/// worse surprise than the naming inconsistency.
pub fn parse_size_mib(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult) = if let Some(v) = t.strip_suffix("tb") {
        (v, 1024 * 1024)
    } else if let Some(v) = t.strip_suffix("gb") {
        (v, 1024)
    } else if let Some(v) = t.strip_suffix("mb") {
        (v, 1)
    } else {
        return Err(format!(
            "`{s}` needs a unit — write it as `512mb`, `4gb` or `1tb`"
        ));
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("`{s}` is not a number with a unit"))?;
    if n <= 0.0 {
        return Err(format!("`{s}` must be greater than zero"));
    }
    Ok((n * mult as f64).round() as u64)
}

/// Parse a duration (`"4h"`, `"30m"`, `"600s"`) into seconds.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult) = if let Some(v) = t.strip_suffix('h') {
        (v, 3600)
    } else if let Some(v) = t.strip_suffix('m') {
        (v, 60)
    } else if let Some(v) = t.strip_suffix('s') {
        (v, 1)
    } else {
        return Err(format!(
            "`{s}` needs a unit — write it as `30s`, `10m` or `4h`"
        ));
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("`{s}` is not a number with a unit"))?;
    if n < 0.0 {
        return Err(format!("`{s}` cannot be negative"));
    }
    Ok((n * mult as f64).round() as u64)
}

/// Render seconds back into the spec's duration form.
pub fn format_duration(secs: u64) -> String {
    if secs == 0 {
        "0s".into()
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Render MiB back into the spec's size form.
pub fn format_size(mib: u64) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{}gb", mib / 1024)
    } else {
        format!("{mib}mb")
    }
}

// ---------------------------------------------------------------------------
// Named sizing tiers
// ---------------------------------------------------------------------------

/// A named size, so sizing becomes a decision someone can be *right* about.
pub struct Tier {
    pub name: &'static str,
    pub vcpus: u8,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub rationale: &'static str,
}

/// The tiers, smallest first.
///
/// Deliberately modest. The host is a laptop also running the user's actual
/// desktop, and a sandbox that makes the machine unusable has failed at its job
/// even if the guest is happy.
pub const TIERS: &[Tier] = &[
    Tier {
        name: "micro",
        vcpus: 1,
        memory_mib: 512,
        disk_mib: 2048,
        rationale: "A shell and a script. Too small for a package manager.",
    },
    Tier {
        name: "dev",
        vcpus: 1,
        memory_mib: 1024,
        disk_mib: 8192,
        rationale: "The default. A language runtime and an editor session.",
    },
    Tier {
        name: "standard",
        vcpus: 2,
        memory_mib: 2048,
        disk_mib: 16384,
        rationale: "An agent that installs dependencies and runs a test suite.",
    },
    Tier {
        name: "performance",
        vcpus: 4,
        memory_mib: 4096,
        disk_mib: 32768,
        rationale: "Compiles. The largest tier that leaves an 8 GiB host usable.",
    },
];

/// Look up a tier by name.
pub fn tier(name: &str) -> Option<&'static Tier> {
    TIERS.iter().find(|t| t.name == name)
}

/// Render the tier table, including *why* each is the size it is.
pub fn describe_tiers() -> String {
    let mut out = String::from("Named sizing tiers:\n\n");
    for t in TIERS {
        let _ = writeln!(
            out,
            "  {:<12} {} vCPU, {} RAM, {} disk\n               {}",
            t.name,
            t.vcpus,
            format_size(t.memory_mib),
            format_size(t.disk_mib),
            t.rationale
        );
    }
    out.push_str(
        "\nA tier sets every field it names; anything set explicitly wins over it.\n\
         Tiers are a chm convenience, not part of the agent-compute spec.\n",
    );
    out
}

// ---------------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------------

impl SandboxSpec {
    /// Parse a spec, refusing a document from a newer chm by name.
    ///
    /// Older versions are deliberately still read: compatibility with what is
    /// already on disk is the entire point of versioning a format. A *newer*
    /// document is refused because serde would silently drop fields this build
    /// does not know, and a sandbox started with half its policy missing is
    /// worse than one that refused to start.
    pub fn parse(raw: &str, whence: &Path) -> Result<Self, String> {
        let spec: Self = serde_json::from_str(raw)
            .map_err(|e| format!("{} is not a valid sandbox spec: {e}", whence.display()))?;
        if spec.spec_version > SPEC_VERSION {
            return Err(format!(
                "{} was written by a newer chm (spec version {}, this build understands {}). \
                 Starting it here could silently drop policy it depends on.",
                whence.display(),
                spec.spec_version,
                SPEC_VERSION
            ));
        }
        Ok(spec)
    }

    /// Read a spec from a path.
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&raw, path)
    }

    /// Find a workspace's spec, if it has one.
    ///
    /// Absence is not an error: a workspace with no spec was simply never asked
    /// to be described, and keeps working exactly as it did before this file
    /// existed.
    pub fn discover(workspace: &Path) -> Result<Option<(Self, PathBuf)>, String> {
        let path = workspace.join(SPEC_FILENAME);
        if !path.is_file() {
            return Ok(None);
        }
        Self::load(&path).map(|s| Some((s, path)))
    }

    /// Serialise, pretty-printed with a trailing newline, so the file is a
    /// well-formed text file and a diff of two specs is line-oriented.
    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into());
        s.push('\n');
        s
    }

    /// Check the document.
    ///
    /// Reports *every* problem rather than the first, because a validator that
    /// makes you re-run it four times to find four mistakes is one people stop
    /// running.
    ///
    /// Refusals fall into three kinds, and the wording of each matters more than
    /// the fact of it: a section of the spec we have not built (say so, and name
    /// the issue), a section we cannot ever build on this substrate (say that
    /// too, so nobody tries), and an ordinary mistake.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();

        // Sections of the agent-compute spec we do not implement. Named, with
        // the issue, because "unknown field" would be both wrong and unhelpful:
        // the field is not unknown, it is unbuilt.
        for key in self.extra.keys() {
            match UNIMPLEMENTED.iter().find(|(name, _, _)| name == key) {
                Some((name, issue, what)) => problems.push(format!(
                    "`{name}` is part of the agent compute spec but this build does not implement \
                     it ({what}). Refusing rather than starting a sandbox weaker than this \
                     document describes — see #{issue}."
                )),
                None => problems.push(format!(
                    "unknown field `{key}` — not part of the sandbox spec this build understands"
                )),
            }
        }

        if let Some(img) = &self.image {
            if img.oci.is_some() {
                problems.push(
                    "image.oci: a spec names something already bootable, and `chm create` boots \
                     rather than builds. Build the image first with `chm image build <REFERENCE> \
                     --kernel <Image> --out <DIR>`, then name what it wrote: `kernel` and \
                     `initramfs`, or `kernel` plus its rootfs.img under `disks`."
                        .into(),
                );
            }
            if img.kernel.is_some() && img.snapshot.is_some() {
                problems.push(
                    "image: `kernel` and `snapshot` are mutually exclusive — a sandbox either \
                     cold-boots or rehydrates, and naming both means the document has not decided"
                        .into(),
                );
            }
            if img.snapshot.is_some() && !img.disks.is_empty() {
                problems.push(
                    "image: `disks` applies to a cold boot; a snapshot already carries its own \
                     disks, and listing them here would not attach them"
                        .into(),
                );
            }
            if img.kernel.is_none() && img.snapshot.is_none() && img.initramfs.is_some() {
                problems.push("image: `initramfs` without a `kernel` has nothing to load".into());
            }
        }

        if let Some(rl) = &self.resource_limits {
            if let Some(name) = &rl.tier
                && tier(name).is_none()
            {
                let known: Vec<_> = TIERS.iter().map(|t| t.name).collect();
                problems.push(format!(
                    "resourceLimits: unknown tier `{name}` (known: {})",
                    known.join(", ")
                ));
            }
            if rl.cpu.as_ref().and_then(|c| c.vcpus) == Some(0) {
                problems.push("resourceLimits.cpu.vcpus must be at least 1".into());
            }
            if let Some(ram) = rl.memory.as_ref().and_then(|m| m.ram.as_deref()) {
                match parse_size_mib(ram) {
                    Err(e) => problems.push(format!("resourceLimits.memory.ram: {e}")),
                    Ok(mib) if mib < 64 => problems.push(format!(
                        "resourceLimits.memory.ram: {ram} is below the 64mb a kernel needs to \
                         reach userspace"
                    )),
                    Ok(_) => {}
                }
            }
            if let Some(d) = rl.disk.as_ref().and_then(|d| d.workspace_size.as_deref())
                && let Err(e) = parse_size_mib(d)
            {
                problems.push(format!("resourceLimits.disk.workspaceSize: {e}"));
            }
            if let Some(t) = &rl.timeout {
                if let Some(w) = t.wall_clock.as_deref()
                    && let Err(e) = parse_duration_secs(w)
                {
                    problems.push(format!("resourceLimits.timeout.wallClock: {e}"));
                }
                if let Some(i) = t.idle.as_deref()
                    && let Err(e) = parse_duration_secs(i)
                {
                    problems.push(format!("resourceLimits.timeout.idle: {e}"));
                }
            }
        }

        if let Some(n) = &self.network_policy {
            if n.policy_file.is_some() && !n.egress.is_empty() {
                problems.push(
                    "networkPolicy: inline `egress` rules and a `policyFile` are two answers to \
                     one question — keep the inline rules for simple cases, or the file for a \
                     full policy, not both"
                        .into(),
                );
            }
            if n.enabled == Some(false) && !n.egress.is_empty() {
                problems.push(
                    "networkPolicy: `egress` names hosts but `enabled` is false, so the guest has \
                     no network device and will reach none of them"
                        .into(),
                );
            }
            if let Some(a) = n.default_action.as_deref()
                && a != "allow"
                && a != "deny"
            {
                problems.push(format!(
                    "networkPolicy.defaultAction: `{a}` is not `allow` or `deny`"
                ));
            }
            for (i, rule) in n.egress.iter().enumerate() {
                if let Some(a) = rule.action.as_deref()
                    && a != "allow"
                    && a != "deny"
                {
                    problems.push(format!(
                        "networkPolicy.egress[{i}].action: `{a}` is not `allow` or `deny`"
                    ));
                }
                if rule.domains.is_empty() {
                    problems.push(format!(
                        "networkPolicy.egress[{i}]: names no domains, so it permits nothing"
                    ));
                }
                for d in &rule.domains {
                    // The spec allows `*.github.com`. Our allow-list matches
                    // literal hostnames, so accepting a wildcard would deny
                    // everything while reading as permissive -- the worst
                    // possible failure for a security control.
                    if d.contains('*') {
                        problems.push(format!(
                            "networkPolicy.egress[{i}]: wildcard `{d}` is in the spec but not \
                             implemented here. This build matches literal hostnames, so a \
                             wildcard would silently match nothing. List the hosts explicitly."
                        ));
                    }
                }
            }

            // Ingress. Upstream models a filter on inbound traffic; this build
            // creates a listener. Every field that would widen the door beyond
            // what `--expose` accepts is refused *by name* -- dropping one would
            // publish a port while the document claimed something narrower.
            if n.enabled == Some(false) && !n.ingress.is_empty() {
                problems.push(
                    "networkPolicy: `ingress` publishes guest ports but `enabled` is false, so \
                     there is no NIC for a host connection to arrive on"
                        .into(),
                );
            }
            let mut seen: Vec<u16> = Vec::new();
            for (i, rule) in n.ingress.iter().enumerate() {
                for r in rule.refusals() {
                    // A field refusal already names its field; a port refusal
                    // names none, so it reads straight off the index.
                    let sep = if r.starts_with('.') { "" } else { ": " };
                    problems.push(format!("networkPolicy.ingress[{i}]{sep}{r}"));
                }
                if let Ok(p) = rule.port_number() {
                    if seen.contains(&p) {
                        problems.push(format!(
                            "networkPolicy.ingress[{i}]: port {p} is published twice; each \
                             guest port is published once, on one host port"
                        ));
                    }
                    seen.push(p);
                }
            }
        }

        if let Some(tp) = &self.tool_policy {
            if tp.approval.is_some() {
                problems.push(
                    "toolPolicy.approval: per-tool allow/deny (the `denyList: [\"bash\"]` case) is \
                     not enforceable here — nothing in chm sees the agent's tool calls. Refusing, \
                     because believing a tool is blocked when it is not is worse than knowing it \
                     is not. See #186."
                        .into(),
                );
            }
            for c in &tp.capabilities {
                if !["filesystem", "network", "subprocess"].contains(&c.as_str()) {
                    problems.push(format!("toolPolicy.capabilities: unknown capability `{c}`"));
                }
                if c == "filesystem" || c == "subprocess" {
                    problems.push(format!(
                        "toolPolicy.capabilities: `{c}` is accepted by the spec but this build \
                         can only enforce `network`. Listing it would imply a control that does \
                         not exist — see #186."
                    ));
                }
            }
        }

        if let Some(cp) = &self.checkpoint
            && let Some(iv) = cp.interval.as_deref()
        {
            match parse_duration_secs(iv) {
                Err(e) => problems.push(format!("checkpoint.interval: {e}")),
                Ok(0) => {
                    let msg = "checkpoint.interval: `0s` would checkpoint continuously";
                    problems.push(msg.into());
                }
                Ok(_) => {}
            }
        }

        if let Some(hr) = &self.host_requirements {
            if let Some(h) = hr.hypervisor.as_deref()
                && h != "cloud-hypervisor"
                && h != "any"
            {
                problems.push(format!(
                    "hostRequirements.hypervisor: this document requires `{h}`, and chm is \
                         cloud-hypervisor on Apple Hypervisor.framework. Running it here would \
                         not be the environment it asked for."
                ));
            }
            if let Some(m) = hr.memory.as_deref()
                && let Err(e) = parse_size_mib(m)
            {
                problems.push(format!("hostRequirements.memory: {e}"));
            }
        }

        // A spec is meant to be committed and reviewed. A credential in `env`
        // would be committed with it, and the credential proxy exists precisely
        // so the guest -- and therefore this file -- never holds one.
        //
        // V9.10 made `env` real, which makes this refusal *more* important
        // rather than less: until #190 a credential here was inert, and now it
        // would be exported into a shell.
        for (key, _) in self.env.iter() {
            let k = key.to_ascii_uppercase();
            if ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY"]
                .iter()
                .any(|needle| k.contains(needle))
            {
                problems.push(format!(
                    "env.{key} looks like a credential. A spec is meant to be committed, and the \
                     guest is never meant to hold one — use `secrets.rulesFile` so it is injected \
                     at the network edge instead."
                ));
            }
            // A name no shell can assign would validate here and then fail at
            // delivery, which is the "described but never delivered" gap this
            // milestone exists to close — so it is caught while the message can
            // still name the file it came from.
            if let Err(e) = postboot::validate_name(key) {
                problems.push(e);
            }
        }

        if let Some(e) = &self.post_boot_command
            && e.is_empty()
        {
            problems.push(
                "postBootCommand: an empty list is not a command; omit the field instead".into(),
            );
        }

        // The fields we understand but cannot yet carry into a guest. Refused
        // for the same reason as everything else here: a sandbox that does not
        // become what its own document describes is the failure this module is
        // written to prevent, and it makes no difference whether the missing
        // piece is somebody else's spec section or our own unbuilt flag.
        //
        // Empty since V9.10 — see [`UNDELIVERED`] for why the mechanism stays.
        for (name, issue, why) in UNDELIVERED {
            if undelivered_field_present(self, name) {
                problems.push(format!(
                    "`{name}` is understood but not yet delivered to the guest ({why}). \
                     Refusing rather than describing a sandbox this build cannot produce \
                     — see #{issue}."
                ));
            }
        }

        problems
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Where a resolved value came from.
///
/// The spec exists so a sandbox can be reviewed before it runs, and a value you
/// cannot trace to its source is not reviewable. Every field in [`Resolved`]
/// carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An explicit command-line flag — how *this run* differs.
    Flag(String),
    /// The spec document — what this sandbox *is*.
    Spec,
    /// A named sizing tier the spec chose.
    Tier(String),
    /// Nobody said; this is the built-in.
    Default,
}

impl Origin {
    /// A short phrase for the `--explain` column.
    pub fn describe(&self) -> String {
        match self {
            Self::Flag(f) => format!("flag {f}"),
            Self::Spec => SPEC_FILENAME.to_string(),
            Self::Tier(t) => format!("tier {t}"),
            Self::Default => "default".into(),
        }
    }
}

/// A value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T> Sourced<T> {
    pub fn new(value: T, origin: Origin) -> Self {
        Self { value, origin }
    }

    /// Take `other` if it is `Some`, recording `origin`; otherwise keep this.
    ///
    /// Layering is a chain of these from lowest precedence to highest, so the
    /// precedence order is visible as the order of the code rather than buried
    /// in nested conditionals.
    #[must_use]
    pub fn or_from(self, other: Option<T>, origin: Origin) -> Self {
        match other {
            Some(value) => Self { value, origin },
            None => self,
        }
    }
}

/// What a sandbox actually is, after layering, with every value traceable.
///
/// The single place where "what will this run be?" has an answer. Both the flags
/// and the spec produce one of these, which is what stops the spec becoming a
/// second source of truth.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub name: Option<String>,
    pub spec_path: Option<PathBuf>,

    pub kernel: Option<Sourced<PathBuf>>,
    pub initramfs: Option<Sourced<PathBuf>>,
    pub cmdline: Option<Sourced<String>>,
    pub disks: Sourced<Vec<PathBuf>>,
    pub snapshot: Option<Sourced<PathBuf>>,

    pub vcpus: Sourced<u8>,
    pub memory_mib: Sourced<u64>,
    pub disk_mib: Option<Sourced<u64>>,

    pub net: Sourced<bool>,
    /// Egress as `host:port`, which is what the rest of the tree speaks.
    pub egress_allow: Sourced<Vec<String>>,
    /// Guest ports to publish, which is all `--expose` accepts.
    ///
    /// A `Vec<u16>` rather than the spec's rules, because that is the whole of
    /// what survives [`SandboxSpec::validate`] -- everything a rule could say
    /// beyond a port number is refused there. Keeping the richer shape here
    /// would leave room for a later reader to honour a field this build cannot.
    pub ingress: Sourced<Vec<u16>>,
    pub egress_policy_file: Option<Sourced<PathBuf>>,
    pub allow_local_egress: Sourced<bool>,

    pub proxy_rules: Option<Sourced<PathBuf>>,
    pub cred_workspace: Option<Sourced<PathBuf>>,

    pub env: Sourced<BTreeMap<String, String>>,
    pub post_boot_command: Option<Sourced<Vec<String>>>,

    pub max_seconds: Sourced<u64>,
    pub idle_exit_seconds: Sourced<u64>,
    pub checkpoint: Sourced<bool>,
    pub checkpoint_interval_secs: Option<Sourced<u64>>,
}

/// Per-start overrides: the flags, as an optional-everything struct.
///
/// Every field is `None` for "this run did not say", which is what lets
/// [`resolve`] layer flags over the spec without a flag that was never passed
/// erasing something the spec did say.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub disks: Option<Vec<PathBuf>>,
    pub snapshot: Option<PathBuf>,
    pub vcpus: Option<u8>,
    pub memory_mib: Option<u64>,
    pub net: Option<bool>,
    pub egress_allow: Option<Vec<String>>,
    pub egress_policy_file: Option<PathBuf>,
    pub allow_local_egress: Option<bool>,
    pub proxy_rules: Option<PathBuf>,
    pub cred_workspace: Option<PathBuf>,
    pub max_seconds: Option<u64>,
    pub idle_exit_seconds: Option<u64>,
    pub checkpoint: Option<bool>,
}

const DEFAULT_VCPUS: u8 = 1;
const DEFAULT_MEMORY_MIB: u64 = 1024;
/// The port an egress rule means when it names none. 443 is the only port
/// anything in this tree has ever wanted by default.
const DEFAULT_EGRESS_PORT: u16 = 443;

/// Flatten the spec's `egress[]` rules into the `host:port` list the NAT speaks.
///
/// Only `allow` rules produce entries: the allow-list *is* the policy, and a
/// `deny` rule inside a default-deny posture adds nothing. A `deny` rule under
/// `defaultAction: "allow"` would be meaningful, which is why that combination
/// is refused in [`SandboxSpec::validate`] rather than quietly under-enforced.
fn flatten_egress(policy: &NetworkPolicy) -> Vec<String> {
    let mut out = Vec::new();
    for rule in &policy.egress {
        if rule.action.as_deref().unwrap_or("allow") != "allow" {
            continue;
        }
        let ports: Vec<u16> = if rule.ports.is_empty() {
            vec![DEFAULT_EGRESS_PORT]
        } else {
            rule.ports.clone()
        };
        for d in &rule.domains {
            for p in &ports {
                out.push(format!("{d}:{p}"));
            }
        }
    }
    out
}

/// Layer a spec and this run's flags into one answer.
///
/// Precedence, lowest first: built-in default, then a named tier, then the spec,
/// then the flags.
///
/// Environment bindings and per-workspace sidecar files are deliberately *not*
/// consulted here. They are resolved by the code that already owns them
/// (`resolve_egress_policy`, `resolve_rules`, `resolve_limits`), and duplicating
/// that order here would create exactly the second source of truth this module
/// exists to avoid. What this returns for those fields is "what the spec and
/// flags said" — which is precisely what those resolvers take as their override
/// argument.
pub fn resolve(spec: Option<&SandboxSpec>, spec_path: Option<PathBuf>, ov: &Overrides) -> Resolved {
    let img = spec.and_then(|s| s.image.as_ref());
    let rl = spec.and_then(|s| s.resource_limits.as_ref());
    let np = spec.and_then(|s| s.network_policy.as_ref());
    let sec = spec.and_then(|s| s.secrets.as_ref());
    let cp = spec.and_then(|s| s.checkpoint.as_ref());

    // A tier is a floor the spec's own explicit fields, and then the flags, are
    // free to lift.
    let named = rl.and_then(|r| r.tier.as_deref()).and_then(tier);
    let tier_origin = || named.map_or(Origin::Default, |t| Origin::Tier(t.name.to_string()));

    let vcpus = Sourced::new(named.map_or(DEFAULT_VCPUS, |t| t.vcpus), tier_origin())
        .or_from(
            rl.and_then(|r| r.cpu.as_ref()).and_then(|c| c.vcpus),
            Origin::Spec,
        )
        .or_from(ov.vcpus, Origin::Flag("--cpus".into()));

    let spec_ram = rl
        .and_then(|r| r.memory.as_ref())
        .and_then(|m| m.ram.as_deref())
        .and_then(|s| parse_size_mib(s).ok());
    let memory_mib = Sourced::new(
        named.map_or(DEFAULT_MEMORY_MIB, |t| t.memory_mib),
        tier_origin(),
    )
    .or_from(spec_ram, Origin::Spec)
    .or_from(ov.memory_mib, Origin::Flag("--memory".into()));

    let spec_disk = rl
        .and_then(|r| r.disk.as_ref())
        .and_then(|d| d.workspace_size.as_deref())
        .and_then(|s| parse_size_mib(s).ok());
    let disk_mib = match (named, spec_disk) {
        (_, Some(v)) => Some(Sourced::new(v, Origin::Spec)),
        (Some(t), None) => Some(Sourced::new(t.disk_mib, Origin::Tier(t.name.into()))),
        (None, None) => None,
    };

    let timeout = rl.and_then(|r| r.timeout.as_ref());
    let spec_wall = timeout
        .and_then(|t| t.wall_clock.as_deref())
        .and_then(|s| parse_duration_secs(s).ok());
    let spec_idle = timeout
        .and_then(|t| t.idle.as_deref())
        .and_then(|s| parse_duration_secs(s).ok());

    let opt = |spec_val: Option<PathBuf>, flag_val: Option<PathBuf>, flag: &str| {
        flag_val
            .map(|v| Sourced::new(v, Origin::Flag(flag.to_string())))
            .or_else(|| spec_val.map(|v| Sourced::new(v, Origin::Spec)))
    };

    // `toolPolicy.capabilities` addresses the network from the agent's side
    // rather than the VM's. Absence of "network" in a list that names any
    // capability at all is a deliberate statement, and the enforcement is real:
    // no NIC is attached.
    let caps = spec
        .and_then(|s| s.tool_policy.as_ref())
        .map(|t| &t.capabilities);
    let cap_net = match caps {
        Some(c) if !c.is_empty() => Some(c.iter().any(|x| x == "network")),
        _ => None,
    };

    Resolved {
        name: spec.and_then(|s| s.name.clone()),
        spec_path,

        kernel: opt(
            img.and_then(|i| i.kernel.clone()),
            ov.kernel.clone(),
            "--kernel",
        ),
        initramfs: opt(
            img.and_then(|i| i.initramfs.clone()),
            ov.initramfs.clone(),
            "--initramfs",
        ),
        cmdline: ov
            .cmdline
            .clone()
            .map(|v| Sourced::new(v, Origin::Flag("--cmdline".into())))
            .or_else(|| {
                img.and_then(|i| i.cmdline.clone())
                    .map(|v| Sourced::new(v, Origin::Spec))
            }),
        disks: Sourced::new(Vec::new(), Origin::Default)
            .or_from(
                img.map(|i| i.disks.clone()).filter(|d| !d.is_empty()),
                Origin::Spec,
            )
            .or_from(ov.disks.clone(), Origin::Flag("--disk".into())),
        snapshot: opt(
            img.and_then(|i| i.snapshot.clone()),
            ov.snapshot.clone(),
            "--snapshot",
        ),

        vcpus,
        memory_mib,
        disk_mib,

        net: Sourced::new(false, Origin::Default)
            .or_from(cap_net, Origin::Spec)
            .or_from(np.and_then(|n| n.enabled), Origin::Spec)
            .or_from(ov.net, Origin::Flag("--net".into())),
        egress_allow: Sourced::new(Vec::new(), Origin::Default)
            .or_from(
                np.map(flatten_egress).filter(|a| !a.is_empty()),
                Origin::Spec,
            )
            .or_from(
                ov.egress_allow.clone(),
                Origin::Flag("--egress-allow".into()),
            ),
        ingress: Sourced::new(Vec::new(), Origin::Default).or_from(
            np.map(|n| {
                // `publishable_port` is the one predicate, shared with
                // `validate`. A rule it refuses is reported there and
                // contributes nothing here, so a document that fails validation
                // cannot publish a port on the strength of a field this build
                // does not honour -- and that holds whether or not the caller
                // remembered to validate first.
                n.ingress
                    .iter()
                    .filter_map(|r| r.publishable_port())
                    .collect::<Vec<u16>>()
            })
            .filter(|p: &Vec<u16>| !p.is_empty()),
            Origin::Spec,
        ),
        egress_policy_file: opt(
            np.and_then(|n| n.policy_file.clone()),
            ov.egress_policy_file.clone(),
            "--egress-policy",
        ),
        allow_local_egress: Sourced::new(false, Origin::Default)
            .or_from(np.and_then(|n| n.allow_local), Origin::Spec)
            .or_from(
                ov.allow_local_egress,
                Origin::Flag("--allow-local-egress".into()),
            ),

        proxy_rules: opt(
            sec.and_then(|c| c.rules_file.clone()),
            ov.proxy_rules.clone(),
            "--proxy-rules",
        ),
        cred_workspace: opt(
            sec.and_then(|c| c.workspace.clone()),
            ov.cred_workspace.clone(),
            "--workspace",
        ),

        env: Sourced::new(BTreeMap::new(), Origin::Default).or_from(
            spec.map(|s| s.env.clone()).filter(|e| !e.is_empty()),
            Origin::Spec,
        ),
        post_boot_command: spec
            .and_then(|s| s.post_boot_command.clone())
            .map(|v| Sourced::new(v, Origin::Spec)),

        max_seconds: Sourced::new(0, Origin::Default)
            .or_from(spec_wall, Origin::Spec)
            .or_from(ov.max_seconds, Origin::Flag("--max-seconds".into())),
        idle_exit_seconds: Sourced::new(DEFAULT_IDLE_EXIT_SECS, Origin::Default)
            .or_from(spec_idle, Origin::Spec)
            .or_from(ov.idle_exit_seconds, Origin::Flag("--idle-exit".into())),
        checkpoint: Sourced::new(false, Origin::Default)
            .or_from(cp.and_then(|c| c.enabled), Origin::Spec)
            .or_from(ov.checkpoint, Origin::Flag("--checkpoint".into())),
        checkpoint_interval_secs: cp
            .and_then(|c| c.interval.as_deref())
            .and_then(|s| parse_duration_secs(s).ok())
            .map(|v| Sourced::new(v, Origin::Spec)),
    }
}

impl Resolved {
    /// Render what this sandbox is, with the origin of every value.
    ///
    /// This is the artifact the whole milestone is for: something to read before
    /// you run, put in a review, or paste into a bug report. It answers "what did
    /// I actually run?" without anyone reconstructing it from a shell history.
    pub fn explain(&self) -> String {
        let mut out = String::new();
        if let Some(n) = &self.name {
            let _ = writeln!(out, "{n}");
        }
        match &self.spec_path {
            Some(p) => {
                let _ = writeln!(out, "  spec: {}", p.display());
            }
            None => out.push_str("  spec: none — this sandbox is described only by its flags\n"),
        }
        out.push('\n');
        out.push_str("  FIELD              VALUE                                FROM\n");

        let mut row = |field: &str, value: String, origin: &Origin| {
            let _ = writeln!(out, "  {field:<18} {value:<36} {}", origin.describe());
        };

        if let Some(s) = &self.snapshot {
            row("snapshot", s.value.display().to_string(), &s.origin);
        }
        if let Some(k) = &self.kernel {
            row("kernel", k.value.display().to_string(), &k.origin);
        }
        if let Some(i) = &self.initramfs {
            row("initramfs", i.value.display().to_string(), &i.origin);
        }
        if let Some(c) = &self.cmdline {
            row("cmdline", c.value.clone(), &c.origin);
        }
        if !self.disks.value.is_empty() {
            let joined = self
                .disks
                .value
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            row("disks", joined, &self.disks.origin);
        }

        row("vcpus", self.vcpus.value.to_string(), &self.vcpus.origin);
        row(
            "memory",
            format_size(self.memory_mib.value),
            &self.memory_mib.origin,
        );
        if let Some(d) = &self.disk_mib {
            row("disk", format_size(d.value), &d.origin);
        }

        row(
            "network",
            if self.net.value {
                "on".into()
            } else {
                "off".into()
            },
            &self.net.origin,
        );
        if self.net.value {
            if self.egress_allow.value.is_empty() {
                row("egress", "deny all".into(), &self.egress_allow.origin);
            } else {
                row(
                    "egress",
                    self.egress_allow.value.join(", "),
                    &self.egress_allow.origin,
                );
            }
            if !self.ingress.value.is_empty() {
                row(
                    "ingress",
                    format!(
                        "{} on {INGRESS_BIND_ADDR}",
                        self.ingress
                            .value
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    &self.ingress.origin,
                );
            }
        }
        if let Some(p) = &self.egress_policy_file {
            row("egress policy", p.value.display().to_string(), &p.origin);
        }
        if self.allow_local_egress.value {
            row(
                "local egress",
                "permitted".into(),
                &self.allow_local_egress.origin,
            );
        }
        if let Some(r) = &self.proxy_rules {
            row("secrets", r.value.display().to_string(), &r.origin);
        }

        if !self.env.value.is_empty() {
            row(
                "env",
                self.env
                    .value
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                &self.env.origin,
            );
        }
        if let Some(e) = &self.post_boot_command {
            row("postBoot", e.value.join(" "), &e.origin);
        }

        row(
            "wallClock",
            if self.max_seconds.value == 0 {
                "unbounded".into()
            } else {
                format_duration(self.max_seconds.value)
            },
            &self.max_seconds.origin,
        );
        row(
            "idle",
            if self.idle_exit_seconds.value == 0 {
                "disabled".into()
            } else {
                format_duration(self.idle_exit_seconds.value)
            },
            &self.idle_exit_seconds.origin,
        );
        row(
            "checkpoint",
            if self.checkpoint.value {
                "on".into()
            } else {
                "off".into()
            },
            &self.checkpoint.origin,
        );
        if let Some(iv) = &self.checkpoint_interval_secs {
            row("checkpoint every", format_duration(iv.value), &iv.origin);
        }

        out
    }

    /// Turn a resolved sandbox back into the argv it is equivalent to.
    ///
    /// This is what keeps the spec honest. The spec gets no private way to start
    /// a guest — it produces the command line a person would have typed, parsed
    /// by the same parser. If the spec could express something the flags cannot,
    /// the divergence shows up here as a field with nowhere to go, rather than
    /// as two subtly different guests.
    pub fn to_create_argv(&self) -> Vec<String> {
        let mut argv = vec!["create".to_string()];
        fn push(argv: &mut Vec<String>, flag: &str, val: String) {
            argv.push(flag.into());
            argv.push(val);
        }
        if let Some(k) = &self.kernel {
            push(&mut argv, "--kernel", k.value.display().to_string());
        }
        if let Some(i) = &self.initramfs {
            push(&mut argv, "--initramfs", i.value.display().to_string());
        }
        if let Some(c) = &self.cmdline {
            push(&mut argv, "--cmdline", c.value.clone());
        }
        for d in &self.disks.value {
            push(&mut argv, "--disk", d.display().to_string());
        }
        push(&mut argv, "--cpus", self.vcpus.value.to_string());
        push(&mut argv, "--memory", self.memory_mib.value.to_string());
        if self.net.value {
            argv.push("--net".into());
        }
        for h in &self.egress_allow.value {
            push(&mut argv, "--egress-allow", h.clone());
        }
        // A published port leaves here as `--expose <PORT>` and nothing else,
        // so a spec cannot open a door the flag could not. Whatever this emits
        // goes back through the same `parse()` a typed flag does, which is what
        // makes that a property of the code rather than a promise.
        for p in &self.ingress.value {
            push(&mut argv, "--expose", p.to_string());
        }
        if let Some(r) = &self.proxy_rules {
            push(&mut argv, "--proxy-rules", r.value.display().to_string());
        }
        if let Some(w) = &self.cred_workspace {
            push(&mut argv, "--workspace", w.value.display().to_string());
        }
        if self.allow_local_egress.value {
            argv.push("--allow-local-egress".into());
        }
        if self.max_seconds.value > 0 {
            push(&mut argv, "--seconds", self.max_seconds.value.to_string());
        }
        for (k, v) in &self.env.value {
            push(&mut argv, "--env", format!("{k}={v}"));
        }
        // `--post-boot-arg`, never `--post-boot`. This argv is spliced *before*
        // the caller's own flags so that a flag wins, and `--post-boot` takes
        // everything after it as the guest's command — so a spec emitting the
        // greedy form would silently eat `--dry-run`, `--cpus 4`, and every
        // other override, destroying the precedence rule this module exists to
        // implement. Measured, not reasoned about: the first build of V9.10 did
        // exactly this and booted a guest when asked to describe one.
        if let Some(pb) = &self.post_boot_command {
            for arg in &pb.value {
                push(&mut argv, "--post-boot-arg", arg.clone());
            }
        }
        argv
    }
}

/// A starter spec, written to teach rather than to be minimal.
///
/// Deliberately a *working* sandbox with the network off, because the first
/// thing anyone does with a generated config is run it, and the safe default has
/// to be the one that costs nothing to get wrong.
pub fn starter(name: &str) -> SandboxSpec {
    SandboxSpec {
        spec_version: SPEC_VERSION,
        name: Some(name.to_string()),
        description: Some("What this sandbox is for.".into()),
        resource_limits: Some(ResourceLimits {
            tier: Some("dev".into()),
            timeout: Some(TimeoutLimits {
                idle: Some(format_duration(DEFAULT_IDLE_EXIT_SECS)),
                ..TimeoutLimits::default()
            }),
            ..ResourceLimits::default()
        }),
        network_policy: Some(NetworkPolicy {
            enabled: Some(false),
            default_action: Some("deny".into()),
            ..NetworkPolicy::default()
        }),
        checkpoint: Some(CheckpointSpec {
            enabled: Some(true),
            ..CheckpointSpec::default()
        }),
        host_requirements: Some(HostRequirements {
            hypervisor: Some("cloud-hypervisor".into()),
            ..HostRequirements::default()
        }),
        ..SandboxSpec::default()
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const SPEC_USAGE: &str = "chm spec — describe a sandbox instead of assembling one\n\
     \n\
     A sandbox spec is a `sandbox.json` in a workspace: what the sandbox is,\n\
     committed alongside the code it runs, rather than a command line somebody\n\
     has to remember. Flags still work and still win — they say how *this run*\n\
     differs from what the sandbox is.\n\
     \n\
     USAGE:\n    \
         chm spec init <WORKSPACE_DIR> [--name NAME] [--force]\n    \
         chm spec show <WORKSPACE_DIR> [--explain] [--argv]\n    \
         chm spec validate <WORKSPACE_DIR|FILE>\n    \
         chm spec tiers\n\
     \n\
     COMMANDS:\n    \
         init      Write a starter sandbox.json you can edit.\n    \
         show      What this sandbox resolves to. --explain adds where each\n              \
         value came from; --argv prints the equivalent `chm create`.\n    \
         validate  Check a spec and report every problem, not just the first.\n              \
         Exits non-zero if anything is wrong.\n    \
         tiers     The named sizing tiers, and what each is for.\n\
     \n\
     This build implements part of the agent compute environment spec. Sections\n\
     it does not implement are refused by name rather than ignored — a sandbox\n\
     that silently starts weaker than its own description is the failure this\n\
     is written to prevent.\n";

/// Resolve `<WORKSPACE_DIR|FILE>` to a spec file, so both forms work.
pub fn spec_file_for(arg: &Path) -> PathBuf {
    if arg.is_dir() {
        arg.join(SPEC_FILENAME)
    } else {
        arg.to_path_buf()
    }
}

fn print_problems(path: &Path, problems: &[String]) {
    eprintln!("{}: {} problem(s)", path.display(), problems.len());
    for p in problems {
        eprintln!("  - {p}");
    }
}

pub fn spec_main(args: &[String]) -> ExitCode {
    let verb = args.first().map(String::as_str);
    if verb.is_none() || matches!(verb, Some("--help" | "-h" | "help")) {
        return answer_group_help("spec", verb.is_some(), SPEC_USAGE);
    }
    match verb {
        Some("tiers") => {
            print!("{}", describe_tiers());
            ExitCode::SUCCESS
        }
        Some("init") => spec_init(&args[1..]),
        Some("show") => spec_show(&args[1..]),
        Some("validate") => spec_validate(&args[1..]),
        Some(other) => {
            // Message and usage on the same stream, as `kernel`, `image` and
            // `ctl` all do. Splitting them sends the half that tells you what
            // to do next to stdout, where a caller reading stderr for the
            // reason never sees it.
            eprintln!(
                "chm spec: unknown command `{other}`\n\n{}",
                SPEC_USAGE.trim_end_matches('\n')
            );
            ExitCode::FAILURE
        }
        None => unreachable!("handled above"),
    }
}

fn spec_init(args: &[String]) -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" if i + 1 < args.len() => {
                name = Some(args[i + 1].clone());
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            a if a.starts_with('-') => {
                eprintln!("chm spec init: unknown option `{a}`");
                return ExitCode::FAILURE;
            }
            a => {
                dir = Some(PathBuf::from(a));
                i += 1;
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("chm spec init: needs a workspace directory\n");
        print!("{SPEC_USAGE}");
        return ExitCode::FAILURE;
    };
    let path = dir.join(SPEC_FILENAME);
    // Overwriting is refused rather than confirmed: a spec is hand-edited, and
    // the edits are the part that matters.
    if path.exists() && !force {
        eprintln!(
            "chm spec init: {} already exists (use --force to overwrite)",
            path.display()
        );
        return ExitCode::FAILURE;
    }
    let default_name = dir.file_name().map_or_else(
        || "sandbox".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let spec = starter(name.as_deref().unwrap_or(&default_name));
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("chm spec init: create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&path, spec.to_json()) {
        eprintln!("chm spec init: write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {}", path.display());
    println!("Edit it, then `chm spec show {} --explain`.", dir.display());
    ExitCode::SUCCESS
}

fn spec_show(args: &[String]) -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let mut explain = false;
    let mut argv_out = false;
    for a in args {
        match a.as_str() {
            "--explain" => explain = true,
            "--argv" => argv_out = true,
            other if other.starts_with('-') => {
                eprintln!("chm spec show: unknown option `{other}`");
                return ExitCode::FAILURE;
            }
            other => dir = Some(PathBuf::from(other)),
        }
    }
    // No argument means "this workspace", which is the common case when you are
    // stood in the directory you are about to run.
    let path = match dir {
        Some(d) => spec_file_for(&d),
        None => match SandboxSpec::discover(Path::new(".")) {
            Ok(Some((_, p))) => p,
            Ok(None) => {
                eprintln!(
                    "chm spec show: no {SPEC_FILENAME} here — name a workspace, or \
                     `chm spec init .` to write one\n"
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("chm spec show: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let spec = match SandboxSpec::load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chm spec show: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Showing a spec that would be refused must say so. Printing a tidy table
    // for a document that will not start anything is the exact shape of lie
    // this milestone is written against.
    let problems = spec.validate();
    let resolved = resolve(Some(&spec), Some(path.clone()), &Overrides::default());

    if argv_out {
        println!("chm {}", resolved.to_create_argv().join(" "));
    } else if explain {
        print!("{}", resolved.explain());
    } else {
        print!("{}", spec.to_json());
    }

    if !problems.is_empty() {
        eprintln!();
        print_problems(&path, &problems);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn spec_validate(args: &[String]) -> ExitCode {
    let Some(arg) = args.iter().find(|a| !a.starts_with('-')) else {
        eprintln!("chm spec validate: needs a workspace directory or a spec file\n");
        print!("{SPEC_USAGE}");
        return ExitCode::FAILURE;
    };
    let path = spec_file_for(Path::new(arg));
    let spec = match SandboxSpec::load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("chm spec validate: {e}");
            return ExitCode::FAILURE;
        }
    };
    let problems = spec.validate();
    if problems.is_empty() {
        println!("{}: ok", path.display());
        ExitCode::SUCCESS
    } else {
        print_problems(&path, &problems);
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(json: &str) -> SandboxSpec {
        SandboxSpec::parse(json, Path::new("<test>")).expect("parses")
    }

    #[test]
    fn sizes_are_binary_and_units_round_trip() {
        assert_eq!(parse_size_mib("512mb").unwrap(), 512);
        assert_eq!(parse_size_mib("4gb").unwrap(), 4096);
        // A bare number is refused: "2048" could be MiB or bytes, and guessing
        // wrong by a factor of a million is not a helpful default.
        assert!(parse_size_mib("2048").is_err());
        assert_eq!(parse_size_mib("1GB").unwrap(), 1024);
        assert!(parse_size_mib("4 potatoes").is_err());
        assert!(parse_size_mib("").is_err());
        // A tier's numbers must survive being rendered and read back, because
        // `spec init` writes them out and the next run parses them again.
        for t in TIERS {
            assert_eq!(
                parse_size_mib(&format_size(t.memory_mib)).unwrap(),
                t.memory_mib
            );
            assert_eq!(
                parse_size_mib(&format_size(t.disk_mib)).unwrap(),
                t.disk_mib
            );
        }
    }

    #[test]
    fn durations_round_trip() {
        assert_eq!(parse_duration_secs("30m").unwrap(), 1800);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
        assert_eq!(parse_duration_secs("45s").unwrap(), 45);
        assert!(
            parse_duration_secs("90").is_err(),
            "a bare number has no unit"
        );
        assert!(parse_duration_secs("soon").is_err());
        for secs in [1_u64, 59, 60, 600, 3600, 86400] {
            assert_eq!(parse_duration_secs(&format_duration(secs)).unwrap(), secs);
        }
    }

    #[test]
    fn a_newer_spec_version_is_refused_by_name() {
        let err = SandboxSpec::parse(r#"{"specVersion": 99}"#, Path::new("x")).unwrap_err();
        assert!(err.contains("newer chm"), "{err}");
        // Older is read: compatibility with what is on disk is the point.
        SandboxSpec::parse(r#"{"specVersion": 0}"#, Path::new("x")).unwrap();
    }

    /// The central rule of this module: a spec section we have not built is
    /// **refused by name with its issue**, never silently dropped.
    ///
    /// Silently ignoring `securityModules` would start a sandbox weaker than the
    /// document describing it, with nothing to tell the operator — the same
    /// failure shape as #178 and #180.
    #[test]
    fn unimplemented_sections_are_refused_by_name_not_ignored() {
        for (name, issue, _) in UNIMPLEMENTED {
            let doc = spec_from(&format!(r#"{{"specVersion":1,"{name}":{{}}}}"#));
            let problems = doc.validate();
            assert!(
                problems
                    .iter()
                    .any(|p| p.contains(name) && p.contains(&issue.to_string())),
                "`{name}` must be refused by name and cite #{issue}, got {problems:?}"
            );
        }
    }

    #[test]
    fn a_typo_is_reported_as_a_typo_not_as_unbuilt() {
        let problems = spec_from(r#"{"specVersion":1,"netwrokPolicy":{}}"#).validate();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("unknown field"), "{problems:?}");
        // and must NOT claim an issue exists for it
        assert!(!problems[0].contains('#'), "{problems:?}");
    }

    /// Wildcards are in the external spec and are *not* implemented here.
    /// Accepting one would compile to a literal-hostname match that can never
    /// fire — a rule that reads as permissive and denies everything.
    #[test]
    fn a_wildcard_domain_is_refused_rather_than_matched_literally() {
        let problems = spec_from(
            r#"{"specVersion":1,"networkPolicy":{"egress":[{"domains":["*.github.com"]}]}}"#,
        )
        .validate();
        assert!(
            problems.iter().any(|p| p.contains("wildcard")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_credential_in_env_is_refused_because_a_spec_gets_committed() {
        let problems =
            spec_from(r#"{"specVersion":1,"env":{"GITHUB_TOKEN":"ghp_x","LANG":"C"}}"#).validate();
        // Alongside the #190 "env is not delivered yet" refusal: the credential
        // objection has to stand on its own, because when #190 lands and that
        // one goes away this one must remain.
        assert!(
            problems
                .iter()
                .any(|p| p.contains("GITHUB_TOKEN") && p.contains("secrets.rulesFile")),
            "{problems:?}"
        );
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let problems = spec_from(
            r#"{"specVersion":1,
                "resourceLimits":{"tier":"huge","memory":{"ram":"1mb"}},
                "networkPolicy":{"defaultAction":"maybe"},
                "securityModules":{}}"#,
        )
        .validate();
        assert!(problems.len() >= 4, "expected all four, got {problems:?}");
    }

    #[test]
    fn a_tier_sets_everything_and_explicit_values_lift_it() {
        let doc = spec_from(r#"{"specVersion":1,"resourceLimits":{"tier":"standard"}}"#);
        let r = resolve(Some(&doc), None, &Overrides::default());
        assert_eq!(r.vcpus.value, 2);
        assert_eq!(r.memory_mib.value, 2048);
        assert_eq!(r.vcpus.origin, Origin::Tier("standard".into()));

        let doc = spec_from(
            r#"{"specVersion":1,"resourceLimits":{"tier":"standard","cpu":{"vcpus":8}}}"#,
        );
        let r = resolve(Some(&doc), None, &Overrides::default());
        assert_eq!(r.vcpus.value, 8);
        assert_eq!(r.vcpus.origin, Origin::Spec);
        // …and the fields the tier still owns keep saying so.
        assert_eq!(r.memory_mib.origin, Origin::Tier("standard".into()));
    }

    /// Precedence, and the reason the origin is carried at all: a flag is how
    /// *this run* differs, so it wins, and the explain output must say which.
    #[test]
    fn a_flag_beats_the_spec_and_the_origin_records_it() {
        let doc = spec_from(r#"{"specVersion":1,"resourceLimits":{"cpu":{"vcpus":2}}}"#);
        let r = resolve(
            Some(&doc),
            None,
            &Overrides {
                vcpus: Some(9),
                ..Overrides::default()
            },
        );
        assert_eq!(r.vcpus.value, 9);
        assert_eq!(r.vcpus.origin, Origin::Flag("--cpus".into()));
        assert!(r.explain().contains("flag --cpus"));
    }

    /// A flag that was *not* passed must not erase what the spec said. This is
    /// the bug a naive `unwrap_or(default)` layering would ship.
    #[test]
    fn an_absent_flag_does_not_overwrite_the_spec() {
        let doc = spec_from(r#"{"specVersion":1,"resourceLimits":{"cpu":{"vcpus":3}}}"#);
        let r = resolve(Some(&doc), None, &Overrides::default());
        assert_eq!(r.vcpus.value, 3);
    }

    #[test]
    fn no_spec_at_all_resolves_to_the_documented_defaults() {
        let r = resolve(None, None, &Overrides::default());
        assert_eq!(r.vcpus.value, DEFAULT_VCPUS);
        assert_eq!(r.memory_mib.value, DEFAULT_MEMORY_MIB);
        assert_eq!(r.idle_exit_seconds.value, DEFAULT_IDLE_EXIT_SECS);
        assert!(!r.net.value, "a sandbox with nothing said gets no network");
        assert!(r.egress_allow.value.is_empty(), "and reaches nothing");
    }

    #[test]
    fn egress_rules_flatten_to_host_port_and_default_to_443() {
        let doc = spec_from(
            r#"{"specVersion":1,"networkPolicy":{"enabled":true,"egress":[
                 {"domains":["api.github.com"]},
                 {"domains":["ports.ubuntu.com"],"ports":[80,443]},
                 {"action":"deny","domains":["evil.example"]}]}}"#,
        );
        let r = resolve(Some(&doc), None, &Overrides::default());
        assert_eq!(
            r.egress_allow.value,
            vec![
                "api.github.com:443",
                "ports.ubuntu.com:80",
                "ports.ubuntu.com:443"
            ]
        );
    }

    /// `to_create_argv` is the honesty mechanism: the spec produces the command
    /// line a person would have typed, parsed by the same parser. If it ever
    /// stopped covering a resolved field, the spec would have gained a private
    /// route to the guest.
    #[test]
    fn the_argv_carries_every_field_the_spec_set() {
        let doc = spec_from(
            r#"{"specVersion":1,
                "image":{"kernel":"/k/Image","initramfs":"/k/initrd","disks":["/d/a.raw","/d/b.raw"],
                         "cmdline":"console=ttyAMA0"},
                "resourceLimits":{"cpu":{"vcpus":4},"memory":{"ram":"3gb"},
                                  "timeout":{"wallClock":"5m"}},
                "networkPolicy":{"enabled":true,"egress":[{"domains":["api.github.com"]}]},
                "secrets":{"rulesFile":"/w/proxy-rules.json","workspace":"/w"}}"#,
        );
        assert!(doc.validate().is_empty(), "{:?}", doc.validate());
        let argv = resolve(Some(&doc), None, &Overrides::default()).to_create_argv();
        let joined = argv.join(" ");
        for expected in [
            "--kernel /k/Image",
            "--initramfs /k/initrd",
            "--cmdline console=ttyAMA0",
            "--disk /d/a.raw",
            "--disk /d/b.raw",
            "--cpus 4",
            "--memory 3072",
            "--net",
            "--egress-allow api.github.com:443",
            "--proxy-rules /w/proxy-rules.json",
            "--workspace /w",
            "--seconds 300",
        ] {
            assert!(
                joined.contains(expected),
                "argv lost `{expected}`: {joined}"
            );
        }
    }

    #[test]
    fn the_starter_spec_is_valid_and_round_trips() {
        let s = starter("demo");
        assert!(s.validate().is_empty(), "{:?}", s.validate());
        let back = SandboxSpec::parse(&s.to_json(), Path::new("x")).unwrap();
        assert_eq!(back.name.as_deref(), Some("demo"));
        // The starter must not quietly enable the network.
        let r = resolve(Some(&back), None, &Overrides::default());
        assert!(!r.net.value);
    }

    #[test]
    fn explain_names_a_source_for_every_line_it_prints() {
        let doc = spec_from(r#"{"specVersion":1,"resourceLimits":{"tier":"micro"}}"#);
        let text = resolve(
            Some(&doc),
            Some(PathBuf::from("/w/sandbox.json")),
            &Overrides::default(),
        )
        .explain();
        for line in text
            .lines()
            .skip(4)
            .filter(|l| l.starts_with("  ") && !l.trim().is_empty())
        {
            assert!(
                ["tier ", "flag ", SPEC_FILENAME, "default"]
                    .iter()
                    .any(|o| line.contains(o)),
                "no origin on: {line}"
            );
        }
    }

    /// A frozen document, checked in, that this build must keep reading — the
    /// #180 discipline applied from the first commit rather than after the first
    /// breakage. Both directions matter: the fields must survive parsing, *and*
    /// nothing in the file may be quietly dropped.
    #[test]
    fn the_frozen_v1_fixture_still_parses_to_the_same_sandbox() {
        let raw = include_str!("../testdata/sandbox-spec-v1.json");
        let doc = SandboxSpec::parse(raw, Path::new("testdata/sandbox-spec-v1.json"))
            .expect("the checked-in v1 spec must still parse");
        assert!(
            doc.validate().is_empty(),
            "the frozen spec must still be startable: {:?}",
            doc.validate()
        );
        assert!(
            doc.extra.is_empty(),
            "fields fell through to `extra`, so this build no longer knows them: {:?}",
            doc.extra.keys().collect::<Vec<_>>()
        );
        let r = resolve(Some(&doc), None, &Overrides::default());
        assert_eq!(r.vcpus.value, 2);
        assert_eq!(r.memory_mib.value, 2048);
        assert_eq!(r.disk_mib.as_ref().unwrap().value, 16384);
        assert!(r.net.value);
        assert_eq!(r.egress_allow.value, vec!["api.github.com:443"]);
        assert_eq!(r.max_seconds.value, 1800);
        assert_eq!(r.idle_exit_seconds.value, 600);
        assert!(r.checkpoint.value);
        assert_eq!(r.checkpoint_interval_secs.as_ref().unwrap().value, 300);
        // Removed from this fixture in V9.3 because the build refused them, and
        // put back in V9.10 when it stopped. The fixture is the record of what
        // this build can be asked for, so it has to move when that moves.
        assert_eq!(r.env.value.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(
            r.post_boot_command.as_ref().unwrap().value,
            vec!["/usr/bin/env".to_string(), "true".to_string()]
        );
    }

    /// The V9.10 inversion of the V9.3 test that used to live here.
    ///
    /// `env` and `postBootCommand` were refused with #190 because nothing
    /// carried them into a guest. Now something does, so the same two documents
    /// must **start** — and, more importantly, must reach the argv, because
    /// "accepted" and "delivered" are exactly the two things V9.3 proved could
    /// come apart.
    #[test]
    fn env_and_post_boot_command_are_accepted_and_reach_the_command_line() {
        for json in [
            r#"{"specVersion":1,"env":{"LANG":"C.UTF-8"}}"#,
            r#"{"specVersion":1,"postBootCommand":["/usr/bin/env","true"]}"#,
        ] {
            let problems = spec_from(json).validate();
            assert!(
                !problems.iter().any(|p| p.contains("190")),
                "no longer undelivered, so #190 must not be cited: {problems:?}"
            );
        }

        let doc = spec_from(
            r#"{"specVersion":1,"env":{"LANG":"C.UTF-8","TZ":"UTC"},
                "postBootCommand":["/usr/bin/env","true"]}"#,
        );
        let argv = resolve(Some(&doc), None, &Overrides::default()).to_create_argv();
        let line = argv.join(" ");
        // Accepting a field and then not emitting it is precisely the V9.3 gap.
        assert!(line.contains("--env LANG=C.UTF-8"), "{line}");
        assert!(line.contains("--env TZ=UTC"), "{line}");
        assert!(
            line.contains("--post-boot-arg /usr/bin/env --post-boot-arg true"),
            "{line}"
        );
    }

    /// The bug this milestone's own hardware run found, frozen as a test.
    ///
    /// `--spec` splices its argv **before** the caller's flags so that a flag
    /// wins. `--post-boot` takes everything after it as the guest's command. Put
    /// those two together and a spec with a `postBootCommand` silently eats
    /// every flag the operator typed — `--dry-run` became an argument to the
    /// guest, so asking `chm create` to *describe* a sandbox booted one instead.
    ///
    /// The other half of this rule — that the spliced argv still parses, and a
    /// flag after it still reaches `chm` — lives in `create.rs`, where the
    /// parser it has to survive is in scope.
    #[test]
    fn a_spec_never_emits_the_greedy_post_boot_flag() {
        let doc = spec_from(
            r#"{"specVersion":1,"postBootCommand":["echo","hi"],
                "resourceLimits":{"cpu":{"vcpus":2}}}"#,
        );
        let argv = resolve(Some(&doc), None, &Overrides::default()).to_create_argv();
        assert!(
            !argv.iter().any(|a| a == "--post-boot"),
            "the greedy form would swallow the caller's flags: {argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == "--post-boot-arg").count(),
            2,
            "one flag per argv element: {argv:?}"
        );
    }

    #[test]
    fn an_env_name_no_shell_can_assign_is_refused_by_the_document() {
        // Otherwise it would validate here and fail at delivery — the same
        // described-but-not-delivered shape, moved one step later.
        let problems = spec_from(r#"{"specVersion":1,"env":{"my-var":"1"}}"#).validate();
        assert!(
            problems.iter().any(|p| p.contains("my-var")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_credential_shaped_env_name_is_still_refused_now_that_env_is_real() {
        // Delivering `env` makes this refusal matter more, not less: before
        // #190 a token here was inert, and now it would be exported.
        let problems = spec_from(r#"{"specVersion":1,"env":{"GITHUB_TOKEN":"ghp_x"}}"#).validate();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("GITHUB_TOKEN") && p.contains("secrets.rulesFile")),
            "{problems:?}"
        );
    }

    /// #386: the `image.oci` refusal cited #153, and #153 shipped -- so a user
    /// reading it was sent to a closed issue for a thing that now exists.
    ///
    /// The class is sharper than one stale number. `image.oci` cited a
    /// *dependency*, and a dependency closes the moment it ships, so the
    /// citation was guaranteed to rot. The `UNIMPLEMENTED` table never rotted
    /// because its numbers track the features themselves. So the rule this
    /// pins is: a refusal cites the issue tracking the missing thing, or it
    /// cites nothing at all.
    ///
    /// Asserted against the strings a user is handed, not against the source.
    /// A source scan cannot tell a refusal from the comment above it, and the
    /// comments here legitimately discuss shipped issues by number.
    #[test]
    fn no_refusal_sends_a_reader_to_an_issue_that_does_not_track_it() {
        let mut tracked: Vec<String> = UNIMPLEMENTED
            .iter()
            .map(|(_, issue, _)| issue.to_string())
            .collect();
        // Refusals outside the table, each citing the issue that tracks the
        // missing thing rather than something it depends on. A new entry here
        // is a deliberate claim, which is the point.
        //
        // 186 -- toolPolicy.approval and toolPolicy.capabilities: both need the
        //        agent's tool calls to pass through chm, which nothing arranges.
        tracked.push("186".into());

        // Every section the table refuses, one document each -- the shape
        // `unimplemented_sections_are_refused_by_name_not_ignored` already
        // proves parses -- plus the ad-hoc refusals a partial spec never reaches.
        let mut problems: Vec<String> = UNIMPLEMENTED
            .iter()
            .flat_map(|(name, _, _)| {
                spec_from(&format!(r#"{{"specVersion":1,"{name}":{{}}}}"#)).validate()
            })
            .collect();
        let adhoc = [
            r#"{"specVersion":1,"image":{"oci":"alpine:3.20"}}"#,
            r#"{"specVersion":1,"toolPolicy":{"approval":{}}}"#,
            r#"{"specVersion":1,"toolPolicy":{"capabilities":["subprocess","quantum"]}}"#,
            r#"{"specVersion":1,"networkPolicy":{"egress":[{"domains":["*.example.com"]}]}}"#,
        ];
        for doc in adhoc {
            let found = spec_from(doc).validate();
            assert!(
                !found.is_empty(),
                "this document no longer trips a refusal, so the guard reads less \
                 than it claims to: {doc}"
            );
            problems.extend(found);
        }

        for problem in &problems {
            let mut rest = problem.as_str();
            while let Some(at) = rest.find('#') {
                rest = &rest[at + 1..];
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if digits.is_empty() {
                    continue;
                }
                assert!(
                    tracked.contains(&digits),
                    "a refusal cites #{digits}, which tracks none of the sections this \
                     build refuses. Cite the issue for the missing thing, or say the \
                     reason plainly with no number -- a dependency's number goes stale \
                     the day the dependency ships (#386). Refusal: {problem}"
                );
            }
        }
    }

    /// The remedy has to be a command that exists. Read the flags out of the
    /// builder's own usage text rather than restating them here, or a rename
    /// leaves this message pointing at nothing -- the #306 shape.
    #[test]
    fn the_oci_refusal_names_the_real_builder_invocation() {
        let problems = spec_from(r#"{"specVersion":1,"image":{"oci":"alpine:3.20"}}"#).validate();
        let refusal = problems
            .iter()
            .find(|p| p.starts_with("image.oci:"))
            .unwrap_or_else(|| panic!("image.oci must still be refused: {problems:?}"));

        let usage = crate::oci::image::usage();
        for flag in ["chm image build", "--kernel", "--out"] {
            assert!(
                names(&usage, flag),
                "`{flag}` is not in `chm image build`'s own usage text any more, so \
                 the image.oci refusal is recommending something that does not exist"
            );
            assert!(
                names(refusal, flag),
                "the image.oci refusal must name `{flag}`: {refusal}"
            );
        }
    }

    /// `contains` is the wrong question for a flag: `--out` is a substring of
    /// `--outdir`, so a rename reads as still present. Require the match to end
    /// at something that cannot continue the token.
    fn names(hay: &str, needle: &str) -> bool {
        hay.match_indices(needle).any(|(at, _)| {
            hay[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric() && c != '-' && c != '_')
        })
    }

    /// The user-facing table is a second copy of the same judgement, and #386
    /// was visible in both. Whitespace is flattened first: prose wraps, and a
    /// guard defeated by a line break reports safety it does not provide. The
    /// remedy is looked for in the section that explains the refusal, not
    /// anywhere in the file -- `chm image build` appears in several places, so
    /// a whole-file search would stay green while the one paragraph a refused
    /// reader is sent to lost it.
    #[test]
    fn the_docs_table_does_not_send_a_reader_to_the_closed_dependency() {
        let doc = include_str!("../../docs/sandbox-spec.md");
        let flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        let stale = format!("{}153", "#");
        assert!(
            !flat.contains(&stale),
            "docs/sandbox-spec.md still cites {stale}, which shipped (#386)"
        );

        let heading = format!("### `image.{}` is refused on purpose", "oci");
        let at = doc
            .find(&heading)
            .unwrap_or_else(|| panic!("docs/sandbox-spec.md lost the section headed `{heading}`"));
        let rest = &doc[at + heading.len()..];
        let section = &rest[..rest.find("\n## ").unwrap_or(rest.len())];
        let flat_section = section.split_whitespace().collect::<Vec<_>>().join(" ");
        let remedy = format!("chm image {}", "build");
        assert!(
            flat_section.contains(&remedy),
            "the docs must name `{remedy}` where they explain the image.oci refusal, \
             or a reader is told no and given nowhere to go"
        );
    }

    // --- #155: guest ingress, named in the spec ---------------------------

    /// The load-bearing guard: a spec cannot open a door the flag could not.
    ///
    /// Everything `ingress` contributes to the command line must be
    /// `--expose <PORT>` pairs and nothing else. Asserting the pairs are
    /// *present* would not catch that -- an extra `--expose-host` token would
    /// sit alongside them and pass. So this diffs the argv against the same
    /// spec with no ingress and requires the difference to be exactly those
    /// tokens.
    #[test]
    fn ingress_can_add_nothing_to_the_argv_but_expose_pairs() {
        let base = spec_from(
            r#"{"specVersion":1,"image":{"kernel":"/k/Image"},
                "networkPolicy":{"enabled":true}}"#,
        );
        let with = spec_from(
            r#"{"specVersion":1,"image":{"kernel":"/k/Image"},
                "networkPolicy":{"enabled":true,"ingress":[
                    {"port":9222,"protocol":"tcp","description":"CDP"},
                    {"port":3000}]}}"#,
        );
        assert!(with.validate().is_empty(), "{:?}", with.validate());

        let a = resolve(Some(&base), None, &Overrides::default()).to_create_argv();
        let b = resolve(Some(&with), None, &Overrides::default()).to_create_argv();
        let added: Vec<String> = b.iter().filter(|t| !a.contains(t)).cloned().collect();
        assert_eq!(
            added,
            vec!["--expose", "9222", "--expose", "3000"],
            "ingress must reach the guest as --expose and nothing else; \
             anything more is a door the spec opened that the flag cannot"
        );
    }

    /// `port_number` is the one place a rule becomes a port.
    ///
    /// `validate` reports with it and `resolve` acts on it. A second reading of
    /// the same JSON would eventually disagree, and the disagreement would be a
    /// document that validated and then published a different port -- so this
    /// reads the production `resolve` and requires it to call the shared
    /// function rather than reach into `.port` itself.
    #[test]
    fn resolve_decides_a_port_only_where_validate_does() {
        let src = include_str!("spec.rs");
        let body = src
            .split_once("pub fn resolve(")
            .expect("resolve must exist to be checked")
            .1
            .split_once("\n}\n")
            .expect("resolve must end")
            .0;
        let shared = format!("{}{}()", "publishable", "_port");
        assert!(
            body.contains(&shared),
            "resolve must turn a rule into a port through `{shared}`, the same predicate \
             validate reports from, or the two can disagree about one document"
        );
    }

    /// Each refusal names the field it refuses, so a reader can find it.
    #[test]
    fn every_field_ingress_cannot_honour_is_refused_by_name() {
        for (json, needle) in [
            (r#"{"port":"3000-3010"}"#, "no range form"),
            (r#"{"port":8080,"host":"0.0.0.0"}"#, ".host"),
            (r#"{"port":8081,"allow":"10.0.0.0/8"}"#, ".allow"),
            (r#"{"port":8082,"deny":"0.0.0.0/0"}"#, ".deny"),
            (r#"{"port":8083,"protocol":"udp"}"#, ".protocol"),
            (r#"{"description":"none"}"#, "names no `port`"),
            (r#"{"port":0}"#, "choose one"),
            (r#"{"port":70000}"#, "is not a TCP port"),
        ] {
            let doc = spec_from(&format!(
                r#"{{"specVersion":1,"networkPolicy":{{"enabled":true,"ingress":[{json}]}}}}"#
            ));
            let problems = doc.validate();
            assert!(
                problems.iter().any(|p| p.contains(needle)),
                "`{json}` must be refused with `{needle}`, not dropped; got {problems:?}"
            );
            // And it must reach nothing.
            let argv = resolve(Some(&doc), None, &Overrides::default()).to_create_argv();
            assert!(
                !argv.join(" ").contains("--expose"),
                "`{json}` was refused, so it must publish no port; got {argv:?}"
            );
        }
    }

    /// A published port needs a NIC to arrive on, and `--expose` already
    /// refuses without `--net`. The spec must refuse the same combination
    /// rather than emit an argv the parser will reject later.
    #[test]
    fn ingress_without_a_network_device_is_refused() {
        let doc = spec_from(
            r#"{"specVersion":1,
                "networkPolicy":{"enabled":false,"ingress":[{"port":9222}]}}"#,
        );
        let problems = doc.validate();
        assert!(
            problems.iter().any(|p| p.contains("no NIC")),
            "ingress with the network off must be refused; got {problems:?}"
        );
    }

    /// The bind address is read, never restated. A refusal that named its own
    /// literal would keep saying `127.0.0.1` after the constant moved.
    ///
    /// This needs **two** guards and neither subsumes the other. The content
    /// check below cannot see a re-hardcoded literal, because the literal is
    /// what the constant currently renders to -- it would sail past a message
    /// that had frozen the address. The source check is what sees that, and it
    /// in turn cannot tell whether the interpolation reaches the sentence a
    /// user reads. Measured: mutating the interpolation to `127.0.0.1` leaves
    /// the content check green.
    #[test]
    fn the_host_refusal_names_the_address_the_bind_actually_uses() {
        let doc = spec_from(
            r#"{"specVersion":1,
                "networkPolicy":{"enabled":true,"ingress":[{"port":80,"host":"0.0.0.0"}]}}"#,
        );
        let problems = doc.validate();
        assert!(
            problems
                .iter()
                .any(|p| p.contains(&INGRESS_BIND_ADDR.to_string())),
            "the refusal must name {INGRESS_BIND_ADDR}, read from the constant the \
             listener binds; got {problems:?}"
        );

        // Scoped to `refusals`, because the constant's name appears elsewhere
        // in this file -- including in this test -- and a needle in more than
        // one place cannot detect its removal from the one that matters.
        let src = include_str!("spec.rs");
        let body = src
            .split_once("pub fn refusals(&self)")
            .expect("refusals must exist to be guarded")
            .1
            .split_once("\n    }\n")
            .expect("refusals must close")
            .0;
        let needle = format!("{{{}}}", "INGRESS_BIND_ADDR");
        assert!(
            body.contains(&needle),
            "the host refusal must interpolate the constant rather than restate \
             its value, or it will keep naming an address the listener no longer binds"
        );
    }

    /// The doc's refusal table and `refusals()` must name the same fields.
    ///
    /// The safe direction of drift is a doc that lists fewer refusals than the
    /// code makes. The dangerous one is the reverse: a table promising that
    /// `deny` is refused, over code that has quietly started accepting it,
    /// tells a reader they have a control they do not have -- the #179 shape,
    /// one layer up. So this reads the field names out of `refusals()` itself
    /// rather than holding a list of its own.
    #[test]
    fn the_doc_promises_exactly_the_refusals_the_code_makes() {
        let src = include_str!("spec.rs");
        let body = src
            .split_once("pub fn refusals(&self)")
            .expect("refusals() must exist")
            .1
            .split_once("\n    }\n")
            .expect("refusals() must close")
            .0;

        let doc = include_str!("../../docs/sandbox-spec.md");
        let section = doc
            .split_once("## `networkPolicy.ingress`")
            .expect("the spec doc must have an ingress section")
            .1
            .split_once("\n## ")
            .expect("the ingress section must end")
            .0;
        // Prose wraps, so a claim can be split across a newline and sail past a
        // substring search. Flatten before looking (see #288's doc guard).
        let flat = section.split_whitespace().collect::<Vec<_>>().join(" ");

        for field in ["host", "allow", "deny", "protocol"] {
            let refused_in_code = body.contains(&format!(".{field}: "));
            let named_in_doc = flat.contains(&format!("| `{field}"));
            assert_eq!(
                refused_in_code, named_in_doc,
                "`{field}`: refusals() refuses it = {refused_in_code}, the doc's table \
                 names it = {named_in_doc}. These must agree -- a doc promising a refusal \
                 the code no longer makes reports a control that is not there."
            );
        }
    }

    /// A port published twice is a property of the *list*, not of any one
    /// rule, so `refusals()` cannot see it and `validate` keeps it. Measured:
    /// deleting this refusal leaves every other ingress guard green, because
    /// each rule is individually perfect.
    #[test]
    fn a_port_named_twice_is_refused_once_by_name() {
        let doc = spec_from(
            r#"{"specVersion":1,"networkPolicy":{"enabled":true,
                "ingress":[{"port":8080},{"port":9222},{"port":8080}]}}"#,
        );
        let problems = doc.validate();
        assert_eq!(
            problems.len(),
            1,
            "one collision is one refusal, naming the second mention; got {problems:?}"
        );
        assert!(
            problems[0].contains("8080") && problems[0].contains("twice"),
            "the refusal must name the port and say it was published twice; got {problems:?}"
        );
        assert!(
            !problems[0].contains("9222"),
            "the port that is fine must not be implicated; got {problems:?}"
        );
    }

    /// Ingress is additive, so it costs no version bump -- an older build
    /// reading a document that names it is incomplete, never wrong.
    #[test]
    fn a_document_naming_ingress_still_parses_without_it() {
        let doc = spec_from(r#"{"specVersion":1,"networkPolicy":{"enabled":true}}"#);
        assert!(
            doc.network_policy
                .as_ref()
                .is_some_and(|n| n.ingress.is_empty()),
            "a policy that names no ingress publishes nothing"
        );
    }
}
