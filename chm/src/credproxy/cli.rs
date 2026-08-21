// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `chm proxy` — inspect, export, and smoke-test the credential proxy.
//!
//! Deliberately weighted towards *showing* rather than *doing*: the proxy runs
//! as part of a VM, and the useful commands here are the ones that let you see
//! what it would do before you trust it with a credential, and confirm it can
//! actually reach an origin from this machine.

use crate::oci::entry::EntryKind;
use crate::oci::initramfs::{Rootfs, write_cpio};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::{env, fs};

use hypervisor::hvf::virtio::nat::InterceptDecider;
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, version};

use crate::audit::AuditLog;

use super::ca::{CA_CERT_FILE, CA_KEY_FILE, ProxyCa};
use super::nat::RuleDecider;
use super::rules::{Destination, Disposition, RuleSet};
use super::server::{self, ProxyConfig};

/// Which authority supplied a piece of a run's configuration.
///
/// It matters because two subsystems now inform each other (V8.7: an injection
/// rule widens the egress allow-list), and a widening is only legitimate when
/// the same authority wrote both halves. A control plane hands its policy down
/// through the environment and stakes a digest on it; a file sitting in a
/// workspace directory must not be able to reopen a host that policy closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Authority {
    /// A CLI flag, or a file in the workspace — the operator at the keyboard.
    Local,
    /// An environment binding the runner set for a governed assignment.
    ControlPlane,
}

/// Where a rule set came from, so `show` can say so.
pub(crate) struct Resolved {
    pub(crate) rules: RuleSet,
    pub(crate) origin: String,
    pub(crate) authority: Authority,
}

/// Resolve the rule set the same way every other local policy resolves:
/// explicit flag, then environment, then the workspace file. Absent all three
/// there is no proxy — not an empty one — because interception must never be
/// something a run acquires by accident.
pub(crate) fn resolve_rules(
    workspace: Option<&Path>,
    cli_override: Option<&Path>,
) -> Result<Option<Resolved>, String> {
    let parse = |raw: &str, origin: String, authority: Authority| match RuleSet::parse(raw) {
        Ok(rules) => Ok(Some(Resolved {
            rules,
            origin,
            authority,
        })),
        Err(e) => Err(format!("{origin}: {e}")),
    };
    if let Some(path) = cli_override {
        let raw =
            fs::read_to_string(path).map_err(|e| format!("--rules {}: {e}", path.display()))?;
        return parse(
            &raw,
            format!("--rules {}", path.display()),
            Authority::Local,
        );
    }
    if let Ok(raw) = env::var("CHM_PROXY_RULES") {
        // Accept either a path or the document itself, because a launcher that
        // holds the rules in memory should not have to write them to disk.
        if let Ok(text) = fs::read_to_string(&raw) {
            return parse(
                &text,
                format!("CHM_PROXY_RULES={raw}"),
                Authority::ControlPlane,
            );
        }
        return parse(
            &raw,
            "CHM_PROXY_RULES".to_string(),
            Authority::ControlPlane,
        );
    }
    if let Some(ws) = workspace {
        let file = ws.join("proxy-rules.json");
        if let Ok(raw) = fs::read_to_string(&file) {
            return parse(&raw, file.display().to_string(), Authority::Local);
        }
    }
    Ok(None)
}

/// The directory the workspace CA lives in.
pub(crate) fn ca_dir(workspace: &Path) -> PathBuf {
    workspace.join("proxy-ca")
}

/// Copy an image's proxy CA into a workspace being created from it (#315).
///
/// A workspace shares its image's base read-only and diverges from there, so
/// the guest inside it is *the same guest*: if the image's rootfs was already
/// provisioned to trust a CA, a workspace that mints a fresh one presents a
/// certificate that guest will never accept. The failure surfaces as a generic
/// curl message naming nothing, while `chm` has just printed a banner saying
/// injection is ACTIVE — the two most visible facts contradict each other and
/// only one of them is reachable without reading this codebase.
///
/// Copied rather than symlinked. [`ProxyCa::load_or_create`] writes into this
/// directory (it tightens permissions, and mints the pair when either file is
/// missing), so a symlink would let a workspace mutate the image every other
/// workspace is sharing — the opposite of the read-only base contract the rest
/// of `workspace_from_image` keeps.
///
/// Returns whether there was anything to inherit. An image with no CA is the
/// ordinary case and not a problem: nothing in that guest trusts anything yet,
/// so a freshly minted workspace CA is the right answer.
pub(crate) fn inherit_ca(image_dir: &Path, ws_dir: &Path) -> Result<bool, String> {
    let from = ca_dir(image_dir);
    let (key, cert) = (from.join(CA_KEY_FILE), from.join(CA_CERT_FILE));
    // Both halves or neither. A cert without its key cannot sign a leaf, so
    // copying half a CA would replace a working mint-fresh path with a proxy
    // that fails at the first interception instead of at creation.
    if !key.exists() || !cert.exists() {
        return Ok(false);
    }
    let to = ca_dir(ws_dir);
    fs::create_dir_all(&to).map_err(|e| format!("create {}: {e}", to.display()))?;
    // Tightened here rather than left to the next `load_or_create`, which is
    // what the running proxy calls: between creating the workspace and starting
    // a VM in it, a 0755 directory holding a CA private key is readable by
    // anyone on the host, and a readable CA key impersonates every intercepted
    // host to the guest.
    let _ = fs::set_permissions(&to, fs::Permissions::from_mode(0o700));
    for (src, name) in [(&key, CA_KEY_FILE), (&cert, CA_CERT_FILE)] {
        let dst = to.join(name);
        fs::copy(src, &dst)
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
    }
    let _ = fs::set_permissions(to.join(CA_KEY_FILE), fs::Permissions::from_mode(0o600));
    Ok(true)
}

/// The image directory a workspace shares its base with, or `None` when this
/// does not look like a workspace created by `chm workspace`.
///
/// Recovered from the `state.json` symlink rather than recorded in a file of
/// our own: the symlink is what actually makes the workspace share that base,
/// so it cannot go stale relative to the thing it describes. A recorded origin
/// could disagree with where the base really is, and would then name the wrong
/// directory in exactly the diagnosis below.
pub(crate) fn base_image_dir(workspace: &Path) -> Option<PathBuf> {
    let target = fs::read_link(workspace.join("state.json")).ok()?;
    target.parent().map(Path::to_path_buf)
}

/// Why the CA this workspace presents is not the one its base image carries, or
/// `None` when they agree, when there is nothing to compare, or when this is
/// not a workspace at all.
///
/// [`inherit_ca`] means a workspace created by this build always agrees. This
/// exists for the ones that already exist: a workspace made by an earlier build
/// stays broken across the upgrade, and without this it stays broken *silently*,
/// which is the whole of what #315 cost.
///
/// Compares the certificate bytes, not fingerprint strings, so the comparison
/// cannot be defeated by a formatting change on either side.
pub(crate) fn inherited_ca_mismatch(workspace: &Path) -> Option<String> {
    let image = base_image_dir(workspace)?;
    let theirs = fs::read(ca_dir(&image).join(CA_CERT_FILE)).ok()?;
    let ours = fs::read(ca_dir(workspace).join(CA_CERT_FILE)).ok()?;
    if theirs == ours {
        return None;
    }
    // Stated as a conditional, because the host cannot read the guest's trust
    // store from here. A user who deliberately re-minted this workspace's CA
    // *and* reinstalled it in the guest is fine, and telling them their setup is
    // broken would be a false alarm. What is certain is which two things differ.
    Some(format!(
        "chm: [proxy] this workspace's CA is not the one its base image carries.\n\
         \x20 workspace {}\n\
         \x20 image     {}\n\
         \x20 If the guest's trust store came from that image, every intercepted\n\
         \x20 request will fail with a generic certificate error naming nothing.\n\
         \x20 Install this workspace's CA in the guest:\n\
         \x20     chm proxy ca --workspace {}",
        ca_dir(workspace).display(),
        ca_dir(&image).display(),
        workspace.display(),
    ))
}

/// A started proxy and the hook that routes flows to it. The proxy is returned
/// so the caller can keep it alive for the life of the VM.
pub(crate) type StartedProxy = (server::RunningProxy, Arc<dyn InterceptDecider>);

/// Start a proxy and build the NAT hook for it, or `None` when this run has no
/// rules. Returns the running proxy too, so the caller can keep it alive and
/// read its audit trail.
/// Start a proxy from rules the caller already resolved, and build the NAT hook
/// for it. Returns `None` when the rules would intercept nothing.
///
/// Callers resolve with [`resolve_rules`] first rather than passing a path here,
/// because the egress allow-list has to be widened (V8.7) *before* the NIC is
/// built, which happens before the proxy can start. Resolving twice would let a
/// rules file edited between the two reads produce a policy and a proxy that
/// disagree about which hosts exist, so there is deliberately no
/// resolve-and-start convenience wrapper.
pub(crate) fn start_resolved(
    workspace: &Path,
    resolved: &Resolved,
) -> Result<Option<StartedProxy>, String> {
    if resolved.rules.intercept_patterns().is_empty() {
        eprintln!(
            "chm: [proxy] {} has no injecting rules; no traffic will be intercepted",
            resolved.origin
        );
        return Ok(None);
    }
    let ca = ProxyCa::load_or_create(&ca_dir(workspace)).map_err(|e| format!("proxy CA: {e}"))?;
    let roots = server::load_roots().map_err(|e| format!("host trust store: {e}"))?;
    let patterns = resolved.rules.intercept_patterns();
    let proxy = server::start(ProxyConfig {
        rules: resolved.rules.clone(),
        ca: Arc::clone(&ca),
        roots,
        // The run's own trail, so a decision outlives the process that made it.
        audit: AuditLog::open(workspace),
    })
    .map_err(|e| format!("start proxy: {e}"))?;
    let decider = RuleDecider::for_proxy(resolved.rules.clone(), &proxy)
        .ok_or_else(|| "rules matched nothing to intercept".to_string())?;
    eprintln!(
        "chm: [proxy] credential injection ACTIVE for {} ({}) — CA {}",
        patterns.join(", "),
        resolved.origin,
        ca.fingerprint()
    );
    // Immediately after the banner, because the banner is the claim this
    // contradicts: it says injection is active and names a CA, and #315 was
    // exactly the case where that sentence was true and useless.
    if let Some(why) = inherited_ca_mismatch(workspace) {
        eprintln!("{why}");
    }
    Ok(Some((proxy, decider)))
}

pub(crate) fn proxy_main(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("show") => show(&args[1..]),
        Some("ca") => ca(&args[1..]),
        Some("check") => check(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("chm proxy: unknown command `{other}`\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
chm proxy — the credential-injecting egress proxy

USAGE:
    chm proxy show [WORKSPACE_DIR|--workspace DIR] [--rules FILE] [--json]
    chm proxy ca   <WORKSPACE_DIR|--workspace DIR> [--out FILE] [--for-guest]
    chm proxy check --host HOST [--port N] [--path P]
                    [--workspace DIR] [--rules FILE] [--control] [--json]

COMMANDS:
    show    What the rules would do, and whether each credential is available.
            Reads no credential values: an `exec` source is never run.
    ca      Print the workspace CA certificate, and how to install it in a guest.
    check   Prove this machine can reach a host through the proxy. Sends a real
            HEAD request; injects only if a rule matches. Use --path to choose
            an endpoint whose answer differs with and without a credential
            (e.g. --path /user on api.github.com) to prove injection worked.
            --control repeats the request with injection disabled and compares:
            if the two answers match, the run proved nothing and says so. A
            green tick that cannot fail is not evidence.

RULES are resolved from --rules, then CHM_PROXY_RULES (a path or the document
itself), then <WORKSPACE_DIR>/proxy-rules.json. With none of these, no traffic
is ever intercepted.
";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Flags that take a value, so an argument scan knows what to skip. Unknown
/// flags are refused rather than assumed to take one: assuming cost us a
/// confusing session, where `proxy show --workspace DIR` swallowed the
/// directory as an unknown flag's value and then reported "not configured" —
/// a wrong answer that looked like a correct one.
const VALUED: [&str; 5] = ["--rules", "--out", "--host", "--port", "--path"];
const VALUELESS: [&str; 3] = ["--json", "--control", "--workspace"];

/// The workspace directory, however the caller chose to say it.
///
/// `chm create` spells this `--workspace`, so accept that spelling here too.
/// One concept with two spellings across sibling subcommands is a papercut
/// that only ever shows up mid-task.
fn workspace_arg(args: &[String]) -> Option<&str> {
    flag(args, "--workspace").or_else(|| positional(args))
}

/// The workspace `chm proxy check` will read its rules from.
///
/// `--workspace` only, unlike `show`, which also takes the directory as a
/// positional. Every argument to `check` is a flag with a value, so a bare
/// path there is far more likely to be a misplaced value than an intended
/// workspace, and silently adopting it would be the same class of mistake as
/// #317 itself: acting confidently on an argument the user did not mean.
///
/// Split out so the resolution can be tested without opening a socket --
/// `check` itself sends a real request, which is exactly why the bug survived.
fn check_workspace(args: &[String]) -> Option<PathBuf> {
    flag(args, "--workspace").map(PathBuf::from)
}

/// Reject flags this command does not know, naming the offender.
/// What each subcommand accepts, named once.
///
/// These were inline literals at the call site and duplicated again in the
/// tests, and that is exactly how `--for-guest` came to be implemented,
/// documented in the banner `chm proxy ca` prints, and refused by the parser
/// as unknown — the handler was unreachable. `usage_promises_only_flags_the_parser_accepts`
/// now holds them to the help text.
const SHOW_FLAGS: &[&str] = &["--rules", "--json", "--workspace"];
const CA_FLAGS: &[&str] = &["--out", "--workspace", "--for-guest"];
const CHECK_FLAGS: &[&str] = &[
    "--host",
    "--port",
    "--path",
    "--rules",
    "--workspace",
    "--control",
    "--json",
];

/// What one subcommand accepts, looked up rather than listed at the call site.
///
/// #317 was a subcommand with *no* allow-list at all: `check` never called
/// `reject_unknown`, so `--workspace` was consumed and dropped and the command
/// still printed a confident verdict. A table keyed by name lets the guard
/// below ask "does every subcommand USAGE documents have one of these?", which
/// is the question that catches a missing list rather than a wrong one.
fn flags_for(cmd: &str) -> Option<&'static [&'static str]> {
    match cmd {
        "show" => Some(SHOW_FLAGS),
        "ca" => Some(CA_FLAGS),
        "check" => Some(CHECK_FLAGS),
        _ => None,
    }
}

/// The remedy `chm proxy ca` prints beside the certificate.
///
/// A const rather than an inline `eprintln!` because it is a *third* place the
/// same promise is made — after `USAGE` and the parser's allow-list — and the
/// two that were already in the code disagreed. A guard that reads only the
/// help text cannot see a hint hardcoded at the point of use; it stays green
/// while the sentence the user actually reads sends them at a flag that does
/// not work.
const CA_GUEST_HINT: &str = "\
`chm proxy ca <WORKSPACE_DIR> --for-guest` prints an installer to
paste into the guest console.";

fn reject_unknown(cmd: &str, args: &[String]) -> Result<(), ExitCode> {
    if let Some(a) = first_unknown_flag(cmd, args) {
        eprintln!("chm proxy {cmd}: unknown flag `{a}`\n\n{USAGE}");
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

/// The first flag `cmd` does not accept, if any.
///
/// An unregistered subcommand gets an empty allow-list, so it refuses
/// *everything* rather than accepting everything. #317 was the permissive
/// version of that mistake: a command with no list took every flag it was
/// handed and still printed a verdict. Failing closed turns the same omission
/// into a command that visibly does not work.
fn first_unknown_flag<'a>(cmd: &str, args: &'a [String]) -> Option<&'a str> {
    let known = flags_for(cmd).unwrap_or(&[]);
    args.iter()
        .map(String::as_str)
        .find(|a| a.starts_with("--") && !known.contains(a))
}

fn positional(args: &[String]) -> Option<&str> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            // `--workspace` is listed as valueless here on purpose: its value
            // is exactly the positional we are looking for, so letting the
            // scan see it is what makes both spellings resolve alike.
            skip = VALUED.contains(&a.as_str()) || !VALUELESS.contains(&a.as_str());
            continue;
        }
        return Some(a);
    }
    None
}

fn show(args: &[String]) -> ExitCode {
    if let Err(e) = reject_unknown("show", args) {
        return e;
    }
    let workspace = workspace_arg(args).map(PathBuf::from);
    let over = flag(args, "--rules").map(PathBuf::from);
    let resolved = match resolve_rules(workspace.as_deref(), over.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("chm proxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    let json = args.iter().any(|a| a == "--json");
    let Some(resolved) = resolved else {
        if json {
            println!(r#"{{"configured":false,"rules":[]}}"#);
        } else {
            println!("credential proxy: not configured — no traffic is intercepted");
            println!("  looked for: --rules, CHM_PROXY_RULES, <workspace>/proxy-rules.json");
        }
        return ExitCode::SUCCESS;
    };

    if json {
        println!("{}", render_show_json(&resolved));
        return ExitCode::SUCCESS;
    }

    match &resolved.rules.label {
        Some(l) => println!("credential proxy: {l} (from {})", resolved.origin),
        None => println!("credential proxy: configured from {}", resolved.origin),
    }
    if resolved.rules.rules.is_empty() {
        println!("  (no injecting rules — nothing is intercepted)");
    }
    for r in &resolved.rules.rules {
        let hosts: Vec<String> = r.hosts.iter().map(ToString::to_string).collect();
        println!("  {} → {}", r.name, hosts.join(", "));
        println!(
            "      injects {} from {} [{}]",
            r.header,
            r.secret.describe(),
            r.secret.availability().as_str()
        );
    }
    if !resolved.rules.passthrough.is_empty() {
        let p: Vec<String> = resolved
            .rules
            .passthrough
            .iter()
            .map(ToString::to_string)
            .collect();
        println!("  never intercepted: {}", p.join(", "));
    }
    println!("\nEverything not listed above is relayed end-to-end; the proxy cannot read it.");
    ExitCode::SUCCESS
}

/// The `show --json` body.
///
/// **Reads no credential value.** `availability()` reports only whether a
/// source resolves; an `exec` source is never run. That is what lets the whole
/// rule set be displayed in a UI without a secret ever reaching it.
pub(crate) fn render_show_json(resolved: &Resolved) -> String {
    let rules: Vec<String> = resolved
        .rules
        .rules
        .iter()
        .map(|r| {
            format!(
                r#"{{"name":{},"hosts":{},"header":{},"source":{},"credential":"{}"}}"#,
                quote(&r.name),
                quote(
                    &r.hosts
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                quote(&r.header),
                quote(&r.secret.describe()),
                r.secret.availability().as_str()
            )
        })
        .collect();
    // `passthrough` and `label` are carried here as well as in the text form.
    // The passthrough list is not decoration: it is the other half of the
    // interception story, and a UI that showed only the injecting rules would
    // imply everything else is intercepted when the opposite is true.
    let passthrough: Vec<String> = resolved
        .rules
        .passthrough
        .iter()
        .map(|p| quote(&p.to_string()))
        .collect();
    format!(
        r#"{{"configured":true,"origin":{},"label":{},"rules":[{}],"passthrough":[{}]}}"#,
        quote(&resolved.origin),
        resolved
            .rules
            .label
            .as_deref()
            .map_or_else(|| "null".to_string(), quote),
        rules.join(","),
        passthrough.join(",")
    )
}

/// The `show --json` body **as the daemon sees it**, for `chm ctl proxy`.
///
/// Credential availability resolves from `env::var` in the calling process, so
/// a rule reads `missing` in one process and `present` in another. `chm serve`
/// is the process that actually injects, so its answer is the only one that
/// describes what the guest will experience.
///
/// Measured: with a token in the daemon's environment and not the app's, the
/// app reported `missing` for a rule the daemon reported `present`. The
/// dangerous inverse is identical in shape — a token in the app's environment
/// and not the daemon's shows green while every request leaves unauthenticated.
pub(crate) fn show_json_for_daemon(workspace: &Path) -> String {
    match resolve_rules(Some(workspace), None) {
        Ok(Some(resolved)) => render_show_json(&resolved),
        Ok(None) => r#"{"configured":false,"rules":[]}"#.to_string(),
        Err(e) => format!(r#"{{"configured":false,"rules":[],"error":{}}}"#, quote(&e)),
    }
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
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

fn ca(args: &[String]) -> ExitCode {
    if let Err(e) = reject_unknown("ca", args) {
        return e;
    }
    let Some(ws) = workspace_arg(args) else {
        eprintln!("chm proxy ca: a workspace directory is required\n\n{USAGE}");
        return ExitCode::FAILURE;
    };
    let ca = match ProxyCa::load_or_create(&ca_dir(Path::new(ws))) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chm proxy ca: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pem = ca.cert_pem();
    if let Some(out) = flag(args, "--out") {
        if let Err(e) = fs::write(out, &pem) {
            eprintln!("chm proxy ca: write {out}: {e}");
            return ExitCode::FAILURE;
        }
        eprintln!("chm proxy ca: wrote {out} (sha256 {})", ca.fingerprint());
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--for-guest") {
        // A single self-contained block, because the way this actually gets into
        // a guest is a paste into the serial console — there is no shared
        // filesystem to copy it through, by design.
        print!("{}", guest_install_script(&pem, &ca.fingerprint()));
        return ExitCode::SUCCESS;
    }
    eprintln!("# sha256 {}", ca.fingerprint());
    for line in CA_GUEST_HINT.lines() {
        eprintln!("# {line}");
    }
    print!("{pem}");
    ExitCode::SUCCESS
}

/// The CA the *running* proxy would actually sign with, as JSON, for the daemon.
///
/// Deliberately read-only: [`ProxyCa::load_or_create`] would mint a trust anchor
/// if none existed, and a process answering a question about someone else's
/// workspace has no business creating one there. Absent is reported as absent.
///
/// This exists because the fingerprint is only useful if it is the one the guest
/// will meet. Measured: a caller resolving the library root got
/// `898b834b…` while the running guest's proxy signed with `79f85a28…` — install
/// the former and the guest trusts a CA nothing uses, so every intercepted
/// connection fails a certificate check *after* the installer reported success.
pub(crate) fn ca_json_for_daemon(workspace: &Path) -> String {
    let dir = ca_dir(workspace);
    match ProxyCa::load_existing(&dir) {
        Ok(Some(ca)) => {
            let pem = ca.cert_pem();
            let script = guest_install_script(&pem, &ca.fingerprint());
            let lines: Vec<String> = guest_install_transfer(&script)
                .iter()
                .map(|l| quote(l))
                .collect();
            format!(
                "{{\"present\":true,\"sha256\":{},\"pem\":{},\"installer\":{},\
                 \"install_lines\":[{}]}}",
                quote(&ca.fingerprint()),
                quote(&pem),
                quote(&script),
                lines.join(",")
            )
        }
        // Not an error: the CA is minted when a proxy first runs, so before the
        // first intercepted connection there is genuinely nothing to install.
        Ok(None) => "{\"present\":false}".to_string(),
        Err(e) => format!("{{\"present\":false,\"error\":{}}}", quote(&e.to_string())),
    }
}

/// The shell block that installs this CA in a Debian/Ubuntu guest and proves it
/// took.
///
/// The proof has to be that the *trust store* accepts the certificate, not that
/// the file we just wrote contains the certificate we just wrote. An earlier
/// version checked the latter and reported success on a guest where
/// `update-ca-certificates` segfaulted and the CA never landed — measured on a
/// rehydrated Graviton capture, where afterwards `/etc/ssl/certs` held no link
/// to it and the bundle did not contain its subject. A check that cannot fail
/// is not evidence, and here it would have sent the reader looking for the bug
/// in the proxy.
///
/// `openssl verify -CApath` is the check because it asks the question the guest
/// will actually ask: does this certificate chain to something the store
/// trusts? For a self-signed CA that is exactly "is it installed".
fn guest_install_script(pem: &str, fingerprint: &str) -> String {
    format!(
        "set -e\n\
         # Root already, or borrow authority only if it is actually available.\n\
         # A container rootfs has no sudo and needs none: its init runs as root,\n\
         # and hardcoding `sudo` made every line of this script fail there.\n\
         if [ \"$(id -u)\" = 0 ]; then S=; elif command -v sudo >/dev/null 2>&1; then S=sudo; else\n\
         \x20 echo 'NOT INSTALLED: not root and no sudo.'; exit 1\n\
         fi\n\
         # The copy that always exists, wherever this guest keeps its trust store.\n\
         $S mkdir -p /etc/gimbal\n\
         $S tee {CA_PATH} >/dev/null <<'GIMBAL_CA_EOF'\n\
         {pem}GIMBAL_CA_EOF\n\
         CRT={CA_PATH}\n\
         # --- the OS trust store, for anything using it (curl, git, apt) -------\n\
         SYS=skipped\n\
         if [ -d /usr/local/share/ca-certificates ] || $S mkdir -p /usr/local/share/ca-certificates 2>/dev/null; then\n\
         \x20 $S cp \"$CRT\" /usr/local/share/ca-certificates/gimbal-proxy.crt\n\
         \x20 $S update-ca-certificates >/dev/null 2>&1 || true\n\
         \x20 if command -v openssl >/dev/null 2>&1; then\n\
         \x20   if ! openssl verify -CApath /etc/ssl/certs \"$CRT\" >/dev/null 2>&1; then\n\
         \x20     # update-ca-certificates is absent or did not take. Do by hand\n\
         \x20     # what it would have done, so a broken helper does not cost us\n\
         \x20     # the install.\n\
         \x20     H=$(openssl x509 -hash -noout -in \"$CRT\") \\\n\
         \x20       && $S cp \"$CRT\" /etc/ssl/certs/gimbal-proxy.pem \\\n\
         \x20       && $S ln -sf gimbal-proxy.pem \"/etc/ssl/certs/$H.0\" || true\n\
         \x20   fi\n\
         \x20   if openssl verify -CApath /etc/ssl/certs \"$CRT\" >/dev/null 2>&1; then\n\
         \x20     SYS=trusted\n\
         \x20   else SYS='NOT TRUSTED'; fi\n\
         \x20 else SYS='installed, unverified (no openssl here)'; fi\n\
         fi\n\
         # --- Node, which does not consult the OS trust store at all ----------\n\
         # Measured, not assumed: with the CA verified in the system store,\n\
         # `node` still failed SELF_SIGNED_CERT_IN_CHAIN against an intercepted\n\
         # host, and the same request succeeded with NODE_EXTRA_CA_CERTS set.\n\
         # A coding agent is a Node program, so leaving this out ships a guest\n\
         # where curl works and the agent does not.\n\
         printf 'export NODE_EXTRA_CA_CERTS=%s\\n' \"$CRT\" | $S tee {ENV_PATH} >/dev/null\n\
         $S mkdir -p /etc/profile.d \\\n\
         \x20 && $S cp {ENV_PATH} /etc/profile.d/gimbal-proxy-ca.sh 2>/dev/null || true\n\
         . {ENV_PATH}\n\
         NODE=skipped\n\
         if command -v node >/dev/null 2>&1; then\n\
         \x20 # Node ignores an unreadable or unparseable NODE_EXTRA_CA_CERTS\n\
         \x20 # *silently*, so the useful check is that node itself can read and\n\
         \x20 # parse this exact file — the failure this catches has no symptom.\n\
         \x20 if node -e 'new (require(\"crypto\").X509Certificate)(require(\"fs\").readFileSync(process.env.NODE_EXTRA_CA_CERTS))' 2>/dev/null; then\n\
         \x20   NODE=configured\n\
         \x20 else NODE='NOT LOADED: node cannot parse the CA file'; fi\n\
         fi\n\
         echo \"system store: $SYS\"\n\
         echo \"node:         $NODE ($CRT)\"\n\
         GOT=$(openssl x509 -noout -fingerprint -sha256 -in \"$CRT\" 2>/dev/null \\\n\
         \x20 | tr -d ':' | tr 'A-Z' 'a-z' | sed 's/.*=//')\n\
         echo \"installed:    ${{GOT:-<no openssl here to read it back>}}\"\n\
         echo \"expected:     {fingerprint}\"\n\
         # A script cannot export into the shell that ran it. Saying otherwise\n\
         # was measured false: `node` still failed SELF_SIGNED_CERT_IN_CHAIN\n\
         # after a run that reported the variable set -- because it was set in\n\
         # this script's shell and nowhere else. And /etc/profile.d is only read\n\
         # by *login* shells, which a container guest's `/bin/sh` is not.\n\
         echo \"this shell:   . {ENV_PATH}\"\n\
         echo \"              (already done if you sourced this script)\"\n",
    )
}

/// Where the CA lands in the guest.
///
/// A fixed path outside the distribution's own trust-store layout, because it
/// has two readers with different needs: `update-ca-certificates` wants its
/// source under `/usr/local/share/ca-certificates`, and `NODE_EXTRA_CA_CERTS`
/// wants a stable file that exists whether or not this guest has a trust store
/// at all. A container rootfs has neither the directory nor the tool.
pub(crate) const CA_PATH: &str = "/etc/gimbal/proxy-ca.crt";

/// A one-line file that a shell can source to pick the CA up.
///
/// Necessary because `export` in a script reaches that script's shell and no
/// other, so the delivery path this repo already uses -- decode, then
/// `sh /tmp/gimbal-ca.sh` -- cannot configure the console it was typed into.
/// Measured: an installer reporting the variable set, in a guest where the next
/// `node` still failed `SELF_SIGNED_CERT_IN_CHAIN`.
pub(crate) const ENV_PATH: &str = "/etc/gimbal/proxy-ca.env";

/// A cpio archive carrying just the CA, for `create` to append to a container
/// image's initramfs.
///
/// The image's initramfs is written once, at `chm image build`, and knows
/// nothing about a workspace. The CA is per-workspace and is generated on
/// demand. The kernel unpacks concatenated archives in order, so the two facts
/// meet without either having to know the other's timing -- the same property
/// the bundled kernel modules already rely on.
///
/// Returns `None` when the workspace has no CA. That is not an error: a run
/// with no `--proxy-rules` is the ordinary case, and a guest that gets no CA
/// is exactly right for it.
/// Unlike [`ca_json_for_daemon`], this one *mints* a CA when none exists yet.
///
/// The distinction is who is asking. That function answers a question about
/// someone else's workspace and has no business creating a trust anchor there.
/// This one runs on the way to starting a proxy in this workspace, and that
/// proxy calls [`ProxyCa::load_or_create`] itself a few hundred lines later --
/// so the CA is coming into existence either way, and the only question is
/// whether the guest is built early enough to know about it.
///
/// Reading rather than creating here looked correct and was measured wrong: a
/// fresh workspace has no CA at initramfs-build time, so the guest shipped
/// without one and the proxy then minted it moments later. The first run of
/// every new workspace would have silently had no CA, and only the *second*
/// would have worked -- the worst shape of bug, because it looks fixed.
pub(crate) fn ca_cpio_for(workspace: &Path) -> Result<Option<Vec<u8>>, String> {
    let ca = ProxyCa::load_or_create(&ca_dir(workspace)).map_err(|e| format!("proxy CA: {e}"))?;
    Ok(Some(ca_cpio_from_pem(&ca.cert_pem())))
}

/// The archive itself, split out so a test can build one without a CA on disk.
///
/// Parent directories are materialized deliberately. A cpio entry whose parent
/// has no entry of its own is dropped by the kernel *in silence* -- measured in
/// #222, where five modules were in the archive and none reached the guest --
/// so `/etc` and `/etc/gimbal` must be present as entries, not merely implied.
pub(crate) fn ca_cpio_from_pem(pem: &str) -> Vec<u8> {
    let mut rootfs = Rootfs::default();
    // Relative, as cpio paths are: a leading slash would create an entry the
    // kernel resolves against nothing.
    let path = CA_PATH.trim_start_matches('/').to_string();
    rootfs.insert(
        path,
        EntryKind::File {
            mode: 0o644,
            size: pem.len() as u64,
        },
        pem.as_bytes().to_vec(),
    );
    rootfs.materialize_parents();
    write_cpio(&rootfs)
}

/// Where the base64 of the installer lands in the guest while it is being typed.
const TRANSFER_B64: &str = "/tmp/gimbal-ca.b64";
/// And where it is decoded before it runs.
const TRANSFER_SH: &str = "/tmp/gimbal-ca.sh";

/// The exact console lines that carry `script` into a guest, and the guest-side
/// check that it arrived intact.
///
/// **Typing a multi-line script at a serial console does not work, and the way
/// it fails is easy to miss.** Measured on a rehydrated Graviton guest with the
/// obvious approach — one line at a time, 60 ms apart: `update-ca-certificates`
/// takes seconds, so the four verification lines behind it sat in the tty input
/// queue, were echoed, and **never ran**. The console showed the script's own
/// text where its output should have been, and the panel reported the script
/// sent — which it was.
///
/// A fixed delay cannot fix this, because the delay would have to be as long as
/// the slowest command in the script and nothing knows what that is.
///
/// So the script crosses as base64 in short appends. Every line but the last is
/// a `printf` that completes in microseconds, so nothing is ever typed at a
/// shell that is busy; the one slow line is last and has nothing behind it. The
/// guest then hashes what it received and compares it with the digest computed
/// here **before running any of it**, so a dropped character becomes a named
/// failure at transfer time (`TRANSFER CORRUPT`) instead of a corrupt
/// certificate that surfaces much later as an unexplained TLS error.
///
/// That digest also settled a question the console could not: captured lines
/// come back with their leading characters missing (`<…AAA' >> /tmp/…`), which
/// looks exactly like dropped input. On the run that installed successfully the
/// digest matched, so every chunk had in fact arrived byte-perfect and the
/// truncation is console rendering, not loss. The check is what makes that
/// distinguishable at all.
///
/// Decoding to a file rather than piping into `bash` keeps the shell's stdin on
/// the tty, so `sudo` can still prompt, and confines `set -e` to the installer
/// instead of leaving it armed in the user's interactive shell.
pub(crate) fn guest_install_transfer(script: &str) -> Vec<String> {
    // Short enough that a whole line is well inside any plausible terminal
    // input limit, long enough that a ~1.6 KB payload is ~10 lines.
    const CHUNK: usize = 160;
    let b64 = base64_encode(script.as_bytes());
    let digest: String = digest(&SHA256, b64.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let mut lines = vec![format!("rm -f {TRANSFER_B64} {TRANSFER_SH}")];
    for chunk in b64.as_bytes().chunks(CHUNK) {
        // Safe unquoted-by-construction: base64's alphabet is A-Za-z0-9+/= and
        // contains no single quote or shell metacharacter, so single-quoting
        // needs no escaping. Asserted by a test rather than left to the reader.
        let part = String::from_utf8_lossy(chunk);
        lines.push(format!("printf %s '{part}' >> {TRANSFER_B64}"));
    }
    lines.push(format!(
        "CS=$(sha256sum {TRANSFER_B64} | cut -d' ' -f1); \
         if [ \"$CS\" = \"{digest}\" ]; then \
         base64 -d {TRANSFER_B64} > {TRANSFER_SH} && bash {TRANSFER_SH}; \
         else echo \"TRANSFER CORRUPT: the console dropped characters (got $CS)\"; fi"
    ));
    lines
}

/// Standard base64, because the guest decodes it with `base64 -d`.
fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b0 = u32::from(group[0]);
        let b1 = group.get(1).map_or(0, |b| u32::from(*b));
        let b2 = group.get(2).map_or(0, |b| u32::from(*b));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(A[((n >> 18) & 63) as usize]));
        out.push(char::from(A[((n >> 12) & 63) as usize]));
        out.push(if group.len() > 1 {
            char::from(A[((n >> 6) & 63) as usize])
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            char::from(A[(n & 63) as usize])
        } else {
            '='
        });
    }
    out
}

/// Everything `chm proxy check` decides before it opens a socket.
#[derive(Debug)]
struct CheckPlan<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
    json: bool,
    want_control: bool,
    over: Option<PathBuf>,
    workspace: Option<PathBuf>,
}

/// Read `check`'s arguments, or say why they cannot be read.
///
/// Split out from `check` so the decisions are reachable from a test.
/// #317 lived here: `workspace` was hardcoded to `None`, so `--workspace DIR`
/// was accepted, dropped, and answered as "no rule matched" -- a legitimate
/// outcome, indistinguishable from a dropped flag. It survived because the
/// only way to observe it was to run the command, and running the command
/// sends a real request to a real host.
fn plan_check(args: &[String]) -> Result<CheckPlan<'_>, String> {
    if let Some(f) = first_unknown_flag("check", args) {
        return Err(format!("unknown flag `{f}`"));
    }
    let host = flag(args, "--host").ok_or("--host is required")?;
    Ok(CheckPlan {
        host,
        port: flag(args, "--port")
            .and_then(|p| p.parse().ok())
            .unwrap_or(443),
        path: flag(args, "--path").unwrap_or("/"),
        json: args.iter().any(|a| a == "--json"),
        want_control: args.iter().any(|a| a == "--control"),
        over: flag(args, "--rules").map(PathBuf::from),
        workspace: check_workspace(args),
    })
}

fn check(args: &[String]) -> ExitCode {
    let plan = match plan_check(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("chm proxy check: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let CheckPlan {
        host,
        port,
        path,
        json,
        want_control,
        over,
        workspace,
    } = plan;

    let outcome = match run_check(
        workspace.as_deref(),
        over.as_deref(),
        host,
        port,
        path,
        want_control,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("chm proxy check: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Outcome {
        addr,
        disposition,
        intercepted,
        status,
        audit,
        control,
    } = outcome;
    let disposition = disposition.as_str();

    if json {
        return check_json(&CheckReport {
            host,
            port,
            path,
            addr,
            disposition,
            intercepted,
            status: &status,
            audit: &audit,
            control: control.as_ref(),
        });
    }

    println!("{host}:{port}{path} → {addr}");
    println!("  disposition: {disposition}");

    match &status {
        Ok(probe) => {
            println!("  origin said: {}", probe.status);
            // On a relayed flow this handshake reached the origin itself. On an
            // intercepted one it terminated on us, so it is the version the
            // *guest* sees; the upstream leg is reported in the audit below.
            let leg = if intercepted {
                "guest tls: "
            } else {
                "origin tls:"
            };
            println!("  {leg}  {}", probe.tls_version);
            println!("  reachable:   yes");
            for ev in audit {
                println!(
                    "  audit:       {} {} {}{}",
                    ev.destination,
                    ev.rule.as_deref().unwrap_or("-"),
                    ev.detail,
                    if ev.injected { " [injected]" } else { "" }
                );
            }
            if let Some(control) = &control {
                print_control(control, &probe.status);
            } else if want_control {
                println!("  control:     skipped — nothing is injected for this host,");
                println!("               so a control run would be the same run.");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("  reachable:   NO — {e}");
            ExitCode::FAILURE
        }
    }
}

/// The result of the same request sent with injection disabled.
struct Control {
    status: Result<String, String>,
}

/// Send the request again end-to-end with an empty rule set, so nothing is
/// injected.
///
/// This exists because **a green tick that cannot fail is not evidence.**
/// `check` on its own proves the host is reachable; it does not prove the
/// credential did anything, and against an endpoint that answers the same way
/// either way it never could. Running the identical request with injection off
/// and comparing is the only thing that distinguishes "injection worked" from
/// "this endpoint does not care".
fn control_probe(
    ca: &Arc<ProxyCa>,
    roots: &Arc<RootCertStore>,
    addr: SocketAddr,
    host: &str,
    path: &str,
) -> Control {
    let proxy = match server::start(ProxyConfig {
        rules: RuleSet::default(),
        ca: Arc::clone(ca),
        roots: Arc::clone(roots),
        // Disabled on purpose. This proxy exists to answer a question the
        // operator asked; recording it would put traffic in the sandbox's
        // trail that the sandbox never generated.
        audit: AuditLog::default(),
    }) {
        Ok(p) => p,
        Err(e) => {
            return Control {
                status: Err(format!("control proxy: {e}")),
            };
        }
    };
    let status = probe(&proxy, ca, addr, host, path, false).map(|p| p.status);
    proxy.stop();
    Control { status }
}

/// What the control run actually established.
///
/// One source of truth for both the text and JSON forms, because these two
/// renderings disagreeing about whether a credential arrived is exactly the
/// class of bug this command exists to catch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The two runs differed, so the credential demonstrably reached the origin.
    ProvesInjection { without: String },
    /// The origin answered identically either way — the run is not evidence.
    ProvesNothing { status: String },
    /// The control could not be run.
    Failed(String),
}

/// Decide what a control run proved.
///
/// The negative case is the point. Against an endpoint that answers the same
/// with and without a credential, `check` is green no matter what the proxy
/// does — including if injection were entirely broken. Saying so is more useful
/// than a tick.
pub(crate) fn verdict(injected_status: &str, control: &Result<String, String>) -> Verdict {
    match control {
        Ok(without) if without == injected_status => Verdict::ProvesNothing {
            status: without.clone(),
        },
        Ok(without) => Verdict::ProvesInjection {
            without: without.clone(),
        },
        Err(e) => Verdict::Failed(e.clone()),
    }
}

/// Report the control, and say plainly when the comparison proved nothing.
fn print_control(control: &Control, injected_status: &str) {
    match verdict(injected_status, &control.status) {
        Verdict::ProvesNothing { status } => {
            println!("  control:     {status} — SAME as with the credential.");
            println!("               This run is not evidence: the endpoint answers");
            println!("               identically either way. Pick a --path whose answer");
            println!("               depends on the credential (e.g. /user on");
            println!("               api.github.com).");
        }
        Verdict::ProvesInjection { without } => {
            println!("  control:     {without} (without the credential)");
            println!("               differs from {injected_status} — injection changed");
            println!("               the origin's answer, so the credential arrived.");
        }
        Verdict::Failed(e) => println!("  control:     could not run — {e}"),
    }
}

/// Everything `check` learned, for the JSON form.
/// Everything one `check` run observed, before it is rendered.
///
/// Extracted so the text form, the JSON form and the daemon verb all describe
/// the *same* run. Two renderers disagreeing about whether a credential arrived
/// is precisely the class of bug this command exists to catch.
pub(crate) struct Outcome {
    addr: SocketAddr,
    disposition: String,
    intercepted: bool,
    status: Result<Probe, String>,
    audit: Vec<server::AuditEvent>,
    control: Option<Control>,
}

/// Perform one check: resolve rules, stand up a proxy, make the request, and
/// optionally repeat it with injection disabled.
fn run_check(
    workspace: Option<&Path>,
    over: Option<&Path>,
    host: &str,
    port: u16,
    path: &str,
    want_control: bool,
) -> Result<Outcome, String> {
    let rules = match resolve_rules(workspace, over)? {
        Some(r) => r.rules,
        None => RuleSet::default(),
    };

    let addr = resolve_one(host, port).ok_or_else(|| format!("cannot resolve {host}"))?;
    let dest = Destination::new(Some(host.to_string()), Some(addr.ip()), port);
    let disposition = match rules.decide(&dest) {
        Disposition::Inject(rule) => format!("INJECT {} ({})", rule.header, rule.name),
        Disposition::PassThrough(reason) => format!("PASS-THROUGH ({})", reason.as_str()),
    };
    let intercepted = matches!(rules.decide(&dest), Disposition::Inject(_));

    let ca = ProxyCa::ephemeral().map_err(|e| format!("ca: {e}"))?;
    let roots = server::load_roots().map_err(|e| format!("host trust store: {e}"))?;
    let proxy = server::start(ProxyConfig {
        rules,
        ca: Arc::clone(&ca),
        roots: Arc::clone(&roots),
        // See `control_probe`: a check is the operator's traffic, not the
        // guest's, and must not appear in the guest's audit trail.
        audit: AuditLog::default(),
    })
    .map_err(|e| format!("start: {e}"))?;

    let status = probe(&proxy, &ca, addr, host, path, intercepted);
    let audit = proxy.audit.recent();
    proxy.stop();

    // The control: the same request with nothing injected. Only meaningful on
    // an intercepted flow — on a relayed one the two runs are the same run.
    let control = if want_control && intercepted {
        Some(control_probe(&ca, &roots, addr, host, path))
    } else {
        None
    };

    Ok(Outcome {
        addr,
        disposition,
        intercepted,
        status,
        audit,
        control,
    })
}

/// Run a check **in the daemon's process** and render it as JSON, for
/// `chm ctl proxy-check`.
///
/// Third place the same provenance trap appears. A credential source resolves
/// from `env::var` in the process that runs the check, and the rule file is
/// found relative to the workspace that process was told about — so a check run
/// by the app can neither see the daemon's rules nor read its secrets, and
/// truthfully reports "no rule matches, relayed end-to-end". Correct, and
/// useless: it can never exercise the injection it exists to test.
pub(crate) fn check_json_for_daemon(
    workspace: &Path,
    host: &str,
    port: u16,
    path: &str,
) -> String {
    match run_check(Some(workspace), None, host, port, path, true) {
        Ok(o) => render_check_json(&CheckReport {
            host,
            port,
            path,
            addr: o.addr,
            disposition: &o.disposition,
            intercepted: o.intercepted,
            status: &o.status,
            audit: &o.audit,
            control: o.control.as_ref(),
        }),
        Err(e) => format!(r#"{{"reachable":false,"error":{}}}"#, quote(&e)),
    }
}

struct CheckReport<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
    addr: SocketAddr,
    disposition: &'a str,
    intercepted: bool,
    status: &'a Result<Probe, String>,
    audit: &'a [super::server::AuditEvent],
    control: Option<&'a Control>,
}

fn check_json(r: &CheckReport) -> ExitCode {
    println!("{}", render_check_json(r));
    // Unreachable is a failure exit even in JSON mode, so a script can branch
    // on `$?` without parsing.
    if r.status.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The `check --json` body.
fn render_check_json(r: &CheckReport) -> String {
    let (reachable, origin_status, tls, error) = match r.status {
        Ok(p) => (true, quote(&p.status), quote(&p.tls_version), "null".into()),
        Err(e) => (false, "null".into(), "null".into(), quote(e)),
    };
    let events: Vec<String> = r
        .audit
        .iter()
        .map(|ev| {
            format!(
                r#"{{"destination":{},"rule":{},"detail":{},"injected":{}}}"#,
                quote(&ev.destination),
                ev.rule.as_deref().map_or_else(|| "null".to_string(), quote),
                quote(&ev.detail),
                ev.injected
            )
        })
        .collect();

    // `proves_injection` is the field a UI should render, not `reachable`.
    // Reachability is table stakes; the question the button is really asking is
    // whether the credential demonstrably arrived.
    let control = match (r.control, r.status) {
        (Some(c), Ok(p)) => match verdict(&p.status, &c.status) {
            Verdict::ProvesInjection { without } => format!(
                r#"{{"status":{},"differs":true,"proves_injection":{}}}"#,
                quote(&without),
                r.intercepted
            ),
            Verdict::ProvesNothing { status } => format!(
                r#"{{"status":{},"differs":false,"proves_injection":false}}"#,
                quote(&status)
            ),
            Verdict::Failed(e) => format!(r#"{{"status":null,"error":{}}}"#, quote(&e)),
        },
        _ => "null".to_string(),
    };

    format!(
        concat!(
            r#"{{"host":{},"port":{},"path":{},"address":{},"disposition":{},"#,
            r#""intercepted":{},"reachable":{},"origin_status":{},"tls":{},"#,
            r#""error":{},"audit":[{}],"control":{}}}"#
        ),
        quote(r.host),
        r.port,
        quote(r.path),
        quote(&r.addr.to_string()),
        quote(r.disposition),
        r.intercepted,
        reachable,
        origin_status,
        tls,
        error,
        events.join(","),
        control
    )
}

fn resolve_one(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

/// Send one minimal request through the proxy and return the origin's status
/// line. An intercepted flow verifies against our own CA (that *is* the
/// interception); a relayed one verifies against the public roots, which proves
/// the origin's real certificate came through untouched.
fn probe(
    proxy: &server::RunningProxy,
    ca: &Arc<ProxyCa>,
    addr: SocketAddr,
    host: &str,
    path: &str,
    intercepted: bool,
) -> Result<Probe, String> {
    let mut roots = RootCertStore::empty();
    if intercepted {
        roots
            .add(CertificateDer::from(ca.cert_der().to_vec()))
            .map_err(|e| format!("trust proxy ca: {e}"))?;
    } else {
        roots = (*server::load_roots().map_err(|e| e.to_string())?).clone();
    }
    // An intercepted flow terminates on our own server, which is TLS 1.3 only.
    // A relayed one reaches the real origin, so this client stands in for the
    // guest's and must be no stricter than one — otherwise `check` reports a
    // host as unreachable that the guest would in fact reach perfectly well.
    let versions: &[&rustls::SupportedProtocolVersion] = if intercepted {
        &[&version::TLS13]
    } else {
        &[&version::TLS13, &version::TLS12]
    };
    let mut cfg = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("bad host: {e}"))?;
    let conn =
        ClientConnection::new(Arc::new(cfg), name).map_err(|e| format!("tls client: {e}"))?;

    let mut sock = TcpStream::connect(proxy.addr).map_err(|e| format!("dial proxy: {e}"))?;
    server::write_preamble(&mut sock, addr.ip(), addr.port(), Some(host))
        .map_err(|e| format!("preamble: {e}"))?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(
        format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: chm-proxy-check\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 512];
    let n = tls.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let tls_version = tls
        .conn
        .protocol_version()
        .map_or_else(|| "unknown".to_string(), |v| format!("{v:?}"));
    Ok(Probe {
        status: text.lines().next().unwrap_or("(empty)").to_string(),
        tls_version,
    })
}

/// What one probe learned. The TLS version is reported because which one an
/// origin offers is not ours to choose, and finding out currently costs an
/// `openssl s_client` invocation and knowing to try.
struct Probe {
    status: String,
    tls_version: String,
}

/// Decide whether a resolved rule set may widen an egress allow-list, and
/// report the widening on stderr so it is never silent.
///
/// **V8.7.** Naming a host in an injection rule *is* the intent to reach it, but
/// the NAT decides a connect before it consults the interception hook, so under
/// a default-deny policy the flow was refused before the proxy could see it —
/// the rules were right, the proxy was running, and the guest was blocked by a
/// subsystem that had never been told. It fails closed, so this is a usability
/// defect rather than a security one; the fix must not turn it into the latter.
///
/// Two guards keep it honest:
///
/// 1. **Same authority, both halves.** A control plane hands its policy down
///    through the environment and stakes a digest on it. A `proxy-rules.json`
///    that merely happens to be in the workspace directory must not reopen a
///    host that policy closed, so a mismatch widens nothing and says why.
/// 2. **Nothing is implied quietly.** Every entry is printed with the rule that
///    implied it, and each entry carries that attribution into every decision it
///    later makes (see `EgressPolicy::allow_implied`).
///
/// Returns the entries to add, which is empty whenever widening is refused.
pub(crate) fn implied_egress_for(
    resolved: &Resolved,
    policy_authority: Authority,
    policy_label: &str,
) -> Vec<String> {
    let implied = resolved.rules.implied_egress_allow();
    for skipped in &implied.skipped {
        eprintln!(
            "chm: [proxy] {skipped} is an IPv6 literal; the egress allow-list is IPv4-only, \
             so this host is not covered and the guest will be denied unless you allow it \
             another way"
        );
    }
    if implied.allow.is_empty() {
        return Vec::new();
    }
    if resolved.authority != policy_authority {
        eprintln!(
            "chm: [proxy] NOT widening egress for {}: the egress policy ({policy_label}) and \
             the injection rules ({}) come from different authorities, and a local file must \
             not reopen a host a governed policy closed. Add {} to the policy itself.",
            implied.allow.join(", "),
            resolved.origin,
            implied.allow.join(", ")
        );
        return Vec::new();
    }
    eprintln!(
        "chm: [proxy] egress widened for {} — implied by the injection rules in {}",
        implied.allow.join(", "),
        resolved.origin
    );
    implied.allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_configuration_means_absent_interception() {
        // The important negative: nothing configured must resolve to *no proxy*,
        // never to an empty one that quietly sits in the data path.
        let dir = std::env::temp_dir().join(format!("chm-proxy-none-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(resolve_rules(Some(&dir), None).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_workspace_file_is_found_without_being_asked_for() {
        let dir = std::env::temp_dir().join(format!("chm-proxy-ws-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("proxy-rules.json"),
            r#"{"version":1,"rules":[{"name":"gh","hosts":["api.github.com"],"env":"T"}]}"#,
        )
        .unwrap();
        let r = resolve_rules(Some(&dir), None).unwrap().expect("found");
        assert_eq!(r.rules.rules.len(), 1);
        assert!(r.origin.ends_with("proxy-rules.json"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_rules_file_is_an_error_not_a_silent_bypass() {
        // Failing open here would mean a typo silently disables injection while
        // the run looks normal — the failure mode most likely to go unnoticed.
        let dir = std::env::temp_dir().join(format!("chm-proxy-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("proxy-rules.json"), "{ not json").unwrap();
        assert!(resolve_rules(Some(&dir), None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_explicit_file_beats_the_workspace() {
        let dir = std::env::temp_dir().join(format!("chm-proxy-ovr-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("proxy-rules.json"),
            r#"{"version":1,"rules":[{"name":"ws","hosts":["a.example.com"],"env":"T"}]}"#,
        )
        .unwrap();
        let explicit = dir.join("other.json");
        fs::write(
            &explicit,
            r#"{"version":1,"rules":[{"name":"cli","hosts":["b.example.com"],"env":"T"}]}"#,
        )
        .unwrap();
        let r = resolve_rules(Some(&dir), Some(&explicit))
            .unwrap()
            .expect("found");
        assert_eq!(r.rules.rules[0].name, "cli");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_control_that_matches_proves_nothing() {
        // The negative that matters. Against an endpoint answering the same
        // either way, `check` is green even if injection were entirely broken —
        // so the verdict must refuse to call that evidence.
        assert_eq!(
            verdict(
                "HTTP/1.1 200 OK",
                &Ok("HTTP/1.1 200 OK".to_string())
            ),
            Verdict::ProvesNothing {
                status: "HTTP/1.1 200 OK".to_string()
            }
        );
    }

    #[test]
    fn a_control_that_differs_proves_the_credential_arrived() {
        // Measured against the real api.github.com/user: 200 with the token
        // injected, 401 without.
        assert_eq!(
            verdict(
                "HTTP/1.1 200 OK",
                &Ok("HTTP/1.1 401 Unauthorized".to_string())
            ),
            Verdict::ProvesInjection {
                without: "HTTP/1.1 401 Unauthorized".to_string()
            }
        );
    }

    #[test]
    fn a_control_that_could_not_run_is_not_silently_a_pass() {
        assert_eq!(
            verdict("HTTP/1.1 200 OK", &Err("connect refused".to_string())),
            Verdict::Failed("connect refused".to_string())
        );
    }

    #[test]
    fn the_workspace_resolves_the_same_however_the_caller_spells_it() {
        // `chm create` takes `--workspace DIR`; this command originally took
        // only a bare positional. Worse, the argument scan assumed every
        // unrecognised flag carried a value, so `--workspace DIR` consumed the
        // directory as that flag's value and the command reported "not
        // configured" -- a wrong answer wearing the costume of a right one.
        let args = |v: &[&str]| -> Vec<String> { v.iter().map(ToString::to_string).collect() };

        assert_eq!(workspace_arg(&args(&["/ws"])).unwrap(), "/ws");
        assert_eq!(
            workspace_arg(&args(&["--workspace", "/ws"])).unwrap(),
            "/ws"
        );
        assert_eq!(
            workspace_arg(&args(&["--workspace", "/ws", "--json"])).unwrap(),
            "/ws"
        );
        // A valued flag before the positional must not swallow it.
        assert_eq!(
            workspace_arg(&args(&["--rules", "/r.json", "/ws"])).unwrap(),
            "/ws"
        );
        assert_eq!(workspace_arg(&args(&["--json"])), None);
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_silently_eating_its_neighbour() {
        // The failure this prevents is not a rejected command, it is an
        // accepted one that quietly did the wrong thing.
        let args: Vec<String> = ["--workspce", "/ws"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(reject_unknown("show", &args).is_err());

        let ok: Vec<String> = ["--workspace", "/ws", "--json"]
            .iter()
            .map(ToString::to_string)
            .collect();
        reject_unknown("show", &ok).unwrap();
    }

    #[test]
    fn show_json_carries_the_hosts_that_are_never_intercepted() {
        // `passthrough` is the other half of the interception story. A UI given
        // only the injecting rules would imply everything else is intercepted,
        // when the opposite is true.
        let dir = std::env::temp_dir().join(format!("chm-proxy-pt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("proxy-rules.json"),
            r#"{"version":1,"label":"L","passthrough":["pinned.example.com"],
                "rules":[{"name":"gh","hosts":["api.github.com"],"env":"T"}]}"#,
        )
        .unwrap();
        let r = resolve_rules(Some(&dir), None).unwrap().expect("found");
        assert_eq!(r.rules.passthrough.len(), 1);
        assert_eq!(r.rules.label.as_deref(), Some("L"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The installer must prove the *trust store* accepts the CA, not that the
    /// file it wrote contains the certificate it wrote.
    ///
    /// Measured on a rehydrated Graviton guest: `update-ca-certificates`
    /// segfaulted, the CA never reached `/etc/ssl/certs`, and the previous
    /// script still printed matching fingerprints — because it only re-read its
    /// own staging file. After this change the same guest reported `trusted:`
    /// and `openssl verify` exited 0, via the direct-link fallback.
    #[test]
    fn the_ca_installer_verifies_against_the_trust_store_not_its_own_file() {
        let script = guest_install_script("-----BEGIN CERTIFICATE-----\nAA\n", "beefcafe");

        // The check that matters: does this cert chain to the guest's store?
        assert!(
            script.contains("openssl verify -CApath /etc/ssl/certs"),
            "the install must be verified against the trust store"
        );
        // A helper that fails must not cost us the install, nor be reported as
        // success -- so there is a fallback and it is guarded by the verify.
        assert!(script.contains("openssl x509 -hash -noout"), "fallback link missing");
        assert!(script.contains("/etc/ssl/certs/$H.0"), "fallback link missing");
        // And a failure has to be sayable. A script that can only print success
        // is the bug this replaced.
        assert!(script.contains("NOT TRUSTED"), "the installer must be able to say no");
        assert!(script.contains("expected:     beefcafe"));
    }

    /// The installer must work on a guest with no sudo and no trust store.
    ///
    /// Measured on a `node:22-slim` container guest: `sudo`, `openssl` and
    /// `update-ca-certificates` are all absent and **none** of
    /// `/usr/local/share/ca-certificates`, `/usr/share/ca-certificates` or
    /// `/etc/ssl/certs` exists. The previous script opened with `sudo tee`, so
    /// every line of it failed — on the image the docs recommend for running an
    /// agent, which is the case this whole feature exists to serve.
    #[test]
    /// A cpio entry whose parent has no entry of its own is dropped by the
    /// kernel in silence. Measured in #222: five modules in the archive, none
    /// in the guest, no message. So the parents must be present as entries.
    fn the_ca_archive_carries_its_own_parent_directories() {
        let pem = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
        let cpio = ca_cpio_from_pem(pem);
        let text = String::from_utf8_lossy(&cpio);
        // `./`-prefixed, which is what `write_cpio` emits and what the kernel
        // resolves against the root it is building. Checked in that exact form
        // after a bare-name check passed against a path that could equally have
        // been absolute -- the assertion has to be able to tell those apart.
        for needed in ["./etc\0", "./etc/gimbal\0", "./etc/gimbal/proxy-ca.crt\0"] {
            assert!(
                text.contains(needed),
                "`{needed}` has no entry, so the kernel drops what is under it \
                 without saying anything"
            );
        }
        assert!(
            text.contains(pem),
            "the archive must carry the certificate itself, not just its name"
        );
        assert!(
            !text.contains("\0/etc/gimbal"),
            "a cpio name must not be absolute; the kernel resolves it against the \
             root it is building, and a leading slash resolves against nothing"
        );
        assert!(text.contains("TRAILER!!!"), "an archive must be terminated");
        assert_eq!(
            cpio.len() % 4,
            0,
            "the archive must end 4-byte aligned, or anything concatenated after \
             it starts misaligned and the kernel stops unpacking -- silently"
        );
    }

    /// The first run of a workspace has no CA on disk yet -- the proxy mints it
    /// later in the same command. If this read rather than created, that first
    /// guest would ship without a CA and only the *second* run would work.
    #[test]
    fn a_fresh_workspace_still_gets_a_ca_rather_than_waiting_for_the_second_run() {
        let dir = std::env::temp_dir().join(format!("chm-cafresh-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        let first = ca_cpio_for(&dir).expect("a fresh workspace must not be refused");
        let pem = ProxyCa::load_existing(&ca_dir(&dir))
            .expect("readable")
            .expect("the CA the proxy will use must now exist")
            .cert_pem();
        let second = ca_cpio_for(&dir).expect("second call");
        fs::remove_dir_all(&dir).ok();

        let bytes = first.expect("a workspace bound for a proxy always gets an archive");
        assert!(
            String::from_utf8_lossy(&bytes).contains(&pem),
            "the archive must carry the CA the proxy will actually sign with"
        );
        assert_eq!(
            Some(bytes),
            second,
            "resolving twice must not mint a second CA; the guest would trust one \
             the proxy does not use, and every intercepted connection would fail \
             a certificate check *after* we reported success"
        );
    }

    #[test]
    fn the_ca_installer_does_not_assume_sudo_or_a_trust_store() {
        let script = guest_install_script("-----BEGIN CERTIFICATE-----\nAA\n", "beefcafe");

        assert!(
            !script.contains("sudo tee") && !script.contains("sudo cp \"$CRT\" /usr"),
            "the installer must not hardcode sudo: a container guest has none"
        );
        assert!(
            script.contains("if [ \"$(id -u)\" = 0 ]; then S=;"),
            "root must be recognised rather than assumed to need sudo"
        );
        // Absent tools must degrade to a named outcome, never a hard failure
        // under `set -e` -- and never a silent claim of success.
        for guard in ["command -v sudo", "command -v openssl", "command -v node"] {
            assert!(
                script.contains(guard),
                "missing availability check: {guard}"
            );
        }
        assert!(
            script.contains("no openssl here"),
            "an unverifiable install must say so rather than claim trust"
        );
    }

    /// Node does not read the OS trust store, so installing there is not enough.
    ///
    /// Measured in one guest, seconds apart, with the CA verified in the system
    /// store: `node` failed `SELF_SIGNED_CERT_IN_CHAIN` against an intercepted
    /// host, and the identical request with `NODE_EXTRA_CA_CERTS` set returned a
    /// real HTTP status. An installer that stops at the system store ships a
    /// guest where `curl` works and the coding agent does not -- and the agent
    /// is the workload.
    #[test]
    fn the_ca_installer_configures_node_as_well_as_the_system_store() {
        let script = guest_install_script("-----BEGIN CERTIFICATE-----\nAA\n", "beefcafe");

        assert!(
            script.contains("NODE_EXTRA_CA_CERTS"),
            "node is not configured"
        );
        // A script cannot export into the shell that ran it, so the variable
        // has to be reachable as a *file* someone can source -- and the script
        // must say so rather than claim the caller's shell is configured.
        assert!(
            script.contains(ENV_PATH),
            "there must be a file a shell can source"
        );
        assert!(
            script.contains(&format!("this shell:   . {ENV_PATH}")),
            "the caller's own shell needs a named, runnable remedy"
        );
        assert!(
            !script.contains("already exported"),
            "claiming the caller's shell is configured was measured false"
        );
        assert!(
            script.contains("/etc/profile.d/gimbal-proxy-ca.sh"),
            "login shells should get it without being asked"
        );
        // Node ignores an unreadable or unparseable file *silently*, so the
        // check has to be that node itself can read this exact one.
        assert!(
            script.contains("X509Certificate") && script.contains("NOT LOADED"),
            "node's silent-ignore failure mode must be detectable"
        );
        // The report must not collapse two different answers into one word.
        assert!(
            script.contains("system store:") && script.contains("node:"),
            "each client's trust must be reported separately"
        );
    }

    /// The transfer must reassemble to exactly the script, and the guest must be
    /// able to tell that it did.
    ///
    /// Decoded with `state_cdn::base64_decode` on purpose: an encoder checked
    /// against its own inverse proves nothing, and the guest will use a third
    /// implementation again (`base64 -d`).
    #[test]
    fn the_install_transfer_reassembles_and_is_checked_before_it_runs() {
        let script = guest_install_script("-----BEGIN CERTIFICATE-----\nQUJD\n", "beefcafe");
        let lines = guest_install_transfer(&script);

        // Reassemble exactly what the guest's file would hold.
        let mut b64 = String::new();
        for line in &lines {
            if let Some(rest) = line.strip_prefix("printf %s '") {
                b64.push_str(rest.split('\'').next().expect("chunk"));
            }
        }
        let decoded = crate::state_cdn::base64_decode(&b64).expect("decodes");
        assert_eq!(String::from_utf8(decoded).expect("utf8"), script);

        // Single-quoting the chunks is only safe because base64 has no quote.
        assert!(!b64.contains('\''), "a quote in the payload would break quoting");

        // The digest the guest compares must be the digest of what it receives,
        // and it must refuse rather than run a script it cannot vouch for.
        let want: String = digest(&SHA256, b64.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let last = lines.last().expect("execute line");
        assert!(last.contains(&want), "the guest must check the digest we computed");
        assert!(last.contains("TRANSFER CORRUPT"), "a dropped character must be named");

        // Every line before the last must be instant, so nothing is ever typed
        // at a shell that is still busy -- that was the original bug.
        for line in &lines[..lines.len() - 1] {
            assert!(
                line.starts_with("printf %s '") || line.starts_with("rm -f "),
                "slow command before the end of the transfer: {line}"
            );
        }
    }

    /// A diagnostic's own traffic must not appear in the subject's trail.
    ///
    /// `chm proxy check` opens real connections, but they are the *operator's*
    /// -- the guest did not make them and may not even be running. Recording
    /// them would put decisions the sandbox never took into the record used to
    /// judge it, so both diagnostic paths take a disabled log deliberately,
    /// while the path that actually serves a guest takes the workspace's.
    #[test]
    fn a_diagnostic_does_not_write_into_the_sandboxs_trail() {
        let ws = env::temp_dir().join(format!("chm-cli-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).unwrap();

        // The disabled handle is what the check paths construct.
        let quiet = AuditLog::default();
        quiet.egress_deny("tcp", "1.2.3.4:443", "r", "p");
        quiet.proxy_decision("api.github.com:443", "inject", "gh");
        assert!(
            !ws.join("audit.jsonl").exists(),
            "a disabled log must not create a trail anywhere"
        );

        // The workspace handle, which `start_for_workspace` uses, does write.
        let live = AuditLog::open(&ws);
        live.proxy_decision("api.github.com:443", "inject", "gh");
        let body = fs::read_to_string(ws.join("audit.jsonl")).unwrap();
        assert!(body.contains("\"disposition\":\"inject\""), "{body}");

        let _ = fs::remove_dir_all(&ws);
    }

    fn resolved(json: &str, authority: Authority) -> Resolved {
        Resolved {
            rules: RuleSet::parse(json).expect("rules should parse"),
            origin: "test".to_string(),
            authority,
        }
    }

    const GH: &str = r#"{"rules":[{"name":"gh","hosts":["api.github.com"],"env":"T"}]}"#;

    #[test]
    fn a_local_rule_widens_a_local_policy() {
        let got = implied_egress_for(
            &resolved(GH, Authority::Local),
            Authority::Local,
            "workspace",
        );
        assert_eq!(got, vec!["api.github.com:443"]);
    }

    #[test]
    fn a_control_plane_rule_widens_a_control_plane_policy() {
        // The control plane issued both halves, so it already intends the guest
        // to reach the hosts it told us to inject into.
        let got = implied_egress_for(
            &resolved(GH, Authority::ControlPlane),
            Authority::ControlPlane,
            "sha256:abc",
        );
        assert_eq!(got, vec!["api.github.com:443"]);
    }

    #[test]
    fn a_local_rules_file_cannot_widen_a_governed_policy() {
        // The one that matters. A `proxy-rules.json` that merely happens to sit
        // in the workspace directory must not reopen a host a digest-carrying
        // control-plane policy closed.
        let got = implied_egress_for(
            &resolved(GH, Authority::Local),
            Authority::ControlPlane,
            "sha256:abc",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn a_governed_rules_binding_cannot_widen_a_local_policy_either() {
        // The mirror case. The guard is "same authority wrote both halves",
        // not "the control plane is trusted", so it refuses both directions
        // rather than encoding a hierarchy nobody asked for.
        let got = implied_egress_for(
            &resolved(GH, Authority::ControlPlane),
            Authority::Local,
            "workspace",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn rules_that_imply_nothing_widen_nothing() {
        let got = implied_egress_for(
            &resolved(r#"{"rules":[]}"#, Authority::Local),
            Authority::Local,
            "workspace",
        );
        assert!(got.is_empty(), "{got:?}");
    }
    /// Every flag the help text offers must be one the parser accepts.
    ///
    /// This is the #210 bug as a test. `--for-guest` was fully implemented,
    /// and the banner `chm proxy ca` prints told the reader to use it — but
    /// the allow-list handed to `reject_unknown` omitted it, so the flag was
    /// refused as unknown and the handler below it could never run. A remedy
    /// that is itself wrong is worse than no remedy: the reader has no reason
    /// left to doubt the tool.
    ///
    /// Reads the promise out of `USAGE` rather than restating it, for the same
    /// reason `chm --help`'s guard reads the dispatch table out of `imp.rs`:
    /// a restated expectation drifts with the thing it is meant to pin.
    #[test]
    fn usage_promises_only_flags_the_parser_accepts() {
        for cmd in subcommands_in_usage() {
            let cmd = cmd.as_str();
            let known = flags_for(cmd).unwrap_or_else(|| {
                panic!(
                    "USAGE documents `chm proxy {cmd}` but no allow-list is \
                     registered for it in `flags_for`, so the parser cannot \
                     refuse anything it is handed -- that was #317"
                )
            });
            let promised = flags_promised_for(cmd);
            assert!(
                !promised.is_empty(),
                "found no `chm proxy {cmd}` line in USAGE — the parser below \
                 has changed shape and this guard is no longer reading it"
            );
            for f in &promised {
                assert!(
                    known.contains(&f.as_str()),
                    "USAGE offers `chm proxy {cmd} {f}` but the parser refuses \
                     it as unknown; promised={promised:?} accepted={known:?}"
                );
            }
        }

        // The hint printed beside the certificate is a third copy of the same
        // promise, and it is the one the user is most likely to act on: it
        // arrives unprompted, in the output they already asked for.
        for f in flags_in(CA_GUEST_HINT) {
            assert!(
                CA_FLAGS.contains(&f.as_str()),
                "the hint printed by `chm proxy ca` tells the reader to use \
                 `{f}`, which the parser refuses as unknown"
            );
        }
    }

    /// Every subcommand USAGE documents, read out of the synopsis block.
    ///
    /// Derived rather than listed so a new subcommand is covered the day it is
    /// documented. #317 shipped because `check` was simply absent from a
    /// hardcoded pair, and nothing noticed the omission.
    fn subcommands_in_usage() -> Vec<String> {
        let section = USAGE
            .split_once("USAGE:\n")
            .expect("USAGE: header")
            .1
            .split("\n\n")
            .next()
            .expect("a synopsis block");
        let mut out: Vec<String> = section
            .lines()
            .filter_map(|l| l.trim().strip_prefix("chm proxy "))
            .filter_map(|r| r.split_whitespace().next())
            .filter(|v| v.chars().all(|c| c.is_ascii_lowercase()))
            .map(str::to_string)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// The flags USAGE offers for one subcommand, including continuation lines.
    fn flags_promised_for(cmd: &str) -> Vec<String> {
        let section = USAGE
            .split_once("USAGE:\n")
            .expect("USAGE: header")
            .1
            .split("\n\n")
            .next()
            .expect("a synopsis block");
        let mut out = Vec::new();
        let mut mine = false;
        for line in section.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("chm proxy ") {
                // A new synopsis entry: it is ours only if the verb matches.
                mine = rest.split_whitespace().next() == Some(cmd);
            }
            if !mine {
                continue;
            }
            out.extend(flags_in(t));
        }
        out.sort();
        out.dedup();
        out
    }

    /// Every `--flag` mentioned in a piece of prose.
    fn flags_in(text: &str) -> Vec<String> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|t| t.starts_with("--") && t.len() > 2)
            .map(str::to_string)
            .collect()
    }

    /// `check` reads its rules from `--workspace`, the same directory `show` reads.
    ///
    /// This is #317 as a test. `chm proxy check --workspace DIR` accepted the
    /// flag, dropped it, and reported `PASS-THROUGH (no-rule)` while
    /// `chm proxy show --workspace DIR` listed a matching rule from the file in
    /// that very directory. Two sibling commands disagreed about what
    /// `--workspace` meant, and the one that disagreed is the *evidence*
    /// command -- the one whose whole purpose is answering "is my credential
    /// actually being injected?".
    ///
    /// What made it survive review is that `no-rule` is not an error. It is a
    /// legitimate outcome meaning "nothing is configured for this host", so
    /// there was no way to tell it apart from a flag that was silently
    /// discarded. During the #286 acceptance run it was read as evidence the
    /// proxy was misconfigured.
    ///
    /// Asserts on the plan rather than on the command, because running the
    /// command opens a real connection to a real host -- which is exactly why
    /// nothing exercised this path.
    #[test]
    fn check_reads_the_workspace_it_is_given() {
        let args = vec![
            "--workspace".to_string(),
            "/tmp/ws-317".to_string(),
            "--host".to_string(),
            "api.github.com".to_string(),
        ];
        let plan = plan_check(&args).expect("a well-formed check");
        assert_eq!(
            plan.workspace.as_deref(),
            Some(Path::new("/tmp/ws-317")),
            "`check --workspace DIR` must resolve DIR; passing None here is \
             #317, and it reports `no-rule` rather than failing"
        );
        assert_eq!(plan.host, "api.github.com");
    }

    /// An argument `check` does not understand is an error, not a shrug.
    ///
    /// `check` had no allow-list at all, so any flag at all was consumed and
    /// the command still rendered a confident verdict below it. A wrong answer
    /// from the evidence command is worse than no answer.
    #[test]
    fn check_refuses_a_flag_it_does_not_know() {
        let args = vec![
            "--host".to_string(),
            "api.github.com".to_string(),
            "--workspce".to_string(), // a plausible typo, not a wild string
            "/tmp/ws-317".to_string(),
        ];
        let err = plan_check(&args).expect_err("a misspelled flag must not pass");
        assert!(
            err.contains("--workspce"),
            "the refusal must name the offending flag, got: {err}"
        );
    }

    /// A subcommand with no registered flags refuses everything.
    ///
    /// The failure mode this rules out is the one #317 shipped: a command that
    /// accepts every flag it is handed. Failing closed makes the same omission
    /// loudly broken instead of quietly permissive.
    #[test]
    fn an_unregistered_subcommand_accepts_nothing() {
        assert!(flags_for("no-such-subcommand").is_none());
        let args = vec!["--json".to_string()];
        assert_eq!(
            first_unknown_flag("no-such-subcommand", &args),
            Some("--json"),
            "an unregistered subcommand must reject flags, not wave them through"
        );
    }

    /// A workspace directory is positional *or* `--workspace`, and `--for-guest`
    /// must survive alongside either — the refusal fired before the handler,
    /// so neither form reached it.
    #[test]
    fn for_guest_is_accepted_in_both_workspace_forms() {
        let positional = vec!["/tmp/ws".to_string(), "--for-guest".to_string()];
        let flagged = vec![
            "--workspace".to_string(),
            "/tmp/ws".to_string(),
            "--for-guest".to_string(),
        ];
        reject_unknown("ca", &positional).unwrap();
        reject_unknown("ca", &flagged).unwrap();
        assert_eq!(workspace_arg(&positional), Some("/tmp/ws"));
        assert_eq!(workspace_arg(&flagged), Some("/tmp/ws"));
    }

    /// A CA directory holding both halves, so a test can assert on inheritance
    /// without minting a real key pair (`load_or_create` is slow and its output
    /// is not what any of these assertions are about).
    fn seed_ca(dir: &Path, key: &[u8], cert: &[u8]) {
        let ca = ca_dir(dir);
        fs::create_dir_all(&ca).unwrap();
        fs::write(ca.join(CA_KEY_FILE), key).unwrap();
        fs::write(ca.join(CA_CERT_FILE), cert).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chm-ca-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn an_image_ca_is_inherited_by_a_workspace_made_from_it() {
        // #315: the guest inside a workspace is the image's guest, so it already
        // trusts the image's CA. Minting a fresh one hands that guest a
        // certificate chain it will refuse, and the refusal names nothing.
        let root = scratch("inherit");
        let (image, ws) = (root.join("image"), root.join("ws"));
        seed_ca(&image, b"image-key", b"image-cert");
        fs::create_dir_all(&ws).unwrap();

        assert!(
            inherit_ca(&image, &ws).unwrap(),
            "there was a CA to inherit"
        );
        assert_eq!(
            fs::read(ca_dir(&ws).join(CA_CERT_FILE)).unwrap(),
            b"image-cert"
        );
        assert_eq!(
            fs::read(ca_dir(&ws).join(CA_KEY_FILE)).unwrap(),
            b"image-key",
            "the key travels too, or the proxy holds a cert it cannot sign with"
        );

        // Copied, not shared: a workspace must not be able to write through to
        // the image every other workspace is sharing read-only.
        assert!(
            !fs::symlink_metadata(ca_dir(&ws).join(CA_CERT_FILE))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::write(ca_dir(&ws).join(CA_CERT_FILE), b"diverged").unwrap();
        assert_eq!(
            fs::read(ca_dir(&image).join(CA_CERT_FILE)).unwrap(),
            b"image-cert"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_image_with_no_ca_leaves_the_workspace_to_mint_its_own() {
        // The ordinary case, and deliberately not an error: a guest that trusts
        // nothing yet is not harmed by a new authority. The bug only bites when
        // the image carries one the guest was provisioned against.
        let root = scratch("nothing");
        let (image, ws) = (root.join("image"), root.join("ws"));
        fs::create_dir_all(&image).unwrap();
        fs::create_dir_all(&ws).unwrap();

        assert!(!inherit_ca(&image, &ws).unwrap());
        assert!(
            !ca_dir(&ws).exists(),
            "an empty CA directory would make `load_or_create` mint into a path \
             that implies it inherited something"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn half_a_ca_is_not_inherited() {
        // A cert without its key cannot sign a leaf. Copying it would replace a
        // working mint-fresh path with a proxy that fails at the first
        // interception -- later, and further from the cause.
        let root = scratch("half");
        let (image, ws) = (root.join("image"), root.join("ws"));
        fs::create_dir_all(ca_dir(&image)).unwrap();
        fs::write(ca_dir(&image).join(CA_CERT_FILE), b"orphan-cert").unwrap();
        fs::create_dir_all(&ws).unwrap();

        assert!(!inherit_ca(&image, &ws).unwrap());
        assert!(!ca_dir(&ws).exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_inherited_ca_keeps_its_private_key_unreadable() {
        // Tightened at copy time rather than at the next `load_or_create`: a
        // workspace can sit between creation and its first run for any length of
        // time, and a host-readable CA key impersonates every intercepted host.
        let root = scratch("perms");
        let (image, ws) = (root.join("image"), root.join("ws"));
        seed_ca(&image, b"k", b"c");
        fs::create_dir_all(&ws).unwrap();
        inherit_ca(&image, &ws).unwrap();

        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(ca_dir(&ws)), 0o700);
        assert_eq!(mode(ca_dir(&ws).join(CA_KEY_FILE)), 0o600);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_workspace_presenting_a_different_ca_from_its_image_is_named() {
        // For the workspaces that already exist. `inherit_ca` means a workspace
        // created by this build always agrees; one created by an earlier build
        // stays broken across the upgrade, and without this it stays broken
        // *silently*, which is the whole of what #315 cost.
        let root = scratch("mismatch");
        let (image, ws) = (root.join("image"), root.join("ws"));
        fs::create_dir_all(&image).unwrap();
        fs::create_dir_all(&ws).unwrap();
        fs::write(image.join("state.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(image.join("state.json"), ws.join("state.json")).unwrap();
        seed_ca(&image, b"image-key", b"image-cert");
        seed_ca(&ws, b"ws-key", b"ws-cert");

        let why = inherited_ca_mismatch(&ws).expect("the two CAs differ");
        assert!(why.contains(&ca_dir(&ws).display().to_string()));
        assert!(
            why.contains(&ca_dir(&image).display().to_string()),
            "naming only one side leaves the reader with nothing to compare"
        );

        // Agreement is silent -- which is what every workspace made by this
        // build looks like.
        fs::write(ca_dir(&ws).join(CA_CERT_FILE), b"image-cert").unwrap();
        assert!(inherited_ca_mismatch(&ws).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_that_is_not_a_workspace_is_not_diagnosed() {
        // No `state.json` symlink means no base image, so there is no second CA
        // to disagree with. Reporting one here would be inventing a comparison.
        let root = scratch("standalone");
        seed_ca(&root, b"k", b"c");
        assert!(base_image_dir(&root).is_none());
        assert!(inherited_ca_mismatch(&root).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_proxy_banner_is_followed_by_the_mismatch_diagnosis() {
        // `start_resolved` binds a listener and needs a resolved rule set, so no
        // unit test can call it — and deleting its call to `inherited_ca_mismatch`
        // left all 877 tests green. An assertion about an outcome structurally
        // cannot see a path that is no longer taken, so this reads the source.
        //
        // The needle is assembled from parts: a literal written out here would
        // match this assertion's own text and could never detect its removal
        // from the place that matters.
        let src = include_str!("cli.rs");
        let needle = format!("if let Some(why) = {}(workspace)", "inherited_ca_mismatch");
        assert!(
            src.contains(&needle),
            "start_resolved must print the #315 mismatch right after the injection \
             banner; the banner claims injection is active and names a CA, which is \
             exactly the sentence #315 made true and useless"
        );
    }
}
