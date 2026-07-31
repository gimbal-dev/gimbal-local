//! `chm proxy` — inspect, export, and smoke-test the credential proxy.
//!
//! Deliberately weighted towards *showing* rather than *doing*: the proxy runs
//! as part of a VM, and the useful commands here are the ones that let you see
//! what it would do before you trust it with a credential, and confirm it can
//! actually reach an origin from this machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::{env, fs};

use hypervisor::hvf::virtio::nat::InterceptDecider;
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, version};

use crate::audit::AuditLog;

use super::ca::ProxyCa;
use super::nat::RuleDecider;
use super::rules::{Destination, Disposition, RuleSet};
use super::server::{self, ProxyConfig};

/// Where a rule set came from, so `show` can say so.
pub(crate) struct Resolved {
    pub(crate) rules: RuleSet,
    pub(crate) origin: String,
}

/// Resolve the rule set the same way every other local policy resolves:
/// explicit flag, then environment, then the workspace file. Absent all three
/// there is no proxy — not an empty one — because interception must never be
/// something a run acquires by accident.
pub(crate) fn resolve_rules(
    workspace: Option<&Path>,
    cli_override: Option<&Path>,
) -> Result<Option<Resolved>, String> {
    let parse = |raw: &str, origin: String| match RuleSet::parse(raw) {
        Ok(rules) => Ok(Some(Resolved { rules, origin })),
        Err(e) => Err(format!("{origin}: {e}")),
    };
    if let Some(path) = cli_override {
        let raw =
            fs::read_to_string(path).map_err(|e| format!("--rules {}: {e}", path.display()))?;
        return parse(&raw, format!("--rules {}", path.display()));
    }
    if let Ok(raw) = env::var("CHM_PROXY_RULES") {
        // Accept either a path or the document itself, because a launcher that
        // holds the rules in memory should not have to write them to disk.
        if let Ok(text) = fs::read_to_string(&raw) {
            return parse(&text, format!("CHM_PROXY_RULES={raw}"));
        }
        return parse(&raw, "CHM_PROXY_RULES".to_string());
    }
    if let Some(ws) = workspace {
        let file = ws.join("proxy-rules.json");
        if let Ok(raw) = fs::read_to_string(&file) {
            return parse(&raw, file.display().to_string());
        }
    }
    Ok(None)
}

/// The directory the workspace CA lives in.
pub(crate) fn ca_dir(workspace: &Path) -> PathBuf {
    workspace.join("proxy-ca")
}

/// A started proxy and the hook that routes flows to it. The proxy is returned
/// so the caller can keep it alive for the life of the VM.
pub(crate) type StartedProxy = (server::RunningProxy, Arc<dyn InterceptDecider>);

/// Start a proxy and build the NAT hook for it, or `None` when this run has no
/// rules. Returns the running proxy too, so the caller can keep it alive and
/// read its audit trail.
pub(crate) fn start_for_workspace(
    workspace: &Path,
    cli_override: Option<&Path>,
) -> Result<Option<StartedProxy>, String> {
    let Some(resolved) = resolve_rules(Some(workspace), cli_override)? else {
        return Ok(None);
    };
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
    let decider = RuleDecider::for_proxy(resolved.rules, &proxy)
        .ok_or_else(|| "rules matched nothing to intercept".to_string())?;
    eprintln!(
        "chm: [proxy] credential injection ACTIVE for {} ({}) — CA {}",
        patterns.join(", "),
        resolved.origin,
        ca.fingerprint()
    );
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
    chm proxy show [WORKSPACE_DIR] [--rules FILE] [--json]
    chm proxy ca   <WORKSPACE_DIR> [--out FILE]
    chm proxy check --host HOST [--port N] [--path P] [--rules FILE]
                    [--control] [--json]

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

fn positional(args: &[String]) -> Option<&str> {
    let mut skip = false;
    for (i, a) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            // Every flag this command takes has a value except --json.
            skip = a != "--json";
            continue;
        }
        let _ = i;
        return Some(a);
    }
    None
}

fn show(args: &[String]) -> ExitCode {
    let workspace = positional(args).map(PathBuf::from);
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
    let Some(ws) = positional(args) else {
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
    eprintln!("# `chm proxy ca <WORKSPACE_DIR> --for-guest` prints an installer to");
    eprintln!("# paste into the guest console.");
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
         sudo tee /usr/local/share/ca-certificates/gimbal-proxy.crt >/dev/null <<'GIMBAL_CA_EOF'\n\
         {pem}GIMBAL_CA_EOF\n\
         CRT=/usr/local/share/ca-certificates/gimbal-proxy.crt\n\
         sudo update-ca-certificates >/dev/null 2>&1 \\\n\
           || echo 'note: update-ca-certificates failed; linking the CA directly'\n\
         if ! openssl verify -CApath /etc/ssl/certs \"$CRT\" >/dev/null 2>&1; then\n\
         \x20 # update-ca-certificates did not take. Do by hand what it would have\n\
         \x20 # done, so a broken helper does not cost us the install.\n\
         \x20 H=$(openssl x509 -hash -noout -in \"$CRT\")\n\
         \x20 sudo cp \"$CRT\" /etc/ssl/certs/gimbal-proxy.pem\n\
         \x20 sudo ln -sf gimbal-proxy.pem \"/etc/ssl/certs/$H.0\"\n\
         fi\n\
         if openssl verify -CApath /etc/ssl/certs \"$CRT\" >/dev/null 2>&1; then\n\
         \x20 echo \"trusted:  $(openssl x509 -noout -fingerprint -sha256 -in \"$CRT\" \\\n\
         \x20   | tr -d ':' | tr 'A-Z' 'a-z' | sed 's/.*=//')\"\n\
         else\n\
         \x20 echo 'NOT TRUSTED: the guest still does not trust this CA.'\n\
         fi\n\
         echo \"expected: {fingerprint}\"\n"
    )
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

fn check(args: &[String]) -> ExitCode {
    let Some(host) = flag(args, "--host") else {
        eprintln!("chm proxy check: --host is required\n\n{USAGE}");
        return ExitCode::FAILURE;
    };
    let port: u16 = flag(args, "--port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let path = flag(args, "--path").unwrap_or("/");
    let json = args.iter().any(|a| a == "--json");
    let want_control = args.iter().any(|a| a == "--control");
    let over = flag(args, "--rules").map(PathBuf::from);

    let outcome = match run_check(None, over.as_deref(), host, port, path, want_control) {
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
        assert!(script.contains("expected: beefcafe"));
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
}
