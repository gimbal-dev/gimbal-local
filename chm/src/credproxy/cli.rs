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
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, version};

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

COMMANDS:
    show    What the rules would do, and whether each credential is available.
            Reads no credential values: an `exec` source is never run.
    ca      Print the workspace CA certificate, and how to install it in a guest.
    check   Prove this machine can reach a host through the proxy. Sends a real
            HEAD request; injects only if a rule matches. Use --path to choose
            an endpoint whose answer differs with and without a credential
            (e.g. --path /user on api.github.com) to prove injection worked.

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
        println!(
            r#"{{"configured":true,"origin":{},"rules":[{}]}}"#,
            quote(&resolved.origin),
            rules.join(",")
        );
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

/// The shell block that installs this CA in a Debian/Ubuntu guest and proves it
/// took, ending with the fingerprint so it can be compared against the host's.
fn guest_install_script(pem: &str, fingerprint: &str) -> String {
    format!(
        "set -e\n\
         sudo tee /usr/local/share/ca-certificates/gimbal-proxy.crt >/dev/null <<'GIMBAL_CA_EOF'\n\
         {pem}GIMBAL_CA_EOF\n\
         sudo update-ca-certificates >/dev/null\n\
         echo \"installed: $(openssl x509 -noout -fingerprint -sha256 \\\n\
           -in /usr/local/share/ca-certificates/gimbal-proxy.crt \\\n\
           | tr -d ':' | tr 'A-Z' 'a-z' | sed 's/.*=//')\"\n\
         echo \"expected:  {fingerprint}\"\n"
    )
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
    let over = flag(args, "--rules").map(PathBuf::from);
    let rules = match resolve_rules(None, over.as_deref()) {
        Ok(Some(r)) => r.rules,
        Ok(None) => RuleSet::default(),
        Err(e) => {
            eprintln!("chm proxy check: {e}");
            return ExitCode::FAILURE;
        }
    };

    let Some(addr) = resolve_one(host, port) else {
        eprintln!("chm proxy check: cannot resolve {host}");
        return ExitCode::FAILURE;
    };
    let dest = Destination::new(Some(host.to_string()), Some(addr.ip()), port);
    let disposition = match rules.decide(&dest) {
        Disposition::Inject(rule) => format!("INJECT {} ({})", rule.header, rule.name),
        Disposition::PassThrough(reason) => format!("PASS-THROUGH ({})", reason.as_str()),
    };

    let ca = match ProxyCa::ephemeral() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chm proxy check: ca: {e}");
            return ExitCode::FAILURE;
        }
    };
    let roots = match server::load_roots() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("chm proxy check: host trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    let intercepted = matches!(rules.decide(&dest), Disposition::Inject(_));
    let proxy = match server::start(ProxyConfig {
        rules,
        ca: Arc::clone(&ca),
        roots: Arc::clone(&roots),
    }) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("chm proxy check: start: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("{host}:{port}{path} → {addr}");
    println!("  disposition: {disposition}");

    let status = probe(&proxy, &ca, addr, host, path, intercepted);
    let audit = proxy.audit.recent();
    proxy.stop();
    match status {
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
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("  reachable:   NO — {e}");
            ExitCode::FAILURE
        }
    }
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
}
