// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! The proxy itself: accept a diverted flow, decide what to do with it, and —
//! for an intercepted destination — attach the credential as the request leaves.
//!
//! # Shape of a connection
//!
//! ```text
//!   guest  ──TCP──▶  userspace NAT  ──loopback──▶  proxy  ──TLS──▶  origin
//!                    (decides to divert)          (injects)      (verified)
//! ```
//!
//! The NAT dials the proxy over loopback and states the destination it was
//! about to dial, in a one-line preamble. The proxy then:
//!
//! 1. Asks the rule set what to do with that destination.
//! 2. For a pass-through, relays bytes and never looks at them.
//! 3. For an interception, terminates TLS with a certificate minted for that
//!    destination, rewrites each request head to carry the credential, and opens
//!    its own **fully verified** TLS connection to the origin.
//!
//! # Two properties worth being explicit about
//!
//! * **Upstream verification is never relaxed.** The proxy validates the origin's
//!   certificate against the host's real root store. Interception changes who
//!   the guest trusts; it does not change who the proxy trusts.
//! * **The credential is chosen by the destination, not by the request.** The
//!   guest's `Host` header and SNI never select a rule. Otherwise anything in
//!   the sandbox could address a request at an allowlisted name and have a
//!   credential attached to a call of its choosing.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, version};

use crate::audit::AuditLog;

use super::ca::ProxyCa;
use super::http::{BodyMode, ChunkedScanner, ParseError, RequestHead};
use super::rules::{Destination, Disposition, RuleSet};

/// The preamble the NAT writes when it hands a flow over.
const PREAMBLE_TAG: &str = "GIMBAL-PROXY/1";

/// How long the proxy waits on an idle connection before tearing it down.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long to wait for the origin to accept a TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Plaintext copy buffer. Large enough that a clone of any real repository is
/// not syscall-bound, small enough to be irrelevant to memory.
const COPY_BUF: usize = 32 * 1024;

/// How many audit records are kept for `chm proxy show`.
const AUDIT_RING: usize = 256;

/// One thing the proxy did, in a form that is safe to print.
#[derive(Clone, Debug)]
pub(crate) struct AuditEvent {
    pub(crate) at_unix: u64,
    pub(crate) destination: String,
    /// The rule that matched, or `None` for a pass-through.
    pub(crate) rule: Option<String>,
    pub(crate) detail: String,
    pub(crate) injected: bool,
}

/// A bounded, in-memory record of proxy activity.
///
/// Deliberately not a general log sink: everything written here is constructed
/// from destinations, rule names, and request lines. A credential never reaches
/// it, because no code path passes one in.
///
/// The ring answers "what is this proxy doing right now". `durable` answers
/// "what did it do", which is a different question and the one usually asked
/// after the guest has stopped — at which point the ring is gone with the
/// process. Both are fed from the single [`Audit::record`] below so they cannot
/// drift apart.
#[derive(Default)]
pub(crate) struct Audit {
    events: Mutex<Vec<AuditEvent>>,
    durable: AuditLog,
    pub(crate) injections: AtomicU64,
    pub(crate) passthroughs: AtomicU64,
    pub(crate) failures: AtomicU64,
}

impl Audit {
    fn record(&self, event: AuditEvent) {
        if env::var_os("CHM_PROXY_LOG").is_some() {
            eprintln!(
                "[proxy] t={} {} {} {}",
                event.at_unix,
                event.destination,
                event.rule.as_deref().unwrap_or("-"),
                event.detail
            );
        }
        self.durable.proxy_decision(
            &event.destination,
            if event.injected { "inject" } else { "relay" },
            event.rule.as_deref().unwrap_or("-"),
        );
        let mut events = self.events.lock().expect("audit");
        if events.len() == AUDIT_RING {
            events.remove(0);
        }
        events.push(event);
    }

    pub(crate) fn recent(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("audit").clone()
    }
}

/// Everything the proxy needs to run.
pub(crate) struct ProxyConfig {
    pub(crate) rules: RuleSet,
    pub(crate) ca: Arc<ProxyCa>,
    /// PEM bundle of trust anchors used to verify origins.
    pub(crate) roots: Arc<rustls::RootCertStore>,
    /// Where to persist decisions, so they outlive the process. Defaults to a
    /// disabled log for callers with no workspace (tests, `chm proxy check`).
    pub(crate) audit: AuditLog,
}

/// A running proxy.
pub(crate) struct RunningProxy {
    pub(crate) addr: SocketAddr,
    pub(crate) audit: Arc<Audit>,
    shutdown: Arc<AtomicBool>,
}

impl RunningProxy {
    /// Stops accepting new flows. In-flight connections finish on their own.
    pub(crate) fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop with a throwaway connection.
        let _ = TcpStream::connect(self.addr);
    }
}

/// Loads trust anchors for verifying origins.
///
/// macOS ships a Mozilla-derived bundle at `/etc/ssl/cert.pem`, which is what
/// `curl` and the system OpenSSL already use. Overridable so a workspace can
/// pin a narrower set.
pub(crate) fn load_roots() -> io::Result<Arc<rustls::RootCertStore>> {
    let path = env::var("CHM_PROXY_CA_BUNDLE").unwrap_or_else(|_| "/etc/ssl/cert.pem".to_string());
    let pem = fs::read_to_string(&path).map_err(|e| {
        io::Error::other(format!(
            "could not read trust anchors from {path}: {e}. Set CHM_PROXY_CA_BUNDLE to a PEM bundle."
        ))
    })?;
    let mut store = rustls::RootCertStore::empty();
    let mut rejected = 0usize;
    for der in super::ca::pem_decode_all(&pem, "CERTIFICATE") {
        if store.add(CertificateDer::from(der)).is_err() {
            rejected += 1;
        }
    }
    if store.is_empty() {
        return Err(io::Error::other(format!(
            "{path} yielded no usable trust anchors ({rejected} rejected)"
        )));
    }
    Ok(Arc::new(store))
}

/// Installs the process-wide crypto provider exactly once.
fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Ignores the error: another caller installing first is fine, and there
        // is only one provider compiled in.
        let _ = ring::default_provider().install_default();
    });
}

/// Starts the proxy on loopback.
///
/// The listener is bound to `127.0.0.1` on an ephemeral port and is never
/// reachable from off the host. The guest cannot address it directly either —
/// it only ever arrives here because the NAT chose to divert a flow.
pub(crate) fn start(config: ProxyConfig) -> io::Result<RunningProxy> {
    install_provider();
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))?;
    let addr = listener.local_addr()?;
    let audit = Arc::new(Audit {
        durable: config.audit.clone(),
        ..Audit::default()
    });
    let shutdown = Arc::new(AtomicBool::new(false));

    let config = Arc::new(config);
    let thread_audit = Arc::clone(&audit);
    let thread_shutdown = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("chm-credproxy".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if thread_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                let audit = Arc::clone(&thread_audit);
                let _ = thread::Builder::new()
                    .name("chm-credproxy-conn".into())
                    .spawn(move || {
                        if let Err(e) = serve_one(stream, &config, &audit) {
                            audit.failures.fetch_add(1, Ordering::Relaxed);
                            audit.record(AuditEvent {
                                at_unix: now_unix(),
                                destination: "-".into(),
                                rule: None,
                                detail: format!("connection failed: {e}"),
                                injected: false,
                            });
                        }
                    });
            }
        })?;

    Ok(RunningProxy {
        addr,
        audit,
        shutdown,
    })
}

/// Reads the destination preamble the NAT wrote.
fn read_preamble(stream: &mut TcpStream) -> io::Result<Destination> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::other("connection closed before the preamble"));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 512 {
            return Err(io::Error::other("preamble is too long"));
        }
    }
    stream.set_read_timeout(None)?;

    let text = String::from_utf8(line).map_err(|_| io::Error::other("preamble is not UTF-8"))?;
    let mut parts = text.trim().split(' ');
    if parts.next() != Some(PREAMBLE_TAG) {
        return Err(io::Error::other("preamble tag did not match"));
    }
    let ip: IpAddr = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("preamble has no destination address"))?;
    let port: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("preamble has no destination port"))?;
    let host = match parts.next() {
        Some("-") | None => None,
        Some(h) => Some(h.to_string()),
    };
    Ok(Destination::new(host, Some(ip), port))
}

fn serve_one(mut guest: TcpStream, config: &ProxyConfig, audit: &Arc<Audit>) -> io::Result<()> {
    guest.set_nodelay(true).ok();
    let dest = read_preamble(&mut guest)?;

    match config.rules.decide(&dest) {
        Disposition::PassThrough(reason) => {
            audit.passthroughs.fetch_add(1, Ordering::Relaxed);
            audit.record(AuditEvent {
                at_unix: now_unix(),
                destination: dest.describe(),
                rule: None,
                detail: format!("relayed opaquely ({})", reason.as_str()),
                injected: false,
            });
            relay_opaque(guest, &dest)
        }
        Disposition::Inject(rule) => {
            let outcome = intercept(guest, &dest, &rule, config, audit);
            if outcome.is_err() {
                audit.failures.fetch_add(1, Ordering::Relaxed);
            }
            outcome
        }
    }
}

/// Relays a connection without inspecting it.
///
/// Used for every destination with no rule. The guest's TLS session is end to
/// end with the origin; the proxy is a dumb pipe and could not read it.
fn relay_opaque(guest: TcpStream, dest: &Destination) -> io::Result<()> {
    let addr = SocketAddr::new(
        dest.ip
            .ok_or_else(|| io::Error::other("pass-through needs a destination address"))?,
        dest.port,
    );
    let upstream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    upstream.set_nodelay(true).ok();

    let (g_read, g_write) = (guest.try_clone()?, guest);
    let (u_read, u_write) = (upstream.try_clone()?, upstream);

    // Plain TCP has no shared state between directions, so a thread per
    // direction is both correct and the simplest thing that works.
    let up = thread::Builder::new()
        .name("chm-credproxy-relay".into())
        .spawn(move || {
            let mut r = g_read;
            let mut w = u_write;
            let _ = io::copy(&mut r, &mut w);
            let _ = w.shutdown(Shutdown::Write);
        })?;

    let mut r = u_read;
    let mut w = g_write;
    let _ = io::copy(&mut r, &mut w);
    let _ = w.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

/// Terminates TLS, injects, and forwards to a verified origin.
fn intercept(
    guest_sock: TcpStream,
    dest: &Destination,
    rule: &super::rules::Rule,
    config: &ProxyConfig,
    audit: &Arc<Audit>,
) -> io::Result<()> {
    let name = dest
        .tls_name()
        .ok_or_else(|| io::Error::other("cannot intercept a destination with no name"))?;

    // Resolve the credential before doing any network work, so a missing token
    // becomes one clear error rather than a puzzling 401 from the origin.
    let secret = rule.secret.resolve().map_err(|e| {
        audit.record(AuditEvent {
            at_unix: now_unix(),
            destination: dest.describe(),
            rule: Some(rule.name.clone()),
            detail: format!("no credential available: {e}"),
            injected: false,
        });
        io::Error::other(format!("rule '{}': {e}", rule.name))
    })?;
    let (header_name, header_value) = rule.render(secret.expose());
    drop(secret);

    // Guest-facing TLS, using a certificate minted for this destination.
    //
    // TLS 1.3 only, deliberately, and unlike the origin-facing side below. We
    // are both ends of this handshake in every sense that matters: we mint the
    // certificate, and the peer is a client inside a sandbox we booted. There
    // is no legacy origin to accommodate, so there is nothing to buy by
    // offering 1.2 here.
    let leaf = config.ca.leaf_for(&name)?;
    let mut server_cfg = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf.cert_der.clone()),
                CertificateDer::from(leaf.ca_der.clone()),
            ],
            PrivateKeyDer::Pkcs8(leaf.key_pkcs8.clone().into()),
        )
        .map_err(|e| io::Error::other(format!("could not build a server config: {e}")))?;
    // Only HTTP/1.1. A client that would rather speak HTTP/2 negotiates down,
    // which keeps the proxy out of h2 framing entirely.
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let guest_tls = ServerConnection::new(Arc::new(server_cfg))
        .map_err(|e| io::Error::other(format!("TLS server setup failed: {e}")))?;

    // Origin-facing TLS, fully verified against the host trust store.
    //
    // 1.3 is preferred and 1.2 accepted, because the origin is not ours to
    // choose: measured 2026-07-31, registry.npmjs.org still refuses TLS 1.3,
    // alone among eleven surveyed ecosystem hosts. Refusing to inject there
    // would not make anything safer — the guest would simply reach npm through
    // the pass-through path instead, with the same origin and the same TLS
    // version, only without the credential and without the audit record.
    // rustls's 1.2 is ECDHE + AEAD only: no CBC, no static RSA, no
    // renegotiation, no compression. The negotiated version is recorded per
    // connection so a downgrade is visible rather than merely permitted.
    let mut client_cfg =
        ClientConfig::builder_with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .with_root_certificates(Arc::clone(&config.roots))
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_cfg = Arc::new(client_cfg);
    let server_name = ServerName::try_from(name.clone())
        .map_err(|_| io::Error::other(format!("'{name}' is not a valid TLS server name")))?;
    let up_tls = ClientConnection::new(Arc::clone(&client_cfg), server_name.clone())
        .map_err(|e| io::Error::other(format!("TLS client setup failed: {e}")))?;

    // Connect to the address the NAT already admitted, not to a fresh lookup of
    // the name. Re-resolving here would let DNS move underneath the policy
    // decision that permitted this flow.
    let addr = SocketAddr::new(
        dest.ip
            .ok_or_else(|| io::Error::other("interception needs a destination address"))?,
        dest.port,
    );
    let mut pump = Pump {
        guest_sock,
        guest_tls,
        up_sock: None,
        up_addr: addr,
        up_tls,
        up_cfg: client_cfg,
        up_name: server_name,
        unsent_request: Vec::new(),
        retried: false,
        injector: Injector::new(
            header_name,
            header_value,
            rule.name.clone(),
            dest.describe(),
            dest.tls_name(),
        ),
        audit: Arc::clone(audit),
        destination: dest.describe(),
        rule: rule.name.clone(),
        upstream_version_logged: false,
    };
    pump.run()
}

/// Rewrites each request head on a connection.
struct Injector {
    header: String,
    value: String,
    rule: String,
    destination: String,
    /// The host this connection was intercepted *as*, for comparison against
    /// what each request claims. Never used to choose a credential.
    expected_host: Option<String>,
    phase: Phase,
    chunked: ChunkedScanner,
}

enum Phase {
    Head,
    Body(BodyMode),
}

impl Injector {
    fn new(
        header: String,
        value: String,
        rule: String,
        destination: String,
        expected_host: Option<String>,
    ) -> Self {
        Self {
            header,
            value,
            rule,
            destination,
            expected_host,
            phase: Phase::Head,
            chunked: ChunkedScanner::default(),
        }
    }

    /// Consumes as much of `buf` as it can, appending rewritten bytes to `out`.
    ///
    /// Returns how many input bytes were used. Anything left over is an
    /// incomplete head or body fragment and is retained by the caller.
    fn process(
        &mut self,
        buf: &[u8],
        out: &mut Vec<u8>,
        audit: &Audit,
    ) -> Result<usize, ParseError> {
        let mut used = 0usize;
        loop {
            let rest = &buf[used..];
            if rest.is_empty() {
                return Ok(used);
            }
            match &mut self.phase {
                Phase::Head => {
                    let head = match RequestHead::parse(rest) {
                        Ok(head) => head,
                        Err(ParseError::Incomplete) => return Ok(used),
                        Err(e) => return Err(e),
                    };
                    let mode = head.body_mode()?;
                    out.extend_from_slice(
                        &head.render_with(&[(self.header.clone(), self.value.clone())]),
                    );
                    // The credential was chosen from the destination the NAT
                    // admitted, so a mismatched Host cannot redirect it. It is
                    // still worth recording: a guest asking one host for another
                    // host's content is the shape of an attempt to misuse us.
                    let claimed = head
                        .header("host")
                        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase());
                    let mismatch = match (&self.expected_host, &claimed) {
                        (Some(expected), Some(claimed)) if expected != claimed => {
                            format!(" [Host claims {claimed}]")
                        }
                        _ => String::new(),
                    };
                    // Counted here, where the header actually goes onto the
                    // wire — not where we decided to intercept. A handshake
                    // that never completes must not inflate a security counter,
                    // and a connection carrying three requests really did
                    // attach three credentials.
                    audit.injections.fetch_add(1, Ordering::Relaxed);
                    audit.record(AuditEvent {
                        at_unix: now_unix(),
                        destination: self.destination.clone(),
                        rule: Some(self.rule.clone()),
                        detail: format!(
                            "{} {} — {} attached{mismatch}",
                            head.method, head.target, self.header
                        ),
                        injected: true,
                    });
                    used += head.len;
                    self.chunked = ChunkedScanner::default();
                    self.phase = match mode {
                        BodyMode::Empty => Phase::Head,
                        other => Phase::Body(other),
                    };
                }
                Phase::Body(BodyMode::Length(remaining)) => {
                    let take = (*remaining).min(rest.len() as u64) as usize;
                    out.extend_from_slice(&rest[..take]);
                    used += take;
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.phase = Phase::Head;
                    }
                }
                Phase::Body(BodyMode::Chunked) => {
                    let consumed = self.chunked.consume(rest)?;
                    out.extend_from_slice(&rest[..consumed]);
                    used += consumed;
                    if self.chunked.is_done() {
                        self.phase = Phase::Head;
                    } else if consumed == 0 {
                        // Need more bytes to make progress on a chunk header.
                        return Ok(used);
                    }
                }
                // An empty body means the next bytes are already the next
                // request head, so go straight back to parsing.
                Phase::Body(BodyMode::Empty) => {
                    self.phase = Phase::Head;
                }
            }
        }
    }
}

/// Drives both TLS connections without blocking either direction on the other.
///
/// A thread per direction cannot work here: each direction needs to write to the
/// *other* connection's TLS state, so blocking reads would deadlock behind the
/// lock. A single non-blocking loop over both sockets avoids that, and matches
/// how the NAT already services its flows.
struct Pump {
    guest_sock: TcpStream,
    guest_tls: ServerConnection,
    /// Dialled on demand, not up front. See [`Pump::dial_upstream`].
    up_sock: Option<TcpStream>,
    up_addr: SocketAddr,
    up_tls: ClientConnection,
    /// Kept so the origin connection can be rebuilt for the single retry in
    /// [`Pump::redial_once`]; a `ClientConnection` that has seen a dead socket
    /// cannot be reused.
    up_cfg: Arc<ClientConfig>,
    up_name: ServerName<'static>,
    /// Request bytes handed to rustls before the origin handshake finished, and
    /// therefore not yet delivered to anyone. Dropped the moment the handshake
    /// completes, which is also the moment retrying stops being safe.
    unsent_request: Vec<u8>,
    /// At most one retry per connection, ever.
    retried: bool,
    injector: Injector,
    audit: Arc<Audit>,
    destination: String,
    rule: String,
    /// Set once the upstream handshake completes, so the version it settled on
    /// is recorded exactly once per connection.
    upstream_version_logged: bool,
}

impl Pump {
    /// Opens the origin connection, which is deliberately deferred until there
    /// are request bytes to send.
    ///
    /// Dialling up front is the obvious shape and it loses requests. The guest's
    /// own TLS handshake with us takes seconds on a small sandbox — measured at
    /// 5–10s for busybox on a 512 MiB guest — and an origin connection opened
    /// before that handshake starts spends all of it idle. api.github.com closes
    /// an idle connection that has sent no request in well under ten seconds
    /// (measured 2026-08-08: a 5s guest handshake survived, 7s and 10s did not),
    /// so the request was written into a connection the origin had already shut.
    /// Dialling here means the connection is only ever as old as the request.
    fn dial_upstream(&mut self) -> io::Result<()> {
        if self.up_sock.is_some() {
            return Ok(());
        }
        let sock = TcpStream::connect_timeout(&self.up_addr, CONNECT_TIMEOUT)?;
        sock.set_nodelay(true).ok();
        sock.set_nonblocking(true)?;
        self.up_sock = Some(sock);
        Ok(())
    }

    /// Redial the origin, once, when it closed before any request byte could
    /// have reached it.
    ///
    /// Lazy dialling (#265) shrank the window between `connect` and `write` from
    /// seconds to microseconds, but it cannot close it: an origin may drop a
    /// connection in that gap, and keep-alive reuse — where the connection is
    /// idle by definition between requests — will widen it again.
    ///
    /// **The safety condition is `is_handshaking()`, and it is the whole
    /// argument.** TLS carries no application data until the handshake
    /// completes, so an origin that dropped us mid-handshake provably never saw
    /// a byte of the request. Replaying it is then indistinguishable from a
    /// first attempt whatever the method, and no idempotence assumption is
    /// needed. Once the handshake is up that guarantee is gone, so the retry
    /// stops — this is not a general HTTP retry and must not become one.
    ///
    /// The retry is audited. A silent one hides a flaky origin behind an
    /// occasional latency spike, which is precisely the thing an operator would
    /// want to see.
    fn redial_once(&mut self) -> io::Result<bool> {
        if self.retried || !self.up_tls.is_handshaking() {
            return Ok(false);
        }
        self.retried = true;
        self.up_tls = ClientConnection::new(Arc::clone(&self.up_cfg), self.up_name.clone())
            .map_err(|e| io::Error::other(format!("TLS client setup failed: {e}")))?;
        self.up_sock = None;
        self.dial_upstream()?;
        if !self.unsent_request.is_empty() {
            // Disjoint field borrows: the TLS state and the replay buffer are
            // different fields, so no clone is needed to satisfy the borrow.
            self.up_tls.writer().write_all(&self.unsent_request)?;
        }
        self.audit.record(AuditEvent {
            at_unix: now_unix(),
            destination: self.destination.clone(),
            rule: Some(self.rule.clone()),
            detail: "origin closed before the request was sent; redialled once".to_string(),
            injected: false,
        });
        Ok(true)
    }

    /// Record which TLS version the origin settled on, once. We accept 1.2
    /// upstream because some origins still require it, and permitting something
    /// silently is not the same as permitting it — this is what makes a
    /// downgrade auditable after the fact rather than merely allowed.
    fn note_upstream_version(&mut self) {
        if self.upstream_version_logged || self.up_tls.is_handshaking() {
            return;
        }
        self.upstream_version_logged = true;
        // Application data can now flow, so the request is no longer replayable
        // and the copy held for that purpose must go.
        self.unsent_request = Vec::new();
        let version = self
            .up_tls
            .protocol_version()
            .map_or_else(|| "unknown".to_string(), |v| format!("{v:?}"));
        self.audit.record(AuditEvent {
            at_unix: now_unix(),
            destination: self.destination.clone(),
            rule: Some(self.rule.clone()),
            detail: format!("upstream TLS {version}"),
            injected: false,
        });
    }

    fn run(&mut self) -> io::Result<()> {
        self.guest_sock.set_nonblocking(true)?;

        let mut pending_from_guest: Vec<u8> = Vec::new();
        let mut guest_closed = false;
        let mut up_closed = false;
        let mut guest_shutdown_sent = false;
        let mut up_shutdown_sent = false;
        let mut last_progress = Instant::now();

        loop {
            let mut progressed = false;

            // --- Ciphertext in.
            if !guest_closed && self.guest_tls.wants_read() {
                match self.guest_tls.read_tls(&mut self.guest_sock) {
                    Ok(0) => guest_closed = true,
                    Ok(_) => {
                        self.guest_tls
                            .process_new_packets()
                            .map_err(|e| io::Error::other(format!("guest TLS error: {e}")))?;
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            if let Some(sock) = self.up_sock.as_mut()
                && !up_closed
                && self.up_tls.wants_read()
            {
                match self.up_tls.read_tls(sock) {
                    // An origin that vanishes here has either finished with us or
                    // never started: `redial_once` tells the two apart by whether
                    // the handshake had completed (#267).
                    Ok(0) => {
                        if self.redial_once()? {
                            progressed = true;
                        } else {
                            up_closed = true;
                        }
                    }
                    Ok(_) => {
                        self.up_tls
                            .process_new_packets()
                            .map_err(|e| io::Error::other(format!("origin TLS error: {e}")))?;
                        self.note_upstream_version();
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        // A reset is the other way an origin closes a connection
                        // it had already given up on.
                        if !self.redial_once()? {
                            return Err(e);
                        }
                        progressed = true;
                    }
                }
            }

            // --- Guest plaintext in, rewritten, out to the origin.
            //
            // `Ok(0)` here is not "nothing to read": rustls returns `WouldBlock`
            // for that. It means the peer sent close_notify, so it is the only
            // notice we get that this direction is finished. Treating it as an
            // empty read leaves the *other* side waiting for bytes that can
            // never arrive — see the close propagation below.
            let mut buf = [0u8; COPY_BUF];
            loop {
                match self.guest_tls.reader().read(&mut buf) {
                    Ok(0) => {
                        guest_closed = true;
                        break;
                    }
                    Ok(n) => {
                        pending_from_guest.extend_from_slice(&buf[..n]);
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            if !pending_from_guest.is_empty() {
                let mut rewritten = Vec::with_capacity(pending_from_guest.len() + 256);
                let used = self
                    .injector
                    .process(&pending_from_guest, &mut rewritten, &self.audit)
                    .map_err(|e| io::Error::other(format!("guest sent a bad request: {e}")))?;
                pending_from_guest.drain(..used);
                if !rewritten.is_empty() {
                    self.dial_upstream()?;
                    // Hold a replayable copy only while the handshake is still
                    // running, which is exactly the window in which replay is
                    // provably safe. See `redial_once`.
                    if self.up_tls.is_handshaking() {
                        self.unsent_request.extend_from_slice(&rewritten);
                    }
                    self.up_tls.writer().write_all(&rewritten)?;
                    progressed = true;
                }
                if pending_from_guest.len() > super::http::MAX_HEAD * 4 {
                    return Err(io::Error::other(
                        "guest buffered more unparsed request data than the proxy will hold",
                    ));
                }
            }

            // --- Origin plaintext straight back to the guest, untouched.
            loop {
                match self.up_tls.reader().read(&mut buf) {
                    Ok(0) => {
                        up_closed = true;
                        break;
                    }
                    Ok(n) => {
                        self.guest_tls.writer().write_all(&buf[..n])?;
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            // --- Ciphertext out.
            if let Some(sock) = self.up_sock.as_mut() {
                progressed |= flush(&mut self.up_tls, sock)?;
            }
            progressed |= flush(&mut self.guest_tls, &mut self.guest_sock)?;

            // --- Half-close propagation.
            if guest_closed && !up_shutdown_sent && pending_from_guest.is_empty() {
                if self.up_sock.is_some() {
                    self.up_tls.send_close_notify();
                } else {
                    // The guest finished without ever sending a request, so no
                    // origin connection was opened and there is nothing to
                    // half-close towards — nor anything that could still reply.
                    up_closed = true;
                }
                up_shutdown_sent = true;
                progressed = true;
            }
            if up_closed && !guest_shutdown_sent {
                self.guest_tls.send_close_notify();
                guest_shutdown_sent = true;
                progressed = true;
            }
            // An origin that was never dialled has nothing buffered that can
            // still go out, so its `wants_write` (the ClientHello, generated
            // when the connection was built) must not hold the pump open.
            let up_drained = self.up_sock.is_none() || !self.up_tls.wants_write();
            if guest_closed && up_closed && !self.guest_tls.wants_write() && up_drained {
                let _ = self.guest_sock.shutdown(Shutdown::Both);
                if let Some(sock) = self.up_sock.as_ref() {
                    let _ = sock.shutdown(Shutdown::Both);
                }
                return Ok(());
            }

            if progressed {
                last_progress = Instant::now();
                continue;
            }
            if last_progress.elapsed() > IDLE_TIMEOUT {
                return Err(io::Error::other("connection idle for too long"));
            }
            self.wait(guest_closed, up_closed)?;
        }
    }

    /// Blocks until either socket has something to do.
    fn wait(&mut self, guest_closed: bool, up_closed: bool) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        // A negative fd is ignored by poll(2), which is how an origin that has
        // not been dialled yet takes part without a special case here.
        let up_fd = self.up_sock.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let mut fds = [
            libc::pollfd {
                fd: self.guest_sock.as_raw_fd(),
                events: poll_events(
                    !guest_closed && self.guest_tls.wants_read(),
                    self.guest_tls.wants_write(),
                ),
                revents: 0,
            },
            libc::pollfd {
                fd: up_fd,
                events: if up_fd < 0 {
                    0
                } else {
                    poll_events(
                        !up_closed && self.up_tls.wants_read(),
                        self.up_tls.wants_write(),
                    )
                },
                revents: 0,
            },
        ];
        if fds.iter().all(|f| f.events == 0) {
            // Nothing either side is waiting on and nothing to send: the
            // connection is finished.
            return Err(io::Error::other("connection stalled with nothing to do"));
        }

        // SAFETY: `fds` is a live, correctly sized array of `pollfd` owned by
        // this frame, and both descriptors are owned by `self` for the duration.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
}

fn poll_events(want_read: bool, want_write: bool) -> libc::c_short {
    let mut events = 0;
    if want_read {
        events |= libc::POLLIN;
    }
    if want_write {
        events |= libc::POLLOUT;
    }
    events
}

/// Drains a connection's outgoing ciphertext, tolerating a full socket buffer.
///
/// Generic over the connection data type so the one implementation serves both
/// the guest-facing server connection and the origin-facing client connection.
fn flush<D>(conn: &mut rustls::ConnectionCommon<D>, sock: &mut TcpStream) -> io::Result<bool> {
    let mut wrote = false;
    while conn.wants_write() {
        match conn.write_tls(sock) {
            Ok(0) => break,
            Ok(_) => wrote = true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(wrote)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes the preamble that hands a destination to the proxy.
///
/// Lives here so the format has exactly one definition, shared by the NAT
/// integration and the tests.
pub(crate) fn write_preamble(
    stream: &mut impl Write,
    ip: IpAddr,
    port: u16,
    host: Option<&str>,
) -> io::Result<()> {
    stream.write_all(&preamble_bytes(ip, port, host))
}

/// The preamble as bytes, for a caller that must hand them to someone else to
/// write. The NAT is such a caller: it does the connecting, but the format is
/// ours, so it never has to know what it is sending.
pub(crate) fn preamble_bytes(ip: IpAddr, port: u16, host: Option<&str>) -> Vec<u8> {
    format!("{PREAMBLE_TAG} {ip} {port} {}\n", host.unwrap_or("-")).into_bytes()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    use rustls::RootCertStore;

    use super::*;

    /// A real TLS origin server that records the request heads it is sent.
    ///
    /// Deliberately a genuine rustls server rather than a stub: the whole claim
    /// being tested is that an *origin* sees an authenticated request, so the
    /// thing on the other end has to behave like one.
    struct Origin {
        addr: SocketAddr,
        seen: mpsc::Receiver<String>,
    }

    fn spawn_origin(ca: &Arc<ProxyCa>, name: &str, exchanges: usize) -> Origin {
        spawn_origin_dropping_first(ca, name, exchanges, 0)
    }

    /// An origin that accepts and immediately drops its first `drops`
    /// connections before behaving normally — a deterministic stand-in for one
    /// that closed an idle keep-alive connection in the microseconds between our
    /// `connect` and our first write (#267). No network, no guest boot.
    fn spawn_origin_dropping_first(
        ca: &Arc<ProxyCa>,
        name: &str,
        exchanges: usize,
        drops: usize,
    ) -> Origin {
        install_provider();
        let leaf = ca.leaf_for(name).expect("origin leaf");
        let mut cfg = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(leaf.cert_der.clone()),
                    CertificateDer::from(leaf.ca_der.clone()),
                ],
                PrivateKeyDer::Pkcs8(leaf.key_pkcs8.clone().into()),
            )
            .expect("origin config");
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0)).expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        let (tx, seen) = mpsc::channel();

        std::thread::spawn(move || {
            for _ in 0..drops {
                let Ok((sock, _)) = listener.accept() else {
                    return;
                };
                // Close without reading a byte, and without a TLS alert: the
                // client learns only that the socket is gone.
                let _ = sock.shutdown(Shutdown::Both);
                drop(sock);
            }
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let conn = ServerConnection::new(Arc::clone(&cfg)).expect("origin tls");
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut done = 0usize;
            while done < exchanges {
                match tls.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
                // Serve every complete request currently buffered.
                while let Ok(head) = RequestHead::parse(&buf) {
                    let mode = head.body_mode().expect("framing");
                    let body_len = match mode {
                        BodyMode::Length(n) => n as usize,
                        _ => 0,
                    };
                    if buf.len() < head.len + body_len {
                        break;
                    }
                    let rendered = String::from_utf8_lossy(&buf[..head.len]).to_string();
                    buf.drain(..head.len + body_len);
                    let _ = tx.send(rendered);
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    let _ = tls.flush();
                    done += 1;
                    if done == exchanges {
                        break;
                    }
                }
            }
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
        });

        Origin { addr, seen }
    }

    pub(crate) fn roots_for(ca: &Arc<ProxyCa>) -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        store
            .add(CertificateDer::from(ca.cert_der().to_vec()))
            .expect("add root");
        Arc::new(store)
    }

    /// A guest-side client: dials the proxy, states its destination, then speaks
    /// ordinary TLS to what it believes is the origin.
    pub(crate) fn guest_request(
        proxy: &RunningProxy,
        trust: &Arc<ProxyCa>,
        origin_addr: SocketAddr,
        name: &str,
        requests: &[&str],
    ) -> io::Result<String> {
        guest_request_trusting(proxy, roots_for(trust), origin_addr, name, requests)
    }

    /// The same guest, but choosing for itself whose certificates it will accept.
    ///
    /// Which trust store a request needs is itself an assertion: an intercepted
    /// flow only verifies against the proxy CA, a relayed one only against the
    /// public roots.
    pub(crate) fn guest_request_trusting(
        proxy: &RunningProxy,
        roots: Arc<RootCertStore>,
        origin_addr: SocketAddr,
        name: &str,
        requests: &[&str],
    ) -> io::Result<String> {
        let mut sock = TcpStream::connect(proxy.addr)?;
        write_preamble(&mut sock, origin_addr.ip(), origin_addr.port(), Some(name))?;

        let mut cfg = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from(name.to_string()).expect("name"),
        )
        .map_err(io::Error::other)?;

        let mut tls = rustls::StreamOwned::new(conn, sock);
        let mut replies = String::new();
        for req in requests {
            tls.write_all(req.as_bytes())?;
            tls.flush()?;
            let mut buf = [0u8; 4096];
            let n = tls.read(&mut buf)?;
            replies.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        Ok(replies)
    }

    fn start_proxy(rules_json: &str, origin_ca: &Arc<ProxyCa>) -> (RunningProxy, Arc<ProxyCa>) {
        let proxy_ca = ProxyCa::ephemeral().expect("proxy ca");
        let proxy = start(ProxyConfig {
            rules: RuleSet::parse(rules_json).expect("rules"),
            ca: Arc::clone(&proxy_ca),
            roots: roots_for(origin_ca),
            audit: AuditLog::default(),
        })
        .expect("proxy starts");
        (proxy, proxy_ca)
    }

    const TOKEN: &str = "ghp_thisisthesecretthatmustnotreachtheguest";

    /// Writes the credential to a per-test file.
    ///
    /// A file rather than an environment variable on purpose: `set_var` mutates
    /// process-global state that every other test in this binary can observe,
    /// and these tests run in parallel.
    fn secret_file(tag: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("chm-proxy-secret-{}-{tag}", std::process::id()));
        std::fs::write(&path, TOKEN).expect("write secret");
        path.to_string_lossy().replace('\\', "\\\\")
    }

    /// Builds a guest-side TLS client that has stated its destination but has
    /// not yet spoken. Separate from [`guest_request`] because these tests care
    /// about *when* things happen, not just the reply.
    fn guest_connection(
        proxy: &RunningProxy,
        trust: &Arc<ProxyCa>,
        origin_addr: SocketAddr,
        name: &str,
    ) -> (ClientConnection, TcpStream) {
        let mut sock = TcpStream::connect(proxy.addr).expect("dial proxy");
        write_preamble(&mut sock, origin_addr.ip(), origin_addr.port(), Some(name))
            .expect("preamble");
        let mut cfg = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_root_certificates(roots_for(trust))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from(name.to_string()).expect("name"),
        )
        .expect("client tls");
        (conn, sock)
    }

    /// An origin that closes cleanly must leave the guest able to tell.
    ///
    /// A client that asked for `Connection: close` — busybox wget does, and it
    /// is what a container image ships — waits for the connection to end. rustls
    /// reports a received close_notify as `Ok(0)` from the plaintext reader and
    /// `WouldBlock` when it is merely out of data, so reading `Ok(0)` as "no
    /// bytes just now" silently drops the only notice that the exchange is over.
    /// The guest then waits for its own timeout: measured 25s in issue #253.
    #[test]
    fn a_clean_origin_close_reaches_the_guest() {
        let secret = secret_file("close");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "origin.test", 1);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"r","hosts":["origin.test"],
                "ports":[{}],"scheme":"bearer","file":"{secret}"}}]}}"#,
            origin.addr.port()
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let (conn, sock) = guest_connection(&proxy, &proxy_ca, origin.addr, "origin.test");
        // Bounded, so a guest left waiting forever fails the test rather than
        // hanging the suite. Generous enough that a slow machine is not the
        // thing being measured.
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("read timeout");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"GET / HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
            .expect("write");
        tls.flush().expect("flush");

        let mut reply = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => reply.extend_from_slice(&chunk[..n]),
                Err(e) => panic!(
                    "the guest must be told the origin closed, instead it waited: {e} \
                     (read so far: {:?})",
                    String::from_utf8_lossy(&reply)
                ),
            }
        }
        assert!(
            String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200"),
            "the reply itself must still arrive: {:?}",
            String::from_utf8_lossy(&reply)
        );
        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("the origin should have received the request");
        assert!(seen.contains("Connection: close"), "{seen}");
        proxy.stop();
    }

    /// The origin connection must not exist before there is something to send.
    ///
    /// Dialling it when the guest connects leaves it idle for the whole
    /// guest-facing handshake — seconds on a small sandbox — and an origin is
    /// entitled to close a connection that has asked for nothing. Measured
    /// against api.github.com on 2026-08-08: a 5s guest handshake survived,
    /// 7s and 10s did not, and the request was then written into a shut
    /// connection.
    #[test]
    fn the_origin_is_not_dialled_before_there_is_a_request() {
        let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(500));
            }
        });

        let secret = secret_file("lazy");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"r","hosts":["origin.test"],
                "ports":[{}],"scheme":"bearer","file":"{secret}"}}]}}"#,
            addr.port()
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let (mut conn, mut sock) = guest_connection(&proxy, &proxy_ca, addr, "origin.test");
        conn.complete_io(&mut sock).expect("guest handshake");
        assert!(
            !conn.is_handshaking(),
            "the guest-facing handshake must have finished, or this proves nothing"
        );
        // Long enough that a proxy which dials up front would have done so.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the origin was dialled before the guest had sent anything"
        );
        proxy.stop();
    }

    /// #267: an origin that closes between our `connect` and our first write
    /// costs the guest a request that was never delivered. Lazy dialling (#265)
    /// made that window microseconds wide instead of seconds, but keep-alive
    /// reuse will widen it again, so the request has to survive it.
    ///
    /// The retry is safe *only* because it happens with the origin handshake
    /// still incomplete: TLS carries no application data before then, so the
    /// dropped origin provably saw nothing and a replay cannot duplicate a side
    /// effect — no idempotence assumption required.
    #[test]
    fn a_request_survives_an_origin_that_closed_before_it_arrived() {
        let secret = secret_file("redial");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin_dropping_first(&origin_ca, "upstream.test", 1, 1);

        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"scheme":"bearer","file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let request = "GET /retry HTTP/1.1\r\nHost: upstream.test\r\n\r\n";
        let reply = guest_request(&proxy, &proxy_ca, origin.addr, "upstream.test", &[request])
            .expect("the request must survive the first origin dropping it");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "reply was {reply:?}");

        // Delivered exactly once, not twice: the replay went to a connection
        // that had never seen the request.
        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("origin should have received the replayed request");
        assert!(seen.contains("GET /retry HTTP/1.1"), "{seen}");
        assert!(
            origin.seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "the request was delivered more than once"
        );

        // A silent retry hides a flaky origin.
        let recorded = proxy.audit.recent();
        assert!(
            recorded.iter().any(|e| e.detail.contains("redialled once")),
            "the retry was not audited: {recorded:?}"
        );
        proxy.stop();
    }

    #[test]
    fn the_origin_sees_a_credential_the_guest_never_sent() {
        let secret = secret_file("inject");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 1);

        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"scheme":"bearer","file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        // The guest sends no credential at all.
        let request =
            "GET /orgs/acme/repos HTTP/1.1\r\nHost: upstream.test\r\nUser-Agent: agent/1\r\n\r\n";
        let reply = guest_request(&proxy, &proxy_ca, origin.addr, "upstream.test", &[request])
            .expect("request should succeed");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "reply was {reply:?}");

        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("origin should have received a request");
        assert!(
            seen.contains(&format!("Authorization: Bearer {TOKEN}")),
            "origin did not see the injected credential:\n{seen}"
        );
        // Everything else about the request survived.
        assert!(seen.contains("GET /orgs/acme/repos HTTP/1.1"), "{seen}");
        assert!(seen.contains("User-Agent: agent/1"), "{seen}");

        assert_eq!(proxy.audit.injections.load(Ordering::Relaxed), 1);
        let recorded = proxy.audit.recent();
        assert!(
            recorded
                .iter()
                .any(|e| e.injected && e.detail.contains("/orgs/acme/repos")),
            "audit missed the injection: {recorded:?}"
        );
        assert!(
            !format!("{recorded:?}").contains(TOKEN),
            "the audit log leaked the credential"
        );
        proxy.stop();
    }

    #[test]
    fn a_placeholder_from_the_guest_is_replaced_not_appended() {
        let secret = secret_file("placeholder");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 1);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"scheme":"basic","file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let request =
            "GET / HTTP/1.1\r\nHost: upstream.test\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\n";
        guest_request(&proxy, &proxy_ca, origin.addr, "upstream.test", &[request])
            .expect("request");

        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("request");
        assert!(
            !seen.contains("PLACEHOLDER"),
            "guest placeholder survived:\n{seen}"
        );
        assert_eq!(
            seen.matches("uthorization:").count(),
            1,
            "duplicate auth header:\n{seen}"
        );
        let expected = super::super::base64::encode(format!("x-access-token:{TOKEN}").as_bytes());
        assert!(
            seen.contains(&format!("Authorization: Basic {expected}")),
            "{seen}"
        );
        proxy.stop();
    }

    #[test]
    fn an_unlisted_destination_is_relayed_without_interception() {
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "elsewhere.test", 1);
        // A rule exists, but for a different host.
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"other","hosts":["upstream.test"],
                "ports":[{}],"file":"/nonexistent/chm/unused"}}]}}"#,
            origin.addr.port()
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        // Trusting only the ORIGIN's CA must work, which is only possible if the
        // origin's own certificate reached the client untouched.
        let reply = guest_request(
            &proxy,
            &origin_ca,
            origin.addr,
            "elsewhere.test",
            &["GET / HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"],
        )
        .expect("pass-through should succeed end to end");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply:?}");

        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("request");
        assert!(
            !seen.contains("Authorization"),
            "nothing should be injected:\n{seen}"
        );
        assert_eq!(proxy.audit.injections.load(Ordering::Relaxed), 0);
        assert_eq!(proxy.audit.passthroughs.load(Ordering::Relaxed), 1);

        // And the converse: trusting only the PROXY's CA must fail, because no
        // certificate was ever minted for this destination.
        let origin2 = spawn_origin(&origin_ca, "elsewhere.test", 1);
        let intercepted = guest_request(
            &proxy,
            &proxy_ca,
            origin2.addr,
            "elsewhere.test",
            &["GET / HTTP/1.1\r\nHost: elsewhere.test\r\n\r\n"],
        );
        assert!(
            intercepted.is_err(),
            "a pass-through destination must not present a proxy certificate"
        );
        proxy.stop();
    }

    #[test]
    fn every_request_on_a_reused_connection_is_injected() {
        let secret = secret_file("keepalive");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 3);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        // A GET, then a POST with a body, then another GET — all on one
        // connection. The POST is the interesting one: if body framing were
        // wrong, the third request head would be misparsed.
        let requests = [
            "GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            "POST /two HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 11\r\n\r\nhello world",
            "GET /three HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ];
        guest_request(&proxy, &proxy_ca, origin.addr, "upstream.test", &requests)
            .expect("all three should succeed");

        let mut targets = Vec::new();
        for _ in 0..3 {
            let seen = origin
                .seen
                .recv_timeout(Duration::from_secs(10))
                .expect("three requests should arrive");
            assert!(
                seen.contains(&format!("Authorization: Bearer {TOKEN}")),
                "a request on the reused connection was not injected:\n{seen}"
            );
            targets.push(seen.lines().next().unwrap_or("").to_string());
        }
        assert!(targets[0].contains("/one"), "{targets:?}");
        assert!(targets[1].contains("/two"), "{targets:?}");
        assert!(targets[2].contains("/three"), "{targets:?}");
        // Three, not one: the counter measures credentials attached, not
        // connections intercepted. Keep-alive is exactly the case where those
        // two numbers diverge, and the attached count is the honest one.
        assert_eq!(
            proxy.audit.injections.load(Ordering::Relaxed),
            3,
            "three requests, three attachments"
        );
        proxy.stop();
    }

    #[test]
    fn a_missing_credential_fails_the_connection_rather_than_going_out_unauthenticated() {
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 1);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"file":"/nonexistent/chm/absent-token"}}]}}"#,
            origin.addr.port()
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let result = guest_request(
            &proxy,
            &proxy_ca,
            origin.addr,
            "upstream.test",
            &["GET / HTTP/1.1\r\nHost: upstream.test\r\n\r\n"],
        );
        assert!(
            result.is_err(),
            "the request must not silently go out unauthenticated"
        );
        assert!(
            origin
                .seen
                .recv_timeout(Duration::from_millis(500))
                .is_err(),
            "nothing should have reached the origin"
        );

        let recorded = proxy.audit.recent();
        assert!(
            recorded
                .iter()
                .any(|e| e.detail.contains("no credential available")),
            "the failure should be explained in the audit log: {recorded:?}"
        );
        proxy.stop();
    }

    #[test]
    fn the_guest_facing_leg_refuses_tls_1_2() {
        // The workspace enables rustls's `tls12` feature so the *upstream* leg
        // can reach origins that still require it. That must not leak into the
        // leg we control on both ends, and a Cargo feature is a poor place for
        // a security property to live — so assert it where it is decided.
        let secret = secret_file("guestleg");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 0);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(proxy_ca.cert_der().to_vec()))
            .expect("trust proxy ca");
        let mut cfg = ClientConfig::builder_with_protocol_versions(&[&version::TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from("upstream.test".to_string()).expect("name"),
        )
        .expect("client");
        let mut sock = TcpStream::connect(proxy.addr).expect("dial");
        write_preamble(
            &mut sock,
            origin.addr.ip(),
            origin.addr.port(),
            Some("upstream.test"),
        )
        .expect("preamble");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        // Assert the consequence rather than the wording: rustls may surface the
        // refusal as a version alert or as an EOF depending on which side gets
        // to speak first, but either way no request reaches the origin and no
        // credential is ever attached.
        let outcome = tls
            .write_all(b"GET / HTTP/1.1\r\nHost: upstream.test\r\n\r\n")
            .and_then(|()| tls.flush())
            .and_then(|()| {
                let mut buf = [0u8; 64];
                tls.read(&mut buf).map(|_| ())
            });
        assert!(
            outcome.is_err(),
            "a TLS 1.2 client must not complete a handshake with us"
        );
        assert_eq!(
            proxy.audit.injections.load(Ordering::Relaxed),
            0,
            "no credential may be attached to a handshake that never completed"
        );
        assert!(
            origin
                .seen
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "the origin must never see a request from a refused handshake"
        );
        proxy.stop();
    }

    #[test]
    fn a_request_that_lies_about_its_host_is_still_signed_for_the_real_one() {
        // The complement of the test below: here the destination *is*
        // intercepted, and the guest lies inside the TLS session instead. The
        // credential must still be the one for the destination — and the lie
        // must be visible in the audit trail, because a guest asking one host
        // for another host's content is worth being able to see after the fact.
        let secret = secret_file("hostlie");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "upstream.test", 1);
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let _ = guest_request(
            &proxy,
            &proxy_ca,
            origin.addr,
            "upstream.test",
            &["GET /secrets HTTP/1.1\r\nHost: victim.example.com\r\n\r\n"],
        );

        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("request");
        assert!(
            seen.contains(TOKEN),
            "the destination's own credential should still be attached:\n{seen}"
        );
        let audit = proxy.audit.recent();
        assert!(
            audit
                .iter()
                .any(|e| e.injected && e.detail.contains("Host claims victim.example.com")),
            "the mismatch must be recorded: {audit:?}"
        );
        proxy.stop();
    }

    #[test]
    fn the_guest_cannot_pick_the_credential_with_its_host_header() {
        let secret = secret_file("spoof");
        let origin_ca = ProxyCa::ephemeral().expect("origin ca");
        let origin = spawn_origin(&origin_ca, "attacker.test", 1);
        // The rule names upstream.test. The guest connects to a different
        // destination but claims to be upstream.test in its Host header.
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"upstream","hosts":["upstream.test"],
                "ports":[{}],"file":"{}"}}]}}"#,
            origin.addr.port(),
            secret
        );
        let (proxy, proxy_ca) = start_proxy(&rules, &origin_ca);

        let _ = guest_request(
            &proxy,
            &origin_ca,
            origin.addr,
            "attacker.test",
            &["GET / HTTP/1.1\r\nHost: upstream.test\r\n\r\n"],
        );

        let seen = origin
            .seen
            .recv_timeout(Duration::from_secs(10))
            .expect("request");
        assert!(
            !seen.contains(TOKEN),
            "a forged Host header pulled the credential out:\n{seen}"
        );
        assert_eq!(proxy.audit.injections.load(Ordering::Relaxed), 0);
        let _ = proxy_ca;
        proxy.stop();
    }

    #[test]
    fn preamble_round_trips() {
        let mut buf = Vec::new();
        write_preamble(
            &mut buf,
            "203.0.113.5".parse().unwrap(),
            443,
            Some("a.example.com"),
        )
        .unwrap();
        assert_eq!(buf, b"GIMBAL-PROXY/1 203.0.113.5 443 a.example.com\n");
        buf.clear();
        write_preamble(&mut buf, "203.0.113.5".parse().unwrap(), 443, None).unwrap();
        assert_eq!(buf, b"GIMBAL-PROXY/1 203.0.113.5 443 -\n");
    }
}

/// Checks against real hosts on the public internet.
///
/// Ignored by default: they need working DNS and egress, so they are not part of
/// the normal suite. They exist because the in-process tests share our own CA
/// code on both sides, and only a real origin proves the parts that cannot be
/// faked — a genuine certificate chain validated against the host trust store,
/// a real ALPN negotiation, and a real server's opinion of our request.
///
/// Run with: `cargo test -p gimbal-local --bins -- --ignored --nocapture live_`
#[cfg(test)]
mod live_tests {
    use std::net::ToSocketAddrs;

    use super::tests::*;
    use super::*;

    fn resolve(host: &str) -> Option<SocketAddr> {
        (host, 443).to_socket_addrs().ok()?.find(|a| a.is_ipv4())
    }

    #[test]
    #[ignore = "needs public internet egress"]
    fn live_injection_works_against_a_tls_1_2_only_origin() {
        // registry.npmjs.org was, when measured on 2026-07-31, the only host of
        // eleven surveyed ecosystem origins that still refuses TLS 1.3 — and it
        // is the one a coding agent needs most. This is the regression test for
        // that: it is a live assertion about someone else's server, so if npm
        // ever enables 1.3 this keeps passing, and if we ever drop `tls12` it
        // fails immediately and for the right reason.
        let host = "registry.npmjs.org";
        let Some(addr) = resolve(host) else {
            eprintln!("skipping: cannot resolve {host}");
            return;
        };
        let secret = std::env::temp_dir().join(format!("chm-live-npm-{}", std::process::id()));
        std::fs::write(&secret, "not-a-real-token").expect("write");
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"npm","hosts":["{host}"],"file":"{}"}}]}}"#,
            secret.display()
        );
        let proxy_ca = ProxyCa::ephemeral().expect("ca");
        let proxy = start(ProxyConfig {
            rules: RuleSet::parse(&rules).expect("rules"),
            ca: Arc::clone(&proxy_ca),
            roots: load_roots().expect("host trust store"),
            audit: AuditLog::default(),
        })
        .expect("proxy");

        let reply = guest_request(
            &proxy,
            &proxy_ca,
            addr,
            host,
            &[&format!(
                "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gimbal-local-test\r\nConnection: close\r\n\r\n"
            )],
        )
        .expect("a TLS 1.2 origin must still be reachable through the proxy");
        assert!(
            reply.starts_with("HTTP/1.1 2"),
            "expected a 2xx from {host}, got: {}",
            reply.lines().next().unwrap_or("(empty)")
        );
        let audit = proxy.audit.recent();
        assert!(
            audit.iter().any(|e| e.detail.starts_with("upstream TLS")),
            "the negotiated upstream version must be recorded: {audit:?}"
        );
        for ev in &audit {
            println!("  {}", ev.detail);
        }
        let _ = std::fs::remove_file(&secret);
        proxy.stop();
    }

    #[test]
    #[ignore = "needs public internet egress"]
    fn live_injection_reaches_a_real_origin() {
        let host = "api.github.com";
        let Some(addr) = resolve(host) else {
            eprintln!("skipping: cannot resolve {host}");
            return;
        };
        // `/zen` answers 200 to an anonymous request and 401 to one carrying a
        // credential it rejects. That difference is the whole experiment: the
        // guest sends no credential either way, so a 401 can only mean the proxy
        // attached one on the way out.
        let request = format!(
            "GET /zen HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gimbal-local-test\r\nConnection: close\r\n\r\n"
        );

        // Control: same proxy, same code path, no rule for this host.
        let control_ca = ProxyCa::ephemeral().expect("ca");
        let _ = &control_ca;
        let control = start(ProxyConfig {
            rules: RuleSet::default(),
            ca: Arc::clone(&control_ca),
            roots: load_roots().expect("host trust store"),
            audit: AuditLog::default(),
        })
        .expect("proxy");
        let anonymous = guest_request_trusting(
            &control,
            load_roots().expect("roots"),
            addr,
            host,
            &[&request],
        )
        .expect("control request should reach GitHub");
        println!(
            "  control (no rule):  {}",
            anonymous.lines().next().unwrap_or("")
        );
        assert!(
            anonymous.starts_with("HTTP/1.1 200"),
            "control should be anonymous and succeed, got:\n{anonymous}"
        );
        control.stop();

        // Experiment: a rule for this host, with a deliberately invalid token.
        // Nothing secret is sent anywhere — the value is a literal placeholder.
        let secret = std::env::temp_dir().join(format!("chm-live-{}", std::process::id()));
        std::fs::write(&secret, "not-a-real-token").expect("write");
        let rules = format!(
            r#"{{"version":1,"rules":[{{"name":"gh","hosts":["{host}"],
                "scheme":"bearer","file":"{}"}}]}}"#,
            secret.display()
        );
        let proxy_ca = ProxyCa::ephemeral().expect("ca");
        let proxy = start(ProxyConfig {
            rules: RuleSet::parse(&rules).expect("rules"),
            ca: Arc::clone(&proxy_ca),
            roots: load_roots().expect("host trust store"),
            audit: AuditLog::default(),
        })
        .expect("proxy");

        let injected = guest_request(&proxy, &proxy_ca, addr, host, &[&request])
            .expect("the request should reach GitHub");
        println!(
            "  with injection:     {}",
            injected.lines().next().unwrap_or("")
        );
        assert!(
            injected.starts_with("HTTP/1.1 401"),
            "the same request that was anonymous above must now carry a credential, got:\n{injected}"
        );
        assert_eq!(proxy.audit.injections.load(Ordering::Relaxed), 1);

        let _ = std::fs::remove_file(&secret);
        proxy.stop();
    }

    #[test]
    #[ignore = "needs public internet egress"]
    fn live_passthrough_preserves_the_real_certificate() {
        let host = "api.github.com";
        let Some(addr) = resolve(host) else {
            eprintln!("skipping: cannot resolve {host}");
            return;
        };
        // No rules at all, so this destination is relayed opaquely.
        let proxy_ca = ProxyCa::ephemeral().expect("ca");
        let proxy = start(ProxyConfig {
            rules: RuleSet::default(),
            ca: Arc::clone(&proxy_ca),
            roots: load_roots().expect("host trust store"),
            audit: AuditLog::default(),
        })
        .expect("proxy");

        // The client trusts only the *public* roots. Success therefore proves it
        // received GitHub's own certificate, not one the proxy minted.
        let mut cfg = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_root_certificates(load_roots().expect("roots"))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = ClientConnection::new(
            Arc::new(cfg),
            ServerName::try_from(host.to_string()).unwrap(),
        )
        .expect("client");

        let mut sock = TcpStream::connect(proxy.addr).expect("dial proxy");
        write_preamble(&mut sock, addr.ip(), addr.port(), Some(host)).expect("preamble");
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(
            format!("GET /zen HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gimbal-local-test\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write");
        let mut buf = [0u8; 2048];
        let n = tls.read(&mut buf).expect("read");
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        println!("passthrough status: {}", reply.lines().next().unwrap_or(""));
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert_eq!(proxy.audit.injections.load(Ordering::Relaxed), 0);
        proxy.stop();
    }
}
