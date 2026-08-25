// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! The userspace egress NAT: real outbound networking for a resumed guest that
//! has no tap, bridge, or host route — its only link is the virtio-net
//! [`NetResponder`](super::net::NetResponder) seam.
//!
//! # How it works
//!
//! A [`smoltcp`] TCP/IP stack terminates the guest's flows as if it were the
//! gateway (`192.168.249.1`, the address capture-side cloud-init points the
//! guest at). Using smoltcp's *AnyIP* mode plus a default route back to our own
//! address, the stack accepts connections addressed to **any** destination, so
//! the guest can dial arbitrary hosts. For each guest flow `chm` opens the
//! matching **host** socket and relays bytes in both directions — a
//! connection-proxy NAT. DNS is answered directly: the guest's queries are
//! parsed, resolved through the host resolver, and replied to.
//!
//! # Why this is also the enforcement point
//!
//! Because `chm` is the process that opens every host socket and asks the host
//! resolver every question, the [`EgressPolicy`] is consulted at exactly the two
//! authoritative moments — DNS resolve and TCP connect — and a denial is
//! enforced by simply *not* acting. The guest has no other way off the machine,
//! so default-deny is unbypassable from inside the sandbox. (M28.2 ships the NAT
//! with an allow-all policy; M28.3 threads the real control-plane profile in.)
//!
//! # Ingress: the mirror image
//!
//! V11.0 adds the other direction, for the one case that needs it: a host
//! process (Playwright, `curl`) reaching a port *inside* the guest. It is the
//! same relay run backwards — a loopback [`TcpListener`] whose accepted
//! connections open a smoltcp socket **towards** the guest — so it reuses
//! [`NatResponder::relay`] and lands in the same `flows` vector under the same
//! [`NatLimits`], rather than growing a second datapath. See
//! [`NatResponder::expose`] for the fail-closed, opt-in-per-port contract.
//!
//! # V0 scope
//!
//! IPv4 TCP + DNS (A records). UDP beyond DNS, IPv6 and ICMP to real hosts are
//! out of scope for V0 — each is a clearly-denied or answered-empty path, never
//! a silently-broken one.

mod device;
mod dns;
pub mod policy;
mod reserved;

#[cfg(test)]
mod relay_test;

use device::{FrameDevice, NAT_MTU};
pub use policy::{Decision, EgressPolicy};
pub use reserved::is_reserved_egress_ip;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::net::NetResponder;

/// Per-socket TCP buffering. 64 KiB each direction is enough for the demo's
/// HTTPS transfers without being wasteful across a handful of flows.
const TCP_BUF: usize = 64 * 1024;
/// How much is read from a host socket per attempt. The relay loops until the
/// host blocks or the guest-facing socket is full, so this bounds one syscall
/// rather than one service pass.
const HOST_READ_CHUNK: usize = 16 * 1024;

/// How long a host connect may take before the flow is torn down.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// The address every host ingress listener binds to.
///
/// **Loopback, always.** An exposed guest port is reachable from processes on
/// this Mac and from nowhere else. Binding wider would put a sandbox's innards
/// on the LAN, which is a separate decision nobody has taken — so it is
/// deliberately a constant rather than a flag, because a flag that accepts
/// `0.0.0.0` is how that decision gets taken by accident. The bind and its test
/// read this same constant; neither restates it.
pub const INGRESS_BIND_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The gateway-side source ports ingress flows dial the guest from: the IANA
/// dynamic range, so a guest's own connection tracking sees an ordinary client.
const INGRESS_PORT_LO: u16 = 49152;
const INGRESS_PORT_HI: u16 = 65535;

/// How much burst the bandwidth token bucket allows: one second of the rate, so
/// a short idle period lets a subsequent transfer briefly run at line rate
/// before settling to the sustained cap.
const BW_BURST_SECS: f64 = 1.0;

/// Datapath resource caps enforced by the NAT (M30.6). Separate from the egress
/// *policy* (which decides *whether* a flow is allowed); these bound *how much* an
/// allowed guest may do, so a permitted destination can't be used to exhaust host
/// sockets or saturate the uplink.
#[derive(Debug, Clone, Default)]
pub struct NatLimits {
    /// Maximum concurrent guest TCP flows (`None` = unlimited). A SYN that would
    /// exceed it is refused like a policy denial.
    pub max_connections: Option<usize>,
    /// Maximum sustained throughput in bytes/sec across all flows, both
    /// directions (`None` = unlimited). Enforced by a token bucket that throttles
    /// relaying (TCP backpressure slows the guest) rather than dropping data.
    pub max_bytes_per_sec: Option<u64>,
}

/// An egress decision worth surfacing to the control-plane audit log. `chm`
/// drains these after servicing the device (see [`NatResponder::drain_events`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressEvent {
    /// `"dns"` or `"tcp"`.
    pub domain: &'static str,
    /// The name (DNS) or `ip:port` (TCP) the guest tried to reach.
    pub target: String,
    /// Whether the flow was permitted.
    pub allowed: bool,
    /// The policy rule that decided it.
    pub rule: String,
    /// The label (digest) of the policy that governed this decision. Carried on
    /// the event itself — rather than re-read at audit time — so the durable
    /// record names the exact policy that made *this* call and cannot drift
    /// from it. This is what proves a cloud-issued policy digest is the same
    /// one enforcing the flow on the Mac.
    pub policy: String,
}

/// The host-connection state of one accepted guest TCP flow.
enum HostSide {
    /// A background thread is dialing the destination; the result arrives here.
    Connecting {
        rx: mpsc::Receiver<std::io::Result<TcpStream>>,
    },
    /// Connected: relay bytes. `pending` holds host bytes not yet accepted by
    /// the guest-facing send buffer (backpressure).
    Relaying {
        stream: TcpStream,
        pending: Vec<u8>,
        host_eof: bool,
    },
}

/// A live TCP flow: its smoltcp socket plus the host side.
///
/// One type for both directions. A guest-initiated (egress) flow's smoltcp
/// socket was accepted from a listener and its host stream was dialled; an
/// inbound (ingress) flow is the reverse. Past that difference the relay is the
/// same, which is why there is one `Flow`, one `flows` vector and one
/// [`NatResponder::service_flows`].
struct Flow {
    handle: SocketHandle,
    host: HostSide,
    /// For an ingress flow, the gateway-side source port smoltcp dialled the
    /// guest from; returned to the pool when the flow retires. `None` for a
    /// guest-initiated flow, whose ports the guest chose.
    ingress_port: Option<u16>,
}

/// One explicitly exposed guest port and the host listener that reaches it.
struct Ingress {
    /// The endpoint *inside the guest* accepted connections are relayed to.
    guest: SocketAddrV4,
    /// Bound on [`INGRESS_BIND_ADDR`], port chosen by the OS. Non-blocking, so
    /// accepting is just another thing the service tick does.
    listener: TcpListener,
    host_port: u16,
}

/// What an [`expose`](NatResponder::expose) produced: the loopback port a host
/// process should dial, and the guest endpoint it reaches.
///
/// Returned rather than printed so the caller owns how it is reported — the
/// port is ephemeral and has to reach the user somehow, and only the caller
/// knows whether that is a console line or a JSON field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exposure {
    /// The OS-chosen port on [`INGRESS_BIND_ADDR`].
    pub host_port: u16,
    /// The guest endpoint it forwards to.
    pub guest: SocketAddrV4,
}

impl Exposure {
    /// The one sentence that tells a user which port to dial.
    ///
    /// Lives here rather than at each call site because two entry points arm
    /// ingress -- a cold boot builds its own NAT, a resume gets one back from
    /// the device manager -- and a host port nobody can dial is the same
    /// failure whichever path produced it. Two copies of this sentence would
    /// be free to drift, and the drift would only ever be visible to whoever
    /// was reading the *other* path's output.
    pub fn describe(&self) -> String {
        format!(
            "ingress {}:{} -> guest {} (loopback only)",
            INGRESS_BIND_ADDR, self.host_port, self.guest
        )
    }
}

/// Where an admitted flow should be sent, instead of straight to its origin.
///
/// Carries the destination *and* the bytes to send first, because the NAT has
/// no opinion about — and deliberately no knowledge of — the handover format.
#[derive(Debug, Clone)]
pub struct Divert {
    /// The local address to dial instead of the origin.
    pub addr: SocketAddr,
    /// Written before any guest bytes, so the far end learns the true origin.
    pub preamble: Vec<u8>,
}

/// Consulted once per admitted flow to ask whether it should be diverted.
///
/// This is the whole of the NAT's involvement in interception. It is expressed
/// as a callback rather than a rule list on purpose: matching rules to hosts,
/// and above all *why* a flow is worth diverting, belongs to the layer that
/// holds the credentials. Keeping that out of the hypervisor crate means this
/// code cannot leak a secret it never receives.
pub trait InterceptDecider: Send + Sync + std::fmt::Debug {
    /// Return `Some` to divert, `None` to dial the origin directly.
    ///
    /// `host` is the name the guest resolved to reach `ip`, when it used our
    /// DNS; a guest that dialled a raw IP supplies `None`.
    fn divert(&self, ip: Ipv4Addr, port: u16, host: Option<&str>) -> Option<Divert>;
}

/// The userspace NAT responder.
pub struct NatResponder {
    iface: Interface,
    device: FrameDevice,
    sockets: SocketSet<'static>,
    policy: EgressPolicy,
    dns: SocketHandle,
    /// Listener sockets pre-armed for an allowed destination, keyed by that
    /// destination, awaiting the guest's SYN.
    listeners: HashMap<SocketAddrV4, SocketHandle>,
    flows: Vec<Flow>,
    /// Ports inside the guest a host process was explicitly allowed to reach,
    /// each with its own loopback listener. Empty unless somebody named one.
    ingress: Vec<Ingress>,
    /// Gateway-side source ports currently used by ingress flows, so two
    /// concurrent inbound connections cannot present the guest with the same
    /// four-tuple.
    ingress_ports: HashSet<u16>,
    /// Where the next ingress source-port search starts.
    next_ingress_port: u16,
    events: Vec<EgressEvent>,
    /// Denials already logged to the console, keyed by `"domain target"`, so a
    /// guest retransmitting a blocked SYN doesn't spam the operator.
    logged_denials: HashSet<String>,
    gateway_ip: Ipv4Addr,
    boot: Instant,
    /// Datapath caps (connections + bandwidth).
    limits: NatLimits,
    /// Bandwidth token bucket: available bytes, refilled at `max_bytes_per_sec`.
    bw_tokens: f64,
    bw_last_refill: Instant,
    /// Optional interception hook; `None` means every flow is dialled directly.
    intercept: Option<Arc<dyn InterceptDecider>>,
}

impl NatResponder {
    /// Build a NAT owning `gateway_ip`/`gateway_mac`, enforcing `policy` (what is
    /// allowed) and `limits` (how much an allowed guest may do).
    pub fn new(
        gateway_ip: [u8; 4],
        gateway_mac: [u8; 6],
        policy: EgressPolicy,
        limits: NatLimits,
    ) -> Self {
        let mut device = FrameDevice::default();
        let mac = EthernetAddress(gateway_mac);
        let mut config = Config::new(HardwareAddress::Ethernet(mac));
        config.random_seed = seed();
        let boot = Instant::now();
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));

        let gw = Ipv4Addr::from(gateway_ip);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gw), 24));
        });
        // Default route via ourselves: with AnyIP this makes smoltcp accept
        // packets addressed to arbitrary destinations (they "route locally").
        let _ = iface.routes_mut().add_default_ipv4_route(gw);
        iface.set_any_ip(true);

        let mut sockets = SocketSet::new(Vec::new());
        let dns = sockets.add(new_dns_socket(gw));

        // Start the bucket full (one burst) so the first transfer isn't throttled
        // from a cold start.
        let bw_tokens = limits
            .max_bytes_per_sec
            .map_or(0.0, |r| r as f64 * BW_BURST_SECS);
        Self {
            iface,
            device,
            sockets,
            policy,
            dns,
            listeners: HashMap::new(),
            flows: Vec::new(),
            ingress: Vec::new(),
            ingress_ports: HashSet::new(),
            next_ingress_port: INGRESS_PORT_LO,
            events: Vec::new(),
            logged_denials: HashSet::new(),
            gateway_ip: gw,
            boot,
            limits,
            bw_tokens,
            bw_last_refill: boot,
            intercept: None,
        }
    }

    /// Install (or clear) the interception hook.
    ///
    /// Separate from the constructor because the proxy binds a port and so is
    /// built after the NAT, and because a caller with no proxy must be able to
    /// leave this untouched.
    pub fn set_intercept(&mut self, decider: Option<Arc<dyn InterceptDecider>>) {
        self.intercept = decider;
    }

    /// Take the egress-decision events accumulated since the last drain.
    pub fn drain_events(&mut self) -> Vec<EgressEvent> {
        std::mem::take(&mut self.events)
    }

    /// Log a blocked flow to the console once per unique target — the visible
    /// proof that the control-plane allow-list is being enforced on the Mac.
    fn note_denial(&mut self, domain: &str, target: &str, rule: &str) {
        let key = format!("{domain} {target}");
        if self.logged_denials.insert(key) {
            eprintln!(
                "chm: [egress] DENY {domain} {target} ({rule}) — sandbox policy {}",
                self.policy.label()
            );
        }
    }

    /// The governing policy label (digest or `"allow-all"`).
    pub fn policy_label(&self) -> &str {
        self.policy.label()
    }

    /// The gateway address the NAT presents to the guest.
    pub fn gateway_ip(&self) -> Ipv4Addr {
        self.gateway_ip
    }

    /// Make one TCP port *inside* the guest reachable from this Mac, on a fresh
    /// loopback port the OS chooses, and return the [`Exposure`] describing it.
    ///
    /// This is the whole of the inbound surface, and it is deliberately narrow:
    ///
    /// * **Opt-in, one port at a time.** There is no range form and no wildcard
    ///   form, so a port nobody named has no host listener and there is no code
    ///   path that could dial it. That is the guarantee, and it is structural
    ///   rather than a check somebody could later delete.
    /// * **Loopback only** — see [`INGRESS_BIND_ADDR`].
    /// * **Ephemeral host port**, so two sandboxes exposing the same guest port
    ///   cannot collide, and neither can a sandbox and something already
    ///   running on this Mac.
    /// * **Fails closed.** Port 0, or a guest port already exposed (which host
    ///   port would a caller then use?), is an error rather than a quiet
    ///   no-op or a second listener nobody can tell apart.
    ///
    /// The caller supplies the guest's full address rather than the NAT
    /// deriving it: the guest's IP is a convention held by `chm` (`GUEST_IP`),
    /// and restating it here would be a second copy free to drift.
    pub fn expose(&mut self, guest: SocketAddrV4) -> Result<Exposure, String> {
        if guest.port() == 0 {
            return Err(
                "cannot expose port 0: it is not a port a guest can listen on, \
                 it is the OS's word for \"choose one\""
                    .to_string(),
            );
        }
        if let Some(prev) = self.ingress.iter().find(|i| i.guest == guest) {
            return Err(format!(
                "guest port {} is already exposed on 127.0.0.1:{}; exposing it \
                 twice would give it two host ports and no way to say which one \
                 is meant",
                guest.port(),
                prev.host_port
            ));
        }
        let bind = SocketAddrV4::new(INGRESS_BIND_ADDR, 0);
        let listener = TcpListener::bind(bind)
            .map_err(|e| format!("binding a host port for guest {guest}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("making the ingress listener for {guest} non-blocking: {e}"))?;
        let host_port = listener
            .local_addr()
            .map_err(|e| format!("reading the ingress port for {guest}: {e}"))?
            .port();
        self.ingress.push(Ingress {
            guest,
            listener,
            host_port,
        });
        Ok(Exposure { host_port, guest })
    }

    /// Every exposure currently armed, in the order they were asked for.
    pub fn exposures(&self) -> Vec<Exposure> {
        self.ingress
            .iter()
            .map(|i| Exposure {
                host_port: i.host_port,
                guest: i.guest,
            })
            .collect()
    }

    /// Accept whatever the host ingress listeners have queued and dial each one
    /// at the guest. Non-blocking: a tick with nothing waiting costs one
    /// `accept` per exposure.
    fn accept_ingress(&mut self) {
        if self.ingress.is_empty() {
            return;
        }
        // Collected first because dialling needs `&mut self` while the listener
        // is borrowed from `self.ingress`.
        let mut accepted: Vec<(SocketAddrV4, TcpStream)> = Vec::new();
        for ing in &self.ingress {
            // An error ends this listener's turn: `WouldBlock` is the normal
            // "nothing waiting", and anything else is this listener's problem,
            // not the next one's.
            while let Ok((stream, _peer)) = ing.listener.accept() {
                accepted.push((ing.guest, stream));
            }
        }
        for (guest, stream) in accepted {
            self.dial_guest(guest, stream);
        }
    }

    /// Open a smoltcp socket towards `guest` for an accepted host connection.
    ///
    /// Dropping `stream` on any refusal is what the host client sees as a
    /// closed connection — a fail-closed path with no silent hang.
    fn dial_guest(&mut self, guest: SocketAddrV4, stream: TcpStream) {
        let target = guest.to_string();
        let policy = self.policy.label().to_string();
        // An exposed port is not a way around the datapath caps: an inbound
        // flow occupies a host socket and a smoltcp socket exactly like a
        // guest-initiated one, and is counted with them.
        if let Some(max) = self.limits.max_connections
            && self.flows.len() + self.listeners.len() >= max
        {
            self.events.push(EgressEvent {
                domain: "ingress",
                target: target.clone(),
                allowed: false,
                rule: "connection-limit".to_string(),
                policy,
            });
            self.note_denial("ingress", &target, "connection-limit");
            return;
        }
        let Some(local_port) = self.free_ingress_port() else {
            self.events.push(EgressEvent {
                domain: "ingress",
                target: target.clone(),
                allowed: false,
                rule: "ingress-ports-exhausted".to_string(),
                policy,
            });
            self.note_denial("ingress", &target, "ingress-ports-exhausted");
            return;
        };
        // The relay reads and writes without blocking on every service tick.
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        stream.set_nodelay(true).ok();

        let handle = self.sockets.add(new_tcp_socket());
        let cx = self.iface.context();
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        let remote = (IpAddress::Ipv4(*guest.ip()), guest.port());
        if sock.connect(cx, remote, local_port).is_err() {
            self.sockets.remove(handle);
            self.events.push(EgressEvent {
                domain: "ingress",
                target: target.clone(),
                allowed: false,
                rule: "connect-failed".to_string(),
                policy,
            });
            return;
        }
        // Bound the *connect* only. A guest that never answers (no such
        // listener behind a live stack, or no stack at all) must fail rather
        // than leave the host client waiting forever; but once established this
        // is cleared, because a CDP websocket sitting idle for a minute is
        // healthy, not stalled.
        sock.set_timeout(Some(smoltcp::time::Duration::from_micros(
            CONNECT_TIMEOUT.as_micros() as u64,
        )));
        self.ingress_ports.insert(local_port);
        self.events.push(EgressEvent {
            domain: "ingress",
            target,
            allowed: true,
            rule: "exposed".to_string(),
            policy,
        });
        self.flows.push(Flow {
            handle,
            host: HostSide::Relaying {
                stream,
                pending: Vec::new(),
                host_eof: false,
            },
            ingress_port: Some(local_port),
        });
    }

    /// Take an unused gateway-side source port, or `None` if every port in the
    /// dynamic range is in flight.
    fn free_ingress_port(&mut self) -> Option<u16> {
        let span = (INGRESS_PORT_HI - INGRESS_PORT_LO) as u32 + 1;
        for _ in 0..span {
            let port = self.next_ingress_port;
            self.next_ingress_port = if port == INGRESS_PORT_HI {
                INGRESS_PORT_LO
            } else {
                port + 1
            };
            if !self.ingress_ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.boot.elapsed().as_micros() as i64)
    }

    /// Pre-arm a listener for a guest SYN, enforcing the connect policy. Returns
    /// `false` if the flow is denied (the caller still feeds the frame, so
    /// smoltcp answers with a RST — a clean connection-refused for the guest).
    fn admit_syn(&mut self, dst: SocketAddrV4) -> bool {
        let decision = self.policy.decide_connect(*dst.ip(), dst.port());
        let allowed = decision.is_allow();
        let policy = self.policy.label().to_string();
        self.events.push(EgressEvent {
            domain: "tcp",
            target: dst.to_string(),
            allowed,
            rule: decision.rule().to_string(),
            policy: policy.clone(),
        });
        if !allowed {
            self.note_denial("tcp", &dst.to_string(), decision.rule());
            return false;
        }
        if self.listeners.contains_key(&dst) {
            return true; // a retransmitted SYN; listener already armed
        }
        // Connection cap: a permitted destination may not be used to open an
        // unbounded number of concurrent flows and exhaust host sockets (M30.6).
        if let Some(max) = self.limits.max_connections
            && self.flows.len() + self.listeners.len() >= max
        {
            self.events.push(EgressEvent {
                domain: "tcp",
                target: dst.to_string(),
                allowed: false,
                rule: "connection-limit".to_string(),
                policy,
            });
            self.note_denial("tcp", &dst.to_string(), "connection-limit");
            return false;
        }
        let mut sock = new_tcp_socket();
        // Listen on the exact destination the guest dialed; AnyIP lets smoltcp
        // accept a SYN to this foreign local address.
        let local = smoltcp::wire::IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(*dst.ip())),
            port: dst.port(),
        };
        if sock.listen(local).is_ok() {
            let handle = self.sockets.add(sock);
            self.listeners.insert(dst, handle);
        }
        true
    }

    /// Advance the stack, service DNS, promote accepted listeners, and relay
    /// established flows. Returns frames to inject into the guest's RX queue.
    fn service(&mut self) -> Vec<Vec<u8>> {
        let now = self.now();
        // Refill the bandwidth token bucket for the elapsed wall-clock time.
        if let Some(rate) = self.limits.max_bytes_per_sec {
            let real_now = Instant::now();
            let dt = real_now.duration_since(self.bw_last_refill).as_secs_f64();
            self.bw_last_refill = real_now;
            let cap = rate as f64 * BW_BURST_SECS;
            self.bw_tokens = (self.bw_tokens + rate as f64 * dt).min(cap);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.service_dns();
        self.accept_ingress();
        self.promote_listeners();
        self.service_flows();
        // Poll again so bytes we pushed into sockets are framed for the guest.
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        let mut out = Vec::new();
        while let Some(frame) = self.device.pop_to_guest() {
            out.push(frame);
        }
        out
    }

    /// Answer any pending guest DNS queries under the egress policy.
    fn service_dns(&mut self) {
        let trace = std::env::var_os("CHM_TRACE_NAT").is_some();
        loop {
            let sock = self.sockets.get_mut::<udp::Socket>(self.dns);
            let (query_bytes, meta) = match sock.recv() {
                Ok((data, meta)) => (data.to_vec(), meta),
                Err(_) => break,
            };
            if trace {
                eprintln!(
                    "chm[nat] dns recv {} byte(s) from {:?}",
                    query_bytes.len(),
                    meta.endpoint
                );
            }
            let Some(query) = dns::parse_query(&query_bytes) else {
                if trace {
                    eprintln!("chm[nat] dns parse failed ({} bytes)", query_bytes.len());
                }
                continue;
            };
            let outcome = self.resolve(&query);
            if trace {
                let kind = match &outcome {
                    dns::Outcome::Answers(a) => format!("Answers({a:?})"),
                    dns::Outcome::Refused => "Refused".to_string(),
                    dns::Outcome::NoData => "NoData".to_string(),
                    dns::Outcome::NxDomain => "NxDomain".to_string(),
                };
                eprintln!("chm[nat] dns query {:?} -> {kind}", query.name);
            }
            let reply = dns::build_response(&query, &outcome);
            // Reply from the address the guest asked (its configured resolver).
            let sock = self.sockets.get_mut::<udp::Socket>(self.dns);
            let _ = sock.send_slice(&reply, meta);
        }
    }

    /// Apply the policy to a DNS query and, if permitted, resolve it through the
    /// host. Records resolved addresses so a later connect-by-IP can be matched
    /// to the allowed name.
    fn resolve(&mut self, query: &dns::Query) -> dns::Outcome {
        if query.qtype == dns::QTYPE_AAAA {
            return dns::Outcome::NoData; // v4-only NAT: no AAAA in V0
        }
        if query.qtype != dns::QTYPE_A {
            return dns::Outcome::NoData;
        }
        let decision = self.policy.decide_dns(&query.name);
        let allowed = decision.is_allow();
        let policy = self.policy.label().to_string();
        self.events.push(EgressEvent {
            domain: "dns",
            target: query.name.clone(),
            allowed,
            rule: decision.rule().to_string(),
            policy: policy.clone(),
        });
        if !allowed {
            self.note_denial("dns", &query.name, decision.rule());
            return dns::Outcome::Refused;
        }
        match host_resolve_a(&query.name) {
            Some(ips) if !ips.is_empty() => {
                // Reserved-address guard (M31.1): never hand the guest a
                // host-internal IP, so a rebinding answer (an allow-listed name
                // resolving to 127.0.0.1 / a private IP / the metadata address)
                // is dropped before the guest can ever dial it.
                let allow_local = self.policy.allow_local_egress();
                let public: Vec<Ipv4Addr> = ips
                    .into_iter()
                    .filter(|ip| allow_local || !is_reserved_egress_ip(*ip))
                    .collect();
                if public.is_empty() {
                    self.events.push(EgressEvent {
                        domain: "dns",
                        target: query.name.clone(),
                        allowed: false,
                        rule: "reserved-address".to_string(),
                        policy,
                    });
                    self.note_denial("dns", &query.name, "reserved-address");
                    return dns::Outcome::NoData;
                }
                for ip in &public {
                    self.policy.record_resolution(&query.name, *ip);
                }
                dns::Outcome::Answers(public)
            }
            Some(_) => dns::Outcome::NoData,
            None => dns::Outcome::NxDomain,
        }
    }

    /// Promote listener sockets that smoltcp has accepted into relaying flows by
    /// kicking off the host connection.
    fn promote_listeners(&mut self) {
        let accepted: Vec<(SocketAddrV4, SocketHandle)> = self
            .listeners
            .iter()
            .filter(|&(_, &h)| {
                let s = self.sockets.get_mut::<tcp::Socket>(h);
                s.remote_endpoint().is_some() && s.state() != tcp::State::Listen
            })
            .map(|(dst, h)| (*dst, *h))
            .collect();

        for (dst, handle) in accepted {
            self.listeners.remove(&dst);
            // Ask before dialling. The hostname comes from the same cache the
            // connect policy matched on, so the decision cannot be moved by DNS
            // changing underneath us between admit and connect.
            let divert = self.intercept.as_ref().and_then(|d| {
                let host = self.policy.resolved_host(*dst.ip());
                d.divert(*dst.ip(), dst.port(), host.as_deref())
            });
            if let Some(d) = &divert {
                self.events.push(EgressEvent {
                    domain: "tcp",
                    target: dst.to_string(),
                    allowed: true,
                    rule: format!("divert {}", d.addr),
                    policy: self.policy.label().to_string(),
                });
            }
            let (tx, rx) = mpsc::channel();
            std::thread::Builder::new()
                .name("chm-nat-connect".into())
                .spawn(move || {
                    let target = divert.as_ref().map_or(SocketAddr::from(dst), |d| d.addr);
                    let res = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).and_then(|mut s| {
                        // The preamble goes out on the still-blocking socket:
                        // it is a few dozen bytes to a local listener, and a
                        // partial write here would desynchronise the far end.
                        if let Some(d) = &divert {
                            s.write_all(&d.preamble)?;
                        }
                        s.set_nonblocking(true)?;
                        s.set_nodelay(true).ok();
                        Ok(s)
                    });
                    let _ = tx.send(res);
                })
                .ok();
            self.flows.push(Flow {
                handle,
                host: HostSide::Connecting { rx },
                ingress_port: None,
            });
        }
    }

    /// Drive every established flow: finish pending connects, relay both ways,
    /// and retire closed flows.
    fn service_flows(&mut self) {
        let mut retire: Vec<usize> = Vec::new();
        // This tick's byte budget from the bandwidth bucket (None = unlimited).
        let mut budget: Option<u64> = self
            .limits
            .max_bytes_per_sec
            .map(|_| self.bw_tokens.max(0.0) as u64);
        for idx in 0..self.flows.len() {
            let handle = self.flows[idx].handle;
            // Resolve a pending connect first (may transition the host side).
            self.advance_connect(idx);
            // An established ingress flow no longer needs its connect deadline
            // (see `dial_guest`): from here on, silence is idleness.
            if self.flows[idx].ingress_port.is_some() {
                let sock = self.sockets.get_mut::<tcp::Socket>(handle);
                if sock.state() == tcp::State::Established && sock.timeout().is_some() {
                    sock.set_timeout(None);
                }
            }

            let done = match &mut self.flows[idx].host {
                HostSide::Connecting { .. } => false,
                HostSide::Relaying { .. } => Self::relay(
                    self.sockets.get_mut::<tcp::Socket>(handle),
                    &mut self.flows[idx].host,
                    &mut budget,
                ),
            };
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            if done || (!sock.is_active() && !sock.is_open()) {
                retire.push(idx);
            }
        }
        // Deduct the bytes actually relayed from the bucket.
        if let Some(remaining) = budget {
            self.bw_tokens = remaining as f64;
        }
        // Retire high-to-low so indices stay valid.
        for idx in retire.into_iter().rev() {
            let flow = self.flows.remove(idx);
            if let Some(port) = flow.ingress_port {
                self.ingress_ports.remove(&port);
            }
            let sock = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            sock.abort();
            self.sockets.remove(flow.handle);
        }
    }

    /// If a flow's host connect has completed, transition it to relaying (or
    /// tear down the guest socket on failure).
    fn advance_connect(&mut self, idx: usize) {
        let handle = self.flows[idx].handle;
        let outcome = match &self.flows[idx].host {
            HostSide::Connecting { rx, .. } => match rx.try_recv() {
                Ok(res) => Some(res),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err(std::io::Error::other("connect thread vanished")))
                }
            },
            HostSide::Relaying { .. } => None,
        };
        if let Some(res) = outcome {
            match res {
                Ok(stream) => {
                    self.flows[idx].host = HostSide::Relaying {
                        stream,
                        pending: Vec::new(),
                        host_eof: false,
                    };
                }
                Err(_) => {
                    // Host unreachable/refused: close the guest side.
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
            }
        }
    }

    /// Relay bytes between one smoltcp socket and its host stream, consuming from
    /// `budget` (the tick's remaining bandwidth allowance; `None` = unlimited).
    /// When the budget is exhausted, bytes are left buffered — TCP backpressure
    /// then slows the sender — rather than dropped. Returns `true` when the flow
    /// is fully done and should be retired.
    ///
    /// Direction-agnostic, and that is the point: `sock` is always the
    /// guest-facing side and `stream` always the host-facing one, whichever end
    /// opened the connection. An ingress flow is this same function with the
    /// request arriving on `stream` instead of `sock`.
    fn relay(sock: &mut tcp::Socket, host: &mut HostSide, budget: &mut Option<u64>) -> bool {
        let HostSide::Relaying {
            stream,
            pending,
            host_eof,
        } = host
        else {
            return false;
        };

        // Guest -> host: consume only what the host accepts (backpressure) and
        // only up to this tick's byte budget.
        while sock.can_recv() {
            let cap = match *budget {
                Some(0) => break, // out of budget this tick
                Some(n) => n as usize,
                None => usize::MAX,
            };
            let mut moved = 0usize;
            let res: Result<Result<(), std::io::Error>, tcp::RecvError> = sock.recv(|buf| {
                if buf.is_empty() {
                    return (0, Ok(()));
                }
                let take = buf.len().min(cap);
                if take == 0 {
                    return (0, Ok(()));
                }
                match stream.write(&buf[..take]) {
                    Ok(0) => (0, Err(std::io::ErrorKind::WriteZero.into())),
                    Ok(n) => {
                        moved = n;
                        (n, Ok(()))
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, Ok(())),
                    Err(e) => (0, Err(e)),
                }
            });
            if matches!(res, Ok(Err(_)) | Err(_)) {
                sock.close();
                break;
            }
            if moved == 0 {
                break; // host not writable right now
            }
            if let Some(b) = budget {
                *b = b.saturating_sub(moved as u64);
            }
        }

        // Host -> guest: flush any backlog first (already-read bytes, not counted
        // again), then keep reading while the host has data and the guest-facing
        // socket has room. One read per pass would cap a flow at 16 KiB per
        // service call regardless of how much the host had ready.
        if !pending.is_empty() {
            let sent = sock.send_slice(pending).unwrap_or(0);
            pending.drain(..sent);
        }
        while pending.is_empty() && !*host_eof && sock.can_send() {
            let cap = match *budget {
                Some(0) => 0,
                Some(n) => (n as usize).min(HOST_READ_CHUNK),
                None => HOST_READ_CHUNK,
            };
            if cap == 0 {
                break;
            }
            let mut buf = [0u8; HOST_READ_CHUNK];
            match stream.read(&mut buf[..cap]) {
                Ok(0) => {
                    *host_eof = true;
                    break;
                }
                Ok(n) => {
                    let sent = sock.send_slice(&buf[..n]).unwrap_or(0);
                    if sent < n {
                        pending.extend_from_slice(&buf[sent..n]);
                    }
                    if let Some(b) = budget {
                        *b = b.saturating_sub(n as u64);
                    }
                    // A short read means the host had nothing more ready; going
                    // round again would only earn a `WouldBlock`.
                    if n < cap {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    *host_eof = true;
                    break;
                }
            }
        }

        // If the host has closed and we've flushed everything, close the guest
        // half. The flow retires once smoltcp finishes the teardown.
        if *host_eof && pending.is_empty() {
            sock.close();
        }
        !sock.is_open() && pending.is_empty()
    }
}

impl NetResponder for NatResponder {
    fn accept(&mut self, frame: &[u8]) {
        if std::env::var_os("CHM_TRACE_NAT").is_some() {
            trace_frame("guest->nat", frame);
        }
        // Pre-arm/enforce on a fresh TCP SYN before smoltcp sees it.
        if let Some(dst) = parse_tcp_syn_dst(frame) {
            self.admit_syn(dst);
        }
        self.device.push_from_guest(frame.to_vec());
    }

    fn service(&mut self) -> Vec<Vec<u8>> {
        NatResponder::service(self)
    }

    fn set_intercept(&mut self, decider: Option<Arc<dyn InterceptDecider>>) {
        NatResponder::set_intercept(self, decider);
    }

    fn drain_egress_events(&mut self) -> Vec<EgressEvent> {
        self.drain_events()
    }
}

/// Log a parsed summary of an Ethernet frame for NAT debugging (ethertype, and
/// for IPv4 the protocol + src/dst ip:port). Behind `CHM_TRACE_NAT`.
fn trace_frame(dir: &str, frame: &[u8]) {
    if frame.len() < 14 {
        eprintln!("chm[nat] {dir} short frame ({} bytes)", frame.len());
        return;
    }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    if et == 0x0806 {
        eprintln!("chm[nat] {dir} ARP");
        return;
    }
    if et != 0x0800 || frame.len() < 34 {
        eprintln!("chm[nat] {dir} ethertype {et:#06x}");
        return;
    }
    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let pname = match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "IP",
    };
    if (proto == 6 || proto == 17) && ip.len() >= ihl + 4 {
        let l4 = &ip[ihl..];
        let sp = u16::from_be_bytes([l4[0], l4[1]]);
        let dp = u16::from_be_bytes([l4[2], l4[3]]);
        eprintln!("chm[nat] {dir} {pname} {src}:{sp} -> {dst}:{dp}");
    } else {
        eprintln!("chm[nat] {dir} {pname} {src} -> {dst}");
    }
}

/// Extract the destination of a fresh TCP SYN (SYN set, ACK clear) from an
/// Ethernet/IPv4 frame, or `None` if it isn't one.
fn parse_tcp_syn_dst(frame: &[u8]) -> Option<SocketAddrV4> {
    const ETH: usize = 14;
    if frame.len() < ETH + 20 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return None; // not IPv4
    }
    let ip = &frame[ETH..];
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl + 20 {
        return None;
    }
    if ip[9] != 6 {
        return None; // not TCP
    }
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let tcp = &ip[ihl..];
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if syn && !ack {
        Some(SocketAddrV4::new(dst_ip, dst_port))
    } else {
        None
    }
}

/// Resolve `name` to its IPv4 addresses through the host resolver. `None` on a
/// resolver error (distinct from "resolved to no A records").
fn host_resolve_a(name: &str) -> Option<Vec<Ipv4Addr>> {
    use std::net::ToSocketAddrs;
    match (name, 0u16).to_socket_addrs() {
        Ok(addrs) => Some(
            addrs
                .filter_map(|a| match a {
                    std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                    std::net::SocketAddr::V6(_) => None,
                })
                .collect(),
        ),
        Err(_) => None,
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
    )
}

fn new_dns_socket(_gw: Ipv4Addr) -> udp::Socket<'static> {
    let mut sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16 * 1024]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16 * 1024]),
    );
    // Bind to :53 on any local address so we catch DNS to whatever resolver the
    // guest was configured with (gateway or a public IP via AnyIP).
    sock.bind(smoltcp::wire::IpListenEndpoint { addr: None, port: 53 })
        .expect("bind dns :53");
    sock
}

fn seed() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5eed_1234)
}

const _: () = assert!(NAT_MTU == 1500);

#[cfg(test)]
mod tests {
    use super::*;

    fn syn_frame(dst_ip: [u8; 4], dst_port: u16, ack: bool) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08; // IPv4 ethertype
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[192, 168, 249, 2]); // src guest
        ip[16..20].copy_from_slice(&dst_ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes()); // src port
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 0x50; // data offset 5
        tcp[13] = if ack { 0x12 } else { 0x02 }; // SYN or SYN|ACK
        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        f
    }

    #[test]
    fn parses_a_fresh_syn_destination() {
        let f = syn_frame([140, 82, 112, 6], 443, false);
        let dst = parse_tcp_syn_dst(&f).expect("syn");
        assert_eq!(dst, SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443));
    }

    #[test]
    fn ignores_syn_ack_and_non_tcp() {
        assert!(parse_tcp_syn_dst(&syn_frame([1, 2, 3, 4], 80, true)).is_none());
        let mut arp = vec![0u8; 42];
        arp[12] = 0x08;
        arp[13] = 0x06; // ARP
        assert!(parse_tcp_syn_dst(&arp).is_none());
    }

    #[test]
    fn reserved_dst_is_refused_under_allow_all() {
        // M31.1: even with an allow-all policy, the NAT must not arm a listener
        // for a host-internal destination (loopback / LAN / metadata), so the
        // guest cannot reach the Mac's own networks.
        let mut nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
            NatLimits::default(),
        );
        for reserved in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(192, 168, 0, 10),
        ] {
            let dst = SocketAddrV4::new(reserved, 80);
            assert!(!nat.admit_syn(dst), "{reserved} must be refused under allow-all");
            assert!(!nat.listeners.contains_key(&dst), "no listener armed for {reserved}");
        }
        let denials = nat.drain_events();
        assert!(
            denials.iter().any(|e| e.rule == "reserved-address" && !e.allowed),
            "a reserved-address denial is recorded"
        );
        // A public destination is still admitted.
        let ok = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        assert!(nat.admit_syn(ok), "a public destination is still allowed");
    }

    #[test]
    fn denied_syn_arms_no_listener_and_records_event() {
        let policy = EgressPolicy::from_profile("deny", &[], &[], "test");
        let mut nat =
            NatResponder::new([192, 168, 249, 1], [0x02, 0, 0, 0, 0, 1], policy, NatLimits::default());
        let dst = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        assert!(!nat.admit_syn(dst), "default-deny refuses the connect");
        assert!(nat.listeners.is_empty(), "no listener armed for a denied dst");
        let events = nat.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain, "tcp");
        assert!(!events[0].allowed);
    }

    #[test]
    fn egress_events_name_the_governing_policy() {
        // M28.4: the durable audit record must name the policy that actually
        // made the call, so a denial on the Mac can be tied back to the exact
        // digest the control plane issued. Both enforcement points (DNS resolve
        // and TCP connect) must carry it.
        let policy =
            EgressPolicy::from_profile("deny", &["example.com".to_string()], &[], "sha256:cafe");
        let mut nat =
            NatResponder::new([192, 168, 249, 1], [0x02, 0, 0, 0, 0, 1], policy, NatLimits::default());
        assert!(!nat.admit_syn(SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443)));
        nat.resolve(&dns::Query {
            id: 1,
            recursion_desired: true,
            name: "blocked.example.net".to_string(),
            qtype: dns::QTYPE_A,
            qclass: 1,
        });
        let events = nat.drain_events();
        assert!(events.iter().any(|e| e.domain == "tcp" && !e.allowed));
        assert!(events.iter().any(|e| e.domain == "dns" && !e.allowed));
        for ev in &events {
            assert_eq!(ev.policy, "sha256:cafe", "{} {} names the policy", ev.domain, ev.target);
        }
    }

    #[test]
    fn allowed_syn_arms_a_listener() {
        let mut nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
            NatLimits::default(),
        );
        let dst = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        assert!(nat.admit_syn(dst));
        assert!(nat.listeners.contains_key(&dst));
        // A retransmitted SYN does not double-arm.
        assert!(nat.admit_syn(dst));
        assert_eq!(nat.listeners.len(), 1);
    }

    #[test]
    fn connection_cap_refuses_syn_over_the_limit() {
        let mut nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
            NatLimits {
                max_connections: Some(2),
                max_bytes_per_sec: None,
            },
        );
        let a = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        let b = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 7), 443);
        let c = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 8), 443);
        assert!(nat.admit_syn(a), "first connect under the cap is admitted");
        assert!(nat.admit_syn(b), "second connect at the cap is admitted");
        assert!(!nat.admit_syn(c), "third connect over the cap is refused");
        assert!(!nat.listeners.contains_key(&c), "no listener armed past the cap");
        let events = nat.drain_events();
        let denial = events
            .iter()
            .find(|e| e.rule == "connection-limit")
            .expect("a connection-limit denial is recorded");
        assert!(!denial.allowed);
        // Below the cap again after one flow is dropped: a retransmit of an
        // already-armed listener still succeeds (does not count as new).
        assert!(nat.admit_syn(a), "retransmit of an armed flow is not re-counted");
    }

    #[test]
    fn construction_wires_gateway_and_dns() {
        let nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
            NatLimits::default(),
        );
        assert_eq!(nat.gateway_ip, Ipv4Addr::new(192, 168, 249, 1));
        assert_eq!(nat.policy_label(), "allow-all");
    }
}
