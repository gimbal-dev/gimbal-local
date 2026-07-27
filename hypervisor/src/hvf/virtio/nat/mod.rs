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
//! # V0 scope
//!
//! IPv4 TCP + DNS (A records). UDP beyond DNS, IPv6, ICMP to real hosts, and
//! inbound/listen are out of scope for V0 — each is a clearly-denied or
//! answered-empty path, never a silently-broken one.

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
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::mpsc;
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

/// A live guest TCP flow: its smoltcp socket plus the host side.
struct Flow {
    handle: SocketHandle,
    host: HostSide,
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
            events: Vec::new(),
            logged_denials: HashSet::new(),
            gateway_ip: gw,
            boot,
            limits,
            bw_tokens,
            bw_last_refill: boot,
        }
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
            let (tx, rx) = mpsc::channel();
            std::thread::Builder::new()
                .name("chm-nat-connect".into())
                .spawn(move || {
                    let res = TcpStream::connect_timeout(&dst.into(), CONNECT_TIMEOUT).and_then(
                        |s| {
                            s.set_nonblocking(true)?;
                            s.set_nodelay(true).ok();
                            Ok(s)
                        },
                    );
                    let _ = tx.send(res);
                })
                .ok();
            self.flows.push(Flow {
                handle,
                host: HostSide::Connecting { rx },
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

    /// Relay bytes between one smoltcp socket and its host stream. Returns
    /// `true` when the flow is fully done and should be retired.
    /// Relay bytes between one smoltcp socket and its host stream, consuming from
    /// `budget` (the tick's remaining bandwidth allowance; `None` = unlimited).
    /// When the budget is exhausted, bytes are left buffered — TCP backpressure
    /// then slows the guest — rather than dropped. Returns `true` when the flow is
    /// fully done and should be retired.
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
    fn allowed_syn_arms_a_listener() {        let mut nat = NatResponder::new(
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
