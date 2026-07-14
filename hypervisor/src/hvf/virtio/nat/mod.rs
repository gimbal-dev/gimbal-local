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

#[cfg(test)]
mod relay_test;

use device::{FrameDevice, NAT_MTU};
pub use policy::{Decision, EgressPolicy};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::net::NetResponder;

/// Per-socket TCP buffering. 64 KiB each direction is enough for the demo's
/// HTTPS transfers without being wasteful across a handful of flows.
const TCP_BUF: usize = 64 * 1024;
/// How long a host connect may take before the flow is torn down.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

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
    gateway_ip: Ipv4Addr,
    boot: Instant,
}

impl NatResponder {
    /// Build a NAT owning `gateway_ip`/`gateway_mac` and enforcing `policy`.
    pub fn new(gateway_ip: [u8; 4], gateway_mac: [u8; 6], policy: EgressPolicy) -> Self {
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

        Self {
            iface,
            device,
            sockets,
            policy,
            dns,
            listeners: HashMap::new(),
            flows: Vec::new(),
            events: Vec::new(),
            gateway_ip: gw,
            boot,
        }
    }

    /// Take the egress-decision events accumulated since the last drain.
    pub fn drain_events(&mut self) -> Vec<EgressEvent> {
        std::mem::take(&mut self.events)
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
        self.events.push(EgressEvent {
            domain: "tcp",
            target: dst.to_string(),
            allowed,
            rule: decision.rule().to_string(),
        });
        if !allowed {
            return false;
        }
        if self.listeners.contains_key(&dst) {
            return true; // a retransmitted SYN; listener already armed
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
        loop {
            let sock = self.sockets.get_mut::<udp::Socket>(self.dns);
            let (query_bytes, meta) = match sock.recv() {
                Ok((data, meta)) => (data.to_vec(), meta),
                Err(_) => break,
            };
            let Some(query) = dns::parse_query(&query_bytes) else {
                continue;
            };
            let outcome = self.resolve(&query);
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
        self.events.push(EgressEvent {
            domain: "dns",
            target: query.name.clone(),
            allowed,
            rule: decision.rule().to_string(),
        });
        if !allowed {
            return dns::Outcome::Refused;
        }
        match host_resolve_a(&query.name) {
            Some(ips) if !ips.is_empty() => {
                for ip in &ips {
                    self.policy.record_resolution(&query.name, *ip);
                }
                dns::Outcome::Answers(ips)
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
        for idx in 0..self.flows.len() {
            let handle = self.flows[idx].handle;
            // Resolve a pending connect first (may transition the host side).
            self.advance_connect(idx);

            let done = match &mut self.flows[idx].host {
                HostSide::Connecting { .. } => false,
                HostSide::Relaying { .. } => Self::relay(
                    self.sockets.get_mut::<tcp::Socket>(handle),
                    &mut self.flows[idx].host,
                ),
            };
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            if done || (!sock.is_active() && !sock.is_open()) {
                retire.push(idx);
            }
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
    fn relay(sock: &mut tcp::Socket, host: &mut HostSide) -> bool {
        let HostSide::Relaying {
            stream,
            pending,
            host_eof,
        } = host
        else {
            return false;
        };

        // Guest -> host: consume only what the host accepts (backpressure).
        while sock.can_recv() {
            let mut wrote_any = false;
            let res: Result<Result<(), std::io::Error>, tcp::RecvError> = sock.recv(|buf| {
                if buf.is_empty() {
                    return (0, Ok(()));
                }
                match stream.write(buf) {
                    Ok(0) => (0, Err(std::io::ErrorKind::WriteZero.into())),
                    Ok(n) => {
                        wrote_any = true;
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
            if !wrote_any {
                break; // host not writable right now
            }
        }

        // Host -> guest: flush any backlog first, then read more.
        if !pending.is_empty() {
            let sent = sock.send_slice(pending).unwrap_or(0);
            pending.drain(..sent);
        }
        if pending.is_empty() && !*host_eof && sock.can_send() {
            let mut buf = [0u8; 16 * 1024];
            match stream.read(&mut buf) {
                Ok(0) => *host_eof = true,
                Ok(n) => {
                    let sent = sock.send_slice(&buf[..n]).unwrap_or(0);
                    if sent < n {
                        pending.extend_from_slice(&buf[sent..n]);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => *host_eof = true,
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
    fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        // Pre-arm/enforce on a fresh TCP SYN before smoltcp sees it.
        if let Some(dst) = parse_tcp_syn_dst(frame) {
            self.admit_syn(dst);
        }
        self.device.push_from_guest(frame.to_vec());
        self.service()
    }

    fn service(&mut self) -> Vec<Vec<u8>> {
        NatResponder::service(self)
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
    fn denied_syn_arms_no_listener_and_records_event() {
        let policy = EgressPolicy::from_profile("deny", &[], &[], "test");
        let mut nat = NatResponder::new([192, 168, 249, 1], [0x02, 0, 0, 0, 0, 1], policy);
        let dst = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        assert!(!nat.admit_syn(dst), "default-deny refuses the connect");
        assert!(nat.listeners.is_empty(), "no listener armed for a denied dst");
        let events = nat.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain, "tcp");
        assert!(!events[0].allowed);
    }

    #[test]
    fn allowed_syn_arms_a_listener() {
        let mut nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
        );
        let dst = SocketAddrV4::new(Ipv4Addr::new(140, 82, 112, 6), 443);
        assert!(nat.admit_syn(dst));
        assert!(nat.listeners.contains_key(&dst));
        // A retransmitted SYN does not double-arm.
        assert!(nat.admit_syn(dst));
        assert_eq!(nat.listeners.len(), 1);
    }

    #[test]
    fn construction_wires_gateway_and_dns() {
        let nat = NatResponder::new(
            [192, 168, 249, 1],
            [0x02, 0, 0, 0, 0, 1],
            EgressPolicy::allow_all(),
        );
        assert_eq!(nat.gateway_ip, Ipv4Addr::new(192, 168, 249, 1));
        assert_eq!(nat.policy_label(), "allow-all");
    }
}
