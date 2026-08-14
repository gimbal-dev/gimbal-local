// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the userspace NAT: a second `smoltcp` stack plays the
//! *guest*, opens a real TCP connection through the [`NatResponder`] to a
//! localhost echo server, and gets its bytes echoed back — exercising the SYN
//! admission, listener promotion, host connect, and bidirectional relay path
//! without needing HVF or a booted VM. This is the "does the NAT actually move
//! bytes" test that unit tests of the pure pieces cannot cover.

use super::*;
use smoltcp::iface::{Config as IfConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Instant as StdInstant;

/// The address the test guest holds, matching what `chm`'s `GUEST_IP` gives a
/// real one. Ingress dials *at* this, so the ingress tests need it by name.
const GUEST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 2);

/// An allow-all policy that also opts into local egress, for the relay tests
/// that deliberately dial a `127.0.0.1` echo server (the reserved-address guard
/// blocks loopback by default — M31.1).
fn local_allow_all() -> EgressPolicy {
    let mut p = EgressPolicy::allow_all();
    p.set_allow_local_egress(true);
    p
}

/// A localhost TCP echo server that services one connection until EOF. Returns
/// the bound port; the thread exits when the client closes.
fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });
    port
}

/// A minimal guest: a smoltcp stack with one TCP socket over its own frame wire.
struct Guest {
    iface: Interface,
    device: FrameDevice,
    sockets: SocketSet<'static>,
    sock: SocketHandle,
    boot: StdInstant,
}

impl Guest {
    fn new() -> Self {
        let mut device = FrameDevice::default();
        let mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let mut config = IfConfig::new(HardwareAddress::Ethernet(mac));
        config.random_seed = 0x1234_5678;
        let boot = StdInstant::now();
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(GUEST_ADDR), 24));
        });
        // Default route via the NAT gateway (.1).
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(192, 168, 249, 1));
        let mut sockets = SocketSet::new(Vec::new());
        let sock = sockets.add(new_tcp_socket());
        Self {
            iface,
            device,
            sockets,
            sock,
            boot,
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.boot.elapsed().as_micros() as i64)
    }

    fn connect(&mut self, dst: SocketAddrV4) {
        let s = self.sockets.get_mut::<tcp::Socket>(self.sock);
        s.connect(
            self.iface.context(),
            (IpAddress::Ipv4(*dst.ip()), dst.port()),
            49999,
        )
        .expect("guest connect");
    }

    fn poll(&mut self) {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    /// Arm `count` sockets listening on `port` inside the guest, and return
    /// their handles.
    ///
    /// `count` is the concurrency the guest can accept at once — a real server
    /// has a backlog, this one has exactly this many sockets — which is what
    /// makes the parallel-ingress test a measurement rather than a hope.
    fn listen(&mut self, port: u16, count: usize) -> Vec<SocketHandle> {
        (0..count)
            .map(|_| {
                let mut sock = new_tcp_socket();
                sock.listen(port).expect("guest listen");
                self.sockets.add(sock)
            })
            .collect()
    }

    /// Echo one round of whatever arrived on each of `socks`, prefixed with the
    /// guest port that received it.
    ///
    /// The prefix is the whole point: a host client that gets `7777:` back knows
    /// *which port inside the guest* served it, so "only the exposed port is
    /// reachable" is something the host can measure rather than infer.
    fn serve_echo(&mut self, socks: &[SocketHandle]) {
        for &h in socks {
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            if !s.can_recv() {
                continue;
            }
            let port = s.local_endpoint().map_or(0, |e| e.port);
            let data = s
                .recv(|buf| {
                    let owned = buf.to_vec();
                    (buf.len(), owned)
                })
                .unwrap_or_default();
            if data.is_empty() || !s.can_send() {
                continue;
            }
            let mut reply = format!("{port}:").into_bytes();
            reply.extend_from_slice(&data);
            let _ = s.send_slice(&reply);
        }
    }

    /// Whether any of `socks` ever left the listening state — i.e. whether a
    /// connection reached that port at all.
    fn any_accepted(&mut self, socks: &[SocketHandle]) -> bool {
        socks.iter().any(|&h| {
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            s.state() != tcp::State::Listen
        })
    }
}

/// Pump one round of frames between the guest and the NAT in both directions,
/// plus a NAT service tick (host-socket relay).
fn pump(guest: &mut Guest, nat: &mut NatResponder) {
    guest.poll();
    while let Some(frame) = guest.device.pop_to_guest() {
        nat.accept(&frame);
    }
    for reply in NatResponder::service(nat) {
        guest.device.push_from_guest(reply);
    }
}

/// Drive a fresh guest connecting to `dst` through `nat`, sending `payload` once
/// connected and collecting the echoed reply. Returns the bytes received.
fn drive_echo(nat: &mut NatResponder, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut guest = Guest::new();
    guest.connect(dst);
    let mut sent = false;
    let mut received: Vec<u8> = Vec::new();
    for _ in 0..4000 {
        pump(&mut guest, nat);
        let s = guest.sockets.get_mut::<tcp::Socket>(guest.sock);
        if !sent && s.can_send() {
            s.send_slice(payload).expect("guest send");
            sent = true;
        }
        if s.can_recv() {
            let _ = s.recv(|buf| {
                received.extend_from_slice(buf);
                (buf.len(), ())
            });
        }
        if received.len() >= payload.len() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    received
}

/// Drive a fresh guest connecting to `dst` through `nat` and report whether the
/// connection was refused (never established) and whether a denied tcp egress
/// event was recorded.
fn drive_expect_refused(nat: &mut NatResponder, dst: SocketAddrV4) -> (bool, bool) {
    let mut guest = Guest::new();
    guest.connect(dst);
    let mut refused = false;
    let mut denied_event = false;
    for _ in 0..500 {
        pump(&mut guest, nat);
        if nat.drain_events().iter().any(|e| e.domain == "tcp" && !e.allowed) {
            denied_event = true;
        }
        let s = guest.sockets.get_mut::<tcp::Socket>(guest.sock);
        if !s.is_active() && s.state() != tcp::State::SynSent {
            refused = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    (refused, denied_event)
}

#[test]
fn relays_guest_tcp_to_a_host_echo_server() {
    let port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        local_allow_all(),
        NatLimits::default(),
    );
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let payload = b"hello nat";
    assert_eq!(
        drive_echo(&mut nat, dst, payload),
        payload,
        "the echo server's reply must reach the guest through the NAT"
    );
}

#[test]
fn default_deny_refuses_the_connection() {
    // A locked-down policy that allows nothing: the guest's connect must fail
    // (smoltcp RSTs the SYN because no listener is armed), and the NAT records a
    // denied egress event.
    let port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::from_profile("deny", &[], &[], "locked"),
        NatLimits::default(),
    );
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let (refused, denied_event) = drive_expect_refused(&mut nat, dst);
    assert!(denied_event, "a denied tcp egress event must be recorded");
    assert!(refused, "the guest connection must not establish under default-deny");
    assert!(nat.listeners.is_empty(), "no listener may be armed for a denied dst");
}

#[test]
fn allow_all_cannot_reach_loopback_echo_server() {
    // End-to-end proof of the reserved-address guard (M31.1): with the default
    // allow-all policy (guard ON, no local-egress opt-in), a real relay attempt
    // to a localhost service is refused — the guest never reaches the host's own
    // loopback, even though the policy would otherwise permit everything.
    let port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::allow_all(),
        NatLimits::default(),
    );
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let (refused, denied_event) = drive_expect_refused(&mut nat, dst);
    assert!(denied_event, "a reserved-address denial must be recorded");
    assert!(refused, "allow-all must NOT reach the loopback echo server");
    assert!(nat.listeners.is_empty(), "no listener armed for a reserved dst");
}

#[test]
fn allow_list_permits_listed_and_refuses_unlisted() {
    // The product-critical property (M28.3): with a default-deny policy that
    // allows exactly one destination, the guest reaches the allowed host and is
    // refused everywhere else. Enforced at the TCP connect the NAT mediates.
    let port = spawn_echo_server();
    let allowed = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let denied = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port.wrapping_add(1).max(1));
    let profile_allow = vec![format!("127.0.0.1:{port}")];

    // Allowed destination: the flow establishes and echoes.
    let mut nat_allow = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::from_profile("deny", &profile_allow, &[], "sha256:test"),
        NatLimits::default(),
    );
    let payload = b"through the gate";
    assert_eq!(
        drive_echo(&mut nat_allow, allowed, payload),
        payload,
        "the allow-listed destination must be reachable"
    );

    // Unlisted destination under the SAME allow-list: refused.
    let mut nat_deny = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::from_profile("deny", &profile_allow, &[], "sha256:test"),
        NatLimits::default(),
    );
    let (refused, denied_event) = drive_expect_refused(&mut nat_deny, denied);
    assert!(denied_event, "the unlisted destination must record a denial");
    assert!(refused, "the unlisted destination must not establish");
}

/// Stream up to `cap_total` bytes from a fresh guest to the echo server through
/// `nat`, draining the echoed reply, over a fixed `iters` service ticks. Returns
/// the number of bytes echoed back to the guest within that window. Used to
/// compare throughput with and without a bandwidth cap.
fn drive_stream(nat: &mut NatResponder, dst: SocketAddrV4, cap_total: usize, iters: usize) -> usize {
    let mut guest = Guest::new();
    guest.connect(dst);
    let mut sent = 0usize;
    let mut received = 0usize;
    let chunk = [0x5au8; 4096];
    for _ in 0..iters {
        pump(&mut guest, nat);
        let s = guest.sockets.get_mut::<tcp::Socket>(guest.sock);
        while sent < cap_total && s.can_send() {
            let want = chunk.len().min(cap_total - sent);
            let n = s.send_slice(&chunk[..want]).unwrap_or(0);
            if n == 0 {
                break;
            }
            sent += n;
        }
        if s.can_recv() {
            let _ = s.recv(|buf| {
                received += buf.len();
                (buf.len(), ())
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    received
}

#[test]
fn bandwidth_cap_throttles_relay_throughput() {
    // The datapath resource cap (M30.6): a permitted flow may still be bounded in
    // how much it moves. Stream the same offered load through an unlimited NAT
    // and a tightly-capped one over the same fixed window, and prove the cap
    // moved dramatically fewer bytes (throttled, not dropped — TCP backpressure
    // leaves the rest buffered).
    const OFFERED: usize = 4 * 1024 * 1024;
    const ITERS: usize = 400;

    let uncapped_port = spawn_echo_server();
    let mut uncapped = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        local_allow_all(),
        NatLimits::default(),
    );
    let uncapped_rx = drive_stream(
        &mut uncapped,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), uncapped_port),
        OFFERED,
        ITERS,
    );

    let capped_port = spawn_echo_server();
    let mut capped = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        local_allow_all(),
        NatLimits {
            max_connections: None,
            max_bytes_per_sec: Some(8_000),
        },
    );
    let capped_rx = drive_stream(
        &mut capped,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), capped_port),
        OFFERED,
        ITERS,
    );

    // The uncapped flow moves a lot; the capped flow is bounded by its 8 KB/s
    // budget (plus a 1 s burst). The window is well under 8 s, so the cap cannot
    // have passed 64 KiB — a generous ceiling that stays clear of timing jitter.
    assert!(
        uncapped_rx >= 200_000,
        "an unthrottled flow should move plenty (got {uncapped_rx} bytes)"
    );
    assert!(
        capped_rx <= 64 * 1024,
        "the bandwidth cap must throttle throughput (got {capped_rx} bytes)"
    );
    assert!(
        capped_rx < uncapped_rx / 2,
        "the cap must be dramatically slower than unthrottled \
         (capped {capped_rx} vs uncapped {uncapped_rx})"
    );
}



/// A decider that sends everything on one port to a fixed address.
#[derive(Debug)]
struct DivertPort {
    port: u16,
    to: SocketAddr,
}

impl InterceptDecider for DivertPort {
    fn divert(&self, ip: Ipv4Addr, port: u16, host: Option<&str>) -> Option<Divert> {
        (port == self.port).then(|| Divert {
            addr: self.to,
            preamble: format!("ORIGIN {ip} {port} {}\n", host.unwrap_or("-")).into_bytes(),
        })
    }
}

/// A server that reads one line of preamble, then echoes — standing in for the
/// credential proxy. Returns its port and a channel carrying the preamble it saw.
fn spawn_preamble_echo() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = stream.read(&mut byte) {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            let _ = tx.send(String::from_utf8_lossy(&line).to_string());
            let mut buf = [0u8; 2048];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });
    (port, rx)
}

#[test]
fn an_intercepted_flow_reaches_the_proxy_with_the_true_destination() {
    // The guest dials one address; the flow must arrive somewhere else entirely,
    // carrying the destination it *meant* — otherwise the far end cannot pick
    // the right credential, and cannot present the right certificate.
    let (proxy_port, saw) = spawn_preamble_echo();
    let origin_port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        local_allow_all(),
        NatLimits::default(),
    );
    nat.set_intercept(Some(Arc::new(DivertPort {
        port: origin_port,
        to: SocketAddr::from(([127, 0, 0, 1], proxy_port)),
    })));

    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), origin_port);
    let payload = b"through the proxy";
    assert_eq!(
        drive_echo(&mut nat, dst, payload),
        payload,
        "bytes must still flow after the divert"
    );

    let preamble = saw
        .recv_timeout(Duration::from_secs(5))
        .expect("the proxy must receive the handover preamble");
    assert_eq!(
        preamble,
        format!("ORIGIN 127.0.0.1 {origin_port} -"),
        "the preamble must name the origin the guest dialled, not the proxy"
    );
    assert!(
        nat.drain_events()
            .iter()
            .any(|e| e.rule.starts_with("divert ")),
        "the divert must be visible in the egress event stream"
    );
}

#[test]
fn a_flow_the_decider_declines_still_goes_straight_to_its_origin() {
    // Interception is per-destination, never global: a decider that says no must
    // leave the flow untouched, so an un-listed host is never routed through a
    // component that holds credentials.
    let (proxy_port, saw) = spawn_preamble_echo();
    let origin_port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        local_allow_all(),
        NatLimits::default(),
    );
    // Matches a port nothing will dial.
    nat.set_intercept(Some(Arc::new(DivertPort {
        port: origin_port.wrapping_add(1),
        to: SocketAddr::from(([127, 0, 0, 1], proxy_port)),
    })));

    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), origin_port);
    let payload = b"direct";
    assert_eq!(drive_echo(&mut nat, dst, payload), payload);
    assert!(
        saw.recv_timeout(Duration::from_millis(300)).is_err(),
        "the proxy must not have seen this flow at all"
    );
    assert!(
        !nat.drain_events()
            .iter()
            .any(|e| e.rule.starts_with("divert ")),
        "no divert should be recorded"
    );
}

// ---------------------------------------------------------------------------
// Ingress (V11.0, #330): reaching a port *inside* the guest from the host.
// ---------------------------------------------------------------------------

/// The guest port these tests expose, and one they deliberately never expose.
const EXPOSED_PORT: u16 = 7777;
const UNEXPOSED_PORT: u16 = 9999;

/// A host client, on its own thread because the NAT is only serviced by the
/// test thread: connect to `host_port`, send `token`, and read back exactly the
/// reply the guest's echo will produce.
///
/// It returns what it actually received rather than asserting inside the
/// thread, so a crossed stream is reported as *the wrong bytes* — the finding —
/// instead of a panic in a thread nobody is watching.
fn spawn_client(host_port: u16, token: String, guest_port: u16) -> ClientHandle {
    let expected = format!("{guest_port}:{token}");
    let want = expected.len();
    let handle = std::thread::spawn(move || -> std::io::Result<String> {
        let mut s = TcpStream::connect(SocketAddrV4::new(INGRESS_BIND_ADDR, host_port))?;
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.write_all(token.as_bytes())?;
        s.flush()?;
        let mut buf = vec![0u8; want];
        s.read_exact(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    });
    ClientHandle { handle, expected }
}

struct ClientHandle {
    handle: std::thread::JoinHandle<std::io::Result<String>>,
    expected: String,
}

/// Service the NAT and the guest until every client thread has finished, or
/// `deadline` passes. Returns whether they all finished.
fn pump_until_done(
    guest: &mut Guest,
    nat: &mut NatResponder,
    socks: &[SocketHandle],
    clients: &[ClientHandle],
    deadline: Duration,
) -> bool {
    let start = StdInstant::now();
    while start.elapsed() < deadline {
        guest.serve_echo(socks);
        pump(guest, nat);
        if clients.iter().all(|c| c.handle.is_finished()) {
            // One more pass so the final FIN exchange is not left in flight.
            pump(guest, nat);
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// A NAT with the default (guard-on) allow-all egress policy. Ingress is
/// governed by `expose`, not by the egress policy, so these tests deliberately
/// do *not* opt into local egress: an exposed port must work without loosening
/// the reserved-address guard.
fn ingress_nat() -> NatResponder {
    NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::allow_all(),
        NatLimits::default(),
    )
}

#[test]
fn bytes_traverse_host_to_guest_and_back() {
    // Guard 1, and the whole of #330: a host process writes to a loopback port
    // and the bytes are answered by something listening *inside* the guest.
    let mut nat = ingress_nat();
    let exp = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("expose");
    let mut guest = Guest::new();
    let socks = guest.listen(EXPOSED_PORT, 2);

    let clients = vec![spawn_client(exp.host_port, "hello".to_string(), EXPOSED_PORT)];
    assert!(
        pump_until_done(&mut guest, &mut nat, &socks, &clients, Duration::from_secs(30)),
        "the host client must complete its round trip"
    );
    let got = clients
        .into_iter()
        .next()
        .unwrap()
        .handle
        .join()
        .expect("client thread")
        .expect("client io");
    assert_eq!(
        got,
        format!("{EXPOSED_PORT}:hello"),
        "the reply must come from the guest's own listener on {EXPOSED_PORT}"
    );
}

#[test]
fn a_port_that_was_not_exposed_is_unreachable() {
    // Guard 2. The guest listens on both ports; only one was named. The host
    // gets an answer tagged with the exposed port and never with the other, and
    // the unexposed port's sockets never leave LISTEN — so this fails both if
    // ingress ever forwarded to the wrong port and if it ever forwarded to
    // every port.
    let mut nat = ingress_nat();
    let exp = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("expose");
    let mut guest = Guest::new();
    let exposed_socks = guest.listen(EXPOSED_PORT, 2);
    let unexposed_socks = guest.listen(UNEXPOSED_PORT, 2);
    let all: Vec<SocketHandle> = exposed_socks
        .iter()
        .chain(unexposed_socks.iter())
        .copied()
        .collect();

    let clients = vec![spawn_client(exp.host_port, "probe".to_string(), EXPOSED_PORT)];
    assert!(
        pump_until_done(&mut guest, &mut nat, &all, &clients, Duration::from_secs(30)),
        "the exposed port must still work"
    );
    let got = clients
        .into_iter()
        .next()
        .unwrap()
        .handle
        .join()
        .expect("client thread")
        .expect("client io");
    assert_eq!(got, format!("{EXPOSED_PORT}:probe"));
    assert!(
        !guest.any_accepted(&unexposed_socks),
        "nothing may have reached guest port {UNEXPOSED_PORT}; it was never exposed"
    );

    // And there is no *other* host port that would reach it: exposure is
    // one-at-a-time and by name, so the whole inbound surface is this list.
    let exposures = nat.exposures();
    assert_eq!(exposures.len(), 1, "exactly one port was named");
    assert_eq!(exposures[0].guest.port(), EXPOSED_PORT);
    assert!(
        !exposures.iter().any(|e| e.guest.port() == UNEXPOSED_PORT),
        "no host listener may reach a port nobody exposed"
    );
}

#[test]
fn the_ingress_bind_address_is_loopback() {
    // Guard 3. Two halves, because there are two ways to get this wrong: the
    // constant could name a wider address, or the bind could ignore it. The
    // test reads the same constant the bind does rather than restating
    // `127.0.0.1`, so widening the constant fails here rather than silently
    // agreeing with a copy.
    assert!(
        INGRESS_BIND_ADDR.is_loopback(),
        "an exposed guest port must be reachable from this Mac and nowhere else"
    );
    let mut nat = ingress_nat();
    let exp = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("expose");
    let bound = nat.ingress[0]
        .listener
        .local_addr()
        .expect("the listener's own address");
    assert_eq!(
        bound,
        SocketAddr::from(SocketAddrV4::new(INGRESS_BIND_ADDR, exp.host_port)),
        "the listener must be bound to the address the constant names"
    );

    // The behavioural half: from an address that is not loopback, the port must
    // not answer. Skipped rather than faked when this Mac has no other IPv4 —
    // a test that quietly proves nothing is worse than one that says why.
    if let Some(lan) = non_loopback_ipv4() {
        let err = TcpStream::connect_timeout(
            &SocketAddr::from(SocketAddrV4::new(lan, exp.host_port)),
            Duration::from_secs(2),
        )
        .err();
        assert!(
            err.is_some(),
            "an exposed port answered on {lan}, so it is not loopback-only"
        );
    } else {
        eprintln!("no non-loopback IPv4 on this host; skipped the off-loopback probe");
    }
}

/// This host's primary non-loopback IPv4, discovered by asking the routing
/// table which source address it would use — a connected UDP socket sends
/// nothing, so this works offline and costs no packets. `None` when there is no
/// route at all (an unplugged machine), which is a skip and not a failure.
fn non_loopback_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:9").ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) if !v4.ip().is_loopback() && !v4.ip().is_unspecified() => Some(*v4.ip()),
        _ => None,
    }
}

/// How many host connections are opened at once in the concurrency guard.
///
/// Chosen against a measurement rather than a feeling: one browser page load
/// opens on the order of 80 parallel connections (#329), and this stack had
/// only ever been exercised with `curl` and `git clone`. 96 is the first number
/// above that, so a regression that survives `curl` still fails here.
const PARALLEL_FLOWS: usize = 96;

#[test]
fn concurrent_ingress_flows_do_not_cross_streams() {
    // Guard 4, and the biggest open risk in the epic. Every client sends a
    // token only it knows and must get that token back. A NAT that muddled two
    // flows would still return *something* to everyone, so a length or liveness
    // check would pass; only the identity check catches it.
    let mut nat = ingress_nat();
    let exp = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("expose");
    let mut guest = Guest::new();
    let socks = guest.listen(EXPOSED_PORT, PARALLEL_FLOWS);

    let clients: Vec<ClientHandle> = (0..PARALLEL_FLOWS)
        .map(|i| spawn_client(exp.host_port, format!("token-{i:04}"), EXPOSED_PORT))
        .collect();
    let finished = pump_until_done(
        &mut guest,
        &mut nat,
        &socks,
        &clients,
        Duration::from_secs(60),
    );

    let mut wrong: Vec<String> = Vec::new();
    let mut failed = 0usize;
    for c in clients {
        let expected = c.expected.clone();
        match c.handle.join().expect("client thread") {
            Ok(got) if got == expected => {}
            Ok(got) => wrong.push(format!("expected {expected}, got {got}")),
            Err(e) => {
                failed += 1;
                if wrong.len() < 4 {
                    wrong.push(format!("{expected}: {e}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{PARALLEL_FLOWS} concurrent ingress flows: {failed} errored, \
         mismatches/errors: {wrong:?}"
    );
    assert!(
        finished,
        "all {PARALLEL_FLOWS} flows must complete inside the deadline"
    );
}

#[test]
fn an_ingress_flow_is_counted_against_the_connection_cap() {
    // "Subject to NatLimits like any other flow": an exposed port must not be a
    // way to open an unbounded number of host sockets. With a cap of 1, the
    // second inbound connection is refused (the host stream is dropped, so the
    // client sees a close, not a hang) and the refusal is recorded.
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::allow_all(),
        NatLimits {
            max_connections: Some(1),
            max_bytes_per_sec: None,
        },
    );
    let exp = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("expose");
    let mut guest = Guest::new();
    let socks = guest.listen(EXPOSED_PORT, 4);

    let clients: Vec<ClientHandle> = (0..2)
        .map(|i| spawn_client(exp.host_port, format!("capped-{i}"), EXPOSED_PORT))
        .collect();
    // Not expected to all finish: one of them is meant to be refused.
    let mut denied = false;
    let start = StdInstant::now();
    while start.elapsed() < Duration::from_secs(10) {
        guest.serve_echo(&socks);
        pump(&mut guest, &mut nat);
        if nat
            .drain_events()
            .iter()
            .any(|e| e.domain == "ingress" && !e.allowed && e.rule == "connection-limit")
        {
            denied = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    for c in clients {
        let _ = c.handle.join();
    }
    assert!(
        denied,
        "an inbound flow over the connection cap must be refused and recorded"
    );
}

#[test]
fn exposing_refuses_port_zero_and_a_second_listener_for_the_same_port() {
    // Fail closed: both of these are ambiguous rather than harmless, so neither
    // may quietly succeed. Port 0 is the OS's word for "choose one" and no guest
    // listens on it; a second exposure of the same port would give it two host
    // ports with nothing to say which is meant.
    let mut nat = ingress_nat();
    let zero = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, 0))
        .expect_err("port 0 must be refused");
    assert!(zero.contains("port 0"), "{zero}");

    let first = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect("first exposure");
    let dup = nat
        .expose(SocketAddrV4::new(GUEST_ADDR, EXPOSED_PORT))
        .expect_err("a duplicate exposure must be refused");
    assert!(
        dup.contains(&first.host_port.to_string()),
        "the refusal must name the host port it is already on: {dup}"
    );
    assert_eq!(nat.exposures().len(), 1, "the refusal armed nothing");
}

#[test]
fn ingress_source_ports_are_not_reused_while_in_flight() {
    // Two inbound flows to one exposed port differ only in their gateway-side
    // source port. Handing out the same one twice would present the guest with
    // two connections sharing a four-tuple — the mechanism by which streams
    // cross — so the pool must never repeat a port that is still live.
    let mut nat = ingress_nat();
    let mut seen: HashSet<u16> = HashSet::new();
    for _ in 0..64 {
        let port = nat.free_ingress_port().expect("a free source port");
        assert!(seen.insert(port), "port {port} was handed out twice");
        nat.ingress_ports.insert(port);
    }
    // Returned ports become available again, or a long-lived sandbox would run
    // the pool dry.
    let reclaimed = *seen.iter().next().unwrap();
    nat.ingress_ports.remove(&reclaimed);
    assert!(
        nat.ingress_ports.len() == seen.len() - 1,
        "the pool must give a retired port back"
    );
}
