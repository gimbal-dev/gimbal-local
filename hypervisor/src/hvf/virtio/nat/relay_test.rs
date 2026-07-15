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
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(192, 168, 249, 2)),
                24,
            ));
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
}

/// Pump one round of frames between the guest and the NAT in both directions,
/// plus a NAT service tick (host-socket relay).
fn pump(guest: &mut Guest, nat: &mut NatResponder) {
    guest.poll();
    while let Some(frame) = guest.device.pop_to_guest() {
        for reply in nat.handle(&frame) {
            guest.device.push_from_guest(reply);
        }
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
        EgressPolicy::allow_all(),
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
        EgressPolicy::allow_all(),
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
        EgressPolicy::allow_all(),
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


