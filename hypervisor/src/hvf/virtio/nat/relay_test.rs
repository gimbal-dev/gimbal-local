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

#[test]
fn relays_guest_tcp_to_a_host_echo_server() {
    let port = spawn_echo_server();
    let mut nat = NatResponder::new(
        [192, 168, 249, 1],
        [0x02, 0, 0, 0, 0, 1],
        EgressPolicy::allow_all(),
    );
    let mut guest = Guest::new();
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    guest.connect(dst);

    let payload = b"hello nat";
    let mut sent = false;
    let mut received: Vec<u8> = Vec::new();

    for _ in 0..4000 {
        pump(&mut guest, &mut nat);

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

    assert_eq!(
        received, payload,
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
    );
    let mut guest = Guest::new();
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    guest.connect(dst);

    let mut refused = false;
    let mut denied_event = false;
    for _ in 0..500 {
        pump(&mut guest, &mut nat);
        if nat.drain_events().iter().any(|e| e.domain == "tcp" && !e.allowed) {
            denied_event = true;
        }
        let s = guest.sockets.get_mut::<tcp::Socket>(guest.sock);
        // A RST drives the guest socket to a closed/non-active state.
        if !s.is_active() && s.state() != tcp::State::SynSent {
            refused = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert!(denied_event, "a denied tcp egress event must be recorded");
    assert!(refused, "the guest connection must not establish under default-deny");
    assert!(nat_never_listened(&nat), "no listener may be armed for a denied dst");
}

/// True if the NAT holds no armed listeners (a denied connect must not create
/// one).
fn nat_never_listened(nat: &NatResponder) -> bool {
    nat.listeners.is_empty()
}
