//! A `virtio-net` device: drain the guest's transmit queue and inject host
//! frames into its receive queue.
//!
//! virtio-net is the first device whose data path is bidirectional and
//! host-driven on the receive side. Two virtqueues carry traffic:
//!
//! * RX (queue 0): the guest posts empty device-writable buffers; the device
//!   fills each with a [`VIRTIO_NET_HDR_LEN`]-byte virtio-net header followed by
//!   a received Ethernet frame.
//! * TX (queue 1): the guest posts device-readable buffers, each a virtio-net
//!   header followed by an Ethernet frame to transmit.
//!
//! Unlike block/rng, the receive direction is not driven by a guest notify: the
//! host must inject frames asynchronously. This module models the device's frame
//! handling and carries a [`NetResponder`] that answers guest traffic (ARP +
//! ICMP echo), so a resumed guest that runs `ping <gateway>` sees real replies
//! over the deliverable message-based-SPI completion path — concrete proof of
//! bidirectional virtio-net flow without a full host TCP/IP stack or NAT.
//!
//! The queue mechanics (popping chains, writing the header, publishing the used
//! ring, signalling the per-queue MSI-X vector) live in the transport
//! ([`super::pci`]); this module owns only the frame semantics and the pending
//! receive backlog.

use std::collections::VecDeque;

/// The modern (`VIRTIO_F_VERSION_1`) virtio-net header length, in bytes:
/// `flags`, `gso_type`, `hdr_len`, `gso_size`, `csum_start`, `csum_offset`,
/// `num_buffers`. cloud-hypervisor negotiates version 1, so every frame on both
/// queues is prefixed by this header.
pub const VIRTIO_NET_HDR_LEN: usize = 12;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const IP_PROTO_ICMP: u8 = 1;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Answers Ethernet frames the guest transmits with the frames a host network
/// would send back. Returning an empty vector means "no reply" (the frame is
/// accepted and dropped, as a real NIC would for traffic not destined here).
pub trait NetResponder: Send {
    /// Given an outbound Ethernet `frame` from the guest, return zero or more
    /// Ethernet frames to deliver back to the guest.
    fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>>;

    /// Advance any asynchronous work (e.g. a userspace NAT polling its host
    /// sockets) and return frames to deliver to the guest, independent of guest
    /// transmit activity. Called periodically by the net service thread. The
    /// default is a no-op: a purely request/reply responder has nothing to do
    /// between guest frames.
    fn service(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// A minimal host responder that makes a resumed guest's link demonstrably
/// live: it answers ARP requests for a synthetic gateway and replies to ICMP
/// echo requests addressed to that gateway. This is enough for `ping <gateway>`
/// to succeed in the guest, proving the TX (guest frame parsed) and RX (host
/// frame accepted by the guest stack) directions end to end.
pub struct EchoResponder {
    gateway_ip: [u8; 4],
    gateway_mac: [u8; 6],
}

impl EchoResponder {
    /// Build a responder that owns `gateway_ip` with the synthetic
    /// `gateway_mac`.
    pub fn new(gateway_ip: [u8; 4], gateway_mac: [u8; 6]) -> Self {
        Self {
            gateway_ip,
            gateway_mac,
        }
    }

    fn handle_arp(&self, frame: &[u8]) -> Option<Vec<u8>> {
        // Ethernet header is 14 bytes; ARP payload is 28 bytes.
        if frame.len() < 14 + 28 {
            return None;
        }
        let arp = &frame[14..14 + 28];
        let oper = u16::from_be_bytes([arp[6], arp[7]]);
        if oper != ARP_OP_REQUEST {
            return None;
        }
        let sha = &arp[8..14]; // sender hardware addr (guest MAC)
        let spa = &arp[14..18]; // sender protocol addr (guest IP)
        let tpa = &arp[24..28]; // target protocol addr (who is being asked)
        if tpa != self.gateway_ip {
            return None;
        }

        let mut reply = Vec::with_capacity(14 + 28);
        // Ethernet: dst = guest, src = gateway, type = ARP.
        reply.extend_from_slice(sha);
        reply.extend_from_slice(&self.gateway_mac);
        reply.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        // ARP reply.
        reply.extend_from_slice(&1u16.to_be_bytes()); // htype Ethernet
        reply.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype IPv4
        reply.push(6); // hlen
        reply.push(4); // plen
        reply.extend_from_slice(&ARP_OP_REPLY.to_be_bytes());
        reply.extend_from_slice(&self.gateway_mac); // sender hw = gateway
        reply.extend_from_slice(&self.gateway_ip); // sender proto = gateway
        reply.extend_from_slice(sha); // target hw = guest
        reply.extend_from_slice(spa); // target proto = guest
        Some(reply)
    }

    fn handle_ipv4(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 14 + 20 {
            return None;
        }
        let eth_src = &frame[6..12];
        let ip = &frame[14..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        if ihl < 20 || ip.len() < ihl {
            return None;
        }
        if ip[9] != IP_PROTO_ICMP {
            return None;
        }
        let src_ip = &ip[12..16];
        let dst_ip = &ip[16..20];
        if dst_ip != self.gateway_ip {
            return None;
        }
        let icmp = &ip[ihl..];
        if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REQUEST {
            return None;
        }

        // Build the echo reply: swap IP src/dst, set ICMP type to 0, recompute
        // both checksums. The IP payload length is preserved.
        let mut out_ip = ip.to_vec();
        out_ip[12..16].copy_from_slice(dst_ip); // src = gateway
        out_ip[16..20].copy_from_slice(src_ip); // dst = guest
        out_ip[10] = 0;
        out_ip[11] = 0;
        let ip_csum = checksum(&out_ip[..ihl]);
        out_ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        let icmp_off = ihl;
        out_ip[icmp_off] = ICMP_ECHO_REPLY;
        out_ip[icmp_off + 2] = 0;
        out_ip[icmp_off + 3] = 0;
        let icmp_csum = checksum(&out_ip[icmp_off..]);
        out_ip[icmp_off + 2..icmp_off + 4].copy_from_slice(&icmp_csum.to_be_bytes());

        let mut reply = Vec::with_capacity(14 + out_ip.len());
        reply.extend_from_slice(eth_src); // dst = guest
        reply.extend_from_slice(&self.gateway_mac); // src = gateway
        reply.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        reply.extend_from_slice(&out_ip);
        Some(reply)
    }
}

impl NetResponder for EchoResponder {
    fn handle(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if frame.len() < 14 {
            return Vec::new();
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let reply = match ethertype {
            ETHERTYPE_ARP => self.handle_arp(frame),
            ETHERTYPE_IPV4 => self.handle_ipv4(frame),
            _ => None,
        };
        reply.into_iter().collect()
    }
}

/// The internet checksum (RFC 1071) over `data`, returned host-order so callers
/// store it big-endian.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A `virtio-net` device. Owns the host responder and the backlog of frames
/// waiting for guest receive buffers; the transport drives both queues.
pub struct NetDevice {
    responder: Box<dyn NetResponder>,
    pending_rx: VecDeque<Vec<u8>>,
}

impl NetDevice {
    /// Build a net device answering guest traffic with `responder`.
    pub fn new(responder: Box<dyn NetResponder>) -> Self {
        Self {
            responder,
            pending_rx: VecDeque::new(),
        }
    }

    /// Process one transmitted Ethernet `frame` (already stripped of its
    /// virtio-net header): queue any reply frames the responder produces for
    /// later injection into the receive queue.
    pub fn handle_tx_frame(&mut self, frame: &[u8]) {
        for reply in self.responder.handle(frame) {
            self.pending_rx.push_back(reply);
        }
    }

    /// Advance the responder's asynchronous work (e.g. a NAT relaying host
    /// socket data) and queue any resulting frames for the guest's receive
    /// queue. Returns whether any frame was produced, so the caller can decide
    /// to wake a parked vCPU. Driven by the net service thread, not a guest
    /// notify.
    pub fn service(&mut self) -> bool {
        let mut produced = false;
        for reply in self.responder.service() {
            self.pending_rx.push_back(reply);
            produced = true;
        }
        produced
    }

    /// Whether a frame is waiting to be delivered into the guest's receive
    /// queue.
    pub fn has_pending_rx(&self) -> bool {
        !self.pending_rx.is_empty()
    }

    /// Take the next frame to inject into the guest's receive queue, if any.
    pub fn pop_rx(&mut self) -> Option<Vec<u8>> {
        self.pending_rx.pop_front()
    }

    /// Return an un-injected frame to the front of the backlog (when no receive
    /// buffer was available to hold it).
    pub fn requeue_rx(&mut self, frame: Vec<u8>) {
        self.pending_rx.push_front(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST_MAC: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
    const GUEST_IP: [u8; 4] = [192, 168, 249, 2];
    const GW_IP: [u8; 4] = [192, 168, 249, 1];
    const GW_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

    fn arp_request() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // broadcast
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.push(6);
        f.push(4);
        f.extend_from_slice(&ARP_OP_REQUEST.to_be_bytes());
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&GUEST_IP);
        f.extend_from_slice(&[0u8; 6]);
        f.extend_from_slice(&GW_IP);
        f
    }

    #[test]
    fn answers_arp_for_the_gateway() {
        let mut r = EchoResponder::new(GW_IP, GW_MAC);
        let replies = r.handle(&arp_request());
        assert_eq!(replies.len(), 1);
        let reply = &replies[0];
        assert_eq!(&reply[0..6], &GUEST_MAC, "dst = guest");
        assert_eq!(&reply[6..12], &GW_MAC, "src = gateway");
        let arp = &reply[14..14 + 28];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), ARP_OP_REPLY);
        assert_eq!(&arp[8..14], &GW_MAC, "sender hw = gateway");
        assert_eq!(&arp[14..18], &GW_IP, "sender proto = gateway");
        assert_eq!(&arp[18..24], &GUEST_MAC, "target hw = guest");
        assert_eq!(&arp[24..28], &GUEST_IP, "target proto = guest");
    }

    #[test]
    fn ignores_arp_for_a_different_ip() {
        let mut r = EchoResponder::new([10, 0, 0, 1], GW_MAC);
        assert!(r.handle(&arp_request()).is_empty());
    }

    fn icmp_echo_request() -> Vec<u8> {
        // Ethernet
        let mut f = Vec::new();
        f.extend_from_slice(&GW_MAC); // dst = gateway
        f.extend_from_slice(&GUEST_MAC); // src = guest
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (20 bytes) + ICMP (8 + 4 payload)
        let icmp = {
            let mut c = vec![ICMP_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1];
            c.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
            let ck = checksum(&c);
            c[2..4].copy_from_slice(&ck.to_be_bytes());
            c
        };
        let total = 20 + icmp.len();
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            (total & 0xff) as u8,
            0,
            1,
            0,
            0,
            64,
            IP_PROTO_ICMP,
            0,
            0,
        ];
        ip.extend_from_slice(&GUEST_IP);
        ip.extend_from_slice(&GW_IP);
        let ck = checksum(&ip);
        ip[10..12].copy_from_slice(&ck.to_be_bytes());
        ip.extend_from_slice(&icmp);
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn answers_icmp_echo_to_the_gateway() {
        let mut r = EchoResponder::new(GW_IP, GW_MAC);
        let req = icmp_echo_request();
        let replies = r.handle(&req);
        assert_eq!(replies.len(), 1, "echo reply produced");
        let reply = &replies[0];
        assert_eq!(&reply[0..6], &GUEST_MAC, "dst = guest");
        assert_eq!(&reply[6..12], &GW_MAC, "src = gateway");
        let ip = &reply[14..];
        assert_eq!(&ip[12..16], &GW_IP, "src ip = gateway");
        assert_eq!(&ip[16..20], &GUEST_IP, "dst ip = guest");
        assert_eq!(checksum(&ip[..20]), 0, "ip checksum valid");
        let icmp = &ip[20..];
        assert_eq!(icmp[0], ICMP_ECHO_REPLY, "type = echo reply");
        assert_eq!(checksum(icmp), 0, "icmp checksum valid");
    }

    #[test]
    fn net_device_queues_replies_for_rx() {
        let mut dev = NetDevice::new(Box::new(EchoResponder::new(GW_IP, GW_MAC)));
        assert!(!dev.has_pending_rx());
        dev.handle_tx_frame(&arp_request());
        assert!(dev.has_pending_rx());
        let frame = dev.pop_rx().expect("a reply frame");
        assert_eq!(&frame[0..6], &GUEST_MAC);
        assert!(!dev.has_pending_rx());
    }
}
