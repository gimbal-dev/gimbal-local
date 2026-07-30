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

/// How many times [`NetDevice::service`] will advance the responder before
/// handing its backlog to the transport. Bounded so that a responder with an
/// endless supply of frames still yields to the guest promptly.
const SERVICE_BURST_PASSES: usize = 32;

/// `VIRTIO_NET_HDR_F_DATA_VALID`: the device has already validated the packet's
/// transport checksum, so the driver need not. Only meaningful to a driver that
/// negotiated `VIRTIO_NET_F_GUEST_CSUM`.
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;

/// `VIRTIO_NET_F_GUEST_CSUM`: the driver accepts packets with a checksum it has
/// been told is already valid.
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const IP_PROTO_ICMP: u8 = 1;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Answers Ethernet frames the guest transmits with the frames a host network
/// would send back.
///
/// Accepting a frame and producing replies are deliberately separate. A guest
/// transmit arrives on a vCPU thread inside an MMIO exit, with the guest stopped
/// for the duration; running the whole stack there makes every packet a stall.
/// [`accept`](NetResponder::accept) therefore only takes ownership of the frame,
/// and [`service`](NetResponder::service) — called on the net service thread —
/// does the work and returns everything to deliver back to the guest. A burst of
/// transmits then costs one pass over the stack instead of one per frame.
pub trait NetResponder: Send {
    /// Take an outbound Ethernet `frame` from the guest. Any frames produced in
    /// response are returned by a subsequent [`service`](Self::service) call.
    /// Must not block: this runs with the guest stopped.
    fn accept(&mut self, frame: &[u8]);

    /// Advance the responder (parsing accepted frames, polling host sockets)
    /// and return frames to deliver to the guest. Called by the net service
    /// thread, which is woken whenever a frame is accepted and otherwise ticks
    /// periodically so host-side arrivals are still picked up.
    fn service(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Take the egress-decision events (allow/deny) accumulated since the last
    /// drain, for the audit trail. The default responder makes no policy
    /// decisions, so it has none.
    fn set_intercept(&mut self, _decider: Option<std::sync::Arc<dyn super::nat::InterceptDecider>>) {}

    /// Take the responder's egress decisions accumulated since the last
    fn drain_egress_events(&mut self) -> Vec<super::nat::EgressEvent> {
        Vec::new()
    }
}

/// A wake handle shared between the vCPU threads and the net service thread.
///
/// The host side of a flow has no readiness signal we can wait on — the NAT
/// discovers host data by polling its sockets — so the service thread ticks.
/// The guest side does have one: a transmit notify. Kicking on that turns a
/// guest ACK into an immediate service pass rather than one that waits out the
/// remainder of a tick, which is what keeps a request/response round trip fast
/// once the stack no longer runs on the vCPU thread.
#[derive(Debug, Default)]
pub struct NetKick {
    pending: std::sync::Mutex<bool>,
    woken: std::sync::Condvar,
}

impl NetKick {
    /// Wake the service thread. Cheap and non-blocking; safe to call from a
    /// vCPU thread inside an MMIO exit.
    pub fn wake(&self) {
        if let Ok(mut p) = self.pending.lock() {
            *p = true;
        }
        self.woken.notify_one();
    }

    /// Block until woken or `timeout` elapses, then consume the wake. A wake
    /// raised while the caller was working is not lost: it is still pending on
    /// entry and returns immediately.
    pub fn wait(&self, timeout: std::time::Duration) {
        let Ok(guard) = self.pending.lock() else { return };
        if let Ok((mut guard, _)) = self.woken.wait_timeout_while(guard, timeout, |p| !*p) {
            *guard = false;
        }
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
    replies: VecDeque<Vec<u8>>,
}

impl EchoResponder {
    /// Build a responder that owns `gateway_ip` with the synthetic
    /// `gateway_mac`.
    pub fn new(gateway_ip: [u8; 4], gateway_mac: [u8; 6]) -> Self {
        Self {
            gateway_ip,
            gateway_mac,
            replies: VecDeque::new(),
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
    fn accept(&mut self, frame: &[u8]) {
        if frame.len() < 14 {
            return;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let reply = match ethertype {
            ETHERTYPE_ARP => self.handle_arp(frame),
            ETHERTYPE_IPV4 => self.handle_ipv4(frame),
            _ => None,
        };
        self.replies.extend(reply);
    }

    fn service(&mut self) -> Vec<Vec<u8>> {
        self.replies.drain(..).collect()
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
    /// The largest frame the guest's receive chains have been observed to hold,
    /// or `None` until the transport has popped one. Receive coalescing is
    /// bounded by this rather than by a constant, so a guest posting single-MTU
    /// buffers keeps getting one segment per frame (see [`super::lro`]).
    rx_capacity: Option<usize>,
    /// Whether the driver negotiated `VIRTIO_NET_F_GUEST_CSUM`, and so will
    /// accept a frame marked `VIRTIO_NET_HDR_F_DATA_VALID` without verifying its
    /// transport checksum.
    guest_csum: bool,
}

impl NetDevice {
    /// Build a net device answering guest traffic with `responder`. The driver
    /// is assumed not to have negotiated checksum offloads; see
    /// [`with_features`](Self::with_features).
    pub fn new(responder: Box<dyn NetResponder>) -> Self {
        Self {
            responder,
            pending_rx: VecDeque::new(),
            rx_capacity: None,
            guest_csum: false,
        }
    }

    /// Record the feature set the driver negotiated, so the device can use the
    /// offloads the guest agreed to. A rehydrated guest bound its features at
    /// capture time and cannot renegotiate, so this is read from the snapshot.
    pub fn with_features(mut self, acked: u64) -> Self {
        self.guest_csum = acked & VIRTIO_NET_F_GUEST_CSUM != 0;
        self
    }

    /// The virtio-net header flags to stamp on frames delivered to the guest.
    ///
    /// We terminate every flow ourselves, so a frame's payload is by
    /// construction what we intend the guest to receive; claiming
    /// `DATA_VALID` is therefore truthful, and it lets both sides skip a
    /// checksum pass over the whole payload.
    pub fn rx_header_flags(&self) -> u8 {
        if self.guest_csum {
            VIRTIO_NET_HDR_F_DATA_VALID
        } else {
            0
        }
    }

    /// Record the writable capacity of a receive descriptor chain the guest
    /// posted. Reported by the transport each time it pops one; the smallest
    /// chain seen is kept, so coalescing never produces a frame that a
    /// subsequent, smaller chain could not hold.
    pub fn observe_rx_capacity(&mut self, bytes: usize) {
        self.rx_capacity = Some(match self.rx_capacity {
            Some(prev) => prev.min(bytes),
            None => bytes,
        });
    }

    /// Take one transmitted Ethernet `frame` (already stripped of its virtio-net
    /// header). The frame is handed to the responder but not acted on here: this
    /// runs on a vCPU thread with the guest stopped, so any reply is produced by
    /// the next [`service`](Self::service) on the net service thread.
    pub fn handle_tx_frame(&mut self, frame: &[u8]) {
        self.responder.accept(frame);
    }

    /// Advance the responder's asynchronous work (e.g. a NAT relaying host
    /// socket data) and queue any resulting frames for the guest's receive
    /// queue. Returns whether any frame was produced, so the caller can decide
    /// to wake a parked vCPU. Driven by the net service thread, not a guest
    /// notify.
    pub fn service(&mut self) -> bool {
        let mut produced = false;
        // Build a backlog before returning, rather than handing the transport
        // whatever a single pass happened to produce. The responder's stack
        // emits only a segment or two per pass, so draining after each one caps
        // coalescing at that same segment or two no matter how large a receive
        // chain the guest posted. Filling one chain's worth first is what lets
        // [`super::lro`] turn the burst into one large frame.
        let target = self
            .rx_capacity
            .map_or(0, |cap| cap.saturating_sub(VIRTIO_NET_HDR_LEN));
        let mut pending_bytes: usize = self.pending_rx.iter().map(Vec::len).sum();
        for _ in 0..SERVICE_BURST_PASSES {
            let mut any = false;
            for reply in self.responder.service() {
                pending_bytes += reply.len();
                self.pending_rx.push_back(reply);
                produced = true;
                any = true;
            }
            // Stop as soon as one chain can be filled, and never spin on a
            // responder with nothing left to give: an idle pass costs a poll of
            // every host socket, and repeating it just burns a core.
            if !any || pending_bytes >= target {
                break;
            }
        }
        produced
    }

    /// Take the responder's accumulated egress-decision events for the audit
    /// trail (see [`NetResponder::drain_egress_events`]).
    pub fn drain_egress_events(&mut self) -> Vec<super::nat::EgressEvent> {
        self.responder.drain_egress_events()
    }

    /// Install the responder's interception hook, if it has one.
    pub fn set_intercept(
        &mut self,
        decider: Option<std::sync::Arc<dyn super::nat::InterceptDecider>>,
    ) {
        self.responder.set_intercept(decider);
    }

    /// Whether a frame is waiting to be delivered into the guest's receive
    /// queue.
    pub fn has_pending_rx(&self) -> bool {
        !self.pending_rx.is_empty()
    }

    /// Take the next frame to inject into the guest's receive queue, if any,
    /// merging any immediately following continuations of the same TCP flow into
    /// it (see [`super::lro`]). Until the transport has reported a chain
    /// capacity, frames are delivered one at a time.
    pub fn pop_rx(&mut self) -> Option<Vec<u8>> {
        let limit = self
            .rx_capacity
            .map_or(0, |cap| cap.saturating_sub(VIRTIO_NET_HDR_LEN));
        // When the frame will carry `DATA_VALID` the guest ignores the transport
        // checksum, so recomputing it over the merged payload would be pure cost.
        super::lro::pop_coalesced(&mut self.pending_rx, limit, !self.guest_csum)
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
        r.accept(&arp_request());
        let replies = r.service();
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
        r.accept(&arp_request());
        assert!(r.service().is_empty());
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
        r.accept(&req);
        let replies = r.service();
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
        // A transmit only hands the frame to the responder; the reply is
        // produced by the service thread, never on the vCPU thread.
        assert!(!dev.has_pending_rx());
        assert!(dev.service(), "service produced a reply");
        assert!(dev.has_pending_rx());
        let frame = dev.pop_rx().expect("a reply frame");
        assert_eq!(&frame[0..6], &GUEST_MAC);
        assert!(!dev.has_pending_rx());
    }
}
