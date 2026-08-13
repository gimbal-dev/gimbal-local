// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! Receive-side coalescing (LRO) for the guest-facing frame path.
//!
//! The userspace NAT emits one Ethernet frame per TCP segment, sized by the
//! synthetic link's 1500-byte MTU. The guest's receive descriptor chains are far
//! larger than that — a Linux `virtio-net` that negotiated `GUEST_TSO4` without
//! `MRG_RXBUF` posts multi-page "big packet" buffers — so delivering one segment
//! per chain wastes almost all of each buffer and costs one descriptor, one used
//! ring entry and one interrupt per 1.4 KiB of payload.
//!
//! This module merges consecutive, in-order segments of the same flow into a
//! single larger IP packet before delivery, exactly as a NIC with large-receive
//! offload does. The guest's TCP receives one big segment instead of forty small
//! ones; nothing about the connection changes, because coalescing is a receive
//! path concern that the sender never observes.
//!
//! Coalescing is deliberately conservative. A segment is only merged when it is
//! provably a plain continuation of the one before it: same flow, contiguous
//! sequence number, no options, not a fragment, and carrying no flag that has
//! meaning beyond "here is more data". Anything else is passed through
//! untouched. The size limit is not a constant — it comes from the writable
//! capacity actually observed in the guest's own receive chains, so a guest that
//! posts single-MTU buffers is never handed a frame it cannot hold.

/// Ethernet header length, and the offset of the IPv4 header within a frame.
const ETH_HDR: usize = 14;
/// The `EtherType` for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// The IPv4 protocol number for TCP.
const IP_PROTO_TCP: u8 = 6;
/// An IPv4 header with no options, in bytes. Coalescing requires this length so
/// the merged packet's header layout is unambiguous.
const IPV4_MIN_HDR: usize = 20;
/// A TCP header with no options, in bytes. Same reasoning as [`IPV4_MIN_HDR`]:
/// merging segments that carry differing options would change their meaning.
const TCP_MIN_HDR: usize = 20;

/// TCP flags that make a segment more than "more data", so it must never be
/// merged into (or absorb) another: FIN, SYN, RST and URG. PSH and ACK are the
/// only flags a pure data segment carries.
const TCP_FLAGS_NOT_DATA: u8 = 0x01 | 0x02 | 0x04 | 0x20;
/// The PSH flag, which propagates from a merged segment to the accumulator so
/// the guest still learns the sender asked for a push.
const TCP_FLAG_PSH: u8 = 0x08;

/// The largest IP packet that can be expressed at all: `tot_len` is a `u16`.
const IP_MAX_TOTAL: usize = u16::MAX as usize;

/// The parsed shape of an IPv4/TCP frame that is a candidate for coalescing.
#[derive(Debug, Clone, Copy)]
struct Seg {
    /// Offset of the TCP payload within the frame.
    payload_at: usize,
    /// Length of the TCP payload in bytes.
    payload_len: usize,
    /// The segment's sequence number.
    seq: u32,
    /// The segment's TCP flags byte.
    flags: u8,
}

/// Parse `frame` as a plain (option-free, unfragmented) IPv4 TCP segment.
/// Returns `None` for anything else — ARP, ICMP, IPv6, fragments, segments with
/// header options, or a frame whose length disagrees with its own IP header.
fn parse(frame: &[u8]) -> Option<Seg> {
    if frame.len() < ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETH_HDR..];
    // Version 4 with no options: anything else changes the header layout.
    if ip[0] != 0x45 || ip[9] != IP_PROTO_TCP {
        return None;
    }
    // Reject fragments: a non-zero offset or the MF bit means this frame is not
    // a whole datagram, so its payload is not a whole run of TCP bytes.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        return None;
    }
    let tot_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    // The IP header must describe exactly the bytes present. A frame shorter
    // than tot_len is truncated; a longer one carries Ethernet padding we would
    // otherwise merge into the stream as if it were payload.
    if tot_len < IPV4_MIN_HDR + TCP_MIN_HDR || ETH_HDR + tot_len != frame.len() {
        return None;
    }
    let tcp = &ip[IPV4_MIN_HDR..];
    // Data offset of 5 words == a 20-byte header, i.e. no TCP options.
    if (tcp[12] >> 4) as usize * 4 != TCP_MIN_HDR {
        return None;
    }
    Some(Seg {
        payload_at: ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR,
        payload_len: tot_len - IPV4_MIN_HDR - TCP_MIN_HDR,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        flags: tcp[13],
    })
}

/// Whether `next` is the immediate continuation of `acc` on the same flow, and
/// so may be merged into it without changing what either segment means.
fn continues(acc: &[u8], a: &Seg, next: &[u8], b: &Seg) -> bool {
    // Both must be pure data segments; a SYN/FIN/RST/URG carries connection
    // state that would be lost or duplicated by merging.
    if a.flags & TCP_FLAGS_NOT_DATA != 0 || b.flags & TCP_FLAGS_NOT_DATA != 0 {
        return false;
    }
    // A zero-length continuation contributes nothing but would still let its
    // (possibly stale) header fields overwrite the accumulator's.
    if b.payload_len == 0 {
        return false;
    }
    // Same flow: Ethernet endpoints, IP endpoints and TCP ports.
    if acc[0..12] != next[0..12] {
        return false;
    }
    let (ai, bi) = (&acc[ETH_HDR..], &next[ETH_HDR..]);
    if ai[12..20] != bi[12..20] {
        return false; // IP src/dst
    }
    let (at, bt) = (&ai[IPV4_MIN_HDR..], &bi[IPV4_MIN_HDR..]);
    if at[0..4] != bt[0..4] {
        return false; // TCP src/dst ports
    }
    // Contiguous: the next segment must start exactly where this one ends, so
    // the merged payload is one unbroken run of the byte stream. Wrapping
    // addition is correct — TCP sequence space is modulo 2^32.
    a.seq.wrapping_add(a.payload_len as u32) == b.seq
}

/// Merge `next`'s payload into `acc`, updating the fields that must reflect the
/// newer segment. The caller checksums once the run is complete: doing it per
/// merge would rescan the whole accumulated payload every time.
fn merge(acc: &mut Vec<u8>, a: &Seg, next: &[u8], b: &Seg) {
    acc.extend_from_slice(&next[b.payload_at..b.payload_at + b.payload_len]);
    let payload = a.payload_len + b.payload_len;

    let bt = &next[ETH_HDR + IPV4_MIN_HDR..];
    let (ack, window, push) = (
        [bt[8], bt[9], bt[10], bt[11]],
        [bt[14], bt[15]],
        b.flags & TCP_FLAG_PSH,
    );

    let tot_len = (IPV4_MIN_HDR + TCP_MIN_HDR + payload) as u16;
    let ip = &mut acc[ETH_HDR..];
    ip[2..4].copy_from_slice(&tot_len.to_be_bytes());
    let tcp = &mut ip[IPV4_MIN_HDR..];
    // Carry forward the newest acknowledgement and window: they describe the
    // sender's current view, and the older values are stale by definition.
    tcp[8..12].copy_from_slice(&ack);
    tcp[14..16].copy_from_slice(&window);
    tcp[13] |= push;
}

/// Recompute the IPv4 header checksum of a merged frame in place, and its TCP
/// checksum too when `tcp` is set.
///
/// The IP header checksum is never optional: Linux verifies it on every ingress
/// packet regardless of any offload the driver negotiated. The TCP checksum is
/// skipped when the frame will be delivered as `VIRTIO_NET_HDR_F_DATA_VALID`,
/// which is the whole payload's worth of work.
fn checksum_in_place(frame: &mut [u8], tcp: bool) {
    let ip_at = ETH_HDR;
    frame[ip_at + 10..ip_at + 12].copy_from_slice(&[0, 0]);
    let ip_csum = ones_complement(&frame[ip_at..ip_at + IPV4_MIN_HDR], 0);
    frame[ip_at + 10..ip_at + 12].copy_from_slice(&ip_csum.to_be_bytes());

    if !tcp {
        return;
    }
    let tcp_at = ip_at + IPV4_MIN_HDR;
    let tcp_len = frame.len() - tcp_at;
    // TCP's pseudo-header: source and destination address, a zero byte, the
    // protocol number, and the TCP length.
    let mut sum: u32 = 0;
    for chunk in frame[ip_at + 12..ip_at + 20].chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += IP_PROTO_TCP as u32 + tcp_len as u32;
    frame[tcp_at + 16..tcp_at + 18].copy_from_slice(&[0, 0]);
    let tcp_csum = ones_complement(&frame[tcp_at..], sum);
    frame[tcp_at + 16..tcp_at + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// The internet checksum (RFC 1071) over `data`, seeded with `init` so a
/// pseudo-header can be folded in.
fn ones_complement(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Take the frame at the front of `queue`, absorbing as many immediately
/// following continuations of the same flow as fit in `limit` bytes.
///
/// `limit` is the guest's own receive capacity, so passing the MTU disables
/// coalescing entirely and the queue drains one frame at a time exactly as
/// before. Frames that are not part of the merged run keep their order relative
/// to each other, because only a strict prefix of the queue is ever consumed.
///
/// `tcp_checksum` selects whether the merged packet's transport checksum is
/// recomputed. A caller that stamps `VIRTIO_NET_HDR_F_DATA_VALID` on the frame
/// passes `false`: the guest will not look at that field, and computing it means
/// a second pass over every byte of the payload.
pub fn pop_coalesced(
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    limit: usize,
    tcp_checksum: bool,
) -> Option<Vec<u8>> {
    let mut acc = queue.pop_front()?;
    let limit = limit.min(ETH_HDR + IP_MAX_TOTAL);
    let Some(mut seg) = parse(&acc) else {
        return Some(acc);
    };
    let mut merged = false;
    while let Some(next) = queue.front() {
        let Some(nseg) = parse(next) else { break };
        if acc.len() + nseg.payload_len > limit {
            break;
        }
        if !continues(&acc, &seg, next, &nseg) {
            break;
        }
        let next = queue.pop_front().expect("peeked");
        merge(&mut acc, &seg, &next, &nseg);
        seg.payload_len += nseg.payload_len;
        seg.flags |= nseg.flags & TCP_FLAG_PSH;
        merged = true;
    }
    // Only a merged packet's headers changed, so an untouched frame keeps the
    // checksums its sender already computed.
    if merged {
        checksum_in_place(&mut acc, tcp_checksum);
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Build a plain IPv4 TCP frame with correct checksums.
    fn seg(seq: u32, payload: &[u8], flags: u8, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR + payload.len()];
        f[0..6].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let tot = (IPV4_MIN_HDR + TCP_MIN_HDR + payload.len()) as u16;
        let ip = &mut f[ETH_HDR..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&tot.to_be_bytes());
        ip[8] = 64; // TTL
        ip[9] = IP_PROTO_TCP;
        ip[12..16].copy_from_slice(&[192, 168, 249, 1]);
        ip[16..20].copy_from_slice(&[192, 168, 249, 2]);
        let tcp = &mut ip[IPV4_MIN_HDR..];
        tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&7u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        f[ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR..].copy_from_slice(payload);
        checksum_in_place(&mut f, true);
        f
    }

    fn payload_of(frame: &[u8]) -> &[u8] {
        &frame[ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR..]
    }

    /// The checksum of a frame is valid iff summing the covered bytes with the
    /// checksum field still in place yields zero.
    fn checksums_valid(frame: &[u8]) -> bool {
        let ip_ok = ones_complement(&frame[ETH_HDR..ETH_HDR + IPV4_MIN_HDR], 0) == 0;
        let tcp_at = ETH_HDR + IPV4_MIN_HDR;
        let mut pseudo: u32 = 0;
        for c in frame[ETH_HDR + 12..ETH_HDR + 20].chunks(2) {
            pseudo += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        pseudo += IP_PROTO_TCP as u32 + (frame.len() - tcp_at) as u32;
        ip_ok && ones_complement(&frame[tcp_at..], pseudo) == 0
    }

    #[test]
    fn merges_contiguous_segments_of_one_flow() {
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(seg(1000, &[1u8; 100], 0x10, 5000));
        q.push_back(seg(1100, &[2u8; 100], 0x10, 5000));
        q.push_back(seg(1200, &[3u8; 100], 0x18, 5000));
        let out = pop_coalesced(&mut q, 65535, true).expect("a frame");
        assert!(q.is_empty(), "all three should have been absorbed");
        let p = payload_of(&out);
        assert_eq!(p.len(), 300, "payloads concatenate");
        assert_eq!(&p[..100], &[1u8; 100]);
        assert_eq!(&p[100..200], &[2u8; 100]);
        assert_eq!(&p[200..], &[3u8; 100]);
        // The merged packet must still be a valid, self-consistent IP datagram.
        let tot = u16::from_be_bytes([out[ETH_HDR + 2], out[ETH_HDR + 3]]) as usize;
        assert_eq!(ETH_HDR + tot, out.len(), "tot_len describes the frame");
        assert!(checksums_valid(&out), "IP and TCP checksums recomputed");
        // The PSH of the last absorbed segment reaches the guest.
        assert_eq!(out[ETH_HDR + IPV4_MIN_HDR + 13] & TCP_FLAG_PSH, TCP_FLAG_PSH);
    }

    #[test]
    fn a_gap_in_the_sequence_stops_the_merge() {
        // Losing this check would splice a hole in the byte stream silently:
        // the guest would accept 200 bytes as contiguous when 100 are missing.
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(seg(1000, &[1u8; 100], 0x10, 5000));
        q.push_back(seg(1200, &[2u8; 100], 0x10, 5000)); // gap at 1100
        let out = pop_coalesced(&mut q, 65535, true).expect("a frame");
        assert_eq!(payload_of(&out).len(), 100, "must not merge across a gap");
        assert_eq!(q.len(), 1, "the discontiguous segment stays queued");
    }

    #[test]
    fn a_different_flow_is_not_merged() {
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(seg(1000, &[1u8; 100], 0x10, 5000));
        q.push_back(seg(1100, &[2u8; 100], 0x10, 5001)); // contiguous seq, other port
        let out = pop_coalesced(&mut q, 65535, true).expect("a frame");
        assert_eq!(payload_of(&out).len(), 100, "ports differ; separate flows");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn connection_state_flags_are_never_merged() {
        // A FIN absorbed into a data segment would lose the close, and a SYN
        // would lose the handshake. Both must be delivered on their own.
        for flag in [0x01u8, 0x02, 0x04, 0x20] {
            let mut q: VecDeque<Vec<u8>> = VecDeque::new();
            q.push_back(seg(1000, &[1u8; 100], 0x10, 5000));
            q.push_back(seg(1100, &[2u8; 100], 0x10 | flag, 5000));
            let out = pop_coalesced(&mut q, 65535, true).expect("a frame");
            assert_eq!(payload_of(&out).len(), 100, "flag {flag:#x} must not merge");
            assert_eq!(q.len(), 1, "flag {flag:#x} segment stays queued");
        }
    }

    #[test]
    fn the_guests_capacity_bounds_the_merged_frame() {
        // The limit is the guest's own receive-chain capacity. Exceeding it
        // would have the transport truncate and drop the frame.
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        for i in 0..8 {
            q.push_back(seg(1000 + i * 100, &[i as u8; 100], 0x10, 5000));
        }
        let limit = ETH_HDR + IPV4_MIN_HDR + TCP_MIN_HDR + 250;
        let out = pop_coalesced(&mut q, limit, true).expect("a frame");
        assert!(out.len() <= limit, "merged {} exceeds limit {limit}", out.len());
        assert_eq!(payload_of(&out).len(), 200, "stops before overrunning");
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn an_mtu_limit_disables_coalescing() {
        // A guest posting single-MTU receive buffers must keep getting one
        // segment per frame, unchanged.
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        let first = seg(1000, &[1u8; 1400], 0x10, 5000);
        q.push_back(first.clone());
        q.push_back(seg(2400, &[2u8; 1400], 0x10, 5000));
        let out = pop_coalesced(&mut q, 1514, true).expect("a frame");
        assert_eq!(out, first, "frame delivered byte-for-byte unchanged");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn non_tcp_frames_pass_through_untouched() {
        let arp = vec![0xffu8; 42];
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(arp.clone());
        q.push_back(seg(1000, &[1u8; 100], 0x10, 5000));
        assert_eq!(pop_coalesced(&mut q, 65535, true).unwrap(), arp);
        assert_eq!(q.len(), 1, "the TCP segment is untouched behind it");
    }

    #[test]
    fn a_padded_frame_is_not_merged() {
        // Ethernet pads short frames to 60 bytes. Merging one would splice the
        // padding into the guest's byte stream as if it were data.
        let mut padded = seg(1000, &[], 0x10, 5000);
        padded.resize(60, 0);
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(padded.clone());
        q.push_back(seg(1000, &[2u8; 100], 0x10, 5000));
        assert_eq!(pop_coalesced(&mut q, 65535, true).unwrap(), padded);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn sequence_wraparound_still_merges() {
        // TCP sequence space is modulo 2^32; a flow that wraps mid-transfer
        // must keep coalescing rather than silently fall back to one frame
        // per segment for the rest of its life.
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        q.push_back(seg(u32::MAX - 49, &[1u8; 100], 0x10, 5000));
        q.push_back(seg(50, &[2u8; 100], 0x10, 5000));
        let out = pop_coalesced(&mut q, 65535, true).expect("a frame");
        assert_eq!(payload_of(&out).len(), 200, "wrapped sequence is contiguous");
        assert!(q.is_empty());
    }
}
