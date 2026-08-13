// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A `smoltcp` [`phy::Device`] that bridges the userspace TCP/IP stack to the
//! virtio-net frame path. It is not a real NIC: its "wire" is two in-memory
//! queues.
//!
//!  * `from_guest` — Ethernet frames the guest transmitted (fed in by the
//!    virtio TX path); `receive` hands them to smoltcp.
//!  * `to_guest` — Ethernet frames smoltcp produced; drained by the NAT and
//!    injected into the guest's virtio RX queue.
//!
//! Checksums are computed in software (the guest and smoltcp both expect valid
//! checksums; there is no hardware offload on this synthetic link).

use smoltcp::phy::{self, Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::collections::VecDeque;

/// The MTU of the synthetic link. 1500 matches what capture-side cloud-init
/// configures on the guest NIC, so no path-MTU surprises.
pub const NAT_MTU: usize = 1500;

/// A frame-queue-backed smoltcp device.
#[derive(Debug, Default)]
pub struct FrameDevice {
    from_guest: VecDeque<Vec<u8>>,
    to_guest: VecDeque<Vec<u8>>,
}

impl FrameDevice {
    /// Queue a guest-transmitted Ethernet `frame` for smoltcp to receive.
    pub fn push_from_guest(&mut self, frame: Vec<u8>) {
        self.from_guest.push_back(frame);
    }

    /// Take the next frame smoltcp produced for delivery to the guest.
    pub fn pop_to_guest(&mut self) -> Option<Vec<u8>> {
        self.to_guest.pop_front()
    }
}

impl Device for FrameDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = NAT_MTU;
        // The guest's virtio-net negotiated TCP/UDP checksum OFFLOAD (the standard
        // VIRTIO_NET_F_CSUM), so it posts TCP/UDP segments with BLANK/partial L4
        // checksums, expecting the "NIC" to complete them. This synthetic link is
        // that NIC, so we must NOT verify those checksums on receive (smoltcp's
        // default would drop them as corrupt — the exact symptom of DNS/TCP
        // silently timing out while ICMP, which virtio-net does not offload,
        // works). Compute valid checksums on transmit so our replies are accepted.
        // IPv4 header + ICMPv4 are not offloaded, so keep verifying those.
        let mut checksum = ChecksumCapabilities::default();
        checksum.tcp = Checksum::Tx;
        checksum.udp = Checksum::Tx;
        caps.checksum = checksum;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.from_guest.pop_front()?;
        let rx = RxToken { buffer };
        let tx = TxToken {
            queue: &mut self.to_guest,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.to_guest,
        })
    }
}

/// A receive token owning one guest-transmitted frame.
#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// A transmit token that appends the produced frame to the to-guest queue.
#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{RxToken as _, TxToken as _};

    #[test]
    fn receive_moves_a_guest_frame_and_offers_a_tx_token() {
        let mut dev = FrameDevice::default();
        dev.push_from_guest(vec![1, 2, 3, 4]);
        let (rx, tx) = dev.receive(Instant::from_millis(0)).expect("a frame");
        rx.consume(|bytes| assert_eq!(bytes, &[1, 2, 3, 4]));
        // The paired tx token delivers a reply into the to-guest queue.
        tx.consume(2, |buf| buf.copy_from_slice(&[9, 9]));
        assert_eq!(dev.pop_to_guest().unwrap(), vec![9, 9]);
        assert!(dev.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn tcp_udp_rx_checksums_are_not_verified() {
        // The guest's virtio-net offloads TCP/UDP checksums, so it posts segments
        // with blank/partial L4 checksums. If we verified them on receive, smoltcp
        // would silently drop every TCP/UDP frame (DNS + connections time out
        // while ICMP works). Assert we only COMPUTE them (Tx), never verify (Rx),
        // for TCP/UDP — while IPv4 + ICMPv4 (not offloaded) stay fully checked.
        let caps = FrameDevice::default().capabilities();
        assert!(!caps.checksum.tcp.rx(), "must not verify guest TCP checksums");
        assert!(caps.checksum.tcp.tx(), "must compute TCP checksums on reply");
        assert!(!caps.checksum.udp.rx(), "must not verify guest UDP checksums");
        assert!(caps.checksum.udp.tx(), "must compute UDP checksums on reply");
        assert!(caps.checksum.ipv4.rx(), "IPv4 header is not offloaded; verify it");
        assert!(caps.checksum.icmpv4.rx(), "ICMPv4 is not offloaded; verify it");
    }

    #[test]
    fn transmit_queues_to_guest() {
        let mut dev = FrameDevice::default();
        let tx = dev.transmit(Instant::from_millis(0)).unwrap();
        tx.consume(3, |buf| buf.copy_from_slice(&[7, 8, 9]));
        assert_eq!(dev.pop_to_guest().unwrap(), vec![7, 8, 9]);
    }

    #[test]
    fn mtu_is_advertised() {
        let dev = FrameDevice::default();
        assert_eq!(dev.capabilities().max_transmission_unit, NAT_MTU);
    }
}
