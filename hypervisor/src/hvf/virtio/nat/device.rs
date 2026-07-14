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

use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
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
        // Compute/verify checksums in software: this is not a real offloading
        // NIC, and the guest posts frames expecting valid checksums.
        caps.checksum = ChecksumCapabilities::default();
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
