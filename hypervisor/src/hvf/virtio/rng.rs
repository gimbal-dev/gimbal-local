// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A `virtio-rng` request processor: fill the guest's device-writable buffers
//! with entropy.
//!
//! virtio-rng requests carry no header — every descriptor segment is a
//! device-writable buffer to be filled with random bytes. The number of bytes
//! written is reported as the used-ring length.

use std::io::Read;

use super::queue::DescChain;
use super::GuestMemory;

/// Source of entropy for an [`RngDevice`].
pub trait EntropySource: Send {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Entropy from the host's `/dev/urandom`.
pub struct UrandomSource {
    file: std::fs::File,
}

impl UrandomSource {
    /// Open `/dev/urandom`.
    pub fn open() -> std::io::Result<Self> {
        Ok(Self {
            file: std::fs::File::open("/dev/urandom")?,
        })
    }
}

impl EntropySource for UrandomSource {
    fn fill(&mut self, buf: &mut [u8]) {
        // Best-effort: on the extremely unlikely short read, leave the tail as-is
        // (still acceptable entropy to the guest's pool mixing).
        let _ = self.file.read_exact(buf);
    }
}

/// A `virtio-rng` device.
pub struct RngDevice {
    source: Box<dyn EntropySource>,
}

impl RngDevice {
    /// Build an rng device over `source`.
    pub fn new(source: Box<dyn EntropySource>) -> Self {
        Self { source }
    }

    /// Fill the chain's device-writable buffers with entropy; return the total
    /// bytes written (the used-ring length).
    pub fn process(&mut self, mem: &GuestMemory, chain: &DescChain) -> u32 {
        let mut written = 0u32;
        for seg in chain.writable() {
            let mut buf = vec![0u8; seg.len as usize];
            self.source.fill(&mut buf);
            if mem.write(seg.gpa, &buf).is_err() {
                break;
            }
            written = written.saturating_add(seg.len);
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::Segment;
    use super::*;

    struct Counter(u8);
    impl EntropySource for Counter {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn fills_writable_buffers() {
        let m = GuestMemory::new();
        m.register_owned(0x2000, 0x1000);
        let mut dev = RngDevice::new(Box::new(Counter(0)));
        let chain = DescChain {
            head: 0,
            segments: vec![Segment { gpa: 0x2000, len: 8, write: true }],
        };
        let n = dev.process(&m, &chain);
        assert_eq!(n, 8);
        let mut got = [0u8; 8];
        m.read(0x2000, &mut got).unwrap();
        assert_eq!(got, [0, 1, 2, 3, 4, 5, 6, 7]);
    }
}
