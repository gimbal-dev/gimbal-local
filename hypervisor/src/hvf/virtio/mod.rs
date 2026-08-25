// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A real, native virtio device model for the macOS rehydration path.
//!
//! A cloud-hypervisor arm64 snapshot resumes with its virtio devices fully
//! driven (`driver_status = DRIVER_OK`): the guest's drivers have already
//! negotiated features and published their split virtqueues in guest RAM. When
//! the resumed guest kicks a queue it performs an MMIO write to the device's
//! virtio-pci notify window, which traps out to us. This module provides the
//! pieces needed to service that:
//!
//! - [`GuestMemory`]: a host view of the guest-physical address space, sharing
//!   the exact same backing pages the hypervisor maps into the guest, so a
//!   device's reads and writes are visible to the guest and vice-versa.
//! - [`queue::Queue`]: a split-virtqueue engine (descriptor chains, including
//!   `VIRTIO_RING_F_INDIRECT_DESC`, and the `VIRTIO_RING_F_EVENT_IDX`
//!   suppression scheme — both of which this snapshot negotiates).
//! - [`block::BlockDevice`] / [`rng::RngDevice`]: the device backends that
//!   consume a popped descriptor chain and produce a used-ring completion.
//!
//! Interrupt *delivery* of the resulting completion is deliberately out of
//! scope here: this snapshot's guest is wired for MSI-X delivered as LPIs via a
//! GIC ITS, and Apple's managed GIC models no ITS (only message-based SPIs via
//! `hv_gic_send_msi`). Closing that gap requires a user-space GICv3 + ITS and is
//! tracked as its own milestone; see `docs/macos-local-runtime.md`. This module
//! still completes requests (writes the used ring and latches the ISR) so the
//! data path is real and unit-testable today.

use std::sync::Mutex;

pub mod block;
pub mod devcore;
pub mod devmgr;
pub mod its;
pub mod mmio;
pub mod lro;
pub mod nat;
pub mod net;
pub(crate) mod pathsafe;
pub mod pci;
pub mod queue;
pub mod rng;

/// The surface a host-side net service thread needs from a virtio NIC,
/// independent of the transport that carries it.
///
/// A cold-booted guest's NIC is virtio-mmio; a restored cloud-hypervisor
/// snapshot's is virtio-pci. The loop that pumps frames does not care which:
/// it attaches a wake handle, services the backend, and drains the egress
/// decisions the audit trail is built from. Naming that surface once is what
/// lets a single service loop serve both, rather than the tree carrying two
/// renderings of one posture -- which drift, and the drift is invisible until
/// a sandbox that was supposed to be recording reaches a host with an empty
/// trail behind it.
pub trait NetIo: Send + Sync {
    /// The device's name, as it appears in an audit record or a refusal.
    fn name(&self) -> &str;
    /// Attach the wake handle the service thread waits on, so a guest transmit
    /// does not have to wait out the poll interval.
    fn set_net_kick(&self, kick: std::sync::Arc<net::NetKick>);
    /// Advance the net backend and deliver any frames it produced. Returns
    /// whether a frame reached the guest.
    fn service_net(&self) -> bool;
    /// Take the egress decisions recorded since the last call. Draining is not
    /// optional: the NAT buffers every decision until somebody takes them.
    fn drain_egress_events(&self) -> Vec<nat::EgressEvent>;
    /// Attach (or clear) the credential proxy's interception decision. On the
    /// trait rather than the concrete types so one caller installs the proxy on
    /// every NIC however it arrived: two renderings of one security posture
    /// drift, and the drift is invisible until a guest reaches a host unsigned.
    fn set_net_intercept(&self, decider: Option<std::sync::Arc<dyn nat::InterceptDecider>>);
    /// Apply a live change to this NIC's egress policy, reporting what it did,
    /// or `None` if this device enforces no policy (#156).
    ///
    /// On the trait for the same reason `set_net_intercept` is: one caller
    /// amends every NIC however it arrived, so a sandbox cannot end up with two
    /// NICs enforcing two different postures because the amendment only reached
    /// the transport somebody happened to think of.
    fn amend_net_egress(&self, amendment: &nat::Amendment) -> Option<nat::AmendOutcome>;
}

impl NetIo for pci::VirtioPciDevice {
    fn name(&self) -> &str {
        pci::VirtioPciDevice::name(self)
    }
    fn set_net_kick(&self, kick: std::sync::Arc<net::NetKick>) {
        pci::VirtioPciDevice::set_net_kick(self, kick);
    }
    fn service_net(&self) -> bool {
        pci::VirtioPciDevice::service_net(self)
    }
    fn drain_egress_events(&self) -> Vec<nat::EgressEvent> {
        pci::VirtioPciDevice::drain_egress_events(self)
    }
    fn set_net_intercept(&self, decider: Option<std::sync::Arc<dyn nat::InterceptDecider>>) {
        pci::VirtioPciDevice::set_net_intercept(self, decider);
    }
    fn amend_net_egress(&self, amendment: &nat::Amendment) -> Option<nat::AmendOutcome> {
        pci::VirtioPciDevice::amend_net_egress(self, amendment)
    }
}

impl NetIo for mmio::VirtioMmioDevice {
    fn name(&self) -> &str {
        mmio::VirtioMmioDevice::name(self)
    }
    fn set_net_kick(&self, kick: std::sync::Arc<net::NetKick>) {
        mmio::VirtioMmioDevice::set_net_kick(self, kick);
    }
    fn service_net(&self) -> bool {
        mmio::VirtioMmioDevice::service_net(self)
    }
    fn drain_egress_events(&self) -> Vec<nat::EgressEvent> {
        mmio::VirtioMmioDevice::drain_egress_events(self)
    }
    fn set_net_intercept(&self, decider: Option<std::sync::Arc<dyn nat::InterceptDecider>>) {
        mmio::VirtioMmioDevice::set_net_intercept(self, decider);
    }
    fn amend_net_egress(&self, amendment: &nat::Amendment) -> Option<nat::AmendOutcome> {
        mmio::VirtioMmioDevice::amend_net_egress(self, amendment)
    }
}

/// A contiguous guest-physical RAM region backed by a host pointer.
struct Region {
    gpa: u64,
    ptr: *mut u8,
    size: usize,
    /// Test-only owning backing. In production the mapping is owned by the
    /// rehydration layer's `GuestRam`; `ptr` then points into that mapping and
    /// `_own` is `None`. For unit tests we own a heap buffer here so `ptr`
    /// stays valid for the region's lifetime (the `Vec` is never resized, so
    /// its heap allocation does not move even if the `Region` itself moves).
    _own: Option<Vec<u8>>,
}

/// A host view of guest-physical memory.
///
/// Holds non-owning pointers to the same pages the hypervisor maps into the
/// guest. Reads and writes therefore observe and mutate live guest RAM. All
/// accesses are bounds-checked against the registered regions.
pub struct GuestMemory {
    regions: Mutex<Vec<Region>>,
}

// SAFETY: the raw pointers address guest RAM that outlives this view (it is
// owned by the rehydration layer for the VM's lifetime, or by the region's own
// `_own` buffer in tests). Accesses are serialized through the `Mutex` and the
// device model never aliases a region with a live Rust reference.
unsafe impl Send for GuestMemory {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for GuestMemory {}

/// Error accessing guest memory through a [`GuestMemory`] view.
#[derive(Debug, PartialEq, Eq)]
pub struct GuestMemError {
    /// The guest-physical address that could not be fully serviced.
    pub gpa: u64,
    /// The number of bytes requested.
    pub len: usize,
}

impl std::fmt::Display for GuestMemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "guest memory access [{:#x}, +{:#x}) is not backed",
            self.gpa, self.len
        )
    }
}

impl std::error::Error for GuestMemError {}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestMemory {
    /// Create an empty view with no regions registered.
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
        }
    }

    /// Register a guest-RAM region `[gpa, gpa+size)` backed by host `ptr`.
    ///
    /// # Safety
    /// `ptr` must be valid for reads and writes of `size` bytes for as long as
    /// this [`GuestMemory`] is used, and must not be aliased by any live Rust
    /// reference.
    pub unsafe fn register(&self, gpa: u64, ptr: *mut u8, size: usize) {
        self.regions.lock().unwrap().push(Region {
            gpa,
            ptr,
            size,
            _own: None,
        });
    }

    /// Register a test region owning a zeroed `size`-byte buffer at `gpa`.
    #[cfg(test)]
    pub fn register_owned(&self, gpa: u64, size: usize) {
        let mut buf = vec![0u8; size];
        let ptr = buf.as_mut_ptr();
        self.regions.lock().unwrap().push(Region {
            gpa,
            ptr,
            size,
            _own: Some(buf),
        });
    }

    /// Run `f` with the host pointer for `[gpa, gpa+len)`, or return an error if
    /// that range is not wholly within one registered region.
    fn with_ptr<R>(
        &self,
        gpa: u64,
        len: usize,
        f: impl FnOnce(*mut u8) -> R,
    ) -> Result<R, GuestMemError> {
        let regions = self.regions.lock().unwrap();
        for r in regions.iter() {
            if gpa >= r.gpa && gpa.saturating_add(len as u64) <= r.gpa + r.size as u64 {
                let off = (gpa - r.gpa) as usize;
                // SAFETY: `off + len <= size` per the bounds check above, so the
                // pointer is in range; the region is valid for the view's life.
                return Ok(f(unsafe { r.ptr.add(off) }));
            }
        }
        Err(GuestMemError { gpa, len })
    }

    /// Run `f` with a shared slice over `[gpa, gpa+len)` of guest RAM.
    ///
    /// This lets a device consume a guest buffer in place — e.g. writing a
    /// virtio-blk payload straight to the backing file — instead of copying it
    /// into a temporary. On a bulk write that removes one full copy of the data
    /// plus a heap allocation per descriptor segment.
    ///
    /// As everywhere else in this module, the caller must only use it for a
    /// buffer the guest has handed to the device (an in-flight descriptor),
    /// which the guest must not touch until the request is completed.
    pub fn with_slice<R>(
        &self,
        gpa: u64,
        len: usize,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, GuestMemError> {
        // SAFETY: `with_ptr` bounds-checks `[gpa, gpa+len)` against a registered
        // region, so the pointer is valid for `len` bytes for the call's life.
        self.with_ptr(gpa, len, |p| f(unsafe { std::slice::from_raw_parts(p, len) }))
    }

    /// Mutable counterpart of [`Self::with_slice`], for filling a guest buffer
    /// (e.g. a virtio-blk read) directly from the backing store.
    pub fn with_slice_mut<R>(
        &self,
        gpa: u64,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, GuestMemError> {
        self.with_ptr(gpa, len, |p| {
            // SAFETY: as `with_slice`; the range is checked to lie in one region
            // and the device owns the buffer for the duration of the request.
            let r = f(unsafe { std::slice::from_raw_parts_mut(p, len) });
            // The callback has just filled guest RAM from the host side -- for
            // virtio-blk, with file content the guest is quite likely to
            // execute. Stage 2 never saw the store, so this is the only place
            // the instruction-cache maintenance can happen for it. No-op unless
            // the guest is one that needs it.
            crate::hvf::icache_wx::on_device_write(p, len);
            r
        })
    }

    /// Guest RAM as `(guest physical base, host base, length)`, for
    /// [`crate::hvf::icache_wx::arm`].
    ///
    /// This view holds the same pointers the hypervisor mapped into the guest,
    /// so it is the natural place to ask: the alternative is reaching into
    /// `Arc<dyn Vm>` for mappings that describe the very same pages.
    pub fn icache_regions(&self) -> Vec<(u64, usize, usize)> {
        self.regions
            .lock()
            .unwrap()
            .iter()
            .map(|r| (r.gpa, r.ptr as usize, r.size))
            .collect()
    }

    /// Read `buf.len()` bytes starting at `gpa`.
    pub fn read(&self, gpa: u64, buf: &mut [u8]) -> Result<(), GuestMemError> {
        let n = buf.len();
        self.with_ptr(gpa, n, |src| {
            // SAFETY: `src` is valid for `n` bytes (checked) and `buf` is a
            // distinct, valid destination of length `n`.
            unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n) };
        })
    }

    /// Write `buf` starting at `gpa`.
    pub fn write(&self, gpa: u64, buf: &[u8]) -> Result<(), GuestMemError> {
        let n = buf.len();
        self.with_ptr(gpa, n, |dst| {
            // SAFETY: `dst` is valid for `n` bytes (checked) and `buf` is a
            // distinct, valid source of length `n`.
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), dst, n) };
            // Every device write into guest RAM funnels through here, so this is
            // the one hook that covers them all. See `with_slice_mut` for why
            // stage 2 cannot do it for us.
            crate::hvf::icache_wx::on_device_write(dst, n);
        })
    }

    /// Read a little-endian `u16` at `gpa`.
    pub fn read_u16(&self, gpa: u64) -> Result<u16, GuestMemError> {
        let mut b = [0u8; 2];
        self.read(gpa, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    /// Read a little-endian `u32` at `gpa`.
    pub fn read_u32(&self, gpa: u64) -> Result<u32, GuestMemError> {
        let mut b = [0u8; 4];
        self.read(gpa, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Read a little-endian `u64` at `gpa`.
    pub fn read_u64(&self, gpa: u64) -> Result<u64, GuestMemError> {
        let mut b = [0u8; 8];
        self.read(gpa, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Write a little-endian `u16` at `gpa`.
    pub fn write_u16(&self, gpa: u64, v: u16) -> Result<(), GuestMemError> {
        self.write(gpa, &v.to_le_bytes())
    }

    /// Write a little-endian `u32` at `gpa`.
    pub fn write_u32(&self, gpa: u64, v: u32) -> Result<(), GuestMemError> {
        self.write(gpa, &v.to_le_bytes())
    }

    /// Write a little-endian `u64` at `gpa`.
    pub fn write_u64(&self, gpa: u64, v: u64) -> Result<(), GuestMemError> {
        self.write(gpa, &v.to_le_bytes())
    }
}

/// virtio feature bits this model cares about (bit positions).
pub mod features {
    /// `VIRTIO_RING_F_INDIRECT_DESC`: a descriptor may reference an indirect
    /// table of further descriptors.
    pub const RING_INDIRECT_DESC: u64 = 1 << 28;
    /// `VIRTIO_RING_F_EVENT_IDX`: used/avail rings carry an event index for
    /// finer interrupt/notification suppression.
    pub const RING_EVENT_IDX: u64 = 1 << 29;
    /// `VIRTIO_F_VERSION_1`: modern (non-legacy) virtio.
    pub const VERSION_1: u64 = 1 << 32;
    /// `VIRTIO_BLK_F_FLUSH`: the device has a volatile write cache, so the
    /// driver must issue `VIRTIO_BLK_T_FLUSH` to make writes durable.
    ///
    /// **This has to be offered.** Without it Linux calls
    /// `blk_queue_write_cache(q, false, false)` and stops emitting barriers
    /// altogether, having been told the device is already write-through. A
    /// file-backed disk is not: it sits behind the host page cache. The guest
    /// then builds a journal whose ordering nothing enforces, and a guest that
    /// stops without unmounting comes back with a filesystem the journal cannot
    /// repair -- measured here as `EXT4-fs error: deleted inode referenced`.
    pub const BLK_FLUSH: u64 = 1 << 9;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn guest_memory_read_write_roundtrip() {
        let mem = GuestMemory::new();
        mem.register_owned(0x4000_0000, 0x1000);
        mem.write_u32(0x4000_0010, 0xdead_beef).unwrap();
        assert_eq!(mem.read_u32(0x4000_0010).unwrap(), 0xdead_beef);
        mem.write(0x4000_0020, b"hello").unwrap();
        let mut b = [0u8; 5];
        mem.read(0x4000_0020, &mut b).unwrap();
        assert_eq!(&b, b"hello");
    }

    #[test]
    fn guest_memory_rejects_out_of_range() {
        let mem = GuestMemory::new();
        mem.register_owned(0x4000_0000, 0x1000);
        mem.read_u32(0x4000_0ffe).unwrap_err(); // straddles the end
        mem.read_u32(0x5000_0000).unwrap_err(); // unbacked
    }

    /// Both transports, reached the way the net service thread reaches them.
    /// A device reached the way the net service thread reaches it, paired with
    /// the name it should answer with.
    type NamedNic = (&'static str, Arc<dyn NetIo>);

    fn as_net_io() -> (Arc<AtomicUsize>, Vec<NamedNic>) {
        use net::{NetDevice, NetResponder};

        // A responder that always has one decision to hand over and one frame
        // to deliver, so an impl that answered with an empty vec is visibly
        // wrong rather than coincidentally right.
        struct Talkative(Arc<AtomicUsize>);
        impl NetResponder for Talkative {
            fn accept(&mut self, _frame: &[u8]) {}
            fn set_intercept(&mut self, _d: Option<Arc<dyn nat::InterceptDecider>>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn service(&mut self) -> Vec<Vec<u8>> {
                vec![vec![0u8; 64]]
            }
            fn drain_egress_events(&mut self) -> Vec<nat::EgressEvent> {
                vec![nat::EgressEvent {
                    domain: "tcp",
                    target: "203.0.113.1:443".into(),
                    allowed: false,
                    rule: "default-deny".into(),
                    policy: "test".into(),
                }]
            }
        }
        let intercepts = Arc::new(AtomicUsize::new(0));
        let backend =
            || devcore::Backend::Net(NetDevice::new(Box::new(Talkative(intercepts.clone()))));
        let mem = || {
            let m = Arc::new(GuestMemory::new());
            m.register_owned(0x4000_0000, 0x1000);
            m
        };
        let pci = Arc::new(pci::VirtioPciDevice::new(
            "pcidev",
            backend(),
            mem(),
            pci::RestoreParams {
                features: features::VERSION_1,
                queues: vec![],
                queue_vectors: vec![],
                device_status: 0x0f,
                device_config: vec![],
            },
        ));
        let m = Arc::new(mmio::VirtioMmioDevice::new(
            "mmiodev",
            backend(),
            mem(),
            mmio::MmioParams {
                device_id: mmio::device_id::NET,
                features: 0,
                num_queues: 2,
                device_config: vec![0; 8],
            },
        ));
        (
            intercepts,
            vec![
                ("pcidev", pci as Arc<dyn NetIo>),
                ("mmiodev", m as Arc<dyn NetIo>),
            ],
        )
    }

    #[test]
    fn a_net_device_is_reached_by_the_same_surface_on_either_transport() {
        // The service thread holds `Arc<dyn NetIo>` and never learns which
        // transport carries the NIC. An impl that answered for the wrong object
        // -- or answered with a constant -- would leave the audit trail of one
        // whole transport silently empty, which is the failure this trait
        // exists to make impossible.
        let (intercepts, devices) = as_net_io();
        for (n, (expected, dev)) in devices.into_iter().enumerate() {
            assert_eq!(dev.name(), expected, "each impl must answer for itself");
            let events = dev.drain_egress_events();
            assert_eq!(
                events.len(),
                1,
                "{expected}: the responder's decisions must reach the audit trail"
            );
            assert_eq!(events[0].target, "203.0.113.1:443");
            // No RX queue is published in this fixture, so nothing can be
            // delivered into the guest and both transports must say so. Weak on
            // its own -- the drain assertion above is what carries the property
            // -- but it does catch an impl answering for a different object.
            assert!(
                !dev.service_net(),
                "{expected}: with no RX queue, no frame can reach the guest"
            );
            dev.set_net_intercept(None);
            assert_eq!(
                intercepts.load(Ordering::SeqCst),
                n + 1,
                "{expected}: the credential proxy must reach this device's own NAT"
            );
        }
    }
}
