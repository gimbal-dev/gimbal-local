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
pub mod devmgr;
pub mod its;
pub mod nat;
pub mod net;
pub(crate) mod pathsafe;
pub mod pci;
pub mod queue;
pub mod rng;

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
            f(unsafe { std::slice::from_raw_parts_mut(p, len) })
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(mem.read_u32(0x4000_0ffe).is_err()); // straddles the end
        assert!(mem.read_u32(0x5000_0000).is_err()); // unbacked
    }
}
