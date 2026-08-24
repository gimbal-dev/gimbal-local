// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A file-backed `virtio-blk` request processor.
//!
//! Consumes a popped [`DescChain`] (header + data + status), performs the I/O
//! against a [`BlockBackend`], and reports the number of bytes written into the
//! chain's device-writable buffers so the caller can complete the used ring.
//!
//! The backend is a trait so the request logic is unit-tested against an
//! in-memory disk; production uses a host file (see [`FileBackend`]).

use std::io;

use super::queue::DescChain;
use super::GuestMemory;

/// virtio-blk request types (`struct virtio_blk_outhdr.type`).
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;
const VIRTIO_BLK_T_DISCARD: u32 = 11;
const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

/// virtio-blk completion status bytes.
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Logical block size assumed by the request encoding.
const SECTOR_SIZE: u64 = 512;

/// Flush a guest write barrier to the host filesystem.
///
/// Rust's [`std::fs::File::sync_data`] maps to `fcntl(F_FULLFSYNC)` on macOS,
/// which asks the drive to flush its own write cache to physical media. That is
/// a genuine hardware barrier and measures ~5 ms on Apple SSDs versus ~0.05 ms
/// for `fsync(2)` — a 100x cost paid on every guest fsync, on the synchronous
/// completion path.
///
/// A guest flush here means "make this durable against the VMM, the guest, and
/// the host OS crashing", which plain `fsync(2)` provides: the data is in the
/// host filesystem, not just our process. It does NOT survive host power loss
/// with the drive cache unwritten. That matches the default of every mainstream
/// VMM (QEMU `cache=writeback`, and Docker Desktop's virtual disk), so a guest
/// gets the durability it would get anywhere else — and, for the disk overlay
/// specifically, durable state is captured by the checkpoint path, not by the
/// per-run overlay.
///
/// Set `CHM_FULL_BARRIER=1` to opt back into the full media barrier.
fn flush_to_host(file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let full = std::env::var_os("CHM_FULL_BARRIER").is_some_and(|v| v != "0");
    if full {
        return file.sync_data();
    }
    // SAFETY: `file` owns a valid open descriptor for the duration of the call.
    let rc = unsafe { libc::fsync(file.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Backing store for a [`BlockDevice`]: a flat, sector-addressed byte array.
pub trait BlockBackend: Send {
    /// Read into `buf` starting at byte `offset`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Write `buf` starting at byte `offset`.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;
    /// Flush any buffered writes to stable storage.
    fn flush(&mut self) -> io::Result<()>;
    /// Capacity in 512-byte sectors.
    fn nsectors(&self) -> u64;
}

/// Outcome of processing one request: the status byte and the number of bytes
/// written into device-writable buffers (which is what goes in the used ring).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completed {
    /// The virtio-blk status byte placed in the chain's status buffer.
    pub status: u8,
    /// Total bytes written into device-writable buffers (data + status byte).
    pub used_len: u32,
}

/// A `virtio-blk` device over a [`BlockBackend`].
pub struct BlockDevice {
    backend: Box<dyn BlockBackend>,
    /// 20-byte device id reported for `VIRTIO_BLK_T_GET_ID`.
    serial: [u8; 20],
}

impl BlockDevice {
    /// Wrap `backend` as a virtio-blk device with the given `serial` id.
    pub fn new(backend: Box<dyn BlockBackend>, serial: &str) -> Self {
        let mut s = [0u8; 20];
        let bytes = serial.as_bytes();
        let n = bytes.len().min(20);
        s[..n].copy_from_slice(&bytes[..n]);
        Self { backend, serial: s }
    }

    /// Capacity in sectors (for the device-config `capacity` field).
    pub fn nsectors(&self) -> u64 {
        self.backend.nsectors()
    }

    /// Process one request descriptor chain against guest memory `mem`.
    ///
    /// Layout: the first readable segment is the 16-byte header; for writes the
    /// remaining readable segments hold the data; for reads/GET_ID the writable
    /// segments (except the final 1-byte status) receive the result; the final
    /// writable byte is the status.
    pub fn process(&mut self, mem: &GuestMemory, chain: &DescChain) -> Completed {
        let (status, data_written) = self
            .dispatch(mem, chain)
            .unwrap_or((VIRTIO_BLK_S_IOERR, 0));

        // The status byte is the last byte of the last device-writable segment.
        let mut used_len = data_written;
        if let Some(seg) = chain.writable().last().copied() {
            let _ = mem.write(seg.gpa + (seg.len as u64).saturating_sub(1), &[status]);
            used_len = used_len.saturating_add(1);
        }
        Completed { status, used_len }
    }

    /// Read the header, dispatch, and return `(status, data_bytes_written)`.
    fn dispatch(&mut self, mem: &GuestMemory, chain: &DescChain) -> Option<(u8, u32)> {
        let hdr_seg = chain.readable().next()?;
        if hdr_seg.len < 16 {
            return Some((VIRTIO_BLK_S_IOERR, 0));
        }
        let req_type = mem.read_u32(hdr_seg.gpa).ok()?;
        let sector = mem.read_u64(hdr_seg.gpa + 8).ok()?;
        let offset = sector.checked_mul(SECTOR_SIZE)?;

        Some(match req_type {
            VIRTIO_BLK_T_IN => self.do_read(mem, chain, offset),
            VIRTIO_BLK_T_OUT => (self.do_write(mem, chain, offset), 0),
            VIRTIO_BLK_T_FLUSH => (
                match self.backend.flush() {
                    Ok(()) => VIRTIO_BLK_S_OK,
                    Err(_) => VIRTIO_BLK_S_IOERR,
                },
                0,
            ),
            VIRTIO_BLK_T_GET_ID => self.do_get_id(mem, chain),
            // DISCARD is only a hint that a range is no longer needed, so
            // acknowledging without punching it is correct.
            //
            // WRITE_ZEROES is NOT a hint: the guest requires the range to read
            // back as zeroes. On a copy-on-write overlay an untouched sector
            // reads *through to the base image*, so acknowledging without
            // zeroing would silently hand the guest stale base content.
            VIRTIO_BLK_T_DISCARD => (VIRTIO_BLK_S_OK, 0),
            VIRTIO_BLK_T_WRITE_ZEROES => (self.do_write_zeroes(mem, chain), 0),
            _ => (VIRTIO_BLK_S_UNSUPP, 0),
        })
    }

    fn do_read(&mut self, mem: &GuestMemory, chain: &DescChain, mut offset: u64) -> (u8, u32) {
        let mut written = 0u32;
        // All writable segments except the final status byte receive data.
        let writable: Vec<_> = chain.writable().copied().collect();
        let data_segs = writable.split_last().map_or(&[][..], |(_, d)| d);
        for seg in data_segs {
            // Fill the guest buffer in place: no temporary, no copy.
            let ok = mem
                .with_slice_mut(seg.gpa, seg.len as usize, |buf| {
                    self.backend.read_at(offset, buf).is_ok()
                })
                .unwrap_or(false);
            if !ok {
                return (VIRTIO_BLK_S_IOERR, written);
            }
            offset += seg.len as u64;
            written = written.saturating_add(seg.len);
        }
        (VIRTIO_BLK_S_OK, written)
    }

    fn do_write(&mut self, mem: &GuestMemory, chain: &DescChain, mut offset: u64) -> u8 {
        // Readable segments after the header hold the data to write.
        let mut readable = chain.readable();
        let _hdr = readable.next();
        for seg in readable {
            // Write straight out of guest RAM: no temporary, no copy.
            let ok = mem
                .with_slice(seg.gpa, seg.len as usize, |buf| {
                    self.backend.write_at(offset, buf).is_ok()
                })
                .unwrap_or(false);
            if !ok {
                return VIRTIO_BLK_S_IOERR;
            }
            offset += seg.len as u64;
        }
        VIRTIO_BLK_S_OK
    }

    /// Zero the sector ranges named by a `VIRTIO_BLK_T_WRITE_ZEROES` request.
    ///
    /// The payload segments each carry a 16-byte
    /// `{ u64 sector, u32 num_sectors, u32 flags }` descriptor. `flags` bit 0 is
    /// UNMAP, a hint that the range may be deallocated; either way the range
    /// must subsequently read back as zeroes, which is what we guarantee by
    /// writing zeroes through the normal backend path.
    fn do_write_zeroes(&mut self, mem: &GuestMemory, chain: &DescChain) -> u8 {
        let mut readable = chain.readable();
        let _hdr = readable.next();
        let mut zeros = Vec::new();
        for seg in readable {
            let mut at = seg.gpa;
            let end = seg.gpa + seg.len as u64;
            while at + 16 <= end {
                let (Ok(sector), Ok(count)) = (mem.read_u64(at), mem.read_u32(at + 8)) else {
                    return VIRTIO_BLK_S_IOERR;
                };
                at += 16;
                let Some(mut offset) = sector.checked_mul(SECTOR_SIZE) else {
                    return VIRTIO_BLK_S_IOERR;
                };
                let mut remaining = count as u64 * SECTOR_SIZE;
                // Chunked so a large range cannot balloon host memory.
                const CHUNK: u64 = 1 << 20;
                while remaining > 0 {
                    let n = remaining.min(CHUNK) as usize;
                    if zeros.len() < n {
                        zeros.resize(n, 0);
                    }
                    if self.backend.write_at(offset, &zeros[..n]).is_err() {
                        return VIRTIO_BLK_S_IOERR;
                    }
                    offset += n as u64;
                    remaining -= n as u64;
                }
            }
        }
        VIRTIO_BLK_S_OK
    }

    fn do_get_id(&mut self, mem: &GuestMemory, chain: &DescChain) -> (u8, u32) {
        let writable: Vec<_> = chain.writable().copied().collect();
        let Some((_status, data_segs)) = writable.split_last() else {
            return (VIRTIO_BLK_S_IOERR, 0);
        };
        if let Some(seg) = data_segs.first() {
            let n = (seg.len as usize).min(self.serial.len());
            if mem.write(seg.gpa, &self.serial[..n]).is_err() {
                return (VIRTIO_BLK_S_IOERR, 0);
            }
            return (VIRTIO_BLK_S_OK, n as u32);
        }
        (VIRTIO_BLK_S_OK, 0)
    }
}

/// A [`BlockBackend`] over a host file (the disk image / sparse overlay).
pub struct FileBackend {
    file: std::fs::File,
    nsectors: u64,
}

impl FileBackend {
    /// Open `path` read/write as a backend of `nsectors` 512-byte sectors.
    ///
    /// Uses a no-follow open: a snapshot bundle cannot substitute a symlink for
    /// the overlay to redirect guest writes onto a host file (M30.1).
    pub fn open(path: &std::path::Path, nsectors: u64) -> io::Result<Self> {
        let file = super::pathsafe::open_rw_create_nofollow(path, false)?;
        Ok(Self { file, nsectors })
    }
}

impl BlockBackend for FileBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buf, offset)
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.write_all_at(buf, offset)
    }
    fn flush(&mut self) -> io::Result<()> {
        flush_to_host(&self.file)
    }
    fn nsectors(&self) -> u64 {
        self.nsectors
    }
}

/// A copy-on-write [`BlockBackend`]: an immutable base image with every write
/// redirected to a per-run sparse overlay.
///
/// This is the backing used when a snapshot ships its real disk. Keeping the
/// base pristine is what makes rehydration *repeatable*: a cloud-hypervisor
/// snapshot restores guest RAM (including the page cache) to the exact instant
/// the snapshot was taken, so the disk the guest sees must also be that exact
/// instant. If guest writes leaked into the base image, the next resume would
/// pair snapshot-era RAM with a drifted disk and the guest's ext4 metadata would
/// fail its checksums (observed as `deleted inode referenced` / EIO). By writing
/// only to an overlay that is recreated each run, every resume starts from the
/// snapshot-consistent disk while writes still persist for the life of the run.
///
/// Reads return overlay bytes for sectors written this run and base bytes
/// otherwise. The written-sector set is an in-memory bitmap (1 bit per 512-byte
/// sector), which is ephemeral by design — it is rebuilt empty on every open.
pub struct OverlayBackend {
    base: std::fs::File,
    overlay: std::fs::File,
    nsectors: u64,
    /// 1 bit per 512-byte sector: set when that sector lives in the overlay.
    written: Vec<u64>,
    /// Sidecar path holding a serialized `written` bitmap, so the overlay's
    /// contents can be reattached after a suspend/resume (see [`Self::resume`]).
    /// `None` disables persistence (the default cold-boot overlay is ephemeral).
    bitmap_path: Option<std::path::PathBuf>,
    /// Cached handle for `bitmap_path`, opened on first persist. A guest fsync
    /// is on the synchronous completion path, and re-opening the sidecar each
    /// time cost milliseconds per flush.
    bitmap_file: Option<std::fs::File>,
    /// Which `BITMAP_CHUNK_BYTES` spans of the serialized bitmap have changed
    /// since the last persist, so a flush rewrites only those. A guest fsync is
    /// on the synchronous completion path, and the full bitmap is 2 MiB for an
    /// 8 GiB disk, so rewriting all of it per flush dominated flush latency.
    bitmap_dirty: Vec<bool>,
}

/// Granularity at which the bitmap sidecar is rewritten. One page: large enough
/// that sequential guest writes touch a single chunk, small enough that a chunk
/// rewrite is cheap.
const BITMAP_CHUNK_BYTES: usize = 4096;
const BITMAP_CHUNK_WORDS: usize = BITMAP_CHUNK_BYTES / 8;

impl OverlayBackend {
    /// Open `base_path` read-only and (re)create a fresh, empty sparse overlay.
    ///
    /// The overlay is truncated on open so each run starts from the base image.
    pub fn open(
        base_path: &std::path::Path,
        overlay_path: &std::path::Path,
        nsectors: u64,
    ) -> io::Result<Self> {
        let base = super::pathsafe::open_ro_nofollow(base_path)?;
        let overlay = super::pathsafe::open_rw_create_nofollow(overlay_path, true)?;
        overlay.set_len(nsectors.saturating_mul(SECTOR_SIZE))?;
        let words = nsectors.div_ceil(64) as usize;
        // A fresh cold-boot overlay leaves no stale bitmap behind. This must not
        // be best-effort: the overlay above was just truncated, so a surviving
        // sidecar would mark sectors as "written" that now read back as zeros
        // instead of falling through to the base image — silently corrupting the
        // guest's filesystem rather than failing. A missing sidecar is the normal
        // case and is not an error.
        match std::fs::remove_file(Self::bitmap_path_for(overlay_path)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            base,
            overlay,
            nsectors,
            written: vec![0u64; words],
            bitmap_path: Some(Self::bitmap_path_for(overlay_path)),
            bitmap_file: None,
            // The sidecar was just removed, so an all-zero bitmap is already
            // consistent with what a persist would find on disk.
            bitmap_dirty: vec![false; words.div_ceil(BITMAP_CHUNK_WORDS)],
        })
    }

    /// Reattach an existing overlay produced by a prior run (suspend/resume):
    /// the overlay file is kept (NOT truncated) and its written-sector bitmap is
    /// reloaded from the sidecar, so disk writes made before the checkpoint are
    /// visible again. Falls back to [`Self::open`] (fresh) if the sidecar is
    /// missing or the wrong size for `nsectors`.
    pub fn resume(
        base_path: &std::path::Path,
        overlay_path: &std::path::Path,
        nsectors: u64,
    ) -> io::Result<Self> {
        let words = nsectors.div_ceil(64) as usize;
        let bitmap_path = Self::bitmap_path_for(overlay_path);
        let written = match std::fs::read(&bitmap_path) {
            Ok(bytes) if bytes.len() == words * 8 => bytes
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<u64>>(),
            _ => return Self::open(base_path, overlay_path, nsectors),
        };
        let base = super::pathsafe::open_ro_nofollow(base_path)?;
        let overlay = super::pathsafe::open_rw_create_nofollow(overlay_path, false)?;
        overlay.set_len(nsectors.saturating_mul(SECTOR_SIZE))?;
        Ok(Self {
            base,
            overlay,
            nsectors,
            written,
            bitmap_path: Some(bitmap_path),
            bitmap_file: None,
            // Loaded straight from the sidecar, so nothing needs rewriting yet.
            bitmap_dirty: vec![false; words.div_ceil(BITMAP_CHUNK_WORDS)],
        })
    }

    /// The bitmap sidecar path for an overlay file (`<overlay>.bitmap`).
    fn bitmap_path_for(overlay_path: &std::path::Path) -> std::path::PathBuf {
        let mut p = overlay_path.as_os_str().to_os_string();
        p.push(".bitmap");
        std::path::PathBuf::from(p)
    }

    /// Persist the written-sector bitmap to its sidecar so a later [`Self::resume`]
    /// can reattach this overlay's contents. Best-effort: a failure here only
    /// means a subsequent resume falls back to a cold overlay.
    fn persist_bitmap(&mut self) {
        let Some(path) = self.bitmap_path.clone() else {
            return;
        };
        if !self.bitmap_dirty.iter().any(|d| *d) {
            return;
        }
        use std::os::unix::fs::FileExt;
        let total = self.written.len() * 8;
        if self.bitmap_file.is_none() {
            let Ok(f) = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
            else {
                return;
            };
            // The sidecar is read back wholesale, so it must always be full
            // length even when only a chunk in the middle has changed.
            if f.metadata().map(|m| m.len()).unwrap_or(0) != total as u64
                && f.set_len(total as u64).is_err()
            {
                return;
            }
            self.bitmap_file = Some(f);
        }
        let Some(f) = self.bitmap_file.as_ref() else {
            return;
        };
        for chunk in 0..self.bitmap_dirty.len() {
            if !self.bitmap_dirty[chunk] {
                continue;
            }
            let lo = chunk * BITMAP_CHUNK_WORDS;
            let hi = ((chunk + 1) * BITMAP_CHUNK_WORDS).min(self.written.len());
            let mut bytes = Vec::with_capacity((hi - lo) * 8);
            for word in &self.written[lo..hi] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            if f.write_all_at(&bytes, (lo * 8) as u64).is_err() {
                return;
            }
            self.bitmap_dirty[chunk] = false;
        }
    }

    #[inline]
    fn is_written(&self, sector: u64) -> bool {
        let (w, b) = ((sector / 64) as usize, sector % 64);
        self.written.get(w).is_some_and(|word| (word >> b) & 1 != 0)
    }

    #[inline]
    fn mark_written(&mut self, sector: u64) {
        let (w, b) = ((sector / 64) as usize, sector % 64);
        if let Some(word) = self.written.get_mut(w) {
            let before = *word;
            *word |= 1u64 << b;
            if *word != before
                && let Some(dirty) = self.bitmap_dirty.get_mut(w / BITMAP_CHUNK_WORDS)
            {
                *dirty = true;
            }
        }
    }

    /// Copy a not-yet-written sector from the base into the overlay so that a
    /// subsequent partial write leaves the untouched bytes equal to the base.
    fn seed_sector(&mut self, sector: u64) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        if self.is_written(sector) {
            return Ok(());
        }
        let mut tmp = [0u8; SECTOR_SIZE as usize];
        let off = sector * SECTOR_SIZE;
        self.base.read_exact_at(&mut tmp, off)?;
        self.overlay.write_all_at(&tmp, off)?;
        self.mark_written(sector);
        Ok(())
    }
}

impl BlockBackend for OverlayBackend {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            let from_overlay = self.is_written(cur / SECTOR_SIZE);
            // Coalesce a run of same-source sectors to limit syscalls.
            let mut run = 0usize;
            while done + run < buf.len() {
                let pos = cur + run as u64;
                if self.is_written(pos / SECTOR_SIZE) != from_overlay {
                    break;
                }
                let in_sec = (SECTOR_SIZE - (pos % SECTOR_SIZE)) as usize;
                run += in_sec.min(buf.len() - done - run);
            }
            let src = if from_overlay { &self.overlay } else { &self.base };
            src.read_exact_at(&mut buf[done..done + run], cur)?;
            done += run;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset + buf.len() as u64;
        // Seed partially-covered edge sectors so their untouched bytes stay equal
        // to the base content (full-sector writes need no seeding).
        if !offset.is_multiple_of(SECTOR_SIZE) {
            self.seed_sector(offset / SECTOR_SIZE)?;
        }
        if !end.is_multiple_of(SECTOR_SIZE) {
            self.seed_sector((end - 1) / SECTOR_SIZE)?;
        }
        self.overlay.write_all_at(buf, offset)?;
        for sector in (offset / SECTOR_SIZE)..=((end - 1) / SECTOR_SIZE) {
            self.mark_written(sector);
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_to_host(&self.overlay)?;
        // Keep the resume sidecar current with the durable overlay so a
        // suspend/resume after a guest fsync sees the same disk.
        self.persist_bitmap();
        Ok(())
    }

    fn nsectors(&self) -> u64 {
        self.nsectors
    }
}

impl Drop for OverlayBackend {
    fn drop(&mut self) {
        // Persist the bitmap on teardown so a graceful stop (which is the normal
        // suspend path) leaves a reattachable overlay.
        self.persist_bitmap();
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::Segment;
    use super::*;

    struct MemDisk(Vec<u8>);
    impl BlockBackend for MemDisk {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            let o = offset as usize;
            if o + buf.len() > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "oob"));
            }
            buf.copy_from_slice(&self.0[o..o + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
            let o = offset as usize;
            if o + buf.len() > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "oob"));
            }
            self.0[o..o + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn nsectors(&self) -> u64 {
            (self.0.len() as u64) / SECTOR_SIZE
        }
    }

    fn mem() -> GuestMemory {
        let m = GuestMemory::new();
        m.register_owned(0x2000, 0x2000);
        m
    }

    fn req(req_type: u32, sector: u64, hdr: u64) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&req_type.to_le_bytes());
        h[8..16].copy_from_slice(&sector.to_le_bytes());
        let _ = hdr;
        h
    }

    fn chain(segs: &[Segment]) -> DescChain {
        DescChain { head: 0, segments: segs.to_vec() }
    }

    #[test]
    fn reads_a_sector_into_guest_memory() {
        let m = mem();
        // Disk: 2 sectors; sector 1 filled with 0xAB.
        let mut disk = vec![0u8; (2 * SECTOR_SIZE) as usize];
        for b in disk[SECTOR_SIZE as usize..].iter_mut() {
            *b = 0xAB;
        }
        let mut dev = BlockDevice::new(Box::new(MemDisk(disk)), "test");

        // Header @0x2000, data buffer @0x2100 (512B, writable), status @0x2400.
        m.write(0x2000, &req(VIRTIO_BLK_T_IN, 1, 0)).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x2100, len: 512, write: true },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        let done = dev.process(&m, &c);
        assert_eq!(done.status, VIRTIO_BLK_S_OK);
        assert_eq!(done.used_len, 513); // 512 data + 1 status
        let mut got = [0u8; 512];
        m.read(0x2100, &mut got).unwrap();
        assert!(got.iter().all(|&b| b == 0xAB));
        assert_eq!(m.read_u32(0x2400).unwrap() & 0xff, VIRTIO_BLK_S_OK as u32);
    }

    #[test]
    fn writes_a_sector_from_guest_memory() {
        let m = mem();
        let mut dev = BlockDevice::new(Box::new(MemDisk(vec![0u8; (2 * SECTOR_SIZE) as usize])), "t");
        m.write(0x2000, &req(VIRTIO_BLK_T_OUT, 0, 0)).unwrap();
        let data = [0x5Au8; 512];
        m.write(0x2100, &data).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x2100, len: 512, write: false },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        let done = dev.process(&m, &c);
        assert_eq!(done.status, VIRTIO_BLK_S_OK);
        assert_eq!(done.used_len, 1); // only the status byte is device-written
    }

    #[test]
    fn get_id_returns_serial() {
        let m = mem();
        let mut dev = BlockDevice::new(Box::new(MemDisk(vec![0u8; 512])), "disk0");
        m.write(0x2000, &req(VIRTIO_BLK_T_GET_ID, 0, 0)).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x2100, len: 20, write: true },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        let done = dev.process(&m, &c);
        assert_eq!(done.status, VIRTIO_BLK_S_OK);
        let mut id = [0u8; 5];
        m.read(0x2100, &mut id).unwrap();
        assert_eq!(&id, b"disk0");
    }

    #[test]
    fn unsupported_request_reports_unsupp() {
        let m = mem();
        let mut dev = BlockDevice::new(Box::new(MemDisk(vec![0u8; 512])), "t");
        m.write(0x2000, &req(0xdead, 0, 0)).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        let done = dev.process(&m, &c);
        assert_eq!(done.status, VIRTIO_BLK_S_UNSUPP);
    }

    /// A guest fsync must leave the bitmap sidecar describing the durable
    /// overlay, so a later resume sees exactly the sectors that were written.
    ///
    /// The sidecar is rewritten incrementally (only changed chunks), so this
    /// deliberately writes sectors in two widely separated bitmap chunks plus a
    /// late write in the *first* chunk -- a whole-file rewrite and a correct
    /// incremental rewrite agree here, but an incremental one that loses track
    /// of a dirtied chunk does not.
    #[test]
    fn overlay_resume_restores_sectors_across_distant_bitmap_chunks() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("chm-cow-resume-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");

        // Enough sectors that the bitmap spans several chunks.
        let nsectors = (BITMAP_CHUNK_WORDS as u64) * 64 * 3;
        let mut f = std::fs::File::create(&base_path).unwrap();
        f.write_all(&vec![0xAAu8; SECTOR_SIZE as usize]).unwrap();
        f.set_len(nsectors * SECTOR_SIZE).unwrap();
        drop(f);

        // Sectors chosen to land in chunk 0, chunk 2, then back to chunk 0.
        let far = (BITMAP_CHUNK_WORDS as u64) * 64 * 2 + 5;
        let marks: [(u64, u8); 3] = [(1, 0x11), (far, 0x22), (7, 0x33)];

        let mut ob = OverlayBackend::open(&base_path, &overlay_path, nsectors).unwrap();
        for (sector, fill) in marks {
            ob.write_at(sector * SECTOR_SIZE, &[fill; SECTOR_SIZE as usize]).unwrap();
            // Each guest fsync persists only what changed since the last one.
            ob.flush().unwrap();
        }
        drop(ob);

        let mut resumed = OverlayBackend::resume(&base_path, &overlay_path, nsectors).unwrap();
        for (sector, fill) in marks {
            let mut got = [0u8; SECTOR_SIZE as usize];
            resumed.read_at(sector * SECTOR_SIZE, &mut got).unwrap();
            assert!(
                got.iter().all(|&b| b == fill),
                "sector {sector} should resume as {fill:#x}, got {:#x}",
                got[0]
            );
        }
        // An untouched sector must still read through to the base.
        let mut got = [0u8; SECTOR_SIZE as usize];
        resumed.read_at(0, &mut got).unwrap();
        assert!(got.iter().all(|&b| b == 0xAA), "untouched sector must read the base");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `WRITE_ZEROES` must actually zero the range, not just be acknowledged.
    ///
    /// This is specifically a copy-on-write hazard: an untouched overlay sector
    /// reads *through to the base image*, so a device that ACKs the request
    /// without writing hands the guest stale base content while reporting
    /// success — silent corruption rather than a visible error.
    #[test]
    fn write_zeroes_actually_zeroes_over_a_cow_base() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("chm-cow-wz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");

        // A base whose every byte is non-zero, so leftover base content is
        // unmistakable in the read-back.
        let nsectors = 8u64;
        let mut f = std::fs::File::create(&base_path).unwrap();
        f.write_all(&vec![0xEEu8; (nsectors * SECTOR_SIZE) as usize]).unwrap();
        drop(f);

        let backend = OverlayBackend::open(&base_path, &overlay_path, nsectors).unwrap();
        let mut dev = BlockDevice::new(Box::new(backend), "t");

        let m = mem();
        m.write(0x2000, &req(VIRTIO_BLK_T_WRITE_ZEROES, 0, 0)).unwrap();
        // Payload: zero 2 sectors starting at sector 1.
        m.write_u64(0x2100, 1).unwrap();
        m.write_u32(0x2108, 2).unwrap();
        m.write_u32(0x210c, 0).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x2100, len: 16, write: false },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        assert_eq!(dev.process(&m, &c).status, VIRTIO_BLK_S_OK);

        // Read sectors 0..3 back through the device and check the boundaries:
        // the zeroed range must be zero, its neighbours must still be base.
        m.write(0x2000, &req(VIRTIO_BLK_T_IN, 0, 0)).unwrap();
        let c = chain(&[
            Segment { gpa: 0x2000, len: 16, write: false },
            Segment { gpa: 0x3000, len: (SECTOR_SIZE * 4) as u32, write: true },
            Segment { gpa: 0x2400, len: 1, write: true },
        ]);
        assert_eq!(dev.process(&m, &c).status, VIRTIO_BLK_S_OK);

        let mut got = vec![0u8; (SECTOR_SIZE * 4) as usize];
        m.read(0x3000, &mut got).unwrap();
        let sec = |i: usize| &got[i * SECTOR_SIZE as usize..(i + 1) * SECTOR_SIZE as usize];
        assert!(sec(0).iter().all(|&b| b == 0xEE), "sector 0 must be untouched base");
        assert!(sec(1).iter().all(|&b| b == 0), "sector 1 must read back as zeroes");
        assert!(sec(2).iter().all(|&b| b == 0), "sector 2 must read back as zeroes");
        assert!(sec(3).iter().all(|&b| b == 0xEE), "sector 3 must be untouched base");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The copy-on-write overlay must keep the base file pristine while still
    /// reflecting writes back to the guest within the same run.
    #[test]
    fn overlay_writes_do_not_touch_the_base() {
        use std::io::Write;        let dir = std::env::temp_dir().join(format!("chm-cow-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");

        // Base: 4 sectors, each filled with its (index+1) byte value.
        let mut base_bytes = Vec::new();
        for s in 0..4u8 {
            base_bytes.extend(std::iter::repeat_n(s + 1, SECTOR_SIZE as usize));
        }
        std::fs::File::create(&base_path).unwrap().write_all(&base_bytes).unwrap();
        let base_before = std::fs::read(&base_path).unwrap();

        let mut ob = OverlayBackend::open(&base_path, &overlay_path, 4).unwrap();

        // Unwritten sectors read through to the base.
        let mut got = [0u8; SECTOR_SIZE as usize];
        ob.read_at(2 * SECTOR_SIZE, &mut got).unwrap();
        assert!(got.iter().all(|&b| b == 3), "sector 2 should read base value 3");

        // Overwrite sector 1 with 0xEE; read it back from the overlay.
        let patch = [0xEEu8; SECTOR_SIZE as usize];
        ob.write_at(SECTOR_SIZE, &patch).unwrap();
        let mut after = [0u8; SECTOR_SIZE as usize];
        ob.read_at(SECTOR_SIZE, &mut after).unwrap();
        assert!(after.iter().all(|&b| b == 0xEE), "sector 1 should read overlay value");

        // A neighbouring, unwritten sector still reads the base value.
        ob.read_at(0, &mut after).unwrap();
        assert!(after.iter().all(|&b| b == 1), "sector 0 stays base value 1");

        // The base file on disk is byte-for-byte unchanged.
        ob.flush().unwrap();
        drop(ob);
        let base_after = std::fs::read(&base_path).unwrap();
        assert_eq!(base_before, base_after, "base image must remain pristine");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cold-boot open truncates the overlay, so any surviving bitmap sidecar
    /// would mark sectors as "written" that now read back as zeros instead of
    /// falling through to the base image. That is silent filesystem corruption,
    /// so the sidecar removal must not be best-effort.
    #[test]
    fn cold_open_does_not_leave_a_stale_bitmap_shadowing_the_base() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("chm-cow-stale-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");

        // Base: 4 sectors, each filled with its (index+1) byte value.
        let mut base_bytes = Vec::new();
        for s in 0..4u8 {
            base_bytes.extend(std::iter::repeat_n(s + 1, SECTOR_SIZE as usize));
        }
        std::fs::File::create(&base_path).unwrap().write_all(&base_bytes).unwrap();

        // A previous session wrote sector 2 and persisted its bitmap.
        let mut first = OverlayBackend::open(&base_path, &overlay_path, 4).unwrap();
        first.write_at(2 * SECTOR_SIZE, &[0xEEu8; SECTOR_SIZE as usize]).unwrap();
        first.flush().unwrap();
        drop(first);
        let sidecar = OverlayBackend::bitmap_path_for(&overlay_path);
        assert!(sidecar.exists(), "the first session should persist a sidecar");

        // Cold boot again. The overlay is truncated, so sector 2 must read the
        // base value — not the zeros a surviving bitmap would expose.
        let mut second = OverlayBackend::open(&base_path, &overlay_path, 4).unwrap();
        assert!(!sidecar.exists(), "a cold open must clear the stale sidecar");
        let mut got = [0u8; SECTOR_SIZE as usize];
        second.read_at(2 * SECTOR_SIZE, &mut got).unwrap();
        assert!(
            got.iter().all(|&b| b == 3),
            "sector 2 must fall through to base value 3, got {:#x}",
            got[0]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The corruption above is only prevented if the removal is *not* silent.
    /// With the sidecar path occupied by a directory the removal cannot succeed,
    /// and a cold open must fail loudly rather than run on with a bitmap it did
    /// not manage to clear.
    #[test]
    fn cold_open_fails_loudly_when_the_stale_bitmap_cannot_be_removed() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("chm-cow-stuck-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");
        std::fs::File::create(&base_path)
            .unwrap()
            .write_all(&vec![7u8; 4 * SECTOR_SIZE as usize])
            .unwrap();

        // Occupy the sidecar path with something `remove_file` cannot delete.
        std::fs::create_dir_all(OverlayBackend::bitmap_path_for(&overlay_path)).unwrap();

        let err = match OverlayBackend::open(&base_path, &overlay_path, 4) {
            Ok(_) => panic!("a cold open that cannot clear the sidecar must fail"),
            Err(e) => e,
        };
        assert_ne!(
            err.kind(),
            io::ErrorKind::NotFound,
            "a missing sidecar is the normal case and must not be reported as an error"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sub-sector (partial) write must preserve the surrounding base bytes by
    /// seeding the affected sector from the base first.
    #[test]
    fn overlay_partial_write_preserves_base_bytes() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("chm-cow-part-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_path = dir.join("base.raw");
        let overlay_path = dir.join("over.raw");

        // One sector full of 0xAB.
        let base_bytes = vec![0xABu8; SECTOR_SIZE as usize];
        std::fs::File::create(&base_path).unwrap().write_all(&base_bytes).unwrap();

        let mut ob = OverlayBackend::open(&base_path, &overlay_path, 1).unwrap();

        // Write 4 bytes in the middle of the sector.
        ob.write_at(100, &[1, 2, 3, 4]).unwrap();

        let mut got = vec![0u8; SECTOR_SIZE as usize];
        ob.read_at(0, &mut got).unwrap();
        assert_eq!(&got[100..104], &[1, 2, 3, 4], "patched bytes present");
        assert!(got[..100].iter().all(|&b| b == 0xAB), "leading bytes from base");
        assert!(got[104..].iter().all(|&b| b == 0xAB), "trailing bytes from base");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
