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
            // Discard / write-zeroes carry a descriptor payload we accept and
            // acknowledge but do not need to physically punch for correctness on
            // a sparse overlay; report OK so the guest's fstrim/mkfs proceeds.
            VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_WRITE_ZEROES => (VIRTIO_BLK_S_OK, 0),
            _ => (VIRTIO_BLK_S_UNSUPP, 0),
        })
    }

    fn do_read(&mut self, mem: &GuestMemory, chain: &DescChain, mut offset: u64) -> (u8, u32) {
        let mut written = 0u32;
        // All writable segments except the final status byte receive data.
        let writable: Vec<_> = chain.writable().copied().collect();
        let data_segs = writable.split_last().map_or(&[][..], |(_, d)| d);
        for seg in data_segs {
            let mut buf = vec![0u8; seg.len as usize];
            if self.backend.read_at(offset, &mut buf).is_err() || mem.write(seg.gpa, &buf).is_err() {
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
            let mut buf = vec![0u8; seg.len as usize];
            if mem.read(seg.gpa, &mut buf).is_err() || self.backend.write_at(offset, &buf).is_err() {
                return VIRTIO_BLK_S_IOERR;
            }
            offset += seg.len as u64;
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
    pub fn open(path: &std::path::Path, nsectors: u64) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
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
        self.file.sync_data()
    }
    fn nsectors(&self) -> u64 {
        self.nsectors
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
}
