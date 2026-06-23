//! A `virtio-pci` (modern, 1.x) transport that services a resumed device's BAR
//! MMIO and drives a backend.
//!
//! The transport models the four capability windows the guest reaches into the
//! device's memory BAR — common configuration, ISR, device-specific config and
//! the notification region — at the exact offsets cloud-hypervisor lays them out
//! (so a snapshot's restored BAR address routes correctly). On a queue
//! notification it pops the available chains, runs them through the backend, and
//! publishes used-ring completions.
//!
//! State (negotiated features, queue addresses, device status, MSI-X vectors) is
//! restored from the snapshot rather than re-negotiated, because a resumed guest
//! does not re-probe.

use std::sync::{Arc, Mutex};

use super::super::devices::MmioDevice;
use super::block::BlockDevice;
use super::queue::Queue;
use super::rng::RngDevice;
use super::GuestMemory;

// BAR sub-region offsets — must match cloud-hypervisor's
// `virtio-devices/src/transport/pci_device.rs` (8 KiB-aligned layout).
const COMMON_CONFIG_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const ISR_OFFSET: u64 = 0x2000;
const DEVICE_CONFIG_OFFSET: u64 = 0x4000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const NOTIFICATION_OFFSET: u64 = 0x6000;
const NOTIFICATION_SIZE: u64 = 0x400 * 4; // MAX_QUEUES * NOTIFY_OFF_MULTIPLIER
/// Total BAR window the device claims (covers MSI-X table + PBA above notify).
pub const CAPABILITY_BAR_SIZE: u64 = 0x80000;

/// virtio device status bits.
const DEVICE_STATUS_DRIVER_OK: u8 = 0x04;

/// The backend a [`VirtioPciDevice`] drives.
pub enum Backend {
    /// A `virtio-blk` device.
    Block(BlockDevice),
    /// A `virtio-rng` device.
    Rng(RngDevice),
}

/// Notified when a queue completion needs to interrupt the guest.
///
/// On a cloud KVM snapshot the guest's vectors are MSI-X delivered as LPIs via a
/// GIC ITS, which Apple's managed GIC cannot replay (it offers only
/// message-based SPIs). Until a user-space GICv3 + ITS lands, the default
/// injector records and logs the pending interrupt so the data path is exercised
/// and observable; it is the single seam a real delivery path plugs into.
pub trait InterruptInjector: Send {
    /// Raise the interrupt for MSI-X table entry `vector`.
    fn signal(&self, vector: u16);
}

/// The default injector: counts and logs pending interrupts.
pub struct LoggingInjector {
    name: String,
    count: Mutex<u64>,
}

impl LoggingInjector {
    /// Create a logging injector labelled `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            count: Mutex::new(0),
        }
    }

    /// Number of interrupts that would have been delivered.
    pub fn pending(&self) -> u64 {
        *self.count.lock().unwrap()
    }
}

impl InterruptInjector for LoggingInjector {
    fn signal(&self, vector: u16) {
        let mut c = self.count.lock().unwrap();
        *c += 1;
        if std::env::var_os("CHM_TRACE_MMIO").is_some() {
            eprintln!(
                "[virtio {}] queue completion ready, MSI-X vector {vector} pending \
                 (#{}) — delivery awaits user-space GIC/ITS",
                self.name, *c
            );
        }
    }
}

struct CommonConfig {
    device_feature_select: u32,
    driver_feature_select: u32,
    device_features: u64,
    driver_features: u64,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
}

struct Inner {
    common: CommonConfig,
    /// One restored queue per virtqueue (index == queue select).
    queues: Vec<Queue>,
    /// Per-queue MSI-X vector (`queue_msix_vector`), index == queue.
    queue_vectors: Vec<u16>,
    backend: Backend,
    device_config: Vec<u8>,
    isr_status: u8,
    mem: Arc<GuestMemory>,
    injector: Box<dyn InterruptInjector>,
}

/// A modern virtio-pci device mapped at a restored BAR base.
pub struct VirtioPciDevice {
    name: String,
    inner: Mutex<Inner>,
}

/// Parameters needed to restore a [`VirtioPciDevice`] from a snapshot.
pub struct RestoreParams {
    /// Negotiated device feature bits (`avail_features`/`acked_features`).
    pub features: u64,
    /// Restored queues (typically one).
    pub queues: Vec<Queue>,
    /// Per-queue MSI-X vector.
    pub queue_vectors: Vec<u16>,
    /// Restored `device_status` (expected to include `DRIVER_OK`).
    pub device_status: u8,
    /// Device-specific config bytes (e.g. `virtio_blk_config`).
    pub device_config: Vec<u8>,
}

impl VirtioPciDevice {
    /// Build a device named `name` driving `backend`, restored from `params`.
    pub fn new(
        name: impl Into<String>,
        backend: Backend,
        mem: Arc<GuestMemory>,
        params: RestoreParams,
    ) -> Self {
        let name = name.into();
        let mut device_config = params.device_config;
        device_config.resize(DEVICE_CONFIG_SIZE as usize, 0);
        let num_queues = params.queues.len() as u16;
        let inner = Inner {
            common: CommonConfig {
                device_feature_select: 0,
                driver_feature_select: 0,
                device_features: params.features,
                driver_features: params.features,
                msix_config: 0,
                num_queues,
                device_status: params.device_status,
                config_generation: 0,
                queue_select: 0,
            },
            queues: params.queues,
            queue_vectors: params.queue_vectors,
            backend,
            device_config,
            isr_status: 0,
            mem,
            injector: Box::new(LoggingInjector::new(name.clone())),
        };
        Self {
            name,
            inner: Mutex::new(inner),
        }
    }

    /// Replace the interrupt injector (e.g. with a real GIC-backed one).
    pub fn set_injector(&self, injector: Box<dyn InterruptInjector>) {
        self.inner.lock().unwrap().injector = injector;
    }

    /// The device's name (for diagnostics).
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Inner {
    /// Service a queue notification: drain and process the available ring.
    fn notify(&mut self, queue_index: u16) {
        let Some(queue) = self.queues.get_mut(queue_index as usize) else {
            return;
        };
        // Snapshot the queue out so we can borrow backend + mem mutably/immutably
        // without aliasing `self`.
        let mem = self.mem.clone();
        let mut completed_any = false;
        loop {
            let chain = match queue.pop(&mem) {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    if std::env::var_os("CHM_TRACE_MMIO").is_some() {
                        eprintln!("[virtio] queue read error: {e}");
                    }
                    break;
                }
            };
            let used_len = match &mut self.backend {
                Backend::Block(b) => b.process(&mem, &chain).used_len,
                Backend::Rng(r) => r.process(&mem, &chain),
            };
            let _ = queue.add_used(&mem, chain.head, used_len);
            completed_any = true;
        }
        if completed_any {
            self.isr_status |= 0x1;
            let needs = queue.needs_interrupt(&mem).unwrap_or(true);
            if needs {
                let vector = self
                    .queue_vectors
                    .get(queue_index as usize)
                    .copied()
                    .unwrap_or(0);
                self.injector.signal(vector);
            }
        }
    }

    fn read_common(&self, offset: u64, data: &mut [u8]) {
        let v: u64 = match offset {
            0x00 => self.common.device_feature_select as u64,
            0x04 => {
                let sel = self.common.device_feature_select;
                (self.common.device_features >> (sel * 32)) & 0xffff_ffff
            }
            0x08 => self.common.driver_feature_select as u64,
            0x0c => {
                let sel = self.common.driver_feature_select;
                (self.common.driver_features >> (sel * 32)) & 0xffff_ffff
            }
            0x10 => self.common.msix_config as u64,
            0x12 => self.common.num_queues as u64,
            0x14 => self.common.device_status as u64,
            0x15 => self.common.config_generation as u64,
            0x16 => self.common.queue_select as u64,
            0x18 => self.queue_field(|q| q.size as u64),
            0x1a => self
                .queue_vectors
                .get(self.common.queue_select as usize)
                .copied()
                .unwrap_or(0) as u64,
            0x1c => self.queue_field(|_| 1), // queue_enable: restored queues are ready
            0x1e => self.common.queue_select as u64, // queue_notify_off == index
            0x20 => self.queue_field(|q| q.desc),
            0x28 => self.queue_field(|q| q.avail),
            0x30 => self.queue_field(|q| q.used),
            _ => 0,
        };
        fill_le(data, v);
    }

    fn queue_field(&self, f: impl Fn(&Queue) -> u64) -> u64 {
        self.queues
            .get(self.common.queue_select as usize)
            .map_or(0, f)
    }

    fn write_common(&mut self, offset: u64, data: &[u8]) {
        let v = parse_le(data);
        match offset {
            0x00 => self.common.device_feature_select = v as u32,
            0x08 => self.common.driver_feature_select = v as u32,
            0x10 => self.common.msix_config = v as u16,
            0x14 => self.common.device_status = v as u8,
            0x16 => self.common.queue_select = v as u16,
            // Post-resume the guest does not re-program queue addresses; accept
            // and ignore writes to those fields to stay robust.
            _ => {}
        }
    }
}

impl MmioDevice for VirtioPciDevice {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let inner = self.inner.lock().unwrap();
        match offset {
            o if o < COMMON_CONFIG_OFFSET + COMMON_CONFIG_SIZE => {
                inner.read_common(o - COMMON_CONFIG_OFFSET, data);
            }
            o if (ISR_OFFSET..ISR_OFFSET + 0x100).contains(&o) => {
                // Reading ISR returns and clears the status (legacy INTx style).
                data.iter_mut().for_each(|b| *b = 0);
                if !data.is_empty() {
                    data[0] = inner.isr_status;
                }
                drop(inner);
                self.inner.lock().unwrap().isr_status = 0;
            }
            o if (DEVICE_CONFIG_OFFSET..DEVICE_CONFIG_OFFSET + DEVICE_CONFIG_SIZE).contains(&o) => {
                let base = (o - DEVICE_CONFIG_OFFSET) as usize;
                for (i, b) in data.iter_mut().enumerate() {
                    *b = inner.device_config.get(base + i).copied().unwrap_or(0);
                }
            }
            _ => data.iter_mut().for_each(|b| *b = 0),
        }
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        match offset {
            o if o < COMMON_CONFIG_OFFSET + COMMON_CONFIG_SIZE => {
                inner.write_common(o - COMMON_CONFIG_OFFSET, data);
            }
            o if (NOTIFICATION_OFFSET..NOTIFICATION_OFFSET + NOTIFICATION_SIZE).contains(&o) => {
                // The written value is the virtqueue index (no NOTIFICATION_DATA).
                let queue_index = parse_le(data) as u16;
                inner.notify(queue_index);
            }
            _ => {}
        }
    }
}

/// Whether a restored `device_status` indicates the driver finished setup.
pub fn driver_ok(status: u8) -> bool {
    status & DEVICE_STATUS_DRIVER_OK != 0
}

fn fill_le(data: &mut [u8], value: u64) {
    let bytes = value.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        *b = bytes.get(i).copied().unwrap_or(0);
    }
}

fn parse_le(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    for (i, b) in data.iter().take(8).enumerate() {
        buf[i] = *b;
    }
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::super::block::BlockBackend;
    use super::super::queue::Queue;
    use super::*;
    use std::io;

    struct MemDisk(Vec<u8>);
    impl BlockBackend for MemDisk {
        fn read_at(&mut self, o: u64, buf: &mut [u8]) -> io::Result<()> {
            buf.copy_from_slice(&self.0[o as usize..o as usize + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, o: u64, buf: &[u8]) -> io::Result<()> {
            self.0[o as usize..o as usize + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn nsectors(&self) -> u64 {
            (self.0.len() / 512) as u64
        }
    }

    // Build a queue with one ready blk read request in guest memory, return the
    // device + mem so the test can notify and inspect the completion.
    fn setup() -> (VirtioPciDevice, Arc<GuestMemory>) {
        let mem = Arc::new(GuestMemory::new());
        mem.register_owned(0x4000_0000, 0x2_0000);
        // Rings near the top of the region.
        let desc = 0x4000_1000;
        let avail = 0x4000_2000;
        let used = 0x4000_3000;
        let qsz = 8u16;
        // desc 0: header (read) @0x40004000 len16 -> desc1
        let wr = |gpa: u64, addr: u64, len: u32, flags: u16, next: u16| {
            mem.write(gpa, &addr.to_le_bytes()).unwrap();
            mem.write_u32(gpa + 8, len).unwrap();
            mem.write_u16(gpa + 12, flags).unwrap();
            mem.write_u16(gpa + 14, next).unwrap();
        };
        wr(desc, 0x4000_4000, 16, 0x1, 1); // NEXT
        wr(desc + 16, 0x4000_5000, 512, 0x3, 2); // NEXT|WRITE -> desc2
        wr(desc + 32, 0x4000_6000, 1, 0x2, 0); // WRITE status
        // virtio-blk IN header, sector 0
        mem.write_u32(0x4000_4000, 0).unwrap();
        mem.write_u64(0x4000_4008, 0).unwrap();
        // avail: head 0, idx 1
        mem.write_u16(avail + 4, 0).unwrap();
        mem.write_u16(avail + 2, 1).unwrap();

        let queue = Queue {
            size: qsz,
            desc,
            avail,
            used,
            event_idx: false,
            indirect: false,
            next_avail: 0,
            next_used: 0,
        };
        let disk = vec![0xCDu8; 512];
        let dev = VirtioPciDevice::new(
            "disk0",
            Backend::Block(BlockDevice::new(Box::new(MemDisk(disk)), "disk0")),
            mem.clone(),
            RestoreParams {
                features: super::super::features::VERSION_1,
                queues: vec![queue],
                queue_vectors: vec![1],
                device_status: 0x0f,
                device_config: vec![],
            },
        );
        (dev, mem)
    }

    #[test]
    fn notify_processes_queue_and_writes_used_ring() {
        let (dev, mem) = setup();
        // Notify queue 0 via the notification window.
        dev.write(NOTIFICATION_OFFSET, &0u16.to_le_bytes());
        // Used ring: idx advanced to 1, element id 0, len 513.
        assert_eq!(mem.read_u16(0x4000_3000 + 2).unwrap(), 1);
        assert_eq!(mem.read_u32(0x4000_3000 + 4).unwrap(), 0); // head id
        assert_eq!(mem.read_u32(0x4000_3000 + 8).unwrap(), 513); // 512 data + status
        // Data buffer got the disk contents.
        assert_eq!(mem.read_u32(0x4000_5000).unwrap(), 0xCDCD_CDCD);
        // Status byte OK.
        assert_eq!(mem.read_u32(0x4000_6000).unwrap() & 0xff, 0);
    }

    #[test]
    fn isr_read_clears_status() {
        let (dev, _mem) = setup();
        dev.write(NOTIFICATION_OFFSET, &0u16.to_le_bytes());
        let mut isr = [0u8; 1];
        dev.read(ISR_OFFSET, &mut isr);
        assert_eq!(isr[0] & 0x1, 0x1, "ISR latched after completion");
        let mut isr2 = [0u8; 1];
        dev.read(ISR_OFFSET, &mut isr2);
        assert_eq!(isr2[0], 0, "ISR cleared on read");
    }

    #[test]
    fn common_config_reports_driver_ok_and_queue_addrs() {
        let (dev, _mem) = setup();
        let mut st = [0u8; 1];
        dev.read(0x14, &mut st); // device_status
        assert!(driver_ok(st[0]));
        let mut desc = [0u8; 8];
        dev.read(0x20, &mut desc); // queue_desc for queue_select 0
        assert_eq!(u64::from_le_bytes(desc), 0x4000_1000);
    }
}
