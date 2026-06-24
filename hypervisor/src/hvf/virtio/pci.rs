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
use super::net::{NetDevice, VIRTIO_NET_HDR_LEN};
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
    /// A `virtio-net` device. Its receive direction is host-driven, so the
    /// transport handles its RX/TX queues specially (see [`Inner::notify_net`]).
    Net(NetDevice),
}

/// virtio-net queue indices (max_virtqueue_pairs = 1): receive then transmit.
const NET_RX_QUEUE: u16 = 0;
const NET_TX_QUEUE: u16 = 1;

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

/// Delivers a message-based SPI to the guest. Apple's managed GIC backs this on
/// hardware (`hv_gic_send_msi`); tests use a recording stub. This is the
/// deliverable counterpart to the ITS path: where a snapshot routes its virtio
/// completions as GICv3 message-based SPIs (MBI) rather than through a GIC ITS,
/// the MSI-X `msg_data` IS the target SPI `INTID`, so a queue completion is
/// delivered directly -- no ITS translation, and no impossible LPI injection.
pub trait MsiSink: Send + Sync {
    /// Deliver message-based SPI `intid` (within the GIC's configured MSI
    /// range) to the guest.
    fn deliver_spi(&self, intid: u32);
}

/// An [`InterruptInjector`] that turns a virtio device's MSI-X vector into a
/// message-based SPI delivered through a [`MsiSink`] (the managed GIC on
/// hardware).
///
/// This is the live, deliverable injector: for a snapshot whose completions are
/// MBI/message-SPI routed, `vector_intids[vector]` is the SPI `INTID` the
/// guest's handler is waiting on, so a queue completion delivers it straight
/// through the GIC doorbell. It is the production path `chm` installs for a
/// deliverable snapshot, in contrast to the ITS injector (whose LPI target the
/// managed GIC cannot deliver).
pub struct MsiSpiInjector {
    name: String,
    /// Target SPI `INTID` for each MSI-X vector, indexed by vector number.
    vector_intids: Vec<u32>,
    sink: Arc<dyn MsiSink>,
}

impl MsiSpiInjector {
    /// Build an injector mapping each MSI-X vector to its SPI `INTID`.
    pub fn new(
        name: impl Into<String>,
        vector_intids: Vec<u32>,
        sink: Arc<dyn MsiSink>,
    ) -> Self {
        Self {
            name: name.into(),
            vector_intids,
            sink,
        }
    }
}

impl InterruptInjector for MsiSpiInjector {
    fn signal(&self, vector: u16) {
        let Some(&intid) = self.vector_intids.get(vector as usize) else {
            eprintln!(
                "[virtio {}] MSI-X vector {vector} has no SPI mapping; dropping",
                self.name
            );
            return;
        };
        if std::env::var_os("CHM_TRACE_MMIO").is_some() {
            eprintln!(
                "[virtio {}] queue completion -> message-based SPI {intid}",
                self.name
            );
        }
        self.sink.deliver_spi(intid);
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

    /// Number of virtqueues this device exposes.
    pub fn num_queues(&self) -> usize {
        self.inner.lock().unwrap().queues.len()
    }

    /// Drain every virtqueue once, completing any requests that were left
    /// in-flight in the available ring at snapshot time (submitted by the guest
    /// but not yet completed) and delivering their completion interrupts.
    ///
    /// A resumed guest does not re-notify a queue it had already kicked before
    /// the snapshot; it waits for the completion interrupt. Without this drain
    /// such a guest blocks forever on its first post-resume I/O wait (e.g. a
    /// mount reading the boot filesystem). Call once after the device tree is
    /// wired and the GIC is live, on the vCPU's owning thread.
    pub fn drain_on_resume(&self) {
        let mut inner = self.inner.lock().unwrap();
        let n = inner.queues.len();
        let trace = std::env::var_os("CHM_TRACE_DRAIN").is_some();
        let mem = inner.mem.clone();
        for qi in 0..n as u16 {
            if trace {
                let q = &inner.queues[qi as usize];
                let avail_idx = q.avail_idx_value(&mem).unwrap_or(0);
                let used_idx = q.used_idx_value(&mem).unwrap_or(0);
                eprintln!(
                    "[drain {}] q{qi}: avail.idx={avail_idx} used.idx={used_idx} \
                     next_avail={} in_flight={}",
                    self.name,
                    q.next_avail,
                    avail_idx != q.next_avail
                );
            }
            // Process anything the guest made available but the capture-side
            // device never consumed; `notify` only signals a completion
            // interrupt when it actually completes a request, so a snapshot
            // whose queues were already quiesced (the cloud-hypervisor case)
            // pops nothing and stays silent. Completions that the capture side
            // DID finish are delivered by the restored GIC pending state.
            inner.notify(qi);
        }
    }
}

impl Inner {
    /// Service a queue notification: drain and process the available ring.
    fn notify(&mut self, queue_index: u16) {
        if matches!(self.backend, Backend::Net(_)) {
            self.notify_net(queue_index);
            return;
        }
        let Some(queue) = self.queues.get_mut(queue_index as usize) else {
            return;
        };
        // Snapshot the queue out so we can borrow backend + mem mutably/immutably
        // without aliasing `self`.
        let mem = self.mem.clone();
        let mut completed_any = false;
        let old_used = queue.next_used;
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
                // Net is dispatched to notify_net before this loop is reached.
                Backend::Net(_) => 0,
            };
            let _ = queue.add_used(&mem, chain.head, used_len);
            completed_any = true;
        }
        if completed_any {
            self.isr_status |= 0x1;
            let needs = queue
                .needs_interrupt(&mem, old_used, queue.next_used)
                .unwrap_or(true);
            if std::env::var_os("CHM_TRACE_NOTIFY").is_some() {
                let ue = mem
                    .read_u16(queue.avail + 4 + 2 * queue.size as u64)
                    .unwrap_or(0);
                eprintln!(
                    "[notify] q{queue_index} completed: old_used={old_used} \
                     new_used={} used_event={ue} event_idx={} needs_irq={needs}",
                    queue.next_used, queue.event_idx
                );
            }
            if needs {
                let vector = self
                    .queue_vectors
                    .get(queue_index as usize)
                    .copied()
                    .unwrap_or(0);
                self.injector.signal(vector);
            }
        }
        // Re-arm notification suppression so the driver kicks us for its NEXT
        // submission. A restored queue carries the capture-side device's stale
        // avail_event/NO_NOTIFY state; without re-arming, a post-resume guest
        // adds buffers (e.g. a jbd2 journal commit) silently and wedges. Done
        // on every notify (and thus on drain_on_resume) regardless of whether
        // anything completed this pass.
        let _ = queue.arm_notification(&mem);
    }

    /// Service a virtio-net queue notification.
    ///
    /// A guest notify on the TX queue means it has frames to send: drain them,
    /// hand each (header-stripped) frame to the responder, complete the TX
    /// descriptors, then push any reply frames into the RX queue. A notify on
    /// the RX queue means the guest posted fresh receive buffers: flush any
    /// backlog into them. Either way we end by trying to deliver pending RX
    /// frames, since a reply produced by a TX notify needs an RX buffer the
    /// guest may already have posted.
    fn notify_net(&mut self, queue_index: u16) {
        let mem = self.mem.clone();
        if queue_index == NET_TX_QUEUE {
            let mut completed = false;
            let Some(tx) = self.queues.get_mut(NET_TX_QUEUE as usize) else {
                return;
            };
            let old_used = tx.next_used;
            while let Ok(Some(chain)) = tx.pop(&mem) {
                // Reassemble the frame from the readable segments and strip the
                // virtio-net header.
                let mut buf = Vec::new();
                for seg in chain.readable() {
                    let mut s = vec![0u8; seg.len as usize];
                    if mem.read(seg.gpa, &mut s).is_ok() {
                        buf.extend_from_slice(&s);
                    }
                }
                if buf.len() > VIRTIO_NET_HDR_LEN
                    && let Backend::Net(n) = &mut self.backend
                {
                    n.handle_tx_frame(&buf[VIRTIO_NET_HDR_LEN..]);
                }
                let _ = tx.add_used(&mem, chain.head, 0);
                completed = true;
            }
            if completed {
                self.isr_status |= 0x1;
                let needs = self
                    .queues
                    .get(NET_TX_QUEUE as usize)
                    .and_then(|q| q.needs_interrupt(&mem, old_used, q.next_used).ok())
                    .unwrap_or(true);
                if needs {
                    let vector = self.queue_vectors.get(NET_TX_QUEUE as usize).copied().unwrap_or(0);
                    self.injector.signal(vector);
                }
            }
            if let Some(tx) = self.queues.get(NET_TX_QUEUE as usize) {
                let _ = tx.arm_notification(&mem);
            }
        } else if queue_index == NET_RX_QUEUE
            && let Some(rx) = self.queues.get(NET_RX_QUEUE as usize)
        {
            let _ = rx.arm_notification(&mem);
        }
        self.flush_rx();
    }

    /// Deliver as many backlogged receive frames as the guest has posted buffers
    /// for: each frame gets a zeroed virtio-net header (`num_buffers = 1`) and is
    /// written into one popped RX descriptor chain, then the RX completion vector
    /// is signalled. A frame with no available buffer is requeued for the next RX
    /// notify.
    fn flush_rx(&mut self) {
        let mem = self.mem.clone();
        let mut delivered = false;
        let old_used = self
            .queues
            .get(NET_RX_QUEUE as usize)
            .map_or(0, |q| q.next_used);
        loop {
            let has_pending = matches!(&self.backend, Backend::Net(n) if n.has_pending_rx());
            if !has_pending {
                break;
            }
            let Some(rx) = self.queues.get_mut(NET_RX_QUEUE as usize) else {
                break;
            };
            let chain = match rx.pop(&mem) {
                Ok(Some(c)) => c,
                _ => break, // no posted buffer: leave the backlog for later
            };
            let frame = match &mut self.backend {
                Backend::Net(n) => n.pop_rx(),
                _ => None,
            };
            let Some(frame) = frame else { break };

            // Compose [virtio-net header][frame] and spread it across the
            // chain's writable segments.
            let mut payload = vec![0u8; VIRTIO_NET_HDR_LEN];
            payload[10] = 1; // num_buffers = 1 (little-endian u16)
            payload.extend_from_slice(&frame);
            let mut written = 0usize;
            let mut offset = 0usize;
            for seg in chain.writable() {
                if offset >= payload.len() {
                    break;
                }
                let take = (seg.len as usize).min(payload.len() - offset);
                if mem.write(seg.gpa, &payload[offset..offset + take]).is_err() {
                    break;
                }
                offset += take;
                written += take;
            }
            if written < payload.len() {
                // The guest's buffer could not hold the frame; drop it (a real
                // NIC would too without mergeable buffers) but still complete the
                // descriptor so the guest reclaims it.
                if std::env::var_os("CHM_TRACE_NET").is_some() {
                    eprintln!("[virtio net] rx frame {} bytes truncated to {written}", payload.len());
                }
            }
            let _ = rx.add_used(&mem, chain.head, written as u32);
            delivered = true;
            if std::env::var_os("CHM_TRACE_NET").is_some() {
                eprintln!("[virtio net] injected rx frame ({} bytes) into guest", frame.len());
            }
        }
        if delivered {
            self.isr_status |= 0x1;
            let needs = self
                .queues
                .get(NET_RX_QUEUE as usize)
                .and_then(|q| q.needs_interrupt(&mem, old_used, q.next_used).ok())
                .unwrap_or(true);
            if needs {
                let vector = self.queue_vectors.get(NET_RX_QUEUE as usize).copied().unwrap_or(0);
                self.injector.signal(vector);
            }
            if let Some(rx) = self.queues.get(NET_RX_QUEUE as usize) {
                let _ = rx.arm_notification(&mem);
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
                if std::env::var_os("CHM_TRACE_NOTIFY").is_some() {
                    let mem = inner.mem.clone();
                    let (ai, na) = inner
                        .queues
                        .get(queue_index as usize)
                        .map_or((0, 0), |q| {
                            (q.avail_idx_value(&mem).unwrap_or(0), q.next_avail)
                        });
                    eprintln!(
                        "[notify] {} queue {queue_index} kicked: avail.idx={ai} next_avail={na}",
                        self.name
                    );
                }
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

    #[derive(Default)]
    struct RecordingMsiSink {
        spis: Mutex<Vec<u32>>,
    }
    impl MsiSink for RecordingMsiSink {
        fn deliver_spi(&self, intid: u32) {
            self.spis.lock().unwrap().push(intid);
        }
    }

    #[test]
    fn msi_spi_injector_maps_vector_to_spi_and_delivers() {
        let sink = Arc::new(RecordingMsiSink::default());
        // Vector 0 -> SPI 35, vector 1 -> SPI 36.
        let injector = MsiSpiInjector::new("disk0", vec![35, 36], sink.clone());
        injector.signal(1);
        injector.signal(0);
        // An out-of-range vector is dropped, not delivered.
        injector.signal(7);
        assert_eq!(*sink.spis.lock().unwrap(), vec![36, 35]);
    }

    #[test]
    fn notify_delivers_completion_through_msi_spi_injector() {
        let (dev, _mem) = setup();
        let sink = Arc::new(RecordingMsiSink::default());
        // setup()'s queue uses MSI-X vector 1; map it to SPI 32.
        dev.set_injector(Box::new(MsiSpiInjector::new("disk0", vec![0, 32], sink.clone())));
        dev.write(NOTIFICATION_OFFSET, &0u16.to_le_bytes());
        assert_eq!(
            *sink.spis.lock().unwrap(),
            vec![32],
            "queue completion did not deliver its SPI through the injector"
        );
    }

    #[test]
    fn drain_on_resume_completes_in_flight_request_and_signals() {
        // setup()'s queue is seeded with avail.idx=1 / next_avail=0, i.e. a
        // request the guest made available but the (capture-side) device had
        // not yet consumed. A resumed guest will not re-notify it, so the
        // resume-time drain must complete it and deliver the completion.
        let (dev, mem) = setup();
        let sink = Arc::new(RecordingMsiSink::default());
        dev.set_injector(Box::new(MsiSpiInjector::new("disk0", vec![0, 32], sink.clone())));
        dev.drain_on_resume();
        // Used ring advanced and the data landed, exactly as a notify would do.
        assert_eq!(mem.read_u16(0x4000_3000 + 2).unwrap(), 1);
        assert_eq!(mem.read_u32(0x4000_5000).unwrap(), 0xCDCD_CDCD);
        assert_eq!(
            *sink.spis.lock().unwrap(),
            vec![32],
            "in-flight completion was not delivered on resume"
        );
    }

    #[test]
    fn drain_on_resume_is_silent_when_queues_quiesced() {
        // A cloud-hypervisor snapshot quiesces its queues before capturing, so
        // there is nothing in-flight; the drain must not fabricate a spurious
        // completion interrupt.
        let (dev, mem) = setup();
        // Seed next_avail == avail.idx so the queue looks already-drained.
        dev.inner.lock().unwrap().queues[0].next_avail = 1;
        let sink = Arc::new(RecordingMsiSink::default());
        dev.set_injector(Box::new(MsiSpiInjector::new("disk0", vec![0, 32], sink.clone())));
        dev.drain_on_resume();
        assert!(
            sink.spis.lock().unwrap().is_empty(),
            "drain delivered a spurious interrupt on a quiesced queue"
        );
        // Used ring untouched.
        assert_eq!(mem.read_u16(0x4000_3000 + 2).unwrap(), 0);
    }

    #[test]
    fn net_tx_arp_request_injects_a_reply_into_rx_and_signals() {
        use super::super::net::{EchoResponder, NetDevice, VIRTIO_NET_HDR_LEN};

        let guest_mac: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let guest_ip: [u8; 4] = [192, 168, 249, 2];
        let gw_ip: [u8; 4] = [192, 168, 249, 1];
        let gw_mac: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

        let mem = Arc::new(GuestMemory::new());
        mem.register_owned(0x4000_0000, 0x2_0000);
        let wr_desc = |gpa: u64, addr: u64, len: u32, flags: u16| {
            mem.write(gpa, &addr.to_le_bytes()).unwrap();
            mem.write_u32(gpa + 8, len).unwrap();
            mem.write_u16(gpa + 12, flags).unwrap();
            mem.write_u16(gpa + 14, 0).unwrap();
        };

        // RX queue (index 0): one empty device-writable buffer.
        let (rx_desc, rx_avail, rx_used, rx_buf) =
            (0x4000_1000u64, 0x4000_1100u64, 0x4000_1200u64, 0x4000_1400u64);
        wr_desc(rx_desc, rx_buf, 256, 0x2); // WRITE
        mem.write_u16(rx_avail + 4, 0).unwrap();
        mem.write_u16(rx_avail + 2, 1).unwrap();

        // TX queue (index 1): a virtio-net header followed by an ARP request.
        let (tx_desc, tx_avail, tx_used, tx_buf) =
            (0x4000_2000u64, 0x4000_2100u64, 0x4000_2200u64, 0x4000_2400u64);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // broadcast
        frame.extend_from_slice(&guest_mac);
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        frame.extend_from_slice(&1u16.to_be_bytes()); // htype
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&1u16.to_be_bytes()); // request
        frame.extend_from_slice(&guest_mac);
        frame.extend_from_slice(&guest_ip);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&gw_ip);
        let mut tx_payload = vec![0u8; VIRTIO_NET_HDR_LEN];
        tx_payload.extend_from_slice(&frame);
        mem.write(tx_buf, &tx_payload).unwrap();
        wr_desc(tx_desc, tx_buf, tx_payload.len() as u32, 0x0); // readable
        mem.write_u16(tx_avail + 4, 0).unwrap();
        mem.write_u16(tx_avail + 2, 1).unwrap();

        let mk_queue = |desc, avail, used| Queue {
            size: 8,
            desc,
            avail,
            used,
            event_idx: false,
            indirect: false,
            next_avail: 0,
            next_used: 0,
        };

        let responder = EchoResponder::new(gw_ip, gw_mac);
        let dev = VirtioPciDevice::new(
            "net2",
            Backend::Net(NetDevice::new(Box::new(responder))),
            mem.clone(),
            RestoreParams {
                features: super::super::features::VERSION_1,
                queues: vec![
                    mk_queue(rx_desc, rx_avail, rx_used),
                    mk_queue(tx_desc, tx_avail, tx_used),
                ],
                queue_vectors: vec![10, 11], // RX vector 10, TX vector 11
                device_status: 0x0f,
                device_config: vec![],
            },
        );
        let sink = Arc::new(RecordingMsiSink::default());
        // vector 10 -> SPI 130 (RX), vector 11 -> SPI 131 (TX).
        let mut intids = vec![0u32; 12];
        intids[10] = 130;
        intids[11] = 131;
        dev.set_injector(Box::new(MsiSpiInjector::new("net2", intids, sink.clone())));

        // Notify the TX queue (index 1): the device parses the frame, produces an
        // ARP reply, and injects it into the RX queue.
        dev.write(NOTIFICATION_OFFSET, &1u16.to_le_bytes());

        // TX consumed.
        assert_eq!(mem.read_u16(tx_used + 2).unwrap(), 1, "TX descriptor completed");
        // RX got the reply.
        assert_eq!(mem.read_u16(rx_used + 2).unwrap(), 1, "RX reply injected");
        let rx_len = mem.read_u32(rx_used + 8).unwrap();
        assert_eq!(rx_len as usize, VIRTIO_NET_HDR_LEN + 42, "header + ARP reply");
        // Ethernet dst of the injected frame is the guest MAC.
        let mut dst = [0u8; 6];
        mem.read(rx_buf + VIRTIO_NET_HDR_LEN as u64, &mut dst).unwrap();
        assert_eq!(dst, guest_mac, "reply addressed to the guest");
        // It is an ARP reply (opcode 2, network byte order) from the gateway.
        let arp = rx_buf + VIRTIO_NET_HDR_LEN as u64 + 14;
        let mut op = [0u8; 2];
        mem.read(arp + 6, &mut op).unwrap();
        assert_eq!(u16::from_be_bytes(op), 2, "ARP reply opcode");
        // Both the RX completion (130) and TX completion (131) were delivered.
        let spis = sink.spis.lock().unwrap().clone();
        assert!(spis.contains(&130), "RX completion SPI delivered, got {spis:?}");
        assert!(spis.contains(&131), "TX completion SPI delivered, got {spis:?}");
    }
}
