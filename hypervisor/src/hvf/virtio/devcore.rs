//! The transport-independent half of a virtio device.
//!
//! A virtio device is two separable things: a *transport*, which is a register
//! map the guest pokes to discover the device and program its virtqueues, and a
//! *device model*, which drains those queues, runs the requests through a
//! backend and publishes completions. This module is the second half, shared
//! verbatim by both transports this backend implements — `virtio-pci`, which a
//! restored cloud snapshot arrives already using, and `virtio-mmio`, which a
//! cold-booted guest discovers from the device tree.
//!
//! Keeping it here is not tidiness. The queue draining, the notification
//! re-arming and the net RX/TX asymmetry are the parts that took measurement to
//! get right; a second copy of them in the second transport is a second place
//! for those lessons to rot.

use std::sync::{Arc, Mutex};

use super::block::BlockDevice;
use super::net::{NetDevice, VIRTIO_NET_HDR_LEN};
use super::queue::Queue;
use super::rng::RngDevice;
use super::GuestMemory;

/// virtio device status bits.
pub(super) const DEVICE_STATUS_DRIVER_OK: u8 = 0x04;

/// The backend a [`super::pci::VirtioPciDevice`] drives.
pub enum Backend {
    /// A `virtio-blk` device.
    Block(BlockDevice),
    /// A `virtio-rng` device.
    Rng(RngDevice),
    /// A `virtio-net` device. Its receive direction is host-driven, so the
    /// transport handles its RX/TX queues specially (see [`DeviceCore::notify_net`]).
    Net(NetDevice),
}

/// virtio-net queue indices (max_virtqueue_pairs = 1): receive then transmit.
pub(super) const NET_RX_QUEUE: u16 = 0;
pub(super) const NET_TX_QUEUE: u16 = 1;

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
pub(super) struct VirtioConfig {
    pub(super) device_feature_select: u32,
    pub(super) driver_feature_select: u32,
    pub(super) device_features: u64,
    pub(super) driver_features: u64,
    pub(super) msix_config: u16,
    pub(super) num_queues: u16,
    pub(super) device_status: u8,
    pub(super) config_generation: u8,
    pub(super) queue_select: u16,
}

pub(super) struct DeviceCore {
    pub(super) common: VirtioConfig,
    /// One restored queue per virtqueue (index == queue select).
    pub(super) queues: Vec<Queue>,
    /// Per-queue MSI-X vector (`queue_msix_vector`), index == queue.
    pub(super) queue_vectors: Vec<u16>,
    pub(super) backend: Backend,
    pub(super) device_config: Vec<u8>,
    pub(super) isr_status: u8,
    pub(super) mem: Arc<GuestMemory>,
    pub(super) injector: Box<dyn InterruptInjector>,
}
impl DeviceCore {
    /// Service a queue notification: drain and process the available ring.
    pub(super) fn notify(&mut self, queue_index: u16) {
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
        let _tx_t = std::time::Instant::now();
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
    /// notify. Returns whether any frame was delivered into the guest.
    pub(super) fn flush_rx(&mut self) -> bool {
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
                _ => {
                    break; // no posted buffer: leave the backlog for later
                }
            };
            let cap: u32 = chain.writable().map(|s| s.len).sum();
            let (frame, hdr_flags) = match &mut self.backend {
                Backend::Net(n) => {
                    // Tell the device how much this guest buffer holds before
                    // asking for a frame, so receive coalescing is bounded by
                    // the guest's real capacity rather than a guess.
                    n.observe_rx_capacity(cap as usize);
                    (n.pop_rx(), n.rx_header_flags())
                }
                _ => (None, 0),
            };
            let Some(frame) = frame else { break };

            // Compose [virtio-net header][frame] and spread it across the
            // chain's writable segments.
            let mut payload = vec![0u8; VIRTIO_NET_HDR_LEN];
            payload[0] = hdr_flags;
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
        delivered
    }

    /// Advance the net responder's asynchronous work (a userspace NAT polling
    /// its host sockets) and deliver any produced frames into the guest's
    /// receive queue. Returns whether a frame reached the guest, so the caller
    /// can wake a parked vCPU to take the RX completion promptly. A no-op for a
    /// non-net backend.
    pub(super) fn service_net(&mut self) -> bool {
        match &mut self.backend {
            Backend::Net(n) => {
                n.service();
            }
            _ => return false,
        }
        self.flush_rx()
    }
}

/// Whether a restored `device_status` indicates the driver finished setup.
pub fn driver_ok(status: u8) -> bool {
    status & DEVICE_STATUS_DRIVER_OK != 0
}

pub(super) fn fill_le(data: &mut [u8], value: u64) {
    let bytes = value.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        *b = bytes.get(i).copied().unwrap_or(0);
    }
}

pub(super) fn parse_le(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    for (i, b) in data.iter().take(8).enumerate() {
        buf[i] = *b;
    }
    u64::from_le_bytes(buf)
}
