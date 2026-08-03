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
use super::devcore::{fill_le, parse_le, DeviceCore, VirtioConfig};
use super::queue::Queue;
use super::GuestMemory;

pub use super::devcore::{
    driver_ok, Backend, InterruptInjector, LoggingInjector, MsiSink, MsiSpiInjector,
};

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



/// A modern virtio-pci device mapped at a restored BAR base.
pub struct VirtioPciDevice {
    name: String,
    inner: Mutex<DeviceCore>,
    /// Wakes the net service thread when the guest transmits. `None` for
    /// non-net devices and for a device built without a service thread.
    kick: Mutex<Option<Arc<super::net::NetKick>>>,
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
        let inner = DeviceCore {
            common: VirtioConfig {
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
            kick: Mutex::new(None),
        }
    }

    /// Attach the wake handle the net service thread waits on, so a guest
    /// transmit is serviced immediately instead of at the next tick.
    pub fn set_net_kick(&self, kick: Arc<super::net::NetKick>) {
        *self.kick.lock().unwrap() = Some(kick);
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

    /// Advance an async net responder (the userspace egress NAT) and inject any
    /// frames it produced into the guest's RX queue. Returns whether a frame
    /// reached the guest. Driven by the net service thread on a periodic tick,
    /// off the vCPU thread; interrupt injection is delivered cross-thread
    /// through the GIC exactly as the vtimer/serial paths are. A no-op for
    /// non-net devices.
    pub fn service_net(&self) -> bool {
        self.inner.lock().unwrap().service_net()
    }

    /// Drain the net backend's accumulated egress-decision events for the audit
    /// trail. Empty for a non-net device or a responder that makes no policy
    /// decisions.
    pub fn drain_egress_events(&self) -> Vec<super::nat::EgressEvent> {
        let mut inner = self.inner.lock().unwrap();
        match &mut inner.backend {
            Backend::Net(n) => n.drain_egress_events(),
            _ => Vec::new(),
        }
    }

    /// Install the interception hook on this device's NAT, if it is a NIC.
    ///
    /// Set after construction because the proxy must bind its port first, and
    /// because a run with no proxy configured leaves this untouched.
    pub fn set_net_intercept(&self, decider: Option<Arc<dyn super::nat::InterceptDecider>>) {
        let mut inner = self.inner.lock().unwrap();
        if let Backend::Net(n) = &mut inner.backend {
            n.set_intercept(decider);
        }
    }
}

/// The virtio-pci *common configuration* window, laid out as
/// `virtio-devices/src/transport/pci_device.rs` lays it out.
///
/// Declared here rather than in `devcore` because these offsets are the PCI
/// transport's, even though the state behind them is the shared device model's.
impl DeviceCore {
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
                // The guest transmitted; the net service thread does the actual
                // stack work, so wake it now rather than let it wait out its
                // tick. Dropping the device lock first keeps the wake off the
                // path any other thread has to contend for.
                let net = matches!(inner.backend, Backend::Net(_));
                drop(inner);
                if net && let Some(kick) = self.kick.lock().unwrap().as_ref() {
                    kick.wake();
                }
            }
            _ => {}
        }
    }
}


#[cfg(test)]
mod tests {
    use super::super::block::{BlockBackend, BlockDevice};
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

        // Notify the TX queue (index 1): the device consumes the frame and hands
        // it to the responder. The reply is produced off the vCPU thread, so the
        // service tick is what injects it into the RX queue.
        dev.write(NOTIFICATION_OFFSET, &1u16.to_le_bytes());
        assert!(dev.service_net(), "service tick injected the reply");

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
