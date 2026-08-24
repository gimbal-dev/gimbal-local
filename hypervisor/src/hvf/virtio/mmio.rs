// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A `virtio-mmio` (version 2) transport, for a guest that has to *discover* its
//! devices rather than resume with them already configured.
//!
//! This is the cold-boot counterpart to [`super::pci`]. The device model behind
//! it is identical — [`DeviceCore`], shared verbatim — but everything the
//! transport does is the mirror image:
//!
//! | | `virtio-pci` (restore) | `virtio-mmio` (cold) |
//! | --- | --- | --- |
//! | features | replayed from the snapshot | negotiated with the driver |
//! | queue addresses | restored, never written | programmed by the driver |
//! | queue size | restored | chosen by the driver, `<= QUEUE_NUM_MAX` |
//! | interrupts | MSI-X vector → LPI/message SPI | one wired SPI, level status |
//!
//! MMIO was chosen for cold boot over building a synthetic PCIe host bridge
//! because the transport is the whole cost: no ECAM window, no BAR
//! programming, no MSI-X tables, no ITS translation. `arch`'s device-tree
//! writer already emits `virtio_mmio@` nodes, so the guest finds the device
//! from the tree we hand it in `x0`.
//!
//! **The one register that is easy to get wrong is `QueueReady`.** The driver
//! writes the descriptor/driver/device addresses *before* it writes
//! `QueueReady = 1`, and it is entitled to program them in any order, so the
//! queue is only safe to service once ready is set. A transport that acted on a
//! notification for a queue whose addresses were half-written would walk a ring
//! at a guest-physical address the driver never finished naming.

use std::sync::{Arc, Mutex};

use super::super::devices::MmioDevice;
use super::devcore::{
    fill_le, parse_le, Backend, DeviceCore, InterruptInjector, LoggingInjector, VirtioConfig,
    DEVICE_STATUS_DRIVER_OK,
};
use super::queue::Queue;
use super::GuestMemory;

/// `"virt"` little-endian — the first thing a driver reads to decide there is a
/// device here at all.
const MAGIC_VALUE: u32 = 0x7472_6976;

/// Transport version. 2 is the modern (non-legacy) layout; a version-1 device
/// would have to expose the obsolete `QueuePFN` page-frame interface instead.
const VERSION: u32 = 2;

/// Reported in `VendorID`. Upstream cloud-hypervisor and QEMU both report
/// something arbitrary here; drivers do not key off it.
const VENDOR_ID: u32 = 0x4348_4D00; // "CHM\0"

/// The largest virtqueue this transport will accept. The driver reads this from
/// `QueueNumMax` and picks its own size at or below it.
const QUEUE_NUM_MAX: u32 = 256;

/// Size of the MMIO window each device claims, matching what the device tree
/// advertises in its `reg` property.
pub const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// Where device-specific configuration starts.
const CONFIG_OFFSET: u64 = 0x100;

/// virtio device IDs (spec §5).
pub mod device_id {
    /// `virtio-net`.
    pub const NET: u32 = 1;
    /// `virtio-blk`.
    pub const BLOCK: u32 = 2;
    /// `virtio-rng` (entropy source).
    pub const ENTROPY: u32 = 4;
}

/// `VIRTIO_NET_F_MAC`: the device supplies the MAC address in its config space,
/// so the guest's NIC has a stable address across boots instead of a random one.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;

/// Driver status bits the transport acts on. `DRIVER_OK` lives in
/// [`super::devcore`] because the restore path reads it out of a snapshot.
const DEVICE_STATUS_FEATURES_OK: u8 = 0x08;

/// `InterruptStatus` bit 0: one or more virtqueues has a new used-ring entry.
const INT_USED_RING: u32 = 0x1;

/// Per-queue programming state the driver builds up before setting `QueueReady`.
///
/// Held separately from [`Queue`] because a queue is only well-formed once all
/// three ring addresses and the size have been written, and the driver writes
/// them one 32-bit half at a time in an order of its choosing.
#[derive(Default, Clone, Copy)]
struct QueueSetup {
    size: u16,
    desc: u64,
    driver: u64,
    device: u64,
    ready: bool,
}

struct MmioRegs {
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u16,
    setups: Vec<QueueSetup>,
    interrupt_status: u32,
}

/// One virtqueue exactly as the driver programmed it, for a snapshot.
///
/// This is [`QueueSetup`] made public, and it is deliberately the *driver's*
/// writes rather than the [`Queue`] they produce. See
/// [`MmioTransportState::queues`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioQueueState {
    /// Ring size in descriptors.
    pub size: u16,
    /// Descriptor table GPA (`QueueDescLow`/`High`).
    pub desc: u64,
    /// Available ring GPA (`QueueDriverLow`/`High`).
    pub driver: u64,
    /// Used ring GPA (`QueueDeviceLow`/`High`).
    pub device: u64,
    /// Whether the driver has finished naming this ring (`QueueReady`).
    pub ready: bool,
}

/// Everything about a live `virtio-mmio` device that a resume has to replay.
///
/// The counterpart of [`super::devmgr::VirtioDeviceDesc`], which describes a
/// device read *out of* a cloud-hypervisor `state.json`. This describes one
/// read out of a device this build is currently running, so a cold-booted guest
/// can originate a snapshot (#378).
///
/// **What is deliberately not here.** The [`Queue`]s in [`DeviceCore`] are
/// absent, because they are not independent state: [`VirtioMmioDevice::publish_queue`]
/// derives each one from `queues[i]` plus `driver_features`, and a restore can
/// re-derive them by running that same function. Recording both would be two
/// descriptions of one machine with no way to tell which was right if they
/// disagreed -- the failure mode `genesis`'s memory layout is written to avoid.
///
/// The ring *indices* (`next_avail`/`next_used`) are absent for a different and
/// stronger reason: they live in guest RAM, which the snapshot dumps verbatim,
/// and [`Queue::restore`] reads them back from there. Serializing them here
/// would be copying a value out of the authoritative store into a second one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmioTransportState {
    /// Device name, e.g. `_disk0`.
    pub name: String,
    /// virtio device type (1 = net, 2 = block).
    pub device_id: u32,
    /// The full feature set this device offered.
    pub device_features: u64,
    /// The subset the driver acknowledged. Authoritative for ring features.
    pub driver_features: u64,
    /// `DeviceFeaturesSel` as last written.
    pub device_features_sel: u32,
    /// `DriverFeaturesSel` as last written.
    pub driver_features_sel: u32,
    /// `QueueSel` as last written.
    pub queue_sel: u16,
    /// `InterruptStatus`, so a resume does not lose an interrupt the driver had
    /// not yet acknowledged.
    pub interrupt_status: u32,
    /// `Status`, which is what tells a resume whether the driver ever finished
    /// bringing this device up.
    pub device_status: u8,
    /// Device-specific config generation counter.
    pub config_generation: u8,
    /// Per-queue driver programming, index == queue select.
    pub queues: Vec<MmioQueueState>,
    /// Device-specific configuration space (e.g. `virtio_blk_config`).
    pub device_config: Vec<u8>,
}

/// A `virtio-mmio` device: the register map, plus the shared device model.
pub struct VirtioMmioDevice {
    name: String,
    device_id: u32,
    /// Features this device offers, as a 64-bit set.
    device_features: u64,
    core: Mutex<DeviceCore>,
    regs: Mutex<MmioRegs>,
    /// Wakes the net service thread when the guest transmits.
    kick: Mutex<Option<Arc<super::net::NetKick>>>,
}

/// How to build a [`VirtioMmioDevice`].
pub struct MmioParams {
    /// virtio device ID, from [`device_id`].
    pub device_id: u32,
    /// Feature bits the device offers. `VIRTIO_F_VERSION_1` is added for you —
    /// a version-2 transport is meaningless without it.
    pub features: u64,
    /// Number of virtqueues the device exposes.
    pub num_queues: u16,
    /// Device-specific configuration bytes (e.g. `virtio_blk_config`).
    pub device_config: Vec<u8>,
}

impl VirtioMmioDevice {
    /// Build a device named `name` driving `backend`.
    pub fn new(
        name: impl Into<String>,
        backend: Backend,
        mem: Arc<GuestMemory>,
        params: MmioParams,
    ) -> Self {
        let name = name.into();
        let device_features = params.features | super::features::VERSION_1;
        let n = params.num_queues as usize;
        let core = DeviceCore {
            common: VirtioConfig {
                device_feature_select: 0,
                driver_feature_select: 0,
                device_features,
                // Nothing is negotiated until the driver writes DriverFeatures.
                driver_features: 0,
                msix_config: 0,
                num_queues: params.num_queues,
                device_status: 0,
                config_generation: 0,
                queue_select: 0,
            },
            // Placeholder queues; the driver programs them and `QueueReady`
            // publishes the result into these slots.
            queues: vec![Queue::default(); n],
            // MMIO has a single wired interrupt, so every queue signals the one
            // vector the injector maps to this device's SPI.
            queue_vectors: vec![0; n],
            backend,
            device_config: params.device_config,
            isr_status: 0,
            mem,
            injector: Box::new(LoggingInjector::new(name.clone())),
        };
        Self {
            name,
            device_id: params.device_id,
            device_features,
            core: Mutex::new(core),
            regs: Mutex::new(MmioRegs {
                device_features_sel: 0,
                driver_features_sel: 0,
                driver_features: 0,
                queue_sel: 0,
                setups: vec![QueueSetup::default(); n],
                interrupt_status: 0,
            }),
            kick: Mutex::new(None),
        }
    }

    /// Rebuild a device from the state a snapshot recorded (#378), driving
    /// `backend`.
    ///
    /// Only the backend is supplied by the caller: it is a *host* resource (an
    /// open file, a NAT responder) that no snapshot can carry. Everything the
    /// guest can observe — name, device id, features, config space, queue
    /// programming, status — comes from `state`, so a restored device is
    /// described by exactly one authority.
    ///
    /// `core.queues` is **derived** from the stored `setups` plus
    /// `driver_features`, the same way [`Self::publish_queue`] derives it when a
    /// driver programs the device live. Deserializing the queues directly would
    /// be a second, independent description of a value that already has one, and
    /// the two would drift silently: the ring features come from what the driver
    /// *acknowledged*, not from what the device offered.
    ///
    /// The progress cursors are the one thing that cannot come from the
    /// document. They live in the guest's own rings, so a ready queue reads them
    /// back out of guest RAM ([`Queue::restore`]) rather than resuming at zero
    /// and re-consuming requests the device already completed.
    pub fn restored(backend: Backend, mem: Arc<GuestMemory>, state: &MmioTransportState) -> Self {
        let acked = state.driver_features;
        let n = state.queues.len();
        let queues = state
            .queues
            .iter()
            .map(|qs| {
                let mut q = Queue {
                    size: qs.size,
                    desc: qs.desc,
                    avail: qs.driver,
                    used: qs.device,
                    event_idx: acked & super::features::RING_EVENT_IDX != 0,
                    indirect: acked & super::features::RING_INDIRECT_DESC != 0,
                    next_avail: 0,
                    next_used: 0,
                };
                // Only a queue the driver marked ready has rings in guest RAM to
                // read: an unready queue's addresses are whatever half-written
                // state the driver had reached, and reading them would seed the
                // cursors from an address that means nothing.
                if qs.ready {
                    let _ = q.restore(&mem);
                }
                q
            })
            .collect();
        let setups = state
            .queues
            .iter()
            .map(|qs| QueueSetup {
                size: qs.size,
                desc: qs.desc,
                driver: qs.driver,
                device: qs.device,
                ready: qs.ready,
            })
            .collect();
        let core = DeviceCore {
            common: VirtioConfig {
                device_feature_select: state.device_features_sel,
                driver_feature_select: state.driver_features_sel,
                device_features: state.device_features,
                driver_features: acked,
                msix_config: 0,
                num_queues: n as u16,
                device_status: state.device_status,
                config_generation: state.config_generation,
                queue_select: state.queue_sel,
            },
            queues,
            queue_vectors: vec![0; n],
            backend,
            device_config: state.device_config.clone(),
            isr_status: 0,
            mem,
            injector: Box::new(LoggingInjector::new(state.name.clone())),
        };
        Self {
            name: state.name.clone(),
            device_id: state.device_id,
            device_features: state.device_features,
            core: Mutex::new(core),
            regs: Mutex::new(MmioRegs {
                device_features_sel: state.device_features_sel,
                driver_features_sel: state.driver_features_sel,
                driver_features: acked,
                queue_sel: state.queue_sel,
                setups,
                interrupt_status: state.interrupt_status,
            }),
            kick: Mutex::new(None),
        }
    }

    /// The device's name (for diagnostics).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read this device's replayable state, for originating a snapshot (#378).
    ///
    /// Takes both locks, `regs` first and then `core`, which is the order every
    /// other path in this file uses (`publish_queue`, `write_status`). Taking
    /// them in the opposite order here would be a lock-ordering inversion and a
    /// deadlock waiting for the one interleaving that hits it.
    pub fn state(&self) -> MmioTransportState {
        let regs = self.regs.lock().unwrap();
        let queues = regs
            .setups
            .iter()
            .map(|s| MmioQueueState {
                size: s.size,
                desc: s.desc,
                driver: s.driver,
                device: s.device,
                ready: s.ready,
            })
            .collect();
        let (
            device_features_sel,
            driver_features_sel,
            driver_features,
            queue_sel,
            interrupt_status,
        ) = (
            regs.device_features_sel,
            regs.driver_features_sel,
            regs.driver_features,
            regs.queue_sel,
            regs.interrupt_status,
        );
        drop(regs);
        let core = self.core.lock().unwrap();
        MmioTransportState {
            name: self.name.clone(),
            device_id: self.device_id,
            device_features: self.device_features,
            driver_features,
            device_features_sel,
            driver_features_sel,
            queue_sel,
            interrupt_status,
            device_status: core.common.device_status,
            config_generation: core.common.config_generation,
            queues,
            device_config: core.device_config.clone(),
        }
    }

    /// Replace the interrupt injector with one that reaches a real GIC.
    pub fn set_injector(&self, injector: Box<dyn InterruptInjector>) {
        self.core.lock().unwrap().injector = injector;
    }

    /// Attach the wake handle the net service thread waits on.
    pub fn set_net_kick(&self, kick: Arc<super::net::NetKick>) {
        *self.kick.lock().unwrap() = Some(kick);
    }

    /// Whether the driver has finished bringing the device up.
    pub fn driver_ok(&self) -> bool {
        self.core.lock().unwrap().common.device_status & DEVICE_STATUS_DRIVER_OK != 0
    }

    /// Advance an async net responder and deliver any frames it produced.
    /// Returns whether a frame reached the guest. A no-op for a non-net device,
    /// and for a device whose driver has not yet posted receive buffers.
    pub fn service_net(&self) -> bool {
        let mut core = self.core.lock().unwrap();
        if core.common.device_status & DEVICE_STATUS_DRIVER_OK == 0 {
            return false;
        }
        let delivered = core.service_net();
        if delivered {
            self.raise(&mut core);
        }
        delivered
    }

    /// Drain the net backend's egress-decision events for the audit trail.
    pub fn drain_egress_events(&self) -> Vec<super::nat::EgressEvent> {
        let mut core = self.core.lock().unwrap();
        match &mut core.backend {
            Backend::Net(n) => n.drain_egress_events(),
            _ => Vec::new(),
        }
    }

    /// Set `InterruptStatus`'s used-ring bit and pulse the wired interrupt.
    ///
    /// The device tree declares this SPI edge-triggered (`IRQ_TYPE_EDGE_RISING`,
    /// as upstream's `create_virtio_node` writes it), so a pulse is the whole
    /// delivery: there is no level to hold high until the driver acknowledges.
    /// `InterruptStatus` still latches, because the driver reads it in its
    /// handler to learn *why* it was interrupted and writes `InterruptACK` to
    /// clear it.
    fn raise(&self, core: &mut DeviceCore) {
        if core.isr_status == 0 {
            return;
        }
        core.isr_status = 0;
        self.regs.lock().unwrap().interrupt_status |= INT_USED_RING;
        core.injector.signal(0);
    }

    /// Publish a driver-programmed queue into the device model.
    ///
    /// Called when `QueueReady` goes to 1. The negotiated ring features come
    /// from `driver_features`, not from what the device offered: a driver is
    /// free to decline `EVENT_IDX` even though we offer it, and a queue that
    /// believed otherwise would read an event index the driver never writes.
    fn publish_queue(&self, index: u16) {
        let regs = self.regs.lock().unwrap();
        let Some(&setup) = regs.setups.get(index as usize) else {
            return;
        };
        let acked = regs.driver_features;
        drop(regs);
        let mut core = self.core.lock().unwrap();
        let Some(q) = core.queues.get_mut(index as usize) else {
            return;
        };
        *q = Queue {
            size: setup.size,
            desc: setup.desc,
            avail: setup.driver,
            used: setup.device,
            event_idx: acked & super::features::RING_EVENT_IDX != 0,
            indirect: acked & super::features::RING_INDIRECT_DESC != 0,
            next_avail: 0,
            next_used: 0,
        };
        if std::env::var_os("CHM_TRACE_MMIO").is_some() {
            eprintln!(
                "[virtio-mmio {}] queue {index} ready: size={} desc={:#x} avail={:#x} \
                 used={:#x} event_idx={} indirect={}",
                self.name, q.size, q.desc, q.avail, q.used, q.event_idx, q.indirect
            );
        }
    }

    /// Install the interception hook on this device's NAT, if it is a NIC.
    ///
    /// The mirror of [`super::pci::VirtioPciDevice::set_net_intercept`]: the
    /// credential proxy is a property of the *network*, not of the transport
    /// the guest happens to reach it through, so a cold-booted guest on
    /// virtio-mmio gets the same edge injection a rehydrated one on virtio-pci
    /// does. Set after construction because the proxy must bind its port first.
    pub fn set_net_intercept(&self, decider: Option<Arc<dyn super::nat::InterceptDecider>>) {
        let mut core = self.core.lock().unwrap();
        if let Backend::Net(n) = &mut core.backend {
            n.set_intercept(decider);
        }
    }

    /// Apply the negotiated feature set to the backend, once the driver has
    /// written `FEATURES_OK`.
    fn commit_features(&self, acked: u64) {
        let mut core = self.core.lock().unwrap();
        core.common.driver_features = acked;
        if let Backend::Net(n) = &mut core.backend {
            n.apply_features(acked);
        }
    }

    /// Reset: the driver wrote `Status = 0`. Everything it programmed goes away,
    /// because it is about to program it again from scratch.
    fn reset(&self) {
        let mut regs = self.regs.lock().unwrap();
        regs.driver_features = 0;
        regs.driver_features_sel = 0;
        regs.device_features_sel = 0;
        regs.queue_sel = 0;
        regs.interrupt_status = 0;
        for s in regs.setups.iter_mut() {
            *s = QueueSetup::default();
        }
        drop(regs);
        let mut core = self.core.lock().unwrap();
        core.common.device_status = 0;
        core.common.driver_features = 0;
        core.isr_status = 0;
        for q in core.queues.iter_mut() {
            *q = Queue::default();
        }
    }
}

impl MmioDevice for VirtioMmioDevice {
    fn read(&self, offset: u64, data: &mut [u8]) {
        if offset >= CONFIG_OFFSET {
            let core = self.core.lock().unwrap();
            let base = (offset - CONFIG_OFFSET) as usize;
            for (i, b) in data.iter_mut().enumerate() {
                *b = core.device_config.get(base + i).copied().unwrap_or(0);
            }
            return;
        }
        let regs = self.regs.lock().unwrap();
        let v: u64 = match offset {
            0x000 => u64::from(MAGIC_VALUE),
            0x004 => u64::from(VERSION),
            0x008 => u64::from(self.device_id),
            0x00c => u64::from(VENDOR_ID),
            0x010 => (self.device_features >> (regs.device_features_sel * 32)) & 0xffff_ffff,
            0x034 => u64::from(QUEUE_NUM_MAX),
            0x044 => u64::from(
                regs.setups
                    .get(regs.queue_sel as usize)
                    .is_some_and(|s| s.ready),
            ),
            0x060 => u64::from(regs.interrupt_status),
            0x070 => u64::from(self.core.lock().unwrap().common.device_status),
            0x0fc => u64::from(self.core.lock().unwrap().common.config_generation),
            _ => 0,
        };
        fill_le(data, v);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let v = parse_le(data);
        if offset >= CONFIG_OFFSET {
            let mut core = self.core.lock().unwrap();
            let base = (offset - CONFIG_OFFSET) as usize;
            for (i, b) in data.iter().enumerate() {
                if let Some(slot) = core.device_config.get_mut(base + i) {
                    *slot = *b;
                }
            }
            return;
        }
        match offset {
            0x014 => self.regs.lock().unwrap().device_features_sel = v as u32,
            0x020 => {
                let mut regs = self.regs.lock().unwrap();
                let sel = regs.driver_features_sel;
                let half = (v & 0xffff_ffff) << (sel * 32);
                let mask = 0xffff_ffffu64 << (sel * 32);
                regs.driver_features = (regs.driver_features & !mask) | half;
            }
            0x024 => self.regs.lock().unwrap().driver_features_sel = v as u32,
            0x030 => {
                let sel = v as u16;
                self.regs.lock().unwrap().queue_sel = sel;
                self.core.lock().unwrap().common.queue_select = sel;
            }
            0x038 => self.with_setup(|s| s.size = v as u16),
            0x044 => {
                let ready = v & 1 != 0;
                let index = self.regs.lock().unwrap().queue_sel;
                self.with_setup(|s| s.ready = ready);
                if ready {
                    self.publish_queue(index);
                }
            }
            0x050 => self.notify(v as u16),
            0x064 => {
                let ack = v as u32;
                self.regs.lock().unwrap().interrupt_status &= !ack;
            }
            0x070 => self.write_status(v as u8),
            0x080 => self.with_setup(|s| s.desc = (s.desc & !0xffff_ffff) | (v & 0xffff_ffff)),
            0x084 => self.with_setup(|s| s.desc = (s.desc & 0xffff_ffff) | (v << 32)),
            0x090 => self.with_setup(|s| s.driver = (s.driver & !0xffff_ffff) | (v & 0xffff_ffff)),
            0x094 => self.with_setup(|s| s.driver = (s.driver & 0xffff_ffff) | (v << 32)),
            0x0a0 => self.with_setup(|s| s.device = (s.device & !0xffff_ffff) | (v & 0xffff_ffff)),
            0x0a4 => self.with_setup(|s| s.device = (s.device & 0xffff_ffff) | (v << 32)),
            _ => {}
        }
    }
}

impl VirtioMmioDevice {
    /// Apply `f` to the currently selected queue's setup.
    fn with_setup(&self, f: impl FnOnce(&mut QueueSetup)) {
        let mut regs = self.regs.lock().unwrap();
        let sel = regs.queue_sel as usize;
        if let Some(s) = regs.setups.get_mut(sel) {
            f(s);
        }
    }

    fn write_status(&self, status: u8) {
        if status == 0 {
            if std::env::var_os("CHM_TRACE_MMIO").is_some() {
                eprintln!("[virtio-mmio {}] driver reset the device", self.name);
            }
            self.reset();
            return;
        }
        let features_ok = status & DEVICE_STATUS_FEATURES_OK != 0;
        let was_features_ok =
            self.core.lock().unwrap().common.device_status & DEVICE_STATUS_FEATURES_OK != 0;
        if features_ok && !was_features_ok {
            let acked = self.regs.lock().unwrap().driver_features;
            self.commit_features(acked);
        }
        self.core.lock().unwrap().common.device_status = status;
        if std::env::var_os("CHM_TRACE_MMIO").is_some() {
            eprintln!("[virtio-mmio {}] status = {status:#04x}", self.name);
        }
    }

    /// Service a `QueueNotify`.
    fn notify(&self, index: u16) {
        let ready = self
            .regs
            .lock()
            .unwrap()
            .setups
            .get(index as usize)
            .is_some_and(|s| s.ready);
        if !ready {
            // See the module note on `QueueReady`: the driver has not finished
            // naming this ring's addresses, so there is nothing safe to walk.
            return;
        }
        let mut core = self.core.lock().unwrap();
        core.notify(index);
        self.raise(&mut core);
        let net = matches!(core.backend, Backend::Net(_));
        drop(core);
        if net && let Some(kick) = self.kick.lock().unwrap().as_ref() {
            kick.wake();
        }
    }
}

/// The `virtio_blk_config` a cold guest reads: capacity in 512-byte sectors at
/// offset 0, everything else zero.
pub fn blk_config(nsectors: u64) -> Vec<u8> {
    let mut cfg = vec![0u8; 0x40];
    cfg[..8].copy_from_slice(&nsectors.to_le_bytes());
    cfg
}

/// The `virtio_net_config` a cold guest reads: the MAC at offset 0, then
/// `status` and `max_virtqueue_pairs`, both left zero (we offer neither
/// `VIRTIO_NET_F_STATUS` nor `_MQ`, so the driver must not read them).
pub fn net_config(mac: [u8; 6]) -> Vec<u8> {
    let mut cfg = vec![0u8; 0x20];
    cfg[..6].copy_from_slice(&mac);
    cfg
}

#[cfg(test)]
mod tests {
    use super::super::block::{BlockBackend, BlockDevice};
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

    fn dev() -> (VirtioMmioDevice, Arc<GuestMemory>) {
        let mem = Arc::new(GuestMemory::new());
        mem.register_owned(0x4000_0000, 0x2_0000);
        let disk = vec![0xabu8; 512 * 8];
        let d = VirtioMmioDevice::new(
            "blk0",
            Backend::Block(BlockDevice::new(Box::new(MemDisk(disk)), "disk0")),
            mem.clone(),
            MmioParams {
                device_id: device_id::BLOCK,
                features: 0,
                num_queues: 1,
                device_config: blk_config(8),
            },
        );
        (d, mem)
    }

    fn read32(d: &VirtioMmioDevice, off: u64) -> u32 {
        let mut b = [0u8; 4];
        d.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    fn write32(d: &VirtioMmioDevice, off: u64, v: u32) {
        d.write(off, &v.to_le_bytes());
    }

    #[test]
    fn identity_registers_are_what_a_driver_probes_for() {
        let (d, _m) = dev();
        assert_eq!(read32(&d, 0x000), MAGIC_VALUE, "MagicValue");
        assert_eq!(read32(&d, 0x004), 2, "Version must be 2, not legacy");
        assert_eq!(read32(&d, 0x008), device_id::BLOCK);
        assert_eq!(read32(&d, 0x034), QUEUE_NUM_MAX);
    }

    #[test]
    fn version_1_is_offered_even_when_the_caller_asks_for_no_features() {
        // A version-2 transport that does not offer VIRTIO_F_VERSION_1 is
        // rejected by Linux with "device does not comply with spec version 1.x".
        let (d, _m) = dev();
        write32(&d, 0x014, 1); // DeviceFeaturesSel = 1 (upper 32 bits)
        let hi = read32(&d, 0x010);
        assert_eq!(hi & 1, 1, "VERSION_1 (bit 32) must be in the upper half");
    }

    #[test]
    fn driver_features_are_assembled_from_both_halves() {
        let (d, _m) = dev();
        write32(&d, 0x024, 0); // DriverFeaturesSel = 0
        write32(&d, 0x020, 0x1000_0000); // RING_INDIRECT_DESC (bit 28)
        write32(&d, 0x024, 1); // DriverFeaturesSel = 1
        write32(&d, 0x020, 0x0000_0001); // VERSION_1 (bit 32)
        write32(&d, 0x070, 0x8); // FEATURES_OK commits them
        let acked = d.core.lock().unwrap().common.driver_features;
        assert_eq!(
            acked,
            super::super::features::RING_INDIRECT_DESC | super::super::features::VERSION_1,
            "acked = {acked:#x}"
        );
    }

    #[test]
    fn a_queue_is_only_published_when_the_driver_sets_ready() {
        let (d, _m) = dev();
        write32(&d, 0x030, 0); // QueueSel = 0
        write32(&d, 0x038, 64); // QueueNum
        write32(&d, 0x080, 0x2000); // QueueDescLow
        write32(&d, 0x090, 0x3000); // QueueDriverLow
        write32(&d, 0x0a0, 0x4000); // QueueDeviceLow
        assert_eq!(
            d.core.lock().unwrap().queues[0].desc,
            0,
            "addresses must not reach the device model before QueueReady"
        );
        write32(&d, 0x044, 1);
        let q = d.core.lock().unwrap().queues[0];
        assert_eq!((q.size, q.desc, q.avail, q.used), (64, 0x2000, 0x3000, 0x4000));
    }

    #[test]
    fn a_notify_for_an_unready_queue_is_ignored() {
        let (d, _m) = dev();
        write32(&d, 0x030, 0);
        write32(&d, 0x080, 0xdead_0000); // a plausible-looking but unfinished address
        // Must not walk the ring: with no QueueReady the driver has not finished
        // programming, and 0xdead0000 is not mapped.
        write32(&d, 0x050, 0);
        assert_eq!(read32(&d, 0x060), 0, "no interrupt should have been raised");
    }

    #[test]
    fn queue_ready_reads_back_what_was_written() {
        // Linux's virtio_mmio probe writes QueueReady then reads it back before
        // trusting the queue; a write-only implementation makes it give up.
        let (d, _m) = dev();
        write32(&d, 0x030, 0);
        assert_eq!(read32(&d, 0x044), 0);
        write32(&d, 0x038, 16);
        write32(&d, 0x044, 1);
        assert_eq!(read32(&d, 0x044), 1);
    }

    #[test]
    fn interrupt_ack_clears_only_the_bits_the_driver_names() {
        let (d, _m) = dev();
        d.regs.lock().unwrap().interrupt_status = 0x3;
        write32(&d, 0x064, 0x1);
        assert_eq!(read32(&d, 0x060), 0x2);
    }

    #[test]
    fn device_config_reports_the_capacity_the_backend_has() {
        let (d, _m) = dev();
        let mut b = [0u8; 8];
        d.read(CONFIG_OFFSET, &mut b);
        assert_eq!(u64::from_le_bytes(b), 8, "capacity in 512-byte sectors");
    }

    #[test]
    fn status_zero_resets_everything_the_driver_programmed() {
        let (d, _m) = dev();
        write32(&d, 0x030, 0);
        write32(&d, 0x038, 64);
        write32(&d, 0x080, 0x2000);
        write32(&d, 0x044, 1);
        write32(&d, 0x070, 0x0f);
        assert!(d.driver_ok());

        write32(&d, 0x070, 0);
        assert!(!d.driver_ok());
        assert_eq!(read32(&d, 0x044), 0, "QueueReady must clear on reset");
        assert_eq!(d.core.lock().unwrap().queues[0].desc, 0);
    }

    #[test]
    fn the_transport_offers_no_queue_larger_than_it_will_service() {
        // QueueNumMax is what bounds a driver's allocation; if the transport
        // advertised more than the ring walker's chain bound, a full ring would
        // be rejected as a descriptor loop.
        assert!(QUEUE_NUM_MAX <= u32::from(u16::MAX));
        assert!(QUEUE_NUM_MAX.is_power_of_two());
    }

    /// The guard #378 rests on: what a driver programmed is what a snapshot
    /// reports.
    ///
    /// Drives the device through the sequence a real `virtio_mmio` driver uses
    /// -- negotiate features, program a ring, set `QueueReady`, then `DRIVER_OK`
    /// -- and asserts every field of [`MmioTransportState`] came back. If any
    /// one of them is dropped on the floor, a cold-booted guest originates a
    /// snapshot that resumes into a device the driver no longer recognises.
    #[test]
    fn the_state_a_snapshot_records_is_what_the_driver_programmed() {
        let (d, _m) = dev();
        write32(&d, 0x024, 0); // DriverFeaturesSel = 0
        write32(&d, 0x020, 0x1000_0000); // RING_INDIRECT_DESC
        write32(&d, 0x024, 1); // DriverFeaturesSel = 1
        write32(&d, 0x020, 0x0000_0001); // VERSION_1
        write32(&d, 0x070, 0x8); // FEATURES_OK
        write32(&d, 0x030, 0); // QueueSel = 0
        write32(&d, 0x038, 64); // QueueNum
        write32(&d, 0x080, 0x2000); // QueueDescLow
        write32(&d, 0x090, 0x3000); // QueueDriverLow
        write32(&d, 0x0a0, 0x4000); // QueueDeviceLow
        write32(&d, 0x044, 1); // QueueReady
        write32(&d, 0x070, 0xf); // ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK

        let s = d.state();
        assert_eq!(s.name, "blk0");
        assert_eq!(s.device_id, device_id::BLOCK);
        assert_eq!(
            s.driver_features,
            super::super::features::RING_INDIRECT_DESC | super::super::features::VERSION_1,
            "the acked set is what ring features are derived from on resume"
        );
        assert_eq!(s.driver_features_sel, 1, "last DriverFeaturesSel written");
        assert_eq!(s.queue_sel, 0);
        assert_eq!(
            s.device_status, 0xf,
            "DRIVER_OK must survive into the snapshot"
        );
        assert_eq!(s.queues.len(), 1);
        assert_eq!(
            s.queues[0],
            MmioQueueState {
                size: 64,
                desc: 0x2000,
                driver: 0x3000,
                device: 0x4000,
                ready: true
            }
        );
        assert_eq!(
            s.device_config,
            blk_config(8),
            "config space is what tells a resumed driver the disk's capacity"
        );
    }

    /// A queue the driver never finished naming must be recorded as not ready.
    ///
    /// The inverse of the guard above, and the one that matters for
    /// correctness: `notify` refuses to walk a ring whose `ready` is false, so a
    /// snapshot that recorded `ready: true` for a half-programmed queue would
    /// resume into a device that walks a ring at an address the driver never
    /// finished writing.
    #[test]
    fn a_half_programmed_queue_is_recorded_as_not_ready() {
        let (d, _m) = dev();
        write32(&d, 0x030, 0);
        write32(&d, 0x038, 64);
        write32(&d, 0x080, 0xdead_0000); // addresses started, QueueReady never set
        let s = d.state();
        assert!(
            !s.queues[0].ready,
            "an unfinished ring must not be marked ready"
        );
        assert_eq!(
            s.device_status, 0,
            "a driver that never came up must say so"
        );
    }

    /// A restored device is described by the document, not by a second
    /// hand-written description of it. Comparing the whole state — rather than
    /// the handful of fields a reviewer thinks to check — is what makes this
    /// guard see a field that is added later and never carried across.
    #[test]
    fn a_restored_device_describes_itself_exactly_as_the_one_it_came_from() {
        // Every field carries a value it could not have taken by default, so
        // dropping any one of them changes the answer. A fixture built by
        // driving a fresh device would leave the rarely-written registers
        // (`interrupt_status`, `config_generation`) at zero, and a guard cannot
        // see a field zeroed to the value it already held.
        let captured = MmioTransportState {
            name: "blk7".into(),
            device_id: device_id::NET,
            device_features: 0x0000_0003_8000_0021,
            driver_features: 0x0000_0001_8000_0001,
            device_features_sel: 1,
            driver_features_sel: 1,
            queue_sel: 1,
            interrupt_status: 0x3,
            device_status: 0xf,
            config_generation: 5,
            queues: vec![
                MmioQueueState {
                    size: 64,
                    desc: RING_DESC,
                    driver: RING_AVAIL,
                    device: RING_USED,
                    ready: true,
                },
                MmioQueueState {
                    size: 32,
                    desc: RING_DESC + 0x4000,
                    driver: RING_AVAIL + 0x4000,
                    device: RING_USED + 0x4000,
                    ready: false,
                },
            ],
            device_config: vec![0xde, 0xad, 0xbe, 0xef, 0x01],
        };
        let (back, _m) = restored_from(&captured);
        assert_eq!(
            back.state(),
            captured,
            "every field a snapshot recorded has to come back, or the guest \
             resumes against a device it never programmed"
        );
    }

    /// The one thing the document cannot carry: the rings are the guest's, and
    /// their indices live in guest RAM. A device that resumed at zero would
    /// re-consume every request it had already completed.
    #[test]
    fn a_restored_queue_resumes_where_the_guest_left_off() {
        let mut s = a_ready_queue_state();
        let (d, mem) = restored_from_with_used_idx(&s, 7);
        {
            let core = d.core.lock().unwrap();
            assert_eq!(
                (core.queues[0].next_used, core.queues[0].next_avail),
                (7, 7),
                "both cursors seed from the live used.idx the guest published"
            );
        }
        // And the reading is of RAM, not of a constant: a different guest is at
        // a different point in its own ring.
        s.queues[0].ready = true;
        mem.write_u16(RING_USED + 2, 19).expect("write used.idx");
        let d2 = VirtioMmioDevice::restored(a_backend(), mem.clone(), &s);
        assert_eq!(d2.core.lock().unwrap().queues[0].next_used, 19);
    }

    /// A queue the driver never finished bringing up has no rings to read: its
    /// addresses are whatever half-written state the driver had reached, and
    /// seeding a cursor from one would be reading an address that means nothing.
    #[test]
    fn an_unready_queue_is_not_seeded_from_addresses_the_driver_never_wrote() {
        let mut s = a_ready_queue_state();
        s.queues[0].ready = false;
        let (d, _m) = restored_from_with_used_idx(&s, 7);
        let core = d.core.lock().unwrap();
        assert_eq!(
            (core.queues[0].next_used, core.queues[0].next_avail),
            (0, 0),
            "an unready queue stays at zero rather than reading a stale address"
        );
    }

    /// The point of restoring the status byte: the guest comes back believing it
    /// finished bringing this device up, and it will never do so again.
    #[test]
    fn a_restored_device_is_already_brought_up() {
        let s = a_ready_queue_state();
        let (d, _m) = restored_from(&s);
        assert!(
            d.driver_ok(),
            "DRIVER_OK has to survive, or the resumed guest waits forever for a \
             device it already configured"
        );
    }

    /// Ring features come from what the driver acknowledged, never from what the
    /// device offered: a driver is free to decline EVENT_IDX, and a restored
    /// queue that believed otherwise would read an index the driver never
    /// writes.
    #[test]
    fn a_restored_queue_takes_its_ring_features_from_the_acked_set() {
        let mut s = a_ready_queue_state();
        s.device_features = super::super::features::RING_EVENT_IDX
            | super::super::features::RING_INDIRECT_DESC
            | super::super::features::VERSION_1;
        s.driver_features = super::super::features::VERSION_1;
        let (d, _m) = restored_from(&s);
        let core = d.core.lock().unwrap();
        assert!(
            !core.queues[0].event_idx && !core.queues[0].indirect,
            "the device offered both and the driver took neither"
        );
    }

    // ---- restore fixtures -------------------------------------------------

    const RING_DESC: u64 = 0x4000_1000;
    const RING_AVAIL: u64 = 0x4000_2000;
    const RING_USED: u64 = 0x4000_3000;

    fn a_backend() -> Backend {
        Backend::Block(BlockDevice::new(
            Box::new(MemDisk(vec![0xabu8; 512 * 8])),
            "disk0",
        ))
    }

    /// A device state as a driver that finished bring-up would leave it.
    fn a_ready_queue_state() -> MmioTransportState {
        MmioTransportState {
            name: "blk0".into(),
            device_id: device_id::BLOCK,
            device_features: super::super::features::VERSION_1,
            driver_features: super::super::features::VERSION_1,
            device_features_sel: 1,
            driver_features_sel: 1,
            queue_sel: 0,
            interrupt_status: 0,
            device_status: 0xf,
            config_generation: 0,
            queues: vec![MmioQueueState {
                size: 64,
                desc: RING_DESC,
                driver: RING_AVAIL,
                device: RING_USED,
                ready: true,
            }],
            device_config: blk_config(8),
        }
    }

    fn restored_from(s: &MmioTransportState) -> (VirtioMmioDevice, Arc<GuestMemory>) {
        restored_from_with_used_idx(s, 0)
    }

    fn restored_from_with_used_idx(
        s: &MmioTransportState,
        used_idx: u16,
    ) -> (VirtioMmioDevice, Arc<GuestMemory>) {
        let mem = Arc::new(GuestMemory::new());
        mem.register_owned(0x4000_0000, 0x2_0000);
        mem.write_u16(RING_USED + 2, used_idx)
            .expect("seed used.idx");
        let d = VirtioMmioDevice::restored(a_backend(), mem.clone(), s);
        (d, mem)
    }
}
