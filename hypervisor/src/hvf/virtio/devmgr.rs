//! Reconstruct the native virtio-pci device model from a cloud-hypervisor
//! snapshot's `device-manager` state.
//!
//! Each virtio device a captured guest used appears twice in the snapshot tree:
//! a transport node `_virtio-pci-<name>` (PCI configuration, MSI-X table, the
//! `virtio_pci_common_config`, and the per-queue ring addresses) and a backing
//! node `<name>` (the device-type state — disk path / sectors / negotiated
//! features for block, etc.). This module joins the two into a
//! [`VirtioDeviceDesc`] and builds a live [`VirtioPciDevice`] from it, restoring
//! the queues exactly where the guest left them (no re-negotiation).

use std::sync::Arc;

use serde_json::Value;

use super::block::{BlockDevice, FileBackend};
use super::pci::{Backend, RestoreParams, VirtioPciDevice, CAPABILITY_BAR_SIZE};
use super::queue::Queue;
use super::rng::{RngDevice, UrandomSource};
use super::GuestMemory;

/// Failure reconstructing the device model from snapshot state.
#[derive(Debug)]
pub enum DevMgrError {
    /// The snapshot JSON did not have the expected shape.
    Malformed(String),
    /// A host-side overlay/backing file could not be created or opened.
    Io(String),
}

impl std::fmt::Display for DevMgrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "device-manager state malformed: {m}"),
            Self::Io(m) => write!(f, "device backing I/O error: {m}"),
        }
    }
}

impl std::error::Error for DevMgrError {}

/// One restored virtqueue's addresses and size.
#[derive(Debug, Clone)]
pub struct QueueState {
    /// Ring size in descriptors.
    pub size: u16,
    /// Descriptor table GPA.
    pub desc: u64,
    /// Available ring GPA.
    pub avail: u64,
    /// Used ring GPA.
    pub used: u64,
}

/// The backend a restored virtio-pci device drives.
#[derive(Debug, Clone)]
pub enum BackendKind {
    /// virtio-blk: a disk image (by file name) with `nsectors` capacity.
    Block {
        /// File name of the disk image as recorded in the snapshot.
        disk_path: String,
        /// Capacity in 512-byte sectors.
        nsectors: u64,
    },
    /// virtio-rng entropy source.
    Rng,
}

/// A fully-parsed virtio-pci device ready to be turned into a live device.
#[derive(Debug, Clone)]
pub struct VirtioDeviceDesc {
    /// Device name (e.g. `_disk0`).
    pub name: String,
    /// Restored BAR0 base (where the device's MMIO window lives).
    pub bar_base: u64,
    /// Negotiated (`acked`) feature bits.
    pub features: u64,
    /// Restored queues.
    pub queues: Vec<QueueState>,
    /// Per-queue MSI-X vector.
    pub queue_vectors: Vec<u16>,
    /// Restored `device_status` (expected to include DRIVER_OK = 0x4).
    pub device_status: u8,
    /// The backend to attach.
    pub backend: BackendKind,
}

fn malformed(m: impl Into<String>) -> DevMgrError {
    DevMgrError::Malformed(m.into())
}

/// Parse the embedded `snapshot_data.state` JSON string at `node`.
fn embedded(node: &Value) -> Result<Value, DevMgrError> {
    let s = node
        .get("snapshot_data")
        .and_then(|d| d.get("state"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| malformed("node has no snapshot_data.state string"))?;
    serde_json::from_str(s).map_err(|e| malformed(format!("state is not valid JSON: {e}")))
}

fn u64_at(v: &Value, key: &str) -> Result<u64, DevMgrError> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(format!("missing u64 `{key}`")))
}

/// Parse every `_virtio-pci-*` device in a `state.json` into descriptors.
pub fn parse_devices(state_json: &str) -> Result<Vec<VirtioDeviceDesc>, DevMgrError> {
    let root: Value =
        serde_json::from_str(state_json).map_err(|e| malformed(format!("invalid state.json: {e}")))?;
    let dm = root
        .get("snapshots")
        .and_then(|s| s.get("device-manager"))
        .and_then(|d| d.get("snapshots"))
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("missing device-manager snapshots"))?;

    let mut out = Vec::new();
    for (key, node) in dm {
        let Some(backing_name) = key.strip_prefix("_virtio-pci-") else {
            continue;
        };
        let backing = dm
            .get(backing_name)
            .ok_or_else(|| malformed(format!("transport `{key}` has no backing `{backing_name}`")))?;
        out.push(parse_one(backing_name, node, backing)?);
    }
    // Stable order (BAR address) so wiring is deterministic.
    out.sort_by_key(|d| d.bar_base);
    Ok(out)
}

fn parse_one(
    name: &str,
    transport: &Value,
    backing: &Value,
) -> Result<VirtioDeviceDesc, DevMgrError> {
    // Transport top-level state: the queue ring addresses.
    let tstate = embedded(transport)?;
    let queues_json = tstate
        .get("queues")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("transport has no queues"))?;
    let mut queues = Vec::with_capacity(queues_json.len());
    for q in queues_json {
        queues.push(QueueState {
            size: u64_at(q, "size")? as u16,
            desc: u64_at(q, "desc_table")?,
            avail: u64_at(q, "avail_ring")?,
            used: u64_at(q, "used_ring")?,
        });
    }

    // Transport sub-snapshots: PCI config (BAR), common config (status/vectors),
    // MSI-X (vectors, fallback).
    let subs = transport
        .get("snapshots")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("transport has no sub-snapshots"))?;

    let pci = subs
        .get("pci_configuration")
        .ok_or_else(|| malformed("missing pci_configuration"))?;
    let pci_state = embedded(pci)?;
    let registers = pci_state
        .get("registers")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("pci_configuration has no registers"))?;
    // BAR0 is config register index 4. Decode 32-bit vs 64-bit memory BARs:
    // bits[2:1]==0b10 (mask 0x6 == 0x4) means the BAR is 64-bit and the next
    // register holds the high 32 bits (e.g. virtio-rng at 0x2_0000_0000).
    let bar0 = registers
        .get(4)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("missing BAR0 register"))?;
    let bar_base = if bar0 & 0x6 == 0x4 {
        let high = registers.get(5).and_then(Value::as_u64).unwrap_or(0);
        (high << 32) | (bar0 & !0xfu64)
    } else {
        bar0 & !0xfu64
    };

    let common = subs
        .get("virtio_pci_common_config")
        .ok_or_else(|| malformed("missing virtio_pci_common_config"))?;
    let common_state = embedded(common)?;
    let device_status = u64_at(&common_state, "driver_status")? as u8;
    let queue_vectors: Vec<u16> = common_state
        .get("msix_queues")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).map(|v| v as u16).collect())
        .unwrap_or_default();

    // Backing device state: features + device type.
    let bstate = embedded(backing)?;
    let features = u64_at(&bstate, "acked_features")
        .or_else(|_| u64_at(&bstate, "avail_features"))
        .unwrap_or(0);

    let backend = if let Ok(nsectors) = u64_at(&bstate, "disk_nsectors") {
        let disk_path = bstate
            .get("disk_path")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string();
        BackendKind::Block {
            disk_path,
            nsectors,
        }
    } else {
        // virtio-rng (or any non-block device) gets the entropy backend.
        BackendKind::Rng
    };

    Ok(VirtioDeviceDesc {
        name: name.to_string(),
        bar_base,
        features,
        queues,
        queue_vectors,
        device_status,
        backend,
    })
}

/// Build the device-config bytes a virtio-blk guest may re-read post-resume.
///
/// Only the capacity (sectors, at offset 0) is load-bearing; the rest is zeroed.
fn blk_device_config(nsectors: u64) -> Vec<u8> {
    let mut cfg = vec![0u8; 0x60];
    cfg[..8].copy_from_slice(&nsectors.to_le_bytes());
    // blk_size lives at offset 20 in virtio_blk_config.
    cfg[20..24].copy_from_slice(&512u32.to_le_bytes());
    cfg
}

/// Turn a [`QueueState`] into a restored [`Queue`], seeding the cursors from the
/// used-ring index (the queue was drained at snapshot quiesce).
fn restore_queue(qs: &QueueState, features: u64, mem: &GuestMemory) -> Queue {
    let mut q = Queue {
        size: qs.size,
        desc: qs.desc,
        avail: qs.avail,
        used: qs.used,
        event_idx: features & super::features::RING_EVENT_IDX != 0,
        indirect: features & super::features::RING_INDIRECT_DESC != 0,
        next_avail: 0,
        next_used: 0,
    };
    // Best-effort: seed next_avail/next_used from the live used.idx.
    let _ = q.restore(mem);
    q
}

/// Build a live [`VirtioPciDevice`] for `desc`, creating a host-backed sparse
/// overlay (in `overlay_dir`) for block devices whose real image is absent.
///
/// Returns the BAR base + size for bus registration alongside the device.
pub fn build_device(
    desc: &VirtioDeviceDesc,
    mem: Arc<GuestMemory>,
    overlay_dir: &std::path::Path,
) -> Result<(u64, u64, Arc<VirtioPciDevice>), DevMgrError> {
    let queues = desc
        .queues
        .iter()
        .map(|qs| restore_queue(qs, desc.features, &mem))
        .collect::<Vec<_>>();

    let (backend, device_config) = match &desc.backend {
        BackendKind::Block {
            disk_path,
            nsectors,
        } => {
            let overlay = overlay_dir.join(sanitize(&format!("{}-{}", desc.name, file_stem(disk_path))));
            ensure_overlay(&overlay, *nsectors)?;
            let fb = FileBackend::open(&overlay, *nsectors)
                .map_err(|e| DevMgrError::Io(format!("open overlay {}: {e}", overlay.display())))?;
            (
                Backend::Block(BlockDevice::new(Box::new(fb), &desc.name)),
                blk_device_config(*nsectors),
            )
        }
        BackendKind::Rng => {
            let src = UrandomSource::open()
                .map_err(|e| DevMgrError::Io(format!("open /dev/urandom: {e}")))?;
            (Backend::Rng(RngDevice::new(Box::new(src))), Vec::new())
        }
    };

    let dev = Arc::new(VirtioPciDevice::new(
        desc.name.clone(),
        backend,
        mem,
        RestoreParams {
            features: desc.features,
            queues,
            queue_vectors: desc.queue_vectors.clone(),
            device_status: desc.device_status,
            device_config,
        },
    ));
    Ok((desc.bar_base, CAPABILITY_BAR_SIZE, dev))
}

/// Create `path` as a sparse file of `nsectors * 512` bytes if it does not yet
/// exist (reads of unwritten regions return zeroes; writes persist).
fn ensure_overlay(path: &std::path::Path, nsectors: u64) -> Result<(), DevMgrError> {
    if path.exists() {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| DevMgrError::Io(format!("create {}: {e}", path.display())))?;
    file.set_len(nsectors.saturating_mul(512))
        .map_err(|e| DevMgrError::Io(format!("size {}: {e}", path.display())))?;
    Ok(())
}

fn file_stem(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(p)
        .to_string()
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../tests/data/devmgr_fixture.json");

    #[test]
    fn parses_block_and_rng_devices() {
        let devs = parse_devices(FIXTURE).expect("parse");
        assert_eq!(devs.len(), 2, "one blk + one rng device");

        let blk = devs.iter().find(|d| matches!(d.backend, BackendKind::Block { .. })).unwrap();
        assert_eq!(blk.bar_base, 0x1008_0000);
        assert!(super::super::pci::driver_ok(blk.device_status));
        assert_eq!(blk.queues.len(), 1);
        assert_eq!(blk.queues[0].size, 128);
        assert_eq!(blk.queues[0].desc, 1142239232);
        assert_eq!(blk.queue_vectors, vec![1]);
        // EVENT_IDX + VERSION_1 negotiated.
        assert!(blk.features & super::super::features::RING_EVENT_IDX != 0);
        assert!(blk.features & super::super::features::VERSION_1 != 0);
        if let BackendKind::Block { nsectors, .. } = &blk.backend {
            assert_eq!(*nsectors, 16777216);
        }

        assert!(devs.iter().any(|d| matches!(d.backend, BackendKind::Rng)));
        // virtio-rng uses a 64-bit BAR at 0x2_0000_0000 (BAR0=0x4, BAR1=0x2).
        let rng = devs.iter().find(|d| matches!(d.backend, BackendKind::Rng)).unwrap();
        assert_eq!(rng.bar_base, 0x2_0000_0000);
    }
}
