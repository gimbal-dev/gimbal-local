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
use super::net::{EchoResponder, NetDevice};
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
    /// A device type this build does not model (rather than silently
    /// mismodeling it).
    Unsupported(String),
}

impl std::fmt::Display for DevMgrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "device-manager state malformed: {m}"),
            Self::Io(m) => write!(f, "device backing I/O error: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported device: {m}"),
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
///
/// The variant is chosen authoritatively from the device's PCI Device ID
/// (`0x1040 + virtio_device_type`), not from heuristics on the backing state,
/// so a device is modeled as exactly what the guest negotiated it to be. An
/// unrecognised type becomes [`BackendKind::Unsupported`] and is rejected at
/// build time rather than silently mismodeled.
#[derive(Debug, Clone)]
pub enum BackendKind {
    /// virtio-blk (type 2): a disk image (by file name) with `nsectors`.
    Block {
        /// File name of the disk image as recorded in the snapshot.
        disk_path: String,
        /// Capacity in 512-byte sectors.
        nsectors: u64,
    },
    /// virtio-net (type 1).
    Net,
    /// virtio-rng (type 4) entropy source.
    Rng,
    /// A virtio device whose type this build does not model. Carries the raw
    /// virtio device type so the rejection message can name it.
    Unsupported {
        /// The virtio device type (PCI Device ID minus `0x1040`).
        virtio_type: u32,
    },
}

/// virtio device type for virtio-net (PCI Device ID `0x1041`).
pub const VIRTIO_TYPE_NET: u32 = 1;
/// virtio device type for virtio-block (PCI Device ID `0x1042`).
pub const VIRTIO_TYPE_BLOCK: u32 = 2;
/// virtio device type for virtio-rng (PCI Device ID `0x1044`).
pub const VIRTIO_TYPE_RNG: u32 = 4;
/// Modern virtio-pci PCI Device IDs are `0x1040 + virtio_device_type`.
const VIRTIO_PCI_DEVICE_ID_BASE: u32 = 0x1040;

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
    /// ITS `DeviceID` (the PCI requester id derived from this device's BDF).
    pub device_id: u32,
    /// MSI-X `msg_data` (the ITS `EventID`) for each table vector, indexed by
    /// vector number.
    pub vector_events: Vec<u32>,
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
    // The device tree (in the device-manager's own state) records each
    // transport's PCI BDF, which is the ITS DeviceID source.
    let bdf_map = parse_bdf_map(&root);
    for (key, node) in dm {
        let Some(backing_name) = key.strip_prefix("_virtio-pci-") else {
            continue;
        };
        let backing = dm
            .get(backing_name)
            .ok_or_else(|| malformed(format!("transport `{key}` has no backing `{backing_name}`")))?;
        let mut desc = parse_one(backing_name, node, backing)?;
        desc.device_id = bdf_map
            .get(key.as_str())
            .copied()
            .flatten()
            .unwrap_or(0);
        out.push(desc);
    }
    // Stable order (BAR address) so wiring is deterministic.
    out.sort_by_key(|d| d.bar_base);
    Ok(out)
}

/// The captured PL011 line/interrupt configuration that a resumed guest's
/// driver believes the hardware still holds (it programmed these before the
/// snapshot and does NOT re-issue them after resume). Restoring them into our
/// fresh [`crate::hvf::devices::Pl011`] is what lets a host keystroke raise the
/// guest's receive interrupt: `int_enabled` (UARTIMSC) carries RXIM, without
/// which an interrupt-driven `agetty` never reads typed input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SerialRegs {
    /// UARTIMSC interrupt mask (cloud-hypervisor `int_enabled`).
    pub imsc: u32,
    /// UARTCR control register.
    pub cr: u32,
    /// UARTLCR_H line control (cloud-hypervisor `lcr`).
    pub lcr_h: u32,
    /// Integer baud divisor.
    pub ibrd: u32,
    /// Fractional baud divisor.
    pub fbrd: u32,
    /// UARTIFLS FIFO level select (cloud-hypervisor `ifl`).
    pub ifls: u32,
}

/// Parse the `__serial` device node's captured PL011 register state, if present.
///
/// cloud-hypervisor serializes the UART under
/// `snapshots/device-manager/snapshots/__serial` as a JSON string with the
/// PrimeCell register fields. Returns `None` when the node is absent or
/// malformed (a guest that polls its UART still works without this).
pub fn parse_serial_state(state_json: &str) -> Option<SerialRegs> {
    let root: Value = serde_json::from_str(state_json).ok()?;
    let node = root.pointer("/snapshots/device-manager/snapshots/__serial")?;
    let st = embedded(node).ok()?;
    let u32_at = |k: &str| st.get(k).and_then(Value::as_u64).map(|v| v as u32);
    Some(SerialRegs {
        imsc: u32_at("int_enabled").unwrap_or(0),
        cr: u32_at("cr").unwrap_or(0),
        lcr_h: u32_at("lcr").unwrap_or(0),
        ibrd: u32_at("ibrd").unwrap_or(0),
        fbrd: u32_at("fbrd").unwrap_or(0),
        ifls: u32_at("ifl").unwrap_or(0),
    })
}

/// Parse the device-manager `device_tree` into a map of transport id -> ITS
/// `DeviceID` (decoded from the recorded `pci_bdf`, `None` for non-PCI nodes).
fn parse_bdf_map(root: &Value) -> std::collections::HashMap<String, Option<u32>> {
    let mut map = std::collections::HashMap::new();
    let dm_state = root
        .pointer("/snapshots/device-manager/snapshot_data/state")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    if let Some(tree) = dm_state
        .as_ref()
        .and_then(|v| v.get("device_tree"))
        .and_then(Value::as_object)
    {
        for (id, node) in tree {
            let dev_id = node
                .get("pci_bdf")
                .and_then(Value::as_str)
                .and_then(bdf_to_device_id);
            map.insert(id.clone(), dev_id);
        }
    }
    map
}

/// Decode a `"DDDD:BB:DD.F"` PCI BDF string into the ITS `DeviceID` (requester
/// id): `(bus << 8) | (device << 3) | function`.
fn bdf_to_device_id(bdf: &str) -> Option<u32> {
    // segment:bus:device.function
    let (head, func) = bdf.rsplit_once('.')?;
    let mut parts = head.split(':');
    let _segment = parts.next()?;
    let bus = u32::from_str_radix(parts.next()?, 16).ok()?;
    let device = u32::from_str_radix(parts.next()?, 16).ok()?;
    let func: u32 = func.parse().ok()?;
    Some((bus << 8) | (device << 3) | (func & 0x7))
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

    // PCI config register 0 is [vendor:device]. A modern virtio-pci function
    // encodes its virtio device type in the Device ID as 0x1040 + type, which
    // is the authoritative classifier (block=0x1042, net=0x1041, rng=0x1044).
    let reg0 = registers
        .first()
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("missing PCI Device/Vendor ID register"))?;
    let pci_device_id = ((reg0 >> 16) & 0xffff) as u32;
    let virtio_type = pci_device_id.saturating_sub(VIRTIO_PCI_DEVICE_ID_BASE);

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

    // MSI-X table: each vector's `msg_data` is the ITS EventID the device emits.
    let vector_events: Vec<u32> = subs
        .get("msix_config")
        .and_then(|m| embedded(m).ok())
        .and_then(|m| {
            m.get("table_entries").and_then(Value::as_array).map(|a| {
                a.iter()
                    .map(|e| e.get("msg_data").and_then(Value::as_u64).unwrap_or(0) as u32)
                    .collect()
            })
        })
        .unwrap_or_default();

    // Backing device state: features + device type.
    let bstate = embedded(backing)?;
    let features = u64_at(&bstate, "acked_features")
        .or_else(|_| u64_at(&bstate, "avail_features"))
        .unwrap_or(0);

    let backend = match virtio_type {
        VIRTIO_TYPE_BLOCK => {
            let nsectors = u64_at(&bstate, "disk_nsectors")?;
            let disk_path = bstate
                .get("disk_path")
                .and_then(Value::as_str)
                .unwrap_or(name)
                .to_string();
            BackendKind::Block {
                disk_path,
                nsectors,
            }
        }
        VIRTIO_TYPE_NET => BackendKind::Net,
        VIRTIO_TYPE_RNG => BackendKind::Rng,
        other => BackendKind::Unsupported { virtio_type: other },
    };

    Ok(VirtioDeviceDesc {
        name: name.to_string(),
        bar_base,
        features,
        queues,
        queue_vectors,
        device_id: 0,
        vector_events,
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
            // Prefer a real disk image shipped alongside the snapshot at
            // `<snapshot>/disks/<device-name>.raw`. CH snapshots reference their
            // disks by host path and do not embed them, so a snapshot packaged
            // WITH its disks lets the guest read its real filesystem (and boot
            // for real) rather than the zero-filled overlay. The shipped image
            // is opened read-write directly (it is a per-snapshot copy, so guest
            // writes are local and do not touch the capture source). Absent a
            // shipped image, fall back to the sparse zero overlay (the data path
            // still completes; reads of unwritten sectors return zero).
            let backing = match shipped_backing(overlay_dir, &desc.name) {
                Some(real) => real,
                None => {
                    let overlay = overlay_dir.join(sanitize(&format!(
                        "{}-{}",
                        desc.name,
                        file_stem(disk_path)
                    )));
                    ensure_overlay(&overlay, *nsectors)?;
                    overlay
                }
            };
            let fb = FileBackend::open(&backing, *nsectors)
                .map_err(|e| DevMgrError::Io(format!("open backing {}: {e}", backing.display())))?;
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
        BackendKind::Net => {
            // The gateway the resumed guest talks to. The capture-side
            // cloud-init configures the guest as 192.168.249.2/24 with this
            // gateway, so the host responder owns .1 and answers the guest's
            // ARP + ICMP echo over the deliverable message-based-SPI path.
            let responder = EchoResponder::new([192, 168, 249, 1], [0x02, 0, 0, 0, 0, 1]);
            (Backend::Net(NetDevice::new(Box::new(responder))), Vec::new())
        }
        BackendKind::Unsupported { virtio_type } => {
            return Err(DevMgrError::Unsupported(format!(
                "device `{}` is virtio type {virtio_type} (PCI Device ID \
                 {:#06x}), which this build does not model; refusing to \
                 mismodel it",
                desc.name,
                0x1040 + virtio_type
            )));
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

/// Resolve a real disk image shipped alongside the snapshot for `dev_name`.
///
/// `overlay_dir` is `<snapshot>/.chm-overlays`, so shipped disks live at
/// `<snapshot>/disks/<device-name>.raw` (the device name is the snapshot's own
/// node name, e.g. `_disk0`). Returns the path only when the file exists, so the
/// caller falls back to a sparse overlay for snapshots packaged without disks.
fn shipped_backing(overlay_dir: &std::path::Path, dev_name: &str) -> Option<std::path::PathBuf> {
    let disks = overlay_dir.parent()?.join("disks");
    for ext in ["raw", "img"] {
        let cand = disks.join(format!("{}.{ext}", sanitize(dev_name)));
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
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

    /// Build a minimal one-device `device-manager` tree whose virtio-pci
    /// function advertises `pci_device_id`, so classification can be exercised
    /// without a full captured snapshot. `extra_backing` is merged into the
    /// backing device state (e.g. `disk_nsectors` for a block device).
    fn one_device_tree(name: &str, pci_device_id: u32, extra_backing: serde_json::Value) -> String {
        let s = |v: &serde_json::Value| serde_json::to_string(v).unwrap();
        let transport = serde_json::json!({
            "snapshot_data": { "state": s(&serde_json::json!({
                "queues": [{
                    "size": 64, "desc_table": 0x1000,
                    "avail_ring": 0x2000, "used_ring": 0x3000
                }]
            })) },
            "snapshots": {
                "pci_configuration": { "snapshot_data": { "state": s(&serde_json::json!({
                    "registers": [
                        0x1af4 | (pci_device_id << 16),
                        0, 0, 0,
                        0x1000_0000u64, 0
                    ]
                })) } },
                "virtio_pci_common_config": { "snapshot_data": { "state": s(&serde_json::json!({
                    "driver_status": 4, "msix_queues": [1]
                })) } }
            }
        });
        let mut backing_state = serde_json::json!({
            "avail_features": 0, "acked_features": 0
        });
        if let serde_json::Value::Object(extra) = extra_backing {
            for (k, v) in extra {
                backing_state[k] = v;
            }
        }
        let backing = serde_json::json!({
            "snapshot_data": { "state": s(&backing_state) }
        });
        let root = serde_json::json!({
            "snapshots": { "device-manager": { "snapshots": {
                name: backing,
                format!("_virtio-pci-{name}"): transport
            } } }
        });
        serde_json::to_string(&root).unwrap()
    }

    #[test]
    fn classifies_devices_by_pci_device_id() {
        // virtio-net (0x1041) -> Net.
        let net = parse_devices(&one_device_tree("_net0", 0x1041, serde_json::json!({})))
            .expect("parse net");
        assert!(matches!(net[0].backend, BackendKind::Net), "0x1041 -> Net");

        // virtio-block (0x1042) -> Block, reading nsectors from backing state.
        let blk = parse_devices(&one_device_tree(
            "_disk0",
            0x1042,
            serde_json::json!({ "disk_nsectors": 2048, "disk_path": "/x.raw" }),
        ))
        .expect("parse block");
        match &blk[0].backend {
            BackendKind::Block { nsectors, disk_path } => {
                assert_eq!(*nsectors, 2048);
                assert_eq!(disk_path, "/x.raw");
            }
            other => panic!("0x1042 should be Block, got {other:?}"),
        }

        // virtio-rng (0x1044) -> Rng.
        let rng = parse_devices(&one_device_tree("_rng0", 0x1044, serde_json::json!({})))
            .expect("parse rng");
        assert!(matches!(rng[0].backend, BackendKind::Rng), "0x1044 -> Rng");

        // An unknown type (here 0x1050 -> type 0x10) is flagged Unsupported,
        // NOT silently mismodeled as rng.
        let unk = parse_devices(&one_device_tree("_mystery", 0x1050, serde_json::json!({})))
            .expect("parse unknown");
        assert!(
            matches!(unk[0].backend, BackendKind::Unsupported { virtio_type: 0x10 }),
            "unknown type -> Unsupported, got {:?}",
            unk[0].backend
        );
    }

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
        // ITS DeviceID from BDF 0000:00:01.0 -> (1<<3) = 0x8; MSI-X EventIDs are
        // the msg_data of each vector (config vec 0 -> event 0, queue vec 1 -> 1).
        assert_eq!(blk.device_id, 0x8);
        assert_eq!(blk.vector_events, vec![0, 1]);
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
        // BDF 0000:00:03.0 -> (3<<3) = 0x18.
        assert_eq!(rng.device_id, 0x18);
    }

    #[test]
    fn parses_serial_register_state() {
        // A minimal device-manager tree carrying just the `__serial` node, with
        // the PL011 register fields cloud-hypervisor serializes (the embedded
        // `state` is itself a JSON string). int_enabled = 0x50 = RXIM|RTIM.
        let json = r#"{"snapshots":{"device-manager":{"snapshots":{"__serial":{"snapshots":{},"snapshot_data":{"state":"{\"flags\":144,\"lcr\":112,\"cr\":3841,\"int_enabled\":80,\"ibrd\":39,\"fbrd\":4,\"ifl\":18}"}}}}}}"#;
        let regs = parse_serial_state(json).expect("serial state");
        assert_eq!(regs.imsc, 0x50, "RXIM|RTIM recovered from int_enabled");
        assert_eq!(regs.cr, 3841);
        assert_eq!(regs.lcr_h, 112);
        assert_eq!(regs.ibrd, 39);
        assert_eq!(regs.fbrd, 4);
        assert_eq!(regs.ifls, 18);

        // Absent node -> None (a polling guest still works without it).
        assert!(parse_serial_state(r#"{"snapshots":{}}"#).is_none());
    }
}
