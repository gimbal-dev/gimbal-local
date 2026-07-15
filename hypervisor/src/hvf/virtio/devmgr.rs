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

use super::block::{BlockBackend, BlockDevice, FileBackend, OverlayBackend};
use super::nat::{EgressPolicy, NatLimits, NatResponder};
use super::net::NetDevice;
use super::pathsafe;
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
    resume: bool,
    net_policy: Option<EgressPolicy>,
    net_limits: NatLimits,
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
            let (backend, _backing) =
                resolve_block_backend(overlay_dir, &desc.name, disk_path, *nsectors, resume)?;
            (
                Backend::Block(BlockDevice::new(backend, &desc.name)),
                blk_device_config(*nsectors),
            )
        }
        BackendKind::Rng => {
            let src = UrandomSource::open()
                .map_err(|e| DevMgrError::Io(format!("open /dev/urandom: {e}")))?;
            (Backend::Rng(RngDevice::new(Box::new(src))), Vec::new())
        }
        BackendKind::Net => {
            // The gateway the resumed guest talks to. Capture-side cloud-init
            // configures the guest as 192.168.249.2/24 with this gateway, so the
            // NAT owns .1 and terminates the guest's flows. The control-plane
            // egress profile (verified by `chm`, M28.1) is enforced here at the
            // DNS resolve + host connect the NAT mediates; absent a bound policy
            // the guest gets unrestricted egress (allow-all).
            let policy = net_policy.unwrap_or_else(EgressPolicy::allow_all);
            if policy.is_restrictive() {
                eprintln!(
                    "chm: virtio-net {} governed by egress policy {} (default-deny \
                     enforced at the NAT)",
                    desc.name,
                    policy.label()
                );
            }
            let responder = NatResponder::new([192, 168, 249, 1], [0x02, 0, 0, 0, 0, 1], policy, net_limits);
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

/// Which host backing a virtio-blk device resolved to. Surfaced so the wiring
/// (and its tests) can reason about whether a snapshot shipped its real disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockBacking {
    /// A real shipped disk, opened as an immutable base with guest writes
    /// redirected to a fresh per-run copy-on-write overlay.
    ShippedCow,
    /// No shipped disk: a sparse zero-filled overlay (unwritten reads return 0).
    ZeroOverlay,
}

/// Resolve the host-side block backend for a device.
///
/// Prefers a real disk image shipped alongside the snapshot at
/// `<snapshot>/disks/<device-name>.raw`. CH snapshots reference their disks by
/// host path and do not embed them, so a snapshot packaged WITH its disks lets
/// the guest read its real filesystem (and do post-resume I/O) rather than a
/// zero-filled overlay.
///
/// A shipped image is treated as an **immutable base**: writes go to a fresh
/// per-run copy-on-write overlay (see [`OverlayBackend`]). That keeps every
/// resume consistent with the snapshot's restored RAM, so rehydration is
/// repeatable and never drifts the base into the ext4 metadata-mismatch / EIO
/// failure mode. Absent a shipped image, fall back to a sparse zero overlay (the
/// data path still completes; reads of unwritten sectors return zero).
pub(crate) fn resolve_block_backend(
    overlay_dir: &std::path::Path,
    dev_name: &str,
    disk_path: &str,
    nsectors: u64,
    resume: bool,
) -> Result<(Box<dyn BlockBackend>, BlockBacking), DevMgrError> {
    match shipped_backing(overlay_dir, dev_name)? {
        Some(base) => {
            let overlay = overlay_dir.join(sanitize(&format!("{dev_name}-cow.raw")));
            // On resume, reattach the overlay from the prior run (so disk writes
            // made before the checkpoint survive); on cold boot, start fresh.
            let ob = if resume {
                OverlayBackend::resume(&base, &overlay, nsectors)
            } else {
                OverlayBackend::open(&base, &overlay, nsectors)
            }
            .map_err(|e| {
                DevMgrError::Io(format!(
                    "open COW base {} / overlay {}: {e}",
                    base.display(),
                    overlay.display()
                ))
            })?;
            Ok((Box::new(ob), BlockBacking::ShippedCow))
        }
        None => {
            let overlay =
                overlay_dir.join(sanitize(&format!("{dev_name}-{}", file_stem(disk_path))));
            ensure_overlay(&overlay, nsectors)?;
            let fb = FileBackend::open(&overlay, nsectors)
                .map_err(|e| DevMgrError::Io(format!("open backing {}: {e}", overlay.display())))?;
            Ok((Box::new(fb), BlockBacking::ZeroOverlay))
        }
    }
}

/// Resolve a real disk image shipped alongside the snapshot for `dev_name`.
///
/// `overlay_dir` is `<snapshot>/.chm-overlays`, so shipped disks live at
/// `<snapshot>/disks/<device-name>.raw` (the device name is the snapshot's own
/// node name, e.g. `_disk0`). Returns the path only when the file exists, so the
/// caller falls back to a sparse overlay for snapshots packaged without disks.
///
/// Security (M30.1): a candidate that exists but is a **symlink** is rejected
/// loudly rather than followed — a malicious bundle could otherwise ship
/// `disks/_disk0.raw -> /etc/passwd` and hand the guest a host file as its disk.
/// The enclosing `disks/` directory may itself be a symlink (the trusted
/// read-only base in the workspace model); only the disk *file* is constrained.
/// `dev_name` is sanitized, so the candidate cannot traverse out of `disks/`.
fn shipped_backing(
    overlay_dir: &std::path::Path,
    dev_name: &str,
) -> Result<Option<std::path::PathBuf>, DevMgrError> {
    let Some(disks) = overlay_dir.parent().map(|p| p.join("disks")) else {
        return Ok(None);
    };
    for ext in ["raw", "img"] {
        let cand = disks.join(format!("{}.{ext}", sanitize(dev_name)));
        match std::fs::symlink_metadata(&cand) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(DevMgrError::Io(format!(
                    "refusing shipped disk {}: it is a symlink (possible tampered bundle)",
                    cand.display()
                )));
            }
            Ok(md) if md.file_type().is_file() => return Ok(Some(cand)),
            _ => continue,
        }
    }
    Ok(None)
}

/// Create `path` as a sparse file of `nsectors * 512` bytes if it does not yet
/// exist (reads of unwritten regions return zeroes; writes persist).
///
/// Security (M30.1): rejects a pre-existing symlink and creates with
/// `O_NOFOLLOW`, so a bundle-planted overlay link cannot redirect the zero
/// overlay onto a host file.
fn ensure_overlay(path: &std::path::Path, nsectors: u64) -> Result<(), DevMgrError> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(DevMgrError::Io(format!(
                "refusing overlay {}: it is a symlink (possible tampered bundle)",
                path.display()
            )));
        }
        // Already a regular file: leave its sparse contents in place.
        Ok(_) => return Ok(()),
        Err(_) => {}
    }
    let file = pathsafe::open_rw_create_nofollow(path, false)
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

    /// Security invariant I1 (M30.5): no host-filesystem passthrough. A snapshot
    /// carrying a virtio-fs (type 26, PCI `0x105A`) or virtio-9p (type 9, PCI
    /// `0x1049`) device must classify as `Unsupported` — the device model only
    /// ever wires block/net/rng, never a host directory mount — so such a device
    /// is refused at build time rather than exposing the host filesystem. If a
    /// future change adds host-FS support it will break this test, forcing a
    /// deliberate security review (see also `scripts/security/`).
    #[test]
    fn host_fs_passthrough_device_types_are_unsupported() {
        // virtio-fs: PCI Device ID 0x105A -> virtio type 26.
        let fs = parse_devices(&one_device_tree("_fs0", 0x105A, serde_json::json!({})))
            .expect("parse virtio-fs");
        assert!(
            matches!(fs[0].backend, BackendKind::Unsupported { virtio_type: 26 }),
            "virtio-fs must be Unsupported (no host FS passthrough), got {:?}",
            fs[0].backend
        );
        // virtio-9p: PCI Device ID 0x1049 -> virtio type 9.
        let p9 = parse_devices(&one_device_tree("_9p0", 0x1049, serde_json::json!({})))
            .expect("parse virtio-9p");
        assert!(
            matches!(p9[0].backend, BackendKind::Unsupported { virtio_type: 9 }),
            "virtio-9p must be Unsupported (no host FS passthrough), got {:?}",
            p9[0].backend
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

    /// The disk-backing selection is the heart of the post-resume I/O fix: when a
    /// snapshot ships its real disk, the guest must read that disk's content
    /// through a copy-on-write overlay (so the base stays pristine and resumes
    /// stay repeatable); when no disk is shipped it falls back to a zero overlay.
    /// This guards both halves of that wiring so a future change cannot silently
    /// regress to the zero-overlay-only behaviour that caused ext4/EIO failures.
    #[test]
    fn resolve_block_backend_prefers_shipped_disk_as_cow() {
        use std::io::Write;

        let root = std::env::temp_dir().join(format!("chm-resolve-cow-{}", std::process::id()));
        let overlay_dir = root.join(".chm-overlays");
        let disks_dir = root.join("disks");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::create_dir_all(&disks_dir).unwrap();

        // Ship a 2-sector disk for `_disk0`: sector 0 = 0xC0, sector 1 = 0xC1.
        let sector = 512usize;
        let mut base = vec![0xC0u8; sector];
        base.extend(std::iter::repeat(0xC1u8).take(sector));
        let base_path = disks_dir.join("_disk0.raw");
        std::fs::File::create(&base_path).unwrap().write_all(&base).unwrap();
        let base_sha_before = std::fs::read(&base_path).unwrap();

        // Shipped path -> COW over the real disk.
        let (mut backend, kind) =
            resolve_block_backend(&overlay_dir, "_disk0", "/capture/guest.raw", 2, false).unwrap();
        assert_eq!(kind, BlockBacking::ShippedCow, "shipped disk must select COW");

        // Reads return the REAL disk content (a zero overlay would return 0x00 —
        // this is precisely the bug that produced ext4 checksum failures / EIO).
        let mut buf = [0u8; 512];
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xC0), "sector 0 reads the shipped disk");
        backend.read_at(512, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xC1), "sector 1 reads the shipped disk");

        // Writes are visible within the run but isolated to the overlay.
        backend.write_at(0, &[0x99u8; 512]).unwrap();
        backend.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x99), "write is visible to the guest");
        backend.flush().unwrap();
        drop(backend);
        assert_eq!(
            base_sha_before,
            std::fs::read(&base_path).unwrap(),
            "the shipped base image must never be mutated by guest writes"
        );

        // No shipped disk -> zero overlay fallback (unwritten reads return zero).
        let (mut zero, zkind) =
            resolve_block_backend(&overlay_dir, "_disk1", "/capture/seed.img", 2, false).unwrap();
        assert_eq!(zkind, BlockBacking::ZeroOverlay, "absent disk falls back to zero overlay");
        zero.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "zero-overlay reads return zero");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Security (M30.1): a shipped disk that is actually a symlink must be
    /// rejected, not followed — otherwise a malicious bundle shipping
    /// `disks/_disk0.raw -> /etc/passwd` would hand the guest a host file as its
    /// read-only disk base (host file disclosure).
    #[test]
    fn resolve_block_backend_rejects_symlinked_shipped_disk() {
        use std::io::Write;
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("chm-resolve-symlink-{}", std::process::id()));
        let overlay_dir = root.join(".chm-overlays");
        let disks_dir = root.join("disks");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::create_dir_all(&disks_dir).unwrap();

        // A host "secret" the malicious bundle wants the guest to read as a disk.
        let secret = root.join("host-secret.txt");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"TOP SECRET HOST DATA")
            .unwrap();
        // The bundle ships disks/_disk0.raw as a symlink to that host file.
        symlink(&secret, disks_dir.join("_disk0.raw")).unwrap();

        let err = match resolve_block_backend(&overlay_dir, "_disk0", "/capture/guest.raw", 2, false)
        {
            Ok(_) => panic!("a symlinked shipped disk must be rejected, not followed"),
            Err(e) => e,
        };
        assert!(
            format!("{err:?}").contains("symlink"),
            "error should name the symlink rejection: {err:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Security (M30.1): a pre-planted overlay symlink must be rejected, so guest
    /// disk writes cannot be redirected (via O_NOFOLLOW) onto a host file.
    #[test]
    fn resolve_block_backend_rejects_symlinked_overlay() {
        use std::io::Write;
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("chm-resolve-ovl-symlink-{}", std::process::id()));
        let overlay_dir = root.join(".chm-overlays");
        let disks_dir = root.join("disks");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::create_dir_all(&disks_dir).unwrap();

        // A legit shipped base disk (so we reach the COW overlay open).
        std::fs::File::create(disks_dir.join("_disk0.raw"))
            .unwrap()
            .write_all(&[0u8; 1024])
            .unwrap();
        // A host file the guest's writes must NOT be redirected onto.
        let victim = root.join("host-victim.txt");
        std::fs::File::create(&victim)
            .unwrap()
            .write_all(b"do not overwrite")
            .unwrap();
        // Pre-plant the per-run overlay as a symlink to the victim.
        symlink(&victim, overlay_dir.join("_disk0-cow.raw")).unwrap();

        assert!(
            resolve_block_backend(&overlay_dir, "_disk0", "/capture/guest.raw", 2, false).is_err(),
            "a symlinked overlay must be rejected"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"do not overwrite",
            "the host victim file must be untouched"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
