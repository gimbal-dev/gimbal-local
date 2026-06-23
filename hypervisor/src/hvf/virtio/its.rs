//! User-space GICv3 ITS (Interrupt Translation Service) model for rehydration.
//!
//! A cloud KVM guest routes its virtio (MSI-X) completions as **LPIs through a
//! GIC ITS**: the device writes its `EventID` to the ITS doorbell
//! (`GITS_TRANSLATER`) and the ITS hardware, capturing the device's PCI
//! requester id as the `DeviceID`, walks its in-memory tables to resolve the
//! pair into a physical LPI `INTID` and a target redistributor (via a
//! collection). Apple's managed GIC (`hv_gic`) has **no ITS** — it only offers
//! message-based SPIs — so a faithfully rehydrated ITS-wired guest needs the
//! translation performed in user space. This module is that translator.
//!
//! It consumes the KVM `gic-v3-its` save state the snapshot already carries
//! (`GITS_BASER[]`, `GITS_CBASER`, `GITS_CWRITER/CREADR`, `GITS_CTLR`) and walks
//! the device/collection tables and per-device Interrupt Translation Tables
//! (ITTs) that KVM flushed into guest RAM on `KVM_DEV_ARM_ITS_SAVE_TABLES`. The
//! in-memory layout follows KVM's table ABI (see
//! `virt/kvm/arm/vgic/vgic-its.c`):
//!
//! * Device Table Entry (8 bytes): `valid[63] | itt_addr[48:5] (>>8) | size[4:0]`
//!   where `size = num_eventid_bits - 1`. An indirect device table adds an L1
//!   level whose entries are `valid[63] | l2_table_addr[51:16]`.
//! * Interrupt Translation Entry (8 bytes): `next[63:48] | pINTID[47:16] | icid[15:0]`.
//! * Collection Table Entry (8 bytes): `valid[63] | rdbase[50:16] | icid[15:0]`.
//!
//! The same table formats are emitted by the ITS command queue
//! (`MAPD`/`MAPC`/`MAPTI`/...), so [`Its::replay_commands`] can reconstruct the
//! mappings straight from the captured command queue as an independent
//! cross-check of the table walk.

use serde_json::Value;

use super::GuestMemory;

/// First INTID in the GICv3 LPI range; anything below is not an LPI.
pub const GICV3_LPI_INTID_BASE: u32 = 8192;

/// Size in bytes of a KVM ITS in-memory translation entry (ITE).
const ITE_SIZE: u64 = 8;

/// Failure parsing ITS state or walking its tables.
#[derive(Debug)]
pub enum ItsError {
    /// The captured ITS state JSON did not have the expected shape.
    Malformed(String),
    /// A guest-memory table access went out of range.
    Memory(String),
}

impl std::fmt::Display for ItsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "ITS state malformed: {m}"),
            Self::Memory(m) => write!(f, "ITS table memory error: {m}"),
        }
    }
}

impl std::error::Error for ItsError {}

/// A resolved physical LPI: the `INTID` the guest's handler expects, plus the
/// redistributor (collection target) the completion routes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lpi {
    /// LPI interrupt id (`>= GICV3_LPI_INTID_BASE`).
    pub intid: u32,
    /// Target redistributor / processor number for the owning collection.
    pub rdbase: u32,
}

/// One decoded `GITS_BASER` table descriptor.
#[derive(Debug, Clone, Copy)]
struct Baser {
    indirect: bool,
    /// Table type: 1 = Devices, 4 = Collections.
    typ: u8,
    entry_size: u64,
    page_size: u64,
    num_pages: u64,
    base: u64,
}

impl Baser {
    /// Decode a `GITS_BASER` register value, or `None` if the Valid bit is clear.
    fn parse(raw: u64) -> Option<Self> {
        if (raw >> 63) & 1 == 0 {
            return None;
        }
        let page_size = match raw & 0x3 {
            0 => 4096,
            1 => 16384,
            _ => 65536,
        };
        Some(Self {
            indirect: (raw >> 62) & 1 != 0,
            typ: ((raw >> 56) & 0x7) as u8,
            entry_size: ((raw >> 48) & 0xff) + 1,
            page_size,
            num_pages: (raw & 0xff) + 1,
            base: Self::decode_base(raw, page_size),
        })
    }

    /// Physical address of the table. For 4K/16K pages the address is
    /// `raw[47:12]`; for 64K pages bits `[51:48]` are carried in `raw[15:12]`.
    fn decode_base(raw: u64, page_size: u64) -> u64 {
        if page_size == 65536 {
            let lo = raw & 0x0000_ffff_ffff_0000;
            let hi = (raw & 0xf000) << 36;
            lo | hi
        } else {
            raw & 0x0000_ffff_ffff_f000
        }
    }

    /// Total number of entries spanned by the (flat) table.
    fn flat_entries(&self) -> u64 {
        self.num_pages * self.page_size / self.entry_size
    }
}

/// The captured ITS configuration: which tables live where, and the command
/// queue pointers.
#[derive(Debug, Clone)]
pub struct ItsConfig {
    /// `GITS_CTLR.Enabled`.
    pub enabled: bool,
    device_baser: Option<Baser>,
    collection_baser: Option<Baser>,
    /// Command-queue base GPA (`GITS_CBASER`).
    cmd_base: u64,
    /// Command-queue size in bytes (`(GITS_CBASER.Size + 1) * 4KiB`).
    cmd_size: u64,
    /// `GITS_CWRITER` byte offset.
    cwriter: u64,
    /// `GITS_CREADR` byte offset.
    creadr: u64,
}

impl ItsConfig {
    /// Parse the KVM ITS register object (the `"Kvm"` payload of the
    /// `gic-v3-its` snapshot node).
    pub fn parse_kvm(kvm: &Value) -> Result<Self, ItsError> {
        let u = |key: &str| -> Result<u64, ItsError> {
            kvm.get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| ItsError::Malformed(format!("missing/!u64 `{key}`")))
        };

        let ctlr = u("its_ctlr")?;
        let basers = kvm
            .get("its_baser")
            .and_then(Value::as_array)
            .ok_or_else(|| ItsError::Malformed("missing `its_baser` array".into()))?;

        let mut device_baser = None;
        let mut collection_baser = None;
        for raw in basers.iter().filter_map(Value::as_u64) {
            if let Some(b) = Baser::parse(raw) {
                match b.typ {
                    1 => device_baser = Some(b),
                    4 => collection_baser = Some(b),
                    _ => {}
                }
            }
        }

        let cbaser = u("its_cbaser")?;
        let cmd_base = cbaser & 0x0000_ffff_ffff_f000;
        let cmd_size = ((cbaser & 0xff) + 1) * 4096;

        Ok(Self {
            enabled: ctlr & 1 != 0,
            device_baser,
            collection_baser,
            cmd_base,
            cmd_size,
            cwriter: u("its_cwriter")?,
            creadr: u("its_creadr")?,
        })
    }

    /// Navigate a full snapshot `state.json` string to the `gic-v3-its` node and
    /// parse its KVM register state.
    pub fn from_snapshot_state(state_json: &str) -> Result<Self, ItsError> {
        let root: Value = serde_json::from_str(state_json)
            .map_err(|e| ItsError::Malformed(format!("state.json parse: {e}")))?;
        let node = root
            .pointer("/snapshots/device-manager/snapshots/gic-v3-its/snapshot_data/state")
            .and_then(Value::as_str)
            .ok_or_else(|| ItsError::Malformed("no gic-v3-its/snapshot_data/state".into()))?;
        let inner: Value = serde_json::from_str(node)
            .map_err(|e| ItsError::Malformed(format!("its state parse: {e}")))?;
        let kvm = inner
            .get("Kvm")
            .ok_or_else(|| ItsError::Malformed("its state is not a KVM ITS".into()))?;
        Self::parse_kvm(kvm)
    }
}

/// A device's resolved Interrupt Translation Table location.
#[derive(Debug, Clone, Copy)]
struct DeviceEntry {
    itt: u64,
    eventid_bits: u32,
}

/// User-space ITS translator built from captured snapshot state.
#[derive(Debug, Clone)]
pub struct Its {
    config: ItsConfig,
}

impl Its {
    /// Build a translator from a parsed [`ItsConfig`].
    pub fn new(config: ItsConfig) -> Self {
        Self { config }
    }

    /// Convenience: build directly from a snapshot `state.json` string.
    pub fn from_snapshot_state(state_json: &str) -> Result<Self, ItsError> {
        Ok(Self::new(ItsConfig::from_snapshot_state(state_json)?))
    }

    /// Whether the captured ITS was enabled (`GITS_CTLR.Enabled`).
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    fn read_u64(mem: &GuestMemory, gpa: u64) -> Result<u64, ItsError> {
        mem.read_u64(gpa)
            .map_err(|e| ItsError::Memory(format!("read @ {gpa:#x}: {e:?}")))
    }

    /// Walk the (possibly indirect) device table to find a device's ITT.
    fn device_entry(
        &self,
        mem: &GuestMemory,
        device_id: u32,
    ) -> Result<Option<DeviceEntry>, ItsError> {
        let Some(baser) = self.config.device_baser else {
            return Ok(None);
        };
        let dte = if baser.indirect {
            let per_l2 = baser.page_size / baser.entry_size;
            let l1_idx = device_id as u64 / per_l2;
            let l2_idx = device_id as u64 % per_l2;
            let l1_entries = baser.num_pages * baser.page_size / 8;
            if l1_idx >= l1_entries {
                return Ok(None);
            }
            let l1e = Self::read_u64(mem, baser.base + l1_idx * 8)?;
            if (l1e >> 63) & 1 == 0 {
                return Ok(None);
            }
            let l2_base = l1e & 0x000f_ffff_ffff_0000;
            Self::read_u64(mem, l2_base + l2_idx * baser.entry_size)?
        } else {
            if device_id as u64 >= baser.flat_entries() {
                return Ok(None);
            }
            Self::read_u64(mem, baser.base + device_id as u64 * baser.entry_size)?
        };

        if (dte >> 63) & 1 == 0 {
            return Ok(None);
        }
        let itt = ((dte >> 5) & ((1 << 44) - 1)) << 8;
        let eventid_bits = ((dte & 0x1f) + 1) as u32;
        Ok(Some(DeviceEntry { itt, eventid_bits }))
    }

    /// Look up a collection's target redistributor.
    fn collection_rdbase(&self, mem: &GuestMemory, icid: u16) -> Result<Option<u32>, ItsError> {
        let Some(baser) = self.config.collection_baser else {
            return Ok(None);
        };
        let cte = if baser.indirect {
            let per_l2 = baser.page_size / baser.entry_size;
            let l1_idx = icid as u64 / per_l2;
            let l2_idx = icid as u64 % per_l2;
            let l1e = Self::read_u64(mem, baser.base + l1_idx * 8)?;
            if (l1e >> 63) & 1 == 0 {
                return Ok(None);
            }
            let l2_base = l1e & 0x000f_ffff_ffff_0000;
            Self::read_u64(mem, l2_base + l2_idx * baser.entry_size)?
        } else {
            if icid as u64 >= baser.flat_entries() {
                return Ok(None);
            }
            Self::read_u64(mem, baser.base + icid as u64 * baser.entry_size)?
        };
        if (cte >> 63) & 1 == 0 {
            return Ok(None);
        }
        Ok(Some(((cte >> 16) & 0x7_ffff_ffff) as u32))
    }

    /// Translate an MSI `(DeviceID, EventID)` into its physical LPI, walking the
    /// device table, the device's ITT, and the collection table in guest RAM.
    /// Returns `None` for an unmapped device/event (no faulting LPI).
    pub fn translate(
        &self,
        mem: &GuestMemory,
        device_id: u32,
        event_id: u32,
    ) -> Result<Option<Lpi>, ItsError> {
        let Some(dev) = self.device_entry(mem, device_id)? else {
            return Ok(None);
        };
        if event_id >= (1u32 << dev.eventid_bits.min(31)) {
            return Ok(None);
        }
        let ite = Self::read_u64(mem, dev.itt + event_id as u64 * ITE_SIZE)?;
        let intid = ((ite >> 16) & 0xffff_ffff) as u32;
        let icid = (ite & 0xffff) as u16;
        if intid < GICV3_LPI_INTID_BASE {
            return Ok(None);
        }
        let Some(rdbase) = self.collection_rdbase(mem, icid)? else {
            return Ok(None);
        };
        Ok(Some(Lpi { intid, rdbase }))
    }

    /// Reconstruct device/event -> LPI mappings by replaying the ITS command
    /// queue between byte offsets `[start, end)` (wrapping at the queue size).
    /// This is an independent path from the table walk: it processes the
    /// architectural `MAPD`/`MAPC`/`MAPTI`/`MAPI` commands the guest issued.
    /// Used as a cross-check of [`Its::translate`] and as the basis for runtime
    /// `GITS_CWRITER` command processing. Each entry is
    /// `(device_id, event_id, intid, icid)`.
    pub fn replay_commands(
        &self,
        mem: &GuestMemory,
        start: u64,
        end: u64,
    ) -> Result<Vec<(u32, u32, u32, u16)>, ItsError> {
        let size = self.config.cmd_size;
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut off = start % size;
        let end = end % size;
        // Walk forward (handling a single wrap) until we reach `end`.
        loop {
            if off == end {
                break;
            }
            let base = self.config.cmd_base + off;
            let dw0 = Self::read_u64(mem, base)?;
            let dw1 = Self::read_u64(mem, base + 8)?;
            let cmd = dw0 & 0xff;
            match cmd {
                // MAPTI: DeviceID=dw0[63:32], EventID=dw1[31:0], pINTID=dw1[63:32], ICID=dw2[15:0]
                0x0a => {
                    let dev = (dw0 >> 32) as u32;
                    let event = (dw1 & 0xffff_ffff) as u32;
                    let intid = (dw1 >> 32) as u32;
                    let dw2 = Self::read_u64(mem, base + 16)?;
                    out.push((dev, event, intid, (dw2 & 0xffff) as u16));
                }
                // MAPI: pINTID == EventID (collection-only short form).
                0x0b => {
                    let dev = (dw0 >> 32) as u32;
                    let event = (dw1 & 0xffff_ffff) as u32;
                    let dw2 = Self::read_u64(mem, base + 16)?;
                    out.push((dev, event, event, (dw2 & 0xffff) as u16));
                }
                _ => {}
            }
            off = (off + 32) % size;
        }
        Ok(out)
    }

    /// Replay the full captured command history (`[0, GITS_CWRITER)`), suitable
    /// for a freshly restored queue that has not wrapped.
    pub fn replay_history(&self, mem: &GuestMemory) -> Result<Vec<(u32, u32, u32, u16)>, ItsError> {
        self.replay_commands(mem, 0, self.config.cwriter)
    }

    /// Replay only commands the guest queued but the ITS had not yet consumed at
    /// capture time (`[GITS_CREADR, GITS_CWRITER)`). On a cleanly quiesced
    /// snapshot this is empty (`CREADR == CWRITER`); at runtime it is the work
    /// to process when the guest advances `GITS_CWRITER`.
    pub fn replay_pending(&self, mem: &GuestMemory) -> Result<Vec<(u32, u32, u32, u16)>, ItsError> {
        self.replay_commands(mem, self.config.creadr, self.config.cwriter)
    }
}

/// Sink that delivers a resolved LPI to the guest's CPU interface. The hardware
/// backend implements this over the GIC; tests use a recording stub.
pub trait LpiSink: Send + Sync {
    /// Deliver `lpi` (already translated from an MSI) to its target
    /// redistributor's CPU interface.
    fn deliver(&self, lpi: Lpi);
}

/// An [`LpiSink`] that records every delivered LPI (and logs under
/// `CHM_TRACE_ITS`). Used until a GIC-backed injection sink lands, and as the
/// observable record that the ITS data path resolved real completions.
#[derive(Default)]
pub struct LoggingLpiSink {
    delivered: std::sync::Mutex<Vec<Lpi>>,
}

impl LoggingLpiSink {
    /// Snapshot of every LPI delivered so far.
    pub fn delivered(&self) -> Vec<Lpi> {
        self.delivered.lock().unwrap().clone()
    }
}

impl LpiSink for LoggingLpiSink {
    fn deliver(&self, lpi: Lpi) {
        if std::env::var_os("CHM_TRACE_ITS").is_some() {
            eprintln!("[its] deliver LPI {} -> redistributor {}", lpi.intid, lpi.rdbase);
        }
        self.delivered.lock().unwrap().push(lpi);
    }
}

/// An [`InterruptInjector`](super::pci::InterruptInjector) that turns a virtio
/// device's MSI-X vector into an LPI via the ITS and hands it to an [`LpiSink`].
///
/// This is the data-path replacement for `LoggingInjector`: when a restored
/// device completes a queue, instead of writing the MSI doorbell (which Apple's
/// GIC could not translate) it resolves the same `(DeviceID, EventID)` the
/// guest's ITS was programmed with into the physical LPI the guest's handler
/// expects, then delivers it.
pub struct ItsInjector {
    name: String,
    its: std::sync::Arc<Its>,
    mem: std::sync::Arc<GuestMemory>,
    device_id: u32,
    /// EventID (`msg_data`) for each MSI-X vector, indexed by vector number.
    vector_events: Vec<u32>,
    sink: std::sync::Arc<dyn LpiSink>,
}

impl ItsInjector {
    /// Build an injector for one device.
    pub fn new(
        name: impl Into<String>,
        its: std::sync::Arc<Its>,
        mem: std::sync::Arc<GuestMemory>,
        device_id: u32,
        vector_events: Vec<u32>,
        sink: std::sync::Arc<dyn LpiSink>,
    ) -> Self {
        Self {
            name: name.into(),
            its,
            mem,
            device_id,
            vector_events,
            sink,
        }
    }

    /// Resolve a vector to its LPI without delivering (used by tests/tracing).
    pub fn resolve(&self, vector: u16) -> Option<Lpi> {
        let event = *self.vector_events.get(vector as usize)?;
        self.its.translate(&self.mem, self.device_id, event).ok().flatten()
    }
}

impl super::pci::InterruptInjector for ItsInjector {
    fn signal(&self, vector: u16) {
        let Some(&event) = self.vector_events.get(vector as usize) else {
            eprintln!(
                "[its {}] MSI-X vector {vector} has no table entry; dropping",
                self.name
            );
            return;
        };
        match self.its.translate(&self.mem, self.device_id, event) {
            Ok(Some(lpi)) => {
                if std::env::var_os("CHM_TRACE_ITS").is_some() {
                    eprintln!(
                        "[its {}] dev {:#x} event {event} -> LPI {} (rd {})",
                        self.name, self.device_id, lpi.intid, lpi.rdbase
                    );
                }
                self.sink.deliver(lpi);
            }
            Ok(None) => eprintln!(
                "[its {}] dev {:#x} event {event} unmapped; dropping completion",
                self.name, self.device_id
            ),
            Err(e) => eprintln!("[its {}] translate failed: {e}", self.name),
        }
    }
}

/// How a snapshot routes its virtio completion interrupts, which decides
/// whether they can be delivered to the guest on Apple's managed GIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionRouting {
    /// No enabled ITS with MSI-wired virtio devices. Completions arrive as
    /// message-based / line SPIs, which the managed GIC CAN deliver
    /// (`hv_gic_send_msi` / `hv_gic_set_spi`).
    DeliverableSpi,
    /// At least one virtio device routes completions through the GIC ITS as
    /// LPIs. Apple's managed GIC has no LPI/ITS support (proven on hardware:
    /// ICH List Registers are EL2/nested-only -> HV_UNSUPPORTED, and no
    /// PROPBASER/PENDBASER/ITS API exists), so these completions CANNOT be
    /// delivered: a rehydrated guest restores but then hangs on its first
    /// device wait with no completion interrupt.
    ItsLpi,
}

/// Classify a snapshot's virtio completion-interrupt routing.
///
/// `wired_devices` is the count of virtio devices that have at least one MSI-X
/// vector mapped to a non-zero DeviceID (i.e. wired to the ITS). LPI routing is
/// only an obstacle when an *enabled* ITS actually has MSI-wired devices; an
/// absent or disabled ITS means completions are delivered as SPIs.
pub fn classify_routing(state_json: &str, wired_devices: usize) -> CompletionRouting {
    if wired_devices == 0 {
        return CompletionRouting::DeliverableSpi;
    }
    match ItsConfig::from_snapshot_state(state_json) {
        Ok(cfg) if cfg.enabled => CompletionRouting::ItsLpi,
        _ => CompletionRouting::DeliverableSpi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `gic-v3-its` KVM register state from the captured arm64 cloud
    /// snapshot (`device-manager/snapshots/gic-v3-its`). BASER0 (Devices,
    /// indirect) @ 0x40240000, BASER1 (Collections, flat) @ 0x40250000,
    /// CBASER @ 0x40230000, CWRITER/CREADR = 608.
    const KVM_ITS_STATE: &str = r#"{"Kvm":{"its_ctlr":2147483649,"its_iidr":1258292283,"its_cbaser":13258597304054776847,"its_cwriter":608,"its_creadr":608,"its_baser":[17944311241357133312,13548798005043594752,0,0,0,0,0,0]}}"#;

    /// Lay down a KVM-format ITS table image in a fresh guest-memory region and
    /// return it. Mirrors the snapshot: an indirect device table, a flat
    /// collection table, and per-device ITTs, mapping dev 0x8/0x10/0x18 events
    /// 0/1 to LPIs 8192..8197, all collection 0 -> rdbase 0.
    fn synthetic_mem() -> GuestMemory {
        let mem = GuestMemory::new();
        // One 16 MiB region covering all the table GPAs (0x4023_0000..).
        let region_base = 0x4000_0000u64;
        mem.register_owned(region_base, 16 * 1024 * 1024);

        let devt = 0x4024_0000u64; // L1 indirect device table
        let colt = 0x4025_0000u64; // flat collection table
        let itt_base = 0x4030_0000u64; // per-device ITTs (laid out by us)

        // Collection 0 -> rdbase 0, valid.
        mem.write_u64(colt, 1u64 << 63).unwrap();

        // L2 device-table page (512 entries) lives just past the L1 page.
        let l2 = devt + 0x1_0000; // L2 page base
        mem.write_u64(devt, (1u64 << 63) | l2).unwrap(); // L1[0] -> L2, valid

        for (i, &dev) in [0x8u32, 0x10, 0x18].iter().enumerate() {
            let itt = itt_base + (i as u64) * 0x1000;
            // DTE: valid | itt(>>8 at shift 5) | size(evbits-1 = 1)
            let dte = (1u64 << 63) | (((itt >> 8) & ((1 << 44) - 1)) << 5) | 1;
            mem.write_u64(l2 + dev as u64 * 8, dte).unwrap();
            for ev in 0..2u32 {
                let intid = 8192 + (i as u64) * 2 + ev as u64;
                // ITE: pINTID[47:16] | icid[15:0]
                let ite = (intid << 16) | 0;
                mem.write_u64(itt + ev as u64 * ITE_SIZE, ite).unwrap();
            }
        }
        mem
    }

    #[test]
    fn parses_real_kvm_its_state() {
        let kvm: Value = serde_json::from_str(KVM_ITS_STATE).unwrap();
        let cfg = ItsConfig::parse_kvm(kvm.get("Kvm").unwrap()).unwrap();
        assert!(cfg.enabled);
        let dev = cfg.device_baser.expect("device baser");
        assert!(dev.indirect);
        assert_eq!(dev.typ, 1);
        assert_eq!(dev.base, 0x4024_0000);
        let col = cfg.collection_baser.expect("collection baser");
        assert!(!col.indirect);
        assert_eq!(col.typ, 4);
        assert_eq!(col.base, 0x4025_0000);
        assert_eq!(cfg.cmd_base, 0x4023_0000);
        assert_eq!(cfg.cwriter, 608);
    }

    #[test]
    fn translates_all_snapshot_devices() {
        let its = Its::from_snapshot_state(&format!(
            r#"{{"snapshots":{{"device-manager":{{"snapshots":{{"gic-v3-its":{{"snapshot_data":{{"state":{}}}}}}}}}}}}}"#,
            serde_json::to_string(KVM_ITS_STATE).unwrap()
        ))
        .unwrap();
        let mem = synthetic_mem();

        let expect = [
            (0x8u32, 0u32, 8192u32),
            (0x8, 1, 8193),
            (0x10, 0, 8194),
            (0x10, 1, 8195),
            (0x18, 0, 8196),
            (0x18, 1, 8197),
        ];
        for (dev, ev, intid) in expect {
            let lpi = its.translate(&mem, dev, ev).unwrap().expect("mapped");
            assert_eq!(lpi.intid, intid, "dev {dev:#x} event {ev}");
            assert_eq!(lpi.rdbase, 0);
        }
    }

    #[test]
    fn unmapped_device_and_event_return_none() {
        let its = Its::new(ItsConfig::parse_kvm(&serde_json::from_str::<Value>(KVM_ITS_STATE).unwrap()["Kvm"]).unwrap());
        let mem = synthetic_mem();
        // Device 0x9 was never mapped (no DTE).
        assert_eq!(its.translate(&mem, 0x9, 0).unwrap(), None);
        // Device 0x8 only has 1 eventid bit -> events 0,1 valid, 2 out of range.
        assert_eq!(its.translate(&mem, 0x8, 2).unwrap(), None);
    }

    #[test]
    fn command_replay_matches_table_walk() {
        // Build a command queue with MAPTI for the same six mappings, place it
        // at the snapshot's CBASER GPA, and confirm replay agrees.
        let its = Its::new(ItsConfig::parse_kvm(&serde_json::from_str::<Value>(KVM_ITS_STATE).unwrap()["Kvm"]).unwrap());
        let mem = synthetic_mem();
        let cq = 0x4023_0000u64;
        let mappings = [
            (0x8u32, 0u32, 8192u32),
            (0x8, 1, 8193),
            (0x10, 0, 8194),
            (0x10, 1, 8195),
            (0x18, 0, 8196),
            (0x18, 1, 8197),
        ];
        for (i, (dev, ev, intid)) in mappings.iter().enumerate() {
            let base = cq + (i as u64) * 32;
            // MAPTI: dw0[7:0]=0x0a, dw0[63:32]=DeviceID
            mem.write_u64(base, 0x0a | ((*dev as u64) << 32)).unwrap();
            // dw1[31:0]=EventID, dw1[63:32]=pINTID
            mem.write_u64(base + 8, (*ev as u64) | ((*intid as u64) << 32))
                .unwrap();
            // dw2[15:0]=ICID
            mem.write_u64(base + 16, 0).unwrap();
            mem.write_u64(base + 24, 0).unwrap();
        }
        let replayed = its.replay_commands(&mem, 0, (mappings.len() * 32) as u64).unwrap();
        assert_eq!(replayed.len(), mappings.len());
        for (dev, ev, intid) in mappings {
            assert!(
                replayed.contains(&(dev, ev, intid, 0)),
                "missing mapping dev {dev:#x} ev {ev}"
            );
            // And the table walk agrees on the same LPI.
            assert_eq!(its.translate(&mem, dev, ev).unwrap().unwrap().intid, intid);
        }
    }

    #[test]
    fn classify_routing_flags_enabled_its_with_wired_devices() {
        let state = its_state_json(KVM_ITS_STATE);
        // An enabled ITS plus MSI-wired virtio devices == undeliverable LPIs.
        assert_eq!(classify_routing(&state, 3), CompletionRouting::ItsLpi);
        // No MSI-wired devices: completions are SPIs, deliverable.
        assert_eq!(classify_routing(&state, 0), CompletionRouting::DeliverableSpi);
    }

    #[test]
    fn classify_routing_allows_disabled_or_absent_its() {
        // GITS_CTLR.Enabled clear -> SPI routing even with wired devices.
        let disabled =
            KVM_ITS_STATE.replace("\"its_ctlr\":2147483649", "\"its_ctlr\":2147483648");
        let state = its_state_json(&disabled);
        assert_eq!(classify_routing(&state, 3), CompletionRouting::DeliverableSpi);
        // No ITS node at all -> deliverable.
        assert_eq!(
            classify_routing(r#"{"snapshots":{}}"#, 3),
            CompletionRouting::DeliverableSpi
        );
    }

    /// Wrap an inner `{"Kvm":...}` ITS blob in the snapshot tree shape that
    /// `from_snapshot_state` walks (the `state` field is a JSON string).
    fn its_state_json(inner: &str) -> String {
        serde_json::json!({
            "snapshots": {
                "device-manager": {
                    "snapshots": {
                        "gic-v3-its": {
                            "snapshot_data": { "state": inner }
                        }
                    }
                }
            }
        })
        .to_string()
    }
}
