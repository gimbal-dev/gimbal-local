//! Reading *and writing* a vanilla Cloud Hypervisor `state.json`.
//!
//! Everything in this tree so far only ever *reads* a `state.json`: it arrives
//! from a KVM host, `hypervisor::hvf::rehydrate` takes it apart, and the Mac
//! restores the machine it describes. Nothing has ever produced one. That is
//! the whole of why a lineage advanced on a Mac cannot go back to the cloud
//! (#353), and half of why one cannot be *originated* here at all (#341).
//!
//! # Why this is a document, not a schema
//!
//! The obvious shape is a `#[derive(Deserialize)]` mirror of the format. This
//! deliberately is not that, for the reason #180 recorded the hard way: a
//! writer that mirrors a reader agrees with it *by construction*, so the pair
//! moves together and the disagreement only shows up on somebody else's disk.
//! A real capture is 57 KB describing eleven devices, a GIC, an ITS, a memory
//! layout and two vCPUs. We need to change perhaps three of those things. A
//! mirror would have to model all of it correctly to avoid destroying the rest,
//! and every field we failed to anticipate would be silently dropped.
//!
//! So the document is held whole, as parsed JSON, and this module exposes
//! typed views onto the specific values a Mac must change. Everything else is
//! carried through untouched because it is never taken apart in the first
//! place. Fidelity is then a property of the structure rather than a promise,
//! and [`VanillaState::changed_paths`] makes it measurable.
//!
//! # The nested-string trap
//!
//! Cloud Hypervisor serializes each component's state and then stores the
//! *result* as a JSON **string** under `snapshot_data.state`. So a `state.json`
//! is a document containing more documents, quoted. Comparing two of them
//! textually reports a difference whenever a nested document is re-serialized
//! with different spacing or key order, which is not a difference at all to the
//! deserializer that actually reads it. [`VanillaState::normalized`] parses
//! those strings back out so comparison happens at the level Cloud Hypervisor
//! itself sees.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::result::Result as StdResult;

use serde_json::{Map, Value};

/// The register block Cloud Hypervisor stores per vCPU, in KVM's own layout.
///
/// Held as the ancestor's own bytes with typed accessors patching in place,
/// never rebuilt from the fields we happen to model. A Mac that reconstructed
/// this block from an HVF vCPU would zero every field HVF does not expose, and
/// the guest would resume into a machine subtly unlike the one it was suspended
/// from. Patching keeps the parent's answer for every question we cannot ask.
///
/// The floating-point state used to be the worked example here. It is not any
/// more: HVF does expose it, and #357 wired it through, so the exporter now
/// patches `fp_regs` from the live vCPU like any other block. Everything still
/// unmodelled -- `__reserved`, and whatever a future `kvm_regs` grows -- is
/// what the ancestor's bytes are still holding.
pub(crate) const CORE_REGS_LEN: usize = 864;

/// Byte offsets into `core_regs`, from `struct kvm_regs` on aarch64:
/// `user_pt_regs` (x0-x30, sp, pc, pstate) then `sp_el1`, `elr_el1`, `spsr[5]`,
/// then `fp_regs` at its natural 16-byte alignment.
const OFF_X0: usize = 0;
const OFF_SP: usize = 248;
const OFF_PC: usize = 256;
const OFF_PSTATE: usize = 264;
const OFF_SP_EL1: usize = 272;
const OFF_ELR_EL1: usize = 280;
const OFF_SPSR: usize = 288;

/// A system register as Cloud Hypervisor stores it: each entry is its own
/// 16-byte array holding a KVM `ONE_REG` id and its value, little-endian, back
/// to back. Measured across all five captures we hold, every vCPU carries
/// exactly 256 of them.
const SYS_REG_PAIR_LEN: usize = 16;

#[derive(Debug)]
pub enum VanillaError {
    Parse(String),
    Missing(String),
    Malformed(String),
}

impl fmt::Display for VanillaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "state.json is not valid JSON: {m}"),
            Self::Missing(m) => write!(f, "state.json has no {m}"),
            Self::Malformed(m) => write!(f, "state.json is malformed: {m}"),
        }
    }
}

impl StdError for VanillaError {}

type Result<T> = StdResult<T, VanillaError>;

/// The guest clock, as the top-level `snapshot_data.state` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The guest's virtual counter at the instant of capture.
    pub cntvct: u64,
    /// The host's wall clock at that same instant, nanoseconds since the epoch.
    pub host_realtime_ns: u64,
    /// The counter frequency the guest believes in. Captured on Graviton this
    /// is 121_875_000; Apple silicon runs at 24_000_000, which is why the
    /// restore path synthesizes a rate rather than adopting one.
    pub cntfrq: u64,
}

/// A KVM register: the `ONE_REG` id and the value behind it.
///
/// Named for the field that carries it, though the field is not purely system
/// registers -- a real capture's 256 entries measure as 234 `ARM64_SYSREG`,
/// 14 `DEMUX` (the cache-level descriptors), and 8 firmware pseudo-registers.
/// That is the whole `ONE_REG` set the capturing VMM chose to save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysReg {
    pub id: u64,
    pub value: u64,
}

/// A vCPU's captured state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vcpu {
    pub mp_state: u32,
    core: Vec<u8>,
    pub sys_regs: Vec<SysReg>,
}

impl Vcpu {
    fn x_offset(i: usize) -> Option<usize> {
        (i <= 30).then(|| OFF_X0 + i * 8)
    }

    fn read(&self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.core[off..off + 8]);
        u64::from_le_bytes(b)
    }

    fn write(&mut self, off: usize, v: u64) {
        self.core[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// `x0`..`x30`. Returns `None` above 30 rather than reading whatever
    /// happens to sit past the general-purpose block.
    pub fn x(&self, i: usize) -> Option<u64> {
        Self::x_offset(i).map(|o| self.read(o))
    }

    pub fn pc(&self) -> u64 {
        self.read(OFF_PC)
    }
    pub fn sp(&self) -> u64 {
        self.read(OFF_SP)
    }
    pub fn pstate(&self) -> u64 {
        self.read(OFF_PSTATE)
    }
    pub fn sp_el1(&self) -> u64 {
        self.read(OFF_SP_EL1)
    }
    pub fn elr_el1(&self) -> u64 {
        self.read(OFF_ELR_EL1)
    }
    /// `spsr[0..5]`.
    pub fn spsr(&self, i: usize) -> Option<u64> {
        (i < 5).then(|| self.read(OFF_SPSR + i * 8))
    }

    /// The whole block, including the floating-point state this type does not
    /// name. Present so a caller can see what it is carrying, not so it can be
    /// rebuilt.
    pub fn core_bytes(&self) -> &[u8] {
        &self.core
    }

    /// Update a core register the capture already carries, addressed by its
    /// byte offset in `struct kvm_regs`. Returns `false` for an offset that is
    /// misaligned or runs past the block, rather than growing it.
    ///
    /// Offsets rather than typed setters because the writer's input is a list
    /// of KVM `ONE_REG` ids, and an id *is* an offset. Routing them through
    /// named accessors would mean re-deriving, here, which offset each id
    /// means -- a second copy of a mapping the KVM ABI already fixes.
    ///
    /// This still patches in place, so nothing here zeroes what it is not
    /// given. It cannot reach the floating-point block at offset 336: no core
    /// id the register-lowering emits lands there, and a `u64` at an 8-byte
    /// stride cannot address a 128-bit vector register anyway. That block is
    /// written by `set_core_bytes`.
    pub fn set_core_reg(&mut self, byte_offset: usize, value: u64) -> bool {
        if !byte_offset.is_multiple_of(8) || byte_offset + 8 > self.core.len() {
            return false;
        }
        self.write(byte_offset, value);
        true
    }

    /// Update a run of bytes in `core_regs` at `byte_offset`, for state whose
    /// width a `ONE_REG` id cannot express.
    ///
    /// The SIMD&FP block is the whole reason this exists. `kvm_core_reg_id`
    /// hardcodes `KVM_REG_SIZE_U64`, so the id space `set_core_reg` speaks can
    /// name neither a 128-bit vector register nor the 32-bit `fpsr`/`fpcr` --
    /// the ids simply do not exist. Lowering carries that state beside the id
    /// list rather than inside it, and it has to land somewhere.
    ///
    /// Deliberately byte-addressed and not 8-aligned: `fpcr` sits at 852.
    /// Returns `false` for a run that would leave the block, rather than
    /// growing it -- the length is the ancestor's, and a write past it would
    /// be describing a `kvm_regs` this capture is not.
    pub fn set_core_bytes(&mut self, byte_offset: usize, bytes: &[u8]) -> bool {
        let Some(end) = byte_offset.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.core.len() {
            return false;
        }
        self.core[byte_offset..end].copy_from_slice(bytes);
        true
    }

    /// The value of a system register by its KVM `ONE_REG` id.
    pub fn sys_reg(&self, id: u64) -> Option<u64> {
        self.sys_regs.iter().find(|r| r.id == id).map(|r| r.value)
    }

    /// Update a system register the capture already carries. Returns `false`
    /// if the capture does not carry it -- deliberately, rather than appending.
    ///
    /// The list is curated, not exhaustive: it is the analogue of the KVM
    /// `ONE_REG` set the capturing VMM chose to save. Adding an entry claims
    /// the receiving VMM will restore it, and #257 is eight months of evidence
    /// about what a wrong belief regarding this list costs. Growing it is a
    /// decision about the format, not a side effect of writing a value.
    pub fn set_sys_reg(&mut self, id: u64, value: u64) -> bool {
        match self.sys_regs.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.value = value;
                true
            }
            None => false,
        }
    }
}

/// A vanilla Cloud Hypervisor `state.json`, held whole.
#[derive(Debug, Clone)]
pub struct VanillaState {
    doc: Value,
}

impl VanillaState {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let doc: Value =
            serde_json::from_slice(bytes).map_err(|e| VanillaError::Parse(e.to_string()))?;
        if !doc.is_object() {
            return Err(VanillaError::Malformed("top level is not an object".into()));
        }
        Ok(Self { doc })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.doc).map_err(|e| VanillaError::Parse(e.to_string()))
    }

    /// Walk to a component node. Every level except the last is reached
    /// through its `snapshots` map -- the same traversal
    /// `hypervisor::hvf::rehydrate::embedded_state` performs on the way in, so
    /// a path that reads here is the path that resolved there.
    fn node_path(path: &[&str]) -> Vec<String> {
        let mut out = vec!["snapshots".to_string()];
        for (i, key) in path.iter().enumerate() {
            out.push((*key).to_string());
            if i + 1 < path.len() {
                out.push("snapshots".to_string());
            }
        }
        out
    }

    fn get_at<'a>(doc: &'a Value, path: &[String]) -> Option<&'a Value> {
        let mut node = doc;
        for key in path {
            node = node.get(key)?;
        }
        Some(node)
    }

    fn get_at_mut<'a>(doc: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
        let mut node = doc;
        for key in path {
            node = node.get_mut(key)?;
        }
        Some(node)
    }

    /// Read a component's embedded state, parsing the quoted document back out.
    fn embedded(&self, path: &[&str]) -> Result<Value> {
        let node = Self::node_path(path);
        let s = Self::get_at(&self.doc, &node)
            .and_then(|n| n.get("snapshot_data"))
            .and_then(|d| d.get("state"))
            .and_then(Value::as_str)
            .ok_or_else(|| VanillaError::Missing(format!("state for `{}`", path.join("/"))))?;
        serde_json::from_str(s).map_err(|e| {
            VanillaError::Malformed(format!("embedded state for `{}`: {e}", path.join("/")))
        })
    }

    /// Write a component's embedded state back, re-quoted.
    fn set_embedded(&mut self, path: &[&str], value: &Value) -> Result<()> {
        let s = serde_json::to_string(value).map_err(|e| VanillaError::Parse(e.to_string()))?;
        let node = Self::node_path(path);
        let slot = Self::get_at_mut(&mut self.doc, &node)
            .and_then(|n| n.get_mut("snapshot_data"))
            .and_then(|d| d.get_mut("state"))
            .ok_or_else(|| VanillaError::Missing(format!("state for `{}`", path.join("/"))))?;
        *slot = Value::String(s);
        Ok(())
    }

    fn top_embedded(&self) -> Result<Value> {
        let s = self
            .doc
            .get("snapshot_data")
            .and_then(|d| d.get("state"))
            .and_then(Value::as_str)
            .ok_or_else(|| VanillaError::Missing("top-level snapshot_data.state".into()))?;
        serde_json::from_str(s)
            .map_err(|e| VanillaError::Malformed(format!("top-level embedded state: {e}")))
    }

    fn set_top_embedded(&mut self, value: &Value) -> Result<()> {
        let s = serde_json::to_string(value).map_err(|e| VanillaError::Parse(e.to_string()))?;
        let slot = self
            .doc
            .get_mut("snapshot_data")
            .and_then(|d| d.get_mut("state"))
            .ok_or_else(|| VanillaError::Missing("top-level snapshot_data.state".into()))?;
        *slot = Value::String(s);
        Ok(())
    }

    /// The guest clock recorded at capture.
    pub fn clock(&self) -> Result<Clock> {
        let top = self.top_embedded()?;
        let c = top
            .get("clock")
            .ok_or_else(|| VanillaError::Missing("clock block".into()))?;
        let field = |k: &str| -> Result<u64> {
            c.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| VanillaError::Missing(format!("clock.{k}")))
        };
        Ok(Clock {
            cntvct: field("cntvct")?,
            host_realtime_ns: field("host_realtime_ns")?,
            cntfrq: field("cntfrq")?,
        })
    }

    /// Record a new capture instant.
    ///
    /// `cntfrq` is carried, never set: it is a property of the hardware the
    /// guest booted on and latched at boot, not of the moment we are recording.
    /// Writing this Mac's 24 MHz into a guest that cached 121.875 MHz would
    /// make the restored machine disagree with itself about how fast time runs.
    pub fn set_capture_instant(&mut self, cntvct: u64, host_realtime_ns: u64) -> Result<()> {
        let mut top = self.top_embedded()?;
        let clock = top
            .get_mut("clock")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| VanillaError::Missing("clock block".into()))?;
        clock.insert("cntvct".into(), Value::from(cntvct));
        clock.insert("host_realtime_ns".into(), Value::from(host_realtime_ns));
        self.set_top_embedded(&top)
    }

    /// The vCPU ids this capture carries, in numeric order.
    pub fn vcpu_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .doc
            .get("snapshots")
            .and_then(|s| s.get("cpu-manager"))
            .and_then(|c| c.get("snapshots"))
            .and_then(Value::as_object)
            .map(|m| m.keys().filter_map(|k| k.parse().ok()).collect())
            .unwrap_or_default();
        ids.sort_unstable();
        ids
    }

    fn vcpu_kvm(&self, id: u32) -> Result<Value> {
        let ids = id.to_string();
        let state = self.embedded(&["cpu-manager", &ids])?;
        state
            .get("Kvm")
            .cloned()
            .ok_or_else(|| VanillaError::Malformed(format!("vCPU {id} state is not a `Kvm` block")))
    }

    fn byte_array(v: &Value) -> Option<Vec<u8>> {
        v.as_array()?
            .iter()
            .map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect()
    }

    fn bytes_field(v: &Value, name: &str, id: u32) -> Result<Vec<u8>> {
        let field = v
            .get(name)
            .ok_or_else(|| VanillaError::Missing(format!("vCPU {id} {name}")))?;
        Self::byte_array(field).ok_or_else(|| {
            VanillaError::Malformed(format!("vCPU {id} {name} is not an array of bytes"))
        })
    }

    pub fn vcpu(&self, id: u32) -> Result<Vcpu> {
        let kvm = self.vcpu_kvm(id)?;

        let mp = Self::bytes_field(&kvm, "mp_state", id)?;
        if mp.len() != 4 {
            return Err(VanillaError::Malformed(format!(
                "vCPU {id} mp_state is {} bytes, expected 4",
                mp.len()
            )));
        }
        let mp_state = u32::from_le_bytes([mp[0], mp[1], mp[2], mp[3]]);

        let core = Self::bytes_field(&kvm, "core_regs", id)?;
        if core.len() != CORE_REGS_LEN {
            return Err(VanillaError::Malformed(format!(
                "vCPU {id} core_regs is {} bytes, expected {CORE_REGS_LEN}",
                core.len()
            )));
        }

        let raw = kvm
            .get("sys_regs")
            .and_then(Value::as_array)
            .ok_or_else(|| VanillaError::Missing(format!("vCPU {id} sys_regs")))?;
        let mut sys_regs = Vec::with_capacity(raw.len());
        for (n, entry) in raw.iter().enumerate() {
            let bytes = Self::byte_array(entry).ok_or_else(|| {
                VanillaError::Malformed(format!(
                    "vCPU {id} sys_regs[{n}] is not an array of bytes"
                ))
            })?;
            if bytes.len() != SYS_REG_PAIR_LEN {
                return Err(VanillaError::Malformed(format!(
                    "vCPU {id} sys_regs[{n}] is {} bytes, expected {SYS_REG_PAIR_LEN}",
                    bytes.len()
                )));
            }
            let mut i = [0u8; 8];
            let mut v = [0u8; 8];
            i.copy_from_slice(&bytes[..8]);
            v.copy_from_slice(&bytes[8..]);
            sys_regs.push(SysReg {
                id: u64::from_le_bytes(i),
                value: u64::from_le_bytes(v),
            });
        }

        Ok(Vcpu {
            mp_state,
            core,
            sys_regs,
        })
    }

    /// Write a vCPU's state back over the one the capture carries.
    ///
    /// Refuses to change the *shape* of what it found. A capture whose
    /// `sys_regs` grew or shrank is no longer the machine the rest of the
    /// document describes, and the receiving VMM would restore a register set
    /// its own curated list does not expect.
    pub fn set_vcpu(&mut self, id: u32, vcpu: &Vcpu) -> Result<()> {
        let existing = self.vcpu(id)?;
        if existing.sys_regs.len() != vcpu.sys_regs.len() {
            return Err(VanillaError::Malformed(format!(
                "vCPU {id} carries {} system registers; refusing to write {}",
                existing.sys_regs.len(),
                vcpu.sys_regs.len()
            )));
        }
        if vcpu.core.len() != CORE_REGS_LEN {
            return Err(VanillaError::Malformed(format!(
                "vCPU {id} core_regs must stay {CORE_REGS_LEN} bytes"
            )));
        }

        let idn = id.to_string();
        let mut state = self.embedded(&["cpu-manager", &idn])?;
        let kvm = state
            .get_mut("Kvm")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| VanillaError::Malformed(format!("vCPU {id} state is not a `Kvm` block")))?;

        let bytes = |b: &[u8]| Value::Array(b.iter().map(|x| Value::from(*x)).collect());
        kvm.insert("mp_state".into(), bytes(&vcpu.mp_state.to_le_bytes()));
        kvm.insert("core_regs".into(), bytes(&vcpu.core));
        let sys: Vec<Value> = vcpu
            .sys_regs
            .iter()
            .map(|r| {
                let mut pair = [0u8; SYS_REG_PAIR_LEN];
                pair[..8].copy_from_slice(&r.id.to_le_bytes());
                pair[8..].copy_from_slice(&r.value.to_le_bytes());
                bytes(&pair)
            })
            .collect();
        kvm.insert("sys_regs".into(), Value::Array(sys));

        self.set_embedded(&["cpu-manager", &idn], &state)
    }

    /// The document with every embedded state string parsed back out.
    ///
    /// This is the level Cloud Hypervisor's own deserializer reads at, so it is
    /// the level two captures should be compared at. Comparing the raw text
    /// instead reports a difference every time a nested document is
    /// re-serialized with different spacing, which is not a difference to
    /// anything that will ever read it.
    pub fn normalized(&self) -> Value {
        fn walk(v: &Value) -> Value {
            match v {
                Value::Object(m) => {
                    let mut out = Map::new();
                    for (k, child) in m {
                        // A `snapshot_data` holds one key, `state`, whose value
                        // is a quoted document rather than a string.
                        if k == "snapshot_data"
                            && let Some(inner) = child.get("state").and_then(Value::as_str)
                            && let Ok(parsed) = serde_json::from_str::<Value>(inner)
                        {
                            let mut d = Map::new();
                            d.insert("state".into(), walk(&parsed));
                            out.insert(k.clone(), Value::Object(d));
                            continue;
                        }
                        out.insert(k.clone(), walk(child));
                    }
                    Value::Object(out)
                }
                Value::Array(a) => Value::Array(a.iter().map(walk).collect()),
                other => other.clone(),
            }
        }
        walk(&self.doc)
    }

    /// Every path at which two captures disagree, compared at the level Cloud
    /// Hypervisor reads.
    ///
    /// This is the instrument that makes fidelity measurable rather than
    /// asserted: rewriting a capture we did not author and getting an empty
    /// list back is evidence, where "the tests pass" is not.
    pub fn changed_paths(&self, other: &Self) -> Vec<String> {
        let mut out = BTreeMap::new();
        diff(&self.normalized(), &other.normalized(), String::new(), &mut out);
        out.into_keys().collect()
    }
}

fn diff(a: &Value, b: &Value, path: String, out: &mut BTreeMap<String, ()>) {
    let here = |p: &str| {
        if path.is_empty() {
            p.to_string()
        } else {
            format!("{path}/{p}")
        }
    };
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, av) in x {
                match y.get(k) {
                    Some(bv) => diff(av, bv, here(k), out),
                    None => {
                        out.insert(here(k), ());
                    }
                }
            }
            for k in y.keys() {
                if !x.contains_key(k) {
                    out.insert(here(k), ());
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                out.insert(path, ());
                return;
            }
            for (i, (av, bv)) in x.iter().zip(y).enumerate() {
                diff(av, bv, here(&i.to_string()), out);
            }
        }
        _ => {
            if a != b {
                out.insert(if path.is_empty() { "/".into() } else { path }, ());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real vanilla Cloud Hypervisor capture, taken on an AWS Graviton2 host
    /// by upstream Cloud Hypervisor, with two vCPUs and a NIC. Nothing in this
    /// tree can regenerate it, which is exactly what makes it evidence: a
    /// failure here means this build no longer understands captures that
    /// already exist, never that the fixture is stale.
    const REAL: &[u8] = include_bytes!("../testdata/vanilla-state-2cpu-net.json");

    /// Any further real captures the machine happens to hold. The frozen
    /// fixture is the gate; these widen it when they are present.
    /// The oracle: five real `state.json` documents authored by upstream Cloud
    /// Hypervisor on AWS Graviton hardware. Nothing in this tree can produce
    /// one, which is exactly what gives them authority a writer/reader pair of
    /// our own could never have (#178, #180).
    ///
    /// They are committed rather than swept out of a scratch directory on
    /// purpose. A sweep that finds nothing degrades to a single document in
    /// silence, and a guard whose coverage can quietly collapse reports safety
    /// it does not provide.
    fn all_captures() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("2cpu-net", REAL),
            (
                "graviton-1",
                include_bytes!("../testdata/vanilla-state-graviton-1.json"),
            ),
            (
                "graviton-2",
                include_bytes!("../testdata/vanilla-state-graviton-2.json"),
            ),
            (
                "graviton-3",
                include_bytes!("../testdata/vanilla-state-graviton-3.json"),
            ),
            (
                "graviton-1cpu",
                include_bytes!("../testdata/vanilla-state-graviton-1cpu.json"),
            ),
        ]
    }

    /// The `kvm_regs` offsets are the one thing in this module that a wrong
    /// belief would corrupt silently: a write lands, the document stays valid,
    /// and the guest comes back somewhere else. So they are measured against
    /// six real vCPUs rather than transcribed from a header.
    ///
    /// The structure is what carries the proof, not the values. Every address
    /// register must land in the kernel half of the address space (and they
    /// vary per capture, so this is KASLR and not a constant), and `pstate`
    /// must decode as EL1h with interrupts masked -- which is where a guest
    /// quiesced for capture has to be. An offset shifted by even one register
    /// breaks all of it at once.
    #[test]
    fn the_core_register_offsets_land_on_real_kernel_state() {
        for (name, bytes) in all_captures() {
            let s = VanillaState::parse(bytes).expect(name);
            for id in s.vcpu_ids() {
                let v = s.vcpu(id).expect(name);
                let kernel = |what: &str, a: u64| {
                    assert_eq!(
                        a >> 48,
                        0xffff,
                        "{name} vcpu{id}: {what} = {a:#018x} is not a kernel address, \
                         so its offset is wrong"
                    );
                };
                kernel("pc", v.pc());
                kernel("sp", v.sp());
                kernel("sp_el1", v.sp_el1());
                kernel("elr_el1", v.elr_el1());

                let pstate = v.pstate();
                assert_eq!(
                    pstate & 0xf,
                    0b0101,
                    "{name} vcpu{id}: pstate {pstate:#x} does not decode as EL1h"
                );
                assert_ne!(
                    pstate & 0x80,
                    0,
                    "{name} vcpu{id}: pstate {pstate:#x} says IRQs are unmasked, \
                     which a quiesced vCPU cannot be"
                );

                assert!(v.spsr(0).is_some());
                assert!(v.spsr(5).is_none(), "spsr[] is 5 wide");
                assert!(v.x(30).is_some() && v.x(31).is_none(), "x0..x30 only");
            }
        }
    }

    /// Every setter, one at a time, against a real capture. The realistic bug
    /// in a table of byte offsets is not a wild pointer -- it is two accessors
    /// sharing one offset after a copy-paste, which no single-register test can
    /// see. So each write must land in its *own* eight bytes and move nothing
    /// else in the 57 KB document.
    #[test]
    fn each_register_setter_writes_only_its_own_field() {
        type Get = fn(&Vcpu) -> u64;
        let fields: [(&str, usize, Get); 5] = [
            ("pc", OFF_PC, Vcpu::pc),
            ("sp", OFF_SP, Vcpu::sp),
            ("pstate", OFF_PSTATE, Vcpu::pstate),
            ("sp_el1", OFF_SP_EL1, Vcpu::sp_el1),
            ("elr_el1", OFF_ELR_EL1, Vcpu::elr_el1),
        ];

        let mut seen = std::collections::BTreeSet::new();
        for (name, off, _) in &fields {
            assert!(seen.insert(*off), "{name} shares offset {off} with another field");
        }

        const PREFIX: &str = "snapshots/cpu-manager/snapshots/0/snapshot_data/state/Kvm/core_regs/";
        let original = VanillaState::parse(REAL).unwrap();
        for (name, off, get) in fields {
            let sentinel = 0xffff_0000_dead_0000 | off as u64;
            let mut advanced = original.clone();
            let mut v = advanced.vcpu(0).unwrap();
            assert!(v.set_core_reg(off, sentinel), "{name}: the offset was refused");
            advanced.set_vcpu(0, &v).unwrap();

            let changed = original.changed_paths(&advanced);
            assert!(!changed.is_empty(), "{name}: the write did not land");
            for p in &changed {
                let idx: usize = p
                    .strip_prefix(PREFIX)
                    .unwrap_or_else(|| panic!("{name}: {p} is outside vCPU 0's core registers"))
                    .parse()
                    .unwrap();
                assert!(
                    (off..off + 8).contains(&idx),
                    "{name}: byte {idx} is outside its own field at {off}"
                );
            }
            assert_eq!(get(&advanced.vcpu(0).unwrap()), sentinel, "{name} did not read back");
        }
    }

    #[test]
    fn the_oracle_is_not_quietly_missing() {
        assert_eq!(
            all_captures().len(),
            5,
            "the round-trip gate is only as strong as the number of documents \
             we did not author that it runs against"
        );
    }

    #[test]
    fn a_real_capture_survives_being_written_back_unchanged() {
        for (name, bytes) in all_captures() {
            let original = VanillaState::parse(bytes).expect(name);
            let rewritten = VanillaState::parse(&original.to_bytes().expect(name)).expect(name);
            let changed = original.changed_paths(&rewritten);
            assert!(
                changed.is_empty(),
                "{name}: rewriting an untouched capture changed {} path(s): {:?}",
                changed.len(),
                &changed[..changed.len().min(8)]
            );
        }
    }

    /// The round trip above passes trivially if nothing is ever taken apart.
    /// This proves the embedded documents really are decoded and re-encoded,
    /// so the fidelity above is a property of a writer that ran, not of a
    /// writer that did nothing.
    #[test]
    fn the_round_trip_actually_re_encodes_the_embedded_documents() {
        let mut s = VanillaState::parse(REAL).unwrap();
        let ids = s.vcpu_ids();
        assert_eq!(ids, vec![0, 1], "the fixture has two vCPUs");

        // Re-encode every embedded document by writing back what we read.
        let clock = s.clock().unwrap();
        s.set_capture_instant(clock.cntvct, clock.host_realtime_ns)
            .unwrap();
        for id in &ids {
            let v = s.vcpu(*id).unwrap();
            s.set_vcpu(*id, &v).unwrap();
        }

        let original = VanillaState::parse(REAL).unwrap();
        assert!(
            original.changed_paths(&s).is_empty(),
            "re-encoding every embedded document must change nothing"
        );
        // ...and the text really did move, or the assertion above proves nothing.
        assert_ne!(
            original.to_bytes().unwrap(),
            s.to_bytes().unwrap(),
            "the embedded documents were never re-encoded, so this test is blind"
        );
    }

    #[test]
    fn the_clock_reads_the_graviton_capture_frequency() {
        let c = VanillaState::parse(REAL).unwrap().clock().unwrap();
        assert_eq!(c.cntfrq, 121_875_000, "captured on a Graviton host");
        assert!(c.cntvct > 0 && c.host_realtime_ns > 0);
    }

    #[test]
    fn recording_a_new_capture_instant_changes_only_the_instant() {
        let original = VanillaState::parse(REAL).unwrap();
        let mut advanced = original.clone();
        advanced.set_capture_instant(999_111_222, 1_800_000_000_000_000_000).unwrap();

        assert_eq!(
            original.changed_paths(&advanced),
            vec![
                "snapshot_data/state/clock/cntvct".to_string(),
                "snapshot_data/state/clock/host_realtime_ns".to_string(),
            ],
            "advancing the clock must not disturb anything else"
        );
        let c = advanced.clock().unwrap();
        assert_eq!(c.cntvct, 999_111_222);
        assert_eq!(
            c.cntfrq, 121_875_000,
            "the frequency is the guest's latched belief, not ours to change"
        );
    }

    #[test]
    fn a_vcpu_register_write_lands_and_disturbs_nothing_else() {
        let original = VanillaState::parse(REAL).unwrap();
        let mut advanced = original.clone();

        let mut v = advanced.vcpu(1).unwrap();
        assert!(v.set_core_reg(OFF_X0, 0xdead_beef_0000_0001));
        assert!(v.set_core_reg(OFF_PC, 0xffff_8000_0800_0000));
        advanced.set_vcpu(1, &v).unwrap();

        // The diff descends to the byte, so the intended blast radius can be
        // stated exactly: x0 occupies core_regs[0..8] and pc core_regs[256..264].
        // Nothing else in the 57 KB document may move -- not vCPU 0, not a
        // device, not the memory map.
        const PREFIX: &str = "snapshots/cpu-manager/snapshots/1/snapshot_data/state/Kvm/core_regs/";
        let changed = original.changed_paths(&advanced);
        assert!(!changed.is_empty(), "the write did not land at all");
        for p in &changed {
            let idx: usize = p
                .strip_prefix(PREFIX)
                .unwrap_or_else(|| panic!("{p} is outside vCPU 1's core registers"))
                .parse()
                .unwrap();
            assert!(
                (OFF_X0..OFF_X0 + 8).contains(&idx) || (OFF_PC..OFF_PC + 8).contains(&idx),
                "byte {idx} is neither x0 nor pc"
            );
        }

        let back = advanced.vcpu(1).unwrap();
        assert_eq!(back.x(0), Some(0xdead_beef_0000_0001));
        assert_eq!(back.pc(), 0xffff_8000_0800_0000);
        assert_eq!(
            back.x(1),
            original.vcpu(1).unwrap().x(1),
            "a neighbouring register moved"
        );
    }

    /// A core-register write must not disturb the bytes around it.
    ///
    /// The floating-point block is the observable stand-in: `set_core_reg`
    /// cannot address it (wrong width, wrong alignment, and no `ONE_REG` core
    /// id lands there), and the fixture carries non-zero bytes in it, so it is
    /// the one region of `core_regs` this test can watch for collateral
    /// damage. `set_core_bytes` writes it deliberately -- that is a different
    /// call, and is what the exporter uses.
    #[test]
    fn a_register_write_carries_state_this_module_cannot_name() {
        let s = VanillaState::parse(REAL).unwrap();
        let before = s.vcpu(0).unwrap();
        let fp_before = before.core_bytes()[336..].to_vec();
        assert!(
            fp_before.iter().any(|b| *b != 0),
            "the fixture's vCPU 0 must carry non-zero floating-point state, \
             or this test cannot observe it being lost"
        );

        let mut s2 = s.clone();
        let mut v = s2.vcpu(0).unwrap();
        assert!(v.set_core_reg(OFF_PC, 0x1234));
        s2.set_vcpu(0, &v).unwrap();

        assert_eq!(
            s2.vcpu(0).unwrap().core_bytes()[336..],
            fp_before[..],
            "state this module does not model was destroyed by a write"
        );
    }

    #[test]
    fn system_registers_decode_as_id_value_pairs() {
        let v = VanillaState::parse(REAL).unwrap().vcpu(0).unwrap();
        assert_eq!(v.sys_regs.len(), 256, "every capture we hold carries 256");

        // Every KVM aarch64 ONE_REG id carries the architecture marker in its
        // top byte and a size class below it. A stride or endianness that has
        // drifted produces ids that do not, which is what makes this an
        // assertion about the decode rather than about the fixture.
        for r in &v.sys_regs {
            assert_eq!(
                r.id >> 56,
                0x60,
                "id {:#x} is not a KVM_REG_ARM64 id, so the decode is wrong",
                r.id
            );
            let size = (r.id >> 48) & 0x00ff;
            assert!(
                size == 0x30 || size == 0x20,
                "id {:#x} has size class {size:#x}, expected u64 or u32",
                r.id
            );
        }

        // The census, measured rather than assumed: this field is not purely
        // system registers, and code that treats it as such will be surprised.
        let coproc = |c: u64| v.sys_regs.iter().filter(|r| (r.id & 0x0fff_0000) >> 16 == c).count();
        assert_eq!(coproc(0x13), 234, "ARM64_SYSREG");
        assert_eq!(coproc(0x11), 14, "DEMUX cache-level descriptors");
    }

    #[test]
    fn the_curated_system_register_list_is_not_grown_by_a_write() {
        let mut s = VanillaState::parse(REAL).unwrap();
        let mut v = s.vcpu(0).unwrap();
        let known = v.sys_regs[0].id;

        assert!(v.set_sys_reg(known, 0x5555), "a carried register is writable");
        assert!(
            !v.set_sys_reg(0xdead_0000_0000_0000, 1),
            "a register the capture does not carry must be refused, not appended"
        );
        s.set_vcpu(0, &v).unwrap();
        assert_eq!(s.vcpu(0).unwrap().sys_reg(known), Some(0x5555));

        v.sys_regs.push(SysReg { id: 1, value: 2 });
        assert!(
            s.set_vcpu(0, &v).is_err(),
            "changing the shape of the register set must be refused"
        );
    }

    #[test]
    fn a_truncated_register_block_is_refused_by_name() {
        let mut doc: Value = serde_json::from_slice(REAL).unwrap();
        let slot = doc["snapshots"]["cpu-manager"]["snapshots"]["0"]["snapshot_data"]["state"]
            .as_str()
            .unwrap()
            .to_string();
        let mut inner: Value = serde_json::from_str(&slot).unwrap();
        let core = inner["Kvm"]["core_regs"].as_array().unwrap().clone();
        inner["Kvm"]["core_regs"] = Value::Array(core[..core.len() - 8].to_vec());
        doc["snapshots"]["cpu-manager"]["snapshots"]["0"]["snapshot_data"]["state"] =
            Value::String(serde_json::to_string(&inner).unwrap());

        let s = VanillaState::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let err = s.vcpu(0).unwrap_err().to_string();
        assert!(
            err.contains("core_regs") && err.contains("856"),
            "the refusal must name the field and what it found, got: {err}"
        );
    }

    #[test]
    fn changed_paths_sees_a_difference_inside_an_embedded_document() {
        let original = VanillaState::parse(REAL).unwrap();
        let mut other = original.clone();
        let mut mem = other.embedded(&["memory-manager"]).unwrap();
        mem["boot_ram"] = Value::from(1u64);
        other.set_embedded(&["memory-manager"], &mem).unwrap();

        assert_eq!(
            original.changed_paths(&other),
            vec!["snapshots/memory-manager/snapshot_data/state/boot_ram".to_string()],
            "a change buried inside a quoted document must be visible"
        );
    }

    #[test]
    fn a_capture_that_is_not_json_is_refused() {
        assert!(VanillaState::parse(b"not json").is_err());
        assert!(VanillaState::parse(b"[1,2,3]").is_err());
    }

    /// A misaligned core-register write must be refused, not truncated.
    ///
    /// `core_regs` is a flat `struct kvm_regs`, so an offset that is not a
    /// multiple of 8 straddles two registers: the write would land half in one
    /// and half in its neighbour, corrupting a register nobody named. Refusing
    /// is the only safe answer, and `set_core_reg` is the sole writer of the
    /// block, so this check is the only thing standing there.
    #[test]
    fn a_misaligned_core_register_write_is_refused() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let doc = VanillaState::parse(&bytes).unwrap();
        let id = doc.vcpu_ids()[0];
        let mut v = doc.vcpu(id).unwrap();
        let before = v.core_bytes().to_vec();
        for bad in [1usize, 4, 7, OFF_PC + 1, CORE_REGS_LEN - 4] {
            assert!(!v.set_core_reg(bad, 0xdead_beef), "offset {bad} must be refused");
        }
        assert!(v.set_core_reg(OFF_PC, 0xdead_beef), "an aligned offset must still work");
        assert!(!v.set_core_reg(CORE_REGS_LEN, 1), "past the end must be refused");
        let mut want = before.clone();
        want[OFF_PC..OFF_PC + 8].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        assert_eq!(v.core_bytes(), &want[..], "a refused write must leave no trace");
    }
}
