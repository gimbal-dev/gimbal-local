//! Software GICv3 **distributor + redistributor** register model (M-USGIC, #81).
//!
//! When Gimbal rehydrates a stock ITS/LPI snapshot it runs with no Apple managed
//! GIC (`hv_gic`); the whole GICv3 lives in userspace. The per-vCPU CPU interface
//! (`ICC_*_EL1`) is modelled in [`crate::hvf::mod`]; this module models the two
//! MMIO-mapped pieces the guest programs:
//!
//! * the **distributor** (GICD, VM-global) — SPI enable/priority/group/config and
//!   affinity routing (`GICD_IROUTER`); and
//! * the **redistributor** (GICR, per-vCPU) — the SGI/PPI frame plus the LPI
//!   control registers (`GICR_CTLR.EnableLPIs`, `PROPBASER`, `PENDBASER`).
//!
//! A guest access to these frames traps to the VMM as a stage-2 data abort
//! (`EC=0x24`) and is dispatched here. The model tracks per-INTID state so an
//! asserted SPI/PPI can be routed to the right vCPU's CPU interface (respecting
//! enable + group), and it can be **seeded from a captured KVM GIC dump** so a
//! resumed guest sees the interrupt configuration it had when snapshotted.
//!
//! Register offsets follow the GICv3 architecture (and match the managed-GIC
//! capture map in `translate.rs`): GICD_CTLR 0x0000, IGROUPR 0x0080, ISENABLER
//! 0x0100, ICENABLER 0x0180, ISPENDR 0x0200, ICPENDR 0x0280, IPRIORITYR 0x0400,
//! ICFGR 0x0C00, IROUTER 0x6000; GICR SGI-frame ISENABLER0 at SGI_BASE+0x0100.

/// First SPI INTID (0..15 SGIs, 16..31 PPIs, 32.. SPIs).
pub const SPI_BASE: u32 = 32;
/// Highest architected SPI INTID + 1 we model (1020; 1020..1023 are special).
pub const INTID_LIMIT: u32 = 1020;

/// `GICD_PIDR2` / `GICR_PIDR2` value advertising GICv3.
///
/// Linux reads these and masks `GIC_PIDR2_ARCH_MASK` (0xf0); 0x30 is v3 and
/// 0x40 is v4. Anything else and it declines to drive the controller at all:
/// `"no distributor detected, giving up"` from `gic_validate_dist_version`, or
/// `-ENODEV` from `gic_iterate_rdists`.
pub const GIC_PIDR2_ARCH_GICV3: u32 = 0x30;

use serde::{Deserialize, Serialize};

/// The GICv3 distributor (GICD): VM-global SPI configuration + routing.
#[derive(Clone, Serialize, Deserialize)]
pub struct Distributor {
    /// GICD_CTLR (group enables + ARE). Stored; ARE_NS is forced on for GICv3.
    ctlr: u32,
    /// Number of INTIDs modelled (multiple of 32, e.g. 256). SGIs+PPIs+SPIs.
    num_irqs: u32,
    /// Per-INTID enable bit (`GICD_ISENABLER`/`ICENABLER`).
    enabled: Vec<bool>,
    /// Per-INTID Group-1 bit (`GICD_IGROUPR`); true = Group1 (the normal case).
    group1: Vec<bool>,
    /// Per-INTID priority byte (`GICD_IPRIORITYR`; lower = higher priority).
    priority: Vec<u8>,
    /// Per-INTID pending bit (`GICD_ISPENDR`/`ICPENDR`).
    pending: Vec<bool>,
    /// Per-INTID edge/level config (`GICD_ICFGR`; true = edge-triggered).
    edge: Vec<bool>,
    /// Per-SPI affinity route (`GICD_IROUTER`, 64-bit). Index by INTID.
    router: Vec<u64>,
}

impl Distributor {
    /// A distributor sized for `num_irqs` interrupts (rounded up to a multiple of
    /// 32, clamped to `[32, INTID_LIMIT]`). All interrupts start disabled,
    /// Group1, priority 0xA0 — the reset-ish state a fresh guest reprograms.
    pub fn new(num_irqs: u32) -> Self {        let n = num_irqs.next_multiple_of(32).clamp(32, INTID_LIMIT) as usize;
        Self {
            ctlr: 0,
            num_irqs: n as u32,
            enabled: vec![false; n],
            group1: vec![true; n],
            priority: vec![0xA0; n],
            pending: vec![false; n],
            edge: vec![false; n],
            router: vec![0; n],
        }
    }

    /// Number of modelled INTIDs.
    pub fn num_irqs(&self) -> u32 {
        self.num_irqs
    }

    /// Is `intid` enabled at the distributor?
    pub fn is_enabled(&self, intid: u32) -> bool {
        (intid as usize) < self.enabled.len() && self.enabled[intid as usize]
    }

    /// The target redistributor/vCPU affinity (Aff3.2.1.0) for an SPI, or `None`
    /// if `GICD_IROUTER.IRM` selects "any" (1-of-N) — the caller picks a target.
    pub fn spi_target_affinity(&self, intid: u32) -> Option<u64> {
        let r = *self.router.get(intid as usize)?;
        if r & (1 << 31) != 0 {
            None // Interrupt Routing Mode = 1: any participating PE.
        } else {
            Some(r & 0xff_00ff_ffff) // Aff3[39:32] | Aff2.1.0[23:0]
        }
    }

    /// Read a 32-bit distributor register at byte `offset` within the GICD frame.
    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            0x0000 => self.ctlr | (1 << 4) | (1 << 5), // ARE_S | ARE_NS
            // GICD_TYPER: ITLinesNumber = num_irqs/32 - 1; no security ext.
            0x0004 => (self.num_irqs / 32) - 1,
            0x0008 => 0x0000_43B0, // GICD_IIDR (Arm implementer, GICv3-ish)
            // GICD_PIDR2, architecture revision in bits[7:4].
            //
            // This is how Linux decides whether there is a GICv3 here at all:
            // `gic_validate_dist_version` reads it, masks 0xf0, and gives up
            // with "no distributor detected" on anything but 0x30 (v3) or
            // 0x40 (v4). Returning 0 from the catch-all made a cold guest
            // abandon its interrupt controller — and, because the timer hangs
            // off it, its clock too.
            //
            // A rehydrated guest never read this: it validated the distributor
            // on the KVM host before capture and does not re-probe on resume.
            // So the first thing a cold boot did was ask the one question this
            // model had never been asked.
            0xFFE8 => GIC_PIDR2_ARCH_GICV3,
            _ if (0x0080..0x0100).contains(&offset) => {
                self.read_bitmap(&self.group1, offset - 0x0080)
            }
            _ if (0x0100..0x0180).contains(&offset) => {
                self.read_bitmap(&self.enabled, offset - 0x0100)
            }
            _ if (0x0180..0x0200).contains(&offset) => {
                self.read_bitmap(&self.enabled, offset - 0x0180)
            }
            _ if (0x0200..0x0280).contains(&offset) => {
                self.read_bitmap(&self.pending, offset - 0x0200)
            }
            _ if (0x0280..0x0300).contains(&offset) => {
                self.read_bitmap(&self.pending, offset - 0x0280)
            }
            _ if (0x0400..0x0800).contains(&offset) => self.read_priority(offset - 0x0400),
            // GICD_ICFGR<n>. `write_cfgr` has always stored this; nothing had
            // ever read it, so it fell to the catch-all and returned 0.
            //
            // Linux does not write this register and move on. `gic_configure_irq`
            // writes it and then **reads it back and compares**, returning
            // -EINVAL on a mismatch — so a model that accepts the write and
            // reports 0 fails every edge-triggered IRQ with
            // `genirq: Setting trigger mode 1 for irq N failed`. The device then
            // gets no `request_irq`, and for the PL011 that means no tty: printk
            // still works (its console write path is polled), but userspace has
            // nowhere to write at all. A whole running system, minus its output.
            //
            // Third register in this model whose only job was to be read back,
            // in a model that until cold boot had only ever been written to.
            _ if (0x0C00..0x0D00).contains(&offset) => self.read_cfgr(offset - 0x0C00),
            _ if (0x6000..0x8000).contains(&offset) => {
                // GICD_IROUTER<n> low word (64-bit reg; caller reads +0 / +4).
                let intid = ((offset - 0x6000) / 8) as usize;
                self.router.get(intid).copied().unwrap_or(0) as u32
            }
            _ => 0,
        }
    }

    /// Write a 32-bit distributor register at byte `offset`.
    pub fn write(&mut self, offset: u64, value: u32) {
        match offset {
            0x0000 => self.ctlr = value,
            _ if (0x0080..0x0100).contains(&offset) => {
                { self.write_bitmap_set(BitField::Group, offset - 0x0080, value, true); }
            }
            // ISENABLER: write-1-to-set.
            _ if (0x0100..0x0180).contains(&offset) => {
                { self.write_bitmap_set(BitField::Enable, offset - 0x0100, value, true); }
            }
            // ICENABLER: write-1-to-clear.
            _ if (0x0180..0x0200).contains(&offset) => {
                { self.write_bitmap_set(BitField::Enable, offset - 0x0180, value, false); }
            }
            // ISPENDR / ICPENDR.
            _ if (0x0200..0x0280).contains(&offset) => {
                { self.write_bitmap_set(BitField::Pending, offset - 0x0200, value, true); }
            }
            _ if (0x0280..0x0300).contains(&offset) => {
                { self.write_bitmap_set(BitField::Pending, offset - 0x0280, value, false); }
            }
            _ if (0x0400..0x0800).contains(&offset) => { self.write_priority(offset - 0x0400, value); }
            _ if (0x0C00..0x0D00).contains(&offset) => { self.write_cfgr(offset - 0x0C00, value); }
            _ if (0x6000..0x8000).contains(&offset) => {
                let intid = ((offset - 0x6000) / 8) as usize;
                if intid < self.router.len() {
                    // 64-bit register written as two 32-bit halves.
                    let hi = (offset - 0x6000) % 8 >= 4;
                    let cur = self.router[intid];
                    self.router[intid] = if hi {
                        (cur & 0x0000_0000_ffff_ffff) | ((value as u64) << 32)
                    } else {
                        (cur & 0xffff_ffff_0000_0000) | value as u64
                    };
                }
            }
            _ => {}
        }
    }

    /// Assert an SPI/PPI as pending. Returns `true` if it is enabled (and so
    /// should be forwarded to a CPU interface); the caller resolves the target
    /// vCPU via [`Self::spi_target_affinity`].
    pub fn assert_spi(&mut self, intid: u32) -> bool {
        let i = intid as usize;
        if i >= self.pending.len() {
            return false;
        }
        self.pending[i] = true;
        self.enabled[i]
    }

    /// Clear an SPI's pending bit (e.g. after it has been acknowledged).
    pub fn clear_pending(&mut self, intid: u32) {
        if let Some(p) = self.pending.get_mut(intid as usize) {
            *p = false;
        }
    }

    fn read_bitmap(&self, bits: &[bool], reg_off: u64) -> u32 {
        let base = (reg_off / 4 * 32) as usize;
        let mut v = 0u32;
        for b in 0..32 {
            if base + b < bits.len() && bits[base + b] {
                v |= 1 << b;
            }
        }
        v
    }

    fn write_bitmap_set(&mut self, field: BitField, reg_off: u64, value: u32, set: bool) {
        let base = (reg_off / 4 * 32) as usize;
        for b in 0..32 {
            if value & (1 << b) == 0 {
                continue;
            }
            let idx = base + b;
            let target = match field {
                BitField::Enable => self.enabled.get_mut(idx),
                BitField::Group => self.group1.get_mut(idx),
                BitField::Pending => self.pending.get_mut(idx),
            };
            if let Some(bit) = target {
                *bit = set;
            }
        }
    }

    fn read_priority(&self, reg_off: u64) -> u32 {
        let base = reg_off as usize; // one byte per INTID
        let mut v = 0u32;
        for b in 0..4 {
            if base + b < self.priority.len() {
                v |= (self.priority[base + b] as u32) << (b * 8);
            }
        }
        v
    }

    fn write_priority(&mut self, reg_off: u64, value: u32) {
        let base = reg_off as usize;
        for b in 0..4 {
            if let Some(p) = self.priority.get_mut(base + b) {
                *p = (value >> (b * 8)) as u8;
            }
        }
    }

    /// Read a `GICD_ICFGR<n>` / `GICR_ICFGR<n>` word back out of `edge`.
    ///
    /// Two bits per INTID, of which only bit 1 is writable (edge=1, level=0);
    /// bit 0 is RES0 on GICv3. Mirrors [`Self::write_cfgr`] exactly, because
    /// the caller that matters is a read-back verifying its own write.
    fn read_cfgr(&self, reg_off: u64) -> u32 {
        let base = (reg_off / 4 * 16) as usize;
        let mut v = 0u32;
        for i in 0..16 {
            if self.edge.get(base + i).copied().unwrap_or(false) {
                v |= 1 << (i * 2 + 1);
            }
        }
        v
    }

    fn write_cfgr(&mut self, reg_off: u64, value: u32) {
        // 2 bits per INTID; bit1 of each field = edge(1)/level(0).
        let base = (reg_off / 4 * 16) as usize;
        for i in 0..16 {
            if let Some(e) = self.edge.get_mut(base + i) {
                *e = (value >> (i * 2 + 1)) & 1 != 0;
            }
        }
    }

    /// Seed per-INTID state from captured KVM `(offset, u64)` distributor
    /// registers (the same `(GICD offset, value)` pairs the managed-GIC path
    /// restores). Recognises the enable/group/priority/config/router registers so
    /// a resumed guest keeps its interrupt configuration.
    pub fn seed_from_kvm(&mut self, regs: &[(u32, u64)]) {
        for &(off, val) in regs {
            let off = off as u64;
            let v = val as u32;
            match off {
                0x0000 => self.ctlr = v,
                _ if (0x0080..0x0100).contains(&off) => {
                    { self.seed_bitmap(BitField::Group, off - 0x0080, v); }
                }
                _ if (0x0100..0x0180).contains(&off) => {
                    { self.seed_bitmap(BitField::Enable, off - 0x0100, v); }
                }
                _ if (0x0400..0x0800).contains(&off) => { self.write_priority(off - 0x0400, v); }
                _ if (0x0C00..0x0D00).contains(&off) => { self.write_cfgr(off - 0x0C00, v); }
                _ if (0x6000..0x8000).contains(&off) => {
                    let intid = ((off - 0x6000) / 8) as usize;
                    if intid < self.router.len() {
                        self.router[intid] = val; // full 64-bit affinity
                    }
                }
                _ => {}
            }
        }
    }

    fn seed_bitmap(&mut self, field: BitField, reg_off: u64, value: u32) {
        let base = (reg_off / 4 * 32) as usize;
        for b in 0..32 {
            let on = value & (1 << b) != 0;
            let idx = base + b;
            let target = match field {
                BitField::Enable => self.enabled.get_mut(idx),
                BitField::Group => self.group1.get_mut(idx),
                BitField::Pending => self.pending.get_mut(idx),
            };
            if let Some(bit) = target {
                *bit = on;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum BitField {
    Enable,
    Group,
    Pending,
}

impl Default for Distributor {
    /// A 256-INTID distributor (SGIs + PPIs + 224 SPIs) — the default shape a
    /// vCPU starts with before the snapshot's captured state is seeded in.
    fn default() -> Self {
        Self::new(256)
    }
}

/// The per-vCPU GICv3 redistributor (GICR): the SGI/PPI frame plus the LPI
/// control registers. Enough state so a guest can enable LPIs and program its
/// PPIs (e.g. the virtual timer PPI 27) without faulting, and so we can honour
/// `GICR_CTLR.EnableLPIs` when deciding whether an LPI is deliverable.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Redistributor {
    /// GICR_CTLR (bit0 = EnableLPIs).
    ctlr: u32,
    /// GICR_WAKER (ProcessorSleep bit1 / ChildrenAsleep bit2).
    waker: u32,
    /// GICR_PROPBASER — LPI configuration table base (enable + priority).
    propbaser: u64,
    /// GICR_PENDBASER — LPI pending table base.
    pendbaser: u64,
    /// SGI/PPI enable bits (INTID 0..31) from the SGI-frame `GICR_ISENABLER0`.
    ppi_enabled: [bool; 32],
    /// Raw `GICR_ICFGR0/1` words for INTIDs 0..31 (SGIs and PPIs), stored so a
    /// read-back sees what was written. Same defect as `GICD_ICFGR`: Linux's
    /// `gic_configure_irq` verifies its own write, so an unstored PPI trigger
    /// config fails `request_percpu_irq` — which is how the architected timer
    /// gets its PPI. Not consulted for delivery: PPIs are asserted explicitly.
    ///
    /// Reset value has SGIs (0..15) edge-triggered, which is architectural and
    /// what Linux expects to read before it writes anything.
    pub ppi_cfg: [u32; 2],

    /// Which vCPU this redistributor belongs to.
    ///
    /// Reported in `GICR_TYPER`, where Linux matches the affinity in bits
    /// [63:32] against the running CPU's `MPIDR_EL1` to decide which
    /// redistributor is *its* redistributor. Getting this wrong on a secondary
    /// core is not a subtle degradation: `gic_populate_rdist` fails, and the
    /// CPU comes up with no per-CPU interrupt controller and therefore no
    /// timer.
    cpu_id: u32,
    /// Whether this is the last redistributor in the contiguous region.
    ///
    /// `gic_iterate_rdists` walks the region until it sees this bit, so
    /// setting it on every redistributor (as this model used to) means Linux
    /// stops after the first one and never finds the others.
    last: bool,
}

/// Byte offset of the SGI/PPI frame within a redistributor (RD_base + 64 KiB).
pub const GICR_SGI_OFFSET: u64 = 0x1_0000;

impl Redistributor {
    pub fn new() -> Self {
        Self::for_cpu(0, true)
    }

    /// A redistributor that knows which vCPU it belongs to, and whether it is
    /// the last in the region.
    ///
    /// Both facts are only ever *read* by a guest that is discovering its
    /// interrupt controller for the first time, which is why a rehydrated
    /// guest — which discovered it on a KVM host, before capture — never
    /// noticed they were wrong. See the field docs.
    pub fn for_cpu(cpu_id: u32, last: bool) -> Self {
        Self {
            // Boot state: not asleep so the guest can bring it up.
            waker: 0,
            // SGIs are always edge-triggered: bit 1 of each 2-bit field.
            ppi_cfg: [0xaaaa_aaaa, 0],
            cpu_id,
            last,
            ..Default::default()
        }
    }

    /// Set which vCPU this redistributor serves and whether it is the last in
    /// the contiguous region. See the field docs; both are discovery-time
    /// facts, so this is applied at construction rather than mid-run.
    pub fn set_identity(&mut self, cpu_id: u32, last: bool) {
        self.cpu_id = cpu_id;
        self.last = last;
    }

    /// True once the guest has set `GICR_CTLR.EnableLPIs` — a precondition for
    /// any LPI to be deliverable to this vCPU.
    pub fn lpis_enabled(&self) -> bool {
        self.ctlr & 1 != 0
    }

    /// Guest physical address of the LPI configuration table (`PROPBASER`),
    /// masked to its base field, or `None` if unset.
    pub fn prop_table(&self) -> Option<u64> {
        let base = self.propbaser & 0x0000_ffff_ffff_f000;
        (base != 0).then_some(base)
    }

    pub fn is_ppi_enabled(&self, intid: u32) -> bool {
        (intid as usize) < 32 && self.ppi_enabled[intid as usize]
    }

    /// Read a 32-bit redistributor register at byte `offset` within the whole
    /// (RD_base + SGI-frame) redistributor window.
    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            0x0000 => self.ctlr,
            0x0004 => 0x0000_43B0, // GICR_IIDR
            // GICR_TYPER low word: PLPIS(bit0)=1 (supports LPIs), Last(bit4)
            // only on the final redistributor, Processor_Number in [23:8].
            0x0008 => {
                let last = if self.last { 1 << 4 } else { 0 };
                (1 << 0) | last | ((self.cpu_id & 0xffff) << 8)
            }
            // GICR_TYPER high word: this redistributor's affinity, which Linux
            // matches against the running CPU's MPIDR_EL1 to find its own.
            0x000C => self.cpu_id,
            // GICR_ICFGR0/1 in the SGI frame: see `ppi_cfg`.
            o if o == GICR_SGI_OFFSET + 0x0C00 => self.ppi_cfg[0],
            o if o == GICR_SGI_OFFSET + 0x0C04 => self.ppi_cfg[1],
            0x0014 => self.waker,
            0x0070 => self.propbaser as u32,
            0x0074 => (self.propbaser >> 32) as u32,
            0x0078 => self.pendbaser as u32,
            0x007C => (self.pendbaser >> 32) as u32,
            // SGI frame: GICR_ISENABLER0 / ICENABLER0.
            o if o == GICR_SGI_OFFSET + 0x0100 || o == GICR_SGI_OFFSET + 0x0180 => {
                let mut v = 0;
                for (b, en) in self.ppi_enabled.iter().enumerate() {
                    if *en {
                        v |= 1 << b;
                    }
                }
                v
            }
            // GICR_PIDR2 in the RD_base frame: architecture revision in
            // bits[7:4]. `gic_iterate_rdists` refuses the whole controller
            // with -ENODEV when this is not v3 or v4.
            0xFFE8 => GIC_PIDR2_ARCH_GICV3,
            _ => 0,
        }
    }

    /// Write a 32-bit redistributor register at byte `offset`.
    pub fn write(&mut self, offset: u64, value: u32) {
        match offset {
            0x0000 => self.ctlr = value,
            // GICR_WAKER: writing ProcessorSleep=0 clears ChildrenAsleep too.
            0x0014 => self.waker = if value & 0b10 == 0 { 0 } else { value },
            // GICR_ICFGR0 is RO for SGIs (they are always edge); ICFGR1 carries
            // the PPI trigger config the timer driver sets.
            o if o == GICR_SGI_OFFSET + 0x0C04 => self.ppi_cfg[1] = value,
            0x0070 => self.propbaser = (self.propbaser & !0xffff_ffff) | value as u64,
            0x0074 => self.propbaser = (self.propbaser & 0xffff_ffff) | ((value as u64) << 32),
            0x0078 => self.pendbaser = (self.pendbaser & !0xffff_ffff) | value as u64,
            0x007C => self.pendbaser = (self.pendbaser & 0xffff_ffff) | ((value as u64) << 32),
            o if o == GICR_SGI_OFFSET + 0x0100 => self.set_ppi_bits(value, true),
            o if o == GICR_SGI_OFFSET + 0x0180 => self.set_ppi_bits(value, false),
            _ => {}
        }
    }

    fn set_ppi_bits(&mut self, value: u32, set: bool) {
        for b in 0..32 {
            if value & (1 << b) != 0 {
                self.ppi_enabled[b] = set;
            }
        }
    }

    /// Seed from captured KVM redistributor `(offset, u64)` registers.
    pub fn seed_from_kvm(&mut self, regs: &[(u32, u64)]) {
        for &(off, val) in regs {
            self.write(off as u64, val as u32);
            // Some registers are 64-bit; also apply the high word.
            match off as u64 {
                0x0070 | 0x0078 => self.write(off as u64 + 4, (val >> 32) as u32),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isenabler_sets_and_icenabler_clears() {
        let mut d = Distributor::new(256);
        // Enable SPI 32 (word 1, bit 0) via GICD_ISENABLER1 @ 0x0104.
        d.write(0x0104, 1);
        assert!(d.is_enabled(32));
        assert_eq!(d.read(0x0104) & 1, 1);
        // Disable via GICD_ICENABLER1 @ 0x0184.
        d.write(0x0184, 1);
        assert!(!d.is_enabled(32));
    }

    #[test]
    fn assert_spi_reports_enabled() {
        let mut d = Distributor::new(256);
        assert!(!d.assert_spi(40), "disabled SPI must not forward");
        d.write(0x0104, 1 << 8); // enable SPI 40 (word1 bit8)
        assert!(d.assert_spi(40), "enabled SPI forwards");
    }

    #[test]
    fn priority_round_trips() {
        let mut d = Distributor::new(256);
        // GICD_IPRIORITYR for INTID 32 is at 0x0400 + 32 = 0x0420, byte 0.
        d.write(0x0420, 0x0000_00F0);
        assert_eq!(d.read(0x0420) & 0xff, 0xF0);
    }

    #[test]
    fn irouter_is_64bit_and_reports_affinity() {
        let mut d = Distributor::new(256);
        // GICD_IROUTER32 @ 0x6000 + 32*8 = 0x6100. Route to affinity 0x1.
        d.write(0x6100, 0x1);
        d.write(0x6104, 0x0);
        assert_eq!(d.spi_target_affinity(32), Some(0x1));
        // IRM (bit31) = any.
        d.write(0x6104, 0);
        d.write(0x6100, 1 << 31);
        assert_eq!(d.spi_target_affinity(32), None);
    }

    #[test]
    fn typer_reports_itlines() {
        let d = Distributor::new(256);
        assert_eq!(d.read(0x0004), 256 / 32 - 1);
    }

    #[test]
    fn seed_from_kvm_restores_enable_and_priority() {
        let mut d = Distributor::new(256);
        // ISENABLER1 (0x0104) bit0 -> SPI 32 enabled; IPRIORITYR32 (0x0420) 0xF0.
        d.seed_from_kvm(&[(0x0104, 0b1), (0x0420, 0xF0)]);
        assert!(d.is_enabled(32));
        assert_eq!(d.read(0x0420) & 0xff, 0xF0);
    }

    #[test]
    fn redistributor_enable_lpis_and_propbaser() {
        let mut r = Redistributor::new();
        assert!(!r.lpis_enabled());
        r.write(0x0070, 0x1234_5000); // PROPBASER low
        r.write(0x0074, 0x0000_00AB); // PROPBASER high
        r.write(0x0000, 1); // GICR_CTLR.EnableLPIs
        assert!(r.lpis_enabled());
        assert_eq!(r.prop_table(), Some(0x0000_00AB_1234_5000 & 0x0000_ffff_ffff_f000));
    }

    #[test]
    fn redistributor_waker_wakes() {
        let mut r = Redistributor::new();
        r.write(0x0014, 0b10); // set ProcessorSleep
        assert_eq!(r.read(0x0014) & 0b10, 0b10);
        r.write(0x0014, 0); // clear ProcessorSleep -> ChildrenAsleep clears too
        assert_eq!(r.read(0x0014), 0);
    }

    #[test]
    fn redistributor_ppi_enable_via_sgi_frame() {
        let mut r = Redistributor::new();
        // Enable PPI 27 (the virtual timer) via SGI-frame ISENABLER0.
        r.write(GICR_SGI_OFFSET + 0x0100, 1 << 27);
        assert!(r.is_ppi_enabled(27));
        r.write(GICR_SGI_OFFSET + 0x0180, 1 << 27);
        assert!(!r.is_ppi_enabled(27));
    }

    /// Every register in this group exists only to be *discovered* — read by a
    /// guest that has not yet decided this hardware is here. A rehydrated guest
    /// never reads any of them, so all four were wrong until the first cold
    /// boot asked. Together they cost a guest its interrupt controller, its
    /// clocksource and its console.

    /// `gic_validate_dist_version` masks GICD_PIDR2 with 0xf0 and accepts only
    /// 0x30 (GICv3) or 0x40 (GICv4). Anything else is
    /// "no distributor detected, giving up" — and the architected timer, which
    /// hangs off the GIC, goes with it.
    #[test]
    fn gicd_pidr2_says_gicv3_or_linux_gives_up() {
        let d = Distributor::new(256);
        assert_eq!(d.read(0xFFE8) & 0xf0, 0x30);
    }

    /// `gic_iterate_rdists` returns -ENODEV on a redistributor whose PIDR2 does
    /// not announce v3, before it ever looks at the affinity.
    #[test]
    fn gicr_pidr2_says_gicv3_too() {
        assert_eq!(Redistributor::for_cpu(0, true).read(0xFFE8) & 0xf0, 0x30);
    }

    /// `gic_populate_rdist` matches `GICR_TYPER[63:32]` against the CPU's
    /// `MPIDR_EL1` affinity, and `gic_iterate_rdists` stops walking the region
    /// at the first redistributor claiming `Last`. Reporting cpu 0 / last=true
    /// from every frame — as `Redistributor::new()` did — means cores 1..n find
    /// no redistributor at all and the walk stops before reaching them.
    #[test]
    fn gicr_typer_carries_this_cpus_identity_and_only_the_last_says_last() {
        const LAST: u32 = 1 << 4;
        for (cpu, last) in [(0u32, false), (1, false), (2, true)] {
            let r = Redistributor::for_cpu(cpu, last);
            assert_eq!(r.read(0x000C), cpu, "GICR_TYPER affinity for cpu {cpu}");
            assert_eq!(
                r.read(0x0008) & LAST != 0,
                last,
                "GICR_TYPER.Last for cpu {cpu}"
            );
        }
    }

    /// `gic_configure_irq` writes GICD_ICFGR and then **reads it back and
    /// compares**, failing the IRQ with -EINVAL on a mismatch. The write had
    /// always been stored; nothing had ever read it, so it returned 0 from the
    /// catch-all and every edge-triggered IRQ failed with
    /// `genirq: Setting trigger mode 1 for irq N failed`. For the PL011 that
    /// meant no `request_irq`, so no tty — printk still worked, because its
    /// console path is polled, and userspace had nowhere to write at all.
    #[test]
    fn gicd_icfgr_reads_back_what_was_written() {
        let mut d = Distributor::new(256);
        // SPI 33 edge-triggered: INTID 33 is field 1 of GICD_ICFGR2 (16 per reg,
        // 33 / 16 = 2), so bit 1*2+1 = 3.
        let reg = 0x0C00 + (33 / 16) * 4;
        let val = 1 << 3;
        d.write(reg, val);
        assert_eq!(d.read(reg) & val, val, "GICD_ICFGR must survive a read-back");
        // ...and the neighbouring INTIDs must stay level-triggered, so the
        // read-back is reporting per-INTID state and not just echoing the word.
        assert_eq!(d.read(reg), val);
    }

    /// Same read-back, in the SGI frame, for the PPI the architected timer uses.
    #[test]
    fn gicr_icfgr_reads_back_and_sgis_report_edge() {
        let mut r = Redistributor::for_cpu(0, true);
        // GICR_ICFGR0 covers INTIDs 0..15 — the SGIs, which are architecturally
        // always edge-triggered and read-only.
        assert_eq!(r.read(GICR_SGI_OFFSET + 0x0C00), 0xaaaa_aaaa);
        // PPI 27 is field 11 of ICFGR1, so bit 11*2+1 = 23.
        let val = 1 << 23;
        r.write(GICR_SGI_OFFSET + 0x0C04, val);
        assert_eq!(r.read(GICR_SGI_OFFSET + 0x0C04), val);
    }
}
