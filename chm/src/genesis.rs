// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Originating a lineage on the Mac: synthesizing a Cloud Hypervisor
//! `state.json` for a machine **`chm` itself cold-booted** (#341).
//!
//! Today the Mac is a receive-only node. `chm run` rehydrates a capture that
//! came from a KVM host, and [`crate::vanilla_export`] can push a lineage back
//! to the cloud -- but only a lineage that came *from* the cloud, because it
//! works by patching this lineage's own ancestor. A guest cold-booted here has
//! no ancestor, so it can never be suspended, forked, resumed or exported. This
//! module is the missing first link: the description of a machine that never
//! had a parent.
//!
//! # Why synthesis is legitimate here, when [`crate::vanilla_export`] says it is not
//!
//! That module argues, correctly, against synthesizing a `state.json`:
//!
//! > Synthesising a `state.json` instead would mean writing every field this
//! > build happens to model and zeroing every field it does not -- and the
//! > fields it does not model are exactly the ones nobody would notice were
//! > missing.
//!
//! The argument is about **unknown unknowns**, and it is unanswerable for the
//! case it addresses: rewriting a 57 KB AWS capture describing eleven devices
//! that some other VMM configured, on hardware we have never seen. There, a
//! field we failed to anticipate is a field that really exists and really
//! matters, and patching keeps the parent's answer to every question we did not
//! know to ask.
//!
//! Here there is no parent and there are no unknown unknowns, because there is
//! nothing in the guest that `chm` did not itself construct. `chm create`
//! chooses the memory layout, places the PL011 and the virtio-mmio devices,
//! sizes the GIC's interrupt width and starts the vCPUs. A field this build does
//! not model is not a field we are dropping -- it is hardware the guest does not
//! have.
//!
//! The concrete form of that argument is one call. `chm create` builds its VM
//! with `rehydrate::prepare_cold_usgic_vm(hv, ram_base, ram_size, host_ptr,
//! vcpus, COLD_NR_IRQS)`, so the machine is **one contiguous RAM region** at a
//! base `chm` picked, a vCPU count `chm` was asked for, and a distributor built
//! by `Distributor::new(COLD_NR_IRQS)`. Beside it sit a PL011, a PL031 and the
//! virtio-mmio devices, each at a window `chm`'s own device tree named.
//! `guest_ram_mappings` is therefore not a lossy summary of something
//! complicated: it is the complete description of a layout with one region in
//! it.
//!
//! **That reasoning is the boundary of this module, and it is narrow.** This may
//! only ever describe a machine `chm` cold-booted. Pointing it at a foreign
//! capture -- anything with a `state.json` of its own -- reinstates every
//! unknown unknown the quote above is about, with none of the protection
//! patching gives. Use [`crate::vanilla_export`] for that; it exists for exactly
//! that case.
//!
//! # What this describes, and what it does not
//!
//! The consumer this is proven against is
//! [`hypervisor::hvf::rehydrate::Snapshot::from_state_json`] -- `chm`'s own
//! reader, and the specification the emitted document is written to. It reads
//! four things: the guest RAM layout, the GIC dump, the per-vCPU KVM register
//! blocks, and the clock. All four are written from measured state.
//!
//! The RAM layout is taken as [`MemMapping`]s and rendered as given, rather than
//! being described some other way and reconstructed here, because it has two
//! consumers and they must not be able to disagree. `checkpoint::write_checkpoint`
//! uses the same slice to decide **where each byte of the RAM dump goes**
//! (`dump_guest_ram` seeks to `file_offset` and writes `size` bytes read from
//! `gpa`); the document this module writes tells a future reader **where each
//! byte came from**. A second description of that layout -- scalars this module
//! turned back into mappings, or a parallel struct with the same four fields --
//! is the one bug class no test of a writer against its own reader can see: the
//! capture parses, resumes, and puts the guest's memory in the wrong place. One
//! value, two consumers, no opportunity to drift.
//!
//! It is **not** yet a document stock cloud-hypervisor could restore, and this
//! module does not pretend otherwise. A stock restore also reads per-device
//! nodes (the serial, each virtio device, the ITS tables) and the rest of the
//! memory-manager's state, none of which this build has ever had to model
//! because nothing in this tree has ever read them. Those are named in
//! [`Genesis::warnings`] rather than implied by silence, in the style
//! [`crate::vanilla_export`] set: the reader of an artefact should not have to
//! discover its boundary by resuming it.

// Nothing outside this module's own tests calls it yet, by design: it is the
// foundation layer of #341 and the cold-boot path that will call it is separate
// work in the same issue. Scoped to this module so it cannot hide dead code
// anywhere else, and it goes away with the first caller.
#![allow(dead_code)]

use std::collections::BTreeMap;

use hypervisor::hvf::VcpuHvfState;
use hypervisor::hvf::checkpoint::CheckpointState;
use hypervisor::hvf::rehydrate::{MemMapping, Snapshot};
use hypervisor::hvf::translate::{self, gic_ingest, kvm_ingest, lower_to_kvm};
use hypervisor::hvf::virtio::devmgr::SerialRegs;
use serde_json::{Map, Value, json};

use crate::vanilla::{CORE_REGS_LEN, VanillaState};

/// A synthesized capture description, plus everything a caller needs to say
/// honestly what it holds.
pub(crate) struct Genesis {
    /// The `state.json` bytes.
    pub bytes: Vec<u8>,
    /// State this synthesis could not carry, each named with its consequence.
    /// Never empty: a cold-booted machine always has at least the device nodes
    /// a stock restore would want.
    pub warnings: Vec<String>,
    /// One line per vCPU, read back out of the document after it was written --
    /// the same cheap human check [`crate::vanilla_export`] prints, and for the
    /// same reason: a misaligned offset shows up as a `pc` of zero or a wild
    /// address at a glance, where a count of written registers does not.
    pub vcpu_summaries: Vec<String>,
    /// The interrupt width the emitted GIC dump describes.
    ///
    /// Read out of the machine's own distributor, not taken from the caller:
    /// `COLD_NR_IRQS` reached `Distributor::new` at boot, so the model already
    /// holds it and a second statement of the width could only disagree.
    pub num_irq: u32,
}

/// Synthesize a `state.json` for the cold-booted machine `state` describes.
///
/// `ram` is the guest's memory layout, rendered into `guest_ram_mappings`
/// exactly as given -- the same slice `checkpoint::write_checkpoint` lays the
/// RAM dump out with. It is deliberately not derived from anything simpler
/// here; see the module documentation for why a second description of this
/// layout is the one mistake nothing downstream can detect.
///
/// `cntfrq` is the counter frequency the guest latched at boot -- on this path
/// the host's, since a cold guest reads the real `CNTFRQ_EL0`; it is a parameter
/// rather than a call to `hypervisor::hvf::host_counter_hz` so this module stays
/// pure data and can be tested for a machine other than the one running the
/// test.
///
/// `serial` is the PL011 configuration the guest programmed, read back off the
/// live device model. It is a parameter for the same reason `ram` is: nothing
/// in a `CheckpointState` carries it, because the software GIC and the vCPUs
/// are all a *suspend* has ever needed. Getting it wrong is quiet -- a guest
/// restored with `imsc` at its reset value executes perfectly and never
/// receives a keystroke, because its driver unmasked the receive interrupt
/// before the capture and does not do so again.
///
/// Every refusal below is a case where writing the document anyway would produce
/// an artefact that reads back as a machine nobody asked for.
pub(crate) fn synthesize(
    state: &CheckpointState,
    ram: &[MemMapping],
    cntfrq: u64,
    serial: SerialRegs,
    serial_intid: u32,
) -> Result<Genesis, String> {
    if ram.is_empty() {
        return Err(
            "a capture with no guest RAM describes no machine: pass the \
                    cold guest's memory layout."
                .to_string(),
        );
    }
    if state.vcpus.is_empty() {
        return Err("this checkpoint captured no vCPUs, so there is no machine \
                    to describe."
            .to_string());
    }
    if cntfrq == 0 {
        return Err("a capture must state the counter frequency its guest \
                    latched at boot. A zero declines the correction on every \
                    later restore, which is how a guest ends up running 5x \
                    slow (see docs/graviton-acid-test-results.md)."
            .to_string());
    }
    let Some(host_realtime_ns) = state.host_realtime_ns else {
        return Err("this checkpoint does not record when it was taken, so the \
                    capture could not say either. A guest restored from it \
                    would wake in the past: repository metadata, TLS validity \
                    and token expiry all read as being from the future."
            .to_string());
    };
    let Some(cntvct) = state.reference_cntvct() else {
        return Err("this checkpoint carries no CNTVCT_EL0, so the capture \
                    cannot state the guest's virtual counter at the instant it \
                    was taken."
            .to_string());
    };

    let num_vcpus = state.vcpus.len();
    let mut warnings = Vec::new();

    // --- the GIC ------------------------------------------------------------
    let gic = synthesize_gic(state, num_vcpus, &mut warnings)?;

    // --- guest RAM ----------------------------------------------------------
    // Rendered as given. The only work here is refusing a layout that would
    // dump wrong, because `dump_guest_ram` will seek to these offsets and trust
    // them, and a checkpoint whose RAM is misplaced still parses and resumes.
    for (i, m) in ram.iter().enumerate() {
        if m.size == 0 {
            return Err(format!(
                "guest RAM region {i} (slot {}) is zero bytes: a region with no \
                 bytes describes nothing and would leave a hole in the dump.",
                m.slot
            ));
        }
        let gpa_end = m.gpa.checked_add(m.size).ok_or_else(|| {
            format!(
                "guest RAM region {i} (slot {}) runs past the end of the \
                 guest-physical address space.",
                m.slot
            )
        })?;
        let file_end = m.file_offset.checked_add(m.size).ok_or_else(|| {
            format!(
                "guest RAM region {i} (slot {}) runs past the end of the \
                 memory-ranges file.",
                m.slot
            )
        })?;
        for (j, other) in ram.iter().enumerate().take(i) {
            // Sizes are non-zero and the ends are checked above, so a plain
            // interval overlap is the whole test in both spaces.
            if m.gpa < other.gpa + other.size && other.gpa < gpa_end {
                return Err(format!(
                    "guest RAM regions {j} and {i} overlap in guest-physical \
                     space ({:#x}+{:#x} and {:#x}+{:#x}): one address would be \
                     restored from two places.",
                    other.gpa, other.size, m.gpa, m.size
                ));
            }
            if m.file_offset < other.file_offset + other.size && other.file_offset < file_end {
                return Err(format!(
                    "guest RAM regions {j} and {i} overlap in memory-ranges \
                     (offset {}+{} and {}+{}): the dump would hold one region's \
                     bytes where the other's belong.",
                    other.file_offset, other.size, m.file_offset, m.size
                ));
            }
        }
    }
    let mappings: Vec<Value> = ram
        .iter()
        .map(|m| {
            json!({
                "gpa": m.gpa,
                "size": m.size,
                "file_offset": m.file_offset,
                "slot": m.slot,
            })
        })
        .collect();

    // --- the vCPUs ----------------------------------------------------------
    let mut cpu_nodes = Map::new();
    let mut sysreg_counts = Vec::with_capacity(num_vcpus);
    for (id, vcpu) in state.vcpus.iter().enumerate() {
        let (node, sysregs) = synthesize_vcpu(&vcpu.state)?;
        sysreg_counts.push(sysregs);
        cpu_nodes.insert(id.to_string(), node);
    }

    let doc = json!({
        "snapshots": {
            "memory-manager": leaf(&json!({ "guest_ram_mappings": mappings }))?,
            "device-manager": {
                "snapshots": {
                    "gic-v3-its": leaf(&json!({
                        "Kvm": {
                            "dist": gic.dist,
                            "rdist": gic.rdist,
                            "icc": gic.icc,
                        }
                    }))?,
                    // The field names are cloud-hypervisor's, not ours, and
                    // three of the six differ from the register they hold
                    // (`int_enabled`, `lcr`, `ifl`). They are written here
                    // and read by `devmgr::parse_serial_state`; the
                    // round-trip test is what holds the two together, since
                    // a rename on one side alone produces a node that
                    // parses into silent defaults rather than an error.
                    "__serial": leaf(&json!({
                        "int_enabled": serial.imsc,
                        "cr": serial.cr,
                        "lcr": serial.lcr_h,
                        "ibrd": serial.ibrd,
                        "fbrd": serial.fbrd,
                        "ifl": serial.ifls,
                    }))?,
                },
                // cloud-hypervisor rebuilds its device manager from a
                // configuration on restore and so re-derives the console's
                // interrupt line rather than reading it back; a capture from it
                // leaves `__serial.resources` empty. There is no configuration
                // to rebuild from for a guest whose device tree we wrote, so the
                // line is recorded here, in upstream's own `Resource::LegacyIrq`
                // shape. Without it a restoring VMM has to guess, and a guess
                // that is wrong delivers every keystroke to an interrupt no
                // device owns: the guest runs perfectly and the console is deaf.
                "snapshot_data": {
                    "state": embed(&json!({
                        "device_tree": {
                            "__serial": {
                                "id": "__serial",
                                "resources": [{ "LegacyIrq": serial_intid }],
                                "children": [],
                            },
                            "gic-v3-its": {
                                "id": "gic-v3-its",
                                "resources": [],
                                "children": [],
                            },
                        },
                        "device_id_cnt": 0,
                    }))?,
                },
            },
            "cpu-manager": {
                "snapshots": Value::Object(cpu_nodes),
                "snapshot_data": { "state": "{}" },
            },
        },
        "snapshot_data": {
            "state": embed(&json!({
                "clock": {
                    "cntvct": cntvct,
                    "host_realtime_ns": host_realtime_ns,
                    "cntfrq": cntfrq,
                }
            }))?,
        },
    });
    // Built as text, then handed on as bytes: a `state.json` is UTF-8 by
    // construction here, and going through a string means no conversion that
    // could fail on the way back out.
    let text = serde_json::to_string(&doc).map_err(|e| format!("serialize state.json: {e}"))?;

    // The document is only worth anything if the reader that will restore it
    // accepts it, so ask that reader rather than trusting the writer. This runs
    // on every synthesis, not only in tests: a capture that cannot be parsed is
    // a failure at the moment of writing, and finding out at restore time means
    // finding out when the machine that could have been re-captured is gone.
    let parsed = Snapshot::from_state_json(&text)
        .map_err(|e| format!("the capture this wrote is not one chm can read back: {e}"))?;
    if parsed.num_vcpus() as usize != num_vcpus {
        return Err(format!(
            "wrote {num_vcpus} vCPU(s) but the document reads back as {}",
            parsed.num_vcpus()
        ));
    }
    // The layout is the field where a mistake is both invisible and
    // unrecoverable, so it is compared as a whole value against the slice the
    // RAM dump will be written from -- in production, not only in tests.
    if parsed.mem_mappings != ram {
        return Err(format!(
            "the memory layout written is not the one that will be dumped: \
             wrote {ram:?}, reads back as {:?}",
            parsed.mem_mappings
        ));
    }
    let bytes = text.into_bytes();

    // Read the vCPU summaries back out of the written bytes, not off the values
    // that produced them, so the lines describe what was actually stored.
    let doc_back = VanillaState::parse(&bytes).map_err(|e| format!("read back state.json: {e}"))?;
    let mut vcpu_summaries = Vec::with_capacity(num_vcpus);
    for id in doc_back.vcpu_ids() {
        let v = doc_back
            .vcpu(id)
            .map_err(|e| format!("read back vCPU {id}: {e}"))?;
        vcpu_summaries.push(format!(
            "vcpu {id}: pc={:#018x} pstate={:#010x} sp={:#018x} sp_el1={:#018x} \
             elr_el1={:#018x} x0={:#018x} mp_state={} sys_regs={} core_regs={}B",
            v.pc(),
            v.pstate(),
            v.sp(),
            v.sp_el1(),
            v.elr_el1(),
            v.x(0).unwrap_or(0),
            v.mp_state,
            v.sys_regs.len(),
            v.core_bytes().len(),
        ));
    }

    warnings.push(format!(
        "each vCPU carries {} system register(s). A KVM capture of the same \
         machine carries ~234: the rest are registers Hypervisor.framework does \
         not expose, so they are absent rather than invented. A restore leaves \
         them at the receiving VMM's own values.",
        sysreg_counts.iter().max().copied().unwrap_or(0)
    ));
    if !serial.receives_by_interrupt() {
        warnings.push(format!(
            "the console's receive interrupt is masked (UARTIMSC = {:#x}). The \
             capture carries that faithfully, but a guest restored from it will \
             not be woken by a keystroke unless it polls -- so an interactive \
             session may look wedged when it is only deaf.",
            serial.imsc
        ));
    }
    warnings.push(
        "this describes only the machine chm builds: guest RAM, the GIC, the \
         vCPUs and the serial port. Stock cloud-hypervisor also reads a node \
         per virtio device, the ITS tables and the rest of the memory-manager's \
         state, none of which this build models -- so the capture is restorable \
         by chm and not yet by the cloud."
            .to_string(),
    );

    Ok(Genesis {
        bytes,
        warnings,
        vcpu_summaries,
        num_irq: gic.num_irq,
    })
}

/// The three KVM GIC register dumps, assembled for every vCPU.
struct GicDumps {
    dist: Vec<u32>,
    rdist: Vec<u32>,
    icc: Vec<u32>,
    num_irq: u32,
}

/// Serialize the software GIC every cold-booted `chm` guest runs on into the
/// three KVM dumps a capture carries.
///
/// The lowering itself lives in `translate::gic_ingest`, next to the reads it
/// inverts, so the writer and the reader cannot be changed apart. What is
/// decided here is the *assembly*: which model is VM-global, and the two-pass
/// interleave a multi-vCPU redistributor dump uses.
fn synthesize_gic(
    state: &CheckpointState,
    num_vcpus: usize,
    warnings: &mut Vec<String>,
) -> Result<GicDumps, String> {
    let mut dists = Vec::with_capacity(num_vcpus);
    for id in 0..num_vcpus {
        let usgic = state.usgic_for(id).ok_or_else(|| {
            format!(
                "this checkpoint carries no software-GIC state for vCPU {id}. \
                 Genesis describes a machine chm cold-booted, which always runs \
                 the userspace GIC; a checkpoint of a rehydrated guest on the \
                 managed GIC is not one this can originate a lineage from."
            )
        })?;
        dists.push(usgic);
    }

    // The distributor is VM-global -- `UsgicCheckpoint` carries a clone of it
    // per vCPU, so disagreement between those clones means the capture is not
    // describing one machine.
    let dist_model = &dists[0].dist;
    let num_irq = dist_model.num_irqs();
    for (id, u) in dists.iter().enumerate().skip(1) {
        if u.dist.num_irqs() != num_irq {
            return Err(format!(
                "vCPU 0 sees a {num_irq}-interrupt distributor but vCPU {id} \
                 sees {}. One VM has one distributor; this checkpoint does not \
                 describe one machine.",
                u.dist.num_irqs()
            ));
        }
    }
    if state.num_irq != 0 && state.num_irq != num_irq {
        return Err(format!(
            "the checkpoint declares {} interrupt lines but its distributor \
             models {num_irq}.",
            state.num_irq
        ));
    }
    let dist = gic_ingest::dist_from_softgic(dist_model).ok_or_else(|| {
        format!(
            "a {num_irq}-interrupt distributor has no KVM dump length, so no \
             reader could recover its width."
        )
    })?;

    // cloud-hypervisor serializes the redistributors in two passes: every
    // vCPU's RD_base words, then every vCPU's SGI-frame words. Concatenating
    // per-vCPU slices instead would hand every secondary core the boot CPU's
    // frame -- the M20 bug, from the writing side.
    let rd_words = gic_ingest::redist_rd_base_words();
    let per_vcpu: Vec<Vec<u32>> = dists
        .iter()
        .map(|u| gic_ingest::redist_from_softgic(&u.redist))
        .collect();
    let mut rdist = Vec::with_capacity(num_vcpus * gic_ingest::redist_words_per_vcpu());
    for slice in &per_vcpu {
        rdist.extend_from_slice(&slice[..rd_words]);
    }
    for slice in &per_vcpu {
        rdist.extend_from_slice(&slice[rd_words..]);
    }

    // The per-vCPU CPU interface. Every vCPU's vector must be the same length,
    // because a reader recovers the per-vCPU slice by dividing the total.
    let mut icc = Vec::new();
    let mut icc_per_vcpu = None;
    for (id, vcpu) in state.vcpus.iter().enumerate() {
        let v = gic_ingest::icc_from_hvf(&vcpu.state.gic_icc).ok_or_else(|| {
            format!(
                "vCPU {id} captured no ICC_CTLR_EL1, so the length of its \
                 CPU-interface dump is unknowable."
            )
        })?;
        match icc_per_vcpu {
            None => icc_per_vcpu = Some(v.len()),
            Some(n) if n != v.len() => {
                return Err(format!(
                    "vCPU {id}'s CPU-interface dump is {} words but vCPU 0's is \
                     {n}. A reader splits the dump evenly, so unequal vectors \
                     would give every vCPU but the first the wrong registers.",
                    v.len()
                ));
            }
            Some(_) => {}
        }
        icc.extend_from_slice(&v);
    }

    // What the software models genuinely have no state for. Said here, by name,
    // rather than left as zeros a reader would take for measurements.
    warnings.push(
        "GICD_ISACTIVER/ICACTIVER and the redistributors' GICR_IGROUPR0, \
         GICR_I{S,C}PENDR0, GICR_I{S,C}ACTIVER0 and GICR_IPRIORITYR0..7 are \
         written as zero: the software GIC holds no such state, tracking active \
         interrupts as a per-vCPU priority stack instead."
            .to_string(),
    );
    if dists
        .iter()
        .any(|u| !u.pending.is_empty() || !u.active_stack().is_empty())
    {
        warnings.push(
            "interrupts already forwarded to a CPU interface (the pending queue \
             and the active-priority stack) are not carried: the KVM dump format \
             has no field for a CPU interface's in-flight state. Distributor \
             pending bits ARE carried."
                .to_string(),
        );
    }
    warnings.push(
        "the CPU interface carries the five ICC registers the software GIC \
         models (PMR, BPR1, CTLR, SRE, IGRPEN1); the active-priority registers \
         are written as zero."
            .to_string(),
    );

    Ok(GicDumps {
        dist,
        rdist,
        icc,
        num_irq,
    })
}

/// Build one vCPU's `cpu-manager` node from its live HVF state, returning the
/// node and how many system registers it carries.
///
/// The HVF -> KVM lowering is [`translate::lower_to_kvm`], reused rather than
/// rewritten for the reason [`crate::vanilla_export`] gives: two implementations
/// of one ABI eventually disagree, and the disagreement is invisible until a
/// guest resumes wrong.
fn synthesize_vcpu(hvf: &VcpuHvfState) -> Result<(Value, usize), String> {
    let kvm = lower_to_kvm(hvf);

    // `struct kvm_regs`, built by writing each lowered register at the offset
    // its ONE_REG id names. Zero-initialised: unlike a patched ancestor there
    // is no earlier machine whose bytes would be the better answer, and a
    // register a cold guest never set really is zero.
    let mut core = vec![0u8; CORE_REGS_LEN];
    for &(id, value) in &kvm.core {
        let off = translate::kvm_core_reg_offset(id).ok_or_else(|| {
            format!("lowered core register {id:#018x} names no offset in kvm_regs")
        })?;
        put(&mut core, off, &value.to_le_bytes())?;
    }
    // The SIMD&FP file travels beside the id list because no 64-bit ONE_REG id
    // can name a 128-bit vector register. `None` means this HVF state predates
    // the capture of it, in which case reset values are all there ever was.
    if let Some(fp) = &kvm.fp {
        for (i, v) in fp.vregs.iter().enumerate() {
            put(&mut core, translate::kvm_fp_vreg_offset(i), v)?;
        }
        put(&mut core, translate::OFF_FPSR, &fp.fpsr.to_le_bytes())?;
        put(&mut core, translate::OFF_FPCR, &fp.fpcr.to_le_bytes())?;
    }

    // Each entry is a 16-byte `kvm_one_reg`: the id, then the value in `addr`.
    // Sorted by id so two runs over the same machine produce identical bytes;
    // `lower_to_kvm` preserves HVF's capture order, which is not a promise the
    // format makes.
    let sys: BTreeMap<u64, u64> = kvm.sys.iter().copied().collect();
    let sys_regs: Vec<Value> = sys
        .iter()
        .map(|(id, value)| {
            let mut pair = [0u8; 16];
            pair[..8].copy_from_slice(&id.to_le_bytes());
            pair[8..].copy_from_slice(&value.to_le_bytes());
            bytes_value(&pair)
        })
        .collect();
    let count = sys_regs.len();

    // A vCPU PSCI-parked at capture must come back parked. The constant comes
    // from `kvm_ingest`, beside the read that consumes it: on aarch64 STOPPED
    // is 5, and the 3 that looks right is x86's HALTED.
    let mp_state = kvm_ingest::kvm_mp_state_for(hvf.mp_state_running);

    let inner = json!({
        "Kvm": {
            "mp_state": bytes_value(&mp_state.to_le_bytes()),
            "core_regs": bytes_value(&core),
            "sys_regs": Value::Array(sys_regs),
        }
    });
    Ok((leaf(&inner)?, count))
}

/// Write `src` at `off` in a `kvm_regs` block, refusing a run that would leave
/// it rather than growing a block that is a fixed-size C struct.
fn put(block: &mut [u8], off: usize, src: &[u8]) -> Result<(), String> {
    let end = off
        .checked_add(src.len())
        .filter(|e| *e <= block.len())
        .ok_or_else(|| {
            format!(
                "register at offset {off} ({} bytes) does not fit in a {}-byte \
                 kvm_regs",
                src.len(),
                block.len()
            )
        })?;
    block[off..end].copy_from_slice(src);
    Ok(())
}

/// A byte array as Cloud Hypervisor serializes a C struct: one JSON number per
/// byte.
fn bytes_value(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|x| Value::from(*x)).collect())
}

/// Quote a document into the JSON *string* Cloud Hypervisor stores a
/// component's state as. The format is a document containing more documents,
/// quoted; see [`crate::vanilla`].
fn embed(v: &Value) -> Result<String, String> {
    serde_json::to_string(v).map_err(|e| format!("serialize embedded state: {e}"))
}

/// A leaf snapshot node: no children, and its state quoted into a string.
fn leaf(state: &Value) -> Result<Value, String> {
    Ok(json!({
        "snapshots": {},
        "snapshot_data": { "state": embed(state)? },
    }))
}

#[cfg(test)]
mod tests {
    use hypervisor::hvf::checkpoint::{UsgicCheckpoint, VcpuCheckpoint};
    use hypervisor::hvf::softgic::{Distributor, GICR_SGI_OFFSET, Redistributor};
    use hypervisor::hvf::{VcpuFpState, VcpuHvfState, rehydrate};

    use super::*;

    // Encodings named once here. They are not asserted against `hvf::ffi` from
    // this crate because that module is private to the hypervisor crate; they
    // are pinned where they can be: `translate::gic_ingest`'s
    // `the_icc_encodings_match_the_hvf_ffi_names` asserts the five ICC values
    // against `hvf::ffi` directly, and `SYSREG_CNTVCT_EL0` is pinned by
    // `a_machine_that_cannot_be_described_is_refused_by_name` -- removing that
    // register must make `reference_cntvct` return `None`, which only happens if
    // the value here is the one the hypervisor crate reads.
    const ICC_PMR_EL1: u16 = 0xc230;
    const ICC_BPR1_EL1: u16 = 0xc663;
    const ICC_CTLR_EL1: u16 = 0xc664;
    const ICC_SRE_EL1: u16 = 0xc665;
    const ICC_IGRPEN1_EL1: u16 = 0xc667;
    const SYSREG_CNTVCT_EL0: u16 = 0xdf02;
    const SYSREG_SCTLR_EL1: u16 = 0xc080;
    const SYSREG_VBAR_EL1: u16 = 0xc600;
    const SYSREG_SP_EL0: u16 = 0xc208;
    const SYSREG_ELR_EL1: u16 = 0xc201;

    /// A vCPU state with every field set to something recognisable, so a
    /// register that lands in the wrong place is visible as the wrong value
    /// rather than as a plausible one.
    fn a_vcpu(id: u64, running: bool) -> VcpuHvfState {
        let mut gpr = [0u64; 31];
        for (i, r) in gpr.iter_mut().enumerate() {
            *r = 0x1000_0000_0000_0000 + id * 0x100 + i as u64;
        }
        VcpuHvfState {
            gpr,
            pc: 0x4000_0000 + id * 0x1000,
            cpsr: 0x3c5,
            sp_el1: 0xffff_8000_0001_0000 + id,
            sysregs: vec![
                (SYSREG_SCTLR_EL1, 0x30d0_1805),
                (SYSREG_VBAR_EL1, 0xffff_8000_0800_0000),
                (SYSREG_SP_EL0, 0xffff_0000_0002_0000 + id),
                (SYSREG_ELR_EL1, 0xffff_8000_0003_0000 + id),
                (SYSREG_CNTVCT_EL0, 0x0000_0001_2345_6789 + id),
            ],
            gic_icc: vec![
                (ICC_PMR_EL1, 0xf0),
                (ICC_BPR1_EL1, 0x6),
                (ICC_CTLR_EL1, 0x0),
                (ICC_SRE_EL1, 0x7),
                (ICC_IGRPEN1_EL1, 0x1),
            ],
            fp: Some(VcpuFpState {
                vregs: (0..32u8).map(|i| [i.wrapping_add(1); 16]).collect(),
                fpsr: 0x10,
                fpcr: 0x0060_0000,
            }),
            mp_state_running: running,
        }
    }

    fn a_usgic(cpu: u32, last: bool) -> UsgicCheckpoint {
        let mut dist = Distributor::new(256);
        dist.write(0x0104, 1); // GICD_ISENABLER1: SPI 32 enabled
        dist.write(0x0420, 0x0000_00f0); // GICD_IPRIORITYR: SPI 32 priority
        dist.write(0x6100, 0x0000_0003); // GICD_IROUTER32 low
        dist.write(0x6104, 0x0000_0007); // GICD_IROUTER32 high (Aff3)
        let mut redist = Redistributor::for_cpu(cpu, last);
        // Enable the vtimer PPI on cpu 0 and a different PPI on cpu 1, so a
        // dump that handed every core the boot CPU's frame is visible.
        redist.write(GICR_SGI_OFFSET + 0x0100, 1 << (27 - u64::from(cpu)));
        redist.write(0x0070, 0xabcd_e000);
        redist.write(0x0074, 0x0000_0042);
        UsgicCheckpoint {
            dist,
            redist,
            pending: Vec::new(),
            active: None,
            active_stack: Vec::new(),
        }
    }

    fn a_checkpoint(n: usize) -> CheckpointState {
        CheckpointState {
            version: 1,
            vcpus: (0..n)
                .map(|id| VcpuCheckpoint {
                    state: a_vcpu(id as u64, id == 0),
                    rdist: Vec::new(),
                })
                .collect(),
            gic_dist: Vec::new(),
            num_irq: 256,
            host_realtime_ns: Some(1_800_000_000_000_000_000),
            usgic: None,
            usgic_cpus: (0..n).map(|id| a_usgic(id as u32, id + 1 == n)).collect(),
        }
    }

    // A two-region layout: enough that a reader taking the second region's
    // bytes from the first region's offset is visible. Written as `MemMapping`
    // because that is the type the RAM dump is laid out from -- the test would
    // not be testing the real path if it built anything else.
    const RAM: &[MemMapping] = &[
        MemMapping {
            slot: 0,
            gpa: 0x4000_0000,
            size: 0x2000_0000,
            file_offset: 0,
        },
        MemMapping {
            slot: 1,
            gpa: 0x1_0000_0000,
            size: 0x1000_0000,
            file_offset: 0x2000_0000,
        },
    ];

    /// The console's interrupt line, as a fixture.
    ///
    /// Deliberately neither `coldboot::PL011_IRQ` (33, what origination really
    /// writes) nor `console::DEFAULT_SERIAL_SPI` (43, what a reader falls back
    /// to when a capture is silent). A test that passed either could go green
    /// against a writer that dropped the value entirely and a reader that
    /// guessed, which is the exact failure this field exists to end.
    const SERIAL_LINE: u32 = 37;

    /// A PL011 as a Linux guest leaves it once a getty has opened `ttyAMA0`:
    /// RXIM|RTIM unmasked, port enabled, 8n1 with FIFOs.
    ///
    /// Every field holds a different value on purpose. Six registers written
    /// through six differently-named JSON keys is exactly the shape where a
    /// swapped pair round-trips perfectly and means something else entirely, so
    /// the fixture is chosen so a swap cannot pass.
    fn a_serial() -> SerialRegs {
        SerialRegs {
            imsc: 0x50,
            cr: 0x301,
            lcr_h: 0x70,
            ibrd: 0x1a,
            fbrd: 0x03,
            ifls: 0x12,
        }
    }

    fn synthesized(n: usize) -> Genesis {
        synthesize(&a_checkpoint(n), RAM, 24_000_000, a_serial(), SERIAL_LINE)
            .expect("a cold machine synthesizes")
    }

    fn parsed(g: &Genesis) -> Snapshot {
        Snapshot::from_state_json(std::str::from_utf8(&g.bytes).expect("utf-8"))
            .expect("the real reader accepts the synthesized capture")
    }

    /// The property that closes the loop: everything put in comes back out of
    /// the real consumer. Not the writer's own reader -- `from_state_json` is
    /// the function that will restore this capture on a Mac, so agreeing with
    /// it is the only agreement worth having.
    #[test]
    fn a_synthesized_capture_reads_back_as_the_machine_it_describes() {
        let ckpt = a_checkpoint(2);
        let g = synthesize(&ckpt, RAM, 24_000_000, a_serial(), SERIAL_LINE).expect("synthesizes");
        let snap = parsed(&g);

        // --- memory ---------------------------------------------------------
        assert_eq!(
            snap.mem_mappings, RAM,
            "the layout in the document must be the layout the RAM dump is \
             written from"
        );

        // --- clock ----------------------------------------------------------
        assert_eq!(snap.captured_cntfrq, Some(24_000_000));
        assert_eq!(snap.captured_realtime_ns, ckpt.host_realtime_ns);

        // --- GIC width ------------------------------------------------------
        assert_eq!(snap.num_irq, 256);
        assert_eq!(g.num_irq, 256);

        // --- vCPUs ----------------------------------------------------------
        assert_eq!(snap.vcpus.len(), 2);
        for (id, back) in snap.vcpus.iter().enumerate() {
            let want = a_vcpu(id as u64, id == 0);
            assert_eq!(back.gpr, want.gpr, "vcpu {id} GPRs");
            assert_eq!(back.pc, want.pc, "vcpu {id} pc");
            assert_eq!(back.cpsr, want.cpsr, "vcpu {id} pstate");
            assert_eq!(back.sp_el1, want.sp_el1, "vcpu {id} sp_el1");
            assert_eq!(
                back.mp_state_running, want.mp_state_running,
                "vcpu {id} mp_state: a parked core must come back parked"
            );
            let got: BTreeMap<u16, u64> = back.sysregs.iter().copied().collect();
            for (enc, value) in &want.sysregs {
                assert_eq!(got.get(enc), Some(value), "vcpu {id} sysreg {enc:#06x}");
            }
            assert_eq!(back.fp, want.fp, "vcpu {id} SIMD&FP file");
            let icc: BTreeMap<u16, u64> = back.gic_icc.iter().copied().collect();
            for (enc, value) in &want.gic_icc {
                assert_eq!(icc.get(enc), Some(value), "vcpu {id} ICC {enc:#06x}");
            }
        }
    }

    /// The distributor and each vCPU's own redistributor survive, and the
    /// redistributor dump is interleaved the way cloud-hypervisor writes it --
    /// concatenating per-vCPU slices instead would give vCPU 1 vCPU 0's frame,
    /// which is why the two vCPUs enable different PPIs here.
    #[test]
    fn every_vcpu_gets_its_own_redistributor_back() {
        let g = synthesized(2);
        let snap = parsed(&g);

        let dist: BTreeMap<u32, u64> = gic_ingest::dist_to_hvf(&snap.gic_dist)
            .expect("the distributor dump translates")
            .into_iter()
            .collect();
        assert_eq!(dist.get(&0x0104), Some(&1), "SPI 32 enable");
        assert_eq!(dist.get(&0x0420), Some(&0xf0), "SPI 32 priority");
        assert_eq!(
            dist.get(&0x6100),
            Some(&0x0000_0007_0000_0003),
            "IROUTER32 must carry the whole 64-bit affinity"
        );

        let rd = gic_ingest::redist_rd_base_words();
        let per = gic_ingest::redist_words_per_vcpu();
        let sgi = per - rd;
        assert_eq!(snap.gic_rdist.len(), 2 * per);
        for id in 0..2usize {
            // Reassemble exactly as `Snapshot::rdist_slice` does.
            let mut slice = snap.gic_rdist[id * rd..(id + 1) * rd].to_vec();
            let sgi_base = 2 * rd;
            slice
                .extend_from_slice(&snap.gic_rdist[sgi_base + id * sgi..sgi_base + (id + 1) * sgi]);
            let regs: BTreeMap<u32, u64> = gic_ingest::redist_to_hvf(&slice)
                .expect("the slice translates")
                .into_iter()
                .collect();
            assert_eq!(
                regs.get(&(GICR_SGI_OFFSET as u32 + 0x0100)),
                Some(&(1u64 << (27 - id))),
                "vcpu {id} must get its own PPI enable, not vcpu 0's"
            );
            assert_eq!(slice[2], 0xabcd_e000, "vcpu {id} PROPBASER low");
            assert_eq!(slice[3], 0x0000_0042, "vcpu {id} PROPBASER high");
        }
    }

    /// The shape `chm create` actually builds: one vCPU and the single
    /// contiguous RAM region `prepare_cold_usgic_vm` maps into slot 0. It has no
    /// interleave and no second region to get wrong, which is exactly why it is
    /// worth its own pass through the reader -- it is the machine most captures
    /// this module writes will describe.
    #[test]
    fn a_single_vcpu_machine_synthesizes() {
        let cold = vec![MemMapping {
            slot: 0,
            gpa: 0x4000_0000,
            size: 0x8000_0000,
            file_offset: 0,
        }];
        let g = synthesize(&a_checkpoint(1), &cold, 24_000_000, a_serial(), SERIAL_LINE)
            .expect("synthesizes");
        let snap = parsed(&g);
        assert_eq!(snap.num_vcpus(), 1);
        assert_eq!(snap.mem_mappings, cold);
        assert_eq!(snap.gic_rdist.len(), gic_ingest::redist_words_per_vcpu());
        assert_eq!(snap.vcpus[0].pc, a_vcpu(0, true).pc);
    }

    /// The clock block must be at the path `chm`'s own reader looks for it,
    /// which is a doubly encoded top-level `snapshot_data.state` -- not a node
    /// under `snapshots`. A guest whose capture states no frequency cannot be
    /// time-corrected automatically, which is the 5.08x dilation.
    #[test]
    fn the_clock_is_where_the_reader_looks_for_it() {
        let g = synthesized(1);
        let text = std::str::from_utf8(&g.bytes).unwrap();
        assert_eq!(rehydrate::snapshot_cntfrq(text), Some(24_000_000));
        // And the same block read through the vanilla document view, which is
        // the path an export would use.
        let clock = VanillaState::parse(&g.bytes).unwrap().clock().unwrap();
        assert_eq!(clock.cntfrq, 24_000_000);
        assert_eq!(clock.host_realtime_ns, 1_800_000_000_000_000_000);
        assert_eq!(clock.cntvct, 0x0000_0001_2345_6789);
    }

    /// Refusals. Each names the machine-shaped reason rather than a schema
    /// violation, because the caller is holding a running guest and needs to
    /// know what about it cannot be described.
    /// The refusal a call produced, or a panic naming what should have been
    /// refused. `expect_err` is not available here because `Genesis` carries the
    /// whole document and printing it on failure buries the assertion.
    fn refused(r: Result<Genesis, String>, what: &str) -> String {
        r.err()
            .unwrap_or_else(|| panic!("{what} must be refused, not synthesized"))
    }

    #[test]
    fn a_machine_that_cannot_be_described_is_refused_by_name() {
        let ckpt = a_checkpoint(1);

        let e = refused(
            synthesize(&ckpt, &[], 24_000_000, a_serial(), SERIAL_LINE),
            "no RAM",
        );
        assert!(e.contains("no guest RAM"), "{e}");

        let e = refused(
            synthesize(&ckpt, RAM, 0, a_serial(), SERIAL_LINE),
            "no counter frequency",
        );
        assert!(e.contains("counter frequency"), "{e}");

        let mut no_vcpus = ckpt.clone();
        no_vcpus.vcpus.clear();
        let e = refused(
            synthesize(&no_vcpus, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "no vCPUs",
        );
        assert!(e.contains("no vCPUs"), "{e}");

        let mut no_time = ckpt.clone();
        no_time.host_realtime_ns = None;
        let e = refused(
            synthesize(&no_time, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "no capture time",
        );
        assert!(e.contains("when it was taken"), "{e}");

        let mut no_counter = ckpt.clone();
        no_counter.vcpus[0]
            .state
            .sysregs
            .retain(|(enc, _)| *enc != SYSREG_CNTVCT_EL0);
        let e = refused(
            synthesize(&no_counter, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "no CNTVCT",
        );
        assert!(e.contains("CNTVCT_EL0"), "{e}");

        let mut managed = ckpt.clone();
        managed.usgic_cpus.clear();
        let e = refused(
            synthesize(&managed, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "not a cold machine",
        );
        assert!(e.contains("software-GIC state for vCPU 0"), "{e}");

        let mut no_icc = ckpt.clone();
        no_icc.vcpus[0].state.gic_icc.clear();
        let e = refused(
            synthesize(&no_icc, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "no ICC_CTLR_EL1",
        );
        assert!(e.contains("ICC_CTLR_EL1"), "{e}");

        let mut widths = a_checkpoint(2);
        widths.usgic_cpus[1].dist = Distributor::new(64);
        let e = refused(
            synthesize(&widths, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "two distributors",
        );
        assert!(e.contains("does not describe one machine"), "{e}");

        let mut declared = a_checkpoint(1);
        declared.num_irq = 128;
        let e = refused(
            synthesize(&declared, RAM, 24_000_000, a_serial(), SERIAL_LINE),
            "width disagreement",
        );
        assert!(e.contains("128 interrupt lines"), "{e}");
    }

    /// What could not be carried is reported, not left for a confused guest.
    /// The list is asserted by name because a warnings vector that quietly
    /// emptied would look exactly like a synthesis that lost nothing.
    #[test]
    fn what_cannot_be_carried_is_named() {
        let mut ckpt = a_checkpoint(1);
        ckpt.usgic_cpus[0].pending = vec![33];
        ckpt.usgic_cpus[0].active_stack = vec![27];
        let g = synthesize(&ckpt, RAM, 24_000_000, a_serial(), SERIAL_LINE).expect("synthesizes");
        let all = g.warnings.join("\n");
        for needle in [
            "GICR_IPRIORITYR0..7",
            "active-priority stack",
            "system register(s)",
            "restorable by chm",
        ] {
            assert!(
                all.contains(needle),
                "no warning mentions `{needle}`:\n{all}"
            );
        }
        // A quiescent machine has nothing in flight, so that warning must not
        // fire -- otherwise it is decoration rather than a report.
        let quiet = synthesize(&a_checkpoint(1), RAM, 24_000_000, a_serial(), SERIAL_LINE)
            .expect("synthesizes");
        assert!(
            !quiet.warnings.join("\n").contains("active-priority stack"),
            "an idle machine reported in-flight interrupts it does not have"
        );
    }

    /// The layout goes in and comes back out as the *same value*. This is the
    /// field where a mistake cannot be caught later: `write_checkpoint` lays the
    /// RAM dump out from this slice and the document says where those bytes came
    /// from, so an ordering, offset or units error produces a capture that
    /// parses, resumes, and has the guest's memory in the wrong place.
    ///
    /// The layout is deliberately awkward -- slots not in array order, a gap in
    /// the file, offsets that are not the running sum of the sizes -- because a
    /// writer that reconstructed the offsets from position or re-indexed the
    /// slots would agree with a tidy one and disagree with this.
    #[test]
    fn the_memory_layout_comes_back_as_the_value_it_was_given() {
        let want = vec![
            MemMapping {
                slot: 2,
                gpa: 0x1_0000_0000,
                size: 0x1000_0000,
                file_offset: 0x3000_0000,
            },
            MemMapping {
                slot: 0,
                gpa: 0x4000_0000,
                size: 0x2000_0000,
                file_offset: 0,
            },
            MemMapping {
                slot: 7,
                gpa: 0x8000_0000,
                size: 0x1000,
                file_offset: 0x8000_0000,
            },
        ];
        let g = synthesize(&a_checkpoint(1), &want, 24_000_000, a_serial(), SERIAL_LINE)
            .expect("synthesizes");
        assert_eq!(parsed(&g).mem_mappings, want);
    }

    /// A layout that would dump wrong is refused rather than written. Each of
    /// these produces a capture that parses and resumes, so the write is the
    /// only place the mistake can still be seen.
    #[test]
    fn a_memory_layout_that_would_dump_wrong_is_refused() {
        let ckpt = a_checkpoint(1);
        let one = |slot, gpa, size, file_offset| MemMapping {
            slot,
            gpa,
            size,
            file_offset,
        };

        let empty = vec![one(0, 0x4000_0000, 0, 0)];
        let e = refused(
            synthesize(&ckpt, &empty, 24_000_000, a_serial(), SERIAL_LINE),
            "a zero-byte region",
        );
        assert!(e.contains("zero bytes"), "{e}");

        let overlap_gpa = vec![
            one(0, 0x4000_0000, 0x2000_0000, 0),
            one(1, 0x5000_0000, 0x1000_0000, 0x2000_0000),
        ];
        let e = refused(
            synthesize(&ckpt, &overlap_gpa, 24_000_000, a_serial(), SERIAL_LINE),
            "regions overlapping in guest-physical space",
        );
        assert!(e.contains("overlap in guest-physical space"), "{e}");

        let overlap_file = vec![
            one(0, 0x4000_0000, 0x2000_0000, 0),
            one(1, 0x1_0000_0000, 0x1000_0000, 0x1fff_f000),
        ];
        let e = refused(
            synthesize(&ckpt, &overlap_file, 24_000_000, a_serial(), SERIAL_LINE),
            "regions overlapping in the dump file",
        );
        assert!(e.contains("overlap in memory-ranges"), "{e}");

        let past_gpa_end = vec![one(0, u64::MAX - 0xfff, 0x2000, 0)];
        let e = refused(
            synthesize(&ckpt, &past_gpa_end, 24_000_000, a_serial(), SERIAL_LINE),
            "a region past the end of guest-physical space",
        );
        assert!(e.contains("guest-physical address space"), "{e}");

        let past_file_end = vec![one(0, 0x4000_0000, 0x2000, u64::MAX - 0xfff)];
        let e = refused(
            synthesize(&ckpt, &past_file_end, 24_000_000, a_serial(), SERIAL_LINE),
            "a region past the end of the dump file",
        );
        assert!(e.contains("memory-ranges file"), "{e}");
    }

    /// The summaries are read back out of the written bytes, so they are the
    /// cheapest check a person can make before trusting a capture.
    #[test]
    fn the_summaries_describe_what_was_written() {
        let g = synthesized(2);
        assert_eq!(g.vcpu_summaries.len(), 2);
        assert!(
            g.vcpu_summaries[0].contains(&format!("pc={:#018x}", a_vcpu(0, true).pc)),
            "{}",
            g.vcpu_summaries[0]
        );
        assert!(
            g.vcpu_summaries[1].contains(&format!("pc={:#018x}", a_vcpu(1, false).pc)),
            "{}",
            g.vcpu_summaries[1]
        );
        // vCPU 1 is parked; on aarch64 that is 5, and it comes from the
        // hypervisor crate rather than being retyped here.
        assert!(
            g.vcpu_summaries[1]
                .contains(&format!("mp_state={}", kvm_ingest::kvm_mp_state_for(false))),
            "{}",
            g.vcpu_summaries[1]
        );
    }

    /// Two syntheses of one machine must be byte-identical -- including when
    /// HVF handed the registers over in a different order, because a capture's
    /// digest is a name for the machine and not for the order it was read in.
    #[test]
    fn synthesizing_the_same_machine_twice_gives_the_same_bytes() {
        assert_eq!(synthesized(2).bytes, synthesized(2).bytes);

        let mut reordered = a_checkpoint(2);
        for v in &mut reordered.vcpus {
            v.state.sysregs.reverse();
        }
        assert_eq!(
            synthesize(&reordered, RAM, 24_000_000, a_serial(), SERIAL_LINE)
                .expect("synthesizes")
                .bytes,
            synthesized(2).bytes,
            "the capture order of the system registers must not reach the bytes"
        );
    }
    /// The load-bearing guard for the console.
    ///
    /// Six registers cross this boundary through JSON keys that are
    /// cloud-hypervisor's names, and three of them differ from the register
    /// they carry. Asking the production reader to parse what the production
    /// writer emitted is the only check with power here: a rename or a swap on
    /// the writing side alone produces a document that is still valid JSON and
    /// still parses, into silent reset values, so nothing downstream reports it
    /// and the guest simply comes back deaf.
    #[test]
    fn the_console_configuration_reads_back_exactly_as_it_was_captured() {
        let g = synthesized(1);
        let text = std::str::from_utf8(&g.bytes).expect("utf-8");
        let back = hypervisor::hvf::virtio::devmgr::parse_serial_state(text)
            .expect("the emitted capture must carry a serial node the restore path finds");
        assert_eq!(
            back,
            a_serial(),
            "every PL011 register must survive the round trip through the document"
        );
    }

    /// The line the console asserts must survive the document, read back by the
    /// restore path's own parser rather than by a second one written here.
    ///
    /// This is the guard the whole field exists for. Without the value on disk
    /// a restoring VMM falls back to a constant derived from a cloud-hypervisor
    /// capture's device order, and a cold-booted guest's PL011 does not sit
    /// there -- so every keystroke lands on an interrupt no device owns and the
    /// guest, which is running perfectly, answers nothing.
    #[test]
    fn the_line_the_console_asserts_reads_back_as_the_one_that_was_captured() {
        let g = synthesized(1);
        let text = std::str::from_utf8(&g.bytes).expect("utf-8");
        let back = hypervisor::hvf::virtio::devmgr::parse_serial_intid(text)
            .expect("the emitted capture must record the console's interrupt line");
        assert_eq!(
            back, SERIAL_LINE,
            "the restore path must read back the line origination captured, not a default"
        );
    }

    /// A capture that predates the field must read as "does not say", not as a
    /// line number.
    ///
    /// Every snapshot cloud-hypervisor has ever written is this case, and the
    /// reader has to be able to tell silence from an answer or it would hand a
    /// zero to the interrupt controller and call it the console.
    #[test]
    fn a_capture_that_does_not_record_a_line_says_nothing_rather_than_zero() {
        let text = r#"{"snapshots":{"device-manager":{"snapshots":{},
            "snapshot_data":{"state":"{\"device_tree\":{\"__serial\":{\"id\":\"__serial\",\"resources\":[],\"children\":[]}}}"}}}}"#;
        assert_eq!(
            hypervisor::hvf::virtio::devmgr::parse_serial_intid(text),
            None,
            "an empty resources list is a capture declining to say, not a line 0"
        );
    }

    /// A guest whose console is deaf must be described as one.    ///
    /// `imsc` at its reset value is a legitimate capture -- a guest that polls
    /// `UARTFR` reads input regardless -- so this is a warning and not a
    /// refusal. It is worth stating because the failure it predicts is the
    /// least legible one available: the guest executes perfectly and answers
    /// nothing.
    #[test]
    fn a_masked_receive_interrupt_is_reported_rather_than_hidden() {
        let deaf = SerialRegs {
            imsc: 0,
            ..a_serial()
        };
        let g =
            synthesize(&a_checkpoint(1), RAM, 24_000_000, deaf, SERIAL_LINE).expect("synthesizes");
        assert!(
            g.warnings.iter().any(|w| w.contains("receive interrupt")),
            "a capture with the receive interrupt masked must say so: {:?}",
            g.warnings
        );
        assert!(
            !synthesized(1)
                .warnings
                .iter()
                .any(|w| w.contains("receive interrupt")),
            "an interrupt-driven console must not draw the warning"
        );
    }

    /// The completeness note must not keep claiming the serial port is missing.
    ///
    /// This document is the only place a caller is told what the artefact does
    /// not carry, so a stale sentence there is worse than none: it sends a
    /// reader looking for a cause that has already been fixed.
    #[test]
    fn the_completeness_note_does_not_still_disown_the_serial_port() {
        let g = synthesized(1);
        let note = g
            .warnings
            .iter()
            .find(|w| w.contains("restorable by chm"))
            .expect("the completeness note must be present");
        assert!(
            note.contains("serial"),
            "the note must count the serial port among what is carried: {note}"
        );
        assert!(
            !note.contains("node per device (serial"),
            "the note must not still list the serial port as absent: {note}"
        );
    }
}
