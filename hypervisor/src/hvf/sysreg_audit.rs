// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Audit which of a capture's system registers this Mac can actually reproduce.
//!
//! # The bug class
//!
//! A guest boots on its capture host, probes that host's identity and feature
//! registers, and **caches the answers** — in kernel data structures, in
//! `cpuinfo`, in glibc's ifunc dispatch tables, in a JIT's code-generation
//! decisions. Rehydrating that guest somewhere else does not re-run those
//! probes. If the new host answers differently, the guest is running on beliefs
//! that are no longer true.
//!
//! We have been bitten by exactly this once already: `CNTFRQ_EL0` is 121 875 000
//! Hz on Graviton2 and 24 000 000 Hz on Apple silicon, Linux reads it once at
//! boot, and the result was a guest whose clock ran **5.08x** slow. It was found
//! by accident, months in. `CNTFRQ_EL0` is not special — it is one register in a
//! family, and the rest were never audited.
//!
//! # Why it is invisible
//!
//! [`crate::hvf::HvfVcpu::set_state`] restores every system register except
//! MPIDR best-effort:
//!
//! ```ignore
//! let _ = self.set_sysreg(id, v);
//! ```
//!
//! That is deliberate and correct — a register that is read-only on this core
//! must not abort an otherwise good restore — but it is *silent*. A register
//! Apple refuses is dropped with no diagnostic, and the guest simply carries on
//! believing whatever its capture host told it.
//!
//! This module makes that silence measurable: it replays a capture's registers
//! against a real HVF vCPU and reports, per register, whether this host
//! reproduces the captured value, clamps it, or refuses it outright.
//!
//! Probing is non-destructive. Each register's pre-probe value is read and
//! rewritten afterwards, so an audit leaves the vCPU as it found it.

use std::sync::Arc;

use anyhow::anyhow;

use crate::hvf::{HvfVcpu, SysregFate};
use crate::hvf::rehydrate::{RehydrateError, Snapshot};
use crate::{Hypervisor, HypervisorVmConfig};

/// One captured register, and what this host does with it.
#[derive(Clone, Debug)]
pub struct SysregFinding {
    /// HVF's 16-bit register encoding (`op0/op1/CRn/CRm/op2` packed).
    pub reg: u16,
    /// The value the capture host recorded.
    pub captured: u64,
    /// What happened when it was replayed here.
    pub fate: SysregFate,
}

impl SysregFinding {
    /// The architectural `S<op0>_<op1>_C<CRn>_C<CRm>_<op2>` name of this
    /// register, and its common name when it has one worth knowing.
    pub fn name(&self) -> String {
        let (op0, op1, crn, crm, op2) = decode(self.reg);
        match well_known(op0, op1, crn, crm, op2) {
            Some(n) => n.to_string(),
            None => format!("S{op0}_{op1}_C{crn}_C{crm}_{op2}"),
        }
    }

    /// Whether this register belongs to the AArch64 **ID space** — the
    /// read-only feature/identity registers at `op0=3, op1=0, CRn=0`, plus the
    /// cache-geometry and counter-frequency registers that behave the same way.
    ///
    /// These are the ones that matter for this bug class: a guest reads them
    /// once and caches the answer forever.
    pub fn is_identity(&self) -> bool {
        let (op0, op1, crn, crm, op2) = decode(self.reg);
        // The ID register block.
        if op0 == 3 && op1 == 0 && crn == 0 {
            return true;
        }
        // Cache geometry (CLIDR/CCSIDR/CSSELR) and CTR_EL0 / DCZID_EL0.
        matches!(
            (op0, op1, crn, crm, op2),
            (3, 1, 0, 0, 0)     // CCSIDR_EL1
                | (3, 1, 0, 0, 1) // CLIDR_EL1
                | (3, 2, 0, 0, 0) // CSSELR_EL1
                | (3, 3, 0, 0, 1) // CTR_EL0
                | (3, 3, 0, 0, 7) // DCZID_EL0
                | (3, 3, 14, 0, 0) // CNTFRQ_EL0
        )
    }

    /// What this specific divergence *means*, for the registers whose behaviour
    /// has actually been measured on hardware.
    ///
    /// A list of 133 divergent registers is data, not an answer. These notes are
    /// the analysis: for each register we have investigated, whether the
    /// difference is benign, safe-by-direction, or a real hazard — and the
    /// evidence behind that call. Registers with no note have not been analysed;
    /// saying nothing is better than implying they were cleared.
    ///
    /// Not restricted to divergent registers, deliberately. The worst finding so
    /// far is a register this Mac reproduces *perfectly* — see
    /// `ID_AA64PFR0_EL1` below.
    ///
    /// Measurements: Apple M3, AWS Graviton2 capture, 2026-07-29. Full write-up
    /// in `docs/cpu-feature-deltas.md`.
    pub fn note(&self) -> Option<&'static str> {
        let (op0, op1, crn, crm, op2) = decode(self.reg);

        // ID_AA64PFR0_EL1 is the inverse case, and the reason this method does
        // not simply skip faithfully restored registers: HVF *accepts* it, so
        // the guest keeps a belief that is true of its capture host and false
        // here. Restoring it perfectly is exactly what makes it dangerous.
        if (op0, op1, crn, crm, op2) == (3, 0, 0, 4, 0) && (self.captured & 0xf) == 2 {
            return Some(
                "RESTORED FAITHFULLY, AND THAT IS THE PROBLEM. The EL0 field reads 2 \
                 — AArch64 and AArch32 — so the guest latched \"32-bit userspace \
                 works\" when it booted on the capture host. Apple silicon has no \
                 AArch32 at any exception level. Measured: executing a 32-bit binary \
                 permanently wedges the vCPU, taking the whole guest with it, and it \
                 cannot be recovered. 64-bit workloads are unaffected. Rewriting the \
                 register now would not help: the capability was latched at boot.",
            );
        }

        if !self.fate.diverges() {
            return None;
        }
        Some(match (op0, op1, crn, crm, op2) {
            (3, 3, 0, 0, 1) => {
                "DIC (bit 29) differs — Graviton2 says 1, Apple says 0 — which made \
                 the guest kernel patch `ic ivau` out of its I-cache maintenance at \
                 boot; on Apple that is architecturally unsound, and it is baked \
                 into the kernel text inside the snapshot. What EL0 sees is no \
                 longer this captured value: the capture also arrives with \
                 SCTLR_EL1.UCT clear, so userspace reads went to a kernel handler \
                 that reported IminLine = 4096 B, and restore now sets UCT so EL0 \
                 reads this Mac's own CTR_EL0 (0x9444c004 — 64 B, DIC 0) instead. \
                 HVF refuses this register and will not report the host's value — \
                 the numbers here were measured from inside a running guest. \
                 See #290 for the stride and #287 for the kernel's own copy."
            }
            (3, 3, 0, 0, 7) => {
                "DC ZVA block size. Measured identical (64 B) on Apple M3 and in \
                 a rehydrated Graviton2 guest, behaviourally confirmed by a \
                 single `dc zva` zeroing exactly 64 bytes. A mismatch here would \
                 corrupt memory past the intended range on every glibc memset."
            }
            (3, 3, 14, 0, 0) => {
                "Counter frequency — the register that caused the 5.08x clock \
                 dilation. Corrected at runtime by re-stepping the vtimer offset; \
                 see the CNTFRQ guard and docs/hvf-compatible-snapshots.md."
            }
            (3, 1, 0, 0, 0) | (3, 1, 0, 0, 1) | (3, 2, 0, 0, 0) => {
                "Cache hierarchy description. Refused by HVF, so the guest sees \
                 Apple's topology. No guest safety property depends on it: the \
                 geometry that maintenance actually uses comes from CTR_EL0, \
                 which matches."
            }
            (3, 0, 0, 0, 6) => {
                "Silicon revision. Refused by HVF. Cosmetic unless a guest gates \
                 an erratum workaround on it — and the erratum-selecting register, \
                 MIDR_EL1, is restored faithfully."
            }
            _ => return None,
        })
    }
}

/// Split HVF's packed encoding back into `op0/op1/CRn/CRm/op2`.
///
/// HVF and KVM share this layout, which is why
/// [`crate::hvf::translate::kvm_sysreg_to_hvf`] can map between them by masking
/// alone.
fn decode(reg: u16) -> (u16, u16, u16, u16, u16) {
    (
        (reg >> 14) & 0x3,
        (reg >> 11) & 0x7,
        (reg >> 7) & 0xf,
        (reg >> 3) & 0xf,
        reg & 0x7,
    )
}

/// Common names for the registers a reader will actually want to recognise.
///
/// Deliberately partial: an unnamed register still prints its architectural
/// `S3_0_C0_C4_0` form, which is unambiguous and greppable against the ARM ARM.
fn well_known(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> Option<&'static str> {
    Some(match (op0, op1, crn, crm, op2) {
        (3, 0, 0, 0, 0) => "MIDR_EL1",
        (3, 0, 0, 0, 5) => "MPIDR_EL1",
        (3, 0, 0, 0, 6) => "REVIDR_EL1",
        (3, 0, 0, 4, 0) => "ID_AA64PFR0_EL1",
        (3, 0, 0, 4, 1) => "ID_AA64PFR1_EL1",
        (3, 0, 0, 5, 0) => "ID_AA64DFR0_EL1",
        (3, 0, 0, 5, 1) => "ID_AA64DFR1_EL1",
        (3, 0, 0, 6, 0) => "ID_AA64ISAR0_EL1",
        (3, 0, 0, 6, 1) => "ID_AA64ISAR1_EL1",
        (3, 0, 0, 7, 0) => "ID_AA64MMFR0_EL1",
        (3, 0, 0, 7, 1) => "ID_AA64MMFR1_EL1",
        (3, 0, 0, 7, 2) => "ID_AA64MMFR2_EL1",
        (3, 1, 0, 0, 0) => "CCSIDR_EL1",
        (3, 1, 0, 0, 1) => "CLIDR_EL1",
        (3, 2, 0, 0, 0) => "CSSELR_EL1",
        (3, 3, 0, 0, 1) => "CTR_EL0",
        (3, 3, 0, 0, 7) => "DCZID_EL0",
        (3, 3, 14, 0, 0) => "CNTFRQ_EL0",
        (3, 0, 1, 0, 0) => "SCTLR_EL1",
        (3, 0, 1, 0, 2) => "CPACR_EL1",
        (3, 0, 2, 0, 0) => "TTBR0_EL1",
        (3, 0, 2, 0, 1) => "TTBR1_EL1",
        (3, 0, 2, 0, 2) => "TCR_EL1",
        _ => return None,
    })
}

/// Replay `vcpu_index`'s captured registers against this host.
///
/// Creates a bare VM with **no guest RAM** — the probe only touches the vCPU
/// register file, so mapping a gigabyte of snapshot memory would be pure cost.
/// This is why the audit runs in milliseconds and can be offered as a routine
/// pre-flight rather than a heavyweight diagnostic.
pub fn audit_snapshot(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    vcpu_index: usize,
) -> Result<Vec<SysregFinding>, RehydrateError> {
    let state = snap.vcpus.get(vcpu_index).ok_or_else(|| {
        RehydrateError::Malformed(format!("snapshot has no vCPU {vcpu_index}"))
    })?;

    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vm: {e}")))?;
    let vm: Arc<dyn crate::Vm> = vm;

    let mut vcpu = vm
        .create_vcpu(0, None)
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vcpu: {e}")))?;
    let concrete = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .ok_or_else(|| RehydrateError::Translate("vCPU is not an HVF vCPU".into()))?;

    Ok(state
        .sysregs
        .iter()
        .map(|&(reg, captured)| SysregFinding {
            reg,
            captured,
            fate: concrete.probe_sysreg(reg, captured),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_packed_encoding_back_to_the_architectural_fields() {
        // MPIDR_EL1 is S3_0_C0_C0_5 and HVF encodes it 0xc005.
        assert_eq!(decode(0xc005), (3, 0, 0, 0, 5));
        // CNTFRQ_EL0 is S3_3_C14_C0_0.
        assert_eq!(decode(0xdf00), (3, 3, 14, 0, 0));
    }

    #[test]
    fn names_the_registers_that_carry_host_identity() {
        let f = |reg| SysregFinding {
            reg,
            captured: 0,
            fate: SysregFate::Restored,
        };
        assert_eq!(f(0xc005).name(), "MPIDR_EL1");
        assert_eq!(f(0xc000).name(), "MIDR_EL1");
        assert_eq!(f(0xdf00).name(), "CNTFRQ_EL0");
    }

    #[test]
    fn falls_back_to_the_architectural_name_when_unknown() {
        // S3_0_C0_C4_2 has no common name; it must still print unambiguously
        // rather than being hidden or labelled "unknown".
        let f = SysregFinding {
            reg: 0xc022,
            captured: 0,
            fate: SysregFate::Restored,
        };
        assert_eq!(f.name(), "S3_0_C0_C4_2");
    }

    #[test]
    fn classifies_the_identity_space_including_the_register_that_bit_us() {
        let f = |reg| SysregFinding {
            reg,
            captured: 0,
            fate: SysregFate::Restored,
        };
        // The whole ID block, cache geometry, and CNTFRQ_EL0 — the register
        // whose mismatch caused the 5.08x clock dilation.
        assert!(f(0xc000).is_identity(), "MIDR_EL1");
        assert!(f(0xc020).is_identity(), "ID_AA64PFR0_EL1");
        assert!(f(0xdf00).is_identity(), "CNTFRQ_EL0");
        assert!(f(0xc800).is_identity(), "CCSIDR_EL1");
        // Ordinary EL1 control registers are guest-owned, not host identity.
        assert!(!f(0xc080).is_identity(), "SCTLR_EL1");
        assert!(!f(0xc100).is_identity(), "TTBR0_EL1");
    }

    #[test]
    fn only_demonstrable_deltas_count_as_divergence() {
        assert!(!SysregFate::Restored.diverges());
        // We cannot prove a delta we cannot read back, so it must not be
        // reported as one.
        assert!(!SysregFate::Unverifiable.diverges());
        assert!(SysregFate::Refused { host: Some(7) }.diverges());
        assert!(
            SysregFate::Clamped {
                observed: 1,
                host: Some(2)
            }
            .diverges()
        );
    }
}
