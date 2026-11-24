// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! Injected HVF write results test local policy, not non-PAC KVM hardware.

use super::*;
use crate::hvf::VcpuHvfState;
use crate::hvf::translate::{lower_to_kvm, raise_from_kvm};

fn refused(code: i32) -> HypervisorCpuError {
    HypervisorCpuError::SetSysRegister(anyhow!("injected HVF write failure: {:#010x}", code as u32))
}

#[test]
fn every_pac_write_failure_refuses_restore_at_that_register() {
    let sysregs: Vec<_> = SYSREG_PAC_KEYS
        .iter()
        .map(|&id| (id, 0x1234_5678_9abc_def0))
        .chain([(SYSREG_TPIDR_EL1, 42)])
        .collect();
    // These are injected backend results, not observed hardware errors.
    for code in [HV_BAD_ARGUMENT, HV_UNSUPPORTED] {
        for &failed in SYSREG_PAC_KEYS {
            let mut writes = Vec::new();
            let error = restore_sysregs(&sysregs, |id, value| {
                writes.push((id, value));
                if id == failed {
                    Err(refused(code))
                } else {
                    Ok(())
                }
            })
            .expect_err("a refused PAC key must abort restore");
            assert!(
                matches!(error, HypervisorCpuError::SetSysRegister(_)),
                "{error:?}"
            );
            let message = format!("{:#}", anyhow!(error));
            assert!(message.contains(&format!("{failed:#06x}")), "{message}");
            assert!(
                message.contains(&format!("{:#010x}", code as u32)),
                "{message}"
            );
            assert!(message.contains("refusing to resume"), "{message}");
            let stop = sysregs.iter().position(|&(id, _)| id == failed).unwrap();
            assert_eq!(writes, sysregs[..=stop], "must stop at {failed:#06x}");
        }
    }
}

#[test]
fn pac_values_survive_translation_and_reach_the_writer_including_zero() {
    for value in [0, u64::MAX, 0x1234_5678_9abc_def0] {
        let original = VcpuHvfState {
            sysregs: SYSREG_PAC_KEYS.iter().map(|&id| (id, value)).collect(),
            ..Default::default()
        };
        // A KVM-shaped register round trip, not an upstream KVM import.
        let translated = raise_from_kvm(&lower_to_kvm(&original));
        let mut writes = Vec::new();
        restore_sysregs(&translated.sysregs, |id, value| {
            if SYSREG_PAC_KEYS.contains(&id) {
                writes.push((id, value));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, original.sysregs);
    }
}

#[test]
fn mpidr_write_failure_still_aborts_restore() {
    let mut writes = Vec::new();
    let error = restore_sysregs(
        &[(SYSREG_MPIDR_EL1, MPIDR_RES1), (SYSREG_TPIDR_EL1, 42)],
        |id, _| {
            writes.push(id);
            Err(refused(HV_BAD_ARGUMENT))
        },
    )
    .expect_err("MPIDR is not best-effort");
    assert_eq!(writes, [SYSREG_MPIDR_EL1]);
    assert!(format!("{:#}", anyhow!(error)).contains("injected HVF write failure"));
}

#[test]
fn non_pac_state_keeps_best_effort_writes_and_counter_bookkeeping() {
    assert_eq!(
        restore_sysregs(&[], |_, _| panic!("empty state must not write")).unwrap(),
        RestoredSysregs::default()
    );
    let mut writes = Vec::new();
    let restored = restore_sysregs(
        &[
            (SYSREG_TPIDR_EL1, 42),
            (SYSREG_MPIDR_EL1, MPIDR_RES1),
            (SYSREG_CNTVCT_EL0, 12345),
        ],
        |id, value| {
            writes.push((id, value));
            if id == SYSREG_MPIDR_EL1 {
                Ok(())
            } else {
                Err(refused(HV_UNSUPPORTED))
            }
        },
    )
    .expect("a non-critical write failure must remain best-effort");
    assert_eq!(
        writes,
        [(SYSREG_TPIDR_EL1, 42), (SYSREG_MPIDR_EL1, MPIDR_RES1)]
    );
    assert_eq!(
        restored,
        RestoredSysregs {
            mpidr: true,
            cntvct: Some(12345),
        }
    );
}

#[test]
fn set_state_propagates_the_restore_policy_error() {
    // Outcome tests cannot catch a caller discarding the helper's error.
    // Read a different file so this needle cannot match its own assertion.
    let source: String = include_str!("mod.rs").split_whitespace().collect();
    let call: String =
        "let restored = restore_sysregs(&s.sysregs, |id, v| self.set_sysreg(id, v))?;"
            .split_whitespace()
            .collect();
    assert_eq!(
        source.matches(&call).count(),
        1,
        "set_state must call the real writer and propagate restore failure"
    );
}

#[cfg(feature = "kvm-snapshot")]
#[test]
fn rehydration_reports_the_pac_register_and_backend_error() {
    let key = SYSREG_APGAKEYHI_EL1;
    let error = restore_sysregs(&[(key, 0)], |_, _| Err(refused(HV_UNSUPPORTED)))
        .expect_err("PAC write must fail");
    let message = super::rehydrate::restore_state_error(7, &error).to_string();
    assert!(message.contains("restore vCPU 7 state"), "{message}");
    assert!(message.contains(&format!("{key:#06x}")), "{message}");
    assert!(message.contains("refusing to resume"), "{message}");
    assert!(
        message.contains(&format!("{:#010x}", HV_UNSUPPORTED as u32)),
        "{message}"
    );
}

#[cfg(feature = "kvm-snapshot")]
#[test]
fn both_rehydration_paths_preserve_restore_error_details() {
    let source: String = include_str!("rehydrate.rs").split_whitespace().collect();
    for state in ["vcpu_state.clone()", "snap.vcpus[id].clone()"] {
        let call = format!(
            "vcpu.set_state(&CpuState::Hvf({state})).map_err(|e|restore_state_error(id,&e))?;"
        );
        assert_eq!(
            source.matches(&call).count(),
            1,
            "restore must keep error details for {state}"
        );
    }
}
