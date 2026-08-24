// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `chm` — the Gimbal Local engine (a macOS fork of Cloud Hypervisor).
//!
//! A standalone Apple Silicon executable that rehydrates a Cloud Hypervisor
//! arm64 KVM snapshot onto Apple's Hypervisor.framework and resumes it locally.
//! It is a thin command-line front end over the in-tree `hypervisor` crate's
//! `hvf` backend (`hypervisor::hvf::rehydrate`), wiring a faithful PL011 serial
//! console so the resumed guest's output streams straight to your terminal.
//!
//! The binary must be code-signed with the `com.apple.security.hypervisor`
//! entitlement before it can create a VM — see `scripts/build-chm.sh`.

// Test code is linted too (see `clippy` in the Makefile). Two style lints fire
// so densely there that they would bury the ones that catch a test which has
// stopped testing -- `dead_code` and the `unused_*` family.
//
//   absolute_paths (259)              `std::...` spelled out inline in a test body.
//   assertions_on_result_states (29)  Deliberately narrowed to the `is_err()` form
//                                     only (#365). `assert!(x.is_ok())` discards the
//                                     error it caught, so those 17 were converted to
//                                     `.unwrap()` and are now refused by
//                                     `hygiene::no_assertion_discards_the_error_it_
//                                     caught` -- a comment saying "is_err() only"
//                                     stops being true the moment someone adds an
//                                     `is_ok()`, so the claim is coupled to a test
//                                     rather than written down. The `is_err()` half
//                                     stays: `unwrap_err()` prints the unexpected
//                                     `Ok` value, which is rarely what you needed.
//   assertions_on_constants (2)       `assert!(CONST >= N, "why")`. Measured, not
//                                     assumed: both still panic when the constant
//                                     moves, so the guards do their job.
//
// Shipped code keeps all three denials. `--all-targets` also builds the plain
// binary target, where cfg(test) is off and none of this applies.
#![cfg_attr(
    test,
    allow(
        clippy::absolute_paths,
        clippy::assertions_on_result_states,
        clippy::assertions_on_constants
    )
)]

// The real implementation only compiles on macOS / Apple Silicon, where
// Hypervisor.framework exists. On every other target the crate still builds
// (so `cargo build --workspace` stays green in Linux CI) but `main` just
// explains that the tool is Apple-Silicon-only.

use std::process::ExitCode;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp;

// Console-output filtering for the interactive serial stream. Pure logic, but
// only used by the macOS console paths, so it is gated like the rest.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod console_filter;

// Framing for `chm exec`: run a command in a running sandbox and recover its
// exit status over the console channel (#149).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod exec;

// Putting a host file into a running guest, chunked so each step frames inside
// the tty's line limit and verified by digest (#316). The way in for anything
// `chm exec` is structurally too small to carry.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod guestcp;

// Delivering a spec's `env` and `postBootCommand` into a guest that is up
// (#190). Reuses the `exec` framing, and establishes readiness by getting an
// answer rather than by matching a prompt string no BYO image is obliged to
// print.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod postboot;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod checkpoint;

// Moving a lineage between machines: the export/import bundle format (V9.5c,
// #177). Lives beside `checkpoint` because it is a *format* question -- what a
// revision is once it leaves this disk -- not a lifecycle one.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod bundle;

// Live checkpointing: the stop-the-world rendezvous that lets a running guest
// be captured and carry on, rather than only being captured on its way out.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod livesnap;

// Recognising the compressed kernel wrappers distros actually ship (#220).
// Shared by cold boot and `image build`, which both take a `--kernel` and were
// each refusing zboot with their own separately-wrong explanation.
mod kernelimage;

// Cold boot: build a guest from a kernel image rather than rehydrate one from
// a capture (#101).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod coldboot;

// Turning a container image into a bootable local image (V9.7, #153). Kept
// beside `coldboot` because its whole output is a cold-boot image directory.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod oci;

// The `chm create` verb: drives a cold guest image on Hypervisor.framework.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod create;

// The declarative sandbox spec (V9.3, #150): describe a sandbox rather than
// assemble one. Uses the agent-compute spec's vocabulary -- see the module docs.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod spec;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod console;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod cloud;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod control_plane;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod serve;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod state_cdn;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod policy;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod firewall;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod signing;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod limits;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod audit;

/// `chm sysregs` — which captured CPU registers this Mac can reproduce (V1.4).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod posture;

/// `chm capabilities` — what this build can and cannot do, and how each claim
/// was reached (V6.5).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod capability;
mod sysregs;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod credproxy;

/// Start-to-ready phase timing (#79).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod startup;

// A registry of running guests (#225). One HVF VM per process means no single
// process can answer "what is running?", so each one records itself and
// anything that wants the answer reads the directory.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod runs;

/// Notice a capture whose partition table does not use the whole disk (#259).
mod disktail;

/// Reading *and writing* a vanilla Cloud Hypervisor `state.json` (#353, #341).
/// Everything else in this tree only ever reads one, which is why a lineage
/// advanced on a Mac could not go back to the cloud.
mod vanilla;

/// Writing a Mac-advanced lineage back out as a vanilla capture (#353), on
/// state captured from a live Hypervisor.framework vCPU -- no KVM, no QEMU and
/// no Linux host anywhere in the path.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vanilla_export;

/// Originating a lineage here (#341): synthesizing a capture for a machine
/// `chm` itself cold-booted, which has no ancestor to patch. Separate from
/// `vanilla_export` because the two answer opposite questions -- that one
/// rewrites a capture we did not author, this one describes a machine nobody
/// else has ever seen.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod genesis;

/// Properties of the test suite itself (#243).
mod hygiene;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> ExitCode {
    imp::main()
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() -> ExitCode {
    eprintln!(
        "chm (the Gimbal Local engine) only runs on Apple Silicon \
         (macOS, arm64).\nThis build targets a different platform and cannot \
         create a Hypervisor.framework VM."
    );
    ExitCode::FAILURE
}
