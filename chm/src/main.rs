// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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
