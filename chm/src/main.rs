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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod checkpoint;

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
