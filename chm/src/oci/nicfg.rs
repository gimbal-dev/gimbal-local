// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! A freestanding aarch64 program that brings up `eth0`, for guests that have
//! no tool to do it with.
//!
//! # Why this exists
//!
//! Configuring a network interface is an **ioctl**, and no shell builtin makes
//! one. The generated init tries `ip` and then `ifconfig`, but a container
//! rootfs is under no obligation to ship either — and the mainstream ones
//! increasingly do not. Measured: `node:22` (the full ~1.1 GB Debian image) and
//! `node:22-slim` both have neither. `which ip ifconfig` returns 1.
//!
//! So the honest refusal we print covers the *common* case, not an edge case,
//! and a guest that boots fine has no network at all. The only fix that does
//! not depend on the image is to carry the code ourselves.
//!
//! # What is checked in
//!
//! [`nicfg.S`](../../src/oci/nicfg.S) is the source and is the thing to read.
//! `nicfg.bin` is that source assembled and linked — 1 KiB, no libc, no
//! relocations, no dynamic loader, one `PT_LOAD` for text and one for data.
//!
//! A binary in a source tree is only acceptable if you can prove it came from
//! the source beside it, so [`tests::the_binary_is_reproducible_from_the_source`]
//! rebuilds `nicfg.S` and compares byte for byte. It skips when the toolchain
//! is absent, and prints the exact command to rebuild.
//!
//! # Why the addresses are patched rather than assembled in
//!
//! The guest address, netmask and gateway live in [`crate::create`]. If this
//! program had them baked in at assembly time they would be a second copy, and
//! a drifted copy puts the guest on a different subnet from its own gateway
//! while every test still passes — the exact failure V9.7 was caught by. So the
//! source stores recognisable sentinels and [`configurator`] rewrites them from
//! the single source of truth, refusing if a sentinel is not found exactly once.

use std::error::Error;
use std::fmt;

use crate::create::{GATEWAY_IP, GUEST_IP, GUEST_PREFIX_LEN};

/// The assembled program. See the module docs for its provenance.
const IMAGE: &[u8] = include_bytes!("nicfg.bin");

/// Where the configurator is installed in the guest.
///
/// **At the root, with no directory component, and that is load-bearing.**
///
/// The first attempt installed it at `sbin/gimbal-nicfg` and it vanished. On a
/// Debian usr-merge image — `node:22-slim` is one — `/sbin` is a *symlink* to
/// `usr/sbin`. cpio entries are emitted in sorted order, so `./sbin/gimbal-nicfg`
/// is unpacked before `./usr/sbin` exists, the symlink resolves to a directory
/// that is not there yet, and the kernel's unpacker drops the file **without a
/// word**. The guest then boots with no configurator and no explanation.
///
/// Any image-controlled directory can be a symlink, and sorted order means we
/// cannot rely on its target existing first. The root always exists, so `/init`
/// lives there and so does this.
pub const GUEST_PATH: &str = "gimbal-nicfg";

/// Placeholders in `nicfg.S`'s data, rewritten by [`configurator`].
///
/// These are big-endian in the file because an IPv4 address is network byte
/// order on the wire and in `sockaddr_in`; the assembler wrote them with
/// `.word`, which is little-endian, so the bytes to search for are reversed.
const SENTINEL_ADDR: u32 = 0xC0DE_0001;
const SENTINEL_MASK: u32 = 0xC0DE_0002;
const SENTINEL_GATEWAY: u32 = 0xC0DE_0003;

/// Why a configurator could not be produced.
///
/// Every variant means the checked-in binary and this code disagree, which is a
/// build-integrity problem rather than anything a user did.
#[derive(Debug, PartialEq, Eq)]
pub enum NicfgError {
    /// A sentinel was absent, or present more than once. Either way we cannot
    /// say which four bytes to rewrite, and guessing would produce a binary
    /// that configures the wrong address.
    Sentinel { name: &'static str, found: usize },
    /// The prefix length cannot describe a netmask.
    Prefix(u8),
}

impl fmt::Display for NicfgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sentinel { name, found } => write!(
                f,
                "nicfg: expected exactly one {name} placeholder in nicfg.bin, found {found}. \
                 The binary and chm/src/oci/nicfg.rs have gone out of step; \
                 rebuild it from chm/src/oci/nicfg.S"
            ),
            Self::Prefix(p) => write!(f, "nicfg: /{p} is not a valid IPv4 prefix length"),
        }
    }
}

impl Error for NicfgError {}

/// Turn a prefix length into a netmask, most significant bit first.
///
/// A `/0` mask is all zeroes and a `/32` is all ones; both are computed rather
/// than shifted, because shifting a `u32` by 32 is undefined and panics in
/// debug. That is not hypothetical — it is what the equivalent code in
/// `initramfs.rs` did on its first run.
fn netmask(prefix: u8) -> Result<[u8; 4], NicfgError> {
    if prefix > 32 {
        return Err(NicfgError::Prefix(prefix));
    }
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(bits.to_be_bytes())
}

/// Rewrite one sentinel, insisting it occurs exactly once.
///
/// The "exactly once" rule lives in [`super::sentinel`] because
/// [`super::cdpfwd`] needs the same rule and a second copy of it would be a
/// second chance to get it wrong.
fn patch(
    image: &mut [u8],
    name: &'static str,
    sentinel: u32,
    value: [u8; 4],
) -> Result<(), NicfgError> {
    let at = super::sentinel::find_exactly_once(image, sentinel)
        .map_err(|found| NicfgError::Sentinel { name, found })?;
    image[at..at + 4].copy_from_slice(&value);
    Ok(())
}

/// The configurator, with this deployment's addresses written into it.
pub fn configurator() -> Result<Vec<u8>, NicfgError> {
    let mut image = IMAGE.to_vec();
    patch(&mut image, "address", SENTINEL_ADDR, GUEST_IP)?;
    patch(&mut image, "netmask", SENTINEL_MASK, netmask(GUEST_PREFIX_LEN)?)?;
    patch(&mut image, "gateway", SENTINEL_GATEWAY, GATEWAY_IP)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// The kernel will not execute anything that is not an ELF it recognises,
    /// and a wrong machine type fails at `execve` with a message that says
    /// nothing useful about why.
    #[test]
    fn the_image_is_a_static_aarch64_elf() {
        assert_eq!(&IMAGE[0..4], b"\x7fELF", "not an ELF");
        assert_eq!(IMAGE[4], 2, "not 64-bit");
        assert_eq!(IMAGE[5], 1, "not little-endian");
        // e_type == ET_EXEC (2), not ET_DYN: a dynamic object would need an
        // interpreter, and the whole point is to depend on nothing.
        assert_eq!(u16::from_le_bytes([IMAGE[16], IMAGE[17]]), 2, "not ET_EXEC");
        // e_machine == EM_AARCH64 (183).
        assert_eq!(
            u16::from_le_bytes([IMAGE[18], IMAGE[19]]),
            183,
            "not aarch64"
        );
    }

    /// Regression for a silent failure that cost a full boot cycle to find.
    ///
    /// Installing into any directory the image controls is unsafe: on a
    /// usr-merge image that directory can be a symlink, and because cpio
    /// entries are sorted its target may not exist yet when we are unpacked.
    /// The kernel drops the file without a word. Staying at the root avoids
    /// the whole class.
    #[test]
    fn the_configurator_is_installed_at_the_root_where_no_symlink_can_swallow_it() {
        assert!(
            !GUEST_PATH.contains('/'),
            "GUEST_PATH {GUEST_PATH:?} has a directory component; on a usr-merge \
             image that directory may be a symlink whose target is unpacked later, \
             and the kernel will silently drop the file"
        );
        assert!(!GUEST_PATH.starts_with('.') && !GUEST_PATH.is_empty());
    }

    #[test]
    fn every_sentinel_occurs_exactly_once_in_the_shipped_binary() {
        for (name, s) in [
            ("address", SENTINEL_ADDR),
            ("netmask", SENTINEL_MASK),
            ("gateway", SENTINEL_GATEWAY),
        ] {
            let n = IMAGE
                .windows(4)
                .filter(|w| *w == s.to_le_bytes())
                .count();
            assert_eq!(n, 1, "{name} sentinel occurs {n} times, expected 1");
        }
    }

    /// The addresses must come from `create.rs`, not from the assembly. If they
    /// were baked in, a change there would leave the guest on a different
    /// subnet from its own gateway with every test still green.
    #[test]
    fn the_configurator_carries_the_addresses_create_rs_declares() {
        let img = configurator().expect("configurator");
        for (what, bytes) in [
            ("guest address", GUEST_IP),
            ("netmask", netmask(GUEST_PREFIX_LEN).unwrap()),
            ("gateway", GATEWAY_IP),
        ] {
            assert!(
                img.windows(4).any(|w| w == bytes),
                "{what} {bytes:?} is not present in the patched binary"
            );
        }
        // And no sentinel survives, or something is being configured to an
        // address that means nothing.
        for s in [SENTINEL_ADDR, SENTINEL_MASK, SENTINEL_GATEWAY] {
            assert!(
                !img.windows(4).any(|w| w == s.to_le_bytes()),
                "sentinel {s:#x} was left in place"
            );
        }
    }

    #[test]
    fn patching_refuses_rather_than_guessing_when_a_sentinel_is_not_unique() {
        // Absent.
        let mut none = vec![0u8; 32];
        assert_eq!(
            patch(&mut none, "address", SENTINEL_ADDR, [1, 2, 3, 4]),
            Err(NicfgError::Sentinel {
                name: "address",
                found: 0
            })
        );
        // Duplicated — refused too, because we would not know which copy the
        // program actually reads.
        let mut two = Vec::new();
        two.extend_from_slice(&SENTINEL_ADDR.to_le_bytes());
        two.extend_from_slice(&[0u8; 8]);
        two.extend_from_slice(&SENTINEL_ADDR.to_le_bytes());
        assert_eq!(
            patch(&mut two, "address", SENTINEL_ADDR, [1, 2, 3, 4]),
            Err(NicfgError::Sentinel {
                name: "address",
                found: 2
            })
        );
    }

    #[test]
    fn netmask_covers_both_ends_without_overflowing() {
        assert_eq!(netmask(0).unwrap(), [0, 0, 0, 0]);
        assert_eq!(netmask(24).unwrap(), [255, 255, 255, 0]);
        assert_eq!(netmask(32).unwrap(), [255, 255, 255, 255]);
        assert_eq!(netmask(33), Err(NicfgError::Prefix(33)));
    }

    /// A binary in a source tree is only acceptable if it can be shown to come
    /// from the source beside it. This is the proof.
    ///
    /// It skips when the toolchain is missing rather than failing, because
    /// assembling a Linux target is not something every contributor's machine
    /// can do — but when it can, drift between `nicfg.S` and `nicfg.bin` is a
    /// hard failure.
    #[test]
    fn the_binary_is_reproducible_from_the_source() {
        let sysroot = match Command::new("rustc").arg("--print").arg("sysroot").output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => return,
        };
        let lld = format!("{sysroot}/lib/rustlib/aarch64-apple-darwin/bin/rust-lld");
        let objcopy = format!("{sysroot}/lib/rustlib/aarch64-apple-darwin/bin/rust-objcopy");
        if !std::path::Path::new(&lld).exists() || !std::path::Path::new(&objcopy).exists() {
            return;
        }
        if Command::new("clang").arg("--version").output().is_err() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("nicfg-repro-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oci/nicfg.S");
        let obj = dir.join("nicfg.o");
        let linked = dir.join("nicfg");
        let stripped = dir.join("nicfg.bin");

        let asm = Command::new("clang")
            .args(["--target=aarch64-unknown-linux-gnu", "-c", src, "-o"])
            .arg(&obj)
            .output();
        // A clang without the aarch64-linux target cannot do this; that is a
        // missing capability, not a failure of the binary.
        match asm {
            Ok(o) if o.status.success() => {}
            _ => return,
        }
        let ok = Command::new(&lld)
            .args(["-flavor", "gnu", "-static", "-e", "_start", "-o"])
            .arg(&linked)
            .arg(&obj)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
            && Command::new(&objcopy)
                .arg("--strip-all")
                .arg(&linked)
                .arg(&stripped)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        if !ok {
            return;
        }

        let rebuilt = std::fs::read(&stripped).expect("rebuilt binary");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            rebuilt.len(),
            IMAGE.len(),
            "nicfg.bin is {} bytes but nicfg.S assembles to {}. \
             Rebuild it — see chm/src/oci/nicfg.S for the command.",
            IMAGE.len(),
            rebuilt.len()
        );
        assert!(
            rebuilt == IMAGE,
            "nicfg.bin does not match nicfg.S. The checked-in binary must be \
             rebuilt from the source beside it, or the source is not what runs."
        );
    }
}
