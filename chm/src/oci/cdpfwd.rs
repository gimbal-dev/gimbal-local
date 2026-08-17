// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! A freestanding aarch64 program that relays the one CDP port from the guest's
//! NIC address to the guest's own loopback, and does nothing else.
//!
//! # Why this exists
//!
//! Chromium's DevTools endpoint binds loopback and there is no switch to move
//! it. Measured on the shipped arm64 binary this image installs:
//!
//! ```text
//! $ strings headless_shell | grep -x 'remote-debugging-[a-z]*'
//! remote-debugging-pipe
//! remote-debugging-port
//! ```
//!
//! There is no `remote-debugging-address`, so the port cannot be moved off
//! `127.0.0.1`. [`crate::create::expose_guest_ports`] dials the guest at
//! [`crate::create::GUEST_IP`]. Both are behaving correctly and they never
//! meet: `chm create --expose 9222` reaches an address with nothing listening.
//!
//! # Why a byte relay and not `--remote-debugging-pipe`
//!
//! Pipe mode is the stronger posture on its face: Chromium speaks CDP over
//! inherited file descriptors and opens no socket at all. It also deletes the
//! HTTP and WebSocket endpoint that `chromium.connectOverCDP()` requires, so
//! something in the guest would have to *become* the DevTools front door: an
//! HTTP server, an RFC 6455 WebSocket server with its SHA-1 and base64
//! handshake and its framing, a synthesised `/json/version`, and multiplexing
//! of many WebSocket clients onto one NUL-delimited pipe pair.
//!
//! That is a protocol implementation inside the guest, and its bug surface is
//! the sum of those protocols. This relay parses nothing whatsoever. Its
//! protocol surface is zero bytes, and Chromium keeps a loopback socket it
//! already has today. The trade is real and it is recorded rather than glossed:
//! pipe mode removes one socket; the bridge that would be needed to keep
//! Playwright working adds far more than one socket's worth of code.
//!
//! # What it will not do, structurally
//!
//! * It never creates a process. There is no `clone`, `fork`, `execve` or
//!   `execveat` in it, and [`tests::the_syscall_vocabulary_is_exactly_the_allow_list`]
//!   decodes every syscall out of the shipped bytes to prove it.
//! * It never opens a file: no `openat` either, by the same proof.
//! * It reads no configuration. It ignores `argv`, and both the address and the
//!   port are patched in from chm's own constants before the image is written.
//! * It binds one address and one port, and the address is the guest's NIC
//!   address rather than a wildcard, so nothing already inside the guest gains
//!   a path it did not have. The only reach added is the host's, which is
//!   exactly what `--expose` authorised.
//!
//! # Why the NIC address and not `0.0.0.0`
//!
//! Measured, and it corrects the shape #339 sketched. In a `linux/arm64`
//! container with `uname -m` confirmed `aarch64`, with a listening socket
//! already on `127.0.0.1:9222`, `bind("192.168.127.2", 9222)` succeeded and
//! `bind("0.0.0.0", 9222)` failed with `EADDRINUSE`. A wildcard bind on the
//! same port as Chromium cannot work, so `0.0.0.0:9222 -> 127.0.0.1:9222`
//! would have needed a second port number. Binding the NIC address needs none,
//! and is the tighter of the two anyway.
//!
//! # What is checked in
//!
//! [`cdpfwd.S`](../../src/oci/cdpfwd.S) is the source and is the thing to read.
//! `cdpfwd.bin` is that source assembled: no libc, no linker, no relocations,
//! one `PT_LOAD` for text and one for BSS. [`tests::the_binary_is_reproducible_from_the_source`]
//! rebuilds it and compares byte for byte.

use std::error::Error;
use std::fmt;

use crate::create::GUEST_IP;
use crate::oci::browser::CDP_PORT;

/// The assembled program. See the module docs for its provenance.
const IMAGE: &[u8] = include_bytes!("cdpfwd.bin");

/// Where the forwarder is installed in the guest.
///
/// At the root with no directory component, for the reason spelled out in
/// [`crate::oci::nicfg::GUEST_PATH`]: on a usr-merge image an image-controlled
/// directory can be a symlink whose target has not been unpacked yet, and the
/// kernel drops the file without a word.
pub const GUEST_PATH: &str = "gimbal-cdpfwd";

/// Placeholders in `cdpfwd.S`'s data, rewritten by [`forwarder`].
///
/// The two port sentinels are the first four bytes of a `sockaddr_in`:
/// `sin_family` (`AF_INET`, 2, little-endian) followed by a `sin_port` that is
/// not a port anyone would bind. Only the port half is rewritten, so the family
/// is never restated here.
const SENTINEL_LISTEN_PORT: u32 = 0xDEC0_0002;
const SENTINEL_UPSTREAM_PORT: u32 = 0xDEC1_0002;
/// The listening address, big-endian in the file because that is what
/// `sin_addr` is on the wire; the assembler's `.word` is little-endian, so the
/// bytes to search for are reversed.
const SENTINEL_ADDR: u32 = 0xC0DE_0001;

/// Why a forwarder could not be produced.
///
/// Both variants mean the checked-in binary and this code disagree, which is a
/// build-integrity problem rather than anything a user did.
#[derive(Debug, PartialEq, Eq)]
pub enum CdpfwdError {
    /// A sentinel was absent, or present more than once. Either way we cannot
    /// say which bytes to rewrite, and guessing would produce a forwarder
    /// listening somewhere nobody asked for.
    Sentinel { name: &'static str, found: usize },
}

impl fmt::Display for CdpfwdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sentinel { name, found } => write!(
                f,
                "cdpfwd: expected exactly one {name} placeholder in cdpfwd.bin, found {found}. \
                 The binary and chm/src/oci/cdpfwd.rs have gone out of step; \
                 rebuild it from chm/src/oci/cdpfwd.S"
            ),
        }
    }
}

impl Error for CdpfwdError {}

/// Rewrite the port half of a `sockaddr_in` sentinel, insisting it occurs
/// exactly once.
///
/// Finding it twice is as bad as not finding it: we would not know which copy
/// the program reads, so both are refused rather than picking the first.
fn patch_port(
    image: &mut [u8],
    name: &'static str,
    sentinel: u32,
    port: u16,
) -> Result<(), CdpfwdError> {
    let at = super::sentinel::find_exactly_once(image, sentinel)
        .map_err(|found| CdpfwdError::Sentinel { name, found })?;
    // The port is network byte order in `sockaddr_in`, and it sits after the
    // two family bytes the sentinel deliberately keeps.
    image[at + 2..at + 4].copy_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Rewrite a four-byte sentinel outright, insisting it occurs exactly once.
fn patch_addr(
    image: &mut [u8],
    name: &'static str,
    sentinel: u32,
    value: [u8; 4],
) -> Result<(), CdpfwdError> {
    let at = super::sentinel::find_exactly_once(image, sentinel)
        .map_err(|found| CdpfwdError::Sentinel { name, found })?;
    image[at..at + 4].copy_from_slice(&value);
    Ok(())
}

/// The forwarder, with this deployment's address and port written into it.
///
/// Both ends carry the *same* port, which is what makes "it forwards exactly
/// one port" a statement about one constant rather than a pair that could
/// drift.
pub fn forwarder() -> Result<Vec<u8>, CdpfwdError> {
    let mut image = IMAGE.to_vec();
    patch_addr(&mut image, "address", SENTINEL_ADDR, GUEST_IP)?;
    patch_port(&mut image, "listen port", SENTINEL_LISTEN_PORT, CDP_PORT)?;
    patch_port(&mut image, "upstream port", SENTINEL_UPSTREAM_PORT, CDP_PORT)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Every syscall the program is allowed to make. `execve` (221), `clone`
    /// (220) and `openat` (56) are conspicuously absent and that absence is the
    /// point; the numbers were read out of `asm-generic/unistd.h` in a
    /// `linux/arm64` container rather than from memory.
    const ALLOWED: &[u32] = &[
        20,  // epoll_create1
        21,  // epoll_ctl
        22,  // epoll_pwait
        57,  // close
        64,  // write
        94,  // exit_group
        198, // socket
        200, // bind
        201, // listen
        203, // connect
        206, // sendto
        207, // recvfrom
        208, // setsockopt
        210, // shutdown
        242, // accept4
    ];

    /// Decode the syscall vocabulary straight out of the shipped bytes.
    ///
    /// Every `svc #0` must be immediately preceded by a `movz x8, #imm16`, so
    /// the number is knowable statically; anything else would mean a syscall
    /// whose number is computed at run time, which is exactly what a decode
    /// like this exists to refuse.
    fn syscalls(image: &[u8]) -> Vec<u32> {
        let word = |i: usize| u32::from_le_bytes(image[i..i + 4].try_into().unwrap());
        let mut found = Vec::new();
        for i in (4..image.len() - 3).step_by(4) {
            if word(i) != 0xD400_0001 {
                continue;
            }
            let prev = word(i - 4);
            // MOVZ Xd, #imm16, LSL #0 is 1101_0010_100 followed by imm16 and
            // Rd; requiring hw == 0 and Rd == x8 pins both the register and the
            // shift, so `movk` chains and wide immediates cannot slip past.
            assert_eq!(
                prev & 0xFFE0_001F,
                0xD280_0008,
                "the svc at offset {i} is not preceded by `movz x8, #imm`; its \
                 syscall number is not statically knowable and this guard \
                 cannot vouch for the program"
            );
            found.push((prev >> 5) & 0xFFFF);
        }
        found
    }

    /// The security-critical guard, and the reason the program is auditable at
    /// all: the vocabulary is read out of the bytes that ship, not out of the
    /// comment beside them.
    #[test]
    fn the_syscall_vocabulary_is_exactly_the_allow_list() {
        let found = syscalls(IMAGE);
        assert!(!found.is_empty(), "no syscalls decoded at all");
        for nr in &found {
            assert!(
                ALLOWED.contains(nr),
                "cdpfwd.bin issues syscall {nr}, which is not on the allow list. \
                 If that is deliberate, justify it in cdpfwd.S and add it here."
            );
        }
        // And the allow list may not rot in the other direction either: a
        // permission nobody uses is a permission that should not be granted.
        for nr in ALLOWED {
            assert!(
                found.contains(nr),
                "syscall {nr} is allowed but never used; drop it from the list"
            );
        }
    }

    /// Stated as the property rather than as a list of numbers, because this is
    /// the sentence the threat model makes: it is not a shell and it is not
    /// `/process/exec` by another name.
    #[test]
    fn it_cannot_create_a_process_or_open_a_file() {
        let found = syscalls(IMAGE);
        for (nr, name) in [
            (220u32, "clone"),
            (221, "execve"),
            (281, "execveat"),
            (56, "openat"),
            (1071, "fork"),
        ] {
            assert!(
                !found.contains(&nr),
                "cdpfwd.bin issues {name} ({nr}); it must never create a process \
                 or open a file"
            );
        }
    }

    #[test]
    fn the_image_is_a_static_aarch64_elf() {
        assert_eq!(&IMAGE[0..4], b"\x7fELF", "not an ELF");
        assert_eq!(IMAGE[4], 2, "not 64-bit");
        assert_eq!(IMAGE[5], 1, "not little-endian");
        // ET_EXEC (2), not ET_DYN: a dynamic object would need an interpreter,
        // and the whole point is to depend on nothing.
        assert_eq!(u16::from_le_bytes([IMAGE[16], IMAGE[17]]), 2, "not ET_EXEC");
        // EM_AARCH64 (183).
        assert_eq!(
            u16::from_le_bytes([IMAGE[18], IMAGE[19]]),
            183,
            "not aarch64"
        );
    }

    #[test]
    fn the_forwarder_is_installed_at_the_root_where_no_symlink_can_swallow_it() {
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
            ("listen port", SENTINEL_LISTEN_PORT),
            ("upstream port", SENTINEL_UPSTREAM_PORT),
        ] {
            let n = IMAGE.windows(4).filter(|w| *w == s.to_le_bytes()).count();
            assert_eq!(n, 1, "{name} sentinel occurs {n} times, expected 1");
        }
    }

    /// The address and the port must come from chm's constants, not from the
    /// assembly. A second copy is a copy that drifts, and a drifted port would
    /// leave the forwarder dialling a Chromium that is not there while every
    /// unit test stayed green.
    #[test]
    fn the_forwarder_carries_the_address_and_port_chm_declares() {
        let img = forwarder().expect("forwarder");
        assert!(
            img.windows(4).any(|w| w == GUEST_IP),
            "guest address {GUEST_IP:?} is not present in the patched binary"
        );
        // Not just present: present *where a `sockaddr_in` keeps its port*.
        // Bytes in the right image at the wrong offset configure nothing, and
        // a guard that only searched would not notice.
        for (name, sentinel) in [
            ("listen", SENTINEL_LISTEN_PORT),
            ("upstream", SENTINEL_UPSTREAM_PORT),
        ] {
            let at = super::super::sentinel::find_exactly_once(IMAGE, sentinel)
                .unwrap_or_else(|n| panic!("{name} sentinel occurs {n} times"));
            assert_eq!(
                img[at..at + 2],
                IMAGE[at..at + 2],
                "patching the {name} port overwrote the address family beside it"
            );
            assert_eq!(
                img[at + 2..at + 4],
                CDP_PORT.to_be_bytes(),
                "the {name} sockaddr does not carry port {CDP_PORT}"
            );
        }
        for s in [SENTINEL_ADDR, SENTINEL_LISTEN_PORT, SENTINEL_UPSTREAM_PORT] {
            assert!(
                !img.windows(4).any(|w| w == s.to_le_bytes()),
                "sentinel {s:#x} was left in place"
            );
        }
    }

    /// The one-port property, read out of the produced image rather than
    /// asserted about the source: both `sockaddr_in`s carry the same port, so
    /// there is no pair of numbers that could drift apart into two ports.
    #[test]
    fn both_ends_of_the_relay_carry_the_same_single_port() {
        let img = forwarder().expect("forwarder");
        let listen = super::super::sentinel::find_exactly_once(IMAGE, SENTINEL_LISTEN_PORT)
            .expect("listen sentinel");
        let upstream = super::super::sentinel::find_exactly_once(IMAGE, SENTINEL_UPSTREAM_PORT)
            .expect("upstream sentinel");
        assert_eq!(
            img[listen + 2..listen + 4],
            img[upstream + 2..upstream + 4],
            "the two ends of the relay carry different ports"
        );
        assert_eq!(
            u16::from_be_bytes([img[listen + 2], img[listen + 3]]),
            CDP_PORT
        );
    }

    #[test]
    fn patching_refuses_rather_than_guessing_when_a_sentinel_is_not_unique() {
        let mut none = vec![0u8; 32];
        assert_eq!(
            patch_addr(&mut none, "address", SENTINEL_ADDR, [1, 2, 3, 4]),
            Err(CdpfwdError::Sentinel {
                name: "address",
                found: 0
            })
        );
        let mut two = Vec::new();
        two.extend_from_slice(&SENTINEL_LISTEN_PORT.to_le_bytes());
        two.extend_from_slice(&[0u8; 8]);
        two.extend_from_slice(&SENTINEL_LISTEN_PORT.to_le_bytes());
        assert_eq!(
            patch_port(&mut two, "listen port", SENTINEL_LISTEN_PORT, 9222),
            Err(CdpfwdError::Sentinel {
                name: "listen port",
                found: 2
            })
        );
    }

    /// A binary in a source tree is only acceptable if it can be shown to come
    /// from the source beside it. This is the proof.
    ///
    /// Unlike the `nicfg` and `modload` equivalents it needs no linker, which
    /// is why it actually runs: `rust-lld` is absent from a Homebrew rust
    /// install, so those two skip there (#340). This needs only `clang` and
    /// `objcopy`.
    #[test]
    fn the_binary_is_reproducible_from_the_source() {
        let sysroot = match Command::new("rustc").arg("--print").arg("sysroot").output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => return,
        };
        let objcopy = format!("{sysroot}/lib/rustlib/aarch64-apple-darwin/bin/rust-objcopy");
        if !std::path::Path::new(&objcopy).exists() {
            return;
        }
        if Command::new("clang").arg("--version").output().is_err() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("cdpfwd-repro-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oci/cdpfwd.S");
        let obj = dir.join("cdpfwd.o");
        let stripped = dir.join("cdpfwd.bin");

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
        let ok = Command::new(&objcopy)
            .args(["-O", "binary", "--only-section=.text"])
            .arg(&obj)
            .arg(&stripped)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "objcopy failed on an object clang had just produced");

        let rebuilt = std::fs::read(&stripped).expect("rebuilt binary");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            rebuilt.len(),
            IMAGE.len(),
            "cdpfwd.bin is {} bytes but cdpfwd.S assembles to {}. \
             Rebuild it — see chm/src/oci/cdpfwd.S for the command.",
            IMAGE.len(),
            rebuilt.len()
        );
        assert!(
            rebuilt == IMAGE,
            "cdpfwd.bin does not match cdpfwd.S. The checked-in binary must be \
             rebuilt from the source beside it, or the source is not what runs."
        );
    }

    /// The program must carry no relocations, or `objcopy -O binary` would emit
    /// bytes with holes in them where addresses should be and the guest would
    /// jump into nothing.
    #[test]
    fn the_program_needs_no_relocation() {
        // A `.rela.text` in the object would mean an unresolved reference. The
        // reproducibility test already proves the object's `.text` is the whole
        // program; this proves nothing was left for a linker to fill in.
        let entry = u64::from_le_bytes(IMAGE[24..32].try_into().unwrap());
        assert_ne!(entry, 0, "e_entry is zero, which no linker filled in");
        let phoff = u64::from_le_bytes(IMAGE[32..40].try_into().unwrap());
        assert_eq!(phoff, 64, "program headers must follow the ELF header");
        assert_eq!(
            u16::from_le_bytes([IMAGE[56], IMAGE[57]]),
            2,
            "expected exactly two PT_LOADs: text and BSS"
        );
    }

    // ------------------------------------------------------------------
    // Behaviour, which needs a Linux kernel to observe.
    //
    // Static decoding proves what the program *cannot* do. What it *does* --
    // one listening socket, ignoring argv, many flows at once, a half-close
    // that arrives -- is only observable by running it, so these drive the real
    // binary in a `linux/arm64` container and read `/proc/net/tcp`.
    //
    // They skip when Docker is absent, because not every contributor has it.
    // `CHM_CDPFWD_CONTAINER=required` turns that skip into a failure, so a
    // mutation run cannot pass by quietly skipping the guards it is meant to
    // break.
    // ------------------------------------------------------------------

    /// Reports the guard's findings as `key=value` lines. Deliberately no JSON:
    /// the parser on this side should be too simple to be wrong.
    const HARNESS: &str = include_str!("cdpfwd_harness.py");

    struct Findings(Vec<(String, String)>);

    impl Findings {
        fn get(&self, key: &str) -> &str {
            self.0
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("the harness reported no {key}: {:?}", self.0))
        }
    }

    /// Run the harness against the real forwarder, or `None` when there is no
    /// Docker to run it in.
    fn in_container() -> Option<Findings> {
        let required = std::env::var("CHM_CDPFWD_CONTAINER").as_deref() == Ok("required");
        let have_docker = Command::new("docker")
            .args(["version", "--format", "{{.Server.Os}}"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !have_docker {
            assert!(
                !required,
                "CHM_CDPFWD_CONTAINER=required but Docker is not running, so \
                 the behavioural guards cannot be observed"
            );
            return None;
        }

        let dir = std::env::temp_dir().join(format!("cdpfwd-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("cdpfwd"), forwarder().expect("forwarder")).expect("write image");
        std::fs::write(dir.join("harness.py"), HARNESS).expect("write harness");

        let out = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--platform",
                "linux/arm64",
                "--cap-add",
                "NET_ADMIN",
                "-v",
            ])
            .arg(format!("{}:/w", dir.display()))
            .args(["python:3.12-alpine", "python", "/w/harness.py"])
            .arg(format!(
                "{}.{}.{}.{}",
                GUEST_IP[0], GUEST_IP[1], GUEST_IP[2], GUEST_IP[3]
            ))
            .arg(CDP_PORT.to_string())
            .output()
            .expect("docker run");
        let _ = std::fs::remove_dir_all(&dir);

        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                !required,
                "CHM_CDPFWD_CONTAINER=required and the harness failed:\n\
                 {text}\n{err}"
            );
            // An arm64 image that will not pull is a missing capability, not a
            // failure of the forwarder.
            return None;
        }
        let findings: Vec<(String, String)> = text
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        assert!(!findings.is_empty(), "the harness reported nothing:\n{text}");
        // The qemu trap: `--platform linux/arm64` can silently give an emulated
        // x86_64, and then none of this measured what it claims to.
        assert_eq!(
            findings
                .iter()
                .find(|(k, _)| k == "uname")
                .map(|(_, v)| v.as_str()),
            Some("aarch64"),
            "the container is not really aarch64:\n{text}"
        );
        Some(Findings(findings))
    }

    /// Security-critical, and one of the two #339 names: whatever else it does,
    /// the forwarder must open **one** listening socket, at the guest's own
    /// address, on the one port.
    #[test]
    fn it_listens_on_exactly_one_socket() {
        let Some(f) = in_container() else { return };
        let want = format!(
            "{}.{}.{}.{}:{CDP_PORT}",
            GUEST_IP[0], GUEST_IP[1], GUEST_IP[2], GUEST_IP[3]
        );
        assert_eq!(
            f.get("new_listeners"),
            want,
            "the forwarder's listening set is not exactly {want}"
        );
        // And it is not a wildcard, which would put the port on every address
        // the guest ever gains rather than the one chm dials.
        assert!(!f.get("new_listeners").starts_with("0.0.0.0:"));
    }

    /// Security-critical, and the other one #339 names: it is started with
    /// `9999 0.0.0.0 /bin/sh` on argv and none of it means anything.
    #[test]
    fn argv_cannot_widen_it() {
        let Some(f) = in_container() else { return };
        assert_eq!(
            f.get("argv"),
            "9999 0.0.0.0 /bin/sh",
            "the harness did not pass the argv this guard exists to ignore"
        );
        let want = format!(
            "{}.{}.{}.{}:{CDP_PORT}",
            GUEST_IP[0], GUEST_IP[1], GUEST_IP[2], GUEST_IP[3]
        );
        assert_eq!(
            f.get("listeners_after"),
            want,
            "argv changed what the forwarder listens on"
        );
        assert_eq!(
            f.get("other_port"),
            "refused",
            "a port from argv was reachable"
        );
        assert_eq!(f.get("alive"), "yes", "the forwarder died on its own argv");
    }

    /// #330 measured the NAT to 96 parallel flows and one page load opens ~80,
    /// so the forwarder must not be the new bottleneck -- and must not cross
    /// two flows' bytes, which a shared buffer would.
    #[test]
    fn ninety_six_concurrent_flows_do_not_cross_streams() {
        let Some(f) = in_container() else { return };
        assert_eq!(
            f.get("concurrent_ok"),
            "96",
            "not every concurrent flow got its own bytes back: {}",
            f.get("concurrent_detail")
        );
        // Correct-under-load is not the same claim as concurrent: a forwarder
        // that served them strictly one at a time would also return every
        // byte. So the flows hold their connections open until the last has
        // arrived, and this is the count of upstream connections the far side
        // had open at once. A single-slot forwarder cannot reach 96 and the
        // barrier breaks instead.
        assert_eq!(
            f.get("peak_upstream"),
            "96",
            "only {} upstream connections were ever open at once",
            f.get("peak_upstream")
        );
        // More at once than there are slots: the listener disarms, the kernel's
        // backlog holds them, and every one still completes. That is the proof
        // there is no accept-and-drop and no busy-wait.
        assert_eq!(
            f.get("over_capacity_ok"),
            "200",
            "flows beyond the slot table were lost rather than queued"
        );
    }

    /// A CDP client that stops sending must still receive what the browser had
    /// left to say, and must then see the end of it.
    #[test]
    fn a_half_close_is_propagated_in_both_directions() {
        let Some(f) = in_container() else { return };
        assert_eq!(
            f.get("half_close_tail"),
            "TAIL",
            "the far side's last bytes did not survive our shutdown(SHUT_WR)"
        );
        assert_eq!(
            f.get("half_close_eof"),
            "yes",
            "the far side's close never reached us, so a client would hang"
        );
    }

    /// Bulk is the only thing that fills a buffer, and a reader that stops
    /// reading is the only thing that fills the forwarder's own send queue --
    /// which is the only way its partial-write cursor is ever used.
    #[test]
    fn a_transfer_larger_than_the_buffers_arrives_intact() {
        let Some(f) = in_container() else { return };
        assert_eq!(
            f.get("bulk_ok"),
            "yes",
            "4 MiB through one connection did not arrive byte for byte ({} \
             bytes back)",
            f.get("bulk_bytes")
        );
        assert_eq!(
            f.get("slow_reader_ok"),
            "yes",
            "a client that stopped reading did not get its bytes back \
             unchanged ({} bytes), so a partial write was mishandled",
            f.get("slow_reader_bytes")
        );
    }
}
