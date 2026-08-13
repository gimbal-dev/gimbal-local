// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! A freestanding aarch64 program that inserts kernel modules, for guests that
//! have no tool to do it with.
//!
//! # Why this exists
//!
//! Inserting a module is a **syscall** (`finit_module`), and no shell builtin
//! makes one. The generated init tries `insmod` first, but a container rootfs is
//! under no obligation to ship it: measured, `node:22-slim` — the glibc base the
//! agent story needs, per #224 — has no `insmod`, no `modprobe` and no
//! `/lib/modules` at all. So a loader that assumed busybox would work on Alpine
//! and fail on exactly the image that matters most.
//!
//! This is the same shape of problem, and the same answer, as
//! [`super::nicfg`]: carry the code ourselves rather than depend on the image.
//!
//! # What is checked in
//!
//! [`modload.S`](../../src/oci/modload.S) is the source and is the thing to
//! read. `modload.bin` is that source assembled and linked — under a kilobyte,
//! no libc, no relocations, no dynamic loader.
//!
//! A binary in a source tree is only acceptable if you can prove it came from
//! the source beside it, so [`tests::the_binary_is_reproducible_from_the_source`]
//! rebuilds `modload.S` and compares byte for byte.
//!
//! # Why it takes paths rather than knowing them
//!
//! The modules to load, and their order, are resolved on the host from each
//! module's own `.modinfo` — see [`super::modules`]. Baking a list in here would
//! be a second copy of that answer, and a drifted copy would load `virtio_net`
//! before its transport, which *succeeds* and still leaves the guest with no
//! interface. Passing them on argv keeps one source of truth.

use std::path::Path;

/// The assembled program. See the module docs for its provenance.
const IMAGE: &[u8] = include_bytes!("modload.bin");

/// Where the loader is installed in the guest.
///
/// At the root with no directory component, for the reason
/// [`super::nicfg::GUEST_PATH`] documents having been bitten by: on a usr-merge
/// image an image-controlled directory can be a symlink whose target has not
/// been unpacked yet, and the kernel drops the file without a word.
pub const GUEST_PATH: &str = "gimbal-modload";

/// The program to install in the guest.
///
/// Unlike [`super::nicfg::configurator`] this needs no patching: it carries no
/// constants that are also declared elsewhere, because the module list arrives
/// on argv.
pub fn loader() -> &'static [u8] {
    IMAGE
}

/// The shell command that loads `paths`, in the order given.
///
/// Ordering is the caller's: it comes from the dependency graph in
/// [`super::modules`], and reordering here would silently undo it.
pub fn command(paths: &[String]) -> String {
    let mut out = String::from("/");
    out.push_str(GUEST_PATH);
    for p in paths {
        out.push(' ');
        out.push_str(&shell_quote(p));
    }
    out
}

/// Single-quote for `/bin/sh`, closing and reopening around any embedded quote.
///
/// These paths are chm's own and hold module names, so nothing hostile is
/// expected — but "expected" is not a security property, and the same escaping
/// discipline applies here as everywhere else a string reaches a guest shell.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Whether a path looks like something we should refuse to hand to the loader.
///
/// The loader writes the path it could not load to stderr and carries on, so a
/// bad path is diagnosed rather than silent — but a path with a newline in it
/// would corrupt that report, and a path is never legitimately like that.
pub fn is_reportable(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|s| !s.is_empty() && !s.contains('\n') && !s.contains('\0'))
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
        assert_eq!(u16::from_le_bytes([IMAGE[16], IMAGE[17]]), 2, "not ET_EXEC");
        assert_eq!(
            u16::from_le_bytes([IMAGE[18], IMAGE[19]]),
            183,
            "not aarch64"
        );
    }

    /// Same regression as `nicfg`: on a usr-merge image a directory component
    /// can be a symlink whose target is unpacked later, and the kernel drops
    /// the file silently.
    #[test]
    fn the_loader_is_installed_at_the_root_where_no_symlink_can_swallow_it() {
        assert!(
            !GUEST_PATH.contains('/'),
            "GUEST_PATH {GUEST_PATH:?} has a directory component"
        );
        assert!(!GUEST_PATH.starts_with('.') && !GUEST_PATH.is_empty());
    }

    /// The order the caller resolved must survive into the command. Loading
    /// `virtio_net` before `virtio_mmio` returns success and still leaves the
    /// guest with no interface — a failure that looks like ours, not the
    /// kernel's.
    #[test]
    fn the_command_preserves_the_order_it_is_given() {
        let cmd = command(&[
            "/gimbal-modules/virtio_mmio.ko".to_string(),
            "/gimbal-modules/failover.ko".to_string(),
            "/gimbal-modules/virtio_net.ko".to_string(),
        ]);
        let mmio = cmd.find("virtio_mmio").expect("mmio present");
        let net = cmd.find("virtio_net").expect("net present");
        assert!(mmio < net, "transport must come first: {cmd}");
        assert!(cmd.starts_with("/gimbal-modload "), "{cmd}");
    }

    /// The real property, asked of the real shell: whatever we build, `sh`
    /// must read back exactly the path we meant. Asserting a metacharacter is
    /// *absent* is the wrong question — this repo has got that wrong twice
    /// (V8.3, V9.7) because the characters legitimately appear inside quotes.
    #[test]
    fn a_hostile_path_is_read_back_unchanged_by_a_real_shell() {
        for hostile in [
            "/a b.ko",
            "/a'b.ko",
            "/a;touch /tmp/chm-modload-pwned;.ko",
            "/a$(touch /tmp/chm-modload-pwned).ko",
            "/a`touch /tmp/chm-modload-pwned`.ko",
            "/a\"b.ko",
            "/a|b.ko",
            "/a&&b.ko",
        ] {
            let script = format!("printf '%s' {}", shell_quote(hostile));
            let out = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("sh runs");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                hostile,
                "sh did not read back {hostile:?}"
            );
        }
        assert!(
            !std::path::Path::new("/tmp/chm-modload-pwned").exists(),
            "an injection probe fired"
        );
    }

    #[test]
    fn a_path_that_would_corrupt_the_loaders_report_is_not_reportable() {
        assert!(is_reportable(Path::new("/gimbal-modules/virtio_net.ko")));
        assert!(!is_reportable(Path::new("/a\nb.ko")));
        assert!(!is_reportable(Path::new("")));
    }

    /// A binary in a source tree is only acceptable if it can be shown to come
    /// from the source beside it. This is the proof. It skips when the
    /// toolchain is missing rather than failing.
    #[test]
    fn the_binary_is_reproducible_from_the_source() {
        let sysroot = match Command::new("rustc").arg("--print").arg("sysroot").output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => return,
        };
        let lld = format!("{sysroot}/lib/rustlib/aarch64-apple-darwin/bin/rust-lld");
        let objcopy = format!("{sysroot}/lib/rustlib/aarch64-apple-darwin/bin/rust-objcopy");
        if !Path::new(&lld).exists() || !Path::new(&objcopy).exists() {
            return;
        }
        if Command::new("clang").arg("--version").output().is_err() {
            return;
        }

        let dir = std::env::temp_dir().join(format!("modload-repro-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oci/modload.S");
        let obj = dir.join("modload.o");
        let linked = dir.join("modload");
        let stripped = dir.join("modload.bin");

        match Command::new("clang")
            .args(["--target=aarch64-unknown-linux-gnu", "-c", src, "-o"])
            .arg(&obj)
            .output()
        {
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
            "modload.bin is {} bytes but modload.S assembles to {}. \
             Rebuild it — see chm/src/oci/modload.S for the command.",
            IMAGE.len(),
            rebuilt.len()
        );
        assert!(
            rebuilt == IMAGE,
            "modload.bin does not match modload.S. The checked-in binary must be \
             rebuilt from the source beside it, or the source is not what runs."
        );
    }
}
