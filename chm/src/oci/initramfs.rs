// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Laying an unpacked rootfs out as a cpio initramfs the kernel can unpack.
//!
//! # Why cpio
//!
//! The kernel's built-in initramfs loader reads exactly one format: **newc**
//! (the "SVR4 / new ASCII" cpio variant), uncompressed or wrapped in one of a
//! few compressors. It is a stream of 110-byte ASCII headers, each followed by
//! a NUL-terminated name and the file body, both padded to 4 bytes. There is no
//! superblock, no allocator, no journal, no inode table to lay out — which is
//! precisely why it is the format we can write correctly on a Mac, and ext4 is
//! not.
//!
//! # The things that silently do not boot
//!
//! Three details here are load-bearing, and each fails as an unexplained kernel
//! panic rather than an error:
//!
//! 1. **`/init` must exist and be executable.** The kernel runs `/init` from
//!    the initramfs; if it is missing it falls through to mounting a root
//!    filesystem it has not been given and panics with `No working init found`.
//! 2. **The trailer must be exactly `TRAILER!!!`** with a zero-size body. Get
//!    it wrong and the unpacker keeps reading past the end of the archive.
//! 3. **Every parent directory must appear before its children.** cpio has no
//!    "create parents" behaviour; a file whose directory has not been seen is
//!    silently dropped, and the guest boots into a rootfs missing exactly the
//!    files you most wanted.
//!
//! The archive is therefore emitted from a sorted path list, which makes (3)
//! true by construction rather than by hoping the layer order was kind.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::iter;

use super::entry::EntryKind;

/// `newc` magic. The other cpio variants are not read by the kernel.
const MAGIC: &str = "070701";

/// File type bits, as they appear in the cpio mode field.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// A rootfs assembled from layers, ready to serialise.
///
/// A `BTreeMap` rather than a `Vec` for two reasons: later layers overwrite
/// earlier ones at the same path (which is exactly what an image expects), and
/// iteration is in path order, which is what makes parents-before-children
/// true.
#[derive(Debug, Default)]
pub struct Rootfs {
    files: BTreeMap<String, Node>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

impl Rootfs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn contains(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    /// Read a node back. Only the tests need this — `apply` writes through
    /// `insert`/`whiteout`/`opaque` and `write_cpio` iterates.
    #[cfg(test)]
    pub fn get(&self, path: &str) -> Option<&Node> {
        self.files.get(path)
    }

    /// Total bytes of file content — what the initramfs will cost in guest RAM,
    /// near enough to size the guest from.
    pub fn content_bytes(&self) -> u64 {
        self.files.values().map(|n| n.data.len() as u64).sum()
    }

    pub fn insert(&mut self, path: String, kind: EntryKind, data: Vec<u8>) {
        self.files.insert(path, Node { kind, data });
    }

    /// Remove one path — an OCI whiteout. Removes a whole subtree when the
    /// victim is a directory, because deleting a directory in the layer model
    /// deletes what was under it.
    pub fn whiteout(&mut self, path: &str) {
        let prefix = format!("{path}/");
        self.files
            .retain(|k, _| k != path && !k.starts_with(&prefix));
    }

    /// Clear everything *under* `dir` while keeping `dir` itself — an OCI
    /// opaque directory. The distinction matters: the upper layer is saying
    /// "this directory's contents are mine alone", not "this directory is
    /// gone".
    pub fn opaque(&mut self, dir: &str) {
        if dir.is_empty() {
            self.files.clear();
            return;
        }
        let prefix = format!("{dir}/");
        self.files.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Make sure every parent directory of every entry exists.
    ///
    /// Real layers usually include their directories, but not always — a layer
    /// carrying only `usr/local/bin/tool` is legal, and without this the tool
    /// would be dropped by the kernel's unpacker with no diagnostic at all.
    pub fn materialize_parents(&mut self) {
        let mut needed: Vec<String> = Vec::new();
        for path in self.files.keys() {
            let mut acc = String::new();
            let mut parts: Vec<&str> = path.split('/').collect();
            parts.pop();
            for p in parts {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(p);
                if !self.files.contains_key(&acc) {
                    needed.push(acc.clone());
                }
            }
        }
        for dir in needed {
            self.files.entry(dir).or_insert_with(|| Node {
                kind: EntryKind::Directory { mode: 0o755 },
                data: Vec::new(),
            });
        }
    }
}

/// Pad a byte vector to a 4-byte boundary, which newc requires after both the
/// name and the body.
fn pad4(out: &mut Vec<u8>, written: usize) {
    let rem = written % 4;
    if rem != 0 {
        out.extend(iter::repeat_n(0u8, 4 - rem));
    }
}

/// Write one newc record.
///
/// The header is thirteen 8-digit hex fields after the magic.
///
/// `ino` and `nlink` together are how cpio expresses hardlinks, and getting
/// them wrong is silent in both directions: a shared `ino` on unrelated files
/// makes the second come out empty, and a unique `ino` on every link turns a
/// busybox image into 400 copies of the same 1 MiB binary. See
/// [`write_cpio`].
fn record(out: &mut Vec<u8>, ino: u32, nlink: u32, mode: u32, name: &str, body: &[u8]) {
    let namesize = name.len() + 1;
    let mut h = String::with_capacity(110);
    let _ = write!(h, "{MAGIC}");
    for v in [
        ino,
        mode,
        0, // uid — everything is root; see the module docs on why we do not
        0, // gid   carry image ownership into a single-user sandbox
        nlink,
        0, // mtime — zeroed so the same image builds byte-identically twice
        body.len() as u32,
        0, // devmajor
        0, // devminor
        0, // rdevmajor
        0, // rdevminor
        namesize as u32,
        0, // check (unused for newc)
    ] {
        let _ = write!(h, "{v:08X}");
    }
    out.extend_from_slice(h.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad4(out, h.len() + namesize);
    out.extend_from_slice(body);
    pad4(out, body.len());
}

/// Follow a hardlink to the regular file it ultimately names.
///
/// Chains are capped: an image can contain a link cycle, and the kernel's
/// unpacker would not survive one any better than we would.
fn resolve_link<'a>(files: &'a BTreeMap<String, Node>, start: &'a str) -> Option<&'a str> {
    let mut cur = start;
    for _ in 0..32 {
        match files.get(cur) {
            Some(Node {
                kind: EntryKind::Hardlink { target },
                ..
            }) => cur = target.as_str(),
            Some(_) => return Some(cur),
            None => return None,
        }
    }
    None
}

/// Serialise a rootfs as an uncompressed newc cpio archive.
///
/// Paths are emitted with a leading `.` (`./usr/bin/env`), which is what real
/// initramfs archives contain and what the kernel's unpacker expects to be
/// relative to the new root.
pub fn write_cpio(rootfs: &Rootfs) -> Vec<u8> {
    // Pass 1: group hardlinks. `ino` is the identity the kernel's unpacker uses
    // to recognise two names as one file, so every member of a group gets the
    // same one and `nlink` counts them.
    //
    // This is not an optimisation. busybox is a single binary hardlinked ~400
    // times: emitting a copy per link turned a 1.8 MiB layer into a 467 MiB
    // initramfs that would not fit in the guest's RAM. Measured, not predicted.
    let mut ino_of: BTreeMap<String, u32> = BTreeMap::new();
    let mut nlink_of: BTreeMap<String, u32> = BTreeMap::new();
    let mut next_ino: u32 = 1;
    for path in rootfs.files.keys() {
        // A group is keyed by the resolved target; a plain file is its own.
        let anchor = match &rootfs.files[path].kind {
            EntryKind::Hardlink { target } => resolve_link(&rootfs.files, target)
                .unwrap_or(path.as_str())
                .to_string(),
            _ => path.clone(),
        };
        let ino = *ino_of.entry(anchor.clone()).or_insert_with(|| {
            let v = next_ino;
            next_ino = next_ino.wrapping_add(1);
            v
        });
        ino_of.insert(path.clone(), ino);
        *nlink_of.entry(anchor).or_insert(0) += 1;
    }

    // Pass 2: emit. Only the first record of a group carries the body; the rest
    // are zero-length, which is exactly what `init/initramfs.c::find_link`
    // expects — it remembers the first name it saw for an inode and links the
    // later ones to it.
    let mut out = Vec::new();
    let mut body_written: BTreeMap<u32, bool> = BTreeMap::new();
    for (path, node) in &rootfs.files {
        let name = format!("./{path}");
        let ino = ino_of.get(path).copied().unwrap_or(1);
        let anchor = match &node.kind {
            EntryKind::Hardlink { target } => resolve_link(&rootfs.files, target)
                .unwrap_or(path.as_str())
                .to_string(),
            _ => path.clone(),
        };
        let nlink = nlink_of.get(&anchor).copied().unwrap_or(1);
        let first = !body_written.get(&ino).copied().unwrap_or(false);
        match &node.kind {
            EntryKind::Directory { mode } => {
                // Directories never share an inode, so nlink stays 1.
                record(&mut out, ino, 1, S_IFDIR | (mode & 0o7777), &name, &[]);
            }
            EntryKind::File { mode, .. } => {
                let body: &[u8] = if first { &node.data } else { &[] };
                record(&mut out, ino, nlink, S_IFREG | (mode & 0o7777), &name, body);
                body_written.insert(ino, true);
            }
            EntryKind::Symlink { target } => {
                // A symlink's target is its *body* in cpio, not a header field.
                record(&mut out, ino, 1, S_IFLNK | 0o777, &name, target.as_bytes());
            }
            EntryKind::Hardlink { .. } => {
                // A link whose target survived a whiteout is emitted as a group
                // member; a dangling one becomes an empty file rather than an
                // archive the kernel cannot unpack.
                let body: &[u8] = match (first, rootfs.files.get(&anchor)) {
                    (true, Some(n)) => &n.data,
                    _ => &[],
                };
                record(&mut out, ino, nlink, S_IFREG | 0o755, &name, body);
                body_written.insert(ino, true);
            }
        }
    }
    record(&mut out, 0, 1, 0, "TRAILER!!!", &[]);
    out
}

/// The `init` a container-derived rootfs does not come with.
///
/// A container image has no init: the runtime provides `/proc`, `/sys`, `/dev`
/// and then execs the entrypoint. Booted as a guest there is no runtime, so
/// this script does that job — mount the pseudo-filesystems, make the device
/// nodes we refused to take from image content, then hand over.
///
/// It is `/bin/sh` rather than a compiled init because every base image that
/// can host a shell session already has a shell, and shipping a binary would
/// mean shipping one per libc.
pub fn default_init(entrypoint: &str, env: &[String], workdir: Option<&str>) -> String {
    // The image's own environment, delivered rather than merely understood.
    //
    // This is not a nicety. `python:3.12-alpine` installs to /usr/local/bin and
    // puts that on PATH *in the image config*; without it the guest boots to a
    // shell where `python3: not found` — the binary is right there, and the
    // sandbox looks broken. Measured on hardware, not predicted.
    let mut exports = String::new();
    for kv in env {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            // A name a shell cannot hold is not delivered silently mangled.
            continue;
        }
        let _ = writeln!(exports, "export {k}={}", sh_quote(v));
    }
    if exports.is_empty() {
        // A container image with no PATH still needs one, and a bare `sh`
        // inherits nothing from a kernel.
        exports
            .push_str("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n");
    }
    let cd = workdir.map_or_else(String::new, |d| format!("cd {} 2>/dev/null\n", sh_quote(d)));

    format!(
        r#"#!/bin/sh
# Generated by `chm image build` -- the init a container image does not carry.
#
# A container runtime sets up these mounts and device nodes before running the
# entrypoint. Booted as a guest there is no runtime, so we do it here. Each
# mount is tolerated failing: a minimal image may lack the mount point, and a
# missing /sys is much better than a kernel panic before any output exists.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || {{
    # devtmpfs is not compiled into every kernel. The handful of nodes a shell
    # session actually needs are cheap to make by hand.
    mkdir -p /dev
    [ -c /dev/console ] || mknod /dev/console c 5 1 2>/dev/null
    [ -c /dev/null ] || mknod /dev/null c 1 3 2>/dev/null
    [ -c /dev/tty ] || mknod /dev/tty c 5 0 2>/dev/null
}}
mount -t tmpfs tmpfs /tmp 2>/dev/null
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts 2>/dev/null

# A container image's /etc/resolv.conf is usually absent or points at a runtime
# resolver that does not exist here.
[ -s /etc/resolv.conf ] || echo "nameserver 1.1.1.1" > /etc/resolv.conf 2>/dev/null

# Loopback, so anything binding 127.0.0.1 works without a network policy.
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null

# The image's declared environment. Without this a shell inherits nothing and
# binaries the image installed outside /bin are unreachable by name.
{exports}{cd}
echo "gimbal: container rootfs up; starting {entrypoint}"
exec {entrypoint}
"#
    )
}

/// Wrap a value so a POSIX shell reads it back byte-for-byte.
///
/// Image `Env` values are attacker-influenced content (they come out of a
/// registry), so this is the same discipline invariant I5 applies to the app's
/// generated commands, not a formatting nicety.
fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(data: &[u8]) -> (EntryKind, Vec<u8>) {
        (
            EntryKind::File {
                mode: 0o644,
                size: data.len() as u64,
            },
            data.to_vec(),
        )
    }

    #[test]
    fn a_later_layer_overwrites_an_earlier_one_at_the_same_path() {
        let mut r = Rootfs::new();
        let (k, d) = f(b"old");
        r.insert("etc/hosts".to_string(), k, d);
        let (k, d) = f(b"new");
        r.insert("etc/hosts".to_string(), k, d);
        assert_eq!(r.get("etc/hosts").unwrap().data, b"new");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_whiteout_on_a_directory_removes_what_was_under_it() {
        let mut r = Rootfs::new();
        for p in ["var/cache", "var/cache/a", "var/cache/deep/b", "var/keep"] {
            let (k, d) = f(b"x");
            r.insert(p.to_string(), k, d);
        }
        r.whiteout("var/cache");
        assert!(!r.contains("var/cache"));
        assert!(!r.contains("var/cache/a"));
        assert!(!r.contains("var/cache/deep/b"));
        assert!(r.contains("var/keep"), "an unrelated path must survive");
    }

    /// Opaque is not whiteout: the directory itself stays, its contents go.
    #[test]
    fn an_opaque_directory_keeps_itself_and_loses_its_contents() {
        let mut r = Rootfs::new();
        for p in ["var/cache", "var/cache/a", "var/other"] {
            let (k, d) = f(b"x");
            r.insert(p.to_string(), k, d);
        }
        r.opaque("var/cache");
        assert!(r.contains("var/cache"), "the directory itself must remain");
        assert!(!r.contains("var/cache/a"));
        assert!(r.contains("var/other"));
    }

    /// The failure mode this exists to prevent is silent: the kernel's unpacker
    /// drops a file whose parent it has not seen, and the guest boots without
    /// it and says nothing.
    #[test]
    fn missing_parent_directories_are_materialized() {
        let mut r = Rootfs::new();
        let (k, d) = f(b"#!/bin/sh\n");
        r.insert("usr/local/bin/tool".to_string(), k, d);
        r.materialize_parents();
        assert!(r.contains("usr"));
        assert!(r.contains("usr/local"));
        assert!(r.contains("usr/local/bin"));
        assert!(matches!(
            r.get("usr/local").unwrap().kind,
            EntryKind::Directory { .. }
        ));
    }

    #[test]
    fn materializing_parents_does_not_clobber_a_real_directory() {
        let mut r = Rootfs::new();
        r.insert(
            "usr".to_string(),
            EntryKind::Directory { mode: 0o700 },
            Vec::new(),
        );
        let (k, d) = f(b"x");
        r.insert("usr/bin/x".to_string(), k, d);
        r.materialize_parents();
        assert!(matches!(
            r.get("usr").unwrap().kind,
            EntryKind::Directory { mode: 0o700 }
        ));
    }

    #[test]
    fn cpio_starts_with_newc_magic_and_ends_with_the_trailer() {
        let mut r = Rootfs::new();
        let (k, d) = f(b"hi");
        r.insert("init".to_string(), k, d);
        let out = write_cpio(&r);
        assert_eq!(&out[0..6], MAGIC.as_bytes());
        let tail = String::from_utf8_lossy(&out[out.len().saturating_sub(64)..]).into_owned();
        assert!(tail.contains("TRAILER!!!"), "{tail}");
    }

    /// Every record must start on a 4-byte boundary, or the kernel's unpacker
    /// reads a header out of the middle of the previous file's body.
    #[test]
    fn every_record_is_four_byte_aligned() {
        let mut r = Rootfs::new();
        // Names and bodies of deliberately awkward lengths.
        for (p, body) in [("a", "1"), ("bb", "22"), ("ccc", "333"), ("dddd", "4444")] {
            let (k, d) = f(body.as_bytes());
            r.insert(p.to_string(), k, d);
        }
        let out = write_cpio(&r);
        let mut off = 0usize;
        let mut seen = 0;
        while off + 110 <= out.len() {
            assert_eq!(off % 4, 0, "record at {off} is not 4-byte aligned");
            assert_eq!(&out[off..off + 6], MAGIC.as_bytes());
            let hex = |a: usize, b: usize| {
                usize::from_str_radix(std::str::from_utf8(&out[off + a..off + b]).unwrap(), 16)
                    .unwrap()
            };
            let filesize = hex(54, 62);
            let namesize = hex(94, 102);
            let name =
                String::from_utf8_lossy(&out[off + 110..off + 110 + namesize - 1]).into_owned();
            off += 110 + namesize;
            off += (4 - off % 4) % 4;
            off += filesize;
            off += (4 - off % 4) % 4;
            seen += 1;
            if name == "TRAILER!!!" {
                break;
            }
        }
        assert_eq!(seen, 5, "four files plus the trailer");
    }

    #[test]
    fn a_symlink_carries_its_target_as_the_body() {
        let mut r = Rootfs::new();
        r.insert(
            "bin/sh".to_string(),
            EntryKind::Symlink {
                target: "/bin/bash".to_string(),
            },
            Vec::new(),
        );
        let out = write_cpio(&r);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("/bin/bash"), "target must be the body");
    }

    #[test]
    fn each_record_gets_its_own_inode() {
        let mut r = Rootfs::new();
        for p in ["a", "b", "c"] {
            let (k, d) = f(b"x");
            r.insert(p.to_string(), k, d);
        }
        let out = write_cpio(&r);
        let inos: Vec<&str> = (0..3)
            .map(|i| {
                let off = find_nth_record(&out, i);
                std::str::from_utf8(&out[off + 6..off + 14]).unwrap()
            })
            .collect();
        assert_eq!(inos.len(), 3);
        assert!(
            inos[0] != inos[1] && inos[1] != inos[2],
            "duplicate inodes make the unpacker treat records as hardlinks: {inos:?}"
        );
    }

    fn find_nth_record(out: &[u8], n: usize) -> usize {
        let mut off = 0usize;
        for _ in 0..n {
            let hex = |a: usize, b: usize| {
                usize::from_str_radix(std::str::from_utf8(&out[off + a..off + b]).unwrap(), 16)
                    .unwrap()
            };
            let filesize = hex(54, 62);
            let namesize = hex(94, 102);
            off += 110 + namesize;
            off += (4 - off % 4) % 4;
            off += filesize;
            off += (4 - off % 4) % 4;
        }
        off
    }

    #[test]
    fn paths_are_emitted_relative_to_the_new_root() {
        let mut r = Rootfs::new();
        let (k, d) = f(b"x");
        r.insert("usr/bin/env".to_string(), k, d);
        let out = write_cpio(&r);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("./usr/bin/env"), "{text}");
    }

    #[test]
    fn content_bytes_measures_what_the_guest_must_hold() {
        let mut r = Rootfs::new();
        let (k, d) = f(&vec![0u8; 1000]);
        r.insert("a".to_string(), k, d);
        let (k, d) = f(&vec![0u8; 24]);
        r.insert("b".to_string(), k, d);
        assert_eq!(r.content_bytes(), 1024);
    }

    #[test]
    fn the_generated_init_mounts_proc_and_execs_the_entrypoint() {
        let s = default_init("/bin/sh", &[], None);
        assert!(s.starts_with("#!/bin/sh"));
        assert!(s.contains("mount -t proc proc /proc"));
        assert!(s.contains("exec /bin/sh"));
    }

    /// devtmpfs is not in every kernel config, and a guest with no
    /// `/dev/console` produces no output at all — the worst possible failure to
    /// debug.
    #[test]
    fn the_init_falls_back_to_making_console_by_hand() {
        let s = default_init("/bin/sh", &[], None);
        assert!(s.contains("mknod /dev/console c 5 1"));
    }

    /// The bug hardware found: `python:3.12-alpine` puts python on PATH in its
    /// image config, and a guest booted without it reports `python3: not found`
    /// while the binary sits in /usr/local/bin. Parsed-but-not-delivered is the
    /// exact false-sell shape this repo keeps catching.
    #[test]
    fn the_images_own_environment_reaches_the_shell() {
        let s = default_init(
            "/bin/sh",
            &["PATH=/usr/local/bin:/usr/bin".to_string()],
            None,
        );
        assert!(s.contains("export PATH='/usr/local/bin:/usr/bin'"), "{s}");
    }

    /// An image with no declared PATH still needs one; a bare `sh` execed by
    /// the kernel inherits nothing.
    #[test]
    fn an_image_with_no_env_still_gets_a_path() {
        let s = default_init("/bin/sh", &[], None);
        assert!(s.contains("export PATH=/usr"), "{s}");
    }

    /// Env values come out of a registry, so they are untrusted input reaching
    /// a generated shell script — invariant I5's discipline, not formatting.
    ///
    /// Asserting a metacharacter is *absent* is the wrong property and this
    /// repo has made that mistake before (V8.3): the characters legitimately
    /// appear inside the quotes. The real property is that a shell parses the
    /// value back to exactly what went in, so this asks the actual shell.
    #[test]
    fn a_hostile_env_value_cannot_break_out_of_its_quotes() {
        for hostile in [
            "a'; rm -rf /; echo '",
            "$(touch /tmp/chm-pwned)",
            "`id`",
            "x\"y",
            "a\\b",
            "; :",
        ] {
            let script = format!("printf %s {}", sh_quote(hostile));
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("run /bin/sh");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                hostile,
                "the shell did not read `{hostile}` back unchanged"
            );
        }
    }

    #[test]
    fn a_name_a_shell_cannot_hold_is_dropped_rather_than_mangled() {
        let s = default_init("/bin/sh", &["BAD-NAME=x".to_string()], None);
        assert!(!s.contains("BAD-NAME"), "{s}");
    }

    #[test]
    fn a_working_directory_is_entered_before_the_entrypoint() {
        let s = default_init("/bin/sh", &[], Some("/srv/app"));
        assert!(s.contains("cd '/srv/app'"), "{s}");
        assert!(
            s.find("cd '/srv/app'").unwrap() < s.find("exec /bin/sh").unwrap(),
            "cd must precede exec"
        );
    }

    /// The `nlink` field is not bookkeeping — it is the switch.
    ///
    /// `init/initramfs.c::maybe_link()` opens with `if (nlink >= 2)`. Below
    /// that it never calls `find_link()` at all, so a group emitted with
    /// `nlink = 1` is *not* linked by the guest: each name is created fresh,
    /// and since only the first member carries a body every other name lands
    /// as a **zero-byte file**. For busybox that is 410 commands that exist,
    /// are executable, and do nothing.
    ///
    /// A mutation test found the existing size assertion could not catch this:
    /// the bytes we write stay small either way, because the saving comes from
    /// the shared body, not from `nlink`. The host-side size and the
    /// guest-side link are two different properties and only one of them was
    /// being checked.
    #[test]
    fn a_hardlink_group_is_emitted_with_an_nlink_the_kernel_will_act_on() {
        let mut r = Rootfs::new();
        let (k, d) = f(b"busybox binary");
        r.insert("bin/busybox".to_string(), k, d);
        for n in 0..3 {
            r.insert(
                format!("bin/cmd{n}"),
                EntryKind::Hardlink {
                    target: "bin/busybox".to_string(),
                },
                Vec::new(),
            );
        }
        let out = write_cpio(&r);

        // newc header: magic(6) ino(8) mode(8) uid(8) gid(8) nlink(8) ...
        let mut group = Vec::new();
        let mut i = 0;
        while let Some(at) = find_from(&out, MAGIC.as_bytes(), i) {
            let hex = |off: usize| {
                let s = String::from_utf8_lossy(&out[at + off..at + off + 8]).into_owned();
                u32::from_str_radix(&s, 16).unwrap_or(0)
            };
            let (ino, nlink, size) = (hex(6), hex(38), hex(54));
            let nlen = hex(94) as usize;
            let name = String::from_utf8_lossy(&out[at + 110..at + 110 + nlen - 1]).into_owned();
            if name.starts_with("./bin/") {
                group.push((name, ino, nlink, size));
            }
            i = at + 6;
        }

        assert_eq!(group.len(), 4, "one binary plus three commands: {group:?}");
        let ino = group[0].1;
        for (name, got_ino, nlink, _) in &group {
            assert_eq!(*got_ino, ino, "`{name}` must share the group's inode");
            assert_eq!(
                *nlink, 4,
                "`{name}` needs nlink >= 2 or the guest will not link it at all"
            );
        }
        let bodies: u32 = group.iter().map(|g| g.3).sum();
        assert_eq!(bodies, 14, "exactly one member carries the content");
    }

    fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        if from >= hay.len() {
            return None;
        }
        hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    }
}
