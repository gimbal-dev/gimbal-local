// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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

use crate::coldboot::CA_SENT_KEY;
use crate::credproxy::cli::{CA_PATH, ENV_PATH};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::iter;
use std::path::Path;
use std::str;

use super::entry::EntryKind;
use crate::coldboot::EPOCH_KEY;
use crate::create::{GATEWAY_IP, GUEST_IP, GUEST_PREFIX_LEN};

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

    /// Read a node back.
    ///
    /// Used by the browser build, which appends to `/etc/passwd` rather than
    /// replacing it (replacing would take `root` with it, and the init runs as
    /// root before it drops), and which needs a victim's size before removing
    /// it in order to report what the subtraction cost.
    pub fn get(&self, path: &str) -> Option<&Node> {
        self.files.get(path)
    }

    /// Every entry in path order, for a serialiser that is not `write_cpio`.
    ///
    /// The order is the `BTreeMap`'s, so parents precede children — the same
    /// property `write_cpio` relies on, and the reason `write_ext2` can build a
    /// directory's contents without a second sort.
    pub fn nodes(&self) -> impl Iterator<Item = (&str, &Node)> {
        self.files.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Follow a hardlink chain to the entry that actually owns the content.
    ///
    /// Exposed because every serialiser has to group hardlinks — a rootfs where
    /// busybox is linked 400 times becomes 400 copies otherwise — and the
    /// chain-walk is not something a caller should reimplement.
    ///
    /// The returned reference borrows the map's own key rather than the caller's
    /// `start`, so the answer outlives the question.
    pub fn resolve_hardlink(&self, start: &str) -> Option<&str> {
        let (mut key, mut node) = self.files.get_key_value(start)?;
        for _ in 0..32 {
            match &node.kind {
                EntryKind::Hardlink { target } => {
                    let (k, n) = self.files.get_key_value(target.as_str())?;
                    key = k;
                    node = n;
                }
                _ => return Some(key.as_str()),
            }
        }
        None
    }

    /// Total bytes of file content — what the initramfs will cost in guest RAM,
    /// near enough to size the guest from.
    pub fn content_bytes(&self) -> u64 {
        self.files.values().map(|n| n.data.len() as u64).sum()
    }

    /// Every path in the image, so a caller can ask a question about the
    /// rootfs as a whole without this type having to know what the question is.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    pub fn insert(&mut self, path: String, kind: EntryKind, data: Vec<u8>) {
        self.files.insert(path, Node { kind, data });
    }

    /// What is at `path` today, if anything.
    ///
    /// Narrower than [`Self::get`] on purpose: the caller that needs this is
    /// asking a question about the *shape* of what is there, and handing it
    /// the node's bytes as well would let it grow into something else.
    pub fn kind_of(&self, path: &str) -> Option<&EntryKind> {
        self.files.get(path).map(|n| &n.kind)
    }

    /// Rewrite `path` so that none of its parent directories is a symlink.
    ///
    /// Writing to `sbin/init` on a usr-merge image — Ubuntu, Debian bookworm,
    /// `node:22-slim` — writes *through* `sbin -> usr/sbin`, and what happens
    /// then is bad in two different ways depending on the serialiser. The cpio
    /// unpacker emits entries in sorted order, so `sbin/init` is unpacked
    /// before `usr/sbin` exists and the kernel drops the file **in silence**;
    /// that is the trap [`super::nicfg::GUEST_PATH`] documents. `write_ext2`
    /// cannot attach a child to a symlink inode at all.
    ///
    /// Measured: a `--disk` build on `ubuntu:24.04` put the generated init at
    /// `sbin/init`, and the guest booted to
    /// `Run /sbin/init as init process` / `Run /bin/sh as init process` —
    /// the kernel tried it, could not find it, and fell through to a shell.
    /// The image looked fine and simply did not run its own init.
    ///
    /// Absolute link targets are taken as rootfs-relative, which is what they
    /// mean inside an image. A chain longer than 32 links is not resolved: it
    /// is either a loop or something adversarial, and returning the path
    /// unchanged leaves the caller no worse off than before this existed.
    pub fn resolve_parents(&self, path: &str) -> String {
        let Some((dir, name)) = path.rsplit_once('/') else {
            return path.to_string();
        };
        let mut acc = String::new();
        for part in dir.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            for _ in 0..32 {
                match self.files.get(&acc).map(|n| &n.kind) {
                    Some(EntryKind::Symlink { target }) => {
                        acc = if let Some(abs) = target.strip_prefix('/') {
                            abs.to_string()
                        } else if let Some((parent, _)) = acc.rsplit_once('/') {
                            format!("{parent}/{target}")
                        } else {
                            target.clone()
                        };
                    }
                    _ => break,
                }
            }
        }
        format!("{acc}/{name}")
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
pub fn default_init(
    entrypoint: &str,
    env: &[String],
    workdir: Option<&str>,
    modules: &[String],
) -> String {
    // Read from the constants `create` declares rather than restated here: a
    // guest configured onto a different subnet from its own gateway has a NIC
    // that is up, has an address, and reaches nothing.
    let dotted = |v: [u8; 4]| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
    let guest_ip = dotted(GUEST_IP);
    let gateway_ip = dotted(GATEWAY_IP);
    let guest_prefix = GUEST_PREFIX_LEN;
    let guest_netmask = dotted(prefix_to_netmask(GUEST_PREFIX_LEN));
    // Read from the module that installs it, so the init cannot name a path
    // the image does not have.
    let nicfg = super::nicfg::GUEST_PATH;
    // Likewise: `create` writes this key onto the command line, and this reads
    // it back. One definition, so the two cannot drift apart into a guest that
    // is silently left at the epoch.
    let epoch_key = EPOCH_KEY;
    let ca_sent_key = CA_SENT_KEY;
    // Read from the credential proxy's own constants. The manual installer and
    // this init must agree on where the CA lives, or a guest that has one is
    // told it does not -- and `chm proxy ca` still prints these paths as the
    // remedy when something goes wrong.
    let ca_crt = CA_PATH;
    let ca_env = ENV_PATH;

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

    // The drivers the kernel needs before it can see anything chm attached.
    //
    // Order is the caller's, resolved from each module's own `depends=`, and
    // must not be rearranged here: `virtio_net` loaded before its transport
    // returns *success* and still leaves the guest with no interface. This
    // block runs before the NIC block below for the same reason -- the NIC
    // block tests for `/sys/class/net/eth0`, which does not exist until the
    // driver is in.
    let load_modules = if modules.is_empty() {
        String::new()
    } else {
        let insmod_lines: String = modules
            .iter()
            .map(|p| format!("    insmod {} 2>/dev/null || __mod_fail=1\n", sh_quote(p)))
            .collect();
        let modload = super::modload::command(modules);
        format!(
            r#"
# Kernel modules chm bundled, because this kernel builds virtio as modules and
# a container rootfs ships no /lib/modules. Without these the guest boots fine
# and has no network and no disk, under a host log saying both are attached.
#
# `insmod` first where the image has it, so failures come back in the guest's
# own words; chm's loader otherwise, because node:22-slim -- the glibc base an
# agent needs -- ships neither insmod nor modprobe.
__mod_fail=0
if [ ! -d /{dir} ]; then
    # chm put these here at build time. If they are gone, the cpio dropped
    # them -- the kernel does that silently when a parent directory has no
    # entry of its own -- and the guest is about to come up with no devices.
    echo "gimbal: /{dir} is missing, so no drivers can be loaded."
    __mod_fail=1
elif command -v insmod >/dev/null 2>&1; then
{insmod_lines}    __mod_how=insmod
else
    {modload} || __mod_fail=1
    __mod_how=chm
fi
if [ "$__mod_fail" = 1 ]; then
    echo "gimbal: some bundled drivers did not load; this guest may have no"
    echo "gimbal: network and no disk. The modules must come from the same"
    echo "gimbal: kernel package as the kernel."
fi

# A module's init returning is not the device being ready. virtio_mmio probes
# on a workqueue, so `eth0` appears some time *after* the load call comes back
# -- and the block below tests for it. Measured: loading via chm's own loader
# is fast enough to lose that race every time, while five `insmod` fork/execs
# happened to be slow enough to win it. A race you win by being slow is one you
# will lose the moment anything gets faster, so it is waited on rather than
# left to luck.
__mod_wait=0
while [ ! -e /sys/class/net/eth0 ] && [ "$__mod_wait" -lt 50 ]; do
    __mod_wait=$((__mod_wait + 1))
    sleep 0.1 2>/dev/null || sleep 1
done
unset __mod_fail __mod_how __mod_wait
"#,
            dir = super::modules::GUEST_DIR,
        )
    };

    format!(
        r#"#!/bin/sh
# Generated by `chm image build` -- the init a container image does not carry.
#
# A container runtime sets up these mounts and device nodes before running the
# entrypoint. Booted as a guest there is no runtime, so we do it here. Each
# mount is tolerated failing: a minimal image may lack the mount point, and a
# missing /sys is much better than a kernel panic before any output exists.

# The entrypoint is written once, in one place, and is reached two ways: either
# re-entered under `setsid` with a controlling terminal (below), or called
# directly if that is not possible. Writing it twice would let the two paths
# drift, and only one of them is the one anybody normally takes.
gimbal_start() {{
{exports}# The proxy CA, if chm delivered one. Sourced here rather than in the main
# body because the `--gimbal-session` re-entry below skips that body entirely,
# and this is the only code both handover paths run.
#
# Only when the image did not set it: an image naming its own bundle is an
# explicit choice, and infrastructure should not silently overwrite one. An
# image that does so will not trust the proxy, which is the caller's decision
# to have made.
if [ -z "${{NODE_EXTRA_CA_CERTS:-}}" ] && [ -r {ca_env} ]; then
    . {ca_env}
fi
{cd}exec {entrypoint}
}}

# Re-entry. The mounts below have already run in the parent, so skip straight
# to the handover, leaving a marker to say the session really started.
if [ "$1" = "--gimbal-session" ]; then
    : > /dev/.gimbal-session 2>/dev/null
    gimbal_start
fi

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

# The wall clock.
#
# A container rootfs ships no /lib/modules, so a kernel that builds its RTC
# driver as a module -- Ubuntu's arm64 generic kernel puts rtc-pl031 in
# linux-modules-extra -- has no way to read the PL031 chm attaches, and the
# guest starts at the Unix epoch. Measured: /dev/rtc0 absent, date 1970-01-01.
#
# That breaks far more than a timestamp. Every TLS certificate is "not yet
# valid" in 1970, so https fails everywhere -- apt, pip, npm, git clone -- with
# an error that reads like a broken network rather than a wrong clock.
#
# chm puts the host's time on the command line at boot, which is the only
# channel that is a boot-time fact rather than a build-time one.
for __a in $(cat /proc/cmdline 2>/dev/null); do
    case "$__a" in
    {epoch_key}=*) __epoch="${{__a#{epoch_key}=}}" ;;
    {ca_sent_key}=*) __ca_sent=1 ;;
    esac
done
if [ -n "$__epoch" ]; then
    # No `||` here on purpose: BusyBox's `date -s` exits 0 even when it fails,
    # so an exit-status branch would be dead code on every Alpine guest. The
    # year check below measures the clock instead, which is the only reading
    # that cannot lie.
    date -s "@$__epoch" >/dev/null 2>&1
fi
unset __a __epoch
# Whatever the reason -- no argument, no `date`, or a `date` that said it
# worked and did not -- a guest left in 1970 does not fail in a way that names
# the clock. It fails with `certificate is not yet valid` on every TLS
# handshake, because 1970 predates every certificate it will ever be shown, and
# that reads as a broken network.
#
# This checks the clock rather than the exit status of the thing that set it,
# because the exit status lies. Measured on BusyBox 1.36 arm64: `date -s @0`
# prints "can't set date: Invalid argument" and **exits 0**, so an `||` branch
# never runs and the failure would be silent. (That particular refusal is
# BusyBox declining to move the clock *backwards* to 1970; setting it forward
# from the command line works, and is verified to work on a kernel with no RTC
# at all.) The point stands: only reading the clock afterwards is trustworthy.
__y=$(date -u +%Y 2>/dev/null)
case "$__y" in
'' | *[!0-9]*) ;;
*)
    if [ "$__y" -lt 2000 ]; then
        echo "gimbal: the guest clock is at the epoch ($(date -u 2>/dev/null))."
        echo "gimbal: every TLS handshake will fail with 'certificate is not"
        echo "gimbal: yet valid' -- that is this clock, not your network."
        echo "gimbal: neither this kernel's RTC nor gimbal.epoch= on the"
        echo "gimbal: command line could set it. A kernel with PL031 builtin"
        echo "gimbal: (Alpine's 'virt') or --modules carrying rtc-pl031 fixes it."
    fi
    ;;
esac
unset __y
{load_modules}
# A container image's /etc/resolv.conf is usually absent or points at a runtime
# resolver that does not exist here.
[ -s /etc/resolv.conf ] || echo "nameserver 1.1.1.1" > /etc/resolv.conf 2>/dev/null

# Loopback, so anything binding 127.0.0.1 works without a network policy.
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null

# The NIC, if chm attached one.
#
# A captured guest receives this from capture-side cloud-init. A container
# rootfs has neither cloud-init nor a DHCP client, so without this the guest
# holds a NIC it can see and cannot use -- which reads as broken networking
# rather than as unconfigured.
#
# Tested at runtime rather than at build time, because the same image is booted
# both with and without --net.
if [ -e /sys/class/net/eth0 ]; then
    if ip link set eth0 up 2>/dev/null &&
       ip addr add {guest_ip}/{guest_prefix} dev eth0 2>/dev/null &&
       ip route add default via {gateway_ip} 2>/dev/null; then
        :
    elif ifconfig eth0 {guest_ip} netmask {guest_netmask} up 2>/dev/null; then
        route add default gw {gateway_ip} 2>/dev/null
    elif /{nicfg} 2>/dev/null; then
        # Neither tool is present, so chm's own configurator does the ioctls.
        # This is the mainstream case, not an edge case: node:22 and
        # node:22-slim both ship neither `ip` nor `ifconfig`.
        :
    else
        # Configuring an interface needs an ioctl, and no shell builtin makes
        # one -- so with no tool and no working configurator there is nothing
        # this init can do. Say so rather than leaving a silent NIC.
        echo "gimbal: eth0 is present but could not be configured: this image"
        echo "gimbal: has no working 'ip' or 'ifconfig', and chm's own"
        echo "gimbal: configurator did not run. Configure it yourself with:"
        echo "gimbal:   <tool> addr add {guest_ip}/{guest_prefix} dev eth0"
        echo "gimbal:   <tool> route add default via {gateway_ip}"
    fi
fi

# {CA_INSTALL_MARKER}
#
# A deliberate, machine-read marker, not a comment. The installer below lives in
# the generated init, which is written once at `chm image build` -- so an image
# built before the installer existed has no installer, nothing at run time
# notices, and the user meets `certificate verify failed` with the CA sitting on
# disk beside them (#266). `create` reads this line back out of the archive it is
# about to hand the kernel and says so when it is missing.
#
# Stated as a capability rather than a version because only the bytes going to
# the kernel can answer "will this guest install the CA". A version number is a
# claim about an init; this line is placed by the code that does the work, and
# `the_marker_is_present_exactly_when_the_installer_is` keeps them together.
#
# The credential proxy's CA, if chm staged one into this rootfs.
#
# Tested at runtime, not at build time: the same image boots both with and
# without --proxy-rules, and only `create` knows which. chm appends a second
# cpio carrying this file when a proxy is in play, so its presence *is* the
# question being asked.
#
# Without this the guest is a manual step away from working, and the failure it
# produces names the wrong thing -- a TLS error that reads as a network fault.
if [ -r {ca_crt} ]; then
    # Node does not consult the OS trust store at all. Measured on one guest
    # seconds apart, same CA file: `node` failed SELF_SIGNED_CERT_IN_CHAIN, and
    # the same request with NODE_EXTRA_CA_CERTS set returned a status. A coding
    # agent is a Node program, so this line is the difference between the agent
    # working and not.
    mkdir -p /etc/gimbal 2>/dev/null
    printf 'export NODE_EXTRA_CA_CERTS=%s\n' {ca_crt} > {ca_env} 2>/dev/null

    # The OS trust store as well, for curl, git, apk and apt.
    #
    # Appending to a bundle the TLS library already reads is the only mechanism
    # here that needs nothing installed -- and the bundle has to exist, or the
    # guest could not have made an HTTPS request in the first place. Measured on
    # alpine:3.20, which has neither `update-ca-certificates` nor the `openssl`
    # CLI: both of the obvious installers silently did nothing and the guest's
    # first HTTPS request failed `certificate verify failed`, i.e. the trust
    # error this whole rung exists to prevent, with the CA sitting on disk.
    #
    # The needle is the certificate's first body line, so re-running is a no-op
    # and a bundle reached twice through a symlink is appended to once.
    __n=0
    __line=$(head -n 2 {ca_crt} 2>/dev/null | tail -n 1)
    for __b in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem \
               /etc/pki/tls/certs/ca-bundle.crt; do
        [ -f "$__b" ] || continue
        grep -qF "$__line" "$__b" 2>/dev/null && continue
        cat {ca_crt} >> "$__b" 2>/dev/null && __n=$((__n + 1))
    done

    # And the proper install where the tooling exists, so a later
    # `update-ca-certificates` regenerates the bundle *with* our CA in it
    # rather than dropping the line we appended above.
    if mkdir -p /usr/local/share/ca-certificates 2>/dev/null; then
        cp {ca_crt} /usr/local/share/ca-certificates/gimbal-proxy.crt 2>/dev/null
        command -v update-ca-certificates >/dev/null 2>&1 &&
            update-ca-certificates >/dev/null 2>&1
    fi
    unset __line

    # Report what happened, not what was attempted. An installer that says it
    # succeeded because a command exited 0 is worse than no installer: the guest
    # then fails a certificate check *after* being told it was trusted, and the
    # error names TLS rather than us.
    if [ "$__n" -gt 0 ]; then
        echo "gimbal: credential proxy CA installed ({ca_crt}); \
$__n system trust store(s) updated"
    else
        echo "gimbal: credential proxy CA at {ca_crt}, and \
NODE_EXTRA_CA_CERTS set, but no system trust store was found here --
gimbal: so node works and curl/git may still refuse the proxy's certificate"
    fi
    unset __n
elif [ -n "$__ca_sent" ]; then
    # chm said it appended a CA archive and the file is not here, so the kernel
    # stopped unpacking before it reached the tail. It does that in silence when
    # the initramfs and its unpacked copy will not both fit in guest RAM --
    # measured on node:22-slim at 768 MiB, where the CA simply was not there.
    #
    # Named rather than left silent because the alternative is a TLS failure
    # later that blames the certificate, or the network, or the clock: anything
    # except the memory setting that actually caused it.
    echo "gimbal: the credential proxy CA did not survive the boot -- the kernel \
stops unpacking the
gimbal: initramfs without saying so when it runs short of memory. Give the guest \
more memory with
gimbal: --memory; until then HTTPS through the proxy fails a certificate check."
fi
unset __ca_sent

echo "gimbal: container rootfs up; starting {entrypoint}"

# Hand over with a controlling terminal, so job control works and Ctrl-C
# interrupts something.
#
# Without one the first line a user reads is "can't access tty; job control
# turned off", which reads as a fault, and SIGINT has no foreground process
# group to be delivered to -- so Ctrl-C does nothing at all.
#
# `setsid` sets the controlling terminal from *its own* stdin, so the
# redirection belongs here rather than on the inner command. /dev/ttyAMA0 and
# not /dev/console: TIOCSCTTY cannot make /dev/console a controlling terminal,
# so attaching to it would leave exactly the problem this solves.
#
# It is deliberately not `exec`d. `exec` is one-way, so an image or kernel
# without a working `setsid -c` would boot to nothing at all rather than to a
# shell without job control. A failure here simply falls through to the plain
# handover below, which is what shipped before and works everywhere.
if [ -c /dev/ttyAMA0 ]; then
    setsid -c /bin/sh /init --gimbal-session </dev/ttyAMA0 >/dev/ttyAMA0 2>&1
    _rc=$?
    # Fall through unless the session provably started. An exit status cannot
    # tell "setsid is absent, or rejected -c" from "the session ran and exited
    # nonzero", and the two need opposite responses -- so the child leaves a
    # marker and that is what decides.
    #
    # The bias is deliberate. Falling through when the session did run costs a
    # second shell, which is odd and harmless; exiting when it never ran means
    # init exits and the kernel panics with no shell at all.
    if [ -e /dev/.gimbal-session ]; then
        exit $_rc
    fi
fi

gimbal_start
"#
    )
}

/// Wrap a value so a POSIX shell reads it back byte-for-byte.
///
/// Image `Env` values are attacker-influenced content (they come out of a
/// registry), so this is the same discipline invariant I5 applies to the app's
/// generated commands, not a formatting nicety.
/// `ifconfig` wants a dotted netmask where `ip` takes a prefix length. Derived
/// rather than written out, so the two forms cannot describe different subnets.
fn prefix_to_netmask(prefix: u8) -> [u8; 4] {
    // Both ends are special-cased because a shift of 32 is undefined and
    // panics in debug -- which is what the first run of this function's own
    // test did, rather than quietly returning a wrong mask in release.
    let bits: u32 = match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - u32::from(p)),
    };
    bits.to_be_bytes()
}

fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

/// The line [`init`] emits to declare that it installs the credential proxy CA.
///
/// Read back by `create` so a stale image is named rather than silently
/// producing a certificate error (#266).
pub const CA_INSTALL_MARKER: &str = "gimbal-capability: proxy-ca-install";

/// Does the init inside this initramfs install the credential proxy CA?
///
/// Answered from the archive's own bytes, for the reason
/// [`crate::oci::modules::bundled_in_initramfs`] gives: a sidecar recording what
/// a build did is a claim, and a stale one the moment anybody rebuilds an
/// initramfs in place.
///
/// Best-effort in the *safe* direction is the opposite of that function's: an
/// unreadable or unfamiliar archive returns `true`, suppressing the warning. A
/// warning shown to someone whose image is fine would send them to rebuild a
/// working image, and the population that reaches an unparseable archive is
/// mostly people supplying their own initramfs -- who never had our installer
/// and are not the ones this warns.
pub fn installs_proxy_ca(path: &Path) -> bool {
    let Ok(d) = fs::read(path) else {
        return true;
    };
    match read_cpio_file(&d, "init") {
        Some(init) => init
            .windows(CA_INSTALL_MARKER.len())
            .any(|w| w == CA_INSTALL_MARKER.as_bytes()),
        // No `init` entry at all is not our generated image.
        None => true,
    }
}

/// The contents of one file in a `newc` cpio, by name, ignoring a `./` prefix.
///
/// Deliberately tolerant: a truncated or unfamiliar archive yields `None`
/// rather than an error, because every caller's question is about what the
/// guest will do, and "cannot tell" and "no" are different answers.
fn read_cpio_file(d: &[u8], want: &str) -> Option<Vec<u8>> {
    let mut i = 0usize;
    while i + 110 <= d.len() {
        if &d[i..i + 6] != b"070701" {
            return None;
        }
        let field = |k: usize| -> Option<usize> {
            let raw = d.get(i + 6 + k * 8..i + 6 + (k + 1) * 8)?;
            usize::from_str_radix(str::from_utf8(raw).ok()?, 16).ok()
        };
        let (filesize, namesize) = (field(6)?, field(11)?);
        if namesize == 0 {
            return None;
        }
        let name = String::from_utf8_lossy(d.get(i + 110..i + 110 + namesize - 1)?).into_owned();
        if name == "TRAILER!!!" {
            return None;
        }
        // Name is padded to 4 bytes from the start of the header; data follows.
        let data_at = i + (110 + namesize).next_multiple_of(4);
        if name.trim_start_matches("./") == want {
            return d.get(data_at..data_at + filesize).map(<[u8]>::to_vec);
        }
        let next = (110 + namesize)
            .checked_next_multiple_of(4)
            .and_then(|h| h.checked_add(filesize.checked_next_multiple_of(4)?))
            .and_then(|step| i.checked_add(step))?;
        if next <= i {
            return None;
        }
        i = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for a boot failure that produced no error message at all.
    ///
    /// A `--disk` build on `ubuntu:24.04` wrote the generated init to
    /// `sbin/init`, but `sbin` is a symlink to `usr/sbin` on every usr-merge
    /// base. The guest booted, printed `Run /sbin/init as init process`,
    /// found nothing, and fell through to `/bin/sh` — an image that looked
    /// built and simply did not run its own init.
    #[test]
    fn a_path_through_a_usr_merge_symlink_is_rewritten_to_the_real_directory() {
        let mut r = Rootfs::new();
        r.insert(
            "sbin".to_string(),
            EntryKind::Symlink {
                target: "usr/sbin".to_string(),
            },
            Vec::new(),
        );
        assert_eq!(
            r.resolve_parents("sbin/init"),
            "usr/sbin/init",
            "the init would be written through a symlink and silently lost"
        );
    }

    /// Debian writes these as absolute links. Taking `/usr/sbin` literally
    /// would put the file outside the rootfs, which is the opposite of the
    /// bug this is fixing.
    #[test]
    fn an_absolute_link_target_is_read_as_rootfs_relative() {
        let mut r = Rootfs::new();
        r.insert(
            "sbin".to_string(),
            EntryKind::Symlink {
                target: "/usr/sbin".to_string(),
            },
            Vec::new(),
        );
        assert_eq!(r.resolve_parents("sbin/init"), "usr/sbin/init");
    }

    /// A relative target resolves against the link's own directory, not
    /// against the root. `usr/lib64 -> lib` means `usr/lib`, never `lib`.
    #[test]
    fn a_relative_link_target_resolves_beside_the_link() {
        let mut r = Rootfs::new();
        r.insert(
            "usr/lib64".to_string(),
            EntryKind::Symlink {
                target: "lib".to_string(),
            },
            Vec::new(),
        );
        assert_eq!(r.resolve_parents("usr/lib64/ld.so"), "usr/lib/ld.so");
    }

    /// A loop must terminate. Returning something is fine; hanging the build
    /// is not.
    #[test]
    fn a_symlink_loop_does_not_hang_the_build() {
        let mut r = Rootfs::new();
        for (from, to) in [("a", "b"), ("b", "a")] {
            r.insert(
                from.to_string(),
                EntryKind::Symlink {
                    target: to.to_string(),
                },
                Vec::new(),
            );
        }
        let _ = r.resolve_parents("a/x");
    }

    /// The ordinary case must be left exactly alone, including a path with no
    /// directory component at all — `/init` and the NIC configurator both live
    /// at the root precisely to avoid this whole class.
    #[test]
    fn a_path_with_no_symlink_in_it_is_returned_unchanged() {
        let mut r = Rootfs::new();
        r.insert(
            "usr/sbin".to_string(),
            EntryKind::Directory { mode: 0o755 },
            Vec::new(),
        );
        assert_eq!(r.resolve_parents("usr/sbin/init"), "usr/sbin/init");
        assert_eq!(r.resolve_parents("init"), "init");
        assert_eq!(r.resolve_parents("etc/passwd"), "etc/passwd");
    }

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
        let (k, d) = f(&[0u8; 24]);
        r.insert("b".to_string(), k, d);
        assert_eq!(r.content_bytes(), 1024);
    }

    #[test]
    fn the_generated_init_mounts_proc_and_execs_the_entrypoint() {
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(s.starts_with("#!/bin/sh"));
        assert!(s.contains("mount -t proc proc /proc"));
        assert!(s.contains("exec /bin/sh"));
    }

    /// devtmpfs is not in every kernel config, and a guest with no
    /// `/dev/console` produces no output at all — the worst possible failure to
    /// debug.
    #[test]
    fn the_init_falls_back_to_making_console_by_hand() {
        let s = default_init("/bin/sh", &[], None, &[]);
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
            &[],
        );
        assert!(s.contains("export PATH='/usr/local/bin:/usr/bin'"), "{s}");
    }

    /// An image with no declared PATH still needs one; a bare `sh` execed by
    /// the kernel inherits nothing.
    #[test]
    fn an_image_with_no_env_still_gets_a_path() {
        let s = default_init("/bin/sh", &[], None, &[]);
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

    /// The CA env has to be sourced on the path everybody actually takes.
    #[test]
    fn the_ca_env_is_sourced_where_both_handover_paths_reach_it() {
        let s = default_init("/bin/sh", &[], None, &[]);
        let start = s.find("gimbal_start() {").expect("no gimbal_start");
        let end = s[start..].find("\n}\n").expect("unterminated") + start;
        let body = &s[start..end];
        assert!(
            body.contains("/etc/gimbal/proxy-ca.env"),
            "the CA env must be sourced inside gimbal_start: the --gimbal-session \
             re-entry skips the whole main body, so anywhere else is lost on the \
             path that actually runs.\n{body}"
        );
        assert!(
            body.find("proxy-ca.env").expect("no env") < body.find("exec ").expect("no exec"),
            "it must be sourced before the entrypoint, or the entrypoint cannot see it"
        );
    }

    /// The marker exists to be read back, so it is worthless if it can drift
    /// away from the installer it describes. Pinned in both directions: an init
    /// with the installer carries the marker, and an init without it does not.
    #[test]
    fn the_marker_is_present_exactly_when_the_installer_is() {
        let s = default_init("/bin/sh", &[], None, &[]);
        let installs = s.contains("if [ -r /etc/gimbal/proxy-ca.crt ]; then");
        let marked = s.contains(CA_INSTALL_MARKER);
        assert!(installs, "the installer is what the marker claims");
        assert_eq!(
            installs, marked,
            "an init that installs the CA must say so, or #266 comes back silently:\n{s}"
        );
    }

    /// `create` decides whether to warn by reading the archive it is about to
    /// hand the kernel, so the read has to work on an archive this module wrote.
    /// A hand-built fixture and a hand-written reader agree by construction --
    /// this repo's recorded #178/#180 failure -- so the real writer builds it.
    #[test]
    fn an_init_we_generated_is_recognised_as_installing_the_ca() {
        let dir = std::env::temp_dir().join(format!("chm-ca-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut r = Rootfs::default();
        let body = default_init("/bin/sh", &[], None, &[]);
        r.insert(
            "init".to_string(),
            EntryKind::File {
                mode: 0o755,
                size: body.len() as u64,
            },
            body.clone().into_bytes(),
        );
        let good = dir.join("good.cpio");
        std::fs::write(&good, write_cpio(&r)).unwrap();
        assert!(
            installs_proxy_ca(&good),
            "an init we just generated must be recognised"
        );

        // A pre-#238 init: same shape, installer absent.
        let mut r2 = Rootfs::default();
        let stale = body
            .replace(CA_INSTALL_MARKER, "")
            .replace("if [ -r /etc/gimbal/proxy-ca.crt ]; then", "if false; then");
        r2.insert(
            "init".to_string(),
            EntryKind::File {
                mode: 0o755,
                size: stale.len() as u64,
            },
            stale.into_bytes(),
        );
        let old = dir.join("old.cpio");
        std::fs::write(&old, write_cpio(&r2)).unwrap();
        assert!(
            !installs_proxy_ca(&old),
            "an init with no installer must be reported, or #266 stays silent"
        );

        // Cannot tell => do not warn: sending someone to rebuild a working
        // image is the worse error, and a foreign archive never had our init.
        let junk = dir.join("junk.bin");
        std::fs::write(&junk, b"not a cpio at all").unwrap();
        assert!(installs_proxy_ca(&junk), "unparseable must not warn");
        assert!(
            installs_proxy_ca(&dir.join("does-not-exist")),
            "unreadable must not warn"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An image that names its own bundle made an explicit choice.
    #[test]
    fn an_image_that_sets_the_variable_itself_wins() {
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            s.contains(r#"[ -z "${NODE_EXTRA_CA_CERTS:-}" ]"#),
            "chm's CA must not overwrite one the image set deliberately:\n{s}"
        );
    }

    /// Conditional at *runtime*: the same image boots with and without a proxy.
    #[test]
    fn the_ca_install_asks_whether_the_file_arrived() {
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            s.contains("if [ -r /etc/gimbal/proxy-ca.crt ]; then"),
            "the presence of the file is the question, so one image serves both runs"
        );
        assert!(
            s.contains("NODE_EXTRA_CA_CERTS"),
            "Node ignores the OS trust store, so the system store alone is not enough"
        );
        assert!(
            s.contains("update-ca-certificates"),
            "curl, git and apt read the OS store, so Node alone is not enough either"
        );
        assert!(
            s.contains("/etc/ssl/certs/ca-certificates.crt") && s.contains(">> \"$__b\""),
            "appending to a bundle the TLS library already reads is the only \
             mechanism that needs nothing installed -- measured on alpine:3.20, \
             which ships neither update-ca-certificates nor the openssl CLI, so \
             without this the CA sits on disk and every HTTPS request still fails"
        );
    }

    #[test]
    /// The kernel drops the tail of an initramfs it cannot fit in memory and
    /// says nothing. Without this branch the guest is silent too, and the
    /// failure surfaces much later as a certificate error naming TLS.
    fn a_ca_that_was_sent_and_did_not_arrive_is_named_rather_than_left_silent() {
        let script = default_init("/bin/sh", &[], None, &[]);
        let key = crate::coldboot::CA_SENT_KEY;
        assert!(
            script.contains(&format!("{key}=*) __ca_sent=1 ;;")),
            "the init must read whether chm claimed to send a CA; without that it \
             cannot tell `no proxy was asked for` from `the archive was lost`"
        );
        assert!(
            script.contains("elif [ -n \"$__ca_sent\" ]; then"),
            "the diagnosis must hang off the *absence* of the file, so it fires \
             exactly when the file did not arrive"
        );
        assert!(
            script.contains("did not survive the boot") && script.contains("--memory"),
            "the message has to name the remedy; `the CA is missing` sends a \
             reader to look at the proxy, which is working"
        );
        let quiet = script
            .split("elif [ -n \"$__ca_sent\" ]; then")
            .nth(1)
            .expect("the branch exists");
        assert!(
            !quiet.starts_with("\nfi"),
            "an empty branch would report nothing, which is the bug"
        );
    }

    #[test]
    fn a_name_a_shell_cannot_hold_is_dropped_rather_than_mangled() {
        let s = default_init("/bin/sh", &["BAD-NAME=x".to_string()], None, &[]);
        assert!(!s.contains("BAD-NAME"), "{s}");
    }

    #[test]
    fn a_working_directory_is_entered_before_the_entrypoint() {
        let s = default_init("/bin/sh", &[], Some("/srv/app"), &[]);
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

    /// The init is a shell script the *guest* runs, so the only authority on
    /// whether it parses is a shell -- not a substring assertion. This asks a
    /// real one, which is what catches an unbalanced quote introduced by an
    /// entrypoint or an env value we interpolated.
    fn sh_parses(script: &str) -> Result<(), String> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut c = Command::new("/bin/sh")
            .args(["-n"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        c.stdin
            .as_mut()
            .ok_or("no stdin")?
            .write_all(script.as_bytes())
            .map_err(|e| e.to_string())?;
        let out = c.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }

    #[test]
    fn a_generated_init_parses_as_a_shell_script() {
        for (name, s) in [
            ("plain", default_init("/bin/sh", &[], None, &[])),
            (
                "quoted entrypoint",
                default_init("/bin/sh -c 'echo hello'", &[], None, &[]),
            ),
            (
                "env and workdir",
                default_init(
                    "/usr/local/bin/python3",
                    &[
                        "PATH=/usr/local/bin:/bin".to_string(),
                        "A=b c'd".to_string(),
                    ],
                    Some("/srv/app"),
                    &[],
                ),
            ),
        ] {
            if let Err(e) = sh_parses(&s) {
                panic!("{name}: generated init does not parse: {e}");
            }
        }
    }

    #[test]
    fn the_entrypoint_is_written_once_so_the_two_paths_cannot_drift() {
        // It is reached both by re-entry under setsid and by the direct
        // fallback. Two copies would let a change land on only one of them,
        // and only one is the path anybody normally takes.
        let s = default_init("/usr/local/bin/gunicorn", &[], None, &[]);
        assert_eq!(
            s.matches("exec /usr/local/bin/gunicorn").count(),
            1,
            "the entrypoint must be spelled out exactly once:\n{s}"
        );
    }

    #[test]
    fn the_session_is_given_a_controlling_terminal() {
        let s = default_init("/bin/sh", &[], None, &[]);
        // Deliberately matched against the invocation and not the word: the
        // script's own comments mention `setsid -c`, so a looser assertion
        // passes happily while the command has lost its flag. That is exactly
        // the mutation this test exists to catch, and it survived one.
        assert!(
            s.contains("\n    setsid -c /bin/sh /init --gimbal-session "),
            "without -c there is no controlling terminal and Ctrl-C does nothing:\n{s}"
        );
        assert!(
            s.contains("--gimbal-session </dev/ttyAMA0 >/dev/ttyAMA0"),
            "setsid takes the ctty from its own stdin, so the tty must be \
             redirected onto setsid itself:\n{s}"
        );
        assert!(
            !s.contains("setsid -c /bin/sh /init --gimbal-session </dev/console"),
            "TIOCSCTTY cannot make /dev/console a controlling terminal, so \
             attaching to it would leave the exact problem this solves"
        );
    }

    #[test]
    fn a_missing_setsid_still_reaches_the_entrypoint() {
        // `exec` is one-way. If the handover were exec'd, an image without a
        // working setsid would boot to nothing at all rather than to a shell
        // without job control.
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            !s.contains("exec setsid"),
            "setsid must not be exec'd, or a failure leaves no fallback:\n{s}"
        );
        let setsid = s.find("setsid -c").expect("no setsid in init");
        let fallback = s.rfind("gimbal_start").expect("no fallback call");
        assert!(
            fallback > setsid,
            "the plain handover must come after the setsid attempt, so a \
             failure falls through to it:\n{s}"
        );
        assert!(
            s.contains("/dev/.gimbal-session"),
            "an exit status cannot distinguish 'setsid never ran the session' \
             from 'the session exited nonzero', and the two need opposite \
             responses -- so a marker must decide:\n{s}"
        );
        // The bias must be toward running the entrypoint again, never toward
        // init exiting: the first costs a second shell, the second is a kernel
        // panic with no shell at all.
        assert!(
            s.contains("if [ -e /dev/.gimbal-session ]; then\n        exit $_rc"),
            "init may only exit when the session provably ran:\n{s}"
        );
    }

    #[test]
    fn re_entry_skips_the_setup_it_has_already_done() {
        let s = default_init("/bin/sh", &[], None, &[]);
        let guard = s
            .find(r#"if [ "$1" = "--gimbal-session" ]"#)
            .expect("no re-entry guard");
        let mounts = s.find("mount -t proc").expect("no proc mount");
        assert!(
            guard < mounts,
            "re-entry must return before remounting what the parent mounted:\n{s}"
        );
    }

    #[test]
    fn the_nic_is_configured_from_the_addresses_chm_itself_uses() {
        // A restated literal here would pass every test while putting the
        // guest on a different subnet from its own gateway -- a NIC that is
        // up, holds an address, and reaches nothing.
        let s = default_init("/bin/sh", &[], None, &[]);
        let d = |v: [u8; 4]| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
        assert!(
            s.contains(&format!(
                "addr add {}/{} dev eth0",
                d(GUEST_IP),
                GUEST_PREFIX_LEN
            )),
            "the guest address must be the one create declares:\n{s}"
        );
        assert!(
            s.contains(&format!("route add default via {}", d(GATEWAY_IP))),
            "the gateway must be the one create declares:\n{s}"
        );
    }

    #[test]
    fn the_two_netmask_forms_describe_one_subnet() {
        // `ip` takes a prefix length and `ifconfig` a dotted mask, so the same
        // subnet is written twice and the two could disagree silently.
        assert_eq!(prefix_to_netmask(24), [255, 255, 255, 0]);
        assert_eq!(prefix_to_netmask(16), [255, 255, 0, 0]);
        assert_eq!(prefix_to_netmask(32), [255, 255, 255, 255]);
        assert_eq!(prefix_to_netmask(0), [0, 0, 0, 0]);

        let s = default_init("/bin/sh", &[], None, &[]);
        let mask = prefix_to_netmask(GUEST_PREFIX_LEN);
        assert!(
            s.contains(&format!(
                "netmask {}.{}.{}.{}",
                mask[0], mask[1], mask[2], mask[3]
            )),
            "the ifconfig branch must carry the mask the prefix means:\n{s}"
        );
    }

    #[test]
    fn a_guest_with_no_nic_is_left_alone() {
        // The same image is booted with and without --net, so this has to be a
        // runtime test in the script and not a build-time decision.
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            s.contains("if [ -e /sys/class/net/eth0 ]; then"),
            "configuring a NIC that was never attached would print errors on \
             every no-network boot:\n{s}"
        );
    }

    #[test]
    fn an_image_with_no_network_tool_still_gets_configured() {
        // Configuring an interface needs an ioctl and no shell builtin makes
        // one. This used to be the end of the story, and the init could only
        // print a refusal -- on the *mainstream* case, since node:22 and
        // node:22-slim ship neither `ip` nor `ifconfig`. chm now carries its
        // own configurator, so there is a third rung before giving up.
        let s = default_init("/bin/sh", &[], None, &[]);
        let nicfg = super::super::nicfg::GUEST_PATH;

        assert!(
            s.contains(&format!("elif /{nicfg} 2>/dev/null; then")),
            "the configurator must be tried before refusing:\n{s}"
        );
        // Order matters: it is the fallback, not the default. An image that
        // ships `ip` should use it, because it is the more capable and more
        // debuggable tool and it is what the distro expects.
        let ip = s.find("ip link set eth0 up").expect("ip rung");
        let ifc = s.find("elif ifconfig eth0").expect("ifconfig rung");
        let own = s.find(&format!("elif /{nicfg}")).expect("nicfg rung");
        assert!(
            ip < ifc && ifc < own,
            "rungs are out of order: ip={ip} ifconfig={ifc} nicfg={own}"
        );
        // And the refusal still exists for the case where even that fails,
        // naming the addresses so the operator can finish the job by hand.
        assert!(
            s.contains("could not be configured"),
            "a silent NIC reads as broken networking:\n{s}"
        );
        assert!(
            s.contains(&format!(
                "addr add {}.{}.{}.{}/",
                GUEST_IP[0], GUEST_IP[1], GUEST_IP[2], GUEST_IP[3]
            )),
            "the refusal must name the address to use:\n{s}"
        );
    }

    /// A guest left in 1970 fails with `certificate is not yet valid` on every
    /// TLS handshake, which names the network for a fault in the clock. The
    /// init is the only place that can see the clock before anything uses it.
    #[test]
    fn the_init_says_so_when_the_clock_is_at_the_epoch() {
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            s.contains("-lt 2000"),
            "init does not check the year:\n{s}"
        );
        // Naming the symptom is the point: the user meets the TLS error first
        // and needs to be able to connect it to this line.
        assert!(
            s.contains("certificate is not"),
            "the warning must name the error the user will actually see:\n{s}"
        );
        // Guarded against a non-numeric `date` output, or the `-lt` aborts the
        // init with a shell error before the entrypoint ever runs.
        assert!(
            s.contains("*[!0-9]*"),
            "an unparsable year would break the comparison:\n{s}"
        );
    }

    #[test]
    fn the_init_reads_the_clock_key_create_actually_writes() {
        // The two halves are in different modules and only ever meet at run
        // time inside a guest, where a mismatch is invisible: the loop simply
        // finds nothing and the clock silently stays at 1970.
        let key = EPOCH_KEY;
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(
            s.contains(&format!("{key}=*)")),
            "init does not match {key}"
        );
        assert!(
            s.contains(&format!("${{__a#{key}=}}")),
            "init does not strip {key}"
        );
        let arg = crate::coldboot::epoch_arg(std::time::SystemTime::now()).unwrap();
        assert!(
            arg.starts_with(&format!("{key}=")),
            "create writes {arg:?}, which this init would not match"
        );
    }

    #[test]
    fn the_clock_is_set_before_anything_needs_it() {
        let s = default_init("/bin/sh", &[], None, &[]);
        let clock = s.find("date -s").expect("no clock rung");
        // Ordering is the property, not presence. Every one of these fails or
        // misbehaves against a 1970 clock -- TLS most obviously -- so setting
        // the clock afterwards would be indistinguishable from not setting it.
        let resolv = s.find("/etc/resolv.conf").expect("no resolv.conf rung");
        let nic = s.find("/sys/class/net/eth0").expect("no nic rung");
        let handover = s.rfind("gimbal_start").expect("no handover");
        assert!(clock < resolv, "clock set after resolv.conf:\n{s}");
        assert!(clock < nic, "clock set after the NIC:\n{s}");
        assert!(clock < handover, "clock set after handover:\n{s}");
    }

    #[test]
    fn a_guest_told_nothing_leaves_its_clock_alone() {
        // An explicit --cmdline carries no key, and a wrong guess would be
        // worse than the epoch: a clock confidently set to the wrong time is
        // harder to diagnose than one obviously stuck in 1970.
        let s = default_init("/bin/sh", &[], None, &[]);
        let script = s
            .split("for __a in")
            .nth(1)
            .expect("no cmdline loop")
            .split("unset __a")
            .next()
            .unwrap();
        assert!(
            script.contains("[ -n \"$__epoch\" ]"),
            "the clock is set unconditionally:\n{script}"
        );
    }

    /// The order the caller resolved is the order the guest loads in.
    ///
    /// This is not cosmetic. `virtio_net` loaded before `virtio_mmio` returns
    /// *success* -- it registers a driver against a bus that is not there --
    /// and the guest comes up with no interface and no error. Sorting these,
    /// or de-duplicating them into a set, would silently reintroduce exactly
    /// the bug the bundling exists to fix.
    #[test]
    fn modules_are_loaded_in_the_order_they_were_given() {
        let mods: Vec<String> = ["virtio_mmio", "failover", "net_failover", "virtio_net"]
            .iter()
            .map(|m| format!("/{}/{m}.ko", super::super::modules::GUEST_DIR))
            .collect();
        let s = default_init("/bin/sh", &[], None, &mods);
        let mut at = 0usize;
        for m in &mods {
            let found = s[at..]
                .find(m.as_str())
                .unwrap_or_else(|| panic!("`{m}` not loaded at all:\n{s}"));
            at += found + 1;
        }
    }

    /// The NIC block tests `/sys/class/net/eth0`, which does not exist until
    /// the driver providing it is in. Loading after it would configure an
    /// interface that is not there yet, and the modules would arrive just too
    /// late to be any use.
    #[test]
    fn modules_load_before_the_interface_is_configured() {
        let mods = vec![format!(
            "/{}/virtio_net.ko",
            super::super::modules::GUEST_DIR
        )];
        let s = default_init("/bin/sh", &[], None, &mods);
        let load = s.find("virtio_net.ko").expect("no module load");
        let nic = s.find("/sys/class/net/eth0").expect("no NIC block");
        assert!(
            load < nic,
            "modules load at {load} but the NIC is configured at {nic}:\n{s}"
        );
    }

    /// An image that needs no modules must not carry the machinery for them:
    /// a guest printing a warning about a loader it does not have is a bug
    /// report waiting to be filed.
    #[test]
    fn no_modules_means_no_module_block_at_all() {
        let s = default_init("/bin/sh", &[], None, &[]);
        assert!(!s.contains(super::super::modules::GUEST_DIR), "{s}");
        assert!(!s.contains(super::super::modload::GUEST_PATH), "{s}");
    }

    /// The generated init is a shell script, and a module path is data from a
    /// module tree we did not write.
    #[test]
    fn a_module_block_still_parses_as_a_shell_script() {
        let mods = vec![
            "/gimbal-modules/virtio_mmio.ko".to_string(),
            "/gimbal-modules/virtio net;touch /tmp/chm-modpwned.ko".to_string(),
        ];
        let s = default_init("/bin/sh", &[], None, &mods);
        if let Err(e) = sh_parses(&s) {
            panic!("generated init does not parse: {e}");
        }
    }

    /// Every file in a cpio needs its parent directory to have an entry of its
    /// own. `init/initramfs.c` does not create missing parents -- `openat`
    /// fails with ENOENT and the kernel drops the file **silently**.
    ///
    /// This is not hypothetical: the first hardware run of #222 put all five
    /// modules in the cpio, and the guest had none of them and said nothing.
    /// The unpacker is the authority here, so the test walks the emitted
    /// archive the way the unpacker does rather than trusting the builder.
    #[test]
    fn every_entry_has_a_parent_directory_ahead_of_it() {
        let mut r = Rootfs::default();
        for d in ["gimbal-modules", "usr", "usr/lib"] {
            r.insert(
                d.to_string(),
                EntryKind::Directory { mode: 0o755 },
                Vec::new(),
            );
        }
        for f in [
            "gimbal-modules/virtio_mmio.ko",
            "gimbal-modules/virtio_net.ko",
            "usr/lib/libc.so",
            "init",
        ] {
            r.insert(
                f.to_string(),
                EntryKind::File {
                    mode: 0o644,
                    size: 1,
                },
                vec![0u8],
            );
        }
        let cpio = write_cpio(&r);

        let mut seen_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (name, is_dir) in walk_cpio(&cpio) {
            let path = name.trim_start_matches("./");
            if let Some((parent, _)) = path.rsplit_once('/') {
                assert!(
                    seen_dirs.contains(parent),
                    "`{path}` is unpacked before its parent `{parent}` exists, so the \
                     kernel drops it without a word"
                );
            }
            if is_dir {
                seen_dirs.insert(path.to_string());
            }
        }
    }

    /// Read an emitted newc archive back the way the kernel's unpacker does.
    fn walk_cpio(d: &[u8]) -> Vec<(String, bool)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 110 <= d.len() {
            assert_eq!(&d[i..i + 6], b"070701", "not a newc header at {i}");
            let f = |k: usize| {
                usize::from_str_radix(
                    std::str::from_utf8(&d[i + 6 + k * 8..i + 6 + (k + 1) * 8]).unwrap(),
                    16,
                )
                .unwrap()
            };
            let mode = f(1);
            let filesize = f(6);
            let namesize = f(11);
            let name = String::from_utf8_lossy(&d[i + 110..i + 110 + namesize - 1]).into_owned();
            if name == "TRAILER!!!" {
                break;
            }
            out.push((name, mode & 0o170000 == 0o040000));
            i += (110 + namesize).div_ceil(4) * 4 + filesize.div_ceil(4) * 4;
        }
        out
    }
}
