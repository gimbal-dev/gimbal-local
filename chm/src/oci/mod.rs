// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm image build` — turn a container image into a bootable local image
//! (V9.7, #153).
//!
//! # The gap
//!
//! Goal **G6** is *create local images — from vanilla or from containers*. The
//! vanilla half shipped in V8.3: put an uncompressed arm64 `Image` and a rootfs
//! in a directory and `chm create` cold-boots it. That works, but the supply of
//! such directories is small and hand-made. Container images are how the world
//! already ships userland, so turning an OCI image into a bootable rootfs turns
//! the entire container ecosystem into sandbox images — and is the natural way
//! to answer *"give me a sandbox with node 22"* without anyone hand-building a
//! filesystem.
//!
//! # Why the output is an initramfs, not a partitioned disk
//!
//! #153 sketches the classic shape: unpack layers into a filesystem image, add
//! an init and a kernel, write a partition table naming root by `PARTUUID`.
//! That is the right shape **on Linux**, and it is not available here. macOS
//! has no `mkfs.ext4`, cannot loopback-mount a Linux filesystem, and `hdiutil`
//! only makes filesystems a Linux guest will not boot from. Writing an ext4
//! formatter from scratch would be a large amount of security-sensitive code
//! whose only purpose is to reach a rootfs we can already produce another way.
//!
//! So the rootfs ships as a **cpio initramfs**, which is a format we can write
//! in a few hundred reviewable lines, and which the cold-boot path already
//! understands: [`crate::coldboot::implied_root_args`] returns `None` when an
//! initramfs is present precisely because the initramfs *is* the root
//! filesystem. That removes the `root=` question rather than answering it, and
//! with it the whole class of PARTUUID-mismatch failures the cold-boot path had
//! to learn about the hard way.
//!
//! The cost is honest and worth stating: an initramfs is unpacked into guest
//! RAM, so the guest needs memory for the rootfs *plus* its workload. The
//! emitted `image.json` therefore carries a `ram_mib` sized from the measured
//! rootfs rather than leaving the user to discover the requirement by watching
//! a guest die. Growing a disk-backed variant later (#180's format work is the
//! natural home) does not invalidate anything here — the image directory shape
//! is the same either way.
//!
//! # Untrusted input
//!
//! Everything unpacked here came off the internet. The policy that decides what
//! a layer entry may do lives in [`entry`], deliberately as a pure function so
//! every attack is a unit test; the parser that feeds it lives in [`targz`],
//! deliberately in-tree so the bound checks are ours. Read those two modules to
//! review the security of this feature; the rest is plumbing.

pub mod apply;
pub mod entry;
pub mod image;
pub mod initramfs;
pub mod nicfg;
pub mod reference;
pub mod registry;
pub mod targz;
