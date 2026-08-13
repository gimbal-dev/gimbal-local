// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Laying an unpacked rootfs out as an ext2 image the guest mounts as its root.
//!
//! # Why this exists, and why it is not a filesystem driver
//!
//! [`super::initramfs::write_cpio`] puts the rootfs in guest RAM, which is what
//! makes an image bootable on a Mac at all, but it means the rootfs *is*
//! resident memory: a `python:3.12-alpine` tree of 50.5 MiB needs a 512 MiB
//! guest to leave room to work in. A CUDA or JDK layer set does not fit that
//! shape at any RAM figure you would want to hand out.
//!
//! There is no `mkfs.ext4` on macOS, `hdiutil` only makes HFS/APFS, and the
//! obvious dodge — build the filesystem *inside* a short-lived guest — does not
//! work either. The applet table of the Alpine initramfs we already boot has
//! exactly one `mkfs`:
//!
//! ```text
//! mkfs.vfat
//! ```
//!
//! and FAT is not a substitute at any price, because a container rootfs is
//! symlinks all the way down (`/bin/sh -> busybox`) and FAT has no symlinks, no
//! ownership and no executable bit.
//!
//! So the image is written here, on the host. The thing that makes that
//! tractable is the scope: this is a **one-shot serialiser for a populate-once
//! tree**, not a filesystem implementation. It runs once, over a rootfs that is
//! already complete, and then never touches the image again — every subsequent
//! write is performed by Linux's own ext2 driver, correct by construction.
//! There is no allocator to get wrong under concurrency, no journal to replay,
//! no truncate/extend path, no free-space reuse. ext2 rather than ext4 for the
//! same reason: no journal, and the on-disk layout is small enough to hold in
//! your head.
//!
//! The acceptance test is not a matter of opinion — the real kernel driver
//! validates the result on every single boot, and it either mounts and the file
//! digests match the source tree, or it does not.
//!
//! # The things that silently do not mount
//!
//! Each of these fails as a mount error or, worse, a tree that is quietly
//! missing files, rather than anything that names itself:
//!
//! 1. **Hardlinks must share an inode.** busybox is one binary hardlinked ~400
//!    times. `write_cpio` learned this the expensive way — emitting a copy per
//!    link turned a 1.8 MiB layer into a 467 MiB archive. Here the same mistake
//!    would multiply the *disk* image instead, so links are grouped exactly as
//!    cpio groups them, by resolved target.
//! 2. **`rec_len` must carry a directory entry to the end of its block.** ext2
//!    directory entries may not span a block, so the last entry in each block
//!    absorbs the remaining space. Get it wrong and the kernel walks off the end
//!    of the block into whatever follows.
//! 3. **`i_blocks` is counted in 512-byte sectors, not filesystem blocks**, and
//!    it must include the indirect blocks, not just the data. It is the field
//!    `du` and the kernel's own accounting read.
//! 4. **A symlink shorter than 60 bytes is stored in the block pointers
//!    themselves** ("fast symlink") and has no data blocks at all. Allocating a
//!    block for it and also writing the target inline gives a symlink that
//!    resolves to garbage.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Seek, SeekFrom, Write};

use super::entry::EntryKind;
use super::initramfs::Rootfs;

/// 4 KiB blocks: the page size on both the host and an arm64 guest, and the
/// size at which the superblock lands cleanly inside block 0 rather than
/// straddling it.
const BLOCK_SIZE: u32 = 4096;
/// `s_magic`. A superblock without this is not examined any further.
const MAGIC: u16 = 0xEF53;
/// The root directory is always inode 2. Inodes 1–10 are reserved.
const ROOT_INO: u32 = 2;
/// First inode available to actual files.
const FIRST_INO: u32 = 11;
/// Revision 1 ("dynamic"), which is what allows a stated inode size.
const REV_DYNAMIC: u32 = 1;
const INODE_SIZE: u16 = 128;
/// Block group descriptors are 32 bytes each in ext2.
const DESC_SIZE: u32 = 32;

/// `INCOMPAT_FILETYPE`: directory entries carry a type byte. Set because the
/// alternative makes the kernel stat every entry to list a directory.
const INCOMPAT_FILETYPE: u32 = 0x0002;
/// `RO_COMPAT_SPARSE_SUPER`: superblock backups only in groups 0, 1 and the
/// powers of 3, 5 and 7. Without it every group carries a full copy of the
/// descriptor table, which on a multi-gigabyte image is real money.
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;

const S_IFREG: u16 = 0o100000;
const S_IFDIR: u16 = 0o040000;
const S_IFLNK: u16 = 0o120000;

const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_SYMLINK: u8 = 7;

/// A symlink target shorter than this is stored in the inode's block pointers.
const FAST_SYMLINK_MAX: usize = 60;

/// Free space left in the image beyond the rootfs, so the guest has somewhere
/// to write. The floor matters more than the fraction: a tiny image that boots
/// and then cannot write a lockfile is not usable.
const SLACK_FLOOR: u64 = 64 * 1024 * 1024;
const SLACK_FRACTION: u64 = 4;

/// What the serialiser produced, for the caller to report and to size a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2Image {
    /// Total image size in bytes.
    pub size_bytes: u64,
    /// Blocks the rootfs itself occupies, including metadata.
    pub used_blocks: u64,
    /// Blocks left for the guest to write into.
    pub free_blocks: u64,
    /// Inodes allocated, including the reserved ones.
    pub inodes: u32,
    /// Distinct inodes saved by grouping hardlinks — the busybox number.
    pub hardlinks_collapsed: u32,
}

/// Why an image could not be written. Both variants name a limit rather than
/// simply failing, because both are reachable from a real container image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ext2Error {
    /// A single file beyond the double-indirect reach of this writer.
    FileTooLarge { path: String, size: u64 },
    /// A path component longer than an ext2 directory entry can name.
    NameTooLong { path: String },
}

impl fmt::Display for Ext2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ext2Error::FileTooLarge { path, size } => write!(
                f,
                "{path} is {size} bytes, past the {} GiB per-file limit of the \
                 ext2 writer (it maps direct and indirect blocks, not triple \
                 indirect); use --initramfs for this image, or open an issue \
                 naming the image so the limit can be raised deliberately",
                max_file_bytes() / (1024 * 1024 * 1024)
            ),
            Ext2Error::NameTooLong { path } => write!(
                f,
                "{path} has a component longer than 255 bytes, which an ext2 \
                 directory entry cannot name"
            ),
        }
    }
}

impl Error for Ext2Error {}

/// Pointers per indirect block.
const fn ptrs_per_block() -> u64 {
    (BLOCK_SIZE / 4) as u64
}

/// The largest file this writer can map: twelve direct blocks, one indirect
/// block's worth, and one double-indirect block's worth.
pub const fn max_file_bytes() -> u64 {
    (12 + ptrs_per_block() + ptrs_per_block() * ptrs_per_block()) * BLOCK_SIZE as u64
}

/// Data blocks a body of `len` bytes needs, and the indirect blocks needed to
/// map them. Returned separately because only the first is content — the second
/// is overhead that still has to be allocated, written and counted in
/// `i_blocks`.
fn blocks_for(len: u64) -> (u64, u64) {
    let bs = BLOCK_SIZE as u64;
    let data = len.div_ceil(bs);
    let ppb = ptrs_per_block();
    let mut meta = 0;
    if data > 12 {
        meta += 1; // the singly-indirect block
        let after_ind = data.saturating_sub(12 + ppb);
        if after_ind > 0 {
            // One double-indirect block, plus a singly-indirect block per
            // `ppb` data blocks under it.
            meta += 1 + after_ind.div_ceil(ppb);
        }
    }
    (data, meta)
}

/// Which groups carry a superblock backup under `sparse_super`.
fn has_super(group: u32) -> bool {
    fn is_power_of(mut n: u32, base: u32) -> bool {
        if n == 0 {
            return false;
        }
        while n.is_multiple_of(base) {
            n /= base;
        }
        n == 1
    }
    group == 0 || group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
}

/// What one inode will contain, resolved before anything is laid out.
enum Body<'a> {
    File(&'a [u8]),
    Symlink(&'a str),
    Dir(Vec<u8>),
}

struct Planned<'a> {
    ino: u32,
    mode: u16,
    links: u16,
    body: Body<'a>,
}

/// A bump allocator over the blocks that are not metadata.
///
/// Sequential by design: the tree is written once, in path order, so files land
/// contiguously and in the order a guest is most likely to read them. There is
/// no free-list because nothing is ever freed here.
struct BlockAlloc {
    /// `(next free block, end exclusive)` per group.
    spans: Vec<(u32, u32)>,
    /// Blocks handed out per group, for `bg_free_blocks_count`.
    used: Vec<u32>,
    cursor: usize,
}

impl BlockAlloc {
    fn alloc(&mut self) -> Option<u32> {
        while self.cursor < self.spans.len() {
            let (next, end) = self.spans[self.cursor];
            if next < end {
                self.spans[self.cursor].0 = next + 1;
                self.used[self.cursor] += 1;
                return Some(next);
            }
            self.cursor += 1;
        }
        None
    }
}

/// Serialise `rootfs` as an ext2 image into `out`.
///
/// `extra_free_bytes` is space beyond the rootfs for the guest to write into;
/// pass `None` for the default, which is the larger of 64 MiB and a quarter of
/// the tree.
pub fn write_ext2<W: Write + Seek>(
    rootfs: &Rootfs,
    out: &mut W,
    extra_free_bytes: Option<u64>,
) -> Result<Ext2Image, Box<dyn Error>> {
    let bs = BLOCK_SIZE as u64;

    // ---- Pass 1: inode identity, with hardlinks grouped by resolved target.
    //
    // This is the busybox lesson from `write_cpio`, in its disk-image form: a
    // rootfs where one binary is linked 400 times must produce one inode, not
    // 400 copies of the body.
    let mut ino_of: BTreeMap<&str, u32> = BTreeMap::new();
    let mut anchor_of: BTreeMap<&str, &str> = BTreeMap::new();
    let mut links_of: BTreeMap<&str, u16> = BTreeMap::new();
    let mut next_ino = FIRST_INO;
    let mut collapsed = 0u32;

    for (path, node) in rootfs.nodes() {
        let anchor = match &node.kind {
            EntryKind::Hardlink { target } => rootfs.resolve_hardlink(target).unwrap_or(path),
            _ => path,
        };
        anchor_of.insert(path, anchor);
        if let Some(&existing) = ino_of.get(anchor) {
            ino_of.insert(path, existing);
            collapsed += 1;
        } else {
            ino_of.insert(anchor, next_ino);
            ino_of.insert(path, next_ino);
            next_ino += 1;
        }
        *links_of.entry(anchor).or_insert(0) += 1;
    }

    // ---- Pass 2: directory contents.
    //
    // Every path's parent gains an entry. The root is implicit — it is never a
    // key in the rootfs — so it is keyed by the empty string.
    let mut children: BTreeMap<&str, Vec<(&str, u32, u8)>> = BTreeMap::new();
    let mut subdirs: BTreeMap<&str, u16> = BTreeMap::new();
    children.insert("", Vec::new());

    for (path, node) in rootfs.nodes() {
        let (parent, name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        if name.len() > 255 {
            return Err(Box::new(Ext2Error::NameTooLong {
                path: path.to_string(),
            }));
        }
        let ftype = match &node.kind {
            EntryKind::Directory { .. } => {
                *subdirs.entry(parent).or_insert(0) += 1;
                FT_DIR
            }
            EntryKind::Symlink { .. } => FT_SYMLINK,
            _ => FT_REG,
        };
        let ino = ino_of[path];
        children.entry(parent).or_default().push((name, ino, ftype));
    }

    // ---- Pass 3: the inode list, in inode-number order.
    let mut planned: Vec<Planned> = Vec::new();
    planned.push(Planned {
        ino: ROOT_INO,
        mode: S_IFDIR | 0o755,
        links: 2 + subdirs.get("").copied().unwrap_or(0),
        body: Body::Dir(serialize_dir(
            ROOT_INO,
            ROOT_INO,
            children.get("").map_or(&[][..], Vec::as_slice),
        )),
    });

    for (path, node) in rootfs.nodes() {
        // Hardlink followers contribute a directory entry and nothing else;
        // the anchor carries the body.
        if anchor_of[path] != path {
            continue;
        }
        let ino = ino_of[path];
        let links = links_of.get(path).copied().unwrap_or(1);
        let parent_ino = match path.rfind('/') {
            Some(i) => ino_of[&path[..i]],
            None => ROOT_INO,
        };
        let planned_node = match &node.kind {
            EntryKind::Directory { mode } => Planned {
                ino,
                mode: S_IFDIR | (*mode as u16 & 0o7777),
                links: 2 + subdirs.get(path).copied().unwrap_or(0),
                body: Body::Dir(serialize_dir(
                    ino,
                    parent_ino,
                    children.get(path).map_or(&[][..], Vec::as_slice),
                )),
            },
            EntryKind::Symlink { target } => Planned {
                ino,
                mode: S_IFLNK | 0o777,
                links: 1,
                body: Body::Symlink(target),
            },
            EntryKind::File { mode, .. } => Planned {
                ino,
                mode: S_IFREG | (*mode as u16 & 0o7777),
                links,
                body: Body::File(&node.data),
            },
            // A hardlink that is its own anchor is a dangling one: its target
            // did not survive a whiteout. cpio makes it an empty file; so do we,
            // rather than write an image with a dirent pointing at nothing.
            EntryKind::Hardlink { .. } => Planned {
                ino,
                mode: S_IFREG | 0o755,
                links,
                body: Body::File(&[]),
            },
        };
        if let Body::File(data) = &planned_node.body
            && data.len() as u64 > max_file_bytes()
        {
            return Err(Box::new(Ext2Error::FileTooLarge {
                path: path.to_string(),
                size: data.len() as u64,
            }));
        }
        planned.push(planned_node);
    }

    // ---- Pass 4: size the filesystem.
    let inodes_count_needed = next_ino; // ino numbers are 1-based; next_ino is the count + 1... see below
    let mut content_blocks = 0u64;
    for p in &planned {
        let len = match &p.body {
            Body::File(d) => d.len() as u64,
            Body::Symlink(t) if t.len() < FAST_SYMLINK_MAX => 0,
            Body::Symlink(t) => t.len() as u64,
            Body::Dir(d) => d.len() as u64,
        };
        let (data, meta) = blocks_for(len);
        content_blocks += data + meta;
    }

    let content_bytes = content_blocks * bs;
    let slack = extra_free_bytes.unwrap_or_else(|| SLACK_FLOOR.max(content_bytes / SLACK_FRACTION));
    let target_data_blocks = content_blocks + slack.div_ceil(bs);

    // `next_ino` is one past the last inode handed out, so it is already the
    // count including the ten reserved ones. Add slack so the guest can create
    // files as well as write to them.
    let inodes_count = (inodes_count_needed + inodes_count_needed / 4 + 64).max(16);
    let blocks_per_group = BLOCK_SIZE * 8;

    // Metadata size depends on the group count, which depends on the total,
    // which depends on the metadata size. Converge by iteration; it settles in
    // two or three rounds because each round only grows the total.
    let mut blocks_count = target_data_blocks + 64;
    let (groups, inodes_per_group, gdt_blocks, itb_per_group) = loop {
        let groups = (blocks_count.div_ceil(blocks_per_group as u64) as u32).max(1);
        let gdt_blocks = ((groups * DESC_SIZE) as u64).div_ceil(bs) as u32;
        let ipg = {
            let raw = inodes_count.div_ceil(groups);
            // The inode bitmap is one block, so a group cannot hold more inodes
            // than a block has bits.
            raw.next_multiple_of(8).clamp(8, BLOCK_SIZE * 8)
        };
        let itb = ((ipg as u64 * INODE_SIZE as u64).div_ceil(bs)) as u32;
        let mut overhead = 0u64;
        for g in 0..groups {
            overhead += 2 + itb as u64;
            if has_super(g) {
                overhead += 1 + gdt_blocks as u64;
            }
        }
        let needed = target_data_blocks + overhead;
        if needed <= blocks_count {
            break (groups, ipg, gdt_blocks, itb);
        }
        blocks_count = needed;
    };

    let inodes_count = inodes_per_group * groups;
    let size_bytes = blocks_count * bs;

    // ---- Pass 5: fix the metadata layout, and build the allocator over what
    // is left.
    let mut group_meta: Vec<(u32, u32, u32)> = Vec::with_capacity(groups as usize); // (block bitmap, inode bitmap, inode table)
    let mut alloc = BlockAlloc {
        spans: Vec::with_capacity(groups as usize),
        used: vec![0; groups as usize],
        cursor: 0,
    };
    for g in 0..groups {
        let group_start = g as u64 * blocks_per_group as u64;
        let group_end = ((g as u64 + 1) * blocks_per_group as u64).min(blocks_count);
        let mut b = group_start;
        if has_super(g) {
            b += 1 + gdt_blocks as u64;
        }
        let block_bitmap = b as u32;
        let inode_bitmap = (b + 1) as u32;
        let inode_table = (b + 2) as u32;
        b += 2 + itb_per_group as u64;
        group_meta.push((block_bitmap, inode_bitmap, inode_table));
        alloc.spans.push((b as u32, group_end as u32));
    }

    // Establish the file's full length up front so every later write lands
    // inside it — a `File` becomes sparse, a `Cursor` zero-fills, and neither
    // leaves a hole the kernel would read as garbage.
    out.seek(SeekFrom::Start(size_bytes - 1))?;
    out.write_all(&[0])?;

    // ---- Pass 6: write the bodies and the inodes.
    let mut used_dirs: Vec<u16> = vec![0; groups as usize];
    let mut free_inodes: Vec<u32> = vec![inodes_per_group; groups as usize];
    let mut inode_used: Vec<u8> = vec![0; inodes_count as usize];
    // Inodes 1..=10 are reserved and must read as in use.
    for slot in inode_used.iter_mut().take((FIRST_INO - 1) as usize) {
        *slot = 1;
        free_inodes[0] -= 1;
    }

    for p in &planned {
        let (bytes, is_dir): (&[u8], bool) = match &p.body {
            Body::File(d) => (d, false),
            Body::Dir(d) => (d.as_slice(), true),
            Body::Symlink(t) => (t.as_bytes(), false),
        };
        let fast_symlink = matches!(&p.body, Body::Symlink(t) if t.len() < FAST_SYMLINK_MAX);

        let mut i_block = [0u32; 15];
        let mut charged = 0u64;
        if fast_symlink {
            // The target lives in the pointer array itself.
            let raw = bytes;
            let mut buf = [0u8; 60];
            buf[..raw.len()].copy_from_slice(raw);
            for (i, chunk) in buf.chunks_exact(4).enumerate() {
                i_block[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        } else if !bytes.is_empty() {
            let (data_blocks, _) = blocks_for(bytes.len() as u64);
            let mut allocated = Vec::with_capacity(data_blocks as usize);
            for i in 0..data_blocks {
                let blk = alloc
                    .alloc()
                    .ok_or_else(|| io::Error::other("ext2: ran out of data blocks"))?;
                allocated.push(blk);
                let start = (i * bs) as usize;
                let end = ((i + 1) * bs).min(bytes.len() as u64) as usize;
                out.seek(SeekFrom::Start(blk as u64 * bs))?;
                out.write_all(&bytes[start..end])?;
            }
            charged = map_blocks(out, &mut alloc, &allocated, &mut i_block)?;
            charged += allocated.len() as u64;
        }

        let group = ((p.ino - 1) / inodes_per_group) as usize;
        let index = (p.ino - 1) % inodes_per_group;
        inode_used[(p.ino - 1) as usize] = 1;
        if p.ino >= FIRST_INO {
            free_inodes[group] -= 1;
        }
        if is_dir {
            used_dirs[group] += 1;
        }

        let size = bytes.len() as u64;
        let offset = group_meta[group].2 as u64 * bs + index as u64 * INODE_SIZE as u64;
        out.seek(SeekFrom::Start(offset))?;
        out.write_all(&inode_bytes(p.mode, size, p.links, charged, &i_block))?;
    }

    // ---- Pass 7: bitmaps, descriptors and superblocks.
    let mut free_blocks_total = 0u64;
    let mut descriptors = Vec::with_capacity(groups as usize * DESC_SIZE as usize);
    for g in 0..groups as usize {
        let group_start = g as u64 * blocks_per_group as u64;
        let group_end = ((g as u64 + 1) * blocks_per_group as u64).min(blocks_count);
        let in_group = (group_end - group_start) as u32;
        let (bbm, ibm, itbl) = group_meta[g];
        let first_free = alloc.spans[g].0;
        let used_here = (first_free as u64 - group_start) as u32;
        let free_here = in_group - used_here;
        free_blocks_total += free_here as u64;

        // Block bitmap: everything up to `first_free` is metadata or data, the
        // rest is free. Bits past the end of a short final group must read as
        // used, or the kernel will try to allocate blocks that are not there.
        let mut bitmap = vec![0u8; BLOCK_SIZE as usize];
        for b in 0..used_here {
            bitmap[(b / 8) as usize] |= 1 << (b % 8);
        }
        for b in in_group..blocks_per_group {
            bitmap[(b / 8) as usize] |= 1 << (b % 8);
        }
        out.seek(SeekFrom::Start(bbm as u64 * bs))?;
        out.write_all(&bitmap)?;

        let mut ibitmap = vec![0u8; BLOCK_SIZE as usize];
        for i in 0..inodes_per_group {
            let global = g as u32 * inodes_per_group + i;
            if global < inodes_count && inode_used[global as usize] == 1 {
                ibitmap[(i / 8) as usize] |= 1 << (i % 8);
            }
        }
        for i in inodes_per_group..(BLOCK_SIZE * 8) {
            ibitmap[(i / 8) as usize] |= 1 << (i % 8);
        }
        out.seek(SeekFrom::Start(ibm as u64 * bs))?;
        out.write_all(&ibitmap)?;

        descriptors.extend_from_slice(&bbm.to_le_bytes());
        descriptors.extend_from_slice(&ibm.to_le_bytes());
        descriptors.extend_from_slice(&itbl.to_le_bytes());
        descriptors.extend_from_slice(&(free_here as u16).to_le_bytes());
        descriptors.extend_from_slice(&(free_inodes[g] as u16).to_le_bytes());
        descriptors.extend_from_slice(&used_dirs[g].to_le_bytes());
        descriptors.extend_from_slice(&[0u8; 14]);
    }

    let free_inodes_total: u32 = free_inodes.iter().sum();
    for g in 0..groups {
        if !has_super(g) {
            continue;
        }
        let group_start = g as u64 * blocks_per_group as u64;
        let sb = superblock_bytes(
            inodes_count,
            blocks_count,
            free_blocks_total,
            free_inodes_total,
            blocks_per_group,
            inodes_per_group,
            g as u16,
        );
        // In group 0 the superblock sits 1024 bytes into block 0, after the
        // space a boot sector would occupy. Backups take the whole first block
        // of their group.
        let at = if g == 0 { 1024 } else { group_start * bs };
        out.seek(SeekFrom::Start(at))?;
        out.write_all(&sb)?;
        out.seek(SeekFrom::Start(group_start * bs + bs))?;
        out.write_all(&descriptors)?;
    }
    out.flush()?;

    Ok(Ext2Image {
        size_bytes,
        used_blocks: blocks_count - free_blocks_total,
        free_blocks: free_blocks_total,
        inodes: inodes_count,
        hardlinks_collapsed: collapsed,
    })
}

/// Fill `i_block` for a file, writing whatever indirect blocks are needed.
/// Returns the number of indirect blocks consumed, which `i_blocks` must count
/// alongside the data.
fn map_blocks<W: Write + Seek>(
    out: &mut W,
    alloc: &mut BlockAlloc,
    data: &[u32],
    i_block: &mut [u32; 15],
) -> io::Result<u64> {
    let bs = BLOCK_SIZE as u64;
    let ppb = ptrs_per_block() as usize;
    let mut meta = 0u64;

    for (i, blk) in data.iter().take(12).enumerate() {
        i_block[i] = *blk;
    }
    if data.len() <= 12 {
        return Ok(0);
    }

    let write_ptr_block = |out: &mut W, ptrs: &[u32], blk: u32| -> io::Result<()> {
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        for (i, p) in ptrs.iter().enumerate() {
            buf[i * 4..i * 4 + 4].copy_from_slice(&p.to_le_bytes());
        }
        out.seek(SeekFrom::Start(blk as u64 * bs))?;
        out.write_all(&buf)
    };

    let rest = &data[12..];
    let single = &rest[..rest.len().min(ppb)];
    let ind = alloc
        .alloc()
        .ok_or_else(|| io::Error::other("ext2: ran out of indirect blocks"))?;
    meta += 1;
    write_ptr_block(out, single, ind)?;
    i_block[12] = ind;

    if rest.len() <= ppb {
        return Ok(meta);
    }

    let double = &rest[ppb..];
    let dind = alloc
        .alloc()
        .ok_or_else(|| io::Error::other("ext2: ran out of indirect blocks"))?;
    meta += 1;
    let mut level1 = Vec::with_capacity(double.len().div_ceil(ppb));
    for chunk in double.chunks(ppb) {
        let blk = alloc
            .alloc()
            .ok_or_else(|| io::Error::other("ext2: ran out of indirect blocks"))?;
        meta += 1;
        write_ptr_block(out, chunk, blk)?;
        level1.push(blk);
    }
    write_ptr_block(out, &level1, dind)?;
    i_block[13] = dind;

    Ok(meta)
}

/// One 128-byte inode. `charged` is data plus indirect blocks; `i_blocks` wants
/// that in 512-byte sectors, which is the field's most-misread property.
fn inode_bytes(mode: u16, size: u64, links: u16, charged: u64, i_block: &[u32; 15]) -> Vec<u8> {
    let mut b = Vec::with_capacity(INODE_SIZE as usize);
    b.extend_from_slice(&mode.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // uid: everything is root
    b.extend_from_slice(&((size & 0xffff_ffff) as u32).to_le_bytes());
    for _ in 0..3 {
        b.extend_from_slice(&0u32.to_le_bytes()); // atime, ctime, mtime
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // dtime
    b.extend_from_slice(&0u16.to_le_bytes()); // gid
    b.extend_from_slice(&links.to_le_bytes());
    b.extend_from_slice(&((charged * (BLOCK_SIZE as u64 / 512)) as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // flags
    b.extend_from_slice(&0u32.to_le_bytes()); // osd1
    for p in i_block {
        b.extend_from_slice(&p.to_le_bytes());
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // generation
    b.extend_from_slice(&0u32.to_le_bytes()); // file_acl
    // For a regular file in rev 1 this field is the high 32 bits of the size.
    let high = if mode & S_IFREG == S_IFREG {
        (size >> 32) as u32
    } else {
        0
    };
    b.extend_from_slice(&high.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // faddr
    b.extend_from_slice(&[0u8; 12]); // osd2
    debug_assert_eq!(b.len(), INODE_SIZE as usize);
    b
}

#[allow(clippy::too_many_arguments)]
fn superblock_bytes(
    inodes_count: u32,
    blocks_count: u64,
    free_blocks: u64,
    free_inodes: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    group_nr: u16,
) -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    let put32 = |off: usize, v: u32, b: &mut Vec<u8>| {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put32(0, inodes_count, &mut b);
    put32(4, blocks_count as u32, &mut b);
    put32(8, 0, &mut b); // reserved blocks: a build artifact reserves nothing
    put32(12, free_blocks as u32, &mut b);
    put32(16, free_inodes, &mut b);
    put32(20, 0, &mut b); // first data block: 0 whenever the block size is > 1 KiB
    put32(24, BLOCK_SIZE.trailing_zeros() - 10, &mut b);
    put32(28, BLOCK_SIZE.trailing_zeros() - 10, &mut b); // frag size == block size
    put32(32, blocks_per_group, &mut b);
    put32(36, blocks_per_group, &mut b);
    put32(40, inodes_per_group, &mut b);
    put32(44, 0, &mut b); // mtime
    put32(48, 0, &mut b); // wtime
    b[52..54].copy_from_slice(&0u16.to_le_bytes()); // mount count
    b[54..56].copy_from_slice(&0xffffu16.to_le_bytes()); // max mount count: never force a check
    b[56..58].copy_from_slice(&MAGIC.to_le_bytes());
    b[58..60].copy_from_slice(&1u16.to_le_bytes()); // state: clean
    b[60..62].copy_from_slice(&1u16.to_le_bytes()); // errors: continue
    b[62..64].copy_from_slice(&0u16.to_le_bytes()); // minor rev
    put32(64, 0, &mut b); // lastcheck
    put32(68, 0, &mut b); // checkinterval: never
    put32(72, 0, &mut b); // creator os: Linux
    put32(76, REV_DYNAMIC, &mut b);
    b[80..82].copy_from_slice(&0u16.to_le_bytes()); // def_resuid
    b[82..84].copy_from_slice(&0u16.to_le_bytes()); // def_resgid
    put32(84, FIRST_INO, &mut b);
    b[88..90].copy_from_slice(&INODE_SIZE.to_le_bytes());
    b[90..92].copy_from_slice(&group_nr.to_le_bytes());
    put32(92, 0, &mut b); // feature_compat: no journal, no dir index
    put32(96, INCOMPAT_FILETYPE, &mut b);
    put32(100, RO_COMPAT_SPARSE_SUPER, &mut b);
    // A fixed UUID and label: the image is reproducible from a digest, so it
    // must not carry a random identifier.
    b[104..120].copy_from_slice(&[
        0x67, 0x69, 0x6d, 0x62, 0x61, 0x6c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    b[120..126].copy_from_slice(b"gimbal");
    b
}

/// Pack a directory's entries into whole blocks.
///
/// `.` and `..` come first because the kernel and every userspace tool expect
/// them at the head, and the last entry in each block absorbs the rest of the
/// block — an entry may not straddle a block boundary.
fn serialize_dir(self_ino: u32, parent_ino: u32, entries: &[(&str, u32, u8)]) -> Vec<u8> {
    let bs = BLOCK_SIZE as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut cur: Vec<u8> = Vec::with_capacity(bs);
    let mut last_off: Option<usize> = None;

    let push = |cur: &mut Vec<u8>,
                    out: &mut Vec<u8>,
                    last_off: &mut Option<usize>,
                    name: &str,
                    ino: u32,
                    ftype: u8| {
        let need = 8 + name.len().next_multiple_of(4);
        if cur.len() + need > bs {
            if let Some(off) = *last_off {
                let fill = (cur.len() - off) + (bs - cur.len());
                cur[off + 4..off + 6].copy_from_slice(&(fill as u16).to_le_bytes());
            }
            cur.resize(bs, 0);
            out.extend_from_slice(cur);
            cur.clear();
            *last_off = None;
        }
        *last_off = Some(cur.len());
        cur.extend_from_slice(&ino.to_le_bytes());
        cur.extend_from_slice(&(need as u16).to_le_bytes());
        cur.push(name.len() as u8);
        cur.push(ftype);
        cur.extend_from_slice(name.as_bytes());
        cur.resize(cur.len().next_multiple_of(4), 0);
    };

    push(&mut cur, &mut out, &mut last_off, ".", self_ino, FT_DIR);
    push(&mut cur, &mut out, &mut last_off, "..", parent_ino, FT_DIR);
    for (name, ino, ftype) in entries {
        push(&mut cur, &mut out, &mut last_off, name, *ino, *ftype);
    }
    if let Some(off) = last_off {
        let fill = (cur.len() - off) + (bs - cur.len());
        cur[off + 4..off + 6].copy_from_slice(&(fill as u16).to_le_bytes());
    }
    cur.resize(bs, 0);
    out.extend_from_slice(&cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn u16_at(img: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([img[off], img[off + 1]])
    }
    fn u32_at(img: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([img[off], img[off + 1], img[off + 2], img[off + 3]])
    }
    /// Byte offset of an inode, read out of the image's own descriptor table
    /// rather than assumed from the layout.
    fn inode_at(img: &[u8], ino: u32) -> usize {
        let ipg = u32_at(img, 1024 + 40);
        let group = (ino - 1) / ipg;
        let desc = BLOCK_SIZE as usize + (group * DESC_SIZE) as usize;
        let table = u32_at(img, desc + 8) as usize;
        table * BLOCK_SIZE as usize + ((ino - 1) % ipg) as usize * INODE_SIZE as usize
    }

    fn build(entries: &[(&str, EntryKind, &[u8])]) -> Vec<u8> {
        let mut fs = Rootfs::new();
        for (path, kind, data) in entries {
            fs.insert(path.to_string(), kind.clone(), data.to_vec());
        }
        fs.materialize_parents();
        let mut cur = Cursor::new(Vec::new());
        write_ext2(&fs, &mut cur, Some(0)).expect("image");
        cur.into_inner()
    }

    /// The busybox lesson, in its disk-image form. `write_cpio` once turned a
    /// 1.8 MiB layer into a 467 MiB archive by emitting one copy per link; the
    /// same mistake here multiplies the disk instead.
    #[test]
    fn hardlinks_share_one_inode_and_one_copy_of_the_body() {
        let body = vec![0xAB; 200_000];
        let mut fs = Rootfs::new();
        fs.insert(
            "bin/busybox".into(),
            EntryKind::File {
                mode: 0o755,
                size: body.len() as u64,
            },
            body.clone(),
        );
        for name in ["sh", "ls", "cat"] {
            fs.insert(
                format!("bin/{name}"),
                EntryKind::Hardlink {
                    target: "bin/busybox".into(),
                },
                Vec::new(),
            );
        }
        fs.materialize_parents();
        let mut cur = Cursor::new(Vec::new());
        let out = write_ext2(&fs, &mut cur, Some(0)).expect("image");
        let img = cur.into_inner();

        assert_eq!(out.hardlinks_collapsed, 3, "three links, one body");

        // All four names resolve to the same inode number, read out of the
        // directory block rather than inferred.
        let dir_ino = {
            // `bin` is the first non-reserved inode allocated after root.
            let mut found = 0;
            for ino in FIRST_INO..FIRST_INO + 8 {
                let off = inode_at(&img, ino);
                if u16_at(&img, off) & S_IFDIR == S_IFDIR {
                    found = ino;
                    break;
                }
            }
            found
        };
        let blk = u32_at(&img, inode_at(&img, dir_ino) + 40) as usize;
        let mut names: Vec<(String, u32)> = Vec::new();
        let mut p = blk * BLOCK_SIZE as usize;
        let end = p + BLOCK_SIZE as usize;
        while p < end {
            let ino = u32_at(&img, p);
            let rec = u16_at(&img, p + 4) as usize;
            let nlen = img[p + 6] as usize;
            if rec == 0 {
                break;
            }
            if ino != 0 {
                names.push((String::from_utf8_lossy(&img[p + 8..p + 8 + nlen]).into(), ino));
            }
            p += rec;
        }
        let of = |n: &str| names.iter().find(|(a, _)| a == n).map(|(_, i)| *i);
        let busybox = of("busybox").expect("busybox present");
        for link in ["sh", "ls", "cat"] {
            assert_eq!(of(link), Some(busybox), "{link} must share busybox's inode");
        }

        // And the body was written once: 200 KB is 49 blocks, so four copies
        // would be unmistakable in the used-block count.
        assert!(
            out.used_blocks < 120,
            "one copy of a 200 KB body, got {} blocks used",
            out.used_blocks
        );
    }

    /// ext2 directory entries may not straddle a block: the last entry in each
    /// block absorbs the remainder. Walking off the end of a block is how this
    /// fails, and it fails as a corrupt listing rather than an error.
    #[test]
    fn directory_entries_fill_their_block_exactly_and_never_straddle() {
        let names: Vec<String> = (0..400).map(|i| format!("entry-number-{i:04}")).collect();
        let entries: Vec<(&str, u32, u8)> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), (i + 20) as u32, FT_REG))
            .collect();
        let packed = serialize_dir(2, 2, &entries);

        assert_eq!(packed.len() % BLOCK_SIZE as usize, 0, "whole blocks only");
        assert!(packed.len() > BLOCK_SIZE as usize, "must span blocks");

        let mut seen = 0;
        for block in packed.chunks(BLOCK_SIZE as usize) {
            let mut p = 0usize;
            while p < block.len() {
                let rec = u16::from_le_bytes([block[p + 4], block[p + 5]]) as usize;
                let nlen = block[p + 6] as usize;
                assert!(rec >= 8 + nlen, "rec_len {rec} cannot hold a {nlen}-byte name");
                assert_eq!(rec % 4, 0, "rec_len must stay 4-byte aligned");
                assert!(
                    p + rec <= block.len(),
                    "entry at {p} with rec_len {rec} runs past the end of its block"
                );
                seen += 1;
                p += rec;
            }
            assert_eq!(p, block.len(), "entries must land exactly on the block end");
        }
        assert_eq!(seen, entries.len() + 2, ". and .. plus every entry");
    }

    /// A target under 60 bytes lives in the block pointers themselves. Giving it
    /// a data block as well produces a symlink that resolves to garbage.
    #[test]
    fn a_short_symlink_is_stored_inline_and_costs_no_blocks() {
        let img = build(&[(
            "bin/sh",
            EntryKind::Symlink {
                target: "busybox".into(),
            },
            b"",
        )]);
        let mut link = 0;
        for ino in FIRST_INO..FIRST_INO + 8 {
            if u16_at(&img, inode_at(&img, ino)) & 0o170000 == S_IFLNK {
                link = ino;
                break;
            }
        }
        assert_ne!(link, 0, "the symlink inode must exist");
        let off = inode_at(&img, link);
        assert_eq!(u32_at(&img, off + 28), 0, "a fast symlink charges no blocks");
        assert_eq!(u32_at(&img, off + 4), 7, "i_size is the target length");
        assert_eq!(&img[off + 40..off + 47], b"busybox", "target stored inline");
    }

    /// The fields a mount actually checks before it will look at anything else.
    #[test]
    fn the_superblock_describes_a_filesystem_the_kernel_will_mount() {
        let img = build(&[(
            "etc/hostname",
            EntryKind::File { mode: 0o644, size: 6 },
            b"gimbal",
        )]);
        assert_eq!(u16_at(&img, 1024 + 56), MAGIC, "s_magic");
        assert_eq!(u16_at(&img, 1024 + 58), 1, "s_state must be clean");
        assert_eq!(u32_at(&img, 1024 + 20), 0, "s_first_data_block is 0 above 1 KiB blocks");
        assert_eq!(u32_at(&img, 1024 + 24), 2, "s_log_block_size for 4 KiB");
        assert_eq!(u32_at(&img, 1024 + 76), REV_DYNAMIC, "rev 1 for a stated inode size");
        assert_eq!(u16_at(&img, 1024 + 88), INODE_SIZE, "s_inode_size");
        assert_eq!(u32_at(&img, 1024 + 84), FIRST_INO, "s_first_ino");
        assert_eq!(u32_at(&img, 1024 + 96), INCOMPAT_FILETYPE, "dirents carry a type");

        // Root is inode 2, is a directory, and links to at least . and ..
        let root = inode_at(&img, ROOT_INO);
        assert_eq!(u16_at(&img, root) & 0o170000, S_IFDIR, "root is a directory");
        assert!(u16_at(&img, root + 26) >= 2, "root nlink counts . and ..");

        // The image is exactly as long as the superblock claims.
        let blocks = u32_at(&img, 1024 + 4) as usize;
        assert_eq!(img.len(), blocks * BLOCK_SIZE as usize, "image length matches s_blocks_count");
    }
}
