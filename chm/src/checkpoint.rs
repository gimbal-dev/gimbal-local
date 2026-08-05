// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! On-disk local checkpoints: the `chm` half of suspend/resume.
//!
//! A checkpoint lets a stopped microVM be brought back exactly where it left off
//! (restored, not cold-booted), mirroring the control plane's Phase 1
//! suspend/resume contract (a second snapshot `kind`: a live checkpoint of
//! memory + device + fs delta). It lives INSIDE the parent snapshot directory so
//! it is co-located with the parent `state.json` (whose device/serial metadata
//! is invariant after boot and reused verbatim) and the disk overlays:
//!
//! ```text
//! <snapshot_dir>/
//!   state.json               parent — device + memory layout (carried as-is)
//!   snapshot/memory-ranges   parent base RAM (cold-boot source)
//!   .chm-overlays/           live disk overlays (+ .bitmap) — reattached on resume
//!   .chm-checkpoint/         THIS checkpoint
//!     checkpoint.json        CheckpointState (vCPU + GIC live state)
//!     memory-ranges          dumped live guest RAM (parent's region layout)
//!     overlays/              captured disk overlays — the RAM's matching disk
//! ```
//!
//! Each revision captures the disk `overlays/` alongside `memory-ranges`, so a
//! revision is a consistent RAM+disk pair: rollback restores both, never an
//! earlier RAM against a later disk (which could corrupt the guest fs).
//!
//! Resume reuses the cold restore machinery, overriding only the runtime-mutable
//! state (vCPU registers, GIC interrupt state, guest RAM) with the captured live
//! values; the parent snapshot still supplies the memory-region layout and the
//! virtio/serial device wiring.

use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::collections::HashSet;
use std::ffi::CString;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use hypervisor::hvf::checkpoint::{CHECKPOINT_VERSION, CheckpointState};
use hypervisor::hvf::rehydrate::MemMapping;
use hypervisor::hvf::virtio::GuestMemory;
use serde::{Deserialize, Serialize};

const CHECKPOINT_SUBDIR: &str = ".chm-checkpoint";
const REVISIONS_SUBDIR: &str = ".chm-revisions";
const MANIFEST: &str = "checkpoint.json";
const MEMORY_RANGES: &str = "memory-ranges";
/// The live disk-overlay directory (CoW writes + bitmaps) at the snapshot root.
const LIVE_OVERLAYS_DIR: &str = ".chm-overlays";
/// A revision's captured copy of the disk overlays, stored inside the revision
/// dir alongside `memory-ranges` so a revision is a consistent RAM+disk pair.
const OVERLAYS_SUBDIR: &str = "overlays";

/// Sidecar recording the live overlay identity a checkpoint was taken against,
/// so resume can tell whether the disk has moved on under it. See
/// [`overlay_drift`].
const OVERLAY_FINGERPRINT: &str = "overlay.fingerprint";

/// How many revisions keep their full (resumable) guest-RAM dump. Older
/// revisions are pruned to manifest-only so the lineage graph survives without
/// the store growing by a full RAM image on every suspend. Overridable via
/// `CHM_MAX_RESUMABLE_REVISIONS`.
const DEFAULT_MAX_RESUMABLE_REVISIONS: usize = 5;

/// On-disk manifest version for the lineage header (independent of the
/// hardware [`CheckpointState`] version).
const REVISION_MANIFEST_VERSION: u32 = 1;

/// A committed revision: the lineage header plus the captured hardware state.
///
/// The header is the spine of the fork/lineage model (see
/// `docs/gimbal-local-fork-model.md`): every checkpoint records the revision it
/// descends from, so a sandbox's suspends form a chain and forks form branches.
/// Today checkpoints are HEAD-only (each suspend overwrites the previous), but
/// the `parent` pointer is preserved so the graph's depth and origin are
/// addressable now and a full revision store is an additive change later.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Revision {
    /// Manifest format version.
    pub manifest_version: u32,
    /// This revision's stable id.
    pub id: String,
    /// The revision this descends from (the previous HEAD), or `None` when it is
    /// rooted directly on the base image.
    pub parent: Option<String>,
    /// The base image (snapshot directory name) this revision deltas.
    pub base_image: String,
    /// Capture time, Unix epoch milliseconds.
    pub created_at_ms: u64,
    /// What produced it (e.g. `"connect"` or `"daemon"`).
    pub origin: String,
    /// Optional human label/message.
    pub label: Option<String>,
    /// The captured live hardware state (vCPU + GIC).
    pub state: CheckpointState,
}

/// The checkpoint directory for a snapshot.
pub(crate) fn checkpoint_dir(snapshot_dir: &Path) -> PathBuf {
    snapshot_dir.join(CHECKPOINT_SUBDIR)
}

/// The dumped-RAM file inside a snapshot's checkpoint.
pub(crate) fn memory_ranges_path(snapshot_dir: &Path) -> PathBuf {
    checkpoint_dir(snapshot_dir).join(MEMORY_RANGES)
}

/// Whether a resumable checkpoint exists for this snapshot.
pub(crate) fn has_checkpoint(snapshot_dir: &Path) -> bool {
    checkpoint_dir(snapshot_dir).join(MANIFEST).is_file()
        && memory_ranges_path(snapshot_dir).is_file()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mint a revision id that sorts by creation time and is unique enough for the
/// local store (millisecond timestamp + this process's low pid bits).
fn mint_revision_id(created_at_ms: u64) -> String {
    format!("rev-{created_at_ms:013}-{:04x}", process::id() & 0xffff)
}

/// Remove any checkpoint so the next start cold-boots from the parent snapshot.
pub(crate) fn clear_checkpoint(snapshot_dir: &Path) {
    let _ = fs::remove_dir_all(checkpoint_dir(snapshot_dir));
}

/// Retire the current checkpoint into the revision store rather than deleting
/// it, and report the id it was filed under.
///
/// `clear_checkpoint` is the right call when HEAD was written by this run's own
/// teardown and the run went badly: a checkpoint of a dead guest is not one the
/// next start should silently resume. It becomes the *wrong* call once
/// continuous snapshots are on, because HEAD is then a point captured minutes
/// earlier from a healthy guest — and #148 exists precisely so that a session
/// which ends badly is not a session whose work is gone.
///
/// Archiving satisfies both duties at once: no HEAD is left for the next start
/// to resume blindly, and the point stays reachable through `chm revisions` /
/// `chm rollback`, which restore its RAM *and* the overlays captured with it.
/// That pairing is the only consistent way back — the live overlays have moved
/// on since, so resuming this RAM against them is exactly the torn RAM/disk pair
/// the #139 drift guard refuses.
pub(crate) fn retire_checkpoint(snapshot_dir: &Path) -> Option<String> {
    let id = read_revision(snapshot_dir).ok()?.id;
    archive_head(snapshot_dir, &id);
    // Keep the store bounded on the way out. Safe for the revision just filed:
    // pruning keeps the newest, and nothing is newer than this.
    prune_revisions(snapshot_dir);
    Some(id)
}

/// Read a revision's full manifest (lineage header + hardware state).
pub(crate) fn read_revision(snapshot_dir: &Path) -> Result<Revision, String> {
    read_revision_manifest(&checkpoint_dir(snapshot_dir))
}

/// Read a revision manifest from an arbitrary revision directory (the current
/// checkpoint, or an archived one under `.chm-revisions/`).
fn read_revision_manifest(rev_dir: &Path) -> Result<Revision, String> {
    let path = rev_dir.join(MANIFEST);
    let body = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let rev: Revision =
        serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if rev.state.version != CHECKPOINT_VERSION {
        return Err(format!(
            "checkpoint version {} is not the supported version {} \
             (delete {} to cold-boot)",
            rev.state.version,
            CHECKPOINT_VERSION,
            rev_dir.display()
        ));
    }
    Ok(rev)
}

/// Read just the hardware state to resume from (the lineage header is metadata).
pub(crate) fn read_checkpoint(snapshot_dir: &Path) -> Result<CheckpointState, String> {
    Ok(read_revision(snapshot_dir)?.state)
}

/// Write a revision atomically: dump live guest RAM into the parent's
/// memory-region layout, then the manifest (lineage header + hardware state).
/// The whole revision is staged in a sibling `.tmp` directory and renamed into
/// place so a crash mid-write never leaves a half-written checkpoint a resume
/// would trust. The new revision's `parent` is the previous HEAD's id, so the
/// lineage chain is preserved even though only HEAD is kept on disk today.
pub(crate) fn write_checkpoint(
    snapshot_dir: &Path,
    state: &CheckpointState,
    guest_mem: &GuestMemory,
    mem_mappings: &[MemMapping],
    origin: &str,
) -> Result<(), String> {
    // The current HEAD (if any) becomes this revision's parent.
    let parent = read_revision(snapshot_dir).ok().map(|r| r.id);
    let created_at_ms = now_ms();
    let base_image = snapshot_dir
        .file_name()
        .map_or_else(
            || snapshot_dir.display().to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
    let revision = Revision {
        manifest_version: REVISION_MANIFEST_VERSION,
        id: mint_revision_id(created_at_ms),
        parent,
        base_image,
        created_at_ms,
        origin: origin.to_string(),
        label: None,
        state: state.clone(),
    };

    let dir = checkpoint_dir(snapshot_dir);
    let mut tmp = dir.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;

    // Write against the previous HEAD's dump where there is one. Two
    // checkpoints seconds apart share almost all of their RAM -- measured at
    // 99.9% identical on a real guest -- so re-writing the whole image is
    // wasted freeze *and* wasted disk.
    let parent_dump = dir.join(MEMORY_RANGES);
    let parent_dump = parent_dump.is_file().then_some(parent_dump);
    dump_guest_ram(
        &tmp.join(MEMORY_RANGES),
        guest_mem,
        mem_mappings,
        parent_dump.as_deref(),
    )?;

    // Capture the disk overlays alongside the RAM dump so this revision is a
    // consistent RAM+disk pair. Without this, rollback would restore an earlier
    // RAM image while the live overlay still held later disk writes -- an
    // inconsistent pair that can corrupt the guest fs on resume (#62).
    snapshot_overlays(snapshot_dir, &tmp)?;

    // Record what the overlays looked like at the instant this RAM was captured.
    // Read from the live dir (not the copy) so resume compares like with like.
    let _ = fs::write(tmp.join(OVERLAY_FINGERPRINT), overlay_fingerprint(snapshot_dir));

    let json =
        serde_json::to_string(&revision).map_err(|e| format!("serialize revision: {e}"))?;
    fs::write(tmp.join(MANIFEST), json.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.join(MANIFEST).display()))?;

    // Archive the current HEAD into the revision store (preserving history),
    // then swap the staged revision into place as the new HEAD. The new
    // revision's `parent` is exactly the current HEAD's id.
    match revision.parent.as_deref() {
        Some(head_id) => archive_head(snapshot_dir, head_id),
        None => {
            let _ = fs::remove_dir_all(&dir);
        }
    }
    fs::rename(&tmp, &dir)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), dir.display()))?;
    prune_revisions(snapshot_dir);
    Ok(())
}

/// The revision store directory (archived past revisions) for a snapshot.
fn revisions_dir(snapshot_dir: &Path) -> PathBuf {
    snapshot_dir.join(REVISIONS_SUBDIR)
}

pub(crate) fn max_resumable_revisions() -> usize {
    env::var("CHM_MAX_RESUMABLE_REVISIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_RESUMABLE_REVISIONS)
}

/// Move the current HEAD checkpoint into the revision store under its id, so it
/// is preserved as a past revision instead of being overwritten.
fn archive_head(snapshot_dir: &Path, head_id: &str) {
    let store = revisions_dir(snapshot_dir);
    if fs::create_dir_all(&store).is_err() {
        let _ = fs::remove_dir_all(checkpoint_dir(snapshot_dir));
        return;
    }
    let dest = store.join(head_id);
    let _ = fs::remove_dir_all(&dest);
    if fs::rename(checkpoint_dir(snapshot_dir), &dest).is_err() {
        // If the move failed, don't leave a stale HEAD behind.
        let _ = fs::remove_dir_all(checkpoint_dir(snapshot_dir));
    }
}

/// A revision in a snapshot's lineage, with whether it can still be resumed /
/// rolled back to (its guest-RAM dump is still present).
pub(crate) struct RevisionInfo {
    pub revision: Revision,
    pub resumable: bool,
    pub is_head: bool,
    /// Where this revision's payload lives — the archive entry, or the
    /// checkpoint dir for HEAD. Needed to size it and to read its pin marker.
    pub dir: PathBuf,
}

/// List a snapshot's revisions oldest-first: the archived ones in the store plus
/// the current HEAD. A revision is `resumable` while its RAM dump is retained.
pub(crate) fn list_revisions(snapshot_dir: &Path) -> Vec<RevisionInfo> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(revisions_dir(snapshot_dir)) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if let Ok(revision) = read_revision_manifest(&dir) {
                let resumable = dir.join(MEMORY_RANGES).is_file();
                out.push(RevisionInfo { revision, resumable, is_head: false, dir });
            }
        }
    }
    if let Ok(revision) = read_revision(snapshot_dir) {
        let resumable = memory_ranges_path(snapshot_dir).is_file();
        let dir = checkpoint_dir(snapshot_dir);
        out.push(RevisionInfo { revision, resumable, is_head: true, dir });
    }
    out.sort_by(|a, b| a.revision.created_at_ms.cmp(&b.revision.created_at_ms));
    out
}

/// A lightweight, serializable view of a revision for the CLI + app (without the
/// heavy hardware state). `resumable` = its RAM dump is retained; `is_head` = it
/// is the current live checkpoint.
#[derive(Serialize)]
pub(crate) struct RevisionSummary {
    pub id: String,
    pub parent: Option<String>,
    pub base_image: String,
    pub created_at_ms: u64,
    pub origin: String,
    pub label: Option<String>,
    pub resumable: bool,
    pub is_head: bool,
    /// A retention root: exempt from age-based pruning.
    pub pinned: bool,
    /// Apparent bytes, which counts content shared with another revision.
    pub bytes: u64,
    /// Bytes deleting this revision would actually give back -- its extents
    /// that no other file shares. Exact, and the number to act on.
    pub frees: u64,
}

/// The snapshot's revisions as serializable summaries (oldest-first).
pub(crate) fn revision_summaries(snapshot_dir: &Path) -> Vec<RevisionSummary> {
    list_revisions(snapshot_dir)
        .into_iter()
        .map(|info| RevisionSummary {
            pinned: is_pinned_dir(&info.dir),
            bytes: revision_bytes(&info.dir),
            frees: revision_frees(&info.dir),
            id: info.revision.id,
            parent: info.revision.parent,
            base_image: info.revision.base_image,
            created_at_ms: info.revision.created_at_ms,
            origin: info.revision.origin,
            label: info.revision.label,
            resumable: info.resumable,
            is_head: info.is_head,
        })
        .collect()
}

/// Bytes held by one revision, counting every file under it.
///
/// This is the *apparent* size. It deliberately double-counts content shared
/// with another revision, because the honest answer to "how big is this one"
/// includes state it depends on. `snapshot_usage` gives the other half — what
/// is actually on the disk — and the two differ exactly by the sharing.
fn revision_frees(dir: &Path) -> u64 {
    fn walk(dir: &Path, seen: &mut HashSet<(u64, u64)>, total: &mut u64) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                walk(&e.path(), seen, total);
            } else if md.is_file() && seen.insert((md.dev(), md.ino())) {
                *total += private_bytes(&e.path(), md.len());
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut HashSet::new(), &mut total);
    total
}

fn revision_bytes(dir: &Path) -> u64 {
    fn walk(dir: &Path, seen: &mut Option<&mut HashSet<(u64, u64)>>, total: &mut u64) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                walk(&e.path(), seen, total);
            } else if md.is_file() {
                // A forked revision hard-links the parent's write-once RAM dump,
                // so the same inode appears under several revisions. Counting it
                // once per link would report disk that does not exist.
                if let Some(set) = seen.as_deref_mut()
                    && !set.insert((md.dev(), md.ino()))
                {
                    continue;
                }
                *total += md.len();
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut None, &mut total);
    total
}

/// What this snapshot's lineage actually occupies on disk, with each inode
/// counted once however many revisions link to it.
///
/// Reported beside the sum of the per-revision figures so the difference — the
/// saving from sharing — is visible rather than inferred. Answering *"what is
/// using 40 GB?"* with a number that double-counts is worse than not answering.
pub(crate) fn snapshot_usage(snapshot_dir: &Path) -> SnapshotUsage {
    fn walk(dir: &Path, seen: &mut HashSet<(u64, u64)>, total: &mut u64) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                walk(&e.path(), seen, total);
            } else if md.is_file() && seen.insert((md.dev(), md.ino())) {
                *total += private_bytes(&e.path(), md.len());
            }
        }
    }
    // `on_disk` must cover exactly the set `apparent` sums, or the difference
    // between them is not the sharing and the comparison is nonsense. Measuring
    // this against a real snapshot reported 58 GiB on disk against 50 GiB of
    // parts — impossible for a deduplicating count, and caused by folding the
    // live overlays in here while no revision owns them. They are real disk, so
    // they are reported, but on their own line.
    let mut seen = HashSet::new();
    let mut on_disk = 0;
    for d in [revisions_dir(snapshot_dir), checkpoint_dir(snapshot_dir)] {
        walk(&d, &mut seen, &mut on_disk);
    }
    let mut live_seen = HashSet::new();
    let mut live_overlays = 0;
    walk(
        &snapshot_dir.join(LIVE_OVERLAYS_DIR),
        &mut live_seen,
        &mut live_overlays,
    );

    let apparent = revision_summaries(snapshot_dir).iter().map(|r| r.bytes).sum();
    SnapshotUsage {
        on_disk,
        apparent,
        live_overlays,
    }
}

/// `ATTR_CMNEXT_PRIVATESIZE` / `FSOPT_ATTR_CMN_EXTENDED`: not in the `libc`
/// crate's macOS bindings, so declared here from `<sys/attr.h>`.
#[cfg(target_os = "macos")]
const ATTR_CMNEXT_PRIVATESIZE: libc::attrgroup_t = 0x0000_0008;
#[cfg(target_os = "macos")]
const FSOPT_ATTR_CMN_EXTENDED: u32 = 0x0000_0020;

/// Bytes of `path` that belong to it alone -- what deleting it would actually
/// free.
///
/// Inode dedup catches a hard link but cannot see an APFS clone, which is a
/// *distinct inode sharing extents*: `st_blocks` reports a 200 MiB clone that
/// cost 32 KiB as a full 200 MiB (measured). Since revisions now clone both the
/// RAM dump and the overlays, counting lengths reported a lineage at 110 GiB
/// that had consumed 131 MiB -- and a user believing it would delete history
/// they never needed to.
///
/// macOS answers this directly. `ATTR_CMNEXT_PRIVATESIZE` excludes every extent
/// shared with another file, so it self-corrects when a parent is pruned: the
/// extents stop being shared and become this file's own. Anywhere the call is
/// not available the apparent length is the honest fallback, because without
/// clone support that *is* the disk.
#[cfg(target_os = "macos")]
fn private_bytes(path: &Path, len: u64) -> u64 {
    #[repr(C, packed(4))]
    struct Packed {
        len: u32,
        private: u64,
    }
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return len;
    };
    // SAFETY: `attrlist` is a plain C struct of integer fields, for which an
    // all-zero bit pattern is a valid (and here deliberate: request nothing)
    // value. Every field is then set explicitly below.
    let mut list: libc::attrlist = unsafe { mem::zeroed() };
    list.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    list.forkattr = ATTR_CMNEXT_PRIVATESIZE;
    let mut out = Packed { len: 0, private: 0 };
    // SAFETY: `c_path` is a NUL-terminated path that outlives the call; `list`
    // is a fully initialised attrlist requesting exactly one fork attribute;
    // and `out` is a correctly packed buffer for that attribute whose size we
    // pass, so the kernel cannot write past it. Any error leaves `out` unused.
    let rc = unsafe {
        libc::getattrlist(
            c_path.as_ptr(),
            ptr::from_mut(&mut list).cast(),
            ptr::from_mut(&mut out).cast(),
            mem::size_of::<Packed>(),
            FSOPT_ATTR_CMN_EXTENDED,
        )
    };
    if rc != 0 || out.len as usize != mem::size_of::<Packed>() {
        return len;
    }
    out.private
}

#[cfg(not(target_os = "macos"))]
fn private_bytes(_path: &Path, len: u64) -> u64 {
    len
}

/// Disk held by a snapshot's lineage, three ways.
///
/// `on_disk` and `apparent` cover the same revisions and differ only by shared
/// content, so `apparent - on_disk` is exactly the saving from sharing -- whether
/// that sharing is a hard link or an APFS clone.
#[derive(Serialize)]
pub(crate) struct SnapshotUsage {
    /// Bytes the whole lineage would give back if deleted -- a *floor*, since
    /// an extent shared by two revisions is exclusive to neither and so counts
    /// in neither. `apparent` is the matching ceiling.
    pub on_disk: u64,
    /// The per-revision figures summed, which counts shared content repeatedly.
    pub apparent: u64,
    /// The live working overlays, which belong to no revision but are still
    /// disk this snapshot is using.
    pub live_overlays: u64,
}


/// Keep the newest `max_resumable_revisions()` archived revisions fully
/// resumable; drop older ones' RAM dumps (keeping their manifest so the lineage
/// graph stays intact) to bound disk growth.
fn prune_revisions(snapshot_dir: &Path) {
    prune_revisions_keeping(snapshot_dir, max_resumable_revisions());
}

fn prune_revisions_keeping(snapshot_dir: &Path, max_resumable: usize) {
    let store = revisions_dir(snapshot_dir);
    let mut archived: Vec<(u64, PathBuf)> = match fs::read_dir(&store) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let dir = e.path();
                read_revision_manifest(&dir).ok().and_then(|r| {
                    dir.join(MEMORY_RANGES)
                        .is_file()
                        .then_some((r.created_at_ms, dir))
                })
            })
            .collect(),
        Err(_) => return,
    };
    // A pinned revision is a retention root: the operator has said this point
    // must remain resumable, so age must not reclaim it. Pins are excluded from
    // the budget entirely rather than counted against it — counting them would
    // mean pinning a point silently shortened the window of recent history,
    // which is the opposite of what pinning is for.
    let (_pinned, mut prunable): (Vec<_>, Vec<_>) =
        archived.drain(..).partition(|(_, dir)| is_pinned_dir(dir));

    let keep = max_resumable.saturating_sub(1);
    if prunable.len() <= keep {
        return;
    }
    prunable.sort_by(|a, b| a.0.cmp(&b.0));
    let drop_count = prunable.len() - keep;
    for (_, dir) in prunable.into_iter().take(drop_count) {
        // Drop the heavy payload (RAM dump + captured overlays) but keep the
        // manifest, so the lineage graph survives as metadata-only.
        let _ = fs::remove_file(dir.join(MEMORY_RANGES));
        let _ = fs::remove_dir_all(dir.join(OVERLAYS_SUBDIR));
    }
}

/// A pinned revision is exempt from age-based pruning.
///
/// The marker is a file in the revision's own directory rather than a field in
/// the manifest, for two reasons: pinning must not rewrite a manifest that a
/// digest may cover, and creating or removing a file is atomic, so a pin cannot
/// be half-applied by an interrupted write.
const PIN_MARKER: &str = "pinned";

fn is_pinned_dir(revision_dir: &Path) -> bool {
    revision_dir.join(PIN_MARKER).is_file()
}

/// Mark a revision as a retention root. Returns whether it changed anything, so
/// a caller can tell "pinned it" from "it was already pinned".
pub(crate) fn pin_revision(
    snapshot_dir: &Path,
    rev_id: &str,
    pinned: bool,
) -> Result<bool, String> {
    let dir = resolve_revision_dir(snapshot_dir, rev_id)?;
    let marker = dir.join(PIN_MARKER);
    let was = marker.is_file();
    if pinned == was {
        return Ok(false);
    }
    if pinned {
        fs::write(&marker, b"retention root\n").map_err(|e| format!("pin {rev_id}: {e}"))?;
    } else {
        fs::remove_file(&marker).map_err(|e| format!("unpin {rev_id}: {e}"))?;
    }
    Ok(true)
}

/// Where a revision id lives, whether it is archived or the live HEAD.
///
/// `chm revisions` prints the HEAD alongside the archive, so accepting only
/// archived ids would reject an id we had just shown — the same trap that
/// `rollback` had to fix.
fn resolve_revision_dir(snapshot_dir: &Path, rev_id: &str) -> Result<PathBuf, String> {
    let archived = revisions_dir(snapshot_dir).join(rev_id);
    if archived.join(MANIFEST).is_file() {
        return Ok(archived);
    }
    let head = checkpoint_dir(snapshot_dir);
    if read_revision_manifest(&head).is_ok_and(|r| r.id == rev_id) {
        return Ok(head);
    }
    Err(format!(
        "no revision {rev_id} in {} (see `chm revisions`)",
        snapshot_dir.display()
    ))
}


/// Roll a snapshot back to an archived revision: it becomes a new HEAD that
/// descends from the target (append-only — history is preserved, not rewound).
/// The target must still be resumable (its RAM dump retained).
pub(crate) fn rollback(snapshot_dir: &Path, rev_id: &str) -> Result<(), String> {
    let mut target = revisions_dir(snapshot_dir).join(rev_id);
    if !target.join(MANIFEST).is_file() {
        // The live HEAD is listed by `chm revisions` but lives in the checkpoint
        // dir rather than the archive, so looking only in the archive rejected an
        // id we had just printed. Rolling back to HEAD is not a no-op and is the
        // documented recovery from overlay drift: it restores the overlays that
        // were captured with that RAM over the diverged live ones. Archive it
        // first, then take the ordinary path.
        match read_revision(snapshot_dir) {
            Ok(head) if head.id == rev_id => {
                archive_head(snapshot_dir, rev_id);
                target = revisions_dir(snapshot_dir).join(rev_id);
                if !target.join(MANIFEST).is_file() {
                    return Err(format!("revision {rev_id} could not be archived"));
                }
            }
            _ => return Err(format!("revision {rev_id} is not in the store")),
        }
    }
    if !target.join(MEMORY_RANGES).is_file() {
        return Err(format!(
            "revision {rev_id} is metadata-only (its RAM was pruned) and cannot be resumed"
        ));
    }

    // Archive the current HEAD so the rollback is non-destructive.
    if let Ok(head) = read_revision(snapshot_dir) {
        archive_head(snapshot_dir, &head.id);
    } else {
        clear_checkpoint(snapshot_dir);
    }

    // Restore the target as a fresh HEAD descending from it (rollback as a new
    // revision, so the lineage stays append-only).
    let dir = checkpoint_dir(snapshot_dir);
    copy_tree(&target, &dir)?;
    // Restore the target revision's disk overlays too, so the rolled-back guest
    // resumes a consistent RAM+disk pair (#62); a no-op for pre-versioning
    // revisions, which keep the existing live overlay.
    restore_overlays(&target, snapshot_dir)?;
    let mut rev = read_revision_manifest(&dir)?;
    let created_at_ms = now_ms();
    rev.parent = Some(rev.id.clone());
    rev.id = mint_revision_id(created_at_ms);
    rev.created_at_ms = created_at_ms;
    rev.origin = "rollback".to_string();
    let json = serde_json::to_string(&rev).map_err(|e| format!("serialize revision: {e}"))?;
    fs::write(dir.join(MANIFEST), json.as_bytes())
        .map_err(|e| format!("write rolled-back manifest: {e}"))?;
    prune_revisions(snapshot_dir);
    Ok(())
}

/// Chunk granularity for delta dumps. A trade between how precisely a change is
/// localised and how many syscalls finding it costs: measured on a real guest,
/// 4 KiB would write 1.2 MiB and 1 MiB would write 136 MiB, for the same 309
/// changed pages. 64 KiB lands at 13 MiB — within an order of magnitude of the
/// floor while keeping the scan a few thousand comparisons rather than a
/// few hundred thousand.
const DELTA_CHUNK: usize = 64 * 1024;

/// Dump every guest-RAM region to `path` at the parent snapshot's `file_offset`s
/// (so the resume maps it with the parent's unchanged region table). Streamed in
/// chunks to bound peak host memory regardless of guest RAM size.
///
/// Given `parent_dump`, writes a *delta*: the parent's image is cloned and only
/// the chunks that actually changed are overwritten. Two checkpoints seconds
/// apart share almost all of their RAM — measured at **99.9% identical** on a
/// real 2 GiB guest, 309 changed pages out of 524288 — so a full rewrite spends
/// the guest's freeze, and a full guest's worth of disk, reproducing bytes that
/// are already on disk.
///
/// The result is byte-for-byte what a full dump would have produced. That is the
/// only thing that makes this safe: a delta that is merely *nearly* right
/// restores a guest whose RAM disagrees with itself.
///
/// On APFS the clone is a copy-on-write reflink, so the unwritten majority costs
/// no new blocks and the parent may still be pruned independently — clones are
/// separate inodes sharing extents, not hard links.
fn dump_guest_ram(
    path: &Path,
    guest_mem: &GuestMemory,
    mem_mappings: &[MemMapping],
    parent_dump: Option<&Path>,
) -> Result<Option<u64>, String> {
    if let Some(parent) = parent_dump {
        match dump_guest_ram_delta(path, guest_mem, mem_mappings, parent) {
            Ok(shared) => return Ok(Some(shared)),
            Err(e) => {
                // A delta is an optimisation, never a requirement. Anything
                // unexpected about the parent — wrong size, unreadable, a
                // filesystem without clone support — falls back to the full
                // write rather than failing the checkpoint.
                let _ = fs::remove_file(path);
                eprintln!("chm: note: full RAM dump ({e})");
            }
        }
    }
    let mut file = fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    for m in mem_mappings {
        file.seek(SeekFrom::Start(m.file_offset))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let mut gpa = m.gpa;
        let mut remaining = m.size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len() as u64) as usize;
            guest_mem
                .read(gpa, &mut buf[..chunk])
                .map_err(|e| format!("read guest RAM @ {gpa:#x}: {e}"))?;
            file.write_all(&buf[..chunk])
                .map_err(|e| format!("write {}: {e}", path.display()))?;
            gpa += chunk as u64;
            remaining -= chunk as u64;
        }
    }
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    Ok(None)
}

/// Clone the parent dump and overwrite only the chunks whose contents differ.
///
/// Returns how many bytes were left untouched from the clone -- the real
/// saving, and the only place on this system that can know it.
///
/// Errors mean "could not take the shortcut", never "the checkpoint failed";
/// the caller falls back to a full dump.
fn dump_guest_ram_delta(
    path: &Path,
    guest_mem: &GuestMemory,
    mem_mappings: &[MemMapping],
    parent: &Path,
) -> Result<u64, String> {
    // Every region must land inside the cloned image, or an unwritten tail would
    // silently keep the parent's bytes there. Checking up front is what lets the
    // loop below trust its own seeks.
    let needed = mem_mappings
        .iter()
        .map(|m| m.file_offset + m.size)
        .max()
        .unwrap_or(0);
    let parent_len = fs::metadata(parent)
        .map_err(|e| format!("stat parent dump: {e}"))?
        .len();
    if parent_len != needed {
        return Err(format!(
            "parent dump is {parent_len} bytes, this guest needs {needed}"
        ));
    }

    fs::copy(parent, path).map_err(|e| format!("clone parent dump: {e}"))?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut live = vec![0u8; DELTA_CHUNK];
    let mut prev = vec![0u8; DELTA_CHUNK];
    let mut written = 0u64;
    for m in mem_mappings {
        let mut gpa = m.gpa;
        let mut offset = m.file_offset;
        let mut remaining = m.size;
        while remaining > 0 {
            let n = remaining.min(DELTA_CHUNK as u64) as usize;
            guest_mem
                .read(gpa, &mut live[..n])
                .map_err(|e| format!("read guest RAM @ {gpa:#x}: {e}"))?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| format!("seek {}: {e}", path.display()))?;
            file.read_exact(&mut prev[..n])
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            if prev[..n] != live[..n] {
                file.seek(SeekFrom::Start(offset))
                    .map_err(|e| format!("seek {}: {e}", path.display()))?;
                file.write_all(&live[..n])
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                written += n as u64;
            }
            gpa += n as u64;
            offset += n as u64;
            remaining -= n as u64;
        }
    }
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    Ok(parent_len.saturating_sub(written))
}

/// Capture the snapshot's live disk overlays into a revision dir (`<rev>/overlays`)
/// so the revision pins the disk state that matches its RAM dump. A no-op when the
/// snapshot has no overlays (a cold image never written to). Called at suspend,
/// when the guest is stopped and the overlays are quiescent.
fn snapshot_overlays(snapshot_dir: &Path, rev_dir: &Path) -> Result<(), String> {
    let live = snapshot_dir.join(LIVE_OVERLAYS_DIR);
    if !live.is_dir() {
        return Ok(());
    }
    copy_tree(&live, &rev_dir.join(OVERLAYS_SUBDIR))
}

/// A cheap identity for the live disk overlays: every file's name, length and
/// modification time, sorted so the result is stable across directory-read
/// order. Empty string when there are no overlays.
///
/// Deliberately not a content hash. The overlays are multi-gigabyte, this runs
/// on the resume path, and the question being asked is only "is this the same
/// overlay the checkpoint was taken against", which a length/mtime pair answers
/// for every way the overlay actually changes (a guest writing through it).
fn overlay_fingerprint(snapshot_dir: &Path) -> String {
    let live = snapshot_dir.join(LIVE_OVERLAYS_DIR);
    let Ok(entries) = fs::read_dir(&live) else {
        return String::new();
    };
    let mut lines: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            Some(format!(
                "{}:{}:{mtime}",
                e.file_name().to_string_lossy(),
                meta.len()
            ))
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

/// Whether the live disk overlays have moved on since this checkpoint's RAM was
/// captured — i.e. whether resuming would pair a guest's remembered filesystem
/// with a different one on disk.
///
/// **This is a correctness guard, not a tidiness check.** Guest RAM holds the
/// kernel's page cache, inode cache and journal head for the filesystem it had
/// mounted. Resume restores that RAM but reattaches whatever the overlay
/// contains *now*, so a session that wrote to disk and then exited **without**
/// `--checkpoint` leaves the next resume describing blocks that have since
/// moved. Measured consequence: the guest comes up, serves RAM-only work
/// normally, and then wedges — `rcu_preempt kthread timer wakeup didn't happen
/// for 60006 jiffies`, no further output — the first time anything touches the
/// diverged part of the tree. Worse, it is self-perpetuating: capturing at
/// teardown then writes the *hung* kernel over the last good checkpoint, so
/// every later resume starts wedged.
///
/// `None` (no drift reported) when the checkpoint predates this guard or
/// captured no overlays, so older checkpoints still resume.
pub(crate) fn overlay_drift(snapshot_dir: &Path) -> Option<OverlayDrift> {
    let recorded =
        fs::read_to_string(checkpoint_dir(snapshot_dir).join(OVERLAY_FINGERPRINT)).ok()?;
    let live = overlay_fingerprint(snapshot_dir);
    if recorded == live {
        return None;
    }
    Some(OverlayDrift {
        recorded_files: recorded.lines().count(),
        live_files: live.lines().count(),
    })
}

/// The result of an [`overlay_drift`] check that found a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OverlayDrift {
    /// How many overlay files the checkpoint was taken against.
    pub(crate) recorded_files: usize,
    /// How many are present now.
    pub(crate) live_files: usize,
}

/// Restore a revision's captured overlays back to the snapshot's live overlay
/// dir, so a rolled-back guest resumes the disk state that matches the restored
/// RAM. Replaces the live overlays wholesale. A no-op when the revision predates
/// overlay versioning (no `overlays/` captured) so older revisions still resume
/// with their existing on-disk overlay rather than erroring.
fn restore_overlays(rev_dir: &Path, snapshot_dir: &Path) -> Result<(), String> {
    let captured = rev_dir.join(OVERLAYS_SUBDIR);
    if !captured.is_dir() {
        return Ok(());
    }
    let live = snapshot_dir.join(LIVE_OVERLAYS_DIR);
    let _ = fs::remove_dir_all(&live);
    copy_tree(&captured, &live)
}

/// Fork a snapshot's current revision into a new snapshot directory.
///
/// The new directory is an independent fork point that descends from the
/// source's current revision (the branch in the lineage DAG). It **references**
/// the source's immutable base read-only (the `state.json`, base RAM and base
/// disks are symlinked, so a large base is not copied) and **copies** the
/// mutable state — the checkpoint (the live RAM + hardware state to resume from)
/// and the disk overlays — so the fork diverges from the parent without
/// disturbing it. The copied revision is re-parented (`parent` = the source
/// revision id, a fresh id, `origin = "fork"`).
///
/// `chm resume <dst>` then runs the fork; the source and the fork now have
/// independent state, both descended from the same revision.
pub(crate) fn fork_into(src_dir: &Path, dst_dir: &Path) -> Result<(), String> {
    if !has_checkpoint(src_dir) {
        return Err(format!(
            "{} has no saved revision to fork (run and suspend it first)",
            src_dir.display()
        ));
    }
    if dst_dir.exists() {
        return Err(format!("destination {} already exists", dst_dir.display()));
    }
    fs::create_dir_all(dst_dir).map_err(|e| format!("create {}: {e}", dst_dir.display()))?;

    // Reference the immutable base read-only (symlinks avoid copying a large
    // base RAM image / disks; the base is never written, so sharing is safe).
    symlink_base(src_dir, dst_dir)?;

    // Copy the mutable state the fork diverges from. The checkpoint's big RAM
    // dump is write-once (never mutated in place — a new suspend stages+renames a
    // fresh file), so it is hard-linked to share the base RAM read-only until the
    // fork diverges (copy-on-write at the file level). Disk overlays *are* written
    // in place during a run, so they must be copied so the fork's disk diverges.
    clone_checkpoint(&checkpoint_dir(src_dir), &checkpoint_dir(dst_dir))?;
    let overlays = src_dir.join(".chm-overlays");
    if overlays.is_dir() {
        copy_tree(&overlays, &dst_dir.join(".chm-overlays"))?;
    }

    // Re-parent the forked revision: it descends from the source's revision.
    let mut rev = read_revision(dst_dir)?;
    let created_at_ms = now_ms();
    rev.parent = Some(rev.id.clone());
    rev.id = mint_revision_id(created_at_ms);
    rev.created_at_ms = created_at_ms;
    rev.origin = "fork".to_string();
    rev.base_image = dst_dir
        .file_name()
        .map_or_else(
            || dst_dir.display().to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
    let json = serde_json::to_string(&rev).map_err(|e| format!("serialize revision: {e}"))?;
    fs::write(checkpoint_dir(dst_dir).join(MANIFEST), json.as_bytes())
        .map_err(|e| format!("write forked manifest: {e}"))?;
    Ok(())
}

/// Create an isolated per-sandbox workspace that references an image's read-only
/// base (`state.json`, `snapshot/`, `disks/` are symlinked) but keeps its own
/// mutable state — disk overlays and the checkpoint/revision store live under
/// `ws_dir`, not the shared image. So N sandboxes launched from the same image
/// diverge independently instead of clobbering each other's disk + checkpoints.
///
/// If the image ships a **golden checkpoint** (a `.chm-checkpoint` captured at a
/// settled, quiescent point — e.g. a fully booted idle login), the workspace is
/// seeded from it: the RAM dump is shared read-only (hard-linked, copy-on-write)
/// and the matching disk overlays are copied so RAM and disk stay consistent.
/// `chm connect <ws_dir> --checkpoint` then RESUMES that settled state instead
/// of cold-booting. This lets an image avoid replaying a fragile boot phase
/// (e.g. cloud-init's `serial-getty` restart) on every new sandbox. When the
/// image has no golden checkpoint the workspace starts cold from the base
/// (`chm run <ws_dir>` cold-boots; a later suspend saves a checkpoint inside the
/// workspace).
pub(crate) fn workspace_from_image(image_dir: &Path, ws_dir: &Path) -> Result<(), String> {
    if ws_dir.exists() {
        return Err(format!("workspace {} already exists", ws_dir.display()));
    }
    fs::create_dir_all(ws_dir).map_err(|e| format!("create {}: {e}", ws_dir.display()))?;
    symlink_base(image_dir, ws_dir)?;

    // Seed a golden checkpoint + its matching disk overlays if the image ships
    // one, so the new sandbox resumes the settled state rather than cold-booting.
    if has_checkpoint(image_dir) {
        clone_checkpoint(&checkpoint_dir(image_dir), &checkpoint_dir(ws_dir))?;
        let overlays = image_dir.join(".chm-overlays");
        if overlays.is_dir() {
            copy_tree(&overlays, &ws_dir.join(".chm-overlays"))?;
        }
    }
    Ok(())
}

/// Symlink an image's immutable base (`state.json`, `snapshot/`, `disks/`) into a
/// destination dir so it is shared read-only rather than copied.
fn symlink_base(image_dir: &Path, dst_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    for item in ["state.json", "snapshot", "disks"] {
        let from = image_dir.join(item);
        if from.exists() {
            let from_abs = from
                .canonicalize()
                .map_err(|e| format!("resolve {}: {e}", from.display()))?;
            symlink(&from_abs, dst_dir.join(item))
                .map_err(|e| format!("link {item} into the workspace: {e}"))?;
        }
    }
    Ok(())
}

/// Clone a checkpoint dir for a fork: hard-link the write-once RAM dump (shared
/// read-only until the fork diverges to a fresh checkpoint) and copy the small
/// manifest (it is rewritten by re-parenting, so it must be private). The
/// captured `overlays/` subdir is copied as a tree. Falls back to a copy if
/// hard-linking fails (e.g. across filesystems).
fn clone_checkpoint(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| format!("create {}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", from.display()))?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            // The captured disk overlays (a directory) copy as a tree.
            copy_tree(&src, &dst)?;
        } else if entry.file_name() == MEMORY_RANGES {
            fs::hard_link(&src, &dst)
                .or_else(|_| fs::copy(&src, &dst).map(|_| ()))
                .map_err(|e| format!("share {} -> {}: {e}", src.display(), dst.display()))?;
        } else {
            fs::copy(&src, &dst)
                .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

/// Recursively copy a directory tree (files + subdirectories).
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| format!("create {}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", from.display()))?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| format!("stat {}: {e}", src.display()))?;
        if ft.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            fs::copy(&src, &dst)
                .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn checkpoint_paths_are_under_the_snapshot_dir() {
        let dir = Path::new("/snap");
        assert_eq!(checkpoint_dir(dir), Path::new("/snap/.chm-checkpoint"));
        assert_eq!(
            memory_ranges_path(dir),
            Path::new("/snap/.chm-checkpoint/memory-ranges")
        );
    }

    #[test]
    fn has_checkpoint_is_false_without_files() {
        let tmp = env::temp_dir().join(format!("chm-ckpt-test-{}", process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        assert!(!has_checkpoint(&tmp));
        clear_checkpoint(&tmp);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn revision_manifest_carries_lineage_through_json() {
        use hypervisor::hvf::checkpoint::CheckpointState;
        let rev = Revision {
            manifest_version: REVISION_MANIFEST_VERSION,
            id: "rev-0000000000001-abcd".into(),
            parent: Some("rev-0000000000000-abcd".into()),
            base_image: "ubuntu-24.04".into(),
            created_at_ms: 1,
            origin: "daemon".into(),
            label: Some("after apt install".into()),
            state: CheckpointState::default(),
        };
        let json = serde_json::to_string(&rev).unwrap();
        let back: Revision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "rev-0000000000001-abcd");
        assert_eq!(back.parent.as_deref(), Some("rev-0000000000000-abcd"));
        assert_eq!(back.base_image, "ubuntu-24.04");
        assert_eq!(back.origin, "daemon");
        assert_eq!(back.label.as_deref(), Some("after apt install"));
    }

    #[test]
    fn revision_ids_sort_by_creation_time() {
        // Zero-padded millis keep ids lexicographically ordered by time, so a
        // lineage view can sort revisions by id.
        assert!(mint_revision_id(1) < mint_revision_id(2));
        assert!(mint_revision_id(999) < mint_revision_id(1000));
    }

    #[test]
    fn fork_branches_a_revision_and_reparents_it() {
        use hypervisor::hvf::checkpoint::{CHECKPOINT_VERSION, CheckpointState};

        let valid_state = CheckpointState {
            version: CHECKPOINT_VERSION,
            ..Default::default()
        };

        let root = env::temp_dir().join(format!("chm-fork-test-{}-{}", process::id(), now_ms()));
        let src = root.join("src");
        let dst = root.join("dst");
        let _ = fs::remove_dir_all(&root);

        // A minimal source snapshot with a base + a checkpoint + an overlay.
        fs::create_dir_all(src.join("snapshot")).unwrap();
        fs::create_dir_all(src.join("disks")).unwrap();
        fs::write(src.join("state.json"), b"{}").unwrap();
        fs::write(src.join("snapshot/memory-ranges"), b"base-ram").unwrap();
        fs::create_dir_all(src.join(".chm-overlays")).unwrap();
        fs::write(src.join(".chm-overlays/d-cow.raw"), b"overlay-bytes").unwrap();

        let ckpt = checkpoint_dir(&src);
        fs::create_dir_all(&ckpt).unwrap();
        fs::write(ckpt.join(MEMORY_RANGES), b"live-ram").unwrap();
        let parent_rev = Revision {
            manifest_version: REVISION_MANIFEST_VERSION,
            id: "rev-0000000000001-aaaa".into(),
            parent: None,
            base_image: "src".into(),
            created_at_ms: 1,
            origin: "connect".into(),
            label: None,
            state: valid_state,
        };
        fs::write(ckpt.join(MANIFEST), serde_json::to_string(&parent_rev).unwrap()).unwrap();

        fork_into(&src, &dst).expect("fork");

        // The fork copied the mutable state and re-parented the revision.
        let forked = read_revision(&dst).expect("read fork revision");
        assert_eq!(forked.parent.as_deref(), Some("rev-0000000000001-aaaa"));
        assert_ne!(forked.id, "rev-0000000000001-aaaa");
        assert_eq!(forked.origin, "fork");
        assert_eq!(
            fs::read(memory_ranges_path(&dst)).unwrap(),
            b"live-ram",
            "the fork sees the live RAM to diverge from"
        );
        // The RAM dump is *shared* read-only (hard-linked), not copied — file-
        // level CoW until the fork's next suspend writes a fresh checkpoint.
        {
            use std::os::unix::fs::MetadataExt;
            let src_ino = fs::metadata(memory_ranges_path(&src)).unwrap().ino();
            let dst_ino = fs::metadata(memory_ranges_path(&dst)).unwrap().ino();
            assert_eq!(src_ino, dst_ino, "fork shares the base RAM via a hard link");
        }
        assert_eq!(
            fs::read(dst.join(".chm-overlays/d-cow.raw")).unwrap(),
            b"overlay-bytes",
            "the fork copies the disk overlay delta"
        );
        // The base is referenced (symlinked), not copied.
        assert!(
            fs::symlink_metadata(dst.join("snapshot"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the immutable base is shared via a symlink, not copied"
        );
        // Forking a dir with no checkpoint is refused.
        assert!(fork_into(&root.join("nope"), &root.join("nope2")).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    /// Build a GuestMemory over two non-adjacent regions, mirroring a real
    /// guest's split RAM, and return it with the backing store the caller must
    /// keep alive.
    fn test_guest_mem(sizes: &[(u64, usize)]) -> (GuestMemory, Vec<Vec<u8>>) {
        let gm = GuestMemory::new();
        let mut owned = Vec::new();
        for (gpa, size) in sizes {
            let mut buf = vec![0u8; *size];
            // SAFETY: `buf` is moved into `owned`, which the caller keeps alive
            // for as long as `gm` is used, and is never aliased by a Rust
            // reference afterwards -- all access goes through `gm`.
            unsafe { gm.register(*gpa, buf.as_mut_ptr(), *size) };
            owned.push(buf);
        }
        (gm, owned)
    }

    /// The property the whole delta optimisation rests on: what it writes must
    /// be indistinguishable from a full dump. A delta that is merely *nearly*
    /// right restores a guest whose RAM disagrees with itself, which is worse
    /// than no checkpoint at all -- and it would not be noticed until a rollback
    /// months later.
    #[test]
    fn a_delta_dump_is_byte_identical_to_a_full_one() {
        let root = std::env::temp_dir().join(format!("chm-delta-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        // Two regions, the second at a file offset the first does not reach --
        // the layout a real snapshot's region table produces.
        const A: u64 = 0x4000_0000;
        const B: u64 = 0x8000_0000;
        const SZ: usize = 4 * DELTA_CHUNK;
        let (gm, _own) = test_guest_mem(&[(A, SZ), (B, SZ)]);
        let maps = vec![
            MemMapping { slot: 0, gpa: A, size: SZ as u64, file_offset: 0 },
            MemMapping { slot: 1, gpa: B, size: SZ as u64, file_offset: SZ as u64 },
        ];

        // A parent image with recognisable content in every chunk.
        for (i, base) in [A, B].iter().enumerate() {
            let fill: Vec<u8> = (0..SZ).map(|n| (n / 7 + i * 3) as u8).collect();
            gm.write(*base, &fill).unwrap();
        }
        let parent = root.join("parent");
        dump_guest_ram(&parent, &gm, &maps, None).unwrap();

        // Change the guest in the places most likely to be missed: the very
        // first byte, the very last byte, and a chunk boundary in each region.
        gm.write(A, b"\xff").unwrap();
        gm.write(A + DELTA_CHUNK as u64 - 1, b"\xfe").unwrap();
        gm.write(B + DELTA_CHUNK as u64, b"\xfd").unwrap();
        gm.write(B + SZ as u64 - 1, b"\xfc").unwrap();

        let full = root.join("full");
        dump_guest_ram(&full, &gm, &maps, None).unwrap();
        let delta = root.join("delta");
        dump_guest_ram(&delta, &gm, &maps, Some(&parent)).unwrap();

        let want = fs::read(&full).unwrap();
        let got = fs::read(&delta).unwrap();
        assert_eq!(want.len(), got.len(), "a delta must not change the image size");
        assert!(
            want == got,
            "delta differs from a full dump at byte {:?}",
            want.iter().zip(&got).position(|(x, y)| x != y)
        );

        // A parent that does not describe this guest is refused rather than
        // used, and the caller falls back to a full dump.
        let short = root.join("short");
        fs::write(&short, b"too small").unwrap();
        assert!(dump_guest_ram_delta(&root.join("out"), &gm, &maps, &short).is_err());
        // ...and going through dump_guest_ram, that fallback still produces the
        // correct image rather than propagating the error.
        let recovered = root.join("recovered");
        dump_guest_ram(&recovered, &gm, &maps, Some(&short)).unwrap();
        assert!(
            fs::read(&recovered).unwrap() == want,
            "the fallback must be correct, not just quiet"
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// A run that ends badly must not throw away a point the cadence took while
    /// the guest was healthy -- that failure is the whole reason #148 exists.
    #[test]
    fn retiring_a_head_files_it_in_the_lineage_instead_of_deleting_it() {
        let root = std::env::temp_dir().join(format!("chm-retire-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        write_test_checkpoint(&root, b"first", "connect-auto");
        write_test_checkpoint(&root, b"second!", "connect-auto");
        let head = read_revision(&root).unwrap().id;

        let retired = retire_checkpoint(&root).expect("HEAD exists, so it is filed");
        assert_eq!(retired, head, "reports the id a reader can roll back to");
        assert!(
            read_revision(&root).is_err(),
            "no HEAD is left for the next start to resume blindly"
        );

        let ids: Vec<_> = list_revisions(&root)
            .into_iter()
            .map(|r| r.revision.id)
            .collect();
        assert!(ids.contains(&head), "the retired point is still reachable: {ids:?}");
        let filed = list_revisions(&root)
            .into_iter()
            .find(|r| r.revision.id == head)
            .unwrap();
        assert!(
            filed.resumable,
            "filed with its RAM, or `chm rollback` could not honour the advice"
        );

        // With nothing to retire the call is a no-op rather than an error, so a
        // caller need not know whether a checkpoint was ever written.
        assert_eq!(retire_checkpoint(&root), None);

        let _ = fs::remove_dir_all(&root);
    }

    /// Write a checkpoint with a given RAM marker + origin into `snapshot_dir`.
    fn write_test_checkpoint(snapshot_dir: &Path, ram: &[u8], origin: &str) {
        use hypervisor::hvf::checkpoint::{CHECKPOINT_VERSION, CheckpointState};
        // Mirror write_checkpoint's archive-then-swap, without a live GuestMemory:
        // archive the current HEAD, then stage a fresh HEAD directly.
        let parent = read_revision(snapshot_dir).ok().map(|r| r.id);
        match &parent {
            Some(id) => archive_head(snapshot_dir, id),
            None => clear_checkpoint(snapshot_dir),
        }
        let dir = checkpoint_dir(snapshot_dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(MEMORY_RANGES), ram).unwrap();
        // Mirror write_checkpoint: capture the live disk overlays into the
        // revision so rollback restores a consistent RAM+disk pair.
        snapshot_overlays(snapshot_dir, &dir).unwrap();
        let created_at_ms = now_ms() + ram.len() as u64; // keep ids ordered in-test
        let rev = Revision {
            manifest_version: REVISION_MANIFEST_VERSION,
            id: mint_revision_id(created_at_ms),
            parent,
            base_image: "snap".into(),
            created_at_ms,
            origin: origin.into(),
            label: None,
            state: CheckpointState {
                version: CHECKPOINT_VERSION,
                ..Default::default()
            },
        };
        fs::write(dir.join(MANIFEST), serde_json::to_string(&rev).unwrap()).unwrap();
        fs::write(
            dir.join(OVERLAY_FINGERPRINT),
            overlay_fingerprint(snapshot_dir),
        )
        .unwrap();
        prune_revisions(snapshot_dir);
    }

    /// `chm revisions` lists HEAD, so `chm rollback` must accept it. It did not:
    /// HEAD lives in the checkpoint dir rather than the archive, so the lookup
    /// rejected an id we had just printed — which made the overlay-drift guard's
    /// recovery advice non-actionable, since rolling back to HEAD is exactly how
    /// you restore the overlays captured with that RAM.
    #[test]
    fn rollback_accepts_the_head_revision_that_revisions_lists() {
        let snap = env::temp_dir().join(format!("chm-rbhead-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(snap.join(LIVE_OVERLAYS_DIR)).unwrap();
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("disk0.raw"), b"aaaa").unwrap();

        write_test_checkpoint(&snap, b"ram-one", "connect");
        let head = read_revision(&snap).unwrap().id;

        // It is the id `chm revisions` reports as HEAD.
        let listed = list_revisions(&snap);
        assert!(
            listed.iter().any(|r| r.is_head && r.revision.id == head),
            "HEAD should be listed"
        );

        // The disk then moves on, which is the drift the guard refuses.
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("disk0.raw"), b"bbbbbbbb").unwrap();
        assert!(overlay_drift(&snap).is_some(), "drift should be detected");

        rollback(&snap, &head).expect("rollback to HEAD must be accepted");

        // And it is a real recovery: the overlays captured with that RAM are back,
        // so the pair is consistent again.
        assert_eq!(
            fs::read(snap.join(LIVE_OVERLAYS_DIR).join("disk0.raw")).unwrap(),
            b"aaaa",
            "rollback should restore the overlay captured with the RAM"
        );
        assert!(overlay_drift(&snap).is_none(), "drift should be cleared");

        // An id that genuinely is not in the store still fails.
        assert!(rollback(&snap, "rev-does-not-exist").is_err());

        let _ = fs::remove_dir_all(&snap);
    }

    /// A checkpoint taken against the overlays that are still there reports no
    /// drift, and one taken before the overlay moved on does.
    ///
    /// This is the guard against the failure that produced
    /// `rcu_preempt kthread timer wakeup didn't happen for 60006 jiffies` and a
    /// wedged guest: a session wrote ~200 MB to disk and exited without
    /// `--checkpoint`, so the next resume restored a kernel whose cached view of
    /// the filesystem no longer matched the blocks underneath it.
    #[test]
    fn overlay_drift_is_flagged_only_when_the_disk_moved_on() {
        let snap = env::temp_dir().join(format!("chm-drift-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(snap.join(LIVE_OVERLAYS_DIR)).unwrap();
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("d-cow.raw"), b"disk-v1").unwrap();

        write_test_checkpoint(&snap, b"ram-v1", "connect");
        assert_eq!(
            overlay_drift(&snap),
            None,
            "RAM and disk were captured together, so resuming them together is safe"
        );

        // A session that writes to disk and exits without checkpointing.
        fs::write(
            snap.join(LIVE_OVERLAYS_DIR).join("d-cow.raw"),
            b"disk-v2-is-longer",
        )
        .unwrap();
        let drift = overlay_drift(&snap).expect("the overlay moved on under the checkpoint");
        assert_eq!((drift.recorded_files, drift.live_files), (1, 1));

        // A brand-new file in the overlay dir counts too.
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("e-cow.raw"), b"another").unwrap();
        assert_eq!(overlay_drift(&snap).map(|d| d.live_files), Some(2));

        let _ = fs::remove_dir_all(&snap);
    }

    /// A checkpoint written before this guard existed carries no fingerprint, and
    /// must still resume rather than being refused for a question it cannot
    /// answer.
    #[test]
    fn overlay_drift_is_silent_for_a_checkpoint_that_predates_the_guard() {
        let snap = env::temp_dir().join(format!("chm-driftold-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(snap.join(LIVE_OVERLAYS_DIR)).unwrap();
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("d-cow.raw"), b"disk-v1").unwrap();
        write_test_checkpoint(&snap, b"ram-v1", "connect");

        fs::remove_file(checkpoint_dir(&snap).join(OVERLAY_FINGERPRINT)).unwrap();
        fs::write(snap.join(LIVE_OVERLAYS_DIR).join("d-cow.raw"), b"changed!").unwrap();

        assert_eq!(
            overlay_drift(&snap),
            None,
            "no recorded fingerprint means no claim either way, so do not block"
        );
        let _ = fs::remove_dir_all(&snap);
    }

    #[test]
    fn revision_store_keeps_history_and_rolls_back() {
        let snap = env::temp_dir().join(format!("chm-revstore-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();

        // Two suspends: the first becomes an archived revision, the second HEAD.
        write_test_checkpoint(&snap, b"ram-v1", "connect");
        let v1 = read_revision(&snap).unwrap().id;
        write_test_checkpoint(&snap, b"ram-v2", "connect");

        let revs = revision_summaries(&snap);
        assert_eq!(revs.len(), 2, "history is preserved, not overwritten");
        assert!(revs[0].created_at_ms <= revs[1].created_at_ms, "oldest-first");
        assert!(revs.iter().any(|r| r.id == v1 && !r.is_head && r.resumable));
        assert!(revs.iter().filter(|r| r.is_head).count() == 1);
        // HEAD is currently ram-v2.
        assert_eq!(fs::read(memory_ranges_path(&snap)).unwrap(), b"ram-v2");

        // Roll back to v1: appended as a fresh HEAD descending from v1.
        rollback(&snap, &v1).unwrap();
        assert_eq!(
            fs::read(memory_ranges_path(&snap)).unwrap(),
            b"ram-v1",
            "rollback restores the target's live RAM"
        );
        let head = read_revision(&snap).unwrap();
        assert_eq!(head.origin, "rollback");
        assert_eq!(head.parent.as_deref(), Some(v1.as_str()));

        // Rolling back to an unknown revision is refused.
        rollback(&snap, "rev-nope").unwrap_err();

        let _ = fs::remove_dir_all(&snap);
    }

    #[test]
    fn rollback_restores_the_disk_overlay_not_just_ram() {
        // A revision is a consistent RAM+disk pair: rolling back must revert the
        // disk overlay too, not leave a later revision's disk writes in place
        // (#62). Without overlay versioning a file written to the persistent disk
        // survived rollback, and RAM-vs-disk skew risked fs corruption on resume.
        let snap = env::temp_dir().join(format!("chm-ovl-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();
        let live = snap.join(LIVE_OVERLAYS_DIR);
        fs::create_dir_all(&live).unwrap();

        // Revision 1: the disk overlay holds v1.
        fs::write(live.join("disk0-cow.raw"), b"disk-v1").unwrap();
        write_test_checkpoint(&snap, b"ram-v1", "connect");
        let v1 = read_revision(&snap).unwrap().id;

        // Revision 2: the guest wrote more to the persistent disk (overlay v2).
        fs::write(live.join("disk0-cow.raw"), b"disk-v2-with-new-file").unwrap();
        write_test_checkpoint(&snap, b"ram-v2", "connect");
        assert_eq!(fs::read(live.join("disk0-cow.raw")).unwrap(), b"disk-v2-with-new-file");

        // Roll back to v1: both RAM and the disk overlay revert to v1.
        rollback(&snap, &v1).unwrap();
        assert_eq!(fs::read(memory_ranges_path(&snap)).unwrap(), b"ram-v1");
        assert_eq!(
            fs::read(snap.join(LIVE_OVERLAYS_DIR).join("disk0-cow.raw")).unwrap(),
            b"disk-v1",
            "rollback must restore the revision's disk overlay, removing v2's writes"
        );

        let _ = fs::remove_dir_all(&snap);
    }

    #[test]
    fn workspace_shares_base_readonly_and_isolates_mutable_state() {
        let root = env::temp_dir().join(format!("chm-ws-test-{}-{}", process::id(), now_ms()));
        let image = root.join("image");
        let ws = root.join("ws");
        let _ = fs::remove_dir_all(&root);

        // A minimal cold image (base only, no checkpoint).
        fs::create_dir_all(image.join("snapshot")).unwrap();
        fs::create_dir_all(image.join("disks")).unwrap();
        fs::write(image.join("state.json"), b"{}").unwrap();
        fs::write(image.join("snapshot/memory-ranges"), b"base-ram").unwrap();

        workspace_from_image(&image, &ws).expect("create workspace");

        // The base is symlinked (shared read-only), not copied.
        for item in ["state.json", "snapshot", "disks"] {
            assert!(
                fs::symlink_metadata(ws.join(item)).unwrap().file_type().is_symlink(),
                "{item} should be a symlink to the image"
            );
        }
        // The base is reachable through the workspace, and it starts cold.
        assert_eq!(fs::read(ws.join("snapshot/memory-ranges")).unwrap(), b"base-ram");
        assert!(!has_checkpoint(&ws));
        // Re-creating over an existing workspace is refused.
        workspace_from_image(&image, &ws).unwrap_err();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn workspace_seeds_golden_checkpoint_and_overlays_from_image() {
        let root = env::temp_dir().join(format!("chm-gold-{}-{}", process::id(), now_ms()));
        let image = root.join("image");
        let ws = root.join("ws");
        let _ = fs::remove_dir_all(&root);

        // An image that ships a golden checkpoint (settled boot) + disk overlays.
        fs::create_dir_all(image.join("snapshot")).unwrap();
        fs::create_dir_all(image.join("disks")).unwrap();
        fs::write(image.join("state.json"), b"{}").unwrap();
        fs::write(image.join("snapshot/memory-ranges"), b"base-ram").unwrap();
        write_test_checkpoint(&image, b"golden-ram", "connect");
        fs::create_dir_all(image.join(".chm-overlays")).unwrap();
        fs::write(image.join(".chm-overlays/disk0-cow.raw"), b"cloud-init-writes").unwrap();

        workspace_from_image(&image, &ws).expect("create workspace");

        // The workspace resumes the golden checkpoint (not a cold boot) with its
        // matching disk overlays, so RAM and disk stay consistent.
        assert!(has_checkpoint(&ws), "workspace should be seeded resumable");
        assert_eq!(
            fs::read(checkpoint_dir(&ws).join(MEMORY_RANGES)).unwrap(),
            b"golden-ram"
        );
        assert_eq!(
            fs::read(ws.join(".chm-overlays/disk0-cow.raw")).unwrap(),
            b"cloud-init-writes"
        );
        // Overlays are copied (private), not shared, so sandboxes diverge.
        fs::write(ws.join(".chm-overlays/disk0-cow.raw"), b"diverged").unwrap();
        assert_eq!(
            fs::read(image.join(".chm-overlays/disk0-cow.raw")).unwrap(),
            b"cloud-init-writes",
            "image overlay must be untouched by a workspace write"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_keeps_only_the_newest_ram_dumps() {
        let snap = env::temp_dir().join(format!("chm-prune-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();

        for i in 0..4u8 {
            write_test_checkpoint(&snap, &[b'r', b'0' + i], "connect");
        }
        // Bound resumable revisions to 2 (HEAD + one archived).
        prune_revisions_keeping(&snap, 2);
        let revs = revision_summaries(&snap);
        // All 4 revisions are still in the lineage (manifests kept)…
        assert_eq!(revs.len(), 4);
        // …but only the newest 2 keep their RAM.
        assert_eq!(revs.iter().filter(|r| r.resumable).count(), 2);
        assert!(revs.last().unwrap().is_head && revs.last().unwrap().resumable);

        let _ = fs::remove_dir_all(&snap);
    }

    /// The reason retention roots exist. Age-based pruning was the *only*
    /// policy, so a point an operator cared about was reclaimed simply by
    /// being old — and continuous checkpointing (V9.1) makes everything old
    /// fast. Same setup as the test above, one pin, opposite outcome.
    #[test]
    fn a_pinned_revision_survives_a_prune_that_would_have_reclaimed_it() {
        let snap = env::temp_dir().join(format!("chm-pin-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();

        for i in 0..4u8 {
            write_test_checkpoint(&snap, &[b'r', b'0' + i], "connect");
        }
        let all = revision_summaries(&snap);
        let oldest = all.first().unwrap().id.clone();
        assert!(!all.first().unwrap().pinned, "nothing is pinned by default");

        // Unpinned, this is exactly the revision `prune_keeps_only_the_newest`
        // drops first.
        assert!(
            pin_revision(&snap, &oldest, true).unwrap(),
            "pin changed state"
        );
        prune_revisions_keeping(&snap, 2);

        let revs = revision_summaries(&snap);
        let kept = revs.iter().find(|r| r.id == oldest).expect("still listed");
        assert!(kept.resumable, "a pinned revision must keep its RAM");
        assert!(kept.pinned);

        // And the pin is *exempt* from the budget rather than counted against
        // it: the newest two are still resumable, so pinning did not silently
        // shorten the window of recent history.
        assert_eq!(revs.iter().filter(|r| r.resumable).count(), 3);

        // Unpinning hands it back to age.
        assert!(pin_revision(&snap, &oldest, false).unwrap());
        prune_revisions_keeping(&snap, 2);
        let revs = revision_summaries(&snap);
        assert!(!revs.iter().find(|r| r.id == oldest).unwrap().resumable);

        let _ = fs::remove_dir_all(&snap);
    }

    /// Pinning is idempotent, and says so rather than reporting a change it did
    /// not make. A caller that cannot tell "pinned it" from "already pinned"
    /// cannot report honestly either.
    #[test]
    fn pinning_twice_reports_no_change_and_an_unknown_id_is_refused() {
        let snap = env::temp_dir().join(format!("chm-pin2-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();
        write_test_checkpoint(&snap, b"only", "connect");
        let id = revision_summaries(&snap).first().unwrap().id.clone();

        assert!(pin_revision(&snap, &id, true).unwrap());
        assert!(
            !pin_revision(&snap, &id, true).unwrap(),
            "second pin is a no-op"
        );

        // An unknown id must be refused, and the refusal must say where to look
        // — a bare "not found" makes the operator guess the id format.
        let err = pin_revision(&snap, "no-such-rev", true).expect_err("must refuse");
        assert!(err.contains("no-such-rev"), "{err}");
        assert!(err.contains("chm revisions"), "refusal must point somewhere: {err}");

        let _ = fs::remove_dir_all(&snap);
    }

    /// HEAD lives in the checkpoint dir, not the archive, so resolving only the
    /// archive would refuse an id `chm revisions` had just printed. `rollback`
    /// already had to learn this; pinning must not relearn it the hard way.
    #[test]
    fn the_live_head_can_be_pinned_by_the_id_that_was_printed() {
        let snap = env::temp_dir().join(format!("chm-pinhead-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();
        write_test_checkpoint(&snap, b"head", "connect");

        let head = revision_summaries(&snap)
            .into_iter()
            .find(|r| r.is_head)
            .expect("a HEAD");
        assert!(pin_revision(&snap, &head.id, true).unwrap());
        assert!(
            revision_summaries(&snap)
                .iter()
                .find(|r| r.is_head)
                .unwrap()
                .pinned
        );

        let _ = fs::remove_dir_all(&snap);
    }

    /// Usage must see through an APFS clone, not just a hard link.
    ///
    /// A cloned dump is a distinct inode sharing extents, so inode dedup misses
    /// it entirely and lengths report disk that does not exist. Measured on a
    /// real lineage before this landed: 110 GiB of parts over 41 MiB of disk,
    /// which would have had a user deleting history they never needed to.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_clone_is_not_counted_as_fresh_disk() {
        let dir = env::temp_dir().join(format!("chm-clone-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        const SIZE: usize = 4 << 20;
        let (gm, _owned) = test_guest_mem(&[(0x4000_0000, SIZE)]);
        gm.write(0x4000_0000, &vec![7u8; SIZE]).unwrap();
        let mappings = [MemMapping {
            slot: 0,
            gpa: 0x4000_0000,
            size: SIZE as u64,
            file_offset: 0,
        }];

        let parent = dir.join("parent");
        dump_guest_ram(&parent, &gm, &mappings, None).unwrap();
        let child = dir.join("child");
        dump_guest_ram(&child, &gm, &mappings, Some(&parent)).unwrap();

        let len = fs::metadata(&child).unwrap().len();
        let priv_child = private_bytes(&child, len);
        assert!(
            priv_child < len / 8,
            "an unmodified clone of {len} bytes must not read as {priv_child} of fresh disk"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// A fork hard-links its parent's write-once RAM dump, so summing per-
    /// revision sizes reports disk that does not exist. Both numbers are
    /// reported precisely so that gap is visible instead of being picked
    /// arbitrarily.
    #[test]
    fn usage_counts_a_shared_ram_dump_once_on_disk_and_twice_apparent() {
        let snap = env::temp_dir().join(format!("chm-usage-{}-{}", process::id(), now_ms()));
        let _ = fs::remove_dir_all(&snap);
        fs::create_dir_all(&snap).unwrap();
        write_test_checkpoint(&snap, &[b'x'; 4096], "connect");
        write_test_checkpoint(&snap, &[b'y'; 4096], "connect");

        // No `on_disk <= apparent` assertion here: the two are in different
        // units. `on_disk` is allocated bytes (block-rounded, so a 4 KiB file
        // and its manifest cost a block each) while `apparent` sums logical
        // lengths. They are comparable at snapshot scale, not at test scale.
        let before = snapshot_usage(&snap);

        // Hard-link one revision's RAM into another, exactly as `fork_into` does.
        let revs = revision_summaries(&snap);
        let src = revisions_dir(&snap).join(&revs[0].id).join(MEMORY_RANGES);
        let link = revisions_dir(&snap).join(&revs[0].id).join("linked-copy");
        fs::hard_link(&src, &link).unwrap();

        let after = snapshot_usage(&snap);
        assert_eq!(
            after.on_disk, before.on_disk,
            "a hard link consumes no additional bytes"
        );
        assert!(
            after.apparent > before.apparent,
            "the per-revision view counts it again: {} vs {}",
            after.apparent,
            before.apparent
        );

        // The invariant a real measurement caught us breaking: a deduplicating
        // count can never exceed the sum it deduplicates. It did, because live
        // overlays were folded into `on_disk` while belonging to no revision.
        // They are now reported separately, so the two views compare.
        fs::create_dir_all(snap.join(LIVE_OVERLAYS_DIR)).unwrap();
        fs::write(
            snap.join(LIVE_OVERLAYS_DIR).join("disk0-cow.raw"),
            [0u8; 8192],
        )
        .unwrap();
        let with_live = snapshot_usage(&snap);
        // The original guard here was `on_disk <= apparent`, which no longer
        // holds in general: `on_disk` became allocated bytes (block-rounded) so
        // it can exceed a sum of logical lengths for tiny files. The assertion
        // below is the direct form of what that one was really testing — live
        // overlays must not be folded into the revision figure — and it would
        // have caught the original bug just as surely.
        assert_eq!(with_live.live_overlays, 8192, "live overlays counted apart");
        assert_eq!(
            with_live.on_disk, after.on_disk,
            "live overlays must not inflate the revision figure"
        );

        let _ = fs::remove_dir_all(&snap);
    }
}
