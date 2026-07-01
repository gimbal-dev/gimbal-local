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
//! ```
//!
//! Resume reuses the cold restore machinery, overriding only the runtime-mutable
//! state (vCPU registers, GIC interrupt state, guest RAM) with the captured live
//! values; the parent snapshot still supplies the memory-region layout and the
//! virtio/serial device wiring.

use std::env;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
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

    dump_guest_ram(&tmp.join(MEMORY_RANGES), guest_mem, mem_mappings)?;

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

fn max_resumable_revisions() -> usize {
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
                out.push(RevisionInfo { revision, resumable, is_head: false });
            }
        }
    }
    if let Ok(revision) = read_revision(snapshot_dir) {
        let resumable = memory_ranges_path(snapshot_dir).is_file();
        out.push(RevisionInfo { revision, resumable, is_head: true });
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
}

/// The snapshot's revisions as serializable summaries (oldest-first).
pub(crate) fn revision_summaries(snapshot_dir: &Path) -> Vec<RevisionSummary> {
    list_revisions(snapshot_dir)
        .into_iter()
        .map(|info| RevisionSummary {
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
    // The live HEAD counts as one resumable revision; keep that many archived.
    let keep = max_resumable.saturating_sub(1);
    if archived.len() <= keep {
        return;
    }
    archived.sort_by(|a, b| a.0.cmp(&b.0));
    let drop_count = archived.len() - keep;
    for (_, dir) in archived.into_iter().take(drop_count) {
        let _ = fs::remove_file(dir.join(MEMORY_RANGES));
    }
}

/// Roll a snapshot back to an archived revision: it becomes a new HEAD that
/// descends from the target (append-only — history is preserved, not rewound).
/// The target must still be resumable (its RAM dump retained).
pub(crate) fn rollback(snapshot_dir: &Path, rev_id: &str) -> Result<(), String> {
    let target = revisions_dir(snapshot_dir).join(rev_id);
    if !target.join(MANIFEST).is_file() {
        return Err(format!("revision {rev_id} is not in the store"));
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

/// Dump every guest-RAM region to `path` at the parent snapshot's `file_offset`s
/// (so the resume maps it with the parent's unchanged region table). Streamed in
/// chunks to bound peak host memory regardless of guest RAM size.
fn dump_guest_ram(
    path: &Path,
    guest_mem: &GuestMemory,
    mem_mappings: &[MemMapping],
) -> Result<(), String> {
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
    Ok(())
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
    use std::os::unix::fs::symlink;

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

    // Reference the immutable base read-only. Symlinks avoid copying a large
    // base RAM image / disks; the base is never written, so sharing is safe.
    for item in ["state.json", "snapshot", "disks"] {
        let from = src_dir.join(item);
        if from.exists() {
            let from_abs = from
                .canonicalize()
                .map_err(|e| format!("resolve {}: {e}", from.display()))?;
            symlink(&from_abs, dst_dir.join(item))
                .map_err(|e| format!("link {item} into the fork: {e}"))?;
        }
    }

    // Copy the mutable state the fork diverges from: the checkpoint (live RAM +
    // hardware state) and the disk overlays.
    copy_tree(&checkpoint_dir(src_dir), &checkpoint_dir(dst_dir))?;
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
            "the fork copies the live RAM to diverge from"
        );
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
        prune_revisions(snapshot_dir);
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
}
