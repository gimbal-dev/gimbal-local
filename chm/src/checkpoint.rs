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
const MANIFEST: &str = "checkpoint.json";
const MEMORY_RANGES: &str = "memory-ranges";

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
    let path = checkpoint_dir(snapshot_dir).join(MANIFEST);
    let body = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let rev: Revision =
        serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if rev.state.version != CHECKPOINT_VERSION {
        return Err(format!(
            "checkpoint version {} is not the supported version {} \
             (delete {} to cold-boot)",
            rev.state.version,
            CHECKPOINT_VERSION,
            checkpoint_dir(snapshot_dir).display()
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

    // Swap the staged revision into place.
    let _ = fs::remove_dir_all(&dir);
    fs::rename(&tmp, &dir)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), dir.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, process};

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
}
