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

use hypervisor::hvf::checkpoint::{CHECKPOINT_VERSION, CheckpointState};
use hypervisor::hvf::rehydrate::MemMapping;
use hypervisor::hvf::virtio::GuestMemory;

const CHECKPOINT_SUBDIR: &str = ".chm-checkpoint";
const MANIFEST: &str = "checkpoint.json";
const MEMORY_RANGES: &str = "memory-ranges";

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

/// Remove any checkpoint so the next start cold-boots from the parent snapshot.
pub(crate) fn clear_checkpoint(snapshot_dir: &Path) {
    let _ = fs::remove_dir_all(checkpoint_dir(snapshot_dir));
}

/// Read a checkpoint's hardware state, rejecting an incompatible version.
pub(crate) fn read_checkpoint(snapshot_dir: &Path) -> Result<CheckpointState, String> {
    let path = checkpoint_dir(snapshot_dir).join(MANIFEST);
    let body = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let state: CheckpointState =
        serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if state.version != CHECKPOINT_VERSION {
        return Err(format!(
            "checkpoint version {} is not the supported version {} \
             (delete {} to cold-boot)",
            state.version,
            CHECKPOINT_VERSION,
            checkpoint_dir(snapshot_dir).display()
        ));
    }
    Ok(state)
}

/// Write a checkpoint atomically: dump live guest RAM into the parent's
/// memory-region layout, then the small hardware-state manifest. The whole
/// checkpoint is staged in a sibling `.tmp` directory and renamed into place so a
/// crash mid-write never leaves a half-written checkpoint a resume would trust.
pub(crate) fn write_checkpoint(
    snapshot_dir: &Path,
    state: &CheckpointState,
    guest_mem: &GuestMemory,
    mem_mappings: &[MemMapping],
) -> Result<(), String> {
    let dir = checkpoint_dir(snapshot_dir);
    let mut tmp = dir.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;

    dump_guest_ram(&tmp.join(MEMORY_RANGES), guest_mem, mem_mappings)?;

    let json =
        serde_json::to_string(state).map_err(|e| format!("serialize checkpoint state: {e}"))?;
    fs::write(tmp.join(MANIFEST), json.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.join(MANIFEST).display()))?;

    // Swap the staged checkpoint into place.
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
}
