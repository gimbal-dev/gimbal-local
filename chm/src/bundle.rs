// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Moving revisions between machines: `chm revisions <dir> export|import`.
//!
//! # Why this is a format question, not a lifecycle chore
//!
//! Constraint **C1** says a vanilla Cloud Hypervisor snapshot stays vanilla.
//! An exported lineage therefore cannot smuggle our metadata into the base
//! snapshot's `state.json` -- so everything we know about a lineage lives in an
//! **outer envelope beside** the compute snapshot, never inside it. That is the
//! whole shape of this format, and it is the same decision `docs/living-workspaces.md`
//! needs, so it is made once here rather than twice, differently.
//!
//! Concretely: a bundle **never contains the base snapshot** and never rewrites
//! it. It records the base's identity as a digest of its `state.json`, and
//! import refuses a target whose digest differs. The vanilla snapshot travels by
//! whatever means it already travels by; we add nothing to it.
//!
//! # Why the payload is chunked rather than copied
//!
//! `dump_guest_ram_delta` clones the previous dump and overwrites only the
//! 64 KiB chunks that changed, so on APFS a five-revision lineage of a 2 GiB
//! guest occupies barely more than one dump -- a measured 25 GiB of apparent
//! size over 1.4 GiB of disk. Copying those files into a bundle would multiply
//! it back out: the export would be ~18x the thing it exported.
//!
//! So a bundle is a small content-addressed store. Each file is split into
//! chunks, each unique chunk is stored once under its sha256, and a revision
//! records the ordered list of chunks that reconstitutes each of its files.
//!
//! **The chunk size is deliberately [`DELTA_CHUNK`]-aligned, and that alignment
//! is load-bearing.** The delta writer rewrites whole 64 KiB chunks at 64 KiB
//! offsets; hashing on the same grid means an unchanged region hashes
//! identically in every revision that contains it. A different size (or an
//! unaligned one) would put a boundary through the middle of every change, and
//! near-identical dumps would share almost nothing.
//!
//! # The bundle
//!
//! ```text
//! <bundle>/
//!   gimbal-export.json          the envelope (C1: ours, beside the snapshot)
//!   chunks/<aa>/<sha256>        each unique 64 KiB chunk, stored once
//! ```
//!
//! There is no directory per revision: a revision *is* its entry in the
//! envelope. That keeps the two halves of the format from disagreeing about
//! which files a revision has.
//!
//! A bundle is a directory rather than an archive so it can be `rsync`ed
//! incrementally and inspected without unpacking. `tar`ing one is a single
//! command and loses nothing, because the deduplication has already happened.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::checkpoint;
use crate::imp::human_bytes;
use crate::signing::to_hex;

/// On-disk format version for the envelope. Bumped when a reader of an older
/// `chm` could misread a newer bundle; a newer `chm` still reads older ones.
const BUNDLE_FORMAT: u32 = 1;

/// The envelope filename. Named after the product rather than after `chm` so it
/// is recognisable in a directory listing on a machine that has never run this.
const ENVELOPE: &str = "gimbal-export.json";

/// Where chunks live inside a bundle.
const CHUNKS_DIR: &str = "chunks";

/// Bytes per chunk. Must stay equal to `checkpoint::DELTA_CHUNK` -- see the
/// module docs for why the alignment, not just the size, is what matters.
/// Asserted by `chunk_size_matches_the_delta_writers_grid`.
const CHUNK: usize = 64 * 1024;

/// Sidecars that are *deliberately* not carried.
///
/// A pin is a statement about **this store's** retention budget, not about the
/// revision. Carrying one would silently consume a budget on the receiving
/// machine that its operator never spent, and would do so invisibly at import
/// time. The importer is told which revisions were pinned at the source and can
/// pin them here if they agree.
///
/// Everything else under a revision directory is carried, including files this
/// build does not recognise. A denylist errs towards a complete revision; an
/// allowlist would silently drop whatever a future version adds and strand the
/// import in a way that looks like corruption.
const NOT_CARRIED: &[&str] = &["pinned"];

/// The envelope: everything about a lineage that is ours rather than Cloud
/// Hypervisor's.
#[derive(Serialize, Deserialize)]
pub(crate) struct Envelope {
    /// Format version of this file.
    pub format: u32,
    /// When the export ran, Unix epoch milliseconds.
    pub created_at_ms: u64,
    /// Chunk size the payload was split on. Recorded so a future reader can
    /// tell a re-grid from a corruption.
    pub chunk_bytes: usize,
    /// What these revisions delta.
    pub base: BaseIdentity,
    /// The exported revisions, oldest first.
    pub revisions: Vec<ExportedRevision>,
}

/// Which base snapshot an exported lineage belongs to.
#[derive(Serialize, Deserialize)]
pub(crate) struct BaseIdentity {
    /// The source snapshot directory's name. Advisory only -- a directory can
    /// be renamed, and two machines will not agree on paths.
    pub name: String,
    /// sha256 of the base snapshot's `state.json`. This is the real identity:
    /// `state.json` carries the memory-region layout and device wiring that a
    /// restored revision's RAM was captured against, so a different digest is a
    /// different machine, whatever the directory is called.
    pub state_sha256: String,
}

/// One revision's payload, as a list of files made of chunks.
#[derive(Serialize, Deserialize)]
pub(crate) struct ExportedRevision {
    pub id: String,
    /// Whether this revision was a retention root at the source. Advisory --
    /// see [`NOT_CARRIED`].
    #[serde(default)]
    pub pinned_at_source: bool,
    pub files: Vec<ExportedFile>,
}

/// A file inside a revision, as an ordered chunk list.
#[derive(Serialize, Deserialize)]
pub(crate) struct ExportedFile {
    /// Path relative to the revision directory, `/`-separated.
    pub path: String,
    /// Exact length, so the final (short) chunk reconstitutes correctly and a
    /// truncated write is detectable.
    pub len: u64,
    /// sha256 of each chunk, in order.
    pub chunks: Vec<String>,
    /// Modification time, nanoseconds since the epoch.
    ///
    /// **Load-bearing, not metadata politeness.** #139's drift guard
    /// fingerprints an overlay as `name:len:mtime`, and a revision ships that
    /// fingerprint beside the files it describes. An import that wrote the
    /// bytes faithfully and let the clock stamp the result would produce a
    /// revision carrying an assertion that contradicts its own contents, and
    /// the only symptom would be a refused resume on the receiving machine —
    /// import reporting success and handing over something nobody can start.
    ///
    /// Reproducing the timestamp is faithful reproduction of the artifact, not
    /// a weakening of the guard: the RAM and the disk were consistent when they
    /// were captured, both halves travel together, and anything that touches
    /// the overlays *after* the import still moves the mtime and still fires.
    pub mtime_ns: u128,
}

impl ExportedRevision {
    /// Apparent bytes of this revision, i.e. what it occupies once written out.
    fn apparent(&self) -> u64 {
        self.files.iter().map(|f| f.len).sum()
    }
}

/// What an export produced.
pub(crate) struct ExportReport {
    pub bundle: PathBuf,
    pub revisions: Vec<String>,
    /// Bytes the revisions occupy when written out individually.
    pub apparent: u64,
    /// Bytes the bundle actually holds, after identical chunks collapse.
    pub stored: u64,
}

/// What an import did, or would do.
pub(crate) struct ImportReport {
    pub imported: Vec<String>,
    /// Revisions already present in the target, left untouched.
    pub skipped: Vec<String>,
    /// Ids that were pinned at the source, so the operator can choose to pin.
    pub pinned_at_source: Vec<String>,
    /// Apparent bytes of what was imported.
    pub bytes: u64,
    /// Bytes actually written to this disk. Lower than `bytes` by whatever the
    /// revisions share, which is the number that answers "what did this cost
    /// me".
    pub written: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// sha256 of a byte slice, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(digest(&SHA256, bytes).as_ref())
}

/// Whether a string is a canonical lowercase sha256 hex digest.
///
/// Chunk names become path segments, so this is the guard that keeps a
/// hand-edited envelope from naming `../../etc/something`. Same discipline as
/// the control-plane pull cache.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Where a chunk lives inside a bundle: `chunks/<aa>/<hex>`.
///
/// Fanned out by the first byte because a 2 GiB dump is 32 768 chunks and a
/// lineage is several of those; one flat directory with a hundred thousand
/// entries is slow to list on every filesystem worth naming.
fn chunk_path(bundle: &Path, hex: &str) -> PathBuf {
    bundle.join(CHUNKS_DIR).join(&hex[..2]).join(hex)
}

/// Digest of a base snapshot's `state.json` -- the identity an import checks.
fn base_state_digest(snapshot_dir: &Path) -> Result<String, String> {
    let path = snapshot_dir.join("state.json");
    let bytes = fs::read(&path)
        .map_err(|e| format!("read {} to identify the base snapshot: {e}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Every regular file under `dir`, as paths relative to it, sorted.
///
/// Sorted so an envelope is reproducible: two exports of the same revision
/// produce byte-identical file lists, which is what makes a diff of two
/// envelopes meaningful.
fn carried_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let entries = fs::read_dir(at).map_err(|e| format!("read {}: {e}", at.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let md = match entry.metadata() {
                Ok(md) => md,
                Err(e) => return Err(format!("stat {}: {e}", path.display())),
            };
            if md.is_dir() {
                walk(root, &path, out)?;
            } else if md.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| format!("{} escaped {}", path.display(), root.display()))?;
                let name = rel.to_string_lossy();
                if NOT_CARRIED.contains(&name.as_ref()) || name.ends_with(".tmp") {
                    continue;
                }
                out.push(rel.to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// Split one file into chunks, writing any chunk the bundle does not already
/// hold. Returns the file's entry.
fn absorb_file(
    bundle: &Path,
    rev_dir: &Path,
    rel: &Path,
    have: &mut BTreeSet<String>,
    stored: &mut u64,
) -> Result<ExportedFile, String> {
    let src = rev_dir.join(rel);
    let mut f = File::open(&src).map_err(|e| format!("open {}: {e}", src.display()))?;
    let mut buf = vec![0u8; CHUNK];
    let mut chunks = Vec::new();
    let mut len = 0u64;
    loop {
        // `read` is allowed to return short; a short read mid-file would
        // re-grid every chunk after it and silently destroy all sharing with
        // the sibling revisions, so fill the buffer before hashing.
        let mut filled = 0;
        while filled < buf.len() {
            let n = f
                .read(&mut buf[filled..])
                .map_err(|e| format!("read {}: {e}", src.display()))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        len += filled as u64;
        let hex = sha256_hex(&buf[..filled]);
        if have.insert(hex.clone()) {
            let dest = chunk_path(bundle, &hex);
            // A chunk already on disk is byte-identical by construction, so a
            // repeat export into the same bundle costs nothing and cannot
            // corrupt anything.
            if !dest.is_file() {
                write_chunk(&dest, &buf[..filled])?;
            }
            *stored += filled as u64;
        }
        chunks.push(hex);
        if filled < buf.len() {
            break;
        }
    }
    let mtime_ns = f
        .metadata()
        .map_err(|e| format!("stat {}: {e}", src.display()))?
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    Ok(ExportedFile {
        path: rel.to_string_lossy().replace('\\', "/"),
        len,
        chunks,
        mtime_ns,
    })
}

/// Write one chunk, staged and renamed so an interrupted export never leaves a
/// short file under a name that claims to be its own hash.
fn write_chunk(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("chunk path {} has no parent", dest.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        "{}.tmp",
        dest.file_name().unwrap_or_default().to_string_lossy()
    ));
    let mut f = File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    drop(f);
    fs::rename(&tmp, dest).map_err(|e| format!("rename {}: {e}", dest.display()))
}

/// Export revisions from a snapshot into a bundle directory.
///
/// `ids` empty means every revision, HEAD included: HEAD is a revision like any
/// other, it just also happens to be the one this machine would resume.
pub(crate) fn export(
    snapshot_dir: &Path,
    ids: &[String],
    bundle: &Path,
) -> Result<ExportReport, String> {
    let base = BaseIdentity {
        name: snapshot_dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        state_sha256: base_state_digest(snapshot_dir)?,
    };

    let all = checkpoint::list_revisions(snapshot_dir);
    if all.is_empty() {
        return Err(format!(
            "no revisions in {} to export (run and suspend it first)",
            snapshot_dir.display()
        ));
    }
    let chosen: Vec<_> = if ids.is_empty() {
        all.iter().collect()
    } else {
        let mut chosen = Vec::new();
        for want in ids {
            let found = all.iter().find(|r| &r.revision.id == want).ok_or_else(|| {
                format!(
                    "no revision {want} in {} (see `chm revisions`)",
                    snapshot_dir.display()
                )
            })?;
            chosen.push(found);
        }
        chosen
    };

    // A metadata-only revision is a headstone: its manifest survives so the
    // graph stays readable, but its RAM is gone. Exporting one would produce a
    // bundle that imports "successfully" into something nobody can resume, so
    // say what is happening rather than shipping a hollow revision.
    let hollow: Vec<&str> = chosen
        .iter()
        .filter(|r| !r.resumable)
        .map(|r| r.revision.id.as_str())
        .collect();
    if !hollow.is_empty() && ids.is_empty() {
        eprintln!(
            "chm export: skipping {} metadata-only revision(s) (their RAM was pruned): {}",
            hollow.len(),
            hollow.join(", ")
        );
    } else if !hollow.is_empty() {
        return Err(format!(
            "{} is metadata-only: its guest RAM was pruned, so there is nothing \
             to export that could be resumed",
            hollow.join(", ")
        ));
    }

    fs::create_dir_all(bundle).map_err(|e| format!("create {}: {e}", bundle.display()))?;

    let mut have = BTreeSet::new();
    let mut stored = 0u64;
    let mut revisions = Vec::new();
    for info in chosen.iter().filter(|r| r.resumable) {
        let mut files = Vec::new();
        for rel in carried_files(&info.dir)? {
            files.push(absorb_file(
                bundle,
                &info.dir,
                &rel,
                &mut have,
                &mut stored,
            )?);
        }
        revisions.push(ExportedRevision {
            id: info.revision.id.clone(),
            pinned_at_source: info.dir.join("pinned").is_file(),
            files,
        });
    }
    if revisions.is_empty() {
        return Err(format!(
            "nothing resumable to export from {}",
            snapshot_dir.display()
        ));
    }

    let envelope = Envelope {
        format: BUNDLE_FORMAT,
        created_at_ms: now_ms(),
        chunk_bytes: CHUNK,
        base,
        revisions,
    };
    let text = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("serialize the envelope: {e}"))?;
    let path = bundle.join(ENVELOPE);
    // Written last, and renamed into place: until the envelope exists the
    // directory is a pile of anonymous chunks, so a killed export cannot be
    // mistaken for a complete bundle.
    let tmp = bundle.join(format!("{ENVELOPE}.tmp"));
    fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("write {}: {e}", path.display()))?;

    Ok(ExportReport {
        bundle: bundle.to_path_buf(),
        apparent: envelope
            .revisions
            .iter()
            .map(ExportedRevision::apparent)
            .sum(),
        revisions: envelope.revisions.iter().map(|r| r.id.clone()).collect(),
        stored,
    })
}

/// Read and validate a bundle's envelope.
pub(crate) fn read_envelope(bundle: &Path) -> Result<Envelope, String> {
    let path = bundle.join(ENVELOPE);
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "read {}: {e} (is {} a bundle written by `chm revisions … export`?)",
            path.display(),
            bundle.display()
        )
    })?;
    let envelope: Envelope =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if envelope.format > BUNDLE_FORMAT {
        return Err(format!(
            "{} is format {} but this build understands {BUNDLE_FORMAT}; upgrade chm",
            path.display(),
            envelope.format
        ));
    }
    Ok(envelope)
}

/// Reject a path that would write outside the revision directory it belongs to.
///
/// The envelope is a plain JSON file an operator can edit, and its `path`
/// fields become filesystem paths. Absolute paths, `..`, and empty names are
/// all refused by name rather than normalised away, because silently rewriting
/// a path an operator wrote is how a traversal becomes invisible.
fn safe_relative(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("a file entry has an empty path".to_string());
    }
    let rel = PathBuf::from(path);
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return Err(format!("unsafe path in the envelope: {path}")),
        }
    }
    Ok(rel)
}

/// Reassemble one file from its chunks, verifying each against its own name.
///
/// `donor` is the same path in the revision written just before this one, whose
/// chunk list we already know. When it exists, the file is APFS-cloned from it
/// and only the chunks whose hashes differ are overwritten -- exactly what
/// `dump_guest_ram_delta` does when *taking* a checkpoint, which is why the
/// saving survives the round trip.
///
/// **Without this, import throws away the very sharing the bundle preserves.**
/// Measured on a real 5-revision lineage: the bundle stores 2.7 GiB, and a
/// naive import wrote 4.4 GiB by the second revision alone. The bundle would
/// have been small and the thing it produced 18x too big.
///
/// Verification is not optional: we are reading every byte anyway, so the only
/// thing a `--no-verify` flag would buy is the chance to write a corrupt
/// checkpoint that fails at resume, months later, with no clue where it came
/// from. On the clone path the skipped chunks are not re-read -- they were
/// verified when the donor was written, in this same run, so the cover is
/// transitive rather than absent.
///
/// Returns the bytes actually written, which is the cost on *this* disk rather
/// than the file's length.
fn emit_file(
    bundle: &Path,
    dest_dir: &Path,
    file: &ExportedFile,
    donor: Option<(&Path, &ExportedFile)>,
) -> Result<u64, String> {
    let rel = safe_relative(&file.path)?;
    let dest = dest_dir.join(&rel);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }

    // The clone shortcut needs a donor of the same length, or the tail past the
    // shorter of the two would silently keep the donor's bytes -- the same
    // check `dump_guest_ram_delta` makes against its parent, for the same
    // reason.
    let donor = donor.filter(|(_, d)| d.len == file.len && d.chunks.len() == file.chunks.len());
    if let Some((donor_dir, donor_file)) = donor {
        let src = donor_dir.join(&rel);
        if clone_file(&src, &dest).is_ok() {
            let written = patch_clone(bundle, &dest, file, donor_file)?;
            set_mtime(&dest, file.mtime_ns)?;
            return Ok(written);
        }
    }

    let out = File::create(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    out.set_len(file.len)
        .map_err(|e| format!("size {}: {e}", dest.display()))?;
    let written = fill_sparse(bundle, &out, &dest, file, |_| true)?;
    drop(out);
    set_mtime(&dest, file.mtime_ns)?;
    Ok(written)
}

/// Restore a file's recorded modification time.
///
/// Applied after the last write, because writing moves it: a clone inherits the
/// donor's mtime and `patch_clone` then stamps it with now, and a fresh write
/// stamps it with now outright. See [`ExportedFile::mtime_ns`] for why this is
/// a correctness requirement rather than tidiness.
fn set_mtime(path: &Path, mtime_ns: u128) -> Result<(), String> {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return Err(format!("{}: path contains a NUL", path.display()));
    };
    let secs = (mtime_ns / 1_000_000_000) as i64;
    let nsec = (mtime_ns % 1_000_000_000) as i64;
    let stamp = libc::timespec {
        tv_sec: secs,
        tv_nsec: nsec,
    };
    // Leave atime alone -- it carries no meaning here and UTIME_OMIT says so
    // explicitly rather than inventing a value.
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        stamp,
    ];
    // SAFETY: `c_path` is a NUL-terminated path that outlives the call and
    // `times` is a two-element timespec array, which is what utimensat reads.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "set mtime on {}: {}",
            path.display(),
            io::Error::last_os_error()
        ))
    }
}

/// Write a file's chunks into `out`, leaving every all-zero chunk as a hole.
///
/// A CoW overlay is mostly hole: measured, a revision's `_disk0-cow.raw` is
/// 8 GiB long and 858 MiB allocated, because the blocks the guest has never
/// written are not there at all. Writing those chunks out as literal zeros
/// reproduces the file's *contents* perfectly and its *shape* not at all --
/// the first import of this lineage cost 8.2 GiB for a file that occupied
/// 858 MiB at the source, and 7.3 GiB of that was zeroes we chose to store.
///
/// A hole reads back as zeros, so skipping one is invisible to every reader;
/// what it is not invisible to is the disk. `set_len` has already fixed the
/// length, so the tail may be skipped too without truncating anything.
///
/// `wanted` decides which indices are candidates at all, so the clone path can
/// reuse this for "only the chunks that differ from the donor".
fn fill_sparse<F: Fn(usize) -> bool>(
    bundle: &Path,
    mut out: &File,
    dest: &Path,
    file: &ExportedFile,
    wanted: F,
) -> Result<u64, String> {
    let mut written = 0u64;
    let mut accounted = 0u64;
    for (i, hex) in file.chunks.iter().enumerate() {
        if !wanted(i) {
            accounted += chunk_len(file, i);
            continue;
        }
        let bytes = load_chunk(bundle, hex, &file.path)?;
        accounted += bytes.len() as u64;
        if bytes.iter().all(|b| *b == 0) {
            continue;
        }
        out.seek(SeekFrom::Start((i * CHUNK) as u64))
            .map_err(|e| format!("seek {}: {e}", dest.display()))?;
        out.write_all(&bytes)
            .map_err(|e| format!("write {}: {e}", dest.display()))?;
        written += bytes.len() as u64;
    }
    if accounted != file.len {
        return Err(format!(
            "{} reassembled to {accounted} bytes but the envelope says {}",
            file.path, file.len
        ));
    }
    Ok(written)
}

/// How long chunk `i` of `file` is: every chunk is full but the last.
fn chunk_len(file: &ExportedFile, i: usize) -> u64 {
    let start = (i as u64) * CHUNK as u64;
    (file.len - start).min(CHUNK as u64)
}

/// Check the overlays an import just wrote against the `overlay.fingerprint`
/// the source machine shipped beside them.
///
/// Worth doing precisely because that fingerprint is **not ours**: it is an
/// independent statement, made on another machine at capture time, about which
/// disk went with which RAM. Every other check here compares the import against
/// the export, and #178/#180 are both records of what that costs — a writer and
/// a reader that agree by construction agree about a bug too.
///
/// This one is the reason the mtime carry is provable rather than hoped for. It
/// fires the moment `emit_file` stops reproducing a timestamp, at import, where
/// the operator can act on it — instead of on the receiving machine at resume,
/// as an error blaming their disk for something the transfer did.
fn verify_overlay_fingerprint(staging: &Path, id: &str) -> Result<(), String> {
    let recorded = match fs::read_to_string(staging.join(checkpoint::OVERLAY_FINGERPRINT)) {
        Ok(t) => t,
        // A revision predating the guard carries no fingerprint, and inventing
        // one here would assert a consistency nobody ever checked.
        Err(_) => return Ok(()),
    };
    let live = checkpoint::fingerprint_overlay_dir(&staging.join("overlays"));
    if checkpoint::comparable_fingerprint(&recorded) == checkpoint::comparable_fingerprint(&live) {
        return Ok(());
    }
    Err(format!(
        "{id}: the overlays this import wrote do not match the fingerprint captured with them.\n  \
         captured: {}\n  written:  {}\n  \
         Resuming this revision would be refused on the receiving machine, so it is refused here.",
        recorded.replace('\n', " | "),
        live.replace('\n', " | "),
    ))
}

/// Read one chunk out of the bundle and prove it is what its name claims.
fn load_chunk(bundle: &Path, hex: &str, for_file: &str) -> Result<Vec<u8>, String> {
    if !is_sha256_hex(hex) {
        return Err(format!("{for_file}: chunk name `{hex}` is not a sha256"));
    }
    let src = chunk_path(bundle, hex);
    let bytes =
        fs::read(&src).map_err(|e| format!("read chunk {} for {for_file}: {e}", src.display()))?;
    let actual = sha256_hex(&bytes);
    if actual != *hex {
        return Err(format!(
            "chunk {hex} is corrupt: its content hashes to {actual}"
        ));
    }
    Ok(bytes)
}

/// Overwrite the chunks of a freshly cloned file that differ from its donor.
///
/// The differing indices come straight out of the envelope, so this reads
/// nothing from the destination at all: the donor's chunk hashes are already
/// recorded, and two chunks with the same sha256 are the same 64 KiB.
///
/// Unlike the fresh path this must write an all-zero chunk out rather than
/// leaving a hole: the clone starts as a copy of the donor, so a chunk that is
/// zero *here* and non-zero *there* is a difference that has to be applied.
/// Skipping it would leave the donor's bytes behind. Sparseness is inherited
/// from the donor, which the fresh path already got right.
fn patch_clone(
    bundle: &Path,
    dest: &Path,
    file: &ExportedFile,
    donor: &ExportedFile,
) -> Result<u64, String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(dest)
        .map_err(|e| format!("open {}: {e}", dest.display()))?;
    let mut written = 0u64;
    for (i, hex) in file.chunks.iter().enumerate() {
        if donor.chunks[i] == *hex {
            continue;
        }
        let bytes = load_chunk(bundle, hex, &file.path)?;
        f.seek(SeekFrom::Start((i * CHUNK) as u64))
            .map_err(|e| format!("seek {}: {e}", dest.display()))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write {}: {e}", dest.display()))?;
        written += bytes.len() as u64;
    }
    drop(f);
    let len = fs::metadata(dest)
        .map_err(|e| format!("stat {}: {e}", dest.display()))?
        .len();
    if len != file.len {
        return Err(format!(
            "{} cloned to {len} bytes but the envelope says {}",
            file.path, file.len
        ));
    }
    Ok(written)
}

/// APFS clone: a distinct file sharing every extent until one of them is
/// written to. `fs::copy` will not do -- measured, a plain copy of a 256 MiB
/// file costs 256 MiB where `clonefile` costs 20 KiB.
///
/// An error is always "could not take the shortcut", never "the import failed":
/// every caller falls back to writing the file out in full.
fn clone_file(src: &Path, dest: &Path) -> Result<(), String> {
    let (Ok(c_src), Ok(c_dest)) = (
        CString::new(src.as_os_str().as_bytes()),
        CString::new(dest.as_os_str().as_bytes()),
    ) else {
        return Err("path contains a NUL".to_string());
    };
    // `clonefile` refuses an existing destination, which is what we want: it
    // can never silently half-overwrite something.
    // SAFETY: both pointers are NUL-terminated paths that outlive the call, and
    // the flags argument is the documented "no flags" value.
    let rc = unsafe { libc::clonefile(c_src.as_ptr(), c_dest.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "clonefile {} -> {}: {}",
            src.display(),
            dest.display(),
            io::Error::last_os_error()
        ))
    }
}

/// How an import should treat a revision id the target already holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnCollision {
    /// Refuse the whole import. The default: an id is minted from a timestamp
    /// plus randomness, so a collision means these are two *different* captures
    /// wearing one name and there is no safe automatic answer.
    Refuse,
    /// Leave what is here and import the rest.
    Skip,
}

/// Import a bundle's revisions into a snapshot's revision store.
///
/// **An imported revision never becomes HEAD.** HEAD is where *this* machine
/// would resume from, and moving it is a decision with a command of its own
/// (`chm rollback`). An import that silently changed which state a `Start`
/// resumes would be the same class of surprise as a checkpoint written over a
/// good one -- and the operator importing a lineage to inspect it has said
/// nothing about wanting to run it.
pub(crate) fn import(
    bundle: &Path,
    snapshot_dir: &Path,
    on_collision: OnCollision,
    dry_run: bool,
) -> Result<ImportReport, String> {
    let envelope = read_envelope(bundle)?;

    let here = base_state_digest(snapshot_dir)?;
    if here != envelope.base.state_sha256 {
        return Err(format!(
            "this bundle was exported from base snapshot `{}` ({}…), but {} is a \
             different machine ({}…). A revision's captured RAM matches the memory \
             layout and device wiring in its own base's state.json; restoring it \
             onto another would be the RAM/disk mismatch resume exists to refuse. \
             Import it into a copy of the snapshot it came from.",
            envelope.base.name,
            &envelope.base.state_sha256[..12],
            snapshot_dir.display(),
            &here[..12],
        ));
    }

    let present: BTreeSet<String> = checkpoint::list_revisions(snapshot_dir)
        .into_iter()
        .map(|r| r.revision.id)
        .collect();

    let mut skipped = Vec::new();
    let mut todo = Vec::new();
    for rev in &envelope.revisions {
        if present.contains(&rev.id) {
            if on_collision == OnCollision::Refuse {
                return Err(format!(
                    "{} already holds a revision {}. Ids carry a timestamp and \
                     random suffix, so two revisions sharing one are two different \
                     captures with the same name, and overwriting either would \
                     destroy state nobody asked to lose. Pass --skip-existing to \
                     import the rest and leave this one alone.",
                    snapshot_dir.display(),
                    rev.id
                ));
            }
            skipped.push(rev.id.clone());
            continue;
        }
        todo.push(rev);
    }

    let bytes: u64 = todo.iter().map(|r| r.apparent()).sum();
    let pinned_at_source = todo
        .iter()
        .filter(|r| r.pinned_at_source)
        .map(|r| r.id.clone())
        .collect();

    if dry_run {
        return Ok(ImportReport {
            imported: todo.iter().map(|r| r.id.clone()).collect(),
            skipped,
            pinned_at_source,
            bytes,
            written: 0,
        });
    }

    let store = checkpoint::revision_store_dir(snapshot_dir);
    fs::create_dir_all(&store).map_err(|e| format!("create {}: {e}", store.display()))?;
    let staging_root = checkpoint::import_staging_dir(snapshot_dir);

    let mut imported = Vec::new();
    let mut written = 0u64;
    // The donor for revision N is revision N-1 of this same import. Envelope
    // order is lineage order, which is where consecutive revisions overlap
    // most -- and because we wrote the donor ourselves, moments ago, we already
    // know every one of its chunk hashes and never have to read it back.
    let mut donor: Option<(PathBuf, &ExportedRevision)> = None;
    for rev in todo {
        // A revision id is minted by us, but this one arrived in a file, so it
        // is caller-supplied text about to become a directory name.
        let id_path = safe_relative(&rev.id)
            .map_err(|_| format!("unsafe revision id in the envelope: {}", rev.id))?;
        if id_path.components().count() != 1 {
            return Err(format!("unsafe revision id in the envelope: {}", rev.id));
        }
        // Assembled outside the store, so a half-written import is never listed
        // as a revision, and reclaimable with `chm revisions <dir> gc`.
        let staging = staging_root.join(&rev.id);
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging).map_err(|e| format!("create {}: {e}", staging.display()))?;
        let dest = store.join(&rev.id);
        let result = (|| -> Result<u64, String> {
            let mut wrote = 0u64;
            for file in &rev.files {
                let from = donor.as_ref().and_then(|(dir, prev)| {
                    prev.files
                        .iter()
                        .find(|f| f.path == file.path)
                        .map(|f| (dir.as_path(), f))
                });
                wrote += emit_file(bundle, &staging, file, from)?;
            }
            // Prove the payload really is a revision, and really is *this*
            // revision, before it becomes visible to every reader. An envelope
            // whose id disagrees with the manifest it carries would produce a
            // directory `chm revisions` names one thing and `rollback` reads as
            // another.
            let manifest = checkpoint::read_revision_manifest_at(&staging)?;
            if manifest.id != rev.id {
                return Err(format!(
                    "the envelope calls this revision {} but its manifest says {}",
                    rev.id, manifest.id
                ));
            }
            verify_overlay_fingerprint(&staging, &rev.id)?;
            Ok(wrote)
        })();
        match result {
            Ok(wrote) => written += wrote,
            Err(e) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(e);
            }
        }
        fs::rename(&staging, &dest).map_err(|e| {
            let _ = fs::remove_dir_all(&staging);
            format!("place {}: {e}", dest.display())
        })?;
        imported.push(rev.id.clone());
        donor = Some((dest, rev));
    }
    // Only when nothing is left in it -- a concurrent import of another bundle
    // may still be assembling here, and removing its tree would be worse than
    // leaving an empty directory behind.
    let _ = fs::remove_dir(&staging_root);

    Ok(ImportReport {
        imported,
        skipped,
        pinned_at_source,
        bytes,
        written,
    })
}

/// A human summary of what a bundle contains, for `import --dry-run` and for
/// looking at a bundle someone handed you.
pub(crate) fn describe(bundle: &Path) -> Result<Vec<String>, String> {
    let envelope = read_envelope(bundle)?;
    let mut out = vec![
        format!("format        {}", envelope.format),
        format!(
            "base          {} (state.json {}…)",
            envelope.base.name,
            &envelope.base.state_sha256[..12.min(envelope.base.state_sha256.len())]
        ),
        format!("chunk         {} bytes", envelope.chunk_bytes),
    ];
    // Count each chunk once across the whole bundle: the saving is the point of
    // the format, so reporting the apparent total alone would hide it.
    let mut unique: BTreeMap<&str, u64> = BTreeMap::new();
    let mut apparent = 0u64;
    for rev in &envelope.revisions {
        apparent += rev.apparent();
        for f in &rev.files {
            for (i, c) in f.chunks.iter().enumerate() {
                let last = i + 1 == f.chunks.len();
                let len = if last {
                    f.len - (i as u64) * envelope.chunk_bytes as u64
                } else {
                    envelope.chunk_bytes as u64
                };
                unique.insert(c, len);
            }
        }
    }
    let stored: u64 = unique.values().sum();
    out.push(format!(
        "revisions     {} ({} apparent, {} stored)",
        envelope.revisions.len(),
        human_bytes(apparent),
        human_bytes(stored)
    ));
    for rev in &envelope.revisions {
        let pin = if rev.pinned_at_source {
            "  [pinned at source]"
        } else {
            ""
        };
        out.push(format!(
            "  {}  {:>10}  {} file(s){pin}",
            rev.id,
            human_bytes(rev.apparent()),
            rev.files.len()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chm-bundle-{}-{name}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn chunk_size_matches_the_delta_writers_grid() {
        // The whole saving depends on hashing on the same 64 KiB grid the delta
        // writer rewrites on. If someone retunes one, this says the other moved
        // too -- otherwise near-identical dumps would share nothing and an
        // export would silently balloon back to its apparent size.
        assert_eq!(CHUNK, checkpoint::delta_chunk_bytes());
    }

    #[test]
    fn a_traversal_in_the_envelope_is_refused_not_normalised() {
        assert!(safe_relative("../../etc/passwd").is_err());
        assert!(safe_relative("/etc/passwd").is_err());
        assert!(safe_relative("overlays/../../x").is_err());
        assert!(safe_relative("").is_err());
        assert!(safe_relative("overlays/disk0.cow").is_ok());
    }

    #[test]
    fn a_chunk_name_must_be_a_canonical_sha256() {
        assert!(is_sha256_hex(&sha256_hex(b"hello")));
        assert!(!is_sha256_hex("../etc"));
        assert!(!is_sha256_hex(&sha256_hex(b"hello").to_uppercase()));
        assert!(!is_sha256_hex("abc"));
    }

    #[test]
    fn identical_content_across_revisions_is_stored_once() {
        let root = tmp("dedup");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();

        // Two files whose first chunk is identical and whose second differs:
        // exactly the shape a delta dump has.
        let mut a = vec![7u8; CHUNK];
        a.extend(vec![1u8; CHUNK]);
        let mut b = vec![7u8; CHUNK];
        b.extend(vec![2u8; CHUNK]);
        fs::write(rev.join("a"), &a).unwrap();
        fs::write(rev.join("b"), &b).unwrap();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let fa = absorb_file(&bundle, &rev, Path::new("a"), &mut have, &mut stored).unwrap();
        let fb = absorb_file(&bundle, &rev, Path::new("b"), &mut have, &mut stored).unwrap();

        assert_eq!(fa.chunks.len(), 2);
        assert_eq!(
            fa.chunks[0], fb.chunks[0],
            "the shared chunk must hash alike"
        );
        assert_ne!(fa.chunks[1], fb.chunks[1]);
        // 4 chunks of apparent content, 3 chunks stored.
        assert_eq!(stored, 3 * CHUNK as u64);
        assert_eq!(have.len(), 3);
    }

    #[test]
    fn a_file_round_trips_through_chunks_byte_for_byte() {
        let root = tmp("roundtrip");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(rev.join("overlays")).unwrap();

        // Deliberately not a chunk multiple, so the short final chunk is
        // exercised rather than assumed.
        let content: Vec<u8> = (0..(CHUNK * 2 + 1234)).map(|i| (i % 251) as u8).collect();
        fs::write(rev.join("overlays/disk0.cow"), &content).unwrap();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let entry = absorb_file(
            &bundle,
            &rev,
            Path::new("overlays/disk0.cow"),
            &mut have,
            &mut stored,
        )
        .unwrap();
        assert_eq!(entry.path, "overlays/disk0.cow");
        assert_eq!(entry.len, content.len() as u64);

        let out = root.join("out");
        emit_file(&bundle, &out, &entry, None).unwrap();
        assert_eq!(fs::read(out.join("overlays/disk0.cow")).unwrap(), content);
    }

    /// A CoW overlay is mostly hole, and an import that fills those holes with
    /// literal zeros reproduces the contents perfectly while costing an order
    /// of magnitude more disk. Measured on the real lineage before this was
    /// fixed: 858 MiB at the source became 8.2 GiB at the destination.
    ///
    /// So assert the *shape* as well as the bytes, using the allocated block
    /// count rather than the length -- the length was always right, which is
    /// exactly why the defect survived a byte-for-byte round-trip test.
    #[test]
    fn a_sparse_overlay_does_not_arrive_filled_with_zeroes() {
        use std::os::unix::fs::MetadataExt;

        let root = tmp("sparse");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(rev.join("overlays")).unwrap();

        // 8 MiB long, one 64 KiB chunk of real content near the end: the shape
        // of an overlay whose guest has written almost nothing.
        let len = 8 * 1024 * 1024u64;
        let src = rev.join("overlays/disk0.cow");
        let f = File::create(&src).unwrap();
        f.set_len(len).unwrap();
        drop(f);
        let mut f = fs::OpenOptions::new().write(true).open(&src).unwrap();
        f.seek(SeekFrom::Start(len - CHUNK as u64)).unwrap();
        f.write_all(&vec![0xab; CHUNK]).unwrap();
        drop(f);

        let before = fs::metadata(&src).unwrap().blocks();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let entry = absorb_file(
            &bundle,
            &rev,
            Path::new("overlays/disk0.cow"),
            &mut have,
            &mut stored,
        )
        .unwrap();

        let out = root.join("out");
        let written = emit_file(&bundle, &out, &entry, None).unwrap();
        let dest = out.join("overlays/disk0.cow");

        // Contents identical: a hole reads back as zeros, so skipping one is
        // invisible to every reader.
        assert_eq!(fs::read(&dest).unwrap(), fs::read(&src).unwrap());
        assert_eq!(fs::metadata(&dest).unwrap().len(), len);

        // And the shape survived. Allow the destination a little slack for
        // filesystem bookkeeping, but nothing like the 128x a dense write costs.
        let after = fs::metadata(&dest).unwrap().blocks();
        assert!(
            after <= before * 2 + 64,
            "sparse overlay arrived dense: {before} blocks at source, {after} at destination"
        );
        assert_eq!(
            written, CHUNK as u64,
            "only the one non-empty chunk should reach the disk"
        );
    }

    /// #139 fingerprints an overlay as `name:len:mtime`, and a revision ships
    /// that fingerprint beside the files it describes. So an import that lets
    /// the clock stamp its output produces a revision that refuses to resume --
    /// on the *receiving* machine, with an error blaming their disk.
    ///
    /// This is the bug that got all the way to hardware: a bundle that verified,
    /// imported, deduplicated beautifully, and could not be started.
    #[test]
    fn a_carried_file_keeps_the_modification_time_the_drift_guard_reads() {
        let root = tmp("mtime");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(rev.join("overlays")).unwrap();

        let src = rev.join("overlays/disk0.cow");
        fs::write(&src, vec![7u8; CHUNK + 9]).unwrap();
        // A time far enough in the past that "now" could never be mistaken for
        // it, and off a second boundary so nanoseconds are exercised too.
        set_mtime(&src, 1_500_000_000_123_456_789).unwrap();
        let want = fs::metadata(&src).unwrap().modified().unwrap();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let entry = absorb_file(
            &bundle,
            &rev,
            Path::new("overlays/disk0.cow"),
            &mut have,
            &mut stored,
        )
        .unwrap();

        let out = root.join("out");
        emit_file(&bundle, &out, &entry, None).unwrap();
        let got = fs::metadata(out.join("overlays/disk0.cow"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(got, want, "the fresh-write path lost the timestamp");

        // And the clone path. The donor must live at the same relative path and
        // genuinely *differ*, or `patch_clone` writes nothing, the clone keeps
        // the donor's inherited timestamp for free, and this asserts nothing at
        // all -- exactly what the first version of this test did, caught by
        // mutating the clone path's `set_mtime` away and watching it stay green.
        let mut content = vec![7u8; CHUNK + 9];
        content[0] = 42;
        fs::write(&src, &content).unwrap();
        set_mtime(&src, 1_500_000_000_987_654_321).unwrap();
        let want2 = fs::metadata(&src).unwrap().modified().unwrap();
        assert_ne!(want2, want, "the two revisions must differ in time as well");
        let entry2 = absorb_file(
            &bundle,
            &rev,
            Path::new("overlays/disk0.cow"),
            &mut have,
            &mut stored,
        )
        .unwrap();
        assert_ne!(
            entry2.chunks[0], entry.chunks[0],
            "the donor must differ, or patch_clone writes nothing"
        );

        let out2 = root.join("out2");
        let wrote = emit_file(&bundle, &out2, &entry2, Some((out.as_path(), &entry))).unwrap();
        assert_eq!(wrote, CHUNK as u64, "the clone path was not taken");
        let cloned = fs::metadata(out2.join("overlays/disk0.cow"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(cloned, want2, "the clone path lost the timestamp");
    }

    /// The fingerprint travels with the revision and was written on another
    /// machine, so checking against it has power every export-vs-import
    /// comparison here lacks. Prove it actually fires.
    #[test]
    fn overlays_that_disagree_with_their_own_fingerprint_are_refused() {
        let root = tmp("fprint");
        let staging = root.join("rev-1-aaaa");
        fs::create_dir_all(staging.join("overlays")).unwrap();
        let cow = staging.join("overlays/disk0.cow");
        fs::write(&cow, b"hello").unwrap();

        let honest = checkpoint::fingerprint_overlay_dir(&staging.join("overlays"));
        fs::write(staging.join(checkpoint::OVERLAY_FINGERPRINT), &honest).unwrap();
        verify_overlay_fingerprint(&staging, "rev-1-aaaa")
            .expect("a faithful import must be accepted");

        // Exactly the damage a missing mtime carry does: right bytes, right
        // length, wrong timestamp.
        set_mtime(&cow, 1_400_000_000_000_000_000).unwrap();
        let err = verify_overlay_fingerprint(&staging, "rev-1-aaaa")
            .expect_err("a moved mtime must be refused");
        assert!(err.contains("do not match the fingerprint"), "{err}");

        // A revision predating the guard carries no fingerprint, and must not
        // be refused for it.
        fs::remove_file(staging.join(checkpoint::OVERLAY_FINGERPRINT)).unwrap();
        verify_overlay_fingerprint(&staging, "rev-1-aaaa")
            .expect("a revision with no fingerprint must still import");
    }

    /// The saving is the whole reason this format exists, and it has to survive
    /// *import*, not just export. Without cloning from the previous revision, a
    /// 2.7 GiB bundle materialises as 50 GiB of disk.
    #[test]
    fn importing_a_second_revision_writes_only_what_changed() {
        let root = tmp("clone");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();

        // Four chunks, of which one differs -- the shape of a delta dump.
        // Values start at 1 so no chunk is accidentally all-zero: the fresh
        // path deliberately leaves those as holes, and that would confuse what
        // this test is measuring.
        let mut a = Vec::new();
        for k in 0..4u8 {
            a.extend(vec![k + 1; CHUNK]);
        }
        // The differing chunk is zeroed rather than changed, because that is
        // the case the clone path must NOT treat as a hole: the clone starts
        // as the donor, so zeros here are a difference to apply, not an
        // absence to skip.
        let mut b = a.clone();
        b[2 * CHUNK..3 * CHUNK].fill(0);

        fs::write(rev.join("m"), &a).unwrap();
        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let fa = absorb_file(&bundle, &rev, Path::new("m"), &mut have, &mut stored).unwrap();
        fs::write(rev.join("m"), &b).unwrap();
        let fb = absorb_file(&bundle, &rev, Path::new("m"), &mut have, &mut stored).unwrap();

        let first = root.join("r1");
        let wrote_a = emit_file(&bundle, &first, &fa, None).unwrap();
        assert_eq!(wrote_a, a.len() as u64, "the first revision has no donor");

        let second = root.join("r2");
        let wrote_b = emit_file(&bundle, &second, &fb, Some((first.as_path(), &fa))).unwrap();
        assert_eq!(
            wrote_b, CHUNK as u64,
            "only the one changed chunk should be written"
        );
        // Correctness is not negotiable for the speedup: the cloned file must
        // be the second revision's content exactly, not the first's with a
        // patch that nearly worked.
        assert_eq!(fs::read(second.join("m")).unwrap(), b);
    }

    /// A clone whose donor is a different length would leave the donor's bytes
    /// in the tail -- silently, and only discoverable by resuming it.
    #[test]
    fn a_donor_of_the_wrong_length_is_not_cloned_from() {
        let root = tmp("mismatch");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();

        let short = vec![1u8; CHUNK];
        let long = vec![1u8; CHUNK * 2];
        fs::write(rev.join("m"), &short).unwrap();
        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let f_short = absorb_file(&bundle, &rev, Path::new("m"), &mut have, &mut stored).unwrap();
        fs::write(rev.join("m"), &long).unwrap();
        let f_long = absorb_file(&bundle, &rev, Path::new("m"), &mut have, &mut stored).unwrap();

        let first = root.join("r1");
        emit_file(&bundle, &first, &f_short, None).unwrap();
        let second = root.join("r2");
        let wrote =
            emit_file(&bundle, &second, &f_long, Some((first.as_path(), &f_short))).unwrap();
        assert_eq!(wrote, long.len() as u64, "a length mismatch must fall back");
        assert_eq!(fs::read(second.join("m")).unwrap(), long);
    }

    #[test]
    fn a_corrupt_chunk_is_caught_at_import_not_at_resume() {
        let root = tmp("corrupt");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();
        fs::write(rev.join("f"), vec![9u8; 4096]).unwrap();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let entry = absorb_file(&bundle, &rev, Path::new("f"), &mut have, &mut stored).unwrap();

        // Flip one byte in the stored chunk, exactly as bit-rot or a truncated
        // transfer would.
        let path = chunk_path(&bundle, &entry.chunks[0]);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 0xff;
        fs::write(&path, &bytes).unwrap();

        let err = emit_file(&bundle, &root.join("out"), &entry, None).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn a_truncated_chunk_list_is_caught_by_the_recorded_length() {
        let root = tmp("truncated");
        let bundle = root.join("b");
        fs::create_dir_all(&bundle).unwrap();
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();
        fs::write(rev.join("f"), vec![3u8; CHUNK * 2]).unwrap();

        let mut have = BTreeSet::new();
        let mut stored = 0u64;
        let mut entry = absorb_file(&bundle, &rev, Path::new("f"), &mut have, &mut stored).unwrap();
        entry.chunks.pop();

        let err = emit_file(&bundle, &root.join("out"), &entry, None).unwrap_err();
        assert!(err.contains("envelope says"), "{err}");
    }

    #[test]
    fn a_pin_is_not_carried_but_is_reported() {
        let root = tmp("pin");
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();
        fs::write(rev.join("checkpoint.json"), b"{}").unwrap();
        fs::write(rev.join("pinned"), b"retention root\n").unwrap();
        fs::write(rev.join("label.tmp"), b"half-written").unwrap();

        let files = carried_files(&rev).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["checkpoint.json".to_string()]);
    }

    #[test]
    fn an_unrecognised_sidecar_is_carried_rather_than_dropped() {
        // A revision must arrive complete. Dropping a file a future build added
        // would strand the import in a way that reads as corruption.
        let root = tmp("unknown");
        let rev = root.join("rev");
        fs::create_dir_all(&rev).unwrap();
        fs::write(rev.join("checkpoint.json"), b"{}").unwrap();
        fs::write(rev.join("something-new"), b"x").unwrap();

        let files = carried_files(&rev).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"something-new".to_string()), "{names:?}");
    }
}
