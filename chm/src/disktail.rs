//! Notice a capture whose partition table does not use the whole disk (#259).
//!
//! A real cloud capture arrives with its root filesystem sized for the cloud
//! instance's *original* volume, not for the disk the snapshot declares. On
//! `graviton-vanilla-2cpu-net` that means `/dev/vda1` mounts with **56 MiB
//! free** while gigabytes sit unused past the end of the last partition.
//! Nothing installs, and the first thing a user does after rehydrating a cloud
//! sandbox is install something.
//!
//! The whole fact is visible from the host: the snapshot declares the device
//! size in sectors, and the disk image carries a GPT that says where the last
//! partition ends. So this warns with the exact commands rather than leaving a
//! user to discover `sgdisk -e` — which is needed *first*, and only because the
//! backup GPT header is no longer at the end of a device that grew.
//!
//! **We cannot repair it from here.** Growing a partition means rewriting the
//! GPT and then `resize2fs` on a mounted ext4 filesystem, from inside a guest
//! whose RAM already describes the old geometry. That is the guest's job, and
//! doing it underneath a restored kernel is the exact metadata-mismatch hazard
//! the overlay model exists to avoid.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use hypervisor::hvf::virtio::devmgr::{BackendKind, parse_devices};

use crate::checkpoint::live_overlays_dir_name;
use crate::imp::human_bytes;

/// Bytes covered by the primary GPT: the protective MBR (LBA 0), the header
/// (LBA 1) and the 32 sectors of partition entries that follow it.
const PRIMARY_GPT_BYTES: u64 = 34 * 512;

/// Say nothing below this much unused tail. A capture is allowed to leave a
/// little slack; a gigabyte is not slack, it is the difference between being
/// able to install a toolchain and not.
const REPORT_THRESHOLD: u64 = 1 << 30;

/// What the capture's own partition table leaves unused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnusedTail {
    /// Size of the block device the snapshot declares.
    pub device_bytes: u64,
    /// First byte past the last partition the GPT describes.
    pub used_bytes: u64,
}

impl UnusedTail {
    pub(crate) fn unused_bytes(&self) -> u64 {
        self.device_bytes.saturating_sub(self.used_bytes)
    }
}

/// Parse the tail from the first [`PRIMARY_GPT_BYTES`] of a disk image.
///
/// `device_sectors` comes from the snapshot's own device state rather than from
/// the image's length: a sparse or copy-on-write image is routinely shorter than
/// the device the guest sees, and the guest's view is the one that decides
/// whether there is room to grow into.
///
/// Returns `None` when there is no GPT to read — an MBR-only or raw-filesystem
/// image is not a thing to guess about.
pub(crate) fn unused_tail(head: &[u8], device_sectors: u64) -> Option<UnusedTail> {
    let hdr = head.get(512..512 + 92)?;
    if &hdr[0..8] != b"EFI PART" {
        return None;
    }
    let u32_at = |b: &[u8], o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
    };
    let u64_at = |b: &[u8], o: usize| -> Option<u64> {
        Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
    };
    let entries_lba = u64_at(hdr, 72)?;
    let count = u32_at(hdr, 80)?;
    let entry_size = u32_at(hdr, 84)?;
    // A malformed header must not turn into a huge read or a panic; these are
    // the sizes a real GPT uses, and anything outside them is not one.
    if !(128..=4096).contains(&entry_size) || !(1..=4096).contains(&count) {
        return None;
    }

    let base = usize::try_from(entries_lba.checked_mul(512)?).ok()?;
    let mut last_used_lba = 0u64;
    for i in 0..count as usize {
        let off = base.checked_add(i.checked_mul(entry_size as usize)?)?;
        let Some(e) = head.get(off..off + 48) else {
            break;
        };
        // An all-zero type GUID means the slot is empty.
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        last_used_lba = last_used_lba.max(u64_at(e, 40)?);
    }
    if last_used_lba == 0 {
        return None;
    }

    Some(UnusedTail {
        device_bytes: device_sectors.saturating_mul(512),
        // The last partition's final LBA is inclusive.
        used_bytes: last_used_lba.saturating_add(1).saturating_mul(512),
    })
}

/// True when `path` has data allocated anywhere in the primary GPT region.
///
/// The copy-on-write overlay is sparse, so a region the guest never wrote is a
/// hole. If the guest *has* written there, it rewrote its own partition table —
/// almost certainly by taking the advice below — and the base image's GPT no
/// longer describes what the guest sees. Reporting from a stale table would nag
/// a user who already fixed it, so stay quiet instead.
///
/// `SEEK_DATA` past the end, or a filesystem that does not support it, both
/// surface as an error, which is read as "no data" — the conservative direction
/// is to stay silent, never to invent a warning.
fn overlay_touched_gpt(path: &Path) -> bool {
    let Ok(f) = File::open(path) else {
        return false;
    };
    use std::os::unix::io::AsRawFd;
    // SAFETY: `lseek` takes a file descriptor and two scalars and touches no
    // memory. The descriptor is owned by `f`, which outlives the call, and a
    // negative return is handled below rather than trusted as an offset.
    let off = unsafe { libc::lseek(f.as_raw_fd(), 0, libc::SEEK_DATA) };
    off >= 0 && (off as u64) < PRIMARY_GPT_BYTES
}

/// The sequence that works, in the one order that works.
///
/// Order is load-bearing and was wrong until #284. `growpart` rewrites the GPT
/// on disk; `partx -u` is the step that carries a new table into an *already
/// running* kernel. Run `partx -u` first and it publishes the geometry the user
/// is trying to leave behind, `growpart` then changes the GPT with nothing left
/// to announce it, and `resize2fs` grows the filesystem to the kernel's
/// unchanged view and correctly reports `Nothing to do!`. Every step "succeeds"
/// and the disk is still full -- a silent no-op at the first thing a user does
/// with a rehydrated capture.
///
/// Measured on `graviton-vanilla-2cpu-net`: in this order the four commands take
/// `/` from 2.4G with 224M free to 6.8G with 4.6G free in a single pass, and
/// `partx -u` exits 0.
///
/// Kept as a function rather than restated at each call site so that the advice
/// `chm` prints and the sequence `docs/first-resume.md` documents cannot drift
/// apart -- a restated constant is how this repo has shipped disagreeing halves
/// before.
pub(crate) fn grow_sequence(dev: &str) -> String {
    format!(
        "sudo sgdisk -e {dev} && sudo growpart {dev} 1 \\\n\
         \x20 && sudo partx -u {dev} && sudo resize2fs {dev}1"
    )
}

/// The advice, kept in one place so a test can hold it to naming every command
/// the sequence actually needs.
pub(crate) fn grow_advice(dev: &str, tail: &UnusedTail) -> String {
    format!(
        "this capture's partition table leaves {} of its {} disk unused, so the guest's \
         root filesystem is smaller than the disk it sits on and may have no room to \
         install anything.\n\
         \n\
         chm cannot grow it from here -- rewriting the partition table and resizing a \
         mounted filesystem has to happen inside the guest. Run this there, once:\n\
         \n\
         \x20   {seq}\n\
         \n\
         `sgdisk -e` comes first because the backup GPT header is no longer at the end \
         of the device, and `growpart` refuses until it is. `partx -u` comes last of the \
         three because it is what tells the running kernel the table changed -- run \
         earlier it announces the old geometry and `resize2fs` finds nothing to do. \
         See docs/first-resume.md.",
        human_bytes(tail.unused_bytes()),
        human_bytes(tail.device_bytes),
        seq = grow_sequence(dev).replace('\n', "\n    "),
    )
}

/// Inspect every block device a capture declares and return the advice for the
/// first one with a materially unused tail.
pub(crate) fn tail_notice(dir: &Path, state_json: &str) -> Option<String> {
    let descs = parse_devices(state_json).ok()?;
    for d in &descs {
        let BackendKind::Block { nsectors, .. } = &d.backend else {
            continue;
        };
        let base = dir.join("disks").join(format!("{}.raw", d.name));
        let Ok(mut f) = File::open(&base) else {
            continue;
        };
        let mut head = vec![0u8; PRIMARY_GPT_BYTES as usize];
        if f.seek(SeekFrom::Start(0)).is_err() || f.read_exact(&mut head).is_err() {
            continue;
        }
        let Some(tail) = unused_tail(&head, *nsectors) else {
            continue;
        };
        if tail.unused_bytes() < REPORT_THRESHOLD {
            continue;
        }
        let overlay = dir
            .join(live_overlays_dir_name())
            .join(format!("{}-cow.raw", d.name));
        if overlay_touched_gpt(&overlay) {
            continue;
        }
        // The guest names the first virtio-blk device `vda` regardless of what
        // the capture host called it.
        return Some(grow_advice("/dev/vda", &tail));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but real GPT: protective MBR, header at LBA 1, entries
    /// at LBA 2, one partition ending at `last_lba`.
    fn gpt(last_lba: u64) -> Vec<u8> {
        let mut d = vec![0u8; PRIMARY_GPT_BYTES as usize];
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        d[512 + 80..512 + 84].copy_from_slice(&128u32.to_le_bytes());
        d[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        let e = 2 * 512;
        d[e..e + 16].copy_from_slice(&[0x0f; 16]);
        d[e + 32..e + 40].copy_from_slice(&2048u64.to_le_bytes());
        d[e + 40..e + 48].copy_from_slice(&last_lba.to_le_bytes());
        d
    }

    /// The measured case: `graviton-vanilla-2cpu-net` declares a disk far bigger
    /// than the partition its root filesystem lives in.
    #[test]
    fn the_unused_tail_is_the_gap_between_the_last_partition_and_the_device() {
        // 2.4 GiB partition on an 8 GiB device.
        let t = unused_tail(&gpt(5_033_950), 16_777_216).expect("a GPT is present");
        assert_eq!(t.device_bytes, 8 << 30);
        assert_eq!(t.used_bytes, 5_033_951 * 512);
        assert!(t.unused_bytes() > 5 << 30, "{}", t.unused_bytes());
    }

    /// After a successful grow the partition reaches the end, and a warning then
    /// would be pure noise.
    #[test]
    fn a_grown_partition_leaves_nothing_worth_reporting() {
        let t = unused_tail(&gpt(16_777_216 - 34), 16_777_216).expect("a GPT is present");
        assert!(t.unused_bytes() < REPORT_THRESHOLD, "{}", t.unused_bytes());
    }

    /// Empty entry slots must not be read as partitions ending at LBA 0, and a
    /// disk with no GPT at all is not something to guess about.
    #[test]
    fn a_disk_without_a_usable_gpt_is_not_guessed_at() {
        assert!(unused_tail(&vec![0u8; PRIMARY_GPT_BYTES as usize], 16_777_216).is_none());
        let mut only_empty_slots = gpt(5_000_000);
        only_empty_slots[1024..1024 + 16].fill(0);
        assert!(unused_tail(&only_empty_slots, 16_777_216).is_none());
        assert!(unused_tail(&[0u8; 16], 16_777_216).is_none());
    }

    /// A header claiming implausible geometry must not panic or turn into a
    /// gigantic read; an untrusted bundle ships this file.
    #[test]
    fn a_malformed_header_is_refused_rather_than_trusted() {
        let mut d = gpt(5_000_000);
        d[512 + 80..512 + 84].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unused_tail(&d, 16_777_216).is_none());
        let mut d = gpt(5_000_000);
        d[512 + 72..512 + 80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(unused_tail(&d, 16_777_216).is_none());
        let mut d = gpt(5_000_000);
        d[512 + 84..512 + 88].copy_from_slice(&1u32.to_le_bytes());
        assert!(unused_tail(&d, 16_777_216).is_none());
    }

    /// The advice is the entire value of the notice. `sgdisk -e` is the step
    /// nobody guesses, and leaving any one of the four out leaves the user
    /// stuck partway.
    #[test]
    fn the_advice_names_every_command_the_sequence_needs() {
        let a = grow_advice(
            "/dev/vda",
            &UnusedTail {
                device_bytes: 8 << 30,
                used_bytes: 2 << 30,
            },
        );
        for cmd in ["sgdisk -e", "partx -u", "growpart", "resize2fs"] {
            assert!(a.contains(cmd), "advice must name `{cmd}`: {a}");
        }
        assert!(a.contains("/dev/vda1"), "resize2fs takes the partition");
        assert!(a.contains("6.0 GiB"), "the size it can reclaim: {a}");
        assert!(
            a.contains("chm cannot grow it from here"),
            "say who has to act"
        );
    }

    /// Order is the whole of #284, and the test above stayed green through it:
    /// a check that every command is *named* structurally cannot see the one
    /// arrangement of those same four commands that silently does nothing.
    ///
    /// `growpart` changes the table, `partx -u` announces the change to a
    /// running kernel, `resize2fs` grows into what the kernel now believes. Any
    /// other order leaves a step talking about geometry that no longer -- or
    /// does not yet -- exist.
    #[test]
    fn the_advice_tells_the_kernel_after_it_changes_the_table() {
        let s = grow_sequence("/dev/vda");
        let at = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}: {s}"));
        let (sgdisk, growpart, partx, resize) = (
            at("sgdisk -e"),
            at("growpart"),
            at("partx -u"),
            at("resize2fs"),
        );
        assert!(
            sgdisk < growpart,
            "growpart refuses until the backup header moves: {s}"
        );
        assert!(
            growpart < partx,
            "partx -u before growpart publishes the geometry being replaced, and \
             resize2fs then reports `Nothing to do!`: {s}"
        );
        assert!(
            partx < resize,
            "resize2fs grows into the kernel's view, so the kernel has to be told first: {s}"
        );
    }

    /// The guest-facing documentation prints the same four commands, and a user
    /// following the doc instead of the notice must not get a different answer.
    /// Comparing against the function rather than against a copied literal is
    /// what makes that true by construction: this repo has shipped an app and an
    /// engine disagreeing about a restated constant more than once.
    #[test]
    fn the_documented_sequence_is_the_one_chm_prints() {
        let doc = include_str!("../../docs/first-resume.md");
        let seq = grow_sequence("/dev/vda");
        assert!(
            doc.contains(&seq),
            "docs/first-resume.md must carry this sequence verbatim:\n{seq}"
        );
    }

    /// Every check in this module is about a *value*, and a value says nothing
    /// about whether anyone asks for it. Dropping the call from `run` or `serve`
    /// leaves all of the above green -- the call-site class this repo has been
    /// caught by five times. Needles are assembled from parts so they cannot
    /// match this assertion's own text.
    #[test]
    fn both_entry_points_actually_ask_for_the_notice() {
        let needle = format!("disktail::tail_{}(dir, &loaded.state_json)", "notice");
        for (name, src) in [
            ("chm run", include_str!("imp.rs")),
            ("chm serve", include_str!("serve.rs")),
        ] {
            assert!(
                src.contains(&needle),
                "{name} must consult the room-to-grow check on resume"
            );
        }
    }

    /// A hole in the overlay is not a rewritten partition table, and a byte
    /// written there is.
    #[test]
    fn an_overlay_that_rewrote_the_partition_table_silences_the_notice() {
        let d = std::env::temp_dir().join(format!("chm-disktail-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();

        let absent = d.join("absent.raw");
        assert!(!overlay_touched_gpt(&absent), "no overlay yet");

        let sparse = d.join("sparse.raw");
        let f = File::create(&sparse).unwrap();
        f.set_len(1 << 20).unwrap();
        assert!(!overlay_touched_gpt(&sparse), "all holes");

        let written = d.join("written.raw");
        std::fs::write(&written, vec![7u8; PRIMARY_GPT_BYTES as usize]).unwrap();
        assert!(
            overlay_touched_gpt(&written),
            "the GPT region was rewritten"
        );

        std::fs::remove_dir_all(&d).ok();
    }
}
