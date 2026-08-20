//! Writing a Mac-advanced lineage back out as a **vanilla** Cloud Hypervisor
//! capture (#353).
//!
//! Everything else in this tree reads a vanilla capture and never writes one,
//! which is what makes the dream one-way: a snapshot comes down from the cloud,
//! runs here, and whatever the guest did on this Mac can never go back. This
//! module closes the loop, and it does it without a Linux host, a KVM ioctl or
//! a QEMU anywhere in the path -- the state it writes was captured from a live
//! Apple Hypervisor.framework vCPU.
//!
//! # Why this is patching, not synthesis
//!
//! The input is **this lineage's own ancestor**. [`checkpoint::symlink_base`]
//! links the base capture's `state.json` into every workspace, so a workspace
//! advanced on a Mac still holds, byte for byte, the `state.json` that AWS
//! wrote. The export starts from those bytes and overwrites only the fields a
//! Mac genuinely re-measured:
//!
//! | field | source | why |
//! | --- | --- | --- |
//! | per-vCPU `core_regs`, `sys_regs` | the checkpoint | HVF captured them |
//! | top-level `clock` | the checkpoint's wall clock | time passed |
//! | everything else | the ancestor, untouched | invariant after boot |
//!
//! That last row is a measurement, not an assumption. Virtio queue addresses
//! and negotiated features are established at boot and `chm` cannot hotplug, so
//! the machine's static shape is the shape the cloud captured. The virtqueue
//! *cursors* need no carrying either: cloud-hypervisor's `state.json` has no
//! `last_avail_idx` field anywhere, because the rings live in guest RAM and RAM
//! is exported whole.
//!
//! Synthesising a `state.json` instead would mean writing every field this
//! build happens to model and zeroing every field it does not -- and the fields
//! it does not model are exactly the ones nobody would notice were missing.
//!
//! # What this export cannot carry, said out loud
//!
//! One thing, reported by name in [`Report::warnings`] rather than discovered
//! later by a confused guest:
//!
//! - **In-flight interrupt state.** `gic-v3-its` is carried from the ancestor.
//!   The ITS tables and register bases are boot-time facts, but a *pending*
//!   interrupt raised on this Mac is not represented in the KVM ITS table
//!   format we would have to write.
//!
//! It is not silent, and it is not guessed at.
//!
//! Floating-point / SIMD registers used to be the other entry here. HVF does
//! expose them -- through a getter and a setter with an ABI sharp enough to
//! need its own trampoline, see `hvf::ffi::set_simd_fp_reg` -- and #357 wired
//! them through, so `core_regs` offset 336 is now written from the live vCPU
//! rather than left at the ancestor's. The old caveat argued the staleness was
//! harmless because Linux keeps a descheduled task's FP state in RAM. That is
//! true and was never the whole picture: the task running *at* the instant of
//! capture has its state in the registers and nowhere else.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hypervisor::hvf::checkpoint::CheckpointState;
use hypervisor::hvf::{SYSREG_CNTV_CTL_EL0, SYSREG_CNTV_CVAL_EL0};
use hypervisor::hvf::translate::{self, kvm_ingest, lower_to_kvm};

use crate::bundle::clone_file;
use crate::checkpoint::read_checkpoint;
use crate::vanilla::{Clock, VanillaState};
#[cfg(test)]
use crate::vanilla::CORE_REGS_LEN;

/// The sector a CoW overlay's bitmap indexes. One bit per sector, packed into
/// little-endian `u64` words -- read from the overlay backend rather than
/// chosen here, because the two must agree exactly.
const SECTOR_BYTES: u64 = 512;

/// Cap on a single coalesced overlay read/write. A fully-written 8 GiB disk is
/// 16.7 million set bits; copying them one sector at a time would be 16.7
/// million syscalls, and copying them in one allocation would be 8 GiB of RAM.
const MAX_RUN_BYTES: u64 = 8 * 1024 * 1024;

/// What an export did, so the caller can print it and a test can assert on it.
pub(crate) struct Report {
    pub vcpus: usize,
    /// Paths within `state.json` whose value differs from the ancestor's,
    /// computed by [`VanillaState::changed_paths`]. The differential guard:
    /// this list should hold vCPU registers and the clock, and nothing else.
    pub changed_paths: Vec<String>,
    /// State this export could not carry, each named with its consequence.
    pub warnings: Vec<String>,
    pub ram_bytes: u64,
    /// `(disk file name, sectors patched from the overlay)`.
    pub disks: Vec<(String, u64)>,
    /// One line per exported vCPU, read back out of the document after it was
    /// written. A misaligned offset or a byte-order slip produces a `pc` of
    /// zero or a wild address, and that is visible at a glance in a way a
    /// count of written registers is not -- so this is the cheapest check a
    /// person can make on an export before trusting it to the cloud.
    pub vcpu_summaries: Vec<String>,
}

/// Export the workspace's current HEAD checkpoint as a vanilla capture in
/// `out`, which must not already exist.
pub(crate) fn export(workspace: &Path, out: &Path) -> Result<Report, String> {
    let base_state = workspace.join("snapshot").join("state.json");
    let base_config = workspace.join("snapshot").join("config.json");
    if !base_state.exists() {
        return Err(format!(
            "{} has no snapshot/state.json, so it is not a snapshot workspace.\n\
             A vanilla export rewrites this lineage's own ancestor; without it \
             there is nothing to rewrite.",
            workspace.display()
        ));
    }
    let ckpt_dir = workspace.join(".chm-checkpoint");
    let ckpt_ram = ckpt_dir.join("memory-ranges");
    if !ckpt_ram.exists() {
        return Err(format!(
            "{} has no checkpoint to export.\n\
             Run the guest and suspend it (or `chm run --checkpoint`) first: \
             an export writes the state a Mac captured, and there is none yet.",
            workspace.display()
        ));
    }
    if out.exists() {
        return Err(format!(
            "{} already exists; refusing to write into it.",
            out.display()
        ));
    }

    let state = read_checkpoint(workspace)?;
    let mut doc = VanillaState::parse(
        &fs::read(&base_state).map_err(|e| format!("read {}: {e}", base_state.display()))?,
    )
    .map_err(|e| format!("{}: {e}", base_state.display()))?;
    let ancestor = doc.clone();

    let mut warnings = Vec::new();
    let mut vcpu_summaries = Vec::new();
    let vcpus = patch_vcpus(&mut doc, &state, &mut warnings, &mut vcpu_summaries)?;
    patch_clock(&mut doc, &state, &ancestor)?;

    warnings.push(
        "gic-v3-its is the ancestor's: interrupts in flight on this Mac at the \
         instant of capture are not carried. The ITS tables and register bases \
         are boot-time facts and are correct."
            .to_string(),
    );

    // Everything above can fail; nothing below has written a byte yet.
    let snap_out = out.join("snapshot");
    fs::create_dir_all(&snap_out).map_err(|e| format!("create {}: {e}", snap_out.display()))?;
    let bytes = doc
        .to_bytes()
        .map_err(|e| format!("serialize state.json: {e}"))?;
    // Both copies, because that is the shape a real capture has: the tarball
    // ships `snapshot/state.json` and an identical `state.json` at the root,
    // and `chm`'s own REQUIRED_BASE reads the root one.
    for p in [out.join("state.json"), snap_out.join("state.json")] {
        fs::write(&p, &bytes).map_err(|e| format!("write {}: {e}", p.display()))?;
    }
    if base_config.exists() {
        fs::copy(&base_config, snap_out.join("config.json"))
            .map_err(|e| format!("copy config.json: {e}"))?;
    }

    let ram_out = snap_out.join("memory-ranges");
    copy_or_clone(&ckpt_ram, &ram_out)?;
    let ram_bytes = fs::metadata(&ram_out)
        .map_err(|e| format!("stat {}: {e}", ram_out.display()))?
        .len();

    let disks = flatten_disks(workspace, &ckpt_dir, out)?;

    Ok(Report {
        vcpus,
        changed_paths: doc.changed_paths(&ancestor),
        warnings,
        ram_bytes,
        disks,
        vcpu_summaries,
    })
}

/// Overwrite each vCPU's register block with what HVF captured.
///
/// The HVF -> KVM lowering is [`translate::lower_to_kvm`], which already exists
/// and is exercised by a hardware round-trip test. Reusing it rather than
/// writing a second mapping here is the point: two implementations of one ABI
/// eventually disagree, and the disagreement would be invisible until a guest
/// resumed wrong in the cloud.
fn patch_vcpus(
    doc: &mut VanillaState,
    state: &CheckpointState,
    warnings: &mut Vec<String>,
    summaries: &mut Vec<String>,
) -> Result<usize, String> {
    let ids = doc.vcpu_ids();
    if ids.len() != state.vcpus.len() {
        return Err(format!(
            "the ancestor declares {} vCPU(s) but the checkpoint captured {}.\n\
             A vanilla export rewrites the ancestor's own machine; it cannot \
             change its shape.",
            ids.len(),
            state.vcpus.len()
        ));
    }

    let mut refused_sys = 0usize;
    let mut refused_core = 0usize;
    for (i, id) in ids.iter().enumerate() {
        let id = *id;
        let mut vcpu = doc
            .vcpu(id)
            .map_err(|e| format!("read vCPU {id} from the ancestor: {e}"))?;
        let hvf = &state.vcpus[i].state;
        let kvm = lower_to_kvm(hvf);

        for &(reg_id, value) in &kvm.core {
            match translate::kvm_core_reg_offset(reg_id) {
                Some(off) if vcpu.set_core_reg(off, value) => {}
                _ => refused_core += 1,
            }
        }
        for &(reg_id, value) in &kvm.sys {
            if !vcpu.set_sys_reg(reg_id, value) {
                refused_sys += 1;
            }
        }
        // The SIMD&FP block travels beside the id list, not inside it: a
        // `ONE_REG` core id is fixed at `KVM_REG_SIZE_U64`, so there is no id
        // that names a 128-bit vector register or a 32-bit `fpsr`/`fpcr`.
        //
        // Skipping it would leave the ancestor's bytes -- which was the
        // documented behaviour until #357, and was wrong for exactly the same
        // reason #257 was: state we did not carry came back as something else's.
        // Every capture measured here has live FP state (up to 25 of 32 vector
        // registers non-zero, `fpsr = 0x10` meaning real arithmetic raised
        // IXC), so the ancestor's bytes describe the guest as it was at
        // *capture*, not as it is now.
        //
        // `None` means the HVF state predates the field, so there is nothing to
        // write and the ancestor's bytes remain the best answer available.
        if let Some(fp) = &kvm.fp {
            for (i, v) in fp.vregs.iter().enumerate() {
                if !vcpu.set_core_bytes(translate::kvm_fp_vreg_offset(i), v) {
                    refused_core += 1;
                }
            }
            if !vcpu.set_core_bytes(translate::OFF_FPSR, &fp.fpsr.to_le_bytes()) {
                refused_core += 1;
            }
            if !vcpu.set_core_bytes(translate::OFF_FPCR, &fp.fpcr.to_le_bytes()) {
                refused_core += 1;
            }
        }
        // A vCPU that PSCI-parked itself must come back parked, or the cloud
        // would start executing a core the guest believes is off. The constant
        // comes from `kvm_ingest`, which sits beside the read that consumes it,
        // rather than being retyped here -- on aarch64 STOPPED is 5, and the
        // 3 that looks right is x86's HALTED.
        vcpu.mp_state = kvm_ingest::kvm_mp_state_for(hvf.mp_state_running);

        doc.set_vcpu(id, &vcpu)
            .map_err(|e| format!("write vCPU {id}: {e}"))?;

        // Read back out of the document rather than off the local value, so
        // the summary describes what was actually stored.
        let w = doc
            .vcpu(id)
            .map_err(|e| format!("read back vCPU {id}: {e}"))?;
        // The virtual timer is read back by name because losing it is not a
        // hypothetical: an unwritten `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` pair is
        // exactly the defect that killed a vCPU's tick for eight months
        // (#257), and `0x4/0x0` is its signature. An export that reproduced it
        // would hand the cloud a guest whose clock never ticks again.
        let ctl = w
            .sys_reg(translate::kvm_sysreg_id(SYSREG_CNTV_CTL_EL0))
            .unwrap_or(0);
        let cval = w
            .sys_reg(translate::kvm_sysreg_id(SYSREG_CNTV_CVAL_EL0))
            .unwrap_or(0);
        if ctl & 1 == 0 && cval == 0 {
            warnings.push(format!(
                "vcpu {id} exports with its virtual timer disabled and no \
                 deadline (CNTV_CTL={ctl:#x}, CNTV_CVAL=0). That guest will \
                 not tick when the cloud resumes it. See #257."
            ));
        }
        summaries.push(format!(
            "vcpu {id}: pc={:#018x} pstate={:#010x} sp={:#018x} sp_el1={:#018x} \
             elr_el1={:#018x} spsr0={:#010x} x0={:#018x} mp_state={} \
             cntv_ctl={ctl:#x} cntv_cval={cval:#x} core_regs={}B",
            w.pc(),
            w.pstate(),
            w.sp(),
            w.sp_el1(),
            w.elr_el1(),
            w.spsr(0).unwrap_or(0),
            w.x(0).unwrap_or(0),
            w.mp_state,
            w.core_bytes().len(),
        ));
    }

    // Refusals are expected and benign in one direction only: HVF's curated
    // capture list is a *subset* of the ~234 registers a capture carries, so
    // every register we hold should have a home. One that does not means the
    // two lists have diverged, which is worth a sentence rather than silence.
    if refused_sys > 0 {
        warnings.push(format!(
            "{refused_sys} captured system register(s) are not carried by the \
             ancestor's ONE_REG list and were not written. The cloud will \
             restore the ancestor's values for those."
        ));
    }
    // KVM keeps the ICC (CPU interface) state in the VGIC *device* state, not
    // in a vCPU's ONE_REG list, so there is no field in a vanilla vCPU entry
    // to put it in. Named rather than dropped, because a silently discarded
    // interrupt-controller register is exactly the class of loss that took
    // eight months to find in #257.
    if !state.vcpus.is_empty() {
        warnings.push(
            "per-vCPU GIC CPU-interface (ICC) registers: a vanilla vCPU entry \
             has no field for them, so the ancestor's `gic-v3-its` device \
             state is carried unchanged."
                .to_string(),
        );
    }
    if refused_core > 0 {
        warnings.push(format!(
            "{refused_core} captured core register(s) did not map into the \
             ancestor's 864-byte kvm_regs block and were not written."
        ));
    }
    Ok(ids.len())
}

/// Rewrite the top-level clock so the exported capture describes the instant
/// the Mac suspended, not the instant AWS captured.
///
/// `CheckpointState` records the host wall clock and nothing else -- `chm`
/// never stores an absolute guest counter, because the guest's counter is
/// derived from the host's minus an offset. So the guest counter is
/// reconstructed from the two facts we do have: where the ancestor's counter
/// was, and how much real time has passed since. That advance across the
/// suspended interval is deliberate and already shipped (a resumed guest's
/// uptime includes the pause), so reporting it here keeps the exported capture
/// agreeing with the guest that will read it.
///
/// `cntfrq` is untouched on purpose: it is the guest's latched belief about its
/// hardware, established at boot, and not ours to revise.
fn patch_clock(
    doc: &mut VanillaState,
    state: &CheckpointState,
    ancestor: &VanillaState,
) -> Result<(), String> {
    let Some(now_ns) = state.host_realtime_ns else {
        return Err(
            "this checkpoint predates the host_realtime_ns field, so the \
             instant it was taken is unknown and the exported clock would be \
             the ancestor's. Take a fresh checkpoint and export that."
                .to_string(),
        );
    };
    let base: Clock = ancestor
        .clock()
        .map_err(|e| format!("read the ancestor's clock: {e}"))?;
    let elapsed_ns = now_ns.saturating_sub(base.host_realtime_ns);
    let ticks = (u128::from(elapsed_ns) * u128::from(base.cntfrq)) / 1_000_000_000u128;
    let cntvct = base.cntvct.saturating_add(ticks.try_into().unwrap_or(u64::MAX));
    doc.set_capture_instant(cntvct, now_ns)
        .map_err(|e| format!("write the clock: {e}"))
}

/// Write each disk as a single flat image: the ancestor's base, with the
/// sectors this Mac wrote laid over it.
///
/// The base is cloned rather than copied, so a 8 GiB disk costs kilobytes until
/// the overlay is patched into it.
fn flatten_disks(
    workspace: &Path,
    ckpt_dir: &Path,
    out: &Path,
) -> Result<Vec<(String, u64)>, String> {
    let disks_in = workspace.join("disks");
    if !disks_in.is_dir() {
        return Ok(Vec::new());
    }
    let disks_out = out.join("disks");
    fs::create_dir_all(&disks_out).map_err(|e| format!("create {}: {e}", disks_out.display()))?;

    let mut names: Vec<PathBuf> = fs::read_dir(&disks_in)
        .map_err(|e| format!("read {}: {e}", disks_in.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    names.sort();

    let mut report = Vec::new();
    for base in names {
        let name = base
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dest = disks_out.join(&name);
        copy_or_clone(&base, &dest)?;

        // `disks/_disk0.raw` is overlaid by `overlays/_disk0-cow.raw`. The
        // bitmap is the authority on what was written; its *absence* is the
        // authority that nothing was, because `OverlayBackend::open` removes
        // the sidecar whenever it starts a fresh overlay. A read-only disk
        // never grows one.
        let stem = name.strip_suffix(".raw").unwrap_or(&name);
        let overlay = ckpt_dir.join("overlays").join(format!("{stem}-cow.raw"));
        let bitmap = ckpt_dir
            .join("overlays")
            .join(format!("{stem}-cow.raw.bitmap"));
        let patched = if overlay.is_file() && bitmap.is_file() {
            patch_from_overlay(&overlay, &bitmap, &dest)?
        } else {
            0
        };
        report.push((name, patched));
    }
    Ok(report)
}

/// Copy each sector the bitmap marks written from `overlay` into `dest`.
/// Returns the number of sectors copied.
fn patch_from_overlay(overlay: &Path, bitmap: &Path, dest: &Path) -> Result<u64, String> {
    let bits = fs::read(bitmap).map_err(|e| format!("read {}: {e}", bitmap.display()))?;
    let mut src = File::open(overlay).map_err(|e| format!("open {}: {e}", overlay.display()))?;
    let mut dst = OpenOptions::new()
        .write(true)
        .open(dest)
        .map_err(|e| format!("open {}: {e}", dest.display()))?;
    let overlay_sectors = src
        .metadata()
        .map_err(|e| format!("stat {}: {e}", overlay.display()))?
        .len()
        / SECTOR_BYTES;

    let mut copied = 0u64;
    let mut buf = Vec::new();
    let mut run: Option<(u64, u64)> = None; // (first sector, count)

    let max_run = MAX_RUN_BYTES / SECTOR_BYTES;
    for (w, word) in bits.chunks_exact(8).enumerate() {
        let mut bits64 = u64::from_le_bytes(word.try_into().unwrap_or([0; 8]));
        if bits64 == 0 {
            flush_run(&mut run, &mut buf, &mut src, &mut dst)?;
            continue;
        }
        while bits64 != 0 {
            let b = bits64.trailing_zeros() as u64;
            bits64 &= bits64 - 1;
            let sector = w as u64 * 64 + b;
            // A bitmap longer than the overlay is a mismatch, not a request.
            if sector >= overlay_sectors {
                flush_run(&mut run, &mut buf, &mut src, &mut dst)?;
                return Ok(copied);
            }
            copied += 1;
            run = match run {
                Some((start, count)) if start + count == sector && count < max_run => {
                    Some((start, count + 1))
                }
                other => {
                    if other.is_some() {
                        let mut r = other;
                        flush_run(&mut r, &mut buf, &mut src, &mut dst)?;
                    }
                    Some((sector, 1))
                }
            };
        }
    }
    flush_run(&mut run, &mut buf, &mut src, &mut dst)?;
    Ok(copied)
}

/// Copy one coalesced run of sectors from the overlay onto the flattened disk.
fn flush_run(
    run: &mut Option<(u64, u64)>,
    buf: &mut Vec<u8>,
    src: &mut File,
    dst: &mut File,
) -> Result<(), String> {
    let Some((start, count)) = run.take() else {
        return Ok(());
    };
    buf.resize((count * SECTOR_BYTES) as usize, 0);
    let off = start * SECTOR_BYTES;
    src.seek(SeekFrom::Start(off))
        .and_then(|_| src.read_exact(buf))
        .map_err(|e| format!("read overlay at sector {start}: {e}"))?;
    dst.seek(SeekFrom::Start(off))
        .and_then(|_| dst.write_all(buf))
        .map_err(|e| format!("write disk at sector {start}: {e}"))?;
    Ok(())
}

/// Clone if the filesystem can, copy if it cannot. A 2 GiB RAM dump and an
/// 8 GiB disk are both free on APFS and both expensive anywhere else, and the
/// export is correct either way.
fn copy_or_clone(src: &Path, dest: &Path) -> Result<(), String> {
    if clone_file(src, dest).is_ok() {
        return Ok(());
    }
    fs::copy(src, dest)
        .map(|_| ())
        .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dest.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypervisor::hvf::{VcpuFpState, FP_VREG_COUNT};

    fn bitmap_with(sectors: &[u64], words: usize) -> Vec<u8> {
        let mut w = vec![0u64; words];
        for &s in sectors {
            w[(s / 64) as usize] |= 1 << (s % 64);
        }
        w.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// The load-bearing property of the disk flatten: exactly the sectors the
    /// bitmap names come from the overlay, and every other sector is still the
    /// base's. A test that only checked file length would pass while the guest
    /// filesystem was silently wrong.
    #[test]
    fn only_the_sectors_the_bitmap_names_are_overlaid() {
        let dir = std::env::temp_dir().join(format!("vx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let n = 128usize;
        let base: Vec<u8> = (0..n).flat_map(|i| vec![b'B'; 512].into_iter().map(move |_| (i as u8).wrapping_add(1))).collect();
        let over: Vec<u8> = (0..n).flat_map(|i| vec![0u8; 512].into_iter().map(move |_| (i as u8).wrapping_add(200))).collect();
        let dest = dir.join("d.raw");
        fs::write(&dest, &base).unwrap();
        fs::write(dir.join("o.raw"), &over).unwrap();
        let written = [0u64, 3, 4, 5, 70, 127];
        fs::write(dir.join("o.bitmap"), bitmap_with(&written, 2)).unwrap();

        let copied =
            patch_from_overlay(&dir.join("o.raw"), &dir.join("o.bitmap"), &dest).unwrap();
        assert_eq!(copied, written.len() as u64);

        let got = fs::read(&dest).unwrap();
        for s in 0..n as u64 {
            let want = if written.contains(&s) { &over } else { &base };
            let a = (s * 512) as usize;
            assert_eq!(
                &got[a..a + 512],
                &want[a..a + 512],
                "sector {s} came from the wrong file"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Contiguous set bits must be coalesced into one read/write, but the
    /// coalescing must not run past a gap -- the bug that would silently drag
    /// unwritten overlay sectors (zeros) over live base data.
    #[test]
    fn a_gap_in_the_bitmap_breaks_the_run() {
        let dir = std::env::temp_dir().join(format!("vxg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let n = 64usize;
        let base = vec![b'B'; n * 512];
        let over = vec![b'O'; n * 512];
        let dest = dir.join("d.raw");
        fs::write(&dest, &base).unwrap();
        fs::write(dir.join("o.raw"), &over).unwrap();
        // Two runs with a hole at sector 2.
        fs::write(dir.join("o.bitmap"), bitmap_with(&[0, 1, 3, 4], 1)).unwrap();

        patch_from_overlay(&dir.join("o.raw"), &dir.join("o.bitmap"), &dest).unwrap();
        let got = fs::read(&dest).unwrap();
        assert_eq!(&got[0..1024], &over[0..1024], "run 0..1 should be overlaid");
        assert_eq!(
            &got[1024..1536],
            &base[1024..1536],
            "sector 2 is not in the bitmap and must keep the base's bytes"
        );
        assert_eq!(
            &got[1536..2560],
            &over[1536..2560],
            "run 3..4 should be overlaid"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A bitmap that claims more sectors than the overlay holds is a format
    /// disagreement. Reading past the end would either fail or, worse, succeed
    /// against a short read and write garbage.
    #[test]
    fn a_bitmap_longer_than_the_overlay_stops_rather_than_reading_past_it() {
        let dir = std::env::temp_dir().join(format!("vxl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("d.raw");
        fs::write(&dest, vec![b'B'; 4 * 512]).unwrap();
        fs::write(dir.join("o.raw"), vec![b'O'; 4 * 512]).unwrap();
        fs::write(dir.join("o.bitmap"), bitmap_with(&[0, 1, 9], 1)).unwrap();

        let copied =
            patch_from_overlay(&dir.join("o.raw"), &dir.join("o.bitmap"), &dest).unwrap();
        assert_eq!(copied, 2, "only the in-range sectors should be copied");
        let got = fs::read(&dest).unwrap();
        assert_eq!(&got[0..1024], &vec![b'O'; 1024][..]);
        assert_eq!(&got[1024..2048], &vec![b'B'; 1024][..]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The counter advances at the guest's own frequency over the real time
    /// that passed -- asserted by driving the real [`patch_clock`] and reading
    /// the result back out of the document.
    ///
    /// The previous version of this guard restated the arithmetic in its own
    /// body and asserted against its restatement, so it agreed with itself no
    /// matter what the product did. Four separate mutations -- never advancing,
    /// computing at nanosecond rate, exporting a checkpoint with no capture
    /// instant, and writing the base counter back -- all left it green. A guard
    /// that cannot fail also reports safety it does not provide.
    ///
    /// `cntfrq` is read from the fixture rather than typed here, so this cannot
    /// pass by agreeing with a constant that drifted.
    #[test]
    fn the_exported_counter_advances_at_the_guests_frequency() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let ancestor = VanillaState::parse(&bytes).unwrap();
        let base = ancestor.clock().expect("the fixture carries a clock");
        assert!(base.cntfrq > 0, "the fixture must name a frequency");

        for secs in [1u64, 3, 18 * 24 * 3600] {
            let mut doc = VanillaState::parse(&bytes).unwrap();
            let now = base.host_realtime_ns + secs * 1_000_000_000;
            let st = CheckpointState {
                version: 1,
                host_realtime_ns: Some(now),
                ..Default::default()
            };
            patch_clock(&mut doc, &st, &ancestor).expect("the clock must be writable");

            let got = doc.clock().unwrap();
            let want = base.cntvct + secs * base.cntfrq;
            assert_eq!(got.cntvct, want, "after {secs}s the counter must advance by secs*cntfrq");
            assert_eq!(got.host_realtime_ns, now, "the capture instant must be the checkpoint's");
            assert_eq!(
                got.cntfrq, base.cntfrq,
                "the frequency is the guest's belief and must never be rewritten"
            );
        }
    }

    /// A checkpoint that cannot say when it was taken must be refused, not
    /// exported with the ancestor's clock.
    ///
    /// Silently shipping the ancestor's instant would hand the cloud a guest
    /// whose counter disagrees with its own wall clock by however long the
    /// lineage has been on this Mac -- days, in the fixture this targets. TLS
    /// handshakes and apt both fail on that, and both blame the network.
    #[test]
    fn a_checkpoint_with_no_capture_instant_is_refused() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let ancestor = VanillaState::parse(&bytes).unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let st = CheckpointState { version: 1, host_realtime_ns: None, ..Default::default() };
        let err = patch_clock(&mut doc, &st, &ancestor).expect_err("must refuse");
        assert!(err.contains("host_realtime_ns"), "the refusal must name the field: {err}");
        assert_eq!(
            doc.to_bytes().unwrap(),
            ancestor.to_bytes().unwrap(),
            "a refused clock write must leave the document untouched"
        );
    }

    /// The writer's `mp_state` must be the value the reader will understand.
    ///
    /// Asserted by round-tripping through the real `snapshot_json_to_hvf`
    /// rather than by comparing two constants, because comparing constants is
    /// how a mirror agrees with itself. This drove out a live bug: the writer
    /// had `STOPPED = 3` typed from memory, which is x86's `HALTED`; on aarch64
    /// it is 5, so a PSCI-parked core would have exported as *runnable* and the
    /// cloud would have started executing a core the guest believes is off.
    #[test]
    fn a_parked_vcpu_survives_the_writer_and_the_reader_agreeing() {
        for running in [true, false] {
            let mp = kvm_ingest::kvm_mp_state_for(running);
            let json = format!(
                r#"{{"Kvm":{{"mp_state":[{},0,0,0],"core_regs":[{}],"sys_regs":[]}}}}"#,
                mp,
                vec!["0"; CORE_REGS_LEN].join(",")
            );
            let back = kvm_ingest::snapshot_json_to_hvf(&json)
                .expect("the reader must accept what the writer emits");
            assert_eq!(
                back.mp_state_running, running,
                "writer emitted mp_state={mp} for running={running}, and the \
                 reader read it back as running={}",
                back.mp_state_running
            );
        }
        assert_ne!(
            kvm_ingest::kvm_mp_state_for(false),
            3,
            "3 is x86's KVM_MP_STATE_HALTED; aarch64's STOPPED is 5"
        );
    }

    /// Build a checkpoint whose vCPUs carry a live, armed virtual timer, in the
    /// same shape [`CheckpointState`] really has.
    #[cfg(test)]
    fn checkpoint_with_vtimer(n: usize, ctl: u64, cval: u64) -> CheckpointState {
        use hypervisor::hvf::checkpoint::VcpuCheckpoint;
        use hypervisor::hvf::VcpuHvfState;
        let mut st = CheckpointState { version: 1, ..Default::default() };
        for i in 0..n {
            let mut v = VcpuHvfState { mp_state_running: true, ..Default::default() };
            v.pc = 0xffff_8000_0000_0000 + i as u64 * 0x1000;
            v.sysregs = vec![
                (SYSREG_CNTV_CVAL_EL0, cval),
                (SYSREG_CNTV_CTL_EL0, ctl),
            ];
            st.vcpus.push(VcpuCheckpoint { state: v, rdist: Vec::new() });
        }
        st
    }

    /// The virtual timer must survive the whole lowering path and be readable
    /// back out of the written document.
    ///
    /// This is the register pair whose loss disabled a vCPU's tick for eight
    /// months (#257). It travels HVF sysreg -> `lower_to_kvm` -> ONE_REG id ->
    /// `set_sys_reg` -> document, and *every* one of those steps could drop it
    /// silently, because a refused write is just a counter here. Asserting the
    /// value comes back out is the only step that spans all of them.
    #[test]
    fn the_virtual_timer_reaches_the_exported_document() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let cp = checkpoint_with_vtimer(2, 0x1, 0x0dad_beef_0000);
        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).expect("the patch must apply");

        for id in doc.vcpu_ids() {
            let v = doc.vcpu(id).unwrap();
            assert_eq!(
                v.sys_reg(translate::kvm_sysreg_id(SYSREG_CNTV_CVAL_EL0)),
                Some(0x0dad_beef_0000),
                "vcpu {id} lost CNTV_CVAL_EL0 on the way out"
            );
            assert_eq!(
                v.sys_reg(translate::kvm_sysreg_id(SYSREG_CNTV_CTL_EL0)),
                Some(0x1),
                "vcpu {id} lost CNTV_CTL_EL0 on the way out"
            );
        }
        assert!(
            !warns.iter().any(|w| w.contains("#257")),
            "an armed timer must not be reported as lost: {warns:?}"
        );
    }

    /// ...and when it genuinely is missing, the export says so by name rather
    /// than shipping a guest that will never tick again in the cloud.
    #[test]
    fn an_export_that_lost_the_virtual_timer_refuses_to_be_quiet() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        // 0x4/0x0 is the signature of an unwritten register: ISTATUS computed
        // against a zero comparator, ENABLE clear. Not a state a guest asks for.
        let cp = checkpoint_with_vtimer(2, 0x4, 0x0);
        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).unwrap();
        assert_eq!(
            warns.iter().filter(|w| w.contains("#257")).count(),
            2,
            "both vCPUs must be named, got: {warns:?}"
        );
    }

    /// The summary reports what the document holds, not what the caller passed.
    ///
    /// It exists to be read by a person deciding whether to trust an export, so
    /// a summary sourced from the input would agree with itself no matter what
    /// the write did -- the mirror failure this repo has recorded twice (#178,
    /// #180).
    #[test]
    fn the_vcpu_summary_describes_what_was_actually_stored() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let cp = checkpoint_with_vtimer(2, 0x1, 0xfeed);
        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).unwrap();
        assert_eq!(sums.len(), 2, "one line per vCPU");
        for (i, line) in sums.iter().enumerate() {
            let want_pc = format!("{:#018x}", 0xffff_8000_0000_0000u64 + i as u64 * 0x1000);
            assert!(line.contains(&want_pc), "line {i} lost the pc it stored: {line}");
            assert!(line.contains("cntv_ctl=0x1"), "line {i}: {line}");
            assert!(line.contains(&format!("core_regs={CORE_REGS_LEN}B")), "line {i}: {line}");
        }
    }

    /// A PSCI-parked vCPU must be *exported* parked -- asserted through the real
    /// export path, not through the constant helper.
    ///
    /// The sibling test proves `kvm_mp_state_for` itself round-trips. It cannot
    /// see a `patch_vcpus` that stopped calling it, and mutation showed exactly
    /// that: retyping x86's HALTED at the call site left the sibling green.
    /// That is the call-site class this repo has recorded eight times now, so
    /// this guard reads the value back out of the written document.
    #[test]
    fn a_parked_vcpu_is_exported_parked() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let mut cp = checkpoint_with_vtimer(2, 0x1, 0x1000);
        cp.vcpus[1].state.mp_state_running = false;
        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).unwrap();

        let ids = doc.vcpu_ids();
        let running = doc.vcpu(ids[0]).unwrap().mp_state;
        let parked = doc.vcpu(ids[1]).unwrap().mp_state;
        assert_eq!(running, 0, "a running vCPU must export as KVM_MP_STATE_RUNNABLE");
        assert_ne!(parked, 3, "3 is x86's HALTED; on aarch64 STOPPED is 5");
        assert_eq!(parked, 5, "a parked vCPU must export as KVM_MP_STATE_STOPPED");

        // ...and the reader that consumes this must agree with what was stored.
        for (id, want) in [(ids[0], true), (ids[1], false)] {
            let m = doc.vcpu(id).unwrap().mp_state;
            let json = format!(
                r#"{{"Kvm":{{"mp_state":{:?},"core_regs":{:?},"sys_regs":[]}}}}"#,
                m.to_le_bytes().to_vec(),
                vec![0u8; CORE_REGS_LEN]
            );
            let back = kvm_ingest::snapshot_json_to_hvf(&json).expect("the reader must parse it");
            assert_eq!(back.mp_state_running, want, "reader disagreed for vcpu {id}");
        }
    }
    /// A distinct byte for every (register, lane) pair, so a vector written to
    /// the wrong offset -- or a block written with a single repeated value --
    /// is visible rather than accidentally correct.
    #[cfg(test)]
    fn fp_pattern(reg: usize) -> [u8; 16] {
        let mut q = [0u8; 16];
        for (lane, b) in q.iter_mut().enumerate() {
            *b = ((reg * 16 + lane) ^ 0x5a) as u8;
        }
        q
    }

    /// The SIMD&FP register file must reach the exported document.
    ///
    /// It cannot travel the ONE_REG id list -- `kvm_core_reg_id` hardcodes
    /// `KVM_REG_SIZE_U64`, so no id names a 128-bit vector register -- so it
    /// rides beside it and is written by byte offset. That makes this the only
    /// block in `core_regs` whose delivery no id-driven test can observe, and
    /// the offsets are the single thing standing between "restored the guest's
    /// FP state" and "corrupted its `spsr` array".
    #[test]
    fn the_simd_registers_reach_the_exported_document() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let ancestor_fp = doc.vcpu(doc.vcpu_ids()[0]).unwrap().core_bytes()[translate::OFF_FP_VREGS..]
            .to_vec();

        let mut cp = checkpoint_with_vtimer(2, 0x1, 0x1000);
        for v in &mut cp.vcpus {
            v.state.fp = Some(VcpuFpState {
                vregs: (0..FP_VREG_COUNT).map(fp_pattern).collect(),
                fpsr: 0x10,
                fpcr: 0x0100_0000,
            });
        }

        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).expect("the patch must apply");

        for id in doc.vcpu_ids() {
            let core = doc.vcpu(id).unwrap().core_bytes().to_vec();
            for i in 0..FP_VREG_COUNT {
                let off = translate::kvm_fp_vreg_offset(i);
                assert_eq!(
                    &core[off..off + 16],
                    &fp_pattern(i)[..],
                    "vcpu {id} vector register {i} did not reach the document"
                );
            }
            let fpsr = u32::from_le_bytes(core[translate::OFF_FPSR..translate::OFF_FPSR + 4].try_into().unwrap());
            let fpcr = u32::from_le_bytes(core[translate::OFF_FPCR..translate::OFF_FPCR + 4].try_into().unwrap());
            assert_eq!(fpsr, 0x10, "vcpu {id} fpsr did not reach the document");
            assert_eq!(fpcr, 0x0100_0000, "vcpu {id} fpcr did not reach the document");
        }

        // The fixture is a real Graviton capture, so its own FP block is live
        // and non-zero. Without this, a patch that wrote nothing at all could
        // still pass if the pattern happened to match -- and it also records
        // that these bytes really were replaced, not merely confirmed.
        assert_ne!(
            ancestor_fp,
            doc.vcpu(doc.vcpu_ids()[0]).unwrap().core_bytes()[translate::OFF_FP_VREGS..].to_vec(),
            "the ancestor's FP block was already the pattern, so this test proved nothing"
        );
    }

    /// A checkpoint with no SIMD state must leave the ancestor's bytes alone.
    ///
    /// `fp` is an `Option` for exactly this: a checkpoint written before #357
    /// carries none, and the honest export of state we never captured is the
    /// parent's answer -- not 32 zeroed vector registers, which would describe
    /// a machine that never existed.
    #[test]
    fn a_checkpoint_with_no_simd_state_keeps_the_ancestors_bytes() {
        let bytes = std::fs::read("testdata/vanilla-state-2cpu-net.json").unwrap();
        let mut doc = VanillaState::parse(&bytes).unwrap();
        let before: Vec<Vec<u8>> = doc
            .vcpu_ids()
            .iter()
            .map(|id| doc.vcpu(*id).unwrap().core_bytes()[translate::OFF_FP_VREGS..].to_vec())
            .collect();
        assert!(
            before[0].iter().any(|b| *b != 0),
            "the fixture must carry live FP state, or this test cannot observe it being lost"
        );

        let cp = checkpoint_with_vtimer(2, 0x1, 0x1000);
        assert!(cp.vcpus[0].state.fp.is_none(), "this test needs the pre-#357 shape");

        let (mut warns, mut sums) = (Vec::new(), Vec::new());
        patch_vcpus(&mut doc, &cp, &mut warns, &mut sums).expect("the patch must apply");

        for (i, id) in doc.vcpu_ids().iter().enumerate() {
            assert_eq!(
                doc.vcpu(*id).unwrap().core_bytes()[translate::OFF_FP_VREGS..],
                before[i][..],
                "vcpu {id}: an absent FP block overwrote the ancestor's bytes"
            );
        }
    }
}
