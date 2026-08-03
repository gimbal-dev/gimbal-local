// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
//! Rehydrate a real cloud-hypervisor arm64 KVM snapshot into a live Apple
//! Hypervisor.framework VM.
//!
//! This is the orchestration that turns the individually-proven translation
//! pieces (vCPU core/sys registers, the GIC CPU-interface (ICC), and the GIC
//! distributor/redistributor — see [`super::translate`]) plus the captured
//! guest RAM into a single running VM. It is the concrete payoff of the port:
//! a snapshot taken by cloud-hypervisor under KVM (in the cloud, or in a nested
//! KVM guest on this Mac) is reconstructed field-by-field on Apple Silicon.
//!
//! The input is a cloud-hypervisor snapshot directory:
//!
//! ```text
//!   state.json                 # the nested snapshot tree (below)
//!   snapshot/memory-ranges     # raw guest RAM, concatenated per region
//! ```
//!
//! `state.json` carries three relevant sub-trees:
//!
//! - `snapshots/cpu-manager/snapshots/<id>/snapshot_data/state` — a JSON STRING
//!   `{"Kvm": VcpuKvmState}` per vCPU (core + system registers).
//! - `snapshots/device-manager/snapshots/gic-v3-its/snapshot_data/state` — a
//!   JSON STRING `{"Kvm": Gicv3ItsState}` (the `dist`/`rdist`/`icc` register
//!   dumps; the per-vCPU ICC lives here, NOT in the vCPU node).
//! - `snapshots/memory-manager/snapshot_data/state` — a JSON STRING describing
//!   `guest_ram_mappings` (where each RAM region maps in guest-physical space
//!   and its offset within `memory-ranges`).
//!
//! What is and is NOT covered (honest boundary): the CPU, the GIC
//! distributor/redistributor SGI-frame state, the per-vCPU ICC, and guest RAM
//! are all restored. The GIC RD_base LPI registers (GICR_PROPBASER/PENDBASER)
//! and the ITS tables — which matter only for guests actively delivering
//! MSI/LPIs — are not, and neither is a userspace device model (virtio/PCI),
//! so a rehydrated guest executes its real captured code until it touches an
//! unmodeled device. Restoring + executing the CPU/memory/interrupt state from
//! a real snapshot is exactly the link this module proves.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use libc::{
    c_void, mmap, munmap, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};

use crate::arch::aarch64::gic::{Vgic, VgicConfig};
use crate::cpu::Vcpu;
use crate::hvf::ffi::SYSREG_CNTVCT_EL0;
use crate::hvf::gic::HvfGicV3;
use crate::hvf::softgic::Distributor;
use crate::hvf::translate::gic_ingest::{
    dist_to_hvf, num_irq_from_dist_len, redist_rd_base_words, redist_to_hvf, redist_words_per_vcpu,
};
use crate::hvf::translate::kvm_ingest::snapshot_json_to_hvf;
use crate::hvf::virtio::GuestMemory;
use crate::hvf::{HvfVcpu, UsgicCpuHandle, UsgicSpiRouter, VcpuHvfState, VtimerClock};
use crate::hypervisor::Hypervisor;
use crate::vm::{Vm, VmOps};
use crate::{CpuState, HypervisorVmConfig};

/// cloud-hypervisor arm64 GIC layout (mirrors `arch::aarch64::layout`). The
/// snapshot does not store the GIC MMIO addresses — they are fixed by the VMM's
/// memory map, so they are reproduced here.
const MAPPED_IO_START: u64 = 0x0900_0000;
const GIC_V3_DIST_SIZE: u64 = 0x01_0000;
const GIC_V3_REDIST_SIZE: u64 = 0x02_0000;
/// Base of cloud-hypervisor's reserved low-MMIO GIC window. The managed GIC is
/// relocated here (distributor first, redistributors above) to satisfy Apple's
/// `hv_gic_create` ordering constraint; see [`Snapshot::vgic_config`].
const GIC_RELOCATED_BASE: u64 = 0x0800_0000;
/// Host-side MSI doorbell window for the managed GIC. A GICv2M-routed snapshot
/// delivers virtio completions as message-based SPIs via `hv_gic_send_msi`,
/// which requires the GIC to be created with a reserved MSI region. This IPA
/// sits above the relocated distributor/redistributors and below the guest's
/// PCI MMIO (0x1000_0000), so it collides with neither; it is a host-only
/// doorbell (the guest never accesses it — it drives ICC system registers and
/// its own, unmapped, v2m frame). Proven on hardware by the M12/M14 tests.
const GIC_MSI_DOORBELL_BASE: u64 = 0x0c00_0000;
const GIC_MSI_DOORBELL_SIZE: u64 = 0x1_0000;

/// Errors raised while parsing or rehydrating a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RehydrateError {
    /// `state.json` (or an embedded state string) did not parse.
    #[error("failed to parse snapshot JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A required node was missing or malformed in the snapshot tree.
    #[error("malformed snapshot: {0}")]
    Malformed(String),
    /// A vCPU or GIC register translation failed.
    #[error("translation failed: {0}")]
    Translate(String),
    /// Mapping the guest-RAM file failed.
    #[error("guest-RAM mmap of {path} failed: {source}")]
    Mmap {
        /// The file that could not be mapped.
        path: String,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// A hypervisor/VM operation failed.
    #[error("hypervisor operation failed: {0}")]
    Hv(#[from] anyhow::Error),
}

/// Format an error together with its full `source()` chain. Our backends stash
/// the actionable detail (e.g. the decoded `hv_return_t` + the entitlement fix
/// for `HV_DENIED`) in the error *source*; a caller that prints only the
/// top-level `Display` (`{e}`) would otherwise drop it and show a bare "Failed
/// to create Vm". This flattens the chain so the remedy always surfaces.
fn full_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

/// One guest-RAM region: where it maps in guest-physical space and where its
/// bytes live inside the `memory-ranges` file.
#[derive(Debug, Clone)]
pub struct MemMapping {
    /// Hypervisor memory-slot index.
    pub slot: u32,
    /// Guest-physical base address.
    pub gpa: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Byte offset of this region within `memory-ranges`.
    pub file_offset: u64,
}

/// A parsed cloud-hypervisor snapshot: everything needed to rebuild the VM,
/// with every register already translated into HVF form.
pub struct Snapshot {
    /// Guest-RAM regions, in slot order.
    pub mem_mappings: Vec<MemMapping>,
    /// Per-vCPU translated state (index == vCPU id), including its ICC vector.
    pub vcpus: Vec<VcpuHvfState>,
    /// GIC distributor dump (`Gicv3ItsState.dist`).
    pub gic_dist: Vec<u32>,
    /// GIC redistributor dump for all vCPUs (`Gicv3ItsState.rdist`).
    pub gic_rdist: Vec<u32>,
    /// Number of interrupt lines the captured GICv3 was built with.
    pub num_irq: u32,
    /// `CNTFRQ_EL0` of the host this snapshot was captured on, when the capture
    /// records it. `None` for a capture predating upstream `69637dde6`.
    pub captured_cntfrq: Option<u64>,
    /// Host wall-clock time at the instant of capture, in nanoseconds since the
    /// Unix epoch. Recorded in the same clock block as [`Self::captured_cntfrq`],
    /// so it is `None` for exactly the same captures.
    pub captured_realtime_ns: Option<u64>,
}

impl Snapshot {
    /// Parse a cloud-hypervisor `state.json` into a translated [`Snapshot`].
    pub fn from_state_json(state_json: &str) -> Result<Self, RehydrateError> {
        let root: serde_json::Value = serde_json::from_str(state_json)?;
        let snaps = root
            .get("snapshots")
            .ok_or_else(|| RehydrateError::Malformed("missing `snapshots`".into()))?;

        // --- memory-manager: guest_ram_mappings ---------------------------------
        let mem_state = embedded_state(snaps, &["memory-manager"])?;
        let mappings_json = mem_state
            .get("guest_ram_mappings")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RehydrateError::Malformed("missing `guest_ram_mappings`".into()))?;
        let mut mem_mappings = Vec::with_capacity(mappings_json.len());
        for m in mappings_json {
            let gpa = u64_field(m, "gpa")?;
            let size = u64_field(m, "size")?;
            let file_offset = u64_field(m, "file_offset")?;
            let slot = u64_field(m, "slot")? as u32;
            mem_mappings.push(MemMapping {
                slot,
                gpa,
                size,
                file_offset,
            });
        }
        if mem_mappings.is_empty() {
            return Err(RehydrateError::Malformed(
                "snapshot has no guest_ram_mappings".into(),
            ));
        }

        // --- device-manager: the GIC (dist/rdist/icc) ---------------------------
        let gic_kvm = embedded_state(snaps, &["device-manager", "gic-v3-its"])?;
        let gic_kvm = gic_kvm
            .get("Kvm")
            .ok_or_else(|| RehydrateError::Malformed("GIC node is not a KVM GIC".into()))?;
        let gic_dist = u32_vec(gic_kvm, "dist")?;
        let gic_rdist = u32_vec(gic_kvm, "rdist")?;
        let gic_icc = u32_vec(gic_kvm, "icc")?;
        let num_irq = num_irq_from_dist_len(gic_dist.len()).ok_or_else(|| {
            RehydrateError::Translate(format!(
                "distributor dump length {} matches no GICv3 width",
                gic_dist.len()
            ))
        })?;

        // --- cpu-manager: per-vCPU state, combined with its ICC slice -----------
        let vcpu_nodes = snaps
            .get("cpu-manager")
            .and_then(|c| c.get("snapshots"))
            .and_then(|v| v.as_object())
            .ok_or_else(|| RehydrateError::Malformed("missing cpu-manager vCPUs".into()))?;
        let num_vcpus = vcpu_nodes.len();
        if num_vcpus == 0 {
            return Err(RehydrateError::Malformed("snapshot has no vCPUs".into()));
        }
        if gic_icc.len() % num_vcpus != 0 {
            return Err(RehydrateError::Translate(format!(
                "ICC dump ({}) does not divide evenly across {num_vcpus} vCPUs",
                gic_icc.len()
            )));
        }
        if gic_rdist.len() % num_vcpus != 0 {
            return Err(RehydrateError::Translate(format!(
                "redistributor dump ({}) does not divide evenly across {num_vcpus} vCPUs",
                gic_rdist.len()
            )));
        }
        let icc_per_vcpu = gic_icc.len() / num_vcpus;

        // vCPU nodes are keyed by stringified id ("0", "1", ...); restore in id
        // order so vCPU i gets the i-th ICC slice.
        let mut vcpus: Vec<VcpuHvfState> = Vec::with_capacity(num_vcpus);
        for id in 0..num_vcpus {
            let node = vcpu_nodes.get(&id.to_string()).ok_or_else(|| {
                RehydrateError::Malformed(format!("missing cpu-manager vCPU `{id}`"))
            })?;
            let state_str = node
                .get("snapshot_data")
                .and_then(|d| d.get("state"))
                .and_then(|s| s.as_str())
                .ok_or_else(|| {
                    RehydrateError::Malformed(format!("vCPU `{id}` has no snapshot state string"))
                })?;
            let mut hvf = snapshot_json_to_hvf(state_str)?;
            let icc_slice = &gic_icc[id * icc_per_vcpu..(id + 1) * icc_per_vcpu];
            if let Some(icc) =
                crate::hvf::translate::gic_ingest::icc_to_hvf(icc_slice)
            {
                hvf.gic_icc = icc;
            }
            vcpus.push(hvf);
        }

        Ok(Snapshot {
            mem_mappings,
            vcpus,
            gic_dist,
            gic_rdist,
            num_irq,
            captured_cntfrq: snapshot_cntfrq(state_json),
            captured_realtime_ns: snapshot_clock_field(state_json, "host_realtime_ns"),
        })
    }

    /// Number of vCPUs in the snapshot.
    pub fn num_vcpus(&self) -> u32 {
        self.vcpus.len() as u32
    }

    /// The [`VgicConfig`] used to recreate the managed GIC for this snapshot.
    ///
    /// Cloud-hypervisor's arm64 map places the redistributors *below* the
    /// distributor (`GIC_V3_DIST_START` is the top of the reserved GIC window
    /// and redistributors grow downward from it). Apple's managed GIC, however,
    /// rejects that ordering: `hv_gic_create` returns `HV_BAD_ARGUMENT`
    /// (0xfae94003) unless the redistributor base is **above** the distributor
    /// base (verified empirically on hardware). The two layouts are therefore
    /// not simultaneously satisfiable.
    ///
    /// This is acceptable because the restored interrupt configuration is
    /// carried by the per-register distributor/redistributor writes and the
    /// per-vCPU ICC system registers — none of which depend on the MMIO base
    /// address. A resumed guest acknowledges/EOIs interrupts purely through
    /// `ICC_*` system registers, so relocating the managed GIC's MMIO base does
    /// not affect interrupt delivery. The only behaviour that would notice the
    /// move is *fresh* GIC MMIO reconfiguration after resume (already performed
    /// before the snapshot); that is the honest boundary of this relocation.
    ///
    /// We keep the GIC inside cloud-hypervisor's reserved low-MMIO window
    /// (`[GIC_RELOCATED_BASE, MAPPED_IO_START)`), so it never collides with
    /// guest RAM or the virtio devices that live at/above `MAPPED_IO_START`.
    pub fn vgic_config(&self) -> VgicConfig {
        let vcpu_count = self.num_vcpus() as u64;
        let redists_size = GIC_V3_REDIST_SIZE * vcpu_count;
        // Distributor first, redistributors immediately above it (HVF order).
        let dist_addr = GIC_RELOCATED_BASE;
        let redists_addr = dist_addr + GIC_V3_DIST_SIZE;
        debug_assert!(
            redists_addr + redists_size <= MAPPED_IO_START,
            "relocated GIC overflows the reserved MMIO window"
        );
        VgicConfig {
            vcpu_count,
            dist_addr,
            dist_size: GIC_V3_DIST_SIZE,
            redists_addr,
            redists_size,
            // Reserve the host-side MSI doorbell so the managed GIC accepts
            // `hv_gic_send_msi`: a GICv2M-routed snapshot delivers virtio
            // completions as message-based SPIs through this region. (An
            // ITS/LPI snapshot has no deliverable MSIs and is rejected by the
            // load-time guard, but reserving the region is harmless for it.)
            msi_addr: GIC_MSI_DOORBELL_BASE,
            msi_size: GIC_MSI_DOORBELL_SIZE,
            nr_irqs: self.num_irq,
        }
    }

    /// A single virtual-counter reference shared by every vCPU, used to keep the
    /// guest's `CNTVCT_EL0` synchronized across cores on resume.
    ///
    /// In a live SMP guest every vCPU reads one system counter, so all
    /// `CNTVCT_EL0` values are identical at any instant. A snapshot, however,
    /// reads each vCPU's registers sequentially, so the captured per-vCPU
    /// `CNTVCT_EL0` values differ (observed ~1.3s apart on a 2-vCPU capture).
    /// If each vCPU reseeds its HVF vtimer offset from its OWN captured value the
    /// resumed cores' virtual counters stay that far apart, which the guest
    /// kernel — which assumes a synchronized counter — cannot tolerate: the
    /// secondary's tick math breaks and it spins instead of taking its timer.
    /// We therefore pick ONE reference (vCPU0's captured `CNTVCT_EL0`) and seed
    /// every vCPU's offset from it, restoring the synchronized-counter invariant.
    fn reference_cntvct(&self) -> Option<u64> {
        self.vcpus
            .first()?
            .sysregs
            .iter()
            .find(|(id, _)| *id == SYSREG_CNTVCT_EL0)
            .map(|(_, v)| *v)
    }

    /// The redistributor dump slice belonging to vCPU `id`, reassembled into the
    /// contiguous per-vCPU order [`redist_to_hvf`] expects (RD_base words then
    /// SGI-frame words).
    ///
    /// cloud-hypervisor serializes the redistributor dump in two passes: all
    /// vCPUs' RD_base registers, then all vCPUs' SGI-frame registers. So for
    /// `n` vCPUs the dump is `[v0 rd][v1 rd]..[v0 sgi][v1 sgi]..` and a naive
    /// `len/n` split scrambles every secondary vCPU's frame. We stitch vCPU
    /// `id`'s RD_base run and SGI run back together here. (For a single vCPU the
    /// two sections are already contiguous, so this reduces to the whole dump.)
    fn rdist_slice(&self, id: usize) -> Vec<u32> {
        reassemble_rdist_slice(&self.gic_rdist, self.vcpus.len(), id)
    }
}

/// Reassemble vCPU `id`'s contiguous redistributor slice (RD_base words then
/// SGI-frame words) out of cloud-hypervisor's two-pass dump of `n` vCPUs:
/// `[v0 rd][v1 rd]..[v0 sgi][v1 sgi]..`. Pure helper so the two-pass arithmetic
/// — the M20 multi-vCPU fix — is unit-testable without a full snapshot.
fn reassemble_rdist_slice(rdist: &[u32], n: usize, id: usize) -> Vec<u32> {
    let rd_words = redist_rd_base_words();
    let per = redist_words_per_vcpu();
    let sgi_words = per - rd_words;
    let sgi_base = n * rd_words;

    let mut out = Vec::with_capacity(per);
    let rd_start = id * rd_words;
    out.extend_from_slice(&rdist[rd_start..rd_start + rd_words]);
    let sgi_start = sgi_base + id * sgi_words;
    out.extend_from_slice(&rdist[sgi_start..sgi_start + sgi_words]);
    out
}

/// File-backed guest RAM: a private (copy-on-write) mapping of a region of the
/// `memory-ranges` file. Private mapping means the resumed guest's writes never
/// reach the on-disk snapshot, so a rehydration attempt cannot corrupt it.
///
/// Exposed (opaque) via [`PreparedVm::ram`] so the SMP resume path can keep the
/// backings alive for the VM's lifetime; callers only ever store it, never read
/// its fields.
pub struct GuestRam {
    ptr: *mut u8,
    size: usize,
    /// Background threads populating the mapping (see `map_file`). Joined in
    /// `Drop` before `munmap` so they can never touch a torn-down mapping.
    willneed: Option<Vec<std::thread::JoinHandle<()>>>,
    /// Set by `Drop` to cut the populate threads short. Without it, tearing down
    /// a short-lived VM waits out the whole ~650ms populate (#79 measures
    /// teardown, and a disposable sandbox may not live that long).
    willneed_stop: Arc<AtomicBool>,
}

// SAFETY: the mapping is owned exclusively by this struct and only handed to
// the hypervisor as a raw guest-physical backing; no Rust aliasing occurs.
unsafe impl Send for GuestRam {}
// SAFETY: see the `Send` impl above — the raw pointer is never aliased and the
// mapping is only read/written by the hypervisor as guest memory.
unsafe impl Sync for GuestRam {}

/// Granularity of the background `MADV_WILLNEED` walk. Small enough that
/// teardown never waits more than one chunk (~40ms), large enough that the
/// syscall count stays trivial (16 calls for a 1 GiB guest).
const WILLNEED_CHUNK: usize = 64 * 1024 * 1024;

/// Number of threads sharing the populate walk.
///
/// One thread is not enough: `MADV_WILLNEED` on 1 GiB takes ~700ms, so a
/// sandbox that starts working immediately (the disposable-sandbox case #79
/// measures) races the populate and only gets part of the benefit. Splitting
/// the walk across threads finishes it sooner. Measured interleaved on an
/// 8-logical-CPU M3 (median of 6, `diskwrite`/`fsyncsmall` in seconds):
/// 1 thread 1.022/0.320, 4 threads 0.807/0.199, 8 threads 0.732/0.178,
/// 16 threads 0.667/0.214 — monotonic to the CPU count, then a wash. So: one
/// thread per logical CPU, capped, because past the core count this is just
/// more threads contending for the same page-fault path.
fn willneed_threads(chunks: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(chunks.max(1))
}

impl GuestRam {
    /// Map `size` bytes at `file_offset` of `path` copy-on-write.
    ///
    /// Fast path (default): a **file-backed `MAP_PRIVATE` mmap** — the guest's
    /// RAM pages fault in lazily from the snapshot file only as the guest touches
    /// them, and any guest write copies-on-write to a private anonymous page
    /// (leaving the snapshot file immutable). A resumed guest touches only its
    /// working set immediately, so this turns a full eager read of the whole
    /// image (hundreds of ms for a 1 GiB snapshot — the dominant startup cost,
    /// #79) into a near-instant mmap plus on-demand faults. `file_offset` must be
    /// page-aligned for a file-backed mmap; when it is not (rare), or if the
    /// mmap is rejected, we fall back to the eager anon+read path. Set
    /// `CHM_EAGER_RAM=1` to force the eager path (A/B comparison / diagnostics).
    ///
    /// Lazy fault-in is near-free to set up but is not free to *use*: every page
    /// the guest touches for the first time costs a synchronous host fault. That
    /// is the dominant cost of a real workload — a guest writing 256 MiB of
    /// previously untouched RAM spent ~1.4 s of a 2.0 s run in fault-in alone,
    /// and the same write repeated in one session was ~60x cheaper (#95). So the
    /// mapping is populated up front with `madvise(MADV_WILLNEED)`.
    ///
    /// That call **blocks** on macOS (measured: ~665 ms for 1 GiB) — it is not
    /// the advisory no-op the Linux semantics suggest — so it runs on background
    /// threads, in chunks so `Drop` can cut it short rather than hold teardown
    /// for its full duration. The mmap step therefore stays ~1.5 ms (the #79
    /// resume win is preserved) while the guest still finds most of its pages
    /// already resident.
    ///
    /// **How big the win is depends on how soon the guest starts working.** The
    /// figure first published for #95 (diskwrite 1.68 s -> 0.54 s, ~3x) was
    /// measured through a benchmark harness that burned ~10 s before the
    /// workload ran, so the populate had always finished first. Removing that
    /// dead time (#79) made the workload race the populate, which is the honest
    /// disposable-sandbox condition and a smaller win; parallelising the walk
    /// is what claws it back. Clean interleaved thread-count sweep on an
    /// 8-logical-CPU M3 (median of 6, diskwrite/fsyncsmall seconds): 1 thread
    /// 1.022/0.320, 8 threads 0.732/0.178. See `scripts/bench/RESULTS.md`.
    ///
    /// `fcntl(F_RDADVISE)` was measured as an alternative and rejected: it warms
    /// the *file's* page cache but not the mapping, and moved the workload not
    /// at all. Because the pages stay clean and file-backed this also avoids the
    /// private-copy footprint that `CHM_EAGER_RAM` forces. Set
    /// `CHM_NO_RAM_WILLNEED=1` to skip it (A/B comparison / diagnostics).
    fn map_file(path: &Path, file_offset: u64, size: usize) -> Result<Self, RehydrateError> {
        use std::os::unix::fs::FileExt;
        // Open and validate the region is within the file.
        let file = std::fs::File::open(path).map_err(|e| RehydrateError::Mmap {
            path: path.display().to_string(),
            source: e,
        })?;
        let len = file
            .metadata()
            .map_err(|e| RehydrateError::Mmap {
                path: path.display().to_string(),
                source: e,
            })?
            .len();
        if file_offset + size as u64 > len {
            return Err(RehydrateError::Malformed(format!(
                "memory region [{file_offset:#x}, +{size:#x}) exceeds {} ({len} bytes)",
                path.display()
            )));
        }

        let timing = std::env::var_os("CHM_TRACE_TIMING").is_some();
        let eager = std::env::var_os("CHM_EAGER_RAM").is_some();
        // mmap requires a page-aligned file offset; Apple Silicon uses 16 KiB
        // pages. `page_size` is queried rather than hard-coded so this stays
        // correct on any host.
        // SAFETY: sysconf with a valid name returns a positive page size.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let aligned = page != 0 && file_offset.is_multiple_of(page);

        if !eager && aligned {
            use std::os::unix::io::AsRawFd;
            let t0 = std::time::Instant::now();
            // File-backed copy-on-write mapping: lazy fault-in from the file,
            // private (COW) so guest writes never touch the snapshot on disk.
            // SAFETY: fd is valid for the call; size/offset validated above.
            let ptr = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE,
                    file.as_raw_fd(),
                    file_offset as libc::off_t,
                )
            };
            if ptr != MAP_FAILED {
                // Populate the mapping off the critical path; see the doc
                // comment above for why this must not run inline.
                let willneed_stop = Arc::new(AtomicBool::new(false));
                let willneed = if std::env::var_os("CHM_NO_RAM_WILLNEED").is_some() {
                    None
                } else {
                    let addr = ptr as usize;
                    let chunks = size.div_ceil(WILLNEED_CHUNK);
                    let nthreads = willneed_threads(chunks);
                    let mut handles = Vec::with_capacity(nthreads);
                    for t in 0..nthreads {
                        let stop = willneed_stop.clone();
                        let h = std::thread::Builder::new()
                            .name(format!("chm-ram-willneed-{t}"))
                            .spawn(move || {
                                // Chunked so `Drop` can cut this short: a whole-region
                                // `madvise` is uninterruptible and would hold teardown
                                // for its full duration. Threads stride through the
                                // chunk list so each covers a disjoint set and no
                                // coordination beyond the stop flag is needed.
                                let mut c = t;
                                while c < chunks && !stop.load(Ordering::Acquire) {
                                    let off = c * WILLNEED_CHUNK;
                                    let len = WILLNEED_CHUNK.min(size - off);
                                    // SAFETY: `[addr, addr+size)` is a live mapping for
                                    // this thread's whole lifetime — `GuestRam::drop`
                                    // joins before `munmap` — and `MADV_WILLNEED` only
                                    // populates pages the guest may touch concurrently,
                                    // which is what a first-touch fault would do anyway.
                                    unsafe {
                                        libc::madvise(
                                            (addr + off) as *mut libc::c_void,
                                            len,
                                            libc::MADV_WILLNEED,
                                        );
                                    }
                                    c += nthreads;
                                }
                            })
                            .ok();
                        if let Some(h) = h {
                            handles.push(h);
                        }
                    }
                    (!handles.is_empty()).then_some(handles)
                };
                if timing {
                    eprintln!(
                        "[timing] map_file mmap(COW) {:.1} MiB in {:?} (lazy fault-in)",
                        size as f64 / (1024.0 * 1024.0),
                        t0.elapsed()
                    );
                }
                return Ok(GuestRam {
                    ptr: ptr as *mut u8,
                    size,
                    willneed,
                    willneed_stop,
                });
            }
            // Fall through to the eager path if the file-backed mmap was rejected.
            if timing {
                eprintln!(
                    "[timing] map_file file-backed mmap rejected ({}); eager read",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Eager path: anonymous backing filled from the file once. Used when the
        // offset is unaligned, the file-backed mmap was rejected, or CHM_EAGER_RAM
        // forces it.
        // SAFETY: standard anonymous read/write mapping; checked below.
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(RehydrateError::Mmap {
                path: path.display().to_string(),
                source: std::io::Error::last_os_error(),
            });
        }
        let ram = GuestRam {
            ptr: ptr as *mut u8,
            size,
            willneed: None,
            willneed_stop: Arc::new(AtomicBool::new(false)),
        };

        // SAFETY: ptr is valid for `size` bytes; we fill it exactly once.
        let buf = unsafe { std::slice::from_raw_parts_mut(ram.ptr, size) };
        let t0 = std::time::Instant::now();
        file.read_exact_at(buf, file_offset)
            .map_err(|e| RehydrateError::Mmap {
                path: path.display().to_string(),
                source: e,
            })?;
        if std::env::var_os("CHM_TRACE_TIMING").is_some() {
            eprintln!(
                "[timing] map_file read {:.1} MiB in {:?}",
                size as f64 / (1024.0 * 1024.0),
                t0.elapsed()
            );
        }
        Ok(ram)
    }

    /// A host view of this region's live guest-RAM bytes.
    ///
    /// Used to dump memory at checkpoint time. Callers MUST pause every vCPU
    /// before reading so the captured page contents are consistent (no vCPU is
    /// mid-write). The slice is valid for `size` bytes for the life of `self`.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `ptr` is a live mapping of exactly `size` bytes owned by this
        // struct; with all vCPUs paused there is no concurrent guest writer, so
        // a shared read is sound.
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    /// This region's size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Whether this region is empty (never true for a mapped region; provided to
    /// satisfy the `len`-without-`is_empty` lint).
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        if let Some(handles) = self.willneed.take() {
            self.willneed_stop.store(true, Ordering::Release);
            for h in handles {
                let _ = h.join();
            }
        }
        // SAFETY: unmapping our own mapping exactly once.
        unsafe {
            munmap(self.ptr as *mut c_void, self.size);
        }
    }
}

/// A live VM rebuilt from a snapshot: memory mapped, GIC + vCPUs restored, ready
/// to `run()`. The guest-RAM backing is owned here so it outlives the mapping.
pub struct RehydratedVm {
    // NOTE: field declaration order is drop order. HVF requires every vCPU to be
    // destroyed before the VM, and the managed GIC + guest-RAM mappings belong
    // to the VM, so the `vm` handle (whose `Drop` calls `hv_vm_destroy`) MUST be
    // dropped last. Declaring it last guarantees that ordering.
    /// Restored vCPUs, in id order. Dropped first (`hv_vcpu_destroy`).
    pub vcpus: Vec<Box<dyn Vcpu>>,
    /// The restored managed GICv3.
    pub gic: Arc<Mutex<dyn Vgic>>,
    /// A host view of the restored guest RAM, sharing the exact backing pointers
    /// handed to the hypervisor. The native virtio device model reads/writes the
    /// guest's rings through this. Kept before `_ram` so it drops first (its raw
    /// pointers must not outlive the mappings).
    pub guest_mem: Arc<GuestMemory>,
    /// Host-side guest-RAM backings (kept alive for the VM's lifetime).
    _ram: Vec<GuestRam>,
    /// The reconstructed VM. Dropped last (`hv_vm_destroy`).
    pub vm: Arc<dyn Vm>,
}

/// Rebuild a live HVF VM from a parsed [`Snapshot`] and its `memory-ranges`
/// file. The returned vCPUs carry the full restored architectural state and can
/// be `run()` immediately.
///
/// Restore order mirrors cloud-hypervisor's own: map RAM, create the GIC,
/// create the vCPUs, restore the distributor, then per vCPU restore its
/// register file (which sets MPIDR + the ICC interface) and its redistributor
/// frame.
pub fn rehydrate(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
    vm_ops: &Arc<dyn VmOps>,
) -> Result<RehydratedVm, RehydrateError> {
    rehydrate_inner(hv, snap, memory_ranges, vm_ops, None)
}

/// Rebuild a live HVF VM, restoring captured live state from `checkpoint`
/// instead of the cold snapshot's registers/GIC (the single-threaded resume
/// path used by the daemon). `memory_ranges` should point at the checkpoint's
/// RAM dump; `snap` still supplies the memory-region layout and device wiring.
pub fn rehydrate_resume(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
    vm_ops: &Arc<dyn VmOps>,
    checkpoint: &crate::hvf::checkpoint::CheckpointState,
) -> Result<RehydratedVm, RehydrateError> {
    rehydrate_inner(hv, snap, memory_ranges, vm_ops, Some(checkpoint))
}

fn rehydrate_inner(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
    vm_ops: &Arc<dyn VmOps>,
    resume_from: Option<&crate::hvf::checkpoint::CheckpointState>,
) -> Result<RehydratedVm, RehydrateError> {
    // Map RAM + create the managed GIC shell (no vCPUs yet).
    let PreparedVm {
        vm,
        gic,
        guest_mem,
        ram,
    } = prepare_vm(hv, snap, memory_ranges)?;

    // --- vCPUs (created before distributor restore so the redistributors
    //     exist) -----------------------------------------------------------
    let mut vcpus = Vec::with_capacity(snap.vcpus.len());
    for id in 0..snap.vcpus.len() {
        let vcpu = vm
            .create_vcpu(id as u32, Some(vm_ops.clone()))
            .map_err(|e| RehydrateError::Hv(anyhow!("create_vcpu {id}: {e}")))?;
        vcpus.push(vcpu);
    }

    // Global distributor restore, then per-vCPU register file + redistributor,
    // then enable Group1 SPI forwarding. (Single-thread path: every vCPU was
    // created on this thread, so its register file may be restored here too.) A
    // live checkpoint overrides the cold snapshot's vCPU/GIC state with the
    // captured values.
    match resume_from {
        Some(cp) => {
            crate::hvf::checkpoint::apply_distributor(&gic, &cp.gic_dist)?;
            let reference = cp.reference_cntvct();
            for (id, vcpu) in vcpus.iter_mut().enumerate() {
                let vc = cp.vcpus.get(id).ok_or_else(|| {
                    RehydrateError::Translate(format!("checkpoint missing vCPU {id}"))
                })?;
                crate::hvf::checkpoint::apply_vcpu(vcpu, vc, reference)?;
            }
        }
        None => {
            restore_distributor(&gic, snap)?;
            for (id, vcpu) in vcpus.iter_mut().enumerate() {
                restore_vcpu_state(vcpu, snap, id)?;
            }
        }
    }
    enable_group1_spi_forwarding(&gic)?;

    Ok(RehydratedVm {
        vcpus,
        gic,
        guest_mem,
        _ram: ram,
        vm,
    })
}

/// The pieces of a **userspace-GIC** rehydrated VM (NO managed GIC). Field order
/// is drop order: `vm` (whose `Drop` calls `hv_vm_destroy`) is declared last so
/// it drops after the vCPUs and RAM mappings, matching HVF's teardown order.
pub struct UsgicVm {
    /// Restored vCPUs, in id order. Each has its `usgic` enabled + seeded.
    pub vcpus: Vec<Box<dyn Vcpu>>,
    /// Host view of restored guest RAM (the virtio device model reads/writes the
    /// guest's rings through this).
    pub guest_mem: Arc<GuestMemory>,
    /// Host-side guest-RAM backings (kept alive for the VM's lifetime).
    _ram: Vec<GuestRam>,
    /// The reconstructed VM. Dropped last (`hv_vm_destroy`).
    pub vm: Arc<dyn Vm>,
}

/// Rehydrate a snapshot onto a **userspace GICv3** — the path for a stock
/// ITS/LPI-routed snapshot, whose virtio completions Apple's managed GIC cannot
/// deliver. Unlike [`rehydrate`], this creates NO managed GIC: it maps RAM,
/// creates vCPUs, restores each register file, and seeds the per-vCPU software
/// distributor/redistributor + CPU-interface bookkeeping from the captured KVM
/// GIC state. The software GIC is wired at the guest's ORIGINAL GIC MMIO bases
/// (the managed path relocates the GIC; the userspace path does not need to).
///
/// The caller must run each vCPU on its own thread (HVF binds a vCPU to its
/// creating thread) and route device/serial completions through
/// [`HvfVcpu::usgic_inject_queue`], waking the vCPU so its run-entry drain takes
/// them. Gated by the caller (only used when `CHM_USERSPACE_GIC` + an ITS
/// snapshot); the managed [`rehydrate`] path is unaffected.
pub fn rehydrate_usgic(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
    vm_ops: &Arc<dyn VmOps>,
    resume: Option<&crate::hvf::checkpoint::CheckpointState>,
) -> Result<UsgicVm, RehydrateError> {
    let timing = std::env::var_os("CHM_TRACE_TIMING").is_some();
    let t_start = std::time::Instant::now();
    let prepared = prepare_usgic_vm(hv, snap, memory_ranges)?;

    // Create + restore every vCPU on this (single) thread. For SMP the caller
    // uses `prepare_usgic_vm` + `restore_usgic_vcpu` directly, one per thread,
    // because HVF binds a vCPU to its creating thread.
    let seed = prepared.seed();
    // One clock for the whole VM: see `counter_clock`.
    let clock = counter_clock(snap, resume)
        .unwrap_or_else(|| VtimerClock::new(0, 0, super::host_counter_hz()));
    let mut vcpus = Vec::with_capacity(snap.vcpus.len());
    for id in 0..snap.vcpus.len() {
        vcpus.push(restore_usgic_vcpu(
            &prepared.vm,
            &seed,
            snap,
            resume,
            id,
            vm_ops,
            &clock,
        )?);
    }
    if timing {
        eprintln!("[timing] rehydrate_usgic total {:?}", t_start.elapsed());
    }

    let UsgicPrepared {
        guest_mem, ram, vm, ..
    } = prepared;
    Ok(UsgicVm {
        vcpus,
        guest_mem,
        _ram: ram,
        vm,
    })
}

/// The pieces of a **userspace-GIC** VM that exist before any vCPU: the VM
/// handle, its mapped guest RAM, the guest's GIC MMIO bases, and the translated
/// distributor dump. Like [`PreparedVm`] for the managed path, this split lets
/// an SMP resume create each vCPU on its own thread (HVF binds a vCPU to its
/// creating thread) after the VM-global RAM mapping is done once here.
pub struct UsgicPrepared {
    /// Host view of restored guest RAM (the virtio device model reads/writes the
    /// guest's rings through this).
    pub guest_mem: Arc<GuestMemory>,
    /// Host-side guest-RAM backings (kept alive for the VM's lifetime).
    ram: Vec<GuestRam>,
    /// The reconstructed VM (shared to each vCPU thread via `.clone()`).
    pub vm: Arc<dyn Vm>,
    /// The per-vCPU seed (GIC bases + translated distributor dump), cheaply
    /// clonable + `Send` so each vCPU thread can carry a copy.
    seed: UsgicSeed,
}

impl UsgicPrepared {
    /// The `Send`-friendly seed each vCPU thread needs to create + restore its
    /// vCPU (GIC MMIO bases + the shared distributor + translated dump).
    pub fn seed(&self) -> UsgicSeed {
        self.seed.clone()
    }

    /// Build an SPI router over the VM-global distributor + the per-vCPU delivery
    /// table, so a device/console thread's SPI lands on the core its
    /// `GICD_IROUTER` affinity names (not always the boot CPU).
    pub fn spi_router(&self, cpus: Arc<Vec<UsgicCpuHandle>>) -> UsgicSpiRouter {
        UsgicSpiRouter::new(self.seed.shared_dist.clone(), cpus)
    }
}

/// The GIC seed shared by every userspace-GIC vCPU: the MMIO bases, the VM-global
/// distributor, and the translated distributor dump. `Clone` + `Send` so an SMP
/// orchestrator can hand a copy to each per-vCPU thread.
#[derive(Clone)]
pub struct UsgicSeed {
    /// MMIO base of the VM-global distributor frame.
    gicd_base: u64,
    /// MMIO base of vCPU 0's redistributor window; vCPU `i` sits one
    /// `GIC_V3_REDIST_SIZE` above.
    gicr_region_base: u64,
    /// The translated distributor dump, seeded into the shared distributor
    /// (shared read-only, so behind an `Arc` to avoid copying per vCPU).
    dist_pairs: Arc<Vec<(u32, u64)>>,
    /// The VM-global software distributor, installed into every vCPU so a
    /// reprogram on any core is visible to all and SPIs route by affinity.
    shared_dist: Arc<Mutex<Distributor>>,
    /// How many vCPUs the VM has, so each redistributor can say whether it is
    /// the last in the region. `gic_iterate_rdists` stops walking at the first
    /// one that claims to be.
    vcpu_count: u64,
}

/// Create the userspace-GIC VM and map its guest RAM (no managed GIC, no vCPUs).
/// The VM-global work; each vCPU is then created + restored via
/// [`restore_usgic_vcpu`] on its own thread.
pub fn prepare_usgic_vm(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
) -> Result<UsgicPrepared, RehydrateError> {
    let timing = std::env::var_os("CHM_TRACE_TIMING").is_some();
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vm: {}", full_chain(&e))))?;

    // --- guest RAM (same mapping as prepare_vm, but no managed GIC after) ---
    let t_ram = std::time::Instant::now();
    let guest_mem = Arc::new(GuestMemory::new());
    let mut ram = Vec::with_capacity(snap.mem_mappings.len());
    for m in &snap.mem_mappings {
        let backing = GuestRam::map_file(memory_ranges, m.file_offset, m.size as usize)?;
        // SAFETY: `backing` outlives the VM (kept alive in `ram`).
        unsafe {
            vm.create_user_memory_region(m.slot, m.gpa, m.size as usize, backing.ptr, false, false)
                .map_err(|e| RehydrateError::Hv(anyhow!("map RAM @ {:#x}: {e}", m.gpa)))?;
            guest_mem.register(m.gpa, backing.ptr, m.size as usize);
        }
        ram.push(backing);
    }
    if timing {
        eprintln!("[timing] RAM map total {:?}", t_ram.elapsed());
    }

    // The guest's original GIC MMIO bases (arch::aarch64::layout): distributor
    // just below the mapped-IO window, per-vCPU redistributors stacked below it.
    let gicd_base = MAPPED_IO_START - GIC_V3_DIST_SIZE;
    let vcpu_count = snap.vcpus.len() as u64;
    let gicr_region_base = gicd_base - vcpu_count * GIC_V3_REDIST_SIZE;

    let dist_pairs = dist_to_hvf(&snap.gic_dist)
        .ok_or_else(|| RehydrateError::Translate("distributor dump did not translate".into()))?;

    // The VM-global distributor, sized once and shared by every vCPU, so a
    // reprogram on any core is visible to all and SPIs route by affinity.
    let shared_dist = Arc::new(Mutex::new(Distributor::new(snap.num_irq)));

    Ok(UsgicPrepared {
        guest_mem,
        ram,
        vm,
        seed: UsgicSeed {
            gicd_base,
            gicr_region_base,
            dist_pairs: Arc::new(dist_pairs),
            shared_dist,
            vcpu_count,
        },
    })
}

/// Create and restore one userspace-GIC vCPU on the CURRENT thread (HVF binds a
/// vCPU to its creating thread). Seeds the per-vCPU software distributor +
/// redistributor + CPU-interface bookkeeping and restores the register file, on
/// a cold rehydrate from `snap` or (when `resume` is set) from the checkpoint.
/// For SMP the caller runs this once per thread after [`prepare_usgic_vm`], then
/// installs the cross-vCPU SGI table via [`HvfVcpu::usgic_set_cpu_table`].
pub fn restore_usgic_vcpu(
    vm: &Arc<dyn Vm>,
    seed: &UsgicSeed,
    snap: &Snapshot,
    resume: Option<&crate::hvf::checkpoint::CheckpointState>,
    id: usize,
    vm_ops: &Arc<dyn VmOps>,
    clock: &Arc<VtimerClock>,
) -> Result<Box<dyn Vcpu>, RehydrateError> {
    let mut vcpu = vm
        .create_vcpu(id as u32, Some(vm_ops.clone()))
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vcpu {id}: {e}")))?;

    let redist_pairs = redist_to_hvf(&snap.rdist_slice(id)).ok_or_else(|| {
        RehydrateError::Translate(format!("vCPU {id} redistributor did not translate"))
    })?;
    let gicr_base = seed.gicr_region_base + id as u64 * GIC_V3_REDIST_SIZE;
    {
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .ok_or_else(|| RehydrateError::Translate("vCPU is not an HVF vCPU".into()))?;
        concrete.set_usgic_enabled(true);
        // Install the VM-global distributor (shared across vCPUs) + set the MMIO
        // bases, then seed. Every vCPU shares the one distributor, so a GICD
        // reprogram on any core is visible to all and SPIs route by affinity.
        concrete.usgic_install_shared_dist(seed.shared_dist.clone());
        concrete.usgic_set_gic_bases(seed.gicd_base, gicr_base);
        // Set on the rehydrate path too. A restored guest normally never
        // re-probes, which is why these registers could be wrong for so long
        // without anyone noticing — but a guest that kexecs, or reloads the
        // driver, does, and then a wrong answer costs it its timer.
        concrete.usgic_set_redist_identity(id as u32, id as u64 + 1 == seed.vcpu_count);
        match resume.and_then(|cp| cp.usgic_for(id)) {
            // Resume: restore the live software-GIC models captured at suspend
            // (SPI/PPI config the guest may have reprogrammed since the parent
            // snapshot, plus any in-flight interrupt), overriding the cold seed.
            // Indexed by id: the redistributor, pending set and active INTID are
            // per-vCPU, so each core gets its own captured state rather than the
            // boot CPU's.
            Some(usgic_cp) => concrete.usgic_restore_softgic(usgic_cp),
            // Cold: seed from the parent snapshot's captured KVM GIC state. On SMP
            // this seeds the shared distributor identically per vCPU (idempotent).
            None => concrete.usgic_seed_gic(&seed.dist_pairs, &redist_pairs),
        }
    }

    // Restore the register file. On resume this is the checkpoint's captured
    // vCPU state; cold it is the parent snapshot's. Because usgic is enabled,
    // set_state seeds the captured ICC bookkeeping into `usgic` instead of a
    // (nonexistent) managed GIC.
    let vcpu_state = match resume {
        Some(cp) => {
            &cp.vcpus
                .get(id)
                .ok_or_else(|| {
                    RehydrateError::Translate(format!(
                        "checkpoint describes {} vCPU(s), cannot restore vCPU {id}",
                        cp.vcpus.len()
                    ))
                })?
                .state
        }
        None => &snap.vcpus[id],
    };
    vcpu.set_state(&CpuState::Hvf(vcpu_state.clone()))
        .map_err(|e| RehydrateError::Hv(anyhow!("restore vCPU {id} state: {e}")))?;

    // Bind this vCPU to the VM's ONE counter clock. Every vCPU programming the
    // same virtual-timer offset is what makes `CNTVCT_EL0` coherent across
    // cores; seeding an offset per vCPU (as this used to) leaves them
    // permanently skewed and wraps the guest's 56-bit clocksource. See
    // [`VtimerClock`].
    {
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .expect("HVF vCPU");
        concrete
            .attach_clock(clock.clone())
            .map_err(|e| RehydrateError::Hv(anyhow!("vCPU {id} attach counter clock: {e}")))?;
    }
    Ok(vcpu)
}

/// Create a userspace-GIC VM over guest RAM the CALLER allocated and filled.
///
/// The cold-boot counterpart to [`prepare_usgic_vm`]. Three things differ, and
/// each of them is the absence of a snapshot rather than a different mechanism:
///
/// - **RAM comes from the caller.** A rehydrate maps the capture's
///   `memory-ranges` file; a cold boot has a kernel and a device tree already
///   written into an anonymous allocation, so this takes the host pointer and
///   maps it as-is. `ram` is therefore empty: this struct does not own the
///   backing, the caller does, and the caller must keep it alive for the VM's
///   lifetime.
/// - **There is no distributor dump to seed.** A cold GIC starts at its
///   architectural reset state, which is what `Distributor::new` already
///   produces, so `dist_pairs` is empty rather than a translation of somebody
///   else's captured registers.
/// - **The GIC bases are the canonical ones.** Same arithmetic as the
///   rehydrate path, but they must also match what the device tree says, which
///   is why `hvf::coldgic` and this function are checked against each other by
///   test rather than by comment.
///
/// # Safety
///
/// `host_ptr` must point to at least `ram_size` bytes that stay valid, and
/// stay unaliased by Rust, for the whole lifetime of the returned VM.
pub unsafe fn prepare_cold_usgic_vm(
    hv: &dyn Hypervisor,
    ram_base: u64,
    ram_size: usize,
    host_ptr: *mut u8,
    vcpu_count: u64,
    num_irq: u32,
) -> Result<UsgicPrepared, RehydrateError> {
    if vcpu_count == 0 {
        return Err(RehydrateError::Translate(
            "a cold guest needs at least one vCPU".into(),
        ));
    }
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vm: {}", full_chain(&e))))?;

    let guest_mem = Arc::new(GuestMemory::new());
    // SAFETY: the caller's contract above — `host_ptr` is valid for `ram_size`
    // bytes and outlives the VM. Slot 0 because a cold guest has exactly one
    // contiguous RAM region, unlike a capture's several.
    unsafe {
        vm.create_user_memory_region(0, ram_base, ram_size, host_ptr, false, false)
            .map_err(|e| RehydrateError::Hv(anyhow!("map cold RAM @ {ram_base:#x}: {e}")))?;
        guest_mem.register(ram_base, host_ptr, ram_size);
    }

    let gicd_base = MAPPED_IO_START - GIC_V3_DIST_SIZE;
    let gicr_region_base = gicd_base - vcpu_count * GIC_V3_REDIST_SIZE;

    Ok(UsgicPrepared {
        guest_mem,
        ram: Vec::new(),
        vm,
        seed: UsgicSeed {
            gicd_base,
            gicr_region_base,
            dist_pairs: Arc::new(Vec::new()),
            shared_dist: Arc::new(Mutex::new(Distributor::new(num_irq))),
            vcpu_count,
        },
    })
}

/// Create one cold-boot vCPU on the CURRENT thread (HVF binds a vCPU to its
/// creating thread).
///
/// The cold-boot counterpart to [`restore_usgic_vcpu`]. It does not call
/// `set_state`: there is no captured register file, so the vCPU keeps HVF's
/// reset state and gets only what the arm64 boot protocol specifies.
///
/// `boot` is `Some((entry, fdt))` for the CPU that starts executing — normally
/// only vCPU 0. Secondaries pass `None` and stay at their reset state until the
/// kernel brings them up through PSCI `CPU_ON`, which is exactly what the
/// device tree's `enable-method = "psci"` promises the kernel it can do.
pub fn create_cold_usgic_vcpu(
    vm: &Arc<dyn Vm>,
    seed: &UsgicSeed,
    id: usize,
    vm_ops: &Arc<dyn VmOps>,
    clock: &Arc<VtimerClock>,
    boot: Option<(u64, u64)>,
) -> Result<Box<dyn Vcpu>, RehydrateError> {
    let mut vcpu = vm
        .create_vcpu(id as u32, Some(vm_ops.clone()))
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vcpu {id}: {e}")))?;

    let gicr_base = seed.gicr_region_base + id as u64 * GIC_V3_REDIST_SIZE;
    {
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .ok_or_else(|| RehydrateError::Translate("vCPU is not an HVF vCPU".into()))?;
        concrete.set_usgic_enabled(true);
        concrete.usgic_install_shared_dist(seed.shared_dist.clone());
        concrete.usgic_set_gic_bases(seed.gicd_base, gicr_base);
        // The guest is about to discover this GIC for the first time, so the
        // redistributor has to be able to identify itself.
        concrete.usgic_set_redist_identity(id as u32, id as u64 + 1 == seed.vcpu_count);
        // No seed: a cold GIC is already at its reset state. Seeding with the
        // empty `dist_pairs` would be a no-op, but calling it would imply
        // there was something to restore.
    }

    if let Some((entry, fdt)) = boot {
        vcpu.setup_regs(id as u32, entry, fdt)
            .map_err(|e| RehydrateError::Hv(anyhow!("cold boot regs for vCPU {id}: {e}")))?;
    } else {
        // A parked secondary still needs its MPIDR to match the device tree's
        // `/cpus/cpu@N` reg, or PSCI CPU_ON targets a core the kernel cannot
        // find. `setup_regs` sets MPIDR as part of the boot protocol; do the
        // same here without giving the core an entry point.
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .expect("HVF vCPU");
        concrete
            .set_mpidr_affinity(id as u32)
            .map_err(|e| RehydrateError::Hv(anyhow!("MPIDR for parked vCPU {id}: {e}")))?;
    }

    {
        let concrete = vcpu
            .as_any_concrete_mut()
            .downcast_mut::<HvfVcpu>()
            .expect("HVF vCPU");
        concrete
            .attach_clock(clock.clone())
            .map_err(|e| RehydrateError::Hv(anyhow!("vCPU {id} attach counter clock: {e}")))?;
    }
    Ok(vcpu)
}

/// Build the one [`VtimerClock`] a rehydrated VM's vCPUs all share, anchored on
/// the snapshot's (or checkpoint's) reference `CNTVCT_EL0` so the guest's
/// virtual counter resumes where it was captured.
///
/// `None` when the snapshot carried no counter at all, in which case the guest
/// keeps HVF's fresh counter and there is nothing to keep coherent.
pub fn counter_clock(
    snap: &Snapshot,
    resume: Option<&crate::hvf::checkpoint::CheckpointState>,
) -> Option<Arc<VtimerClock>> {
    // Take the counter and the wall-clock time from the SAME source, or the
    // elapsed span is measured between two unrelated instants.
    let (captured, captured_realtime_ns) = match resume {
        Some(cp) => (cp.reference_cntvct()?, cp.host_realtime_ns),
        None => (snap.reference_cntvct()?, snap.captured_realtime_ns),
    };
    // The capture's own recorded frequency is the default: correcting the rate
    // costs a measured 2.8% of wall time in stop-the-world barriers, and leaving
    // it uncorrected costs a Graviton guest a 5.078x time dilation, which makes
    // every timeout, sleep and scheduler tick in it wrong. An explicit
    // `CHM_GUEST_CNTFRQ` overrides either way, including `0` to opt out.
    let guest_hz = effective_guest_hz(requested_guest_cntfrq(), snap.captured_cntfrq);
    // The guest reads ticks at the frequency it believes it has, whether or not
    // the rate is being corrected, so the elapsed span converts with that.
    let believed_hz = snap.captured_cntfrq.unwrap_or(guest_hz);
    let reference = advance_to_wall_clock(
        captured,
        captured_realtime_ns,
        now_realtime_ns(),
        believed_hz,
    );
    Some(VtimerClock::new(
        reference,
        guest_hz,
        super::host_counter_hz(),
    ))
}

/// The `cntfrq` recorded in a snapshot's top-level clock block, if present.
///
/// cloud-hypervisor stores it as a JSON *string* under `snapshot_data.state`
/// that has to be parsed a second time:
/// `{"clock":{"cntvct":..,"host_realtime_ns":..,"cntfrq":24000000}}`.
///
/// `None` when the capture predates upstream `69637dde6` ("hypervisor: aarch64:
/// capture the guest counter for snapshot/restore"), which introduced the block
/// — a v52.0 capture writes `{}` here.
pub fn snapshot_cntfrq(state_json: &str) -> Option<u64> {
    snapshot_clock_field(state_json, "cntfrq")
}

/// One `u64` out of a snapshot's doubly encoded top-level clock block.
fn snapshot_clock_field(state_json: &str, field: &str) -> Option<u64> {
    let root: serde_json::Value = serde_json::from_str(state_json).ok()?;
    let inner = root.get("snapshot_data")?.get("state")?.as_str()?;
    let clock: serde_json::Value = serde_json::from_str(inner).ok()?;
    clock.get("clock")?.get(field)?.as_u64()
}

/// Nanoseconds since the Unix epoch at 2020-01-01, used only as a floor for
/// deciding whether a recorded capture time is a real timestamp.
const PLAUSIBLE_EPOCH_FLOOR_NS: u64 = 1_577_836_800_000_000_000;

/// Advance a captured `CNTVCT_EL0` by the wall-clock time that has passed since
/// the capture, so a resumed guest wakes up believing the current date.
///
/// Without this a snapshot resumes frozen at the instant it was taken, and the
/// staleness is not cosmetic: measured on a capture 5 hours old, `apt-get
/// update` **refused** `noble-updates` and `noble-security` with *"Release file
/// is not valid yet (invalid for another 4h 2min 0s)"*, because repository
/// metadata published after the capture is dated in the guest's future. TLS
/// certificate validity, token expiry and `make` all have the same exposure,
/// and it grows the longer a snapshot sits in a registry.
///
/// This is what the KVM path already does on restore (`restore_clock`), so it is
/// parity rather than novelty. `elapsed` is converted with the **guest's**
/// counter frequency, since that is the rate at which the guest interprets the
/// ticks it reads, whether or not the rate is being corrected.
///
/// Returns `captured` unchanged when the capture recorded no time, when the
/// recorded time is not plausibly a Unix timestamp (a zero or garbage field
/// would otherwise throw the guest ~57 years forward), or when the host clock is
/// behind the capture.
fn advance_to_wall_clock(
    captured: u64,
    captured_realtime_ns: Option<u64>,
    now_realtime_ns: u64,
    guest_hz: u64,
) -> u64 {
    let Some(then) = captured_realtime_ns.filter(|ns| *ns >= PLAUSIBLE_EPOCH_FLOOR_NS) else {
        return captured;
    };
    if guest_hz == 0 {
        return captured;
    }
    let elapsed_ns = u128::from(now_realtime_ns.saturating_sub(then));
    let ticks = elapsed_ns * u128::from(guest_hz) / 1_000_000_000;
    captured.wrapping_add(u64::try_from(ticks).unwrap_or(0))
}

/// Host wall clock now, in nanoseconds since the Unix epoch.
fn now_realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// The frequency the counter should be made to run at: an explicit override
/// first, else whatever the capture recorded, else 0 (leave it at the host
/// rate). `Some(0)` from the override is the opt-out and deliberately wins over
/// a recorded frequency.
fn effective_guest_hz(override_hz: Option<u64>, captured: Option<u64>) -> u64 {
    override_hz.or(captured).unwrap_or(0)
}

/// An explicit `CHM_GUEST_CNTFRQ` override. `Some(0)` means "do not scale".
///
/// A guest caches `CNTFRQ_EL0` once at boot and never re-reads it, and Apple
/// exposes no way to change the value an HVF guest sees, so a snapshot captured
/// on a host with a different counter frequency has permanently wrong
/// timekeeping unless the counter is made to run at the rate the guest expects.
///
/// This used to be the *only* way to turn that synthesis on, because a
/// pre-`69637dde6` capture does not record the frequency and guessing it would
/// have been worse than a visibly slow guest. It is now an override: a capture
/// that states its own frequency is believed (see [`snapshot_cntfrq`]), and this
/// exists to correct a capture that cannot, or to switch the correction off.
fn requested_guest_cntfrq() -> Option<u64> {
    std::env::var("CHM_GUEST_CNTFRQ")
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// This vCPU's SMP cross-delivery handle (its injection queue + wake), for the
/// userspace-GIC SGI routing table. `None` if the vCPU is not an HVF vCPU.
pub fn usgic_cpu_handle(vcpu: &mut Box<dyn Vcpu>) -> Option<UsgicCpuHandle> {
    vcpu.as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .map(|c| c.usgic_cpu_handle())
}

/// Install the cross-vCPU SGI delivery table (every vCPU's inject queue + wake,
/// indexed by vCPU id) on this vCPU, so an SGI it raises routes to the target
/// core(s). A no-op if the vCPU is not an HVF vCPU.
pub fn usgic_set_cpu_table(vcpu: &mut Box<dyn Vcpu>, table: Arc<Vec<UsgicCpuHandle>>) {
    if let Some(c) = vcpu.as_any_concrete_mut().downcast_mut::<HvfVcpu>() {
        c.usgic_set_cpu_table(table);
    }
}
/// VM handle, its mapped guest RAM, the restored-shell managed GIC, and a host
/// view of guest memory.
///
/// This split exists for SMP resume: HVF binds every vCPU to the host thread
/// that created it, so each vCPU must be created (and have its register file
/// restored, and be run) on its own thread. The work that is NOT per-vCPU —
/// mapping RAM and creating the GIC — happens here on the calling thread, and
/// the caller then spawns one thread per vCPU.
pub struct PreparedVm {
    /// The restored-shell managed GICv3 (distributor not yet restored).
    pub gic: Arc<Mutex<dyn Vgic>>,
    /// Host view of guest RAM, sharing the hypervisor's backing pointers.
    pub guest_mem: Arc<GuestMemory>,
    /// Host-side guest-RAM backings (keep alive for the VM's lifetime; must
    /// outlive `guest_mem` and the VM mapping).
    pub ram: Vec<GuestRam>,
    /// The reconstructed VM. Declared LAST so it is dropped last: HVF requires
    /// every vCPU to be destroyed before the VM, and the GIC + guest-RAM
    /// mappings belong to the VM, so `hv_vm_destroy` must run after them.
    pub vm: Arc<dyn Vm>,
}

/// Create the VM, map guest RAM, and create the managed GIC shell — everything
/// up to (but not including) vCPU creation. See [`PreparedVm`].
pub fn prepare_vm(
    hv: &dyn Hypervisor,
    snap: &Snapshot,
    memory_ranges: &Path,
) -> Result<PreparedVm, RehydrateError> {
    let vm = hv
        .create_vm(HypervisorVmConfig {
            nested: false,
            smt_enabled: false,
        })
        .map_err(|e| RehydrateError::Hv(anyhow!("create_vm: {}", full_chain(&e))))?;

    // --- guest RAM ----------------------------------------------------------
    let guest_mem = Arc::new(GuestMemory::new());
    let mut ram = Vec::with_capacity(snap.mem_mappings.len());
    for m in &snap.mem_mappings {
        let backing = GuestRam::map_file(memory_ranges, m.file_offset, m.size as usize)?;
        // SAFETY: `backing` outlives the VM (the caller keeps `ram` alive).
        unsafe {
            vm.create_user_memory_region(m.slot, m.gpa, m.size as usize, backing.ptr, false, false)
                .map_err(|e| RehydrateError::Hv(anyhow!("map RAM @ {:#x}: {e}", m.gpa)))?;
        }
        // Register the SAME host pointer with the device-model memory view so a
        // virtio device sees exactly what the guest sees.
        // SAFETY: `backing.ptr` is valid for `m.size` bytes for the VM's
        // lifetime; the caller drops `guest_mem` before `ram`, so the pointer
        // never outlives its mapping, and the device model is the only other
        // reader/writer of guest RAM.
        unsafe {
            guest_mem.register(m.gpa, backing.ptr, m.size as usize);
        }
        ram.push(backing);
    }

    // --- GIC ---------------------------------------------------------------
    let gic = vm.create_vgic(&snap.vgic_config()).map_err(|e| {
        use std::error::Error;
        let mut msg = format!("create_vgic: {e}");
        let mut src = e.source();
        while let Some(s) = src {
            msg.push_str(&format!(" -> {s}"));
            src = s.source();
        }
        RehydrateError::Hv(anyhow!(msg))
    })?;

    Ok(PreparedVm {
        vm,
        gic,
        guest_mem,
        ram,
    })
}

/// Restore the global GIC distributor registers from the snapshot.
///
/// Skips the distributor *active* SPI registers (GICD_ISACTIVER 0x300 /
/// GICD_ICACTIVER 0x380, the 0x300..0x400 block). Apple's managed GIC cannot
/// accept a cold-restored active SPI: hv_gic_set_distributor_reg(ISACTIVER)
/// walks an internal active-redistributor list that is only built as the GIC
/// itself delivers an interrupt, so a restore-time write dereferences a null
/// entry and faults (proven on hardware, macOS 26.x). A GICv2M-routed snapshot
/// is the first to carry active SPIs at all (virtio completions are SPIs, not
/// LPIs), which is why earlier ITS snapshots never hit this.
///
/// Correctness is preserved without the distributor active bit: a vCPU that was
/// mid-IRQ-handler at snapshot has its CPU-interface active-priority state
/// (ICC_AP1R*) restored via set_state, so it still performs the priority drop
/// on EOI and returns from the handler. The pending registers (ISPENDR/ICPENDR)
/// ARE restored, so any not-yet-taken completion fires.
pub fn restore_distributor(
    gic: &Arc<Mutex<dyn Vgic>>,
    snap: &Snapshot,
) -> Result<(), RehydrateError> {
    let mut guard = gic.lock().unwrap();
    let concrete = guard
        .as_any_concrete_mut()
        .downcast_mut::<HvfGicV3>()
        .ok_or_else(|| RehydrateError::Translate("GIC is not an HVF GIC".into()))?;
    let dist_pairs = dist_to_hvf(&snap.gic_dist)
        .ok_or_else(|| RehydrateError::Translate("distributor dump did not translate".into()))?;
    for (reg, val) in dist_pairs {
        // GICD_ISACTIVER (0x300..0x380) / GICD_ICACTIVER (0x380..0x400).
        if (0x300..0x400).contains(&reg) {
            continue;
        }
        concrete
            .set_distributor_reg(reg, val)
            .map_err(|e| RehydrateError::Hv(anyhow!("set GICD[{reg:#x}]: {e}")))?;
    }
    Ok(())
}

/// Restore one vCPU's architectural state: its register file (which sets MPIDR
/// and the ICC CPU interface) and then its GIC redistributor frame.
///
/// MUST run on the host thread that created — and will run — this vCPU: HVF
/// binds a vCPU to its creating thread, and the register/redistributor writes
/// go through that thread's vCPU handle. The global distributor must already be
/// restored ([`restore_distributor`]) so the redistributors exist.
pub fn restore_vcpu_state(
    vcpu: &mut Box<dyn Vcpu>,
    snap: &Snapshot,
    id: usize,
) -> Result<(), RehydrateError> {
    vcpu.set_state(&CpuState::Hvf(snap.vcpus[id].clone()))
        .map_err(|e| RehydrateError::Hv(anyhow!("restore vCPU {id} state: {e}")))?;

    let redist_pairs = redist_to_hvf(&snap.rdist_slice(id)).ok_or_else(|| {
        RehydrateError::Translate(format!("vCPU {id} redistributor did not translate"))
    })?;
    let concrete = vcpu
        .as_any_concrete_mut()
        .downcast_mut::<HvfVcpu>()
        .ok_or_else(|| RehydrateError::Translate("vCPU is not an HVF vCPU".into()))?;
    for (reg, val) in redist_pairs {
        concrete
            .set_redistributor_reg(reg, val)
            .map_err(|e| RehydrateError::Hv(anyhow!("vCPU {id} set GICR[{reg:#x}]: {e}")))?;
    }

    // Reseed this vCPU's virtual-counter offset from the SHARED reference (vCPU0's
    // captured CNTVCT) rather than its own, so every core resumes on one
    // synchronized virtual counter. `set_state` already seeded a per-vCPU offset
    // from this vCPU's own captured CNTVCT; on an SMP guest those values diverge
    // and the secondary's timer never fires, so this override is load-bearing for
    // multi-vCPU resume (and a harmless no-op re-seed for a single vCPU, whose
    // reference IS its own CNTVCT). See [`Snapshot::reference_cntvct`].
    //
    // NOTE: this is the managed-GIC (GICv2M) path, which seeds each vCPU on its
    // own thread and so still leaves cores skewed by however far apart those
    // calls land — the defect [`VtimerClock`] closes on the userspace-GIC path.
    // Vanilla GICv3 snapshots (the supported contract since #102) never come
    // through here; rate scaling is deliberately not offered on this path
    // because without the clock it cannot be made coherent.
    if let Some(reference) = snap.reference_cntvct() {
        concrete
            .restore_vtimer_offset(reference)
            .map_err(|e| RehydrateError::Hv(anyhow!("vCPU {id} reseed vtimer offset: {e}")))?;
    }
    Ok(())
}

/// Enable Group1 SPI forwarding in the distributor.
///
/// cloud-hypervisor's KVM distributor dump (`VGIC_DIST_REGS`) starts at
/// GICD_STATUSR and does NOT carry GICD_CTLR, so the distributor restore never
/// enables interrupt-group forwarding. Apple's managed GIC comes up with
/// GICD_CTLR = ARE | DS (0x50) but both group-enable bits clear, so the
/// distributor forwards NO SPIs: a resumed guest still takes redistributor PPIs
/// (the virtual timer, gated only by ICC_IGRPEN1) and so drives systemd, but
/// every virtio completion delivered as a Group1 message-based SPI sits pending
/// in the distributor and is never presented to the CPU interface — the guest
/// blocks forever on its first post-resume disk write (jbd2). Set
/// GICD_CTLR.EnableGrp1 so Group1 SPIs forward; the guest ran with Group1
/// enabled at capture, so this restores its real distributor state. Call after
/// the redistributors/MPIDR are restored to respect HVF ordering.
pub fn enable_group1_spi_forwarding(
    gic: &Arc<Mutex<dyn Vgic>>,
) -> Result<(), RehydrateError> {
    const GICD_CTLR_ENABLE_GRP1: u64 = 1 << 1;
    let mut guard = gic.lock().unwrap();
    let concrete = guard
        .as_any_concrete_mut()
        .downcast_mut::<HvfGicV3>()
        .ok_or_else(|| RehydrateError::Translate("GIC is not an HVF GIC".into()))?;
    let ctlr = concrete
        .distributor_reg(0x0000)
        .map_err(|e| RehydrateError::Hv(anyhow!("read GICD_CTLR: {e}")))?;
    concrete
        .set_distributor_reg(0x0000, ctlr | GICD_CTLR_ENABLE_GRP1)
        .map_err(|e| RehydrateError::Hv(anyhow!("set GICD_CTLR: {e}")))?;
    Ok(())
}

// --- small JSON helpers -----------------------------------------------------

/// Pull the embedded `snapshot_data.state` string out of a nested snapshot node
/// and parse it as JSON. `path` walks `snapshots` keys down to the target node.
fn embedded_state(
    snaps: &serde_json::Value,
    path: &[&str],
) -> Result<serde_json::Value, RehydrateError> {
    let mut node = snaps;
    for (i, key) in path.iter().enumerate() {
        node = node
            .get(key)
            .ok_or_else(|| RehydrateError::Malformed(format!("missing snapshot node `{key}`")))?;
        // Every level except the last is reached through its `snapshots` map.
        if i + 1 < path.len() {
            node = node
                .get("snapshots")
                .ok_or_else(|| RehydrateError::Malformed(format!("`{key}` has no children")))?;
        }
    }
    let state_str = node
        .get("snapshot_data")
        .and_then(|d| d.get("state"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            RehydrateError::Malformed(format!("node `{}` has no state string", path.join("/")))
        })?;
    Ok(serde_json::from_str(state_str)?)
}

fn u64_field(v: &serde_json::Value, key: &str) -> Result<u64, RehydrateError> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| RehydrateError::Malformed(format!("missing/invalid u64 field `{key}`")))
}

fn u32_vec(v: &serde_json::Value, key: &str) -> Result<Vec<u32>, RehydrateError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| RehydrateError::Malformed(format!("missing array field `{key}`")))?
        .iter()
        .map(|n| {
            n.as_u64()
                .map(|x| x as u32)
                .ok_or_else(|| RehydrateError::Malformed(format!("non-integer in `{key}`")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture states its own counter frequency, so believing it is what
    /// makes a vanilla cloud snapshot keep correct time with no flags at all.
    /// An explicit override still wins — including `0`, which is the documented
    /// way to decline the correction and accept the dilation instead.
    #[test]
    fn a_captures_own_frequency_drives_correction_unless_overridden() {
        // Nothing known, nothing to do.
        assert_eq!(effective_guest_hz(None, None), 0);
        // The Graviton2 case: the capture says 121.875 MHz, so use it.
        assert_eq!(effective_guest_hz(None, Some(121_875_000)), 121_875_000);
        // A pre-69637dde6 capture records nothing; the override supplies it.
        assert_eq!(effective_guest_hz(Some(121_875_000), None), 121_875_000);
        // The override beats the recorded value when they disagree.
        assert_eq!(
            effective_guest_hz(Some(100_000_000), Some(121_875_000)),
            100_000_000
        );
        // `CHM_GUEST_CNTFRQ=0` opts out even though the capture states a rate.
        assert_eq!(effective_guest_hz(Some(0), Some(121_875_000)), 0);
    }

    /// A snapshot resumes frozen at the instant it was captured unless the
    /// elapsed wall time is added back, and a stale guest clock is not cosmetic:
    /// a 5-hour-old capture had `apt-get update` refuse two repositories as
    /// "not valid yet". Converted with the frequency the GUEST believes it has,
    /// since that is the rate it reads its own counter at.
    #[test]
    fn the_counter_is_advanced_over_the_time_a_snapshot_sat_still() {
        const HZ: u64 = 121_875_000;
        let then = PLAUSIBLE_EPOCH_FLOOR_NS + 86_400_000_000_000;

        // Five hours later: 5 * 3600 * 121_875_000 ticks further on.
        let five_hours = 5 * 3_600 * 1_000_000_000u64;
        assert_eq!(
            advance_to_wall_clock(1_000, Some(then), then + five_hours, HZ),
            1_000 + 5 * 3_600 * HZ
        );

        // Same instant: nothing to add.
        assert_eq!(advance_to_wall_clock(1_000, Some(then), then, HZ), 1_000);

        // Host clock BEHIND the capture: never rewind the guest.
        assert_eq!(
            advance_to_wall_clock(1_000, Some(then), then - 60_000_000_000, HZ),
            1_000
        );

        // A capture that recorded no time is left exactly as captured.
        assert_eq!(advance_to_wall_clock(1_000, None, then, HZ), 1_000);

        // A zero or otherwise implausible field would throw the guest ~57 years
        // forward, so it is rejected rather than believed.
        assert_eq!(advance_to_wall_clock(1_000, Some(0), then, HZ), 1_000);
        assert_eq!(
            advance_to_wall_clock(1_000, Some(PLAUSIBLE_EPOCH_FLOOR_NS - 1), then, HZ),
            1_000
        );

        // Unknown guest frequency: the tick conversion is undefined, so skip it.
        assert_eq!(
            advance_to_wall_clock(1_000, Some(then), then + five_hours, 0),
            1_000
        );
    }

    /// The clock block is doubly encoded — a JSON string inside JSON — and a
    /// capture predating upstream `69637dde6` writes `{}` there rather than
    /// omitting it, so "absent" has to be distinguished from "malformed".
    #[test]
    fn snapshot_cntfrq_reads_the_doubly_encoded_clock_block() {
        let with_clock =
            r#"{"snapshot_data":{"state":"{\"clock\":{\"cntvct\":1,\"cntfrq\":121875000}}"}}"#;
        assert_eq!(snapshot_cntfrq(with_clock), Some(121_875_000));
        assert_eq!(snapshot_cntfrq(r#"{"snapshot_data":{"state":"{}"}}"#), None);
        assert_eq!(snapshot_cntfrq(r#"{"snapshots":{}}"#), None);
        assert_eq!(snapshot_cntfrq("not json"), None);
    }

    /// The populate walk strides threads across chunks, so a thread count above
    /// the chunk count would spawn threads with no work — and a count of zero
    /// would silently skip the populate entirely, quietly undoing #95.
    #[test]
    fn willneed_thread_count_is_bounded_by_chunks_and_never_zero() {
        assert_eq!(
            willneed_threads(1),
            1,
            "a single chunk needs a single thread"
        );
        assert_eq!(
            willneed_threads(0),
            1,
            "an empty region must still be valid"
        );
        let many = willneed_threads(1024);
        assert!((1..=8).contains(&many), "unbounded thread count: {many}");
        // Monotonic: more chunks can never mean fewer threads.
        assert!(willneed_threads(16) >= willneed_threads(2));
    }

    // cloud-hypervisor dumps redistributors in two passes: every vCPU's RD_base
    // registers, then every vCPU's SGI-frame registers. `reassemble_rdist_slice`
    // must stitch one vCPU's two runs back into the contiguous order
    // `redist_to_hvf` expects. Build a synthetic 2-vCPU dump whose words encode
    // their (section, vcpu, index) so the reassembly is checkable exactly.
    #[test]
    fn reassembles_two_pass_redistributor_dump() {
        let rd = redist_rd_base_words();
        let per = redist_words_per_vcpu();
        let sgi = per - rd;
        let n = 2;

        // Layout: [v0 rd][v1 rd][v0 sgi][v1 sgi]. Encode each word distinctly.
        let mut dump = vec![0u32; n * per];
        for v in 0..n {
            for i in 0..rd {
                dump[v * rd + i] = 0x1000 + (v as u32) * 0x100 + i as u32; // rd
            }
            for i in 0..sgi {
                dump[n * rd + v * sgi + i] = 0x2000 + (v as u32) * 0x100 + i as u32; // sgi
            }
        }

        for v in 0..n {
            let slice = reassemble_rdist_slice(&dump, n, v);
            assert_eq!(slice.len(), per, "slice for vcpu {v} must be one full vcpu");
            for i in 0..rd {
                assert_eq!(slice[i], 0x1000 + (v as u32) * 0x100 + i as u32);
            }
            for i in 0..sgi {
                assert_eq!(slice[rd + i], 0x2000 + (v as u32) * 0x100 + i as u32);
            }
        }
    }

    // For a single vCPU the two sections are already contiguous, so the slice is
    // the whole dump unchanged (the pre-M20 behaviour we must not regress).
    #[test]
    fn single_vcpu_slice_is_identity() {
        let per = redist_words_per_vcpu();
        let dump: Vec<u32> = (0..per as u32).collect();
        assert_eq!(reassemble_rdist_slice(&dump, 1, 0), dump);
    }
}
