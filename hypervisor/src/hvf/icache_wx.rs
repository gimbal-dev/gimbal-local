// Copyright © 2026 Gimbal
//
// SPDX-License-Identifier: Apache-2.0

//! Host-side instruction-cache maintenance for guests whose kernel skips it.
//!
//! # The problem this exists to solve
//!
//! Linux decides once, at boot, whether it must issue `ic ivau` when it makes
//! a page executable. If `CTR_EL0.DIC` reads 1 the hardware promises the
//! instruction cache snoops the data side, so the kernel *alternative-patches
//! the `ic ivau` out of `caches_clean_inval_pou()`* — the function behind
//! `__sync_icache_dcache()`, which runs on every `execve` and every shared
//! library mapping, not merely in a JIT.
//!
//! Graviton2 reports `DIC = 1`. Apple silicon reports `DIC = 0`. A snapshot
//! captured on Graviton carries those NOPs in its kernel text, and rehydrating
//! it here does not — cannot — put the instruction back: the decision was made
//! and burned in before we ever saw the guest.
//!
//! The consequence for *self-modifying code* is measured: a rehydrated guest
//! that maps a page RW, writes instructions into it, `mprotect`s it RX and
//! calls it fetched stale instructions **955 times out of 1000**, and an
//! explicit `ic ivau` took the same probe to **0 of 1000**. That is the hazard
//! this module exists for, and it is why `npm`, Java and .NET die on a
//! rehydrated capture.
//!
//! # What this module is NOT the cause of (#274), and how that was established
//!
//! This module was originally built on the belief that the same elision
//! explained the userspace crashes a rehydrated guest suffers under ordinary
//! `dd`/`sync`/`rm` load — 30-35 processes killed in 16 minutes against zero
//! for the identical load cold-booted. **That attribution is false**, and the
//! disproof is recorded here because the reasoning was expensive:
//!
//! - Arming the DMA hook and instrumenting it proved the mechanism *live*:
//!   1,277,598 invalidations over 266 MiB in a single short run. The crash
//!   count did not move.
//! - The primitive itself was then proved rather than assumed, by
//!   `host_side_icache_invalidation_is_visible_to_the_guest`: the guest runs a
//!   routine, the host overwrites it through the host mapping and calls
//!   `sys_icache_invalidate`, and the guest's next call returns the *new*
//!   answer. So a null result is disconfirmation of the hypothesis, not of the
//!   mechanism.
//! - Running the identical load entirely in `tmpfs` — zero virtio-blk data
//!   traffic, so nothing for the DMA hook to cover — still crashed 27 times.
//! - The signal composition argued against it all along: 18 of the 35 were
//!   glibc *data*-integrity aborts (`stack smashing detected`, malloc tcache)
//!   and only 1 was SIGILL. A stale fetch presents as SIGILL; it does not
//!   present as a valid code path finding a smashed canary.
//!
//! The real cause is a different boot-latched CPU feature: Graviton2 advertises
//! 16-bit ASIDs (`ID_AA64MMFR0_EL1.ASIDBits = 2`, and the guest log confirms
//! `ASID allocator initialised with 32768 entries`) while Apple silicon
//! implements 8, so past ~256 live address spaces unrelated processes share TLB
//! contexts. `chm`'s `asid_width_guard` warns about it; see
//! `docs/cpu-feature-deltas.md`.
//!
//! # Why the host can fix the hazard it *does* cover
//!
//! Guest RAM is ordinary memory in this process, and the instruction cache is
//! physically indexed, so `sys_icache_invalidate` on our own mapping reaches
//! exactly the lines the guest would have invalidated. The guest cannot repair
//! itself; we can repair it from outside.
//!
//! What is *not* available is doing it bluntly. Invalidating a whole 8 GiB
//! guest measures at 1.7-2.9 s — unusable at any cadence. It has to be paid
//! per page, only for pages that are actually written and then executed.
//!
//! # The two mechanisms, and why one is not enough
//!
//! Content arrives in a guest page by two completely different routes, and
//! they need different treatment:
//!
//! 1. **The guest's own CPU writes it** — a JIT, a module load, ftrace, a
//!    static-key patch. Caught by stage-2 W^X: RAM is held writable but not
//!    executable, so the first *fetch* from a page traps, we invalidate that
//!    page and grant execute. A later *write* to an executable page traps in
//!    turn, and we take execute away again so the next fetch re-invalidates.
//!    Feasibility of both halves is proved on hardware by
//!    `hvf_can_trap_a_guest_instruction_fetch_and_grant_execute_afterwards`.
//!    This is the route the 955/1000 probe measures, and it is the one that is
//!    **off by default** — see the granule livelock below.
//!
//! 2. **We write it, for a device** — a virtio-blk read landing file content in
//!    the page cache. Invisible to stage 2: the host stores into its own
//!    mapping, so no guest fault occurs and the page keeps whatever permission
//!    it had. Handled instead by invalidating the destination range as the DMA
//!    completes, which is the same thing the guest kernel would have done had
//!    it not been patched. Cheap, cannot livelock, and therefore on by default
//!    — but note that its measured benefit is, so far, **zero**: it was armed
//!    to fix #274 and #274 turned out to be something else. It is kept because
//!    it is the correct behaviour for a kernel that has been patched not to do
//!    it, not because a workload has yet been shown to need it.
//!
//! Neither subsumes the other, and only one of them is on by default. Why is
//! the next section, and it was measured rather than reasoned.
//!
//! # Why stage-2 W^X is opt-in: the granule livelocks
//!
//! `hv_vm_protect` works in *host* pages, and Apple silicon pages in 16 KiB
//! while the guest pages in 4 KiB. One host page therefore covers four guest
//! pages, and a thread whose code and data land in the same 16 KiB — which
//! costs only 4 KiB of separation — makes **no forward progress at all**:
//!
//! ```text
//! fetch  -> page not executable -> grant X, revoke W -> retry
//! store  -> page not writable   -> grant W, revoke X -> retry
//! fetch  -> ...
//! ```
//!
//! Neither fault ever retires an instruction. Measured on a rehydrated
//! 2-vCPU Graviton capture: `watchdog: BUG: soft lockup - CPU#0 stuck for 21s!
//! [sd-resolve:510]`, climbing past 558s, starting the instant the guest
//! resumed and before any load was applied. The other vCPU ran normally, which
//! is the signature — this traps a *thread*, not a machine.
//!
//! Splitting W from X is only sound when the granule can separate them, so
//! this half stays behind `CHM_ICACHE_WX_STRICT=1` until it carries a
//! progress guarantee (promote a thrashing page to RWX and re-arm it at a
//! synchronisation point, rather than bouncing it forever). It is kept, rather
//! than deleted, because it is the only mechanism that can reach the *kernel*
//! side of the same hazard — module loading, ftrace, BPF and static-key
//! patching — which is the leading suspect for the permanent resume wedge in
//! #257.
//!
//! The DMA half has no such problem: it does no permission changes and cannot
//! livelock. That is the default — see above for the honest accounting of what
//! it has been measured to buy.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::ffi::{HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_vm_protect};

// SAFETY: libSystem. Cleans the data cache and invalidates the instruction
// cache for a host virtual range — the maintenance a JIT performs, and exactly
// the sequence the guest kernel's `caches_clean_inval_pou()` has had patched
// out.
unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
}

/// A stretch of guest RAM, with the host mapping that backs it.
#[derive(Clone, Copy, Debug)]
struct Region {
    ipa: u64,
    host_va: usize,
    size: usize,
}

impl Region {
    fn contains(&self, ipa: u64) -> bool {
        ipa >= self.ipa && (ipa - self.ipa) < self.size as u64
    }

    /// Host address for a guest physical address inside this region.
    fn host_of(&self, ipa: u64) -> usize {
        self.host_va + (ipa - self.ipa) as usize
    }
}

/// Which way a page is currently usable. A page is never both, which is the
/// whole point: the transition between them is the only moment we get to do
/// the maintenance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PageState {
    /// Writable, not executable. Every page starts here.
    Writable,
    /// Executable, not writable. Its instruction cache was invalidated at the
    /// moment it was granted execute.
    Executable,
}

/// Process-global, deliberately.
///
/// `hv_vm_map` and `hv_vm_protect` take no VM handle: they act on *the*
/// VM of this process, because HVF permits exactly one. A per-`HvfVm` field
/// would imply a multiplicity the platform does not have, and would then need
/// threading down to every vCPU that takes a fault.
struct State {
    regions: Vec<Region>,
    pages: HashMap<u64, PageState>,
    page_size: usize,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static ARMED: AtomicBool = AtomicBool::new(false);
static WX_ENFORCED: AtomicBool = AtomicBool::new(false);

static EXEC_FAULTS: AtomicU64 = AtomicU64::new(0);
static WRITE_FAULTS: AtomicU64 = AtomicU64::new(0);
static DMA_INVALIDATIONS: AtomicU64 = AtomicU64::new(0);
static DMA_BYTES: AtomicU64 = AtomicU64::new(0);

/// Is host-side maintenance switched on for this VM?
///
/// Read on the data-abort path, so it is an atomic rather than a lock: a guest
/// that never enables this must not pay a mutex per MMIO exit.
pub fn armed() -> bool {
    ARMED.load(Ordering::Relaxed)
}

/// Is the stage-2 W^X half switched on as well?
///
/// Separate from [`armed`] because it is the half that can livelock on a 16 KiB
/// granule (see the module docs), so it is opt-in while the DMA half is not.
pub fn wx_enforced() -> bool {
    WX_ENFORCED.load(Ordering::Relaxed)
}

/// Host page size, which is the granule `hv_vm_protect` insists on.
fn host_page_size() -> usize {
    // SAFETY: libc, no arguments that can be invalid.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as usize } else { 16384 }
}

/// Invalidate the instruction cache for a host range.
fn invalidate(host_va: usize, len: usize) {
    // SAFETY: the caller has established that `host_va..host_va+len` lies
    // inside a live guest-RAM mapping, which we own for the VM's lifetime.
    unsafe { sys_icache_invalidate(host_va as *mut c_void, len) };
}

fn protect(ipa: u64, size: usize, flags: u64) -> Result<(), i32> {
    // SAFETY: FFI. `ipa..ipa+size` is page-aligned and inside a region that was
    // mapped by `create_user_memory_region` and is not unmapped while armed.
    let rc = unsafe { hv_vm_protect(ipa, size, flags) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Start holding guest RAM writable-but-not-executable.
///
/// `regions` is `(guest physical base, host virtual base, length)`. Called once
/// the guest's RAM is mapped and its contents are final — after a snapshot
/// restore has written them, not before, since restoring RAM is itself a bulk
/// host write into pages the guest is about to execute.
///
/// The whole of RAM is invalidated once here. That is the expensive operation
/// this design otherwise avoids, and it is affordable exactly once, at a point
/// where the guest is not yet running and a second or two is not a stall.
pub fn arm(regions: &[(u64, usize, usize)]) -> Result<(), String> {
    let strict = std::env::var("CHM_ICACHE_WX_STRICT").as_deref() == Ok("1");
    let page_size = host_page_size();
    let mut regs = Vec::with_capacity(regions.len());
    for &(ipa, host_va, size) in regions {
        if strict && (ipa % page_size as u64 != 0 || size % page_size != 0) {
            return Err(format!(
                "guest RAM region {ipa:#x}+{size:#x} is not a multiple of the \
                 {page_size}-byte host page, so stage-2 permissions cannot be \
                 changed a page at a time"
            ));
        }
        // Whatever wrote this RAM -- a snapshot restore, a kernel load -- wrote
        // it from the host side, so it carries exactly the hazard this module
        // exists for. This is the one blanket invalidation the design allows
        // itself, and it is affordable because the guest is not yet running.
        invalidate(host_va, size);
        if strict {
            protect(ipa, size, HV_MEMORY_READ | HV_MEMORY_WRITE).map_err(|rc| {
                format!(
                    "hv_vm_protect({ipa:#x}, {size:#x}, RW) failed: {:#010x}",
                    rc as u32
                )
            })?;
        }
        regs.push(Region { ipa, host_va, size });
    }
    *STATE.lock().unwrap() = Some(State {
        regions: regs,
        pages: HashMap::new(),
        page_size,
    });
    WX_ENFORCED.store(strict, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Stop enforcing W^X and hand every page back as read/write/execute.
///
/// Used when tearing a VM down, and by tests that need the ordinary mapping
/// back. Failures are reported but do not abort the rest of the walk: a VM on
/// its way out should release what it can.
pub fn disarm() {
    let was_enforcing = WX_ENFORCED.swap(false, Ordering::SeqCst);
    ARMED.store(false, Ordering::SeqCst);
    let mut guard = STATE.lock().unwrap();
    if let Some(state) = guard.take()
        && was_enforcing
    {
        for r in &state.regions {
            let _ = protect(
                r.ipa,
                r.size,
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            );
        }
    }
}

/// The guest tried to fetch an instruction from a page we are holding
/// non-executable.
///
/// This is the moment the maintenance has to happen: the page's contents are
/// final (the writer has stopped, or it would still be writing) and the guest
/// has not yet run a single instruction from it. Invalidate, then grant
/// execute and take write away, so that anything writing to it later comes
/// back through [`on_write_fault`] and we get to do this again.
///
/// Returns false when the address is not guest RAM we manage, in which case the
/// caller must treat the fault as it would have before.
pub fn on_exec_fault(ipa: u64) -> bool {
    if !wx_enforced() {
        return false;
    }
    let mut guard = STATE.lock().unwrap();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    let page_size = state.page_size;
    let Some(region) = state.regions.iter().copied().find(|r| r.contains(ipa)) else {
        return false;
    };
    let page = ipa & !(page_size as u64 - 1);
    invalidate(region.host_of(page), page_size);
    if protect(page, page_size, HV_MEMORY_READ | HV_MEMORY_EXEC).is_err() {
        return false;
    }
    state.pages.insert(page, PageState::Executable);
    EXEC_FAULTS.fetch_add(1, Ordering::Relaxed);
    true
}

/// The guest wrote to a page we had granted execute.
///
/// Take execute away rather than invalidating now: the write is only starting,
/// and whatever else the writer is about to store would land after an
/// invalidation done here. Deferring to the next fetch is both cheaper and the
/// only ordering that is actually correct.
///
/// Returns false when this is not a page we manage — importantly including
/// every MMIO address, so a device access is never mistaken for a W^X fault.
pub fn on_write_fault(ipa: u64) -> bool {
    if !wx_enforced() {
        return false;
    }
    let mut guard = STATE.lock().unwrap();
    let Some(state) = guard.as_mut() else {
        return false;
    };
    let page_size = state.page_size;
    if !state.regions.iter().any(|r| r.contains(ipa)) {
        return false;
    }
    let page = ipa & !(page_size as u64 - 1);
    // A page we have never granted execute to is already writable, so a fault
    // on it is not ours — say so rather than silently absorbing a fault the
    // guest needs to see reported.
    if state.pages.get(&page) != Some(&PageState::Executable) {
        return false;
    }
    if protect(page, page_size, HV_MEMORY_READ | HV_MEMORY_WRITE).is_err() {
        return false;
    }
    state.pages.insert(page, PageState::Writable);
    WRITE_FAULTS.fetch_add(1, Ordering::Relaxed);
    true
}

/// A device just wrote `len` bytes into guest RAM at host address `dst`.
///
/// Call this *after* the bytes have landed. Stage 2 cannot see this write — it
/// went through our own mapping, not the guest's — so there is no fault to
/// hang the maintenance off, and a page that was already executable would keep
/// its stale instruction lines. This is the path an `execve` takes: file
/// content DMAs into a page-cache page and is then jumped to.
///
/// Takes the host address rather than the guest physical one because the
/// caller already has it, and that keeps this path free of both a lock and a
/// region lookup. It runs on every virtio completion — including four-byte
/// used-ring updates — so anything more than an atomic load and the
/// invalidation itself would be a tax on the whole device stack.
///
/// Cheap by construction: proportional to the transfer, not to RAM.
pub fn on_device_write(dst: *mut u8, len: usize) {
    if len == 0 || !armed() {
        return;
    }
    invalidate(dst as usize, len);
    DMA_INVALIDATIONS.fetch_add(1, Ordering::Relaxed);
    DMA_BYTES.fetch_add(len as u64, Ordering::Relaxed);
}

/// `(exec faults, write faults, device invalidations, bytes invalidated)`.
///
/// Exposed so the cost can be reported rather than guessed: the ping-pong a
/// 16 KiB granule can cause on a mixed code/data page is visible here as write
/// faults climbing with exec faults.
pub fn stats() -> (u64, u64, u64, u64) {
    (
        EXEC_FAULTS.load(Ordering::Relaxed),
        WRITE_FAULTS.load(Ordering::Relaxed),
        DMA_INVALIDATIONS.load(Ordering::Relaxed),
        DMA_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The region arithmetic is what decides whether a fault is ours at all, so
    /// an off-by-one here would either drop real MMIO into the W^X path or let
    /// a guest-RAM fault escape to the MMIO handler.
    #[test]
    fn a_region_owns_its_first_byte_and_not_the_one_past_its_end() {
        let r = Region {
            ipa: 0x4000_0000,
            host_va: 0x1_0000,
            size: 0x1000,
        };
        assert!(r.contains(0x4000_0000), "the base address is inside");
        assert!(r.contains(0x4000_0fff), "the last byte is inside");
        assert!(!r.contains(0x4000_1000), "one past the end is outside");
        assert!(!r.contains(0x3fff_ffff), "one before the base is outside");
    }

    /// The host address has to be derived from the offset, not assumed equal to
    /// the IPA: invalidating the wrong host range would report success while
    /// leaving the guest executing stale bytes.
    #[test]
    fn the_host_address_tracks_the_offset_into_the_region() {
        let r = Region {
            ipa: 0x4000_0000,
            host_va: 0x1_0000,
            size: 0x1_0000,
        };
        assert_eq!(r.host_of(0x4000_0000), 0x1_0000);
        assert_eq!(r.host_of(0x4000_1234), 0x1_1234);
    }

    /// `hv_vm_protect` refuses anything that is not page aligned, so arming on a
    /// misaligned region must be refused here with an explanation rather than
    /// failing later as an opaque HVF error code.
    #[test]
    fn arming_refuses_a_region_that_cannot_be_protected_a_page_at_a_time() {
        // SAFETY: single-threaded test; the variable is read by `arm` below.
        unsafe { std::env::set_var("CHM_ICACHE_WX_STRICT", "1") };
        let page = host_page_size();
        let backing = vec![0u8; page];
        let err = arm(&[(page as u64 + 1, backing.as_ptr() as usize, page)])
            .expect_err("misaligned base accepted");
        // SAFETY: as above.
        unsafe { std::env::remove_var("CHM_ICACHE_WX_STRICT") };
        assert!(err.contains("host page"), "the refusal must say why: {err}");
        assert!(!armed(), "a refused arm must not leave the VM armed");
    }

    /// The stage-2 half livelocks on a 16 KiB granule (see the module docs), so
    /// it must stay off unless it is asked for by name. If this ever defaults
    /// on again, a rehydrated guest soft-locks on resume.
    #[test]
    fn the_stage_two_half_is_off_unless_it_is_asked_for() {
        disarm();
        // SAFETY: single-threaded test.
        unsafe { std::env::remove_var("CHM_ICACHE_WX_STRICT") };
        let page = host_page_size();
        let backing = vec![0u8; page];
        arm(&[(0x4000_0000, backing.as_ptr() as usize, page)]).expect("arm");
        assert!(armed(), "the DMA half is the default and must be on");
        assert!(
            !wx_enforced(),
            "stage-2 W^X must not be enabled without CHM_ICACHE_WX_STRICT=1"
        );
        assert!(
            !on_exec_fault(0x4000_0000),
            "no fault may be claimed while stage-2 permissions were never changed"
        );
        assert!(!on_write_fault(0x4000_0000));
        disarm();
    }

    /// Nothing may claim a fault while disarmed — otherwise a VM that never
    /// enabled this would have its MMIO swallowed.
    #[test]
    fn a_disarmed_vm_claims_no_faults() {
        disarm();
        assert!(!armed());
        assert!(!on_exec_fault(0x4000_0000));
        assert!(!on_write_fault(0x4000_0000));
        // Must not panic, and must do nothing.
        let mut byte = 0u8;
        on_device_write(&raw mut byte, 1);
    }
}
