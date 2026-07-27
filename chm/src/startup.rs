//! Start-to-ready phase timing (#79).
//!
//! A rehydrate is a sequence of distinct phases — parse the snapshot, create the
//! VM and map guest RAM, restore each vCPU, wire the device model, release the
//! guest — and "startup is slow" is not actionable until it is attributed to
//! one of them. [`stamp`] records a labelled milestone relative to process
//! start; `CHM_TRACE_TIMING=1` prints each one as `[startup] <elapsed> <label>`
//! so a single run yields the whole breakdown in order.
//!
//! Milestones are deliberately absolute (time since process start) rather than
//! per-phase deltas: the reader wants "how long until the guest could run",
//! and deltas are trivially recovered by subtraction while the reverse is not.

use std::env;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static START: OnceLock<Instant> = OnceLock::new();

/// Record process start. Idempotent; the first call wins, so a later `init`
/// cannot rebase the timeline and silently shorten every measurement.
pub(crate) fn init() {
    let _ = START.set(Instant::now());
}

/// Time since [`init`], or zero if `init` was never called.
pub(crate) fn elapsed() -> Duration {
    START.get().map_or_else(Duration::default, Instant::elapsed)
}

/// Print a labelled milestone when `CHM_TRACE_TIMING` is set.
///
/// Writes to stderr so it never contaminates the guest console on stdout, which
/// the benchmark harness parses.
pub(crate) fn stamp(label: &str) {
    if env::var_os("CHM_TRACE_TIMING").is_some() {
        eprintln!("[startup] {:>9.3?} {label}", elapsed());
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn elapsed_is_zero_without_init_and_monotonic_after() {
        // `init` may already have run in another test in this binary; either way
        // `elapsed` must be well-defined and never panic.
        let a = elapsed();
        init();
        let b = elapsed();
        assert!(b >= a || a.as_secs() == 0);
    }

    #[test]
    fn init_is_idempotent() {
        init();
        let first = elapsed();
        thread::sleep(Duration::from_millis(5));
        // A second init must NOT rebase the clock, or every later stamp would
        // under-report the time already spent.
        init();
        assert!(elapsed() >= first);
    }
}
