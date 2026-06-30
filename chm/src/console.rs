// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Interactive serial console: host keyboard -> guest PL011 receive path.
//!
//! The resumed guest's `agetty`/shell reads `ttyAMA0` through the PL011's
//! interrupt-driven receive FIFO. This module puts the controlling terminal
//! into raw mode (so keystrokes reach the guest immediately, unbuffered and
//! un-echoed by the host) and runs a background thread that feeds stdin bytes
//! into the [`Pl011`] and asserts the UART's interrupt line through the managed
//! GIC, so the guest takes the receive interrupt and reads the byte.
//!
//! A `Ctrl-A x` escape (the QEMU convention) restores the terminal and ends the
//! session, since raw mode otherwise routes `Ctrl-C` to the guest rather than
//! `chm`. It, terminating signals (window close / `kill`), and a guest
//! power-off all funnel through one graceful shutdown that tears the VM down.

use std::io::{self, Read};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use std::{env, mem, thread};

use hypervisor::hvf::devices::Pl011;
use hypervisor::hvf::virtio::pci::MsiSink;

/// Serial PL011 interrupt, as a GIC SPI INTID.
///
/// The serial console's IRQ is NOT carried in the snapshot's serialized device
/// state (the `__serial` node holds only PL011 register values, and the guest
/// FDT that names it is reclaimed RAM after boot), so it cannot be read back
/// directly. It is instead determined by cloud-hypervisor's device/IRQ
/// allocation at capture time. For our GICv2M capture recipe the only
/// enabled non-MSI distributor SPIs are 42 and 43 (the legacy RTC/GPIO/GED/
/// serial block; the virtio MSI-X vectors occupy 128+), and 43 is the
/// interrupt-driven `agetty` line — empirically confirmed by a full
/// host-keystroke login round-trip. `CHM_SERIAL_SPI` overrides it for a
/// snapshot captured under a different device/IRQ order.
const DEFAULT_SERIAL_SPI: u32 = 43;

/// Resolve the serial console's SPI INTID, honoring a `CHM_SERIAL_SPI` override.
pub(crate) fn serial_spi() -> u32 {
    env::var("CHM_SERIAL_SPI")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_SERIAL_SPI)
}

const CTRL_A: u8 = 0x01;

/// A small copyable handle that restores the terminal to its saved mode. Both
/// the [`RawConsole`] guard (on `Drop`) and the stdin pump (on the `Ctrl-A x`
/// escape, before `process::exit`) hold one, so whichever path ends the session
/// puts the terminal back.
#[derive(Clone, Copy)]
pub(crate) struct RestoreHandle {
    fd: i32,
    original: libc::termios,
    active: bool,
}

impl RestoreHandle {
    /// Restore the original terminal mode. Idempotent and safe to call from any
    /// thread (`tcsetattr` on a fd is reentrant for our use).
    pub(crate) fn restore(&self) {
        if self.active {
            // SAFETY: original was filled by tcgetattr on this same fd.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

/// Saved terminal state that restores the controlling terminal to its original
/// (cooked) mode when dropped, so a `chm` exit never leaves the user's shell in
/// raw mode.
pub(crate) struct RawConsole {
    handle: RestoreHandle,
}

impl RawConsole {
    /// Put stdin into raw mode if it is a TTY. When stdin is not a terminal
    /// (e.g. piped input or a non-interactive run) this is a no-op and the
    /// returned guard restores nothing.
    pub(crate) fn enable() -> Self {
        let fd = libc::STDIN_FILENO;
        // SAFETY: isatty just inspects the fd.
        let is_tty = unsafe { libc::isatty(fd) } == 1;
        // SAFETY: termios is a plain C struct; tcgetattr fills it for a valid fd.
        let mut original: libc::termios = unsafe { mem::zeroed() };
        if !is_tty {
            return Self {
                handle: RestoreHandle {
                    fd,
                    original,
                    active: false,
                },
            };
        }
        // SAFETY: fd is a TTY; &mut original is valid for the duration.
        unsafe {
            libc::tcgetattr(fd, &mut original);
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        Self {
            handle: RestoreHandle {
                fd,
                original,
                active: true,
            },
        }
    }

    /// A copyable handle that restores this terminal's original mode.
    pub(crate) fn handle(&self) -> RestoreHandle {
        self.handle
    }
}

impl Drop for RawConsole {
    fn drop(&mut self) {
        self.handle.restore();
    }
}

/// Process-global shutdown request. Set by the terminal signal handlers
/// ([`install_signal_handlers`]) and by the `Ctrl-A x` quit escape; polled by
/// the interactive console loop. Every way of ending an interactive session —
/// closing the window (`SIGHUP`), `Ctrl-C`/`kill` (`SIGINT`/`SIGTERM`),
/// `Ctrl-A x`, or the guest powering off — funnels through the SAME graceful
/// teardown that destroys the HVF VM (`hv_vm_destroy`) and restores the
/// terminal, so a session never leaks the one-per-process VM nor leaves the
/// shell in raw mode.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// `true` once a signal or the quit escape has asked the session to end.
pub(crate) fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

/// Ask the interactive session to shut down gracefully.
pub(crate) fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// Terminal-restore state captured for the async-signal-safe signal handler. A
/// handler may run on any thread at any time and must not lock or allocate, so
/// the fd lives in an atomic and the saved (cooked) termios is published once as
/// a leaked `Box` whose pointer the handler only ever reads.
static RESTORE_FD: AtomicI32 = AtomicI32::new(-1);
static RESTORE_TERMIOS: AtomicPtr<libc::termios> = AtomicPtr::new(ptr::null_mut());

/// Async-signal-safe handler for `SIGHUP`/`SIGINT`/`SIGTERM`: restore the
/// terminal, then request graceful shutdown. It does NOT exit the process —
/// that would skip the VM teardown — it lets the console loop return so `run()`
/// kicks the vCPUs, joins their threads, and drops the VM (`hv_vm_destroy`).
extern "C" fn handle_term_signal(_sig: libc::c_int) {
    let fd = RESTORE_FD.load(Ordering::Acquire);
    let termios = RESTORE_TERMIOS.load(Ordering::Acquire);
    if fd >= 0 && !termios.is_null() {
        // SAFETY: `termios` points at a leaked `Box<libc::termios>` filled by
        // `tcgetattr` on this same fd and published before the handler was
        // installed; it is only ever read. `tcsetattr` is async-signal-safe.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, termios);
        }
    }
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// Install graceful-shutdown handlers for the controlling-process termination
/// signals so closing the terminal window (`SIGHUP`) or any `kill`
/// (`SIGTERM`/`SIGINT`) tears the VM down cleanly instead of dying mid-run with
/// the HVF VM still mapped and the terminal stuck in raw mode.
///
/// In raw mode the tty does not synthesize `SIGINT` from `Ctrl-C` (it reaches
/// the guest as a byte, which is what an interactive shell expects); the
/// `SIGINT` handler therefore only matters for an external `kill -INT` or a
/// non-tty run, where graceful teardown is still the right behavior.
pub(crate) fn install_signal_handlers(restore: RestoreHandle) {
    if restore.active {
        let boxed = Box::into_raw(Box::new(restore.original));
        RESTORE_TERMIOS.store(boxed, Ordering::Release);
        RESTORE_FD.store(restore.fd, Ordering::Release);
    }
    for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
        // SAFETY: zero-initialized sigaction is valid; the handler is
        // async-signal-safe; we install a process-wide disposition once.
        unsafe {
            let mut action: libc::sigaction = mem::zeroed();
            action.sa_sigaction = handle_term_signal as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &action, ptr::null_mut());
        }
    }
}

/// Spawn the host-input pump. Reads stdin and feeds each byte into `uart`,
/// asserting the serial SPI through `sink` so the guest takes its receive
/// interrupt. Watches for the `Ctrl-A x` escape, in which case it restores the
/// terminal (via `restore`) and requests a graceful session shutdown.
///
/// The thread is detached: it blocks on stdin for the life of the VM and the
/// process tears it down on exit. The `Ctrl-A x` escape sets the shared
/// shutdown flag rather than calling `process::exit`, so the run loop returns
/// and `run()` destroys the HVF VM via `Drop` — the same path a terminating
/// signal or a guest power-off takes.
pub(crate) fn spawn_stdin_pump(
    uart: Arc<Pl011>,
    sink: Arc<dyn MsiSink>,
    restore: RestoreHandle,
) {
    let spi = serial_spi();
    let trace = env::var_os("CHM_TRACE_INPUT").is_some();
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 64];
        // True once we have seen a lone Ctrl-A and are awaiting the next byte.
        let mut escape_pending = false;
        loop {
            let n = match stdin.read(&mut buf) {
                Ok(0) => break, // stdin closed (EOF)
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let mut out: Vec<u8> = Vec::with_capacity(n);
            for &b in &buf[..n] {
                if escape_pending {
                    escape_pending = false;
                    match b {
                        b'x' => {
                            // Funnel the quit escape through the same graceful
                            // teardown as a signal or guest power-off: restore
                            // the terminal, request shutdown, and end the pump.
                            // run_console observes the request and returns, so
                            // run() destroys the HVF VM via Drop. A bare
                            // process::exit here would skip that and leak the
                            // VM until the OS reaped the process.
                            restore.restore();
                            request_shutdown();
                            return;
                        }
                        // Ctrl-A Ctrl-A sends a literal Ctrl-A to the guest.
                        CTRL_A => out.push(CTRL_A),
                        // Any other key after Ctrl-A is passed through verbatim
                        // (the Ctrl-A is swallowed as a dead escape prefix).
                        other => out.push(other),
                    }
                } else if b == CTRL_A {
                    escape_pending = true;
                } else {
                    out.push(b);
                }
            }
            if !out.is_empty() {
                let assert = uart.push_input(&out);
                if trace {
                    eprintln!(
                        "[chm-input] {} byte(s) {:02x?} -> push_input assert={assert} spi={spi}",
                        out.len(),
                        out
                    );
                }
                if assert {
                    sink.deliver_spi(spi);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_flag_round_trips_and_handler_sets_it() {
        // This is the only test that touches the process-global flag, so there
        // is no cross-test race. Start from a known-clear state.
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
        assert!(!shutdown_requested());

        request_shutdown();
        assert!(shutdown_requested(), "request_shutdown must be observable");

        // The signal handler must also raise the flag — every terminating
        // signal funnels into the same graceful teardown as Ctrl-A x. With no
        // terminal published (fd == -1) it skips tcsetattr, so calling it
        // directly here is safe and exercises the flag path.
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
        handle_term_signal(libc::SIGTERM);
        assert!(
            shutdown_requested(),
            "a terminating signal must request graceful shutdown"
        );

        // Leave it clear so nothing observes a stale request.
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
    }
}

