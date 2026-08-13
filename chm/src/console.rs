// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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
use std::time::Duration;
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
/// interrupt, then invoking `wake` so a vCPU idling in its WFI park takes that
/// interrupt immediately instead of after the idle poll interval. Watches for
/// the `Ctrl-A x` escape, in which case it restores the terminal (via `restore`)
/// and requests a graceful session shutdown.
///
/// The thread is detached: it blocks on stdin for the life of the VM and the
/// process tears it down on exit. The `Ctrl-A x` escape sets the shared
/// shutdown flag rather than calling `process::exit`, so the run loop returns
/// and `run()` destroys the HVF VM via `Drop` — the same path a terminating
/// signal or a guest power-off takes.
/// Queues host bytes into the guest's PL011 receive FIFO and raises the serial
/// interrupt for them.
///
/// Shared by the CLI's stdin pump and the daemon's `input` command so both
/// deliver keystrokes identically — the daemon's console would otherwise be
/// write-only from the guest's side, i.e. an app could watch a VM but never
/// type into it.
pub(crate) type ConsoleInput = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Build a [`ConsoleInput`] over a guest's PL011 and its serial interrupt sink.
///
/// `spi` is the INTID the console's device tree gave the PL011, and it differs
/// per machine: a rehydrated capture inherits whatever the capturing VMM chose
/// (see [`serial_spi`]), while a cold-booted guest gets the one *we* wrote into
/// the tree we built. Passing it explicitly is what stops a `CHM_SERIAL_SPI`
/// set for a snapshot from silently retargeting a cold guest's keystrokes at an
/// interrupt nothing is listening on.
pub(crate) fn console_input(
    uart: Arc<Pl011>,
    sink: Arc<dyn MsiSink>,
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    spi: u32,
) -> ConsoleInput {
    let trace = env::var_os("CHM_TRACE_INPUT").is_some();
    Arc::new(move |bytes: &[u8]| {
        if bytes.is_empty() {
            return;
        }
        // `push_input` reports whether the guest's receive interrupt should be
        // raised; the re-assert tick covers the case where it is unmasked later.
        let assert = uart.push_input(bytes);
        if trace {
            eprintln!(
                "[chm-input] {} byte(s) {:02x?} -> push_input assert={assert} spi={spi}",
                bytes.len(),
                bytes
            );
        }
        if assert {
            sink.deliver_spi(spi);
            // Wake a WFI-parked vCPU so it takes the serial interrupt now,
            // rather than at its next idle re-evaluation poll.
            if let Some(wake) = &wake {
                wake();
            }
        }
    })
}

pub(crate) fn spawn_stdin_pump(
    uart: Arc<Pl011>,
    sink: Arc<dyn MsiSink>,
    restore: RestoreHandle,
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    spi: u32,
) {
    let deliver = console_input(uart, sink, wake, spi);
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
            deliver(&out);
        }
    });
}

/// Cadence at which the serial re-assert tick re-evaluates the receive
/// interrupt. Short enough that a wedged getty recovers imperceptibly, long
/// enough to be negligible overhead; it only ever acts when input is genuinely
/// stuck (pending in the FIFO with the guest's RXIM unmasked).
const SERIAL_REASSERT_INTERVAL: Duration = Duration::from_millis(50);

/// Spawn the serial re-assert tick: a lightweight watchdog that restores the
/// PL011 receive interrupt's level-triggered semantics. This model only pulses
/// the serial SPI when the host types (see [`spawn_stdin_pump`]); a guest that
/// unmasks RXIM *after* input was already queued — the cloud-init
/// `systemctl restart serial-getty@ttyAMA0` reopening the tty is the canonical
/// case — or that returns from its ISR with bytes still buffered would otherwise
/// wait for the next keystroke to be interrupted, wedging an interactive session
/// that produced no new input. The tick re-asserts the SPI (and wakes a parked
/// vCPU) whenever [`Pl011::rx_irq_pending`] holds, so pending input can never be
/// stranded. It exits when `running` clears.
pub(crate) fn spawn_serial_reassert(
    uart: Arc<Pl011>,
    sink: Arc<dyn MsiSink>,
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    running: Arc<AtomicBool>,
    spi: u32,
) -> thread::JoinHandle<()> {
    let trace = env::var_os("CHM_TRACE_INPUT").is_some();
    thread::Builder::new()
        .name("chm-serial-reassert".into())
        .spawn(move || {
            while running.load(Ordering::Acquire) {
                thread::sleep(SERIAL_REASSERT_INTERVAL);
                if uart.rx_irq_pending() {
                    if trace {
                        eprintln!("[chm-input] re-asserting stuck serial RX irq spi={spi}");
                    }
                    sink.deliver_spi(spi);
                    if let Some(wake) = &wake {
                        wake();
                    }
                }
            }
        })
        .expect("spawn serial re-assert thread")
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

