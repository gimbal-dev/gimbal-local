// Copyright © 2026 Cloud Hypervisor macOS port
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Cross-platform compatibility shims.
//!
//! The VMM signals interrupts and ioevents through `EventFd`. On Linux this is
//! the kernel `eventfd(2)` exposed by `vmm-sys-util`. macOS has no `eventfd`, so
//! for the Hypervisor.framework backend we provide a self-pipe + atomic-counter
//! replacement with the same counter semantics, pollable via `kqueue`.

#[cfg(target_os = "linux")]
pub use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

#[cfg(not(target_os = "linux"))]
pub use self::macos::{EFD_NONBLOCK, EventFd};

#[cfg(not(target_os = "linux"))]
mod macos {
    use std::io;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    const O_NONBLOCK: i32 = 0x0004;
    const F_SETFL: i32 = 4;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    // The query halves of the pairs above. Only the tests read flags back —
    // production code sets them and moves on — so they are test-only rather
    // than carrying an #[allow(dead_code)] that would also hide a real one.
    #[cfg(test)]
    const F_GETFL: i32 = 3;
    #[cfg(test)]
    const F_GETFD: i32 = 1;

    pub const EFD_NONBLOCK: i32 = O_NONBLOCK;

    const POLLIN: i16 = 0x0001;

    #[repr(C)]
    struct PollFd {
        fd: RawFd,
        events: i16,
        revents: i16,
    }

    unsafe extern "C" {
        fn pipe(fds: *mut i32) -> i32;
        fn read(fd: i32, buf: *mut core::ffi::c_void, n: usize) -> isize;
        fn write(fd: i32, buf: *const core::ffi::c_void, n: usize) -> isize;
        fn close(fd: i32) -> i32;
        // `fcntl` is variadic in C (`int fcntl(int, int, ...)`), and on Apple
        // arm64 a variadic argument is passed on the STACK while a fixed one is
        // passed in a register. Declaring the third argument as fixed therefore
        // hands `fcntl` whatever happens to sit on the stack: measured as 0x0
        // under `-C opt-level=0` and 0x4000c0 under `-C opt-level=s`, so
        // `O_NONBLOCK` was never actually set and a debug build only worked by
        // luck. It must be declared variadic to match the ABI.
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32;
    }

    struct Inner {
        rd: RawFd,
        wr: RawFd,
        count: AtomicU64,
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            // SAFETY: we exclusively own these fds.
            unsafe {
                close(self.rd);
                close(self.wr);
            }
        }
    }

    /// A macOS replacement for `vmm_sys_util::eventfd::EventFd`.
    ///
    /// Non-semaphore semantics: `write(v)` adds `v` to the counter; `read()`
    /// returns the accumulated value and resets it to zero (or `WouldBlock`).
    #[derive(Clone)]
    pub struct EventFd {
        inner: Arc<Inner>,
    }

    impl EventFd {
        pub fn new(flags: i32) -> io::Result<EventFd> {
            let mut fds = [0i32; 2];
            // SAFETY: `fds` is a valid 2-element array.
            if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let (rd, wr) = (fds[0], fds[1]);
            // SAFETY: configuring fds we own.
            //
            // `O_CLOEXEC` is a file-DESCRIPTOR flag and must be set with
            // `F_SETFD`/`FD_CLOEXEC`; passing it to `F_SETFL` (which only accepts
            // status flags such as `O_NONBLOCK`) fails with EINVAL on macOS and
            // silently leaves the descriptor BLOCKING. That made `drain_pipe`'s
            // trailing read block forever on an empty pipe, so `wait_timeout`
            // could wedge its caller. Set the two flag classes separately.
            unsafe {
                fcntl(rd, F_SETFL, O_NONBLOCK);
                fcntl(rd, F_SETFD, FD_CLOEXEC);
                fcntl(wr, F_SETFL, flags & O_NONBLOCK);
                fcntl(wr, F_SETFD, FD_CLOEXEC);
            }
            Ok(EventFd {
                inner: Arc::new(Inner {
                    rd,
                    wr,
                    count: AtomicU64::new(0),
                }),
            })
        }

        pub fn write(&self, v: u64) -> io::Result<()> {
            if v == 0 {
                return Ok(());
            }
            // Transition empty -> non-empty wakes any poller exactly once.
            if self.inner.count.fetch_add(v, Ordering::SeqCst) == 0 {
                let b = [1u8; 1];
                // SAFETY: 1-byte write from a valid buffer to our pipe.
                let n = unsafe { write(self.inner.wr, b.as_ptr() as *const _, 1) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::WouldBlock {
                        return Err(e);
                    }
                }
            }
            Ok(())
        }

        pub fn read(&self) -> io::Result<u64> {
            self.drain_pipe();
            let v = self.inner.count.swap(0, Ordering::SeqCst);
            if v == 0 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(v)
            }
        }

        /// Drain any readable bytes from the self-pipe. `rd` is non-blocking, so
        /// `read(2)` returns `-1`/`WouldBlock` (n <= 0) once the pipe is empty.
        fn drain_pipe(&self) {
            let mut buf = [0u8; 64];
            loop {
                // SAFETY: reading into a valid local buffer from our pipe.
                let n = unsafe { read(self.inner.rd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    break;
                }
            }
        }

        /// Block until the counter is non-zero (a `write` happened) or
        /// `timeout_ms` elapses, then atomically take and return the counter
        /// (0 on timeout). A negative `timeout_ms` blocks indefinitely.
        ///
        /// This is the wakeup primitive the HVF backend parks a WFI-idling vCPU
        /// on: a device/IRQ thread asserts an interrupt and `write()`s here to
        /// wake the vCPU thread. The non-semaphore counter semantics make the
        /// wakeup race-free — a `write` that lands before this call leaves the
        /// counter non-zero, so the fast path returns immediately and no wakeup
        /// is lost.
        pub fn wait_timeout(&self, timeout_ms: i32) -> io::Result<u64> {
            // Fast path: already signaled (write landed before we parked).
            let v = self.inner.count.swap(0, Ordering::SeqCst);
            if v != 0 {
                self.drain_pipe();
                return Ok(v);
            }
            let mut pfd = PollFd {
                fd: self.inner.rd,
                events: POLLIN,
                revents: 0,
            };
            // SAFETY: single valid pollfd for the lifetime of the call.
            let r = unsafe { poll(&mut pfd as *mut PollFd, 1, timeout_ms) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            self.drain_pipe();
            Ok(self.inner.count.swap(0, Ordering::SeqCst))
        }

        pub fn try_clone(&self) -> io::Result<EventFd> {
            Ok(EventFd {
                inner: self.inner.clone(),
            })
        }
    }

    impl AsRawFd for EventFd {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.rd
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{AsRawFd, EFD_NONBLOCK, EventFd};
        use std::io;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        /// Run `f` on a helper thread and fail (rather than hang the suite) if it
        /// does not finish in time. The bug these tests guard against is a
        /// *blocking* descriptor, whose symptom is an unbounded wait.
        fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(limit)
                .expect("EventFd operation blocked: the read fd is not O_NONBLOCK")
        }

        /// `wait_timeout` on an idle EventFd must return at its timeout. It used
        /// to block forever: `O_CLOEXEC` was passed to `F_SETFL`, which fails on
        /// macOS and left the read fd blocking, so `drain_pipe`'s trailing read
        /// never returned.
        #[test]
        fn wait_timeout_returns_when_idle() {
            let fd = EventFd::new(EFD_NONBLOCK).unwrap();
            let got = within(Duration::from_secs(5), move || fd.wait_timeout(20).unwrap());
            assert_eq!(got, 0, "an idle wait must time out reporting no wakeups");
        }

        /// A pending write is taken by the fast path, and the *next* wait (with
        /// the pipe now drained) must still return rather than block.
        #[test]
        fn wait_timeout_drains_then_stays_responsive() {
            let fd = EventFd::new(EFD_NONBLOCK).unwrap();
            fd.write(1).unwrap();
            let got = within(Duration::from_secs(5), move || {
                let first = fd.wait_timeout(20).unwrap();
                let second = fd.wait_timeout(20).unwrap();
                (first, second)
            });
            assert_eq!(got.0, 1, "the pending wakeup should be reported");
            assert_eq!(got.1, 0, "the drained fd should then time out cleanly");
        }

        /// A write from another thread must wake a parked waiter promptly -- this
        /// is the property the vCPU WFI park relies on to take virtio completions
        /// without waiting out its full nap.
        #[test]
        fn a_cross_thread_write_wakes_a_parked_waiter() {
            let fd = EventFd::new(EFD_NONBLOCK).unwrap();
            let waker = fd.try_clone().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                let _ = waker.write(1);
            });
            let got = within(Duration::from_secs(5), move || fd.wait_timeout(5_000).unwrap());
            assert_eq!(got, 1, "the parked waiter should observe the cross-thread write");
        }

        /// The read descriptor really is `O_NONBLOCK`, asked of the kernel.
        ///
        /// The three tests above assert the *behaviour* that depends on this, and
        /// they are the ones that matter -- but they only fired in a release
        /// build. `fcntl` is variadic in C, and a non-variadic Rust declaration
        /// passes the third argument in a register where Apple arm64 expects it
        /// on the stack, so the flag actually applied was whatever the stack
        /// happened to hold: 0x0 under `-C opt-level=0` (harmless here, because
        /// the tests' pipes are drained before the blocking read is reached) and
        /// 0x4000c0 under `-C opt-level=s`. A guard that only fires in one
        /// profile is a guard nobody runs, so this asks the descriptor directly
        /// and fails identically in both.
        #[test]
        fn the_read_fd_is_really_non_blocking() {
            let fd = EventFd::new(EFD_NONBLOCK).unwrap();
            // SAFETY: querying flags on a descriptor the EventFd owns and keeps
            // alive for the duration of this call.
            let flags = unsafe { super::fcntl(fd.as_raw_fd(), super::F_GETFL) };
            assert!(flags >= 0, "F_GETFL failed: {}", io::Error::last_os_error());
            assert_eq!(
                flags & super::O_NONBLOCK,
                super::O_NONBLOCK,
                "read fd flags 0x{flags:x} lack O_NONBLOCK; drain_pipe would block forever"
            );

            // SAFETY: same descriptor, descriptor-flag class this time.
            let fdflags = unsafe { super::fcntl(fd.as_raw_fd(), super::F_GETFD) };
            assert!(
                fdflags >= 0,
                "F_GETFD failed: {}",
                io::Error::last_os_error()
            );
            assert_eq!(
                fdflags & super::FD_CLOEXEC,
                super::FD_CLOEXEC,
                "read fd flags 0x{fdflags:x} lack FD_CLOEXEC; it would leak into a guest's children"
            );
        }
    }
}
