//! Live checkpointing: capture a running guest and let it carry on.
//!
//! Every checkpoint before this one was a *suspend* — the vCPU threads left
//! their run loops, captured themselves on the way out, and the process exited.
//! That is fine for "stop and save", and useless for a timeline: the only
//! points on it are the ones a human happened to stop at.
//!
//! The obstacle is not the capture, it is *where* the capture has to happen. A
//! vCPU's register file and software-GIC model can only be read on the thread
//! that created it, because HVF binds a vCPU to its owning thread. A
//! coordinator thread cannot reach in and take them. So a live checkpoint is
//! necessarily a rendezvous: kick every vCPU out of the guest, have each one
//! capture *itself*, park them all while the coordinator writes guest RAM (with
//! no guest writer running, so the dump is consistent), then let them go.
//!
//! This module is that rendezvous, and nothing else. It is generic over the
//! capture type so it can be tested without an HVF vCPU in the picture.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Why a live checkpoint did not happen. Never a reason to stop the guest.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GateError {
    /// Not every vCPU reached the barrier in time. The checkpoint is abandoned
    /// and the guest runs on.
    ///
    /// Abandoning is the entire point. A checkpoint assembled from some vCPUs'
    /// registers and another vCPU's still-running ones is not a slightly worse
    /// checkpoint, it is a corrupt one that would resume into an inconsistent
    /// machine — and it would look fine on disk. The vtimer stepper makes the
    /// same trade for the same reason: degrade to "we did not do it", never to
    /// "we did half of it".
    Timeout { arrived: usize, of: usize },
    /// The VM is shutting down, or a request is already in flight.
    Unavailable,
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::Timeout { arrived, of } => write!(
                f,
                "only {arrived} of {of} vCPUs reached the checkpoint barrier"
            ),
            GateError::Unavailable => write!(f, "checkpoint barrier unavailable"),
        }
    }
}

struct GateState<T> {
    /// vCPU captures for the current epoch, indexed by vCPU id.
    captures: Vec<Option<T>>,
    /// How many vCPUs have captured and parked for the current epoch.
    arrived: usize,
    /// The highest epoch the coordinator has finished with, however it
    /// finished. A vCPU parked for epoch E leaves when this reaches E.
    ///
    /// This is a monotonic watermark rather than a bare "holding" flag because
    /// a flag deadlocks the second checkpoint: vCPUs released from epoch 1 have
    /// not necessarily woken by the time epoch 2 sets the flag again, so they
    /// see it set, stay parked, and never loop round to notice epoch 2. The
    /// barrier then times out with nobody arriving, on a perfectly healthy VM.
    released_through: u64,
    /// Set while a request is in flight, so two coordinators cannot both
    /// believe they stopped the world.
    in_flight: bool,
}

/// A stop-the-world barrier for capturing a running guest.
pub(crate) struct CheckpointGate<T> {
    /// Read by every vCPU on every exit from guest execution, so it is an
    /// atomic rather than something behind the mutex: the common case is "no
    /// checkpoint is pending", and that case must not cost a lock acquisition
    /// on the hottest path in the VM.
    epoch: AtomicU64,
    /// Set once at teardown. Releases anyone parked, permanently.
    closed: AtomicBool,
    inner: Mutex<GateState<T>>,
    cv: Condvar,
    vcpus: usize,
}

impl<T> CheckpointGate<T> {
    pub(crate) fn new(vcpus: usize) -> Self {
        Self {
            epoch: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            inner: Mutex::new(GateState {
                captures: (0..vcpus).map(|_| None).collect(),
                arrived: 0,
                released_through: 0,
                in_flight: false,
            }),
            cv: Condvar::new(),
            vcpus,
        }
    }

    /// The current request generation, as a vCPU should read it: one relaxed
    /// load per guest exit. A vCPU services a request when this differs from
    /// the epoch it last serviced, which makes a request impossible to miss and
    /// impossible to serve twice.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Called by a vCPU thread that has noticed a new epoch: hand over this
    /// vCPU's capture and park until the coordinator has finished with `epoch`.
    ///
    /// A vCPU that arrives after the coordinator has already given up returns
    /// immediately rather than parking, so a timed-out request cannot strand a
    /// core that was merely slow.
    pub(crate) fn arrive_and_park(&self, id: usize, epoch: u64, capture: T) {
        let mut g = self.inner.lock().unwrap();
        if id < g.captures.len() {
            g.captures[id] = Some(capture);
        }
        g.arrived += 1;
        if g.arrived == self.vcpus {
            self.cv.notify_all();
        }
        while g.released_through < epoch && !self.is_closed() {
            g = self.cv.wait(g).unwrap();
        }
    }

    /// Stop the world and collect every vCPU's capture.
    ///
    /// `kick` must force every vCPU out of guest execution *and* out of any
    /// host-side idle park — a core halted in WFI has already left the guest,
    /// so kicking `hv_vcpu_run` alone would leave it asleep and the barrier
    /// would time out on an idle VM, which is exactly when a checkpoint is most
    /// likely to be worth taking.
    ///
    /// On success the caller holds the world stopped until it calls
    /// [`Self::release`]; guest RAM has no writer for that window, which is
    /// what makes the dump consistent.
    pub(crate) fn stop_the_world(
        &self,
        kick: &dyn Fn(),
        timeout: Duration,
    ) -> Result<Vec<T>, GateError> {
        if self.is_closed() {
            return Err(GateError::Unavailable);
        }
        {
            let mut g = self.inner.lock().unwrap();
            if g.in_flight {
                return Err(GateError::Unavailable);
            }
            g.in_flight = true;
            g.arrived = 0;
            for c in g.captures.iter_mut() {
                *c = None;
            }
        }
        let epoch = self.epoch.fetch_add(1, Ordering::Release) + 1;
        kick();

        let mut g = self.inner.lock().unwrap();
        let deadline = Instant::now() + timeout;
        while g.arrived < self.vcpus {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (ng, _) = self.cv.wait_timeout(g, deadline - now).unwrap();
            g = ng;
        }
        // Defensive on the second condition: `arrived` counting every vCPU
        // should mean every slot is filled, but writing a checkpoint short of a
        // vCPU is precisely the corruption this type exists to prevent, so
        // prove it rather than assume it.
        let out: Vec<T> = g.captures.iter_mut().filter_map(Option::take).collect();
        if g.arrived < self.vcpus || out.len() != self.vcpus {
            let arrived = out.len().min(g.arrived);
            // Abandoning still has to free whoever did arrive, or a missed
            // checkpoint would hang the VM it was meant to be invisible to.
            g.released_through = epoch;
            g.in_flight = false;
            drop(g);
            self.cv.notify_all();
            return Err(GateError::Timeout {
                arrived,
                of: self.vcpus,
            });
        }
        Ok(out)
    }

    /// Let the guest run again. Must be called after a successful
    /// [`Self::stop_the_world`], however the write went: a failed write is a
    /// lost checkpoint, while a world left stopped is a hung VM.
    pub(crate) fn release(&self) {
        let mut g = self.inner.lock().unwrap();
        g.released_through = self.epoch.load(Ordering::Acquire);
        g.in_flight = false;
        drop(g);
        self.cv.notify_all();
    }

    /// Permanently release everyone, for teardown. A vCPU parked here when the
    /// VM is stopping must not keep the process alive.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut g = self.inner.lock().unwrap();
        g.released_through = u64::MAX;
        g.in_flight = false;
        drop(g);
        self.cv.notify_all();
    }
}

/// A pause latch for host-side threads that write into **guest memory**.
///
/// Stopping every vCPU is necessary for a consistent RAM dump but it is not
/// sufficient, because the guest is not the only thing writing its own memory.
/// `chm-net-service` runs on its own thread and publishes received frames
/// straight into the guest's virtio RX ring — buffers, then the used-ring index.
/// Dumping RAM across that would capture a ring whose index promises a frame the
/// buffer does not contain, and the guest would resume and read it.
///
/// Block is **not** in this set, and that is a structural property rather than
/// luck: `DeviceCore::notify` drains, processes and publishes synchronously on
/// the vCPU thread that took the MMIO/PCI trap, so a vCPU parked at the
/// [`CheckpointGate`] provably cannot be halfway through a block request. The
/// console threads are not in this set either: they own a `Pl011` FIFO, not a
/// `GuestMemory`, so a keystroke landing mid-dump is captured (or missed) as
/// device state, never as a torn ring.
///
/// Writers park at a pass boundary, never mid-pass, so the observable guest
/// state is always a whole number of delivered frames.
///
/// Writers **register themselves** rather than being counted up front. A VM's
/// device set is decided while it is being wired, after this latch has to exist,
/// and guessing the count wrong in either direction is bad in a way that would
/// not show up until a checkpoint: too high and every pause waits out its whole
/// timeout, too low and the dump races a writer.
pub(crate) struct Quiesce {
    paused: AtomicBool,
    closed: AtomicBool,
    /// How many writers are parked right now.
    parked: Mutex<usize>,
    cv: Condvar,
    writers: AtomicUsize,
}

impl Quiesce {
    pub(crate) fn new() -> Self {
        Self {
            paused: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            parked: Mutex::new(0),
            cv: Condvar::new(),
            writers: AtomicUsize::new(0),
        }
    }

    /// Declare that one more thread writes guest memory and will call
    /// [`Self::park_if_paused`] at each pass boundary. Must happen before the
    /// thread's first write, and before any checkpoint can be requested.
    pub(crate) fn register(&self) {
        self.writers.fetch_add(1, Ordering::Release);
    }

    /// Cheap enough to call at the top of every service pass: one relaxed load
    /// when no checkpoint is pending.
    pub(crate) fn park_if_paused(&self) {
        if !self.paused.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut n = self.parked.lock().unwrap();
        *n += 1;
        self.cv.notify_all();
        while self.paused.load(Ordering::Acquire) && !self.closed.load(Ordering::Acquire) {
            n = self.cv.wait(n).unwrap();
        }
        *n -= 1;
    }

    /// Stop every writer at a pass boundary. `wake` must poke anything that
    /// might be sleeping on an interval, or this waits out its whole timeout for
    /// no reason.
    pub(crate) fn pause(&self, wake: &dyn Fn(), timeout: Duration) -> Result<(), GateError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(GateError::Unavailable);
        }
        let writers = self.writers.load(Ordering::Acquire);
        if writers == 0 {
            return Ok(());
        }
        self.paused.store(true, Ordering::Release);
        wake();
        let mut n = self.parked.lock().unwrap();
        let deadline = Instant::now() + timeout;
        while *n < writers {
            // Teardown must abort a pause in progress, not make the process wait
            // out the whole timeout before it can exit.
            if self.closed.load(Ordering::Acquire) {
                drop(n);
                return Err(GateError::Unavailable);
            }
            let now = Instant::now();
            if now >= deadline {
                let arrived = *n;
                drop(n);
                self.resume();
                return Err(GateError::Timeout {
                    arrived,
                    of: writers,
                });
            }
            let (nn, _) = self.cv.wait_timeout(n, deadline - now).unwrap();
            n = nn;
        }
        Ok(())
    }

    pub(crate) fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        let _g = self.parked.lock().unwrap();
        drop(_g);
        self.cv.notify_all();
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.paused.store(false, Ordering::Release);
        let _g = self.parked.lock().unwrap();
        drop(_g);
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    /// Stand-in for a vCPU thread: loops, notices new epochs, captures itself.
    ///
    /// It waits on `ready` immediately after reading its baseline epoch. That
    /// ordering is not test scaffolding for its own sake: a vCPU that first
    /// reads the epoch *after* a request is already in flight starts level with
    /// it and never services it, so the coordinator would time out through no
    /// fault of the gate. Production gets the ordering for free -- every vCPU
    /// thread is spawned and held at the `go` gate long before anything can ask
    /// for a checkpoint -- and this barrier reproduces it rather than leaving
    /// the tests to win a race.
    fn spawn_vcpu(
        gate: Arc<CheckpointGate<usize>>,
        id: usize,
        run: Arc<AtomicBool>,
        captures: Arc<AtomicUsize>,
        ready: Arc<Barrier>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut mine = gate.epoch();
            ready.wait();
            while run.load(Ordering::Relaxed) {
                let e = gate.epoch();
                if e != mine {
                    mine = e;
                    captures.fetch_add(1, Ordering::Relaxed);
                    gate.arrive_and_park(id, e, id * 100);
                }
                std::hint::spin_loop();
            }
        })
    }

    #[test]
    fn every_vcpu_captures_itself_and_the_guest_runs_on() {
        let gate = Arc::new(CheckpointGate::<usize>::new(3));
        let run = Arc::new(AtomicBool::new(true));
        let n = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(Barrier::new(4));
        let threads: Vec<_> = (0..3)
            .map(|id| spawn_vcpu(gate.clone(), id, run.clone(), n.clone(), ready.clone()))
            .collect();
        ready.wait();

        let got = gate
            .stop_the_world(&|| {}, Duration::from_secs(5))
            .expect("all three vCPUs should reach the barrier");
        // Indexed by vCPU id, not by arrival order: a checkpoint that attributed
        // vCPU 2's registers to vCPU 0 would resume into nonsense.
        assert_eq!(got, vec![0, 100, 200]);
        gate.release();

        // The guest carries on, which is the whole difference between this and
        // a suspend: a second checkpoint must be possible.
        let again = gate
            .stop_the_world(&|| {}, Duration::from_secs(5))
            .expect("a live checkpoint must be repeatable");
        assert_eq!(again, vec![0, 100, 200]);
        gate.release();

        run.store(false, Ordering::Relaxed);
        gate.close();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(n.load(Ordering::Relaxed), 6, "3 vCPUs x 2 checkpoints");
    }

    /// The load-bearing refusal: a checkpoint missing a vCPU is not a worse
    /// checkpoint, it is a corrupt one, and it would look fine on disk.
    #[test]
    fn a_vcpu_that_never_arrives_abandons_the_checkpoint_rather_than_tearing_it() {
        let gate = Arc::new(CheckpointGate::<usize>::new(2));
        let run = Arc::new(AtomicBool::new(true));
        let n = Arc::new(AtomicUsize::new(0));
        // Only vCPU 0 is alive; vCPU 1 is wedged and will never arrive.
        let ready = Arc::new(Barrier::new(2));
        let t = spawn_vcpu(gate.clone(), 0, run.clone(), n.clone(), ready.clone());
        ready.wait();

        let err = gate
            .stop_the_world(&|| {}, Duration::from_millis(150))
            .expect_err("one missing vCPU must abandon the checkpoint");
        assert_eq!(err, GateError::Timeout { arrived: 1, of: 2 });

        // And the world must be running again, or a failed checkpoint would
        // have hung the VM it was supposed to be transparent to.
        run.store(false, Ordering::Relaxed);
        gate.close();
        t.join().unwrap();
    }

    /// A vCPU that was merely slow must not be stranded by a request the
    /// coordinator has already given up on.
    #[test]
    fn a_late_vcpu_is_not_stranded_by_an_abandoned_request() {
        let gate = Arc::new(CheckpointGate::<usize>::new(2));
        let err = gate
            .stop_the_world(&|| {}, Duration::from_millis(50))
            .expect_err("nobody is running, so this must time out");
        assert_eq!(err, GateError::Timeout { arrived: 0, of: 2 });

        // Arriving now must return rather than park forever.
        let g = gate.clone();
        let late = thread::spawn(move || g.arrive_and_park(0, 1, 7));
        let start = Instant::now();
        late.join()
            .expect("a late arrival must not park indefinitely");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "late arrival parked for {:?}",
            start.elapsed()
        );
    }

    /// Teardown must free a parked vCPU, or stopping the VM would hang on the
    /// checkpoint machinery that was meant to be invisible.
    #[test]
    fn closing_the_gate_releases_a_parked_vcpu() {
        let gate = Arc::new(CheckpointGate::<usize>::new(2));
        let g = gate.clone();
        // One vCPU arrives for a request that will never complete.
        let parked = thread::spawn(move || {
            // Park for an epoch the coordinator will never finish.
            g.arrive_and_park(0, 99, 1);
        });
        thread::sleep(Duration::from_millis(50));
        gate.close();
        let start = Instant::now();
        parked.join().expect("close must release the parked vCPU");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    /// Two coordinators must not both believe they stopped the world.
    #[test]
    fn a_second_request_while_one_is_in_flight_is_refused() {
        let gate = Arc::new(CheckpointGate::<usize>::new(1));
        let run = Arc::new(AtomicBool::new(true));
        let n = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(Barrier::new(2));
        let t = spawn_vcpu(gate.clone(), 0, run.clone(), n.clone(), ready.clone());
        ready.wait();

        let held = gate
            .stop_the_world(&|| {}, Duration::from_secs(5))
            .expect("first request");
        assert_eq!(held, vec![0]);
        assert_eq!(
            gate.stop_the_world(&|| {}, Duration::from_millis(50)),
            Err(GateError::Unavailable),
            "the world is already stopped"
        );
        gate.release();

        run.store(false, Ordering::Relaxed);
        gate.close();
        t.join().unwrap();
    }

    /// Concurrency code that passes once has proved almost nothing. Hammer the
    /// barrier: many rounds, several vCPUs, no sleep between release and the
    /// next request — which is exactly the window where the original "holding"
    /// flag deadlocked, because vCPUs released from round N had not yet woken
    /// when round N+1 set the flag again.
    #[test]
    fn back_to_back_checkpoints_do_not_deadlock_under_repetition() {
        const VCPUS: usize = 4;
        const ROUNDS: usize = 200;
        let gate = Arc::new(CheckpointGate::<usize>::new(VCPUS));
        let run = Arc::new(AtomicBool::new(true));
        let n = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(Barrier::new(VCPUS + 1));
        let threads: Vec<_> = (0..VCPUS)
            .map(|id| spawn_vcpu(gate.clone(), id, run.clone(), n.clone(), ready.clone()))
            .collect();
        ready.wait();
        for round in 0..ROUNDS {
            let got = gate
                .stop_the_world(&|| {}, Duration::from_secs(10))
                .unwrap_or_else(|e| panic!("round {round} stalled: {e}"));
            assert_eq!(got.len(), VCPUS, "round {round} lost a vCPU");
            gate.release();
        }

        run.store(false, Ordering::Relaxed);
        gate.close();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            n.load(Ordering::Relaxed),
            VCPUS * ROUNDS,
            "every vCPU must service every round exactly once"
        );
    }

    /// The property that makes a live RAM dump safe: while paused, no writer is
    /// inside a pass. Asserted by having the writer set a flag for the whole
    /// duration of its "write into guest memory" region and checking that the
    /// coordinator never observes it set.
    #[test]
    fn no_writer_is_mid_pass_while_the_world_is_paused() {
        let q = Arc::new(Quiesce::new());
        q.register();
        q.register();
        let run = Arc::new(AtomicBool::new(true));
        // One counter per writer so a set bit is unambiguous about who set it.
        let inside = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let passes = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..2)
            .map(|w| {
                let q = q.clone();
                let run = run.clone();
                let inside = inside.clone();
                let passes = passes.clone();
                thread::spawn(move || {
                    while run.load(Ordering::Relaxed) {
                        q.park_if_paused();
                        inside[w].store(true, Ordering::Release);
                        // Stand-in for service_net(): touches guest memory.
                        thread::sleep(Duration::from_micros(50));
                        inside[w].store(false, Ordering::Release);
                        passes.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for round in 0..50 {
            q.pause(&|| {}, Duration::from_secs(5))
                .unwrap_or_else(|e| panic!("round {round}: {e}"));
            // This is the RAM dump window.
            for w in 0..2 {
                assert!(
                    !inside[w].load(Ordering::Acquire),
                    "round {round}: writer {w} was mid-pass during the dump"
                );
            }
            thread::sleep(Duration::from_micros(200));
            for w in 0..2 {
                assert!(
                    !inside[w].load(Ordering::Acquire),
                    "round {round}: writer {w} entered a pass while paused"
                );
            }
            q.resume();
        }

        run.store(false, Ordering::Relaxed);
        q.close();
        for t in threads {
            t.join().unwrap();
        }
        assert!(
            passes.load(Ordering::Relaxed) > 0,
            "the writers must actually have run between pauses, not just starved"
        );
    }

    /// A writer that never comes back must not leave the guest's network wedged.
    #[test]
    fn a_writer_that_never_parks_gives_up_and_resumes_the_rest() {
        let q = Quiesce::new();
        q.register();
        let err = q
            .pause(&|| {}, Duration::from_millis(100))
            .expect_err("nobody is running, so this must time out");
        assert_eq!(err, GateError::Timeout { arrived: 0, of: 1 });
        // And crucially it must have un-paused itself: a failed checkpoint that
        // left the net service parked would silently kill guest networking.
        let q = Arc::new(q);
        let g = q.clone();
        let t = thread::spawn(move || g.park_if_paused());
        let start = Instant::now();
        t.join()
            .expect("writer must not park after an abandoned pause");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    /// A VM with no NIC has nothing to quiesce and must not pay for it.
    #[test]
    fn a_vm_with_no_writers_pauses_instantly() {
        let q = Quiesce::new();
        let start = Instant::now();
        q.pause(&|| {}, Duration::from_secs(5)).expect("no writers");
        assert!(start.elapsed() < Duration::from_millis(50));
        q.resume();
    }

    /// Teardown must free a parked writer.
    #[test]
    fn closing_releases_a_parked_writer() {
        let q = Arc::new(Quiesce::new());
        q.register();
        q.register();
        let g = q.clone();
        let parked = thread::spawn(move || g.park_if_paused());
        // Only one of the two writers exists, so this pause can never complete.
        let q2 = q.clone();
        let pauser = thread::spawn(move || {
            let _ = q2.pause(&|| {}, Duration::from_secs(30));
        });
        thread::sleep(Duration::from_millis(50));
        q.close();
        let start = Instant::now();
        parked.join().expect("close must release the parked writer");
        pauser.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
