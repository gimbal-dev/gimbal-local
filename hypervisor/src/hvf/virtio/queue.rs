//! A split-virtqueue engine over [`GuestMemory`].
//!
//! Implements the virtio 1.x split virtqueue layout (descriptor table, available
//! ring, used ring) including:
//! - chained descriptors via `VIRTQ_DESC_F_NEXT`,
//! - indirect descriptor tables via `VIRTQ_DESC_F_INDIRECT`
//!   (`VIRTIO_RING_F_INDIRECT_DESC`), and
//! - the `VIRTIO_RING_F_EVENT_IDX` used-event suppression scheme.
//!
//! The engine reads and writes the rings directly in live guest RAM, so a
//! resumed guest and the device backend share exactly the queues the snapshot
//! restored. Restoring is just a matter of seeding `next_avail`/`next_used` from
//! the live ring indices (see [`Queue::restore`]).

use super::{GuestMemError, GuestMemory};

/// `VIRTQ_DESC_F_NEXT`: the descriptor continues via its `next` field.
const VIRTQ_DESC_F_NEXT: u16 = 0x1;
/// `VIRTQ_DESC_F_WRITE`: the descriptor is device-writable (driver-readable
/// otherwise).
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
/// `VIRTQ_DESC_F_INDIRECT`: the descriptor points at an indirect descriptor
/// table.
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

const DESC_SIZE: u64 = 16;

/// One segment of a popped descriptor chain: a guest buffer plus its direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Guest-physical address of the buffer.
    pub gpa: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// `true` if the device writes this buffer (driver-readable otherwise).
    pub write: bool,
}

/// A popped available descriptor chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescChain {
    /// Index of the head descriptor — pass back to [`Queue::add_used`].
    pub head: u16,
    /// The buffers making up the chain, in order.
    pub segments: Vec<Segment>,
}

impl DescChain {
    /// Driver-readable segments (device input), in order.
    pub fn readable(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| !s.write)
    }

    /// Device-writable segments (device output), in order.
    pub fn writable(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.write)
    }

    /// Total device-writable capacity in bytes.
    pub fn writable_len(&self) -> u32 {
        self.writable().map(|s| s.len).sum()
    }
}

/// A split virtqueue bound to its rings in guest RAM.
///
/// `Default` is the unprogrammed state: a cold guest's transport starts every
/// queue here and the driver fills it in, whereas a restored one arrives with
/// every field already known.
#[derive(Default, Clone, Copy)]
pub struct Queue {
    /// Number of entries (a power of two).
    pub size: u16,
    /// Guest-physical address of the descriptor table.
    pub desc: u64,
    /// Guest-physical address of the available ring.
    pub avail: u64,
    /// Guest-physical address of the used ring.
    pub used: u64,
    /// `VIRTIO_RING_F_EVENT_IDX` negotiated.
    pub event_idx: bool,
    /// `VIRTIO_RING_F_INDIRECT_DESC` negotiated.
    pub indirect: bool,
    /// Next available-ring index the device will consume.
    pub next_avail: u16,
    /// Next used-ring index the device will fill.
    pub next_used: u16,
}

impl Queue {
    /// Bytes consumed walking a chain longer than this are treated as a loop and
    /// rejected, bounding work to the ring size.
    fn max_chain(&self) -> u32 {
        // A direct chain cannot exceed the ring size; indirect tables add their
        // own entries, bounded below by `max_indirect`.
        self.size as u32
    }

    fn max_indirect(&self) -> u16 {
        // An indirect table holds at most `len / 16` descriptors; cap defensively
        // at a generous multiple of the queue size.
        self.size.saturating_mul(4).max(256)
    }

    /// avail.idx lives at `avail + 2` (after the 2-byte flags field).
    fn avail_idx(&self, mem: &GuestMemory) -> Result<u16, GuestMemError> {
        mem.read_u16(self.avail + 2)
    }

    /// The `i`-th available ring entry (a descriptor head index).
    fn avail_ring(&self, mem: &GuestMemory, i: u16) -> Result<u16, GuestMemError> {
        let off = 4 + 2 * (i % self.size) as u64;
        mem.read_u16(self.avail + off)
    }

    /// Read descriptor `index` from `table` (defaults to the queue's own table).
    fn read_desc(
        &self,
        mem: &GuestMemory,
        table: u64,
        index: u16,
    ) -> Result<(u64, u32, u16, u16), GuestMemError> {
        let base = table + DESC_SIZE * index as u64;
        let addr = mem.read_u64(base)?;
        let len = mem.read_u32(base + 8)?;
        let flags = mem.read_u16(base + 12)?;
        let next = mem.read_u16(base + 14)?;
        Ok((addr, len, flags, next))
    }

    /// Pop the next available descriptor chain, or `None` if the driver has not
    /// made one available since `next_avail`.
    pub fn pop(&mut self, mem: &GuestMemory) -> Result<Option<DescChain>, GuestMemError> {
        if self.next_avail == self.avail_idx(mem)? {
            return Ok(None);
        }
        let head = self.avail_ring(mem, self.next_avail)?;
        let segments = self.collect_chain(mem, head)?;
        self.next_avail = self.next_avail.wrapping_add(1);
        Ok(Some(DescChain { head, segments }))
    }

    /// Walk a descriptor chain starting at `head` into a flat segment list,
    /// expanding any indirect table encountered.
    fn collect_chain(&self, mem: &GuestMemory, head: u16) -> Result<Vec<Segment>, GuestMemError> {
        let mut segments = Vec::new();
        let mut index = head;
        let mut steps = 0u32;
        loop {
            if index >= self.size || steps > self.max_chain() {
                // Malformed chain (out-of-range index or a cycle); stop here and
                // return what we have rather than spin.
                break;
            }
            let (addr, len, flags, next) = self.read_desc(mem, self.desc, index)?;
            if flags & VIRTQ_DESC_F_INDIRECT != 0 {
                self.expand_indirect(mem, addr, len, &mut segments)?;
            } else {
                segments.push(Segment {
                    gpa: addr,
                    len,
                    write: flags & VIRTQ_DESC_F_WRITE != 0,
                });
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            index = next;
            steps += 1;
        }
        Ok(segments)
    }

    /// Expand an indirect descriptor table (`len / 16` descriptors at `table`).
    fn expand_indirect(
        &self,
        mem: &GuestMemory,
        table: u64,
        len: u32,
        segments: &mut Vec<Segment>,
    ) -> Result<(), GuestMemError> {
        let count = (len as u64 / DESC_SIZE) as u16;
        let mut index = 0u16;
        let mut steps = 0u16;
        loop {
            if index >= count || steps > self.max_indirect() {
                break;
            }
            let (addr, dlen, flags, next) = self.read_desc(mem, table, index)?;
            // Nested indirect tables are illegal in virtio; treat as a plain
            // buffer to avoid recursion.
            segments.push(Segment {
                gpa: addr,
                len: dlen,
                write: flags & VIRTQ_DESC_F_WRITE != 0,
            });
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            index = next;
            steps += 1;
        }
        Ok(())
    }

    /// Mark the chain headed by `head` complete, having written `len` bytes into
    /// its device-writable buffers. Appends a used-ring element and publishes the
    /// updated used index.
    pub fn add_used(&mut self, mem: &GuestMemory, head: u16, len: u32) -> Result<(), GuestMemError> {
        let slot = self.next_used % self.size;
        // used.ring starts at used + 4 (after flags + idx); each element is
        // {le32 id, le32 len}.
        let elem = self.used + 4 + 8 * slot as u64;
        mem.write_u32(elem, head as u32)?;
        mem.write_u32(elem + 4, len)?;
        self.next_used = self.next_used.wrapping_add(1);
        // Publish the new index last so the driver never sees a half-written
        // element (single-threaded host, but keep the ordering honest).
        mem.write_u16(self.used + 2, self.next_used)?;
        Ok(())
    }

    /// Whether the driver should be interrupted after publishing used indices
    /// in the range `(old_used, new_used]`.
    ///
    /// With `VIRTIO_RING_F_EVENT_IDX`, the driver publishes a `used_event` index
    /// (the last u16 of the available ring) asking to be interrupted once the
    /// device's `used.idx` passes it. We mirror the kernel's `vring_need_event`
    /// crossing test exactly: signal iff `used_event` lies within the freshly
    /// published window. The earlier "exact equality" rule
    /// (`next_used == used_event + 1`) silently dropped completions whenever the
    /// restored `used_event` did not line up one-past the current index — which
    /// is exactly the post-resume case, leaving a guest (e.g. jbd2) blocked on a
    /// completion whose used element was published but never signalled.
    /// Otherwise we honour `VRING_AVAIL_F_NO_INTERRUPT` in the avail-ring flags.
    pub fn needs_interrupt(
        &self,
        mem: &GuestMemory,
        old_used: u16,
        new_used: u16,
    ) -> Result<bool, GuestMemError> {
        if self.event_idx {
            let used_event = mem.read_u16(self.avail + 4 + 2 * self.size as u64)?;
            // vring_need_event: (u16)(new - event - 1) < (u16)(new - old).
            let a = new_used.wrapping_sub(used_event).wrapping_sub(1);
            let b = new_used.wrapping_sub(old_used);
            Ok(a < b)
        } else {
            let avail_flags = mem.read_u16(self.avail)?;
            const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
            Ok(avail_flags & VRING_AVAIL_F_NO_INTERRUPT == 0)
        }
    }

    /// Re-arm split-ring notification suppression so the driver will kick the
    /// device on its NEXT submission.
    ///
    /// A virtio driver suppresses queue notifications (the MMIO kick that wakes
    /// this poll-on-notify device) in one of two ways:
    /// - with `VIRTIO_RING_F_EVENT_IDX`, it only kicks when `avail.idx` crosses
    ///   the device-published `avail_event` (the last u16 of the used ring);
    /// - otherwise it honours `VRING_USED_F_NO_NOTIFY` in the used-ring flags.
    ///
    /// Both fields are written by the DEVICE. A restored snapshot carries the
    /// capture-side device's stale values: under EVENT_IDX `avail_event` may sit
    /// ahead of the current `avail.idx`, so the guest adds its next buffer (e.g.
    /// a jbd2 journal commit) WITHOUT kicking and then blocks forever waiting for
    /// a completion this device never sees. Re-pointing `avail_event` at the
    /// current `avail.idx` (and clearing NO_NOTIFY) makes the very next
    /// submission notify us, restoring forward progress. No-op when the device
    /// has no queue memory mapped yet.
    pub fn arm_notification(&self, mem: &GuestMemory) -> Result<(), GuestMemError> {
        if self.event_idx {
            // used ring: flags(2) + idx(2) + ring[size]*8, then avail_event(2).
            let avail_event_addr = self.used + 4 + 8 * self.size as u64;
            let cur = self.avail_idx(mem)?;
            mem.write_u16(avail_event_addr, cur)?;
        } else {
            // Clear VRING_USED_F_NO_NOTIFY (bit 0) so the driver kicks again.
            let flags = mem.read_u16(self.used)?;
            mem.write_u16(self.used, flags & !1)?;
        }
        Ok(())
    }

    /// Restore the engine's progress cursors from the live rings: the device
    /// resumes consuming at the driver's current `avail.idx` viewpoint and
    /// producing at the current `used.idx`. At snapshot time the queues were
    /// quiesced (drained), so both cursors equal the published indices.
    pub fn restore(&mut self, mem: &GuestMemory) -> Result<(), GuestMemError> {
        self.next_used = mem.read_u16(self.used + 2)?;
        // The device has consumed everything the driver had made available up to
        // the quiesce point; seed next_avail from used.idx so only *new*
        // post-resume submissions are processed.
        self.next_avail = self.next_used;
        Ok(())
    }

    /// The driver's published `avail.idx` (head of the available ring). Used at
    /// resume time to detect requests left in-flight across a snapshot.
    pub fn avail_idx_value(&self, mem: &GuestMemory) -> Result<u16, GuestMemError> {
        self.avail_idx(mem)
    }

    /// The device's published `used.idx` (head of the used ring).
    pub fn used_idx_value(&self, mem: &GuestMemory) -> Result<u16, GuestMemError> {
        mem.read_u16(self.used + 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ring layout used by the tests, all within one 64 KiB region at 0x1000.
    const QSZ: u16 = 8;
    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x1000 + DESC_SIZE * QSZ as u64; // 0x1080
    const USED: u64 = AVAIL + 4 + 2 * QSZ as u64 + 2; // after avail ring + used_event

    fn mem() -> GuestMemory {
        let m = GuestMemory::new();
        m.register_owned(0x1000, 0x4000);
        m
    }

    fn queue() -> Queue {
        Queue {
            size: QSZ,
            desc: DESC,
            avail: AVAIL,
            used: USED,
            event_idx: false,
            indirect: true,
            next_avail: 0,
            next_used: 0,
        }
    }

    fn write_desc(m: &GuestMemory, table: u64, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let base = table + DESC_SIZE * i as u64;
        m.write(base, &addr.to_le_bytes()).unwrap();
        m.write_u32(base + 8, len).unwrap();
        m.write_u16(base + 12, flags).unwrap();
        m.write_u16(base + 14, next).unwrap();
    }

    fn publish_avail(m: &GuestMemory, slot: u16, head: u16, idx: u16) {
        m.write_u16(AVAIL + 4 + 2 * slot as u64, head).unwrap();
        m.write_u16(AVAIL + 2, idx).unwrap();
    }

    #[test]
    fn pops_a_two_descriptor_chain() {
        let m = mem();
        let mut q = queue();
        // desc 0: readable header @0x2000 len 16, next=1
        write_desc(&m, DESC, 0, 0x2000, 16, VIRTQ_DESC_F_NEXT, 1);
        // desc 1: writable status @0x2010 len 1, end
        write_desc(&m, DESC, 1, 0x2010, 1, VIRTQ_DESC_F_WRITE, 0);
        publish_avail(&m, 0, 0, 1);

        let chain = q.pop(&m).unwrap().expect("a chain");
        assert_eq!(chain.head, 0);
        assert_eq!(
            chain.segments,
            vec![
                Segment { gpa: 0x2000, len: 16, write: false },
                Segment { gpa: 0x2010, len: 1, write: true },
            ]
        );
        assert_eq!(chain.writable_len(), 1);
        assert!(q.pop(&m).unwrap().is_none()); // nothing more available
    }

    #[test]
    fn expands_indirect_table() {
        let m = mem();
        let mut q = queue();
        // desc 0 is indirect, pointing at a 2-entry table at 0x3000.
        write_desc(&m, DESC, 0, 0x3000, (2 * DESC_SIZE) as u32, VIRTQ_DESC_F_INDIRECT, 0);
        write_desc(&m, 0x3000, 0, 0x2000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_desc(&m, 0x3000, 1, 0x2010, 512, VIRTQ_DESC_F_WRITE, 0);
        publish_avail(&m, 0, 0, 1);

        let chain = q.pop(&m).unwrap().expect("a chain");
        assert_eq!(
            chain.segments,
            vec![
                Segment { gpa: 0x2000, len: 16, write: false },
                Segment { gpa: 0x2010, len: 512, write: true },
            ]
        );
    }

    #[test]
    fn add_used_publishes_element_and_index() {
        let m = mem();
        let mut q = queue();
        q.add_used(&m, 3, 137).unwrap();
        assert_eq!(m.read_u32(USED + 4).unwrap(), 3); // id
        assert_eq!(m.read_u32(USED + 8).unwrap(), 137); // len
        assert_eq!(m.read_u16(USED + 2).unwrap(), 1); // used.idx
        assert_eq!(q.next_used, 1);
    }

    #[test]
    fn no_interrupt_flag_is_honoured() {
        let m = mem();
        let q = queue();
        m.write_u16(AVAIL, 0).unwrap(); // flags = 0
        assert!(q.needs_interrupt(&m, 0, 1).unwrap());
        m.write_u16(AVAIL, 1).unwrap(); // VRING_AVAIL_F_NO_INTERRUPT
        assert!(!q.needs_interrupt(&m, 0, 1).unwrap());
    }

    #[test]
    fn event_idx_interrupt_crosses_used_event() {
        // used_event lives at the last u16 of the avail ring.
        let used_event_addr = AVAIL + 4 + 2 * QSZ as u64;
        let m = mem();
        let mut q = queue();
        q.event_idx = true;

        // Driver asks to be woken at used_event = 4 (i.e. when used.idx reaches
        // 5). Publishing the window (4, 5] crosses it -> interrupt.
        m.write_u16(used_event_addr, 4).unwrap();
        assert!(q.needs_interrupt(&m, 4, 5).unwrap());
        // A batch that stops short of the wake point (3, 4] does not cross it.
        assert!(!q.needs_interrupt(&m, 3, 4).unwrap());
        // A multi-completion batch that OVERSHOOTS the wake point still signals:
        // window (4, 7] contains used_event=4's wake point (5). The old
        // exact-equality rule (new_used == used_event+1) dropped this, leaving a
        // post-resume guest blocked on a batched completion.
        assert!(q.needs_interrupt(&m, 4, 7).unwrap());
    }

    #[test]
    fn arm_notification_points_avail_event_at_current_idx() {
        let avail_event_addr = USED + 4 + 8 * QSZ as u64;
        let m = mem();
        let mut q = queue();
        q.event_idx = true;
        m.write_u16(AVAIL + 2, 42).unwrap(); // avail.idx
        m.write_u16(avail_event_addr, 7).unwrap(); // stale capture-side value
        q.arm_notification(&m).unwrap();
        assert_eq!(m.read_u16(avail_event_addr).unwrap(), 42);
    }

    #[test]
    fn restore_seeds_cursors_from_used_idx() {
        let m = mem();
        let mut q = queue();
        m.write_u16(USED + 2, 5).unwrap();
        q.restore(&m).unwrap();
        assert_eq!(q.next_used, 5);
        assert_eq!(q.next_avail, 5);
    }
}
