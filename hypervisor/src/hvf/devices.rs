// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! A minimal, real MMIO device model for the macOS rehydration path.
//!
//! When a rehydrated guest ([`crate::hvf::rehydrate`]) executes, every access
//! that is *not* backed by mapped guest RAM traps out to the [`VmOps`] the
//! caller supplied. The vmm (Phase 3) will eventually provide the full
//! virtio/PCI device tree here; this module is the first real seed of that
//! layer: an address-routed [`MmioBus`] plus a faithful enough ARM PrimeCell
//! PL011 UART ([`Pl011`]) to service a resumed Linux/UEFI guest's serial
//! console so its output is actually produced rather than discarded.
//!
//! The devices use interior mutability (a `Mutex` per device) because `VmOps`
//! is invoked through a shared `&self`.

use std::sync::{Arc, Mutex, RwLock};

use crate::vm::{Result as VmOpsResult, VmOps};

/// A single memory-mapped device occupying a contiguous IPA range.
///
/// Offsets passed to [`MmioDevice::read`]/[`MmioDevice::write`] are relative to
/// the device's base address. Implementations are shared (`&self`) and must use
/// interior mutability for any state they keep.
pub trait MmioDevice: Send + Sync {
    /// Service a read of `data.len()` bytes at `offset` within the device.
    fn read(&self, offset: u64, data: &mut [u8]);
    /// Service a write of `data` at `offset` within the device.
    fn write(&self, offset: u64, data: &[u8]);
}

struct BusEntry {
    base: u64,
    size: u64,
    dev: Arc<dyn MmioDevice>,
}

/// When `CHM_TRACE_MMIO` is set, log accesses that hit no mapped device. Used
/// to characterize which device windows a rehydrated guest reaches for that the
/// current model does not yet provide (PCI ECAM, virtio-pci BARs).
fn trace_unclaimed(op: &str, gpa: u64, len: usize) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ENABLED: AtomicBool = AtomicBool::new(false);
    static INIT: AtomicBool = AtomicBool::new(false);
    if !INIT.swap(true, Ordering::Relaxed) {
        ENABLED.store(
            std::env::var_os("CHM_TRACE_MMIO").is_some(),
            Ordering::Relaxed,
        );
    }
    if ENABLED.load(Ordering::Relaxed) {
        eprintln!("[mmio-unclaimed] {op} {gpa:#012x} ({len})");
    }
}

/// An address-routed MMIO bus that implements [`VmOps`].
///
/// Accesses are dispatched to the device whose `[base, base+size)` range
/// contains the faulting address. Unclaimed reads return all-zeroes (RAZ) and
/// unclaimed writes are dropped (WI), which keeps a probing guest making
/// forward progress instead of spinning on an undefined register.
#[derive(Default)]
pub struct MmioBus {
    devices: RwLock<Vec<BusEntry>>,
}

impl MmioBus {
    /// Create an empty bus.
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
        }
    }

    /// Map `dev` into `[base, base+size)`. Ranges must not overlap.
    ///
    /// Takes `&self` (the device list is interior-mutable) so devices can be
    /// installed after the bus is already shared as an `Arc<dyn VmOps>` — e.g.
    /// the rehydration path adds virtio devices only once guest RAM is mapped.
    pub fn add(&self, base: u64, size: u64, dev: Arc<dyn MmioDevice>) {
        let mut devices = self.devices.write().unwrap();
        debug_assert!(
            !devices
                .iter()
                .any(|e| base < e.base + e.size && e.base < base + size),
            "MmioBus device ranges overlap"
        );
        devices.push(BusEntry { base, size, dev });
    }

    fn find(&self, gpa: u64) -> Option<(Arc<dyn MmioDevice>, u64)> {
        self.devices
            .read()
            .unwrap()
            .iter()
            .find(|e| gpa >= e.base && gpa < e.base + e.size)
            .map(|e| (e.dev.clone(), gpa - e.base))
    }
}

impl VmOps for MmioBus {
    fn guest_mem_write(&self, _gpa: u64, buf: &[u8]) -> VmOpsResult<usize> {
        // Guest RAM is mapped directly into the guest via
        // `create_user_memory_region`, so the hypervisor never routes mapped-RAM
        // accesses back through this callback.
        Ok(buf.len())
    }

    fn guest_mem_read(&self, _gpa: u64, buf: &mut [u8]) -> VmOpsResult<usize> {
        Ok(buf.len())
    }

    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> VmOpsResult<()> {
        match self.find(gpa) {
            Some((dev, offset)) => dev.read(offset, data),
            None => {
                data.fill(0);
                trace_unclaimed("r", gpa, data.len());
            }
        }
        Ok(())
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        match self.find(gpa) {
            Some((dev, offset)) => dev.write(offset, data),
            None => trace_unclaimed("w", gpa, data.len()),
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, _port: u64, data: &mut [u8]) -> VmOpsResult<()> {
        data.fill(0);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, _port: u64, _data: &[u8]) -> VmOpsResult<()> {
        Ok(())
    }
}

// --- PL011 ------------------------------------------------------------------

// Register byte offsets within the 0x1000 PL011 MMIO window.
const UARTDR: u64 = 0x000; // data
const UARTRSR_ECR: u64 = 0x004; // receive status / error clear
const UARTFR: u64 = 0x018; // flag register
const UARTIBRD: u64 = 0x024; // integer baud rate divisor
const UARTFBRD: u64 = 0x028; // fractional baud rate divisor
const UARTLCR_H: u64 = 0x02c; // line control
const UARTCR: u64 = 0x030; // control
const UARTIFLS: u64 = 0x034; // interrupt FIFO level select
const UARTIMSC: u64 = 0x038; // interrupt mask set/clear
const UARTRIS: u64 = 0x03c; // raw interrupt status
const UARTMIS: u64 = 0x040; // masked interrupt status
const UARTICR: u64 = 0x044; // interrupt clear
const UART_ID_LOW: u64 = 0xfe0; // PeriphID0..3 + PCellID0..3 (0xfe0..0x1000)

// Flag register bits.
const FR_TXFE: u32 = 1 << 7; // transmit FIFO empty
const FR_RXFF: u32 = 1 << 6; // receive FIFO full
const FR_RXFE: u32 = 1 << 4; // receive FIFO empty
// Modem-status flags. These reflect a virtual serial line whose carrier is
// permanently present: Data Carrier Detect, Data Set Ready, and Clear To Send
// are always asserted. A guest `agetty` that opens `ttyAMA0` without `CLOCAL`
// blocks in `open()` until Carrier Detect is seen; a resumed snapshot whose
// cloud-init restarts `serial-getty@ttyAMA0` reopens the tty against this fresh
// model, so without a live carrier the new getty would hang before it could
// print `login:` (the console appears dead). Tying them high matches how a
// console UART presents to the guest.
const FR_CTS: u32 = 1 << 0; // clear to send
const FR_DSR: u32 = 1 << 1; // data set ready
const FR_DCD: u32 = 1 << 2; // data carrier detect
const FR_MODEM_PRESENT: u32 = FR_CTS | FR_DSR | FR_DCD;

// Interrupt bits, shared by UARTRIS / UARTMIS / UARTIMSC / UARTICR.
const INT_RX: u32 = 1 << 4; // receive interrupt (RXRIS/RXMIS/RXIM)
const INT_RT: u32 = 1 << 6; // receive-timeout interrupt (RTRIS/RTMIS/RTIM)

/// Depth of the receive FIFO. The PL011 FIFO is 16 entries deep; host input
/// beyond that backs up in [`Pl011State::read_fifo`] and is fed in as the guest
/// drains the visible FIFO.
const RX_FIFO_DEPTH: usize = 16;

// PrimeCell identification bytes, one per 4-byte slot from 0xfe0..0x1000.
const PL011_ID: [u8; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

#[derive(Default)]
struct Pl011State {
    ibrd: u32,
    fbrd: u32,
    lcr_h: u32,
    cr: u32,
    ifls: u32,
    imsc: u32,
    /// Bytes the guest has transmitted, in order.
    tx: Vec<u8>,
    /// Bytes received from the host, waiting for the guest to read `UARTDR`.
    read_fifo: std::collections::VecDeque<u8>,
}

/// A faithful-enough ARM PrimeCell PL011 UART for servicing a resumed guest's
/// serial console, in both directions.
///
/// Transmit always reports ready (the host sink never backpressures), so the
/// guest's `putc` fast-path completes and the bytes it writes to `UARTDR` are
/// captured in [`Pl011::take_output`]. Receive is host-driven:
/// [`Pl011::push_input`] enqueues bytes the host typed, a `UARTDR` read pops the
/// next one, and the flag/interrupt registers reflect FIFO state so an
/// interrupt-driven guest tty (e.g. `agetty` on `ttyAMA0`) sees its receive
/// interrupt and reads the data. Programmable registers round-trip so a guest
/// that reconfigures the port after resume reads back what it wrote, and the
/// PrimeCell ID block reads its architectural constants so driver probes
/// succeed.
pub struct Pl011 {
    state: Mutex<Pl011State>,
}

impl Default for Pl011 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pl011 {
    /// Create a PL011 with empty FIFOs and cleared programmable registers.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Pl011State::default()),
        }
    }

    /// Drain and return everything the guest has transmitted so far.
    pub fn take_output(&self) -> Vec<u8> {
        std::mem::take(&mut self.state.lock().unwrap().tx)
    }

    /// Seed the line/interrupt configuration captured from the snapshot's
    /// `__serial` node so our fresh model matches what the resumed guest's
    /// driver believes the hardware holds.
    ///
    /// This is essential for interactive receive: a guest programs UARTIMSC
    /// (RXIM) once when it opens the tty, BEFORE the snapshot, and does not
    /// re-issue it after resume. Without restoring `imsc` our model would treat
    /// the receive interrupt as masked and never assert it for typed input, so
    /// an interrupt-driven `agetty` would never read the host's keystrokes.
    pub fn restore(&self, imsc: u32, cr: u32, lcr_h: u32, ibrd: u32, fbrd: u32, ifls: u32) {
        let mut st = self.state.lock().unwrap();
        st.imsc = imsc;
        st.cr = cr;
        st.lcr_h = lcr_h;
        st.ibrd = ibrd;
        st.fbrd = fbrd;
        st.ifls = ifls;
    }

    /// Enqueue host input for the guest to receive. Returns `true` when the
    /// guest has unmasked the receive interrupt, i.e. the caller should now
    /// assert the UART's interrupt line so the guest's tty handler runs and
    /// reads `UARTDR`. A guest that polls (rather than using interrupts) reads
    /// the data regardless, so a `false` return is not an error.
    pub fn push_input(&self, bytes: &[u8]) -> bool {
        let mut st = self.state.lock().unwrap();
        for &b in bytes {
            st.read_fifo.push_back(b);
        }
        // The receive (RXIM) or receive-timeout (RTIM) mask being set means the
        // guest is interrupt-driven on RX; either one warrants asserting.
        !st.read_fifo.is_empty() && (st.imsc & (INT_RX | INT_RT)) != 0
    }

    /// Whether the receive interrupt should currently be asserted: there is
    /// unread input in the FIFO and the guest has RXIM/RTIM unmasked. The PL011
    /// receive interrupt is level-triggered — it stays asserted while data is
    /// pending — but this model only pulses the SPI from [`Self::push_input`] on
    /// a fresh keystroke. A guest that unmasks RXIM *after* input was queued
    /// (e.g. a getty reopening `ttyAMA0`), or that returns from its ISR with
    /// bytes still buffered, would otherwise never see another edge. A serial
    /// service tick polls this and re-asserts, restoring level semantics so the
    /// guest can never wedge with input stuck in the FIFO.
    pub fn rx_irq_pending(&self) -> bool {
        let st = self.state.lock().unwrap();
        !st.read_fifo.is_empty() && (st.imsc & (INT_RX | INT_RT)) != 0
    }
}

fn read_u32(data: &mut [u8], value: u32) {
    let bytes = value.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        *b = bytes.get(i).copied().unwrap_or(0);
    }
}

fn write_u32(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    for (i, b) in data.iter().take(4).enumerate() {
        buf[i] = *b;
    }
    u32::from_le_bytes(buf)
}

impl Pl011State {
    /// Raw interrupt status (UARTRIS): receive and receive-timeout bits track
    /// the FIFO. We assert both whenever data is present, which matches what an
    /// interrupt-driven Linux `amba-pl011` driver expects (it drains the FIFO
    /// until empty on either bit).
    fn raw_interrupt_status(&self) -> u32 {
        if self.read_fifo.is_empty() {
            0
        } else {
            INT_RX | INT_RT
        }
    }

    /// Flag register (UARTFR): TX always empty/ready, RX flags from the FIFO,
    /// and the modem-status lines (DCD/DSR/CTS) tied high so a guest that opens
    /// the tty waiting for carrier proceeds.
    fn flags(&self) -> u32 {
        let mut fr = FR_TXFE | FR_MODEM_PRESENT;
        if self.read_fifo.is_empty() {
            fr |= FR_RXFE;
        } else if self.read_fifo.len() >= RX_FIFO_DEPTH {
            fr |= FR_RXFF;
        }
        fr
    }
}

impl MmioDevice for Pl011 {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut st = self.state.lock().unwrap();
        let val = match offset {
            // Reading the data register pops the next received byte (or 0 when
            // the FIFO is empty); the error/status bits in the high half are
            // always clear for host-injected input.
            UARTDR => st.read_fifo.pop_front().map_or(0, u32::from),
            UARTRSR_ECR => 0,
            UARTFR => st.flags(),
            UARTIBRD => st.ibrd,
            UARTFBRD => st.fbrd,
            UARTLCR_H => st.lcr_h,
            UARTCR => st.cr,
            UARTIFLS => st.ifls,
            UARTIMSC => st.imsc,
            UARTRIS => st.raw_interrupt_status(),
            UARTMIS => st.raw_interrupt_status() & st.imsc,
            off if (UART_ID_LOW..0x1000).contains(&off) => {
                let idx = ((off - UART_ID_LOW) / 4) as usize;
                PL011_ID.get(idx).copied().unwrap_or(0) as u32
            }
            _ => 0,
        };
        read_u32(data, val);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let val = write_u32(data);
        let mut st = self.state.lock().unwrap();
        match offset {
            UARTDR => st.tx.push(val as u8),
            UARTIBRD => st.ibrd = val,
            UARTFBRD => st.fbrd = val,
            UARTLCR_H => st.lcr_h = val,
            UARTCR => st.cr = val,
            UARTIFLS => st.ifls = val,
            UARTIMSC => st.imsc = val,
            // Write-1-to-clear / read-side registers: the receive interrupt is
            // recomputed from the FIFO on every read, so an ICR write that
            // clears RXIC/RTIC while data remains correctly re-asserts on the
            // next read. Nothing to store.
            UARTICR | UARTRSR_ECR => {}
            _ => {}
        }
    }
}

/// PL031 real-time clock registers.
const RTCDR: u64 = 0x000; // data (current value), seconds since the epoch
const RTCMR: u64 = 0x004; // match
const RTCLR: u64 = 0x008; // load
const RTCCR: u64 = 0x00c; // control
const RTCIMSC: u64 = 0x010; // interrupt mask
const RTCRIS: u64 = 0x014; // raw interrupt status
const RTCMIS: u64 = 0x018; // masked interrupt status
const RTCICR: u64 = 0x01c; // interrupt clear
const RTC_ID_LOW: u64 = 0xfe0; // PeriphID0..3 + PCellID0..3

/// PrimeCell identification bytes for the PL031, one per 4-byte slot.
const PL031_ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

#[derive(Default)]
struct Pl031State {
    /// Guest-visible time minus host time, in seconds. Non-zero only after the
    /// guest writes `RTCLR`, which is the guest saying "the clock is wrong, it
    /// is actually this" -- honoured rather than ignored, so `hwclock -w`
    /// behaves, but kept as an offset because the host clock is what actually
    /// advances.
    offset: i64,
    mr: u32,
    imsc: u32,
    /// Set when the counter has passed `mr` since the last clear.
    ris: u32,
}

/// A PL031 real-time clock reading the host's wall clock.
///
/// **A guest with no RTC does not know what year it is**, and on a cold boot
/// there is no snapshot to inherit a time from. Linux falls back to the epoch
/// or to a build-time constant, `systemd-timesyncd` cannot correct it without
/// network, and the network cannot come up cleanly because *every* TLS
/// handshake rejects certificates that are "not yet valid". That failure is
/// silent and looks like a network fault, which is why it is worth a device.
///
/// Deliberately read-only in effect: the guest sees host wall-clock seconds.
/// It is the same clock the vtimer is stepped against, so the two cannot drift
/// apart the way a separately-seeded RTC would.
pub struct Pl031 {
    state: Mutex<Pl031State>,
}

impl Default for Pl031 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pl031 {
    /// Create a PL031 tracking the host wall clock with no offset.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Pl031State::default()),
        }
    }

    /// Host wall-clock seconds since the Unix epoch.
    fn host_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn now(&self, st: &Pl031State) -> u32 {
        // Saturating rather than wrapping: a clock that reads 1970 is a
        // recognisable failure, one that wraps to 2106 is not.
        Self::host_now()
            .saturating_add(st.offset)
            .clamp(0, u32::MAX as i64) as u32
    }
}

impl MmioDevice for Pl031 {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut st = self.state.lock().unwrap();
        let now = self.now(&st);
        if now >= st.mr {
            st.ris = 1;
        }
        let val = match offset {
            RTCDR => now,
            RTCMR => st.mr,
            // The load register reads back the same counter it set.
            RTCLR => now,
            // Bit 0 reads as 1: the counter is always enabled. Writing it is a
            // no-op on real silicon too.
            RTCCR => 1,
            RTCIMSC => st.imsc,
            RTCRIS => st.ris,
            RTCMIS => st.ris & st.imsc,
            RTC_ID_LOW..0x1000 => u32::from(PL031_ID[((offset - RTC_ID_LOW) >> 2) as usize & 7]),
            _ => 0,
        };
        read_u32(data, val);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let val = write_u32(data);
        let mut st = self.state.lock().unwrap();
        match offset {
            RTCLR => {
                let now = Self::host_now();
                st.offset = i64::from(val) - now;
            }
            RTCMR => st.mr = val,
            RTCIMSC => st.imsc = val & 1,
            RTCICR => {
                if val & 1 != 0 {
                    st.ris = 0;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pl011_captures_transmitted_bytes() {
        let uart = Pl011::new();
        // Guest's putc fast-path: poll FR until TX ready, then write the byte.
        for &c in b"hi\n" {
            let mut fr = [0u8; 4];
            uart.read(UARTFR, &mut fr);
            assert_ne!(u32::from_le_bytes(fr) & FR_TXFE, 0, "TX must report ready");
            uart.write(UARTDR, &[c]);
        }
        assert_eq!(uart.take_output(), b"hi\n");
        // Output is drained by take_output.
        assert!(uart.take_output().is_empty());
    }

    #[test]
    fn pl011_flag_register_asserts_carrier() {
        // A guest agetty opening ttyAMA0 without CLOCAL blocks in open() until
        // Data Carrier Detect is seen; the modem-status lines must read asserted
        // so a serial-getty restart on a resumed snapshot does not hang before
        // printing its login prompt.
        let uart = Pl011::new();
        let mut fr = [0u8; 4];
        uart.read(UARTFR, &mut fr);
        let fr = u32::from_le_bytes(fr);
        assert_ne!(fr & FR_DCD, 0, "DCD (carrier) must read asserted");
        assert_ne!(fr & FR_DSR, 0, "DSR must read asserted");
        assert_ne!(fr & FR_CTS, 0, "CTS must read asserted");
    }

    #[test]
    fn pl011_id_block_reads_primecell_constants() {
        let uart = Pl011::new();
        for (i, &want) in PL011_ID.iter().enumerate() {
            let mut data = [0u8; 4];
            uart.read(UART_ID_LOW + (i as u64) * 4, &mut data);
            assert_eq!(data[0], want, "PrimeCell ID byte {i}");
        }
    }

    #[test]
    fn pl011_programmable_registers_round_trip() {
        let uart = Pl011::new();
        uart.write(UARTIBRD, &0x1234u32.to_le_bytes());
        uart.write(UARTCR, &0x0301u32.to_le_bytes());
        let mut data = [0u8; 4];
        uart.read(UARTIBRD, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0x1234);
        uart.read(UARTCR, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0x0301);
    }

    #[test]
    fn mmio_bus_routes_by_address() {
        let uart = Arc::new(Pl011::new());
        let bus = MmioBus::new();
        bus.add(0x0900_0000, 0x1000, uart.clone());

        // Write a byte to the UART data register through the bus.
        bus.mmio_write(0x0900_0000 + UARTDR, b"Z").unwrap();
        assert_eq!(uart.take_output(), b"Z");

        // Unclaimed address reads back as zero.
        let mut data = [0xffu8; 4];
        bus.mmio_read(0x1000_0000, &mut data).unwrap();
        assert_eq!(data, [0, 0, 0, 0]);
    }

    fn read_reg(uart: &Pl011, off: u64) -> u32 {
        let mut d = [0u8; 4];
        uart.read(off, &mut d);
        u32::from_le_bytes(d)
    }

    #[test]
    fn pl011_rx_fifo_delivers_input_in_order() {
        let uart = Pl011::new();
        // Empty FIFO: RXFE set, DR reads zero.
        assert_ne!(read_reg(&uart, UARTFR) & FR_RXFE, 0, "RXFE set when empty");
        assert_eq!(read_reg(&uart, UARTDR), 0);

        uart.push_input(b"ab");
        // Data present: RXFE clear.
        assert_eq!(read_reg(&uart, UARTFR) & FR_RXFE, 0, "RXFE clear with data");
        assert_eq!(read_reg(&uart, UARTDR), u32::from(b'a'));
        assert_eq!(read_reg(&uart, UARTDR), u32::from(b'b'));
        // Drained: RXFE set again.
        assert_ne!(read_reg(&uart, UARTFR) & FR_RXFE, 0);
        assert_eq!(read_reg(&uart, UARTDR), 0);
    }

    #[test]
    fn pl011_rx_interrupt_tracks_mask_and_fifo() {
        let uart = Pl011::new();
        // Mask cleared: push reports no need to assert, but data still queues.
        assert!(!uart.push_input(b"x"), "no assert while RX masked");
        assert_eq!(read_reg(&uart, UARTRIS) & INT_RX, INT_RX, "raw status set");
        assert_eq!(read_reg(&uart, UARTMIS) & INT_RX, 0, "masked status gated");

        // Guest unmasks RX (RXIM). A further push asks the caller to assert.
        uart.write(UARTIMSC, &INT_RX.to_le_bytes());
        assert!(uart.push_input(b"y"), "assert once RX unmasked");
        assert_eq!(read_reg(&uart, UARTMIS) & INT_RX, INT_RX, "masked status set");

        // Draining the FIFO clears the receive interrupt.
        let _ = read_reg(&uart, UARTDR);
        let _ = read_reg(&uart, UARTDR);
        assert_eq!(read_reg(&uart, UARTRIS) & (INT_RX | INT_RT), 0, "cleared");
        assert_eq!(read_reg(&uart, UARTMIS) & (INT_RX | INT_RT), 0);
    }

    #[test]
    fn pl011_rx_irq_pending_tracks_level_state() {
        let uart = Pl011::new();
        // Nothing queued: not pending regardless of mask.
        assert!(!uart.rx_irq_pending(), "no pending irq with empty FIFO");
        uart.write(UARTIMSC, &INT_RX.to_le_bytes());
        assert!(!uart.rx_irq_pending(), "still nothing pending, FIFO empty");

        // Data present + unmasked: the receive irq is level-asserted.
        uart.push_input(b"z");
        assert!(uart.rx_irq_pending(), "pending with data + RXIM unmasked");

        // Draining the FIFO clears it.
        let _ = read_reg(&uart, UARTDR);
        assert!(!uart.rx_irq_pending(), "cleared once the FIFO drains");
    }

    #[test]
    fn pl011_rx_irq_reasserts_after_unmask_with_pending_data() {
        // The freeze scenario: input is queued while RX is masked (push_input
        // reports no assert), then the guest unmasks RXIM *after* — e.g. a getty
        // reopening ttyAMA0. push_input is not called again (no new keystroke),
        // so nothing re-pulses the SPI; the serial re-assert tick relies on
        // rx_irq_pending() staying true so the stranded input is delivered.
        let uart = Pl011::new();
        assert!(!uart.push_input(b"login"), "queued while masked, no assert");
        assert!(!uart.rx_irq_pending(), "masked: irq not pending yet");

        // Guest unmasks RX with the five bytes still sitting in the FIFO.
        uart.write(UARTIMSC, &INT_RX.to_le_bytes());
        assert!(
            uart.rx_irq_pending(),
            "after unmask with pending data the irq must be assertable — otherwise \
             the guest wedges waiting for an edge that already passed"
        );
    }

    #[test]
    fn pl011_restore_seeds_rx_mask_so_input_asserts() {
        // A resumed guest programs UARTIMSC (RXIM) before the snapshot and does
        // not re-issue it after restore. Without seeding the mask the model
        // would treat receive as masked and never assert for typed input.
        let uart = Pl011::new();
        assert!(!uart.push_input(b"a"), "masked before restore");

        // Restore the captured `__serial` state (int_enabled = 0x50 = RXIM|RTIM).
        uart.restore(INT_RX | INT_RT, 0x0f01, 0x70, 39, 4, 0x12);
        assert!(uart.push_input(b"b"), "assert once restored mask has RXIM");
        assert_eq!(read_reg(&uart, UARTMIS) & INT_RX, INT_RX);
        // Line/baud registers round-trip from the restored state.
        assert_eq!(read_reg(&uart, UARTIMSC), INT_RX | INT_RT);
        assert_eq!(read_reg(&uart, UARTIBRD), 39);
    }
}
