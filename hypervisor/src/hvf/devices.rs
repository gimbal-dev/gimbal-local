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

use std::sync::{Arc, Mutex};

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

/// An address-routed MMIO bus that implements [`VmOps`].
///
/// Accesses are dispatched to the device whose `[base, base+size)` range
/// contains the faulting address. Unclaimed reads return all-zeroes (RAZ) and
/// unclaimed writes are dropped (WI), which keeps a probing guest making
/// forward progress instead of spinning on an undefined register.
#[derive(Default)]
pub struct MmioBus {
    devices: Vec<BusEntry>,
}

impl MmioBus {
    /// Create an empty bus.
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Map `dev` into `[base, base+size)`. Ranges must not overlap.
    pub fn add(&mut self, base: u64, size: u64, dev: Arc<dyn MmioDevice>) {
        debug_assert!(
            !self
                .devices
                .iter()
                .any(|e| base < e.base + e.size && e.base < base + size),
            "MmioBus device ranges overlap"
        );
        self.devices.push(BusEntry { base, size, dev });
    }

    fn find(&self, gpa: u64) -> Option<(&Arc<dyn MmioDevice>, u64)> {
        self.devices
            .iter()
            .find(|e| gpa >= e.base && gpa < e.base + e.size)
            .map(|e| (&e.dev, gpa - e.base))
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
            None => data.fill(0),
        }
        Ok(())
    }

    fn mmio_write(&self, gpa: u64, data: &[u8]) -> VmOpsResult<()> {
        if let Some((dev, offset)) = self.find(gpa) {
            dev.write(offset, data);
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
const FR_RXFE: u32 = 1 << 4; // receive FIFO empty

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
}

/// A faithful-enough ARM PrimeCell PL011 UART for servicing a resumed guest's
/// serial console.
///
/// Transmit always reports ready (the host sink never backpressures), so the
/// guest's `putc` fast-path completes and the bytes it writes to `UARTDR` are
/// captured in [`Pl011::take_output`]. Receive is reported permanently empty
/// (no host-side input is injected yet). Programmable registers round-trip so a
/// guest that reconfigures the port after resume reads back what it wrote, and
/// the PrimeCell ID block reads its architectural constants so driver probes
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

impl MmioDevice for Pl011 {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let st = self.state.lock().unwrap();
        let val = match offset {
            // Receive FIFO is always empty; report no data.
            UARTDR => 0,
            UARTRSR_ECR => 0,
            // Always ready to transmit, never anything to receive.
            UARTFR => FR_TXFE | FR_RXFE,
            UARTIBRD => st.ibrd,
            UARTFBRD => st.fbrd,
            UARTLCR_H => st.lcr_h,
            UARTCR => st.cr,
            UARTIFLS => st.ifls,
            UARTIMSC => st.imsc,
            // No interrupts are raised by this minimal model.
            UARTRIS | UARTMIS => 0,
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
            // Write-1-to-clear / read-side registers: nothing to store.
            UARTICR | UARTRSR_ECR => {}
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
        let mut bus = MmioBus::new();
        bus.add(0x0900_0000, 0x1000, uart.clone());

        // Write a byte to the UART data register through the bus.
        bus.mmio_write(0x0900_0000 + UARTDR, b"Z").unwrap();
        assert_eq!(uart.take_output(), b"Z");

        // Unclaimed address reads back as zero.
        let mut data = [0xffu8; 4];
        bus.mmio_read(0x1000_0000, &mut data).unwrap();
        assert_eq!(data, [0, 0, 0, 0]);
    }
}
