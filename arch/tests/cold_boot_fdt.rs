// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: Apache-2.0

//! Proving a cold-boot device tree can be built on macOS.
//!
//! The roadmap recorded `arch` as unbuildable on macOS, which made cold boot
//! (#101) look like it needed a port of a 1325-line FDT generator before it
//! could start. Re-measured, that was wrong: the conclusion had been reached
//! with `--no-default-features` (no hypervisor backend selected, so its enums
//! are empty and every match is non-exhaustive) and with `--features kvm`
//! (`kvm-ioctls` does not build on macOS at all). Neither is the feature set
//! this project uses.
//!
//! These tests exist so that cannot be believed again by inspection. They build
//! a real device tree, on this host, and read it back with an independent
//! parser — not the writer that produced it. If `arch` stops working on macOS,
//! this fails rather than a note somewhere going stale.

#![cfg(all(target_os = "macos", target_arch = "aarch64", feature = "hvf"))]

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use vm_memory::bitmap::AtomicBitmap;

use arch::aarch64::fdt::{DeviceInfoForFdt, create_fdt};
use arch::aarch64::layout;
use arch::{DeviceType, NumaNodes};
use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::hvf::coldgic::{COLD_BOOT_NR_IRQS, ColdBootGic, layout as cold_layout};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

#[derive(Clone, Debug)]
struct FdtDevice {
    addr: u64,
    irq: u32,
    len: u64,
}

impl DeviceInfoForFdt for FdtDevice {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irq
    }
    fn length(&self) -> u64 {
        self.len
    }
}

const RAM_SIZE: u64 = 256 << 20;

fn guest_memory(size: u64) -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(layout::RAM_START, size as usize)])
        .expect("allocating guest RAM on the host")
}

/// Build a device tree the way a cold boot would: our GIC, a PL011 console at
/// the canonical address, and a kernel command line.
fn build_tree(vcpus: u64) -> Vec<u8> {
    let gic = ColdBootGic::new(vcpus).expect("GIC layout for this vCPU count");
    let gic: Arc<Mutex<dyn Vgic>> = Arc::new(Mutex::new(gic));

    let mut devices: HashMap<(DeviceType, String), FdtDevice> = HashMap::new();
    devices.insert(
        (DeviceType::Serial, "serial".to_string()),
        FdtDevice {
            addr: layout::LEGACY_SERIAL_MAPPED_IO_START.0,
            irq: 33,
            len: 0x1000,
        },
    );

    let mpidr: Vec<u64> = (0..vcpus).collect();
    create_fdt(
        &guest_memory(RAM_SIZE),
        "console=ttyAMA0 reboot=k panic=1",
        &mpidr,
        None,
        &devices,
        &gic,
        &None,
        &[],
        &NumaNodes::default(),
        None,
        false,
    )
    .expect("create_fdt on macOS")
}

/// Read a `reg` property as a list of 64-bit big-endian cells.
fn reg_cells(prop: &[u8]) -> Vec<u64> {
    prop.chunks_exact(8)
        .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
        .collect()
}

#[test]
fn arch_builds_a_real_device_tree_on_macos() {
    let blob = build_tree(1);

    // A flattened device tree starts with magic 0xd00dfeed, and the header's
    // totalsize must match what we were handed. Checking the bytes rather than
    // trusting the writer's Ok.
    assert!(
        blob.len() > 64,
        "implausibly small blob: {} bytes",
        blob.len()
    );
    assert_eq!(&blob[0..4], &[0xd0, 0x0d, 0xfe, 0xed], "FDT magic");

    let totalsize = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    assert_eq!(totalsize, blob.len(), "header totalsize vs actual length");
}

#[test]
fn the_tree_parses_and_describes_our_gic() {
    let blob = build_tree(2);
    let fdt = fdt_parser::Fdt::new(&blob).expect("parsing the blob we just wrote");

    let intc = fdt
        .find_node("/intc")
        .expect("device tree must contain an interrupt controller");

    let compatible = intc
        .property("compatible")
        .and_then(|p| p.as_str())
        .expect("intc compatible");
    assert_eq!(compatible, "arm,gic-v3");

    // The addresses in the tree must be the ones ColdBootGic reports — the
    // point of the type is that a kernel is told where the GIC actually is.
    let gic = ColdBootGic::new(2).unwrap();
    let [dist, dist_size, redist, redist_size] = gic.device_properties();

    let reg = reg_cells(intc.property("reg").expect("intc reg").value);
    assert_eq!(
        reg,
        vec![dist, dist_size, redist, redist_size],
        "intc reg must match the GIC's own address map"
    );
}

#[test]
fn redistributor_frames_scale_with_vcpu_count_in_the_tree() {
    // Not just in the struct — in the bytes a guest would read.
    for vcpus in [1u64, 2, 4, 8] {
        let blob = build_tree(vcpus);
        let fdt = fdt_parser::Fdt::new(&blob).unwrap();
        let intc = fdt.find_node("/intc").unwrap();
        let reg = reg_cells(intc.property("reg").unwrap().value);
        assert_eq!(
            reg[3],
            cold_layout::GIC_V3_REDIST_SIZE * vcpus,
            "redistributor window for {vcpus} vCPUs"
        );
    }
}

#[test]
fn the_kernel_command_line_survives_into_the_tree() {
    let blob = build_tree(1);
    let fdt = fdt_parser::Fdt::new(&blob).unwrap();
    let bootargs = fdt
        .find_node("/chosen")
        .and_then(|n| n.property("bootargs"))
        .and_then(|p| p.as_str())
        .expect("chosen/bootargs");
    assert_eq!(bootargs, "console=ttyAMA0 reboot=k panic=1");
}

#[test]
fn the_console_a_cold_guest_would_use_is_described() {
    // Without this node the kernel boots and says nothing, which is
    // indistinguishable from not booting.
    let blob = build_tree(1);
    let fdt = fdt_parser::Fdt::new(&blob).unwrap();
    let uart = fdt
        .all_nodes()
        .find(|n| n.name.starts_with("pl011@"))
        .expect("a PL011 node");
    let reg = reg_cells(uart.property("reg").expect("uart reg").value);
    assert_eq!(reg[0], layout::LEGACY_SERIAL_MAPPED_IO_START.0);
}

#[test]
fn the_tree_fits_the_region_reserved_for_it() {
    // FDT_START is the base of guest RAM, so a tree larger than FDT_MAX_SIZE
    // would be written over the kernel rather than beneath it.
    for vcpus in [1u64, 8, 32] {
        let blob = build_tree(vcpus);
        assert!(
            (blob.len() as u64) < layout::FDT_MAX_SIZE,
            "{vcpus}-vCPU tree is {} bytes, over the {} reserved",
            blob.len(),
            layout::FDT_MAX_SIZE
        );
    }
}

#[test]
fn cold_gic_layout_constants_match_arch() {
    // `hypervisor` cannot depend on `arch` (arch depends on hypervisor), so the
    // GIC window is written down in both. This test is the join: if either
    // moves, it fails here rather than producing a tree that points a kernel at
    // an address nothing serves.
    assert_eq!(cold_layout::GIC_V3_DIST_SIZE, layout::GIC_V3_DIST_SIZE);
    assert_eq!(cold_layout::GIC_V3_DIST_START, layout::GIC_V3_DIST_START.0);
    assert_eq!(cold_layout::GIC_V3_REDIST_SIZE, layout::GIC_V3_REDIST_SIZE);
    assert_eq!(
        cold_layout::MAPPED_IO_START,
        layout::LEGACY_SERIAL_MAPPED_IO_START.0,
        "MAPPED_IO_START is where the legacy devices begin"
    );
}

#[test]
fn memory_node_describes_the_ram_we_allocated() {
    let blob = build_tree(1);
    let fdt = fdt_parser::Fdt::new(&blob).unwrap();
    let mem = fdt
        .all_nodes()
        .find(|n| n.name.starts_with("memory@"))
        .expect("a memory node");
    let reg = reg_cells(mem.property("reg").expect("memory reg").value);
    assert_eq!(reg[0], layout::RAM_START.0, "RAM base");
    assert_eq!(reg[1], RAM_SIZE, "RAM size");
}

#[test]
fn nr_irqs_is_the_cold_boot_default() {
    // The tree does not carry the line count, but the GIC config does, and the
    // distributor is initialised from it. Pinned so a silent change is caught.
    assert_eq!(ColdBootGic::new(1).unwrap().nr_irqs(), COLD_BOOT_NR_IRQS);
    assert_eq!(COLD_BOOT_NR_IRQS, 256);
}

/// Print the tree a cold boot would hand a kernel.
///
/// Ignored by default because it asserts nothing — it is here so the thing
/// being claimed can be read rather than taken on trust:
/// `cargo test -p arch --features hvf --test cold_boot_fdt -- --ignored --nocapture`
#[test]
#[ignore = "diagnostic, prints the tree"]
fn dump_the_tree() {
    let blob = build_tree(2);
    let fdt = fdt_parser::Fdt::new(&blob).unwrap();
    println!("--- cold-boot device tree, 2 vCPU, {} bytes ---", blob.len());
    for node in fdt.all_nodes() {
        let name = if node.name.is_empty() { "/" } else { node.name };
        println!("  {name}");
        for p in node.properties() {
            let rendered = p.as_str().map_or_else(
                || format!("<{} bytes> {:02x?}", p.value.len(), p.value),
                |s| format!("{s:?}"),
            );
            println!("      {} = {rendered}", p.name);
        }
    }
}
