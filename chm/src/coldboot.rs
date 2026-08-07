//! Build a bootable guest from a kernel image, with no snapshot involved.
//!
//! Everything else in this binary *rehydrates*: guest RAM arrives from a
//! capture with a kernel already resident, a device tree already written, and
//! every register already meaningful. This module is the other direction — it
//! constructs that state from nothing, so a sandbox can start from an image you
//! downloaded rather than a capture somebody made for you on a KVM host.
//!
//! ## What "from nothing" actually has to produce
//!
//! The arm64 Linux boot protocol is short enough to state completely, and each
//! line of it is a thing this module must get exactly right:
//!
//! - The kernel image is loaded at a 2 MiB-aligned address, and the header's
//!   `image_size` (not the *file* size) is the memory it needs — the tail is
//!   BSS, which is not in the file but must be present and zeroed in RAM.
//! - `x0` holds the physical address of a flattened device tree; `x1`–`x3` are
//!   zero.
//! - The CPU enters at EL1 with the MMU off, D-cache off, interrupts masked.
//! - Secondary CPUs stay parked until the kernel brings them up through PSCI.
//!
//! The register half is already implemented — `HvfVcpu::setup_regs` has done it
//! since the SMP work, because a *restored* secondary vCPU enters through the
//! same door. What was missing was the memory half: the image, the tree, and an
//! honest description of the machine the tree describes.
//!
//! ## Why this is not in `arch`
//!
//! `arch` is upstream code and already contains every piece: the aarch64 memory
//! layout, the FDT writer, the PE loader wiring. It was believed not to build
//! on macOS for a month; it does (see `docs/roadmap.md`). So this module adds
//! nothing to `arch` and instead composes it, which keeps the fork surface at
//! zero for the 1325 lines that matter most.
//!
//! ## What it deliberately refuses
//!
//! A kernel that is not an arm64 `Image` is rejected here, by reading the
//! header, rather than deeper in the loader. The most likely mistake is handing
//! it a distro `vmlinuz`, which on arm64 is a *gzip stream*, not an image — and
//! `linux-loader`'s error for that is `InvalidImageMagicNumber`, which sends you
//! looking for a corrupt file instead of a `gunzip`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use crate::kernelimage;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use arch::DeviceType;
use hypervisor::hvf::virtio::mmio::VIRTIO_MMIO_SIZE;
use arch::NumaNodes;
use arch::aarch64::fdt::DeviceInfoForFdt;
use arch::aarch64::fdt::create_fdt;
use arch::aarch64::fdt::write_fdt_to_memory;
use std::fmt;

use arch::InitramfsConfig;
use arch::aarch64::layout;
use hypervisor::arch::aarch64::gic::Vgic;
use hypervisor::hvf::coldgic::ColdBootGic;
use linux_loader::loader::KernelLoader;
use linux_loader::loader::pe::PE;
use vm_memory::GuestAddress;
use vm_memory::Bytes;
use vm_memory::bitmap::AtomicBitmap;

/// Guest memory type used throughout: matches what `arch`'s FDT writer and
/// `linux-loader` expect, so neither needs an adapter.
pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

/// Offset of the arm64 image magic within the 64-byte kernel header.
///
/// Documented in `Documentation/arch/arm64/booting.rst`. The four bytes are
/// `ARM\x64`; everything before them is a small PE/COFF stub so the same file
/// can also be an EFI application.
/// One definition, in [`crate::kernelimage`], which is where the decoding that
/// depends on it lives. Two copies of "what an arm64 kernel looks like" is the
/// drift that let this file and `oci::image` refuse the same kernel for two
/// different wrong reasons (#220).
#[cfg(test)]
use kernelimage::{ARM64_MAGIC, ARM64_MAGIC_OFFSET};

/// The alignment upstream loads an arm64 kernel at.
///
/// The boot protocol asks for 2 MiB so the kernel can use block mappings for
/// its own linear map from the first instruction.
const KERNEL_ALIGNMENT: u64 = 0x20_0000;

/// PL011 interrupt, as an absolute SPI number.
///
/// `create_serial_node` subtracts `IRQ_BASE` before writing the device tree, so
/// this is the number the *interrupt controller* uses, and the tree ends up
/// with the SPI-relative one. Matches upstream's `AARCH64_UART_IRQ` + `IRQ_BASE`
/// and, more importantly, matches what our own PL011 asserts.
pub const PL011_IRQ: u32 = 33;

/// Size of the PL011 MMIO window. Matches `imp::PL011_SIZE`, which is what the
/// bus actually registers; a test below holds the two together.
const PL011_SIZE: u64 = 0x1000;

/// The PL011 window size the device tree advertises.
///
/// Exposed so the runner can assert it equals the window the MMIO bus actually
/// serves, rather than the two agreeing by coincidence.
#[cfg(test)]
pub fn pl011_size() -> u64 {
    PL011_SIZE
}

/// Base of the first `virtio-mmio` window.
///
/// `MEM_32BIT_DEVICES_START` is the 512 MiB hole upstream already reserves for
/// device MMIO below RAM, so a window here collides with nothing the kernel is
/// told about — and, unlike a PCI BAR, its address is ours to pick because the
/// device tree names it.
const VIRTIO_MMIO_BASE: u64 = layout::MEM_32BIT_DEVICES_START.0;

/// Which virtio drivers a kernel carries *built in*.
///
/// Cold boot puts every device on **virtio-mmio** (`VIRTIO_MMIO_BASE`, above),
/// and an initramfs-only guest built from a container image has no
/// `/lib/modules` — a container rootfs never ships one. So a kernel that builds
/// virtio as loadable modules pairs with a container image to produce a guest
/// that boots to a shell and then has no network and no disk. `--net` is
/// accepted, the device is placed and logged, and the guest cannot see it,
/// which reads as broken networking rather than a missing driver.
///
/// A built-in driver links its `.name` string into the kernel image; a modular
/// one carries that string in its `.ko` instead. An arm64 `Image` is
/// uncompressed by definition -- that is why `check_kernel` insists on one --
/// so the strings are plainly readable. Matching is NUL-delimited so a longer
/// symbol that merely starts with the same text cannot count.
///
/// Measured across four kernels, three of which ship a `.config` giving ground
/// truth:
///
/// | kernel | `virtio-mmio` string | `CONFIG_VIRTIO_MMIO` |
/// | --- | --- | --- |
/// | Alpine 6.6 `virt` | absent | `m` |
/// | Firecracker CI 6.1 | present | `y` |
/// | Firecracker CI 5.10 | present | `y` |
/// | Ubuntu 6.8 `generic` | present | verified by booting: a NIC with no `modprobe` |
///
/// The discriminating control is inside a single binary rather than between
/// them: Alpine's `virtio-pci` string *is* present and its `CONFIG_VIRTIO_PCI`
/// *is* `y`, while the Firecracker kernels have neither. So this tracks
/// per-driver configuration, not how many strings a kernel happens to hold.
///
/// **Absence is the only thing worth reporting, and only ever as a warning.**
/// A kernel naming the driver certainly has it; a kernel that does not is very
/// likely modular but is being judged by a heuristic over a binary, and
/// refusing a boot outright on that would be a wrong answer that costs the user
/// a working guest. A warning that is occasionally unnecessary is cheap; a
/// refusal that is occasionally wrong is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioBuiltin {
    /// The transport. Without it the others cannot bind, whatever they say.
    pub mmio: bool,
    pub net: bool,
    pub blk: bool,
}

impl VirtioBuiltin {
    /// Scan an uncompressed arm64 kernel `Image` for built-in virtio drivers.
    pub fn scan(kernel: &[u8]) -> Self {
        let has = |needle: &str| {
            let mut pat = Vec::with_capacity(needle.len() + 2);
            pat.push(0u8);
            pat.extend_from_slice(needle.as_bytes());
            pat.push(0u8);
            kernel.windows(pat.len()).any(|w| w == pat)
        };
        Self {
            mmio: has("virtio-mmio"),
            net: has("virtio_net"),
            blk: has("virtio_blk"),
        }
    }

    /// The sentence to show a user, or `None` when nothing is wrong.
    ///
    /// The transport is reported on its own, because loading `virtio_net`
    /// against a kernel with no `virtio_mmio` returns success and still leaves
    /// no interface -- the driver registers onto a bus that is not there. That
    /// is the detail that turns an hour of debugging into a minute, so it is
    /// stated rather than left to be rediscovered.
    pub fn warning(&self) -> Option<String> {
        if self.mmio && self.net && self.blk {
            return None;
        }
        let mut missing = Vec::new();
        if !self.mmio {
            missing.push("virtio_mmio (the transport itself)");
        }
        if !self.net {
            missing.push("virtio_net");
        }
        if !self.blk {
            missing.push("virtio_blk");
        }
        Some(format!(
            "this kernel does not appear to have {} built in.\n    \
             Cold boot puts every device on virtio-mmio, and a container rootfs \
             ships no /lib/modules,\n    \
             so --net and --disk will be accepted and the guest will still see \
             no NIC and no disk.\n    \
             An Ubuntu `generic` arm64 kernel has these built in and is known to \
             work; Alpine's `virt` does not.\n    \
             If you must use this kernel, supply the matching modules and load \
             virtio_mmio *as well as* virtio_net.",
            missing.join(", ")
        ))
    }
}

/// `INTID` of the first virtio device. PL011 holds 33; SPIs count up from
/// `IRQ_BASE` (32), so 34 is the next free one.
/// SPI for the PL031 RTC. The guest never actually takes it -- Linux's pl031
/// driver only arms the alarm interrupt when userspace sets a wakealarm -- but
/// the FDT node requires one and an interrupt the tree does not describe is a
/// worse failure than one that is never raised.
pub const PL031_IRQ: u32 = PL011_IRQ + 1;

/// Size of the PL031 MMIO window.
pub const PL031_SIZE: u64 = 0x1000;

const VIRTIO_IRQ_BASE: u32 = PL031_IRQ + 1;

/// The most virtio devices a cold guest can have, bounding both the MMIO
/// windows and the SPIs they consume out of `COLD_NR_IRQS`.
const MAX_VIRTIO_DEVICES: usize = 8;

/// What kind of device sits in a `virtio-mmio` window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VirtioKind {
    /// `virtio-blk`, backed by a raw disk image.
    Block,
    /// `virtio-net`, backed by the userspace NAT.
    Net,
}

/// Where a virtio device was placed, so the runner can build the matching
/// device and register it on the MMIO bus at exactly the address the guest was
/// told to look.
///
/// The device tree and the bus are two independent statements about the same
/// machine, and a cold guest believes the tree. Returning the placement rather
/// than having both sides recompute it from constants is what keeps them from
/// drifting apart silently.
#[derive(Clone, Debug)]
pub struct VirtioPlacement {
    /// Which device this is.
    pub kind: VirtioKind,
    /// Zero-based index within its kind (disk 0, disk 1, ...).
    pub index: usize,
    /// Guest-physical base of the MMIO window.
    pub base: u64,
    /// Size of the window.
    pub size: u64,
    /// GIC `INTID` the device asserts (absolute, not SPI-relative).
    pub intid: u32,
    /// Backing file, for a block device.
    pub path: Option<PathBuf>,
}

/// A device as the FDT writer wants to see it.
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

/// What the caller asked for.
#[derive(Clone, Debug)]
pub struct ColdBootConfig {
    /// Path to an uncompressed arm64 `Image`.
    pub kernel: PathBuf,
    /// Optional initramfs/initrd. Without one the kernel reaches
    /// `prepare_namespace` and panics with `VFS: Unable to mount root fs`,
    /// which is the correct behaviour for a kernel with nothing to run.
    pub initramfs: Option<PathBuf>,
    /// Kernel command line. Written into `/chosen/bootargs`.
    pub cmdline: String,
    /// Number of vCPUs. vCPU 0 boots; the rest wait for PSCI `CPU_ON`.
    pub vcpus: u8,
    /// Guest RAM in MiB.
    pub memory_mib: u64,
    /// Raw disk images to attach as `virtio-blk` devices, in order. The first
    /// becomes `/dev/vda`.
    pub disks: Vec<PathBuf>,
    /// Attach a `virtio-net` NIC backed by the userspace NAT.
    pub net: bool,
}

impl Default for ColdBootConfig {
    fn default() -> Self {
        Self {
            kernel: PathBuf::new(),
            initramfs: None,
            cmdline: default_cmdline(),
            vcpus: 1,
            memory_mib: 1024,
            disks: Vec::new(),
            net: false,
        }
    }
}

/// The command line a cold guest gets unless told otherwise.
///
/// `console=ttyAMA0` because the PL011 at `LEGACY_SERIAL_MAPPED_IO_START` is
/// the only output device a cold guest has before it finds a disk, and
/// `earlycon` because without it the first ~2 seconds of boot — precisely the
/// part that tells you whether the device tree was right — is buffered and lost
/// if the kernel panics before it opens the console properly.
pub fn default_cmdline() -> String {
    "console=ttyAMA0 earlycon=pl011,0x9000000 reboot=k panic=1".to_string()
}

/// The command-line key carrying the host's wall clock into a cold guest.
///
/// Named once here because two sides have to agree on it: `create` writes it
/// and the generated init reads it back out of `/proc/cmdline`. Two spellings
/// would leave the guest silently at the epoch, which is the failure this
/// exists to prevent.
pub const EPOCH_KEY: &str = "gimbal.epoch";

/// The clock argument for a guest booting now, or `None` if the host clock is
/// itself before 1970.
///
/// # Why the guest needs telling at all
///
/// chm attaches a PL031, but a driver is the guest's half of that bargain and a
/// container rootfs ships no `/lib/modules` — Ubuntu's arm64 generic kernel
/// puts `rtc-pl031` in `linux-modules-extra`, so `/dev/rtc0` is simply absent
/// and the guest starts at the Unix epoch. Measured, not predicted.
///
/// The command line is the right channel because it is the one thing about a
/// guest that is decided at *boot*. The initramfs is written once by
/// `chm image build` and booted many times, so a time baked in there would be
/// the time the image was built.
pub fn epoch_arg(now: SystemTime) -> Option<String> {
    let secs = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!("{EPOCH_KEY}={secs}"))
}

/// The largest guest RAM a single low-memory region can hold: everything from
/// `RAM_START` (1 GiB) up to the 32-bit device window at `MEM_32BIT_RESERVED_START`
/// (0xfc00_0000), which works out at 3008 MiB.
pub const MAX_MEMORY_MIB: u64 = (layout::MEM_32BIT_RESERVED_START.0 - layout::RAM_START.0) >> 20;

/// GPT partition type GUID for "Linux filesystem data" — the type every distro
/// cloud image gives its root partition.
const GPT_LINUX_FS_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

/// Render 16 raw GPT GUID bytes as the canonical mixed-endian string.
///
/// GPT stores the first three fields little-endian and the last two big-endian,
/// so a straight hex dump of the bytes is *not* the GUID anyone else prints. Get
/// this wrong and `root=PARTUUID=` silently fails to match, which the kernel
/// reports only as an unhelpful `VFS: Unable to mount root fs`.
fn gpt_guid_to_string(raw: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);
    let mut tail = String::new();
    for b in &raw[8..16] {
        let _ = write!(tail, "{b:02x}");
    }
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        &tail[0..4],
        &tail[4..16]
    )
}

/// The unique GUID of the largest Linux-filesystem-data partition on `disk`.
///
/// Returns `None` when the disk has no GPT (a bare filesystem image, which is
/// the whole device and needs no partition selector) or has a GPT with no Linux
/// data partition (an image shaped in a way we cannot reason about — better to
/// leave the caller's fallback in place than to invent a partition number).
///
/// Reading the *type* GUID rather than trusting a partition index is what makes
/// this survive real cloud images: Ubuntu's arm64 image puts root at index 1 but
/// also carries an ESP and a `/boot`, and other distros order them differently.
fn gpt_root_partuuid(disk: &Path) -> Option<String> {
    const SECTOR: u64 = 512;
    let mut f = File::open(disk).ok()?;
    let mut header = [0u8; 92];
    f.seek(SeekFrom::Start(SECTOR)).ok()?;
    f.read_exact(&mut header).ok()?;
    if &header[0..8] != b"EFI PART" {
        return None;
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().ok()?);
    let n_entries = u32::from_le_bytes(header[80..84].try_into().ok()?);
    let entry_size = u32::from_le_bytes(header[84..88].try_into().ok()?);
    // Guard against a corrupt header turning into a multi-GB read.
    if !(128..=4096).contains(&entry_size) || n_entries > 1024 {
        return None;
    }
    f.seek(SeekFrom::Start(entries_lba.checked_mul(SECTOR)?))
        .ok()?;
    let mut entry = vec![0u8; entry_size as usize];
    let mut best: Option<(u64, String)> = None;
    for _ in 0..n_entries {
        if f.read_exact(&mut entry).is_err() {
            break;
        }
        let ty: [u8; 16] = entry[0..16].try_into().ok()?;
        if ty == [0u8; 16] {
            continue;
        }
        if gpt_guid_to_string(&ty) != GPT_LINUX_FS_DATA {
            continue;
        }
        let uniq: [u8; 16] = entry[16..32].try_into().ok()?;
        let first = u64::from_le_bytes(entry[32..40].try_into().ok()?);
        let last = u64::from_le_bytes(entry[40..48].try_into().ok()?);
        let sectors = last.saturating_sub(first);
        if best.as_ref().is_none_or(|(n, _)| sectors > *n) {
            best = Some((sectors, gpt_guid_to_string(&uniq)));
        }
    }
    best.map(|(_, guid)| guid)
}

/// The `root=` a cold guest needs when its only filesystem is a disk.
///
/// A kernel with no initramfs and no `root=` reaches `prepare_namespace` with
/// nothing to mount and panics.
///
/// **`/dev/vdaN` is not a stable name.** Ubuntu's `virtio_blk` probes
/// asynchronously, so with more than one disk attached the letters are assigned
/// in completion order, not bus order — adding a second `--disk` to a working
/// command line moved root and panicked the guest with `unknown-block(253,1)`.
/// So when the first disk carries a GPT we name the root partition by its own
/// GUID, which the kernel resolves itself with no initramfs and no ambiguity.
///
/// A bare (unpartitioned) filesystem image keeps `root=/dev/vda`: there is no
/// partition to name, and with one disk the letter is not in doubt.
///
/// Returns `None` when an initramfs was given (it *is* the root filesystem, and
/// forcing a pivot would break the common case of a self-contained initramfs)
/// or when there is no disk to point at.
pub fn implied_root_args(cfg: &ColdBootConfig) -> Option<String> {
    if cfg.initramfs.is_some() {
        return None;
    }
    let first = cfg.disks.first()?;
    match gpt_root_partuuid(first) {
        Some(guid) => Some(format!("root=PARTUUID={guid} rw")),
        None => Some("root=/dev/vda rw".to_string()),
    }
}

/// A guest image, built and resident in host memory, ready to be mapped.
pub struct ColdGuestImage {
    /// Anonymous host memory holding the whole guest physical address space
    /// from `RAM_START`. Owns the allocation; must outlive the VM mapping.
    pub mem: GuestMemoryMmap,
    /// Where vCPU 0 starts executing.
    pub entry: GuestAddress,
    /// Value for `x0`: physical address of the device tree.
    pub fdt: GuestAddress,
    /// Size of the written device tree, in bytes.
    pub fdt_len: usize,
    /// Guest-physical base of RAM.
    pub ram_base: u64,
    /// Guest RAM size in bytes.
    pub ram_size: usize,
    /// Kernel image size taken from the header (includes BSS), for reporting.
    pub kernel_image_size: u64,
    /// Bytes actually read from the kernel file, for reporting.
    pub kernel_file_size: u64,
    /// Where the initramfs landed, if there is one: `(guest address, bytes)`.
    pub initramfs_placed: Option<(u64, u64)>,
    /// Every virtio device described in the tree, with the window and `INTID`
    /// the guest will use to reach it.
    pub virtio: Vec<VirtioPlacement>,
}

/// Reports the physical layout rather than the memory: `GuestMemoryMmap` is not
/// `Debug`, and a megabyte of guest RAM is not what a failing assertion wants to
/// print anyway.
impl fmt::Debug for ColdGuestImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColdGuestImage")
            .field("entry", &format_args!("{:#x}", self.entry.0))
            .field("fdt", &format_args!("{:#x}", self.fdt.0))
            .field("fdt_len", &self.fdt_len)
            .field("ram", &format_args!("{:#x}+{:#x}", self.ram_base, self.ram_size))
            .field("kernel_image_size", &self.kernel_image_size)
            .field("initramfs_placed", &self.initramfs_placed)
            .finish()
    }
}

impl ColdGuestImage {
    /// Host pointer to the base of guest RAM.
    ///
    /// This is what gets handed to `hv_vm_map`. Returned as a raw pointer
    /// because that is the shape the hypervisor FFI takes; the allocation
    /// itself stays owned by `mem`.
    pub fn host_ptr(&self) -> *mut u8 {
        use vm_memory::GuestMemory as _;
        let region = self
            .mem
            .find_region(GuestAddress(self.ram_base))
            .expect("guest RAM region exists: it was just allocated at this address");
        region.as_ptr()
    }

    /// A human-readable summary of the physical memory map this image assumes.
    ///
    /// Printed at start because when a cold boot produces no console output at
    /// all, the address map is the first thing to check and the hardest thing
    /// to recover after the fact.
    pub fn memory_map(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "  RAM        {:#012x}..{:#012x}  ({} MiB)",
            self.ram_base,
            self.ram_base + self.ram_size as u64,
            self.ram_size >> 20
        );
        let _ = writeln!(
            s,
            "  FDT        {:#012x}..{:#012x}  ({} bytes)",
            self.fdt.0,
            self.fdt.0 + self.fdt_len as u64,
            self.fdt_len
        );
        let _ = writeln!(
            s,
            "  kernel     {:#012x}..{:#012x}  ({} MiB incl. BSS, {} MiB in file)",
            self.entry.0,
            self.entry.0 + self.kernel_image_size,
            self.kernel_image_size >> 20,
            self.kernel_file_size >> 20
        );
        let _ = write!(
            s,
            "  pl011      {:#012x}..{:#012x}  (SPI {})",
            layout::LEGACY_SERIAL_MAPPED_IO_START.0,
            layout::LEGACY_SERIAL_MAPPED_IO_START.0 + PL011_SIZE,
            PL011_IRQ
        );
        for d in &self.virtio {
            let _ = write!(
                s,
                "\n  virtio-{:<4} {:#012x}..{:#012x}  (SPI {})",
                d.kind.tag(),
                d.base,
                d.base + d.size,
                d.intid
            );
        }
        s
    }
}

/// Assign an MMIO window and an `INTID` to every virtio device the config asks
/// for, in a fixed order: disks first, then the NIC.
///
/// The order is what makes `root=/dev/vda` mean anything — Linux names virtio
/// block devices in probe order, and it probes `virtio_mmio` nodes in address
/// order.
fn place_virtio(cfg: &ColdBootConfig) -> Result<Vec<VirtioPlacement>, String> {
    let count = cfg.disks.len() + usize::from(cfg.net);
    if count > MAX_VIRTIO_DEVICES {
        return Err(format!(
            "{count} virtio devices requested but at most {MAX_VIRTIO_DEVICES} fit \
             the reserved MMIO window and SPI range"
        ));
    }
    let mut out = Vec::with_capacity(count);
    for (i, path) in cfg.disks.iter().enumerate() {
        if !path.is_file() {
            return Err(format!("disk image {} is not a file", path.display()));
        }
        out.push(VirtioPlacement {
            kind: VirtioKind::Block,
            index: i,
            base: VIRTIO_MMIO_BASE + (i as u64) * VIRTIO_MMIO_SIZE,
            size: VIRTIO_MMIO_SIZE,
            intid: VIRTIO_IRQ_BASE + i as u32,
            path: Some(path.clone()),
        });
    }
    if cfg.net {
        let i = cfg.disks.len();
        out.push(VirtioPlacement {
            kind: VirtioKind::Net,
            index: i,
            base: VIRTIO_MMIO_BASE + (i as u64) * VIRTIO_MMIO_SIZE,
            size: VIRTIO_MMIO_SIZE,
            intid: VIRTIO_IRQ_BASE + i as u32,
            path: None,
        });
    }
    Ok(out)
}

impl VirtioKind {
    /// Short name used in the device tree node label and in diagnostics.
    fn tag(self) -> &'static str {
        match self {
            VirtioKind::Block => "blk",
            VirtioKind::Net => "net",
        }
    }
}

/// Read the kernel, unwrapping whatever the distro wrapped it in, and report
/// `(image, image_size, text_offset)`.
///
/// The bytes come back rather than a path, because after unwrapping there may
/// be no file holding them. Writing a decompressed kernel to a temp file would
/// need somewhere to put it, a cleanup owner and a failure mode when the disk
/// is full — for a 34 MiB buffer that is already being read into RAM to be
/// copied into guest RAM.
///
/// Refusals name what the file actually is; see [`crate::kernelimage`] for why
/// that matters more than it sounds (#220).
fn read_kernel_image(path: &Path) -> Result<(Vec<u8>, u64, u64), String> {
    let raw = fs::read(path).map_err(|e| format!("opening kernel {}: {e}", path.display()))?;
    let label = path.display().to_string();
    let (image, form) = kernelimage::decode(&raw, &label)?;
    let image = image.into_owned();

    if form.was_compressed() {
        // Said out loud because the kernel that boots is not the file that was
        // named, and a `uname -r` that surprises someone should have an
        // explanation earlier in the same transcript.
        println!("chm: kernel {} — {}", path.display(), form.describe());
    }

    // `decode` has already checked the magic, so a short read here would be a
    // bug in this crate rather than a bad file.
    if image.len() < 64 {
        return Err(format!(
            "{} decoded to {} bytes, too short for an arm64 header",
            path.display(),
            image.len()
        ));
    }

    let text_offset = u64::from_le_bytes(image[8..16].try_into().expect("8 bytes"));
    let image_size = u64::from_le_bytes(image[16..24].try_into().expect("8 bytes"));
    Ok((image, image_size, text_offset))
}

/// Build a cold guest image: allocate RAM, load the kernel, write the tree.
///
/// The result is a byte-exact picture of what guest RAM must contain at the
/// instant vCPU 0 starts. Nothing here touches the hypervisor, which is why it
/// is testable without an entitlement or a VM slot.
pub fn build(cfg: &ColdBootConfig) -> Result<ColdGuestImage, String> {
    if cfg.vcpus == 0 {
        return Err("a guest needs at least one vCPU".to_string());
    }
    if cfg.memory_mib == 0 {
        return Err("a guest needs some RAM".to_string());
    }

    // Guest RAM starts at 1 GiB and the window from `MEM_32BIT_RESERVED_START`
    // to 4 GiB is reserved for 32-bit device BARs, so a single contiguous region
    // cannot cross it. Upstream's FDT generator supports a second region above
    // 4 GiB, but this cold-boot path builds one; asking for more than the gap
    // allows would otherwise `panic!` deep inside `arch`'s FDT writer with a raw
    // address dump, which is not a usable answer to "why won't my VM start".
    if cfg.memory_mib > MAX_MEMORY_MIB {
        return Err(format!(
            "{} MiB of RAM does not fit below the 32-bit device window: guest RAM \
             starts at {:#x} and a single region must end by {:#x}. The most this \
             cold-boot path can give a guest is {MAX_MEMORY_MIB} MiB.",
            cfg.memory_mib,
            layout::RAM_START.0,
            layout::MEM_32BIT_RESERVED_START.0
        ));
    }

    let (kernel_image, image_size, text_offset) = read_kernel_image(&cfg.kernel)?;
    let ram_size = (cfg.memory_mib << 20) as usize;
    let ram_base = layout::RAM_START.0;

    // The kernel lands after the reserved FDT and ACPI windows, rounded up to
    // the 2 MiB the boot protocol asks for. `text_offset` is honoured on top of
    // that; modern kernels set it to 0 and declare "load me anywhere", but it
    // is part of the contract and older images do use it.
    let kernel_addr = layout::KERNEL_START.0.div_ceil(KERNEL_ALIGNMENT) * KERNEL_ALIGNMENT
        + text_offset;

    // `image_size` covers BSS, which is not in the file. If it does not fit,
    // the kernel will fault clearing memory it was promised, so refuse now
    // rather than watch a guest die silently with no console.
    let kernel_end = kernel_addr + image_size;
    let ram_end = ram_base + ram_size as u64;
    if kernel_end > ram_end {
        return Err(format!(
            "kernel needs {:#x} bytes at {kernel_addr:#x} (ends {kernel_end:#x}) \
             but RAM ends at {ram_end:#x}; give the guest at least {} MiB",
            image_size,
            (kernel_end - ram_base).div_ceil(1 << 20)
        ));
    }

    let mem = GuestMemoryMmap::from_ranges(&[(layout::RAM_START, ram_size)])
        .map_err(|e| format!("allocating {} MiB of guest RAM: {e}", cfg.memory_mib))?;

    let kernel_file_size = kernel_image.len() as u64;
    let mut kernel_reader = Cursor::new(kernel_image);

    let loaded = PE::load(
        &mem,
        Some(GuestAddress(kernel_addr)),
        &mut kernel_reader,
        None,
    )
    .map_err(|e| format!("loading {} at {kernel_addr:#x}: {e}", cfg.kernel.display()))?;
    let entry = loaded.kernel_load;

    // --- the initramfs -----------------------------------------------------
    //
    // Placed at the TOP of RAM rather than just after the kernel. The kernel
    // reserves its own image plus BSS and then frees the initrd once it has
    // unpacked it, so anywhere in RAM works architecturally — but sitting it
    // high keeps it clear of the kernel's `image_size` (which covers BSS not
    // present in the file, so "just after the file" would be inside the
    // kernel's own memory). Aligned down to a page so the guest's early
    // `memblock_reserve` covers whole pages.
    let initramfs_placed = match &cfg.initramfs {
        None => None,
        Some(path) => {
            let mut f = File::open(path)
                .map_err(|e| format!("opening initramfs {}: {e}", path.display()))?;
            let size = f
                .seek(SeekFrom::End(0))
                .map_err(|e| format!("sizing initramfs {}: {e}", path.display()))?;
            f.seek(SeekFrom::Start(0))
                .map_err(|e| format!("rewinding initramfs {}: {e}", path.display()))?;
            let addr = (ram_end - size) & !0xfff_u64;
            if addr < kernel_end {
                return Err(format!(
                    "initramfs is {} MiB and the kernel ends at {kernel_end:#x}, so it \
                     would not fit below the {} MiB of RAM; give the guest more memory",
                    size.div_ceil(1 << 20),
                    cfg.memory_mib
                ));
            }
            mem.read_exact_volatile_from(GuestAddress(addr), &mut f, size as usize)
                .map_err(|e| format!("loading initramfs {}: {e}", path.display()))?;
            Some((addr, size))
        }
    };
    let initramfs_cfg = initramfs_placed.map(|(addr, size)| InitramfsConfig {
        address: GuestAddress(addr),
        size: size as usize,
    });

    // --- the device tree ---------------------------------------------------
    //
    // The GIC description is `ColdBootGic`, which reports the canonical arm64
    // window rather than the relocated one the managed GIC forces on the
    // rehydrate path. See `hypervisor::hvf::coldgic`.
    let cold_gic = ColdBootGic::new(u64::from(cfg.vcpus)).ok_or_else(|| {
        format!(
            "{} vCPUs do not fit the arm64 GIC window: their redistributors would \
             run below the reserved firmware region",
            cfg.vcpus
        )
    })?;
    let gic: Arc<Mutex<dyn Vgic>> = Arc::new(Mutex::new(cold_gic));

    let mut device_info: HashMap<(DeviceType, String), FdtDevice> = HashMap::new();
    device_info.insert(
        (DeviceType::Serial, DeviceType::Serial.to_string()),
        FdtDevice {
            addr: layout::LEGACY_SERIAL_MAPPED_IO_START.0,
            irq: PL011_IRQ,
            len: PL011_SIZE,
        },
    );

    // A cold guest has no snapshot to inherit a wall clock from, so without
    // this it boots believing it is whenever the kernel was built. Every TLS
    // handshake then rejects certificates as "not yet valid", which presents as
    // a network fault and is not one. See `Pl031`.
    device_info.insert(
        (DeviceType::Rtc, DeviceType::Rtc.to_string()),
        FdtDevice {
            addr: layout::LEGACY_RTC_MAPPED_IO_START.0,
            irq: PL031_IRQ,
            len: PL031_SIZE,
        },
    );

    let virtio = place_virtio(cfg)?;
    for dev in &virtio {
        // `create_virtio_node` writes `dev_info.irq()` into the tree verbatim,
        // where `create_serial_node` subtracts `IRQ_BASE` first. So the FDT
        // wants the SPI-*relative* number here, while `intid` stays absolute
        // because that is what the interrupt controller is asked for.
        device_info.insert(
            (
                DeviceType::Virtio(dev.index as u32),
                format!("virtio-{}-{}", dev.kind.tag(), dev.index),
            ),
            FdtDevice {
                addr: dev.base,
                irq: dev.intid - layout::IRQ_BASE,
                len: dev.size,
            },
        );
    }

    // MPIDR_EL1 affinity for each vCPU. Bit 31 (`MPIDR_EL1.U`... actually the
    // RES1 bit) is set on every real arm64 CPU and Linux checks for it, so the
    // tree must carry it: the `reg` property of each `/cpus/cpu@N` node is
    // matched against the MPIDR the CPU actually reads, and `setup_regs`
    // programs the same `0x8000_0000 | id`.
    let mpidrs: Vec<u64> = (0..u64::from(cfg.vcpus))
        .map(|i| 0x8000_0000_u64 | i)
        .collect();

    let fdt_bytes = create_fdt(
        &mem,
        &cfg.cmdline,
        &mpidrs,
        None,
        &device_info,
        &gic,
        &initramfs_cfg,
        &[],
        &NumaNodes::default(),
        None,
        false,
    )
    .map_err(|e| format!("building the device tree: {e:?}"))?;

    if fdt_bytes.len() as u64 > layout::FDT_MAX_SIZE {
        return Err(format!(
            "device tree is {} bytes, which does not fit the {} byte window at {:#x}",
            fdt_bytes.len(),
            layout::FDT_MAX_SIZE,
            layout::FDT_START.0
        ));
    }
    write_fdt_to_memory(&fdt_bytes, &mem).map_err(|e| format!("writing the device tree: {e:?}"))?;

    Ok(ColdGuestImage {
        mem,
        entry,
        fdt: layout::FDT_START,
        fdt_len: fdt_bytes.len(),
        ram_base,
        ram_size,
        kernel_image_size: image_size,
        kernel_file_size,
        initramfs_placed,
        virtio,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a file with a valid arm64 header and `body_len` bytes of payload.
    fn fake_image(dir: &Path, name: &str, image_size: u64, text_offset: u64, body_len: usize) -> PathBuf {
        let mut hdr = [0_u8; 64];
        // MZ, so the PE loader recognises it the way a real Image is recognised.
        hdr[0] = b'M';
        hdr[1] = b'Z';
        hdr[8..16].copy_from_slice(&text_offset.to_le_bytes());
        hdr[16..24].copy_from_slice(&image_size.to_le_bytes());
        hdr[ARM64_MAGIC_OFFSET as usize..ARM64_MAGIC_OFFSET as usize + 4]
            .copy_from_slice(&ARM64_MAGIC);
        let p = dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(&hdr).unwrap();
        f.write_all(&vec![0_u8; body_len]).unwrap();
        p
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "chm-coldboot-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The header is read from the *decoded* image, so a wrapped kernel's
    /// header is the inner kernel's header and not the wrapper's. Getting this
    /// wrong would size guest RAM against a compressed payload and place the
    /// kernel somewhere it does not belong.
    #[test]
    fn a_wrapped_kernels_header_is_read_from_the_kernel_inside_it() {
        let d = tmpdir("gzip");
        let inner = std::fs::read(fake_image(&d, "inner", 0x0387_0000, 0, 4096)).unwrap();
        let mut enc =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&inner).unwrap();
        let p = d.join("vmlinuz");
        std::fs::write(&p, enc.finish().unwrap()).unwrap();

        let (image, image_size, text_offset) = read_kernel_image(&p).unwrap();
        assert_eq!(image_size, 0x0387_0000);
        assert_eq!(text_offset, 0);
        assert_eq!(image, inner);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_file_too_short_to_hold_a_header_says_so() {
        let d = tmpdir("short");
        let p = d.join("tiny");
        File::create(&p).unwrap().write_all(b"nope").unwrap();
        let err = read_kernel_image(&p).unwrap_err();
        assert!(err.contains("too small"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_header_is_read_not_guessed() {
        let d = tmpdir("hdr");
        let p = fake_image(&d, "Image", 0x0387_0000, 0, 4096);
        let (_, image_size, text_offset) = read_kernel_image(&p).unwrap();
        assert_eq!(image_size, 0x0387_0000);
        assert_eq!(text_offset, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_kernel_that_does_not_fit_is_refused_before_the_guest_dies_silently() {
        let d = tmpdir("toobig");
        // Declare 4 GiB of image (mostly BSS) but hand over a small file.
        let p = fake_image(&d, "Image", 4 << 30, 0, 4096);
        let cfg = ColdBootConfig {
            kernel: p,
            memory_mib: 256,
            ..ColdBootConfig::default()
        };
        let err = build(&cfg).unwrap_err();
        assert!(err.contains("but RAM ends at"), "{err}");
        // It must say how much RAM would be enough, not just that it failed.
        assert!(err.contains("at least"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zero_vcpus_and_zero_ram_are_refused() {
        let cfg = ColdBootConfig {
            vcpus: 0,
            ..ColdBootConfig::default()
        };
        assert!(build(&cfg).unwrap_err().contains("at least one vCPU"));
        let cfg = ColdBootConfig {
            memory_mib: 0,
            ..ColdBootConfig::default()
        };
        assert!(build(&cfg).unwrap_err().contains("some RAM"));
    }

    #[test]
    fn the_default_cmdline_names_the_console_a_cold_guest_actually_has() {
        let c = default_cmdline();
        assert!(c.contains("console=ttyAMA0"), "{c}");
        // earlycon must point at the same PL011 the device tree describes, or
        // the earliest output — the part that proves the tree was right — is lost.
        assert!(
            c.contains(&format!(
                "earlycon=pl011,{:#x}",
                layout::LEGACY_SERIAL_MAPPED_IO_START.0
            )),
            "{c}"
        );
    }

    #[test]
    fn the_kernel_load_address_clears_the_fdt_and_acpi_windows() {
        let aligned =
            layout::KERNEL_START.0.div_ceil(KERNEL_ALIGNMENT) * KERNEL_ALIGNMENT;
        assert!(
            aligned >= layout::FDT_START.0 + layout::FDT_MAX_SIZE,
            "kernel at {aligned:#x} would overwrite the device tree window"
        );
        assert!(aligned.is_multiple_of(KERNEL_ALIGNMENT));
    }

    /// A synthetic arm64 `Image`: a valid 64-byte header declaring `image_size`
    /// (the kernel's in-memory footprint, BSS included) followed by that many
    /// bytes of payload. Deterministic, so these tests do not depend on a real
    /// kernel being downloaded to this machine.
    /// Write a synthetic kernel with a valid arm64 header.
    ///
    /// The path is unique per call. Three tests ask for the same `image_size`,
    /// and `fs::write` truncates before it writes — so a shared path lets one
    /// test read a zero-length header out from under another. That is a race
    /// the test harness creates, not one the code under test has.
    fn synthetic_kernel(image_size: u64) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "chm-coldboot-synth-{image_size:#x}-{}-{n}.Image",
            std::process::id()
        ));
        let mut img = vec![0u8; image_size as usize];
        // text_offset at 0x08, image_size at 0x10, flags at 0x18 (LE, 4K, 2MB),
        // magic at 0x38. Matches Documentation/arch/arm64/booting.rst.
        img[0x10..0x18].copy_from_slice(&image_size.to_le_bytes());
        img[0x18..0x20].copy_from_slice(&0xa_u64.to_le_bytes());
        let m = ARM64_MAGIC_OFFSET as usize;
        img[m..m + 4].copy_from_slice(&ARM64_MAGIC);
        std::fs::write(&p, &img).expect("writing a synthetic kernel");
        p
    }

    /// An initramfs must land above the kernel and below the top of RAM, and
    /// the tree must carry the range — `linux,initrd-start`/`-end` in /chosen
    /// is the only way the kernel learns it is there.
    #[test]
    fn an_initramfs_is_placed_above_the_kernel_and_inside_ram() {
        let kernel = synthetic_kernel(8 << 20);
        let mut initrd = std::env::temp_dir();
        initrd.push("chm-coldboot-initrd-placement.bin");
        std::fs::write(&initrd, vec![0x5au8; 3 << 20]).expect("writing a fake initramfs");

        let cfg = ColdBootConfig {
            kernel,
            initramfs: Some(initrd.clone()),
            memory_mib: 512,
            ..Default::default()
        };
        let img = build(&cfg).expect("building with an initramfs");
        let (addr, size) = img.initramfs_placed.expect("initramfs must be placed");
        assert_eq!(size, 3 << 20);
        assert!(
            addr >= img.entry.0 + img.kernel_image_size,
            "initramfs at {addr:#x} overlaps the kernel image"
        );
        assert!(
            addr + size <= img.ram_base + img.ram_size as u64,
            "initramfs at {addr:#x}+{size:#x} runs past the top of RAM"
        );
        assert_eq!(addr & 0xfff, 0, "initramfs must be page-aligned");
        let _ = std::fs::remove_file(&initrd);
    }

    /// Without one, `initramfs_placed` stays `None` and the kernel is left to
    /// panic at `VFS: Unable to mount root fs` — which is correct, not a bug.
    #[test]
    fn no_initramfs_means_no_placement() {
        let kernel = synthetic_kernel(8 << 20);
        let cfg = ColdBootConfig {
            kernel,
            memory_mib: 512,
            ..Default::default()
        };
        assert!(build(&cfg).expect("building").initramfs_placed.is_none());
    }

    /// An initramfs that cannot fit below the top of RAM must be refused by
    /// name, with the fix in the message, rather than silently truncated.
    #[test]
    fn an_oversized_initramfs_is_refused_with_advice() {
        let kernel = synthetic_kernel(8 << 20);
        let mut initrd = std::env::temp_dir();
        initrd.push("chm-coldboot-initrd-oversize.bin");
        std::fs::write(&initrd, vec![0u8; 200 << 20]).expect("writing a fake initramfs");
        let cfg = ColdBootConfig {
            kernel,
            initramfs: Some(initrd.clone()),
            memory_mib: 128,
            ..Default::default()
        };
        let e = build(&cfg).unwrap_err();
        assert!(
            e.contains("initramfs") && e.contains("more memory"),
            "error must name the file and the fix: {e}"
        );
        let _ = std::fs::remove_file(&initrd);
    }

    /// Create `n` empty files to stand in for disk images.
    fn fake_disks(dir: &Path, n: usize) -> Vec<PathBuf> {
        (0..n)
            .map(|i| {
                let p = dir.join(format!("d{i}.img"));
                File::create(&p).unwrap().write_all(&[0_u8; 512]).unwrap();
                p
            })
            .collect()
    }

    #[test]
    fn disks_are_placed_before_the_nic_so_the_first_disk_is_vda() {
        let d = tmpdir("order");
        let cfg = ColdBootConfig {
            disks: fake_disks(&d, 2),
            net: true,
            ..Default::default()
        };
        let p = place_virtio(&cfg).unwrap();
        assert_eq!(p.len(), 3);
        // Linux probes virtio_mmio nodes in address order and names blocks in
        // probe order, so a NIC placed first would rename /dev/vda to /dev/vdb.
        assert_eq!(p[0].kind, VirtioKind::Block);
        assert_eq!(p[1].kind, VirtioKind::Block);
        assert_eq!(p[2].kind, VirtioKind::Net);
        assert!(p[0].base < p[1].base && p[1].base < p[2].base);
    }

    #[test]
    fn placements_are_consecutive_and_do_not_overlap() {
        let d = tmpdir("layout");
        let cfg = ColdBootConfig {
            disks: fake_disks(&d, 3),
            net: true,
            ..Default::default()
        };
        let p = place_virtio(&cfg).unwrap();
        for (i, e) in p.iter().enumerate() {
            assert_eq!(e.base, VIRTIO_MMIO_BASE + i as u64 * VIRTIO_MMIO_SIZE);
            assert_eq!(e.size, VIRTIO_MMIO_SIZE);
            // The FDT and the MMIO bus are handed the same numbers; an INTID
            // collision here is silent and only shows up as a wedged guest.
            assert_eq!(e.intid, VIRTIO_IRQ_BASE + i as u32);
        }
        assert!(
            VIRTIO_IRQ_BASE > PL011_IRQ,
            "virtio SPIs must not collide with the PL011"
        );
        let last = p.last().unwrap();
        assert!(
            last.base + last.size <= super::layout::MEM_32BIT_DEVICES_START.0
                + super::layout::MEM_32BIT_DEVICES_SIZE,
            "virtio windows must stay inside the 32-bit device hole"
        );
    }

    #[test]
    fn too_many_virtio_devices_is_refused_rather_than_silently_truncated() {
        let d = tmpdir("toomany");
        let cfg = ColdBootConfig {
            disks: fake_disks(&d, MAX_VIRTIO_DEVICES),
            net: true,
            ..Default::default()
        };
        let e = place_virtio(&cfg).unwrap_err();
        assert!(
            e.contains(&MAX_VIRTIO_DEVICES.to_string()),
            "error must say the limit: {e}"
        );
    }

    #[test]
    fn a_missing_disk_image_is_refused_before_the_guest_starts() {
        let cfg = ColdBootConfig {
            disks: vec![PathBuf::from("/nonexistent/nope.img")],
            ..Default::default()
        };
        let e = place_virtio(&cfg).unwrap_err();
        assert!(e.contains("nope.img"), "error must name the file: {e}");
    }

    #[test]
    fn root_is_implied_only_when_a_disk_is_the_only_filesystem() {
        let d = tmpdir("root");
        let disks = fake_disks(&d, 1);
        // Disk, no initramfs: the kernel has nothing to mount without root=.
        let with_disk = ColdBootConfig {
            disks: disks.clone(),
            ..Default::default()
        };
        assert_eq!(
            implied_root_args(&with_disk).as_deref(),
            Some("root=/dev/vda rw")
        );
        // An initramfs IS the root filesystem; forcing a pivot would break it.
        let with_both = ColdBootConfig {
            disks,
            initramfs: Some(d.join("initrd")),
            ..Default::default()
        };
        assert_eq!(implied_root_args(&with_both), None);
        // Nothing to point root= at.
        assert_eq!(implied_root_args(&ColdBootConfig::default()), None);
    }

    /// Build a minimal but structurally real GPT: protective MBR, header at
    /// LBA 1, entry array at LBA 2. `parts` is `(type guid, unique guid, first
    /// lba, last lba)`.
    fn synth_gpt(parts: &[(&str, &str, u64, u64)]) -> Vec<u8> {
        fn guid_bytes(s: &str) -> [u8; 16] {
            let hex: Vec<u8> = s
                .chars()
                .filter(|c| *c != '-')
                .collect::<Vec<_>>()
                .chunks(2)
                .map(|c| u8::from_str_radix(&c.iter().collect::<String>(), 16).unwrap())
                .collect();
            let mut out = [0u8; 16];
            out[0..4].copy_from_slice(&u32::from_str_radix(&s[0..8], 16).unwrap().to_le_bytes());
            out[4..6].copy_from_slice(&u16::from_str_radix(&s[9..13], 16).unwrap().to_le_bytes());
            out[6..8].copy_from_slice(&u16::from_str_radix(&s[14..18], 16).unwrap().to_le_bytes());
            out[8..16].copy_from_slice(&hex[8..16]);
            out
        }
        let mut d = vec![0u8; 512 * 34];
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        d[512 + 80..512 + 84].copy_from_slice(&(parts.len() as u32).to_le_bytes());
        d[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        for (i, (ty, uniq, first, last)) in parts.iter().enumerate() {
            let off = 512 * 2 + i * 128;
            d[off..off + 16].copy_from_slice(&guid_bytes(ty));
            d[off + 16..off + 32].copy_from_slice(&guid_bytes(uniq));
            d[off + 32..off + 40].copy_from_slice(&first.to_le_bytes());
            d[off + 40..off + 48].copy_from_slice(&last.to_le_bytes());
        }
        d
    }

    #[test]
    fn gpt_guid_round_trips_mixed_endian() {
        // The byte order is the whole point: the first three fields are little
        // endian on disk, the last two big endian. A straight hex dump would
        // render this as 5e89825e-9c9a-0e46-... and never match.
        let raw = [
            0x5e, 0x89, 0x82, 0x5e, 0x9c, 0x9a, 0x0e, 0x46, 0x9a, 0x0f, 0x96, 0xa5, 0xe8, 0xf3,
            0x95, 0x24,
        ];
        assert_eq!(
            gpt_guid_to_string(&raw),
            "5e82895e-9a9c-460e-9a0f-96a5e8f39524"
        );
    }

    #[test]
    fn gpt_root_picks_the_largest_linux_partition() {
        let dir = std::env::temp_dir().join(format!("chm-gpt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("gpt.raw");
        // An Ubuntu-shaped image: root first, then an ESP and a /boot, both of
        // which a naive "first partition" or "largest partition" rule could
        // pick. Only the type GUID distinguishes them.
        std::fs::write(
            &img,
            synth_gpt(&[
                (
                    "0fc63daf-8483-4772-8e79-3d69d8477de4",
                    "11111111-2222-3333-4444-555555555555",
                    227328,
                    16777182,
                ),
                (
                    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    2048,
                    227327,
                ),
                (
                    "bc13c2ff-59e6-4262-a352-b275fd6f7172",
                    "99999999-8888-7777-6666-555555555555",
                    1024,
                    2047,
                ),
            ]),
        )
        .unwrap();
        assert_eq!(
            gpt_root_partuuid(&img).as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );

        let cfg = ColdBootConfig {
            disks: vec![img.clone()],
            ..Default::default()
        };
        assert_eq!(
            implied_root_args(&cfg).as_deref(),
            Some("root=PARTUUID=11111111-2222-3333-4444-555555555555 rw")
        );

        // A GPT with no Linux data partition tells us nothing, so the caller's
        // whole-disk fallback stands rather than us inventing a partition index.
        let esp_only = dir.join("esponly.raw");
        std::fs::write(
            &esp_only,
            synth_gpt(&[(
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                2048,
                227327,
            )]),
        )
        .unwrap();
        assert_eq!(gpt_root_partuuid(&esp_only), None);

        // A bare filesystem image has no GPT signature and stays /dev/vda.
        let bare = dir.join("bare.raw");
        std::fs::write(&bare, vec![0u8; 512 * 34]).unwrap();
        assert_eq!(gpt_root_partuuid(&bare), None);
        let cfg = ColdBootConfig {
            disks: vec![bare],
            ..Default::default()
        };
        assert_eq!(implied_root_args(&cfg).as_deref(), Some("root=/dev/vda rw"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ground truth, from kernels that ship their own `.config`.
    ///
    /// The fixtures are the smallest slices that carry the signal rather than
    /// whole kernels: a real `Image` is 16-58 MiB and none of them belong in
    /// git. What is reproduced faithfully is the *shape* -- NUL-delimited C
    /// strings in a blob of unrelated bytes -- because that is what `scan`
    /// depends on.
    fn kernel_like(names: &[&str]) -> Vec<u8> {
        let mut v = vec![0x5au8; 512];
        for n in names {
            v.push(0);
            v.extend_from_slice(n.as_bytes());
            v.push(0);
            v.extend_from_slice(&[0x17; 64]);
        }
        v
    }

    #[test]
    fn a_modular_kernel_is_reported_as_missing_every_driver() {
        // Alpine 6.6 `virt`: CONFIG_VIRTIO_MMIO/NET/BLK=m, CONFIG_VIRTIO_PCI=y.
        // Measured on the real Image: the three module strings are absent and
        // `virtio-pci` is present, which is why the scan is per-driver rather
        // than "does this kernel mention virtio".
        let k = kernel_like(&["virtio-pci", "virtio", "virtio,mmio"]);
        let v = VirtioBuiltin::scan(&k);
        assert!(!v.mmio && !v.net && !v.blk);
        let w = v.warning().expect("a modular kernel must warn");
        assert!(w.contains("virtio_mmio (the transport itself)"), "{w}");
        assert!(w.contains("virtio_net") && w.contains("virtio_blk"), "{w}");
    }

    #[test]
    fn a_builtin_kernel_is_silent() {
        // Firecracker CI 6.1.128 and 5.10.233: MMIO/NET/BLK all `y`, and no
        // CONFIG_VIRTIO_PCI at all.
        let k = kernel_like(&["virtio-mmio", "virtio_net", "virtio_blk"]);
        let v = VirtioBuiltin::scan(&k);
        assert!(v.mmio && v.net && v.blk);
        assert!(
            v.warning().is_none(),
            "a working kernel must not be warned about"
        );
    }

    /// The transport is the one that decides, and it fails silently: loading
    /// `virtio_net` against a kernel with no `virtio_mmio` returns success and
    /// still leaves no interface. A kernel carrying the device drivers but not
    /// the bus must therefore still warn, and must name the bus.
    #[test]
    fn drivers_without_their_transport_still_warn() {
        let k = kernel_like(&["virtio_net", "virtio_blk"]);
        let v = VirtioBuiltin::scan(&k);
        assert!(!v.mmio && v.net && v.blk);
        let w = v.warning().expect("no transport must warn");
        assert!(w.contains("virtio_mmio (the transport itself)"), "{w}");
        assert!(
            !w.contains(", virtio_net"),
            "must not blame a driver that is present: {w}"
        );
    }

    /// Matching is NUL-delimited, so a longer symbol beginning with the same
    /// text is not the driver. Without this, `virtio_net_hdr` or a kernel
    /// parameter like `virtio_net.napi_tx` -- which really is present in the
    /// Firecracker kernels -- would be read as the driver being built in and a
    /// broken pairing would be reported as fine.
    #[test]
    fn a_longer_symbol_is_not_the_driver() {
        let k = kernel_like(&["virtio_net.napi_tx", "virtio-mmio-cmdline"]);
        let v = VirtioBuiltin::scan(&k);
        assert!(!v.net, "`virtio_net.napi_tx` is not `virtio_net`");
        assert!(!v.mmio, "`virtio-mmio-cmdline` is not `virtio-mmio`");
    }
}
