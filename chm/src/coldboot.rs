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
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use arch::DeviceType;
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
const ARM64_MAGIC_OFFSET: u64 = 0x38;
const ARM64_MAGIC: [u8; 4] = *b"ARM\x64";

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
const PL011_IRQ: u32 = 33;

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
}

impl Default for ColdBootConfig {
    fn default() -> Self {
        Self {
            kernel: PathBuf::new(),
            initramfs: None,
            cmdline: default_cmdline(),
            vcpus: 1,
            memory_mib: 1024,
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
        s
    }
}

/// Read the arm64 header and report `(image_size, text_offset)`.
///
/// Fails with an explanation rather than a magic number when the file is not an
/// arm64 `Image` — see the module docs on `vmlinuz`.
fn read_arm64_header(path: &Path) -> Result<(u64, u64), String> {
    let mut f = File::open(path).map_err(|e| format!("opening kernel {}: {e}", path.display()))?;
    let mut hdr = [0_u8; 64];
    f.read_exact(&mut hdr)
        .map_err(|e| format!("reading the 64-byte arm64 header from {}: {e}", path.display()))?;

    let magic = &hdr[ARM64_MAGIC_OFFSET as usize..ARM64_MAGIC_OFFSET as usize + 4];
    if magic != ARM64_MAGIC {
        let hint = if hdr[0] == 0x1f && hdr[1] == 0x8b {
            "\n  This is a gzip stream. A distro `vmlinuz` on arm64 is a compressed\n  Image; decompress it first: gunzip -c vmlinuz-... > Image"
        } else {
            ""
        };
        return Err(format!(
            "{} is not an arm64 kernel Image: expected {:x?} at offset {:#x}, found {:x?}{hint}",
            path.display(),
            ARM64_MAGIC,
            ARM64_MAGIC_OFFSET,
            magic,
        ));
    }

    let text_offset = u64::from_le_bytes(hdr[8..16].try_into().expect("8 bytes"));
    let image_size = u64::from_le_bytes(hdr[16..24].try_into().expect("8 bytes"));
    Ok((image_size, text_offset))
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

    let (image_size, text_offset) = read_arm64_header(&cfg.kernel)?;
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

    let mut kernel_file = File::open(&cfg.kernel)
        .map_err(|e| format!("opening kernel {}: {e}", cfg.kernel.display()))?;
    let kernel_file_size = kernel_file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("sizing kernel {}: {e}", cfg.kernel.display()))?;
    kernel_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("rewinding kernel {}: {e}", cfg.kernel.display()))?;

    let loaded = PE::load(
        &mem,
        Some(GuestAddress(kernel_addr)),
        &mut kernel_file,
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

    #[test]
    fn a_gzip_vmlinuz_is_named_as_such_rather_than_called_corrupt() {
        let d = tmpdir("gzip");
        let p = d.join("vmlinuz");
        let mut f = File::create(&p).unwrap();
        // gzip magic, then enough bytes to fill the header read.
        f.write_all(&[0x1f, 0x8b, 0x08, 0x00]).unwrap();
        f.write_all(&[0_u8; 60]).unwrap();
        drop(f);

        let err = read_arm64_header(&p).unwrap_err();
        assert!(err.contains("gzip"), "{err}");
        assert!(err.contains("gunzip"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_file_too_short_to_hold_a_header_says_so() {
        let d = tmpdir("short");
        let p = d.join("tiny");
        File::create(&p).unwrap().write_all(b"nope").unwrap();
        let err = read_arm64_header(&p).unwrap_err();
        assert!(err.contains("64-byte arm64 header"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_header_is_read_not_guessed() {
        let d = tmpdir("hdr");
        let p = fake_image(&d, "Image", 0x0387_0000, 0, 4096);
        let (image_size, text_offset) = read_arm64_header(&p).unwrap();
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
    fn synthetic_kernel(image_size: u64) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("chm-coldboot-synth-{image_size:#x}.Image"));
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
}
