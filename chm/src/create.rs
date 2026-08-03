//! `chm create` — start a guest from a kernel image, with no capture involved.
//!
//! [`super::coldboot`] builds the guest's memory image; this drives it on
//! Hypervisor.framework. The two are separate because the first is pure and
//! testable without an entitlement or the process-global VM slot, and the
//! second is neither.
//!
//! ## Why the userspace GIC, on a path with no snapshot to be compatible with
//!
//! Cold boot could in principle use Apple's managed GIC: there is no captured
//! interrupt state to restore, which is the constraint that forced the
//! userspace GIC on the rehydrate path. It uses the userspace GIC anyway, for
//! two reasons that are about the guest rather than about us.
//!
//! The first is that `hv_gic_create` fixes the GIC's MMIO layout in ways the
//! device tree then has to agree with — redistributors *above* the distributor,
//! which is not the canonical arm64 arrangement (see `hvf::coldgic`). A cold
//! guest reads its layout from a tree we write, so there is no reason to accept
//! that constraint.
//!
//! The second is that the managed GIC cannot deliver LPIs to a non-nested EL1
//! guest, which is the whole reason the userspace GIC exists. A cold guest that
//! later gains virtio-pci devices would hit exactly the wall documented in
//! `routes_completions_as_lpis`. Starting on the path that works avoids
//! building a second one that does not.

use std::io::Write;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::Condvar;
use std::sync::atomic::Ordering;
use std::fs;
use std::time::Duration;
use std::time::Instant;

use hypervisor::VmExit;
use hypervisor::VmOps;
use hypervisor::hvf::VtimerClock;
use hypervisor::hvf::devices::MmioBus;
use hypervisor::hvf::devices::Pl011;
use hypervisor::hvf::host_counter_hz;
use hypervisor::hvf::rehydrate;

use hypervisor::hvf::HvfHypervisor;
use hypervisor::hvf::UsgicSpiRouter;
use hypervisor::hvf::virtio::GuestMemory;
use hypervisor::hvf::virtio::block::{BlockDevice, FileBackend};
use hypervisor::hvf::virtio::devcore::{Backend, MsiSink, MsiSpiInjector};
use hypervisor::hvf::virtio::features;
use hypervisor::hvf::virtio::mmio::{self, MmioParams, VirtioMmioDevice, device_id};
use hypervisor::hvf::virtio::nat::{EgressPolicy, NatLimits, NatResponder};
use hypervisor::hvf::virtio::net::{NetDevice, NetKick};

use crate::coldboot;
use crate::coldboot::ColdBootConfig;
use crate::coldboot::VirtioKind;
use crate::imp::PL011_BASE;
use crate::imp::PL011_SIZE;

/// The NAT gateway the guest talks to, and the MAC we hand its NIC.
///
/// Same subnet the restore path's NAT uses, so a guest image built for one
/// works unchanged on the other.
const GATEWAY_IP: [u8; 4] = [192, 168, 249, 1];
const GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

/// How long the net service thread waits for a guest transmit before servicing
/// anyway. Matches the restore path's interval; a transmit wakes it at once.
const NET_SERVICE_INTERVAL: Duration = Duration::from_millis(2);

/// An [`MsiSink`] that hands an `INTID` to the userspace GIC's SPI router, so a
/// device thread's completion is delivered on the vCPU the interrupt is routed
/// to rather than asserted from a thread that does not own the line.
struct ColdSpiSink {
    router: Arc<UsgicSpiRouter>,
}

impl MsiSink for ColdSpiSink {
    fn deliver_spi(&self, intid: u32) {
        self.router.deliver_spi(intid);
    }
}

/// Number of interrupt lines the cold GIC distributor is sized for.
///
/// Matches `hypervisor::hvf::coldgic::COLD_BOOT_NR_IRQS`, which is what the
/// device tree advertises. Held together by a test.
const COLD_NR_IRQS: u32 = 256;

/// Minimal `VmOps` for a cold guest: an MMIO bus and nothing else.
///
/// PSCI `CPU_ON` returns "not supported" until SMP cold boot is wired, which is
/// the honest answer — the device tree says `enable-method = "psci"`, and a
/// kernel that asks and is told no logs a failed secondary rather than hanging
/// waiting for a core that will never come up.
struct ColdVmOps {
    bus: Arc<MmioBus>,
}

impl VmOps for ColdVmOps {
    fn guest_mem_write(&self, gpa: u64, buf: &[u8]) -> Result<usize, hypervisor::HypervisorVmError> {
        self.bus.guest_mem_write(gpa, buf)
    }
    fn guest_mem_read(
        &self,
        gpa: u64,
        buf: &mut [u8],
    ) -> Result<usize, hypervisor::HypervisorVmError> {
        self.bus.guest_mem_read(gpa, buf)
    }
    fn mmio_read(&self, gpa: u64, data: &mut [u8]) -> Result<(), hypervisor::HypervisorVmError> {
        self.bus.mmio_read(gpa, data)
    }
    fn mmio_write(&self, gpa: u64, data: &[u8]) -> Result<(), hypervisor::HypervisorVmError> {
        self.bus.mmio_write(gpa, data)
    }
    fn psci_vcpu_on(
        &self,
        _target_mpidr: u64,
        _entry: u64,
        _context: u64,
    ) -> Result<i64, hypervisor::HypervisorVmError> {
        // PSCI_NOT_SUPPORTED. See the struct docs.
        Ok(-1)
    }
}

#[derive(Clone, Debug)]
struct CreateArgs {
    cfg: ColdBootConfig,
    /// Build and describe the guest image, but do not create a VM. The whole
    /// memory-image half is testable this way with no entitlement and no VM
    /// slot, which matters because `hv_vm_create` is process-global.
    dry_run: bool,
    /// Stop after this many seconds. A cold boot that produces no output is
    /// the normal early failure mode, so this is not optional.
    max_seconds: u64,
    /// Hosts the guest may reach, as `host:port`. Empty means the default
    /// deny-all posture, which is what an unconfigured sandbox gets everywhere
    /// else in this tree (see `docs/security-model.md` §1a).
    egress_allow: Vec<String>,
}

fn usage() -> String {
    "chm create --kernel <Image> [options]\n\
     \n\
     Start a guest from an arm64 kernel image, with no snapshot.\n\
     \n\
     Options:\n\
     \x20 --kernel <path>     Uncompressed arm64 Image (required).\n\
     \x20                     A distro vmlinuz is gzip; gunzip it first.\n\
     \x20 --initramfs <path>  initrd/initramfs cpio (optional). Without one\n\
     \x20                     the kernel panics at `VFS: unable to mount\n\
     \x20                     root fs`, which is correct: it has nothing to run.\n\
     \x20 --cmdline <str>     Kernel command line.\n\
     \x20 --cpus <n>          vCPUs (default 1).\n\
     \x20 --memory <MiB>      Guest RAM in MiB (default 1024).\n\
     \x20 --disk <path>       Raw disk image as virtio-blk. Repeatable; the\n\
     \x20                     first becomes /dev/vda.\n\
     \x20 --net               Attach a virtio-net NIC on the userspace NAT.\n\
     \x20 --egress-allow <h:p>  Permit egress to host:port. Repeatable.\n\
     \x20                     Without any, the NIC is up but reaches nothing.\n\
     \x20 --seconds <n>       Stop after n seconds (default 30).\n\
     \x20 --dry-run           Build and describe the guest image; do not run it.\n"
        .to_string()
}

fn parse(raw: &[String]) -> Result<CreateArgs, String> {
    let mut cfg = ColdBootConfig::default();
    let mut dry_run = false;
    let mut max_seconds = 30_u64;
    let mut kernel: Option<PathBuf> = None;
    let mut egress_allow: Vec<String> = Vec::new();
    let mut cmdline_explicit = false;

    let mut i = 0;
    while i < raw.len() {
        let arg = raw[i].as_str();
        let mut value = |what: &str| -> Result<String, String> {
            i += 1;
            raw.get(i)
                .cloned()
                .ok_or_else(|| format!("{what} needs a value"))
        };
        match arg {
            "--kernel" => kernel = Some(PathBuf::from(value("--kernel")?)),
            "--initramfs" | "--initrd" => {
                cfg.initramfs = Some(PathBuf::from(value("--initramfs")?));
            }
            "--cmdline" => {
                cfg.cmdline = value("--cmdline")?;
                cmdline_explicit = true;
            }
            "--cpus" => {
                cfg.vcpus = value("--cpus")?
                    .parse()
                    .map_err(|e| format!("--cpus: {e}"))?;
            }
            "--memory" => {
                cfg.memory_mib = value("--memory")?
                    .parse()
                    .map_err(|e| format!("--memory: {e}"))?;
            }
            "--seconds" => {
                max_seconds = value("--seconds")?
                    .parse()
                    .map_err(|e| format!("--seconds: {e}"))?;
            }
            "--disk" => cfg.disks.push(PathBuf::from(value("--disk")?)),
            "--net" => cfg.net = true,
            "--egress-allow" => egress_allow.push(value("--egress-allow")?),
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown option {other}\n\n{}", usage())),
        }
        i += 1;
    }

    cfg.kernel = kernel.ok_or_else(|| format!("--kernel is required\n\n{}", usage()))?;
    if !egress_allow.is_empty() && !cfg.net {
        return Err("--egress-allow needs --net; there is no NIC to allow through".into());
    }
    // Only when the caller did not write a command line themselves: an explicit
    // `--cmdline` is the caller saying they know what the kernel needs, and
    // appending to it could contradict a `root=` they chose deliberately.
    if !cmdline_explicit
        && let Some(extra) = coldboot::implied_root_args(&cfg)
    {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    Ok(CreateArgs {
        cfg,
        dry_run,
        max_seconds,
        egress_allow,
    })
}

pub fn create_main(raw: &[String]) -> ExitCode {
    let args = match parse(raw) {
        Ok(a) => a,
        Err(msg) => {
            // `--help` returns the usage text as an "error"; it is not one.
            if msg.starts_with("chm create") {
                print!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("chm create: {msg}");
            return ExitCode::FAILURE;
        }
    };

    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("chm create: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &CreateArgs) -> Result<ExitCode, String> {
    let t_build = Instant::now();
    let image = coldboot::build(&args.cfg)?;
    let build_ms = t_build.elapsed().as_secs_f64() * 1000.0;

    println!(
        "chm create: {} vCPU, {} MiB, kernel {}",
        args.cfg.vcpus,
        args.cfg.memory_mib,
        args.cfg.kernel.display()
    );
    println!("{}", image.memory_map());
    if let Some((addr, size)) = image.initramfs_placed {
        println!(
            "  initramfs  {addr:#x}..{:#x} ({:.1} MiB)",
            addr + size,
            size as f64 / (1u64 << 20) as f64
        );
    }
    println!("  cmdline    {}", args.cfg.cmdline);
    println!("  built in   {build_ms:.1} ms");

    if args.dry_run {
        println!("chm create: --dry-run, not starting a VM");
        return Ok(ExitCode::SUCCESS);
    }

    let hv = HvfHypervisor::new()
        .map_err(|e| format!("Hypervisor.framework unavailable: {e}"))?;

    let uart = Arc::new(Pl011::new());
    let bus = Arc::new(MmioBus::new());
    bus.add(PL011_BASE, PL011_SIZE, uart.clone());

    // SAFETY: `image` owns the allocation and is kept alive below (it is
    // dropped only after `prepared`, which holds the VM). `host_ptr` is the
    // base of that single contiguous region.
    let prepared = unsafe {
        rehydrate::prepare_cold_usgic_vm(
            hv.as_ref(),
            image.ram_base,
            image.ram_size,
            image.host_ptr(),
            u64::from(args.cfg.vcpus),
            COLD_NR_IRQS,
        )
    }
    .map_err(|e| format!("preparing the cold VM: {e}"))?;

    // virtio devices go on the bus at exactly the windows the device tree
    // named, and their guest memory is the same `GuestMemory` the VM was mapped
    // with -- the device walks the guest's rings through the host mapping.
    let devices = build_virtio(&image, &prepared.guest_mem, args)?;
    for (place, dev) in &devices {
        bus.add(place.base, place.size, dev.clone());
    }
    let net_devices: Vec<Arc<VirtioMmioDevice>> = devices
        .iter()
        .filter(|(p, _)| p.kind == VirtioKind::Net)
        .map(|(_, d)| d.clone())
        .collect();
    let vm_ops: Arc<dyn VmOps> = Arc::new(ColdVmOps { bus });

    // A cold guest reads the host's own counter frequency, so there is no rate
    // to synthesize and no stepper to run: an unscaled clock, anchored now.
    let clock = VtimerClock::new(0, 0, host_counter_hz());

    let running = Arc::new(AtomicBool::new(true));

    // Console: drain the UART to stdout on a helper thread so the vCPU thread
    // only ever runs the guest.
    let console = {
        let uart = uart.clone();
        let running = running.clone();
        thread::Builder::new()
            .name("cold-console".into())
            .spawn(move || {
                let mut out = io::stdout();
                while running.load(Ordering::Acquire) {
                    let bytes = uart.take_output();
                    if bytes.is_empty() {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    let _ = out.write_all(&bytes);
                    let _ = out.flush();
                }
                let rest = uart.take_output();
                if !rest.is_empty() {
                    let _ = out.write_all(&rest);
                    let _ = out.flush();
                }
            })
            .map_err(|e| format!("spawning the console thread: {e}"))?
    };

    let vm = prepared.vm.clone();
    let seed = prepared.seed();
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);

    // The vCPU's GIC handle only exists once the vCPU does, and the vCPU can
    // only be created on the thread that will run it. So the device injectors
    // are installed inside that thread, before its first `run()`: a device that
    // completed a request before its injector was live would set the ISR bit
    // and drop the interrupt, and the guest would wait on it forever.
    let ready = Arc::new((Mutex::new(false), Condvar::new()));

    // The guest runs on its own thread because HVF binds a vCPU to the thread
    // that created it, and the deadline has to be enforced from outside it.
    let outcome: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));
    let vcpu_thread = {
        let running = running.clone();
        let outcome = outcome.clone();
        let entry = image.entry.0;
        let fdt = image.fdt.0;
        let devices = devices.clone();
        let spi_seed = prepared.seed();
        let ready = ready.clone();
        thread::Builder::new()
            .name("cold-vcpu0".into())
            .spawn(move || {
                let mut vcpu = match rehydrate::create_cold_usgic_vcpu(
                    &vm,
                    &seed,
                    0,
                    &vm_ops,
                    &clock,
                    Some((entry, fdt)),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        *outcome.lock().unwrap() = Some(Err(format!("creating vCPU 0: {e}")));
                        running.store(false, Ordering::Release);
                        signal_ready(&ready);
                        return;
                    }
                };
                if let Some(handle) = rehydrate::usgic_cpu_handle(&mut vcpu) {
                    let router = Arc::new(spi_seed.spi_router(Arc::new(vec![handle])));
                    let sink: Arc<dyn MsiSink> = Arc::new(ColdSpiSink { router });
                    for (place, dev) in &devices {
                        // One wired interrupt per device, so the vector table
                        // has a single entry and every queue signals vector 0.
                        dev.set_injector(Box::new(MsiSpiInjector::new(
                            dev.name().to_string(),
                            vec![place.intid],
                            sink.clone(),
                        )));
                    }
                }
                signal_ready(&ready);
                while running.load(Ordering::Acquire) {
                    match vcpu.run() {
                        Ok(VmExit::Ignore) => {}
                        Ok(VmExit::Shutdown | VmExit::Reset) => {
                            *outcome.lock().unwrap() = Some(Ok("guest powered off".into()));
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Ok(other) => {
                            *outcome.lock().unwrap() =
                                Some(Err(format!("unexpected vCPU exit: {other:?}")));
                            running.store(false, Ordering::Release);
                            break;
                        }
                        Err(e) => {
                            // The full source chain, not just the outermost
                            // display: `HypervisorCpuError::RunVcpu` renders as
                            // a bare "Failed to run vcpu", and the whole
                            // diagnosis (the HVF status code, the ESR, the
                            // faulting IPA) lives in the wrapped cause.
                            let mut msg = format!("vCPU run: {e}");
                            let mut src = Error::source(&e);
                            while let Some(cause) = src {
                                msg.push_str(&format!(": {cause}"));
                                src = cause.source();
                            }
                            *outcome.lock().unwrap() = Some(Err(msg));
                            running.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
            })
            .map_err(|e| format!("spawning the vCPU thread: {e}"))?
    };

    // The NAT lives on its own thread: a guest transmit only enqueues the frame
    // and wakes it, so the vCPU returns to the guest from its MMIO exit instead
    // of running a TCP stack inside it.
    let net_thread = if net_devices.is_empty() {
        None
    } else {
        let running = running.clone();
        let ready = ready.clone();
        let kick = Arc::new(NetKick::default());
        for dev in &net_devices {
            dev.set_net_kick(kick.clone());
        }
        Some(
            thread::Builder::new()
                .name("cold-net".into())
                .spawn(move || {
                    await_ready(&ready);
                    while running.load(Ordering::Acquire) {
                        for dev in &net_devices {
                            dev.service_net();
                        }
                        kick.wait(NET_SERVICE_INTERVAL);
                    }
                })
                .map_err(|e| format!("spawning the net service thread: {e}"))?,
        )
    };

    while running.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let timed_out = running.load(Ordering::Acquire);
    running.store(false, Ordering::Release);

    let _ = vcpu_thread.join();
    let _ = console.join();
    if let Some(t) = net_thread {
        let _ = t.join();
    }

    // `image` must outlive the VM: `prepared` holds the VM and unmaps guest RAM
    // on drop, and the pointer it was given belongs to `image`.
    drop(prepared);
    drop(image);

    let result = outcome.lock().unwrap().take();
    match result {
        Some(Ok(msg)) => {
            println!("\nchm create: {msg}");
            Ok(ExitCode::SUCCESS)
        }
        Some(Err(e)) => Err(e),
        None if timed_out => {
            println!("\nchm create: stopped after {}s", args.max_seconds);
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::SUCCESS),
    }
}


/// Release everyone waiting on the vCPU thread's setup, whether it succeeded or
/// not: a failed vCPU still has to unblock the threads that would otherwise
/// wait out the whole deadline for it.
fn signal_ready(ready: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cv) = &**ready;
    *lock.lock().unwrap() = true;
    cv.notify_all();
}

/// Wait for the vCPU thread to finish installing device injectors.
fn await_ready(ready: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cv) = &**ready;
    let mut done = lock.lock().unwrap();
    while !*done {
        done = cv.wait(done).unwrap();
    }
}

/// Build a `virtio-mmio` device for each placement the image reserved.
///
/// The device model is shared with the restore path — same queue walker, same
/// backends — so a cold guest's disk I/O is serviced by exactly the code a
/// rehydrated one's is. Only the transport differs, because only the discovery
/// differs.
fn build_virtio(
    image: &coldboot::ColdGuestImage,
    mem: &Arc<GuestMemory>,
    args: &CreateArgs,
) -> Result<Vec<(coldboot::VirtioPlacement, Arc<VirtioMmioDevice>)>, String> {
    let mut out = Vec::new();
    for place in &image.virtio {
        let dev = match place.kind {
            VirtioKind::Block => {
                let path = place
                    .path
                    .as_ref()
                    .ok_or_else(|| "a block placement with no backing file".to_string())?;
                // The capacity is the file's own size, rounded down: a raw
                // image with a partial trailing sector has no sector there to
                // read, and reporting one would hand the guest an EIO at the
                // end of every whole-device read.
                let bytes = fs::metadata(path)
                    .map_err(|e| format!("stat disk {}: {e}", path.display()))?
                    .len();
                let nsectors = bytes / 512;
                if nsectors == 0 {
                    return Err(format!("disk {} is smaller than one sector", path.display()));
                }
                let backend = FileBackend::open(path, nsectors)
                    .map_err(|e| format!("opening disk {}: {e}", path.display()))?;
                let serial = format!("chm-disk{}", place.index);
                VirtioMmioDevice::new(
                    format!("blk{}", place.index),
                    Backend::Block(BlockDevice::new(Box::new(backend), &serial)),
                    mem.clone(),
                    MmioParams {
                        device_id: device_id::BLOCK,
                        features: features::RING_INDIRECT_DESC | features::RING_EVENT_IDX,
                        num_queues: 1,
                        device_config: mmio::blk_config(nsectors),
                    },
                )
            }
            VirtioKind::Net => {
                // Deny-all unless the caller named destinations, matching the
                // default posture every other entry point starts from.
                let policy = EgressPolicy::from_profile(
                    "deny",
                    &args.egress_allow,
                    &[],
                    "chm create --egress-allow",
                );
                let responder =
                    NatResponder::new(GATEWAY_IP, GATEWAY_MAC, policy, NatLimits::default());
                VirtioMmioDevice::new(
                    "net0",
                    Backend::Net(NetDevice::new(Box::new(responder))),
                    mem.clone(),
                    MmioParams {
                        device_id: device_id::NET,
                        features: features::RING_INDIRECT_DESC
                            | features::RING_EVENT_IDX
                            | mmio::VIRTIO_NET_F_MAC,
                        num_queues: 2,
                        device_config: mmio::net_config(GUEST_MAC),
                    },
                )
            }
        };
        out.push((place.clone(), Arc::new(dev)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn kernel_is_required_and_the_error_says_so() {
        let e = parse(&args(&["--cpus", "2"])).unwrap_err();
        assert!(e.contains("--kernel is required"), "{e}");
    }

    #[test]
    fn options_parse_to_the_values_given() {
        let a = parse(&args(&[
            "--kernel", "/tmp/Image", "--cpus", "4", "--memory", "2048", "--seconds", "7",
            "--cmdline", "console=ttyAMA0 quiet", "--dry-run",
        ]))
        .unwrap();
        assert_eq!(a.cfg.kernel, PathBuf::from("/tmp/Image"));
        assert_eq!(a.cfg.vcpus, 4);
        assert_eq!(a.cfg.memory_mib, 2048);
        assert_eq!(a.max_seconds, 7);
        assert_eq!(a.cfg.cmdline, "console=ttyAMA0 quiet");
        assert!(a.dry_run);
    }

    #[test]
    fn an_option_missing_its_value_is_named() {
        let e = parse(&args(&["--kernel"])).unwrap_err();
        assert!(e.contains("--kernel needs a value"), "{e}");
    }

    #[test]
    fn an_unknown_option_prints_the_usage_rather_than_only_complaining() {
        let e = parse(&args(&["--kernel", "/tmp/Image", "--nope"])).unwrap_err();
        assert!(e.contains("unknown option --nope"), "{e}");
        assert!(e.contains("--dry-run"), "{e}");
    }

    /// The interrupt-line count this module tells `prepare_cold_usgic_vm` to
    /// size the distributor for must equal the one `coldgic` advertises in the
    /// device tree. If they drift, the guest is handed a tree describing more
    /// interrupts than the distributor models.
    #[test]
    fn the_distributor_is_sized_for_what_the_device_tree_advertises() {
        assert_eq!(
            COLD_NR_IRQS,
            hypervisor::hvf::coldgic::COLD_BOOT_NR_IRQS,
            "cold GIC interrupt-line count drifted between the runner and the tree"
        );
    }

    /// The PL011 window the device tree describes must be the window the MMIO
    /// bus actually serves, or the guest's console writes land nowhere and a
    /// cold boot looks like a hang.
    #[test]
    fn the_console_the_tree_describes_is_the_one_the_bus_serves() {
        assert_eq!(
            crate::imp::PL011_BASE,
            arch::aarch64::layout::LEGACY_SERIAL_MAPPED_IO_START.0
        );
        assert_eq!(crate::imp::PL011_SIZE, coldboot::pl011_size());
    }

    /// A real Linux kernel, if one is present, must be recognised. Skipped
    /// rather than failed when it is not: this proves the reader against the
    /// real thing without making the suite depend on a 57 MB download.
    #[test]
    fn a_real_kernel_image_if_present_is_recognised() {
        let p = std::path::Path::new("/tmp/Image");
        if !p.exists() {
            return;
        }
        use std::io::Read as _;
        let mut hdr = [0_u8; 64];
        std::fs::File::open(p).unwrap().read_exact(&mut hdr).unwrap();
        assert_eq!(&hdr[0x38..0x3c], b"ARM\x64", "not an arm64 Image");
        let cfg = ColdBootConfig {
            kernel: p.to_path_buf(),
            memory_mib: 512,
            ..ColdBootConfig::default()
        };
        let img = coldboot::build(&cfg).expect("building a guest image from a real kernel");
        assert!(img.fdt_len > 1000, "device tree suspiciously small");
        assert!(img.entry.0 > img.fdt.0, "kernel must land above the tree");
    }

    #[test]
    fn egress_allow_without_a_nic_is_a_parse_error_not_a_silent_no_op() {
        // Accepting this would read as "egress is restricted to this host" when
        // in fact there is no NIC at all — a misleading kind of safe.
        let e = parse(&args(&[
            "--kernel", "/tmp/Image", "--egress-allow", "api.github.com:443",
        ]))
        .unwrap_err();
        assert!(e.contains("--net"), "error must name the missing flag: {e}");
    }

    #[test]
    fn disks_accumulate_in_order_and_net_is_off_by_default() {
        let a = parse(&args(&[
            "--kernel", "/tmp/Image", "--disk", "/tmp/a.img", "--disk", "/tmp/b.img",
        ]))
        .unwrap();
        assert_eq!(a.cfg.disks.len(), 2);
        assert!(a.cfg.disks[0].ends_with("a.img"));
        assert!(a.cfg.disks[1].ends_with("b.img"));
        assert!(!a.cfg.net);
        assert!(a.egress_allow.is_empty(), "default posture is deny-all");
    }

    #[test]
    fn a_disk_with_no_initramfs_gets_root_appended() {
        let a = parse(&args(&["--kernel", "/tmp/Image", "--disk", "/tmp/a.img"])).unwrap();
        assert!(
            a.cfg.cmdline.ends_with("root=/dev/vda rw"),
            "cmdline was {:?}",
            a.cfg.cmdline
        );
        assert!(a.cfg.cmdline.contains("console=ttyAMA0"), "default kept");
    }

    #[test]
    fn an_explicit_cmdline_is_never_appended_to() {
        // The caller may have chosen a different root deliberately; appending
        // a second root= would silently override it.
        let a = parse(&args(&[
            "--kernel", "/tmp/Image", "--disk", "/tmp/a.img",
            "--cmdline", "console=ttyAMA0 root=/dev/vda2 ro",
        ]))
        .unwrap();
        assert_eq!(a.cfg.cmdline, "console=ttyAMA0 root=/dev/vda2 ro");
    }

    #[test]
    fn an_initramfs_suppresses_the_implied_root() {
        let a = parse(&args(&[
            "--kernel", "/tmp/Image", "--disk", "/tmp/a.img", "--initramfs", "/tmp/i.gz",
        ]))
        .unwrap();
        assert!(
            !a.cfg.cmdline.contains("root="),
            "an initramfs is the root fs: {:?}",
            a.cfg.cmdline
        );
    }
}
