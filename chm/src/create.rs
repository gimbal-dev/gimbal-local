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

use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use std::{fs, io, thread};

use arch::aarch64::layout::LEGACY_RTC_MAPPED_IO_START;
use hypervisor::hvf::devices::{MmioBus, Pl011, Pl031};
use hypervisor::hvf::virtio::block::{BlockDevice, FileBackend};
use hypervisor::hvf::virtio::devcore::{Backend, MsiSink, MsiSpiInjector};
use hypervisor::hvf::virtio::mmio::{self, MmioParams, VirtioMmioDevice, device_id};
use hypervisor::hvf::virtio::nat::{EgressPolicy, NatLimits, NatResponder};
use hypervisor::hvf::virtio::net::{NetDevice, NetKick};
use hypervisor::hvf::virtio::{GuestMemory, features};
use hypervisor::hvf::{
    HvfHypervisor, UsgicCpuHandle, UsgicSpiRouter, VtimerClock, host_counter_hz, rehydrate,
};
use hypervisor::{VmExit, VmOps};

use crate::coldboot::{ColdBootConfig, VirtioKind};
use crate::console::RawConsole;
use crate::imp::{
    CpuPowerSlot, PL011_BASE, PL011_SIZE, PsciCoordinator, apply_psci_cpu_on_state,
    wait_for_cpu_on_request,
};
use crate::spec::{Overrides, SandboxSpec, resolve, spec_file_for};
use crate::{coldboot, console, credproxy, postboot};

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

/// `VmOps` for a cold guest: an MMIO bus and the PSCI power coordinator.
///
/// The device tree says `enable-method = "psci"`, so `CPU_ON` is the only way
/// the kernel can start a secondary. The coordinator is shared with the vCPU
/// threads: this call runs on whichever vCPU made the SMC, and the target's own
/// thread is parked on the matching condition variable.
struct ColdVmOps {
    bus: Arc<MmioBus>,
    psci: Arc<PsciCoordinator>,
}

impl VmOps for ColdVmOps {
    fn guest_mem_write(
        &self,
        gpa: u64,
        buf: &[u8],
    ) -> Result<usize, hypervisor::HypervisorVmError> {
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
        target_mpidr: u64,
        entry: u64,
        context: u64,
    ) -> Result<i64, hypervisor::HypervisorVmError> {
        Ok(self.psci.cpu_on(target_mpidr, entry, context))
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
    /// Credential-injection rules for the egress proxy. The guest never holds
    /// the credential; the header is attached as the request leaves. See
    /// `docs/credential-proxy.md`.
    proxy_rules: Option<PathBuf>,
    /// Where the proxy CA and audit trail live. Defaults to the rules file's
    /// own directory, so the common case needs one flag rather than two. A CA
    /// is a persistent trust root, so it belongs somewhere the caller chose,
    /// never a temporary directory.
    workspace: Option<PathBuf>,
    /// What a spec's `env` and `postBootCommand` asked to happen inside the
    /// guest once it is up. Empty on every path that did not ask for either, so
    /// the existing behaviour is not merely preserved but untouched — the whole
    /// mechanism is skipped rather than run and found to have nothing to do.
    postboot: postboot::Plan,
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
     \x20                     Without any, the NIC is up but reaches nothing\n\
     \x20                     beyond the hosts --proxy-rules implies.\n\
     \x20 --proxy-rules <path>  Credential-injection rules (see chm proxy).\n\
     \x20                     The hosts they name become reachable too:\n\
     \x20                     naming a host in a rule is the intent to reach\n\
     \x20                     it. Each implied allowance is printed.\n\
     \x20 --workspace <path>  Where the proxy CA and audit trail live.\n\
     \x20                     Defaults to the --proxy-rules file's own\n\
     \x20                     directory, because a CA is a trust root that\n\
     \x20                     has to outlive the run.\n\
     \x20 --seconds <n>       Stop after n seconds (default 30). 0 runs until\n\
     \x20                     the guest powers off or you press Ctrl-A x.\n\
     \x20 --env KEY=VALUE     Export a variable in the guest's console shell\n\
     \x20                     once it is up. Repeatable. Reaches the post-boot\n\
     \x20                     command, later `chm exec`s and your own session,\n\
     \x20                     but not a fresh login after that shell exits.\n\
     \x20                     Never put a credential here — see chm proxy.\n\
     \x20 --post-boot <argv…> Run a command once the guest has a shell, before\n\
     \x20                     the console is yours. Everything after it is the\n\
     \x20                     argv, so put it last. A non-zero exit fails the\n\
     \x20                     run: a sandbox whose setup failed is not the\n\
     \x20                     sandbox that was asked for.\n\
     \x20 --post-boot-arg <s> One argv element of the same command. Repeatable,\n\
     \x20                     and not greedy, so it can be followed by other\n\
     \x20                     flags — which is why --spec expands to this form\n\
     \x20                     and your own --post-boot still overrides it.\n\
     \x20 --dry-run           Build and describe the guest image; do not run it.\n\
     \x20 --spec <path>       A sandbox.json (or a workspace holding one) that\n\
     \x20                     describes this sandbox. It expands to exactly the\n\
     \x20                     flags below, which are then applied on top: the\n\
     \x20                     spec says what the sandbox is, flags say how this\n\
     \x20                     run differs. See `chm spec`.\n"
        .to_string()
}

fn parse(raw: &[String]) -> Result<CreateArgs, String> {
    let mut cfg = ColdBootConfig::default();
    let mut dry_run = false;
    let mut max_seconds = 30_u64;
    let mut kernel: Option<PathBuf> = None;
    let mut egress_allow: Vec<String> = Vec::new();
    let mut cmdline_explicit = false;
    let mut cmdline_extra: Vec<String> = Vec::new();
    let mut proxy_rules: Option<PathBuf> = None;
    let mut workspace: Option<PathBuf> = None;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut post_boot: Option<Vec<String>> = None;

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
            // Append rather than replace, so one extra kernel argument does not
            // cost you the auto-detected `root=`. Without this the only way to
            // add (say) a `systemd.mask=` was to hand-write the whole command
            // line, and then you own working out the root partition yourself.
            "--cmdline-extra" => {
                cmdline_extra.push(value("--cmdline-extra")?);
            }
            "--proxy-rules" => {
                proxy_rules = Some(PathBuf::from(value("--proxy-rules")?));
            }
            "--workspace" => {
                workspace = Some(PathBuf::from(value("--workspace")?));
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
            "--env" => {
                let (k, v) = postboot::parse_assignment(&value("--env")?)?;
                env.insert(k, v);
            }
            // Everything after `--post-boot` is the command's argv, including
            // anything that looks like one of our own flags. A command is not
            // obliged to avoid names `chm` happens to use, and the alternative —
            // one quoted string — would make it a shell *line*, which is exactly
            // the ambiguity `chm exec` refuses (I5).
            //
            // Which is why a spec must NOT expand to this form. `--spec` splices
            // its argv *before* the caller's flags so that a flag wins, and a
            // greedy `--post-boot` there would eat every one of them — turning
            // `--dry-run` into an argument to the guest's command. That is not
            // hypothetical: it is what the first build of this milestone did,
            // and it booted a VM instead of describing one. Machines use
            // `--post-boot-arg`; humans keep this.
            "--post-boot" => {
                let rest: Vec<String> = raw[i + 1..].to_vec();
                if rest.is_empty() {
                    return Err("--post-boot needs a command".to_string());
                }
                // Replaces rather than appends: a command is a whole thing, so
                // a flag overrides a spec's instead of concatenating onto it.
                post_boot = Some(rest);
                i = raw.len();
                continue;
            }
            // One argv element at a time, so the flag is not greedy and can
            // therefore be followed by others. Appends, because a whole command
            // arrives as a run of these.
            "--post-boot-arg" => {
                post_boot
                    .get_or_insert_with(Vec::new)
                    .push(value("--post-boot-arg")?);
            }
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
    if proxy_rules.is_some() && !cfg.net {
        return Err("--proxy-rules needs --net; there is no traffic to intercept".into());
    }
    // Only when the caller did not write a command line themselves: an explicit
    // `--cmdline` is the caller saying they know what the kernel needs, and
    // appending to it could contradict a `root=` they chose deliberately.
    if !cmdline_explicit && let Some(extra) = coldboot::implied_root_args(&cfg) {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    for extra in &cmdline_extra {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    Ok(CreateArgs {
        cfg,
        dry_run,
        max_seconds,
        egress_allow,
        proxy_rules,
        workspace,
        postboot: postboot::Plan { env, post_boot },
    })
}

/// Expand a `--spec` into the flags it stands for, ahead of the caller's own.
///
/// The spec deliberately gets **no** private route into `ColdBootConfig`. It
/// produces the argv a person would have typed and hands it to the same parser,
/// which is what stops it becoming a second way to configure a guest that can
/// drift from the first. Placing the expansion *before* the caller's flags is
/// the whole of the precedence rule: scalar options are last-wins in `parse`, so
/// a flag beats the spec, and repeatable ones accumulate.
fn expand_spec(raw: &[String]) -> Result<Vec<String>, String> {
    let Some(i) = raw.iter().position(|a| a == "--spec") else {
        return Ok(raw.to_vec());
    };
    let path = raw
        .get(i + 1)
        .ok_or_else(|| "--spec needs a path".to_string())?;
    let path = spec_file_for(Path::new(path));

    let doc = SandboxSpec::load(&path)?;
    // Refuse before starting anything. A spec whose policy this build cannot
    // honour must not quietly become a guest with less policy than the document
    // it was started from.
    let problems = doc.validate();
    if !problems.is_empty() {
        let mut msg = format!("{} cannot start this sandbox:", path.display());
        for p in &problems {
            msg.push_str("\n  - ");
            msg.push_str(p);
        }
        return Err(msg);
    }

    let resolved = resolve(Some(&doc), Some(path.clone()), &Overrides::default());
    let mut argv = resolved.to_create_argv();
    // `to_create_argv` renders the whole command; here we are already inside it.
    if argv.first().map(String::as_str) == Some("create") {
        argv.remove(0);
    }
    eprintln!("chm create: from {} ({} flags)", path.display(), argv.len());

    let mut out = argv;
    out.extend_from_slice(&raw[..i]);
    out.extend_from_slice(&raw[i + 2..]);
    Ok(out)
}

pub fn create_main(raw: &[String]) -> ExitCode {
    let raw = match expand_spec(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("chm create: {e}");
            return ExitCode::FAILURE;
        }
    };
    let raw = &raw[..];
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

    let hv = HvfHypervisor::new().map_err(|e| format!("Hypervisor.framework unavailable: {e}"))?;

    let uart = Arc::new(Pl011::new());
    let bus = Arc::new(MmioBus::new());
    bus.add(PL011_BASE, PL011_SIZE, uart.clone());
    // The wall clock. Cheap, and without it the guest's idea of "now" is a
    // kernel build constant, which breaks TLS rather than merely being untidy.
    bus.add(
        LEGACY_RTC_MAPPED_IO_START.0,
        coldboot::PL031_SIZE,
        Arc::new(Pl031::new()),
    );

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

    // Resolve the injection rules *before* the NIC is built: naming a host in a
    // rule is the intent to reach it (V8.7), and the NAT's allow-list is baked
    // into the net device at construction. Resolved once and reused below, so a
    // rules file edited between the two reads cannot produce a policy and a
    // proxy that disagree about which hosts exist.
    let proxy_rules = match args.proxy_rules.as_deref() {
        Some(rules) => credproxy::cli::resolve_rules(args.workspace.as_deref(), Some(rules))
            .map_err(|e| format!("credential proxy: {e}"))?,
        None => None,
    };
    // Both halves are the local operator's here: `--egress-allow` and
    // `--proxy-rules` are flags on this very command line. `chm create` has no
    // control-plane path at all.
    let implied_egress = proxy_rules.as_ref().map_or_else(Vec::new, |r| {
        credproxy::cli::implied_egress_for(
            r,
            credproxy::cli::Authority::Local,
            "chm create --egress-allow",
        )
    });

    // virtio devices go on the bus at exactly the windows the device tree
    // named, and their guest memory is the same `GuestMemory` the VM was mapped
    // with -- the device walks the guest's rings through the host mapping.
    let devices = build_virtio(&image, &prepared.guest_mem, args, &implied_egress)?;
    for (place, dev) in &devices {
        bus.add(place.base, place.size, dev.clone());
    }
    let net_devices: Vec<Arc<VirtioMmioDevice>> = devices
        .iter()
        .filter(|(p, _)| p.kind == VirtioKind::Net)
        .map(|(_, d)| d.clone())
        .collect();

    // The credential proxy, if the caller configured one. Installed after the
    // NIC exists because the hook is per-device and the proxy must bind its
    // port first. `chm` is already the guest's whole network, so this is the
    // one chokepoint every outbound call crosses -- the same edge injection a
    // rehydrated guest gets, on a guest that was never captured anywhere.
    let _proxy = match (args.proxy_rules.as_deref(), proxy_rules.as_ref()) {
        (Some(rules), Some(resolved)) => {
            // The rules file's own directory is the default workspace: a CA is
            // a persistent trust root, so it must not land in a temp dir the
            // next run cannot find.
            let ws = args
                .workspace
                .clone()
                .or_else(|| rules.parent().map(Path::to_path_buf))
                .ok_or_else(|| "--proxy-rules has no directory; pass --workspace".to_string())?;
            // Fail closed: rules that cannot be honoured stop the run rather
            // than booting a guest whose calls go out unsigned and unaudited.
            match credproxy::cli::start_resolved(&ws, resolved)
                .map_err(|e| format!("credential proxy: {e}"))?
            {
                Some((proxy, decider)) => {
                    for dev in &net_devices {
                        dev.set_net_intercept(Some(Arc::clone(&decider)));
                    }
                    Some(proxy)
                }
                None => None,
            }
        }
        _ => None,
    };

    // vCPU 0 is running because the boot protocol started it there; every
    // secondary waits for the kernel to ask by PSCI `CPU_ON`.
    let psci = PsciCoordinator::cold(usize::from(args.cfg.vcpus).max(1));
    let vm_ops: Arc<dyn VmOps> = Arc::new(ColdVmOps {
        bus,
        psci: psci.clone(),
    });

    // A cold guest reads the host's own counter frequency, so there is no rate
    // to synthesize and no stepper to run: an unscaled clock, anchored now.
    let clock = VtimerClock::new(0, 0, host_counter_hz());

    let running = Arc::new(AtomicBool::new(true));

    // Console: drain the UART to stdout on a helper thread so the vCPU thread
    // only ever runs the guest.
    //
    // When something has to be delivered into the guest (#190), that thread also
    // *tees* what it printed into a bounded tail, because `take_output` consumes
    // and a second reader would steal bytes from the operator's own screen. The
    // tee is `None` on every other run, so a plain `chm create` allocates
    // nothing and behaves exactly as before.
    let tail: Option<Arc<ConsoleTail>> =
        (!args.postboot.is_empty()).then(|| Arc::new(ConsoleTail::default()));
    let console = {
        let uart = uart.clone();
        let running = running.clone();
        let tail = tail.clone();
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
                    if let Some(t) = &tail {
                        t.push(&bytes);
                    }
                    let _ = out.write_all(&bytes);
                    let _ = out.flush();
                }
                let rest = uart.take_output();
                if !rest.is_empty() {
                    if let Some(t) = &tail {
                        t.push(&rest);
                    }
                    let _ = out.write_all(&rest);
                    let _ = out.flush();
                }
            })
            .map_err(|e| format!("spawning the console thread: {e}"))?
    };

    // The net service thread must not touch a device before its injector is
    // installed, so it waits on this.
    let ready = Arc::new((Mutex::new(false), Condvar::new()));

    let vm = prepared.vm.clone();
    let seed = prepared.seed();
    // `--seconds 0` means "no deadline": an interactive session ends when the
    // guest powers off or the operator asks (Ctrl-A x, or a terminating signal),
    // not when a stopwatch the operator never set runs out.
    let deadline =
        (args.max_seconds > 0).then(|| Instant::now() + Duration::from_secs(args.max_seconds));
    let vcpus = usize::from(args.cfg.vcpus).max(1);

    // Each vCPU thread reports its GIC handle here, then waits on `go_rx` for
    // the completed cross-vCPU table. Two things need every vCPU to exist
    // first, and neither can be done from inside one vCPU's thread:
    //
    //  - SGI delivery. Linux IPIs secondaries to bring them up, so a table
    //    missing a core means that core never sees its wake-up.
    //  - Device injectors. A device that completed a request before its
    //    injector was live would set the ISR bit and drop the interrupt, and
    //    the guest would wait on it forever.
    // The exit signal comes back with the GIC handle because it can only be
    // taken from the vCPU, on the vCPU's own thread, but must be *called* from
    // the orchestrator: a guest that spins without trapping (a kernel panic
    // reboot loop is the case that found this) never returns from `hv_vcpu_run`,
    // so the run loop never re-reads `running` and the join below would wait for
    // a guest that is never coming back. `hv_vcpus_exit` is what makes
    // `--seconds` a promise rather than a hope.
    type CpuReport = (usize, UsgicCpuHandle, Option<Arc<dyn Fn() + Send + Sync>>);
    let (setup_tx, setup_rx) = mpsc::channel::<Result<CpuReport, String>>();
    let mut go_txs = Vec::with_capacity(vcpus);
    let outcome: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));
    let mut vcpu_threads = Vec::with_capacity(vcpus);

    for id in 0..vcpus {
        let (go_tx, go_rx) = mpsc::channel::<Arc<Vec<UsgicCpuHandle>>>();
        go_txs.push(go_tx);
        let vm = vm.clone();
        let seed = seed.clone();
        let vm_ops = vm_ops.clone();
        let clock = clock.clone();
        let running = running.clone();
        let outcome = outcome.clone();
        let setup_tx = setup_tx.clone();
        let slot = psci.slot(id);
        // Only the boot CPU gets an entry point and a device tree. A secondary
        // keeps HVF's reset state until `CPU_ON` names an address for it.
        let boot = (id == 0).then_some((image.entry.0, image.fdt.0));
        vcpu_threads.push(
            thread::Builder::new()
                .name(format!("cold-vcpu{id}"))
                .spawn(move || {
                    let mut vcpu = match rehydrate::create_cold_usgic_vcpu(
                        &vm, &seed, id, &vm_ops, &clock, boot,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = setup_tx.send(Err(format!("creating vCPU {id}: {e}")));
                            return;
                        }
                    };
                    let Some(handle) = rehydrate::usgic_cpu_handle(&mut vcpu) else {
                        let _ = setup_tx.send(Err(format!("vCPU {id} is not an HVF vCPU")));
                        return;
                    };
                    let exit = vcpu.exit_signal();
                    if setup_tx.send(Ok((id, handle, exit))).is_err() {
                        return;
                    }
                    drop(setup_tx);
                    // A dropped sender means the orchestrator gave up on setup.
                    let Ok(table) = go_rx.recv() else { return };
                    rehydrate::usgic_set_cpu_table(&mut vcpu, table);

                    if id != 0 {
                        // Park until the kernel asks for this core. The entry
                        // point and context arrive with the request, and both
                        // must be in the register file before the first run().
                        let Some((entry, context)) = wait_for_cpu_on_request(&slot, &running)
                        else {
                            return;
                        };
                        if let Err(e) = apply_psci_cpu_on_state(vcpu.as_mut(), entry, context) {
                            *outcome.lock().unwrap() = Some(Err(format!("vCPU {id}: {e}")));
                            running.store(false, Ordering::Release);
                            return;
                        }
                    }

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
                                    Some(Err(format!("vCPU {id} unexpected exit: {other:?}")));
                                running.store(false, Ordering::Release);
                                break;
                            }
                            Err(e) => {
                                // The full source chain, not just the outermost
                                // display: `HypervisorCpuError::RunVcpu` renders
                                // as a bare "Failed to run vcpu", and the whole
                                // diagnosis (the HVF status code, the ESR, the
                                // faulting IPA) lives in the wrapped cause.
                                let mut msg = format!("vCPU {id} run: {e}");
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
                    // A secondary that stops must be marked off, or the kernel
                    // sees ALREADY_ON if it retries.
                    psci_mark_offline(&slot);
                })
                .map_err(|e| format!("spawning vCPU thread {id}: {e}"))?,
        );
    }
    drop(setup_tx);

    // Collect every vCPU's handle, in id order: the SGI table is indexed by
    // vCPU id, and the channel does not promise arrival order.
    let mut handles: Vec<Option<UsgicCpuHandle>> = (0..vcpus).map(|_| None).collect();
    let mut exits: Vec<Option<Arc<dyn Fn() + Send + Sync>>> = (0..vcpus).map(|_| None).collect();
    for _ in 0..vcpus {
        match setup_rx.recv() {
            Ok(Ok((id, h, exit))) => {
                handles[id] = Some(h);
                exits[id] = exit;
            }
            Ok(Err(e)) => {
                running.store(false, Ordering::Release);
                drop(go_txs);
                for t in vcpu_threads {
                    let _ = t.join();
                }
                return Err(e);
            }
            Err(_) => {
                running.store(false, Ordering::Release);
                drop(go_txs);
                for t in vcpu_threads {
                    let _ = t.join();
                }
                return Err("a vCPU thread exited before reporting in".into());
            }
        }
    }
    let cpu_table: Arc<Vec<UsgicCpuHandle>> =
        Arc::new(handles.into_iter().map(Option::unwrap).collect());

    // Now every redistributor exists, so an SPI can be routed to the core its
    // `GICD_IROUTER` affinity names rather than always to the boot CPU.
    let router = Arc::new(seed.spi_router(cpu_table.clone()));
    let sink: Arc<dyn MsiSink> = Arc::new(ColdSpiSink { router });
    for (place, dev) in &devices {
        // One wired interrupt per device, so the vector table has a single
        // entry and every queue signals vector 0.
        dev.set_injector(Box::new(MsiSpiInjector::new(
            dev.name().to_string(),
            vec![place.intid],
            sink.clone(),
        )));
    }
    signal_ready(&ready);
    for go_tx in &go_txs {
        let _ = go_tx.send(cpu_table.clone());
    }

    // Console input. Until now a cold guest could only be watched: the UART
    // drained to stdout and nothing ever reached its receive FIFO, so a shell on
    // `ttyAMA0` was unreachable and the guest could not be asked to do anything.
    //
    // The PL011's INTID is passed explicitly rather than read from the
    // environment, because a cold guest's device tree is one *we* wrote:
    // `CHM_SERIAL_SPI` describes a captured VMM's device order and would aim a
    // cold guest's keystrokes at an interrupt no device owns. The SPI router
    // already wakes the vCPU it delivers to, so no separate wake is needed.
    //
    // `RawConsole::enable` is a no-op when stdin is not a TTY, so a piped or
    // redirected run gets the input pump without anyone touching terminal modes.
    let raw_console = RawConsole::enable();
    console::install_signal_handlers(raw_console.handle());
    console::spawn_stdin_pump(
        uart.clone(),
        sink.clone(),
        raw_console.handle(),
        None,
        coldboot::PL011_IRQ,
    );
    // Restores level-triggered receive semantics: a getty that unmasks RXIM
    // after input was already queued would otherwise wait for a keystroke that
    // has, from the typist's point of view, already been sent.
    let serial_reassert = console::spawn_serial_reassert(
        uart.clone(),
        sink.clone(),
        None,
        running.clone(),
        coldboot::PL011_IRQ,
    );

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

    // Deliver what the spec asked to happen inside the guest, on its own thread
    // so the orchestrator's deadline loop keeps running: readiness can take a
    // minute on a slow boot, and a `--seconds` promise must not become a hope
    // because we were blocked waiting for a shell.
    //
    // It starts *after* the stdin pump is installed, so an operator watching the
    // console sees the delivery happen rather than finding it already done.
    let postboot_result: Arc<Mutex<Option<Result<postboot::Report, postboot::Failure>>>> =
        Arc::new(Mutex::new(None));
    let postboot_thread = match &tail {
        None => None,
        Some(tail) => {
            let plan = args.postboot.clone();
            let slot = postboot_result.clone();
            let running_pb = running.clone();
            let ch = GuestConsole {
                input: console::console_input(
                    uart.clone(),
                    sink.clone(),
                    None,
                    coldboot::PL011_IRQ,
                ),
                tail: tail.clone(),
                running: running.clone(),
            };
            Some(
                thread::Builder::new()
                    .name("cold-postboot".into())
                    .spawn(move || {
                        let r = postboot::deliver(
                            &ch,
                            &plan,
                            postboot::DEFAULT_READY_TIMEOUT,
                            postboot::DEFAULT_STEP_TIMEOUT,
                        );
                        let failed = r.is_err();
                        match &r {
                            Ok(postboot::Report::Delivered {
                                exported,
                                post_boot_code,
                            }) => {
                                if *exported > 0 {
                                    eprintln!("\nchm create: exported {exported} variable(s)");
                                }
                                if let Some(c) = post_boot_code {
                                    eprintln!("chm create: postBootCommand exited {c}");
                                }
                            }
                            Ok(postboot::Report::NothingToDo) => {}
                            Err(e) => eprintln!("\nchm create: {}", e.message()),
                        }
                        *slot.lock().unwrap() = Some(r);
                        // A setup that failed leaves a guest that is not the one
                        // the document described, so the run ends rather than
                        // handing over a sandbox nobody asked for.
                        if failed {
                            running_pb.store(false, Ordering::Release);
                        }
                    })
                    .map_err(|e| format!("spawning the post-boot thread: {e}"))?,
            )
        }
    };

    while running.load(Ordering::Acquire)
        && deadline.is_none_or(|d| Instant::now() < d)
        && !console::shutdown_requested()
    {
        thread::sleep(Duration::from_millis(50));
    }
    // Only a deadline that actually expired counts as a timeout; an operator
    // ending the session is a normal exit, not a run that overran.
    let timed_out = running.load(Ordering::Acquire) && !console::shutdown_requested();
    running.store(false, Ordering::Release);

    // Release any secondary still parked waiting for a CPU_ON that will not
    // come, or the join below blocks until its 100 ms poll expires.
    psci.wake_all();
    // And force any vCPU still inside `hv_vcpu_run` back out, so it re-reads
    // `running` and leaves. Without this a guest executing without trapping
    // holds the join open for as long as it keeps doing so, which is forever
    // for a panic reboot loop.
    for exit in exits.iter().flatten() {
        exit();
    }
    for t in vcpu_threads {
        let _ = t.join();
    }
    let _ = console.join();
    let _ = serial_reassert.join();
    if let Some(t) = net_thread {
        let _ = t.join();
    }
    if let Some(t) = postboot_thread {
        let _ = t.join();
    }

    // `image` must outlive the VM: `prepared` holds the VM and unmaps guest RAM
    // on drop, and the pointer it was given belongs to `image`.
    drop(prepared);
    drop(image);

    // A delivery failure outranks a clean guest exit. The guest may well have
    // powered off tidily; the point is that it was never the guest the document
    // described, and reporting success would be the #192 mistake in a new place
    // — a conclusion reached and then not acted on.
    if let Some(Err(e)) = postboot_result.lock().unwrap().take() {
        return Err(e.message());
    }

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
/// A bounded copy of what the console printed, so post-boot delivery can read
/// the guest's answers without taking bytes off the operator's screen.
///
/// Bounded because a guest can print forever and this is a side-channel, not a
/// log: only the recent tail can matter, since every framed step starts by
/// noting the current length and reads forward from there. Losing older bytes is
/// what [`exec::ExecOutcome::Truncated`] exists to report, so eviction becomes a
/// named failure rather than a wrong answer.
#[derive(Default)]
struct ConsoleTail {
    /// Text kept, oldest first.
    buf: Mutex<String>,
    /// How many bytes have been evicted from the front.
    dropped: Mutex<usize>,
}

impl ConsoleTail {
    /// Roughly the daemon's ring, and comfortably above `exec::MAX_OUTPUT`, so a
    /// step that overflows is reported as overflow rather than as eviction.
    const CAP: usize = 256 * 1024;

    fn push(&self, bytes: &[u8]) {
        let mut buf = self.buf.lock().unwrap();
        buf.push_str(&String::from_utf8_lossy(bytes));
        if buf.len() > Self::CAP {
            // Trim on a char boundary: the tail is read as `&str`, and slicing
            // mid-codepoint would panic on a guest that prints UTF-8.
            let mut cut = buf.len() - Self::CAP;
            while cut < buf.len() && !buf.is_char_boundary(cut) {
                cut += 1;
            }
            *self.dropped.lock().unwrap() += cut;
            let kept = buf.split_off(cut);
            *buf = kept;
        }
    }

    fn text(&self) -> String {
        self.buf.lock().unwrap().clone()
    }
}

/// The running cold guest, as [`postboot`] needs to see it.
struct GuestConsole {
    input: console::ConsoleInput,
    tail: Arc<ConsoleTail>,
    running: Arc<AtomicBool>,
}

impl postboot::Console for GuestConsole {
    fn send(&self, bytes: &[u8]) {
        // The same path a keystroke takes — push to the FIFO, raise the receive
        // interrupt, wake a parked vCPU — rather than a second injection route
        // that could work when typing does not, or vice versa.
        (self.input)(bytes);
    }
    fn transcript(&self) -> String {
        self.tail.text()
    }
    fn stopped(&self) -> bool {
        !self.running.load(Ordering::Acquire) || console::shutdown_requested()
    }
}

/// Mark a vCPU powered off so a later `CPU_ON` is accepted rather than being
/// told `ALREADY_ON` for a core that is not running.
fn psci_mark_offline(slot: &CpuPowerSlot) {
    let (lock, cv) = &**slot;
    let mut st = lock.lock().unwrap();
    st.online = false;
    st.cpu_on = None;
    cv.notify_all();
}

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
    implied_egress: &[String],
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
                    return Err(format!(
                        "disk {} is smaller than one sector",
                        path.display()
                    ));
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
                        features: features::RING_INDIRECT_DESC
                            | features::RING_EVENT_IDX
                            | features::BLK_FLUSH,
                        num_queues: 1,
                        device_config: mmio::blk_config(nsectors),
                    },
                )
            }
            VirtioKind::Net => {
                // Deny-all unless the caller named destinations. This is
                // deliberately *stricter* than the resume path, which runs
                // unrestricted when a workspace has no policy file: a
                // rehydrated snapshot arrives expecting the network it was
                // captured with, but a cold guest is being described here for
                // the first time and nobody is owed a connection they have not
                // asked for. Measured on hardware: within 100 s of boot a stock
                // Ubuntu rootfs reaches for ntp/changelogs/entropy.ubuntu.com
                // and api.snapcraft.io unprompted. See `security-model.md` §1a.
                let mut policy = EgressPolicy::from_profile(
                    "deny",
                    &args.egress_allow,
                    &[],
                    "chm create --egress-allow",
                );
                // A credential rule's hosts are reachable by implication (V8.7),
                // each entry carrying the attribution into its own decisions.
                policy.allow_implied(implied_egress, "implied by --proxy-rules");
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
            "--kernel",
            "/tmp/Image",
            "--cpus",
            "4",
            "--memory",
            "2048",
            "--seconds",
            "7",
            "--cmdline",
            "console=ttyAMA0 quiet",
            "--dry-run",
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
        std::fs::File::open(p)
            .unwrap()
            .read_exact(&mut hdr)
            .unwrap();
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
            "--kernel",
            "/tmp/Image",
            "--egress-allow",
            "api.github.com:443",
        ]))
        .unwrap_err();
        assert!(e.contains("--net"), "error must name the missing flag: {e}");
    }

    #[test]
    fn disks_accumulate_in_order_and_net_is_off_by_default() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--disk",
            "/tmp/b.img",
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
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--cmdline",
            "console=ttyAMA0 root=/dev/vda2 ro",
        ]))
        .unwrap();
        assert_eq!(a.cfg.cmdline, "console=ttyAMA0 root=/dev/vda2 ro");
    }

    #[test]
    fn an_initramfs_suppresses_the_implied_root() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--initramfs",
            "/tmp/i.gz",
        ]))
        .unwrap();
        assert!(
            !a.cfg.cmdline.contains("root="),
            "an initramfs is the root fs: {:?}",
            a.cfg.cmdline
        );
    }

    /// Mirror what `--spec` does at `expand_spec`: render the document to argv,
    /// drop the leading `create` (we are already inside it), then append the
    /// caller's own flags — which is the ordering that gives a flag the last
    /// word, and the ordering a greedy `--post-boot` destroys.
    fn spliced(json: &str, caller: &[&str]) -> Vec<String> {
        let doc = SandboxSpec::parse(json, Path::new("t.json")).unwrap();
        let mut argv = resolve(Some(&doc), None, &Overrides::default()).to_create_argv();
        if argv.first().map(String::as_str) == Some("create") {
            argv.remove(0);
        }
        argv.extend(caller.iter().map(|s| (*s).to_string()));
        argv
    }

    /// The bug this milestone's own hardware run found, frozen as a test.
    ///
    /// `--spec` splices the spec's argv **before** the caller's flags so that a
    /// flag wins. `--post-boot` takes everything after it as the guest's
    /// command. Put those together and a spec with a `postBootCommand` eats
    /// every flag the operator typed: `chm create --spec … --dry-run` handed
    /// `--dry-run` to the guest and **booted a VM when asked to describe one**.
    ///
    /// So this asserts the consequence, not just the cause — the real parser
    /// must still see a flag that follows the whole spliced expansion.
    #[test]
    fn a_flag_after_a_spec_expansion_still_reaches_chm() {
        let argv = spliced(
            r#"{"specVersion":1,"postBootCommand":["echo","hi"],"env":{"A":"1"}}"#,
            &["--dry-run", "--kernel", "/dev/null"],
        );
        let a = parse(&argv).expect("a spliced argv must parse");
        assert!(a.dry_run, "the caller's own flag was swallowed: {argv:?}");
        assert_eq!(
            a.postboot.post_boot.as_deref(),
            Some(&["echo".to_string(), "hi".to_string()][..])
        );
        assert_eq!(a.postboot.env.get("A").map(String::as_str), Some("1"));
    }

    /// The override half: a spec says what the sandbox *is*, a flag says how
    /// *this run* differs, so a typed `--post-boot` replaces the spec's command
    /// rather than concatenating onto it and producing a third nobody asked for.
    #[test]
    fn a_typed_post_boot_replaces_the_specs_command() {
        let argv = spliced(
            r#"{"specVersion":1,"postBootCommand":["echo","from-spec"]}"#,
            &["--kernel", "/dev/null", "--post-boot", "echo", "from-flag"],
        );
        let a = parse(&argv).expect("must parse");
        assert_eq!(
            a.postboot.post_boot.as_deref(),
            Some(&["echo".to_string(), "from-flag".to_string()][..])
        );
    }

    /// A guest command is not obliged to avoid words `chm` uses as flags.
    #[test]
    fn a_guest_command_may_contain_our_own_flag_names() {
        let a = parse(&[
            "--kernel".into(),
            "/dev/null".into(),
            "--post-boot".into(),
            "sh".into(),
            "-c".into(),
            "--dry-run --cpus 9".into(),
        ])
        .expect("must parse");
        assert!(!a.dry_run);
        assert_eq!(a.postboot.post_boot.as_ref().unwrap().len(), 3);
    }
}
