// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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
use std::io::{stdin, IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io, thread};

use arch::aarch64::layout::LEGACY_RTC_MAPPED_IO_START;
use hypervisor::hvf::checkpoint::{self as hvf_checkpoint};
use hypervisor::hvf::devices::{MmioBus, Pl011, Pl031};
use hypervisor::hvf::rehydrate::MemMapping;
use hypervisor::hvf::virtio::block::{BlockDevice, FileBackend};
use hypervisor::hvf::virtio::devcore::{Backend, MsiSink, MsiSpiInjector};
use hypervisor::hvf::virtio::devmgr::{self, SerialRegs};
use hypervisor::hvf::virtio::mmio::{self, MmioParams, VirtioMmioDevice, device_id};
use hypervisor::hvf::virtio::nat::{EgressPolicy, INGRESS_BIND_ADDR, NatLimits, NatResponder};
use hypervisor::hvf::virtio::net::{NetDevice, NetKick};
use hypervisor::hvf::virtio::{GuestMemory, NetIo, features};
use hypervisor::hvf::{
    HvfHypervisor, UsgicCpuHandle, UsgicSpiRouter, VtimerClock, host_counter_hz, rehydrate,
};
use hypervisor::{Vcpu, VmExit, VmOps};

use crate::audit::{AuditLog, EgressTally};
use crate::coldboot::{ColdBootConfig, VirtioKind};
use crate::console::RawConsole;
use crate::imp::{
    CpuPowerSlot, IDLE_RESIDENCY_PERCENT, IdleResidency, NET_SERVICE_INTERVAL, PL011_BASE,
    PL011_SIZE, PsciCoordinator, UsgicCapture, apply_psci_cpu_on_state, collect_usgic_checkpoint,
    egress_posture_line, net_service_pass, wait_for_cpu_on_request,
};
use crate::oci::initramfs::installs_proxy_ca;
use crate::oci::modules;
use crate::runs;
use crate::spec::{Overrides, SandboxSpec, resolve, spec_file_for};
use crate::{bundle, checkpoint, coldboot, console, credproxy, genesis, postboot, serve};
/// The NAT gateway the guest talks to, and the MAC we hand its NIC.
///
/// Same subnet the restore path's NAT uses, so a guest image built for one
/// works unchanged on the other.
pub const GATEWAY_IP: [u8; 4] = [192, 168, 249, 1];
/// The address a guest is expected to hold.
///
/// The NAT does not enforce it -- its DNS socket binds to any address and the
/// relay translates whatever source it sees -- so this is a convention, and
/// convention is exactly why it has to be written down once. A captured guest
/// receives it from capture-side cloud-init; a container rootfs has no
/// cloud-init and no DHCP client, so the generated init assigns it, and the
/// two must agree or the guest is on the wrong subnet from its own gateway.
pub const GUEST_IP: [u8; 4] = [192, 168, 249, 2];
/// Prefix length of the subnet [`GATEWAY_IP`] and [`GUEST_IP`] share.
pub const GUEST_PREFIX_LEN: u8 = 24;
const GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

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
    /// Stop after this many seconds; `0` means no deadline.
    ///
    /// #305: this used to default to 30 unconditionally, so an operator sitting
    /// at a console we had just told to "press Ctrl-A x to end the session" got
    /// thirty seconds and then `stopped after 30s` — and asked another LLM what
    /// had gone wrong, because the number was the only thing we said. The
    /// principle was already written down one line from the default that broke
    /// it: an interactive session ends when the guest powers off or the
    /// operator asks, *not when a stopwatch the operator never set runs out*.
    ///
    /// So it now defaults by who is driving. A tty on stdin means a human is
    /// there to end it; a pipe means a script or the daemon, where an
    /// unattended cold boot that produces no output really is the normal early
    /// failure mode and a deadline is what stops it hanging CI.
    max_seconds: u64,
    /// Stop once the guest has been idle for this many seconds; `0` means no
    /// idle supervisor. Off by default: a cold boot is the interactive path,
    /// and stopping a session the operator never asked to have timed is the
    /// #305 mistake in a second place.
    ///
    /// "Idle" is measured, not inferred. Console silence alone is a guess --
    /// a guest compiling for ten minutes says nothing and is the busiest it
    /// will ever be -- so a silent window only counts when the vCPUs were
    /// parked in the host-side WFI path for most of it (#171, #403). This is
    /// deliberately *not* a preservation control: what survives the stop is
    /// `--originate`'s business, and it fires on this path exactly as it does
    /// on the `--seconds` one.
    idle_exit_secs: u64,
    /// Where to publish this guest's control socket, or `None` for no socket
    /// (#401).
    ///
    /// Cold boot's console was its only interface: the guest could be typed at
    /// by whoever held the terminal, and by nobody else. So `chm exec`,
    /// `chm ctl input/console/status` and `chm proxy ca --install` -- every
    /// tool that drives a sandbox -- worked on daemon-started guests and not on
    /// the one path a Mac with no snapshot can actually use. This publishes the
    /// running guest behind the same `VmInner` those verbs already read, so
    /// they serve it with no second implementation.
    socket: Option<PathBuf>,
    /// Hosts the guest may reach, as `host:port`. Empty means the default
    /// deny-all posture, which is what an unconfigured sandbox gets everywhere
    /// else in this tree (see `docs/security-model.md` §1a).
    egress_allow: Vec<String>,
    /// TCP ports *inside* the guest a process on this Mac may reach, each
    /// forwarded from its own ephemeral loopback port (V11.0, #330). Empty
    /// means nothing inside the guest is reachable, which is the posture every
    /// sandbox has had until now.
    expose: Vec<u16>,
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
    /// Where to write a snapshot of this guest when it stops (#341).
    ///
    /// Cold boot is the only way a machine comes into existence here, and until
    /// now it was also the only thing that could not produce a snapshot: every
    /// capture in this tree descends from one taken on Graviton, because
    /// `chm resume` can extend a lineage but nothing could *start* one. A
    /// checkpoint cannot do it either — `imp::load_snapshot` requires a
    /// `state.json` and a `memory-ranges` to apply a checkpoint *to*, so a
    /// checkpoint is a delta against a snapshot that must already exist.
    ///
    /// So this writes the real thing: a vanilla snapshot directory, in the
    /// layout `vanilla_export` produces and `chm run` reads.
    originate: Option<PathBuf>,
    /// `chm` flags a greedy `--post-boot` handed to the guest's command instead.
    ///
    /// Carried rather than printed from inside `parse` so the detection is
    /// reachable from a test that goes through the real parser -- the flag is
    /// swallowed by the parser, so a check that does not run the parser is
    /// checking something else.
    post_boot_swallowed: Vec<String>,
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
     \x20 --initrd <path>     Alias for --initramfs, for anyone arriving from\n\
     \x20                     a QEMU or libvirt command line.\n\
     \x20 --cmdline <str>     Kernel command line.\n\
     \x20 --cmdline-extra <s> One more word on the kernel command line, appended\n\
     \x20                     to whatever --cmdline said. Repeatable, so a spec\n\
     \x20                     or a script can add an argument without having to\n\
     \x20                     restate the whole line. A `root=` or\n\
     \x20                     `gimbal.epoch=` here counts as yours, and\n\
     \x20                     suppresses the one chm would have implied.\n\
     \x20 --cpus <n>          vCPUs (default 1).\n\
     \x20 --memory <MiB>      Guest RAM in MiB (default 1024).\n\
     \x20 --disk <path>       Raw disk image as virtio-blk. Repeatable; the\n\
     \x20                     first becomes /dev/vda.\n\
     \x20 --net               Attach a virtio-net NIC on the userspace NAT.\n\
     \x20 --egress-allow <h:p>  Permit egress to host:port. Repeatable.\n\
     \x20                     Without any, the NIC is up but reaches nothing\n\
     \x20                     beyond the hosts --proxy-rules implies.\n\
     \x20 --expose <port>     Make one TCP port inside the guest reachable\n\
     \x20                     from this Mac. Repeatable, one port each; there\n\
     \x20                     is no range and no wildcard. Each gets its own\n\
     \x20                     ephemeral 127.0.0.1 port, printed at start-up,\n\
     \x20                     so two sandboxes cannot collide. Loopback only.\n\
     \x20 --proxy-rules <path>  Credential-injection rules (see chm proxy).\n\
     \x20                     The hosts they name become reachable too:\n\
     \x20                     naming a host in a rule is the intent to reach\n\
     \x20                     it. Each implied allowance is printed.\n\
     \x20 --workspace <path>  Where the proxy CA and audit trail live.\n\
     \x20                     Defaults to the --proxy-rules file's own\n\
     \x20                     directory, because a CA is a trust root that\n\
     \x20                     has to outlive the run.\n\
     \x20 --seconds <n>       Stop after n seconds. Defaults to 0 (no deadline)\n\
     \x20                     when stdin is a terminal -- a session you are\n\
     \x20                     sitting at ends when you say so -- and to 30\n\
     \x20                     when it is a pipe, where an unattended boot that\n\
     \x20                     produces nothing would otherwise hang forever.\n\
     \x20 --idle-exit <n>     Stop once the guest has been idle for n seconds\n\
     \x20                     (default 0, off). Idle means measured idle: the\n\
     \x20                     console has been silent for n seconds *and* the\n\
     \x20                     vCPUs were parked for most of that window. A\n\
     \x20                     guest that is quietly compiling keeps running,\n\
     \x20                     and says so once per silent window.\n\
     \x20                     It decides when to stop, not what to keep: pass\n\
     \x20                     --originate as well to preserve the guest.\n\
     \x20 --socket <path>     Serve the daemon's control socket for this cold\n\
     \x20                     guest, so `chm exec`, `chm ctl input`, `chm ctl\n\
     \x20                     console`, `chm ctl status` and `chm proxy ca\n\
     \x20                     --install` reach it the same way they reach a\n\
     \x20                     guest started by `chm serve`. The library verbs\n\
     \x20                     (list, start, shutdown) are refused with a note\n\
     \x20                     saying where they do work: a cold boot has no\n\
     \x20                     library behind it. Put the socket under your\n\
     \x20                     home directory -- /tmp is a symlink on macOS and\n\
     \x20                     a private runtime dir may not be one.\n\
     \x20 --originate <dir>   Snapshot this guest into <dir> when it stops, as\n\
     \x20                     a cloud-hypervisor snapshot directory that\n\
     \x20                     `chm run <dir>` resumes. This is how a lineage\n\
     \x20                     starts on the Mac: every other capture here\n\
     \x20                     descends from one taken on a Graviton host,\n\
     \x20                     because resuming can extend a lineage but not\n\
     \x20                     begin one. Not usable with --dry-run.\n\
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
     \x20                     run differs. See `chm spec`.\n\
     \x20 --help              This text.\n"
        .to_string()
}

/// How long to run when nobody said, decided by who is driving.
///
/// A tty on stdin means an operator is sitting there and will end the session
/// themselves -- which is exactly what the console tells them to do. Giving
/// them a stopwatch as well contradicts our own message and, in the one report
/// we have of it, ended a working exploratory session at thirty seconds (#305).
///
/// A pipe means a script, CI, or the daemon. There, an unattended cold boot
/// that produces no output is the normal early failure mode and a deadline is
/// the thing that stops it hanging forever, so the old default stands.
///
/// Split out from [`parse`] so the decision is testable without a terminal.
fn default_max_seconds(stdin_is_tty: bool) -> u64 {
    if stdin_is_tty {
        0
    } else {
        30
    }
}

/// Parse one `--expose` value into the guest TCP port it names.
///
/// **Fails closed.** A bare decimal port in `1..=65535` and nothing else. Every
/// other shape people reasonably type — `7777/tcp`, `8080:7777`,
/// `127.0.0.1:7777`, `7000-7100` — means something specific in some other tool
/// and something *different* in each, so guessing here is guessing which port
/// of a sandbox becomes reachable from the host. The refusal says what the
/// value would have had to be, because "invalid" alone leaves the caller to
/// find out by experiment which of the four they typed.
fn parse_expose(raw: &str) -> Result<u16, String> {
    let port: u16 = raw.parse().map_err(|_| {
        format!(
            "--expose {raw}: expose takes one guest TCP port and nothing else, \
             as a plain number (--expose 7777). There is no host:guest form (the \
             host port is ephemeral and chm prints it), no /tcp suffix, and no \
             range: each port is named on its own."
        )
    })?;
    if port == 0 {
        return Err(
            "--expose 0: port 0 is the OS's word for \"choose one\", not a port \
             a guest can listen on. Name the port your program binds inside the \
             guest."
                .to_string(),
        );
    }
    Ok(port)
}

/// Every long option `parse` understands.
///
/// It exists for one reader: the note that tells you a greedy `--post-boot`
/// swallowed a flag you meant for `chm`. `create_flags_named_in_the_parser`
/// reads the parser's own match arms out of this file and requires each to
/// appear here, so a new flag cannot be added and quietly left out of the note.
const CREATE_FLAGS: &[&str] = &[
    "--kernel",
    "--initramfs",
    "--initrd",
    "--cmdline",
    "--cmdline-extra",
    "--proxy-rules",
    "--workspace",
    "--originate",
    "--cpus",
    "--memory",
    "--seconds",
    "--idle-exit",
    "--socket",
    "--disk",
    "--net",
    "--egress-allow",
    "--expose",
    "--env",
    "--post-boot",
    "--post-boot-arg",
    "--dry-run",
    "-h",
    "--help",
];

/// The `chm` flags a greedy `--post-boot` took as arguments to the guest's
/// command.
///
/// `--post-boot` has to be greedy -- the guest's command is entitled to its own
/// `--dry-run` and we cannot know it was not meant for the guest. But being
/// *right* is not the same as being *legible*: `--originate` typed after it
/// produced no lineage, no error and an exit status of 0, and the only trace was
/// the guest echoing our own flag back inside its argv. So say what happened.
///
/// Pure, and it returns the flags rather than a sentence, so the decision is
/// testable without a console and the phrasing can change without the test.
fn post_boot_swallowed_chm_flags(argv: &[String]) -> Vec<String> {
    argv.iter()
        .filter(|a| CREATE_FLAGS.contains(&a.as_str()))
        .cloned()
        .collect()
}

fn parse(raw: &[String]) -> Result<CreateArgs, String> {
    let mut cfg = ColdBootConfig::default();
    let mut dry_run = false;
    let mut max_seconds = default_max_seconds(stdin().is_terminal());
    let mut idle_exit_secs = 0u64;
    let mut socket: Option<PathBuf> = None;
    let mut kernel: Option<PathBuf> = None;
    let mut egress_allow: Vec<String> = Vec::new();
    let mut expose: Vec<u16> = Vec::new();
    let mut cmdline_extra: Vec<String> = Vec::new();
    let mut proxy_rules: Option<PathBuf> = None;
    let mut workspace: Option<PathBuf> = None;
    let mut originate: Option<PathBuf> = None;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut post_boot: Option<Vec<String>> = None;
    let mut post_boot_swallowed: Vec<String> = Vec::new();

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
            "--originate" => {
                originate = Some(PathBuf::from(value("--originate")?));
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
            "--idle-exit" => {
                idle_exit_secs = value("--idle-exit")?
                    .parse()
                    .map_err(|e| format!("--idle-exit: {e}"))?;
            }
            "--socket" => socket = Some(PathBuf::from(value("--socket")?)),
            "--disk" => cfg.disks.push(PathBuf::from(value("--disk")?)),
            "--net" => cfg.net = true,
            "--egress-allow" => egress_allow.push(value("--egress-allow")?),
            "--expose" => {
                let port = parse_expose(&value("--expose")?)?;
                // Ambiguous rather than harmless: the same port named twice
                // would get two host ports, and nothing would say which one the
                // caller meant to hand out.
                if expose.contains(&port) {
                    return Err(format!(
                        "--expose {port} was given twice; each guest port is \
                         exposed once, on one host port"
                    ));
                }
                expose.push(port);
            }
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
                post_boot_swallowed = post_boot_swallowed_chm_flags(&rest);
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
    if !expose.is_empty() && !cfg.net {
        return Err(
            "--expose needs --net; there is no NIC for a host connection to arrive on".into(),
        );
    }
    if proxy_rules.is_some() && !cfg.net {
        return Err("--proxy-rules needs --net; there is no traffic to intercept".into());
    }
    // Only when the caller's own command line does not name a root filesystem.
    //
    // The rule used to be `!cmdline_explicit` -- *any* `--cmdline` at all
    // suppressed this -- and that is the same false analogy #224 fixed for the
    // wall clock, one field over. Naming a console is not choosing a root
    // device. A caller who passes `--disk` has already said what they want
    // mounted, and there is no command line for which "and therefore this guest
    // has no root filesystem" is the intent; the kernel's only report is
    // `VFS: Unable to mount root fs`, which reads as a broken disk image.
    //
    // Measured blast radius, same as #224's: the app emits
    // `--cmdline console=ttyAMA0` on every cold boot, so every app-started
    // guest with a disk and no initramfs took the suppressed path.
    //
    // A caller who writes `root=` themselves is still taken at their word, and
    // then owns the mount flags that travel with it.
    let root_set = coldboot::mentions_root(&cfg.cmdline)
        || cmdline_extra.iter().any(|e| coldboot::mentions_root(e));
    if !root_set && let Some(extra) = coldboot::implied_root_args(&cfg) {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    // The guest's wall clock. Appended on the same terms and for the same
    // reason: it is a fact about the moment this guest is booting, not a choice
    // the caller made differently.
    // Suppressing it here was a real, measured bug rather than a hypothetical:
    // the app emits `--cmdline console=ttyAMA0` on every cold boot, so every
    // app-started guest took this branch. On a kernel with PL031 builtin the
    // guest reads the RTC and nobody notices; on one without — Ubuntu's arm64
    // generic kernel — the guest silently starts at the epoch and *every* TLS
    // handshake fails with "certificate is not yet valid", which reads as a
    // broken network. So the safety net was disabled in precisely the
    // configuration where it was the only thing that could work.
    //
    // A caller who writes `gimbal.epoch=` themselves is taken at their word.
    let epoch_set = coldboot::mentions_epoch(&cfg.cmdline)
        || cmdline_extra.iter().any(|e| coldboot::mentions_epoch(e));
    if !epoch_set && let Some(extra) = coldboot::epoch_arg(SystemTime::now()) {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    for extra in &cmdline_extra {
        cfg.cmdline = format!("{} {extra}", cfg.cmdline);
    }
    // `--dry-run` returns before a VM exists, so there would be no machine to
    // describe and no RAM to dump. Refusing beats writing nothing and exiting 0,
    // which reads as "originated" to any script checking the status.
    if dry_run && originate.is_some() {
        return Err("--originate needs a running guest to snapshot, and \
                    --dry-run stops before one is created. Drop one of them."
            .to_string());
    }
    // A synthesized `state.json` now carries a node per virtio device, so a
    // guest's disks are described rather than silently dropped. The refusal
    // that used to stand here (#341, lifted by #378) exists no more.
    Ok(CreateArgs {
        cfg,
        dry_run,
        max_seconds,
        idle_exit_secs,
        socket,
        egress_allow,
        expose,
        proxy_rules,
        workspace,
        postboot: postboot::Plan { env, post_boot },
        originate,
        post_boot_swallowed,
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

    if !args.post_boot_swallowed.is_empty() {
        let named = args.post_boot_swallowed.join(" ");
        eprintln!(
            "chm: note: --post-boot takes every remaining word as the guest's \
             command, so {named} went to the guest and not to chm. If you meant \
             it for chm, put it before --post-boot; if you meant it for the \
             guest, this is already what you asked for. (--post-boot-arg takes \
             one argv element at a time and is not greedy.)"
        );
    }

    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("chm create: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The CA archive to append to this run's initramfs, if there is one to append.
///
/// Deliberately silent and `None` in every case where a CA is not clearly
/// wanted: no `--proxy-rules` at all, a rules file that resolves to nothing, or
/// a workspace whose CA has not been generated yet. A first run generates the
/// CA when the proxy starts, which is after this point -- so the honest answer
/// there is that this guest does not have one, not a boot failure.
///
/// Only for container guests. A rehydrated snapshot's filesystem is the user's,
/// and this appends to an initramfs chm itself wrote; there is no initramfs on
/// the rehydrate path to append to.
fn ca_archive_for(args: &CreateArgs) -> Result<Option<Vec<u8>>, String> {
    let Some(rules) = args.proxy_rules.as_deref() else {
        return Ok(None);
    };
    if args.cfg.initramfs.is_none() {
        return Ok(None);
    }
    // The same workspace derivation the proxy itself uses below. Two
    // derivations would eventually disagree, and the symptom would be a CA
    // installed in the guest that does not match the one intercepting its
    // traffic -- a TLS failure that names neither.
    let Some(ws) = args
        .workspace
        .clone()
        .or_else(|| rules.parent().map(Path::to_path_buf))
    else {
        return Ok(None);
    };
    credproxy::cli::ca_cpio_for(&ws)
}

/// Why a run that a control client stopped ended, for the operator watching
/// this console -- who is not necessarily the person who issued the stop.
///
/// Every other ending explains itself: the idle and deadline arms, and the
/// guest's own message. A `chm ctl stop` landed in the bare `None`
/// fall-through and printed *nothing at all*, which is a worse version of the
/// dead end #304/#305/#306 each closed -- not a true sentence with no next
/// step, but no sentence. Reachable only since #401 gave cold boot a socket,
/// so it is this change's to fix.
///
/// A value rather than an inline `println!` so the prose is testable: the
/// three things it must say are what make it useful, and asserting them
/// against source text cannot survive the line wrapping.
fn client_stop_report(socket: Option<&Path>, originating: bool) -> String {
    let where_from = socket.map_or_else(
        || "the control socket".to_string(),
        |p| format!("`chm ctl stop` on {}", p.display()),
    );
    let kept = if originating {
        "--originate ran after the guest halted, so this run was preserved."
    } else {
        "Nothing was preserved: a stop chooses when to stop, --originate \
         chooses what to keep."
    };
    format!(
        "chm create: stopped on request -- {where_from}, so it was neither the \
         guest halting nor a deadline expiring.\n  {kept}"
    )
}

/// What `chm ctl status` should call this guest.
///
/// A cold boot is named by nothing -- there is no library entry to take a name
/// from -- so use the directory the kernel came out of, which is what the
/// operator picked and will recognise (`~/gimbal-images/final-alpine` reads back
/// as `final-alpine`).
fn cold_guest_name(args: &CreateArgs) -> String {
    args.cfg
        .kernel
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "cold-boot".to_string())
}

/// The directory `posture`, `proxy` and `audit` should assess for this guest.
///
/// The same derivation the credential proxy uses below, deliberately: two
/// derivations would eventually disagree, and `chm proxy ca --install` over this
/// socket would then install a CA from one place while the proxy intercepted
/// with another.
fn cold_guest_dir(args: &CreateArgs) -> PathBuf {
    args.workspace
        .clone()
        .or_else(|| {
            args.proxy_rules
                .as_deref()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

fn run(args: &CreateArgs) -> Result<ExitCode, String> {
    // The credential proxy's CA has to be in the rootfs before the rootfs is in
    // guest RAM, and `build` below is what puts it there. So this is resolved
    // first, even though the proxy itself does not start until the NIC exists.
    //
    // A CA that arrives later cannot help: the guest's init reads it during
    // boot, and by the time the proxy starts the kernel has already unpacked
    // the archive it was given.
    let ca_cpio = ca_archive_for(args)?;
    if ca_cpio.is_some()
        && let Some(initramfs) = args.cfg.initramfs.as_deref()
        && !installs_proxy_ca(initramfs)
    {
        // The installer lives in the generated init, which is written once at
        // `chm image build` (#266). We are staging a CA into an image whose init
        // predates it: the file will be there and nothing will install it, and
        // the user meets `certificate verify failed` -- the exact error the
        // installer exists to prevent -- with no message either way.
        //
        // Said here rather than left to the guest because the guest cannot know:
        // the code that would have reported it is the code that is missing.
        eprintln!(
            "chm: warning: this image's init predates the proxy CA installer, so the CA \n\
             chm: will be staged at {} and never trusted. HTTPS through the proxy will \n\
             chm: fail a certificate check. Rebuild the image with `chm image build` to fix it.",
            credproxy::cli::CA_PATH,
        );
    }

    let t_build = Instant::now();
    // The only field that differs from `args.cfg`, and the only consumer of it
    // is `build`. Everything below reads `args.cfg`, which is identical in
    // every respect that any of it looks at.
    let mut cfg = coldboot::ColdBootConfig {
        initramfs_append: ca_cpio,
        ..args.cfg.clone()
    };
    if cfg.initramfs_append.is_some() {
        cfg.cmdline = format!("{} {}=1", cfg.cmdline, coldboot::CA_SENT_KEY);
    }
    let image = coldboot::build(&cfg)?;
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
    // An initramfs has to be resident twice while the kernel unpacks it -- the
    // archive itself, plus the rootfs it is writing into page cache -- and only
    // then is the archive freed. Exceed that and the kernel stops unpacking
    // *silently*: the guest boots, the rootfs looks complete, and whatever was
    // at the tail is simply absent. Measured on node:22-slim at 768 MiB, where
    // the appended CA archive vanished with no message from anything.
    //
    // A warning rather than a refusal, because this is a heuristic about the
    // guest's memory and the threshold is calibrated from three measurements,
    // not derived. Refusing a boot that would have worked is worse than warning
    // about one that does.
    if let Some((_, size)) = image.initramfs_placed {
        let ram = args.cfg.memory_mib << 20;
        if size * 4 > ram {
            println!(
                "  NOTE       the initramfs is {:.0} MiB of the guest's {} MiB. The \
                 kernel needs it and its\n             unpacked copy resident at once, \
                 and stops unpacking without saying so if it\n             cannot: \
                 files at the end of the archive then simply do not exist.\n\
                 \x20            Give it more memory with --memory if something is missing.",
                size as f64 / (1u64 << 20) as f64,
                args.cfg.memory_mib
            );
        }
    }
    // `cfg`, not `args.cfg`: the CA flag is added above and the printed command
    // line has to be the one the guest is actually given.
    println!("  cmdline    {}", cfg.cmdline);
    println!("  built in   {build_ms:.1} ms");

    // Only when a device was actually asked for: that is the moment the request
    // and what the guest will see diverge. Placed here, immediately under the
    // device table, because that block is where someone looks to check the NIC
    // they asked for was attached -- and it will say it was.
    if args.cfg.net || !args.cfg.disks.is_empty() {
        let kernel_bytes = fs::read(&args.cfg.kernel)
            .map_err(|e| format!("cannot read kernel `{}`: {e}", args.cfg.kernel.display()))?;
        // An initramfs built by `chm image build --modules` carries the
        // drivers this kernel lacks. Warning about them anyway would be
        // telling someone to fix something already fixed, in the same breath
        // as the device table that is about to work -- and a warning that is
        // wrong gets the next true one read the same way.
        let bundled = args
            .cfg
            .initramfs
            .as_deref()
            .map(modules::bundled_in_initramfs)
            .unwrap_or_default();
        let supplied: Vec<&str> = bundled.iter().map(String::as_str).collect();
        if let Some(w) = coldboot::VirtioBuiltin::scan(&kernel_bytes)
            .satisfied_by(&supplied)
            .warning()
        {
            println!("\n  NOTE: {w}");
        }
    }

    if args.dry_run {
        println!("chm create: --dry-run, not starting a VM");
        return Ok(ExitCode::SUCCESS);
    }

    let hv = HvfHypervisor::new().map_err(|e| format!("Hypervisor.framework unavailable: {e}"))?;

    // Announce the run now that a VM is genuinely being created, and hold the
    // registration for the rest of this function. Before this point there is
    // nothing to report; after `--dry-run` returns there never will be.
    //
    // The label comes from the image directory rather than the kernel file,
    // because every image has a kernel called `Image` and a list of six rows
    // all saying "Image" is a list that tells you nothing.
    let image_dir = args
        .cfg
        .kernel
        .parent()
        .unwrap_or(&args.cfg.kernel)
        .to_path_buf();
    let _registration = runs::register(
        runs::Kind::Cold,
        &runs::label_for(&image_dir),
        &image_dir.display().to_string(),
        args.cfg.vcpus.into(),
        args.cfg.memory_mib,
        &args.expose,
    )
    .unwrap_or_else(|e| {
        // A registry that cannot be written is a guest you cannot see, not a
        // guest you cannot have. Say so and carry on.
        eprintln!("chm: warning: could not record this run: {e}");
        None
    });

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
    // When something has to be delivered into the guest (#190) or a control
    // client has to be able to read it (#401), that thread also *tees* what it
    // printed into a bounded ring, because `take_output` consumes and a second
    // reader would steal bytes from the operator's own screen.
    //
    // One ring serves both, and it is the daemon's own `VmInner`: `--socket`
    // then reuses `handle_conn` verbatim rather than growing a second
    // implementation of the exec framing, the input path and the console
    // buffer. The tee is `None` on every other run, so a plain `chm create`
    // allocates nothing and behaves exactly as before.
    let control: Option<Arc<serve::ColdControl>> = match &args.socket {
        Some(path) => Some(Arc::new(serve::ColdControl::bound(
            &cold_guest_name(args),
            cold_guest_dir(args),
            path.clone(),
        )?)),
        None if !args.postboot.is_empty() => Some(Arc::new(serve::ColdControl::detached())),
        None => None,
    };
    // Unlike the tail, this is armed on every run: a panic is exactly the
    // outcome a caller most needs to hear about, and it costs one scan of bytes
    // that are being copied to stdout anyway.
    let panic_watch = Arc::new(PanicWatch::default());
    // Bumped once per batch of guest output. The idle supervisor watches this
    // rather than sharing an `Instant`: it only needs to know *that* the guest
    // spoke since it last looked, and a counter needs no lock on a path that
    // copies bytes to a terminal.
    //
    // The console thread is the only observer of guest output in this process,
    // so this is the only place the fact is available at all.
    let spoke = Arc::new(AtomicU64::new(0));
    let console = {
        let uart = uart.clone();
        let running = running.clone();
        let control = control.clone();
        let panic_watch = panic_watch.clone();
        let spoke = spoke.clone();
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
                    if let Some(c) = &control {
                        c.push(&bytes);
                    }
                    panic_watch.push(&bytes);
                    spoke.fetch_add(1, Ordering::Release);
                    let _ = out.write_all(&bytes);
                    let _ = out.flush();
                }
                let rest = uart.take_output();
                if !rest.is_empty() {
                    if let Some(c) = &control {
                        c.push(&rest);
                    }
                    panic_watch.push(&rest);
                    spoke.fetch_add(1, Ordering::Release);
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
    // The parked-nanoseconds counter travels the same way and for the same
    // reason: `wfi_parked_ns()` can only be read from the vCPU it belongs to,
    // and the idle supervisor that reads it lives on the orchestrator. It is
    // what makes `--idle-exit` a measurement rather than a guess about silence.
    type CpuReport = (
        usize,
        UsgicCpuHandle,
        Option<Arc<dyn Fn() + Send + Sync>>,
        Option<Arc<AtomicU64>>,
    );
    let (setup_tx, setup_rx) = mpsc::channel::<Result<CpuReport, String>>();
    // The origination capture channel (#341). `Some` only when `--originate`
    // asked for a snapshot, so an ordinary cold boot does no capture work at
    // all rather than doing it and throwing the result away.
    //
    // `collect_usgic_checkpoint` waits for exactly one capture per vCPU, so a
    // thread that takes any path out without sending would hang the collector
    // rather than fail it. That is why the capture below sits at a single exit
    // point every path funnels through, instead of at the end of the run loop.
    //
    // The receiver is held apart from the sender so the orchestrator's own
    // sender can be dropped once every thread has its clone. Keeping it alive
    // would defeat the collector's only escape: `recv()` fails when the last
    // sender goes, and a sender nobody sends on keeps the channel open forever.
    // The single exit point is the belt; this is the braces, and it is what
    // turns "origination hung after the guest ran perfectly" into an error that
    // names the vCPU.
    let (capture_tx, capture_rx) = if args.originate.is_some() {
        let (tx, rx) = mpsc::channel::<(usize, UsgicCapture)>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
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
        let capture_tx = capture_tx.clone();
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
                    let parked = vcpu.wfi_parked_ns();
                    if setup_tx.send(Ok((id, handle, exit, parked))).is_err() {
                        return;
                    }
                    drop(setup_tx);
                    // A dropped sender means the orchestrator gave up on setup.
                    let Ok(table) = go_rx.recv() else { return };
                    rehydrate::usgic_set_cpu_table(&mut vcpu, table);

                    // Everything that runs the guest lives in this closure, so
                    // that every way out of it -- a secondary the kernel never
                    // turned on, a failed CPU_ON, a run error, a clean
                    // power-off -- arrives at the single capture below.
                    //
                    // `collect_usgic_checkpoint` waits for exactly one capture
                    // per vCPU, so a path that returned straight out of the
                    // thread instead would *hang* origination rather than fail
                    // it, at the end of a boot that had otherwise worked. A
                    // never-onlined secondary is not an edge case here: a guest
                    // given four vCPUs that brings up one leaves three parked,
                    // and all four still have to appear in the snapshot.
                    let run_guest = |vcpu: &mut Box<dyn Vcpu>| {
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
                                Ok(VmExit::Shutdown) => {
                                    *outcome.lock().unwrap() = Some(Ok("guest powered off".into()));
                                    running.store(false, Ordering::Release);
                                    break;
                                }
                                Ok(VmExit::Reset) => {
                                    // Not the same event, and conflating them is
                                    // what let a kernel panic read as a clean
                                    // stop: a panic reboots, so it arrives here.
                                    // `chm create` does not restart the guest, so
                                    // this is still the end of the run.
                                    *outcome.lock().unwrap() = Some(Ok("guest reset".into()));
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
                    };
                    run_guest(&mut vcpu);

                    // The capture runs here because HVF register reads are only
                    // valid from the vCPU's owning thread -- the same reason
                    // `imp`'s suspend path captures on the vCPU thread and
                    // assembles on the orchestrator. It is taken after the run
                    // loop has left, so the vCPU is idle and nothing is going to
                    // change underneath it.
                    if let Some(tx) = capture_tx {
                        let captured = hvf_checkpoint::capture_usgic_vcpu(&mut vcpu)
                            .map_err(|e| format!("{e:#}"));
                        // Sent whether it succeeded or failed. The collector
                        // counts messages and names the failing vCPU, so
                        // dropping a failed capture would turn a legible error
                        // into a silent wait for a message that never comes.
                        let _ = tx.send((id, captured));
                    }

                    // A secondary that stops must be marked off, or the kernel
                    // sees ALREADY_ON if it retries.
                    psci_mark_offline(&slot);
                })
                .map_err(|e| format!("spawning vCPU thread {id}: {e}"))?,
        );
    }
    drop(setup_tx);
    // Every thread now holds its own clone, so this one can go. See the channel's
    // construction: the collector's only way to fail rather than wait forever is
    // for the last sender to disappear.
    drop(capture_tx);

    // Collect every vCPU's handle, in id order: the SGI table is indexed by
    // vCPU id, and the channel does not promise arrival order.
    let mut handles: Vec<Option<UsgicCpuHandle>> = (0..vcpus).map(|_| None).collect();
    let mut exits: Vec<Option<Arc<dyn Fn() + Send + Sync>>> = (0..vcpus).map(|_| None).collect();
    // Indexed by id like the others, though the idle supervisor only ever sums
    // it: a residency figure is about the machine, not about any one core.
    let mut all_parked: Vec<Option<Arc<AtomicU64>>> = (0..vcpus).map(|_| None).collect();
    for _ in 0..vcpus {
        match setup_rx.recv() {
            Ok(Ok((id, h, exit, parked))) => {
                handles[id] = Some(h);
                exits[id] = exit;
                all_parked[id] = parked;
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
        // Collected before the loop rather than shared behind a lock: every
        // vCPU has already reported in by here (the `setup_rx` drain above is
        // synchronous), so the set is complete and never changes again.
        let exits: Vec<Arc<dyn Fn() + Send + Sync>> = exits.iter().flatten().cloned().collect();
        // A workspace is where an audit trail can live; without one the handle
        // records nothing. Draining is *not* conditional on that, because the
        // NAT buffers every decision until somebody takes them — an undrained
        // cold boot grows that buffer for the life of the guest, and `--seconds
        // 0` is the shape this path is normally run in.
        let audit = args
            .workspace
            .as_deref()
            .map(AuditLog::open)
            .unwrap_or_default();
        Some(
            thread::Builder::new()
                .name("cold-net".into())
                .spawn(move || {
                    await_ready(&ready);
                    // Deduplicates, so a page opening eighty connections to one
                    // allowed host writes one record rather than eighty.
                    let mut tally = EgressTally::default();
                    while running.load(Ordering::Acquire) {
                        let delivered = net_service_pass(
                            net_devices.iter().map(|d| d.as_ref() as &dyn NetIo),
                            &mut tally,
                            &audit,
                        );
                        if delivered {
                            // The frame is in the ring and the SPI is raised,
                            // but a vCPU parked in WFI does not see either until
                            // something takes it out of `hv_vcpu_run`. Waiting
                            // for its own poll to expire is a latency the guest
                            // pays on every inbound packet.
                            for exit in &exits {
                                exit();
                            }
                            // And go straight round again: a bulk transfer is
                            // many chains, and sleeping the interval between
                            // them caps inbound throughput at one chain per
                            // interval no matter how much is waiting.
                            continue;
                        }
                        kick.wait(NET_SERVICE_INTERVAL);
                    }
                    // The per-flow lines above are the detail; without this the
                    // trail has no totals, so a reader cannot tell a complete
                    // record from a truncated one.
                    audit.egress_summary(&tally);
                })
                .map_err(|e| format!("spawning the net service thread: {e}"))?,
        )
    };

    // Publish the guest's two control channels (#401).
    //
    // `input` is the same injector the console pump uses, deliberately: a second
    // route into the FIFO could work when typing does not, or vice versa, and
    // the symptom would be a socket that appears to work and delivers nothing.
    // `kick` forces every vCPU out of `hv_vcpu_run` so a `stop` lands on a guest
    // that is sitting in a trap rather than waiting for it to come out on its
    // own. Both here rather than at construction because `exits` only exists
    // once every vCPU has reported in.
    if let Some(c) = &control {
        let kicks: Vec<Arc<dyn Fn() + Send + Sync>> = exits.iter().flatten().cloned().collect();
        c.publish(
            console::console_input(uart.clone(), sink.clone(), None, coldboot::PL011_IRQ),
            Arc::new(move || {
                for kick in &kicks {
                    kick();
                }
            }),
        );
    }

    // Deliver what the spec asked to happen inside the guest, on its own thread
    // so the orchestrator's deadline loop keeps running: readiness can take a
    // minute on a slow boot, and a `--seconds` promise must not become a hope
    // because we were blocked waiting for a shell.
    //
    // It starts *after* the stdin pump is installed, so an operator watching the
    // console sees the delivery happen rather than finding it already done.
    let postboot_result: Arc<Mutex<Option<Result<postboot::Report, postboot::Failure>>>> =
        Arc::new(Mutex::new(None));
    // Gated on the plan, not on the ring: `--socket` arms the ring too, and
    // spawning a delivery thread with nothing to deliver would drive a console
    // probe into a guest whose operator asked for neither.
    let postboot_thread = match (&control, args.postboot.is_empty()) {
        (Some(control), false) => {
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
                control: control.clone(),
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
        _ => None,
    };

    // A panicked guest that never resets is the one case with no other way out:
    // `running` stays true because no vCPU ever exits, and `--seconds 0` means
    // no deadline will fire either. See `PANIC_SILENCE_GRACE`.
    //
    // Only when nobody is driving. On a tty the operator can see the panic on
    // their own screen and end the session themselves, and tearing down a
    // session someone is sitting at -- on the strength of a string the guest
    // printed -- is a worse failure than waiting. Same "who is driving?"
    // distinction as `default_max_seconds`, and for the same reason.
    let unattended = !stdin().is_terminal();
    // `--idle-exit 0` means no idle supervisor, the same way `--seconds 0` means
    // no deadline.
    let idle = (args.idle_exit_secs > 0).then(|| Duration::from_secs(args.idle_exit_secs));
    let mut residency = IdleResidency::new(&all_parked);
    let mut last_output = Instant::now();
    let mut last_spoke = spoke.load(Ordering::Acquire);
    // One explanation per silent window, not one per 50 ms poll. Cleared when
    // the guest speaks, so a second quiet stretch is reported again.
    let mut withheld = false;
    // Distinguishes this stop from the `--seconds` one in the report below.
    // `timed_out` cannot tell them apart: both leave `running` true with no
    // shutdown requested.
    let mut stopped_idle = false;
    // A control client asked this guest to stop (#401). Read as a closure so
    // the loop condition names the question rather than the plumbing, and so a
    // run with no socket pays nothing for it.
    let stop_asked = || control.as_ref().is_some_and(|c| c.stop_requested());
    while running.load(Ordering::Acquire)
        && deadline.is_none_or(|d| Instant::now() < d)
        && !console::shutdown_requested()
        && !stop_asked()
        && !(unattended && panic_watch.settled_after_panic(PANIC_SILENCE_GRACE, Instant::now()))
    {
        thread::sleep(Duration::from_millis(50));
        let Some(idle) = idle else { continue };
        // The console thread bumped its counter, so the guest said something
        // since the last poll: the silent window starts again from here.
        let now_spoke = spoke.load(Ordering::Acquire);
        if now_spoke != last_spoke {
            last_spoke = now_spoke;
            last_output = Instant::now();
            residency.restart();
            withheld = false;
            continue;
        }
        let silent_for = last_output.elapsed();
        residency.trace(silent_for);
        if silent_for < idle {
            continue;
        }
        match residency.idle_over(silent_for) {
            // Silent and genuinely parked: the guest is waiting, not working.
            // `None` is "no vCPU publishes a counter" -- a missing instrument is
            // not evidence of busyness, and the pre-#171 behaviour was to stop
            // on silence alone, so this is where that lands.
            Some(true) | None => {
                stopped_idle = true;
                break;
            }
            // Silent but running guest code -- a compile, an agent thinking, a
            // package resolve. Console silence was the only thing that ever made
            // this look idle, and it was wrong.
            Some(false) => {
                if !withheld {
                    withheld = true;
                    eprintln!(
                        "[idle] guest silent for {}s but its vCPUs were parked only {}% of it \
                         (idle needs {}%), so it is working, not idle -- not stopping",
                        silent_for.as_secs(),
                        residency.percent_over(silent_for),
                        IDLE_RESIDENCY_PERCENT,
                    );
                }
            }
        }
    }
    // Only a deadline that actually expired counts as a timeout; an operator
    // ending the session is a normal exit, not a run that overran. Nor is an
    // idle stop, which has its own report, nor a `chm ctl stop`, which is the
    // same deliberate ending arriving over a socket instead of a keyboard.
    //
    // `!stopped_idle` is redundant *today*: the idle arm below is matched
    // first, so this value is never read on an idle stop. It is kept so the
    // two stops are exclusive by predicate rather than by position, and it is
    // recorded here that removing it fires no test -- the arm order is what
    // `the_idle_stop_reports_itself_rather_than_the_deadline` actually guards.
    let stopped_by_client = stop_asked();
    let timed_out = running.load(Ordering::Acquire)
        && !console::shutdown_requested()
        && !stopped_idle
        && !stopped_by_client;
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

    // Take the control socket down and record why the guest ended (#401).
    //
    // After the joins, because a `stop` client blocks until the status says
    // `Stopped` and the honest moment to say so is once the vCPUs have actually
    // gone -- but before `--originate` below, which can take a while on a large
    // guest and must not hold a client waiting on a machine that has already
    // halted.
    if let Some(c) = &control {
        c.finish(if stopped_by_client {
            "stopped on request"
        } else if stopped_idle {
            "stopped idle"
        } else if timed_out {
            "deadline expired"
        } else {
            "guest ended"
        });
    }

    // #341. This is the only window where both things are true at once: every
    // vCPU has stopped and delivered its state, and guest RAM is still mapped.
    // `drop(prepared)` two statements below unmaps it.
    //
    // Skipped when the guest itself failed. A snapshot of a machine that died
    // mid-run is not a lineage anyone wants to descend from, and the guest's own
    // error is the more useful thing to report — writing the snapshot anyway
    // would bury it behind a capture failure it probably caused.
    if let (Some(dir), Some(capture_rx)) = (args.originate.as_deref(), capture_rx.as_ref()) {
        let guest_failed = matches!(*outcome.lock().unwrap(), Some(Err(_)));
        if guest_failed {
            eprintln!(
                "chm: not originating {}: the guest failed, and a snapshot of a \
                 machine that did not finish starting is not one to build on.",
                dir.display()
            );
        } else {
            originate_snapshot(
                dir,
                capture_rx,
                vcpus,
                &OriginatedRam {
                    mem: &prepared.guest_mem,
                    base: image.ram_base,
                    size: image.ram_size as u64,
                },
                // Read off the live device the guest programmed, at the last
                // moment it is still the machine being described.
                uart.capture(),
                &devices,
            )?;
        }
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
    // The console has been fully drained by now -- `console.join()` is above --
    // so these are the last word rather than a race with a line still in flight.
    //
    // A dirty rootfs is a warning about a *previous* run, so it is printed
    // alongside whatever this run did rather than replacing it. A panic is about
    // this run, and outranks whatever the exit reason looked like.
    if panic_watch.unchecked_fs() {
        println!("\nchm create: {}", unchecked_fs_report());
    }
    if panic_watch.panicked() {
        return Err(panic_report());
    }
    match result {
        Some(Ok(msg)) => {
            println!("\nchm create: {msg}");
            Ok(ExitCode::SUCCESS)
        }
        Some(Err(e)) => Err(e),
        None if stopped_idle => {
            println!(
                "\nchm create: stopped after {}s idle -- the --idle-exit supervisor, not \
                 the guest.\n  The guest was silent and its vCPUs were parked for at least \
                 {}% of that window, so it was waiting rather than working.\n  Use \
                 `--idle-exit N` to allow longer, or `--idle-exit 0` for no idle \
                 supervisor.{}",
                args.idle_exit_secs,
                IDLE_RESIDENCY_PERCENT,
                if args.originate.is_some() {
                    ""
                } else {
                    "\n  Nothing was preserved: --idle-exit chooses when to stop, and \
                     --originate chooses what to keep."
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        None if timed_out => {
            println!(
                "\nchm create: stopped after {}s -- the --seconds deadline, not the \
                 guest.\n  The guest was running and has been torn down. Use \
                 `--seconds N` to allow longer, or `--seconds 0` for no deadline.",
                args.max_seconds
            );
            Ok(ExitCode::SUCCESS)
        }
        None if stopped_by_client => {
            println!(
                "\n{}",
                client_stop_report(args.socket.as_deref(), args.originate.is_some())
            );
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::SUCCESS),
    }
}

/// Release everyone waiting on the vCPU thread's setup, whether it succeeded or
/// not: a failed vCPU still has to unblock the threads that would otherwise
/// wait out the whole deadline for it.
/// Notices the two kernel lines a caller must not miss, as the console streams
/// past.
///
/// **The panic.** A panic and a deliberate `reboot` both leave through PSCI
/// `SYSTEM_RESET`, so [`VmExit`] cannot tell them apart -- the console is the
/// only channel that names one.
///
/// **The unchecked filesystem.** A guest that was power-cut rather than stopped
/// leaves its rootfs marked dirty, and the kernel says so on the *next* boot.
/// Nothing surfaced it, so the damage announced itself only to a reader of the
/// scrollback -- and there is no `e2fsck` on macOS to answer it with, which is
/// exactly why the user needs to be told while they still have the choice.
///
/// Reading the console is trusting guest output, which is why this changes only
/// what is *reported*: a guest that prints these lines without meaning them has
/// misdescribed its own console, and repeating what it said is still the honest
/// answer.
///
/// Streaming rather than buffered, because unlike [`ConsoleTail`] this runs on
/// every guest: it keeps only enough of the previous write to catch a line split
/// across two.
#[derive(Default)]
struct PanicWatch {
    panicked: AtomicBool,
    unchecked_fs: AtomicBool,
    carry: Mutex<String>,
    /// When the console last produced any output at all. `None` until the first
    /// byte arrives, so a guest that has never spoken is never mistaken for one
    /// that has fallen silent.
    last_output: Mutex<Option<Instant>>,
}

impl PanicWatch {
    /// The stable half of `Kernel panic - not syncing: <reason>`. The reason
    /// varies with the cause (`Attempted to kill init!`, `VFS: Unable to mount
    /// root fs`); this prefix comes from `panic()` itself.
    const PANIC: &'static str = "Kernel panic - not syncing";
    /// `ext4_fill_super` emits this when the superblock's `EXT4_VALID_FS` bit is
    /// clear, i.e. the previous mount was never cleanly ended.
    const UNCHECKED: &'static str = "mounting unchecked fs";

    fn push(&self, bytes: &[u8]) {
        self.push_at(bytes, Instant::now());
    }

    /// The body of [`push`](Self::push) with the clock supplied, so the silence
    /// window is testable without sleeping for it.
    fn push_at(&self, bytes: &[u8], now: Instant) {
        *self.last_output.lock().unwrap() = Some(now);
        let mut carry = self.carry.lock().unwrap();
        carry.push_str(&String::from_utf8_lossy(bytes));
        for (needle, flag) in [
            (Self::PANIC, &self.panicked),
            (Self::UNCHECKED, &self.unchecked_fs),
        ] {
            if carry.contains(needle) {
                flag.store(true, Ordering::Relaxed);
            }
        }
        // Keep only what a line straddling this write could still need.
        let keep = Self::PANIC.len().max(Self::UNCHECKED.len()) - 1;
        if carry.len() > keep {
            let mut cut = carry.len() - keep;
            // Trim on a char boundary: a guest can print UTF-8, and splitting
            // mid-codepoint would panic in here rather than report one.
            while cut < carry.len() && !carry.is_char_boundary(cut) {
                cut += 1;
            }
            let kept = carry.split_off(cut);
            *carry = kept;
        }
    }

    fn panicked(&self) -> bool {
        self.panicked.load(Ordering::Relaxed)
    }

    fn unchecked_fs(&self) -> bool {
        self.unchecked_fs.load(Ordering::Relaxed)
    }

    /// Whether a panic has been seen and the console has said nothing since,
    /// for at least `grace`.
    ///
    /// Two conditions, not one, and the second is what makes this safe to act
    /// on. `Kernel panic - not syncing` is matched as a substring of guest
    /// output, so a guest that merely *prints* the words trips the flag -- and
    /// a guest still printing is a guest still running. Silence after the fact
    /// is the part that says the kernel actually stopped.
    fn settled_after_panic(&self, grace: Duration, now: Instant) -> bool {
        self.panicked()
            && self
                .last_output
                .lock()
                .unwrap()
                .is_some_and(|at| now.duration_since(at) >= grace)
    }
}

/// How long a panicked guest must stay silent before `chm` stops waiting on it.
///
/// A panic is only fatal to the run when the kernel *halts*, and it halts only
/// when the command line carries no `panic=N`. With one, the guest resets, the
/// vCPU threads see it, and the ordinary exit path runs long before this does --
/// so this is the backstop for the case where nothing else can ever fire.
///
/// Fifteen seconds is chosen to sit clear of a slow console drain while still
/// being a bound a person will wait through. It is deliberately not tuneable:
/// a knob here would be a knob for how long to wait for something that is never
/// coming.
const PANIC_SILENCE_GRACE: Duration = Duration::from_secs(15);

/// What to say about a guest that panicked.
///
/// Named as an error rather than folded into the success message because the
/// exit status is the only part a script reads, and reporting a panic as `0` is
/// the specific defect this exists to close.
fn panic_report() -> String {
    "the guest kernel panicked; the run did not end cleanly.\n  \
     A panic reboots immediately, so anything the guest had not written to disk \
     is gone, and\n  a writable rootfs is left marked dirty -- the next boot \
     will report an unchecked\n  filesystem, and there is no e2fsck on macOS to \
     repair it with.\n  The panic reason is in the console output above, on the \
     `Kernel panic - not syncing` line."
        .into()
}

/// What to say about a guest whose rootfs arrived dirty.
fn unchecked_fs_report() -> String {
    "the guest reported `mounting unchecked fs` -- this disk was power-cut \
     rather than\n  stopped, by an earlier run. Its rootfs may carry lost \
     inodes, and there is no\n  e2fsck on macOS to repair it. Rebuild the image \
     if the guest starts misbehaving."
        .into()
}

/// The running cold guest, as [`postboot`] needs to see it.
///
/// Reads its transcript out of the same [`ColdControl`] ring a control client
/// reads over the socket (#401), so the two cannot disagree about what the guest
/// said.
struct GuestConsole {
    input: console::ConsoleInput,
    control: Arc<serve::ColdControl>,
    running: Arc<AtomicBool>,
}

impl postboot::Console for GuestConsole {
    fn send(&self, bytes: &[u8]) {
        // The same path a keystroke takes — push to the FIFO, raise the receive
        // interrupt, wake a parked vCPU — rather than a second injection route
        // that could work when typing does not, or vice versa.
        (self.input)(bytes);
    }
    fn transcript(&self) -> Vec<u8> {
        self.control.transcript()
    }
    fn stopped(&self) -> bool {
        !self.running.load(Ordering::Acquire)
            || console::shutdown_requested()
            || self.control.stop_requested()
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

/// Arm one loopback listener per `--expose`d guest port and report each one.
///
/// The ports are reported rather than returned because they are the *only*
/// thing the caller can act on: the host port is ephemeral by design (so two
/// sandboxes cannot collide) and nobody can dial a number they were not told.
/// A failure to bind is fatal — a guest booting without the port somebody asked
/// for is a sandbox that silently is not the one they asked for.
fn expose_guest_ports(mut nat: NatResponder, ports: &[u16]) -> Result<NatResponder, String> {
    for &port in ports {
        let exposure = nat.expose(SocketAddrV4::new(Ipv4Addr::from(GUEST_IP), port))?;
        eprintln!(
            "chm: ingress {}:{} -> guest {} (loopback only)",
            INGRESS_BIND_ADDR,
            exposure.host_port,
            exposure.guest
        );
    }
    Ok(nat)
}

/// Write a cloud-hypervisor snapshot directory describing the guest that has
/// just stopped, giving a lineage its first link (#341).
///
/// Until this existed, every snapshot in this tree descended from one taken on a
/// Graviton host: `chm resume` can extend a lineage and `vanilla_export` can send
/// one back to the cloud, but neither can *begin* one, and a checkpoint cannot
/// either — `imp::load_snapshot` requires a `state.json` and a `memory-ranges`
/// to apply a checkpoint to, so a checkpoint is a delta against a snapshot that
/// already exists.
///
/// The output is therefore the real article rather than a chm-private format:
/// the same layout [`crate::vanilla_export`] produces, which means the artefact
/// is vanilla by construction instead of by later conversion.
///
/// MUST be called after every vCPU thread has joined (so all the captures have
/// been sent, and nothing is still changing the machine) and before `prepared`
/// is dropped (which unmaps guest RAM).
///
/// `devices` is the same vector the bus was built from, so the windows recorded
/// in the document are the windows the guest's drivers are bound to rather than
/// a second derivation of them.
/// The guest's memory, and where the guest sees it.
///
/// One fact about one machine rather than three parameters, for the reason the
/// `mappings` comment below gives: the dump and the document that describes it
/// must be two uses of a single value, never two descriptions of it. Three
/// separate arguments let a caller pass the memory of one machine with the base
/// address of another, and the result is a snapshot that parses, validates,
/// resumes, and has the guest's RAM in the wrong place.
struct OriginatedRam<'a> {
    mem: &'a GuestMemory,
    base: u64,
    size: u64,
}

fn originate_snapshot(
    dir: &Path,
    capture_rx: &mpsc::Receiver<(usize, UsgicCapture)>,
    vcpus: usize,
    ram: &OriginatedRam<'_>,
    serial: SerialRegs,
    devices: &[(coldboot::VirtioPlacement, Arc<VirtioMmioDevice>)],
) -> Result<(), String> {
    // Refuse rather than merge: writing into a directory that already holds a
    // snapshot would leave a `state.json` from this run beside a
    // `memory-ranges` from another, which is a machine that never existed and
    // resumes without complaining.
    if dir.exists()
        && dir
            .read_dir()
            .map_err(|e| format!("reading {}: {e}", dir.display()))?
            .next()
            .is_some()
    {
        return Err(format!(
            "{} already exists and is not empty. Originating into it would mix \
             this guest's state with whatever is already there; name a new \
             directory.",
            dir.display()
        ));
    }

    // The same assembler the suspend path uses, not a second one: two
    // assemblers would be two chances to write a shape only one of them reads.
    let state = collect_usgic_checkpoint(capture_rx, COLD_NR_IRQS, vcpus)?;

    // `prepare_cold_usgic_vm` maps exactly one contiguous region, into slot 0,
    // at the start of the dump. This single value then goes to both consumers:
    // `dump_guest_ram` to decide where each byte goes, and `genesis::synthesize`
    // to record where each byte came from. Handing them one value rather than
    // two descriptions of it is the whole design — if those two ever disagreed,
    // the snapshot would parse, validate, resume, and have the guest's memory in
    // the wrong place, which no test of our writer against our own reader could
    // see.
    let mappings = vec![MemMapping {
        slot: 0,
        gpa: ram.base,
        size: ram.size,
        file_offset: 0,
    }];

    // A cold guest read the host's real `CNTFRQ_EL0` at boot, so that is the
    // frequency the snapshot must declare: a restore that assumes a different
    // one runs the guest's clock at the wrong rate.
    //
    // The console's interrupt line is passed for the same reason and is read
    // from the one place that decides it: `spawn_stdin_pump` above asserts
    // `coldboot::PL011_IRQ`, so a capture claiming anything else would describe
    // a machine this one never was. Restating the number here would let the two
    // drift into a snapshot whose console is deaf.
    // Read off the live transports at the same instant the vCPUs stopped, and
    // paired with the placement each was registered at. Both halves come from
    // the objects the machine actually ran on: nothing here recomputes a window
    // from `coldboot`'s constants, so a device node cannot describe a machine
    // this one was not.
    let virtio: Vec<genesis::VirtioNode> = devices
        .iter()
        .map(|(place, dev)| genesis::VirtioNode {
            transport: dev.state(),
            base: place.base,
            size: place.size,
            intid: place.intid,
            backing: place.path.as_ref().map(|p| p.display().to_string()),
        })
        .collect();

    let genesis = genesis::synthesize(
        &state,
        &mappings,
        host_counter_hz(),
        serial,
        coldboot::PL011_IRQ,
        &virtio,
    )?;

    // Read the document back and count what it describes, rather than trusting
    // that it describes what was handed over. The two sides come from different
    // places on purpose: `devices` is the machine that just stopped, and the
    // count is parsed out of the bytes about to be written. A change that stops
    // devices reaching the synthesizer moves the synthesizer's inputs and its
    // outputs together, so no assertion about the rendering can see it -- but
    // the machine still had disks, and this comparison still fails.
    let described = genesis::virtio_nodes_in(&genesis.bytes)?;
    if described != devices.len() {
        return Err(format!(
            "this guest ran {} virtio device(s) but the snapshot describes {}. \
             Resuming it would hand the guest's kernel a machine missing the \
             devices its drivers are bound to; refusing rather than writing a \
             lineage that cannot come back.",
            devices.len(),
            described
        ));
    }

    let snapshot = dir.join("snapshot");
    fs::create_dir_all(&snapshot).map_err(|e| format!("creating {}: {e}", snapshot.display()))?;

    // The disks travel with the RAM, at the instant the RAM was taken. A
    // cold-booted guest's kernel has its filesystem's metadata cached in the
    // pages about to be dumped, so resuming that RAM against anything other
    // than the disk it was cached from is the ext4 metadata-mismatch failure
    // mode (roadmap V6.7): the guest reads `Input/output error` on files it can
    // see in its own page cache. RAM and disk are captured together or neither
    // is worth having.
    let shipped = ship_disks(dir, &virtio)?;

    // cloud-hypervisor ships `state.json` at both the root and inside
    // `snapshot/`, and different readers reach for different ones, so both are
    // written from the same bytes rather than serialized twice.
    for p in [dir.join("state.json"), snapshot.join("state.json")] {
        fs::write(&p, &genesis.bytes).map_err(|e| format!("writing {}: {e}", p.display()))?;
    }
    let ranges = snapshot.join("memory-ranges");
    // `None`: there is no parent dump to delta against. A lineage's first
    // snapshot is by definition the one with nothing behind it.
    checkpoint::dump_guest_ram(&ranges, ram.mem, &mappings, None)?;

    verify_shipped_disks(dir, &String::from_utf8_lossy(&genesis.bytes), shipped)?;

    println!(
        "chm: originated {} ({} vCPU(s), {} MiB, {} IRQs, {} disk(s))",
        dir.display(),
        vcpus,
        ram.size >> 20,
        genesis.num_irq,
        shipped
    );
    for line in &genesis.vcpu_summaries {
        println!("chm:   {line}");
    }
    // Printed, not buried: the caller is about to be told a snapshot exists, and
    // what it does not carry is part of what it is. Saying nothing here would
    // let the artefact's shape imply a completeness it does not have.
    for w in &genesis.warnings {
        println!("chm: note: {w}");
    }
    Ok(())
}

/// Confirm the restore path can find every disk the document describes.
///
/// This asks the *reader*, not the writer. [`devmgr::parse_mmio_devices`] is
/// the parser a resume will use to decide which devices exist, and
/// [`devmgr::shipped_backing`] is what it will then call to find each disk --
/// so both halves of the restore path are run against the bytes just written,
/// rather than against the values that produced them.
///
/// A check against the caller's own device list could not do this. Shipping a
/// disk under a name the reader does not compute moves the writer's input and
/// its output together, so every assertion about the writer stays true while
/// the resume silently falls back to a sparse zero overlay and the guest comes
/// back to a disk full of holes. This comparison fails exactly then, and it
/// fails just as well if the shipping step stops being called at all -- which
/// no assertion about `ship_disks`'s own behaviour can see.
pub(crate) fn verify_shipped_disks(
    dir: &Path,
    state_json: &str,
    shipped: usize,
) -> Result<(), String> {
    let overlay_dir = dir.join(checkpoint::live_overlays_dir_name());
    let mut found = 0;
    for desc in devmgr::parse_mmio_devices(state_json)
        .map_err(|e| format!("reading back the snapshot just written: {e}"))?
    {
        if !matches!(desc.backend, devmgr::BackendKind::Block { .. }) {
            continue;
        }
        match devmgr::shipped_backing(&overlay_dir, &desc.name) {
            Ok(Some(_)) => found += 1,
            Ok(None) => {
                return Err(format!(
                    "the snapshot describes a disk for `{}` but a resume would \
                     find no image for it, so the guest would come back on an \
                     empty overlay against RAM that has its filesystem cached. \
                     Refusing rather than writing a lineage that reads as corrupt.",
                    desc.name
                ));
            }
            Err(e) => {
                return Err(format!(
                    "checking the shipped disk for `{}`: {e}",
                    desc.name
                ));
            }
        }
    }
    if found != shipped {
        return Err(format!(
            "shipped {shipped} disk image(s) but a resume would find {found}. \
             Refusing rather than writing a lineage whose disks are not the ones \
             this guest ran."
        ));
    }
    Ok(())
}

/// Ship a copy of every disk the guest was running, where a resume will look.
///
/// The location is not computed here: [`devmgr::shipped_backing_candidates`] is
/// the reader's own view of the layout, and its first entry is the canonical
/// write target. Two descriptions of one path is how a writer comes to put a
/// real disk somewhere the restore path never looks.
///
/// `clonefile` is what makes capturing the disk at the same instant as the RAM
/// affordable: an APFS clone shares every extent, so a 25 GiB disk costs
/// ~0 bytes and is frozen from the moment it is taken even though the caller's
/// own file stays writable. A symlink would be free too and is not an option --
/// the restore path refuses one by name as a possibly tampered bundle, and it
/// is right to, because a link is a promise about a file that can be broken
/// after the promise is made.
///
/// Returns how many images were written.
pub(crate) fn ship_disks(dir: &Path, nodes: &[genesis::VirtioNode]) -> Result<usize, String> {
    let overlay_dir = dir.join(checkpoint::live_overlays_dir_name());
    let mut shipped = 0;
    for node in nodes {
        // A node with no backing file is not a disk -- the net device has none.
        let Some(src) = node.backing.as_deref() else {
            continue;
        };
        let src = Path::new(src);
        let dest = devmgr::shipped_backing_candidates(&overlay_dir, &node.transport.name)
            .into_iter()
            .next()
            .ok_or_else(|| {
                format!(
                    "cannot place a shipped disk relative to {}",
                    overlay_dir.display()
                )
            })?;
        // Sanitization maps several device names onto one filename, so two
        // devices can collide here. Refuse: letting the second clone overwrite
        // the first would hand one guest disk to two drivers, and the resume
        // would look entirely well-formed.
        if dest.exists() {
            return Err(format!(
                "device `{}` would ship its disk to {}, which is already taken \
                 by another device whose name sanitizes the same way. Refusing \
                 rather than letting one guest disk replace another.",
                node.transport.name,
                dest.display()
            ));
        }
        let parent = dest
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", dest.display()))?;
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
        if let Err(e) = bundle::clone_file(src, &dest) {
            // Not fatal on its own: `clonefile` only works within one APFS
            // volume, and a disk sitting on another filesystem still has to
            // travel. Copying is slow and correct; refusing would be neither.
            // Said out loud because the cost is the user's to know about.
            println!("chm: note: {e}; copying the disk instead, which is slower");
            fs::copy(src, &dest).map_err(|e| {
                format!("copying disk {} to {}: {e}", src.display(), dest.display())
            })?;
        }
        shipped += 1;
    }
    Ok(shipped)
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
                // Same sentence, same function as the resume path. Two renderings
                // of one posture drift, and the drift is invisible: both look
                // like a correct report of a sandbox that is not the one running.
                eprintln!("chm: {}", egress_posture_line(Some(&policy)));
                let responder =
                    NatResponder::new(GATEWAY_IP, GATEWAY_MAC, policy, NatLimits::default());
                let responder = expose_guest_ports(responder, &args.expose)?;
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
    /// chm knows both numbers before the guest boots, so a silently-dropped
    /// tail can be predicted rather than discovered inside a TLS error.
    #[test]
    fn a_cold_boot_says_so_when_the_initramfs_will_not_fit_twice_in_ram() {
        let src = include_str!("create.rs");
        let needle = format!("if {} * 4 > {} {{", "size", "ram");
        assert!(
            src.contains(&needle),
            "the warning must compare the archive against the guest's RAM; the \
             kernel needs the archive and its unpacked copy resident at once"
        );
        assert!(
            src.contains("stops unpacking without saying so"),
            "the note has to say the kernel is silent, or a reader will assume \
             a missing file would have been reported"
        );
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
        // The caller's words, in order and unaltered. The clock is appended
        // after them, so this asserts the prefix rather than equality.
        assert!(
            a.cfg.cmdline.starts_with("console=ttyAMA0 quiet"),
            "cmdline was {:?}",
            a.cfg.cmdline
        );
        assert!(a.dry_run);
    }

    /// #305. Our first outside tester was exploring a working shell when the
    /// session ended with `stopped after 30s`, and had to ask another LLM why.
    /// The principle was already written down beside the deadline -- "not when
    /// a stopwatch the operator never set runs out" -- and the default
    /// contradicted it.
    ///
    /// A tty means someone is there and the console has already told them how
    /// to leave. A pipe means CI or the daemon, where a silent cold boot really
    /// does need a deadline; that case keeps the old default, so this cannot
    /// hang an unattended run.
    #[test]
    fn an_operator_at_a_terminal_is_not_given_a_stopwatch_they_never_set() {
        assert_eq!(
            default_max_seconds(true),
            0,
            "0 means no deadline: an interactive session ends when the operator says"
        );
        assert_eq!(
            default_max_seconds(false),
            30,
            "a script or the daemon still gets a deadline, or a silent boot hangs it"
        );
    }

    /// The number alone is what sent the tester elsewhere for an answer, so the
    /// message has to carry what they went looking for: that the deadline was
    /// ours rather than the guest's, what became of the guest, and the flags
    /// that change it.
    ///
    /// The bar is our own egress line, which they praised in the same session
    /// and resolved unaided: it names the rule, the reason, and the flag.
    ///
    /// The anchor is deliberately the `-- the` that follows the number rather
    /// than the number alone: #404 added a second `stopped after {}s` message
    /// above this one, and the shorter needle silently began describing that
    /// one instead. A needle that matches in more than one place cannot detect
    /// its removal from the one that matters.
    #[test]
    fn the_deadline_message_says_whose_deadline_it_was_and_how_to_change_it() {
        let src = include_str!("create.rs");
        let anchor = format!("chm create: stopped after {{}}s -- {}", "the");
        assert_eq!(
            src.matches(anchor.as_str()).count(),
            1,
            "the anchor must name exactly one message, or this guard describes \
             a message nobody meant it to"
        );
        let (_, after) = src
            .split_once(anchor.as_str())
            .expect("the deadline message is still here");
        let msg = &after[..500.min(after.len())];

        for needed in ["--seconds 0", "--seconds N", "torn down", "not the"] {
            assert!(
                msg.contains(needed),
                "the deadline message must mention {needed:?}"
            );
        }
    }

    /// The idle stop has a different cause and a different remedy, so it needs
    /// its own sentence rather than the deadline's -- otherwise a caller who
    /// never passed `--seconds` is told their `--seconds` deadline expired and
    /// goes looking for a flag they did not set.
    #[test]
    fn the_idle_message_says_it_was_the_supervisor_and_what_it_measured() {
        let src = include_str!("create.rs");
        let anchor = format!("chm create: stopped after {{}}s {}", "idle");
        let (_, after) = src
            .split_once(anchor.as_str())
            .expect("the idle message is still here");
        let msg = &after[..600.min(after.len())];

        for needed in [
            "--idle-exit N",
            "--idle-exit 0",
            "parked",
            "waiting rather than working",
        ] {
            assert!(
                msg.contains(needed),
                "the idle message must mention {needed:?}"
            );
        }
        assert!(
            msg.contains("Nothing was preserved"),
            "a stop that keeps nothing must say so, or the silence reads as a \
             snapshot that was taken"
        );
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
    fn expose_takes_a_bare_port_and_refuses_every_other_shape() {
        // Fail closed. Each of these means something in *some* tool and
        // something different in each, so a guess here is a guess about which
        // port of a sandbox becomes reachable from this Mac. The refusal has to
        // name the form that would have worked, or the caller finds out by
        // experiment.
        let ok = parse(&args(&[
            "--kernel", "/tmp/Image", "--net", "--expose", "7777", "--expose", "9222",
        ]))
        .unwrap();
        assert_eq!(ok.expose, vec![7777, 9222], "each named port, in order");

        for bad in [
            "7777/tcp",
            "8080:7777",
            "127.0.0.1:7777",
            "7000-7100",
            "cdp",
            "",
            "-1",
            "70000",
        ] {
            let e = parse(&args(&["--kernel", "/tmp/Image", "--net", "--expose", bad]))
                .unwrap_err();
            assert!(
                e.contains("--expose") && e.contains("plain number"),
                "`--expose {bad}` must refuse and say what would work: {e}"
            );
        }

        let zero = parse(&args(&["--kernel", "/tmp/Image", "--net", "--expose", "0"])).unwrap_err();
        assert!(zero.contains("choose one"), "port 0 must be refused: {zero}");
    }

    #[test]
    fn exposing_the_same_port_twice_is_ambiguous_and_refused() {
        let e = parse(&args(&[
            "--kernel", "/tmp/Image", "--net", "--expose", "7777", "--expose", "7777",
        ]))
        .unwrap_err();
        assert!(e.contains("twice"), "{e}");
    }

    #[test]
    fn expose_without_a_nic_is_a_parse_error_not_a_silent_no_op() {
        // Same reasoning as --egress-allow: accepting it would promise a
        // reachable port to a guest that has no NIC for the connection to
        // arrive on, and the caller would only find out by curling it.
        let e = parse(&args(&["--kernel", "/tmp/Image", "--expose", "7777"])).unwrap_err();
        assert!(e.contains("--net"), "error must name the missing flag: {e}");
    }

    #[test]
    fn nothing_inside_a_guest_is_reachable_unless_it_was_named() {
        // The opt-in half of the contract, stated as a property of the default:
        // a guest with a NIC and no --expose has no inbound surface at all.
        let a = parse(&args(&["--kernel", "/tmp/Image", "--net"])).unwrap();
        assert!(
            a.expose.is_empty(),
            "a sandbox is reachable from the host only where somebody said so"
        );
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
            a.cfg.cmdline.contains("root=/dev/vda rw"),
            "cmdline was {:?}",
            a.cfg.cmdline
        );
        assert!(a.cfg.cmdline.contains("console=ttyAMA0"), "default kept");
    }

    #[test]
    fn an_explicit_cmdline_still_gets_a_clock() {
        // The bug this exists to prevent: the app emits `--cmdline
        // console=ttyAMA0` on every cold boot, and the epoch used to be
        // suppressed whenever a cmdline was given -- so the safety net was off
        // in exactly the case that needed it. A guest at the epoch fails every
        // TLS handshake with "certificate is not yet valid", which reads as a
        // network fault.
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--cmdline",
            "console=ttyAMA0",
        ]))
        .unwrap();
        let key = crate::coldboot::EPOCH_KEY;
        let secs = a
            .cfg
            .cmdline
            .split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} on {:?}", a.cfg.cmdline))
            .parse::<u64>()
            .expect("epoch is a decimal number");
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(secs.abs_diff(now) < 60, "cmdline says {secs}");
        // The caller's own words survive untouched.
        assert!(a.cfg.cmdline.contains("console=ttyAMA0"));
    }

    #[test]
    fn a_caller_who_sets_the_clock_themselves_keeps_it() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--cmdline",
            "console=ttyAMA0 gimbal.epoch=42",
        ]))
        .unwrap();
        let key = crate::coldboot::EPOCH_KEY;
        let mine: Vec<_> = a
            .cfg
            .cmdline
            .split_whitespace()
            .filter(|w| w.starts_with(&format!("{key}=")))
            .collect();
        // Exactly one, and theirs. Two keys would leave which one wins to the
        // init's parse order, which is not a thing a caller should have to know.
        assert_eq!(mine, ["gimbal.epoch=42"], "on {:?}", a.cfg.cmdline);
    }

    #[test]
    fn a_console_argument_is_not_mistaken_for_a_clock() {
        assert!(!crate::coldboot::mentions_epoch("console=ttyAMA0 root=/dev/vda"));
        assert!(crate::coldboot::mentions_epoch("console=ttyAMA0 gimbal.epoch=7"));
        // A key that merely ends with ours is a different key.
        assert!(!crate::coldboot::mentions_epoch("not.gimbal.epoch=7"));
    }

    #[test]
    fn a_cold_guest_is_told_what_time_it_is() {
        let a = parse(&args(&["--kernel", "/tmp/Image"])).unwrap();
        let key = crate::coldboot::EPOCH_KEY;
        let secs = a
            .cfg
            .cmdline
            .split_whitespace()
            .find_map(|w| w.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} on {:?}", a.cfg.cmdline))
            .parse::<u64>()
            .expect("epoch is a decimal number");
        // Bounded rather than merely present: a key carrying a garbage or
        // zero value would satisfy a `contains` check and still leave the
        // guest at the epoch, which is the whole failure being prevented.
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            secs.abs_diff(now) < 60,
            "cmdline says {secs}, host says {now}"
        );
    }

    #[test]
    fn an_explicit_cmdline_is_never_given_a_second_root() {
        // The caller may have chosen a different root deliberately; appending
        // a second root= would silently override it. The clock is appended
        // (it is a fact, not a choice -- see the parse site), so this asserts
        // the property that actually matters rather than exact equality.
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--cmdline",
            "console=ttyAMA0 root=/dev/vda2 ro",
        ]))
        .unwrap();
        let roots: Vec<_> = a
            .cfg
            .cmdline
            .split_whitespace()
            .filter(|w| w.starts_with("root="))
            .collect();
        assert_eq!(roots, ["root=/dev/vda2"], "on {:?}", a.cfg.cmdline);
        assert!(a.cfg.cmdline.starts_with("console=ttyAMA0 root=/dev/vda2 ro"));
    }

    #[test]
    fn an_explicit_cmdline_without_a_root_still_gets_one() {
        // The bug (#389): the rule was `!cmdline_explicit`, so *any* `--cmdline`
        // suppressed the derived `root=`. Naming a console is not choosing a
        // root device, and the kernel's only report is `VFS: Unable to mount
        // root fs`, which reads as a broken disk image. The app emits
        // `--cmdline console=ttyAMA0` on every cold boot, so this was the
        // ordinary path, not a corner.
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--cmdline",
            "console=ttyAMA0 quiet",
        ]))
        .unwrap();
        let roots: Vec<_> = a
            .cfg
            .cmdline
            .split_whitespace()
            .filter(|w| w.starts_with("root="))
            .collect();
        assert_eq!(roots, ["root=/dev/vda"], "on {:?}", a.cfg.cmdline);
        assert!(
            a.cfg.cmdline.starts_with("console=ttyAMA0 quiet"),
            "the caller's own line is kept intact: {:?}",
            a.cfg.cmdline
        );
    }

    #[test]
    fn a_root_in_cmdline_extra_also_suppresses_the_implied_one() {
        // `--cmdline-extra` is appended after this decision is taken, so a root
        // named there has to be consulted here or the guest gets two.
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/a.img",
            "--cmdline-extra",
            "root=/dev/vda3",
        ]))
        .unwrap();
        let roots: Vec<_> = a
            .cfg
            .cmdline
            .split_whitespace()
            .filter(|w| w.starts_with("root="))
            .collect();
        assert_eq!(roots, ["root=/dev/vda3"], "on {:?}", a.cfg.cmdline);
    }

    #[test]
    fn a_key_that_merely_ends_in_root_is_not_a_root() {
        // Word-and-key-wise, not a substring search. `dm-mod.create=...` and
        // friends genuinely appear on real command lines, and treating one as a
        // root would put us back at the panic this all exists to prevent.
        for theirs in ["vroot=/dev/x", "myroot=/dev/x", "rootwait"] {
            let a = parse(&args(&[
                "--kernel",
                "/tmp/Image",
                "--disk",
                "/tmp/a.img",
                "--cmdline",
                theirs,
            ]))
            .unwrap();
            assert!(
                a.cfg.cmdline.contains("root=/dev/vda"),
                "{theirs:?} is not a root assignment, so one is still owed: {:?}",
                a.cfg.cmdline
            );
        }
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

    /// A guard is worth nothing if production stops calling it.
    ///
    /// Six times in this repo a rule has been correct, tested, and unreachable
    /// because the call site quietly stopped consulting it -- and an assertion
    /// about an *outcome* structurally cannot see a path that is no longer
    /// taken. Every test below reads a generated init or an emitted archive, so
    /// `run` resolving the CA and then discarding it leaves all of them green.
    ///
    /// The needles are assembled from parts on purpose: a literal would match
    /// this test's own source and pass while `run` did nothing at all.
    #[test]
    fn the_resolved_ca_reaches_the_guest_rather_than_being_computed_and_dropped() {
        let src = include_str!("create.rs");
        let resolved = format!("let {} = {}(args)?;", "ca_cpio", "ca_archive_for");
        assert!(
            src.contains(&resolved),
            "`run` must resolve the CA archive; without this the proxy still \
             starts and the guest never learns to trust it"
        );
        let carried = format!("{}: {},", "initramfs_append", "ca_cpio");
        assert!(
            src.contains(&carried),
            "the resolved archive must reach the boot config -- resolving it and \
             dropping it costs nothing visible and breaks every guest"
        );
        let flagged = format!("{}, coldboot::{}_KEY)", "cfg.cmdline", "CA_SENT");
        assert!(
            src.contains(&flagged),
            "the command line must say a CA was sent, or the init cannot tell \
             `no proxy was asked for` from `the archive was lost in the boot`"
        );
    }

    /// The stale-image warning (#266) is a side effect, so no assertion about a
    /// return value can see it stop happening. This repo has lost that exact
    /// bet seven times now, so the call site itself is the thing pinned.
    ///
    /// The needle is assembled from parts so it cannot match this test's own
    /// text and pass by reading itself.
    #[test]
    fn create_still_checks_whether_the_image_installs_the_ca() {
        let src = include_str!("create.rs");
        let needle = format!("{}{}", "installs_proxy", "_ca(initramfs)");
        assert!(
            src.contains(&format!("!{needle}")),
            "create must still ask the archive whether its init installs the CA, and act \
             on the answer; without it a pre-#238 image fails a certificate check in silence"
        );
    }

    /// A denial the guest was told about must also survive the guest.
    ///
    /// The console print is a stream nobody is watching once the VM stops; the
    /// audit trail is the only channel that can answer "what did this sandbox
    /// try to reach" afterwards. Before this, the cold-boot path opened no
    /// `AuditLog` at all, so `--workspace`'s own help text ("Where the proxy CA
    /// and audit trail live") over-promised on every `chm create`.
    #[test]
    fn a_denied_flow_reaches_the_audit_trail() {
        let dir = std::env::temp_dir().join(format!("chm-egaudit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit = crate::audit::AuditLog::open(&dir);
        let mut tally = crate::audit::EgressTally::default();

        crate::audit::record_egress(
            vec![egress_event("dns", "neverssl.com", false)],
            &mut tally,
            &audit,
        );

        let trail = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        assert!(
            trail.contains(r#""event":"egress-deny""#) && trail.contains("neverssl.com"),
            "a refused destination must be named in audit.jsonl, got: {trail}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One page can open eighty connections to one host. Eighty identical lines
    /// would bury the one refusal a reader is looking for.
    #[test]
    fn a_repeated_decision_is_recorded_once() {
        let dir = std::env::temp_dir().join(format!("chm-egdedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit = crate::audit::AuditLog::open(&dir);
        let mut tally = crate::audit::EgressTally::default();

        for _ in 0..80 {
            crate::audit::record_egress(
                vec![egress_event("tcp", "10.0.0.1:443", true)],
                &mut tally,
                &audit,
            );
        }

        let trail = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        let n = trail.lines().filter(|l| l.contains("10.0.0.1:443")).count();
        assert_eq!(n, 1, "eighty identical flows must write one record, wrote {n}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The defect this whole change exists to fix: the events pile up until
    /// somebody takes them, and nothing else in the process ever does.
    ///
    /// Draining is therefore *not* conditional on a workspace. With no
    /// `--workspace` the handle is the disabled one and drops every record --
    /// but the buffer must still be emptied, or a `--seconds 0` guest grows it
    /// for its whole life. `AuditLog::default()` is exactly that handle, so
    /// this asserts the drain happens on the path where nothing is written.
    #[test]
    fn events_are_consumed_even_with_no_workspace() {
        let audit = crate::audit::AuditLog::default();
        let mut tally = crate::audit::EgressTally::default();
        let events = vec![
            egress_event("dns", "a.example", false),
            egress_event("dns", "b.example", false),
        ];

        crate::audit::record_egress(events, &mut tally, &audit);

        // `record_egress` takes the vector by value, so consuming it is what
        // bounds the buffer; the tally having seen both is the observable proof
        // that neither was skipped on the no-workspace path.
        assert!(
            !tally.observe("dns", "a.example", "default-deny", false),
            "the first event was never observed, so the drain did not reach it"
        );
        assert!(
            !tally.observe("dns", "b.example", "default-deny", false),
            "the second event was never observed, so the drain stopped early"
        );
    }

    /// The cold-boot net loop lives inside a four-hundred-line function no test
    /// can call, so the only way to hold it to its contract is to read it. Four
    /// claims, each of which was false on this path until V11.3:
    ///
    /// 1. it services through the shared pass, which drains as it goes;
    /// 2. it never services a device directly, the shape that leaves
    ///    `drain_egress_events()` uncalled and the NAT's buffer growing;
    /// 3. it wakes the vCPUs when a pass delivered, because a frame sitting in
    ///    the ring behind a parked vCPU has not arrived;
    /// 4. it writes the totals, without which a cold boot's trail has per-flow
    ///    lines and no way to tell a complete record from a truncated one.
    #[test]
    fn the_cold_net_loop_services_the_way_the_restore_path_does() {
        let src = include_str!("create.rs");
        // Assembled from parts so this literal is not itself a match (the file
        // reads its own source), and asserted unique so a second occurrence
        // cannot silently shift `nth(1)` onto some other region -- which is
        // exactly what a rename of the production line would otherwise do.
        let spawn = format!("let mut tally = {}::default();", "EgressTally");
        assert_eq!(
            src.matches(&spawn).count(),
            1,
            "the cold-net loop's tally must be the only match for {spawn:?}, \
             or this guard reads a region that is not the loop"
        );
        let body = src
            .split(&spawn)
            .nth(1)
            .and_then(|s| s.split("spawning the net service thread").next())
            .expect("the cold-net loop must still spawn with a tally");
        assert!(
            body.contains(&format!("{}(", "net_service_pass")),
            "the cold-net loop must service through the shared pass, which drains"
        );
        assert!(
            !body.contains(&format!(".{}()", "service_net")),
            "the cold-net loop must not service a device directly -- that is the \
             shape that leaves drain_egress_events() uncalled and the buffer growing"
        );
        assert!(
            body.contains(&format!("for exit in &{}", "exits")),
            "a delivered frame must take the vCPUs out of WFI; otherwise the guest \
             pays its own poll interval as latency on every inbound packet"
        );
        assert!(
            body.contains(&format!("audit.{}(&tally)", "egress_summary")),
            "the cold-boot trail must carry totals, or a reader cannot tell a \
             complete record from a truncated one"
        );
    }

    /// The interval is the restore path's, imported rather than restated. A
    /// second declaration is two numbers that can drift, and the drift would be
    /// invisible: both loops would keep working, at different rates, and only a
    /// throughput measurement across the two paths would ever show it.
    #[test]
    fn the_service_interval_is_not_restated_here() {
        let src = include_str!("create.rs");
        assert!(
            !src.contains(&format!("const {}", "NET_SERVICE_INTERVAL")),
            "the cold-boot path must import the interval from imp, not declare \
             its own copy of it"
        );
    }

    fn egress_event(
        domain: &'static str,
        target: &str,
        allowed: bool,
    ) -> hypervisor::hvf::virtio::nat::EgressEvent {
        hypervisor::hvf::virtio::nat::EgressEvent {
            domain,
            target: target.to_string(),
            allowed,
            rule: if allowed { "allow".into() } else { "default-deny".into() },
            policy: "test-policy".into(),
        }
    }

    /// `--originate` has to name the directory it will write.
    #[test]
    fn originate_parses_to_the_directory_it_was_given() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--originate",
            "/tmp/lineage",
        ]))
        .expect("parses");
        assert_eq!(a.originate.as_deref(), Some(Path::new("/tmp/lineage")));
        let bare = parse(&args(&["--kernel", "/tmp/Image"])).expect("parses");
        assert!(
            bare.originate.is_none(),
            "origination must be something the caller asked for"
        );
    }

    /// A dry run has no guest, so it has nothing to originate from.
    ///
    /// Exiting 0 having written nothing is the shape that reads as success to
    /// any script checking the status -- the caller would believe a lineage
    /// exists and discover otherwise at the first resume.
    #[test]
    fn a_dry_run_cannot_originate_and_says_so() {
        let e = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--originate",
            "/tmp/lineage",
            "--dry-run",
        ]))
        .unwrap_err();
        assert!(e.contains("--originate"), "{e}");
        assert!(
            e.contains("running guest"),
            "the refusal has to say why, not just that: {e}"
        );
    }

    /// A guest with a disk is the only kind of guest worth originating from.
    ///
    /// This used to be refused: the synthesized capture had no device nodes, so
    /// a snapshot would have restored to a machine whose RAM believed in a
    /// filesystem that was not there -- the #139 failure shape, arrived at by
    /// omission rather than by drift. #378 gave the document `_virtio-mmio-*`
    /// nodes, so the refusal came down. The guard stays, inverted, because the
    /// combination is the whole point of the feature (#361): a browser sandbox
    /// has a rootfs, and a lineage that cannot start from one starts from
    /// nothing anybody wants.
    #[test]
    fn a_guest_with_disks_can_originate_a_lineage() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--disk",
            "/tmp/root.img",
            "--originate",
            "/tmp/lineage",
        ]))
        .expect("a disk-backed guest must be able to begin a lineage");
        assert_eq!(a.cfg.disks, vec![PathBuf::from("/tmp/root.img")]);
        assert_eq!(a.originate, Some(PathBuf::from("/tmp/lineage")));
    }

    /// The console configuration must be read from the live device.
    ///
    /// `Pl011::capture()` reads the registers the guest itself programmed. A
    /// caller that passed a constructed `SerialRegs` instead would write a
    /// document describing a console nobody configured, and the guest would
    /// resume unable to hear a keystroke while executing perfectly -- the least
    /// legible failure this path has.
    #[test]
    fn the_originated_console_is_read_from_the_device_the_guest_programmed() {
        let src = include_str!("create.rs");
        let needle = format!("{}.{}()", "uart", "capture");
        assert!(
            src.contains(&needle),
            "origination must capture the live PL011, not describe a fresh one"
        );
    }

    /// A vCPU that never sends must fail origination, not stall it.
    ///
    /// `collect_usgic_checkpoint` calls `recv()` exactly once per vCPU, and
    /// `recv()` returns an error only when the *last* sender is dropped. While
    /// the orchestrator held its own sender through teardown, a thread that
    /// exited without sending left the collector waiting on a channel nobody
    /// would ever write to again -- origination hanging after a guest ran
    /// perfectly, with no message.
    ///
    /// This is why `run` drops `capture_tx` once every thread holds a clone.
    /// The test dropping the sender here is not tidiness; it *is* the property.
    /// A guard whose failure mode is "the suite hangs" is not a guard, so this
    /// runs the collector on its own thread and fails on the timeout instead.
    #[test]
    fn a_vcpu_that_exits_without_capturing_fails_origination_rather_than_hanging() {
        let (tx, rx) = mpsc::channel::<(usize, UsgicCapture)>();
        // Two vCPUs declared, nothing sent, and the last sender gone: the exact
        // shape of a thread taking an early exit out of the run loop.
        drop(tx);

        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();
        thread::spawn(move || {
            let r = collect_usgic_checkpoint(&rx, COLD_NR_IRQS, 2).map(|_| ());
            let _ = done_tx.send(r);
        });

        let outcome = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the collector must return; waiting forever is the bug");
        let e = outcome.expect_err("no capture was sent, so there is nothing to assemble");
        assert!(
            e.contains("exited before sending"),
            "the error has to name what went wrong, or a hang is merely traded \
             for a mystery: {e}"
        );
    }

    /// The orchestrator must let go of its own capture sender.
    ///
    /// The guard above proves the *collector* escapes once the last sender is
    /// gone. It cannot see whether `run` actually lets go of its own, because
    /// the test drops a sender it made itself -- the call-site blind spot this
    /// repo has now been bitten by seven times. So read the source instead.
    ///
    /// The needle is assembled from parts: written whole it would match this
    /// assertion's own text and pass while `run` held the sender forever.
    #[test]
    fn the_orchestrator_lets_go_of_its_capture_sender() {
        let src = include_str!("create.rs");
        let needle = format!("{}({}_{});", "drop", "capture", "tx");
        assert!(
            src.contains(&needle),
            "run must drop its own capture sender once every vCPU thread holds \
             a clone, or the collector's only escape is closed and origination \
             waits forever on a guest that already finished"
        );
    }

    /// The devices a guest ran must reach the synthesizer.
    ///
    /// Every assertion about the emitted document lives in `genesis` and asks
    /// what the rendering looks like for the devices it was given. A change
    /// here that stops handing devices over moves the synthesizer's inputs and
    /// its outputs together: it is asked to describe a diskless machine, does
    /// so correctly, and every one of those assertions still passes. That is
    /// the eighth time this repository has been bitten by a mutation at a call
    /// site rather than in the thing called, so this guard reads the call site
    /// itself.
    ///
    /// `originate_snapshot` also compares the document's device count against
    /// the machine's at run time, which is the half that protects a shipped
    /// binary. This is the half that fails in the suite, before anyone builds
    /// one.
    ///
    /// The needle is assembled rather than written out, because a literal would
    /// appear in this function and match itself -- a guard that finds its own
    /// assertion text cannot detect the code's disappearance.
    #[test]
    fn the_devices_the_guest_ran_are_handed_to_the_synthesizer() {
        let src = include_str!("create.rs");
        let passed = format!("&{},\n    )?;", "virtio");
        assert!(
            src.contains(&passed),
            "`genesis::synthesize` must be called with the nodes mapped from \
             the live devices. Passing an empty slice, or dropping the \
             argument, would emit a snapshot describing a machine with no \
             disks -- which resumes, and hands the guest's kernel nothing its \
             drivers are bound to."
        );

        let built = format!(
            "devices\n        .iter()\n        .map(|(place, dev)| genesis::{}",
            "VirtioNode"
        );
        assert!(
            src.contains(&built),
            "the nodes must be mapped from `devices`, the vector the bus was \
             built from. Deriving them from `coldboot`'s constants instead \
             would let the recorded windows drift from the ones the guest's \
             drivers are actually bound to."
        );
    }

    /// The run-time half: a document that does not describe the machine it came
    /// from is refused rather than written.
    #[test]
    fn a_snapshot_that_lost_the_guests_devices_is_refused_by_name() {
        let src = include_str!("create.rs");
        let check = format!("genesis::virtio_nodes_in(&genesis.{})?", "bytes");
        assert!(
            src.contains(&check),
            "the count must be read back out of the bytes about to be written. \
             Counting the caller's own vector instead would compare a value \
             with itself and agree however wrong it was."
        );
        assert!(
            src.contains("but the snapshot describes"),
            "the refusal must name both counts, or the operator is told a \
             lineage failed without being told what was missing from it"
        );
    }

    /// The bug: `--originate` typed after `--post-boot` was taken as an argument
    /// to the guest's command. No lineage, no error, exit 0 -- the only trace
    /// was the guest echoing our own flag back inside its argv, and the run
    /// otherwise looked perfect. Greed is correct (a guest command may carry a
    /// word we also use) so the cure is legibility, not a parse change.
    #[test]
    fn a_chm_flag_after_post_boot_is_reported_as_swallowed() {
        let a = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--post-boot",
            "sh",
            "-c",
            "true",
            "--originate",
            "/tmp/lin",
        ]))
        .unwrap();
        assert_eq!(a.originate, None, "greed is the behaviour under test");
        assert_eq!(
            a.post_boot_swallowed,
            vec!["--originate".to_string()],
            "the flag the parser ate has to be nameable, or the note cannot say \
             which word went to the guest"
        );
    }

    /// The other half, and the one that decides whether the note is worth
    /// having: an ordinary command must not be accused of anything. A guest
    /// command routinely carries words that are not our flags.
    #[test]
    fn an_ordinary_post_boot_command_is_not_reported() {
        let a = parse(&args(&[
            "--originate",
            "/tmp/lin",
            "--kernel",
            "/tmp/Image",
            "--post-boot",
            "sh",
            "-c",
            "echo --net --disk hello",
        ]))
        .unwrap();
        assert!(
            a.post_boot_swallowed.is_empty(),
            "--net and --disk inside a quoted shell word are one argv element, \
             not flags, and a note that fires on them is noise"
        );
        assert!(
            a.originate.is_some(),
            "a flag before --post-boot still lands"
        );
    }

    /// `CREATE_FLAGS` is a second copy of the parser's vocabulary, and a second
    /// copy drifts: a flag added to the match and not here would be swallowed
    /// silently, which is the bug this note exists to close. So read the
    /// parser's own arms out of this file rather than trusting the list.
    #[test]
    fn create_flags_named_in_the_parser() {
        let src = include_str!("create.rs");
        let body = src
            .split_once("fn parse(raw: &[String])")
            .expect("the parser must still be named this")
            .1;
        let body = body.split_once("\n    Ok(CreateArgs {").unwrap().0;
        let mut found = 0usize;
        for line in body.lines() {
            let t = line.trim();
            // A match arm, not a string used in a message: `"--x" =>` or
            // `"--x" | "--y" =>`.
            if !t.starts_with('"') || !t.contains("=>") {
                continue;
            }
            for flag in t.split("=>").next().unwrap().split('|') {
                let flag = flag.trim().trim_matches('"');
                if !flag.starts_with('-') {
                    continue;
                }
                found += 1;
                assert!(
                    CREATE_FLAGS.contains(&flag),
                    "{flag} is a create flag the parser understands but \
                     CREATE_FLAGS does not, so typing it after --post-boot \
                     would be swallowed with no note"
                );
            }
        }
        assert!(
            found >= 15,
            "only {found} arms found -- the extraction stopped matching the \
             parser's shape, so this guard is passing without reading anything"
        );
    }

    /// `CREATE_FLAGS` agreeing with the parser proves the flag is *understood*,
    /// not that anyone can find out it exists. #151/V9.4 established that a
    /// subcommand nobody can discover is a subcommand nobody has, and a flag is
    /// the same claim one level down: `--socket` reached the parser first and
    /// was absent from `--help`, so the only way to learn it existed was to
    /// read the source.
    ///
    /// It reports every absentee in one failure rather than the first, because
    /// its own first run found three (`--socket`, `--initrd`, `--cmdline-extra`)
    /// and an assert inside the loop made that three full suite runs. A guard
    /// that stops at the first finding charges a round trip per defect.
    #[test]
    fn every_create_flag_is_in_the_help() {
        let help = usage();
        let missing: Vec<&str> = CREATE_FLAGS
            .iter()
            .filter(|flag| !help.contains(**flag))
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "{} are flags `chm create` accepts and `chm create --help` never \
             mentions, so the only way to find them is to read the source",
            missing.join(", ")
        );
        assert!(
            CREATE_FLAGS.len() >= 20,
            "only {} flags -- the list stopped being the parser's vocabulary, \
             so this guard is passing without reading anything",
            CREATE_FLAGS.len()
        );
    }

    /// A test can see that `parse` *recorded* the swallowed flags and still not
    /// see that nobody prints them: an assertion about a value cannot observe a
    /// call site that no longer exists. This repo has been caught by that seven
    /// times, so read the source.
    #[test]
    fn the_swallowed_flags_are_actually_printed() {
        let src = include_str!("create.rs");
        let needle = format!("args.{}.is_empty()", "post_boot_swallowed");
        assert!(
            src.contains(&needle),
            "nothing consults the swallowed flags, so they are recorded and \
             never said out loud -- which is the original bug with extra steps"
        );
        // Assembled, because a literal here would be found by `contains` in
        // this very assertion -- a needle that matches its own test can never
        // detect its removal from the code (§43).
        let remedy = format!("put it {} --post-boot", "before");
        assert!(
            src.contains(&remedy),
            "the note must carry the remedy: a true sentence that leaves the \
             reader with no next step is what #305 and #306 were about"
        );
    }

    /// A panic banner rarely arrives in one write: the UART is drained in
    /// whatever chunks the guest happened to produce.
    #[test]
    fn a_panic_banner_split_across_writes_is_still_seen() {
        let w = PanicWatch::default();
        w.push(b"[   12.3] Kernel pa");
        assert!(!w.panicked(), "half a banner is not a panic");
        w.push(b"nic - not syncing: Attempted to kill init!\n");
        assert!(
            w.panicked(),
            "the two halves join at the carry, or every panic split by a UART \
             read boundary is reported as a clean stop -- which is the defect"
        );
    }

    /// The carry must not be able to grow without bound: this runs on every
    /// guest, and a guest can print forever.
    #[test]
    fn a_long_clean_transcript_neither_fires_nor_accumulates() {
        let w = PanicWatch::default();
        for _ in 0..1000 {
            w.push(b"[    0.000000] a perfectly ordinary line of boot output\n");
        }
        assert!(!w.panicked(), "ordinary boot output is not a panic");
        assert!(
            !w.unchecked_fs(),
            "ordinary boot output is not a dirty rootfs"
        );
        let held = w.carry.lock().unwrap().len();
        assert!(
            held < 64,
            "the carry keeps only what a split line could need, but held {held} \
             bytes -- an unbounded carry is a leak on every run"
        );
    }

    #[test]
    fn a_dirty_rootfs_is_noticed_separately_from_a_panic() {
        let w = PanicWatch::default();
        w.push(b"[    0.6] EXT4-fs (vda): warning: mounting unchecked fs, running e2fsck is recommended\n");
        assert!(
            w.unchecked_fs(),
            "the warning is the only notice this damage gets"
        );
        assert!(
            !w.panicked(),
            "a dirty rootfs is a report about an earlier run; calling it a panic \
             would blame this one for something it did not do"
        );
    }

    /// The four states the silence window has to tell apart. A halting panic
    /// (#390) is the only one with no other way out of the wait loop: `running`
    /// stays true because no vCPU ever exits, and `--seconds 0` means no
    /// deadline fires either.
    #[test]
    fn only_a_panic_followed_by_silence_ends_the_wait() {
        let grace = Duration::from_secs(15);
        let t0 = Instant::now();
        let after = t0 + grace + Duration::from_secs(1);

        let quiet = PanicWatch::default();
        assert!(
            !quiet.settled_after_panic(grace, after),
            "a guest that has never printed anything has not panicked; silence \
             alone must never end a run"
        );

        let busy = PanicWatch::default();
        busy.push_at(b"[    3.0] an ordinary line\n", t0);
        assert!(
            !busy.settled_after_panic(grace, after),
            "long silence without a panic is an idle guest, which is normal"
        );

        let talking = PanicWatch::default();
        talking.push_at(b"[    3.0] Kernel panic - not syncing: test\n", t0);
        talking.push_at(b"[   40.0] and yet here I still am\n", after);
        assert!(
            !talking.settled_after_panic(grace, after),
            "the panic string is matched in guest output, so a guest that merely \
             printed the words trips the flag -- and one still printing is still \
             running. This is the false positive the silence half exists to stop."
        );

        let halted = PanicWatch::default();
        halted.push_at(b"[    3.0] Kernel panic - not syncing: test\n", t0);
        assert!(
            halted.settled_after_panic(grace, after),
            "panicked and silent since: nothing else can ever end this run"
        );
        assert!(
            !halted.settled_after_panic(grace, t0 + Duration::from_secs(1)),
            "and not before the grace has actually elapsed"
        );
    }

    /// The loop condition is where the fix lives; a `PanicWatch` that knows it
    /// has settled changes nothing if nobody asks it. Sixth-plus instance of
    /// the call-site class in this repo, so it gets its own guard.
    #[test]
    fn the_wait_loop_asks_whether_a_panicked_guest_has_settled() {
        let src = include_str!("create.rs");
        let call = format!("panic_watch.{}(PANIC_SILENCE_GRACE,", "settled_after_panic");
        assert!(
            src.contains(&call),
            "the wait loop must consult {call:?}, or a halting panic hangs \
             forever with `--seconds 0`"
        );
        let gate = format!("let {} = !stdin().is_terminal();", "unattended");
        assert!(
            src.contains(&gate),
            "and it must be gated on {gate:?}: an operator at a tty can see the \
             panic and end the session themselves, and tearing down a session \
             someone is sitting at is the worse failure"
        );
    }

    /// Both reports have to leave the reader with a next step, not just a fact.
    #[test]
    fn both_reports_name_the_consequence_and_the_missing_repair() {
        let panic = panic_report();
        let dirty = unchecked_fs_report();
        for (what, text) in [("panic", &panic), ("unchecked fs", &dirty)] {
            assert!(
                text.contains("e2fsck"),
                "the {what} report must say the repair does not exist here, or \
                 the reader goes looking for a tool macOS has never had"
            );
        }
        assert!(
            panic.contains("Kernel panic - not syncing"),
            "the panic report must name the line to look for, since the reason \
             itself is only ever on the console"
        );
        assert!(
            dirty.contains("Rebuild the image"),
            "with no repair tool, rebuilding is the only remedy there is -- a \
             report with no remedy is the shape #305 and #306 were about"
        );
    }

    /// The two exits are different events and the flattening of them is exactly
    /// what let a kernel panic read as `guest powered off`, rc=0.
    #[test]
    fn a_reset_is_not_reported_as_a_power_off() {
        let src = include_str!("create.rs");
        // Assembled: a literal would be matched by this assertion's own text.
        let flattened = format!("VmExit::Shutdown {} VmExit::Reset", "|");
        assert!(
            !src.contains(&flattened),
            "a panic reboots, so it arrives as Reset; sharing an arm with \
             Shutdown is what reported it as a clean power-off"
        );
        assert!(
            src.contains(&format!("Ok(\"guest {}\".into())", "reset")),
            "Reset needs its own message, or splitting the arm changes nothing \
             a caller can see"
        );
    }

    /// The panic verdict is read after the console thread has been joined. Read
    /// before, it would race the banner still sitting in the UART.
    #[test]
    fn the_panic_verdict_is_read_after_the_console_is_drained() {
        let src = include_str!("create.rs");
        let joined = src
            .find(&format!("let _ = console.{}();", "join"))
            .expect("the console thread is joined somewhere");
        let read = src
            .rfind(&format!("if panic_watch.{}() {{", "panicked"))
            .expect("something consults the panic watch");
        assert!(
            joined < read,
            "the verdict is read at {read} but the console is only drained at \
             {joined}: a panic printed in the last write would be missed, and \
             missing it is the whole defect"
        );
        let returned = format!("return Err(panic_{}())", "report");
        assert!(
            src.contains(&returned),
            "a panic has to leave through the error path: the exit status is the \
             only part a script reads, and rc=0 for a panic is the defect"
        );
    }

    /// The banner lands in the *final* drain, because the kernel prints it and
    /// resets, which is what ends the loop. Watching only the loop body would
    /// miss every panic there has ever been.
    #[test]
    fn both_console_drains_feed_the_panic_watch() {
        let src = include_str!("create.rs");
        let call = format!("panic_watch.{}(&", "push");
        let sites = src.matches(&call).count();
        assert_eq!(
            sites, 2,
            "expected the loop body and the post-loop drain to both feed the \
             watch, found {sites} call sites"
        );
        for (what, arg) in [("the loop body", "bytes"), ("the final drain", "rest")] {
            assert!(
                src.contains(&format!("{call}{arg});")),
                "{what} does not feed the watch: a panic printed there is \
                 reported as a clean stop, which is the defect"
            );
        }
    }

    /// The idle supervisor is off unless asked for, and parses like its sibling.
    ///
    /// Deliberately not tty-dependent the way `--seconds` is (#305): a deadline
    /// answers "how long may this run at most", which an unattended pipe needs
    /// an answer to. An idle teardown is a different question, and adding one
    /// nobody asked for to an interactive session would be #305 in reverse.
    #[test]
    fn idle_exit_is_off_until_asked_for() {
        let off = parse(&args(&["--kernel", "/tmp/Image"])).unwrap();
        assert_eq!(
            off.idle_exit_secs, 0,
            "an unasked-for idle stop is a surprise"
        );

        let on = parse(&args(&["--kernel", "/tmp/Image", "--idle-exit", "45"])).unwrap();
        assert_eq!(on.idle_exit_secs, 45);
        assert_eq!(
            on.max_seconds,
            default_max_seconds(stdin().is_terminal()),
            "--idle-exit says when to stop, and must not also move the deadline"
        );

        let e = parse(&args(&["--kernel", "/tmp/Image", "--idle-exit", "soon"])).unwrap_err();
        assert!(
            e.contains("--idle-exit"),
            "the refusal must name the flag: {e}"
        );
    }

    /// #404's open question, answered in the source rather than in a comment.
    ///
    /// `--idle-exit` decides *when* a run stops; `--originate` decides *what*
    /// survives it. Implying one from the other would write a snapshot the
    /// caller never asked for, and there is no way to un-ask for it.
    #[test]
    fn idle_exit_does_not_imply_originate() {
        let a = parse(&args(&["--kernel", "/tmp/Image", "--idle-exit", "30"])).unwrap();
        assert!(
            a.originate.is_none(),
            "asking when to stop is not asking for a lineage"
        );
    }

    /// The two stops have different causes and different remedies, so a caller
    /// reading the last line of a run must be able to tell which fired. They
    /// are indistinguishable to `timed_out` -- both leave the guest running
    /// with no shutdown requested -- so the reason is carried explicitly.
    #[test]
    fn the_idle_stop_reports_itself_rather_than_the_deadline() {
        let src = include_str!("create.rs");
        let marker = format!("None if {}_idle =>", "stopped");
        assert!(
            src.contains(&marker),
            "the idle stop needs its own arm before the timeout one, or it \
             reports a --seconds deadline the caller never set"
        );
        let idle_at = src.find(&marker).unwrap();
        let timeout_at = src.find("None if timed_out =>").unwrap();
        assert!(
            idle_at < timeout_at,
            "the idle arm must come first: an idle stop also satisfies the \
             timeout arm's shape"
        );
    }

    /// The residency counter can only be read from the vCPU that owns it, so if
    /// it does not travel with the GIC handle it cannot reach the supervisor at
    /// all -- and `IdleResidency::new` would see an empty slice, report `None`,
    /// and stop on console silence alone. That is the pre-#171 behaviour
    /// wearing #404's flag, which is the worst of both.
    #[test]
    fn every_vcpu_reports_its_parked_counter_to_the_supervisor() {
        let src = include_str!("create.rs");
        let read = format!("vcpu.{}()", "wfi_parked_ns");
        assert!(
            src.contains(&read),
            "no vCPU reads its parked counter, so residency has no evidence"
        );
        assert!(
            src.contains(&format!("{}[id] = parked;", "all_parked")),
            "the drain must place each counter by vCPU id, since the channel \
             does not promise arrival order"
        );
        assert!(
            src.contains(&format!("{}::new(&all_parked)", "IdleResidency")),
            "the supervisor must be built from the collected counters"
        );
    }

    /// The console thread is this process's only observer of guest output, so a
    /// silent-window clock that it does not feed can never restart -- and every
    /// run would be declared idle exactly `--idle-exit` seconds after boot,
    /// however loud the guest was.
    #[test]
    fn both_console_drains_report_that_the_guest_spoke() {
        let src = include_str!("create.rs");
        let call = format!("{}.fetch_add(1, Ordering::Release);", "spoke");
        let sites = src.matches(&call).count();
        assert_eq!(
            sites, 2,
            "expected the loop body and the post-loop drain to both report \
             output, found {sites}"
        );
    }

    /// #155: what a spec asks for has to survive the parser it is spliced into.
    ///
    /// `expand_spec` renders a document to argv and hands it back to `parse`,
    /// so a spec can only ever request ingress that a typed `--expose` could
    /// have requested. Asserting that in `spec.rs` would assert it against a
    /// model of the parser; asserting it here runs the parser.
    #[test]
    fn a_specs_ingress_is_something_the_flag_could_have_asked_for() {
        let doc: crate::spec::SandboxSpec = serde_json::from_str(
            r#"{"specVersion":1,"image":{"kernel":"/tmp/Image"},
                "networkPolicy":{"enabled":true,"ingress":[
                    {"port":9222,"protocol":"tcp"},{"port":3000}]}}"#,
        )
        .expect("the fixture must parse");
        assert!(doc.validate().is_empty(), "{:?}", doc.validate());

        let mut argv = crate::spec::resolve(Some(&doc), None, &crate::spec::Overrides::default())
            .to_create_argv();
        if argv.first().map(String::as_str) == Some("create") {
            argv.remove(0);
        }
        let parsed = parse(&argv).expect("a spec must render argv this parser accepts");
        assert_eq!(
            parsed.expose,
            vec![9222, 3000],
            "the spec's ports must arrive as the parser's ports, in the order named"
        );
    }

    /// #155: a document that validates as *refused* must never start as
    /// *honoured*. That is the whole milestone, and it has two independent
    /// halves.
    ///
    /// This is the first: `expand_spec` refuses before anything starts. The
    /// second is that `resolve` publishes only through `publishable_port()`,
    /// so it does not depend on this call having happened -- measured by
    /// deleting the `validate()` below and running the real binary, which
    /// rendered **zero** `--expose` flags for this same document. Both halves
    /// are kept: this one refuses the *whole* document, including the sections
    /// this build cannot honour at all, which no per-rule predicate can see.
    #[test]
    fn a_document_validate_refuses_cannot_start() {
        let dir = std::env::temp_dir().join(format!("chm-specref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(
            dir.join("sandbox.json"),
            r#"{"specVersion":1,"networkPolicy":{"enabled":true,
                "ingress":[{"port":8080,"host":"0.0.0.0"}]}}"#,
        )
        .expect("write the spec");

        let raw = args(&[
            "--spec",
            &dir.display().to_string(),
            "--kernel",
            "/tmp/Image",
        ]);
        let e = expand_spec(&raw).expect_err("a refused document must not expand into a command");
        assert!(
            e.contains("host") || e.contains("0.0.0.0"),
            "the refusal must survive to the caller and name what it refused; got {e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The spec is spliced *before* the caller's flags, so naming the same port
    /// in both is the parser's existing duplicate refusal -- and that is the
    /// honest answer, because there is only one host port per guest port.
    /// Silently collapsing them would hide that the document and the command
    /// line disagreed.
    #[test]
    fn a_port_named_by_both_the_spec_and_a_flag_is_refused_by_name() {
        let e = parse(&args(&[
            "--kernel",
            "/tmp/Image",
            "--net",
            "--expose",
            "9222",
            "--expose",
            "9222",
        ]))
        .unwrap_err();
        assert!(
            e.contains("9222") && e.contains("twice"),
            "the collision must name the port and say it was given twice; got {e}"
        );
    }

}

/// Guards for the cold-boot control socket (#401).
#[cfg(test)]
mod cold_socket_tests {
    use super::{CREATE_FLAGS, cold_guest_dir, cold_guest_name, parse};
    use std::path::{Path, PathBuf};

    fn args(extra: &[&str]) -> super::CreateArgs {
        let mut v: Vec<String> = vec!["--kernel".into(), "/dev/null".into()];
        v.extend(extra.iter().map(|s| (*s).to_string()));
        parse(&v).expect("must parse")
    }

    #[test]
    fn the_socket_flag_reaches_the_field_it_names() {
        assert_eq!(args(&[]).socket, None, "no --socket must arm no socket");
        assert_eq!(
            args(&["--socket", "/Users/x/chm.sock"]).socket,
            Some(PathBuf::from("/Users/x/chm.sock"))
        );
        assert!(CREATE_FLAGS.contains(&"--socket"));
    }

    /// `cold_guest_dir` exists only to *agree* with the credential proxy's own
    /// workspace derivation. `ca_archive_for` states the hazard in full: two
    /// derivations eventually disagree, and the symptom is a CA installed in the
    /// guest that does not match the one intercepting its traffic -- a TLS
    /// failure that names neither. `running_vm_dir` prefers `vm.dir`, and that
    /// is what `posture`, `proxy` and `audit` assess over this socket, so a
    /// third derivation would reintroduce exactly that bug one layer up.
    #[test]
    fn the_guest_dir_is_the_proxys_own_derivation() {
        // Both set: the workspace wins, in both derivations.
        let a = args(&[
            "--net",
            "--workspace",
            "/ws/explicit",
            "--proxy-rules",
            "/other/rules.json",
        ]);
        assert_eq!(cold_guest_dir(&a), PathBuf::from("/ws/explicit"));

        // Only rules: the rules file's parent, in both derivations.
        let b = args(&["--net", "--proxy-rules", "/lab/one/proxy-rules.json"]);
        assert_eq!(cold_guest_dir(&b), PathBuf::from("/lab/one"));

        // Neither: there is nowhere to assess, and the current directory is what
        // every other path here falls back to.
        assert_eq!(cold_guest_dir(&args(&[])), PathBuf::from("."));

        // And the shape is read out of the source, because agreeing today is not
        // the property -- staying the same expression is.
        let src = include_str!("create.rs");
        let needle = format!("args.proxy_rules{}", "\n                .as_deref()");
        assert!(
            src.contains(&needle),
            "cold_guest_dir must still derive from --proxy-rules the way \
             ca_archive_for does, or `chm proxy ca --install` over this socket \
             installs a CA the proxy is not using"
        );
    }

    /// A cold boot has no library entry to take a name from, so `chm ctl status`
    /// over this socket would otherwise report a guest called nothing.
    #[test]
    fn the_guest_is_named_after_the_image_the_operator_picked() {
        let a = args(&[]);
        let named = |k: &str| {
            let mut b = a.clone();
            b.cfg.kernel = PathBuf::from(k);
            cold_guest_name(&b)
        };
        assert_eq!(
            named("/Users/x/gimbal-images/final-alpine/Image"),
            "final-alpine"
        );
        // A kernel with no parent directory still has to answer something a
        // status line can print.
        assert_eq!(named("Image"), "cold-boot");
        assert_eq!(named("/Image"), "cold-boot");
        assert!(!cold_guest_name(&a).is_empty());
        assert!(Path::new("/dev/null").exists());
    }

    /// The teardown decisions are all *call sites*, and this repo has been
    /// caught seven times by a rule that stayed correct while nothing consulted
    /// it. Every one of these is invisible to an assertion about a value.
    ///
    /// Needles are assembled from parts: a literal would match this test's own
    /// source and pass while `run` did none of it.
    #[test]
    fn the_teardown_still_consults_the_socket() {
        let src = include_str!("create.rs");

        let waits = format!("&& !{}()", "stop_asked");
        assert!(
            src.contains(&waits),
            "the wait loop must consult stop_requested, or `chm ctl stop` over \
             this socket sets a flag nobody reads and the guest runs on"
        );

        let excluded = format!("&& !{};", "stopped_by_client");
        assert!(
            src.contains(&excluded),
            "timed_out must exclude a client stop: a stop leaves `running` true \
             with no shutdown requested, which is the exact shape timed_out was \
             testing for, so a deliberate stop reports as a deadline overrun"
        );

        // Spanning the binding, not just the call: a first draft matched
        // `c.finish(if stopped_by_client` alone and stayed green when the
        // mutation swapped `&control` for a `None`, leaving the call text
        // present and unreachable. A needle that survives the removal of the
        // thing it guards reports safety it does not provide.
        let finished = format!(
            "if let Some(c) = &control {{\n        c.{}(if stopped_by_client",
            "finish"
        );
        assert!(
            src.contains(&finished),
            "the socket must be taken down with a reason, and from the ring the \
             run actually armed, or a `stop` client blocks forever on a guest \
             that has already halted"
        );

        // Gated on the plan, not on the ring: `--socket` arms the ring too, so
        // `match &control` alone would drive a console probe into a guest whose
        // operator asked for neither.
        let gated = format!("match (&control, args.postboot.{})", "is_empty()");
        assert!(
            src.contains(&gated),
            "the post-boot thread must be gated on the plan, or --socket alone \
             starts delivering a plan nobody wrote"
        );
    }
}

#[cfg(test)]
mod client_stop_report_tests {
    use super::client_stop_report;
    use std::path::Path;

    /// The three things an operator needs from an ending they did not cause:
    /// who stopped it, that it was not the guest or a deadline, and what
    /// survived. A message missing the last one leaves them guessing whether
    /// their work is gone.
    #[test]
    fn the_report_names_the_actor_the_channel_and_what_survived() {
        let msg = client_stop_report(Some(Path::new("/tmp/x.sock")), false);
        assert!(
            msg.contains("/tmp/x.sock"),
            "name the socket the stop came in on, or the operator cannot tell \
             which of several sandboxes was stopped: {msg}"
        );
        assert!(
            msg.contains("neither the guest") && msg.contains("deadline"),
            "the neighbouring arms blame the guest and the deadline, so this \
             one must rule both out or it reads as one of them: {msg}"
        );
        assert!(
            msg.contains("Nothing was preserved"),
            "with no --originate a stop keeps nothing, and silence about that \
             is how someone learns it the expensive way: {msg}"
        );
        let kept = client_stop_report(Some(Path::new("/tmp/x.sock")), true);
        assert!(
            kept.contains("--originate ran") && !kept.contains("Nothing was preserved"),
            "and it must not claim a loss that did not happen: {kept}"
        );
    }

    /// `--socket` is optional, and a report that renders an empty path is worse
    /// than one that admits it does not know.
    #[test]
    fn the_report_survives_a_run_with_no_socket_path() {
        let msg = client_stop_report(None, false);
        assert!(
            msg.contains("the control socket"),
            "fall back to naming the channel generically: {msg}"
        );
        assert!(
            !msg.contains("on \n") && !msg.contains("on ,"),
            "and never render a blank where a path should be: {msg}"
        );
    }

    /// A pure function nobody calls reports nothing. The call-site class has
    /// caught this repo eight times, so read the source of the arm itself.
    #[test]
    fn the_ending_match_actually_calls_it() {
        let src = include_str!("create.rs");
        // Assembled from parts, or this assertion is its own needle (§43).
        let arm = format!("None if {} =>", "stopped_by_client");
        assert!(
            src.contains(&arm),
            "without its own arm a client stop falls through to the bare `None` \
             and the run ends in silence again"
        );
        let call = format!("{}(args.socket.as_deref()", "client_stop_report");
        assert!(
            src.contains(&call),
            "the arm must call the function this module tests, or the prose \
             proved here is not the prose printed"
        );
    }
}
