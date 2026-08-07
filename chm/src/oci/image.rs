// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm image build` — turn a container image into something this Mac can boot.
//!
//! # What comes out
//!
//! A **V8.3 image directory**: the format `chm create` already boots and the app
//! already discovers. No new format, no new discovery code, no new rejection
//! vocabulary. A directory holding
//!
//! ```text
//! Image        the kernel (copied from --kernel)
//! initramfs    the container's root filesystem, as newc cpio
//! image.json   kernel/initramfs/cmdline/vcpus/ram_mib
//! BUILD.txt    what was pulled, what was refused, and when
//! ```
//!
//! # Where the kernel comes from, said out loud
//!
//! **A container image contains no kernel.** It never has: `docker run` shares
//! the host's. So a build cannot conjure one, and this command requires
//! `--kernel <Image>`. When it is missing we *look* in the image library and
//! name the kernels we found — the answer to "where do I get one" is a path on
//! this machine, not a paragraph of prose.
//!
//! Magicking one up would be the false sell this repo keeps refusing: a build
//! that silently paired an arbitrary kernel with an arbitrary rootfs would boot
//! into failures the user has no way to attribute.
//!
//! # Sizing
//!
//! An initramfs is unpacked **into guest RAM**, so the rootfs is resident twice
//! during boot (the compressed-in-memory archive plus the unpacked tmpfs) and
//! once after. `ram_mib` is therefore derived from the measured rootfs rather
//! than defaulted, and the arithmetic is stated in `BUILD.txt` so a user
//! resizing it knows what they are trading.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::apply;
use super::initramfs::{default_init, write_cpio};
use super::reference::{self, Reference};
use super::nicfg;
use super::registry::{self, ImageConfig, Registry};
use super::targz;
use crate::coldboot::VirtioBuiltin;
use crate::imp::human_bytes;
use crate::kernelimage::{self, KernelForm};
use crate::oci::entry::EntryKind;
use flate2::read::GzDecoder;
use serde_json::{json, Value};
use zstd::stream::read::Decoder as ZstdDecoder;

/// Cap on a single decompressed layer, and on the running total. A registry can
/// serve a 200 MB layer that expands to 40 GB; the limit is what stops that
/// filling the disk before anything notices.
const LAYER_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Headroom over the rootfs for the kernel, page tables, and the guest actually
/// doing something once it boots. Below this even a shell prompt is tight.
const RAM_FLOOR_MIB: u64 = 512;

pub fn image_main(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("build") => match build(&args[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("chm image build: {e}");
                ExitCode::FAILURE
            }
        },
        Some("--help") | Some("-h") | None => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("chm image: unknown subcommand `{other}`\n\n{}", usage());
            ExitCode::FAILURE
        }
    }
}

pub fn usage() -> String {
    "chm image — build a bootable image directory from a container image\n\
     \n\
     A container image has a root filesystem but no kernel; a guest needs both.\n\
     This pulls the rootfs and pairs it with a kernel you already have, writing\n\
     the same image directory `chm create` and the app already understand.\n\
     \n\
     USAGE:\n    \
         chm image build <REFERENCE> --kernel <Image> [OPTIONS]\n\
     \n\
     ARGS:\n    \
         <REFERENCE>   e.g. `alpine:3.20`, `docker.io/library/ubuntu:24.04`,\n                  \
         `ghcr.io/owner/name:tag`. Defaults to Docker Hub and `latest`.\n\
     \n\
     OPTIONS:\n    \
         --kernel <PATH>   An uncompressed arm64 `Image`. Required: a container\n                      \
         image carries no kernel.\n    \
         --out <DIR>       Where to write the image directory\n                      \
         (default: <images library>/<name>-<tag>).\n    \
         --entrypoint <C>  Override the command init hands over to. Default is\n                      \
         the image's own Entrypoint+Cmd, or /bin/sh.\n    \
         --ram-mib <N>     Guest RAM. Default is sized from the rootfs, because\n                      \
         an initramfs is unpacked into memory.\n    \
         --vcpus <N>       Default 2.\n    \
         --platform <P>    os/arch[/variant]. Default linux/arm64, which takes an\n                      \
         unspecified variant or v8. Name one (e.g. linux/arm64/v9)\n                      \
         to select among an image's arm64 variants. A platform\n                      \
         this host cannot boot is refused rather than built.\n    \
         --dry-run         Resolve and report without writing anything.\n\
     \n\
     NOTE: the rootfs ships as an initramfs, so it lives in guest RAM and\n     \
     changes do not persist across a boot. Attach a disk with `chm create\n     \
     --disk` for state that should survive.\n"
        .to_string()
}

#[derive(Debug)]
struct Args {
    reference: Reference,
    kernel: Option<PathBuf>,
    out: Option<PathBuf>,
    entrypoint: Option<String>,
    ram_mib: Option<u64>,
    vcpus: u32,
    dry_run: bool,
    platform: registry::Platform,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut reference = None;
    let mut kernel = None;
    let mut out = None;
    let mut entrypoint = None;
    let mut ram_mib = None;
    let mut vcpus = 2;
    let mut dry_run = false;
    let mut platform = registry::Platform::host();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut next = |what: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{what} needs a value"))
        };
        match a {
            "--kernel" => kernel = Some(PathBuf::from(next("--kernel")?)),
            "--out" => out = Some(PathBuf::from(next("--out")?)),
            "--entrypoint" => entrypoint = Some(next("--entrypoint")?),
            "--ram-mib" => {
                let v = next("--ram-mib")?;
                ram_mib = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("--ram-mib wants a number, got `{v}`"))?,
                );
            }
            "--vcpus" => {
                let v = next("--vcpus")?;
                vcpus = v
                    .parse()
                    .map_err(|_| format!("--vcpus wants a number, got `{v}`"))?;
            }
            "--platform" => platform = registry::parse_platform(&next("--platform")?)?,
            "--dry-run" => dry_run = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`\n\n{}", usage()));
            }
            other => {
                if reference.is_some() {
                    return Err(format!("unexpected second reference `{other}`"));
                }
                reference = Some(reference::parse(other)?);
            }
        }
        i += 1;
    }
    Ok(Args {
        reference: reference.ok_or_else(|| format!("which image?\n\n{}", usage()))?,
        kernel,
        out,
        entrypoint,
        ram_mib,
        vcpus,
        dry_run,
        platform,
    })
}

/// The images library the app uses, so a built image lands where the app looks.
fn images_library() -> PathBuf {
    if let Some(v) = env::var_os("GIMBAL_IMAGES") {
        return PathBuf::from(v);
    }
    let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("gimbal-images")
}

/// Look for kernels the user already has, so "--kernel is required" can point at
/// real paths on this machine rather than leaving them to search.
fn discover_kernels(library: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(library) else {
        return found;
    };
    for e in entries.flatten() {
        let candidate = e.path().join("Image");
        if candidate.is_file() {
            found.push(candidate);
        }
    }
    found.sort();
    found
}

/// Read a kernel, unwrapping whatever the distro wrapped it in.
///
/// Returns the bytes of an uncompressed arm64 `Image` and what the file turned
/// out to be, so the caller can say what it did rather than silently accepting
/// something different from what was passed.
///
/// This runs at build time on purpose. Discovering a kernel is unusable 30
/// seconds into a boot that produces no console output is the worst place to
/// find out, and this is the one moment the user is *choosing* a kernel and can
/// pick another for free.
fn read_kernel(path: &Path) -> Result<(Vec<u8>, KernelForm), String> {
    let data =
        fs::read(path).map_err(|e| format!("cannot read kernel `{}`: {e}", path.display()))?;
    let label = path.display().to_string();
    let (image, form) = kernelimage::decode(&data, &label)?;
    Ok((image.into_owned(), form))
}

/// Warn if this kernel and a container rootfs cannot give the guest devices.
///
/// Build time is the one moment the user is *choosing* a kernel and can pick a
/// different one for free. Discovering it later costs a boot, and the symptom
/// -- `ip: can't find device 'eth0'` under a device chm has logged as attached
/// -- points at the network rather than at the pairing.
///
/// This does not refuse. The image is perfectly good for a workload that needs
/// no devices, and that is the flow that works today; see `VirtioBuiltin` for
/// why absence is warned about rather than enforced.
/// Takes the *decoded* image, never the file on disk. A wrapped kernel's
/// compressed bytes contain none of the strings this scans for, so scanning
/// the file would report "no virtio built in" for a kernel that has it -- a
/// warning that is wrong in the direction that sends someone chasing #222 for
/// a guest whose devices would have worked.
fn warn_kernel_virtio(image: &[u8]) -> Option<String> {
    VirtioBuiltin::scan(image).warning()
}

/// Which C library the image ships, when it can be told.
///
/// This is not trivia. A prebuilt native addon is linked against one of these
/// and will not load against the other, and the failure surfaces long after the
/// build, in a message that never mentions the base image — see
/// [`Libc::warning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Libc {
    Gnu,
    Musl,
    Unknown,
}

impl Libc {
    /// The one case worth interrupting someone over. The message carries no
    /// indentation of its own — each caller owns its own layout, and one baked
    /// in indent can only ever line up under one of them. glibc is the assumption
    /// most prebuilt binaries are built against, so it needs no comment, and
    /// `Unknown` must not be reported as a problem — an image we cannot
    /// classify is not thereby broken, and guessing would make the note
    /// worthless everywhere.
    pub fn warning(self) -> Option<&'static str> {
        match self {
            Self::Musl => Some(
                "this image uses musl. Prebuilt Node-API addons are linked against\n\
                 glibc and fail here with `napi_* has not been loaded` — the GitHub\n\
                 Copilot CLI among them. Measured: node:22-alpine fails, node:22-slim\n\
                 succeeds, same node version. Use a glibc base to run an agent inside.",
            ),
            Self::Gnu | Self::Unknown => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Gnu => "glibc",
            Self::Musl => "musl",
            Self::Unknown => "not identified",
        }
    }
}

/// Is this file name a shared object rather than something merely named after
/// one? What follows `.so` must be a version — nothing, or `.1`, or `.6`. This
/// exists because `ld-linux-aarch64.so.1.txt` passed a naive `.contains(".so")`
/// and classified a whole image on the strength of a text file.
fn is_shared_object(base: &str) -> bool {
    match base.split_once(".so") {
        None => false,
        Some((_, "")) => true,
        Some((_, rest)) => rest
            .strip_prefix('.')
            .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.')),
    }
}

/// Classify by the dynamic loader's **file name**, never its directory.
///
/// Measured rather than assumed, because the obvious rule is wrong: musl sits
/// at `lib/ld-musl-aarch64.so.1` while Debian's glibc is usr-merged three
/// levels down at `usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`. Anchoring
/// to a directory would classify every usr-merged glibc image as unknown.
///
/// A loader is a shared object, so the name has to look like one — see
/// [`is_shared_object`]. Without that, a note *about* the loader
/// (`ld-linux-aarch64.so.1.txt`) classifies the whole image.
///
/// **An image carrying both loaders is `Unknown`, deliberately.** Both readings
/// are real — a Debian image with `musl-dev` runs a glibc `node` whose addons
/// load fine, an Alpine image with `gcompat` runs a musl `node` whose addons do
/// not — and nothing here can tell them apart. A warning that fires on a
/// working image is worse than a missing one, because it teaches people to
/// ignore it everywhere.
pub fn libc_flavour<'a>(paths: impl Iterator<Item = &'a str>) -> Libc {
    let (mut gnu, mut musl) = (false, false);
    for p in paths {
        let base = p.rsplit('/').next().unwrap_or(p);
        if !is_shared_object(base) {
            continue;
        }
        if base.starts_with("ld-musl-") {
            musl = true;
        }
        if base.starts_with("ld-linux-") || base == "libc.so.6" {
            gnu = true;
        }
    }
    match (gnu, musl) {
        (false, true) => Libc::Musl,
        (true, false) => Libc::Gnu,
        _ => Libc::Unknown,
    }
}

/// Round the measured rootfs up into a guest RAM figure.
///
/// An initramfs is copied into RAM and then unpacked into a tmpfs, so the
/// content is resident roughly twice at the peak. Doubling and adding headroom
/// is the arithmetic; it is written into `BUILD.txt` so a user overriding it can
/// see what they are trading rather than guessing.
pub fn size_ram_mib(rootfs_bytes: u64) -> u64 {
    let mib = rootfs_bytes.div_ceil(1024 * 1024);
    let sized = mib * 2 + 256;
    let rounded = sized.div_ceil(256) * 256;
    rounded.max(RAM_FLOOR_MIB)
}

/// A default output directory name from the reference, safe as a path segment.
pub fn default_out_name(reference: &Reference) -> String {
    let name = reference.repository.rsplit('/').next().unwrap_or("image");
    let tag = reference.reference.replace(':', "-");
    let raw = format!("{name}-{tag}");
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn build(args: &[String]) -> Result<ExitCode, String> {
    if args.first().is_some_and(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }
    let args = parse(args)?;
    let library = images_library();

    let kernel = match &args.kernel {
        Some(k) => {
            let (bytes, form) = read_kernel(k)?;
            if form.was_compressed() {
                println!(
                    "chm image build: kernel {} — {}",
                    k.display(),
                    form.describe()
                );
            }
            Some((k.clone(), bytes))
        }
        None if args.dry_run => None,
        None => {
            let found = discover_kernels(&library);
            let hint = if found.is_empty() {
                format!(
                    "No `Image` found under {}. A cold-boot kernel comes from an \
                     existing image directory, or from an Ubuntu arm64 kernel package.",
                    library.display()
                )
            } else {
                let list: Vec<String> =
                    found.iter().map(|p| format!("  {}", p.display())).collect();
                format!("Kernels on this machine:\n{}", list.join("\n"))
            };
            return Err(format!(
                "--kernel is required: a container image carries no kernel, only a \
                 root filesystem.\n{hint}"
            ));
        }
    };

    let out = args
        .out
        .clone()
        .unwrap_or_else(|| library.join(default_out_name(&args.reference)));

    println!("chm image build: {}", args.reference.display());

    let mut reg = Registry::new(args.reference.clone());
    let manifest = reg.manifest(&args.platform)?;
    let layers = registry::layer_specs(&manifest)?;
    // Refuse a format we cannot read *before* pulling gigabytes of it.
    for l in &layers {
        l.readable()?;
    }
    println!("  {} layer(s)", layers.len());

    let config = match registry::config_digest(&manifest) {
        Some(d) => {
            let raw = reg.blob(&d)?;
            let v: Value = serde_json::from_slice(&raw)
                .map_err(|e| format!("image config was not JSON: {e}"))?;
            registry::parse_config(&v)
        }
        None => ImageConfig::default(),
    };
    let entrypoint = args
        .entrypoint
        .clone()
        .unwrap_or_else(|| config.boot_command());
    println!("  entrypoint: {entrypoint}");

    let mut read_layers = Vec::new();
    let mut pulled = 0u64;
    for (i, spec) in layers.iter().enumerate() {
        let blob = reg.blob(&spec.digest)?;
        pulled += blob.len() as u64;
        let layer = read_blob(&blob, LAYER_LIMIT_BYTES)?;
        println!(
            "  layer {}/{}: {} entries, {} compressed",
            i + 1,
            layers.len(),
            layer.entries.len(),
            human_bytes(blob.len() as u64)
        );
        read_layers.push(layer);
    }

    let (mut rootfs, report) = apply::apply(&read_layers);
    let content = rootfs.content_bytes();
    println!("  rootfs: {} paths, {}", rootfs.len(), human_bytes(content));

    // Classify what the *image* shipped, before the generated init is added —
    // the init is ours and carries no loader, but the question being answered
    // is about the base someone chose.
    let libc = libc_flavour(rootfs.paths());

    print_report(&report);

    // The generated init goes in last, so image content can never shadow it —
    // a layer shipping its own `/init` would otherwise decide what a guest runs
    // before any of our setup happened.
    let init = default_init(&entrypoint, &config.env, config.workdir.as_deref());
    rootfs.insert(
        "init".to_string(),
        EntryKind::File {
            mode: 0o755,
            size: init.len() as u64,
        },
        init.into_bytes(),
    );
    // chm's own NIC configurator, for the images that ship neither `ip` nor
    // `ifconfig` — which includes node:22 and node:22-slim. Installed beside
    // the init and, like it, last, so image content cannot shadow it.
    //
    // A failure here is a build-integrity problem, not something the user's
    // image did, so it is reported and the build continues: the init still
    // falls through to a refusal that names the addresses, which is what
    // happened before this existed.
    match nicfg::configurator() {
        Ok(bytes) => {
            rootfs.insert(
                nicfg::GUEST_PATH.to_string(),
                EntryKind::File {
                    mode: 0o755,
                    size: bytes.len() as u64,
                },
                bytes,
            );
        }
        Err(e) => eprintln!("  warning: {e}"),
    }
    // The mount points the init needs. A `FROM scratch` image has none of these,
    // and a missing /proc turns into a guest that boots to a shell where nothing
    // works, which reads as a broken kernel.
    for d in ["proc", "sys", "dev", "tmp", "etc", "dev/pts"] {
        if !rootfs.contains(d) {
            rootfs.insert(
                d.to_string(),
                EntryKind::Directory { mode: 0o755 },
                Vec::new(),
            );
        }
    }

    let cpio = write_cpio(&rootfs);
    let ram = args.ram_mib.unwrap_or_else(|| size_ram_mib(content));
    println!(
        "  initramfs: {} · guest RAM {} MiB",
        human_bytes(cpio.len() as u64),
        ram
    );

    if args.dry_run {
        println!("  --dry-run: nothing written (would be {})", out.display());
        // A dry run is precisely when someone is checking whether their kernel
        // is the right one, so it is the last place that should stay quiet.
        if let Some(w) = kernel.as_ref().and_then(|(_, b)| warn_kernel_virtio(b)) {
            println!("\nNOTE: {w}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let (kernel_path, kernel_image) = kernel.ok_or("--kernel is required")?;
    write_image_dir(
        &out,
        &kernel_path,
        &kernel_image,
        &cpio,
        &args,
        ram,
        &entrypoint,
        &report,
        pulled,
        libc,
    )?;

    println!("\nWrote {}", out.display());
    if let Some(w) = libc.warning() {
        println!("\nNOTE: {}", w.replace('\n', "\n      "));
    }
    if let Some(w) = warn_kernel_virtio(&kernel_image) {
        println!("\nNOTE: {w}");
    }
    println!(
        "Boot it:  chm create --kernel {}/Image --initramfs {}/initramfs \\\n\
         \t    --cpus {} --memory {}",
        out.display(),
        out.display(),
        args.vcpus,
        ram
    );
    println!("      or: pick it in Gimbal Local under New sandbox.");
    if report.has_findings() {
        println!("See {}/BUILD.txt for what was refused.", out.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// Decompress if needed, then parse the tar.
///
/// The media type is authoritative for *refusing* a format, but the magic bytes
/// decide how to *read* one: registries in the wild label gzip layers as plain
/// `tar` often enough that trusting the label alone turns a working image into
/// an unexplained parse error.
/// Decompress a layer blob, choosing the codec by **magic bytes** rather than by
/// the media type the registry declared.
///
/// Registries mislabel layers often enough that the declared `mediaType` is a
/// hint, not a fact — a gzip layer served as `tar` and a `tar+gzip` that is
/// really plain tar are both things this has already had to survive. Sniffing
/// costs four bytes and cannot be wrong about what it is looking at.
///
/// The bomb limit is passed through unchanged and applies to the running total
/// of unpacked bytes, which matters more here than for gzip: zstd reaches far
/// higher ratios, so this is the format where that limit earns its keep.
fn read_blob(blob: &[u8], limit: u64) -> Result<targz::Layer, String> {
    if blob.starts_with(&[0x1f, 0x8b]) {
        return targz::read_layer(GzDecoder::new(blob), limit);
    }
    // zstd frame magic, little-endian 0xFD2FB528.
    if blob.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let dec = ZstdDecoder::new(blob)
            .map_err(|e| format!("this layer is zstd but could not be opened: {e}"))?;
        return targz::read_layer(dec, limit);
    }
    targz::read_layer(blob, limit)
}

fn print_report(report: &apply::Report) {
    if report.whiteouts > 0 || report.opaques > 0 {
        println!(
            "  {} whiteout(s), {} opaque directory marker(s) applied",
            report.whiteouts, report.opaques
        );
    }
    for r in &report.sanitised {
        println!("  changed: {r}");
    }
    for r in &report.refused {
        println!("  REFUSED: {r}");
    }
    for n in &report.skipped_nodes {
        println!("  skipped: {n}");
    }
}

#[allow(clippy::too_many_arguments)]
fn write_image_dir(
    out: &Path,
    kernel_path: &Path,
    kernel_image: &[u8],
    cpio: &[u8],
    args: &Args,
    ram: u64,
    entrypoint: &str,
    report: &apply::Report,
    pulled: u64,
    libc: Libc,
) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    // Write the decoded bytes rather than copying the source file: what the
    // user passed may have been an EFI zboot or gzip wrapper, and the image
    // directory has to hold a bootable `Image`. Writing also keeps the earlier
    // property that the directory works when the original kernel is moved or
    // deleted, which a link would not.
    let kernel_dst = out.join("Image");
    fs::write(&kernel_dst, kernel_image)
        .map_err(|e| format!("write kernel to {}: {e}", kernel_dst.display()))?;

    let initramfs_dst = out.join("initramfs");
    fs::write(&initramfs_dst, cpio)
        .map_err(|e| format!("write {}: {e}", initramfs_dst.display()))?;

    let manifest = manifest(args.vcpus, ram);

    let manifest_path = out.join("image.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("encode image.json: {e}"))?,
    )
    .map_err(|e| format!("write {}: {e}", manifest_path.display()))?;

    let mut notes = String::new();
    let _ = writeln!(
        notes,
        "built by `chm image build` from {}",
        args.reference.display()
    );
    let _ = writeln!(notes, "kernel:     {} (copied)", kernel_path.display());
    let _ = writeln!(notes, "entrypoint: {entrypoint}");
    let _ = writeln!(notes, "libc:       {}", libc.label());
    if let Some(w) = libc.warning() {
        let _ = writeln!(notes, "            {}", w.replace('\n', "\n            "));
    }
    let _ = writeln!(notes, "pulled:     {} compressed", human_bytes(pulled));
    let _ = writeln!(notes, "initramfs:  {}", human_bytes(cpio.len() as u64));
    let _ = writeln!(
        notes,
        "ram_mib:    {ram} — an initramfs unpacks into guest RAM, so the rootfs is\n            \
         resident roughly twice at the peak. Override with --ram-mib."
    );
    let _ = writeln!(
        notes,
        "\nThe rootfs is an initramfs: it lives in RAM and does not persist across\n\
         a boot. Attach a disk with `chm create --disk` for state that should survive."
    );
    if report.has_findings() {
        let _ = writeln!(notes, "\nWhat was refused or changed:");
        for r in &report.refused {
            let _ = writeln!(notes, "  REFUSED {r}");
        }
        for r in &report.sanitised {
            let _ = writeln!(notes, "  CHANGED {r}");
        }
        for n in &report.skipped_nodes {
            let _ = writeln!(notes, "  SKIPPED {n}");
        }
    }
    fs::write(out.join("BUILD.txt"), notes).map_err(|e| format!("write BUILD.txt: {e}"))?;
    Ok(())
}

/// What `image.json` says about a freshly built image.
///
/// # Why there is no `cmdline` here
///
/// A container rootfs needs nothing beyond what `chm create` already boots
/// with, and naming it here would not be a *copy* of that default -- it would
/// be a second definition of it, which is worse than none.
///
/// Worse in a specific, measured way: the app passes a manifest `cmdline`
/// straight to `--cmdline`, and an explicit `--cmdline` is by design never
/// appended to. So restating the console alone silently removed `earlycon`,
/// `panic=1` and the guest's wall clock -- every one of them, and only on the
/// path a user takes through the app, which is the path whose command line
/// nobody reads.
///
/// An image that genuinely needs different boot arguments can still say so.
/// This is about not claiming to need them when we do not.
fn manifest(vcpus: u32, ram_mib: u64) -> serde_json::Value {
    json!({
        "kernel": "Image",
        "initramfs": "initramfs",
        "vcpus": vcpus,
        "ram_mib": ram_mib,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn a_reference_and_a_kernel_are_parsed() {
        let a = parse(&[
            "alpine:3.20".to_string(),
            "--kernel".to_string(),
            "/k/Image".to_string(),
        ])
        .unwrap();
        assert_eq!(a.reference.repository, "library/alpine");
        assert_eq!(a.kernel.unwrap(), PathBuf::from("/k/Image"));
        assert_eq!(a.vcpus, 2);
    }

    #[test]
    fn a_missing_reference_is_refused_with_the_help() {
        let e = parse(&["--kernel".to_string(), "/k".to_string()]).unwrap_err();
        assert!(e.contains("which image?"), "{e}");
    }

    #[test]
    fn an_unknown_option_is_refused_rather_than_treated_as_a_reference() {
        let e = parse(&["--wat".to_string()]).unwrap_err();
        assert!(e.contains("unknown option"), "{e}");
    }

    #[test]
    fn a_non_numeric_ram_is_refused_by_name() {
        let e = parse(&["a".to_string(), "--ram-mib".to_string(), "lots".to_string()]).unwrap_err();
        assert!(e.contains("--ram-mib wants a number"), "{e}");
    }

    /// Sizing must never come back below the floor, or a tiny image produces a
    /// guest with no room to do anything once it boots.
    #[test]
    fn a_tiny_rootfs_still_gets_workable_ram() {
        assert_eq!(size_ram_mib(0), RAM_FLOOR_MIB);
        assert_eq!(size_ram_mib(1024), RAM_FLOOR_MIB);
    }

    /// The doubling is the load-bearing part: an initramfs is resident twice
    /// during unpack, so sizing RAM at the rootfs size boots into an OOM that
    /// looks like a corrupt archive.
    #[test]
    fn a_large_rootfs_gets_more_than_twice_its_size() {
        let gib = 1024 * 1024 * 1024;
        let ram = size_ram_mib(gib);
        assert!(ram >= 2048, "1 GiB rootfs sized at {ram} MiB");
        assert_eq!(ram % 256, 0, "rounded to a sane boundary");
    }

    #[test]
    fn the_default_output_name_is_a_safe_path_segment() {
        let r = reference::parse("ghcr.io/owner/name:v1.2").unwrap();
        assert_eq!(default_out_name(&r), "name-v1.2");
        let r = reference::parse(&format!("ubuntu@sha256:{}", "ab".repeat(32))).unwrap();
        let n = default_out_name(&r);
        assert!(!n.contains(':'), "{n}");
        assert!(!n.contains('/'), "{n}");
    }

    /// A wrapped kernel is unwrapped rather than refused, and the bytes that
    /// reach the image directory are the ones a guest can execute. The old
    /// behaviour here was to refuse gzip and tell the user to run `gunzip`
    /// themselves, which is a chore we can do for them (#220).
    #[test]
    fn a_gzip_kernel_is_unwrapped_rather_than_refused() {
        let dir = env::temp_dir().join(format!("chm-img-{}", process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("Image.gz");
        let mut inner = vec![0u8; 4096];
        inner[56..60].copy_from_slice(b"ARM\x64");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut enc, &inner).unwrap();
        fs::write(&p, enc.finish().unwrap()).unwrap();

        let (bytes, form) = read_kernel(&p).unwrap();
        assert_eq!(&bytes[56..60], b"ARM\x64");
        assert!(form.was_compressed(), "{form:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// An x86 kernel produces a guest that emits nothing at all, which reads as
    /// a broken hypervisor rather than the wrong file.
    #[test]
    fn a_kernel_without_the_arm64_magic_is_refused() {
        let dir = env::temp_dir().join(format!("chm-img2-{}", process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("Image");
        fs::write(&p, vec![0u8; 128]).unwrap();
        let e = read_kernel(&p).unwrap_err();
        assert!(e.contains("arm64"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The virtio scan must see the decoded kernel.
    ///
    /// A wrapped kernel's compressed bytes contain none of the strings
    /// [`VirtioBuiltin::scan`] looks for, so scanning the file on disk reports
    /// "no virtio built in" for a kernel that has it — sending someone down the
    /// #222 module-loading workaround for a guest whose devices would have
    /// worked. Wrong in the direction that costs an afternoon.
    #[test]
    fn the_virtio_scan_reads_the_decoded_kernel_not_the_wrapper() {
        let dir = env::temp_dir().join(format!("chm-imgv-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        // A kernel that does carry all three virtio strings, so the correct
        // answer is silence.
        let mut inner = vec![0u8; 8192];
        inner[56..60].copy_from_slice(b"ARM\x64");
        let mut at = 1024;
        for s in ["virtio-mmio", "virtio_net", "virtio_blk"] {
            inner[at] = 0;
            inner[at + 1..at + 1 + s.len()].copy_from_slice(s.as_bytes());
            inner[at + 1 + s.len()] = 0;
            at += 64;
        }
        assert!(
            warn_kernel_virtio(&inner).is_none(),
            "the uncompressed form should warn about nothing"
        );

        let p = dir.join("vmlinuz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut enc, &inner).unwrap();
        fs::write(&p, enc.finish().unwrap()).unwrap();

        let (decoded, _) = read_kernel(&p).unwrap();
        assert!(
            warn_kernel_virtio(&decoded).is_none(),
            "a wrapped kernel with virtio built in must not be warned about"
        );
        // And the thing that must never be what gets scanned:
        assert!(
            warn_kernel_virtio(&fs::read(&p).unwrap()).is_some(),
            "precondition: the compressed bytes really do look device-less"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The bytes in the image directory must be the ones a guest can execute,
    /// not the file that was named.
    ///
    /// Without this, `image build` accepts a zboot kernel, prints that it
    /// decompressed it, and writes the *wrapper* into `Image` — an image that
    /// announces success and cannot boot. Every other test in this file passes
    /// while that is true, because none of them reads what was written.
    #[test]
    fn the_image_directory_holds_the_decoded_kernel_not_the_file_named() {
        let dir = env::temp_dir().join(format!("chm-imgw-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        // A source file that is deliberately NOT a bootable Image, so copying
        // it instead of writing the decoded bytes is unmistakable.
        let src = dir.join("vmlinuz");
        fs::write(&src, b"wrapper bytes, not a kernel").unwrap();

        let mut decoded = vec![0u8; 4096];
        decoded[56..60].copy_from_slice(b"ARM\x64");

        let out = dir.join("image");
        write_image_dir(
            &out,
            &src,
            &decoded,
            b"cpio",
            &parse(&["alpine:3.20".to_string()]).unwrap(),
            512,
            "/bin/sh",
            &apply::Report::default(),
            0,
            Libc::Musl,
        )
        .unwrap();

        let written = fs::read(out.join("Image")).unwrap();
        assert_eq!(written, decoded, "the wrapper was written, not the kernel");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_arm64_header_is_accepted() {
        let dir = env::temp_dir().join(format!("chm-img3-{}", process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("Image");
        let mut data = vec![0u8; 128];
        data[56..60].copy_from_slice(b"ARM\x64");
        fs::write(&p, &data).unwrap();
        let (bytes, form) = read_kernel(&p).unwrap();
        assert_eq!(bytes, data);
        assert!(!form.was_compressed(), "{form:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A console mismatch produces a guest that boots correctly and emits
    /// nothing — the failure mode hardest to attribute. This asserts against
    /// `create.rs`'s own source so the two cannot drift apart silently.
    #[test]
    fn the_manifest_does_not_restate_the_default_command_line() {
        // The app passes a manifest cmdline straight to `--cmdline`, and that
        // flag is deliberately never appended to -- so a manifest that merely
        // repeats the default is not a no-op, it is a silent downgrade.
        let m = manifest(2, 1024);
        assert!(
            m.get("cmdline").is_none(),
            "image.json names a command line again: {m}"
        );
        // The default it defers to still has to name a console the guest has.
        assert!(
            crate::coldboot::default_cmdline().contains("console=ttyAMA0"),
            "chm create no longer defaults to ttyAMA0"
        );
    }

    #[test]
    fn the_help_names_the_kernel_requirement() {
        let u = usage();
        assert!(u.contains("--kernel"), "{u}");
        assert!(
            u.contains("carries no kernel") || u.contains("carries no kernel"),
            "{u}"
        );
    }

    /// A ustar entry, enough of a tar writer to build a real layer in-test.
    fn tar_entry(name: &str, body: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        h[156] = b'0';
        h[257..262].copy_from_slice(b"ustar");
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h.extend_from_slice(body);
        h.extend(std::iter::repeat_n(0u8, (512 - body.len() % 512) % 512));
        h
    }

    /// A zstd layer is decompressed and read (#206).
    ///
    /// This is the assertion the feature actually rests on. Removing the
    /// pull-time refusal is necessary and proves nothing on its own -- without
    /// this, `chm image build` would accept a zstd image and then fail deep in
    /// the tar reader with "unreadable size field", which is a worse outcome
    /// than the honest refusal it replaced.
    ///
    /// Compressed here with the real encoder rather than a checked-in blob, so
    /// the test exercises a frame the zstd crate itself considers valid.
    #[test]
    fn a_zstd_compressed_layer_is_decompressed_and_read() {
        let tar = tar_entry("etc/hostname", b"gimbal\n");
        let squashed = zstd::stream::encode_all(&tar[..], 3).expect("encode");

        assert_eq!(
            &squashed[..4],
            &[0x28, 0xb5, 0x2f, 0xfd],
            "the encoder must emit the magic read_blob sniffs for"
        );
        assert!(
            squashed != tar,
            "the fixture must actually be compressed, or this proves nothing"
        );

        let layer = read_blob(&squashed, 1 << 20).expect("a zstd layer must be readable");
        assert_eq!(layer.entries.len(), 1);
        assert_eq!(layer.entries[0].raw.path, "etc/hostname");
        assert_eq!(layer.entries[0].data, b"gimbal\n");
    }

    /// The codec is chosen by magic, not by the media type -- so a layer whose
    /// bytes are zstd is read no matter what the registry called it, and the
    /// gzip and plain-tar paths still work beside it.
    ///
    /// Registries mislabel layers often enough that this is the difference
    /// between working and not: `read_blob` never sees a `mediaType` at all.
    #[test]
    fn every_codec_is_recognised_by_its_bytes() {
        let tar = tar_entry("etc/hostname", b"gimbal\n");

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let gz = gz.finish().unwrap();

        let zs = zstd::stream::encode_all(&tar[..], 3).unwrap();

        for (what, blob) in [("plain", &tar), ("gzip", &gz), ("zstd", &zs)] {
            let layer = read_blob(blob, 1 << 20)
                .unwrap_or_else(|e| panic!("the {what} layer must be readable: {e}"));
            assert_eq!(
                layer.entries[0].data, b"gimbal\n",
                "the {what} layer must decode to the same bytes"
            );
        }
    }

    /// The decompression-bomb limit applies to zstd too.
    ///
    /// This is the format where it earns its keep: zstd reaches far higher
    /// ratios than gzip, so a limit that only covered the gzip path would leave
    /// the dangerous codec unguarded. 4 MiB of zeroes compresses to a few
    /// hundred bytes -- small enough that no size check on the *blob* would ever
    /// notice, which is exactly why the limit is on the unpacked running total.
    #[test]
    fn a_zstd_bomb_is_stopped_by_the_same_limit_gzip_is() {
        let tar = tar_entry("big", &vec![0u8; 4 << 20]);
        let bomb = zstd::stream::encode_all(&tar[..], 19).unwrap();
        assert!(
            bomb.len() < 64 * 1024,
            "the fixture must be a real bomb (got {} bytes), or the limit is not \
             what stopped it",
            bomb.len()
        );

        let e = read_blob(&bomb, 1 << 20).expect_err("a zstd bomb must be refused");
        assert!(
            e.contains("too large") || e.contains("limit"),
            "the refusal must name the limit, got: {e}"
        );
    }

    /// The exact path Debian's node:22-slim ships, read back out of the cpio
    /// this build produced. Three levels down and usr-merged, which is why the
    /// classifier matches a file name rather than a directory.
    #[test]
    fn a_usr_merged_glibc_image_is_recognised() {
        let paths = [
            "usr/bin/node",
            "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            "usr/lib/aarch64-linux-gnu/libc.so.6",
        ];
        assert_eq!(libc_flavour(paths.into_iter()), Libc::Gnu);
        assert_eq!(libc_flavour(paths.into_iter()).warning(), None);
    }

    /// The exact path node:22-alpine ships. Directly under `lib/`, nowhere
    /// near where glibc lives.
    #[test]
    fn a_musl_image_is_recognised_and_warned_about() {
        let paths = ["usr/bin/node", "lib/ld-musl-aarch64.so.1"];
        assert_eq!(libc_flavour(paths.into_iter()), Libc::Musl);
        let w = libc_flavour(paths.into_iter())
            .warning()
            .expect("musl is the case worth interrupting someone over");
        assert!(w.contains("napi_"), "name the symptom the user will actually see: {w}");
        assert!(w.contains("glibc"), "name the remedy: {w}");
    }

    /// The classifier is documented as layout-independent, so it is asserted at
    /// a second layout. Without this, anchoring the musl branch to `lib/` — the
    /// one place Alpine happens to put it — passes the whole suite, which is
    /// exactly what mutation M2 demonstrated.
    #[test]
    fn a_musl_loader_is_recognised_wherever_it_sits() {
        for p in [
            "lib/ld-musl-aarch64.so.1",
            "usr/lib/ld-musl-aarch64.so.1",
            "usr/lib/aarch64-linux-musl/ld-musl-aarch64.so.1",
        ] {
            assert_eq!(
                libc_flavour(["usr/bin/node", p].into_iter()),
                Libc::Musl,
                "{p} should classify"
            );
        }
    }

    /// An image we cannot classify is not thereby broken. Reporting it as a
    /// problem would make the note worthless on every image that is fine.
    #[test]
    fn an_unclassifiable_image_is_not_reported_as_a_problem() {
        let paths = ["bin/busybox", "etc/passwd"];
        assert_eq!(libc_flavour(paths.into_iter()), Libc::Unknown);
        assert_eq!(libc_flavour(paths.into_iter()).warning(), None);
        assert_eq!(Libc::Unknown.label(), "not identified");
    }

    /// Both readings of a two-loader image are real and nothing here can tell
    /// them apart, so it must not claim either. A warning that fires on a
    /// working glibc image is worse than a missing one.
    #[test]
    fn an_image_with_both_loaders_claims_neither() {
        let both = [
            "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            "lib/ld-musl-aarch64.so.1",
        ];
        assert_eq!(libc_flavour(both.into_iter()), Libc::Unknown);
        assert_eq!(libc_flavour(both.into_iter()).warning(), None);
        // Order must not decide it.
        let reversed: Vec<&str> = both.into_iter().rev().collect();
        assert_eq!(libc_flavour(reversed.into_iter()), Libc::Unknown);
    }

    /// A note *about* the loader is not a loader. `.so` is what separates them,
    /// and this fired for real on the first run.
    #[test]
    fn a_file_named_after_a_loader_does_not_classify_the_image() {
        let paths = ["opt/ld-musl-notes/README", "srv/ld-linux-aarch64.so.1.txt"];
        assert_eq!(libc_flavour(paths.into_iter()), Libc::Unknown);
    }

}
