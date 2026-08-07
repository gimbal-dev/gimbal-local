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

/// The kernel command line written into `image.json`.
///
/// `console=ttyAMA0` matches `chm create`'s own default (`create.rs`). It is
/// asserted against that default in a test, because the two drifting apart
/// yields a guest that boots and says nothing.
const DEFAULT_CMDLINE: &str = "console=ttyAMA0";

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

/// Is this file an uncompressed arm64 kernel `Image`?
///
/// The app already refuses a gzip-compressed kernel by magic bytes and explains
/// why; refusing it here too means the failure appears at build time rather than
/// 30 seconds into a boot that produces no output.
fn check_kernel(path: &Path) -> Result<(), String> {
    let data =
        fs::read(path).map_err(|e| format!("cannot read kernel `{}`: {e}", path.display()))?;
    if data.len() < 64 {
        return Err(format!("`{}` is too small to be a kernel", path.display()));
    }
    if data[..2] == [0x1f, 0x8b] {
        return Err(format!(
            "`{}` is gzip-compressed; cold boot needs an uncompressed arm64 Image. \
             Run `gunzip -c {} > Image` first.",
            path.display(),
            path.display()
        ));
    }
    // arm64 Image header magic at offset 56: "ARM\x64".
    if &data[56..60] != b"ARM\x64" {
        return Err(format!(
            "`{}` does not carry the arm64 kernel Image magic. \
             An x86 bzImage or a vmlinux ELF will not boot on this Mac.",
            path.display()
        ));
    }
    Ok(())
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
fn warn_kernel_virtio(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    VirtioBuiltin::scan(&data).warning()
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
            check_kernel(k)?;
            Some(k.clone())
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
        if let Some(w) = kernel.as_deref().and_then(warn_kernel_virtio) {
            println!("\nNOTE: {w}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let kernel = kernel.ok_or("--kernel is required")?;
    write_image_dir(
        &out,
        &kernel,
        &cpio,
        &args,
        ram,
        &entrypoint,
        &report,
        pulled,
    )?;

    println!("\nWrote {}", out.display());
    if let Some(w) = warn_kernel_virtio(&kernel) {
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
    kernel: &Path,
    cpio: &[u8],
    args: &Args,
    ram: u64,
    entrypoint: &str,
    report: &apply::Report,
    pulled: u64,
) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    // Copy rather than link: the image directory has to keep working when the
    // kernel it was built from is moved or deleted, and `chm` opens disks
    // no-follow so a directory of links is a format that half-works.
    let kernel_dst = out.join("Image");
    fs::copy(kernel, &kernel_dst)
        .map_err(|e| format!("copy kernel to {}: {e}", kernel_dst.display()))?;

    let initramfs_dst = out.join("initramfs");
    fs::write(&initramfs_dst, cpio)
        .map_err(|e| format!("write {}: {e}", initramfs_dst.display()))?;

    let manifest = json!({
        "kernel": "Image",
        "initramfs": "initramfs",
        // `chm create`'s own default console. Getting this wrong produces a
        // guest that boots correctly and emits nothing, which is
        // indistinguishable from a hang. Deliberately without `quiet`: a
        // container rootfs is a new thing to boot and the kernel messages are
        // how a user finds out what it did.
        "cmdline": DEFAULT_CMDLINE,
        "vcpus": args.vcpus,
        "ram_mib": ram,
    });
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
    let _ = writeln!(notes, "kernel:     {} (copied)", kernel.display());
    let _ = writeln!(notes, "entrypoint: {entrypoint}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;
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

    #[test]
    fn a_gzip_kernel_is_refused_with_the_remedy() {
        let dir = env::temp_dir().join(format!("chm-img-{}", process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("Image");
        let mut data = vec![0x1f, 0x8b];
        data.extend(iter::repeat_n(0u8, 100));
        fs::write(&p, &data).unwrap();
        let e = check_kernel(&p).unwrap_err();
        assert!(e.contains("gunzip"), "{e}");
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
        let e = check_kernel(&p).unwrap_err();
        assert!(e.contains("arm64 kernel Image magic"), "{e}");
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
        check_kernel(&p).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// A console mismatch produces a guest that boots correctly and emits
    /// nothing — the failure mode hardest to attribute. This asserts against
    /// `create.rs`'s own source so the two cannot drift apart silently.
    #[test]
    fn the_written_cmdline_matches_the_console_chm_create_uses() {
        let create = include_str!("../create.rs");
        assert!(
            create.contains("console=ttyAMA0"),
            "chm create no longer defaults to ttyAMA0; image.json would name a \
             console the guest does not have"
        );
        assert!(DEFAULT_CMDLINE.contains("console=ttyAMA0"));
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
}
