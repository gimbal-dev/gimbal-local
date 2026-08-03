// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// A bootable guest that exists as **files on this Mac** — a kernel, optionally
/// an initramfs and disks — with no snapshot and no control plane anywhere in
/// the path.
///
/// This is the "bring your own image" half of the local MVP. Every other way to
/// start a sandbox in this app begins with something captured on a KVM host: a
/// library snapshot, or a bundle brought down from a control plane. That makes
/// the app's most basic capability — *start a Linux guest* — depend on
/// infrastructure the user may not have. A local image removes that dependency
/// entirely: `chm create` cold-boots it on HVF directly.
///
/// Cold boot is not merely a convenience here. A cold-booted guest reads *this*
/// Mac's `CTR_EL0` and keeps its `ic ivau` instructions, so it is immune by
/// construction to the instruction-cache staleness that makes JIT workloads
/// (node, npm) fault on a Graviton capture. See `docs/cpu-feature-deltas.md`.
struct LocalImage: Identifiable, Equatable, Hashable {
    /// Directory name — stable, unique within a library, and what the user sees.
    var id: String { name }

    let name: String
    /// Absolute path to the image directory.
    let path: String
    /// Uncompressed arm64 `Image`. A distro `vmlinuz` is gzip and will not boot;
    /// discovery refuses one rather than letting the guest fail confusingly.
    let kernelPath: String
    let initramfsPath: String?
    /// Raw disk images. The first becomes `/dev/vda`.
    let diskPaths: [String]
    let cmdline: String?
    let vcpus: Int?
    let ramMib: Int?

    /// Manifest shape for `image.json`. Every field except `kernel` is optional,
    /// so the smallest useful manifest is one line.
    struct Manifest: Codable {
        var kernel: String?
        var initramfs: String?
        var disks: [String]?
        var cmdline: String?
        var vcpus: Int?
        var ramMib: Int?

        enum CodingKeys: String, CodingKey {
            case kernel, initramfs, disks, cmdline, vcpus
            case ramMib = "ram_mib"
        }
    }

    /// Why an image directory could not be used, phrased so the UI can show it
    /// without the user having to go read `chm create --help`.
    enum Rejection: Equatable {
        case noKernel
        case kernelIsCompressed(String)
        case missingFile(String)
        case symlinkedDisk(String)

        var reason: String {
            switch self {
            case .noKernel:
                return "No kernel — expected an `Image` file or an `image.json` naming one"
            case .kernelIsCompressed(let name):
                return "`\(name)` is gzip-compressed; cold boot needs an uncompressed arm64 Image (gunzip it first)"
            case .missingFile(let name):
                return "`\(name)` is named in image.json but is not in the directory"
            case .symlinkedDisk(let name):
                return "`\(name)` is a symlink; disks are opened no-follow so a link cannot redirect guest writes onto a host file. Use `cp -c \(name)` — an APFS clone is instant and costs no space."
            }
        }
    }
}

/// Discovers local images in a directory, and explains the ones it refuses.
///
/// Kept a pure function over an injected file lister so the whole policy —
/// which layouts are accepted, which are refused and why — is unit-tested
/// without touching a real filesystem.
enum LocalImageLibrary {
    /// Filenames accepted as an uncompressed arm64 kernel, in preference order.
    static let kernelNames = ["Image", "vmlinux", "kernel"]
    /// Filenames that are *nearly* right and produce a confusing failure, so we
    /// name the problem instead of booting into a panic.
    static let compressedKernelNames = ["Image.gz", "vmlinuz", "vmlinuz.gz", "zImage"]
    /// Filenames accepted as a root disk when there is no manifest.
    static let diskNames = ["rootfs.img", "rootfs.raw", "disk.img", "disk.raw"]
    static let initramfsNames = ["initramfs", "initrd", "initramfs.cpio", "initrd.img"]

    struct Entry: Equatable {
        let name: String
        let image: LocalImage?
        let rejection: LocalImage.Rejection?
    }

    /// Classify one image directory from its listing. `manifestJSON` is the
    /// contents of `image.json` if present.
    ///
    /// A manifest wins over convention, because someone who wrote one meant it;
    /// but a manifest naming a file that is not there is an error rather than a
    /// silent fallback, or a typo would boot the wrong disk.
    static func classify(
        name: String,
        path: String,
        entries: [String],
        manifestJSON: Data?,
        isSymlink: (String) -> Bool = { _ in false }
    ) -> Entry {
        let present = Set(entries)

        func reject(_ r: LocalImage.Rejection) -> Entry {
            Entry(name: name, image: nil, rejection: r)
        }
        func joined(_ file: String) -> String {
            (path as NSString).appendingPathComponent(file)
        }

        var manifest: LocalImage.Manifest?
        if let manifestJSON,
           let decoded = try? JSONDecoder().decode(LocalImage.Manifest.self, from: manifestJSON)
        {
            manifest = decoded
        }

        // Kernel.
        let kernelFile: String
        if let named = manifest?.kernel, !named.isEmpty {
            guard present.contains(named) else { return reject(.missingFile(named)) }
            kernelFile = named
        } else if let found = kernelNames.first(where: { present.contains($0) }) {
            kernelFile = found
        } else if let compressed = compressedKernelNames.first(where: { present.contains($0) }) {
            return reject(.kernelIsCompressed(compressed))
        } else {
            return reject(.noKernel)
        }

        // A manifest-named kernel that is itself gzip is the same trap.
        if compressedKernelNames.contains(kernelFile) {
            return reject(.kernelIsCompressed(kernelFile))
        }

        // Initramfs.
        var initramfs: String?
        if let named = manifest?.initramfs, !named.isEmpty {
            guard present.contains(named) else { return reject(.missingFile(named)) }
            initramfs = joined(named)
        } else if let found = initramfsNames.first(where: { present.contains($0) }) {
            initramfs = joined(found)
        }

        // Disks. `chm` opens them no-follow on purpose (M30.1), so a symlinked
        // disk fails ~25s into a boot with an errno that reads like a broken
        // image. Naming it here costs one lstat and turns a confusing runtime
        // failure into a fixable one -- the same trade as the gzip kernel. We
        // do not resolve the link ourselves: laundering it in the app would
        // defeat the control uniformly.
        var disks: [String] = []
        if let named = manifest?.disks, !named.isEmpty {
            for disk in named {
                guard present.contains(disk) else { return reject(.missingFile(disk)) }
                if isSymlink(disk) { return reject(.symlinkedDisk(disk)) }
                disks.append(joined(disk))
            }
        } else if let found = diskNames.first(where: { present.contains($0) }) {
            if isSymlink(found) { return reject(.symlinkedDisk(found)) }
            disks = [joined(found)]
        }

        return Entry(
            name: name,
            image: LocalImage(
                name: name,
                path: path,
                kernelPath: joined(kernelFile),
                initramfsPath: initramfs,
                diskPaths: disks,
                cmdline: manifest?.cmdline,
                vcpus: manifest?.vcpus,
                ramMib: manifest?.ramMib
            ),
            rejection: nil
        )
    }

    /// Scan `root` for image directories. Returns entries sorted by name so the
    /// UI order is stable across launches.
    static func scan(root: String, fileManager: FileManager = .default) -> [Entry] {
        guard !root.isEmpty,
              let children = try? fileManager.contentsOfDirectory(atPath: root)
        else {
            return []
        }

        var found: [Entry] = []
        for child in children.sorted() where !child.hasPrefix(".") {
            let dir = (root as NSString).appendingPathComponent(child)
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else {
                continue
            }
            guard let entries = try? fileManager.contentsOfDirectory(atPath: dir) else { continue }

            // A snapshot bundle is not a local image; skipping it keeps a user
            // who points this at their snapshot library from seeing every
            // bundle listed as a broken image.
            if entries.contains("state.json") { continue }

            let manifestPath = (dir as NSString).appendingPathComponent("image.json")
            let manifestJSON = fileManager.contents(atPath: manifestPath)
            found.append(
                classify(
                    name: child, path: dir, entries: entries, manifestJSON: manifestJSON,
                    isSymlink: { file in
                        let full = (dir as NSString).appendingPathComponent(file)
                        let attrs = try? fileManager.attributesOfItem(atPath: full)
                        return (attrs?[.type] as? FileAttributeType) == .typeSymbolicLink
                    }
                )
            )
        }
        return found
    }
}
