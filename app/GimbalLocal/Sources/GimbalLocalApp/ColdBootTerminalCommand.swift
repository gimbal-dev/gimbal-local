// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// Builds the shell command Gimbal Local hands to Terminal.app to cold-boot a
/// local image with `chm create` — no snapshot, no control plane.
///
/// Security (invariant I5, `docs/security-model.md`): identical discipline to
/// `InteractiveTerminalCommand` — every interpolated value is single-quoted and
/// screened for control characters, because the app launches host commands and
/// a path must never become host shell code. This is a separate builder rather
/// than a parameter on the connect one because the two commands share no
/// arguments, and folding them together would produce a builder whose
/// correctness depends on which half of its inputs are nil.
///
/// A subprocess, rather than a daemon call, is the *correct* shape here and not
/// a shortcut: `hv_vm_create` is process-global, so one HVF VM per process is a
/// hard platform constraint. The daemon owns a single VM slot; routing cold
/// boots through it would serialise them behind whatever the daemon is already
/// running. This is also how the app already runs `chm connect`.
enum ColdBootTerminalCommand {
    enum BuildError: Error, LocalizedError, Equatable {
        case invalidPath(String)
        /// An egress host with a shell metacharacter or control character.
        case invalidEgressHost(String)

        var errorDescription: String? {
            switch self {
            case .invalidPath(let path):
                return "refusing to cold-boot with a path containing control characters: \(path)"
            case .invalidEgressHost(let host):
                return "refusing to allow egress to a malformed host: \(host)"
            }
        }
    }

    private static let sessionBanner = "Gimbal Local — cold boot (no snapshot)"
    private static let usageHint =
        "Booting a local image directly on Hypervisor.framework. This guest was "
        + "never captured anywhere: it starts from a kernel on this Mac. Press "
        + "Ctrl-A x to stop it."
    private static let sessionEndedNotice =
        "-- Cold boot ended. Start it again from Gimbal Local. --"

    /// Options the UI can vary per launch. Defaults mirror `chm create`'s own,
    /// so an unset field means "whatever chm does", never a value we invented.
    struct Options: Equatable {
        var vcpus: Int?
        var ramMib: Int?
        var cmdline: String?
        /// `host:port` pairs the guest may reach. Empty keeps the default
        /// deny-all posture that every other sandbox in this tree gets.
        var egressAllow: [String] = []
        /// Attach a NIC. Required for any egress at all.
        var net: Bool = false
        /// Seconds before `chm` stops the guest. 0 runs until the guest powers
        /// off or the user presses Ctrl-A x — which is what an interactive
        /// terminal session wants, because a timer expiring mid-write is a
        /// power cut on a writable disk.
        var seconds: Int = 0
        /// Credential-proxy rules file, and the workspace holding its CA.
        var proxyRules: String?
        var workspace: String?
    }

    /// True when `host` is a plausible `host:port` and carries nothing that
    /// could escape a single-quoted shell word or break the argument list.
    static func isCleanEgressHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 255 else { return false }
        guard InteractiveTerminalCommand.isCleanPath(host) else { return false }
        // Quoting already neutralises metacharacters; this is the second layer,
        // rejecting anything that is not host:port shaped so a typo surfaces
        // here rather than as an opaque chm parse error.
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:_[]")
        return host.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// Build the `&&`-joined shell command that cold-boots `image`.
    ///
    /// Throws `BuildError` if any path carries a control character or an egress
    /// host is malformed.
    static func shellCommand(
        chmPath: String,
        image: LocalImage,
        options: Options,
        workdir: String
    ) throws -> String {
        var paths = [chmPath, image.kernelPath, workdir]
        if let initramfs = image.initramfsPath { paths.append(initramfs) }
        paths.append(contentsOf: image.diskPaths)
        if let rules = options.proxyRules { paths.append(rules) }
        if let workspace = options.workspace { paths.append(workspace) }
        for path in paths where !InteractiveTerminalCommand.isCleanPath(path) {
            throw BuildError.invalidPath(path)
        }
        for host in options.egressAllow where !isCleanEgressHost(host) {
            throw BuildError.invalidEgressHost(host)
        }

        let quote = InteractiveTerminalCommand.shellQuote

        var argv = [quote(chmPath), "create", "--kernel", quote(image.kernelPath)]
        if let initramfs = image.initramfsPath {
            argv.append(contentsOf: ["--initramfs", quote(initramfs)])
        }
        for disk in image.diskPaths {
            argv.append(contentsOf: ["--disk", quote(disk)])
        }
        if let cmdline = options.cmdline ?? image.cmdline, !cmdline.isEmpty {
            guard InteractiveTerminalCommand.isCleanPath(cmdline) else {
                throw BuildError.invalidPath(cmdline)
            }
            argv.append(contentsOf: ["--cmdline", quote(cmdline)])
        }
        if let cpus = options.vcpus ?? image.vcpus {
            argv.append(contentsOf: ["--cpus", String(cpus)])
        }
        if let ram = options.ramMib ?? image.ramMib {
            argv.append(contentsOf: ["--memory", String(ram)])
        }
        if options.net {
            argv.append("--net")
        }
        for host in options.egressAllow {
            argv.append(contentsOf: ["--egress-allow", quote(host)])
        }
        if let rules = options.proxyRules {
            argv.append(contentsOf: ["--proxy-rules", quote(rules)])
        }
        if let workspace = options.workspace {
            argv.append(contentsOf: ["--workspace", quote(workspace)])
        }
        argv.append(contentsOf: ["--seconds", String(max(0, options.seconds))])

        return wrap(argv: argv, workdir: workdir, quote: quote)
    }

    /// Build the command that cold-boots whatever `specDirectory/sandbox.json`
    /// describes.
    ///
    /// This is the de-duplication #150 asked for. `shellCommand` above knows the
    /// name and meaning of eleven `chm create` flags, and every one of them is a
    /// fact about `chm` that the app has to be kept in step with by hand. Here
    /// the app knows one flag, and the sandbox's own file carries the rest — so
    /// a flag `chm` gains, renames or changes the default of costs no change
    /// here at all.
    ///
    /// The escaping surface shrinks with it: two paths to validate instead of
    /// eleven, under the same invariant-I5 discipline.
    static func specShellCommand(
        chmPath: String,
        specDirectory: String,
        workdir: String
    ) throws -> String {
        for path in [chmPath, specDirectory, workdir]
        where !InteractiveTerminalCommand.isCleanPath(path) {
            throw BuildError.invalidPath(path)
        }
        let quote = InteractiveTerminalCommand.shellQuote
        let argv = [quote(chmPath), "create", "--spec", quote(specDirectory)]
        return wrap(argv: argv, workdir: workdir, quote: quote)
    }

    /// The shared banner/`cd`/exit wrapper both routes end in, so the session a
    /// user sees is identical whichever produced it.
    private static func wrap(
        argv: [String],
        workdir: String,
        quote: (String) -> String
    ) -> String {
        [
            "cd \(quote(workdir))",
            "echo \(quote(sessionBanner))",
            "echo \(quote(usageHint))",
            argv.joined(separator: " "),
        ].joined(separator: " && ")
            + "; echo \(quote(sessionEndedNotice)); exit"
    }
}
