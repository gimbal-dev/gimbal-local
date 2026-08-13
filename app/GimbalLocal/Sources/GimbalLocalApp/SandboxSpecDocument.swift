// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// A `sandbox.json` the app can write, matching the document `chm spec` reads.
///
/// The app is deliberately **not** the authority on what a spec means. It writes
/// the file and asks `chm spec validate` whether it is any good, the same
/// division of labour `CredentialRuleBuilder` uses (V8.4): the app owns the
/// editing experience, `chm` owns the rules. Two implementations of one
/// validator eventually disagree, and the disagreement always surfaces as a
/// sandbox that started differently from the way the UI described it.
///
/// The field names are not ours. They come from the agent compute environment
/// spec, whose `hostRequirements.hypervisor` enumeration names
/// `cloud-hypervisor` — so a document written here is meant to be readable by
/// something other than us. See `chm/src/spec.rs` for the full argument.
struct SandboxSpecDocument: Codable, Equatable {
    var specVersion: Int = 1
    var name: String?
    var description: String?
    var image: Image?
    var resourceLimits: ResourceLimits?
    var networkPolicy: NetworkPolicy?
    var secrets: Secrets?
    var checkpoint: Checkpoint?
    var hostRequirements: HostRequirements?

    struct Image: Codable, Equatable {
        var kernel: String?
        var initramfs: String?
        var cmdline: String?
        var disks: [String]?
    }

    struct ResourceLimits: Codable, Equatable {
        var tier: String?
        var cpu: Cpu?
        var memory: Memory?
        var timeout: Timeout?

        struct Cpu: Codable, Equatable { var vcpus: Int? }
        struct Memory: Codable, Equatable { var ram: String? }
        struct Timeout: Codable, Equatable {
            var wallClock: String?
            var idle: String?
        }
    }

    struct NetworkPolicy: Codable, Equatable {
        var enabled: Bool?
        var defaultAction: String?
        var egress: [EgressRule]?

        struct EgressRule: Codable, Equatable {
            var action: String?
            var domains: [String]
            var ports: [Int]?
            var description: String?
        }
    }

    struct Secrets: Codable, Equatable {
        var rulesFile: String?
        var workspace: String?
    }

    struct Checkpoint: Codable, Equatable {
        var enabled: Bool?
        var interval: String?
    }

    struct HostRequirements: Codable, Equatable {
        var hypervisor: String?
        var arch: String?
    }

    /// The named sizing tiers, mirrored from `chm spec tiers` so the picker has
    /// something to show before any subprocess runs. `chm` remains authoritative:
    /// an unknown tier is refused there, not silently corrected here.
    static let tiers = ["micro", "dev", "standard", "performance"]

    static let filename = "sandbox.json"

    /// Describe an already-discovered image as a spec.
    ///
    /// This is the app's half of the de-duplication: instead of assembling
    /// eleven `chm create` flags at launch, it writes what the sandbox *is*
    /// once, and the launch command becomes a single `--spec`.
    static func describing(
        image: LocalImage,
        options: ColdBootTerminalCommand.Options
    ) -> SandboxSpecDocument {
        var doc = SandboxSpecDocument()
        doc.name = image.name
        doc.image = Image(
            kernel: image.kernelPath,
            initramfs: image.initramfsPath,
            cmdline: options.cmdline ?? image.cmdline,
            disks: image.diskPaths.isEmpty ? nil : image.diskPaths
        )

        let vcpus = options.vcpus ?? image.vcpus
        let ram = options.ramMib ?? image.ramMib
        if vcpus != nil || ram != nil || options.seconds > 0 {
            doc.resourceLimits = ResourceLimits(
                cpu: vcpus.map { ResourceLimits.Cpu(vcpus: $0) },
                memory: ram.map { ResourceLimits.Memory(ram: "\($0)mb") },
                timeout: options.seconds > 0
                    ? ResourceLimits.Timeout(wallClock: "\(options.seconds)s")
                    : nil
            )
        }

        // An egress host arrives as `host:port`, which is how every other part
        // of this tree speaks. The spec separates the two, so split rather than
        // pass the joined form through as a hostname that could never match.
        let rules: [NetworkPolicy.EgressRule] = options.egressAllow.map { entry in
            let parts = entry.split(separator: ":", maxSplits: 1)
            let host = String(parts.first ?? "")
            let port = parts.count > 1 ? Int(parts[1]) : nil
            return NetworkPolicy.EgressRule(
                action: "allow",
                domains: [host],
                ports: port.map { [$0] }
            )
        }
        doc.networkPolicy = NetworkPolicy(
            enabled: options.net,
            defaultAction: "deny",
            egress: rules.isEmpty ? nil : rules
        )

        if options.proxyRules != nil || options.workspace != nil {
            doc.secrets = Secrets(rulesFile: options.proxyRules, workspace: options.workspace)
        }
        doc.hostRequirements = HostRequirements(hypervisor: "cloud-hypervisor", arch: "aarch64")
        return doc
    }

    /// Serialise the way `chm spec init` does: pretty, key-sorted, newline-ended,
    /// so a spec written by the app and one written by the CLI diff cleanly
    /// against each other.
    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(self)
        data.append(0x0A)
        return data
    }

    /// Write `sandbox.json` into `directory`.
    ///
    /// Refuses to clobber unless asked: a spec is hand-edited, and the edits are
    /// the part worth protecting.
    @discardableResult
    func write(into directory: String, overwrite: Bool = false) throws -> String {
        let path = (directory as NSString).appendingPathComponent(Self.filename)
        if !overwrite, FileManager.default.fileExists(atPath: path) {
            throw SpecError.alreadyExists(path)
        }
        try encoded().write(to: URL(fileURLWithPath: path), options: .atomic)
        return path
    }

    static func read(from directory: String) throws -> SandboxSpecDocument {
        let path = (directory as NSString).appendingPathComponent(Self.filename)
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(SandboxSpecDocument.self, from: data)
    }

    /// Is there a spec in this directory?
    static func exists(in directory: String) -> Bool {
        FileManager.default.fileExists(
            atPath: (directory as NSString).appendingPathComponent(filename))
    }

    enum SpecError: LocalizedError, Equatable {
        case alreadyExists(String)

        var errorDescription: String? {
            switch self {
            case .alreadyExists(let path):
                return "\(path) already exists — open it rather than overwriting your edits"
            }
        }
    }
}

/// The result of asking `chm` whether a spec is any good.
struct SpecValidation: Equatable {
    var ok: Bool
    /// One entry per problem, already phrased for a human by `chm spec validate`
    /// — which is the point of asking it rather than re-deriving the rules here.
    var problems: [String]

    /// Parse `chm spec validate` output.
    ///
    /// The exit status is what decides; the text is only ever the explanation.
    /// Reading a verdict out of prose would break the first time the wording
    /// improved.
    static func parse(exitCode: Int32, output: String) -> SpecValidation {
        guard exitCode != 0 else { return SpecValidation(ok: true, problems: []) }
        let problems = output
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("- ") }
            .map { String($0.dropFirst(2)) }
        // A non-zero exit with nothing parseable is still a failure. Reporting
        // "valid" because we could not read the reason would be the worst
        // possible reading of a refusal.
        return SpecValidation(
            ok: false,
            problems: problems.isEmpty ? [output.trimmingCharacters(in: .whitespacesAndNewlines)]
                : problems
        )
    }
}
