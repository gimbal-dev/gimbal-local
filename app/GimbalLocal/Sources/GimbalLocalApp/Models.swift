// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

struct AppSettings: Equatable {
    var chmPath: String
    var libraryPath: String
    /// Directory holding bring-your-own images: a kernel plus optional
    /// initramfs/disks per subdirectory. Separate from `libraryPath` because a
    /// snapshot bundle and a cold-boot image are different things with
    /// different provenance — one was captured on a KVM host, the other is
    /// files you put on this Mac.
    var localImagesPath: String
    var socketPath: String
    var controlPlaneURL: String

    static let defaults = AppSettings(
        chmPath: defaultChmPath(),
        libraryPath: defaultLibraryPath(),
        localImagesPath: defaultLocalImagesPath(),
        socketPath: "\(NSTemporaryDirectory())gimbal-local/chm.sock",
        controlPlaneURL: "http://127.0.0.1:8080"
    )

    /// Where cold-boot images live.
    ///
    /// This must agree with `chm`'s `images_library()`, because `chm image
    /// build` is the thing that *writes* here and this is the thing that reads.
    /// They disagreed until V9.7: `chm` wrote to `~/gimbal-images` while this
    /// returned `<repo>/images`, a directory that had never existed — so the
    /// New sandbox menu said "No local images yet" with images sitting on
    /// disk. Two implementations of one rule, drifting exactly as you would
    /// expect.
    ///
    /// Unlike `chmPath` and `libraryPath`, there is no repo-root branch here.
    /// `chm` is a build artefact so looking beside the checkout is right for
    /// it; images are user data a shipped app must still find when there is no
    /// checkout at all. `GIMBAL_IMAGES` remains the override, and is the same
    /// variable `chm` reads.
    private static func defaultLocalImagesPath() -> String {
        if let images = ProcessInfo.processInfo.environment["GIMBAL_IMAGES"], !images.isEmpty {
            return images
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "gimbal-images").path
    }

    private static func defaultChmPath() -> String {
        if let chm = ProcessInfo.processInfo.environment["CHM_PATH"], !chm.isEmpty {
            return chm
        }
        if let root = repoRootCandidate() {
            return root.appending(path: "target/debug/chm").path
        }
        return "target/debug/chm"
    }

    private static func defaultLibraryPath() -> String {
        if let library = ProcessInfo.processInfo.environment["GIMBAL_LIBRARY"], !library.isEmpty {
            return library
        }
        if let root = repoRootCandidate() {
            return root.appending(path: "snapshots").path
        }
        return "snapshots"
    }

    private static func repoRootCandidate() -> URL? {
        if let root = ProcessInfo.processInfo.environment["GIMBAL_LOCAL_REPO"], !root.isEmpty {
            return URL(fileURLWithPath: root)
        }

        let fm = FileManager.default
        var candidates = [
            URL(fileURLWithPath: fm.currentDirectoryPath),
            Bundle.main.bundleURL,
        ]

        if let executable = Bundle.main.executableURL {
            candidates.append(executable.deletingLastPathComponent())
        }

        for start in candidates {
            var dir = start
            for _ in 0..<8 {
                if fm.fileExists(atPath: dir.appending(path: "Cargo.toml").path),
                   fm.fileExists(atPath: dir.appending(path: "chm/Cargo.toml").path)
                {
                    return dir
                }
                let parent = dir.deletingLastPathComponent()
                if parent.path == dir.path {
                    break
                }
                dir = parent
            }
        }

        return nil
    }
}

struct SnapshotSummary: Codable, Identifiable, Equatable, Hashable {
    var id: String { name }

    let name: String
    let path: String
    let vcpus: Int
    let ramMib: Int

    enum CodingKeys: String, CodingKey {
        case name
        case path
        case vcpus
        case ramMib = "ram_mib"
    }
}

struct SnapshotList: Codable, Equatable {
    let snapshots: [SnapshotSummary]
}

struct SandboxStatus: Codable, Equatable {
    enum State: String, Codable {
        case disconnected
        case idle
        case running
        case stopped
        case unknown
    }

    var state: State
    var name: String?
    var uptimeSeconds: Int?
    var consoleBytes: Int?
    var reason: String?
    var message: String?
    /// The snapshot library the daemon is actually serving. Optional because the
    /// app connects to daemons it did not build, including ones predating the
    /// field; a missing value means "it did not say", never "it agrees".
    var library: String?

    enum CodingKeys: String, CodingKey {
        case state
        case name
        case uptimeSeconds = "uptime_seconds"
        case consoleBytes = "console_bytes"
        case reason
        case message
        case library
    }

    static let disconnected = SandboxStatus(
        state: .disconnected,
        name: nil,
        uptimeSeconds: nil,
        consoleBytes: nil,
        reason: nil,
        message: "chm serve is not reachable"
    )
}

/// Where a sandbox runs. Local sandboxes are HVF guests on this Mac; remote is
/// a planned location served by the control plane. The UI treats both uniformly
/// so location stays an implementation detail the user rarely has to think about.
enum SandboxLocation: String, Codable, Hashable {
    case local
    case remote

    var label: String { self == .local ? "Local" : "Remote" }
    var symbol: String { self == .local ? "desktopcomputer" : "cloud" }
}

/// A sandbox *instance* — distinct from the snapshot image it was created from.
/// The UI is built around a list of these so a user can keep several sandboxes
/// (even several from the same image) and run them as the engine allows.
struct Sandbox: Identifiable, Hashable {
    enum State: Hashable {
        case running
        case starting
        case stopped
        case failed

        var label: String {
            switch self {
            case .running: return "Running"
            case .starting: return "Starting"
            case .stopped: return "Stopped"
            case .failed: return "Failed"
            }
        }
    }

    let id: String
    var name: String
    var snapshotName: String
    var location: SandboxLocation
    var state: State
    var uptimeSeconds: Int?
    var consoleBytes: Int?
    var reason: String?
    var workspacePath: String?
}

/// The persisted shape of a sandbox (the live `state` is derived at runtime from
/// the engine), stored in `UserDefaults` so a user's sandboxes survive launches.
struct StoredSandbox: Codable, Hashable {
    let id: String
    var name: String
    var snapshotName: String
    var location: SandboxLocation
    /// The per-sandbox workspace directory (shares the image's read-only base but
    /// keeps its own disk overlays + checkpoint/revision store). `nil` until first
    /// run; created lazily so sandboxes from the same image stay isolated.
    var workspacePath: String?

    enum CodingKeys: String, CodingKey {
        case id, name, snapshotName, location, workspacePath
    }
}

/// The global default resource limits applied to a new sandbox's workspace
/// (`chm limits set`) unless the sandbox already has its own. All values are
/// optional (nil = no limit on that axis); `enabled` gates whether the defaults
/// are applied at all.
struct DefaultLimits: Codable, Equatable {
    var enabled: Bool
    var maxVcpus: Int?
    var maxMemoryMb: Int?
    var maxDiskMb: Int?
    var maxWallSeconds: Int?
    var maxConsoleMb: Int?
    var maxConnections: Int?
    var maxBandwidthKbps: Int?
}

/// The global default egress posture applied to a new sandbox's workspace
/// (`chm firewall set`) unless the sandbox already has its own.
enum DefaultEgressMode: String, Codable, CaseIterable {
    case open       // unrestricted (no policy written)
    case noNetwork  // default-deny, no allow rules
    case allowlist  // default-deny + an allow list
}

struct DefaultFirewall: Codable, Equatable {
    var enabled: Bool
    var mode: DefaultEgressMode
    var allow: [String]
}

/// App-wide default controls applied to every new sandbox, so a user gets sane
/// guard rails without configuring each sandbox. Persisted in `UserDefaults`.
struct GlobalDefaults: Codable, Equatable {
    var limits: DefaultLimits
    var firewall: DefaultFirewall

    /// Sane out-of-the-box controls: a generous disk + console cap on (so a
    /// runaway can't exhaust the host), and the firewall **on** in default-deny
    /// mode (M31.2) — a new sandbox has no public egress until the user allow-lists
    /// what it needs. (Host loopback / LAN / link-local are always blocked by the
    /// reserved-address guard, M31.1, regardless of this policy.)
    static let sane = GlobalDefaults(
        limits: DefaultLimits(
            enabled: true,
            maxVcpus: nil,
            maxMemoryMb: nil,
            maxDiskMb: 8192,
            maxWallSeconds: nil,
            maxConsoleMb: 64,
            maxConnections: nil,
            maxBandwidthKbps: nil
        ),
        firewall: DefaultFirewall(enabled: true, mode: .allowlist, allow: [])
    )
}

/// A committed revision (live checkpoint) read from a snapshot's
/// `.chm-checkpoint/checkpoint.json` manifest. The lineage header is the spine
/// of the fork model (see `docs/gimbal-local-fork-model.md`): each revision
/// records the one it descends from, so suspends form a chain and forks (later)
/// form branches. Only the header is decoded here — the heavy hardware state in
/// the same file is ignored.
struct Revision: Codable, Equatable, Hashable, Identifiable {
    let id: String
    let parent: String?
    let baseImage: String
    let createdAtMs: UInt64
    let origin: String
    let label: String?

    enum CodingKeys: String, CodingKey {
        case id, parent, origin, label
        case baseImage = "base_image"
        case createdAtMs = "created_at_ms"
    }

    var createdAt: Date { Date(timeIntervalSince1970: Double(createdAtMs) / 1000.0) }

    /// A short, human-friendly id (the random suffix), e.g. `abcd`.
    var shortId: String {
        String(id.split(separator: "-").last ?? Substring(id))
    }
}

/// One entry in a snapshot's revision lineage, as reported by
/// `chm revisions --json`. Unlike `Revision` (the single HEAD manifest decoded
/// directly), this is the full store view: every archived revision plus HEAD,
/// with whether it is still `resumable` (its live RAM is retained).
struct RevisionSummary: Codable, Identifiable, Equatable, Hashable {
    let id: String
    let parent: String?
    let baseImage: String
    let createdAtMs: UInt64
    let origin: String
    let label: String?
    let resumable: Bool
    let isHead: Bool

    enum CodingKeys: String, CodingKey {
        case id, parent, origin, label, resumable
        case baseImage = "base_image"
        case createdAtMs = "created_at_ms"
        case isHead = "is_head"
    }

    var createdAt: Date { Date(timeIntervalSince1970: Double(createdAtMs) / 1000.0) }

    var shortId: String {
        String(id.split(separator: "-").last ?? Substring(id))
    }
}

/// A sandbox's local egress firewall posture, as reported by
/// `chm firewall show <dir> --json`. The same file (`egress-policy.json`) the
/// control plane teleports for a cloud run, but here authored locally — so a
/// no-control-plane user governs outbound network the same way. `source` is
/// `local` (a workspace file), `control-plane` (a bound cloud policy, read-only
/// here), or `none` (unrestricted).
struct EgressPolicy: Codable, Equatable, Hashable {
    var source: String
    var defaultStance: String
    var allow: [String]
    var deny: [String]
    var label: String?
    var restrictive: Bool
    var path: String?

    enum CodingKeys: String, CodingKey {
        case source
        case defaultStance = "default"
        case allow, deny, label, restrictive, path
    }

    /// The three postures the UI offers, derived from the raw policy.
    enum Mode: Hashable {
        case open        // unrestricted egress (no policy, or default-allow)
        case noNetwork   // default-deny with nothing allowed
        case allowList   // default-deny with an explicit allow-list
    }

    var mode: Mode {
        guard restrictive else { return .open }
        if defaultStance.lowercased() == "deny" && allow.isEmpty { return .noNetwork }
        return .allowList
    }

    /// True when a cloud control plane bound this policy — the local UI shows it
    /// read-only rather than letting a user edit a plane-governed posture.
    var isControlPlaneBound: Bool { source == "control-plane" }

    static let unrestricted = EgressPolicy(
        source: "none",
        defaultStance: "allow",
        allow: [],
        deny: [],
        label: nil,
        restrictive: false,
        path: nil
    )
}

/// Sidebar selection / primary navigation. The two `…Home` cases are the main
/// pages; the others focus a specific instance or image.
enum SidebarItem: Hashable {
    case sandboxesHome
    case snapshotsHome
    case cloudHome
    case securityHome
    case proxyHome
    case activityHome
    case capabilityHome
    case sandbox(String)   // sandbox id
    case snapshot(String)  // snapshot name
}

/// A revision branch as the control plane tracks it (`chm branches --json`,
/// `GET /branches`). A branch is a movable, human-named pointer at a revision;
/// Phase 4's "git for live compute" surface. Read-only in the app for now.
struct PlaneBranch: Codable, Identifiable, Equatable, Hashable {
    let branchId: String
    let name: String
    let owner: String
    let headSnapshotId: String?
    let reviewStatus: String?
    let baseBranch: String?
    let pageACLs: [PlaneBranchACL]?

    var id: String { branchId }

    enum CodingKeys: String, CodingKey {
        case branchId = "branch_id"
        case name, owner
        case headSnapshotId = "head_snapshot_id"
        case reviewStatus = "review_status"
        case baseBranch = "base_branch"
        case pageACLs = "page_acls"
    }

    var aclCount: Int { pageACLs?.count ?? 0 }

    /// The head revision's short id (last `-` segment), or "empty" if unset.
    var shortHead: String {
        guard let head = headSnapshotId, !head.isEmpty else { return "empty" }
        return String(head.split(separator: "-").last ?? Substring(head))
    }

    /// Review status for display; a branch with no gate shows "open".
    var reviewLabel: String {
        guard let s = reviewStatus, !s.isEmpty else { return "open" }
        return s
    }
}

struct PlaneBranchACL: Codable, Equatable, Hashable {
    let audience: String?
}

struct PlaneBranchList: Codable, Equatable {
    let branches: [PlaneBranch]
}

/// A snapshot as the *control plane* sees it (`GET /snapshots`) — distinct from a
/// local library image (`SnapshotSummary`). It carries provenance (where it was
/// captured / ran) and the gic mode, so the UI can show where it came from and
/// whether this Mac can rehydrate it.
struct CloudSnapshot: Identifiable, Equatable, Hashable {
    let id: String                // snapshot_id
    let status: String            // available, capturing, …
    let kind: String              // full | checkpoint
    let sourceKind: String?       // local-lima | cloud-runner | container | …
    let gicMode: String?          // gicv2m-message-spi | its-lpi
    let originSubstrate: String?  // linux-kvm | apple-hvf
    let vcpus: Int
    let ramMib: Int
    let compatibility: String     // runnable | incompatible | …
    let hasLocalCopy: Bool
    /// True when the manifest ships a disk image (`disks/…`). A real captured
    /// snapshot does; a protocol fixture (state.json + memory-ranges only) does
    /// not — so this is a pre-flight "is this actually bootable" hint that
    /// mirrors the runner's authoritative `snapshots`-state check.
    var hasDiskImage: Bool = true

    /// Whether *this Mac* can rehydrate the snapshot. Mirrors the runner's
    /// `hvf_restorable`: the managed GIC runs a `gicv2m-message-spi` capture,
    /// and the userspace GICv3 runs a vanilla `its-lpi` one, so both are
    /// restorable and `chm` picks the path itself. An unknown mode is not.
    var restorableOnHVF: Bool {
        switch gicMode {
        case nil, "", "gicv2m-message-spi", "its-lpi": return true
        default: return false
        }
    }

    /// Whether the *control plane* will hand the bundle over. gctl still gates
    /// assign-run on gic mode, so a vanilla capture it has classified as
    /// not-runnable is refused with a 422 before we ever see the bytes. That is
    /// a different statement from "this Mac cannot run it", and conflating the
    /// two is what produced the old recapture-with-GICv2M advice.
    var planeWillRelease: Bool { compatibility == "runnable" }

    /// Best pre-flight guess at whether bringing this down will actually boot:
    /// restorable here, released by the plane, **and** it ships a disk image. A
    /// snapshot missing its disk is a fixture / not bootable, so the UI can
    /// steer the user to a real one instead of a confusing post-download
    /// failure.
    var likelyBootable: Bool { restorableOnHVF && planeWillRelease && hasDiskImage }

    /// A short reason this snapshot cannot be brought down to run, or nil.
    var notBootableReason: String? {
        if !restorableOnHVF {
            let mode = (gicMode?.isEmpty == false) ? gicMode! : "unknown"
            return "Interrupt routing `\(mode)` is not one this Mac can rehydrate"
        }
        if !planeWillRelease {
            return "The control plane classifies this as \(compatibility), so it will not release it"
        }
        if !hasDiskImage {
            return "No disk image — a protocol fixture, not a bootable snapshot"
        }
        return nil
    }

    var isCheckpoint: Bool { kind == "checkpoint" }

    /// A short "where it came from" line, or nil for a plain local image.
    var originLabel: String? {
        switch sourceKind {
        case "cloud-runner": return "ran in cloud" + (originSubstrate.map { " · \($0)" } ?? "")
        case "local-lima": return "captured on Lima KVM"
        case "container": return "from container image"
        case let other?: return other
        case nil: return nil
        }
    }
}

struct CloudOverview: Equatable {
    enum State: Equatable {
        case offline(String)
        case online
    }

    var state: State
    var runners: Int?
    var snapshots: Int?
    var sandboxes: Int?
    var costSummary: String?

    static let offline = CloudOverview(
        state: .offline("gimbal-cloud-control is not reachable"),
        runners: nil,
        snapshots: nil,
        sandboxes: nil,
        costSummary: nil
    )
}

/// A control key the console can send to the guest that a plain text field
/// cannot express.
///
/// Deliberately small: these are the keys that *unstick* a session (interrupt a
/// runaway command, end input, clear a half-typed line), not an attempt to be a
/// full terminal. Anything richer belongs in the Terminal.app session.
enum ConsoleKey: String, CaseIterable, Identifiable {
    case returnKey
    case interrupt
    case endOfFile
    case clearLine

    var id: String { rawValue }

    /// The wire text for `chm ctl input`, which decodes `\xNN` escapes.
    var wireText: String {
        switch self {
        case .returnKey: return "\\n"
        case .interrupt: return "\\x03"   // Ctrl-C
        case .endOfFile: return "\\x04"   // Ctrl-D
        case .clearLine: return "\\x15"   // Ctrl-U
        }
    }

    var label: String {
        switch self {
        case .returnKey: return "Return"
        case .interrupt: return "Ctrl-C"
        case .endOfFile: return "Ctrl-D"
        case .clearLine: return "Ctrl-U"
        }
    }

    var help: String {
        switch self {
        case .returnKey: return "Press Return — wakes a resumed guest that has not printed yet"
        case .interrupt: return "Interrupt the running command"
        case .endOfFile: return "End of input (log out of a shell)"
        case .clearLine: return "Clear the half-typed line"
        }
    }
}

// MARK: - Security posture (`chm posture` / `chm ctl posture`)

/// One security control, as `chm` resolved it.
struct PostureControl: Codable, Equatable, Hashable, Identifiable {
    /// The security-model invariant this implements (`I10`), or `—` for a
    /// control that has no invariant number.
    var invariant: String
    var control: String
    var state: State
    /// How this was decided — the source, not a restatement of the state. This
    /// is the field that tells a user *which* env var or file did it, so it is
    /// never elided in the UI.
    var detail: String

    var id: String { "\(invariant)/\(control)" }

    enum State: String, Codable, Equatable, Hashable {
        /// On, at or above the safe default.
        case active
        /// On, but deliberately relaxed from the safe default. The only state
        /// that should ever alarm anyone.
        case weakened
        /// Off, and off is the documented posture — not a weakening.
        case notApplicable = "not-applicable"
    }

    /// An unrecognised state decodes as `weakened`, not as "fine".
    ///
    /// If a future `chm` adds a fourth state, a UI that fell back to `active`
    /// would quietly show green for something it does not understand. Failing
    /// towards alarm is the only safe direction for a security panel.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        invariant = try c.decode(String.self, forKey: .invariant)
        control = try c.decode(String.self, forKey: .control)
        detail = try c.decode(String.self, forKey: .detail)
        let raw = try c.decode(String.self, forKey: .state)
        state = State(rawValue: raw) ?? .weakened
    }
}

/// A whole posture report, and — critically — whose it is.
struct PostureReport: Codable, Equatable {
    var workspace: String
    var weakened: Int
    var controls: [PostureControl]
    /// `daemon` when the running daemon answered for itself. Absent on the
    /// output of a plain `chm posture`, which describes the calling process.
    var source: String?
    /// Which directory the daemon chose: `running-vm`, `library-root` or
    /// `requested`.
    var assessed: String?

    /// Whether this describes the process that actually runs guests.
    ///
    /// Most of the posture is read from the environment of whichever process
    /// computes it. `chm serve` runs the guest, so only the daemon's answer
    /// describes the sandbox: a report gathered by the app itself would show
    /// green over a daemon started with `CHM_ALLOW_LOCAL_EGRESS=1`. The UI says
    /// which one it has rather than implying they are the same.
    var isFromDaemon: Bool { source == "daemon" }

    var weakenedControls: [PostureControl] { controls.filter { $0.state == .weakened } }

    /// Where the daemon looked, in words. `nil` when this is not a daemon
    /// report and there is nothing to disclose.
    var scopeDescription: String? {
        switch assessed {
        case "running-vm": return "the running sandbox"
        case "library-root": return "the snapshot library (no sandbox running)"
        case "requested": return "the requested workspace"
        default: return nil
        }
    }
}

// MARK: - Credential proxy (V6.2)

/// One injection rule as `chm proxy show --json` reports it.
///
/// Deliberately carries no credential **value** and never can: `chm proxy show`
/// does not read one (an `exec` source is not run), and `credential` is only an
/// availability word. The app must be able to display the whole rule set
/// without ever holding a secret, because "the secret is never anywhere the job
/// can reach" is worth less if it is sitting in a SwiftUI view's memory.
struct ProxyRule: Codable, Equatable, Hashable, Identifiable {
    var name: String
    /// Comma-joined host patterns, as the CLI emits them.
    var hosts: String
    /// The header the credential is attached to (`Authorization`).
    var header: String
    /// Where the credential comes from — `env:GH_TOKEN`, `exec:...` — never
    /// what it is.
    var source: String
    /// `present` · `empty` · `missing` · `on-demand`.
    var credential: String

    var id: String { name }

    var hostList: [String] {
        hosts.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
    }

    /// True when a request to a matching host would go out unauthenticated.
    ///
    /// `on-demand` is not a problem: it means the credential is minted when a
    /// request actually arrives, which is the stronger arrangement — there is
    /// no standing token to steal.
    var willFailToInject: Bool {
        credential == "missing" || credential == "empty"
    }
}

struct ProxyConfiguration: Codable, Equatable {
    var configured: Bool
    var origin: String?
    var label: String?
    var rules: [ProxyRule]
    /// Hosts explicitly never intercepted. The other half of the story: without
    /// it a reader would assume everything not listed as a rule *is*
    /// intercepted, when the opposite is true.
    var passthrough: [String]?
    /// `"daemon"` when `chm serve` answered. Absent means this app answered
    /// about *itself*, so credential availability describes the wrong process.
    var source: String?
    /// Which directory the daemon resolved rules from: `running-vm`,
    /// `library-root`, or `requested`.
    var assessed: String?
    /// The directory itself. Naming it is the difference between "add
    /// proxy-rules.json to the workspace" being advice and being actionable:
    /// the library root is never a guest's workspace, so a file left there is
    /// read by nothing.
    var scopeDir: String?

    enum CodingKeys: String, CodingKey {
        case configured, origin, label, rules, passthrough, source, assessed
        case scopeDir = "scope_dir"
    }

    var passthroughHosts: [String] { passthrough ?? [] }

    /// True when the process that will actually inject is the one that answered.
    var isFromDaemon: Bool { source == "daemon" }

    /// True when the answer describes a sandbox that is running right now, so
    /// "nothing is intercepted" is a live finding rather than a placeholder.
    var describesRunningVm: Bool { isFromDaemon && assessed == "running-vm" }

    var rulesMissingCredentials: [ProxyRule] { rules.filter(\.willFailToInject) }
}

/// One line of the proxy's decision log for a `check` run.
struct ProxyAuditEvent: Codable, Equatable, Hashable, Identifiable {
    var destination: String
    var rule: String?
    var detail: String
    var injected: Bool

    var id: String { "\(destination)|\(detail)" }
}

/// The control run: the same request with injection disabled.
struct ProxyControlResult: Codable, Equatable {
    var status: String?
    var differs: Bool?
    /// The only field worth rendering as a verdict. `reachable` is table stakes;
    /// this is whether the credential demonstrably arrived.
    var provesInjection: Bool?
    var error: String?

    enum CodingKeys: String, CodingKey {
        case status, differs, error
        case provesInjection = "proves_injection"
    }
}

/// The result of `chm proxy check --json`.
struct ProxyCheckResult: Codable, Equatable {
    var host: String
    var port: Int
    var path: String
    var address: String?
    var disposition: String
    var intercepted: Bool
    var reachable: Bool
    var originStatus: String?
    var tls: String?
    var error: String?
    var audit: [ProxyAuditEvent]
    var control: ProxyControlResult?

    enum CodingKeys: String, CodingKey {
        case host, port, path, address, disposition, intercepted, reachable, tls, error, audit, control
        case originStatus = "origin_status"
    }

    /// What to actually tell the user, in one sentence.
    ///
    /// Reachability alone is not a pass. A run against an endpoint that answers
    /// the same with and without a credential is green no matter what the proxy
    /// does — including if injection were completely broken — so that case is
    /// reported as inconclusive rather than as success.
    enum Verdict: Equatable {
        case unreachable(String)
        case provesInjection(without: String)
        case inconclusive(String)
        case relayed
        case noControl
    }

    var verdict: Verdict {
        guard reachable else { return .unreachable(error ?? "unknown error") }
        guard intercepted else { return .relayed }
        guard let control else { return .noControl }
        if let error = control.error { return .inconclusive("control run failed: \(error)") }
        if control.provesInjection == true, let status = control.status {
            return .provesInjection(without: status)
        }
        return .inconclusive(
            "the origin answered \(control.status ?? "the same") with and without the "
                + "credential, so this run cannot tell whether injection worked"
        )
    }
}

/// The workspace CA, and the script that installs it in a guest.
struct ProxyCa: Equatable {
    var fingerprint: String
    var installScript: String
    /// The exact console lines to type, with a guest-side digest check.
    ///
    /// Empty when the daemon predates the checked transfer. Typing
    /// `installScript` line by line was measured to drop characters and to
    /// strand every line behind a slow command in the tty queue, so the two are
    /// not interchangeable and the caller must say which it used.
    var installLines: [String] = []
    /// `"daemon"` when `chm serve` answered. Absent means this app resolved a CA
    /// in *its own* view of the workspace, which need not be the one the running
    /// proxy signs with.
    var source: String?
    /// The directory the CA was read from.
    var scopeDir: String?

    var isFromDaemon: Bool { source == "daemon" }
}

/// Wire shape of `chm ctl proxy ca`.
///
/// `present: false` is not an error — the CA is minted when a proxy first runs,
/// so before the first intercepted connection there is genuinely nothing to
/// install, and offering an install button then would create a trust anchor the
/// guest would have to trust for no reason.
struct ProxyCaReport: Codable {
    var source: String?
    var assessed: String?
    var scopeDir: String?
    var present: Bool
    var sha256: String?
    var pem: String?
    var installer: String?
    var installLines: [String]?
    var error: String?

    enum CodingKeys: String, CodingKey {
        case source, assessed, present, sha256, pem, installer, error
        case scopeDir = "scope_dir"
        case installLines = "install_lines"
    }
}

// MARK: - Audit trail

/// One durable record from a sandbox's `audit.jsonl`.
///
/// Deliberately loose: the trail is append-only and written by whatever version
/// of `chm` was running at the time, so a reader that refuses to decode an event
/// it has not seen before would blank the whole page over one unfamiliar line.
/// Unknown events still render — with their timestamp and whatever fields they
/// do carry — because a record you cannot fully interpret is still evidence that
/// *something happened*, which is the one thing an empty list would deny.
struct AuditRecord: Codable, Identifiable, Equatable {
    /// Stable only within one decode. The trail has no identifier of its own —
    /// two identical denials a second apart are genuinely two records — so a
    /// content-derived id would collapse them in a `ForEach` and hide repeats.
    var id = UUID()
    var event: String
    var ts: String?
    var domain: String?
    var target: String?
    var rule: String?
    var policy: String?
    var destination: String?
    var disposition: String?
    var allowed: Int?
    var denied: Int?
    var distinctAllowed: Int?
    var distinctDenied: Int?
    var truncated: Bool?
    var reason: String?
    var vcpus: Int?

    enum CodingKeys: String, CodingKey {
        case event, ts, domain, target, rule, policy, destination, disposition
        case allowed, denied, truncated, reason, vcpus
        case distinctAllowed = "distinct_allowed"
        case distinctDenied = "distinct_denied"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        event = (try? c.decode(String.self, forKey: .event)) ?? "unknown"
        ts = try? c.decode(String.self, forKey: .ts)
        domain = try? c.decode(String.self, forKey: .domain)
        target = try? c.decode(String.self, forKey: .target)
        rule = try? c.decode(String.self, forKey: .rule)
        policy = try? c.decode(String.self, forKey: .policy)
        destination = try? c.decode(String.self, forKey: .destination)
        disposition = try? c.decode(String.self, forKey: .disposition)
        allowed = try? c.decode(Int.self, forKey: .allowed)
        denied = try? c.decode(Int.self, forKey: .denied)
        distinctAllowed = try? c.decode(Int.self, forKey: .distinctAllowed)
        distinctDenied = try? c.decode(Int.self, forKey: .distinctDenied)
        truncated = try? c.decode(Bool.self, forKey: .truncated)
        reason = try? c.decode(String.self, forKey: .reason)
        vcpus = try? c.decode(Int.self, forKey: .vcpus)
    }

    /// What the record is a decision *about*: an egress event names a target, a
    /// proxy event names a destination.
    var subject: String { target ?? destination ?? "" }

    /// The four dispositions the panel groups by. `nil` for session and summary
    /// records, which are context rather than decisions.
    var kind: Kind? {
        switch event {
        case "egress-allow": return .allowed
        case "egress-deny": return .denied
        case "proxy":
            switch disposition {
            case "inject": return .injected
            case "relay": return .relayed
            default: return nil
            }
        default: return nil
        }
    }

    enum Kind: String, CaseIterable {
        case allowed, denied, injected, relayed
    }
}

/// A sandbox with recorded history, offered when nothing is running.
struct AuditCandidate: Codable, Equatable, Identifiable {
    var name: String
    var dir: String
    var bytes: Int

    var id: String { dir }
}

/// A sandbox's durable audit trail, as the daemon reports it.
///
/// The honesty flags are the point of this type. An empty `records` list has two
/// completely different meanings — "the sandbox never opened a socket" and "this
/// build never wrote down the ones it did" — and a panel that cannot tell them
/// apart will present the second as the first, which is a reassuring answer to a
/// question that was never asked.
struct AuditTrail: Codable, Equatable {
    var source: String?
    var assessed: String?
    var scopeDir: String?
    var present: Bool
    var path: String?
    var total: Int
    /// False when nothing in the file proves this `chm` records permitted
    /// egress. Then "0 allowed" means *not recorded*, never *none*.
    var recordsAllowEgress: Bool
    /// True when a session hit the distinct-flow cap, so the per-flow detail is
    /// known to be incomplete while the totals stay exact.
    var truncated: Bool
    var records: [AuditRecord]
    /// Sandboxes with history, when the daemon has none in scope. Present only
    /// for `assessed == "no-sandbox-in-scope"`.
    var candidates: [AuditCandidate]?
    var error: String?

    enum CodingKeys: String, CodingKey {
        case source, assessed, present, path, total, truncated, records, candidates, error
        case scopeDir = "scope_dir"
        case recordsAllowEgress = "records_allow_egress"
    }

    var isFromDaemon: Bool { source == "daemon" }

    /// True when the daemon had no sandbox to report on — which is a fact about
    /// this reader, not about any guest, and must never render as "no activity".
    var hasNoSandboxInScope: Bool { assessed == "no-sandbox-in-scope" }

    func count(_ kind: AuditRecord.Kind) -> Int {
        records.filter { $0.kind == kind }.count
    }

    /// The most recent summary, which carries the exact totals even when the
    /// per-flow list was capped.
    var summary: AuditRecord? {
        records.last { $0.event == "egress-summary" }
    }

    /// The policy digest the decisions were actually made under, and whether the
    /// file contains more than one. Two digests in one trail means the policy
    /// changed mid-session, and the panel must not present the newest as though
    /// it governed the older decisions.
    var policyDigests: [String] {
        var seen: [String] = []
        for r in records {
            guard let p = r.policy, !p.isEmpty, !seen.contains(p) else { continue }
            seen.append(p)
        }
        return seen
    }
}

// MARK: - Capabilities (V6.5)

/// How strongly a capability claim is held, strongest first.
///
/// Rendering these identically would throw away the only thing that makes the
/// panel more useful than a README. `built` in particular is the grade of the
/// bug this milestone was named for: true of the compiler, silent about the
/// machine.
enum CapabilityEvidence: String, Codable {
    case probed
    case observed
    case recorded
    case built
    case documented

    /// Whether the claim was established by doing something, now, rather than
    /// by having been written down.
    var isMeasured: Bool { self == .probed || self == .observed }

    var label: String {
        switch self {
        case .probed: return "probed just now"
        case .observed: return "observed running"
        case .recorded: return "read from the capture"
        case .built: return "compiled in"
        case .documented: return "written down, unchecked"
        }
    }
}

/// The verdict on one capability.
enum CapabilitySupport: String, Codable {
    case yes
    case degraded
    case no
    case unknown

    var label: String {
        switch self {
        case .yes: return "Yes"
        case .degraded: return "Degraded"
        case .no: return "No"
        case .unknown: return "Unknown"
        }
    }
}

/// One claim, with the evidence behind it.
struct CapabilityClaim: Codable, Identifiable, Equatable {
    var id: String
    var title: String
    var detail: String
    /// Unknown wire values decode to `.unknown`, never to a yes. A newer daemon
    /// must not be able to make this app render a verdict it does not
    /// understand as a working one.
    var support: CapabilitySupport
    var evidence: CapabilityEvidence

    enum CodingKeys: String, CodingKey { case id, title, support, evidence, detail }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
        title = (try? c.decode(String.self, forKey: .title)) ?? id
        detail = (try? c.decode(String.self, forKey: .detail)) ?? ""
        let s = (try? c.decode(String.self, forKey: .support)) ?? ""
        support = CapabilitySupport(rawValue: s) ?? .unknown
        let e = (try? c.decode(String.self, forKey: .evidence)) ?? ""
        // An unrecognised grade is the weakest, not the strongest: a claim this
        // app cannot grade has not been shown to be measured.
        evidence = CapabilityEvidence(rawValue: e) ?? .documented
    }
}

/// The result of checking one snapshot against this build.
struct CapabilityPreflight: Codable, Equatable {
    var dir: String
    var readable: Bool
    var refusals: Int
    var degraded: Int
    var unknowns: Int
    var summary: String
    var findings: [CapabilityClaim]
}

/// `chm ctl capabilities` — what the daemon's binary can do, plus (when there is
/// one in scope) what it makes of a specific snapshot.
struct CapabilityReport: Codable, Equatable {
    var source: String?
    var assessed: String?
    var scopeDir: String?
    var capabilities: [CapabilityClaim]
    var preflight: CapabilityPreflight?

    enum CodingKeys: String, CodingKey {
        case source, assessed, capabilities, preflight
        case scopeDir = "scope_dir"
    }

    var isFromDaemon: Bool { source == "daemon" }

    /// True when no snapshot was in scope. A fact about this reader, not about
    /// any capture, and it must not read as "nothing to check".
    var hasNoSnapshotInScope: Bool { assessed == "no-snapshot-in-scope" }

    /// Claims established by doing something rather than by assertion.
    var measuredCount: Int { capabilities.filter { $0.evidence.isMeasured }.count }

    /// Claims that are only as good as the last person to edit them.
    var documentedCount: Int { capabilities.filter { $0.evidence == .documented }.count }
}
