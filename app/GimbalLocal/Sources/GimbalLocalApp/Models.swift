// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

struct AppSettings {
    var chmPath: String
    var libraryPath: String
    var socketPath: String
    var controlPlaneURL: String

    static let defaults = AppSettings(
        chmPath: defaultChmPath(),
        libraryPath: defaultLibraryPath(),
        socketPath: "\(NSTemporaryDirectory())gimbal-local/chm.sock",
        controlPlaneURL: "http://127.0.0.1:8080"
    )

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

    enum CodingKeys: String, CodingKey {
        case state
        case name
        case uptimeSeconds = "uptime_seconds"
        case consoleBytes = "console_bytes"
        case reason
        case message
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
