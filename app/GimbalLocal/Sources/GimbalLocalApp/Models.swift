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
        socketPath: "\(NSTemporaryDirectory())chm.sock",
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

/// Sidebar selection / primary navigation. The two `…Home` cases are the main
/// pages; the others focus a specific instance or image.
enum SidebarItem: Hashable {
    case sandboxesHome
    case snapshotsHome
    case cloudHome
    case sandbox(String)   // sandbox id
    case snapshot(String)  // snapshot name
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

    /// HVF (Apple's managed GIC) delivers message-based SPIs only, so only a
    /// `gicv2m-message-spi` snapshot is restorable here — mirrors the runner's
    /// local gic gate. Anything else stays cloud-only.
    var restorableOnHVF: Bool {
        compatibility == "runnable" && (gicMode == nil || gicMode == "gicv2m-message-spi")
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
