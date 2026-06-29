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
