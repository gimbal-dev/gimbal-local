// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

struct CommandResult {
    let output: String
    let status: Int32
}

enum ChmClientError: LocalizedError {
    case commandFailed(String, Int32)
    case invalidJSON(String)

    var errorDescription: String? {
        switch self {
        case let .commandFailed(output, status):
            return "chm exited with status \(status): \(output.trimmingCharacters(in: .whitespacesAndNewlines))"
        case let .invalidJSON(output):
            return "chm returned invalid JSON: \(output.trimmingCharacters(in: .whitespacesAndNewlines))"
        }
    }
}

struct ChmClient {
    func listSnapshots(settings: AppSettings) async throws -> [SnapshotSummary] {
        let output = try await runChecked(settings: settings, args: ["ctl", "list", "--json"])
        return try Self.parseSnapshotList(output)
    }

    func status(settings: AppSettings) async throws -> SandboxStatus {
        let output = try await runChecked(settings: settings, args: ["ctl", "status", "--json"])
        return try Self.parseStatus(output)
    }

    func startSnapshot(_ name: String, settings: AppSettings) async throws -> String {
        try await runChecked(settings: settings, args: ["ctl", "start", name])
    }

    func stop(settings: AppSettings) async throws -> String {
        try await runChecked(settings: settings, args: ["ctl", "stop"])
    }

    func shutdown(settings: AppSettings) async throws -> String {
        try await runChecked(settings: settings, args: ["ctl", "shutdown"])
    }

    func run(settings: AppSettings, args: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: settings.chmPath)
                    process.arguments = args + ["--socket", settings.socketPath]

                    let pipe = Pipe()
                    process.standardOutput = pipe
                    process.standardError = pipe

                    try process.run()
                    process.waitUntilExit()

                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    let output = String(decoding: data, as: UTF8.self)
                    continuation.resume(returning: CommandResult(output: output, status: process.terminationStatus))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func runChecked(settings: AppSettings, args: [String]) async throws -> String {
        let result = try await run(settings: settings, args: args)
        guard result.status == 0 else {
            throw ChmClientError.commandFailed(result.output, result.status)
        }
        return result.output
    }

    static func parseSnapshotList(_ output: String) throws -> [SnapshotSummary] {
        guard let data = output.data(using: .utf8) else {
            throw ChmClientError.invalidJSON(output)
        }
        do {
            return try JSONDecoder().decode(SnapshotList.self, from: data).snapshots
        } catch {
            throw ChmClientError.invalidJSON(output)
        }
    }

    static func parseStatus(_ output: String) throws -> SandboxStatus {
        guard let data = output.data(using: .utf8) else {
            throw ChmClientError.invalidJSON(output)
        }
        do {
            return try JSONDecoder().decode(SandboxStatus.self, from: data)
        } catch {
            throw ChmClientError.invalidJSON(output)
        }
    }
}
