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

    /// Type at the running guest's console (`chm ctl input`).
    ///
    /// `text` is already-encoded wire text — use ``encodeLine(_:)`` or one of the
    /// ``ConsoleKey`` values to build it, never a raw user string, because the
    /// daemon interprets backslash escapes.
    func sendInput(_ text: String, settings: AppSettings) async throws -> String {
        try await runChecked(settings: settings, args: ["ctl", "input", text])
    }

    /// Encode a line the user typed for `chm ctl input`, which reads `\n`, `\t`,
    /// `\xNN` and `\\` as escapes.
    ///
    /// A raw string would be misread: `printf 'a\nb'` typed in the box would
    /// arrive at the guest as two lines. Doubling every backslash first makes
    /// the line arrive exactly as typed. `chm ctl input` sends its argument
    /// as-is with no trailing newline, so Return is an explicit `\n`.
    static func encodeLine(_ line: String, pressReturn: Bool = true) -> String {
        var encoded = line.replacingOccurrences(of: "\\", with: "\\\\")
        if pressReturn { encoded += "\\n" }
        return encoded
    }

    func shutdown(settings: AppSettings) async throws -> String {
        try await runChecked(settings: settings, args: ["ctl", "shutdown"])
    }

    /// Fork a snapshot's current revision into a new snapshot directory (a
    /// branch in the lineage). Unlike the daemon commands this takes no socket,
    /// so it runs `chm fork` directly rather than through `run`.
    func fork(from src: String, to dst: String, settings: AppSettings) async throws -> String {
        let result = await runRaw(settings: settings, args: ["fork", src, dst])
        guard result.status == 0 else {
            throw ChmClientError.commandFailed(result.output, result.status)
        }
        return result.output
    }

    /// List a snapshot's revision lineage via `chm revisions <dir> --json`.
    func revisions(path: String, settings: AppSettings) async -> [RevisionSummary] {
        let result = await runRaw(settings: settings, args: ["revisions", path, "--json"])
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let revs = try? JSONDecoder().decode([RevisionSummary].self, from: data)
        else {
            return []
        }
        return revs
    }

    /// Roll a snapshot back to an archived revision via `chm rollback`.
    func rollback(path: String, revID: String, settings: AppSettings) async -> CommandResult {
        await runRaw(settings: settings, args: ["rollback", path, revID])
    }

    /// List the control plane's revision branches (`chm branches --json`). Talks
    /// HTTP to the plane, not the daemon, so it uses `--api` and no `--socket`.
    /// Returns [] on any failure (offline plane, decode error) so the UI degrades
    /// quietly rather than throwing.
    func branches(api: String, settings: AppSettings) async -> [PlaneBranch] {
        let result = await runRaw(settings: settings, args: ["branches", "--json", "--api", api])
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let list = try? JSONDecoder().decode(PlaneBranchList.self, from: data)
        else {
            return []
        }
        return list.branches
    }

    /// Set a branch's review status (`pending` / `approved` / `rejected`).
    func reviewBranch(_ name: String, status: String, api: String, settings: AppSettings) async -> CommandResult {
        await runRaw(settings: settings, args: ["branches", "review", "--branch", name, "--status", status, "--api", api])
    }

    /// Merge the `from` branch's head into `target` (review-gated on the plane).
    func mergeBranch(target: String, from: String, api: String, settings: AppSettings) async -> CommandResult {
        await runRaw(settings: settings, args: ["branches", "merge", "--target", target, "--from", from, "--api", api])
    }

    /// Create an isolated per-sandbox workspace (`chm workspace <image> <ws>`).
    func createWorkspace(image: String, workspace: String, settings: AppSettings) async -> CommandResult {
        await runRaw(settings: settings, args: ["workspace", image, workspace])
    }

    /// Read a directory's effective egress firewall posture
    /// (`chm firewall show <dir> --json`). Returns `.unrestricted` on any failure
    /// or when no directory is known yet, so the UI degrades to "open".
    func firewallShow(path: String, settings: AppSettings) async -> EgressPolicy {
        let result = await runRaw(settings: settings, args: ["firewall", "show", path, "--json"])
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let policy = try? JSONDecoder().decode(EgressPolicy.self, from: data)
        else {
            return .unrestricted
        }
        return policy
    }

    /// Write a directory's egress policy (`chm firewall set`). Writes exactly the
    /// requested state — the UI passes the full desired allow/deny lists.
    func firewallSet(
        path: String,
        defaultStance: String,
        allow: [String],
        deny: [String],
        settings: AppSettings
    ) async -> CommandResult {
        var args = ["firewall", "set", path, "--default", defaultStance]
        for rule in allow { args += ["--allow", rule] }
        for rule in deny { args += ["--deny", rule] }
        return await runRaw(settings: settings, args: args)
    }

    /// Remove a directory's egress policy (`chm firewall clear`) — back to
    /// unrestricted egress.
    func firewallClear(path: String, settings: AppSettings) async -> CommandResult {
        await runRaw(settings: settings, args: ["firewall", "clear", path])
    }

    /// Write a directory's resource limits (`chm limits set`). Only the set axes
    /// are passed; an omitted axis means "no limit" there.
    func limitsSet(
        path: String,
        limits: DefaultLimits,
        settings: AppSettings
    ) async -> CommandResult {
        var args = ["limits", "set", path]
        if let v = limits.maxVcpus { args += ["--max-vcpus", String(v)] }
        if let v = limits.maxMemoryMb { args += ["--max-memory-mb", String(v)] }
        if let v = limits.maxDiskMb { args += ["--max-disk-mb", String(v)] }
        if let v = limits.maxWallSeconds { args += ["--max-wall-seconds", String(v)] }
        if let v = limits.maxConsoleMb { args += ["--max-console-mb", String(v)] }
        if let v = limits.maxConnections { args += ["--max-connections", String(v)] }
        if let v = limits.maxBandwidthKbps { args += ["--max-bandwidth-kbps", String(v)] }
        args += ["--label", "app-default"]
        return await runRaw(settings: settings, args: args)
    }

    /// Drive the control-plane runner pipeline for one snapshot: register →
    /// assign-run → verify checksums → mark-local-copy → run/resume, reporting
    /// state to the plane. Runs `chm runner run` with **no** `--socket` (it talks
    /// HTTP to the plane, not the local daemon). Returns the combined output +
    /// exit status so the caller can surface the honest outcome.
    func runnerRun(snapshotID: String, api: String, owner: String, settings: AppSettings) async -> CommandResult {
        await runRaw(
            settings: settings,
            args: ["runner", "run", snapshotID, "--api", api, "--owner", owner]
        )
    }

    /// Run `chm <args>` directly (no `--socket` appended), capturing combined
    /// stdout+stderr. Used for one-shot commands (`fork`, `runner`) that talk to
    /// the plane or filesystem rather than the local daemon. Never throws on a
    /// non-zero exit — the status is returned so callers can report it honestly.
    func runRaw(settings: AppSettings, args: [String]) async -> CommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: settings.chmPath)
                process.arguments = args
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                do {
                    try process.run()
                    process.waitUntilExit()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    let output = String(decoding: data, as: UTF8.self)
                    continuation.resume(
                        returning: CommandResult(output: output, status: process.terminationStatus)
                    )
                } catch {
                    continuation.resume(
                        returning: CommandResult(
                            output: "failed to launch chm: \(error.localizedDescription)",
                            status: -1
                        )
                    )
                }
            }
        }
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
