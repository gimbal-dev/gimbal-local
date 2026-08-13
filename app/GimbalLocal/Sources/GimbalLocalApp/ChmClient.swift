// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

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

/// Why a posture read produced nothing to show.
///
/// A security panel must not fail silently — an empty panel reads as "nothing
/// is wrong" — so the reason is carried all the way to the view.
struct PostureUnavailable: LocalizedError {
    let reason: String
    var errorDescription: String? { reason }
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

    /// Every guest running on this machine (`chm ps`).
    ///
    /// Deliberately **not** `runChecked`: a failure here means the app cannot
    /// enumerate runs, which is a worse state to be in silently than to report
    /// nothing, but it must never take down a refresh that is also fetching
    /// snapshots and status. An unreadable registry yields an empty list, and
    /// the caller decides what to say about it.
    func runningGuests(settings: AppSettings) async -> [RunRecord] {
        guard let result = try? await run(settings: settings, args: ["ps", "--json"]),
              result.status == 0
        else {
            return []
        }
        return Self.parseRunList(result.output)
    }

    static func parseRunList(_ output: String) -> [RunRecord] {
        guard let data = output.data(using: .utf8),
              let list = try? JSONDecoder().decode(RunList.self, from: data)
        else {
            return []
        }
        return list.runs
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

    /// Read the security posture that governs a sandbox.
    ///
    /// Prefers the **daemon's** answer (`chm ctl posture`), because most of the
    /// posture is resolved from the environment of whichever process computes
    /// it, and `chm serve` is the process that runs the guest. Shelling out to
    /// our own `chm posture` would describe *this app*: attach to a daemon
    /// someone started with `CHM_ALLOW_LOCAL_EGRESS=1` and the panel would show
    /// green over a sandbox that can reach the LAN and 169.254.169.254.
    /// Verified: with an identical caller environment, the local read says
    /// `weakened: 0` and the daemon says `weakened: 1`.
    ///
    /// Falls back to a local read only when the daemon is unreachable. The
    /// result carries `source`, so the view can say which one it got rather
    /// than implying they are interchangeable.
    ///
    /// - Note: `chm posture` exits **1** when a control is weakened. That is a
    ///   *result*, not a failure, so status 0 and 1 are both decoded and only
    ///   anything else is an error. Treating non-zero as failure here would
    ///   blank the panel in exactly the case it exists for.
    ///
    /// - Parameter localFallbackPath: the workspace to assess if we have to
    ///   read locally. Deliberately *not* passed to the daemon: the daemon
    ///   knows which VM is actually running and which directory it came from,
    ///   and that is a better answer than one this app guesses.
    func posture(
        localFallbackPath: String?,
        settings: AppSettings
    ) async -> Result<PostureReport, PostureUnavailable> {
        let viaDaemon = await runRaw(
            settings: settings,
            args: ["ctl", "posture", "--socket", settings.socketPath]
        )
        if let report = Self.decodePosture(viaDaemon) {
            return .success(report)
        }

        // No daemon (or it answered something unusable): fall back to reading
        // our own environment, which the view labels as such.
        guard let path = localFallbackPath else {
            return .failure(PostureUnavailable(
                reason: "chm serve is not reachable, and there is no workspace to assess locally."
            ))
        }
        let local = await runRaw(settings: settings, args: ["posture", path, "--json"])
        if let report = Self.decodePosture(local) {
            return .success(report)
        }
        let text = local.output.trimmingCharacters(in: .whitespacesAndNewlines)
        return .failure(PostureUnavailable(
            reason: text.isEmpty ? "chm posture returned nothing." : text
        ))
    }

    /// Decode a posture report, accepting the weakened exit status.
    ///
    /// `nil` when the output is not a posture report at all — a daemon that
    /// does not know the verb answers `error\tunknown command`, and an older
    /// `chm` may not have `ctl posture`, both of which should fall through to
    /// the local path rather than surfacing as a hard error.
    static func decodePosture(_ result: CommandResult) -> PostureReport? {
        guard result.status == 0 || result.status == 1 else { return nil }
        guard let data = result.output.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(PostureReport.self, from: data)
    }

    // MARK: - Credential proxy (V6.2)

    /// Read the credential-proxy rule set.
    ///
    /// Runs `chm proxy show --json`, which by contract **never reads a
    /// credential value** — an `exec` source is not executed, and each rule
    /// reports only whether its credential is present. The app therefore
    /// displays the whole configuration without a secret ever entering this
    /// process.
    ///
    /// Prefers the **daemon's** answer (`chm ctl proxy`) for the same reason
    /// `posture` does: whether a credential resolves is read from `env::var`
    /// in whichever process answers, and `chm serve` is the process that
    /// actually injects. Asking ourselves describes this app.
    ///
    /// Measured while building this panel: with the token in the daemon's
    /// environment and not the app's, the local read said `missing` for a rule
    /// the daemon said was `present`. That direction merely nags. The inverse —
    /// token in the app, none in the daemon — shows a green panel while every
    /// request leaves the guest unauthenticated, which is the reason this is
    /// not a cosmetic preference.
    ///
    /// Falls back to reading the rule *file* locally, which still gives the
    /// rules, hosts and passthrough list; only credential availability is
    /// then describing the wrong process, and `source` says so.
    func proxyShow(path: String, settings: AppSettings) async -> ProxyConfiguration? {
        let viaDaemon = await runRaw(
            settings: settings,
            args: ["ctl", "proxy", "--socket", settings.socketPath]
        )
        if let config = Self.decodeProxy(viaDaemon) { return config }
        return Self.decodeProxy(
            await runRaw(settings: settings, args: ["proxy", "show", path, "--json"])
        )
    }

    /// Decode a proxy configuration, returning `nil` when the output is not one
    /// — an older daemon answers `error\tunknown command`, which must fall
    /// through to the local read rather than blanking the panel.
    static func decodeProxy(_ result: CommandResult) -> ProxyConfiguration? {
        guard result.status == 0, let data = result.output.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ProxyConfiguration.self, from: data)
    }

    /// Fetch the workspace CA and the script that installs it in a guest.
    ///
    /// Two invocations because the fingerprint goes to stderr on the plain form
    /// while `--for-guest` emits the installer on stdout. The fingerprint is
    /// what makes the install verifiable: the script ends by printing the
    /// certificate it actually installed, so it can be compared against this.
    /// The CA the guest will actually have to trust.
    ///
    /// Daemon-first, and here the stakes are highest of the four provenance
    /// fixes. A CA is per-workspace, and the app's idea of the workspace is the
    /// library root while a running guest's proxy uses the sandbox folder.
    /// Measured: `898b834b…` here against `79f85a28…` in the guest. Installing
    /// this app's answer would make the guest trust a certificate nothing signs
    /// with — and because the installer compares what it installed against the
    /// fingerprint it was handed, both would agree and the panel would report
    /// success while every intercepted connection failed a certificate check.
    func proxyCa(path: String, settings: AppSettings) async -> ProxyCa? {
        let viaDaemon = await runRaw(
            settings: settings,
            args: ["ctl", "proxy", "ca", "--socket", settings.socketPath]
        )
        if let ca = Self.decodeCa(viaDaemon) { return ca }

        let script = await runRaw(settings: settings, args: ["proxy", "ca", path, "--for-guest"])
        guard script.status == 0, !script.output.isEmpty else { return nil }
        let plain = await runRaw(settings: settings, args: ["proxy", "ca", path])
        let fingerprint = Self.fingerprint(fromCaOutput: plain.output) ?? "unknown"
        return ProxyCa(
            fingerprint: fingerprint,
            installScript: script.output,
            source: nil,
            scopeDir: path
        )
    }

    /// The running sandbox's durable audit trail.
    ///
    /// Daemon-only, with no local fallback — and that is deliberate. Every other
    /// reader here degrades to answering from this app's own view when `chm
    /// serve` is silent, but there is no useful local answer for a *trail*: the
    /// records are written by the process running the guest, so an app-side read
    /// of some other directory would either find nothing (rendering as "this
    /// sandbox made no network calls", the most reassuring possible lie) or find
    /// a stale file from a previous session and present it as current. Returning
    /// nil lets the page say it does not know, which is the true answer.
    func auditTrail(settings: AppSettings, dir: String? = nil, tail: Int = 200) async -> AuditTrail? {
        var args = ["ctl", "audit"]
        if let dir { args.append(dir) }
        args += ["--tail", String(tail), "--socket", settings.socketPath]
        let result = await runRaw(settings: settings, args: args)
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let trail = try? JSONDecoder().decode(AuditTrail.self, from: data)
        else {
            return nil
        }
        return trail
    }

    /// Decode `chm ctl proxy ca`. Returns nil when the daemon has no CA yet, so
    /// the caller falls through rather than offering to install nothing.
    static func decodeCa(_ result: CommandResult) -> ProxyCa? {
        guard result.status == 0, let data = result.output.data(using: .utf8),
              let report = try? JSONDecoder().decode(ProxyCaReport.self, from: data),
              report.present,
              let sha = report.sha256, let installer = report.installer
        else {
            return nil
        }
        return ProxyCa(
            fingerprint: sha,
            installScript: installer,
            installLines: report.installLines ?? [],
            source: report.source,
            scopeDir: report.scopeDir
        )
    }

    /// Pull the sha256 out of `chm proxy ca`'s `# sha256 <hex>` preamble.
    static func fingerprint(fromCaOutput output: String) -> String? {
        for line in output.split(separator: "\n") where line.hasPrefix("# sha256 ") {
            let hex = line.dropFirst("# sha256 ".count).trimmingCharacters(in: .whitespaces)
            if !hex.isEmpty { return hex }
        }
        return nil
    }

    /// Send a real request through the proxy, with the control run.
    ///
    /// `--control` is not optional here. Without it the button is a green tick
    /// that cannot fail: against an endpoint answering the same either way,
    /// `check` succeeds even if injection is entirely broken. The control
    /// repeats the identical request with injection disabled so the two answers
    /// can be compared, which is the only thing that makes this evidence.
    ///
    /// - Note: exits non-zero when the host is unreachable, which is a *result*
    ///   we want to display, so the payload is decoded on any status.
    func proxyCheck(
        host: String,
        path: String,
        rulesFile: String?,
        settings: AppSettings
    ) async -> ProxyCheckResult? {
        // Ask the daemon first, for the third time and the strongest reason:
        // a check run here resolves rules relative to *this* process and reads
        // credentials from *this* environment, so it truthfully reports "no
        // rule matches, relayed end-to-end" — correct, and useless, because it
        // can never exercise the injection the button exists to test. Measured:
        // the app's own run said PASS-THROUGH/401 against the identical rule
        // the daemon injected on and got 200.
        let viaDaemon = await runRaw(
            settings: settings,
            args: ["ctl", "proxy", "check", "--host", host, "--path", path,
                   "--socket", settings.socketPath]
        )
        if let report = Self.decodeCheck(viaDaemon) { return report }

        var args = ["proxy", "check", "--host", host, "--path", path, "--control", "--json"]
        if let rulesFile { args += ["--rules", rulesFile] }
        return Self.decodeCheck(await runRaw(settings: settings, args: args))
    }

    /// Decode a check report. Unlike the others this accepts a **non-zero**
    /// status: `check` exits 1 when the origin was unreachable, and an
    /// unreachable origin is a result worth showing, not a failure to hide.
    static func decodeCheck(_ result: CommandResult) -> ProxyCheckResult? {
        guard let data = result.output.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ProxyCheckResult.self, from: data)
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

    /// The argv for a command, including the daemon socket where that means
    /// anything.
    ///
    /// `--socket` names the daemon to talk to, so it belongs on commands that
    /// talk to one. `chm ps` reads a directory of records written by every guest
    /// process on the machine and never opens the socket, so it refuses the flag
    /// outright — and because `run` appended it unconditionally, the app's very
    /// first call failed with `unknown option --socket` and the list came back
    /// empty. That looked exactly like the bug it was meant to fix: a guest was
    /// running and the app said nothing was.
    ///
    /// A pure function so the invocation is testable. Every unit test here reads
    /// *output*, and no amount of parsing coverage can see a command that never
    /// ran.
    static func argv(for args: [String], socketPath: String) -> [String] {
        guard args.first != "ps" else { return args }
        return args + ["--socket", socketPath]
    }

    func run(settings: AppSettings, args: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: settings.chmPath)
                    process.arguments = Self.argv(for: args, socketPath: settings.socketPath)

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
