// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

enum EngineTone: Equatable {
    case active   // a sandbox is actively running
    case ready    // engine reachable and idle
    case offline  // engine not reachable
    case unknown  // no status yet
}

struct EngineIndicator {
    let label: String
    let detail: String
    let symbol: String
    let tone: EngineTone
}

@MainActor
final class AppModel: ObservableObject {
    @Published var settings = AppSettings.defaults
    @Published var snapshots: [SnapshotSummary] = []
    @Published var status = SandboxStatus.disconnected
    @Published var cloud = CloudOverview.offline
    @Published var consoleText = ""
    @Published var activityLog = ""
    @Published var selectedSnapshot: SnapshotSummary?
    @Published var isRefreshing = false
    @Published var daemonPID: Int32?
    @Published var recentSandboxNames: [String] = []

    // Sandbox-instance layer (the UI is built around N sandboxes / N snapshots).
    @Published var selection: SidebarItem? = .sandboxesHome
    @Published var storedSandboxes: [StoredSandbox] = []
    @Published var activeLocalSandboxID: String?
    @Published var welcomeDismissed = UserDefaults.standard.bool(forKey: "gimbal.welcomeDismissed")

    private let chm = ChmClient()
    private let controlPlane = CloudControlClient()
    private var daemonProcess: Process?
    private var consoleProcess: Process?
    private var attemptedAutoStart = false
    private let consoleLimit = 512 * 1024

    private let recentsDefaultsKey = "gimbal.recentSandboxNames"
    private let sandboxesDefaultsKey = "gimbal.sandboxes"
    private let welcomeDefaultsKey = "gimbal.welcomeDismissed"
    private let maxRecents = 8

    func bootstrap() async {
        loadRecents()
        loadSandboxes()
        await refreshAll()
        guard status.state == .disconnected, !attemptedAutoStart else {
            return
        }

        attemptedAutoStart = true
        appendLog("local daemon not reachable; starting chm serve automatically")
        startDaemon(reason: "auto-start")
        try? await Task.sleep(for: .milliseconds(500))
        await refreshAll()
    }

    func refreshAll() async {
        isRefreshing = true
        defer { isRefreshing = false }

        await refreshLocal()
        cloud = await controlPlane.overview(baseURL: settings.controlPlaneURL)
    }

    func refreshLocal() async {
        do {
            async let loadedSnapshots = chm.listSnapshots(settings: settings)
            async let loadedStatus = chm.status(settings: settings)
            snapshots = try await loadedSnapshots
            status = try await loadedStatus
            if selectedSnapshot == nil {
                selectedSnapshot = snapshots.first
            }
            if status.state == .running, consoleProcess == nil {
                attachConsole(clear: consoleText.isEmpty)
            }
        } catch {
            status = SandboxStatus.disconnected
            snapshots = []
            appendLog("local runtime: \(error.localizedDescription)")
        }
    }

    func startDaemon() {
        startDaemon(reason: "manual")
    }

    private func startDaemon(reason: String) {
        guard daemonProcess == nil else {
            appendLog("chm serve is already managed by this app")
            return
        }

        do {
            try FileManager.default.createDirectory(
                atPath: settings.libraryPath,
                withIntermediateDirectories: true
            )
        } catch {
            appendLog("failed to create snapshot library: \(error.localizedDescription)")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: settings.chmPath)
        process.arguments = [
            "serve",
            settings.libraryPath,
            "--socket",
            settings.socketPath,
            "--idle-exit",
            "0",
        ]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor in self?.appendLog(text.trimmingCharacters(in: .newlines)) }
        }
        process.terminationHandler = { [weak self] process in
            Task { @MainActor in
                guard self?.daemonProcess === process else { return }
                self?.daemonProcess = nil
                self?.daemonPID = nil
                self?.appendLog("chm serve exited with status \(process.terminationStatus)")
            }
        }

        do {
            try process.run()
            daemonProcess = process
            daemonPID = process.processIdentifier
            appendLog("started chm serve via \(reason) (pid \(process.processIdentifier))")
            Task { await refreshLocal() }
        } catch {
            appendLog("failed to start chm serve: \(error.localizedDescription)")
        }
    }

    func shutdownDaemon() {
        Task {
            do {
                let output = try await chm.shutdown(settings: settings)
                appendLog(output)
            } catch {
                appendLog("shutdown failed: \(error.localizedDescription)")
                daemonProcess?.terminate()
            }
            daemonProcess = nil
            daemonPID = nil
            await refreshLocal()
        }
    }

    func restartDaemon() {
        Task {
            appendLog("restarting local engine")
            do {
                let output = try await chm.shutdown(settings: settings)
                appendLog(output)
            } catch {
                appendLog("restart: shutdown step skipped (\(error.localizedDescription))")
                daemonProcess?.terminate()
            }
            daemonProcess = nil
            daemonPID = nil
            try? await Task.sleep(for: .milliseconds(400))
            startDaemon(reason: "restart")
            try? await Task.sleep(for: .milliseconds(500))
            await refreshLocal()
        }
    }

    func startSelectedSnapshot() {
        guard let snapshot = selectedSnapshot else {
            appendLog("select a snapshot first")
            return
        }
        consoleText = ""
        recordRecentActivity(snapshot.name)
        Task {
            do {
                let output = try await chm.startSnapshot(snapshot.name, settings: settings)
                appendLog(output)
                attachConsole(clear: true)
                try? await Task.sleep(for: .milliseconds(900))
                await refreshLocal()
                if status.state == .stopped, let reason = status.reason {
                    appendLog("sandbox stopped before producing console output: \(reason)")
                }
            } catch {
                appendLog("start failed: \(error.localizedDescription)")
            }
        }
    }

    func connectToSelectedSnapshot() {
        guard let snapshot = selectedSnapshot else {
            appendLog("select a snapshot first")
            return
        }

        Task {
            do {
                try openInteractiveTerminal(for: snapshot)
                appendLog("opened interactive terminal for \(snapshot.name)")
                try? await Task.sleep(for: .milliseconds(500))
                await refreshLocal()
            } catch {
                appendLog("terminal connect failed: \(error.localizedDescription)")
            }
        }
    }

    func stopSandbox() {
        Task {
            do {
                let output = try await chm.stop(settings: settings)
                appendLog(output)
            } catch {
                appendLog("stop failed: \(error.localizedDescription)")
            }
            let process = consoleProcess
            process?.terminate()
            consoleProcess = nil
            await refreshLocal()
        }
    }

    func attachConsole(clear: Bool = false) {
        consoleProcess?.terminate()
        if clear {
            consoleText = ""
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: settings.chmPath)
        process.arguments = ["ctl", "console", "--socket", settings.socketPath]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor in self?.appendConsole(text) }
        }
        process.terminationHandler = { [weak self] process in
            Task { @MainActor in
                guard self?.consoleProcess === process else { return }
                pipe.fileHandleForReading.readabilityHandler = nil
                self?.consoleProcess = nil
                self?.appendLog("read-only console stream ended with status \(process.terminationStatus)")
            }
        }

        do {
            try process.run()
            consoleProcess = process
            appendLog("attached read-only console stream")
        } catch {
            appendLog("console attach failed: \(error.localizedDescription)")
        }
    }

    private func appendConsole(_ text: String) {
        consoleText.append(text)
        if consoleText.count > consoleLimit {
            consoleText.removeFirst(consoleText.count - consoleLimit)
        }
    }

    private func openInteractiveTerminal(for snapshot: SnapshotSummary) throws {
        let command = [
            "cd \(shellQuote(FileManager.default.currentDirectoryPath))",
            "echo 'Gimbal Local interactive session: \(snapshot.name)'",
            "echo 'Login with ubuntu / ubuntu if prompted. Exit the console with Ctrl-A x.'",
            "\(shellQuote(settings.chmPath)) connect \(shellQuote(snapshot.path)) --socket \(shellQuote(settings.socketPath)) --idle-exit 0",
        ].joined(separator: " && ")

        let script = """
        tell application "Terminal"
            activate
            do script \(appleScriptString(command))
        end tell
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(decoding: data, as: UTF8.self)
            throw NSError(
                domain: "GimbalLocal.Terminal",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: output.trimmingCharacters(in: .whitespacesAndNewlines)]
            )
        }
    }

    private func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func appleScriptString(_ value: String) -> String {
        "\"\(value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
    }

    func appendLog(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let timestamp = ISO8601DateFormatter().string(from: Date())
        activityLog.append("[\(timestamp)] \(trimmed)\n")
    }

    // MARK: - Sandbox instances

    /// Live sandboxes, derived from the persisted instances plus the engine
    /// status. Because the local engine runs one VM at a time, at most one
    /// sandbox is `.running` (the one we last started); the rest are `.stopped`.
    var sandboxes: [Sandbox] {
        storedSandboxes.map { stored in
            let isActive = stored.id == activeLocalSandboxID
            let state: Sandbox.State
            switch (isActive, status.state) {
            case (true, .running):
                state = .running
            case (true, .stopped):
                state = status.reason != nil ? .failed : .stopped
            default:
                state = .stopped
            }
            return Sandbox(
                id: stored.id,
                name: stored.name,
                snapshotName: stored.snapshotName,
                location: stored.location,
                state: state,
                uptimeSeconds: isActive ? status.uptimeSeconds : nil,
                consoleBytes: isActive ? status.consoleBytes : nil,
                reason: isActive ? status.reason : nil
            )
        }
    }

    func sandbox(id: String) -> Sandbox? {
        sandboxes.first { $0.id == id }
    }

    func snapshot(named name: String) -> SnapshotSummary? {
        snapshots.first { $0.name == name }
    }

    /// Create a new sandbox instance from a snapshot image and focus it. Names
    /// are made unique so several sandboxes can come from the same image.
    @discardableResult
    func newSandbox(fromSnapshotNamed name: String) -> Sandbox? {
        guard let snapshot = snapshot(named: name) else {
            appendLog("cannot create sandbox: snapshot \(name) not in library")
            return nil
        }
        let existing = Set(storedSandboxes.map(\.name))
        var candidate = snapshot.name
        var suffix = 2
        while existing.contains(candidate) {
            candidate = "\(snapshot.name)-\(suffix)"
            suffix += 1
        }
        let stored = StoredSandbox(
            id: UUID().uuidString,
            name: candidate,
            snapshotName: snapshot.name,
            location: .local
        )
        storedSandboxes.append(stored)
        saveSandboxes()
        appendLog("created sandbox \(candidate) from \(snapshot.name)")
        selection = .sandbox(stored.id)
        return sandbox(id: stored.id)
    }

    func startSandbox(_ sandbox: Sandbox) {
        activeLocalSandboxID = sandbox.id
        consoleText = ""
        recordRecentActivity(sandbox.snapshotName)
        Task {
            do {
                let output = try await chm.startSnapshot(sandbox.snapshotName, settings: settings)
                appendLog(output)
                attachConsole(clear: true)
                try? await Task.sleep(for: .milliseconds(900))
                await refreshLocal()
            } catch {
                appendLog("start failed: \(error.localizedDescription)")
            }
        }
    }

    /// Open an interactive terminal *inside* the sandbox — the primary way to
    /// work in a sandbox (vs. only viewing its console).
    func connect(to sandbox: Sandbox) {
        guard let snapshot = snapshot(named: sandbox.snapshotName) else {
            appendLog("cannot connect: snapshot \(sandbox.snapshotName) not in library")
            return
        }
        activeLocalSandboxID = sandbox.id
        Task {
            do {
                try openInteractiveTerminal(for: snapshot)
                appendLog("opened interactive terminal for \(sandbox.name)")
                try? await Task.sleep(for: .milliseconds(500))
                await refreshLocal()
            } catch {
                appendLog("terminal connect failed: \(error.localizedDescription)")
            }
        }
    }

    func stop(_ sandbox: Sandbox) {
        Task {
            do {
                let output = try await chm.stop(settings: settings)
                appendLog(output)
            } catch {
                appendLog("stop failed: \(error.localizedDescription)")
            }
            if activeLocalSandboxID == sandbox.id {
                activeLocalSandboxID = nil
            }
            consoleProcess?.terminate()
            consoleProcess = nil
            await refreshLocal()
        }
    }

    func deleteSandbox(_ sandbox: Sandbox) {
        if activeLocalSandboxID == sandbox.id {
            stop(sandbox)
        }
        storedSandboxes.removeAll { $0.id == sandbox.id }
        saveSandboxes()
        if case let .sandbox(id)? = selection, id == sandbox.id {
            selection = .sandboxesHome
        }
        appendLog("removed sandbox \(sandbox.name)")
    }

    func dismissWelcome() {
        welcomeDismissed = true
        UserDefaults.standard.set(true, forKey: welcomeDefaultsKey)
    }

    func loadSandboxes() {
        guard let data = UserDefaults.standard.data(forKey: sandboxesDefaultsKey),
              let list = try? JSONDecoder().decode([StoredSandbox].self, from: data)
        else { return }
        storedSandboxes = list
    }

    private func saveSandboxes() {
        if let data = try? JSONEncoder().encode(storedSandboxes) {
            UserDefaults.standard.set(data, forKey: sandboxesDefaultsKey)
        }
    }

    var engineIndicator: EngineIndicator {
        switch status.state {
        case .running:
            return EngineIndicator(
                label: "Sandbox running",
                detail: status.name ?? "guest active",
                symbol: "play.circle.fill",
                tone: .active
            )
        case .idle:
            return EngineIndicator(
                label: "Engine ready",
                detail: daemonPID != nil ? "managed by app" : "reachable",
                symbol: "bolt.horizontal.circle.fill",
                tone: .ready
            )
        case .stopped:
            return EngineIndicator(
                label: "Engine idle",
                detail: "last sandbox stopped",
                symbol: "pause.circle.fill",
                tone: .ready
            )
        case .disconnected:
            return EngineIndicator(
                label: "Engine offline",
                detail: "chm serve not reachable",
                symbol: "exclamationmark.triangle.fill",
                tone: .offline
            )
        case .unknown:
            return EngineIndicator(
                label: "Engine status unknown",
                detail: "no status yet",
                symbol: "questionmark.circle.fill",
                tone: .unknown
            )
        }
    }

    /// Recent sandboxes (most-recently started first), then the rest of the
    /// library. Falls back to the full library when nothing has run yet.
    var recentSandboxes: [SnapshotSummary] {
        let byName = Dictionary(
            snapshots.map { ($0.name, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let ordered = recentSandboxNames.compactMap { byName[$0] }
        guard !ordered.isEmpty else { return snapshots }
        let seen = Set(ordered.map(\.name))
        return ordered + snapshots.filter { !seen.contains($0.name) }
    }

    func loadRecents() {
        if let saved = UserDefaults.standard.stringArray(forKey: recentsDefaultsKey) {
            recentSandboxNames = saved
        }
    }

    private func recordRecentActivity(_ name: String) {
        var list = recentSandboxNames.filter { $0 != name }
        list.insert(name, at: 0)
        if list.count > maxRecents {
            list = Array(list.prefix(maxRecents))
        }
        recentSandboxNames = list
        UserDefaults.standard.set(list, forKey: recentsDefaultsKey)
    }

    var consoleDisplayText: String {
        if !consoleText.isEmpty {
            return consoleText
        }
        if status.state == .stopped, let reason = status.reason {
            return """
            Sandbox stopped before guest console output was available.

            \(reason)
            """
        }
        return "Read-only serial output will stream here after a sandbox is running."
    }

    var isConsoleStreaming: Bool {
        consoleProcess != nil && status.state == .running
    }
}
