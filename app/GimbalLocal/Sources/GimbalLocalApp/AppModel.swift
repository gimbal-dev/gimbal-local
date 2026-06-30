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

/// Pure decision for whether an interactive `chm connect` session has ended,
/// based on its PID lock file. Factored out so it is unit-testable without a
/// running VM. `chm connect --session-lock` writes the file on start and its
/// graceful teardown removes it on EVERY exit (window close, Ctrl-A x, a
/// terminating signal, or guest power-off), so the file vanishing is an honest
/// end-of-session signal; the embedded PID lets us also catch a stale lock left
/// only by an uncatchable SIGKILL.
enum InteractiveLiveness {
    static func sessionEnded(
        lockExists: Bool,
        ownerAlive: Bool,
        lockSeen: Bool,
        pastStartDeadline: Bool
    ) -> Bool {
        if lockExists {
            // Live only while the process that owns the lock is still around.
            return !ownerAlive
        }
        // No lock file. If we already saw it, a clean teardown removed it.
        if lockSeen {
            return true
        }
        // Never seen yet: the session may still be starting — only give up once
        // the start grace period has elapsed (so a slow launch isn't dropped).
        return pastStartDeadline
    }
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
    @Published var startingSandboxID: String?
    @Published var interactiveSandboxID: String?
    @Published var welcomeDismissed = UserDefaults.standard.bool(forKey: "gimbal.welcomeDismissed")

    private let chm = ChmClient()
    private let controlPlane = CloudControlClient()
    private var daemonProcess: Process?
    private var consoleProcess: Process?
    private var attemptedAutoStart = false
    private let consoleLimit = 512 * 1024

    // Liveness tracking for an open `chm connect` session. The interactive
    // console runs in Terminal.app (outside our process) and stops the daemon
    // VM, so the daemon cannot report it; instead `chm connect --session-lock`
    // maintains a PID file we watch to learn when the user ends the session —
    // including by simply closing the Terminal window.
    private var interactiveLockPath: String?
    private var interactiveLockSeen = false
    private var interactiveDeadline: Date?

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

    private func openInteractiveTerminal(for snapshot: SnapshotSummary, lockPath: String? = nil) throws {
        var connectCmd = "\(shellQuote(settings.chmPath)) connect \(shellQuote(snapshot.path)) --socket \(shellQuote(settings.socketPath)) --idle-exit 0"
        if let lockPath {
            connectCmd += " --session-lock \(shellQuote(lockPath))"
        }
        let command = [
            "cd \(shellQuote(FileManager.default.currentDirectoryPath))",
            "echo 'Gimbal Local interactive session: \(snapshot.name)'",
            "echo 'Login with ubuntu / ubuntu if prompted. Close this window or press Ctrl-A x to end the session — it shuts the sandbox down cleanly.'",
            connectCmd,
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

    /// Reconcile an open interactive session against its PID lock file, clearing
    /// the "connected" state once the user has ended it (e.g. by closing the
    /// Terminal window). Cheap; driven by the periodic refresh loop.
    func reconcileInteractiveSession() {
        guard let id = interactiveSandboxID, let lockPath = interactiveLockPath else {
            return
        }
        let fm = FileManager.default
        let lockExists = fm.fileExists(atPath: lockPath)
        if lockExists {
            interactiveLockSeen = true
        }
        let ownerAlive = lockExists && lockOwnerAlive(lockPath)
        let pastDeadline = interactiveDeadline.map { Date() > $0 } ?? false
        let ended = InteractiveLiveness.sessionEnded(
            lockExists: lockExists,
            ownerAlive: ownerAlive,
            lockSeen: interactiveLockSeen,
            pastStartDeadline: pastDeadline
        )
        guard ended else { return }

        appendLog("interactive session for \(sandbox(id: id)?.name ?? id) ended")
        // The connect process stopped the daemon VM and owned the slot itself,
        // so once it's gone the sandbox is no longer running locally.
        if activeLocalSandboxID == id { activeLocalSandboxID = nil }
        // Remove a stale lock left only by an uncatchable SIGKILL.
        if lockExists { try? fm.removeItem(atPath: lockPath) }
        clearInteractiveTracking()
        Task { await refreshLocal() }
    }

    /// True if the PID recorded in `lockPath` names a live process.
    private func lockOwnerAlive(_ lockPath: String) -> Bool {
        guard
            let body = try? String(contentsOfFile: lockPath, encoding: .utf8),
            let pid = Int32(body.trimmingCharacters(in: .whitespacesAndNewlines))
        else {
            // Unreadable/unparseable lock: treat as not-alive so we never wedge.
            return false
        }
        // kill(pid, 0): 0 => alive; EPERM => alive but not ours; ESRCH => gone.
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }

    /// Path of the per-sandbox interactive session lock file, under the app's
    /// Application Support directory.
    private func sessionLockPath(for id: String) -> String {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("gimbal-local/sessions", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let safe = String(id.map { $0.isLetter || $0.isNumber ? $0 : "-" })
        return base.appendingPathComponent("\(safe).lock").path
    }

    /// Clear all interactive-session tracking in one place.
    private func clearInteractiveTracking() {
        interactiveSandboxID = nil
        interactiveLockPath = nil
        interactiveLockSeen = false
        interactiveDeadline = nil
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

    /// Live sandboxes, derived from the persisted instances plus runtime state.
    /// Three signals drive a sandbox's state: an in-flight start
    /// (`startingSandboxID`), an open interactive terminal session
    /// (`interactiveSandboxID`, which the daemon can't see because `chm connect`
    /// takes over the VM in its own process), and the daemon's reported status
    /// for the active local sandbox. Because the local engine runs one VM at a
    /// time, at most one sandbox is live.
    var sandboxes: [Sandbox] {
        storedSandboxes.map { stored in
            let state = liveState(for: stored.id)
            let isActive = stored.id == activeLocalSandboxID
            return Sandbox(
                id: stored.id,
                name: stored.name,
                snapshotName: stored.snapshotName,
                location: stored.location,
                state: state,
                uptimeSeconds: isActive ? status.uptimeSeconds : nil,
                consoleBytes: isActive ? status.consoleBytes : nil,
                reason: (isActive && state == .failed) ? status.reason : nil
            )
        }
    }

    private func liveState(for id: String) -> Sandbox.State {
        if id == interactiveSandboxID {
            return .running
        }
        if id == startingSandboxID {
            return .starting
        }
        guard id == activeLocalSandboxID else {
            return .stopped
        }
        switch status.state {
        case .running:
            return .running
        case .stopped:
            return status.reason != nil ? .failed : .stopped
        case .idle, .disconnected, .unknown:
            return .stopped
        }
    }

    /// Is there already a live local sandbox occupying the single VM slot?
    var hasLiveLocalSandbox: Bool {
        sandboxes.contains { $0.state == .running || $0.state == .starting }
    }

    func sandbox(id: String) -> Sandbox? {
        sandboxes.first { $0.id == id }
    }

    func snapshot(named name: String) -> SnapshotSummary? {
        snapshots.first { $0.name == name }
    }

    /// Create a new sandbox instance from a snapshot image and focus it, without
    /// starting it. Names are made unique so several sandboxes can come from the
    /// same image. Returns the created sandbox (its live state is derived).
    @discardableResult
    func createSandbox(fromSnapshotNamed name: String) -> Sandbox? {
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

    /// Create a sandbox and immediately auto-start it (the "New sandbox" action).
    @discardableResult
    func newSandbox(fromSnapshotNamed name: String) -> Sandbox? {
        guard let created = createSandbox(fromSnapshotNamed: name) else { return nil }
        startSandbox(created)
        return created
    }

    func startSandbox(_ sandbox: Sandbox) {
        guard liveState(for: sandbox.id) != .running, liveState(for: sandbox.id) != .starting else {
            appendLog("\(sandbox.name) is already running")
            return
        }
        activeLocalSandboxID = sandbox.id
        startingSandboxID = sandbox.id
        clearInteractiveTracking()
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
            if startingSandboxID == sandbox.id {
                startingSandboxID = nil
            }
        }
    }

    /// Open an interactive terminal *inside* the sandbox — the primary way to
    /// work in a sandbox. `chm connect` takes over the local VM slot in its own
    /// process, so we mark the sandbox interactive here (the daemon can't report
    /// it) and keep it shown as running until the user stops it.
    func connect(to sandbox: Sandbox) {
        guard let snapshot = snapshot(named: sandbox.snapshotName) else {
            appendLog("cannot connect: snapshot \(sandbox.snapshotName) not in library")
            return
        }
        activeLocalSandboxID = sandbox.id
        startingSandboxID = nil
        interactiveSandboxID = sandbox.id
        // Maintain a PID lock so the session's end (including a closed window) is
        // detectable by reconcileInteractiveSession.
        let lockPath = sessionLockPath(for: sandbox.id)
        interactiveLockPath = lockPath
        interactiveLockSeen = false
        interactiveDeadline = Date().addingTimeInterval(20)
        // `chm connect` stops the daemon-run VM and takes over; drop our
        // read-only console stream so the two don't fight over the slot.
        consoleProcess?.terminate()
        consoleProcess = nil
        Task {
            do {
                try openInteractiveTerminal(for: snapshot, lockPath: lockPath)
                appendLog("opened interactive terminal for \(sandbox.name)")
            } catch {
                appendLog("terminal connect failed: \(error.localizedDescription)")
                if interactiveSandboxID == sandbox.id {
                    clearInteractiveTracking()
                }
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
            if activeLocalSandboxID == sandbox.id { activeLocalSandboxID = nil }
            if startingSandboxID == sandbox.id { startingSandboxID = nil }
            if interactiveSandboxID == sandbox.id { clearInteractiveTracking() }
            consoleProcess?.terminate()
            consoleProcess = nil
            await refreshLocal()
        }
    }

    func deleteSandbox(_ sandbox: Sandbox) {
        if activeLocalSandboxID == sandbox.id || interactiveSandboxID == sandbox.id {
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

    /// True while a sandbox is being worked in via an interactive Terminal
    /// session (`chm connect`), whose console lives in Terminal.app rather than
    /// the app's read-only stream.
    var hasInteractiveSession: Bool {
        interactiveSandboxID != nil
    }
}
