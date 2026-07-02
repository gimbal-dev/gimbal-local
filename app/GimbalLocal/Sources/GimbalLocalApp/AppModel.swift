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
    @Published var cloudSnapshots: [CloudSnapshot] = []
    @Published var branches: [PlaneBranch] = []
    @Published var bringingDownID: String?
    // Live state for cloud-origin sandboxes (they run via the one-shot `chm
    // runner`, not the daemon, so their state is tracked here rather than derived
    // from `chm ctl status`).
    @Published var cloudSandboxStates: [String: Sandbox.State] = [:]
    @Published var cloudSandboxReasons: [String: String] = [:]
    // Revision lineage per directory (sandbox workspace or image), from
    // `chm revisions --json`, + the directory currently being rolled back.
    @Published var revisionsByPath: [String: [RevisionSummary]] = [:]
    @Published var rollingBackPath: String?
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
        cloudSnapshots = await controlPlane.listSnapshots(baseURL: settings.controlPlaneURL)
        branches = await chm.branches(api: settings.controlPlaneURL, settings: settings)
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

    /// Bring a snapshot down from the control plane and run it here as a
    /// first-class **cloud-origin sandbox**: drives the `chm runner` pipeline
    /// (assign-run → verify → mark-local-copy → run/resume) and tracks the run as
    /// a sandbox that appears in the unified list alongside local ones, marked
    /// with a cloud badge. "Remote vs local" stays an implementation detail.
    func bringDownAndRun(_ snapshot: CloudSnapshot) {
        guard bringingDownID == nil else { return }
        guard snapshot.restorableOnHVF else {
            appendLog("cloud: \(snapshot.id) is not HVF-restorable (gic \(snapshot.gicMode ?? "?")) — stays cloud-only")
            return
        }
        // One cloud sandbox per cloud snapshot: reuse it on re-run so the list
        // stays clean, create it the first time.
        let sandboxID = "cloud-\(snapshot.id)"
        if !storedSandboxes.contains(where: { $0.id == sandboxID }) {
            storedSandboxes.append(
                StoredSandbox(
                    id: sandboxID,
                    name: cloudSandboxName(snapshot.id),
                    snapshotName: snapshot.id,
                    location: .remote
                )
            )
            saveSandboxes()
        }
        selection = .sandbox(sandboxID)
        runCloudSandbox(sandboxID: sandboxID, snapshotID: snapshot.id, isCheckpoint: snapshot.isCheckpoint)
    }

    /// Re-run an existing cloud-origin sandbox (bring its snapshot down again).
    func rerunCloudSandbox(_ sandbox: Sandbox) {
        guard sandbox.location == .remote, bringingDownID == nil else { return }
        let isCheckpoint = cloudSnapshots.first { $0.id == sandbox.snapshotName }?.isCheckpoint ?? true
        runCloudSandbox(sandboxID: sandbox.id, snapshotID: sandbox.snapshotName, isCheckpoint: isCheckpoint)
    }

    private func runCloudSandbox(sandboxID: String, snapshotID: String, isCheckpoint: Bool) {
        bringingDownID = snapshotID
        cloudSandboxStates[sandboxID] = .starting
        cloudSandboxReasons[sandboxID] = nil
        let verb = isCheckpoint ? "resume" : "run"
        appendLog("cloud: bringing down \(snapshotID) — assign-run → verify → \(verb)")
        Task {
            let result = await chm.runnerRun(
                snapshotID: snapshotID,
                api: settings.controlPlaneURL,
                owner: "gimbal-local",
                settings: settings
            )
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { appendLog(trimmed) }
            if result.status == 0 {
                cloudSandboxStates[sandboxID] = .stopped
                appendLog("cloud: \(snapshotID) ran to completion locally")
            } else if result.output.contains("protocol fixture") {
                cloudSandboxStates[sandboxID] = .failed
                cloudSandboxReasons[sandboxID] = "Protocol fixture — pulls + verifies, but needs a real snapshot to boot on HVF."
                appendLog("cloud: \(snapshotID) is a protocol fixture — needs a real snapshot to boot on HVF")
            } else {
                cloudSandboxStates[sandboxID] = .failed
                cloudSandboxReasons[sandboxID] = "Run exited \(result.status). See the activity log for details."
                appendLog("cloud: \(snapshotID) did not complete cleanly (exit \(result.status))")
            }
            bringingDownID = nil
            await refreshAll()
        }
    }

    private func cloudSandboxName(_ snapshotID: String) -> String {
        let short = snapshotID.replacingOccurrences(of: "snap-", with: "").prefix(8)
        return "cloud \(short)"
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

    private func openInteractiveTerminal(runPath: String, lockPath: String? = nil) throws {
        // `--checkpoint` makes the session resume from a saved checkpoint if one
        // exists and capture a fresh one when it ends cleanly — so closing the
        // window suspends the sandbox and reconnecting brings it back where it
        // was (live memory + disk), rather than cold-booting. `runPath` is the
        // sandbox's isolated workspace so its state stays separate from other
        // sandboxes launched from the same image.
        //
        // Terminal.app's `do script` runs a command *string*, so we cannot hand
        // it a raw argv. Instead every interpolated value is single-quoted and
        // control-character-validated by `InteractiveTerminalCommand` (M30.3),
        // then the whole command is escaped once more for the AppleScript string
        // literal — so a path can never break out into host shell code.
        let command = try InteractiveTerminalCommand.shellCommand(
            chmPath: settings.chmPath,
            runPath: runPath,
            socketPath: settings.socketPath,
            lockPath: lockPath,
            workdir: FileManager.default.currentDirectoryPath
        )

        let script = """
        tell application "Terminal"
            activate
            do script \(InteractiveTerminalCommand.appleScriptString(command))
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
            let reason: String?
            if stored.location == .remote {
                reason = (state == .failed) ? cloudSandboxReasons[stored.id] : nil
            } else {
                reason = (isActive && state == .failed) ? status.reason : nil
            }
            return Sandbox(
                id: stored.id,
                name: stored.name,
                snapshotName: stored.snapshotName,
                location: stored.location,
                state: state,
                uptimeSeconds: isActive ? status.uptimeSeconds : nil,
                consoleBytes: isActive ? status.consoleBytes : nil,
                reason: reason,
                workspacePath: stored.workspacePath
            )
        }
    }

    private func liveState(for id: String) -> Sandbox.State {
        // Cloud-origin sandboxes track their own run state.
        if let cloudState = cloudSandboxStates[id] {
            return cloudState
        }
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

    /// The per-sandbox workspace directory for a sandbox id (a sibling of the
    /// library so it never appears in the daemon's image scan).
    private func workspacePath(for sandboxID: String) -> String {
        URL(fileURLWithPath: settings.libraryPath)
            .deletingLastPathComponent()
            .appendingPathComponent(".chm-workspaces")
            .appendingPathComponent(sandboxID)
            .path
    }

    /// Ensure a sandbox has its own isolated workspace, creating it from the
    /// image on first use. Returns the path to run from — the workspace on
    /// success, or the shared image path as a safe fallback if creation fails
    /// (so a sandbox always runs, matching the pre-workspace behaviour).
    func ensureWorkspace(sandboxID: String) async -> String? {
        guard let idx = storedSandboxes.firstIndex(where: { $0.id == sandboxID }) else { return nil }
        let stored = storedSandboxes[idx]
        guard let image = snapshot(named: stored.snapshotName) else {
            appendLog("cannot prepare workspace: image \(stored.snapshotName) not in library")
            return nil
        }
        let fm = FileManager.default
        let ws = stored.workspacePath ?? workspacePath(for: sandboxID)
        if fm.fileExists(atPath: ws + "/state.json") {
            if storedSandboxes[idx].workspacePath == nil {
                storedSandboxes[idx].workspacePath = ws
                saveSandboxes()
            }
            return ws
        }
        // Fresh (or partial) — (re)create the workspace from the image.
        try? fm.removeItem(atPath: ws)
        let result = await chm.createWorkspace(image: image.path, workspace: ws, settings: settings)
        guard result.status == 0, fm.fileExists(atPath: ws + "/state.json") else {
            appendLog("workspace setup failed for \(stored.name); running from the shared image instead")
            return image.path
        }
        storedSandboxes[idx].workspacePath = ws
        saveSandboxes()
        appendLog("prepared isolated workspace for \(stored.name)")
        return ws
    }

    /// The current saved revision (live checkpoint) for a snapshot image, read
    /// from its `.chm-checkpoint/checkpoint.json` lineage manifest. `nil` when no
    /// checkpoint exists (the sandbox has never been suspended). Cheap: the
    /// manifest is a few KB (the RAM dump lives in a sibling file).
    func revision(forSnapshotNamed name: String) -> Revision? {
        guard let snapshot = snapshot(named: name) else { return nil }
        let manifest = URL(fileURLWithPath: snapshot.path)
            .appendingPathComponent(".chm-checkpoint")
            .appendingPathComponent("checkpoint.json")
        guard let data = try? Data(contentsOf: manifest) else { return nil }
        return try? JSONDecoder().decode(Revision.self, from: data)
    }

    /// Load the revision lineage (`chm revisions --json`) for a directory (a
    /// sandbox workspace or an image) into `revisionsByPath` for the history view.
    func refreshRevisions(path: String) {
        guard !path.isEmpty else { return }
        Task {
            revisionsByPath[path] = await chm.revisions(path: path, settings: settings)
        }
    }

    /// Roll a directory back to an archived revision (appended as a fresh HEAD),
    /// then refresh its lineage.
    func rollback(path: String, toRevision revID: String) {
        guard !path.isEmpty, rollingBackPath == nil else { return }
        rollingBackPath = path
        appendLog("rolling back to \(revID)")
        Task {
            let result = await chm.rollback(path: path, revID: revID, settings: settings)
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { appendLog(trimmed) }
            rollingBackPath = nil
            refreshRevisions(path: path)
        }
    }

    /// Fork a snapshot's current revision into a new branched snapshot in the
    /// library, then surface it (refresh) and focus it. The fork shares the
    /// parent's immutable base and diverges from a copy of its live state — the
    /// branch point in the lineage graph. Requires a saved revision (suspend the
    /// sandbox first).
    func forkSnapshot(named name: String) {
        guard let image = snapshot(named: name) else {
            appendLog("cannot fork: snapshot \(name) not in library")
            return
        }
        guard revision(forSnapshotNamed: name) != nil else {
            appendLog("cannot fork \(name): no saved revision yet — suspend it first")
            return
        }
        let forkName = "\(name)-fork-\(Int(Date().timeIntervalSince1970))"
        let dst = URL(fileURLWithPath: settings.libraryPath)
            .appendingPathComponent(forkName)
            .path
        Task {
            do {
                let output = try await chm.fork(from: image.path, to: dst, settings: settings)
                appendLog(output.trimmingCharacters(in: .whitespacesAndNewlines))
                await refreshLocal()
                // Surface the fork as a sandbox the user can launch immediately.
                if snapshot(named: forkName) != nil {
                    _ = createSandbox(fromSnapshotNamed: forkName)
                }
            } catch {
                appendLog("fork failed: \(error.localizedDescription)")
            }
        }
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
            let runPath = await ensureWorkspace(sandboxID: sandbox.id) ?? sandbox.snapshotName
            do {
                let output = try await chm.startSnapshot(runPath, settings: settings)
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
            let runPath = await ensureWorkspace(sandboxID: sandbox.id) ?? snapshot.path
            do {
                try openInteractiveTerminal(runPath: runPath, lockPath: lockPath)
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
        // Remove the per-sandbox workspace (overlays + checkpoints); the shared
        // image base is only symlinked, so this never touches the library.
        if let ws = storedSandboxes.first(where: { $0.id == sandbox.id })?.workspacePath {
            try? FileManager.default.removeItem(atPath: ws)
        }
        storedSandboxes.removeAll { $0.id == sandbox.id }
        cloudSandboxStates[sandbox.id] = nil
        cloudSandboxReasons[sandbox.id] = nil
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
