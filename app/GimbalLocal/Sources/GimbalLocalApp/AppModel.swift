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
    // Egress firewall posture per sandbox id, from `chm firewall show --json`,
    // + the sandbox whose policy is currently being written.
    @Published var egressPolicyBySandbox: [String: EgressPolicy] = [:]
    @Published var applyingFirewallID: String?
    @Published var consoleText = ""
    /// Whether anything has been typed at the current guest yet. A resumed guest
    /// stays completely silent until it is, so this is what lets the UI say
    /// "silent because nobody has typed" instead of leaving the user staring at
    /// an empty pane wondering whether it hung.
    @Published var consoleHasBeenTypedAt = false
    @Published var activityLog = ""
    @Published var selectedSnapshot: SnapshotSummary?
    @Published var isRefreshing = false
    @Published var daemonPID: Int32?
    @Published var recentSandboxNames: [String] = []

    // Sandbox-instance layer (the UI is built around N sandboxes / N snapshots).
    @Published var selection: SidebarItem? = .sandboxesHome
    @Published var storedSandboxes: [StoredSandbox] = []
    /// App-wide default controls applied to every new sandbox (limits + firewall).
    @Published var globalDefaults: GlobalDefaults = .sane
    @Published var activeLocalSandboxID: String?
    @Published var startingSandboxID: String?
    @Published var interactiveSandboxID: String?
    /// Authoritative set of local sandboxes with a live `chm connect` VM, derived
    /// by scanning the per-sandbox session-lock files (`reconcileSessions`). This
    /// is the source of truth for local liveness — correct across app restarts
    /// and independent of which session's console the app happens to be tracking.
    @Published var liveLocalSessionIDs: Set<String> = []
    @Published var welcomeDismissed = UserDefaults.standard.bool(forKey: "gimbal.welcomeDismissed")

    /// Local-only mode: hide every surface that needs the control plane.
    ///
    /// Gimbal Local is useful with no control plane at all — it cold-boots its
    /// own guests and runs images from disk. Showing a Cloud section that can
    /// only ever say "offline" advertises a dependency the app does not have,
    /// which is both untrue and discouraging. This lets an install be honestly
    /// local.
    ///
    /// Off by default, because hiding a feature the user has is worse than
    /// showing one they have not set up yet. `UserDefaults.bool` returns false
    /// when the key is absent, so the default falls out of the read.
    @Published var localOnly = UserDefaults.standard.bool(forKey: "gimbal.localOnly")

    /// The last security posture we were able to read, and why we could not.
    ///
    /// Held as an optional rather than defaulting to an empty report on
    /// purpose: "we do not know" and "nothing is wrong" must not render the
    /// same way. `postureError` carries the reason so the panel can say it.
    @Published var posture: PostureReport?
    @Published var postureError: String?
    @Published var isCheckingPosture = false

    /// Credential-proxy state (V6.2). No credential value ever lands here —
    /// `chm proxy show` does not read one, by design.
    @Published var proxyConfig: ProxyConfiguration?
    @Published var proxyCa: ProxyCa?
    @Published var proxyCheck: ProxyCheckResult?
    @Published var isCheckingProxy = false
    @Published var proxyCheckHost = "api.github.com"
    @Published var proxyCheckPath = "/user"
    @Published var isInstallingCa = false

    /// The running sandbox's audit trail (V6.3). Optional because "the daemon
    /// did not answer" and "the sandbox made no calls" are different facts and
    /// must not render alike — an empty trail is the more alarming of the two,
    /// not the less.
    @Published var auditTrail: AuditTrail?
    @Published var isLoadingAudit = false
    @Published var capabilities: CapabilityReport?
    @Published var isLoadingCapabilities = false
    /// A sandbox the user chose to read history for while nothing is running.
    private var auditScopeDir: String?

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
    private let globalDefaultsKey = "gimbal.globalDefaults"
    private let localOnlyDefaultsKey = "gimbal.localOnly"
    private let maxRecents = 8

    func bootstrap() async {
        loadRecents()
        loadSandboxes()
        loadGlobalDefaults()
        // Adopt any sessions still alive from a previous app run before the first
        // refresh, so an inherited `chm connect` VM shows running and its slot is
        // protected rather than appearing free (#71).
        reconcileSessions()
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

        // Local-only means local-only. Hiding the cloud UI while still calling
        // out to a control plane every refresh would make the setting a
        // cosmetic lie -- the user asked the app not to depend on one, so it
        // must not reach for one. This also keeps a stale `cloud` snapshot list
        // from lingering behind the toggle.
        guard !localOnly else {
            cloud = CloudOverview(
                state: .offline("local-only mode"),
                runners: nil,
                snapshots: nil,
                sandboxes: nil,
                costSummary: nil
            )
            cloudSnapshots = []
            branches = []
            return
        }

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

    /// Re-read which security controls are actually in force.
    ///
    /// Asks the **daemon** first (`chm ctl posture`), because posture is
    /// resolved from the environment of whichever process computes it and
    /// `chm serve` is the process that owns the guest — this app's own
    /// environment can differ from it entirely when we attached to a daemon we
    /// did not start (see `startDaemon`, which only manages a daemon it
    /// launched itself).
    func refreshPosture() async {
        guard !isCheckingPosture else { return }
        isCheckingPosture = true
        defer { isCheckingPosture = false }

        switch await chm.posture(localFallbackPath: settings.libraryPath, settings: settings) {
        case let .success(report):
            posture = report
            postureError = nil
        case let .failure(error):
            // Keep the last good report on screen rather than flashing to an
            // unknown state on a transient failure, but surface the reason.
            postureError = error.reason
            if posture == nil { appendLog("posture: \(error.reason)") }
        }
    }

    /// Re-read the credential-proxy configuration and CA.
    func refreshProxy() async {
        proxyConfig = await chm.proxyShow(path: settings.libraryPath, settings: settings)
        if proxyCa == nil {
            proxyCa = await chm.proxyCa(path: settings.libraryPath, settings: settings)
        }
    }

    /// Send a real request through the proxy, with its control run.
    func runProxyCheck() async {
        guard !isCheckingProxy else { return }
        isCheckingProxy = true
        defer { isCheckingProxy = false }
        let host = proxyCheckHost.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return }
        let path = proxyCheckPath.isEmpty ? "/" : proxyCheckPath
        proxyCheck = await chm.proxyCheck(
            host: host,
            path: path,
            rulesFile: nil,
            settings: settings
        )
        if proxyCheck == nil {
            appendLog("proxy check: chm returned nothing usable for \(host)\(path)")
        }
    }

    /// Re-read the running sandbox's audit trail.
    ///
    /// A failed read clears the trail rather than leaving the last good one on
    /// screen. That is the opposite of the posture policy above, and on purpose:
    /// a stale *posture* is still a description of a configuration that probably
    /// has not changed, but a stale *trail* is a claim about what a sandbox is
    /// doing right now, and showing yesterday's decisions as today's is worse
    /// than showing none.
    func refreshAudit(dir: String? = nil) async {
        guard !isLoadingAudit else { return }
        isLoadingAudit = true
        defer { isLoadingAudit = false }
        // A directory the user picked sticks, so a reload does not throw them
        // back to the picker mid-read. Cleared as soon as a sandbox is running,
        // because the live one is then unambiguously the subject.
        if let dir { auditScopeDir = dir }
        if status.state == .running { auditScopeDir = nil }
        auditTrail = await chm.auditTrail(settings: settings, dir: auditScopeDir)
    }

    /// What the daemon's binary can do, and what it makes of the snapshot in
    /// scope.
    ///
    /// Cleared on failure rather than left stale. Posture can survive a missed
    /// refresh because a configuration probably has not changed, but a
    /// capability answer is partly a probe of *this moment* — the binary may
    /// have been rebuilt out from under the daemon, losing its entitlement —
    /// and a stale yes is the exact shape of the bug this panel exists to end.
    func refreshCapabilities(dir: String? = nil) async {
        guard !isLoadingCapabilities else { return }
        isLoadingCapabilities = true
        defer { isLoadingCapabilities = false }
        capabilities = await chm.capabilities(settings: settings, dir: dir)
    }

    /// Install the workspace CA inside the running guest.
    ///
    /// Typed at the console rather than copied in, because there is no shared
    /// filesystem — that is the point of I1, not an oversight. The script is a
    /// heredoc, so it is sent a line at a time and the guest's shell assembles
    /// it; the last two lines print the installed fingerprint and the expected
    /// one, so the console itself is the proof the install took.
    func installProxyCaInGuest() {
        guard status.state == .running else {
            appendLog("cannot install the CA: no sandbox is running")
            return
        }
        guard let ca = proxyCa else {
            appendLog("cannot install the CA: no workspace CA has been generated yet")
            return
        }
        guard !isInstallingCa else { return }
        isInstallingCa = true
        appendLog("installing proxy CA \(ca.fingerprint) in the guest…")
        Task {
            defer { isInstallingCa = false }
            if consoleProcess == nil { attachConsole() }
            // Prefer the checked transfer. Typing the script line by line was
            // measured to fail on a rehydrated Graviton guest: because
            // `update-ca-certificates` takes seconds, every verification line
            // behind it sat in the tty queue, was echoed, and never ran — so
            // the console showed the script instead of its output and this
            // panel had nothing to report. The checked transfer sends only
            // instant commands until the end and makes the guest hash what it
            // got before running any of it.
            let unchecked = ca.installLines.isEmpty
            let lines: [String] = unchecked
                ? ca.installScript.split(separator: "\n", omittingEmptySubsequences: false)
                    .map(String.init)
                : ca.installLines
            if unchecked {
                appendLog(
                    "note: this chm build predates the checked CA transfer, so the script is "
                        + "being typed line by line — a console drop will corrupt it silently"
                )
            }
            for line in lines {
                do {
                    _ = try await chm.sendInput(
                        ChmClient.encodeLine(line),
                        settings: settings
                    )
                } catch {
                    appendLog("CA install failed: \(error.localizedDescription)")
                    return
                }
                // Paced because this is a serial console and the payload is
                // ~10 lines. With the checked transfer the pacing no longer has
                // to be *correct* — every line but the last returns in
                // microseconds, and anything the console still drops is caught
                // by the digest instead of becoming a corrupt certificate.
                try? await Task.sleep(for: .milliseconds(60))
            }
            consoleHasBeenTypedAt = true
            appendLog(
                "CA script sent — the guest prints `trusted:` with the fingerprint if its "
                    + "trust store now accepts the CA, `NOT TRUSTED` if it does not, or "
                    + "`TRANSFER CORRUPT` if the console dropped characters on the way in. "
                    + "Measured on a rehydrated Graviton guest: update-ca-certificates can "
                    + "segfault and the CA never lands, so the console line is the proof, "
                    + "not this message."
            )
        }
    }

    /// Bring a snapshot down from the control plane and run it here as a
    /// first-class **cloud-origin sandbox**: drives the `chm runner` pipeline
    /// (assign-run → verify → mark-local-copy → run/resume) and tracks the run as
    /// a sandbox that appears in the unified list alongside local ones, marked
    /// with a cloud badge. "Remote vs local" stays an implementation detail.
    func bringDownAndRun(_ snapshot: CloudSnapshot) {
        guard bringingDownID == nil else { return }
        if let reason = snapshot.notBootableReason {
            appendLog("cloud: \(snapshot.id) can't run here — \(reason)")
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

    /// Set a branch's review gate (`pending` / `approved` / `rejected`) via
    /// `chm branches review`, then refresh so the UI reflects the new status.
    func setBranchReview(_ name: String, status: String) {
        Task {
            let result = await chm.reviewBranch(
                name, status: status, api: settings.controlPlaneURL, settings: settings
            )
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            appendLog(
                result.status == 0
                    ? "branch \(name): review → \(status)"
                    : "branch \(name): review failed — \(trimmed)"
            )
            await refreshAll()
        }
    }

    /// Merge `from` into `target` via `chm branches merge` (review-gated on the
    /// plane), then refresh.
    func mergeBranches(target: String, from: String) {
        Task {
            let result = await chm.mergeBranch(
                target: target, from: from, api: settings.controlPlaneURL, settings: settings
            )
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            appendLog(
                result.status == 0
                    ? "merged \(from) → \(target)"
                    : "merge \(from) → \(target) failed — \(trimmed)"
            )
            await refreshAll()
        }
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
        consoleHasBeenTypedAt = false
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

    /// Type a line at the running guest's console.
    ///
    /// This is what makes a vanilla capture usable from the app rather than from
    /// a Terminal window: a resumed guest emits **nothing at all** until it is
    /// typed at, so without an input path Start looks indistinguishable from a
    /// hang.
    func sendConsoleLine(_ line: String) {
        sendConsole(ChmClient.encodeLine(line), describedAs: line.isEmpty ? "Return" : line)
    }

    /// Send a control key the text field cannot express (Ctrl-C, Ctrl-D, …).
    func sendConsoleKey(_ key: ConsoleKey) {
        sendConsole(key.wireText, describedAs: key.label)
    }

    private func sendConsole(_ wireText: String, describedAs description: String) {
        guard status.state == .running else {
            appendLog("cannot type at the console: no sandbox is running")
            return
        }
        // The stream is what shows the guest's reply, so make sure it is live
        // before the keystroke lands rather than after.
        if consoleProcess == nil {
            attachConsole()
        }
        Task {
            do {
                _ = try await chm.sendInput(wireText, settings: settings)
                consoleHasBeenTypedAt = true
            } catch {
                appendLog("sending `\(description)` failed: \(error.localizedDescription)")
            }
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
        // it a raw argv for `chm` itself. But we avoid a second escaping layer by
        // passing the (already single-quoted, control-char-validated by
        // `InteractiveTerminalCommand`, M30.3) command to `osascript` as an
        // argv parameter via `on run argv` — never interpolated into the
        // AppleScript source — so a path can never break out of the script text
        // into host code (M30.3 follow-up, #67).
        let command = try InteractiveTerminalCommand.shellCommand(
            chmPath: settings.chmPath,
            runPath: runPath,
            socketPath: settings.socketPath,
            lockPath: lockPath,
            workdir: FileManager.default.currentDirectoryPath
        )

        // The script is a constant with no interpolation; the command travels as
        // argv item 1, so AppleScript string-literal escaping is not needed.
        let script = """
        on run argv
            tell application "Terminal"
                activate
                do script (item 1 of argv)
            end tell
        end run
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script, command]

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

    /// Reconcile the authoritative session registry: scan every stored local
    /// sandbox's PID lock, derive liveness from the owning process, reap dead
    /// locks, and update `liveLocalSessionIDs`. Also detects when the tracked
    /// console session ends (e.g. the user closed the Terminal window). Cheap;
    /// driven by the periodic refresh loop and by launch guards.
    ///
    /// This is authoritative across app restarts: a `chm connect` VM launched by
    /// a previous app run still owns its lock, so it is re-detected as live and
    /// the single HVF slot stays protected, instead of appearing free.
    func reconcileSessions() {
        let fm = FileManager.default
        var live: Set<String> = []
        for stored in storedSandboxes where stored.location == .local {
            let lock = sessionLockPath(for: stored.id)
            guard fm.fileExists(atPath: lock) else { continue }
            if lockOwnerAlive(lock) {
                live.insert(stored.id)
                if stored.id == interactiveSandboxID { interactiveLockSeen = true }
            } else {
                // Owner gone without cleanup (e.g. SIGKILL): reap the stale lock.
                try? fm.removeItem(atPath: lock)
            }
        }

        // The just-launched console session may not have written its lock yet;
        // keep it live through the start grace period so a slow launch isn't
        // dropped, and detect a genuine end to clear console tracking.
        if let id = interactiveSandboxID, !live.contains(id) {
            let lock = sessionLockPath(for: id)
            let lockExists = fm.fileExists(atPath: lock)
            let ended = InteractiveLiveness.sessionEnded(
                lockExists: lockExists,
                ownerAlive: lockExists && lockOwnerAlive(lock),
                lockSeen: interactiveLockSeen,
                pastStartDeadline: interactiveDeadline.map { Date() > $0 } ?? true
            )
            if ended {
                appendLog("interactive session for \(sandbox(id: id)?.name ?? id) ended")
                if activeLocalSandboxID == id { activeLocalSandboxID = nil }
                if lockExists { try? fm.removeItem(atPath: lock) }
                clearInteractiveTracking()
                Task { await refreshLocal() }
            } else {
                // Still within the launch grace period — treat as live.
                live.insert(id)
            }
        }

        liveLocalSessionIDs = live
    }

    /// The PID recorded in a sandbox's session lock, if the file names a live
    /// process. Used to authoritatively stop a `chm connect` session.
    private func liveSessionPID(for id: String) -> Int32? {
        let lock = sessionLockPath(for: id)
        guard
            FileManager.default.fileExists(atPath: lock),
            let body = try? String(contentsOfFile: lock, encoding: .utf8),
            let pid = Int32(body.trimmingCharacters(in: .whitespacesAndNewlines)),
            kill(pid, 0) == 0 || errno == EPERM
        else {
            return nil
        }
        return pid
    }

    /// The sandbox (other than `exclude`) currently holding the single local VM
    /// slot via a live `chm connect` session, if any. Re-scans the registry first
    /// so the decision is fresh. Used to prevent slot contention on launch.
    func liveSlotHolder(excluding exclude: String?) -> Sandbox? {
        reconcileSessions()
        return slotHolder(excluding: exclude)
    }

    /// The current slot holder from the cached registry, without re-scanning.
    func slotHolder(excluding exclude: String?) -> Sandbox? {
        guard let id = liveLocalSessionIDs.first(where: { $0 != exclude }) else { return nil }
        return sandbox(id: id)
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
    /// Application Support directory. Internal (not private) so the session
    /// registry's real scan/reap path can be exercised in tests.
    func sessionLockPath(for id: String) -> String {
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
        // The session registry is authoritative for local liveness: a live
        // `chm connect` VM (tracked or inherited from a previous app run) means
        // the sandbox is running, regardless of the daemon slot (#61, #71).
        if liveLocalSessionIDs.contains(id) {
            return .running
        }
        if id == startingSandboxID {
            return .starting
        }
        // Fall back to the daemon's status for a daemon-run active sandbox.
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
        await applyGlobalDefaults(toWorkspace: ws, sandboxName: stored.name)
        return ws
    }

    /// Apply the app's global default limits + firewall to a freshly created
    /// workspace, so every new sandbox gets sane guard rails without per-sandbox
    /// setup. Only writes a control the workspace does not already have (so a
    /// re-created workspace or a user-authored policy is never clobbered), and
    /// only when that default is enabled.
    private func applyGlobalDefaults(toWorkspace ws: String, sandboxName: String) async {
        let fm = FileManager.default
        let defaults = globalDefaults

        if defaults.limits.enabled, !fm.fileExists(atPath: ws + "/limits.json") {
            let result = await chm.limitsSet(path: ws, limits: defaults.limits, settings: settings)
            if result.status == 0 {
                appendLog("applied default limits to \(sandboxName)")
            }
        }

        if defaults.firewall.enabled, !fm.fileExists(atPath: ws + "/egress-policy.json") {
            let fw = defaults.firewall
            let result: CommandResult
            switch fw.mode {
            case .open:
                result = await chm.firewallClear(path: ws, settings: settings)
            case .noNetwork:
                result = await chm.firewallSet(
                    path: ws, defaultStance: "deny", allow: [], deny: [], settings: settings)
            case .allowlist:
                result = await chm.firewallSet(
                    path: ws, defaultStance: "deny", allow: fw.allow, deny: [], settings: settings)
            }
            if result.status == 0 {
                appendLog("applied default firewall (\(fw.mode.rawValue)) to \(sandboxName)")
            }
        }
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

    // MARK: - Local egress firewall (per-sandbox connectivity)

    /// The directory whose `egress-policy.json` governs a sandbox: its isolated
    /// workspace once it exists, else `nil` (no policy can be bound until the
    /// sandbox has a workspace, which is created lazily on first run or apply).
    private func firewallDir(for sandbox: Sandbox) -> String? {
        if let ws = storedSandboxes.first(where: { $0.id == sandbox.id })?.workspacePath {
            return ws
        }
        return sandbox.workspacePath
    }

    /// Load a sandbox's egress posture into `egressPolicyBySandbox`. A sandbox
    /// with no workspace yet has no policy — it shows as unrestricted until the
    /// user applies one (which creates the workspace).
    func refreshFirewall(for sandbox: Sandbox) {
        guard let dir = firewallDir(for: sandbox) else {
            egressPolicyBySandbox[sandbox.id] = .unrestricted
            return
        }
        Task {
            egressPolicyBySandbox[sandbox.id] = await chm.firewallShow(path: dir, settings: settings)
        }
    }

    /// Apply a connectivity posture to a sandbox, authoring its workspace
    /// `egress-policy.json` via `chm firewall`. Ensures the workspace exists first
    /// so the policy is per-sandbox (not shared across sandboxes of one image).
    /// Takes effect on the sandbox's next start (the daemon reads the file when it
    /// wires the guest's network).
    func setConnectivity(for sandbox: Sandbox, mode: EgressPolicy.Mode, allow: [String]) {
        guard applyingFirewallID == nil else { return }
        applyingFirewallID = sandbox.id
        Task {
            defer { applyingFirewallID = nil }
            guard let dir = await ensureWorkspace(sandboxID: sandbox.id) else {
                appendLog("cannot set connectivity for \(sandbox.name): no workspace")
                return
            }
            let result: CommandResult
            switch mode {
            case .open:
                result = await chm.firewallClear(path: dir, settings: settings)
            case .noNetwork:
                result = await chm.firewallSet(
                    path: dir, defaultStance: "deny", allow: [], deny: [], settings: settings
                )
            case .allowList:
                let rules = allow
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                result = await chm.firewallSet(
                    path: dir, defaultStance: "deny", allow: rules, deny: [], settings: settings
                )
            }
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { appendLog(trimmed) }
            egressPolicyBySandbox[sandbox.id] = await chm.firewallShow(path: dir, settings: settings)
            if sandbox.state == .running {
                appendLog("connectivity change applies the next time \(sandbox.name) starts")
            }
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
        // Single HVF slot: don't start a second VM while another sandbox is live.
        if let holder = liveSlotHolder(excluding: sandbox.id) {
            appendLog(
                "cannot start \(sandbox.name): \(holder.name) is using the single local VM slot — stop it first"
            )
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
        // Single HVF slot: refuse to open a second VM while another sandbox holds
        // a live session, which would contend on the slot (the second VM can be
        // "alive" but non-functional). Authoritative via the session registry so
        // this holds even for a session inherited from a previous app run (#71).
        if let holder = liveSlotHolder(excluding: sandbox.id) {
            appendLog(
                "cannot connect \(sandbox.name): \(holder.name) is using the single local VM slot — stop it first"
            )
            return
        }
        activeLocalSandboxID = sandbox.id
        startingSandboxID = nil
        interactiveSandboxID = sandbox.id
        // Maintain a PID lock so the session's end (including a closed window) is
        // detectable by the session registry (reconcileSessions).
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
        // A `chm connect` session runs its own VM (not the daemon's), so stopping
        // it means terminating that process. Signal the lock owner so the VM tears
        // down cleanly (chm's Drop destroys the HVF VM); then reap tracking. This
        // makes Stop authoritative for connect sessions, not just daemon-run ones.
        if let pid = liveSessionPID(for: sandbox.id) {
            kill(pid, SIGTERM)
            appendLog("stopping \(sandbox.name) (signalled its session)")
        }
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
            let lock = sessionLockPath(for: sandbox.id)
            try? FileManager.default.removeItem(atPath: lock)
            consoleProcess?.terminate()
            consoleProcess = nil
            reconcileSessions()
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

    /// Persist local-only mode, and make sure the user is not left staring at a
    /// page that no longer has a way back. Hiding the section the current
    /// selection lives in would otherwise strand the detail pane on a view the
    /// sidebar can no longer reach.
    func saveLocalOnly() {
        UserDefaults.standard.set(localOnly, forKey: localOnlyDefaultsKey)
        if localOnly, selection == .cloudHome {
            selection = .sandboxesHome
        }
    }

    func loadSandboxes() {
        guard let data = UserDefaults.standard.data(forKey: sandboxesDefaultsKey),
              let list = try? JSONDecoder().decode([StoredSandbox].self, from: data)
        else { return }
        storedSandboxes = list
    }

    func loadGlobalDefaults() {
        guard let data = UserDefaults.standard.data(forKey: globalDefaultsKey),
              let defaults = try? JSONDecoder().decode(GlobalDefaults.self, from: data)
        else { return }
        globalDefaults = defaults
    }

    /// Persist the global defaults (call after the user edits them in Settings).
    func saveGlobalDefaults() {
        if let data = try? JSONEncoder().encode(globalDefaults) {
            UserDefaults.standard.set(data, forKey: globalDefaultsKey)
        }
    }

    private func saveSandboxes() {
        if let data = try? JSONEncoder().encode(storedSandboxes) {
            UserDefaults.standard.set(data, forKey: sandboxesDefaultsKey)
        }
    }

    var engineIndicator: EngineIndicator {
        // Reconcile liveness from all signals, not the daemon slot alone: an
        // app-launched sandbox runs via `chm connect` in its own process (its own
        // VM, tracked by a session lock), which the daemon's `ctl status` cannot
        // see. So the daemon slot can read idle while a sandbox the user is
        // actively in is very much alive. Reflect any live sandbox as running
        // rather than reporting the engine idle (#61).
        if status.state != .running {
            let live = sandboxes.filter { $0.state == .running || $0.state == .starting }
            if !live.isEmpty {
                return EngineIndicator(
                    label: live.count == 1 ? "Sandbox running" : "\(live.count) sandboxes running",
                    detail: live.count == 1
                        ? (live.first?.name ?? "interactive session")
                        : "interactive sessions",
                    symbol: "play.circle.fill",
                    tone: .active
                )
            }
        }
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
        if status.state == .running {
            // Not a hang, and worth saying plainly: a guest restored from a
            // snapshot resumes at whatever it was doing when it was captured —
            // usually sitting at an idle prompt — so it prints nothing until it
            // is typed at.
            return """
            The guest is running and silent.

            A resumed snapshot picks up where it was captured, so it prints
            nothing until you type. Press Return below to wake its prompt.
            """
        }
        return "Serial output will stream here after a sandbox is running."
    }

    /// True when the guest is up but has produced nothing and has not been typed
    /// at — the moment the UI should nudge rather than look broken.
    var consoleAwaitsFirstKeystroke: Bool {
        status.state == .running && consoleText.isEmpty && !consoleHasBeenTypedAt
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
