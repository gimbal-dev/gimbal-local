// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import AppKit
import SwiftUI

// MARK: - Sandboxes main page

struct SandboxesPage: View {
    @EnvironmentObject private var model: AppModel

    private let columns = [GridItem(.adaptive(minimum: 320, maximum: 460), spacing: 16)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if !model.welcomeDismissed {
                    WelcomeBanner()
                }

                PageHeader(
                    title: "Sandboxes",
                    subtitle: "Run and work inside your sandboxes — local or brought down from the cloud."
                ) {
                    NewSandboxMenu(prominent: true)
                }

                if model.sandboxes.isEmpty {
                    SandboxesEmptyState()
                } else {
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
                        ForEach(model.sandboxes) { sandbox in
                            SandboxCard(sandbox: sandbox)
                        }
                    }
                }
            }
            .padding(28)
        }
    }
}

private struct WelcomeBanner: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack(alignment: .topTrailing) {
            HStack(spacing: 18) {
                AppIconView(size: 58)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Welcome to Gimbal Local")
                        .font(.title2.weight(.heavy))
                        .foregroundStyle(.white)
                    Text("Create a sandbox from a snapshot image, then open a terminal and work inside it. The local engine starts itself.")
                        .font(.callout)
                        .foregroundStyle(.white.opacity(0.78))
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(22)
            .padding(.trailing, 16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .fill(Theme.heroGradient)
            }
            .overlay {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(.white.opacity(0.12), lineWidth: 1)
            }

            Button {
                model.dismissWelcome()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.white.opacity(0.85))
                    .padding(8)
                    .background(.white.opacity(0.14), in: Circle())
            }
            .buttonStyle(.plain)
            .padding(12)
            .help("Dismiss")
        }
    }
}

private struct SandboxesEmptyState: View {
    @EnvironmentObject private var model: AppModel

    private var guidance: FirstRunGuidance.State {
        FirstRunGuidance.evaluate(
            hasSnapshots: !model.snapshots.isEmpty,
            localImages: model.localImages,
            imagesPath: model.settings.localImagesPath
        )
    }

    var body: some View {
        let g = guidance
        VStack(spacing: 16) {
            Image(systemName: "shippingbox")
                .font(.system(size: 52))
                .foregroundStyle(Theme.cyan)
            Text(g.headline)
                .font(.title2.weight(.bold))
            Text.authored(g.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)
            if !g.rejections.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(g.rejections, id: \.name) { r in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.name).font(.callout.weight(.semibold))
                                Text.authored(r.reason)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .frame(maxWidth: 460, alignment: .leading)
                .padding(12)
                .background {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(.orange.opacity(0.08))
                }
            }

            // Never disabled. The menu explains what is missing and where to
            // put it, so opening it always teaches something; a greyed-out
            // button teaches nothing. The bug this replaces gated it on the
            // snapshot library being non-empty, which greyed out cold boot —
            // the one path that needs no snapshot, no KVM host and no control
            // plane. Keeping the decision out of the four call sites means it
            // cannot come back at one of them.
            NewSandboxMenu(prominent: true)

            HStack(spacing: 12) {
                if !model.snapshots.isEmpty {
                    Button("Browse snapshots") { model.selection = .snapshotsHome }
                        .buttonStyle(.bordered)
                }
                if !g.canStartSomething {
                    Button("Open images folder") {
                        revealImagesFolder(model.settings.localImagesPath)
                    }
                    .buttonStyle(.bordered)
                    SettingsLink { Text("Settings") }
                        .buttonStyle(.bordered)
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 320)
        .padding(40)
        .background {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay {
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(.white.opacity(0.12), lineWidth: 1)
                }
        }
    }
}

/// Open the configured images folder in Finder, creating it first if it is not
/// there yet.
///
/// Creating it is the point: on a first run the folder usually does not exist,
/// and a button that opens nothing teaches nothing. Making it means the next
/// step ("put a folder in here") is something the user can actually see.
private func revealImagesFolder(_ path: String) {
    guard !path.isEmpty else { return }
    let expanded = (path as NSString).expandingTildeInPath
    var isDir: ObjCBool = false
    if !FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir) {
        try? FileManager.default.createDirectory(
            atPath: expanded, withIntermediateDirectories: true
        )
    }
    NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: expanded)
}

// MARK: - Sandbox card

private struct SandboxCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Theme.blueprintGradient)
                        .frame(width: 40, height: 40)
                    Image(systemName: "shippingbox.fill").foregroundStyle(.white)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(sandbox.name).font(.headline).lineLimit(1)
                    Text("from \(sandbox.snapshotName)")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
            }

            HStack(spacing: 8) {
                SandboxStateBadge(state: sandbox.state)
                LocationBadge(location: sandbox.location)
            }

            if sandbox.location == .remote {
                RemoteSandboxActions(sandbox: sandbox)
            } else {
                LocalSandboxActions(sandbox: sandbox)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay {
                    RoundedRectangle(cornerRadius: 22, style: .continuous)
                        .stroke(.white.opacity(0.13), lineWidth: 1)
                }
        }
        .contentShape(Rectangle())
        .onTapGesture { model.selection = .sandbox(sandbox.id) }
    }
}

/// Actions for a local (daemon-backed) sandbox: open a terminal, start/stop.
private struct LocalSandboxActions: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    private var isLive: Bool { sandbox.state == .running || sandbox.state == .starting }

    var body: some View {
        HStack(spacing: 10) {
            Button {
                model.connect(to: sandbox)
            } label: {
                Label("Open terminal", systemImage: "terminal.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Menu {
                Button {
                    model.startSandbox(sandbox)
                } label: {
                    Label("Start", systemImage: "play.fill")
                }
                .disabled(isLive)

                Button {
                    model.stop(sandbox)
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .disabled(!isLive)

                Button {
                    model.selection = .sandbox(sandbox.id)
                } label: {
                    Label("Open details", systemImage: "info.circle")
                }
                Divider()
                Button(role: .destructive) {
                    model.deleteSandbox(sandbox)
                } label: {
                    Label("Remove sandbox", systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.button)
            .buttonStyle(.bordered)
            .fixedSize()
        }
    }
}

/// Actions for a cloud-origin sandbox: it runs one-shot through `chm runner`, so
/// the primary action is to bring it down again rather than attach a terminal.
private struct RemoteSandboxActions: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    private var isBusy: Bool { model.bringingDownID == sandbox.snapshotName }

    var body: some View {
        HStack(spacing: 10) {
            Button {
                model.rerunCloudSandbox(sandbox)
            } label: {
                HStack(spacing: 8) {
                    if isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.down.circle.fill")
                    }
                    Text(isBusy ? "Bringing down…" : "Bring down again")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.bringingDownID != nil)

            Menu {
                Button {
                    model.selection = .sandbox(sandbox.id)
                } label: {
                    Label("Open details", systemImage: "info.circle")
                }
                Divider()
                Button(role: .destructive) {
                    model.deleteSandbox(sandbox)
                } label: {
                    Label("Remove sandbox", systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.button)
            .buttonStyle(.bordered)
            .fixedSize()
        }
    }
}

// MARK: - Sandbox detail (work inside)

struct SandboxDetailPage: View {
    @EnvironmentObject private var model: AppModel
    let sandboxID: String

    var body: some View {
        if let sandbox = model.sandbox(id: sandboxID) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    PageHeader(title: sandbox.name, subtitle: "from \(sandbox.snapshotName)") {
                        HStack(spacing: 8) {
                            SandboxStateBadge(state: sandbox.state)
                            LocationBadge(location: sandbox.location)
                        }
                    }

                    if sandbox.location == .remote {
                        RemoteSandboxCard(sandbox: sandbox)
                    } else {
                        WorkInsideCard(sandbox: sandbox)
                        SandboxControlsCard(sandbox: sandbox)
                        ConnectivityCard(sandbox: sandbox)
                        WorkspaceLocationCard(sandbox: sandbox)
                        RevisionHistoryCard(
                            dirPath: sandbox.workspacePath,
                            emptyHint: "Run this sandbox (Open terminal), then end the session to save its live state as a revision here — isolated from other sandboxes of the same image."
                        )
                        ConsoleExpander()
                    }
                }
                .padding(28)
            }
        } else {
            ContentUnavailableView(
                "Sandbox not found",
                systemImage: "shippingbox",
                description: Text("It may have been removed.")
            )
        }
    }
}

/// Detail for a cloud-origin sandbox: provenance + a bring-down control. It runs
/// one-shot through `chm runner`, so there is no persistent daemon session to
/// attach a terminal to (yet) — bringing it down resumes/runs it on HVF.
private struct RemoteSandboxCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    private var cloudSnapshot: CloudSnapshot? {
        model.cloudSnapshots.first { $0.id == sandbox.snapshotName }
    }
    private var isBusy: Bool { model.bringingDownID == sandbox.snapshotName }

    var body: some View {
        GlassCard(title: "Cloud sandbox", subtitle: "brought down from the control plane", systemImage: "cloud.fill") {
            Text("This sandbox comes from a control-plane snapshot. Bringing it down drives the runner pipeline — assign-run → verify → \(cloudSnapshot?.isCheckpoint == true ? "resume" : "run") — and rehydrates it locally on Apple HVF.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            MetricRow(label: "Snapshot", value: sandbox.snapshotName)
            if let snap = cloudSnapshot {
                MetricRow(label: "Kind", value: snap.kind)
                if let origin = snap.originLabel {
                    MetricRow(label: "Origin", value: origin)
                }
                MetricRow(label: "Shape", value: "\(snap.vcpus) vCPU · \(snap.ramMib) MiB")
            }

            if sandbox.state == .failed, let reason = sandbox.reason {
                FailureBanner(reason: reason)
            }

            Button {
                model.rerunCloudSandbox(sandbox)
            } label: {
                HStack(spacing: 8) {
                    if isBusy { ProgressView().controlSize(.small) }
                    Label(isBusy ? "Bringing down…" : "Bring down & run", systemImage: "arrow.down.circle.fill")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.bringingDownID != nil || cloudSnapshot?.restorableOnHVF == false)

            Button(role: .destructive) {
                model.deleteSandbox(sandbox)
            } label: {
                Label("Remove sandbox", systemImage: "trash").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
    }
}

private struct WorkInsideCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    var body: some View {
        GlassCard(title: "Work inside", subtitle: "interactive shell session", systemImage: "terminal.fill") {
            Text("Open a terminal into the sandbox and run commands directly. Log in with `ubuntu` / `ubuntu` if prompted. Close the window or press Ctrl-A x to suspend — your live state is saved, and reconnecting resumes exactly where you left off.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                model.connect(to: sandbox)
            } label: {
                Label("Open terminal", systemImage: "terminal.fill")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }
}

private struct SandboxControlsCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    var body: some View {
        GlassCard(title: "Lifecycle", subtitle: "start, stop, and status", systemImage: "bolt.horizontal.circle.fill") {
            HStack(spacing: 12) {
                BigMetric(title: "State", value: sandbox.state.label, color: Theme.color(for: sandbox.state))
                BigMetric(title: "Uptime", value: uptime(sandbox), color: Theme.cyan)
                BigMetric(title: "Console", value: consoleBytes(sandbox), color: Theme.purple)
            }

            if sandbox.state == .failed, let reason = sandbox.reason {
                FailureBanner(reason: reason)
            }

            // Why Start is disabled. Without this the button was enabled, did
            // nothing, and wrote its reason to a log the user never opens.
            if let contention {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.orange)
                    Text(contention.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    if let holder = model.slotHolder(excluding: sandbox.id) {
                        Button(contention.remedyLabel) { model.stop(holder) }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                }
            }

            HStack(spacing: 10) {
                Button {
                    model.startSandbox(sandbox)
                } label: {
                    Label(sandbox.state == .starting ? "Starting…" : "Start", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(isLive || contention != nil)

                Button(role: .destructive) {
                    model.stop(sandbox)
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
                .disabled(!isLive)

                Spacer()

                Button(role: .destructive) {
                    model.deleteSandbox(sandbox)
                } label: {
                    Label("Remove", systemImage: "trash")
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private var isLive: Bool {
        sandbox.state == .running || sandbox.state == .starting
    }

    /// `nil` whenever the slot is free or this sandbox is the one using it —
    /// so the explanation appears exactly when Start would otherwise have been
    /// refused, and never otherwise.
    private var contention: SlotContention.State? {
        SlotContention.evaluate(
            holderName: model.slotHolder(excluding: sandbox.id)?.name,
            thisSandboxIsLive: isLive
        )
    }

    private func uptime(_ sandbox: Sandbox) -> String {
        guard let seconds = sandbox.uptimeSeconds else { return "—" }
        return "\(seconds)s"
    }

    private func consoleBytes(_ sandbox: Sandbox) -> String {
        guard let bytes = sandbox.consoleBytes else { return "0 B" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

/// Per-sandbox outbound network firewall. A client of `chm firewall`: the user
/// picks a posture (Open / No network / Allow-list) and the model writes the
/// sandbox workspace's `egress-policy.json`, which the userspace NAT enforces on
/// the next start — no control plane required. A cloud-bound policy is shown
/// read-only.
private struct ConnectivityCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    @State private var mode: EgressPolicy.Mode = .open
    @State private var rules: [String] = []
    @State private var newRule = ""

    private var policy: EgressPolicy { model.egressPolicyBySandbox[sandbox.id] ?? .unrestricted }
    private var isApplying: Bool { model.applyingFirewallID == sandbox.id }

    var body: some View {
        GlassCard(title: "Connectivity", subtitle: "outbound network firewall", systemImage: "network") {
            if policy.isControlPlaneBound {
                controlPlaneBound
            } else {
                editor
            }
        }
        .task(id: sandbox.id) { model.refreshFirewall(for: sandbox) }
        .onChange(of: policy) { _, _ in syncFromPolicy() }
        .onAppear(perform: syncFromPolicy)
    }

    // MARK: locally-authored editor

    private var editor: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("Egress", selection: $mode) {
                Text("Open").tag(EgressPolicy.Mode.open)
                Text("No network").tag(EgressPolicy.Mode.noNetwork)
                Text("Allow-list").tag(EgressPolicy.Mode.allowList)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(isApplying)

            Text(modeHint)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if mode == .allowList {
                allowListEditor
            }

            Divider().opacity(0.25)

            HStack(spacing: 10) {
                StatusDot(color: posture.color, size: 7)
                Text(posture.text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                Button {
                    model.setConnectivity(for: sandbox, mode: mode, allow: rules)
                } label: {
                    if isApplying {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Apply")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isApplying || !hasChanges)
            }
        }
    }

    private var allowListEditor: some View {
        VStack(alignment: .leading, spacing: 8) {
            if rules.isEmpty {
                Text("No destinations allowed yet — the guest can reach nothing until you add one.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(rules, id: \.self) { rule in
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.caption)
                            .foregroundStyle(Theme.green)
                        Text(rule)
                            .font(.callout.monospaced())
                        Spacer()
                        Button {
                            rules.removeAll { $0 == rule }
                        } label: {
                            Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .disabled(isApplying)
                    }
                }
            }
            HStack(spacing: 8) {
                TextField("host:port  ·  e.g. github.com:443", text: $newRule)
                    .textFieldStyle(.roundedBorder)
                    .font(.callout.monospaced())
                    .onSubmit(addRule)
                    .disabled(isApplying)
                Button("Add", action: addRule)
                    .disabled(isApplying || newRule.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    // MARK: control-plane-bound (read-only)

    private var controlPlaneBound: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Governed by the control plane", systemImage: "lock.shield.fill")
                .font(.headline)
                .foregroundStyle(Theme.purple)
            Text(posture.text)
                .font(.callout)
                .foregroundStyle(.secondary)
            if let label = policy.label {
                Text("policy \(label)")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }
            Text("This sandbox's egress is set by a bound control-plane policy and can't be edited locally.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: helpers

    private var modeHint: String {
        switch mode {
        case .open:
            return "Unrestricted outbound network — the guest can reach anything."
        case .noNetwork:
            return "Default-deny with nothing allowed — the guest is fully offline."
        case .allowList:
            return "Default-deny except the destinations below. A guest that dials a raw IP (skipping DNS) is denied too."
        }
    }

    private var posture: (text: String, color: Color) {
        switch policy.mode {
        case .open:
            return ("Active: unrestricted egress", Theme.cyan)
        case .noNetwork:
            return ("Active: no network", Theme.orange)
        case .allowList:
            return ("Active: \(policy.allow.count) destination\(policy.allow.count == 1 ? "" : "s") allowed", Theme.green)
        }
    }

    private var hasChanges: Bool {
        if mode != policy.mode { return true }
        if mode == .allowList { return Set(cleanRules) != Set(policy.allow) }
        return false
    }

    private var cleanRules: [String] {
        rules.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private func addRule() {
        let rule = newRule.trimmingCharacters(in: .whitespaces)
        guard !rule.isEmpty, !rules.contains(rule) else { return }
        rules.append(rule)
        newRule = ""
    }

    private func syncFromPolicy() {
        mode = policy.mode
        rules = policy.allow
    }
}

/// The guest console. Interactive: a resumed snapshot prints nothing until it is
/// typed at, so an output-only pane would make a perfectly healthy vanilla guest
/// look hung. Collapsed by default so the detail view stays focused.
private struct ConsoleExpander: View {
    @EnvironmentObject private var model: AppModel
    @State private var expanded = false
    @State private var input = ""
    @FocusState private var inputFocused: Bool

    private var canType: Bool { model.status.state == .running }

    var body: some View {
        GlassCard(title: "Console", subtitle: "serial console — type here", systemImage: "text.alignleft") {
            if model.hasInteractiveSession {
                Label("This sandbox is open in a Terminal session — work in that window. The in-app console pauses while you're connected.", systemImage: "terminal.fill")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                DisclosureGroup(isExpanded: $expanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 10) {
                            StatusPill(
                                text: model.isConsoleStreaming ? "Streaming live" : "Not streaming",
                                systemImage: model.isConsoleStreaming ? "dot.radiowaves.left.and.right" : "eye.fill",
                                color: model.isConsoleStreaming ? Theme.green : Theme.cyan
                            )
                            Button("Refresh") { model.attachConsole() }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            Spacer()
                        }
                        TerminalPane(
                            text: model.consoleDisplayText,
                            mode: .console(isStreaming: model.isConsoleStreaming)
                        )
                        .frame(minHeight: 260)

                        if model.consoleAwaitsFirstKeystroke {
                            Label(
                                "Silence is expected — a restored guest waits at its prompt. Press Return to wake it.",
                                systemImage: "info.circle"
                            )
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        }

                        inputRow
                    }
                    .padding(.top, 10)
                } label: {
                    Text(expanded ? "Hide console" : "Show console")
                        .font(.callout.weight(.semibold))
                }
            }
        }
    }

    private var inputRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                TextField(canType ? "Type a command, then Return" : "Start the sandbox to type", text: $input)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .focused($inputFocused)
                    .disabled(!canType)
                    .onSubmit(send)
                Button("Send", action: send)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(!canType)
            }
            HStack(spacing: 8) {
                ForEach(ConsoleKey.allCases) { key in
                    Button(key.label) { model.sendConsoleKey(key) }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(!canType)
                        .help(key.help)
                }
                Spacer()
            }
        }
    }

    private func send() {
        guard canType else { return }
        model.sendConsoleLine(input)
        input = ""
        inputFocused = true
    }
}

struct FailureBanner: View {
    let reason: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Sandbox stopped before it became interactive", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(Theme.orange)
            Text(shortReason)
                .font(.caption)
                .foregroundStyle(.primary)
                .lineLimit(6)
                .textSelection(.enabled)
            if reason.contains("ITS") || reason.contains("LPI") {
                Text("A vanilla ITS/LPI capture runs here on the userspace GICv3, so this is not a routing incompatibility. If CHM_ALLOW_ITS_LPI is set, unset it — it forces the capture onto the managed GIC, which cannot deliver LPI completions, so the guest stalls on its first I/O.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .background(Theme.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(Theme.orange.opacity(0.35), lineWidth: 1)
        }
    }

    private var shortReason: String {
        reason.replacingOccurrences(
            of: "Set CHM_ALLOW_ITS_LPI=1 to bypass this guard and run anyway (the guest will likely stall on first I/O).",
            with: ""
        )
        .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
private struct WorkspaceLocationCard: View {
    @EnvironmentObject private var model: AppModel
    let sandbox: Sandbox

    var body: some View {
        if let location = model.workspaceLocation(for: sandbox) {
            GlassCard(title: "Stored at", subtitle: "disk, overlays and revisions", systemImage: "externaldrive.fill") {
                Text(location.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)

                if location.outsideLibrary, let note = location.note, let remedy = location.remedy {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(note)
                                .font(.caption)
                                .foregroundStyle(.primary)
                                .fixedSize(horizontal: false, vertical: true)
                            Text(remedy)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 8)
                    }
                }
            }
        }
    }
}
