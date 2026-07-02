// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "shippingbox")
                .font(.system(size: 52))
                .foregroundStyle(Theme.cyan)
            Text("No sandboxes yet")
                .font(.title2.weight(.bold))
            Text(model.snapshots.isEmpty
                 ? "Add snapshot images to your library, then create a sandbox from one."
                 : "Create your first sandbox from a snapshot image to get started.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)

            NewSandboxMenu(prominent: true)
                .disabled(model.snapshots.isEmpty)

            if model.snapshots.isEmpty {
                Button("Browse snapshots") { model.selection = .snapshotsHome }
                    .buttonStyle(.bordered)
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

            HStack(spacing: 10) {
                Button {
                    model.startSandbox(sandbox)
                } label: {
                    Label(sandbox.state == .starting ? "Starting…" : "Start", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(isLive)

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

    private func uptime(_ sandbox: Sandbox) -> String {
        guard let seconds = sandbox.uptimeSeconds else { return "—" }
        return "\(seconds)s"
    }

    private func consoleBytes(_ sandbox: Sandbox) -> String {
        guard let bytes = sandbox.consoleBytes else { return "0 B" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

/// The read-only console, intentionally secondary: collapsed by default so the
/// detail view stays focused on working *inside* the sandbox rather than just
/// watching it.
private struct ConsoleExpander: View {
    @EnvironmentObject private var model: AppModel
    @State private var expanded = false

    var body: some View {
        GlassCard(title: "Console output", subtitle: "read-only serial stream", systemImage: "text.alignleft") {
            if model.hasInteractiveSession {
                Label("This sandbox is open in a Terminal session — work in that window. The read-only stream pauses while you're connected.", systemImage: "terminal.fill")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                DisclosureGroup(isExpanded: $expanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 10) {
                            StatusPill(
                                text: model.isConsoleStreaming ? "Streaming live" : "Read-only output",
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
                    }
                    .padding(.top, 10)
                } label: {
                    Text(expanded ? "Hide console" : "Show console")
                        .font(.callout.weight(.semibold))
                }
            }
        }
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
                Text("This is a snapshot compatibility issue, not a UI/console issue. Re-capture with GICv2M/message-SPI routing before it can run locally.")
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
