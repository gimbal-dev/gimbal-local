// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 280, ideal: 320, max: 380)
        } detail: {
            Dashboard()
        }
        .tint(Theme.cyan)
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)

                Button(role: .destructive) {
                    model.stopSandbox()
                } label: {
                    Label("Stop Sandbox", systemImage: "stop.circle.fill")
                }
            }
        }
    }
}

private struct Sidebar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Theme.sidebarBackground
                .ignoresSafeArea()

            List(selection: $model.selectedSnapshot) {
                Section {
                    BrandHeader()
                        .listRowInsets(EdgeInsets(top: 16, leading: 12, bottom: 18, trailing: 12))
                        .listRowBackground(Color.clear)
                }

                Section {
                    CreateSandboxButton()
                }

                Section("Sandboxes") {
                    ForEach(model.snapshots) { snapshot in
                        SnapshotRow(snapshot: snapshot)
                            .tag(Optional(snapshot))
                    }
                    if model.snapshots.isEmpty {
                        EmptySidebarState()
                    }
                }

                Section("System health") {
                    CompactStatusRow(title: "Local engine", subtitle: localDaemonSubtitle, systemImage: "heart.fill", color: localDaemonColor)
                    CompactStatusRow(title: "Control plane", subtitle: cloudSubtitle, systemImage: "cloud.fill", color: cloudColor)
                }

                Section("Advanced") {
                    DisclosureGroup("Runtime paths") {
                        SettingsFields()
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .navigationTitle("Gimbal")
        }
    }

    private var localDaemonSubtitle: String {
        switch model.status.state {
        case .disconnected:
            return "not reachable"
        case .idle:
            return "ready"
        case .running:
            return "sandbox running"
        case .stopped:
            return "last sandbox stopped"
        case .unknown:
            return "unknown"
        }
    }

    private var localDaemonColor: Color {
        switch model.status.state {
        case .running:
            return Theme.green
        case .idle, .stopped:
            return Theme.cyan
        case .disconnected, .unknown:
            return Theme.orange
        }
    }

    private var cloudSubtitle: String {
        switch model.cloud.state {
        case .online:
            return "gctl online"
        case .offline:
            return "optional"
        }
    }

    private var cloudColor: Color {
        switch model.cloud.state {
        case .online:
            return Theme.green
        case .offline:
            return Theme.purple
        }
    }
}

private struct CreateSandboxButton: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
            } label: {
                Label("Create from container image", systemImage: "plus.circle.fill")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.borderedProminent)
            .disabled(true)

            Text("Coming soon: pull an OCI image, build a VM snapshot behind the scenes, then run it here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 6)
    }
}

private struct BrandHeader: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Theme.logoGradient)
                    .frame(width: 56, height: 56)
                    .shadow(color: Theme.cyan.opacity(0.45), radius: 18, y: 8)
                Image(systemName: "sparkles")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Gimbal Local")
                    .font(.system(size: 27, weight: .heavy, design: .rounded))
                Text("Cloud sandboxes, rehydrated on your Mac.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct SnapshotRow: View {
    let snapshot: SnapshotSummary

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Theme.blueprintGradient)
                    .frame(width: 42, height: 42)
                Image(systemName: "cube.transparent")
                    .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(snapshot.name)
                    .font(.headline)
                    .lineLimit(1)
                Text("\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 5)
    }
}

private struct EmptySidebarState: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("No snapshots yet", systemImage: "tray")
                .font(.headline)
            Text("Point the library at a folder of ch-snapshot directories.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Container-image creation is planned; for now sandboxes are imported snapshots.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 8)
    }
}

private struct CompactStatusRow: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let color: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct SettingsFields: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            PrettyTextField(title: "chm", text: $model.settings.chmPath, placeholder: "target/debug/chm")
            PrettyTextField(title: "Library", text: $model.settings.libraryPath, placeholder: "snapshots")
            PrettyTextField(title: "Socket", text: $model.settings.socketPath, placeholder: "/tmp/chm.sock")
            PrettyTextField(
                title: "Control plane",
                text: $model.settings.controlPlaneURL,
                placeholder: "http://127.0.0.1:8080"
            )
        }
        .padding(.vertical, 4)
    }
}

private struct PrettyTextField: View {
    let title: String
    @Binding var text: String
    let placeholder: String

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(.secondary)
            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .font(.system(.caption, design: .monospaced))
                .padding(8)
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        }
    }
}

private struct Dashboard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Theme.dashboardBackground
                .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Hero()
                    HealthStrip()

                    HStack(alignment: .top, spacing: 16) {
                        SnapshotCard()
                        SandboxCard()
                    }

                    ConsoleCard()
                    CloudCard()
                    ActivityCard()
                }
                .padding(28)
            }
        }
    }
}

private struct Hero: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack(alignment: .bottomLeading) {
            RoundedRectangle(cornerRadius: 30, style: .continuous)
                .fill(Theme.heroGradient)
                .overlay(alignment: .topTrailing) {
                    OrbitalBadge()
                        .padding(28)
                }
                .overlay {
                    GeometryReader { proxy in
                        Path { path in
                            let w = proxy.size.width
                            let h = proxy.size.height
                            path.move(to: CGPoint(x: w * 0.05, y: h * 0.75))
                            path.addCurve(
                                to: CGPoint(x: w * 0.95, y: h * 0.32),
                                control1: CGPoint(x: w * 0.32, y: h * 0.12),
                                control2: CGPoint(x: w * 0.64, y: h * 0.96)
                            )
                        }
                        .stroke(.white.opacity(0.20), style: StrokeStyle(lineWidth: 1.3, dash: [8, 8]))
                    }
                }
                .shadow(color: Theme.cyan.opacity(0.18), radius: 34, y: 18)

            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 10) {
                    StatusPill(
                        text: model.status.state == .running ? "Sandbox live" : "Local-first runtime",
                        systemImage: model.status.state == .running ? "dot.radiowaves.left.and.right" : "cpu",
                        color: model.status.state == .running ? Theme.green : Theme.cyan
                    )
                    StatusPill(
                        text: cloudPillText,
                        systemImage: "cloud",
                        color: cloudPillColor
                    )
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Create and run local sandboxes.")
                        .font(.system(size: 42, weight: .black, design: .rounded))
                        .foregroundStyle(.white)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Pick a sandbox, start it, and watch the guest console. The local engine starts itself; container-image creation will hide the snapshot factory behind one button.")
                        .font(.title3)
                        .foregroundStyle(.white.opacity(0.78))
                        .frame(maxWidth: 760, alignment: .leading)
                }

                HStack(spacing: 12) {
                    Button {
                        model.startSelectedSnapshot()
                    } label: {
                        Label("Start selected sandbox", systemImage: "play.fill")
                            .font(.headline)
                            .padding(.horizontal, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(model.selectedSnapshot == nil)

                    Button {
                    } label: {
                        Label("Create from image", systemImage: "plus")
                            .font(.headline)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(true)
                }
            }
            .padding(34)
        }
        .frame(minHeight: 320)
    }

    private var cloudPillText: String {
        switch model.cloud.state {
        case .online:
            return "Control plane online"
        case .offline:
            return "Control plane optional"
        }
    }

    private var cloudPillColor: Color {
        switch model.cloud.state {
        case .online:
            return Theme.green
        case .offline:
            return Theme.purple
        }
    }
}

private struct HealthStrip: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(spacing: 12) {
            HealthPill(title: "Local engine", detail: localDetail, color: localColor, systemImage: "cpu")
            HealthPill(title: "Library", detail: "\(model.snapshots.count) sandbox\(model.snapshots.count == 1 ? "" : "es")", color: Theme.cyan, systemImage: "square.stack.3d.up")
            HealthPill(title: "Control plane", detail: cloudDetail, color: cloudColor, systemImage: "cloud")
            Spacer()
        }
    }

    private var localDetail: String {
        switch model.status.state {
        case .disconnected:
            return "starting or offline"
        case .running:
            return "sandbox running"
        case .idle, .stopped:
            return "ready"
        case .unknown:
            return "unknown"
        }
    }

    private var localColor: Color {
        model.status.state == .disconnected ? Theme.orange : Theme.green
    }

    private var cloudDetail: String {
        switch model.cloud.state {
        case .online:
            return "online"
        case .offline:
            return "optional"
        }
    }

    private var cloudColor: Color {
        switch model.cloud.state {
        case .online:
            return Theme.green
        case .offline:
            return Theme.purple
        }
    }
}

private struct HealthPill: View {
    let title: String
    let detail: String
    let color: Color
    let systemImage: String

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: systemImage)
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.caption.weight(.bold))
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 9)
        .background(.ultraThinMaterial, in: Capsule())
    }
}

private struct OrbitalBadge: View {
    var body: some View {
        ZStack {
            Circle()
                .stroke(.white.opacity(0.18), lineWidth: 1)
                .frame(width: 156, height: 156)
            Circle()
                .stroke(.white.opacity(0.13), lineWidth: 1)
                .frame(width: 104, height: 104)
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.white.opacity(0.13))
                .frame(width: 88, height: 88)
                .overlay {
                    Image(systemName: "server.rack")
                        .font(.system(size: 42, weight: .semibold))
                        .foregroundStyle(.white)
                }
            Circle()
                .fill(Theme.green)
                .frame(width: 15, height: 15)
                .offset(x: 58, y: -46)
            Circle()
                .fill(Theme.cyan)
                .frame(width: 11, height: 11)
                .offset(x: -62, y: 42)
        }
    }
}

private struct RuntimeCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Local runtime", subtitle: "chm serve", systemImage: "desktopcomputer") {
            HStack(spacing: 12) {
                BigMetric(title: "Daemon", value: daemonBadge, color: daemonColor)
                BigMetric(title: "Snapshots", value: "\(model.snapshots.count)", color: Theme.cyan)
            }

            Divider().opacity(0.35)

            MetricRow(label: "Socket", value: model.settings.socketPath)
            MetricRow(label: "Library", value: model.settings.libraryPath)

            HStack {
                Button("Start") {
                    model.startDaemon()
                }
                .buttonStyle(.borderedProminent)

                Button("Shutdown", role: .destructive) {
                    model.shutdownDaemon()
                }
                .buttonStyle(.bordered)
            }
            .padding(.top, 4)
        }
    }

    private var daemonBadge: String {
        if model.daemonPID != nil {
            return "Managed"
        }
        return model.status.state == .disconnected ? "Offline" : "Online"
    }

    private var daemonColor: Color {
        model.status.state == .disconnected ? Theme.orange : Theme.green
    }
}

private struct CloudCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Control plane", subtitle: "gimbal-cloud-control", systemImage: "cloud.fill") {
            HStack(spacing: 12) {
                BigMetric(title: "API", value: apiState, color: apiColor)
                BigMetric(title: "Cost", value: costValue, color: Theme.purple)
            }

            Divider().opacity(0.35)

            HStack(spacing: 10) {
                CountChip(title: "Runners", value: model.cloud.runners)
                CountChip(title: "Snapshots", value: model.cloud.snapshots)
                CountChip(title: "Sandboxes", value: model.cloud.sandboxes)
            }

            Text(cloudDetail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var apiState: String {
        switch model.cloud.state {
        case .online:
            return "Online"
        case .offline:
            return "Optional"
        }
    }

    private var apiColor: Color {
        switch model.cloud.state {
        case .online:
            return Theme.green
        case .offline:
            return Theme.purple
        }
    }

    private var costValue: String {
        model.cloud.costSummary == nil ? "—" : "Ready"
    }

    private var cloudDetail: String {
        switch model.cloud.state {
        case .online:
            return model.cloud.costSummary ?? "Control plane is reachable. Cost view did not return a summary yet."
        case let .offline(reason):
            return "Offline for now: \(reason)"
        }
    }
}

private struct SandboxCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Sandbox state", subtitle: "local HVF guest", systemImage: "shippingbox.fill") {
            HStack(spacing: 12) {
                BigMetric(title: "State", value: model.status.state.rawValue.capitalized, color: statusColor)
                BigMetric(title: "Console", value: consoleBytes, color: Theme.cyan)
            }

            Divider().opacity(0.35)

            if model.status.state == .stopped, let reason = model.status.reason {
                FailureBanner(reason: reason)
            }

            MetricRow(label: "Name", value: model.status.name ?? "none")
            MetricRow(label: "Uptime", value: uptime)

            HStack {
                Button("Attach console") {
                    model.attachConsole()
                }
                .buttonStyle(.bordered)

                Button("Stop", role: .destructive) {
                    model.stopSandbox()
                }
                .buttonStyle(.bordered)
            }
            .padding(.top, 4)
        }
    }

    private var statusColor: Color {
        switch model.status.state {
        case .running:
            return Theme.green
        case .idle, .stopped:
            return Theme.cyan
        case .disconnected, .unknown:
            return Theme.orange
        }
    }

    private var uptime: String {
        guard let seconds = model.status.uptimeSeconds else { return "not running" }
        return "\(seconds)s"
    }

    private var consoleBytes: String {
        guard let bytes = model.status.consoleBytes else { return "0 B" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

private struct SnapshotCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Selected sandbox", subtitle: "snapshot-backed", systemImage: "externaldrive.fill") {
            if let snapshot = model.selectedSnapshot {
                HStack(spacing: 12) {
                    BigMetric(title: "vCPU", value: "\(snapshot.vcpus)", color: Theme.cyan)
                    BigMetric(title: "Memory", value: "\(snapshot.ramMib) MiB", color: Theme.purple)
                }

                Divider().opacity(0.35)

                MetricRow(label: "Name", value: snapshot.name)
                MetricRow(label: "Path", value: snapshot.path)

                Text("This sandbox starts from a Cloud Hypervisor snapshot. Container-image creation will generate one of these behind the scenes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Button {
                    model.startSelectedSnapshot()
                } label: {
                    Label("Start sandbox", systemImage: "play.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 4)
            } else {
                EmptySelection()
            }
        }
    }
}

private struct EmptySelection: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "arrow.left.circle")
                .font(.system(size: 44))
                .foregroundStyle(Theme.cyan)
            Text("Select a snapshot from the sidebar.")
                .font(.headline)
            Text("When the library is populated, this panel becomes your launch pad.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 170)
    }
}

private struct ConsoleCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Live console", subtitle: "guest serial output", systemImage: "terminal.fill") {
            TerminalPane(text: model.consoleDisplayText)
                .frame(minHeight: 270)
        }
    }
}

private struct FailureBanner: View {
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
        reason.replacingOccurrences(of: "Set CHM_ALLOW_ITS_LPI=1 to bypass this guard and run anyway (the guest will likely stall on first I/O).", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct ActivityCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(title: "Activity", subtitle: "local orchestration log", systemImage: "waveform.path.ecg.rectangle.fill") {
            TerminalPane(text: model.activityLog.isEmpty ? "No app activity yet." : model.activityLog, compact: true)
                .frame(minHeight: 130)
        }
    }
}

private struct GlassCard<Content: View>: View {
    let title: String
    let subtitle: String
    let systemImage: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Theme.iconGradient)
                        .frame(width: 42, height: 42)
                    Image(systemName: systemImage)
                        .foregroundStyle(.white)
                        .font(.system(size: 18, weight: .bold))
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.title3.bold())
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay {
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(.white.opacity(0.14), lineWidth: 1)
                }
        }
        .shadow(color: .black.opacity(0.11), radius: 24, y: 14)
    }
}

private struct BigMetric: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .black))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 22, weight: .heavy, design: .rounded))
                .foregroundStyle(color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private struct CountChip: View {
    let title: String
    let value: Int?

    var body: some View {
        VStack(spacing: 2) {
            Text(value.map(String.init) ?? "—")
                .font(.system(size: 18, weight: .heavy, design: .rounded))
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct StatusPill: View {
    let text: String
    let systemImage: String
    let color: Color

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.system(.caption, design: .rounded).weight(.bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(color.opacity(0.28), in: Capsule())
            .overlay {
                Capsule()
                    .stroke(.white.opacity(0.20), lineWidth: 1)
            }
    }
}

private struct TerminalPane: View {
    let text: String
    var compact = false

    var body: some View {
        ScrollView {
            Text(text)
                .font(.system(compact ? .caption : .body, design: .monospaced))
                .foregroundStyle(text == placeholder ? .secondary : Theme.terminalText)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding(16)
        }
        .background {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Theme.terminalBackground)
                .overlay(alignment: .topLeading) {
                    HStack(spacing: 6) {
                        Circle().fill(Color(red: 1.0, green: 0.37, blue: 0.32)).frame(width: 10, height: 10)
                        Circle().fill(Color(red: 1.0, green: 0.78, blue: 0.27)).frame(width: 10, height: 10)
                        Circle().fill(Color(red: 0.20, green: 0.82, blue: 0.38)).frame(width: 10, height: 10)
                    }
                    .padding(13)
                }
        }
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var placeholder: String {
        compact ? "No app activity yet." : "Console output will appear here after attach/start."
    }
}

private struct MetricRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 86, alignment: .leading)
            Text(value)
                .font(.callout)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(2)
                .textSelection(.enabled)
        }
    }
}

private enum Theme {
    static let cyan = Color(red: 0.18, green: 0.78, blue: 0.96)
    static let green = Color(red: 0.25, green: 0.86, blue: 0.55)
    static let purple = Color(red: 0.62, green: 0.43, blue: 1.0)
    static let orange = Color(red: 1.0, green: 0.60, blue: 0.22)
    static let terminalText = Color(red: 0.74, green: 0.99, blue: 0.89)
    static let terminalBackground = Color(red: 0.02, green: 0.05, blue: 0.09)

    static let logoGradient = LinearGradient(
        colors: [cyan, purple],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let iconGradient = LinearGradient(
        colors: [cyan.opacity(0.95), purple.opacity(0.95)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let blueprintGradient = LinearGradient(
        colors: [Color(red: 0.12, green: 0.38, blue: 0.72), cyan],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let heroGradient = LinearGradient(
        colors: [
            Color(red: 0.04, green: 0.08, blue: 0.18),
            Color(red: 0.09, green: 0.18, blue: 0.38),
            Color(red: 0.24, green: 0.13, blue: 0.42),
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let sidebarBackground = LinearGradient(
        colors: [
            Color(nsColor: .controlBackgroundColor),
            Color(nsColor: .windowBackgroundColor),
        ],
        startPoint: .top,
        endPoint: .bottom
    )
    static var dashboardBackground: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.055, green: 0.075, blue: 0.12),
                    Color(red: 0.085, green: 0.105, blue: 0.17),
                    Color(nsColor: .windowBackgroundColor),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            Circle()
                .fill(cyan.opacity(0.18))
                .frame(width: 420, height: 420)
                .blur(radius: 90)
                .offset(x: -320, y: -260)
            Circle()
                .fill(purple.opacity(0.16))
                .frame(width: 520, height: 520)
                .blur(radius: 110)
                .offset(x: 420, y: -130)
        }
    }
}
