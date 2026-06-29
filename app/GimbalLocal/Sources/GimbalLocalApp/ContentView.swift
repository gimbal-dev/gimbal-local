// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationSplitView {
            Sidebar()
        } detail: {
            Dashboard()
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)

                Button {
                    model.startDaemon()
                } label: {
                    Label("Start Daemon", systemImage: "play.circle")
                }

                Button(role: .destructive) {
                    model.stopSandbox()
                } label: {
                    Label("Stop Sandbox", systemImage: "stop.circle")
                }
            }
        }
    }
}

private struct Sidebar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        List(selection: $model.selectedSnapshot) {
            Section("Local sandboxes") {
                ForEach(model.snapshots) { snapshot in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(snapshot.name)
                            .font(.headline)
                        Text("\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .tag(Optional(snapshot))
                }
                if model.snapshots.isEmpty {
                    Text("No snapshots loaded")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Settings") {
                SettingsFields()
            }
        }
        .navigationTitle("Gimbal Local")
    }
}

private struct SettingsFields: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledContent("chm") {
                TextField("target/debug/chm", text: $model.settings.chmPath)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledContent("Library") {
                TextField("snapshots", text: $model.settings.libraryPath)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledContent("Socket") {
                TextField("/tmp/chm.sock", text: $model.settings.socketPath)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledContent("Control plane") {
                TextField("http://127.0.0.1:8080", text: $model.settings.controlPlaneURL)
                    .textFieldStyle(.roundedBorder)
            }
        }
        .font(.caption)
    }
}

private struct Dashboard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Header()

                HStack(alignment: .top, spacing: 16) {
                    RuntimeCard()
                    CloudCard()
                }

                HStack(alignment: .top, spacing: 16) {
                    SandboxCard()
                    SnapshotCard()
                }

                ConsoleCard()
                ActivityCard()
            }
            .padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct Header: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Local cloud sandboxes")
                .font(.largeTitle.bold())
            Text("A Docker Desktop-style control surface for Cloud Hypervisor snapshots rehydrated on Apple HVF.")
                .foregroundStyle(.secondary)
        }
    }
}

private struct RuntimeCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Local runtime", systemImage: "desktopcomputer") {
            MetricRow(label: "Daemon", value: daemonState)
            MetricRow(label: "Socket", value: model.settings.socketPath)
            MetricRow(label: "Library", value: model.settings.libraryPath)

            HStack {
                Button("Start daemon") {
                    model.startDaemon()
                }
                Button("Shutdown daemon", role: .destructive) {
                    model.shutdownDaemon()
                }
            }
        }
    }

    private var daemonState: String {
        if let pid = model.daemonPID {
            return "managed by app (pid \(pid))"
        }
        switch model.status.state {
        case .disconnected:
            return "not reachable"
        default:
            return "reachable"
        }
    }
}

private struct CloudCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Cloud control plane", systemImage: "cloud") {
            switch model.cloud.state {
            case .online:
                MetricRow(label: "API", value: "online")
            case let .offline(reason):
                MetricRow(label: "API", value: "offline — \(reason)")
            }
            MetricRow(label: "Runners", value: display(model.cloud.runners))
            MetricRow(label: "Snapshots", value: display(model.cloud.snapshots))
            MetricRow(label: "Sandboxes", value: display(model.cloud.sandboxes))
            MetricRow(label: "Cost", value: model.cloud.costSummary ?? "not available")
        }
    }

    private func display(_ value: Int?) -> String {
        value.map(String.init) ?? "not available"
    }
}

private struct SandboxCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Running sandbox", systemImage: "shippingbox") {
            MetricRow(label: "State", value: model.status.state.rawValue)
            MetricRow(label: "Name", value: model.status.name ?? "none")
            MetricRow(label: "Uptime", value: uptime)
            MetricRow(label: "Console", value: consoleBytes)
            if let reason = model.status.reason {
                MetricRow(label: "Reason", value: reason)
            }

            HStack {
                Button("Attach console") {
                    model.attachConsole()
                }
                Button("Stop", role: .destructive) {
                    model.stopSandbox()
                }
            }
        }
    }

    private var uptime: String {
        guard let seconds = model.status.uptimeSeconds else { return "not running" }
        return "\(seconds)s"
    }

    private var consoleBytes: String {
        guard let bytes = model.status.consoleBytes else { return "0 bytes" }
        return "\(bytes) bytes"
    }
}

private struct SnapshotCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Selected snapshot", systemImage: "externaldrive") {
            if let snapshot = model.selectedSnapshot {
                MetricRow(label: "Name", value: snapshot.name)
                MetricRow(label: "Path", value: snapshot.path)
                MetricRow(label: "Shape", value: "\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB")
                Button("Start local sandbox") {
                    model.startSelectedSnapshot()
                }
                .buttonStyle(.borderedProminent)
            } else {
                Text("Select a snapshot from the sidebar.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct ConsoleCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Console", systemImage: "terminal") {
            ScrollView {
                Text(model.consoleText.isEmpty ? "Console output will appear here after attach/start." : model.consoleText)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(12)
            }
            .frame(minHeight: 220)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }
}

private struct ActivityCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Activity", systemImage: "list.bullet.rectangle") {
            ScrollView {
                Text(model.activityLog.isEmpty ? "No app activity yet." : model.activityLog)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(12)
            }
            .frame(minHeight: 120)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }
}

private struct Card<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: systemImage)
                .font(.title3.bold())
            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }
}

private struct MetricRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 96, alignment: .leading)
            Text(value)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
        }
    }
}
