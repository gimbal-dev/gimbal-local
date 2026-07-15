// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            EngineSettingsTab()
                .tabItem { Label("Engine", systemImage: "cpu") }
            DefaultsSettingsTab()
                .tabItem { Label("Defaults", systemImage: "slider.horizontal.3") }
            PathsSettingsTab()
                .tabItem { Label("Runtime", systemImage: "folder") }
            ControlPlaneSettingsTab()
                .tabItem { Label("Control plane", systemImage: "cloud") }
        }
        .frame(width: 520, height: 440)
    }
}

/// Global default controls (limits + firewall) applied to every new sandbox.
private struct DefaultsSettingsTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("Resource limits") {
                Toggle("Apply default limits to new sandboxes", isOn: $model.globalDefaults.limits.enabled)
                Text("Sane guard rails so a runaway guest can't exhaust the host. Per-sandbox limits (if set) always win.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                OptionalIntRow(label: "Max disk overlay", unit: "MiB", value: $model.globalDefaults.limits.maxDiskMb)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max console output", unit: "MiB", value: $model.globalDefaults.limits.maxConsoleMb)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max wall-clock", unit: "sec", value: $model.globalDefaults.limits.maxWallSeconds)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max vCPUs", unit: "", value: $model.globalDefaults.limits.maxVcpus)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max memory", unit: "MiB", value: $model.globalDefaults.limits.maxMemoryMb)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max connections", unit: "", value: $model.globalDefaults.limits.maxConnections)
                    .disabled(!model.globalDefaults.limits.enabled)
                OptionalIntRow(label: "Max bandwidth", unit: "kbps", value: $model.globalDefaults.limits.maxBandwidthKbps)
                    .disabled(!model.globalDefaults.limits.enabled)
            }

            Section("Connectivity") {
                Toggle("Apply default firewall to new sandboxes", isOn: $model.globalDefaults.firewall.enabled)
                Picker("Default egress", selection: $model.globalDefaults.firewall.mode) {
                    Text("Open (unrestricted)").tag(DefaultEgressMode.open)
                    Text("No network").tag(DefaultEgressMode.noNetwork)
                    Text("Allow-list").tag(DefaultEgressMode.allowlist)
                }
                .disabled(!model.globalDefaults.firewall.enabled)

                if model.globalDefaults.firewall.mode == .allowlist {
                    AllowListEditor(rules: $model.globalDefaults.firewall.allow)
                        .disabled(!model.globalDefaults.firewall.enabled)
                }
                Text("Applied only to new sandboxes; a sandbox's own Connectivity setting overrides it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .onChange(of: model.globalDefaults) { _, _ in model.saveGlobalDefaults() }
    }
}

/// A labelled optional-integer field: a checkbox enables the limit, a text field
/// holds its value. Unchecked means "no limit on this axis" (nil).
private struct OptionalIntRow: View {
    let label: String
    let unit: String
    @Binding var value: Int?

    var body: some View {
        HStack {
            Toggle(isOn: Binding(
                get: { value != nil },
                set: { on in value = on ? (value ?? 0) : nil }
            )) {
                Text(label)
            }
            .toggleStyle(.checkbox)
            Spacer()
            if value != nil {
                TextField("", value: Binding(
                    get: { value ?? 0 },
                    set: { value = max(0, $0) }
                ), format: .number)
                .frame(width: 80)
                .multilineTextAlignment(.trailing)
                .textFieldStyle(.roundedBorder)
                if !unit.isEmpty {
                    Text(unit).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// A simple editable list of `host[:port]` allow rules.
private struct AllowListEditor: View {
    @Binding var rules: [String]
    @State private var draft = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(rules.enumerated()), id: \.offset) { index, rule in
                HStack {
                    Text(rule).font(.callout.monospaced())
                    Spacer()
                    Button(role: .destructive) {
                        rules.remove(at: index)
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                }
            }
            HStack {
                TextField("host:port (e.g. github.com:443)", text: $draft)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    let trimmed = draft.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty, !rules.contains(trimmed) {
                        rules.append(trimmed)
                    }
                    draft = ""
                }
                .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}

private struct EngineSettingsTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("Status") {
                LabeledContent("Engine") {
                    HStack(spacing: 8) {
                        StatusDot(color: Theme.color(for: model.engineIndicator.tone))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(model.engineIndicator.label)
                            Text(model.engineIndicator.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                if let pid = model.daemonPID {
                    LabeledContent("Managed process", value: "pid \(pid)")
                }
            }

            Section("Lifecycle") {
                HStack(spacing: 10) {
                    Button {
                        model.startDaemon()
                    } label: {
                        Label("Start", systemImage: "play.fill")
                    }

                    Button {
                        model.restartDaemon()
                    } label: {
                        Label("Restart", systemImage: "arrow.clockwise")
                    }

                    Button(role: .destructive) {
                        model.shutdownDaemon()
                    } label: {
                        Label("Shut down", systemImage: "stop.fill")
                    }
                }

                Text("Restart gracefully shuts down chm serve and starts a fresh managed instance — use it if the engine becomes unresponsive.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }
}

private struct PathsSettingsTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("Runtime paths") {
                PathField(label: "chm binary", text: $model.settings.chmPath, prompt: "target/debug/chm")
                PathField(label: "Snapshot library", text: $model.settings.libraryPath, prompt: "snapshots")
                PathField(label: "Socket", text: $model.settings.socketPath, prompt: "/tmp/gimbal-local/chm.sock")
            }

            Section {
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Apply & refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)
            } footer: {
                Text("These point the app at the local runtime.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

private struct ControlPlaneSettingsTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("Connection") {
                PathField(
                    label: "Control plane URL",
                    text: $model.settings.controlPlaneURL,
                    prompt: "http://127.0.0.1:8080"
                )
                LabeledContent("Status") {
                    HStack(spacing: 8) {
                        StatusDot(color: cloudColor)
                        Text(cloudLabel)
                    }
                }
            }

            Section("Overview") {
                LabeledContent("Runners", value: count(model.cloud.runners))
                LabeledContent("Snapshots", value: count(model.cloud.snapshots))
                LabeledContent("Sandboxes", value: count(model.cloud.sandboxes))
                LabeledContent("Cost", value: model.cloud.costSummary ?? "—")
            }

            Section {
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)
            } footer: {
                Text("The control plane (gimbal-cloud-control) is optional. When connected it powers remote sandboxes and cost signals; the local engine works without it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func count(_ value: Int?) -> String {
        value.map(String.init) ?? "—"
    }

    private var cloudLabel: String {
        switch model.cloud.state {
        case .online: return "Online"
        case let .offline(reason): return "Offline — \(reason)"
        }
    }

    private var cloudColor: Color {
        switch model.cloud.state {
        case .online: return Theme.green
        case .offline: return Theme.purple
        }
    }
}

private struct PathField: View {
    let label: String
    @Binding var text: String
    let prompt: String

    var body: some View {
        TextField(label, text: $text, prompt: Text(prompt))
            .font(.system(.body, design: .monospaced))
            .textFieldStyle(.roundedBorder)
    }
}
