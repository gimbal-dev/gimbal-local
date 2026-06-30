// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            EngineSettingsTab()
                .tabItem { Label("Engine", systemImage: "cpu") }
            PathsSettingsTab()
                .tabItem { Label("Runtime", systemImage: "folder") }
        }
        .frame(width: 500, height: 380)
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
                PathField(label: "Socket", text: $model.settings.socketPath, prompt: "/tmp/chm.sock")
            }

            Section("Control plane") {
                PathField(
                    label: "Control plane URL",
                    text: $model.settings.controlPlaneURL,
                    prompt: "http://127.0.0.1:8080"
                )
            }

            Section {
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Apply & refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)
            } footer: {
                Text("These point the app at the local runtime and the optional control plane.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
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
