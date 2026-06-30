// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

// MARK: - Snapshots main page

struct SnapshotsPage: View {
    @EnvironmentObject private var model: AppModel

    private let columns = [GridItem(.adaptive(minimum: 320, maximum: 460), spacing: 16)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Snapshots",
                    subtitle: "Image templates you launch sandboxes from."
                ) {
                    Button {
                        Task { await model.refreshAll() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isRefreshing)
                }

                if model.snapshots.isEmpty {
                    SnapshotsEmptyState()
                } else {
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
                        ForEach(model.snapshots) { snapshot in
                            SnapshotCard(snapshot: snapshot)
                        }
                    }
                }
            }
            .padding(28)
        }
    }
}

private struct SnapshotsEmptyState: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "externaldrive.badge.questionmark")
                .font(.system(size: 50))
                .foregroundStyle(Theme.cyan)
            Text("No snapshot images")
                .font(.title2.weight(.bold))
            Text("Point the snapshot library at a folder of ch-snapshot directories. Each one becomes a launchable image here.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 440)
            Text(model.settings.libraryPath)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
            SettingsLink {
                Label("Open settings", systemImage: "slider.horizontal.3")
            }
            .buttonStyle(.bordered)
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

// MARK: - Snapshot card

private struct SnapshotCard: View {
    @EnvironmentObject private var model: AppModel
    let snapshot: SnapshotSummary

    private var derivedSandboxes: Int {
        model.sandboxes.filter { $0.snapshotName == snapshot.name }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Theme.blueprintGradient)
                        .frame(width: 40, height: 40)
                    Image(systemName: "cube.transparent").foregroundStyle(.white)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(snapshot.name).font(.headline).lineLimit(1)
                    Text("\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            if derivedSandboxes > 0 {
                Text("\(derivedSandboxes) sandbox\(derivedSandboxes == 1 ? "" : "es") created from this image")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            HStack(spacing: 10) {
                Button {
                    model.newSandbox(fromSnapshotNamed: snapshot.name)
                } label: {
                    Label("Launch sandbox", systemImage: "play.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Button {
                    model.selection = .snapshot(snapshot.name)
                } label: {
                    Image(systemName: "info.circle")
                }
                .buttonStyle(.bordered)
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
        .onTapGesture { model.selection = .snapshot(snapshot.name) }
    }
}

// MARK: - Snapshot detail

struct SnapshotDetailPage: View {
    @EnvironmentObject private var model: AppModel
    let snapshotName: String

    var body: some View {
        if let snapshot = model.snapshot(named: snapshotName) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    PageHeader(title: snapshot.name, subtitle: "snapshot image") {
                        Button {
                            model.newSandbox(fromSnapshotNamed: snapshot.name)
                        } label: {
                            Label("Launch sandbox", systemImage: "play.fill")
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }

                    GlassCard(title: "Image", subtitle: "Cloud Hypervisor snapshot", systemImage: "externaldrive.fill") {
                        HStack(spacing: 12) {
                            BigMetric(title: "vCPU", value: "\(snapshot.vcpus)", color: Theme.cyan)
                            BigMetric(title: "Memory", value: "\(snapshot.ramMib) MiB", color: Theme.purple)
                        }
                        Divider().opacity(0.35)
                        MetricRow(label: "Name", value: snapshot.name)
                        MetricRow(label: "Path", value: snapshot.path)
                    }

                    DerivedSandboxesCard(snapshotName: snapshot.name)
                }
                .padding(28)
            }
        } else {
            ContentUnavailableView(
                "Snapshot not found",
                systemImage: "externaldrive",
                description: Text("It may have left the library.")
            )
        }
    }
}

private struct DerivedSandboxesCard: View {
    @EnvironmentObject private var model: AppModel
    let snapshotName: String

    private var derived: [Sandbox] {
        model.sandboxes.filter { $0.snapshotName == snapshotName }
    }

    var body: some View {
        GlassCard(title: "Sandboxes", subtitle: "instances from this image", systemImage: "shippingbox.fill") {
            if derived.isEmpty {
                Text("No sandboxes yet. Launch one to run this image — you can launch several from the same image.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(derived) { sandbox in
                    HStack(spacing: 10) {
                        StatusDot(color: Theme.color(for: sandbox.state), size: 8)
                        Text(sandbox.name).font(.callout.weight(.medium))
                        SandboxStateBadge(state: sandbox.state)
                        Spacer()
                        Button("Open") { model.selection = .sandbox(sandbox.id) }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }
}
