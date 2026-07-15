// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 260, ideal: 300, max: 360)
        } detail: {
            Detail()
        }
        .tint(Theme.cyan)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            EngineStatusBar()
        }
        .toolbar {
            ToolbarItemGroup {
                NewSandboxMenu()
                Button {
                    Task { await model.refreshAll() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isRefreshing)
            }
        }
    }
}

// MARK: - Sidebar

private struct Sidebar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Theme.sidebarBackground.ignoresSafeArea()

            List(selection: $model.selection) {
                Section {
                    BrandHeader()
                        .listRowInsets(EdgeInsets(top: 14, leading: 12, bottom: 16, trailing: 12))
                        .listRowBackground(Color.clear)
                }

                Section("Sandboxes") {
                    SidebarPageRow(
                        title: "All sandboxes",
                        systemImage: "shippingbox.fill",
                        count: model.sandboxes.count
                    )
                    .tag(SidebarItem.sandboxesHome)

                    ForEach(model.sandboxes) { sandbox in
                        SidebarSandboxRow(sandbox: sandbox)
                            .tag(SidebarItem.sandbox(sandbox.id))
                    }

                    NewSandboxMenu()
                        .padding(.vertical, 2)
                }

                Section("Snapshots") {
                    SidebarPageRow(
                        title: "All snapshots",
                        systemImage: "externaldrive.fill",
                        count: model.snapshots.count
                    )
                    .tag(SidebarItem.snapshotsHome)

                    ForEach(model.snapshots) { snapshot in
                        SidebarSnapshotRow(snapshot: snapshot)
                            .tag(SidebarItem.snapshot(snapshot.name))
                    }

                    if model.snapshots.isEmpty {
                        Text("No images in the library yet.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Section("Cloud") {
                    SidebarPageRow(
                        title: "Cloud snapshots",
                        systemImage: "cloud.fill",
                        count: model.cloudSnapshots.count
                    )
                    .tag(SidebarItem.cloudHome)

                    if case .offline = model.cloud.state {
                        Text("Control plane offline.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .navigationTitle("Gimbal")
        }
    }
}

private struct BrandHeader: View {
    var body: some View {
        HStack(spacing: 12) {
            AppIconView(size: 46)
            VStack(alignment: .leading, spacing: 2) {
                Text("Gimbal Local")
                    .font(.system(size: 20, weight: .heavy, design: .rounded))
                Text("Sandboxes on your Mac")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct SidebarPageRow: View {
    let title: String
    let systemImage: String
    let count: Int

    var body: some View {
        Label {
            HStack {
                Text(title).font(.headline)
                Spacer()
                Text("\(count)")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
            }
        } icon: {
            Image(systemName: systemImage).foregroundStyle(Theme.cyan)
        }
        .padding(.vertical, 3)
    }
}

private struct SidebarSandboxRow: View {
    let sandbox: Sandbox

    var body: some View {
        HStack(spacing: 10) {
            StatusDot(color: Theme.color(for: sandbox.state), size: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(sandbox.name)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text(sandbox.snapshotName)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            Image(systemName: sandbox.location.symbol)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.leading, 6)
        .padding(.vertical, 2)
    }
}

private struct SidebarSnapshotRow: View {
    let snapshot: SnapshotSummary

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "cube.transparent")
                .foregroundStyle(Theme.cyan.opacity(0.85))
            VStack(alignment: .leading, spacing: 2) {
                Text(snapshot.name)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text("\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.leading, 6)
        .padding(.vertical, 2)
    }
}

// MARK: - Detail router

private struct Detail: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Theme.dashboardBackground.ignoresSafeArea()

            switch model.selection ?? .sandboxesHome {
            case .sandboxesHome:
                SandboxesPage()
            case .snapshotsHome:
                SnapshotsPage()
            case .cloudHome:
                CloudSnapshotsPage()
            case let .sandbox(id):
                SandboxDetailPage(sandboxID: id)
            case let .snapshot(name):
                SnapshotDetailPage(snapshotName: name)
            }
        }
        .task {
            while !Task.isCancelled {
                // Reconcile the session registry (detect ended sessions, reap
                // dead locks, keep liveness authoritative) every tick, even when
                // the daemon isn't running.
                model.reconcileSessions()
                if model.status.state == .running {
                    await model.refreshLocal()
                }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
}

// MARK: - Bottom engine + control-plane bar

private struct EngineStatusBar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        let engine = model.engineIndicator
        HStack(spacing: 10) {
            StatusDot(color: Theme.color(for: engine.tone))
            Text(engine.label)
                .font(.caption.weight(.semibold))
            Text(engine.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer(minLength: 12)

            if model.isRefreshing {
                ProgressView().controlSize(.small).padding(.trailing, 2)
            }

            HStack(spacing: 6) {
                StatusDot(color: cloudColor, size: 7)
                Text(cloudLabel)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            SettingsLink {
                Image(systemName: "slider.horizontal.3")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Settings")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    private var cloudLabel: String {
        switch model.cloud.state {
        case .online: return "Control plane online"
        case .offline: return "Control plane optional"
        }
    }

    private var cloudColor: Color {
        switch model.cloud.state {
        case .online: return Theme.green
        case .offline: return Theme.purple
        }
    }
}

// MARK: - Shared page chrome

struct PageHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 30, weight: .heavy, design: .rounded))
                    .foregroundStyle(.white)
                Text(subtitle)
                    .font(.title3)
                    .foregroundStyle(.white.opacity(0.7))
            }
            Spacer()
            trailing
        }
    }
}
