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

                Section("Posture") {
                    SidebarSecurityRow(report: model.posture)
                        .tag(SidebarItem.securityHome)

                    SidebarProxyRow(config: model.proxyConfig)
                        .tag(SidebarItem.proxyHome)

                    SidebarActivityRow(trail: model.auditTrail)
                        .tag(SidebarItem.activityHome)

                    SidebarCapabilityRow(report: model.capabilities)
                        .tag(SidebarItem.capabilityHome)
                }

                if !model.localOnly {
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

/// Security in the sidebar, with the weakened count visible **without
/// navigating**. A count you have to go looking for is a count nobody reads;
/// the whole point of the panel is that a weakened control announces itself.
private struct SidebarSecurityRow: View {
    let report: PostureReport?

    var body: some View {
        Label {
            HStack {
                Text("Security").font(.headline)
                Spacer()
                badge
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder private var badge: some View {
        if let report {
            Text(report.weakened == 0 ? "OK" : "\(report.weakened)")
                .font(.caption.weight(.bold))
                .foregroundStyle(report.weakened == 0 ? .secondary : Color.white)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(
                    report.weakened == 0 ? AnyShapeStyle(.quaternary) : AnyShapeStyle(Theme.orange),
                    in: Capsule()
                )
        } else {
            Text("?")
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(.quaternary, in: Capsule())
        }
    }

    private var symbol: String {
        guard let report else { return "questionmark.shield.fill" }
        return report.weakened == 0 ? "checkmark.shield.fill" : "exclamationmark.shield.fill"
    }

    private var tint: Color {
        guard let report else { return .gray }
        return report.weakened == 0 ? Theme.green : Theme.orange
    }
}

/// The proxy in the sidebar. Shows the rule count, or a warning when a rule
/// cannot resolve its credential — that case sends requests out
/// *unauthenticated* rather than failing, which from inside the guest looks
/// like a broken API rather than a misconfigured proxy.
private struct SidebarProxyRow: View {
    let config: ProxyConfiguration?

    var body: some View {
        Label {
            HStack {
                Text("Credentials").font(.headline)
                Spacer()
                badge
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .padding(.vertical, 3)
    }

    /// Only counted when the **daemon** answered. Credential availability read
    /// from this app's own environment says nothing about the process that
    /// injects, and an alarm sourced from the wrong process is worse than no
    /// alarm: it trains the reader to ignore it.
    private var broken: Int {
        guard let config, config.isFromDaemon else { return 0 }
        return config.rulesMissingCredentials.count
    }

    @ViewBuilder private var badge: some View {
        if let config, config.configured {
            Text(broken > 0 ? "\(broken)!" : "\(config.rules.count)")
                .font(.caption.weight(.bold))
                .foregroundStyle(broken > 0 ? Color.white : .secondary)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(
                    broken > 0 ? AnyShapeStyle(Theme.orange) : AnyShapeStyle(.quaternary),
                    in: Capsule()
                )
        } else {
            Text("off")
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(.quaternary, in: Capsule())
        }
    }

    private var symbol: String {
        guard let config, config.configured else { return "key.slash" }
        return broken > 0 ? "exclamationmark.triangle.fill" : "key.horizontal.fill"
    }

    private var tint: Color {
        guard let config, config.configured else { return .gray }
        return broken > 0 ? Theme.orange : Theme.purple
    }
}

/// The sidebar's capability row.
///
/// Deliberately badge-free when the daemon has not answered. A count here would
/// be this app's own guess at what `chm` can do, which is precisely the thing
/// the page refuses to render.
private struct SidebarCapabilityRow: View {
    let report: CapabilityReport?

    var body: some View {
        Label {
            HStack {
                Text("Capabilities").font(.headline)
                Spacer()
                if let report {
                    Text("\(report.measuredCount)/\(report.capabilities.count)")
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                        .foregroundStyle(.secondary)
                }
            }
        } icon: {
            Image(systemName: report == nil ? "questionmark.circle" : "checkmark.seal")
                .foregroundStyle(report == nil ? Color.secondary : Theme.purple)
        }
        .padding(.vertical, 3)
    }
}

private struct SidebarActivityRow: View {
    let trail: AuditTrail?

    var body: some View {
        Label {
            HStack {
                Text("Activity").font(.headline)
                Spacer()
                badge
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .padding(.vertical, 3)
    }

    /// Denials are the number worth carrying into the sidebar: they are the
    /// events a reader would want to be told about without going looking. The
    /// count is shown only when the trail came from the daemon and is complete
    /// enough to mean something — `?` otherwise, because a confident `0` beside
    /// a trail that cannot record is the same lie the page exists to avoid.
    @ViewBuilder private var badge: some View {
        if let trail, trail.isFromDaemon, trail.present {
            let denied = trail.count(.denied)
            Text(denied > 0 ? "\(denied)" : "\(trail.total)")
                .font(.caption.weight(.bold))
                .foregroundStyle(denied > 0 ? Color.white : .secondary)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(
                    denied > 0 ? AnyShapeStyle(Theme.orange) : AnyShapeStyle(.quaternary),
                    in: Capsule()
                )
        } else {
            Text("?")
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(.quaternary, in: Capsule())
        }
    }

    private var symbol: String {
        guard let trail, trail.isFromDaemon, trail.present else { return "questionmark.circle" }
        return trail.count(.denied) > 0 ? "hand.raised.fill" : "arrow.left.arrow.right.circle.fill"
    }

    private var tint: Color {
        guard let trail, trail.isFromDaemon, trail.present else { return .gray }
        return trail.count(.denied) > 0 ? Theme.orange : Theme.cyan
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
            case .securityHome:
                SecurityPage()
            case .proxyHome:
                ProxyPage()
            case .activityHome:
                ActivityPage()
            case .capabilityHome:
                CapabilityPage()
            case let .sandbox(id):
                SandboxDetailPage(sandboxID: id)
            case let .snapshot(name):
                SnapshotDetailPage(snapshotName: name)
            }
        }
        .task {
            var tick = 0
            while !Task.isCancelled {
                // Reconcile the session registry (detect ended sessions, reap
                // dead locks, keep liveness authoritative) every tick, even when
                // the daemon isn't running.
                model.reconcileSessions()
                if model.status.state == .running {
                    await model.refreshLocal()
                }
                // Posture on its own slower cadence: it shells out to chm, and
                // it changes only when the daemon is restarted with a different
                // environment. Refreshed here rather than only on the Security
                // page so the sidebar's weakened count is true without having
                // to navigate to it — a warning you must go looking for is a
                // warning nobody sees.
                if tick % 10 == 0 {
                    await model.refreshPosture()
                    await model.refreshProxy()
                }
                tick += 1
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

            if !model.localOnly {
                HStack(spacing: 6) {
                    StatusDot(color: cloudColor, size: 7)
                    Text(cloudLabel)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
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
