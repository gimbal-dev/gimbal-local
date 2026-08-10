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

                    RevisionHistoryCard(dirPath: snapshot.path)

                    LineageCard(snapshotName: snapshot.name)
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

// MARK: - Revision history

/// The revision lineage (from `chm revisions`) for a directory — a sandbox
/// workspace or a snapshot image: each suspend / fork / rollback, newest first,
/// with a roll-back action on resumable archived revisions.
struct RevisionHistoryCard: View {
    @EnvironmentObject private var model: AppModel
    /// The directory whose revisions to show (a sandbox workspace, or an image).
    /// `nil` when the sandbox has not run yet (no workspace).
    let dirPath: String?
    /// The lead sentence of the empty state. How points *arrive* is appended
    /// from the cadence rather than written here, so the two cannot disagree.
    var emptyLead = "No saved points yet."

    private var revisions: [RevisionSummary] {
        guard let dirPath else { return [] }
        return (model.revisionsByPath[dirPath] ?? []).reversed()
    }

    var body: some View {
        GlassCard(
            title: "Revision history",
            subtitle: "suspend · fork · rollback lineage",
            systemImage: "clock.arrow.circlepath"
        ) {
            if revisions.isEmpty {
                Text(emptyLead + " " + model.snapshotCadence.howPointsArrive)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(revisions) { rev in
                    HStack(spacing: 10) {
                        Image(systemName: rev.isHead ? "smallcircle.filled.circle.fill" : "circle")
                            .font(.caption)
                            .foregroundStyle(rev.isHead ? Theme.green : Theme.cyan)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 6) {
                                Text(rev.originEntryPoint).font(.callout.weight(.medium))
                                // chm has always distinguished a point the
                                // cadence took from one a person asked for; the
                                // app has never shown it. They answer different
                                // questions, so rolling back to one is a
                                // different decision from rolling back to the
                                // other.
                                if rev.isAutomatic {
                                    Text("auto")
                                        .font(.caption2.weight(.semibold))
                                        .foregroundStyle(Theme.cyan)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Theme.cyan.opacity(0.16), in: Capsule())
                                }
                                Text(rev.shortId)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.tertiary)
                            }
                            Text(Self.age(rev.createdAt) + (rev.resumable ? "" : " · metadata-only"))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if rev.isHead {
                            Text("HEAD")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(Theme.green)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background(Theme.green.opacity(0.16), in: Capsule())
                        } else if rev.resumable, let dirPath {
                            Button("Roll back") {
                                model.rollback(path: dirPath, toRevision: rev.id)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(model.rollingBackPath != nil)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Divider().opacity(0.25)
                Label(
                    "Rolling back appends a new revision that restores an earlier live state — history is preserved, not rewound. Only the newest few revisions keep their full RAM (older ones stay in the graph as metadata).",
                    systemImage: "info.circle"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .task(id: dirPath) {
            // Poll while the card is visible so a snapshot taken during a live
            // session (suspend / on-delta capture) surfaces within a couple of
            // seconds, instead of only when the sandbox is re-selected (#69). The
            // task is cancelled when the card disappears or dirPath changes.
            guard let dirPath else { return }
            while !Task.isCancelled {
                model.refreshRevisions(path: dirPath)
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// A compact relative age like "2m ago" / "3h ago" / "just now".
    static func age(_ date: Date) -> String {
        let seconds = max(0, Date().timeIntervalSince(date))
        switch seconds {
        case ..<5: return "just now"
        case ..<60: return "\(Int(seconds))s ago"
        case ..<3600: return "\(Int(seconds / 60))m ago"
        case ..<86400: return "\(Int(seconds / 3600))h ago"
        default: return "\(Int(seconds / 86400))d ago"
        }
    }
}

// MARK: - Lineage

/// The relationship between a snapshot image, its saved revisions (live
/// checkpoints), and the sandboxes that run from it — rendered as an indented
/// tree. Today a snapshot has at most one revision (HEAD); the layout is built
/// for the fork future (see docs/gimbal-local-fork-model.md), where a revision
/// branches into several child sandboxes/revisions.
// Not `private`: `revisionSubtitle` is the one place the `-auto` marker turns
// into words, and a rule about what the user reads should be reachable by a
// test rather than only by rendering a view.
struct LineageCard: View {
    @EnvironmentObject private var model: AppModel
    let snapshotName: String

    private var derived: [Sandbox] {
        model.sandboxes.filter { $0.snapshotName == snapshotName }
    }

    var body: some View {
        GlassCard(
            title: "Lineage",
            subtitle: "image → revisions → sandboxes",
            systemImage: "point.3.connected.trianglepath.dotted"
        ) {
            VStack(alignment: .leading, spacing: 0) {
                LineageRow(
                    depth: 0,
                    symbol: "externaldrive.fill",
                    color: Theme.purple,
                    title: snapshotName,
                    subtitle: "base image",
                    badge: "image"
                )

                if let rev = model.revision(forSnapshotNamed: snapshotName) {
                    LineageRow(
                        depth: 1,
                        symbol: "clock.arrow.circlepath",
                        color: Theme.cyan,
                        title: "revision \(rev.shortId)",
                        subtitle: Self.revisionSubtitle(rev, createdAt: rev.createdAt)
                            + (rev.parent == nil ? "" : " · has parent"),
                        badge: "revision"
                    )
                    ForEach(derived) { sandbox in
                        LineageRow(
                            depth: 2,
                            symbol: "shippingbox.fill",
                            color: Theme.color(for: sandbox.state),
                            title: sandbox.name,
                            subtitle: sandbox.state.label.lowercased(),
                            badge: sandbox.location.label
                        )
                    }
                    HStack {
                        Spacer()
                        Button {
                            model.forkSnapshot(named: snapshotName)
                        } label: {
                            Label("Fork this revision", systemImage: "arrow.triangle.branch")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(.top, 2)
                } else {
                    ForEach(derived) { sandbox in
                        LineageRow(
                            depth: 1,
                            symbol: "shippingbox.fill",
                            color: Theme.color(for: sandbox.state),
                            title: sandbox.name,
                            subtitle: sandbox.state.label.lowercased(),
                            badge: sandbox.location.label
                        )
                    }
                    if derived.isEmpty {
                        LineageRow(
                            depth: 1,
                            symbol: "circle.dashed",
                            color: .secondary,
                            title: "No revisions yet",
                            subtitle: "stop a running sandbox to save its live state here",
                            badge: nil
                        )
                    }
                }
            }

            Divider().opacity(0.25)
            Label(
                "Fork branches a revision into an independent sandbox that shares its base but diverges from a copy of its live state — the graph branches here.",
                systemImage: "arrow.triangle.branch"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// A compact relative age like "2m ago" / "3h ago" / "just now".
    static func age(_ date: Date) -> String {
        let seconds = max(0, Date().timeIntervalSince(date))
        switch seconds {
        case ..<5: return "just now"
        case ..<60: return "\(Int(seconds))s ago"
        case ..<3600: return "\(Int(seconds / 60))m ago"
        case ..<86400: return "\(Int(seconds / 3600))h ago"
        default: return "\(Int(seconds / 86400))d ago"
        }
    }

    /// The lineage row's one-line description of a revision.
    ///
    /// Extracted so the `-auto` marker is a value the tests can ask for rather
    /// than a string assembled inside a `ViewBuilder`, where it is only
    /// reachable by rendering.
    static func revisionSubtitle(_ rev: some RevisionOrigin, createdAt: Date) -> String {
        var parts = ["saved \(age(createdAt))", "via \(rev.originEntryPoint)"]
        if rev.isAutomatic { parts[1] += " (auto)" }

        return parts.joined(separator: " · ")
    }
}

/// One node in the lineage tree, indented by `depth` with a connector elbow.
private struct LineageRow: View {
    let depth: Int
    let symbol: String
    let color: Color
    let title: String
    let subtitle: String
    let badge: String?

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            if depth > 0 {
                ForEach(0..<depth, id: \.self) { i in
                    Text(i == depth - 1 ? "└─" : "  ")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }
            }
            Image(systemName: symbol)
                .foregroundStyle(color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.callout.weight(.medium))
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let badge {
                Text(badge)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(color.opacity(0.16)))
                    .foregroundStyle(color)
            }
        }
        .padding(.vertical, 5)
    }
}
