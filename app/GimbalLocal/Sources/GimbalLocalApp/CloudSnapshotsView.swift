// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

// MARK: - Cloud snapshots main page

/// Browse the snapshots the control plane knows about and bring one down to run
/// on this Mac. "Remote vs local" is meant to be an implementation detail: a
/// cloud snapshot is brought down and rehydrated locally through the same `chm`
/// runner pipeline the CLI uses.
struct CloudSnapshotsPage: View {
    @EnvironmentObject private var model: AppModel

    private let columns = [GridItem(.adaptive(minimum: 340, maximum: 480), spacing: 16)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Cloud snapshots",
                    subtitle: "Bring a snapshot down from the control plane and run it here."
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

                if case let .offline(reason) = model.cloud.state {
                    CloudOfflineState(reason: reason)
                } else if model.cloudSnapshots.isEmpty {
                    CloudEmptyState()
                } else {
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
                        ForEach(model.cloudSnapshots) { snapshot in
                            CloudSnapshotCard(snapshot: snapshot)
                        }
                    }
                }

                if !model.branches.isEmpty {
                    BranchesSection(branches: model.branches)
                }

                if !model.activityLog.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Activity")
                            .font(.title3.bold())
                            .foregroundStyle(.white)
                        TerminalPane(text: model.activityLog, mode: .activity)
                            .frame(height: 200)
                    }
                }
            }
            .padding(28)
        }
    }
}

// MARK: - Branches (Phase 4 — git for live compute)

/// Read-only surface of the plane's revision branches: what a session was
/// committed onto, its head revision, review gate, and any per-page ACLs. This
/// is the human-facing version-control view over the push/pull revision graph.
private struct BranchesSection: View {
    let branches: [PlaneBranch]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "arrow.triangle.branch")
                    .foregroundStyle(.white.opacity(0.8))
                Text("Branches")
                    .font(.title3.bold())
                    .foregroundStyle(.white)
                Text("\(branches.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.white.opacity(0.6))
            }
            Text("Revision branches on the control plane — commit with `chm push`, rehydrate with `chm pull`.")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.55))

            VStack(spacing: 0) {
                ForEach(branches) { branch in
                    BranchRow(branch: branch, allBranches: branches)
                    if branch.id != branches.last?.id {
                        Divider().overlay(Color.white.opacity(0.08))
                    }
                }
            }
            .background(Color.white.opacity(0.04))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }
}

private struct BranchRow: View {
    @EnvironmentObject private var model: AppModel
    let branch: PlaneBranch
    let allBranches: [PlaneBranch]

    private var reviewColor: Color {
        switch branch.reviewStatus {
        case "approved": return .green
        case "pending": return .orange
        case "rejected": return .red
        default: return .secondary
        }
    }

    /// Other branches whose head can be merged into this one.
    private var mergeSources: [PlaneBranch] {
        allBranches.filter { $0.id != branch.id }
    }

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(branch.name)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.white)
                Text("head \(branch.shortHead) · \(branch.owner)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.white.opacity(0.5))
            }
            Spacer()
            if branch.aclCount > 0 {
                Label("\(branch.aclCount) ACL", systemImage: "lock.shield")
                    .font(.caption2)
                    .foregroundStyle(.white.opacity(0.6))
            }

            // Review gate — a menu to set pending / approved / rejected.
            Menu {
                ForEach(["approved", "pending", "rejected"], id: \.self) { status in
                    Button {
                        model.setBranchReview(branch.name, status: status)
                    } label: {
                        Label(status.capitalized, systemImage: branch.reviewStatus == status ? "checkmark" : "")
                    }
                }
            } label: {
                Text(branch.reviewLabel)
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(reviewColor.opacity(0.18))
                    .foregroundStyle(reviewColor)
                    .clipShape(Capsule())
            }
            .menuStyle(.borderlessButton)
            .fixedSize()

            // Merge another branch's head into this one (review-gated on the plane).
            Menu {
                if mergeSources.isEmpty {
                    Text("No other branches")
                } else {
                    ForEach(mergeSources) { source in
                        Button("Merge \(source.name) → \(branch.name)") {
                            model.mergeBranches(target: branch.name, from: source.name)
                        }
                    }
                }
            } label: {
                Image(systemName: "arrow.triangle.merge")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.7))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(mergeSources.isEmpty)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

// MARK: - Cloud snapshot card

private struct CloudSnapshotCard: View {
    @EnvironmentObject private var model: AppModel
    let snapshot: CloudSnapshot

    private var isBusy: Bool { model.bringingDownID == snapshot.id }
    private var anyBusy: Bool { model.bringingDownID != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Theme.iconGradient)
                        .frame(width: 40, height: 40)
                    Image(systemName: snapshot.isCheckpoint ? "clock.arrow.circlepath" : "cloud.fill")
                        .foregroundStyle(.white)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(snapshot.id)
                        .font(.headline)
                        .lineLimit(1)
                        .textSelection(.enabled)
                    Text("\(snapshot.vcpus) vCPU · \(snapshot.ramMib) MiB · \(snapshot.kind)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            FlowTags {
                if let origin = snapshot.originLabel {
                    CloudTag(text: origin, color: Theme.purple, systemImage: "point.3.filled.connected.trianglepath.dotted")
                }
                if snapshot.hasLocalCopy {
                    CloudTag(text: "local copy", color: Theme.green, systemImage: "internaldrive")
                }
                CloudTag(
                    text: snapshot.restorableOnHVF
                        ? "runnable on HVF"
                        : "cloud-only · \(snapshot.gicMode ?? snapshot.compatibility)",
                    color: snapshot.restorableOnHVF ? Theme.green : Theme.orange,
                    systemImage: snapshot.restorableOnHVF ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
                )
                if snapshot.restorableOnHVF && !snapshot.planeWillRelease {
                    CloudTag(
                        text: "plane says \(snapshot.compatibility)",
                        color: Theme.orange,
                        systemImage: "cloud.fill"
                    )
                }
                if snapshot.restorableOnHVF && snapshot.planeWillRelease && !snapshot.hasDiskImage {
                    CloudTag(
                        text: "fixture · no disk",
                        color: Theme.orange,
                        systemImage: "questionmark.folder.fill"
                    )
                }
            }

            Button {
                model.bringDownAndRun(snapshot)
            } label: {
                HStack(spacing: 8) {
                    if isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.down.circle.fill")
                    }
                    Text(bringDownLabel)
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!snapshot.likelyBootable || anyBusy)

            if let reason = snapshot.notBootableReason {
                Text(bootBlockedHelp(reason))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
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
    }

    private var bringDownLabel: String {
        if isBusy { return "Bringing down…" }
        return snapshot.isCheckpoint ? "Bring down & resume" : "Bring down & run"
    }

    /// Fuller guidance for why the bring-down button is disabled.
    private func bootBlockedHelp(_ reason: String) -> String {
        if !snapshot.restorableOnHVF {
            return "\(reason). `chm` runs a GICv2M capture on Apple's managed GIC "
                + "and a vanilla ITS/LPI one on its own userspace GICv3, but this "
                + "snapshot declares neither."
        }
        if !snapshot.planeWillRelease {
            return "\(reason). This Mac can rehydrate it — the refusal is the "
                + "plane's, not ours."
        }
        // No disk image: a protocol fixture, not a bootable capture.
        return "\(reason). Pick a snapshot captured from a real host — it ships a "
            + "disk image and boots here."
    }
}

// MARK: - Small pieces

private struct CloudTag: View {
    let text: String
    let color: Color
    let systemImage: String

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.14), in: Capsule())
    }
}

/// A simple wrapping row of tags so provenance/compat badges reflow instead of
/// clipping on a narrow card.
private struct FlowTags<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: 6) {
            content
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct CloudOfflineState: View {
    let reason: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "cloud.slash")
                .font(.system(size: 46))
                .foregroundStyle(Theme.orange)
            Text("Control plane offline")
                .font(.title2.weight(.bold))
            Text("Gimbal Local works fully offline. Cloud snapshots appear here when a control plane is reachable.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 440)
            Text(reason)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
            SettingsLink {
                Label("Control-plane settings", systemImage: "slider.horizontal.3")
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, minHeight: 300)
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

private struct CloudEmptyState: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "cloud")
                .font(.system(size: 46))
                .foregroundStyle(Theme.cyan)
            Text("No cloud snapshots")
                .font(.title2.weight(.bold))
            Text("When the control plane has snapshots, they appear here to bring down and run locally.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 440)
        }
        .frame(maxWidth: .infinity, minHeight: 300)
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
