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
            .disabled(!snapshot.restorableOnHVF || anyBusy)

            if !snapshot.restorableOnHVF {
                Text("Not restorable on this Mac — HVF delivers message-SPI only. Stays cloud-only; recapture with CH_GIC_V2M=1 to bring it here.")
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
