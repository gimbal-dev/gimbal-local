// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import SwiftUI

// MARK: - Security posture page (V6.1)

/// What is actually protecting this sandbox, right now.
///
/// The design rule for this whole file comes from `docs/security-model.md` §4:
/// **a control you believe is on but is not is worse than one you know is off.**
/// So the page never renders an assumption. Every row is a control `chm`
/// resolved, every weakened row names the thing that weakened it, and when the
/// report describes some *other* process's environment the page says so loudly
/// rather than quietly showing green.
struct SecurityPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Security",
                    subtitle: "The controls standing between a sandbox and this Mac."
                ) {
                    Button {
                        Task { await model.refreshPosture() }
                    } label: {
                        Label("Re-check", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isCheckingPosture)
                }

                if let report = model.posture {
                    PostureSummary(report: report)
                    if !report.isFromDaemon {
                        ProvenanceWarning()
                    }
                    PostureControlList(report: report)
                } else if model.isCheckingPosture {
                    PostureLoading()
                } else {
                    PostureUnavailableState(reason: model.postureError)
                }
            }
            .padding(28)
        }
        .task { await model.refreshPosture() }
    }
}

// MARK: - Summary

private struct PostureSummary: View {
    let report: PostureReport

    private var isClean: Bool { report.weakened == 0 }

    var body: some View {
        GlassCard(
            title: isClean ? "No control is weakened" : weakenedTitle,
            subtitle: subtitle,
            systemImage: isClean ? "checkmark.shield.fill" : "exclamationmark.shield.fill"
        ) {
            HStack(spacing: 12) {
                BigMetric(
                    title: "Controls",
                    value: "\(report.controls.count)",
                    color: Theme.cyan
                )
                BigMetric(
                    title: "Weakened",
                    value: "\(report.weakened)",
                    color: isClean ? Theme.green : Theme.orange
                )
            }

            if !isClean {
                Text(
                    "A weakened control is a deliberate opt-out, not a bug — but "
                        + "it is only safe if you meant it. Each one below names what turned it off."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }

            MetricRow(label: "Workspace", value: DisplayPath.abbreviated(report.workspace))
            if let scope = report.scopeDescription {
                MetricRow(label: "Scope", value: scope)
            }
        }
    }

    private var weakenedTitle: String {
        report.weakened == 1 ? "1 control is weakened" : "\(report.weakened) controls are weakened"
    }

    private var subtitle: String {
        report.isFromDaemon
            ? "Read from the running chm serve — the process that owns the guest."
            : "Read from this app's own environment. See the warning below."
    }
}

/// Shown when we could not get the daemon's answer.
///
/// This is not cosmetic. Most controls resolve from the environment of whatever
/// process computes them, and `chm serve` is the process that runs the guest —
/// so a locally-computed report describes *this app*, which may have been
/// launched with an entirely different environment from the daemon it attached
/// to. Measured: with an identical caller environment, the local read reported
/// zero weakened controls while the daemon reported one, and the one was the
/// guest being able to reach the LAN and 169.254.169.254.
private struct ProvenanceWarning: View {
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.title3)
                .foregroundStyle(Theme.orange)

            VStack(alignment: .leading, spacing: 5) {
                Text("This describes the app, not the sandbox")
                    .font(.headline)
                Text(
                    "chm serve did not answer, so these controls were resolved from this app's "
                        + "environment instead of the daemon's. If the daemon was started from a "
                        + "terminal, or by another tool, its environment may differ and the real "
                        + "posture may be weaker than what is shown. Start the daemon from this "
                        + "app, or re-check once it is reachable, for an answer that is actually "
                        + "about the running guest."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Theme.orange.opacity(0.45), lineWidth: 1)
        }
    }
}

// MARK: - Control list

private struct PostureControlList: View {
    let report: PostureReport

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Weakened controls sort first: the point of the page is that you
            // should not have to scroll to find out something is off.
            ForEach(sorted) { control in
                PostureControlRow(control: control)
            }
        }
    }

    private var sorted: [PostureControl] {
        report.controls.sorted { lhs, rhs in
            if lhs.state.sortRank != rhs.state.sortRank {
                return lhs.state.sortRank < rhs.state.sortRank
            }
            return lhs.invariant.localizedStandardCompare(rhs.invariant) == .orderedAscending
        }
    }
}

private struct PostureControlRow: View {
    let control: PostureControl

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: control.state.symbol)
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(control.state.tint)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(control.control)
                        .font(.headline)

                    Spacer(minLength: 0)

                    Text(control.state.label.uppercased())
                        .font(.system(size: 10, weight: .black))
                        .foregroundStyle(control.state.tint)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(control.state.tint.opacity(0.15), in: Capsule())
                }

                // Never truncated: for a weakened control this sentence names
                // the environment variable responsible, which is the only part
                // of the row you can actually act on.
                Text(control.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay {
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(
                            control.state == .weakened
                                ? Theme.orange.opacity(0.5) : .white.opacity(0.10),
                            lineWidth: control.state == .weakened ? 1.5 : 1
                        )
                }
        }
    }
}

// MARK: - Non-report states

private struct PostureLoading: View {
    var body: some View {
        HStack(spacing: 12) {
            ProgressView().controlSize(.small)
            Text("Asking chm what is protecting this sandbox…")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 220)
    }
}

/// Deliberately alarming rather than blank.
///
/// An empty security panel reads as "nothing is wrong". If we could not
/// determine the posture, the honest thing to display is that we do not know.
private struct PostureUnavailableState: View {
    let reason: String?

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "questionmark.shield.fill")
                .font(.system(size: 50))
                .foregroundStyle(Theme.orange)
            Text("Posture unknown")
                .font(.title2.weight(.bold))
            Text(
                "chm could not tell us which controls are in force. Treat this as "
                    + "unknown, not as safe."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 440)

            if let reason, !reason.isEmpty {
                Text(reason)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 520)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 300)
    }
}

// MARK: - Presentation for a control state

extension PostureControl.State {
    var label: String {
        switch self {
        case .active: return "Active"
        case .weakened: return "Weakened"
        case .notApplicable: return "N/A"
        }
    }

    var symbol: String {
        switch self {
        case .active: return "checkmark.shield.fill"
        case .weakened: return "exclamationmark.shield.fill"
        case .notApplicable: return "minus.circle"
        }
    }

    var tint: Color {
        switch self {
        case .active: return Theme.green
        case .weakened: return Theme.orange
        case .notApplicable: return .gray
        }
    }

    /// Weakened first — you should not have to scroll to find the bad news.
    var sortRank: Int {
        switch self {
        case .weakened: return 0
        case .active: return 1
        case .notApplicable: return 2
        }
    }
}
