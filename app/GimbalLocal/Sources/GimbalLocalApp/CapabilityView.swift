// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

// MARK: - Capabilities page (V6.5)

/// What this build can and cannot do — and how each claim was reached.
///
/// The problem this page exists to end is that, until now, the way to learn
/// whether something worked was to run it and watch. A crash is an expensive,
/// ambiguous, after-the-fact answer to a question that was askable in advance,
/// and — worse — its *absence* is not the opposite of a crash. A guest that
/// resumes and then runs at a fifth of real speed never crashed.
///
/// The obvious way to build this page would be a list of things we believe.
/// That is the shape of a bug this project has now hit nine times: an answer
/// computed in the wrong place, then presented with the confidence of a
/// measurement. The ninth instance was in this very question and had been in the
/// tree since the port began — `is_available()` was documented as checking the
/// hypervisor entitlement and implemented as `cfg!(target_os = "macos")`, so it
/// said yes for a binary that `hv_vm_create` would refuse outright.
///
/// So no claim here appears without its grade. "We created a VM two seconds ago
/// and it worked" and "someone wrote this down" both render as a green tick if
/// you let them, and the whole value of the page is that they do not.
struct CapabilityPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Capabilities",
                    subtitle: "What this build can do, and how we know."
                ) {
                    Button {
                        Task { await model.refreshCapabilities() }
                    } label: {
                        Label("Re-check", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isLoadingCapabilities)
                }

                if let report = model.capabilities {
                    if !report.isFromDaemon {
                        CapabilityProvenanceWarning()
                    }
                    CapabilityEvidenceCard(report: report)
                    if let pre = report.preflight {
                        PreflightCard(preflight: pre)
                    } else if report.hasNoSnapshotInScope {
                        NoSnapshotInScopeCard()
                    }
                    CapabilityListCard(report: report)
                } else {
                    CapabilityUnavailableCard()
                }
            }
            .padding(28)
        }
        .task { await model.refreshCapabilities() }
    }
}

// MARK: - Honest states

/// The daemon did not answer.
///
/// This page shows nothing rather than falling back to a list compiled into the
/// app. That fallback is available and it is exactly the wrong thing: it would
/// describe this app's idea of `chm`, not the binary that would run the guest —
/// which may be an older build, or the same source signed differently. Being
/// confidently wrong about capability is the failure this page exists to end,
/// so it declines to guess.
private struct CapabilityUnavailableCard: View {
    var body: some View {
        GlassCard(
            title: "Not established",
            subtitle: "chm serve did not answer.",
            systemImage: "questionmark.circle.fill"
        ) {
            Text(
                "This app deliberately keeps no capability list of its own. Anything it "
                    + "showed here would describe a binary it is not talking to — possibly an "
                    + "older chm, or the same code signed without the hypervisor entitlement. "
                    + "The only honest source is the process that would actually run the guest, "
                    + "so with that process silent there is nothing to report."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// The answer did not carry daemon provenance.
private struct CapabilityProvenanceWarning: View {
    var body: some View {
        GlassCard(
            title: "Unknown source",
            subtitle: "This answer did not identify itself as coming from the daemon.",
            systemImage: "exclamationmark.triangle.fill"
        ) {
            Text(
                "Treat everything below as unverified. A capability report is only worth "
                    + "as much as the process that produced it."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// No snapshot to check — a fact about this reader, not about any capture.
private struct NoSnapshotInScopeCard: View {
    var body: some View {
        GlassCard(
            title: "No snapshot checked",
            subtitle: "Nothing is running, so nothing was inspected.",
            systemImage: "questionmark.folder"
        ) {
            Text(
                "The claims below are about this build. Whether a particular capture "
                    + "resumes is a question about that capture — start a sandbox, or run "
                    + "`chm capabilities <dir>`, to have it checked. This card is here so "
                    + "an absent preflight is not mistaken for a clean one."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Evidence summary

/// How much of this page was measured versus merely asserted.
///
/// This is the number that keeps the page honest over time. Claims decay: a
/// documented gap is only as good as the last person to edit it, and nothing in
/// the build will notice when it goes stale. Showing the split makes that
/// visible instead of letting a written-down claim borrow the credibility of a
/// probed one sitting next to it.
private struct CapabilityEvidenceCard: View {
    let report: CapabilityReport

    var body: some View {
        GlassCard(
            title: "How these claims were reached",
            subtitle: report.assessed.map { "Scope: \($0)" } ?? "",
            systemImage: "checkmark.seal"
        ) {
            HStack(spacing: 12) {
                BigMetric(
                    title: "Measured",
                    value: "\(report.measuredCount)",
                    color: .green
                )
                BigMetric(
                    title: "Written down",
                    value: "\(report.documentedCount)",
                    color: .orange
                )
                BigMetric(
                    title: "Claims",
                    value: "\(report.capabilities.count)",
                    color: .secondary
                )
            }
            Text(
                "Measured means something was done just now, or is happening as you read "
                    + "this. Written down means a human asserted it and nothing checks it — "
                    + "honest, useful, and the grade a claim decays to when the code moves "
                    + "underneath it."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Preflight

/// What this build makes of the snapshot in scope, before it is run.
private struct PreflightCard: View {
    let preflight: CapabilityPreflight

    var body: some View {
        GlassCard(
            title: "This snapshot",
            subtitle: preflight.dir,
            systemImage: preflight.refusals > 0 ? "xmark.octagon.fill" : "list.bullet.clipboard"
        ) {
            Text(preflight.summary)
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(preflight.refusals > 0 ? Color.red : .primary)

            Text(
                "Checked without running it. Nothing here says the guest will boot — that "
                    + "depends on code this process has not executed. It says only that the "
                    + "checks this build knows how to make raised no objection, which is a "
                    + "smaller claim and the only one available."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            if preflight.readable {
                VStack(spacing: 0) {
                    ForEach(preflight.findings) { f in
                        ClaimRow(claim: f)
                    }
                }
            } else if let first = preflight.findings.first {
                ClaimRow(claim: first)
            }
        }
    }
}

// MARK: - Claims

private struct CapabilityListCard: View {
    let report: CapabilityReport

    var body: some View {
        GlassCard(
            title: "This build",
            subtitle: "Independent of any snapshot.",
            systemImage: "cpu"
        ) {
            VStack(spacing: 0) {
                ForEach(report.capabilities) { c in
                    ClaimRow(claim: c)
                }
            }
        }
    }
}

/// One claim: verdict, evidence grade, and the detail that carries the numbers.
private struct ClaimRow: View {
    let claim: CapabilityClaim

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: icon)
                    .foregroundStyle(color)
                    .font(.system(size: 13, weight: .bold))
                    .frame(width: 16)
                Text(claim.title)
                    .font(.system(size: 13, weight: .semibold))
                Spacer(minLength: 8)
                Text(claim.evidence.label)
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(claim.evidence.isMeasured ? Color.green : .secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        (claim.evidence.isMeasured ? Color.green : Color.secondary)
                            .opacity(0.14),
                        in: Capsule()
                    )
            }
            Text(claim.detail)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 26)
        }
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Color.secondary.opacity(0.12)).frame(height: 1)
        }
    }

    private var color: Color {
        switch claim.support {
        case .yes: return .green
        case .degraded: return .orange
        case .no: return .red
        case .unknown: return .secondary
        }
    }

    private var icon: String {
        switch claim.support {
        case .yes: return "checkmark.circle.fill"
        case .degraded: return "exclamationmark.triangle.fill"
        case .no: return "xmark.circle.fill"
        case .unknown: return "questionmark.circle.fill"
        }
    }
}
