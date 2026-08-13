// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import SwiftUI

// MARK: - Activity page (V6.3)

/// What actually left the sandbox.
///
/// Every other security surface in this app describes a *configuration* — what
/// the rules say, what the posture allows, which CA is trusted. This one is the
/// only place that reports **events**, and that difference drives its whole
/// design.
///
/// A configuration panel is safe when it is empty: no rules means nothing is
/// injected. An events panel is not. An empty list here has two readings —
/// "this sandbox never opened a socket" and "nobody wrote down the ones it
/// did" — and they are opposite conclusions drawn from identical pixels. The
/// reassuring one is also the one a reader reaches for by default, so the honest
/// states are not a footnote on this page; they are the first thing it renders
/// and they replace the counts entirely rather than sitting beside them.
struct ActivityPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Activity",
                    subtitle: "What left the sandbox, and what was turned back."
                ) {
                    Button {
                        Task { await model.refreshAudit() }
                    } label: {
                        Label("Reload", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isLoadingAudit)
                }

                if let trail = model.auditTrail {
                    if !trail.isFromDaemon {
                        AuditProvenanceWarning()
                    }
                    if trail.hasNoSandboxInScope {
                        AuditPickSandboxCard(trail: trail)
                    } else if !trail.present {
                        AuditAbsentCard(trail: trail)
                    } else {
                        AuditCountsCard(trail: trail)
                        AuditPolicyCard(trail: trail)
                        AuditDecisionsCard(trail: trail)
                    }
                } else {
                    AuditUnavailableCard(running: model.status.state == .running)
                }
            }
            .padding(28)
        }
        .task { await model.refreshAudit() }
    }
}

// MARK: - Honest states

/// The daemon did not answer, so this page has nothing to report.
///
/// It says so instead of rendering zeros. Zeros would be a claim about the
/// guest's behaviour that nothing here is entitled to make.
private struct AuditUnavailableCard: View {
    let running: Bool

    var body: some View {
        GlassCard(
            title: "No answer from the sandbox",
            subtitle: running
                ? "A sandbox is running, but chm serve did not return its trail."
                : "Start a sandbox to see what it does on the network.",
            systemImage: "questionmark.circle.fill"
        ) {
            Text(
                "This page reports events, not settings, so it deliberately shows nothing "
                    + "rather than zeros. A row of zeros would read as \"this sandbox made no "
                    + "network calls\", which is a statement about the guest — and with no "
                    + "answer from the process running it, that is not something this app can "
                    + "know."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Nothing is running, so the daemon has no sandbox in scope.
///
/// The trail is durable precisely so it can be read after the fact, and the
/// moment a sandbox stops is when someone actually sits down to check what it
/// did. Reporting "no records" here would answer a question about a guest with
/// a fact about this reader's own selection — so the page names the sandboxes
/// that *do* have history and lets you open one.
private struct AuditPickSandboxCard: View {
    let trail: AuditTrail
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(
            title: "No sandbox is running",
            subtitle: candidates.isEmpty
                ? "No sandbox in this library has recorded history yet."
                : "Pick a sandbox to read what it did.",
            systemImage: "clock.arrow.circlepath"
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text(
                    "Records outlive the sandbox that wrote them, so stopping one does not "
                        + "erase what it did. This page is not showing zero activity — it has "
                        + "not been told which sandbox to report on."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                ForEach(candidates) { c in
                    Button {
                        Task { await model.refreshAudit(dir: c.dir) }
                    } label: {
                        HStack {
                            Image(systemName: "doc.text.magnifyingglass")
                            VStack(alignment: .leading, spacing: 1) {
                                Text(c.name).font(.callout.weight(.medium))
                                Text(c.dir).font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(ByteCountFormatter.string(fromByteCount: Int64(c.bytes), countStyle: .file))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }

    private var candidates: [AuditCandidate] { trail.candidates ?? [] }
}

/// There is no trail file yet.
private struct AuditAbsentCard: View {
    let trail: AuditTrail

    var body: some View {
        GlassCard(
            title: "No trail recorded yet",
            subtitle: "This workspace has not written an audit record.",
            systemImage: "doc.badge.clock"
        ) {
            VStack(alignment: .leading, spacing: 10) {
                Text(
                    "The trail is created the first time a sandbox starts in this workspace. "
                        + "Until then there is nothing to show, and — importantly — no basis "
                        + "for saying the sandbox has been quiet."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                if let scope = trail.scopeDir {
                    MetricRow(label: "Workspace", value: scope)
                }
            }
        }
    }
}

private struct AuditProvenanceWarning: View {
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.title3)
                .foregroundStyle(Theme.orange)

            VStack(alignment: .leading, spacing: 5) {
                Text("This trail did not come from the daemon")
                    .font(.headline)
                Text(
                    "The records below were not sourced from the process running the guest, "
                        + "so they may describe a different workspace or an earlier session. "
                        + "Treat them as history, not as what is happening now."
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

// MARK: - Counts

private struct AuditCountsCard: View {
    let trail: AuditTrail

    var body: some View {
        GlassCard(
            title: "Decisions",
            subtitle: subtitle,
            systemImage: "arrow.left.arrow.right.circle.fill"
        ) {
            VStack(alignment: .leading, spacing: 14) {
                if !trail.recordsAllowEgress {
                    NotRecordedNotice()
                }

                HStack(spacing: 26) {
                    if trail.recordsAllowEgress {
                        BigMetric(
                            title: "Allowed",
                            value: "\(allowed)",
                            color: Theme.green
                        )
                    } else {
                        // Not a zero. A zero here would be a measurement.
                        BigMetric(title: "Allowed", value: "—", color: .secondary)
                    }
                    BigMetric(title: "Denied", value: "\(trail.count(.denied))", color: Theme.orange)
                    BigMetric(
                        title: "Credential attached",
                        value: "\(trail.count(.injected))",
                        color: Theme.purple
                    )
                    BigMetric(title: "Relayed", value: "\(trail.count(.relayed))", color: Theme.cyan)
                }

                if let s = trail.summary {
                    SummaryLine(summary: s)
                }

                if trail.truncated {
                    TruncatedNotice()
                }
            }
        }
    }

    /// The exact totals come from the summary when there is one: the per-flow
    /// lines are capped, but the counters that produced the summary never were,
    /// so preferring them turns a capped list into an exact number.
    private var allowed: Int {
        trail.summary?.allowed ?? trail.count(.allowed)
    }

    private var subtitle: String {
        let n = trail.total
        return n == 1 ? "1 record in this workspace's trail" : "\(n) records in this workspace's trail"
    }
}

/// The single most important sentence on this page.
private struct NotRecordedNotice: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "eye.slash.fill").foregroundStyle(Theme.orange)
            Text(
                "This trail predates allow-recording. Earlier builds wrote down refusals "
                    + "only, so the absence of allowed traffic here means it was never "
                    + "recorded — not that none occurred. Start a new sandbox to get a trail "
                    + "that can answer the question."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct TruncatedNotice: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "scissors").foregroundStyle(Theme.orange)
            Text(
                "A session reached the per-flow limit, so the list of destinations below is "
                    + "incomplete. The totals above stay exact — the counters kept running "
                    + "after the detail stopped."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct SummaryLine: View {
    let summary: AuditRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Last session totals").font(.caption.bold()).foregroundStyle(.secondary)
            Text(text)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var text: String {
        let a = summary.allowed ?? 0
        let d = summary.denied ?? 0
        let da = summary.distinctAllowed ?? 0
        let dd = summary.distinctDenied ?? 0
        return "\(a) allowed (\(da) distinct) · \(d) denied (\(dd) distinct)"
    }
}

// MARK: - Policy

private struct AuditPolicyCard: View {
    let trail: AuditTrail

    var body: some View {
        GlassCard(
            title: "Policy in force",
            subtitle: "The rules these decisions were actually made under.",
            systemImage: "checkmark.shield.fill"
        ) {
            VStack(alignment: .leading, spacing: 10) {
                if digests.isEmpty {
                    Text("No decision in this trail carries a policy hash.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(digests, id: \.self) { d in
                        MetricRow(label: "Content hash", value: d)
                    }
                }

                if digests.count > 1 {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.orange)
                        Text(
                            "The policy changed while this trail was being written. Decisions "
                                + "above were not all made under the same rules, so the newest "
                                + "hash does not describe the older ones."
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        Theme.orange.opacity(0.12),
                        in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                    )
                }

                if let path = trail.path {
                    MetricRow(label: "Trail", value: path)
                }
            }
        }
    }

    private var digests: [String] { trail.policyDigests }
}

// MARK: - The log

private struct AuditDecisionsCard: View {
    let trail: AuditTrail
    @State private var filter: AuditRecord.Kind?

    var body: some View {
        GlassCard(
            title: "Decision log",
            subtitle: "Most recent last. Each line is one decision about one destination.",
            systemImage: "list.bullet.rectangle.portrait.fill"
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Show", selection: $filter) {
                    Text("All").tag(AuditRecord.Kind?.none)
                    ForEach(AuditRecord.Kind.allCases, id: \.self) { k in
                        Text(k.rawValue.capitalized).tag(AuditRecord.Kind?.some(k))
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                if visible.isEmpty {
                    Text(emptyText)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(visible) { record in
                            AuditRow(record: record)
                            if record.id != visible.last?.id {
                                Divider().opacity(0.15)
                            }
                        }
                    }
                }
            }
        }
    }

    private var visible: [AuditRecord] {
        trail.records.filter { r in
            guard let kind = r.kind else { return false }
            guard let filter else { return true }
            return kind == filter
        }
    }

    /// Never "nothing happened". With a filter applied it is a statement about
    /// the filter; without one it defers to whichever honesty flag applies.
    private var emptyText: String {
        if let filter {
            return "No \(filter.rawValue) decisions in the records shown."
        }
        if !trail.recordsAllowEgress {
            return
                "This trail records refusals only, and there were none. It cannot tell you "
                + "what the sandbox reached."
        }
        return
            "No network decisions recorded. The sandbox started, and nothing tried to leave it."
    }
}

private struct AuditRow: View {
    let record: AuditRecord

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(record.subject)
                    .font(.system(.callout, design: .monospaced))
                if let rule = record.rule, !rule.isEmpty {
                    Text(rule).font(.caption).foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 8)

            Text(label)
                .font(.caption.weight(.bold))
                .foregroundStyle(tint)

            if let ts = record.ts {
                Text(ts.suffix(13).prefix(8))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 7)
    }

    private var label: String {
        switch record.kind {
        case .allowed: return "ALLOWED"
        case .denied: return "DENIED"
        case .injected: return "CREDENTIAL"
        case .relayed: return "RELAYED"
        case nil: return record.event.uppercased()
        }
    }

    private var symbol: String {
        switch record.kind {
        case .allowed: return "arrow.up.right"
        case .denied: return "hand.raised.fill"
        case .injected: return "key.fill"
        case .relayed: return "arrow.turn.up.right"
        case nil: return "circle"
        }
    }

    private var tint: Color {
        switch record.kind {
        case .allowed: return Theme.green
        case .denied: return Theme.orange
        case .injected: return Theme.purple
        case .relayed: return Theme.cyan
        case nil: return .secondary
        }
    }
}
