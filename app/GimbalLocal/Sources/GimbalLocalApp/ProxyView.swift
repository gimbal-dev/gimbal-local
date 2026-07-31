// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

// MARK: - Credential proxy page (V6.2)

/// Where credentials live, and proof they are not in the guest.
///
/// The proxy's whole claim is that a remote-call secret is attached **as the
/// request leaves**, so a guest with full control of itself still never holds
/// it. That claim is only worth something if it can be inspected and tested, so
/// this page does three things and refuses to fake any of them:
///
/// 1. Shows every rule, its destinations, and *where* its credential comes from
///    — never the value. `chm proxy show` cannot read one even if asked.
/// 2. Hands you the CA install, which is a guest-side action, as a button.
/// 3. Sends a real request **with a control run**, because a green tick that
///    cannot fail is not evidence.
struct ProxyPage: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                PageHeader(
                    title: "Credential proxy",
                    subtitle: "Secrets attached as a request leaves, so the guest never holds them."
                ) {
                    Button {
                        Task { await model.refreshProxy() }
                    } label: {
                        Label("Reload", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }

                if let config = model.proxyConfig, config.configured {
                    ProxyRulesCard(config: config)
                    ProxyPassthroughCard(config: config)
                    ProxyCaCard()
                    ProxyCheckCard()
                } else {
                    ProxyNotConfigured(config: model.proxyConfig)
                }
            }
            .padding(28)
        }
        .task { await model.refreshProxy() }
    }
}

// MARK: - Rules

private struct ProxyRulesCard: View {
    let config: ProxyConfiguration

    var body: some View {
        GlassCard(
            title: config.label ?? "Injection rules",
            subtitle: "\(config.rules.count) rule(s) · from \(config.origin ?? "unknown")",
            systemImage: "key.horizontal.fill"
        ) {
            if config.rules.isEmpty {
                Text("No injecting rules — nothing is intercepted, everything is relayed.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            ForEach(config.rules) { rule in
                ProxyRuleRow(rule: rule)
            }

            if !config.rulesMissingCredentials.isEmpty {
                // Worth its own line: a rule whose credential is absent still
                // intercepts, so the request goes out *unauthenticated* rather
                // than failing loudly. That looks like a broken API, not a
                // misconfigured proxy, and is miserable to debug from inside a
                // guest that cannot see any of this.
                Label(
                    "\(config.rulesMissingCredentials.count) rule(s) have no credential "
                        + "available. Matching requests are still intercepted, and go out "
                        + "unauthenticated.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.callout)
                .foregroundStyle(Theme.orange)
                .fixedSize(horizontal: false, vertical: true)
            }

            if !config.isFromDaemon {
                // Same trap as the security panel, and it bites harder here.
                // Whether a credential resolves is read from the environment of
                // whichever process answers. When the daemon cannot be reached
                // we answer from this app — so a token this app happens to hold
                // would read "present" while the daemon that actually injects
                // has nothing, and every request would leave unauthenticated
                // behind a green panel.
                ProvenanceWarning(
                    text: "The daemon did not answer, so credential availability below "
                        + "describes this app, not the sandbox. Start a sandbox to get the "
                        + "real answer."
                )
            }

            Text(
                "The app never sees a credential value: `chm proxy show` does not read one, "
                    + "and an `exec` source is never run."
                    + (config.isFromDaemon
                        ? "  Answered by chm serve (\(config.assessed ?? "unknown"))."
                        : "  Answered by this app.")
            )
            .font(.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// The banner shown when an answer came from the wrong process.
///
/// Shared rather than inlined because it now appears three times: an alarm
/// sourced from the wrong environment is worse than no alarm, so the caveat has
/// to read identically wherever it applies.
private struct ProvenanceWarning: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "questionmark.circle.fill")
            .font(.callout)
            .foregroundStyle(Theme.orange)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct ProxyRuleRow: View {    let rule: ProxyRule

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Text(rule.name).font(.headline)
                Spacer(minLength: 0)
                CredentialBadge(availability: rule.credential)
            }

            HStack(alignment: .top, spacing: 6) {
                Image(systemName: "arrow.right.circle.fill")
                    .foregroundStyle(Theme.cyan)
                    .font(.caption)
                Text(rule.hostList.joined(separator: ", "))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("injects **\(rule.header)** from `\(rule.source)`")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            (rule.willFailToInject ? Theme.orange : Theme.cyan).opacity(0.08),
            in: RoundedRectangle(cornerRadius: 14, style: .continuous)
        )
    }
}

private struct CredentialBadge: View {
    let availability: String

    var body: some View {
        Text(label.uppercased())
            .font(.system(size: 10, weight: .black))
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(tint.opacity(0.15), in: Capsule())
            .help(explanation)
    }

    private var label: String {
        switch availability {
        case "present": return "available"
        case "on-demand": return "minted per call"
        case "empty": return "empty"
        case "missing": return "missing"
        default: return availability
        }
    }

    private var tint: Color {
        switch availability {
        // `on-demand` is the *strongest* arrangement, not a caveat: the token
        // is minted when a request actually arrives, so there is no standing
        // credential to steal.
        case "present", "on-demand": return Theme.green
        case "empty", "missing": return Theme.orange
        default: return .gray
        }
    }

    private var explanation: String {
        switch availability {
        case "present": return "The source resolves to a value right now."
        case "on-demand":
            return "Minted when a matching request arrives — no standing token exists."
        case "empty": return "The source resolves, but to an empty value."
        case "missing": return "The source does not resolve. Requests go out unauthenticated."
        default: return availability
        }
    }
}

// MARK: - Passthrough

private struct ProxyPassthroughCard: View {
    let config: ProxyConfiguration

    var body: some View {
        GlassCard(
            title: "What is not intercepted",
            subtitle: "Relayed end-to-end — the proxy cannot read it.",
            systemImage: "lock.shield"
        ) {
            if config.passthroughHosts.isEmpty {
                Text("No host is explicitly pinned to passthrough.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Text(config.passthroughHosts.joined(separator: ", "))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text(
                "Everything not matched by a rule above is relayed end-to-end: TLS terminates "
                    + "at the origin, not here, so the proxy sees only the destination. "
                    + "Interception is the exception, not the default."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - CA

private struct ProxyCaCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(
            title: "Guest trust",
            subtitle: "Rewriting headers on HTTPS means terminating TLS, which the guest must trust.",
            systemImage: "checkmark.seal.fill"
        ) {
            if let ca = model.proxyCa {
                MetricRow(label: "CA sha256", value: ca.fingerprint)
                if let dir = ca.scopeDir {
                    MetricRow(label: "Read from", value: dir)
                }
                if !ca.isFromDaemon {
                    // A CA is per-workspace, and this process's idea of the
                    // workspace need not be the running guest's. Installing the
                    // wrong one is silent: the installer compares what it wrote
                    // against the fingerprint it was handed, so it agrees with
                    // itself and reports success while TLS fails in the guest.
                    ProvenanceWarning(
                        text: "This CA was resolved by the app, not by the process running "
                            + "the guest. If they disagree, installing it makes the guest "
                            + "trust a certificate nothing signs with — and the installer "
                            + "would still report success."
                    )
                }
            } else {
                Text("No workspace CA yet — it is generated on first use.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Text(
                "There is no shared filesystem to copy a certificate through — that is I1 "
                    + "working, not a gap — so the installer is typed at the guest's console. "
                    + "The guest hashes what it received before running any of it, then "
                    + "prints whether its trust store actually accepts the CA. The console "
                    + "is the proof it took."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                Button {
                    model.installProxyCaInGuest()
                } label: {
                    Label("Install CA in guest", systemImage: "arrow.down.doc.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(
                    model.proxyCa == nil || model.status.state != .running || model.isInstallingCa
                )

                if model.isInstallingCa {
                    ProgressView().controlSize(.small)
                }

                if model.status.state != .running {
                    Text("Start a sandbox first.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }
}

// MARK: - Check

private struct ProxyCheckCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        GlassCard(
            title: "Test a rule",
            subtitle: "A real request, plus the same request with injection off.",
            systemImage: "checkmark.circle.badge.questionmark"
        ) {
            HStack(spacing: 10) {
                TextField("host", text: $model.proxyCheckHost)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 240)
                TextField("path", text: $model.proxyCheckPath)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 160)
                Button {
                    Task { await model.runProxyCheck() }
                } label: {
                    Label("Run test", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isCheckingProxy || model.proxyCheckHost.isEmpty)
                if model.isCheckingProxy { ProgressView().controlSize(.small) }
            }

            Text(
                "Pick a path whose answer depends on the credential — `/user` on "
                    + "api.github.com answers 200 authenticated and 401 not. Against a path "
                    + "that answers the same either way this test cannot prove anything, and "
                    + "it will say so rather than showing a tick."
            )
            .font(.caption)
            .foregroundStyle(.tertiary)
            .fixedSize(horizontal: false, vertical: true)

            if let result = model.proxyCheck {
                Divider()
                ProxyCheckResultView(result: result)
            }
        }
    }
}

private struct ProxyCheckResultView: View {
    let result: ProxyCheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: verdictSymbol)
                    .font(.title3)
                    .foregroundStyle(verdictTint)
                VStack(alignment: .leading, spacing: 3) {
                    Text(verdictTitle).font(.headline)
                    Text(verdictDetail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(verdictTint.opacity(0.11), in: RoundedRectangle(cornerRadius: 16, style: .continuous))

            MetricRow(label: "Destination", value: "\(result.host):\(result.port)\(result.path)")
            if let address = result.address {
                MetricRow(label: "Resolved", value: address)
            }
            MetricRow(label: "Disposition", value: result.disposition)
            if let status = result.originStatus {
                MetricRow(label: "Origin said", value: status)
            }
            if let tls = result.tls {
                MetricRow(label: "TLS", value: tls)
            }

            if !result.audit.isEmpty {
                Text("DECISION LOG")
                    .font(.system(size: 10, weight: .black))
                    .foregroundStyle(.secondary)
                ForEach(result.audit) { event in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: event.injected ? "key.fill" : "arrow.right")
                            .font(.caption2)
                            .foregroundStyle(event.injected ? Theme.purple : .secondary)
                            .frame(width: 14)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(event.detail)
                                .font(.system(.caption, design: .monospaced))
                                .fixedSize(horizontal: false, vertical: true)
                            Text(event.destination)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        Spacer(minLength: 0)
                    }
                }
            }
        }
    }

    private var verdictTitle: String {
        switch result.verdict {
        case .provesInjection: return "The credential reached the origin"
        case .inconclusive: return "This run proved nothing"
        case .unreachable: return "Could not reach the host"
        case .relayed: return "Relayed end-to-end, not intercepted"
        case .noControl: return "Reachable — but no control run"
        }
    }

    private var verdictDetail: String {
        switch result.verdict {
        case let .provesInjection(without):
            return "Without injection the same request got \(without), with it "
                + "\(result.originStatus ?? "a different answer"). The difference is the proof: "
                + "the guest sent nothing, and the origin still authenticated it."
        case let .inconclusive(why):
            return why
        case let .unreachable(error):
            return error
        case .relayed:
            return "No rule matches this host, so the proxy did not terminate TLS — it saw the "
                + "destination and nothing else. Reachability is confirmed."
        case .noControl:
            return "The request succeeded, but without a control run there is nothing to "
                + "compare it against."
        }
    }

    private var verdictTint: Color {
        switch result.verdict {
        case .provesInjection: return Theme.green
        case .relayed: return Theme.cyan
        case .inconclusive, .noControl: return Theme.orange
        case .unreachable: return Theme.orange
        }
    }

    private var verdictSymbol: String {
        switch result.verdict {
        case .provesInjection: return "checkmark.seal.fill"
        case .relayed: return "arrow.left.arrow.right.circle.fill"
        case .inconclusive, .noControl: return "questionmark.circle.fill"
        case .unreachable: return "xmark.octagon.fill"
        }
    }
}

// MARK: - Empty state

private struct ProxyNotConfigured: View {
    /// Nil when `chm` itself could not be reached — which is a different
    /// thing from "no rules", and must not be rendered as reassurance.
    let config: ProxyConfiguration?

    private var hasAnswer: Bool { config != nil }

    /// A guest that is running right now with no proxy is a live finding. The
    /// same words about an idle library root are a placeholder, and reading one
    /// as the other is how a reader concludes a sandbox is safe when nothing
    /// has been assessed.
    private var isLive: Bool { config?.describesRunningVm ?? false }

    private var headline: String {
        guard hasAnswer else { return "Could not read the proxy config" }
        return isLive
            ? "This sandbox has no credential proxy"
            : "No credential proxy configured"
    }

    private var detail: String {
        guard hasAnswer else {
            return "chm did not answer. Treat this as unknown rather than as "
                + "\"nothing is intercepted\"."
        }
        let consequence =
            "No traffic is intercepted, and no credential is injected. A guest that "
            + "needs a secret has to hold it itself — which is exactly what the "
            + "proxy exists to avoid."
        return isLive
            ? "The running sandbox was checked, and it configures no rules. " + consequence
            : consequence
    }

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: hasAnswer ? "key.slash.fill" : "questionmark.circle.fill")
                .font(.system(size: 50))
                .foregroundStyle(hasAnswer ? Theme.cyan : Theme.orange)
            Text(headline)
                .font(.title2.weight(.bold))
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)

            if hasAnswer {
                // Naming the directory is the whole value of this line: rules
                // dropped in the library root are read by nothing, because a
                // guest's workspace is its own folder.
                VStack(spacing: 4) {
                    if let dir = config?.scopeDir {
                        Text("Rules would be read from \(dir)/proxy-rules.json")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                    }
                    Text("Put `proxy-rules.json` there, or set CHM_PROXY_RULES.")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: 620)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 320)
    }
}
