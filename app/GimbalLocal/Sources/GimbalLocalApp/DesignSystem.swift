// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI
import AppKit

// MARK: - Theme

enum Theme {
    static let cyan = Color(red: 0.18, green: 0.78, blue: 0.96)
    static let green = Color(red: 0.25, green: 0.86, blue: 0.55)
    static let purple = Color(red: 0.62, green: 0.43, blue: 1.0)
    static let orange = Color(red: 1.0, green: 0.60, blue: 0.22)
    static let terminalText = Color(red: 0.74, green: 0.99, blue: 0.89)
    static let terminalBackground = Color(red: 0.02, green: 0.05, blue: 0.09)

    static func color(for tone: EngineTone) -> Color {
        switch tone {
        case .active: return green
        case .ready: return cyan
        case .offline: return orange
        case .unknown: return .gray
        }
    }

    static func color(for state: Sandbox.State) -> Color {
        switch state {
        case .running: return green
        case .starting: return cyan
        case .stopped: return .gray
        case .failed: return orange
        }
    }

    static let logoGradient = LinearGradient(
        colors: [cyan, purple],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let iconGradient = LinearGradient(
        colors: [cyan.opacity(0.95), purple.opacity(0.95)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let blueprintGradient = LinearGradient(
        colors: [Color(red: 0.12, green: 0.38, blue: 0.72), cyan],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let heroGradient = LinearGradient(
        colors: [
            Color(red: 0.04, green: 0.08, blue: 0.18),
            Color(red: 0.09, green: 0.18, blue: 0.38),
            Color(red: 0.24, green: 0.13, blue: 0.42),
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    static let sidebarBackground = LinearGradient(
        colors: [
            Color(nsColor: .controlBackgroundColor),
            Color(nsColor: .windowBackgroundColor),
        ],
        startPoint: .top,
        endPoint: .bottom
    )
    static var dashboardBackground: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.055, green: 0.075, blue: 0.12),
                    Color(red: 0.085, green: 0.105, blue: 0.17),
                    Color(nsColor: .windowBackgroundColor),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            Circle()
                .fill(cyan.opacity(0.18))
                .frame(width: 420, height: 420)
                .blur(radius: 90)
                .offset(x: -320, y: -260)
            Circle()
                .fill(purple.opacity(0.16))
                .frame(width: 520, height: 520)
                .blur(radius: 110)
                .offset(x: 420, y: -130)
        }
    }
}

// MARK: - App icon

/// The bundled rounded app icon, loaded once. Falls back to the system app icon
/// (and then a gradient glyph) so previews and non-bundle runs still render.
enum AppIconImage {
    @MainActor static let shared: NSImage? = {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let image = NSImage(contentsOf: url) {
            return image
        }
        return NSImage(named: "NSApplicationIcon")
    }()
}

struct AppIconView: View {
    var size: CGFloat = 44

    var body: some View {
        if let image = AppIconImage.shared {
            Image(nsImage: image)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
                .shadow(color: Theme.cyan.opacity(0.35), radius: size * 0.22, y: size * 0.10)
        } else {
            RoundedRectangle(cornerRadius: size * 0.32, style: .continuous)
                .fill(Theme.logoGradient)
                .frame(width: size, height: size)
                .overlay {
                    Image(systemName: "gyroscope")
                        .font(.system(size: size * 0.5, weight: .bold))
                        .foregroundStyle(.white)
                }
        }
    }
}

// MARK: - Status atoms

struct StatusDot: View {
    let color: Color
    var size: CGFloat = 9

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .overlay {
                Circle().stroke(.white.opacity(0.35), lineWidth: 0.5)
            }
            .shadow(color: color.opacity(0.7), radius: 3)
    }
}

struct StatusPill: View {
    let text: String
    let systemImage: String
    let color: Color

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.system(.caption, design: .rounded).weight(.bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(color.opacity(0.28), in: Capsule())
            .overlay {
                Capsule().stroke(.white.opacity(0.20), lineWidth: 1)
            }
    }
}

struct SandboxStateBadge: View {
    let state: Sandbox.State

    var body: some View {
        let color = Theme.color(for: state)
        HStack(spacing: 6) {
            StatusDot(color: color, size: 7)
            Text(state.label)
                .font(.caption.weight(.bold))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(color.opacity(0.14), in: Capsule())
    }
}

struct LocationBadge: View {
    let location: SandboxLocation

    var body: some View {
        let color = location == .local ? Theme.cyan : Theme.purple
        Label(location.label, systemImage: location.symbol)
            .font(.caption2.weight(.bold))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.13), in: Capsule())
    }
}

// MARK: - Cards & metrics

struct GlassCard<Content: View>: View {
    let title: String
    let subtitle: String
    let systemImage: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Theme.iconGradient)
                        .frame(width: 42, height: 42)
                    Image(systemName: systemImage)
                        .foregroundStyle(.white)
                        .font(.system(size: 18, weight: .bold))
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.title3.bold())
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay {
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(.white.opacity(0.14), lineWidth: 1)
                }
        }
        .shadow(color: .black.opacity(0.11), radius: 24, y: 14)
    }
}

struct BigMetric: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .black))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 22, weight: .heavy, design: .rounded))
                .foregroundStyle(color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

struct MetricRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)
            Text(value)
                .font(.callout)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(2)
                .textSelection(.enabled)
        }
    }
}

// MARK: - Terminal / log pane

struct TerminalPane: View {
    enum Mode: Equatable {
        case console(isStreaming: Bool)
        case activity
    }

    let text: String
    var mode: Mode = .console(isStreaming: false)

    /// The console pane accepts keystrokes (see `ConsoleExpander`), so the badge
    /// points at the input row rather than claiming the stream is read-only.
    static let consoleBadgeText = "TYPE BELOW"

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text(text)
                        .font(.system(isCompact ? .caption : .body, design: .monospaced))
                        .foregroundStyle(Theme.terminalText)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(16)
                    Color.clear.frame(height: 1).id("terminal-bottom")
                }
            }
            .onChange(of: text) {
                withAnimation(.easeOut(duration: 0.18)) {
                    proxy.scrollTo("terminal-bottom", anchor: .bottom)
                }
            }
        }
        .background {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Theme.terminalBackground)
                .overlay(alignment: .topLeading) {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(streamColor)
                            .frame(width: 9, height: 9)
                            .shadow(color: streamColor.opacity(0.9), radius: isStreaming ? 8 : 0)
                        Text(headerText)
                            .font(.system(size: 10, weight: .black, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.72))
                        if case .console = mode {
                            Text(TerminalPane.consoleBadgeText)
                                .font(.system(size: 10, weight: .black, design: .monospaced))
                                .foregroundStyle(Theme.purple)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 3)
                                .background(Theme.purple.opacity(0.16), in: Capsule())
                        }
                    }
                    .padding(13)
                }
        }
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var isCompact: Bool { mode == .activity }

    private var isStreaming: Bool {
        if case let .console(isStreaming) = mode { return isStreaming }
        return false
    }

    private var streamColor: Color {
        isStreaming ? Theme.green : Theme.cyan.opacity(0.65)
    }

    private var headerText: String {
        switch mode {
        case let .console(isStreaming):
            return isStreaming ? "SERIAL STREAM LIVE" : "SERIAL STREAM"
        case .activity:
            return "ACTIVITY LOG"
        }
    }
}

// MARK: - New sandbox control

/// A menu that creates a sandbox from one of the library's snapshot images.
/// Shared by the sidebar, the Sandboxes page, and the empty state so "new
/// sandbox" behaves identically everywhere.
struct NewSandboxMenu: View {
    @EnvironmentObject private var model: AppModel
    var prominent = false

    var body: some View {
        let menu = Menu {
            if model.snapshots.isEmpty {
                Text("No snapshot images in the library")
            } else {
                ForEach(model.snapshots) { snapshot in
                    Button {
                        model.newSandbox(fromSnapshotNamed: snapshot.name)
                    } label: {
                        Text("\(snapshot.name)  ·  \(snapshot.vcpus) vCPU, \(snapshot.ramMib) MiB")
                    }
                }
            }
        } label: {
            Label("New sandbox", systemImage: "plus")
        }
        .menuStyle(.button)
        .fixedSize()

        if prominent {
            menu.buttonStyle(.borderedProminent).controlSize(.large)
        } else {
            menu.buttonStyle(.bordered)
        }
    }
}
