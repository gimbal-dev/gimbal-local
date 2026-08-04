import SwiftUI

/// A guided editor for `proxy-rules.json`.
///
/// The reason this screen exists is narrower than "the CLI is inconvenient".
/// The credential design rests on one property — **the rule file names where a
/// secret comes from, never the secret itself** — and a hand-written JSON file
/// gives a reader no hint that this matters. The obvious thing to write, if you
/// have only seen the schema, is a `token` field with your token in it.
///
/// So the builder is not a JSON text box with syntax colouring. It offers no
/// field that can hold a secret value, because `ProxyRuleDraft.Source` has no
/// case that can carry one. The safe shape is the only shape you can express
/// here, and the trade-off of each source is stated where you pick it rather
/// than in a document you would have to go and find.
///
/// Before anything is written, the generated document is handed to the real
/// `chm` binary for validation. A Swift reimplementation of the parser would
/// drift from the Rust one and start accepting files the engine refuses; the
/// engine's own answer is the only one worth showing.
struct CredentialRuleBuilder: View {
    /// Where a written file would land. Nil means we could not resolve it, in
    /// which case writing is not offered — silently choosing a directory would
    /// put rules somewhere nothing reads them.
    let scopeDir: String?
    let chmPath: String
    var onWritten: (() -> Void)?

    @Environment(\.dismiss) private var dismiss

    @State private var drafts: [ProxyRuleDraft] = [ProxyRuleDraft.githubExample()]
    @State private var selection: Int = 0
    @State private var verdict: ProxyRuleValidator.Verdict = .unchecked
    @State private var checking = false
    @State private var writeError: String?
    @State private var wroteTo: String?

    private var draft: ProxyRuleDraft {
        get { drafts.indices.contains(selection) ? drafts[selection] : ProxyRuleDraft() }
        nonmutating set {
            guard drafts.indices.contains(selection) else { return }
            drafts[selection] = newValue
            verdict = .unchecked
        }
    }

    private var json: String {
        ProxyRuleDraft.render(rules: drafts, label: "built in Gimbal Local")
    }

    private var allProblems: [String] {
        drafts.enumerated().flatMap { index, d in
            d.problems.map { drafts.count > 1 ? "Rule \(index + 1): \($0)" : $0 }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                editor
                    .frame(minWidth: 380, idealWidth: 430)
                preview
                    .frame(minWidth: 320)
            }
            Divider()
            footer
        }
        .frame(minWidth: 820, minHeight: 620)
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Attach a credential at the network edge")
                .font(.title3.weight(.bold))
            Text(
                "The sandbox never receives the secret. It makes an ordinary HTTPS request; "
                    + "chm adds the header on the way out, from a source that stays on this Mac."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }

    // MARK: - Editor

    private var editor: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if drafts.count > 1 {
                    Picker("Rule", selection: $selection) {
                        ForEach(drafts.indices, id: \.self) { i in
                            Text(drafts[i].name.isEmpty ? "Rule \(i + 1)" : drafts[i].name).tag(i)
                        }
                    }
                    .pickerStyle(.segmented)
                }

                field("Name", help: "Appears in the audit log, so make it recognisable.") {
                    TextField("github", text: binding(\.name))
                }

                field(
                    "Hosts",
                    help: "Only these destinations are intercepted. One per line, or comma "
                        + "separated. `*.example.com` covers subdomains; a bare `*` is refused."
                ) {
                    TextEditor(text: binding(\.hosts))
                        .font(.system(.body, design: .monospaced))
                        .frame(height: 58)
                        .overlay(
                            RoundedRectangle(cornerRadius: 5)
                                .stroke(Color.secondary.opacity(0.25))
                        )
                }

                sourceSection
                schemeSection

                DisclosureGroup("Advanced") {
                    VStack(alignment: .leading, spacing: 14) {
                        field("Ports", help: "Defaults to 443. Comma separated.") {
                            TextField("443", text: binding(\.ports))
                        }
                        field("Header", help: "Defaults to Authorization.") {
                            TextField("Authorization", text: binding(\.header))
                        }
                        Toggle("Allow plaintext HTTP to these hosts", isOn: binding(\.allowCleartext))
                        Text(
                            "Off by default, and worth leaving off: a credential on a cleartext "
                                + "connection is readable by anything on the path."
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.top, 8)
                }
                .font(.callout.weight(.medium))
            }
            .padding(16)
        }
    }

    private var sourceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Where the secret comes from")
                .font(.callout.weight(.semibold))

            Picker(
                "",
                selection: Binding(
                    get: { draft.source.kind },
                    set: { draft.source = .make($0, draft.source.reference) }
                )
            ) {
                ForEach(ProxyRuleDraft.Source.Kind.allCases, id: \.self) { kind in
                    Text(kind.label).tag(kind)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            TextField(
                draft.source.kind.prompt,
                text: Binding(
                    get: { draft.source.reference },
                    set: { draft.source = .make(draft.source.kind, $0) }
                )
            )
            .font(.system(.body, design: .monospaced))

            Text.authored(draft.source.kind.tradeoff)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // The single most important sentence on this screen. Someone who
            // misreads the field above and pastes a token has put a secret into
            // a file, which is the failure this whole design exists to prevent.
            Label(
                "This is a reference, not the secret. Nothing you type here is a token —"
                    + " it names where chm should look, on this Mac, at the moment it is needed.",
                systemImage: "lock.shield"
            )
            .font(.caption)
            .foregroundStyle(Theme.cyan)
            .fixedSize(horizontal: false, vertical: true)

            if draft.source.kind == .command {
                field("Cache for (seconds)", help: "Optional. Avoids re-running a slow command.") {
                    TextField("300", text: binding(\.ttlSeconds))
                }
            }
        }
    }

    private var schemeSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("How it is sent")
                .font(.callout.weight(.semibold))
            Picker("", selection: binding(\.scheme)) {
                ForEach(ProxyRuleDraft.Scheme.allCases, id: \.self) { s in
                    Text(s.label).tag(s)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            Text.authored(draft.scheme.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if draft.scheme == .basic {
                field("Username", help: "Defaults to x-access-token, which is what GitHub expects.") {
                    TextField("x-access-token", text: binding(\.username))
                }
            }
            if draft.scheme == .template {
                field("Template", help: "Must contain {secret}, or nothing would be injected.") {
                    TextField("token {secret}", text: binding(\.template))
                        .font(.system(.body, design: .monospaced))
                }
            }
        }
    }

    // MARK: - Preview

    private var preview: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("proxy-rules.json")
                    .font(.callout.weight(.semibold))
                Spacer()
                Button {
                    #if os(macOS)
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(json, forType: .string)
                    #endif
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Divider()

            ScrollView {
                Text(json)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }

            Divider()
            verdictBar
        }
    }

    @ViewBuilder
    private var verdictBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !allProblems.isEmpty {
                ForEach(allProblems, id: \.self) { p in
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(Theme.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                switch verdict {
                case .unchecked:
                    Label(
                        "Not checked yet. Verify runs the real chm parser, not a copy of it.",
                        systemImage: "circle.dashed"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                case let .accepted(summary):
                    Label("chm accepted this file", systemImage: "checkmark.seal.fill")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(Theme.green)
                    Text(summary)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                case let .refused(message):
                    Label("chm refused this file", systemImage: "xmark.octagon.fill")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.red)
                    Text(message)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                case let .unavailable(why):
                    Label("Could not run chm — treat this as unverified", systemImage: "questionmark.circle.fill")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(Theme.orange)
                    Text(why)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }

            if let wroteTo {
                Label("Written to \(wroteTo)", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(Theme.green)
                    .textSelection(.enabled)
            }
            if let writeError {
                Label(writeError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: 10) {
            Button {
                drafts.append(ProxyRuleDraft())
                selection = drafts.count - 1
                verdict = .unchecked
            } label: {
                Label("Add rule", systemImage: "plus")
            }

            if drafts.count > 1 {
                Button(role: .destructive) {
                    drafts.remove(at: selection)
                    selection = min(selection, drafts.count - 1)
                    verdict = .unchecked
                } label: {
                    Label("Remove", systemImage: "minus")
                }
            }

            Spacer()

            if checking {
                ProgressView().controlSize(.small)
            }

            Button("Verify with chm") { verify() }
                .disabled(!allProblems.isEmpty || checking)

            Button(writeButtonTitle) { write() }
                .buttonStyle(.borderedProminent)
                .disabled(!canWrite)
                .help(
                    scopeDir == nil
                        ? "No workspace directory resolved, so there is nowhere to write."
                        : "Writes proxy-rules.json into the sandbox workspace."
                )

            Button("Close") { dismiss() }
        }
        .padding(16)
    }

    private var writeButtonTitle: String {
        scopeDir == nil ? "No workspace" : "Save to workspace"
    }

    /// Deliberately gated on a *successful* chm verdict rather than on local
    /// validation. Writing a file the engine will refuse produces a sandbox
    /// that fails at boot with no clue why, which is worse than not writing.
    private var canWrite: Bool {
        guard scopeDir != nil, allProblems.isEmpty, !checking else { return false }
        if case .accepted = verdict { return true }
        return false
    }

    // MARK: - Actions

    private func verify() {
        checking = true
        writeError = nil
        let doc = json
        let binary = chmPath
        Task.detached {
            let result = ProxyRuleValidator.validate(json: doc, chmPath: binary)
            await MainActor.run {
                verdict = result
                checking = false
            }
        }
    }

    private func write() {
        guard let dir = scopeDir else { return }
        let path = (dir as NSString).appendingPathComponent("proxy-rules.json")
        do {
            try FileManager.default.createDirectory(
                atPath: dir, withIntermediateDirectories: true
            )
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            wroteTo = path
            writeError = nil
            onWritten?()
        } catch {
            writeError = "Could not write \(path): \(error.localizedDescription)"
        }
    }

    private func field(
        _ title: String,
        help: String,
        @ViewBuilder content: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.callout.weight(.semibold))
            content()
            Text.authored(help)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<ProxyRuleDraft, T>) -> Binding<T> {
        Binding(
            get: { draft[keyPath: keyPath] },
            set: {
                var d = draft
                d[keyPath: keyPath] = $0
                draft = d
            }
        )
    }

}

/// Maps a chm verdict onto the view's own enum. Split out so it can be
/// tested without a view: the interesting cases are "refused" versus
/// "could not run", which must never be collapsed into each other.
enum ProxyRuleValidator {
    /// The three outcomes, kept distinct on purpose. "chm refused this" and
    /// "chm could not be run" look alike in a UI and mean opposite things:
    /// one is a finding about the file, the other is an absence of any
    /// finding at all, and collapsing them would let an unverified document
    /// read as a checked one.
    enum Verdict: Equatable {
        case unchecked
        /// chm compiled the document and reported this summary.
        case accepted(String)
        /// chm refused it. Its own words, not a paraphrase.
        case refused(String)
        /// chm could not be run at all, which is not the same as a refusal.
        case unavailable(String)
    }

    static func validate(json: String, chmPath: String) -> Verdict {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gimbal-rules-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tmp) }
        do {
            try json.write(to: tmp, atomically: true, encoding: .utf8)
        } catch {
            return .unavailable("Could not write a temporary file: \(error.localizedDescription)")
        }

        guard FileManager.default.isExecutableFile(atPath: chmPath) else {
            return .unavailable("chm not found at \(chmPath)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: chmPath)
        process.arguments = ["proxy", "show", "--rules", tmp.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return .unavailable("Could not run chm: \(error.localizedDescription)")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if process.terminationStatus == 0 {
            return .accepted(trimmed.isEmpty ? "Compiled with no findings." : trimmed)
        }
        return .refused(trimmed.isEmpty ? "chm exited \(process.terminationStatus)." : trimmed)
    }
}
