// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// Builds a `proxy-rules.json` document without a text editor.
///
/// ## Why this type cannot hold a secret
///
/// The proxy's entire claim is that the guest never holds the credential. A
/// rule file is therefore **not** where a secret lives — it names *where the
/// secret comes from* (`env:GH_TOKEN`, a file, a command to run) and `chm`
/// resolves that on the host, at the moment a request leaves.
///
/// A builder UI is the obvious place for that distinction to quietly collapse:
/// a "token" field, helpfully saved, and the secret is now in a JSON file in a
/// workspace the guest can read. So `Source` below carries a *reference* and
/// has no case that carries a value. There is no field to type a token into,
/// because the safe design is the only one expressible.
struct ProxyRuleDraft: Equatable {
    /// Names the rule in the audit log, so a reader can tell which rule fired.
    var name: String = ""
    /// Newline- or comma-separated host patterns.
    var hosts: String = ""
    var ports: String = ""
    var header: String = "Authorization"
    var scheme: Scheme = .bearer
    /// Only meaningful for `.basic`; forge tokens conventionally use a
    /// placeholder username, which is why `chm` defaults it.
    var username: String = ""
    /// Only meaningful for `.template`; must contain `{secret}`.
    var template: String = ""
    var source: Source = .environment("")
    /// Cache lifetime for an `exec` secret.
    var ttlSeconds: String = ""
    /// Sending a credential over plaintext HTTP is refused unless asked for
    /// explicitly, because it is almost always a mistake rather than a choice.
    var allowCleartext: Bool = false

    enum Scheme: String, CaseIterable, Equatable {
        case bearer, basic, template

        var label: String {
            switch self {
            case .bearer: "Bearer token"
            case .basic: "Basic auth"
            case .template: "Custom template"
            }
        }

        var explanation: String {
            switch self {
            case .bearer: "Sends `Authorization: Bearer <secret>`."
            case .basic: "Sends `Authorization: Basic <base64 of username:secret>`."
            case .template: "You write the header value; `{secret}` is replaced."
            }
        }
    }

    /// Where the secret comes from. Every case holds a **reference**, resolved
    /// on the host at request time -- never the secret itself.
    enum Source: Equatable {
        /// An environment variable of the `chm` process.
        case environment(String)
        /// A file on the host, read at request time.
        case file(String)
        /// A command run on the host; its stdout is the secret.
        case command(String)

        var kind: Kind {
            switch self {
            case .environment: .environment
            case .file: .file
            case .command: .command
            }
        }

        var reference: String {
            switch self {
            case let .environment(v), let .file(v), let .command(v): v
            }
        }

        static func make(_ kind: Kind, _ reference: String) -> Source {
            switch kind {
            case .environment: .environment(reference)
            case .file: .file(reference)
            case .command: .command(reference)
            }
        }

        enum Kind: String, CaseIterable {
            case environment, file, command

            var label: String {
                switch self {
                case .environment: "Environment variable"
                case .file: "File on this Mac"
                case .command: "Command output"
                }
            }

            var prompt: String {
                switch self {
                case .environment: "GH_TOKEN"
                case .file: "~/.secrets/token"
                case .command: "gh auth token"
                }
            }

            /// Said in the builder, where the decision is actually made.
            var tradeoff: String {
                switch self {
                case .environment:
                    "Read from the environment `chm` was started with. Simplest, "
                        + "and the value never touches disk."
                case .file:
                    "Read from the host filesystem at request time. The guest "
                        + "cannot see this path -- it is outside the sandbox."
                case .command:
                    "Run on the host and its output used as the secret. Use this "
                        + "for short-lived tokens; set a lifetime so it is refreshed."
                }
            }
        }
    }

    // MARK: - Validation

    /// What is wrong, in the order a person would fix it. Empty means the draft
    /// is worth handing to `chm`, which remains the authority -- this exists so
    /// the obvious mistakes are named while typing, not to re-implement the
    /// compiler in Swift.
    var problems: [String] {
        var out: [String] = []

        if name.trimmed.isEmpty {
            out.append("Give the rule a name, so the audit log can identify which rule fired.")
        }
        if hostList.isEmpty {
            out.append("Add at least one host, or the rule can never match.")
        }
        for host in hostList where host.contains("://") {
            out.append("Host \u{201C}\(host)\u{201D} looks like a URL. Use just the hostname, e.g. api.github.com.")
        }
        for host in hostList where host.contains("/") {
            out.append("Host \u{201C}\(host)\u{201D} contains a path. Rules match on host and port only.")
        }
        if header.trimmed.isEmpty {
            out.append("Name the header the credential is attached to (usually Authorization).")
        }
        for port in portStrings where UInt16(port) == nil {
            out.append("\u{201C}\(port)\u{201D} is not a port number.")
        }
        if scheme == .template, !template.contains("{secret}") {
            out.append("The template has no {secret} placeholder, so nothing would be injected.")
        }
        if source.reference.trimmed.isEmpty {
            switch source.kind {
            case .environment: out.append("Name the environment variable holding the secret.")
            case .file: out.append("Give the path to the file holding the secret.")
            case .command: out.append("Give the command that prints the secret.")
            }
        }
        if case .environment = source, source.reference.contains("=") {
            // The likeliest way someone puts a secret in the file by accident.
            out.append(
                "That looks like NAME=value. Enter only the variable name — the "
                    + "value stays in your environment and never enters this file."
            )
        }
        if !ttlSeconds.trimmed.isEmpty, UInt64(ttlSeconds.trimmed) == nil {
            out.append("Lifetime must be a whole number of seconds.")
        }
        if !ttlSeconds.trimmed.isEmpty, source.kind != .command {
            out.append("A lifetime only applies to a command, which is the only source that is re-run.")
        }
        return out
    }

    var isValid: Bool { problems.isEmpty }

    var hostList: [String] {
        hosts
            .split(whereSeparator: { $0 == "," || $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    var portStrings: [String] {
        ports
            .split(whereSeparator: { $0 == "," || $0.isNewline || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: - Emission

    /// The rule as it appears inside the document's `rules` array.
    ///
    /// Key order is fixed rather than alphabetical so a generated file reads
    /// top-down the way the rule was described: what it is, where it applies,
    /// what it sends, where that comes from.
    func ruleObject() -> [(String, Any)] {
        var out: [(String, Any)] = [
            ("name", name.trimmed),
            ("hosts", hostList),
        ]
        let portNumbers = portStrings.compactMap { UInt16($0) }
        if !portNumbers.isEmpty {
            out.append(("ports", portNumbers.map(Int.init)))
        }
        let trimmedHeader = header.trimmed
        if !trimmedHeader.isEmpty, trimmedHeader.caseInsensitiveCompare("Authorization") != .orderedSame {
            out.append(("header", trimmedHeader))
        }
        if scheme != .bearer {
            out.append(("scheme", scheme.rawValue))
        }
        if scheme == .basic, !username.trimmed.isEmpty {
            out.append(("username", username.trimmed))
        }
        if scheme == .template {
            out.append(("template", template))
        }
        switch source {
        case let .environment(v): out.append(("env", v.trimmed))
        case let .file(v): out.append(("file", v.trimmed))
        case let .command(v): out.append(("exec", Self.splitCommand(v)))
        }
        if source.kind == .command, let ttl = UInt64(ttlSeconds.trimmed) {
            out.append(("ttl_secs", Int(ttl)))
        }
        if allowCleartext {
            out.append(("allow_cleartext", true))
        }
        return out
    }

    /// A whole document containing this one rule, ready to write.
    func documentJSON(label: String? = nil, passthrough: [String] = []) -> String {
        Self.render(rules: [self], label: label, passthrough: passthrough)
    }

    /// A starting point that is deliberately real rather than a placeholder.
    ///
    /// It uses `gh auth token` because that is the source with the best
    /// properties on a developer's Mac — short-lived, refreshed by the tool
    /// that owns it, and never written to a file we would then have to protect.
    /// Someone who changes nothing still gets a safe rule.
    static func githubExample() -> ProxyRuleDraft {
        var draft = ProxyRuleDraft()
        draft.name = "github"
        draft.hosts = "api.github.com\ngithub.com"
        draft.scheme = .bearer
        draft.source = .command("gh auth token")
        draft.ttlSeconds = "300"
        return draft
    }

    /// Rendered by hand rather than via `JSONSerialization` because that sorts
    /// keys or emits them in hash order, and a file a person is meant to read
    /// and edit should keep the order the fields were explained in.
    static func render(
        rules: [ProxyRuleDraft],
        label: String?,
        passthrough: [String] = []
    ) -> String {
        var lines = ["{", "  \"version\": 1,"]
        if let label, !label.trimmed.isEmpty {
            lines.append("  \"label\": \(quote(label.trimmed)),")
        }
        lines.append("  \"rules\": [")
        for (index, rule) in rules.enumerated() {
            lines.append("    {")
            let fields = rule.ruleObject()
            for (fieldIndex, field) in fields.enumerated() {
                let comma = fieldIndex == fields.count - 1 ? "" : ","
                lines.append("      \(quote(field.0)): \(literal(field.1))\(comma)")
            }
            lines.append(index == rules.count - 1 ? "    }" : "    },")
        }
        if passthrough.isEmpty {
            lines.append("  ]")
        } else {
            lines.append("  ],")
            lines.append("  \"passthrough\": \(literal(passthrough))")
        }
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    /// Splits a command the way a shell would for the simple cases, so
    /// `gh auth token` becomes `["gh","auth","token"]`. Quoted arguments are
    /// honoured; `chm` execs the array directly and never runs a shell, so
    /// there is no shell to inject into.
    static func splitCommand(_ input: String) -> [String] {
        var args: [String] = []
        var current = ""
        var quote: Character?
        var started = false
        for character in input {
            if let active = quote {
                if character == active {
                    quote = nil
                } else {
                    current.append(character)
                }
            } else if character == "\"" || character == "'" {
                quote = character
                started = true
            } else if character.isWhitespace {
                if started || !current.isEmpty {
                    args.append(current)
                    current = ""
                    started = false
                }
            } else {
                current.append(character)
            }
        }
        if started || !current.isEmpty {
            args.append(current)
        }
        return args
    }

    private static func quote(_ value: String) -> String {
        var out = "\""
        for character in value.unicodeScalars {
            switch character {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\t": out += "\\t"
            case "\r": out += "\\r"
            default:
                if character.value < 0x20 {
                    out += String(format: "\\u%04x", character.value)
                } else {
                    out.unicodeScalars.append(character)
                }
            }
        }
        return out + "\""
    }

    private static func literal(_ value: Any) -> String {
        switch value {
        case let text as String: quote(text)
        case let flag as Bool: flag ? "true" : "false"
        case let number as Int: String(number)
        case let list as [String]: "[" + list.map(quote).joined(separator: ", ") + "]"
        case let list as [Int]: "[" + list.map(String.init).joined(separator: ", ") + "]"
        default: quote(String(describing: value))
        }
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
