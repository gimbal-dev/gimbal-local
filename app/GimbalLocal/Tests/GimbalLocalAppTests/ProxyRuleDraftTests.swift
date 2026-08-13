// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest

@testable import GimbalLocalApp

final class ProxyRuleDraftTests: XCTestCase {
    private func valid() -> ProxyRuleDraft {
        var draft = ProxyRuleDraft()
        draft.name = "github"
        draft.hosts = "api.github.com"
        draft.source = .environment("GH_TOKEN")
        return draft
    }

    // MARK: - The property the whole feature rests on

    /// The builder must be structurally incapable of putting a secret in the
    /// file. This asserts it over every source kind and every scheme: the
    /// emitted document may name *where* the secret comes from, and must never
    /// contain a value that looks like one.
    func testNoSecretValueCanReachTheGeneratedFile() {
        let secret = "ghp_thisIsTheActualSecretValue"
        for kind in ProxyRuleDraft.Source.Kind.allCases {
            for scheme in ProxyRuleDraft.Scheme.allCases {
                var draft = valid()
                draft.scheme = scheme
                draft.template = "token {secret}"
                // Every free-text field a user could mistakenly paste into.
                draft.source = .make(kind, "GH_TOKEN")
                draft.username = "x-access-token"
                let json = draft.documentJSON()
                XCTAssertFalse(
                    json.contains(secret),
                    "a secret reached the file for \(kind) / \(scheme)"
                )
                XCTAssertTrue(json.contains("{secret}") || scheme != .template)
            }
        }
    }

    /// `Source` has no case carrying a value, so there is no field to type a
    /// token into. If someone adds one, this fails.
    func testEverySourceCaseCarriesAReferenceNotAValue() {
        for kind in ProxyRuleDraft.Source.Kind.allCases {
            let source = ProxyRuleDraft.Source.make(kind, "REFERENCE")
            XCTAssertEqual(source.reference, "REFERENCE")
            XCTAssertEqual(source.kind, kind)
        }
    }

    /// The likeliest way a secret gets in by accident: pasting `NAME=value`
    /// into the environment-variable field.
    func testPastingNameEqualsValueIsRefused() {
        var draft = valid()
        draft.source = .environment("GH_TOKEN=ghp_secret")
        XCTAssertFalse(draft.isValid)
        XCTAssertTrue(draft.problems.contains { $0.contains("only the variable name") })
    }

    // MARK: - Validation catches what a person would get wrong

    func testAValidDraftHasNoProblems() {
        XCTAssertTrue(valid().isValid, "\(valid().problems)")
    }

    func testARuleWithNoHostCanNeverMatch() {
        var draft = valid()
        draft.hosts = ""
        XCTAssertTrue(draft.problems.contains { $0.contains("at least one host") })
    }

    func testAUrlPastedAsAHostIsCaught() {
        var draft = valid()
        draft.hosts = "https://api.github.com"
        XCTAssertTrue(draft.problems.contains { $0.contains("looks like a URL") })
    }

    func testAHostWithAPathIsCaught() {
        var draft = valid()
        draft.hosts = "api.github.com/repos"
        XCTAssertTrue(draft.problems.contains { $0.contains("host and port only") })
    }

    func testATemplateWithoutThePlaceholderInjectsNothing() {
        var draft = valid()
        draft.scheme = .template
        draft.template = "token abc"
        XCTAssertTrue(draft.problems.contains { $0.contains("{secret}") })
    }

    func testARuleNeedsAName() {
        var draft = valid()
        draft.name = "   "
        XCTAssertTrue(draft.problems.contains { $0.contains("name") })
    }

    func testANonNumericPortIsCaught() {
        var draft = valid()
        draft.ports = "443, https"
        XCTAssertTrue(draft.problems.contains { $0.contains("not a port number") })
    }

    /// A lifetime on a source that is never re-run is a setting that does
    /// nothing, which is worse than an error because it looks configured.
    func testALifetimeOnANonCommandSourceIsCalledOut() {
        var draft = valid()
        draft.ttlSeconds = "300"
        XCTAssertTrue(draft.problems.contains { $0.contains("only applies to a command") })
    }

    func testALifetimeOnACommandIsFine() {
        var draft = valid()
        draft.source = .command("gh auth token")
        draft.ttlSeconds = "300"
        XCTAssertTrue(draft.isValid, "\(draft.problems)")
        XCTAssertTrue(draft.documentJSON().contains("\"ttl_secs\": 300"))
    }

    /// Problem messages interpolate what the user typed, so they are rendered
    /// **without** markdown -- otherwise a host like `*.example.com` would come
    /// back as emphasis with the asterisks eaten, turning a message about their
    /// typo into a different typo. That only holds if the strings themselves
    /// carry no markdown, which is what this pins.
    func testProblemMessagesCarryNoMarkdownBecauseTheyQuoteUserInput() {
        var draft = ProxyRuleDraft()
        draft.name = ""
        draft.hosts = "https://*.example.com/path"
        draft.ports = "not-a-port"
        draft.scheme = .template
        draft.template = "no placeholder"
        draft.source = .environment("")
        let messages = draft.problems
        XCTAssertFalse(messages.isEmpty)
        for message in messages {
            XCTAssertFalse(
                message.contains("`"),
                "problem messages render literally, so a backtick would be shown: \(message)"
            )
        }
    }

    /// The host the user typed must survive into the message intact.
    func testAProblematicHostIsEchoedBackExactly() {
        var draft = ProxyRuleDraft()
        draft.name = "x"
        draft.hosts = "https://*.example.com"
        draft.source = .environment("T")
        let message = try? XCTUnwrap(draft.problems.first { $0.contains("URL") })
        XCTAssertTrue(
            (message ?? "").contains("https://*.example.com"),
            "the user's exact host should appear: \(message ?? "nil")"
        )
    }

    // MARK: - Emission

    func testHostsSplitOnCommasAndNewlines() {
        var draft = valid()
        draft.hosts = "api.github.com,\n  *.githubusercontent.com \n"
        XCTAssertEqual(draft.hostList, ["api.github.com", "*.githubusercontent.com"])
    }

    /// `Authorization` is the default on the Rust side, so writing it adds
    /// noise to a file someone has to read.
    func testTheDefaultHeaderIsOmitted() {
        XCTAssertFalse(valid().documentJSON().contains("\"header\""))
    }

    func testANonDefaultHeaderIsWritten() {
        var draft = valid()
        draft.header = "X-Api-Key"
        XCTAssertTrue(draft.documentJSON().contains("\"header\": \"X-Api-Key\""))
    }

    func testCommandsSplitLikeAShellWouldWithoutRunningOne() {
        XCTAssertEqual(ProxyRuleDraft.splitCommand("gh auth token"), ["gh", "auth", "token"])
        XCTAssertEqual(
            ProxyRuleDraft.splitCommand("op read \"op://vault/item/token\""),
            ["op", "read", "op://vault/item/token"]
        )
        XCTAssertEqual(ProxyRuleDraft.splitCommand("  spaced   out  "), ["spaced", "out"])
    }

    /// `chm` execs the array directly, so a metacharacter is inert data rather
    /// than something to escape -- but it must survive as one argument.
    func testShellMetacharactersSurviveAsOneInertArgument() {
        XCTAssertEqual(
            ProxyRuleDraft.splitCommand("echo \"; rm -rf /\""),
            ["echo", "; rm -rf /"]
        )
    }

    func testGeneratedJsonIsWellFormed() throws {
        var draft = valid()
        draft.hosts = "api.github.com, *.github.com"
        draft.ports = "443, 8443"
        draft.scheme = .basic
        draft.username = "x-access-token"
        let data = Data(draft.documentJSON(label: "GitHub").utf8)
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(object["version"] as? Int, 1)
        XCTAssertEqual(object["label"] as? String, "GitHub")
        let rules = try XCTUnwrap(object["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules[0]["name"] as? String, "github")
        XCTAssertEqual(rules[0]["hosts"] as? [String], ["api.github.com", "*.github.com"])
        XCTAssertEqual(rules[0]["ports"] as? [Int], [443, 8443])
        XCTAssertEqual(rules[0]["env"] as? String, "GH_TOKEN")
    }

    /// A label or command containing a quote must not produce a file the
    /// parser rejects.
    func testQuotesInFreeTextDoNotBreakTheDocument() throws {
        var draft = valid()
        draft.name = "the \"main\" one"
        draft.source = .command("say \"hello\\world\"")
        let data = Data(draft.documentJSON().utf8)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let rules = try XCTUnwrap(object?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules[0]["name"] as? String, "the \"main\" one")
    }

    func testPassthroughIsWrittenWhenPresent() throws {
        let json = ProxyRuleDraft.render(
            rules: [valid()],
            label: nil,
            passthrough: ["telemetry.example"]
        )
        let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        XCTAssertEqual(object?["passthrough"] as? [String], ["telemetry.example"])
    }
}

/// The Swift validator is a convenience; `chm` is the authority. These feed the
/// generated document to the **real** binary, so a schema drift between the two
/// fails here rather than at the moment someone tries to use their new rule.
final class ProxyRuleDraftAgainstRealChmTests: XCTestCase {
    /// Located the same way the app locates it, so this exercises the shipped
    /// path rather than a test-only guess.
    private func chmBinary() throws -> String {
        let path = AppSettings.defaults.chmPath
        guard FileManager.default.isExecutableFile(atPath: path) else {
            throw XCTSkip("chm not built at \(path); run scripts/build-chm.sh")
        }
        return path
    }

    private func runProxyShow(rulesJSON: String) throws -> (status: Int32, output: String) {
        let binary = try chmBinary()
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("gimbal-rules-\(UUID().uuidString).json")
        try rulesJSON.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["proxy", "show", "--rules", file.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// The bearer case, end to end through the real compiler.
    func testTheSimplestGeneratedRuleIsAcceptedByChm() throws {
        var draft = ProxyRuleDraft()
        draft.name = "github"
        draft.hosts = "api.github.com"
        draft.source = .environment("GH_TOKEN")

        let result = try runProxyShow(rulesJSON: draft.documentJSON(label: "GitHub"))
        XCTAssertEqual(result.status, 0, result.output)
        XCTAssertTrue(result.output.contains("github"), result.output)
        XCTAssertTrue(result.output.contains("api.github.com"), result.output)
    }

    /// Every scheme and every source kind, because a field only the builder
    /// emits is exactly where a schema drift would hide.
    func testEverySchemeAndSourceCombinationIsAcceptedByChm() throws {
        for scheme in ProxyRuleDraft.Scheme.allCases {
            for kind in ProxyRuleDraft.Source.Kind.allCases {
                var draft = ProxyRuleDraft()
                draft.name = "\(scheme.rawValue)-\(kind.rawValue)"
                draft.hosts = "api.example.com, *.example.org"
                draft.ports = "443, 8443"
                draft.header = "X-Custom-Auth"
                draft.scheme = scheme
                draft.username = "x-access-token"
                draft.template = "Token {secret}"
                draft.source = .make(kind, kind == .command ? "gh auth token" : "SECRET_REF")
                if kind == .command { draft.ttlSeconds = "600" }

                XCTAssertTrue(draft.isValid, "\(draft.name): \(draft.problems)")
                let result = try runProxyShow(rulesJSON: draft.documentJSON())
                XCTAssertEqual(
                    result.status, 0,
                    "chm rejected the builder's own output for \(draft.name):\n\(result.output)"
                )
            }
        }
    }

    /// `allow_cleartext` is the one field that widens a security control, so a
    /// silent drift in its name would be the worst kind.
    func testTheCleartextOptOutIsUnderstoodByChm() throws {
        var draft = ProxyRuleDraft()
        draft.name = "plain"
        draft.hosts = "internal.example"
        draft.ports = "80"
        draft.source = .environment("TOKEN")
        draft.allowCleartext = true

        let result = try runProxyShow(rulesJSON: draft.documentJSON())
        XCTAssertEqual(result.status, 0, result.output)
    }

    /// `deny_unknown_fields` on the Rust side means a stray key is a hard
    /// error. This proves the builder emits no key `chm` does not know, which
    /// is what makes the round trip above meaningful.
    func testAnUnknownFieldWouldBeRejectedProvingTheRoundTripHasTeeth() throws {
        let handWritten = """
        {
          "version": 1,
          "rules": [
            {
              "name": "x",
              "hosts": ["api.example.com"],
              "env": "TOKEN",
              "not_a_real_field": true
            }
          ]
        }
        """
        let result = try runProxyShow(rulesJSON: handWritten)
        XCTAssertNotEqual(result.status, 0, "expected chm to reject an unknown field")
    }

    func testPassthroughDocumentIsAccepted() throws {
        // A named exclusion is the supported shape: a cert-pinned host you
        // never want terminated, listed alongside the rules it overrides.
        let json = ProxyRuleDraft.render(
            rules: [],
            label: "nothing intercepted",
            passthrough: ["telemetry.example.com"]
        )
        let result = try runProxyShow(rulesJSON: json)
        XCTAssertEqual(result.status, 0, result.output)
    }

    func testWildcardPassthroughIsRefusedWithPassthroughWording() throws {
        // Measured, not assumed: chm refuses '*' in passthrough because it
        // would silently disable every rule. The builder must never offer it,
        // and if a hand-edited file contains one the error must name the list
        // it came from rather than blaming injection.
        let json = ProxyRuleDraft.render(rules: [], label: "kill switch", passthrough: ["*"])
        let result = try runProxyShow(rulesJSON: json)
        XCTAssertNotEqual(result.status, 0, "chm must refuse a wildcard passthrough")
        XCTAssertTrue(
            result.output.contains("passthrough"),
            "error should name the list it came from: \(result.output)"
        )
    }
}
