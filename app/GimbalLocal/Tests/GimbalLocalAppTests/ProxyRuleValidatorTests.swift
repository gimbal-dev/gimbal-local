import XCTest

@testable import GimbalLocalApp

/// Tests for the layer that turns a `chm` exit code into something a person
/// reads. The interesting property is not "does valid JSON pass" — it is that
/// **"chm refused this file" and "chm could not be run" stay distinct**. They
/// look almost identical in a UI and mean opposite things: one is a finding
/// about the document, the other is the absence of any finding, and a builder
/// that renders the second as the first would let someone write a file
/// believing it had been checked when nothing checked it.
final class ProxyRuleValidatorTests: XCTestCase {
    /// The real binary, or nil when it has not been built. Nil skips rather
    /// than fails: a missing build artifact is not a defect in this code.
    private var chmPath: String? {
        let candidates = [
            FileManager.default.currentDirectoryPath + "/../../target/debug/chm",
            FileManager.default.currentDirectoryPath + "/../../../target/debug/chm",
            NSHomeDirectory()
                + "/StudioProjects/copilot-worktrees/cloud-hypervisor-mac"
                + "/nebuk89-cuddly-robot/target/debug/chm",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func testAMissingBinaryIsUnavailableRatherThanRefused() {
        let verdict = ProxyRuleValidator.validate(
            json: "{}",
            chmPath: "/nonexistent/definitely/not/chm"
        )
        guard case .unavailable = verdict else {
            return XCTFail("a missing binary must not read as a refusal: \(verdict)")
        }
    }

    func testAValidDocumentIsAccepted() throws {
        guard let chmPath else { throw XCTSkip("chm not built") }
        var draft = ProxyRuleDraft.githubExample()
        draft.source = .environment("GH_TOKEN")
        draft.ttlSeconds = ""
        let verdict = ProxyRuleValidator.validate(
            json: ProxyRuleDraft.render(rules: [draft], label: "test"),
            chmPath: chmPath
        )
        guard case .accepted = verdict else {
            return XCTFail("chm should accept a well-formed rule: \(verdict)")
        }
    }

    func testAnInvalidDocumentIsRefusedWithChmsOwnWords() throws {
        guard let chmPath else { throw XCTSkip("chm not built") }
        // A wildcard injection host: refused by the engine, and the reason is
        // worth surfacing verbatim because it explains the security model.
        let json = """
            {
              "version": 1,
              "rules": [{"name": "everything", "hosts": ["*"], "env": "T"}]
            }
            """
        let verdict = ProxyRuleValidator.validate(
            json: json,
            chmPath: chmPath
        )
        guard case let .refused(message) = verdict else {
            return XCTFail("chm must refuse a wildcard host: \(verdict)")
        }
        XCTAssertTrue(
            message.lowercased().contains("*") || message.lowercased().contains("host"),
            "the refusal should carry chm's own explanation: \(message)"
        )
    }

    /// The default the builder opens with must itself be acceptable. A starting
    /// point that the engine refuses would teach the wrong shape on first
    /// contact, which is the opposite of the point of this screen.
    func testTheBuilderDefaultIsAcceptedByChm() throws {
        guard let chmPath else { throw XCTSkip("chm not built") }
        let verdict = ProxyRuleValidator.validate(
            json: ProxyRuleDraft.render(
                rules: [ProxyRuleDraft.githubExample()],
                label: "built in Gimbal Local"
            ),
            chmPath: chmPath
        )
        guard case .accepted = verdict else {
            return XCTFail("the default rule the UI ships must compile: \(verdict)")
        }
    }

    func testTheDefaultCarriesNoSecretValue() {
        let draft = ProxyRuleDraft.githubExample()
        // The starting point must name a source, not hold a value. If this
        // ever becomes an `.environment` with a literal or a template with a
        // baked token, the screen stops teaching the property it exists for.
        guard case let .command(reference) = draft.source else {
            return XCTFail("the default should reference a command")
        }
        XCTAssertEqual(reference, "gh auth token")
        let json = ProxyRuleDraft.render(rules: [draft], label: nil)
        XCTAssertFalse(json.contains("ghp_"), "no token-shaped literal may appear")
        XCTAssertTrue(json.contains("\"exec\""), "the source must be by reference")
    }
}
