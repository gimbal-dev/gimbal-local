// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation
import Testing

@testable import GimbalLocalApp

/// The value: does the app agree with the daemon about which library is live?
@Suite("LibraryAgreement")
struct LibraryAgreementTests {
    @Test("agreement is silent")
    func testMatchingPathsProduceNothing() {
        #expect(LibraryAgreement.evaluate(daemonLibrary: "/a/lib", configured: "/a/lib") == nil)
    }

    @Test("a disagreement names both paths")
    func testDisagreementNamesBoth() throws {
        let state = try #require(
            LibraryAgreement.evaluate(daemonLibrary: "/served/lib", configured: "/mine/lib")
        )
        #expect(state.serving == "/served/lib")
        #expect(state.configured == "/mine/lib")
        #expect(state.note.contains("/served/lib"))
        #expect(state.remedy.contains("/mine/lib"))
    }

    /// The remedy must name *both* ways out. Only offering "change your setting"
    /// tells someone to abandon the library they meant to use.
    @Test("the remedy offers stopping the engine and matching the setting")
    func testRemedyOffersBothDirections() throws {
        let state = try #require(
            LibraryAgreement.evaluate(daemonLibrary: "/served", configured: "/mine")
        )
        #expect(state.remedy.lowercased().contains("stop the engine"))
        #expect(state.remedy.contains("set the library here"))
    }

    /// The note must not read as data loss. The snapshots are fine; they are
    /// simply not the ones being listed.
    @Test("the remedy says nothing is lost")
    func testRemedySaysNothingIsLost() throws {
        let state = try #require(
            LibraryAgreement.evaluate(daemonLibrary: "/served", configured: "/mine")
        )
        #expect(state.remedy.contains("Nothing is lost"))
    }

    /// A daemon that predates the field, or an unreachable one, says nothing.
    /// Reporting that as a disagreement would warn about a mismatch that may
    /// not exist — worse than the silence it replaces.
    @Test("a daemon that did not say is not reported as disagreeing")
    func testMissingDaemonLibraryIsNotADisagreement() {
        #expect(LibraryAgreement.evaluate(daemonLibrary: nil, configured: "/mine") == nil)
        #expect(LibraryAgreement.evaluate(daemonLibrary: "", configured: "/mine") == nil)
    }

    @Test("no configured path is nothing to compare")
    func testEmptyConfiguredIsNotADisagreement() {
        #expect(LibraryAgreement.evaluate(daemonLibrary: "/served", configured: "") == nil)
    }

    /// `/a/lib` and `/a/./lib` are the same directory. Reporting them as a
    /// disagreement would produce a warning nobody can act on, because the two
    /// paths already agree.
    @Test("paths are standardized before comparing")
    func testEquivalentPathsAgree() {
        #expect(LibraryAgreement.evaluate(daemonLibrary: "/a/./lib", configured: "/a/lib") == nil)
        #expect(LibraryAgreement.evaluate(daemonLibrary: "/a/b/../lib", configured: "/a/lib") == nil)
    }

    /// A shared prefix is not a match: `/a/lib` and `/a/lib-old` are different
    /// libraries and must be reported.
    @Test("a sibling with a shared prefix disagrees")
    func testSharedPrefixIsStillADisagreement() {
        #expect(LibraryAgreement.evaluate(daemonLibrary: "/a/lib-old", configured: "/a/lib") != nil)
    }
}

/// The wiring: does the app stop contradicting itself on screen?
@Suite("LibraryAgreement wiring")
@MainActor
struct LibraryAgreementWiringTests {
    private func model(daemonLibrary: String?, configured: String) -> AppModel {
        let m = AppModel()
        m.settings.libraryPath = configured
        var status = SandboxStatus.disconnected
        status.library = daemonLibrary
        m.status = status
        return m
    }

    @Test("the model surfaces a disagreement")
    func testModelSurfacesDisagreement() {
        let m = model(daemonLibrary: "/served", configured: "/mine")
        #expect(m.libraryAgreement?.serving == "/served")
    }

    @Test("the model is silent when they agree")
    func testModelSilentOnAgreement() {
        let m = model(daemonLibrary: "/same", configured: "/same")
        #expect(m.libraryAgreement == nil)
    }

    /// The bug, exactly as it appeared: a banner predicting an empty list above
    /// a sidebar that was not empty. The prediction is what must go.
    @Test("the overtaken empty-list notice is withdrawn")
    func testEmptyListNoticeIsWithdrawnWhenADaemonServesElsewhere() {
        let m = model(daemonLibrary: "/served", configured: "/mine")
        m.settingsNotices = [.presentButEmpty(field: .libraryPath, path: "/mine")]

        #expect(m.visibleSettingsNotices.isEmpty)
        #expect(m.libraryAgreement != nil)
    }

    /// Only the *prediction* is withdrawn. A library that does not exist is
    /// still worth saying, and a notice about a different setting is untouched.
    @Test("other notices survive a disagreement")
    func testUnrelatedNoticesSurvive() {
        let m = model(daemonLibrary: "/served", configured: "/mine")
        m.settingsNotices = [
            .presentButEmpty(field: .libraryPath, path: "/mine"),
            .presentButEmpty(field: .localImagesPath, path: "/imgs"),
            .missingKept(field: .libraryPath, saved: "/mine"),
        ]

        let visible = m.visibleSettingsNotices
        #expect(visible.count == 2)
        #expect(visible.contains { $0.field == .localImagesPath })
        #expect(visible.contains { if case .missingKept = $0 { return true } else { return false } })
    }

    /// Without a disagreement the notice is correct and must still be shown —
    /// an empty library really does produce an empty list.
    @Test("the empty-list notice stays when the daemon agrees")
    func testEmptyListNoticeSurvivesWhenLibrariesAgree() {
        let m = model(daemonLibrary: "/mine", configured: "/mine")
        m.settingsNotices = [.presentButEmpty(field: .libraryPath, path: "/mine")]

        #expect(m.visibleSettingsNotices.count == 1)
    }

    /// A daemon that never reported a library must not cause a correct notice
    /// to be withdrawn — that would restore the original silence.
    @Test("a silent daemon does not withdraw the notice")
    func testSilentDaemonKeepsTheNotice() {
        let m = model(daemonLibrary: nil, configured: "/mine")
        m.settingsNotices = [.presentButEmpty(field: .libraryPath, path: "/mine")]

        #expect(m.visibleSettingsNotices.count == 1)
        #expect(m.libraryAgreement == nil)
    }
}

/// The wire: the app can only compare what the daemon sends.
@Suite("Status decodes the daemon library")
struct StatusLibraryDecodingTests {
    @Test("library is decoded from an idle daemon")
    func testIdleStatusCarriesLibrary() throws {
        let status = try ChmClient.parseStatus(#"{"state":"idle","library":"/a/lib"}"#)
        #expect(status.library == "/a/lib")
    }

    @Test("library is decoded from a running daemon")
    func testRunningStatusCarriesLibrary() throws {
        let status = try ChmClient.parseStatus(
            #"{"state":"running","name":"x","uptime_seconds":3,"console_bytes":0,"library":"/a/lib"}"#
        )
        #expect(status.library == "/a/lib")
        #expect(status.state == .running)
    }

    /// A daemon built before this field must still parse. The app connects to
    /// whichever `chm serve` owns the socket, which is not necessarily one it
    /// built or started.
    @Test("an older daemon without the field still parses")
    func testStatusWithoutLibraryStillParses() throws {
        let status = try ChmClient.parseStatus(#"{"state":"idle"}"#)
        #expect(status.library == nil)
        #expect(status.state == .idle)
    }

    /// The app *reads* cold-boot images; `chm image build` *writes* them. Two
    /// programs, one rule, and until V9.7 they disagreed: `chm` wrote to
    /// `~/gimbal-images` while the app looked in `<repo>/images`, a directory
    /// that had never existed. The New sandbox menu therefore said "No local
    /// images yet" while three images sat on disk — a refusal that was
    /// perfectly worded and completely wrong.
    ///
    /// This reads `chm`'s own source rather than restating its answer, so the
    /// two cannot drift apart again without something going red. A restated
    /// constant would have passed happily through the whole bug.
    @Test("the app looks for images where chm writes them")
    func testImageLibraryAgreesWithChm() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // GimbalLocalAppTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // GimbalLocal
            .deletingLastPathComponent()  // app
            .deletingLastPathComponent()  // repo root
        let source = try String(
            contentsOf: repo.appending(path: "chm/src/oci/image.rs"), encoding: .utf8
        )

        // `chm`'s images_library(): $GIMBAL_IMAGES, else $HOME/gimbal-images.
        #expect(
            source.contains(#"env::var_os("GIMBAL_IMAGES")"#),
            "chm no longer reads GIMBAL_IMAGES; the app still does"
        )
        #expect(
            source.contains(#"home.join("gimbal-images")"#),
            "chm's fallback moved; AppSettings.defaultLocalImagesPath must follow"
        )

        let home = FileManager.default.homeDirectoryForCurrentUser.appending(path: "gimbal-images")
        #expect(AppSettings.defaults.localImagesPath == home.path)
    }
}
