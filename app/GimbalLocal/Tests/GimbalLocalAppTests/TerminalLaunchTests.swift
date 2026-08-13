// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest

@testable import GimbalLocalApp

/// What the user is told when "Open terminal" will not work.
///
/// #192 gave Start a named refusal and left this button — the one people
/// actually press — silent. These assert the *sentences*, because the defect was
/// never in the decision (it was always right) and always in the delivery.
final class TerminalLaunchTests: XCTestCase {
    // MARK: - the common case

    func testNothingToSayWhenEverythingIsReady() {
        XCTAssertTrue(TerminalLaunch.blockers(.init()).isEmpty)
    }

    // MARK: - chm

    func testAMissingChmIsNamedWithItsPath() {
        let out = TerminalLaunch.blockers(.init(chm: .missing, chmPath: "/nope/chm"))
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].message.contains("/nope/chm"), out[0].message)
        XCTAssertTrue(out[0].remedy.contains("Settings"), out[0].remedy)
    }

    func testAChmThatIsAFolderSaysSoRatherThanSayingMissing() {
        let dir = TerminalLaunch.blockers(.init(chm: .populatedDirectory, chmPath: "/opt/chm"))
        XCTAssertEqual(dir.count, 1)
        XCTAssertTrue(dir[0].message.contains("folder"), dir[0].message)
        // "not there" would send someone looking for a file that is right where
        // they put it — the wrong remedy, delivered confidently.
        XCTAssertFalse(dir[0].message.contains("not there"), dir[0].message)
    }

    func testAChmWithoutTheExecuteBitGetsChmodNotReinstall() {
        let out = TerminalLaunch.blockers(.init(chm: .notExecutable, chmPath: "/bin/chm"))
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].remedy.contains("chmod"), out[0].remedy)
    }

    func testAnEmptyChmPathStillProducesAReadableSentence() {
        let out = TerminalLaunch.blockers(.init(chm: .missing, chmPath: ""))
        XCTAssertEqual(out.count, 1)
        XCTAssertFalse(out[0].message.hasPrefix(" "), out[0].message)
        XCTAssertTrue(out[0].message.contains("chm path"), out[0].message)
    }

    // MARK: - the terminal-specific refusals Start does not have

    func testAMissingImageIsARefusalOfItsOwn() {
        let out = TerminalLaunch.blockers(
            .init(snapshotName: "graviton-2", snapshotInLibrary: false)
        )
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].message.contains("graviton-2"), out[0].message)
        XCTAssertNil(out[0].remedyLabel, "the app cannot restore an image for you")
    }

    func testAMissingTerminalAppIsARefusalOfItsOwn() {
        let out = TerminalLaunch.blockers(.init(terminalAppPresent: false))
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].message.contains("Terminal.app"), out[0].message)
    }

    // MARK: - the one genuinely shared with Start

    func testTheSlotRefusalIsReusedNotRewritten() {
        let slot = SlotContention.evaluate(holderName: "graviton-1", thisSandboxIsLive: false)
        let out = TerminalLaunch.blockers(.init(slot: slot))
        XCTAssertEqual(out.count, 1)
        // Same sentence Start shows: two wordings for one constraint would drift.
        XCTAssertEqual(out[0].message, slot?.message)
        XCTAssertEqual(out[0].remedyLabel, "Stop graviton-1")
    }

    func testALiveSandboxIsNotBlockedByItself() {
        let slot = SlotContention.evaluate(holderName: nil, thisSandboxIsLive: true)
        XCTAssertTrue(TerminalLaunch.blockers(.init(slot: slot)).isEmpty)
    }

    // MARK: - the property the issue actually asked for

    func testEveryBlockerIsReportedNotJustTheFirst() {
        // Clearing one problem and finding another waiting is how a fixable
        // setup comes to feel like a broken app.
        let out = TerminalLaunch.blockers(
            .init(
                slot: SlotContention.evaluate(holderName: "other", thisSandboxIsLive: false),
                snapshotName: "img",
                snapshotInLibrary: false,
                chm: .missing,
                chmPath: "/nope/chm",
                terminalAppPresent: false
            )
        )
        XCTAssertEqual(out.count, 4)
    }

    func testTheEngineIsReportedBeforeTheTransientSlot() {
        let out = TerminalLaunch.blockers(
            .init(
                slot: SlotContention.evaluate(holderName: "other", thisSandboxIsLive: false),
                chm: .missing,
                chmPath: "/nope/chm"
            )
        )
        // A held slot resolves itself when the other sandbox stops; a missing
        // binary never does. Lead with the one that will still be true tomorrow.
        XCTAssertTrue(out[0].message.contains("/nope/chm"), out[0].message)
        XCTAssertEqual(out.count, 2)
    }

    func testEveryBlockerCarriesARemedy() {
        // A refusal without a way forward is the failure this type exists to end,
        // so this holds for every branch rather than for the ones we remembered.
        let all: [TerminalLaunch.Preconditions] = [
            .init(chm: .missing, chmPath: "/x"),
            .init(chm: .notExecutable, chmPath: "/x"),
            .init(chm: .emptyDirectory, chmPath: "/x"),
            .init(chm: .populatedDirectory, chmPath: "/x"),
            .init(snapshotName: "i", snapshotInLibrary: false),
            .init(terminalAppPresent: false),
            .init(slot: SlotContention.evaluate(holderName: "h", thisSandboxIsLive: false)),
        ]
        for p in all {
            for blocker in TerminalLaunch.blockers(p) {
                XCTAssertFalse(blocker.message.isEmpty)
                XCTAssertFalse(blocker.remedy.isEmpty, blocker.message)
            }
        }
    }

    func testOnlyTheSlotOffersAButton() {
        // A button that restates advice promises an action the app cannot take.
        let noButton: [TerminalLaunch.Preconditions] = [
            .init(chm: .missing, chmPath: "/x"),
            .init(snapshotName: "i", snapshotInLibrary: false),
            .init(terminalAppPresent: false),
        ]
        for p in noButton {
            XCTAssertTrue(TerminalLaunch.blockers(p).allSatisfy { $0.remedyLabel == nil })
        }
        let slot = TerminalLaunch.blockers(
            .init(slot: SlotContention.evaluate(holderName: "h", thisSandboxIsLive: false))
        )
        XCTAssertNotNil(slot.first?.remedyLabel)
    }
}

/// The call site, not the value type.
///
/// V9.5c's lesson, learned the expensive way: mutating a function is not the
/// same as mutating its call site. `TerminalLaunch.blockers` can be perfect and
/// still be consulted by nobody, which is precisely the shape of the bug being
/// fixed — the decision was always right, the delivery was missing.
final class TerminalLaunchWiringTests: XCTestCase {
    @MainActor
    private func modelWithOneSandbox() -> (AppModel, Sandbox) {
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let sandbox = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        return (model, sandbox)
    }

    @MainActor
    func testAModelWithAUsableSetupReportsNoBlockers() {
        let (model, sandbox) = modelWithOneSandbox()
        model.settings.chmPath = "/bin/sh"  // a real executable file
        XCTAssertTrue(model.terminalLaunchBlockers(for: sandbox).isEmpty)
    }

    @MainActor
    func testAnImageMissingFromTheLibraryReachesTheBlockerList() {
        let (model, sandbox) = modelWithOneSandbox()
        model.settings.chmPath = "/bin/sh"
        model.snapshots = []  // the library lost it
        let out = model.terminalLaunchBlockers(for: sandbox)
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].message.contains("ubuntu"), out[0].message)
    }

    @MainActor
    func testTheChmPathIsProbedWithTheSameProbeSettingsUses() {
        let (model, sandbox) = modelWithOneSandbox()
        model.settings.chmPath = "/definitely/not/here/chm"
        let out = model.terminalLaunchBlockers(for: sandbox)
        XCTAssertEqual(out.count, 1)
        XCTAssertTrue(out[0].message.contains("/definitely/not/here/chm"), out[0].message)
    }

    @MainActor
    func testABlockedConnectRefusesVisiblyAndStartsNothing() {
        // The bug: this pressed, did nothing, changed no state, and wrote its
        // reason to a log nobody opens.
        let (model, sandbox) = modelWithOneSandbox()
        model.settings.chmPath = "/definitely/not/here/chm"

        model.connect(to: sandbox)

        XCTAssertNotNil(model.terminalLaunchFailure, "the press must say something")
        XCTAssertNil(model.interactiveSandboxID, "and must not claim a session it did not open")
        XCTAssertNil(model.activeLocalSandboxID)
    }

    @MainActor
    func testAStaleRefusalDoesNotSurviveTheNextAttempt() {
        // A refusal that outlives its cause is its own kind of lie: the user
        // fixes the path and is still told the old thing.
        //
        // Both attempts here are blocked, on purpose — the success path opens a
        // real Terminal.app and is proved on hardware instead. What this pins is
        // that the message belongs to *this* press.
        let (model, sandbox) = modelWithOneSandbox()
        model.settings.chmPath = "/definitely/not/here/chm"
        model.connect(to: sandbox)
        let first = model.terminalLaunchFailure

        model.settings.chmPath = "/bin/sh"
        model.snapshots = []  // a different problem entirely
        model.connect(to: sandbox)

        XCTAssertNotNil(model.terminalLaunchFailure)
        XCTAssertNotEqual(model.terminalLaunchFailure, first)
        XCTAssertTrue(model.terminalLaunchFailure?.contains("ubuntu") == true)
    }
}
