// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest
@testable import GimbalLocalApp

/// Quitting the app must stop the daemon the app started (#360).
///
/// The bug had two halves and needed both: nothing terminated `chm serve` on
/// quit, and the daemon would never reap itself. An orphan holds the
/// process-global HVF slot, so the next `chm run` fails `HV_BUSY` with nothing
/// on screen to blame, and the next launch adopts the orphan and silently pins
/// the previous library.
final class QuitDispositionTests: XCTestCase {
    private func guestRecord(pid: Int32, label: String) -> RunRecord {
        RunRecord(
            pid: pid,
            kind: .run,
            label: label,
            source: "test",
            startedAtMs: 0,
            vcpus: 2,
            memoryMib: 2048
        )
    }

    /// The app adopts an already running daemon rather than starting a second
    /// one. Killing an engine the user started in a terminal would be acting
    /// unannounced on their behalf, so "did we start it" is the question, not
    /// "is one reachable".
    func testAnAdoptedDaemonIsNotOursToStop() {
        XCTAssertEqual(
            QuitDisposition.decide(startedDaemon: false, runningGuests: []),
            .nothingToStop
        )
        XCTAssertEqual(
            QuitDisposition.decide(
                startedDaemon: false,
                runningGuests: [guestRecord(pid: 1, label: "ubuntu")]
            ),
            .nothingToStop,
            "a daemon this app did not start stays up even with guests on it"
        )
    }

    /// The plain case, and the one the leak was made of.
    func testOurOwnIdleDaemonIsStopped() {
        XCTAssertEqual(
            QuitDisposition.decide(startedDaemon: true, runningGuests: []),
            .stopDaemon
        )
    }

    /// #192/#195: do not stop a running guest without saying so.
    func testRunningGuestsAreNamedRatherThanKilledSilently() {
        let disposition = QuitDisposition.decide(
            startedDaemon: true,
            runningGuests: [
                guestRecord(pid: 10, label: "ubuntu-noble"),
                guestRecord(pid: 11, label: "browser"),
            ]
        )
        XCTAssertEqual(disposition, .confirm(running: ["ubuntu-noble", "browser"]))
    }

    /// The prompt has to name the guests. "Some guests are running" gives the
    /// user no basis for the choice the dialog is asking them to make.
    func testTheConfirmationNamesEveryGuest() {
        let message = QuitDisposition.confirmationMessage(
            running: ["ubuntu-noble", "browser"]
        )
        XCTAssertTrue(message.contains("ubuntu-noble"), message)
        XCTAssertTrue(message.contains("browser"), message)
        XCTAssertTrue(message.contains("2 guests are"), message)

        let single = QuitDisposition.confirmationMessage(running: ["only-one"])
        XCTAssertTrue(single.contains("1 guest is"), single)
    }

    /// A test that only exercised `decide` would pass against the original bug,
    /// because the bug was that **nothing called it**. This reads the app's own
    /// source so the hook cannot quietly go missing again.
    func testTheAppActuallyConsultsTheDispositionOnQuit() throws {
        let source = try Self.appSource("GimbalLocalApp.swift")

        for (needle, why) in [
            (
                "func applicationShouldTerminate",
                "the app implements no termination hook again, so chm serve is "
                    + "reparented to launchd and runs forever (#360)"
            ),
            (
                "QuitDisposition.decide",
                "quit no longer asks what should happen to the daemon, so the "
                    + "running-guest and adopted-daemon cases are unguarded"
            ),
            (
                "stopDaemonAndWait",
                "quit no longer awaits the shutdown; a detached Task loses the "
                    + "race against app exit, which is the leak itself"
            ),
            (
                "appDelegate.model = model",
                "the delegate never receives the model, so it takes the "
                    + "nothingToStop branch every time and stops nothing"
            ),
        ] {
            XCTAssertTrue(source.contains(needle), "GimbalLocalApp.swift: \(why)")
        }
    }

    /// `--idle-exit` is not a daemon idle timer, and treating it as one would
    /// have shipped a different bug: `idle_exit_secs` reaches only the guest
    /// run loop, where it ends a **guest** after console silence. Passing a
    /// non-zero value would kill quiet guests and still leak the daemon.
    func testIdleExitGovernsGuestsRatherThanTheDaemon() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let serve = try String(
            contentsOf: repo.appending(path: "chm/src/serve.rs"), encoding: .utf8
        )
        XCTAssertTrue(
            serve.contains("Outcome::Idle(opts.idle_exit_secs)"),
            "chm/src/serve.rs no longer resolves --idle-exit to a guest Outcome. "
                + "If it became a daemon-level timer, the quit hook can be "
                + "reconsidered; until then it must not be mistaken for one."
        )
    }

    /// `decide` is only ever as good as the flag it is handed, and every other
    /// test here passes that flag as a literal. Mutating `startedDaemon` to
    /// return `true` unconditionally left all six of them green while the app
    /// would have killed a daemon somebody else started.
    @MainActor
    func testAFreshModelHasStartedNoDaemon() {
        XCTAssertFalse(
            AppModel().startedDaemon,
            "a model that has spawned nothing must not claim it started a daemon, "
                + "or quitting stops one the CLI or a previous launch owns (#360)"
        )
    }

    /// The behavioural test above cannot see the likelier regression: reading
    /// `daemonPID`, which is also set for a daemon the app merely adopted
    /// (AppModel.swift, the `guard daemonProcess == nil` adoption path). A
    /// fresh model has neither, so both spellings pass it.
    func testStartedDaemonAsksWhetherThisAppSpawnedTheProcess() throws {
        let source = try Self.appSource("AppModel.swift")
        XCTAssertTrue(
            source.contains("var startedDaemon: Bool { daemonProcess != nil }"),
            "AppModel.swift: startedDaemon must test the handle to a process this app "
                + "spawned. daemonPID is also populated when the app adopts a daemon "
                + "started elsewhere, so reading it would make quit stop somebody "
                + "else's daemon without saying so (#192, #195)"
        )
    }

    /// These guards pin the structure of a call site, not its behaviour: they
    /// can see that quit still asks, never that it asks correctly.
    private static func appSource(_ name: String) throws -> String {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // GimbalLocalAppTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // GimbalLocal
            .deletingLastPathComponent()  // app
            .deletingLastPathComponent()  // repo root
        return try String(
            contentsOf: repo.appending(path: "app/GimbalLocal/Sources/GimbalLocalApp/\(name)"),
            encoding: .utf8
        )
    }
}
