// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest
@testable import GimbalLocalApp

/// What the app knows about guests it did not start.
///
/// The reported bug (#225) is that the app said `All sandboxes 0` while a guest
/// it had launched itself was running in a Terminal window. Everything here is
/// a value over plain inputs, so the rules can be checked without a hypervisor,
/// a daemon, or a Terminal.
final class RunningGuestsTests: XCTestCase {
    private func record(
        pid: Int32,
        kind: RunRecord.Kind = .cold,
        label: String = "alpine",
        startedAtMs: UInt64 = 0
    ) -> RunRecord {
        RunRecord(
            pid: pid,
            kind: kind,
            label: label,
            source: "/images/\(label)",
            startedAtMs: startedAtMs,
            vcpus: 2,
            memoryMib: 512
        )
    }

    /// The engine's wire format is the app's input, so it is decoded from a
    /// literal captured off a real `chm ps --json` rather than re-encoded by the
    /// same types that read it — a writer and reader that agree by construction
    /// agree about a bug too (#178, #180).
    func testRealEngineOutputDecodes() {
        let wire = """
        {"runs":[{"pid":79135,"kind":"cold","label":"final-alpine",\
        "source":"/Users/n/gimbal-images/final-alpine","started_at_ms":1786117003793,\
        "vcpus":2,"memory_mib":512}]}
        """
        let runs = ChmClient.parseRunList(wire)
        XCTAssertEqual(runs.count, 1)
        XCTAssertEqual(runs[0].pid, 79135)
        XCTAssertEqual(runs[0].kind, .cold)
        XCTAssertEqual(runs[0].label, "final-alpine")
        XCTAssertEqual(runs[0].vcpus, 2)
        XCTAssertEqual(runs[0].memoryMib, 512)
    }

    /// Garbage must yield nothing rather than take down the refresh that also
    /// fetches snapshots and status.
    func testUnreadableOutputIsEmptyRatherThanFatal() {
        XCTAssertTrue(ChmClient.parseRunList("").isEmpty)
        XCTAssertTrue(ChmClient.parseRunList("No guests running.").isEmpty)
        XCTAssertTrue(ChmClient.parseRunList("{\"runs\":").isEmpty)
    }

    /// A `chm connect` session is registered by the engine *and* tracked here by
    /// session lock. Listing both would show one guest twice.
    func testASessionTheAppAlreadyTracksIsNotListedAgain() {
        let all = [
            record(pid: 100, kind: .connect, label: "graviton-2"),
            record(pid: 200, kind: .cold, label: "alpine"),
        ]
        let out = unattributedRuns(all: all, attributedPIDs: [100])
        XCTAssertEqual(out.map(\.pid), [200], "the tracked session was listed twice")
    }

    /// The case that is the whole bug: a cold boot is a subprocess this app
    /// cannot track, so nothing attributes it and it must survive the filter.
    func testAColdBootIsAlwaysListedBecauseNothingElseShowsIt() {
        let all = [record(pid: 777, kind: .cold, label: "alpine")]
        XCTAssertEqual(unattributedRuns(all: all, attributedPIDs: []).count, 1)
    }

    /// Attribution is by PID, not by label. Two sandboxes can share a directory
    /// name, and a name collision must not silently hide a running guest.
    func testASharedLabelDoesNotHideASecondGuest() {
        let all = [
            record(pid: 100, kind: .connect, label: "alpine"),
            record(pid: 200, kind: .cold, label: "alpine"),
        ]
        let out = unattributedRuns(all: all, attributedPIDs: [100])
        XCTAssertEqual(out.map(\.pid), [200], "a shared label hid a second guest")
    }

    /// A run whose kind we cannot describe is refused by the engine, so the app
    /// never has to guess. Proving it here means the app's own decoder does not
    /// quietly reintroduce a guess of its own.
    func testAnUnknownKindIsNotDecodedIntoSomethingElse() {
        let wire = """
        {"runs":[{"pid":1,"kind":"teleport","label":"a","source":"/s",\
        "started_at_ms":1,"vcpus":1,"memory_mib":1}]}
        """
        XCTAssertTrue(ChmClient.parseRunList(wire).isEmpty)
    }

    func testUptimeReadsInUnitsAPersonUses() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        let r = record(pid: 1, startedAtMs: UInt64(start.timeIntervalSince1970 * 1000))
        XCTAssertEqual(r.uptimeDescription(now: start.addingTimeInterval(9)), "9s")
        XCTAssertEqual(r.uptimeDescription(now: start.addingTimeInterval(605)), "10m")
        XCTAssertEqual(r.uptimeDescription(now: start.addingTimeInterval(7500)), "2h 5m")
        // A clock that disagrees with the engine's must not render a negative
        // age, which reads as a guest starting in the future.
        XCTAssertEqual(r.uptimeDescription(now: start.addingTimeInterval(-60)), "0s")
    }

    /// The reported sentence itself: with a guest running, the page must not
    /// claim there is nothing.
    func testTheEmptyStateDoesNotDenyARunningGuest() {
        let g = FirstRunGuidance.evaluate(
            hasSnapshots: false,
            localImages: [],
            imagesPath: "/images",
            runningGuests: 1
        )
        XCTAssertNotEqual(g.headline, "No sandboxes yet", "the app denied a running guest")
        XCTAssertTrue(g.detail.contains("1 guest is running"), "it did not say what is running")
        XCTAssertTrue(g.canStartSomething)
    }

    /// With nothing running the original guidance is unchanged — the fix adds a
    /// case rather than rewriting the first-run experience V8.5 shipped.
    func testGuidanceIsUnchangedWhenNothingIsRunning() {
        let g = FirstRunGuidance.evaluate(
            hasSnapshots: false,
            localImages: [],
            imagesPath: "/images",
            runningGuests: 0
        )
        XCTAssertEqual(g.headline, "Add an image to get started")
    }

    /// The sidebar section is hidden when empty, so it does not become furniture
    /// that stops being read.
    func testTheSidebarSectionIsConditionalOnThereBeingSomethingToShow() {
        let src = ContentViewSource.text
        XCTAssertTrue(
            src.contains("if !model.unlistedRunningGuests.isEmpty {"),
            "the Running now section is rendered unconditionally"
        )
    }

    /// The run list is polled on a cadence, not only when something else asks.
    ///
    /// A guest is another process: it can appear (started from the CLI, which is
    /// the whole of #225) or vanish (expiry, `exit`, a crash) with the app doing
    /// nothing. Found on hardware — Stop killed the guest and the row stayed on
    /// screen with its uptime still climbing, because the only timer in the view
    /// ticked the label and never re-read the registry.
    func testTheRunListIsPolledOnATimer() {
        let src = ContentViewSource.text
        XCTAssertTrue(
            src.contains("pollRunningGuests"),
            "nothing re-reads the run registry, so a row outlives its process"
        )
        XCTAssertTrue(
            src.contains("Timer.publish(every: 2"),
            "the poll cadence is gone"
        )
    }

    /// The poll is cheap, because it runs forever.
    func testThePollDoesNotDragTheWholeRefreshAlong() {
        let src = AppModelSource.text
        guard let r = src.range(of: "func pollRunningGuests() async {"),
              let end = src.range(of: "\n    }", range: r.upperBound..<src.endIndex)
        else { return XCTFail("pollRunningGuests is gone") }
        let body = String(src[r.upperBound..<end.lowerBound])
        XCTAssertFalse(
            body.contains("refreshLocal"),
            "the 2s poll calls refreshLocal, which shells out four times"
        )
    }

    /// SIGTERM is reported as a request, not as an outcome.
    func testStopDoesNotClaimTheGuestIsGone() {
        let src = AppModelSource.text
        guard let r = src.range(of: "func stopRunningGuest("),
              let end = src.range(of: "\n    }", range: r.upperBound..<src.endIndex)
        else { return XCTFail("stopRunningGuest is gone") }
        let body = String(src[r.upperBound..<end.lowerBound])
        XCTAssertTrue(body.contains("stoppingPIDs.insert"), "the stop is not recorded")
        XCTAssertFalse(
            body.contains("runningGuests.removeAll") || body.contains("refreshLocal"),
            "the row is removed or re-read before the guest has actually gone"
        )
    }

    /// A reused PID does not inherit the previous occupant's "stopping" label.
    func testStoppingIsForgottenWhenTheProcessGoes() {
        let src = AppModelSource.text
        XCTAssertTrue(
            src.contains("stoppingPIDs.formIntersection"),
            "stopped PIDs are never forgotten, so a reused PID reads as stopping"
        )
    }

    /// A PID is shown as a PID, not as a formatted number.
    ///
    /// `help` takes a `LocalizedStringKey`, so an interpolated integer is locale
    /// formatted: pid 92384 rendered as "92,384", which cannot be pasted into
    /// `kill`. Found on screen, not by a test, because the value is correct
    /// everywhere except where it is displayed.
    func testAPidIsNotLocaleFormatted() {
        let src = ContentViewSource.text
        XCTAssertTrue(
            src.contains("pid " + "\\(String(record.pid))"),
            "a PID is interpolated as a number, so it renders with a thousands separator"
        )
    }

    /// `chm ps` is invoked in a form the engine accepts.
    ///
    /// This is the bug hardware found and every parsing test missed: `run`
    /// appended `--socket` to everything, `chm ps` refuses it, and the app got
    /// an empty list — indistinguishable from "nothing is running", which is
    /// precisely the bug being fixed. A test that reads *output* cannot see a
    /// command that never ran.
    func testPsIsNotSentTheDaemonSocket() {
        let argv = ChmClient.argv(for: ["ps", "--json"], socketPath: "/tmp/s.sock")
        XCTAssertEqual(argv, ["ps", "--json"], "chm ps was sent a flag it refuses")
    }

    /// The flag is still appended to everything that does talk to the daemon.
    func testDaemonCommandsStillCarryTheSocket() {
        XCTAssertEqual(
            ChmClient.argv(for: ["ctl", "list", "--json"], socketPath: "/tmp/s.sock"),
            ["ctl", "list", "--json", "--socket", "/tmp/s.sock"]
        )
    }

    /// The empty state actually consults the run count.
    ///
    /// `testTheEmptyStateDoesNotDenyARunningGuest` calls `evaluate` directly, so
    /// it stays green if the *call site* stops passing the count — the failure
    /// this repo has now hit four times (V9.5c, V9.11a, #222, here). Removing
    /// the parameter's default makes the argument mandatory, so dropping it is a
    /// compile error; passing a literal still compiles, and that is what this
    /// catches.
    func testTheEmptyStateCallSiteAsksHowManyGuestsAreRunning() {
        let src = SandboxesViewSource.text
        XCTAssertTrue(
            src.contains("runningGuests: model.unlistedRunningGuests.count"),
            "the empty state no longer asks what is running, so it denies it again"
        )
    }

    /// A guest is stopped by asking, not by killing.
    ///
    /// A source guard because the alternative is signalling a real process in a
    /// unit test. `SIGKILL` would leave RAM describing a filesystem that moved,
    /// which is the state #139 exists to refuse — so the choice of signal is a
    /// correctness property, not a preference.
    func testAGuestIsAskedToStopRatherThanKilled() {
        let src = AppModelSource.text
        XCTAssertTrue(
            src.contains("kill(record.pid, \(("SIG") + "TERM"))"),
            "stopRunningGuest no longer sends SIGTERM"
        )
        XCTAssertFalse(
            src.contains("kill(record.pid, \(("SIG") + "KILL"))"),
            "stopRunningGuest power-cuts a guest with a writable disk"
        )
    }

    /// A failed refresh must not answer "nothing is running".
    ///
    /// The registry is a directory on disk and does not depend on the daemon, so
    /// clearing the list because `chm ctl status` failed would use the failure of
    /// one question to answer another — the #202 mistake.
    func testAFailedRefreshDoesNotClaimNothingIsRunning() {
        let src = AppModelSource.text
        XCTAssertFalse(
            src.contains("runningGuests = []"),
            "a failed refresh clears the run list, so a live guest disappears"
        )
    }
}

/// Reads a source file so a guard can see a *call site*, which an assertion
/// about an outcome structurally cannot. Needles are assembled from parts where
/// they would otherwise match this file's own text.
enum AppModelSource {
    static var text: String {
        (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
    }
    static var path: String {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // GimbalLocalAppTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // GimbalLocal
            .appendingPathComponent("Sources/GimbalLocalApp/AppModel.swift")
            .path
    }
}

enum SandboxesViewSource {
    static var text: String {
        let p = URL(fileURLWithPath: AppModelSource.path)
            .deletingLastPathComponent()
            .appendingPathComponent("SandboxesView.swift")
            .path
        return (try? String(contentsOfFile: p, encoding: .utf8)) ?? ""
    }
}

enum ContentViewSource {
    static var text: String {
        let p = URL(fileURLWithPath: AppModelSource.path)
            .deletingLastPathComponent()
            .appendingPathComponent("ContentView.swift")
            .path
        return (try? String(contentsOfFile: p, encoding: .utf8)) ?? ""
    }
}
