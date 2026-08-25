// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation
import XCTest

@testable import GimbalLocalApp

/// Guards on the test helper itself.
///
/// A helper that cleans up after tests is exactly the kind of code nobody
/// notices is broken: it fails by leaving litter on a machine, silently, one
/// file at a time. 136 files had accumulated here before anyone looked.
final class ThrowawayDefaultsTests: XCTestCase {
    /// Cleaning up a test suite must remove the file, not just the values.
    ///
    /// `removePersistentDomain(forName:)` reads like the whole cleanup and is
    /// half of it: the values go and `cfprefsd` leaves a 42-byte `{}` plist in
    /// `~/Library/Preferences`. These tests already called it, so the bug was
    /// never a missing teardown — it was a teardown that did less than its name
    /// says. 136 files had accumulated before anyone counted them.
    ///
    /// The file here is written by hand rather than by opening the suite,
    /// because opening a suite is what registers it with `cfprefsd` — and a
    /// registered domain is written back out at process exit, after every
    /// teardown block has run. A guard that leaked a file to prove files are
    /// not leaked would be self-refuting.
    func testCleanupRemovesTheFileAndNotJustTheValues() throws {
        let suite = ThrowawayDefaults.makeSuiteName()
        let url = try XCTUnwrap(ThrowawayDefaults.plistURL(for: suite))
        try Data("<plist/>".utf8).write(to: url)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))

        ThrowawayDefaults.destroy(suite: suite)

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: url.path),
            "cleanup left \(url.lastPathComponent) behind on this machine"
        )
        XCTAssertTrue(ThrowawayDefaults.isFullyDestroyed(suite: suite))
    }

    /// A suite name that could escape `~/Library/Preferences` yields no path.
    ///
    /// The cleanup deletes a file it derives from a string, so the derivation
    /// must refuse anything it cannot vouch for rather than compose a path and
    /// delete whatever is there.
    func testACleanupPathIsNeverGuessed() {
        XCTAssertNil(ThrowawayDefaults.plistURL(for: ""))
        XCTAssertNil(ThrowawayDefaults.plistURL(for: "../../etc/passwd"))
        XCTAssertNotNil(ThrowawayDefaults.plistURL(for: "gimbal.tests.abc"))
    }

    /// The sweep collects litter from previous runs and nothing else.
    ///
    /// It deletes files in a directory full of other applications' settings,
    /// so the prefix match is the whole safety argument and is worth asserting
    /// directly rather than trusting by inspection.
    func testTheSweepTakesOnlyOurOwnLitter() throws {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences")
        let ours = dir.appendingPathComponent("\(ThrowawayDefaults.suitePrefix)\(UUID().uuidString).plist")
        let theirs = dir.appendingPathComponent("gimbal.tests.notours.\(UUID().uuidString).example")
        try Data("<plist/>".utf8).write(to: ours)
        try Data("<plist/>".utf8).write(to: theirs)
        defer { try? FileManager.default.removeItem(at: theirs) }

        ThrowawayDefaults.sweepStaleSuites()

        XCTAssertFalse(FileManager.default.fileExists(atPath: ours.path), "the sweep missed our own leftover")
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: theirs.path),
            "the sweep deleted a file that is not a suite plist"
        )
    }
}

extension ThrowawayDefaultsTests {
    /// The helper must actually register its cleanup.
    ///
    /// Every other guard here asserts an *outcome*, and an outcome assertion
    /// cannot see a cleanup that is never invoked: the leak it causes only
    /// becomes visible after the test process exits, which is after the last
    /// thing any test can observe. Deleting the `addTeardownBlock` line leaves
    /// all of them green.
    ///
    /// So this one reads the source instead — the same shape as the guard that
    /// keeps `chm --help` honest about its own dispatch table. It is a weaker
    /// kind of evidence, and it is the only kind available for this property.
    func testTheHelperRegistersItsCleanup() throws {
        let helper = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("ThrowawayDefaults.swift")
        let source = try String(contentsOf: helper, encoding: .utf8)

        let body = try XCTUnwrap(
            source.range(of: "func throwawayDefaults").map { String(source[$0.lowerBound...]) },
            "throwawayDefaults() is gone, so nothing here describes how tests get a store"
        )
        XCTAssertTrue(
            body.contains("addTeardownBlock"),
            "throwawayDefaults() hands out a suite without registering its cleanup"
        )
        XCTAssertTrue(
            body.contains("ThrowawayDefaults.destroy(suite:"),
            "the teardown no longer calls destroy, so the file is left behind"
        )
    }

    /// Every test that wants a real `UserDefaults` must get it from the helper.
    ///
    /// This is the guard the other four structurally could not be. All of them
    /// assert on the helper -- that it deletes the file, that it refuses a path
    /// it cannot vouch for, that it registers its teardown. **None of them can
    /// see a test that never calls the helper at all**, and two had been
    /// opening their own suites since before the helper existed:
    ///
    /// - `SnapshotCadenceTests` tore down with `removePersistentDomain`, which
    ///   is the exact API this helper exists because it does less than its name
    ///   suggests: the values go, the plist stays.
    /// - `LocalOnlyDefaultTests` passed a `UserDefaults` object's `description`
    ///   as a domain name, which is not one, so it cleared nothing whatsoever.
    ///   It also keyed the suite on the process id, which the kernel recycles,
    ///   so a file left by an earlier run could be read back by a later one as
    ///   though this run had written it -- a flake with an invisible cause.
    ///
    /// Measured after a full `swift test`: seven plists left behind in
    /// `~/Library/Preferences`, five of them from those two classes.
    ///
    /// The needle is assembled from parts so this guard cannot match its own
    /// assertion text. A source guard that satisfies itself reports safety it
    /// does not provide.
    func testEveryTestGetsItsSuiteFromTheHelper() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let needle = "UserDefaults(" + "suiteName:"
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.hasSuffix(".swift") && $0 != "ThrowawayDefaults.swift" }
            .sorted()

        // Prove the instrument can see anything at all before recording that it
        // found nothing: an empty file list would pass this test by default.
        XCTAssertFalse(names.isEmpty, "no sibling test sources were read, so this guard checked nothing")

        var offenders: [String] = []
        for name in names {
            let source = try String(contentsOf: dir.appendingPathComponent(name), encoding: .utf8)
            if source.contains(needle) { offenders.append(name) }
        }

        XCTAssertEqual(
            offenders, [],
            "these open a defaults suite directly instead of calling throwawayDefaults(), "
                + "so each one leaves a plist in ~/Library/Preferences after every run"
        )
    }
}
