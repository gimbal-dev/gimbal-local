// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation
import XCTest

/// A `UserDefaults` suite that removes itself completely when the test ends.
///
/// `removePersistentDomain(forName:)` looks like the whole cleanup and is only
/// half of it: it drops the *values*, and `cfprefsd` still leaves the plist on
/// disk. Measured — a 42-byte file containing `{}`, one per suite created, and
/// **136 of them** had accumulated in `~/Library/Preferences` by the time a
/// clean-machine acceptance run went looking for stray state. They were the
/// last gimbal artifacts found on that machine, after several sweeps that each
/// believed they were the final one.
///
/// Two reasons this is worth a helper rather than another `defer`:
///
/// - the tests already *had* the `defer`, so the failure was not forgetting to
///   clean up, it was cleaning up with an API that does less than its name
///   suggests. Another call site would have got it wrong the same way.
/// - a stale suite is a latent flake. A test reading a key it did not write in
///   *this* run can pass or fail on residue from months ago, and the residue is
///   invisible.
enum ThrowawayDefaults {
    /// Removes a suite's values **and** the file `cfprefsd` leaves behind.
    ///
    /// Separated from the teardown block so it can be tested directly: a
    /// cleanup that only ever runs after the test it belongs to is a cleanup
    /// nothing can assert on.
    static func destroy(suite: String) {
        UserDefaults.standard.removePersistentDomain(forName: suite)
        UserDefaults.standard.synchronize()
        if let url = plistURL(for: suite) {
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// True when nothing is left that `cfprefsd` could write back out.
    ///
    /// The exit-time flush happens after the last teardown block, so no test
    /// can observe it directly. This is the observable proxy: a domain holding
    /// no values has nothing to re-create the file with.
    ///
    /// Deliberately asks `UserDefaults.standard` rather than opening a handle
    /// on the suite. **Opening one is not a free observation** — it registers
    /// the domain with `cfprefsd`, which then writes the file out at process
    /// exit whether or not anything was ever stored in it. An earlier version
    /// of `destroy` opened a handle to clear the suite "properly" and turned a
    /// one-file leak into three: the cleanup was creating what it was cleaning.
    static func isFullyDestroyed(suite: String) -> Bool {
        let cleared = UserDefaults.standard.persistentDomain(forName: suite)?.isEmpty ?? true
        let onDisk = plistURL(for: suite).map { FileManager.default.fileExists(atPath: $0.path) } ?? false
        return cleared && !onDisk
    }

    /// Where a suite's backing file lands for a non-sandboxed process.
    ///
    /// Returns nil rather than guessing if the layout is not the one we know;
    /// the domain removal above is still correct either way, so a wrong path
    /// here must not turn into a wrong deletion.
    static func plistURL(for suite: String) -> URL? {
        guard !suite.isEmpty, !suite.contains("/") else { return nil }
        return FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences")
            .appendingPathComponent("\(suite).plist")
    }

    /// The prefix every suite this helper mints shares, so a sweep can
    /// recognise its own litter and nothing else.
    static let suitePrefix = "gimbal.tests."

    /// Deletes plists left behind by *previous* test processes.
    ///
    /// This is the half that in-process teardown structurally cannot do.
    /// Measured: opening `UserDefaults(suiteName:)` registers the domain with
    /// `cfprefsd`, which writes the file out when the process exits — after
    /// the last teardown block has run. So a run can always leave up to one
    /// file per suite it opened, no matter how carefully it tidies up.
    ///
    /// Sweeping on the way *in* is race-free, because the processes that wrote
    /// those files are gone. Together the two halves bound the litter at one
    /// run's worth instead of letting it grow without limit — which is the
    /// actual complaint: 136 files had accumulated, not 3.
    ///
    /// - Returns: how many stale files were removed.
    @discardableResult
    static func sweepStaleSuites() -> Int {
        let dir = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences")
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return 0 }
        var removed = 0
        for name in names where name.hasPrefix(suitePrefix) && name.hasSuffix(".plist") {
            let suite = String(name.dropLast(".plist".count))
            UserDefaults.standard.removePersistentDomain(forName: suite)
            if (try? FileManager.default.removeItem(at: dir.appendingPathComponent(name))) != nil {
                removed += 1
            }
        }
        return removed
    }

    /// A suite name no other run can collide with.
    static func makeSuiteName() -> String { "\(suitePrefix)\(UUID().uuidString)" }
}

extension XCTestCase {
    /// A real `UserDefaults` that leaves nothing behind on this machine.
    ///
    /// Uses `addTeardownBlock` rather than the caller's `defer` so the cleanup
    /// cannot be skipped by an early `throw` in the body of a test.
    func throwawayDefaults(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> UserDefaults {
        ThrowawayDefaults.sweepStaleSuites()
        let suite = ThrowawayDefaults.makeSuiteName()
        let store = try XCTUnwrap(
            UserDefaults(suiteName: suite),
            "could not open a throwaway defaults suite",
            file: file,
            line: line
        )
        addTeardownBlock { ThrowawayDefaults.destroy(suite: suite) }
        return store
    }
}
