// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest

@testable import GimbalLocalApp

/// `SettingsStore.restore` is pure, so every one of these drives the real
/// policy with no filesystem, no `UserDefaults` and no environment.
final class SettingsStoreTests: XCTestCase {
    private let base = AppSettings(
        chmPath: "/repo/target/debug/chm",
        libraryPath: "/repo/snapshots",
        localImagesPath: "/repo/images",
        socketPath: "/tmp/chm.sock",
        controlPlaneURL: "http://127.0.0.1:8080"
    )

    private func restore(
        saved: [SettingsField: String] = [:],
        environment: [String: String] = [:],
        existing: Set<String> = [],
        states: [String: PathState] = [:]
    ) -> SettingsStore.Restored {
        SettingsStore.restore(
            saved: saved,
            defaults: base,
            environment: environment,
            probe: { path in
                if let explicit = states[path] { return explicit }
                guard existing.contains(path) else { return .missing }
                // A path named in `existing` is healthy for whatever wants it.
                // Those tests are about precedence, not usability; the ones
                // about usability pass `states` and say exactly what they mean.
                return path.hasSuffix("/chm") ? .executableFile : .populatedDirectory
            }
        )
    }

    /// Everything below asserts against paths that exist unless the test is
    /// about absence, so a missing-path notice never masquerades as a
    /// precedence result.
    private var allBasePaths: Set<String> {
        [base.chmPath, base.libraryPath, base.localImagesPath, base.socketPath]
    }

    // MARK: - The point of the feature

    func testASavedPathSurvivesTheNextLaunch() {
        let restored = restore(
            saved: [.chmPath: "/opt/mine/chm", .localImagesPath: "/Volumes/big/images"],
            existing: allBasePaths.union(["/opt/mine/chm", "/Volumes/big/images"])
        )
        XCTAssertEqual(restored.settings.chmPath, "/opt/mine/chm")
        XCTAssertEqual(restored.settings.localImagesPath, "/Volumes/big/images")
        XCTAssertTrue(restored.notices.isEmpty)
    }

    func testNothingSavedFallsBackToTheDerivedDefaults() {
        let restored = restore(existing: allBasePaths)
        XCTAssertEqual(restored.settings, base)
        XCTAssertTrue(restored.notices.isEmpty)
        XCTAssertTrue(restored.environmentOverridden.isEmpty)
    }

    func testAnEmptySavedStringIsTreatedAsUnset() {
        // Clearing the field in the UI must not persist "" and then resolve to
        // an empty chm path on the next launch.
        let restored = restore(saved: [.chmPath: ""], existing: allBasePaths)
        XCTAssertEqual(restored.settings.chmPath, base.chmPath)
    }

    // MARK: - Precedence: environment > saved > default

    func testAnExplicitEnvironmentVariableBeatsAValueSavedWeeksAgo() {
        let restored = restore(
            saved: [.chmPath: "/opt/mine/chm"],
            environment: ["CHM_PATH": "/ci/chm"],
            existing: allBasePaths.union(["/opt/mine/chm", "/ci/chm"])
        )
        XCTAssertEqual(restored.settings.chmPath, "/ci/chm")
        XCTAssertTrue(restored.environmentOverridden.contains(.chmPath))
    }

    func testTheOverrideIsReportedRatherThanHidden() {
        let restored = restore(
            saved: [.libraryPath: "/opt/snaps"],
            environment: ["GIMBAL_LIBRARY": "/ci/snaps"],
            existing: allBasePaths.union(["/opt/snaps", "/ci/snaps"])
        )
        XCTAssertEqual(
            restored.notices,
            [.environmentOverride(
                field: .libraryPath,
                variable: "GIMBAL_LIBRARY",
                saved: "/opt/snaps",
                active: "/ci/snaps"
            )]
        )
        // The message has to name both, or it cannot be acted on.
        let message = restored.notices[0].message
        XCTAssertTrue(message.contains("/ci/snaps"))
        XCTAssertTrue(message.contains("/opt/snaps"))
        XCTAssertTrue(message.contains("GIMBAL_LIBRARY"))
    }

    func testAnEnvironmentVariableAgreeingWithTheSavedValueIsNotWorthMentioning() {
        let restored = restore(
            saved: [.chmPath: "/ci/chm"],
            environment: ["CHM_PATH": "/ci/chm"],
            existing: allBasePaths.union(["/ci/chm"])
        )
        XCTAssertTrue(restored.notices.isEmpty)
        XCTAssertTrue(restored.environmentOverridden.contains(.chmPath))
    }

    func testAnEmptyEnvironmentVariableDoesNotCount() {
        // `CHM_PATH=` exported but blank is not an instruction.
        let restored = restore(
            saved: [.chmPath: "/opt/mine/chm"],
            environment: ["CHM_PATH": ""],
            existing: allBasePaths.union(["/opt/mine/chm"])
        )
        XCTAssertEqual(restored.settings.chmPath, "/opt/mine/chm")
        XCTAssertFalse(restored.environmentOverridden.contains(.chmPath))
    }

    /// The reason `environmentOverridden` exists at all: writing an environment
    /// value back would destroy the user's own saved path the first time they
    /// launched under CI, and they would never get it back.
    func testAnEnvironmentOverriddenFieldIsNeverWrittenBack() {
        let restored = restore(
            saved: [.chmPath: "/opt/mine/chm"],
            environment: ["CHM_PATH": "/ci/chm"],
            existing: allBasePaths.union(["/opt/mine/chm", "/ci/chm"])
        )
        let toWrite = SettingsStore.persistable(
            restored.settings,
            environmentOverridden: restored.environmentOverridden
        )
        XCTAssertNil(toWrite[.chmPath])
        // ...while everything the environment is silent about still persists.
        XCTAssertEqual(toWrite[.libraryPath], base.libraryPath)
        XCTAssertEqual(toWrite[.socketPath], base.socketPath)
    }

    // MARK: - A path that has gone away

    func testAMissingChmBinaryFallsBackAndSaysSo() {
        let restored = restore(
            saved: [.chmPath: "/gone/chm"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.chmPath, base.chmPath)
        XCTAssertEqual(
            restored.notices,
            [.missingFallback(field: .chmPath, saved: "/gone/chm", fallback: base.chmPath)]
        )
    }

    /// Falling back to a default that is *also* missing would print a notice
    /// reading like a fix while changing nothing. Say the truth instead.
    func testWhenTheDefaultIsAlsoMissingWeKeepTheSavedPathAndDoNotClaimAFallback() {
        let restored = restore(saved: [.chmPath: "/gone/chm"], existing: [])
        XCTAssertEqual(restored.settings.chmPath, "/gone/chm")
        XCTAssertEqual(restored.notices, [.missingKept(field: .chmPath, saved: "/gone/chm")])
    }

    /// A missing images directory is an empty list, not a failure -- and
    /// silently swapping in the repo's own images would show the user someone
    /// else's images rather than telling them their volume is unmounted.
    func testAMissingImageDirectoryIsKeptNotReplaced() {
        let restored = restore(
            saved: [.localImagesPath: "/Volumes/unplugged/images"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.localImagesPath, "/Volumes/unplugged/images")
        XCTAssertEqual(
            restored.notices,
            [.missingKept(field: .localImagesPath, saved: "/Volumes/unplugged/images")]
        )
    }

    func testAMissingSnapshotLibraryIsAlsoKept() {
        let restored = restore(
            saved: [.libraryPath: "/Volumes/unplugged/snaps"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.libraryPath, "/Volumes/unplugged/snaps")
        XCTAssertEqual(restored.notices.count, 1)
    }

    /// The socket does not exist until `chm serve` creates it, so complaining
    /// about it would fire on every clean launch.
    func testAnAbsentSocketIsNotWorthMentioning() {
        let restored = restore(
            saved: [.socketPath: "/tmp/not-yet.sock"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.socketPath, "/tmp/not-yet.sock")
        XCTAssertTrue(restored.notices.isEmpty)
    }

    /// A control plane URL is not a path; running `exists` over it would
    /// declare every URL missing.
    func testAControlPlaneURLIsNeverTreatedAsAPath() {
        let restored = restore(
            saved: [.controlPlaneURL: "https://plane.example/api"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.controlPlaneURL, "https://plane.example/api")
        XCTAssertTrue(restored.notices.isEmpty)
    }

    /// A first launch in a fresh checkout has no built binary. That is the
    /// ordinary state, not something the user did, so it must not produce a
    /// warning about a value they never chose.
    func testADerivedDefaultThatIsAbsentDoesNotWarn() {
        let restored = restore(existing: [])
        XCTAssertTrue(restored.notices.isEmpty)
        XCTAssertEqual(restored.settings, base)
    }

    /// An environment variable pointing somewhere that does not exist is still
    /// worth flagging -- it is an explicit instruction that will not work.
    func testAMissingEnvironmentPathIsReported() {
        let restored = restore(
            environment: ["CHM_PATH": "/ci/gone/chm"],
            existing: allBasePaths
        )
        XCTAssertEqual(restored.settings.chmPath, base.chmPath)
        XCTAssertEqual(
            restored.notices,
            [.missingFallback(field: .chmPath, saved: "/ci/gone/chm", fallback: base.chmPath)]
        )
    }

    // MARK: - Wiring that is easy to get wrong once and never notice

    func testEveryFieldHasADistinctDefaultsKeyAndTheyAreNamespaced() {
        let keys = SettingsField.allCases.map(\.defaultsKey)
        XCTAssertEqual(Set(keys).count, keys.count)
        for key in keys {
            XCTAssertTrue(key.hasPrefix("gimbal.settings."), "\(key) escapes the namespace")
        }
    }

    /// A copy-pasted key path would make two fields alias, so one would
    /// overwrite the other on every save.
    func testEveryFieldWritesToADistinctProperty() {
        for field in SettingsField.allCases {
            var probe = base
            probe[keyPath: field.keyPath] = "sentinel-\(field.rawValue)"
            let changed = SettingsField.allCases.filter { probe[keyPath: $0.keyPath] != base[keyPath: $0.keyPath] }
            XCTAssertEqual(changed, [field], "\(field.rawValue) does not have its own property")
        }
    }

    func testRoundTripThroughPersistableRestoresEveryField() {
        var chosen = base
        for field in SettingsField.allCases {
            chosen[keyPath: field.keyPath] = "/chosen/\(field.rawValue)"
        }
        let saved = SettingsStore.persistable(chosen, environmentOverridden: [])
        let restored = SettingsStore.restore(
            saved: saved,
            defaults: base,
            environment: [:],
            probe: { $0.contains("chm") ? .executableFile : .populatedDirectory }
        )
        XCTAssertEqual(restored.settings, chosen)
    }

    // MARK: - The impure edge: a real UserDefaults round trip

    /// The pure tests above cannot catch a key typo between `save` and `load`,
    /// because both would use the same wrong key from `defaultsKey`. This one
    /// drives real storage.
    func testSaveThenLoadThroughRealUserDefaults() throws {
        let store = try throwawayDefaults()

        var chosen = base
        chosen.chmPath = "/opt/persisted/chm"
        chosen.libraryPath = "/opt/persisted/snaps"
        chosen.localImagesPath = "/opt/persisted/images"
        chosen.socketPath = "/opt/persisted/chm.sock"
        chosen.controlPlaneURL = "https://persisted.example"

        SettingsStore.save(chosen, environmentOverridden: [], defaults: store)

        var readBack: [SettingsField: String] = [:]
        for field in SettingsField.allCases {
            readBack[field] = store.string(forKey: field.defaultsKey)
        }
        let restored = SettingsStore.restore(
            saved: readBack,
            defaults: base,
            environment: [:],
            probe: { $0.contains("chm") ? .executableFile : .populatedDirectory }
        )
        XCTAssertEqual(restored.settings, chosen)
    }

    func testAnEnvironmentOverriddenFieldNeverReachesStorage() throws {
        let store = try throwawayDefaults()

        store.set("/opt/mine/chm", forKey: SettingsField.chmPath.defaultsKey)

        var active = base
        active.chmPath = "/ci/chm"
        SettingsStore.save(active, environmentOverridden: [.chmPath], defaults: store)

        // The user's own path is still there, untouched, ready for a launch
        // without the variable set.
        XCTAssertEqual(store.string(forKey: SettingsField.chmPath.defaultsKey), "/opt/mine/chm")
    }

    // MARK: - The wiring, which the pure tests cannot see

    /// The policy above is worthless if nothing calls it. This drives the real
    /// `AppModel`: mutate `settings` as the settings pane does through its
    /// binding, and the value must land in real storage with no explicit save.
    @MainActor
    func testEditingSettingsOnTheModelPersistsWithoutAnExplicitSave() {
        let model = AppModel()
        let key = SettingsField.localImagesPath.defaultsKey
        let unique = "/tmp/gimbal-wiring-\(UUID().uuidString)"
        defer { UserDefaults.standard.removeObject(forKey: key) }

        model.settings.localImagesPath = unique

        XCTAssertEqual(UserDefaults.standard.string(forKey: key), unique)
    }

    /// ...and `loadSettings` must read it back on the next launch.
    @MainActor
    func testLoadSettingsPicksUpAPersistedValue() {
        let key = SettingsField.localImagesPath.defaultsKey
        let unique = "/tmp/gimbal-wiring-\(UUID().uuidString)"
        UserDefaults.standard.set(unique, forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        let model = AppModel()
        model.loadSettings()

        XCTAssertEqual(model.settings.localImagesPath, unique)
        // The directory does not exist, so the user is told rather than left to
        // wonder why the list is empty.
        //
        // Asserted by containment, not equality. The other two fields resolve
        // to paths *inside the checkout* -- a built `chm` and a `snapshots`
        // directory -- so an equality assertion here is really an assertion
        // about the developer's machine: it passes in a worktree that has been
        // built in and fails on a cold build in a fresh one. Caught doing
        // exactly that, verifying that each commit tests alone.
        XCTAssertTrue(
            model.settingsNotices.contains(.missingKept(field: .localImagesPath, saved: unique)),
            "the missing image directory must be reported, got \(model.settingsNotices)"
        )
    }

    /// Restoring must not write the derived defaults back: a repo path
    /// discovered on this launch would then be frozen into every future one,
    /// surviving a move or a rebuild elsewhere.
    @MainActor
    func testRestoringDoesNotPersistValuesTheUserNeverChose() {
        let key = SettingsField.chmPath.defaultsKey
        UserDefaults.standard.removeObject(forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        let model = AppModel()
        model.loadSettings()

        XCTAssertNil(UserDefaults.standard.string(forKey: key))
    }
}

// MARK: - Present, and still useless
//
// The bug these cover, in full: a snapshot library left pointing at a directory
// that exists and is empty passed `fileExists`, produced no notice at all, and
// the app came up with an empty list and nothing to say. Existence was never
// the right question.

extension SettingsStoreTests {
    func testAnEmptyLibraryIsReportedRatherThanPassingSilently() {
        let restored = restore(
            saved: [.libraryPath: "/volume/snapshots"],
            states: [
                "/volume/snapshots": .emptyDirectory,
                base.chmPath: .executableFile,
                base.localImagesPath: .populatedDirectory,
            ]
        )
        XCTAssertEqual(
            restored.notices,
            [.presentButEmpty(field: .libraryPath, path: "/volume/snapshots")]
        )
        // Reported, not overridden: the user's choice still stands.
        XCTAssertEqual(restored.settings.libraryPath, "/volume/snapshots")
    }

    func testAnEmptyImageFolderIsReportedToo() {
        let restored = restore(
            saved: [.localImagesPath: "/volume/images"],
            states: [
                "/volume/images": .emptyDirectory,
                base.chmPath: .executableFile,
                base.libraryPath: .populatedDirectory,
            ]
        )
        XCTAssertEqual(
            restored.notices,
            [.presentButEmpty(field: .localImagesPath, path: "/volume/images")]
        )
    }

    func testAPopulatedLibrarySaysNothing() {
        let restored = restore(
            saved: [.libraryPath: "/volume/snapshots"],
            states: [
                "/volume/snapshots": .populatedDirectory,
                base.chmPath: .executableFile,
                base.localImagesPath: .populatedDirectory,
            ]
        )
        XCTAssertTrue(restored.notices.isEmpty, "a working library must stay silent")
    }

    /// `fileExists` answers **true** for a directory, so a `chmPath` pointing at
    /// one used to be accepted and then fail on every spawn.
    func testADirectoryWhereTheBinaryBelongsIsRefused() {
        let restored = restore(
            saved: [.chmPath: "/opt/chm-dir"],
            states: [
                "/opt/chm-dir": .populatedDirectory,
                base.chmPath: .missing,
                base.libraryPath: .populatedDirectory,
                base.localImagesPath: .populatedDirectory,
            ]
        )
        XCTAssertEqual(
            restored.notices,
            [.notExecutable(field: .chmPath, path: "/opt/chm-dir")]
        )
    }

    func testANonExecutableBinaryFallsBackWhenTheDefaultCanActuallyRun() {
        let restored = restore(
            saved: [.chmPath: "/opt/chm.txt"],
            states: [
                "/opt/chm.txt": .notExecutable,
                base.chmPath: .executableFile,
                base.libraryPath: .populatedDirectory,
                base.localImagesPath: .populatedDirectory,
            ]
        )
        XCTAssertEqual(
            restored.notices,
            [.missingFallback(field: .chmPath, saved: "/opt/chm.txt", fallback: base.chmPath)]
        )
        XCTAssertEqual(restored.settings.chmPath, base.chmPath)
    }

    /// An empty *socket* directory is not a defect — `chm` creates the socket on
    /// demand — so `.nothing` must genuinely opt out rather than fall through to
    /// the directory rule.
    func testFieldsThatRequireNothingAreNeverComplainedAbout() {
        let restored = restore(
            saved: [.socketPath: "/tmp/sock"],
            states: [
                "/tmp/sock": .emptyDirectory,
                base.chmPath: .executableFile,
                base.libraryPath: .populatedDirectory,
                base.localImagesPath: .populatedDirectory,
            ]
        )
        XCTAssertTrue(restored.notices.isEmpty)
    }

    /// The probe is the one impure part, and its ordering is load-bearing:
    /// `isExecutableFile` returns true for a searchable directory, so a
    /// directory has to be classified before that question is ever asked.
    func testTheRealProbeTellsADirectoryFromAnExecutable() throws {
        let fm = FileManager.default
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("gimbal-probe-\(UUID().uuidString)")
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        let emptyDir = root.appendingPathComponent("empty")
        try fm.createDirectory(at: emptyDir, withIntermediateDirectories: true)

        let fullDir = root.appendingPathComponent("full")
        try fm.createDirectory(at: fullDir, withIntermediateDirectories: true)
        try "x".write(to: fullDir.appendingPathComponent("thing"), atomically: true, encoding: .utf8)

        let hiddenOnly = root.appendingPathComponent("hidden")
        try fm.createDirectory(at: hiddenOnly, withIntermediateDirectories: true)
        try "x".write(to: hiddenOnly.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)

        let plain = root.appendingPathComponent("plain.txt")
        try "x".write(to: plain, atomically: true, encoding: .utf8)

        let runnable = root.appendingPathComponent("runnable")
        try "#!/bin/sh\n".write(to: runnable, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: runnable.path)

        XCTAssertEqual(SettingsStore.probeFilesystem(emptyDir.path), .emptyDirectory)
        XCTAssertEqual(SettingsStore.probeFilesystem(fullDir.path), .populatedDirectory)
        XCTAssertEqual(
            SettingsStore.probeFilesystem(hiddenOnly.path), .emptyDirectory,
            "a stray .DS_Store is not content the user put there"
        )
        XCTAssertEqual(SettingsStore.probeFilesystem(plain.path), .notExecutable)
        XCTAssertEqual(SettingsStore.probeFilesystem(runnable.path), .executableFile)
        XCTAssertEqual(
            SettingsStore.probeFilesystem(root.appendingPathComponent("nope").path), .missing
        )
    }
}

// MARK: - Why Start did nothing

final class SlotContentionTests: XCTestCase {
    func testAFreeSlotSaysNothing() {
        XCTAssertNil(SlotContention.evaluate(holderName: nil, thisSandboxIsLive: false))
    }

    /// The running sandbox is not blocked by itself. Callers pass
    /// `slotHolder(excluding:)`, but this must hold even if one forgets.
    func testTheRunningSandboxIsNotBlockedByItself() {
        XCTAssertNil(SlotContention.evaluate(holderName: "graviton-2", thisSandboxIsLive: true))
    }

    func testABlockedSandboxNamesTheHolderAndTheRemedy() throws {
        let state = try XCTUnwrap(
            SlotContention.evaluate(holderName: "ch-arm-stock-its", thisSandboxIsLive: false)
        )
        XCTAssertEqual(state.holderName, "ch-arm-stock-its")
        XCTAssertTrue(
            state.message.contains("ch-arm-stock-its"),
            "a refusal that does not name the holder cannot be acted on: \(state.message)"
        )
        XCTAssertTrue(
            state.message.contains("one VM per process"),
            "the constraint is the whole explanation: \(state.message)"
        )
        XCTAssertEqual(state.remedyLabel, "Stop ch-arm-stock-its")
    }

    /// An empty name would render "  is running and holds…", which reads as a
    /// bug in the app rather than a fact about it.
    func testAnEmptyHolderNameIsTreatedAsNoHolder() {
        XCTAssertNil(SlotContention.evaluate(holderName: "", thisSandboxIsLive: false))
    }
}

// MARK: - A running guest survives an app restart

/// Quit the app with a sandbox running, reopen it, and every row read
/// "Stopped" while `chm ctl status` said `running` — because the app matched
/// the daemon's VM against a variable that only remembers sandboxes started
/// since launch. The daemon reports the name; nobody read it.
final class DaemonRunOwnerTests: XCTestCase {
    private let candidates: [(id: String, name: String)] = [
        (id: "4E40B07F-7534-48F4-B519-1EE674EF8E5D", name: "graviton-2"),
        (id: "9BEA5058-1111-2222-3333-444455556666", name: "ch-arm-stock-its"),
    ]

    func testTheDaemonsUUIDResolvesToTheSandboxThatOwnsIt() {
        XCTAssertEqual(
            DaemonRunOwner.match(
                reportedName: "4E40B07F-7534-48F4-B519-1EE674EF8E5D",
                candidates: candidates
            ),
            "4E40B07F-7534-48F4-B519-1EE674EF8E5D"
        )
    }

    func testALibraryNameResolvesToo() {
        XCTAssertEqual(
            DaemonRunOwner.match(reportedName: "ch-arm-stock-its", candidates: candidates),
            "9BEA5058-1111-2222-3333-444455556666"
        )
    }

    /// A guest started outside the app is real, and claiming an unrelated row
    /// for it would be worse than admitting we do not know whose it is.
    func testAnUnknownGuestClaimsNobody() {
        XCTAssertNil(DaemonRunOwner.match(reportedName: "someones-scratch-vm", candidates: candidates))
    }

    func testNothingRunningResolvesToNothing() {
        XCTAssertNil(DaemonRunOwner.match(reportedName: nil, candidates: candidates))
        XCTAssertNil(DaemonRunOwner.match(reportedName: "", candidates: candidates))
    }

    /// Names are user-chosen and need not be unique. Guessing would mark one
    /// sandbox running *and* disable Start on the other, from a coin toss.
    func testADuplicateNameResolvesToNothingRatherThanGuessing() {
        let twins: [(id: String, name: String)] = [
            (id: "a", name: "dev"),
            (id: "b", name: "dev"),
        ]
        XCTAssertNil(DaemonRunOwner.match(reportedName: "dev", candidates: twins))
    }

    /// An id must win even when some other sandbox happens to be *named* that.
    func testIdentityBeatsANameCollision() {
        let tricky: [(id: String, name: String)] = [
            (id: "sandbox-7", name: "unrelated"),
            (id: "zzz", name: "sandbox-7"),
        ]
        XCTAssertEqual(DaemonRunOwner.match(reportedName: "sandbox-7", candidates: tricky), "sandbox-7")
    }
}
