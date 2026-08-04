// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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
        existing: Set<String> = []
    ) -> SettingsStore.Restored {
        SettingsStore.restore(
            saved: saved,
            defaults: base,
            environment: environment,
            exists: { existing.contains($0) }
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
            exists: { _ in true }
        )
        XCTAssertEqual(restored.settings, chosen)
    }

    // MARK: - The impure edge: a real UserDefaults round trip

    /// The pure tests above cannot catch a key typo between `save` and `load`,
    /// because both would use the same wrong key from `defaultsKey`. This one
    /// drives real storage.
    func testSaveThenLoadThroughRealUserDefaults() throws {
        let suite = "gimbal.tests.\(UUID().uuidString)"
        let store = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { UserDefaults.standard.removePersistentDomain(forName: suite) }

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
            exists: { _ in true }
        )
        XCTAssertEqual(restored.settings, chosen)
    }

    func testAnEnvironmentOverriddenFieldNeverReachesStorage() throws {
        let suite = "gimbal.tests.\(UUID().uuidString)"
        let store = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { UserDefaults.standard.removePersistentDomain(forName: suite) }

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
        XCTAssertEqual(
            model.settingsNotices,
            [.missingKept(field: .localImagesPath, saved: unique)]
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
