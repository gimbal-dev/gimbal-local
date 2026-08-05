// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// The five settings, named once so persistence, environment lookup and the
/// user-facing label can never drift apart.
enum SettingsField: String, CaseIterable {
    case chmPath
    case libraryPath
    case localImagesPath
    case socketPath
    case controlPlaneURL

    var defaultsKey: String { "gimbal.settings.\(rawValue)" }

    /// The environment variable that, when set, is a deliberate act by whoever
    /// launched the app and therefore outranks anything saved earlier.
    /// `socketPath` and `controlPlaneURL` have no such variable today; adding
    /// one here is all that would be needed.
    var environmentVariable: String? {
        switch self {
        case .chmPath: "CHM_PATH"
        case .libraryPath: "GIMBAL_LIBRARY"
        case .localImagesPath: "GIMBAL_IMAGES"
        case .socketPath, .controlPlaneURL: nil
        }
    }

    var label: String {
        switch self {
        case .chmPath: "chm binary"
        case .libraryPath: "Snapshot library"
        case .localImagesPath: "Local images"
        case .socketPath: "Daemon socket"
        case .controlPlaneURL: "Control plane URL"
        }
    }

    var keyPath: WritableKeyPath<AppSettings, String> {
        switch self {
        case .chmPath: \.chmPath
        case .libraryPath: \.libraryPath
        case .localImagesPath: \.localImagesPath
        case .socketPath: \.socketPath
        case .controlPlaneURL: \.controlPlaneURL
        }
    }

    /// How much we care that the path is not there.
    ///
    /// Only `chmPath` is *fatal*: without the binary every command fails with an
    /// obscure error, so falling back to the default at least has a chance of
    /// working. The two directories are deliberately **not** replaced — silently
    /// swapping in a different directory would show the user someone else's
    /// images instead of telling them their external volume is unmounted.
    /// `socketPath` is created by `chm` on demand and `controlPlaneURL` is not a
    /// path at all.
    var absence: Absence {
        switch self {
        case .chmPath: .fallBackToDefault
        case .libraryPath, .localImagesPath: .keepAndSaySo
        case .socketPath, .controlPlaneURL: .expected
        }
    }

    enum Absence {
        case fallBackToDefault
        case keepAndSaySo
        case expected
    }

    /// What the path has to be able to *do*, which is not the same question as
    /// whether it is there.
    ///
    /// This distinction is the whole point. Asking `fileExists` of a snapshot
    /// library that exists and is empty returns `true`, and the app then starts
    /// with nothing in it and nothing to say — which is indistinguishable from
    /// being broken. Asking `fileExists` of `chmPath` returns `true` for a
    /// directory, or for a file with no execute bit, neither of which can be
    /// spawned.
    var needs: Requirement {
        switch self {
        case .chmPath: .executable
        // A library or image folder is *for* holding things. Empty is a legal
        // state, not an error -- but it is worth saying out loud, because the
        // symptom (an app with nothing in it) reads like a failure.
        case .libraryPath, .localImagesPath: .directoryWithSomethingIn
        case .socketPath, .controlPlaneURL: .nothing
        }
    }

    enum Requirement {
        case executable
        case directoryWithSomethingIn
        case nothing
    }
}

/// What a path turned out to be. Kept separate from `SettingsField` so the
/// policy stays pure and every branch below is reachable from a test without a
/// filesystem.
enum PathState: Equatable {
    case missing
    /// A directory with at least one visible entry in it.
    case populatedDirectory
    /// A directory that is there and has nothing in it.
    case emptyDirectory
    case executableFile
    /// A file that is there and cannot be spawned -- no execute bit, or it is a
    /// directory where a binary was expected.
    case notExecutable

    var exists: Bool { self != .missing }
}

/// Restores `AppSettings` across launches without letting a value saved weeks
/// ago quietly win an argument it should lose.
///
/// The precedence is **environment > saved > derived default**. An environment
/// variable is an explicit instruction from whoever started the process; a saved
/// value is an instruction from a past self. When they disagree the environment
/// wins for this launch, the saved value stays on disk untouched, and the
/// disagreement is reported rather than hidden.
enum SettingsStore {
    struct Restored: Equatable {
        var settings: AppSettings
        var notices: [Notice]
        /// Fields taking their value from the environment this launch. Writing
        /// these back would overwrite the user's own saved path with a
        /// transient environment value, losing it the moment the variable goes
        /// away — so `persist` skips them.
        var environmentOverridden: Set<SettingsField>
    }

    enum Notice: Equatable {
        /// A saved value lost to an environment variable for this launch.
        case environmentOverride(field: SettingsField, variable: String, saved: String, active: String)
        /// A saved path is gone and was replaced.
        case missingFallback(field: SettingsField, saved: String, fallback: String)
        /// A saved path is gone and was kept anyway, because absence is not fatal.
        case missingKept(field: SettingsField, saved: String)
        /// The directory is there and has nothing in it. Not an error — but the
        /// symptom (an app with an empty list) reads exactly like a broken one,
        /// so it is worth a sentence.
        case presentButEmpty(field: SettingsField, path: String)
        /// The path is there and cannot be run: a directory, or a file with no
        /// execute bit. `fileExists` says yes to both.
        case notExecutable(field: SettingsField, path: String)

        var message: String {
            switch self {
            case let .environmentOverride(field, variable, saved, active):
                "\(field.label): using \(active) from $\(variable); your saved \(saved) is unchanged and returns when the variable is unset."
            case let .missingFallback(field, saved, fallback):
                "\(field.label): \(saved) no longer exists, so this launch is using \(fallback)."
            case let .missingKept(field, saved):
                "\(field.label): \(saved) does not exist yet."
            case let .presentButEmpty(field, path):
                "\(field.label): \(path) exists but is empty, so this list will stay blank until something is put there."
            case let .notExecutable(field, path):
                "\(field.label): \(path) exists but cannot be run, so every command will fail."
            }
        }
    }

    /// Pure: no `UserDefaults`, no `ProcessInfo`, no filesystem. Everything the
    /// policy depends on arrives as an argument, so every branch below is
    /// reachable from a test.
    ///
    /// `probe` replaced an earlier `exists` predicate, and that swap *is* the
    /// fix: a path that is present but useless — an empty snapshot library, a
    /// `chm` that is a directory — passed the existence test and produced no
    /// notice at all, so the app came up empty and silent.
    static func restore(
        saved: [SettingsField: String],
        defaults: AppSettings,
        environment: [String: String],
        probe: (String) -> PathState
    ) -> Restored {
        var settings = defaults
        var notices: [Notice] = []
        var overridden: Set<SettingsField> = []

        for field in SettingsField.allCases {
            let fallback = defaults[keyPath: field.keyPath]
            let savedValue = saved[field].flatMap { $0.isEmpty ? nil : $0 }
            let fromEnvironment = field.environmentVariable
                .flatMap { environment[$0] }
                .flatMap { $0.isEmpty ? nil : $0 }

            var active: String
            if let fromEnvironment {
                active = fromEnvironment
                overridden.insert(field)
                if let savedValue, savedValue != fromEnvironment {
                    notices.append(.environmentOverride(
                        field: field,
                        variable: field.environmentVariable ?? "",
                        saved: savedValue,
                        active: fromEnvironment
                    ))
                }
            } else if let savedValue {
                active = savedValue
            } else {
                active = fallback
            }

            // Only a value the user chose is worth complaining about. A derived
            // default that is absent is the ordinary state of a fresh checkout,
            // and saying so on first launch would be noise, not help.
            let chosen = fromEnvironment ?? savedValue
            if let chosen {
                let state = probe(chosen)
                if !state.exists {
                    switch field.absence {
                    case .fallBackToDefault:
                        // Falling back to the same path we just rejected would be a
                        // notice that reads like a fix and changes nothing.
                        if fallback != chosen, probe(fallback).exists {
                            notices.append(.missingFallback(field: field, saved: chosen, fallback: fallback))
                            active = fallback
                        } else {
                            notices.append(.missingKept(field: field, saved: chosen))
                        }
                    case .keepAndSaySo:
                        notices.append(.missingKept(field: field, saved: chosen))
                    case .expected:
                        break
                    }
                } else {
                    // Present, and still possibly useless. This is the case the
                    // old existence check could not see at all.
                    switch (field.needs, state) {
                    case (.executable, .notExecutable),
                         (.executable, .populatedDirectory),
                         (.executable, .emptyDirectory):
                        // A directory named where a binary belongs cannot be
                        // spawned either, so it lands here rather than passing.
                        if fallback != chosen, probe(fallback) == .executableFile {
                            notices.append(.missingFallback(field: field, saved: chosen, fallback: fallback))
                            active = fallback
                        } else {
                            notices.append(.notExecutable(field: field, path: chosen))
                        }
                    case (.directoryWithSomethingIn, .emptyDirectory):
                        notices.append(.presentButEmpty(field: field, path: chosen))
                    default:
                        break
                    }
                }
            }

            settings[keyPath: field.keyPath] = active
        }

        return Restored(settings: settings, notices: notices, environmentOverridden: overridden)
    }

    /// The fields worth writing back: everything the environment is not
    /// currently dictating.
    static func persistable(
        _ settings: AppSettings,
        environmentOverridden: Set<SettingsField>
    ) -> [SettingsField: String] {
        var out: [SettingsField: String] = [:]
        for field in SettingsField.allCases where !environmentOverridden.contains(field) {
            out[field] = settings[keyPath: field.keyPath]
        }
        return out
    }

    // MARK: - The impure edges, kept thin on purpose

    static func load(defaults store: UserDefaults = .standard) -> Restored {
        var saved: [SettingsField: String] = [:]
        for field in SettingsField.allCases {
            if let value = store.string(forKey: field.defaultsKey) {
                saved[field] = value
            }
        }
        let fm = FileManager.default
        return restore(
            saved: saved,
            defaults: .defaults,
            environment: ProcessInfo.processInfo.environment,
            probe: { probeFilesystem($0, fm: fm) }
        )
    }

    /// The one place that touches the disk. Ordered so a directory is
    /// classified as a directory before anything asks whether it can be run —
    /// `isExecutableFile` answers **true** for a directory with the search bit
    /// set, which is exactly the trap that let a directory pass as `chm`.
    static func probeFilesystem(_ path: String, fm: FileManager = .default) -> PathState {
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDirectory) else { return .missing }
        if isDirectory.boolValue {
            let entries = (try? fm.contentsOfDirectory(atPath: path)) ?? []
            // `.DS_Store` and friends are not content the user put there, and
            // counting them would turn "empty" into a state nobody can reach.
            let visible = entries.filter { !$0.hasPrefix(".") }
            return visible.isEmpty ? .emptyDirectory : .populatedDirectory
        }
        return fm.isExecutableFile(atPath: path) ? .executableFile : .notExecutable
    }

    static func save(
        _ settings: AppSettings,
        environmentOverridden: Set<SettingsField>,
        defaults store: UserDefaults = .standard
    ) {
        for (field, value) in persistable(settings, environmentOverridden: environmentOverridden) {
            store.set(value, forKey: field.defaultsKey)
        }
    }
}
