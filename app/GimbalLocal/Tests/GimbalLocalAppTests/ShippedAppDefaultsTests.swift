// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation
import Testing

@testable import GimbalLocalApp

/// The value: can this app find its own parts on a Mac that has never seen the
/// source tree?
///
/// Every one of these paths worked for two years because every run happened
/// inside a checkout. `repoRootCandidate()` always found something, so the
/// last-resort branches were never taken and never noticed. These tests take
/// them deliberately, by passing `repoRoot: nil` — the state of a downloaded
/// `.app` and a state a test running inside this repo cannot otherwise reach.
@Suite("Shipped-app defaults")
struct ShippedAppDefaultsTests {
    private let home = URL(fileURLWithPath: "/Users/someone")
    private let checkout = URL(fileURLWithPath: "/Users/someone/src/gimbal-local")

    // MARK: - chm

    /// The bug #144 is about. A shipped app has no checkout, so this is the
    /// branch every downloaded copy takes on first launch.
    @Test("with no checkout, chm resolves inside the bundle")
    func testBundledChmWins() {
        let resolved = AppSettings.resolveChmPath(
            env: nil,
            bundled: "/Applications/Gimbal Local.app/Contents/MacOS/chm",
            repoRoot: nil,
            home: home
        )
        #expect(resolved == "/Applications/Gimbal Local.app/Contents/MacOS/chm")
    }

    /// Version skew is the hazard: the app parses `chm`'s JSON output, so a
    /// stale `target/debug/chm` from an unrelated branch would be found and
    /// used silently. The bundled binary is the one this app was built and
    /// signed against, so it wins even when a checkout is sitting right there.
    @Test("a bundled chm is preferred over a checkout that happens to be present")
    func testBundledBeatsCheckout() {
        let resolved = AppSettings.resolveChmPath(
            env: nil,
            bundled: "/Applications/Gimbal Local.app/Contents/MacOS/chm",
            repoRoot: checkout,
            home: home
        )
        #expect(resolved.hasPrefix("/Applications/"))
        #expect(!resolved.contains("target/debug"))
    }

    /// A debug bundle deliberately ships no `chm`, so developers keep getting
    /// their working build. That absence is the whole mechanism — there is no
    /// mode flag to set wrongly.
    @Test("a debug build with no bundled chm still finds the checkout")
    func testDeveloperKeepsTheirBuild() {
        let resolved = AppSettings.resolveChmPath(
            env: nil,
            bundled: nil,
            repoRoot: checkout,
            home: home
        )
        #expect(resolved == "/Users/someone/src/gimbal-local/target/debug/chm")
    }

    @Test("CHM_PATH overrides everything")
    func testEnvWins() {
        let resolved = AppSettings.resolveChmPath(
            env: "/opt/chm",
            bundled: "/Applications/Gimbal Local.app/Contents/MacOS/chm",
            repoRoot: checkout,
            home: home
        )
        #expect(resolved == "/opt/chm")
    }

    /// An empty environment variable is not a choice. Treating `CHM_PATH=""` as
    /// an answer would resolve to nothing at all and report it as a missing
    /// binary rather than as an unset variable.
    @Test("an empty CHM_PATH is ignored rather than obeyed")
    func testEmptyEnvIgnored() {
        let resolved = AppSettings.resolveChmPath(
            env: "",
            bundled: nil,
            repoRoot: checkout,
            home: home
        )
        #expect(resolved.contains("target/debug/chm"))
    }

    // MARK: - the library

    /// The regression that made "nothing starts from the UI" look like an empty
    /// library. An app launched from Finder inherits `/` as its working
    /// directory, so a relative `"snapshots"` meant `/snapshots` — which nobody
    /// can create without root.
    @Test("with no checkout the library is absolute, never relative")
    func testLibraryIsAbsolute() {
        let resolved = AppSettings.resolveLibraryPath(env: nil, repoRoot: nil, home: home)
        #expect(resolved.hasPrefix("/"))
        #expect(resolved == "/Users/someone/gimbal-snapshots")
    }

    /// It sits beside `~/gimbal-images`, so the two halves of an install are in
    /// one place rather than one in the home directory and one under `/`.
    @Test("the library is a sibling of the images directory")
    func testLibrarySitsBesideImages() {
        let library = AppSettings.resolveLibraryPath(env: nil, repoRoot: nil, home: home)
        #expect(URL(fileURLWithPath: library).deletingLastPathComponent().path == home.path)
    }

    @Test("a checkout still wins for developers")
    func testLibraryPrefersCheckout() {
        let resolved = AppSettings.resolveLibraryPath(env: nil, repoRoot: checkout, home: home)
        #expect(resolved == "/Users/someone/src/gimbal-local/snapshots")
    }

    @Test("GIMBAL_LIBRARY overrides everything")
    func testLibraryEnvWins() {
        let resolved = AppSettings.resolveLibraryPath(
            env: "/mnt/library", repoRoot: checkout, home: home
        )
        #expect(resolved == "/mnt/library")
    }

    // MARK: - the invariant that covers paths nobody has thought of yet

    /// Whatever the branch, a resolved path must be absolute. A relative path
    /// is not a worse answer than a wrong one — it is a *silent* one, because
    /// it resolves against a working directory that differs between a Finder
    /// launch and a terminal launch. The same input then behaves differently
    /// depending on how the app was started.
    @Test("no resolution, on any branch, can return a relative path")
    func testNoBranchReturnsRelative() {
        let bundles = ["/Applications/Gimbal Local.app/Contents/MacOS/chm", nil]
        let roots: [URL?] = [checkout, nil]
        for bundled in bundles {
            for root in roots {
                let chm = AppSettings.resolveChmPath(
                    env: nil, bundled: bundled, repoRoot: root, home: home
                )
                #expect(chm.hasPrefix("/"), "chm path is relative: \(chm)")
            }
            _ = bundled
        }
        for root in roots {
            let library = AppSettings.resolveLibraryPath(env: nil, repoRoot: root, home: home)
            #expect(library.hasPrefix("/"), "library path is relative: \(library)")
        }
    }
}

// MARK: - Path presentation

@Suite("Display paths")
struct DisplayPathTests {
    @Test("a path inside home is abbreviated")
    func insideHome() {
        #expect(DisplayPath.abbreviated("/Users/ana/gimbal-snapshots", home: "/Users/ana")
            == "~/gimbal-snapshots")
    }

    @Test("home itself is just a tilde")
    func homeItself() {
        #expect(DisplayPath.abbreviated("/Users/ana", home: "/Users/ana") == "~")
    }

    /// The one that must never be wrong. `/Users/ana` is a *string* prefix of
    /// `/Users/anabel`, and they are different people's directories — so a
    /// prefix check would render somebody else's path as `~/work`, which does
    /// not exist. Same lesson as `WorkspaceLocation.isContained`.
    @Test("a sibling sharing a prefix is not abbreviated")
    func siblingPrefix() {
        #expect(DisplayPath.abbreviated("/Users/anabel/work", home: "/Users/ana")
            == "/Users/anabel/work")
    }

    @Test("a path outside home is left alone")
    func outsideHome() {
        #expect(DisplayPath.abbreviated("/opt/snapshots", home: "/Users/ana") == "/opt/snapshots")
    }

    /// A relative path cannot be resolved against a home directory, so it is
    /// returned untouched rather than guessed at.
    @Test("a relative path is left alone")
    func relativePath() {
        #expect(DisplayPath.abbreviated("snapshots", home: "/Users/ana") == "snapshots")
    }

    @Test("trailing slashes do not defeat the match")
    func trailingSlashes() {
        #expect(DisplayPath.abbreviated("/Users/ana/lib/", home: "/Users/ana/") == "~/lib")
    }
}
