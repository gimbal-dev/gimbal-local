// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest

@testable import GimbalLocalApp

/// Whether a sandbox's state is still somewhere the user expects it.
///
/// The bug this closes is not that these sandboxes are broken — they run fine.
/// It is that their state sits in a folder the user abandoned when they fixed
/// their library setting, and nothing on screen says so.
final class WorkspaceLocationTests: XCTestCase {
    private let library = "/Users/x/gimbal-images"
    private var root: String { WorkspaceLocation.workspaceRoot(libraryPath: library) }

    func testTheRootIsASiblingOfTheLibrary() {
        // Must agree with AppModel.workspacePath(for:), which puts workspaces
        // beside the library so they never appear in the daemon's image scan.
        XCTAssertEqual(root, "/Users/x/.chm-workspaces")
    }

    func testASandboxUnderTheCurrentLibraryHasNothingToExplain() {
        let state = WorkspaceLocation.evaluate(
            workspacePath: root + "/abc-123",
            libraryPath: library
        )
        XCTAssertEqual(state?.outsideLibrary, false)
        XCTAssertNil(state?.note)
        XCTAssertNil(state?.remedy)
    }

    func testASandboxLeftBehindByAFixedLibrarySettingIsMarked() {
        // The reported case: created while libraryPath pointed at an abandoned
        // folder, still bound to it after the setting was corrected.
        let state = WorkspaceLocation.evaluate(
            workspacePath: "/Users/x/gimbal-persist-test/.chm-workspaces/abc-123",
            libraryPath: library
        )
        XCTAssertEqual(state?.outsideLibrary, true)
        XCTAssertNotNil(state?.note)
        XCTAssertNotNil(state?.remedy)
    }

    func testTheRemedyWarnsThatDeletingTheFolderDestroysTheSandbox() {
        // The whole point of surfacing this: the user is about to tidy up a
        // folder they think is dead.
        let state = WorkspaceLocation.evaluate(
            workspacePath: "/elsewhere/.chm-workspaces/abc",
            libraryPath: library
        )
        let remedy = try? XCTUnwrap(state?.remedy)
        XCTAssertEqual(remedy?.contains("delet"), true, remedy ?? "")
    }

    func testTheAppNeverOffersToMoveIt() {
        // Silently relocating a workspace is a data-moving operation done on
        // someone's behalf without asking — the exact class of thing #192 was
        // about. The remedy names an explicit, lossy action instead.
        let state = WorkspaceLocation.evaluate(
            workspacePath: "/elsewhere/.chm-workspaces/abc",
            libraryPath: library
        )
        let remedy = state?.remedy ?? ""
        XCTAssertTrue(remedy.contains("remove and recreate"), remedy)
        XCTAssertFalse(remedy.lowercased().contains("move it for you"), remedy)
    }

    func testANeverStartedSandboxHasNoLocationToBeWrongAbout() {
        XCTAssertNil(WorkspaceLocation.evaluate(workspacePath: nil, libraryPath: library))
        XCTAssertNil(WorkspaceLocation.evaluate(workspacePath: "", libraryPath: library))
    }

    // MARK: - containment

    func testASiblingWithASharedPrefixIsNotContained() {
        // "/a/b-old" has "/a/b" as a string prefix and is a different directory.
        // A prefix check would call an orphaned sandbox fine, which is the one
        // answer that must never be wrong here.
        XCTAssertFalse(WorkspaceLocation.isContained(path: "/a/b-old/c", in: "/a/b"))
        XCTAssertTrue(WorkspaceLocation.isContained(path: "/a/b/c", in: "/a/b"))
    }

    func testARootIsNotContainedInItself() {
        // The workspace root itself is not a workspace; treating it as one would
        // silently accept a path that cannot hold a sandbox.
        XCTAssertFalse(WorkspaceLocation.isContained(path: "/a/b", in: "/a/b"))
    }

    func testTrailingSlashesAndDoubleSeparatorsDoNotChangeTheAnswer() {
        XCTAssertTrue(WorkspaceLocation.isContained(path: "/a/b/c/", in: "/a/b/"))
        XCTAssertTrue(WorkspaceLocation.isContained(path: "/a//b/c", in: "/a/b"))
    }

    func testRelativeSegmentsAreResolvedBeforeComparing() {
        // "…/.chm-workspaces/../elsewhere/abc" is outside, and reads as inside.
        let state = WorkspaceLocation.evaluate(
            workspacePath: "/Users/x/.chm-workspaces/../elsewhere/abc",
            libraryPath: library
        )
        XCTAssertEqual(state?.outsideLibrary, true)
        XCTAssertFalse(state?.path.contains("..") ?? true, state?.path ?? "")
    }
}
