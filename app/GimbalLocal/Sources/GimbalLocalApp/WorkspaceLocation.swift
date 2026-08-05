// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// Where a sandbox's state actually lives, and whether that is still somewhere
/// the user expects.
///
/// A sandbox records the workspace path it was created with and never revisits
/// it. That is the right default — relocating a running sandbox's storage out
/// from under it would be worse than leaving it — but it interacts badly with a
/// library setting that was wrong at the time. Every sandbox created while
/// `libraryPath` pointed at an abandoned folder is still bound to it. They run,
/// so nothing looks wrong, and their state sits in a directory the user has
/// moved on from and will plausibly delete.
///
/// **The app states this and does not act on it.** Silently relocating a
/// workspace is a data-moving operation performed on someone's behalf without
/// asking, and #192 was about the app doing things without saying so — the fix
/// for which is not a different unannounced action. So: name the path, mark it
/// when it is outside the current library, name the remedy, stop.
///
/// Pure string work on purpose. No filesystem, so every branch is reachable from
/// a test, and so this cannot become slow enough to matter in a view body.
enum WorkspaceLocation {
    struct State: Equatable {
        /// The workspace directory, as recorded on the sandbox.
        let path: String
        /// True when it does not sit under the current library's workspace root.
        let outsideLibrary: Bool
        /// The sentence shown when `outsideLibrary`. `nil` otherwise — a sandbox
        /// in the ordinary place has nothing to explain.
        let note: String?
        /// What to do about it, when there is something to do.
        let remedy: String?
    }

    /// The directory workspaces are created in for a given library path. Must
    /// agree with `AppModel.workspacePath(for:)`; it is derived from the same
    /// rule (a sibling of the library, so it never appears in the daemon's image
    /// scan) rather than repeated as a literal.
    static func workspaceRoot(libraryPath: String) -> String {
        URL(fileURLWithPath: (libraryPath as NSString).standardizingPath)
            .deletingLastPathComponent()
            .appendingPathComponent(".chm-workspaces")
            .path
    }

    /// - Parameters:
    ///   - workspacePath: the path recorded on the sandbox, or `nil` if it has
    ///     never been started. `nil` returns `nil`: a sandbox with no workspace
    ///     has no location to be wrong about, and inventing one would report an
    ///     orphan that does not exist yet.
    ///   - libraryPath: the library as configured *now*.
    static func evaluate(workspacePath: String?, libraryPath: String) -> State? {
        guard let workspacePath, !workspacePath.isEmpty else { return nil }
        let path = (workspacePath as NSString).standardizingPath
        let root = workspaceRoot(libraryPath: libraryPath)

        guard !isContained(path: path, in: root) else {
            return State(path: path, outsideLibrary: false, note: nil, remedy: nil)
        }

        return State(
            path: path,
            outsideLibrary: true,
            note:
                "This sandbox's state is kept outside the current library. It was created while "
                + "the library pointed somewhere else, and a sandbox keeps the workspace it was "
                + "created with.",
            remedy:
                "It still works from there. Nothing moves it, so deleting that folder would "
                + "delete this sandbox's disk and saved revisions. To keep it with the others, "
                + "remove and recreate the sandbox — that starts a fresh workspace under the "
                + "current library, and loses what is in the old one."
        )
    }

    /// Path containment by components, not by prefix. `"/a/b-old"` has
    /// `"/a/b"` as a string prefix and is a different directory; a check that
    /// missed that would report an orphaned sandbox as fine, which is the one
    /// answer that must never be wrong here.
    static func isContained(path: String, in root: String) -> Bool {
        let p = components(path)
        let r = components(root)
        guard !r.isEmpty, p.count > r.count else { return false }
        return Array(p.prefix(r.count)) == r
    }

    private static func components(_ path: String) -> [String] {
        path.split(separator: "/").map(String.init)
    }
}
