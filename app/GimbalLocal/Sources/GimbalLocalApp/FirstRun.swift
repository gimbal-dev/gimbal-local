// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// What to tell someone who opens this app and cannot start anything yet.
///
/// Kept as a value computed from plain inputs rather than as logic inside a
/// SwiftUI view, so what the app says on a first run — and, more importantly,
/// *whether it lets you press the button* — is unit-tested.
///
/// The distinction that matters is between a user who has nothing and a user
/// who has something that did not work. The second one has already tried, and
/// `LocalImageLibrary` already knows exactly what is wrong and how to fix it
/// (`Rejection.reason` names the remedy: "gunzip it first", "use `cp -c`").
/// Showing that only after a failed attempt wastes the best explanation we have.
enum FirstRunGuidance {
    /// A cold boot needs no snapshot, no KVM host and no control plane, so a
    /// local image is the one path that works on a Mac that has never talked to
    /// either. The empty state must never imply otherwise.
    struct State: Equatable {
        /// Whether *anything* can be started. Drives the New sandbox button.
        let canStartSomething: Bool
        let headline: String
        let detail: String
        /// Directories that look like image attempts but were refused, with the
        /// reason. Empty unless the user has actually put something there.
        let rejections: [(name: String, reason: String)]

        static func == (lhs: State, rhs: State) -> Bool {
            lhs.canStartSomething == rhs.canStartSomething
                && lhs.headline == rhs.headline
                && lhs.detail == rhs.detail
                && lhs.rejections.map(\.name) == rhs.rejections.map(\.name)
                && lhs.rejections.map(\.reason) == rhs.rejections.map(\.reason)
        }
    }

    /// What a usable image directory contains. Stated once, here, so the empty
    /// state and the New sandbox menu cannot drift apart on the answer.
    static let layoutHelp = """
        An image is a **folder** containing an uncompressed arm64 `Image` \
        kernel. Everything else is optional: an `initramfs`, raw disks \
        (`rootfs.img` becomes `/dev/vda`), and an `image.json` naming them \
        explicitly if the filenames differ.
        """

    /// The same load-bearing fact as `layoutHelp`, short enough for a menu row.
    ///
    /// Deliberately **plain prose with no markdown**: SwiftUI only parses
    /// markdown out of string *literals*, so a runtime string in a menu renders
    /// its backticks as literal characters. `layoutHelp` keeps its markdown
    /// because the empty state renders it through `Text.authored`.
    ///
    /// Both are checked against each other by a test, so the menu and the empty
    /// state cannot come to disagree about what a kernel file is.
    static func layoutOneLine(imagesPath: String) -> String {
        "Put a folder with an uncompressed arm64 Image file in \(imagesPath)"
    }

    /// Strip markdown emphasis for somewhere that cannot render it — menus, in
    /// practice. Applied to `Rejection.reason`, which is authored as markdown
    /// for the empty state and would otherwise leak backticks into a menu row.
    static func plain(_ markdown: String) -> String {
        markdown.replacingOccurrences(of: "`", with: "")
    }

    static func evaluate(
        hasSnapshots: Bool,
        localImages: [LocalImageLibrary.Entry],
        imagesPath: String
    ) -> State {
        let bootable = localImages.filter { $0.image != nil }
        let refused = localImages.filter { $0.image == nil }
        let rejections = refused.map {
            (name: $0.name, reason: $0.rejection?.reason ?? "unusable")
        }

        // A bootable local image is sufficient on its own. Gating the button on
        // snapshots is the bug this replaces: cold boot exists precisely so the
        // app does not need something captured on a KVM host first.
        let canStart = hasSnapshots || !bootable.isEmpty
        if canStart {
            return State(
                canStartSomething: true,
                headline: "No sandboxes yet",
                detail: "Create your first sandbox — from a snapshot image, or by "
                    + "cold-booting a local image.",
                rejections: rejections
            )
        }

        // Something is there and none of it worked. This is the most useful
        // state to be in, because the reason is already known precisely.
        if !refused.isEmpty {
            let noun = refused.count == 1 ? "folder" : "folders"
            return State(
                canStartSomething: false,
                headline: "Nothing here can boot yet",
                detail: "Found \(refused.count) \(noun) in `\(imagesPath)` that cannot "
                    + "be used. Each reason below names the fix.",
                rejections: rejections
            )
        }

        // Nothing anywhere: the true first run. Teach the layout and say where
        // we are looking, because neither is guessable.
        return State(
            canStartSomething: false,
            headline: "Add an image to get started",
            detail: "\(layoutHelp)\n\nDrop one into `\(imagesPath)` — the folder name "
                + "becomes the image name. Change where this app looks in Settings › "
                + "Paths › Local images.\n\nA cold boot needs no snapshot and no "
                + "control plane, so this works on a Mac that has never had either.",
            rejections: []
        )
    }
}
