// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

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
        An image is a **folder** containing an arm64 `Image` kernel — \
        gzip and EFI zboot kernels such as Alpine's `vmlinuz-virt` are \
        unwrapped for you. Everything else is optional: an `initramfs`, raw \
        disks (`rootfs.img` becomes `/dev/vda`), and an `image.json` naming \
        them explicitly if the filenames differ.
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
        "Put a folder with an arm64 Image kernel (gzip is fine) in \(imagesPath)"
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
        imagesPath: String,
        // No default. A default is what let the call site drop this argument
        // and still compile, so every test asserting the *outcome* stayed green
        // while the app went back to denying a running guest. Requiring it makes
        // that mutation a compile error rather than a silent regression — the
        // same move that keeps the `fcntl` variadic declaration from reverting.
        runningGuests: Int
    ) -> State {
        // "No sandboxes yet" while a guest this app started is running in a
        // Terminal window is the lie #225 reports, and it is a lie the app is
        // uniquely placed to tell: a cold boot is a subprocess, so it never
        // becomes a saved sandbox no matter how long it runs. Say what is
        // actually true instead — there is nothing *saved* — and name the
        // difference, because it is the thing a reader does not know.
        if runningGuests > 0 {
            let noun = runningGuests == 1 ? "guest is" : "guests are"
            return State(
                canStartSomething: true,
                headline: "Nothing saved yet",
                detail: "\(runningGuests) \(noun) running now, listed under "
                    + "**Running now**. A cold boot runs straight from an image "
                    + "and is not saved as a sandbox, so this page stays empty "
                    + "until you create one from a snapshot.",
                rejections: []
            )
        }
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

    /// The one-paragraph pitch on the welcome banner.
    ///
    /// **This is not decoration.** The banner shipped saying *"create a sandbox
    /// from a snapshot image"* and nothing else — the exact sentence #175
    /// removed from the empty state, because a snapshot is captured on a KVM
    /// host and someone whose only machine is this Mac cannot produce one. The
    /// banner is the *more* prominent of the two: it renders first, and it keeps
    /// rendering after the empty state has been replaced by a sandbox list. So
    /// the fix landed in one place and the lie survived in the louder one.
    ///
    /// A value rather than a literal in the view, so a test can assert both
    /// routes are named. Kept to prose a banner can hold; the layout detail
    /// lives in `layoutHelp`.
    static let welcome = """
        Cold-boot a local image, or rehydrate a Cloud Hypervisor snapshot \
        brought down from the cloud. Either way the engine starts itself and \
        you get a terminal inside the sandbox.
        """
}
