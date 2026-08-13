// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// Why "Open terminal" would do nothing.
///
/// #192 gave Start a named refusal, a remedy button and a disabled state. Open
/// terminal was left with the original shape — `appendLog` and `return` — and it
/// is the *more* likely button to be pressed, because it is the primary action
/// on a sandbox row.
///
/// **This is not `SlotContention` called in one more place.** Start and Open
/// terminal fail for different sets of reasons: opening a terminal additionally
/// needs a `chm` that can be spawned, a Terminal.app to spawn it in, and an
/// image still in the library. Copying the slot check alone would have fixed the
/// case we happened to hit and left the rest silent — the same mistake in a new
/// place. So the slot case is *reused* (it is genuinely shared) and the rest is
/// enumerated here.
///
/// **Every blocker is reported, not just the first.** Clearing one and finding
/// another waiting is how a fixable problem comes to feel like a broken app.
///
/// **A missing workspace is deliberately not a blocker.** `ensureWorkspace`
/// recreates one from the image when `state.json` is absent — self-healing that
/// predates this and is load-bearing (it is what lets the workspace directory be
/// deleted to reclaim space). Listing it here would refuse a launch that works.
/// What genuinely cannot be recovered is the *image*, and that is checked.
enum TerminalLaunch {
    /// One reason, in the two parts a user needs: what is true, and what to do.
    struct Blocker: Equatable {
        /// What is wrong, in a sentence.
        let message: String
        /// What resolves it. Always present — a refusal without a way forward is
        /// the failure this type exists to end.
        let remedy: String
        /// Set only when the app can resolve it in one press. `nil` means the
        /// remedy is something the user does elsewhere, and inventing a button
        /// for it would promise an action the app cannot perform.
        let remedyLabel: String?
    }

    /// Everything that must hold before a terminal can open, gathered in one
    /// place so a new precondition cannot be added without deciding what the
    /// user is told about it.
    struct Preconditions: Equatable {
        /// From `SlotContention.evaluate` — the one genuinely shared refusal.
        var slot: SlotContention.State?
        /// The image this sandbox was created from.
        var snapshotName: String
        /// Whether that image is still in the library. `ensureWorkspace` needs
        /// it to (re)create a workspace, and `chm` needs it to boot.
        var snapshotInLibrary: Bool
        /// What the configured `chm` path turned out to be, from the same probe
        /// Settings uses — so the app cannot hold two opinions about whether
        /// `chm` is usable.
        var chm: PathState
        /// The path being probed, so the message can name it.
        var chmPath: String
        /// Whether a Terminal.app was found to hand the command to.
        var terminalAppPresent: Bool

        init(
            slot: SlotContention.State? = nil,
            snapshotName: String = "",
            snapshotInLibrary: Bool = true,
            chm: PathState = .executableFile,
            chmPath: String = "",
            terminalAppPresent: Bool = true
        ) {
            self.slot = slot
            self.snapshotName = snapshotName
            self.snapshotInLibrary = snapshotInLibrary
            self.chm = chm
            self.chmPath = chmPath
            self.terminalAppPresent = terminalAppPresent
        }
    }

    /// Ordered most-fundamental first: without `chm` nothing else matters, and a
    /// held slot is last because it is the only transient one — it resolves
    /// itself the moment the other sandbox stops.
    ///
    /// Empty means the launch is expected to work. It must stay empty in the
    /// common case or the card becomes noise nobody reads.
    static func blockers(_ p: Preconditions) -> [Blocker] {
        var out: [Blocker] = []

        if let chm = chmBlocker(state: p.chm, path: p.chmPath) {
            out.append(chm)
        }

        if !p.snapshotInLibrary {
            out.append(
                Blocker(
                    message: "The image \(p.snapshotName) is no longer in the library.",
                    remedy:
                        "A sandbox boots from its image every time, so it cannot open without one. "
                        + "Restore it, or point the library at the folder that holds it in Settings.",
                    remedyLabel: nil
                )
            )
        }

        if !p.terminalAppPresent {
            out.append(
                Blocker(
                    message: "Terminal.app was not found.",
                    remedy:
                        "The session runs in Terminal.app, which the app asks macOS to open. "
                        + "Reinstall or re-enable it, then try again.",
                    remedyLabel: nil
                )
            )
        }

        if let slot = p.slot {
            out.append(
                Blocker(
                    message: slot.message,
                    remedy: "Stop it and this sandbox can take the slot.",
                    remedyLabel: slot.remedyLabel
                )
            )
        }

        return out
    }

    /// A `chm` that cannot be spawned is reported *here*, before the click,
    /// rather than as a Terminal window that opens and says "command not found"
    /// — which reads as a broken sandbox rather than a wrong setting.
    private static func chmBlocker(state: PathState, path: String) -> Blocker? {
        let named = path.isEmpty ? "The chm path" : path
        let settings = "Set the chm path in Settings."
        switch state {
        case .executableFile:
            return nil
        case .missing:
            return Blocker(
                message: "\(named) is not there.",
                remedy: "The sandbox engine is what the terminal session runs. \(settings)",
                remedyLabel: nil
            )
        case .notExecutable:
            return Blocker(
                message: "\(named) cannot be run.",
                remedy: "It needs the execute bit — `chmod +x` it, or \(settings.lowercasedFirst)",
                remedyLabel: nil
            )
        case .emptyDirectory, .populatedDirectory:
            return Blocker(
                message: "\(named) is a folder, not the chm binary.",
                remedy: "Point it at the executable itself, usually `target/debug/chm`. \(settings)",
                remedyLabel: nil
            )
        }
    }
}

extension String {
    /// Lets one canonical sentence be reused mid-sentence without keeping a
    /// second copy of its wording, which would be a place for the two to drift.
    var lowercasedFirst: String {
        guard let first else { return self }
        return first.lowercased() + dropFirst()
    }
}
