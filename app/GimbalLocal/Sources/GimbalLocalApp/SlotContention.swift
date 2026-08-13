// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// Why Start did nothing.
///
/// `hv_vm_create` is process-global on Apple silicon: one VM per process. The
/// app runs each guest as its own `chm` subprocess and holds a single live slot,
/// so starting a second sandbox while one is running is refused.
///
/// **The refusal was always correct. It was delivered nowhere.** `startSandbox`
/// wrote "X is using the single local VM slot" to `appendLog`, which lands in
/// the Activity page — so pressing Start on a stopped sandbox did nothing
/// visible, no error, no state change, and the app read as broken when it was
/// working exactly as designed. The same failure shape as a silently-ignored
/// spec field: the program knows precisely what is wrong and says it somewhere
/// nobody is looking.
///
/// Kept as a value over plain inputs rather than logic inside a view, so *what
/// the user is told* is unit-tested — the same reason `FirstRunGuidance` is a
/// value.
enum SlotContention {
    struct State: Equatable {
        /// The sandbox currently holding the single VM slot.
        let holderName: String
        /// Shown next to the disabled Start button.
        let message: String
        /// The label of the button that resolves it, naming the holder so the
        /// destructive action cannot be misread as acting on the sandbox the
        /// user is looking at.
        let remedyLabel: String
    }

    /// The constraint stated once, here, so the card and any future call site
    /// cannot come to disagree about *why* this happens.
    static let reason =
        "Apple's Hypervisor.framework allows one VM per process, and each sandbox runs in its own."

    /// - Parameters:
    ///   - holderName: the sandbox holding the slot, or `nil` if it is free.
    ///     Callers pass `slotHolder(excluding:)` so a sandbox never reports
    ///     itself as its own blocker.
    ///   - thisSandboxIsLive: whether the sandbox being looked at is the one
    ///     running. A live sandbox is not blocked by anything.
    ///
    /// Returns `nil` when there is nothing to say, which is the common case —
    /// this must never become a banner that is always on screen.
    static func evaluate(holderName: String?, thisSandboxIsLive: Bool) -> State? {
        guard !thisSandboxIsLive, let holderName, !holderName.isEmpty else { return nil }
        return State(
            holderName: holderName,
            message: "\(holderName) is running and holds the single VM slot. \(reason)",
            remedyLabel: "Stop \(holderName)"
        )
    }
}
