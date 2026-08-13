// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// How often a running sandbox checkpoints itself, without stopping.
///
/// V9.1 shipped the cadence in the engine and a timeline in the app, and the
/// two never met: the only way to turn it on was `CHM_SNAPSHOT_INTERVAL_SECS`,
/// which the app never set. So the headline capability — *a session that ends
/// badly is not a session whose work is gone* — was unreachable for anyone who
/// had not read `docs/environment-variables.md` before launching the app.
///
/// The choices are deliberately few and fixed. A free-form seconds field would
/// invite `1`, and a checkpoint freezes the guest while it captures RAM, so the
/// cost of a bad answer lands on the guest rather than on the form. The steps
/// below are far enough apart that picking the next one up is a real decision.
enum SnapshotCadence: Int, CaseIterable, Identifiable, Codable {
    case off = 0
    case everyFifteenSeconds = 15
    case everyMinute = 60
    case everyFiveMinutes = 300

    var id: Int { rawValue }

    /// Where the choice is stored. Declared here rather than in `AppModel`
    /// because the read happens in a `@Published` initializer, which cannot see
    /// `self` — so the alternative is the literal written out twice, once for
    /// the read and once for the write, with a typo in either one silently
    /// meaning "the setting never persisted".
    static let defaultsKey = "gimbal.snapshotCadence"

    /// The value handed to `chm --snapshot-every`. Seconds is the unit on both
    /// sides, and `off` is `0` rather than an omitted flag **on purpose**: the
    /// flag beats `CHM_SNAPSHOT_INTERVAL_SECS`, so passing `0` is how a user who
    /// chose "off" stays off inside an environment that turns the cadence on.
    /// Omitting the flag would silently defer to that environment and hand them
    /// a cadence they had just declined.
    var seconds: Int { rawValue }

    var label: String {
        switch self {
        case .off: "Off"
        case .everyFifteenSeconds: "Every 15 seconds"
        case .everyMinute: "Every minute"
        case .everyFiveMinutes: "Every 5 minutes"
        }
    }

    /// The honest way to let someone choose an interval is their own number,
    /// not ours — so this describes the shape of the trade and points at where
    /// `chm` prints the freeze it actually measured, rather than quoting a
    /// figure measured on different hardware with a different guest.
    static let explanation =
        "A running sandbox saves its live state on this cadence, so closing a "
        + "window or a crash does not lose the session. Each save briefly "
        + "freezes the guest to capture memory — chm prints how long it "
        + "actually took, in the session window — and only the most recent "
        + "saves stay resumable."

    /// How points arrive in the timeline, given this cadence.
    ///
    /// The empty-state hints used to say only *"end the session to save its
    /// live state"*, which was accurate exactly because the app could not turn
    /// the cadence on. It stops being accurate the moment it can, so the
    /// sentence has to move with the setting rather than be a literal in a
    /// view — otherwise this is the #192 shape again, where the app knows
    /// something true and renders something else.
    ///
    /// When the cadence is off the hint also names where to turn it on, since
    /// an empty timeline is exactly when someone is wondering why it is empty.
    var howPointsArrive: String {
        switch self {
        case .off:
            "Ending a session (close its terminal, or Stop it) saves its live "
                + "state as a point here. To have that happen on a cadence "
                + "while it runs, turn on Settings › General › Save live state."
        default:
            "Points are saved \(label.lowercased()) while a sandbox runs, and "
                + "again when a session ends."
        }
    }

    /// Read the stored choice.
    ///
    /// An absent key reads as `0`, which is also `.off` — so a first launch and
    /// a deliberate "off" are the same answer here, and that is correct while
    /// off is the default. It stops being correct the day the default changes:
    /// a silent `0` would then hold every existing user at the old default with
    /// no way to tell that from a choice, and this is where the
    /// `object(forKey:)` check goes when that happens. It is *not* here now,
    /// because a check that cannot change an answer still reports that
    /// something was checked.
    ///
    /// An unrecognised value falls back to off rather than to the nearest
    /// cadence. A value written by a newer build means we do not know what was
    /// chosen, and freezing someone's guest on an interval they never picked is
    /// a worse answer than not freezing it at all.
    static func stored(in defaults: UserDefaults, key: String) -> SnapshotCadence {
        SnapshotCadence(rawValue: defaults.integer(forKey: key)) ?? .off
    }
}
