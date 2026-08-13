// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// Whether the library this app is *configured* for is the library actually
/// being *served*.
///
/// The snapshot list does not come from `settings.libraryPath`. It comes from
/// the daemon: `chm ctl list` is answered by whichever `chm serve` owns the
/// socket, and that daemon's library is fixed at `chm serve <dir>` with no
/// per-request override. The app connects to a daemon it did not necessarily
/// start — `startDaemon` guards on the app's *own* process handle, so one left
/// by the CLI or a previous run is adopted as-is — and nothing restarts a
/// daemon when the setting changes.
///
/// So the two can disagree, and when they do every surface that describes the
/// configured path is describing something that is not producing the list. The
/// observed symptom was a settings banner saying the library "is empty, so this
/// list will stay blank" directly above a sidebar listing seven snapshots. The
/// app was contradicting itself on screen, which is the G9 failure #192 and
/// #195/#196 exist to stop.
///
/// **Deliberately not a fix that restarts the daemon.** Doing that on a
/// settings change would stop a running guest without asking — the same
/// unannounced action #192 and #195 both refused. State the disagreement, name
/// what is in force, say how to resolve it, and stop.
///
/// Pure string work: no filesystem, no process, so every branch is reachable
/// from a test and this cannot be slow in a view body.
enum LibraryAgreement {
    struct State: Equatable {
        /// The library actually answering `chm ctl list`.
        let serving: String
        /// What this app has configured.
        let configured: String
        /// The sentence describing the disagreement.
        let note: String
        /// What to do about it.
        let remedy: String
    }

    /// - Parameters:
    ///   - daemonLibrary: `library` from `chm ctl status --json`, or `nil` when
    ///     the daemon is unreachable or predates the field. `nil` returns `nil`:
    ///     a daemon that did not say cannot be reported as disagreeing, and
    ///     guessing would produce a warning that is wrong half the time.
    ///   - configured: `settings.libraryPath`.
    /// - Returns: `nil` when they agree or when there is nothing to compare.
    static func evaluate(daemonLibrary: String?, configured: String) -> State? {
        guard let daemonLibrary, !daemonLibrary.isEmpty, !configured.isEmpty else { return nil }

        let serving = (daemonLibrary as NSString).standardizingPath
        let mine = (configured as NSString).standardizingPath
        guard serving != mine else { return nil }

        return State(
            serving: serving,
            configured: mine,
            note:
                "The snapshot list is coming from \(serving), not the library configured here. "
                + "A running engine keeps the library it was started with, and this app connected "
                + "to one that was already running.",
            remedy:
                "Nothing is lost — the snapshots in \(mine) are still there, just not being read. "
                + "Stop the engine and let the app start it again to serve \(mine), or set the "
                + "library here to \(serving) to match what is running."
        )
    }
}
