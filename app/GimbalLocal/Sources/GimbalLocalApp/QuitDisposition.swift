// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import Foundation

/// What quitting should do about the daemon this app started (#360).
///
/// Quitting used to leave `chm serve` running forever. A macOS child is
/// reparented to launchd when its parent exits, not killed, and the app
/// implemented no termination hook — so the daemon outlived the UI that owned
/// it. That bites three ways: the HVF VM slot is process-global, so an orphan
/// holding a guest makes the next `chm run` fail `HV_BUSY` with nothing on
/// screen to blame; the next launch adopts the orphan, silently pinning the
/// previous library; and quitting an app is a reasonable way to expect its VM
/// engine to stop.
///
/// The obvious-looking alternative does not work. `--idle-exit` is *not* a
/// daemon idle timer: `idle_exit_secs` reaches only the guest run loop
/// (`chm/src/serve.rs:1482`), where it exits a **guest** after console silence.
/// Passing a non-zero value would kill quiet guests and still leak the daemon.
///
/// The decision is kept separate from the acting so it can be tested without an
/// `NSApplication`. The wiring that consults it is guarded separately, because
/// a test that only exercises this enum would pass against the original bug.
enum QuitDisposition: Equatable {
    /// This app started no daemon. Whatever is listening is not ours to stop,
    /// and quitting leaks nothing.
    case nothingToStop

    /// We started a daemon and no guest is running. Stop it, then quit.
    case stopDaemon

    /// We started a daemon and guests are running. #192/#195: do not stop a
    /// running guest without saying so. Name them and let the user choose.
    case confirm(running: [String])

    /// `startedDaemon` must mean *this app holds the process handle*, not
    /// merely that a daemon is reachable. Adopting an orphan and then killing
    /// it on quit would stop an engine the user did not start here.
    static func decide(startedDaemon: Bool, runningGuests: [RunRecord]) -> QuitDisposition {
        guard startedDaemon else { return .nothingToStop }
        guard !runningGuests.isEmpty else { return .stopDaemon }
        return .confirm(running: runningGuests.map(\.label))
    }

    /// The prompt shown for `.confirm`, naming what is still running.
    ///
    /// It names the guests rather than saying "some guests are running",
    /// because the whole point of asking is that the user can only make the
    /// choice if they know what they are about to lose.
    static func confirmationMessage(running: [String]) -> String {
        let list = running.map { "  \u{2022} \($0)" }.joined(separator: "\n")
        let noun = running.count == 1 ? "guest is" : "guests are"
        return "\(running.count) \(noun) still running:\n\n\(list)\n\n"
            + "Quitting stops the local engine and these guests with it."
    }
}
