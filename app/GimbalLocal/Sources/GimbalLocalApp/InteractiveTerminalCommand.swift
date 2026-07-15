// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// Builds the shell command Gimbal Local hands to Terminal.app to open an
/// interactive `chm connect` session.
///
/// Security (M30.1/M30.3 — see `docs/security-model.md`, invariant I5): the app
/// launches host commands, so it must never let a path or setting become host
/// shell code. Terminal.app's `do script` runs a command *string*, so a raw
/// argv is not an option for `chm` itself; instead this builder single-quotes
/// every interpolated value (robust against every shell metacharacter) and
/// rejects control characters — newlines/NUL/ESC never appear in a real path and
/// are exactly what would break the single-quote composition. The resulting
/// command string is delivered to `osascript` as an argv parameter (not
/// interpolated into the AppleScript source, see `AppModel`), so this is the
/// only escaping layer. The logic is a pure, static builder so it is unit-tested
/// against adversarial inputs rather than exercised only through the live
/// Terminal.
enum InteractiveTerminalCommand {
    enum BuildError: Error, LocalizedError, Equatable {
        /// A path contained a control character (newline, NUL, …) and was refused.
        case invalidPath(String)

        var errorDescription: String? {
            switch self {
            case .invalidPath(let path):
                return "refusing to open a terminal for a path with control characters: \(path)"
            }
        }
    }

    /// The first banner line (constant, no interpolation).
    private static let sessionBanner = "Gimbal Local interactive session"
    /// The usage hint shown before the session starts (constant, no interpolation).
    private static let usageHint =
        "Login with ubuntu / ubuntu if prompted. Close this window or press "
        + "Ctrl-A x to end the session — it suspends the sandbox (live state "
        + "saved); reconnect to resume where you left off."

    /// Shown once the session ends, so the window makes clear it is over — the
    /// guest is gone and this is no longer a sandbox prompt (constant, no
    /// interpolation).
    private static let sessionEndedNotice =
        "-- Sandbox session ended. Reopen it from Gimbal Local to reconnect. --"

    /// Single-quote `value` for POSIX `sh`: wrap in `'…'`, closing/escaping/
    /// reopening each embedded single quote (`'\''`). Inside single quotes every
    /// other character — `;`, `$( )`, backticks, `&&`, spaces — is literal, so
    /// this neutralizes shell injection.
    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// True when `value` has no control characters (the class that breaks quoting
    /// composition and never legitimately appears in a filesystem path).
    static func isCleanPath(_ value: String) -> Bool {
        !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    /// Build the `&&`-joined shell command that `cd`s to `workdir`, prints the
    /// banner, and runs `chm connect <runPath>` against `socketPath` (with an
    /// optional session lock). Every interpolated path is validated and quoted.
    ///
    /// Throws `BuildError.invalidPath` if any path carries a control character.
    static func shellCommand(
        chmPath: String,
        runPath: String,
        socketPath: String,
        lockPath: String?,
        workdir: String
    ) throws -> String {
        var paths = [chmPath, runPath, socketPath, workdir]
        if let lockPath { paths.append(lockPath) }
        for path in paths where !isCleanPath(path) {
            throw BuildError.invalidPath(path)
        }

        var connect = [
            shellQuote(chmPath), "connect", shellQuote(runPath),
            "--socket", shellQuote(socketPath),
            "--checkpoint", "--idle-exit", "0",
        ]
        if let lockPath {
            connect.append(contentsOf: ["--session-lock", shellQuote(lockPath)])
        }

        return [
            "cd \(shellQuote(workdir))",
            "echo \(shellQuote(sessionBanner))",
            "echo \(shellQuote(usageHint))",
            connect.joined(separator: " "),
        ].joined(separator: " && ")
            // Once `chm connect` exits (the guest shut down or the session was
            // suspended), print a clear end-of-session notice and exit the shell
            // instead of dropping back to an interactive host shell sitting in
            // the workspace directory — where an unwitting `ls`/`rm` would hit
            // the Mac, not the (now gone) sandbox. `;` (not `&&`) so the notice
            // and exit run on any chm exit status.
            + "; echo \(shellQuote(sessionEndedNotice)); exit"
    }
}
