// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

/// Which stored sandbox the daemon's running VM belongs to.
///
/// The app used to answer this from `activeLocalSandboxID`, a variable set when
/// *this process* started a sandbox. It is in-memory only, so quitting and
/// reopening the app lost it — and then every row read **Stopped** while
/// `chm ctl status` said `running`, because the running VM matched no sandbox
/// the app believed it had started. The daemon was reporting the answer the
/// whole time and nobody read it.
///
/// So the daemon's own report is the durable signal, and it survives a restart
/// precisely because it does not live in this process.
enum DaemonRunOwner {
    /// - Parameters:
    ///   - reportedName: `SandboxStatus.name` — what the daemon calls the VM it
    ///     is running. App-created sandboxes are workspaces named by UUID, so
    ///     this is usually a sandbox `id`; a sandbox started from a library
    ///     entry reports that library name instead.
    ///   - candidates: `(id, name)` for every local stored sandbox.
    ///
    /// Returns the matching sandbox `id`, or `nil` when the daemon is running
    /// something this app does not know about — a `chm run` from a terminal,
    /// say. Claiming an unrelated row would be worse than saying nothing.
    static func match(reportedName: String?, candidates: [(id: String, name: String)]) -> String? {
        guard let reportedName, !reportedName.isEmpty else { return nil }

        // Identity first: an id is unambiguous, a display name is not.
        if let byID = candidates.first(where: { $0.id == reportedName }) {
            return byID.id
        }

        // Names are user-chosen and need not be unique. Two sandboxes sharing a
        // name would make this a coin toss, and marking the wrong one running
        // would then also disable Start on the one that is genuinely stopped —
        // so an ambiguous name resolves to nothing at all.
        let byName = candidates.filter { $0.name == reportedName }
        return byName.count == 1 ? byName[0].id : nil
    }
}
