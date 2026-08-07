import Foundation

/// One guest running on this machine, as `chm ps` reports it.
///
/// The engine owns this fact because the app cannot hold it. A cold boot is
/// launched into Terminal.app through `osascript`, so this process never sees
/// the child's PID, and `chm ctl list` only ever describes what the *daemon*
/// started. Between them the app had no way to know that its own flagship
/// feature was running (#225).
struct RunRecord: Codable, Equatable, Identifiable {
    enum Kind: String, Codable {
        /// `chm create` — a cold boot, with no snapshot in the path.
        case cold
        /// `chm run` — a snapshot rehydrated directly.
        case run
        /// `chm connect` — an interactive session against a sandbox.
        case connect
    }

    let pid: Int32
    let kind: Kind
    let label: String
    let source: String
    let startedAtMs: UInt64
    let vcpus: Int
    let memoryMib: UInt64

    var id: Int32 { pid }

    enum CodingKeys: String, CodingKey {
        case pid
        case kind
        case label
        case source
        case startedAtMs = "started_at_ms"
        case vcpus
        case memoryMib = "memory_mib"
    }

    /// How this run was started, in words a reader can act on.
    var kindDescription: String {
        switch kind {
        case .cold: "Cold boot"
        case .run: "Snapshot"
        case .connect: "Session"
        }
    }

    var sizeDescription: String {
        "\(vcpus) vCPU · \(memoryMib) MiB"
    }

    /// How long this guest has been up, given the current wall clock.
    ///
    /// Taken as a parameter rather than read from `Date()` so the formatting is
    /// testable without waiting for real time to pass.
    func uptimeDescription(now: Date) -> String {
        let started = Date(timeIntervalSince1970: Double(startedAtMs) / 1000)
        let seconds = max(0, Int(now.timeIntervalSince(started)))
        if seconds < 60 { return "\(seconds)s" }
        if seconds < 3600 { return "\(seconds / 60)m" }
        return "\(seconds / 3600)h \((seconds % 3600) / 60)m"
    }
}

struct RunList: Codable, Equatable {
    let runs: [RunRecord]
}

/// Which running guests the app is not already showing somewhere else.
///
/// `chm connect` registers its runs too, and those are the sessions the app
/// already tracks by session lock and already renders as a running sandbox. So
/// the registry is a superset of what is on screen, and listing all of it would
/// report one guest twice — the same double-count the daemon's guest is kept out
/// of the registry to avoid.
///
/// Attribution is **by PID**, not by name. A label is a directory name and two
/// sandboxes can share one; a PID is the operating system's own answer to "is
/// this the same process", which is exactly the question being asked. The
/// V9.11 rule applies here too: where a name would have to be guessed, do not
/// guess.
///
/// A pure function over its inputs so the rule can be tested without a running
/// guest, a daemon, or a Terminal window.
func unattributedRuns(all: [RunRecord], attributedPIDs: Set<Int32>) -> [RunRecord] {
    all.filter { !attributedPIDs.contains($0.pid) }
}
