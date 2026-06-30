// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest
@testable import GimbalLocalApp

final class GimbalLocalAppTests: XCTestCase {
    func testParsesSnapshotListFromChmJSON() throws {
        let json = """
        {"snapshots":[{"name":"ubuntu","path":"/tmp/ubuntu","vcpus":2,"ram_mib":1024}]}
        """

        let snapshots = try ChmClient.parseSnapshotList(json)

        XCTAssertEqual(snapshots, [
            SnapshotSummary(name: "ubuntu", path: "/tmp/ubuntu", vcpus: 2, ramMib: 1024)
        ])
    }

    func testParsesRunningStatusFromChmJSON() throws {
        let json = """
        {"state":"running","name":"ubuntu","uptime_seconds":7,"console_bytes":42}
        """

        let status = try ChmClient.parseStatus(json)

        XCTAssertEqual(status.state, .running)
        XCTAssertEqual(status.name, "ubuntu")
        XCTAssertEqual(status.uptimeSeconds, 7)
        XCTAssertEqual(status.consoleBytes, 42)
    }

    func testCountsCommonControlPlaneEnvelopeShapes() throws {
        XCTAssertEqual(
            CloudControlClient.countItems(in: Data(#"[{"id":"r1"},{"id":"r2"}]"#.utf8)),
            2
        )
        XCTAssertEqual(
            CloudControlClient.countItems(in: Data(#"{"snapshots":[{"id":"s1"}]}"#.utf8)),
            1
        )
        XCTAssertEqual(
            CloudControlClient.countItems(in: Data(#"{"items":[{"id":"x"},{"id":"y"},{"id":"z"}]}"#.utf8)),
            3
        )
    }

    func testExtractsControlPlaneCostSummary() throws {
        XCTAssertEqual(
            CloudControlClient.shortSummary(from: Data(#"{"warning":"bare metal is running"}"#.utf8)),
            "bare metal is running"
        )
        XCTAssertEqual(
            CloudControlClient.shortSummary(from: Data(#"{"resources":[{"id":"i-1"}]}"#.utf8)),
            "1 running cloud resource(s)"
        )
    }

    @MainActor
    func testEngineIndicatorReflectsSandboxState() {
        let model = AppModel()

        model.status = SandboxStatus(state: .disconnected, name: nil, uptimeSeconds: nil, consoleBytes: nil, reason: nil, message: nil)
        XCTAssertEqual(model.engineIndicator.tone, .offline)

        model.status = SandboxStatus(state: .idle, name: nil, uptimeSeconds: nil, consoleBytes: nil, reason: nil, message: nil)
        XCTAssertEqual(model.engineIndicator.tone, .ready)

        model.status = SandboxStatus(state: .stopped, name: nil, uptimeSeconds: nil, consoleBytes: nil, reason: "boom", message: nil)
        XCTAssertEqual(model.engineIndicator.tone, .ready)

        model.status = SandboxStatus(state: .running, name: "ubuntu", uptimeSeconds: 3, consoleBytes: 0, reason: nil, message: nil)
        XCTAssertEqual(model.engineIndicator.tone, .active)
        XCTAssertEqual(model.engineIndicator.detail, "ubuntu")
    }

    @MainActor
    func testRecentSandboxesFloatRecentsToFront() {
        let model = AppModel()
        let alpha = SnapshotSummary(name: "alpha", path: "/a", vcpus: 1, ramMib: 256)
        let bravo = SnapshotSummary(name: "bravo", path: "/b", vcpus: 2, ramMib: 512)
        let charlie = SnapshotSummary(name: "charlie", path: "/c", vcpus: 4, ramMib: 1024)
        model.snapshots = [alpha, bravo, charlie]

        // No recents yet → fall back to library order.
        XCTAssertEqual(model.recentSandboxes.map(\.name), ["alpha", "bravo", "charlie"])

        // Recents float to the front (most-recent first); the rest follow.
        model.recentSandboxNames = ["charlie", "alpha"]
        XCTAssertEqual(model.recentSandboxes.map(\.name), ["charlie", "alpha", "bravo"])

        // Stale names not present in the library are ignored.
        model.recentSandboxNames = ["ghost", "bravo"]
        XCTAssertEqual(model.recentSandboxes.map(\.name), ["bravo", "alpha", "charlie"])
    }

    @MainActor
    func testCreateSandboxFromSnapshotMakesUniqueNames() {
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]

        let first = model.createSandbox(fromSnapshotNamed: "ubuntu")
        let second = model.createSandbox(fromSnapshotNamed: "ubuntu")

        XCTAssertEqual(first?.name, "ubuntu")
        XCTAssertEqual(second?.name, "ubuntu-2")
        XCTAssertEqual(model.sandboxes.count, 2)
        // Both instances share the same source image.
        XCTAssertEqual(Set(model.sandboxes.map(\.snapshotName)), ["ubuntu"])
        // A freshly created sandbox (not yet started) is stopped.
        XCTAssertEqual(first.map { model.sandbox(id: $0.id)?.state }, .some(.stopped))
    }

    @MainActor
    func testStartingSandboxIsNotRestartable() {
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let s = model.createSandbox(fromSnapshotNamed: "ubuntu")!

        // Mark a start in flight: the sandbox is "starting" and counts as live.
        model.startingSandboxID = s.id
        XCTAssertEqual(model.sandbox(id: s.id)?.state, .starting)
        XCTAssertTrue(model.hasLiveLocalSandbox)
    }

    @MainActor
    func testInteractiveSessionShowsRunningEvenWhenDaemonStopped() {
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let s = model.createSandbox(fromSnapshotNamed: "ubuntu")!

        // `chm connect` takes over the VM in its own process, so the daemon
        // reports nothing running — but the sandbox must still read as running
        // because the user is working inside it.
        model.interactiveSandboxID = s.id
        model.activeLocalSandboxID = s.id
        model.status = SandboxStatus(state: .disconnected, name: nil, uptimeSeconds: nil, consoleBytes: nil, reason: nil, message: nil)

        XCTAssertEqual(model.sandbox(id: s.id)?.state, .running)
        XCTAssertTrue(model.hasInteractiveSession)
    }

    @MainActor
    func testOnlyTheActiveSandboxReflectsRunningState() {
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let a = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        let b = model.createSandbox(fromSnapshotNamed: "ubuntu")!

        // Engine reports a running VM and `a` is the active instance.
        model.activeLocalSandboxID = a.id
        model.status = SandboxStatus(state: .running, name: "ubuntu", uptimeSeconds: 5, consoleBytes: 10, reason: nil, message: nil)

        XCTAssertEqual(model.sandbox(id: a.id)?.state, .running)
        XCTAssertEqual(model.sandbox(id: b.id)?.state, .stopped)
        XCTAssertEqual(model.sandbox(id: a.id)?.uptimeSeconds, 5)

        // A failed engine status surfaces on the active sandbox as `.failed`.
        model.status = SandboxStatus(state: .stopped, name: "ubuntu", uptimeSeconds: nil, consoleBytes: nil, reason: "boom", message: nil)
        XCTAssertEqual(model.sandbox(id: a.id)?.state, .failed)
    }
}
