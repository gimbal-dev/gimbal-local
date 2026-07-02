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

    func testInteractiveLivenessDecision() {
        // Lock present + owner alive => session is still live.
        XCTAssertFalse(InteractiveLiveness.sessionEnded(
            lockExists: true, ownerAlive: true, lockSeen: true, pastStartDeadline: false))

        // Lock present but the owning process is gone (stale SIGKILL lock) => ended.
        XCTAssertTrue(InteractiveLiveness.sessionEnded(
            lockExists: true, ownerAlive: false, lockSeen: true, pastStartDeadline: false))

        // Lock removed after we had seen it (clean teardown / window close) => ended.
        XCTAssertTrue(InteractiveLiveness.sessionEnded(
            lockExists: false, ownerAlive: false, lockSeen: true, pastStartDeadline: false))

        // Not seen yet and still within the start grace window => not ended (starting).
        XCTAssertFalse(InteractiveLiveness.sessionEnded(
            lockExists: false, ownerAlive: false, lockSeen: false, pastStartDeadline: false))

        // Never appeared and the grace window elapsed => give up, treat as ended.
        XCTAssertTrue(InteractiveLiveness.sessionEnded(
            lockExists: false, ownerAlive: false, lockSeen: false, pastStartDeadline: true))
    }

    func testRevisionDecodesLineageHeaderIgnoringHardwareState() throws {
        // Matches what chm writes to .chm-checkpoint/checkpoint.json: a lineage
        // header plus a heavy `state` object the app must ignore.
        let json = """
        {
          "manifest_version": 1,
          "id": "rev-0000000001234-ab12",
          "parent": "rev-0000000001000-ab12",
          "base_image": "ch-arm-v2m-demo",
          "created_at_ms": 1234,
          "origin": "daemon",
          "label": null,
          "state": {"version": 1, "vcpus": [], "gic_dist": [], "num_irq": 64}
        }
        """

        let rev = try JSONDecoder().decode(Revision.self, from: Data(json.utf8))

        XCTAssertEqual(rev.id, "rev-0000000001234-ab12")
        XCTAssertEqual(rev.parent, "rev-0000000001000-ab12")
        XCTAssertEqual(rev.baseImage, "ch-arm-v2m-demo")
        XCTAssertEqual(rev.origin, "daemon")
        XCTAssertNil(rev.label)
        XCTAssertEqual(rev.shortId, "ab12")
        XCTAssertEqual(rev.createdAt, Date(timeIntervalSince1970: 1.234))
    }

    func testParsesCloudSnapshotsWithProvenanceAndLocalCopy() throws {
        let json = """
        [
          {
            "snapshot_id": "snap-cb2039b86703",
            "status": "available",
            "kind": "checkpoint",
            "manifest": {
              "source_kind": "cloud-runner",
              "origin_substrate": "linux-kvm",
              "gic_mode": "gicv2m-message-spi",
              "vcpu_count": 1,
              "memory_bytes": 1073741824,
              "compatibility_status": "runnable"
            },
            "storage_locations": [
              {"kind": "object-store", "verified": true},
              {"kind": "local-runner", "verified": true}
            ]
          }
        ]
        """

        let snaps = CloudControlClient.parseSnapshots(Data(json.utf8))
        XCTAssertEqual(snaps.count, 1)
        let s = try XCTUnwrap(snaps.first)
        XCTAssertEqual(s.id, "snap-cb2039b86703")
        XCTAssertEqual(s.kind, "checkpoint")
        XCTAssertTrue(s.isCheckpoint)
        XCTAssertEqual(s.sourceKind, "cloud-runner")
        XCTAssertEqual(s.originSubstrate, "linux-kvm")
        XCTAssertEqual(s.vcpus, 1)
        XCTAssertEqual(s.ramMib, 1024)
        XCTAssertTrue(s.hasLocalCopy)
        XCTAssertTrue(s.restorableOnHVF)
        XCTAssertEqual(s.originLabel, "ran in cloud · linux-kvm")
    }

    func testCloudSnapshotGicGateMarksItsLpiCloudOnly() throws {
        let json = """
        [
          {
            "snapshot_id": "snap-itslpi",
            "status": "available",
            "kind": "full",
            "manifest": {
              "source_kind": "local-lima",
              "gic_mode": "its-lpi",
              "vcpu_count": 2,
              "memory_bytes": 2147483648,
              "compatibility_status": "runnable"
            },
            "storage_locations": [{"kind": "object-store", "verified": true}]
          }
        ]
        """

        let s = try XCTUnwrap(CloudControlClient.parseSnapshots(Data(json.utf8)).first)
        XCTAssertFalse(s.hasLocalCopy)
        XCTAssertFalse(s.restorableOnHVF, "its-lpi is not HVF-restorable")
        XCTAssertEqual(s.originLabel, "captured on Lima KVM")
        XCTAssertEqual(s.ramMib, 2048)
    }

    func testParsesCloudSnapshotsIgnoresMalformedEntries() throws {
        // Missing snapshot_id → dropped; empty array → empty result.
        XCTAssertTrue(CloudControlClient.parseSnapshots(Data("[{}]".utf8)).isEmpty)
        XCTAssertTrue(CloudControlClient.parseSnapshots(Data("[]".utf8)).isEmpty)
        XCTAssertTrue(CloudControlClient.parseSnapshots(Data("not json".utf8)).isEmpty)
    }

    func testStoredSandboxDecodesLegacyDataWithoutWorkspacePath() throws {
        // Sandboxes persisted before per-sandbox workspaces have no workspacePath.
        let legacy = """
        {"id":"s1","name":"box","snapshotName":"ubuntu","location":"local"}
        """
        let s = try JSONDecoder().decode(StoredSandbox.self, from: Data(legacy.utf8))
        XCTAssertEqual(s.id, "s1")
        XCTAssertEqual(s.location, .local)
        XCTAssertNil(s.workspacePath)
        // A round-trip with a workspace path is preserved.
        var withWS = s
        withWS.workspacePath = "/tmp/ws/s1"
        let back = try JSONDecoder().decode(StoredSandbox.self, from: JSONEncoder().encode(withWS))
        XCTAssertEqual(back.workspacePath, "/tmp/ws/s1")
    }

    func testDecodesRevisionSummariesFromChmRevisionsJSON() throws {
        let json = """
        [
          {"id":"rev-1-aaaa","parent":null,"base_image":"demo","created_at_ms":1000,"origin":"connect","label":null,"resumable":true,"is_head":false},
          {"id":"rev-2-bbbb","parent":"rev-1-aaaa","base_image":"demo","created_at_ms":2000,"origin":"rollback","label":null,"resumable":true,"is_head":true}
        ]
        """
        let revs = try JSONDecoder().decode([RevisionSummary].self, from: Data(json.utf8))
        XCTAssertEqual(revs.count, 2)
        XCTAssertEqual(revs[0].id, "rev-1-aaaa")
        XCTAssertNil(revs[0].parent)
        XCTAssertFalse(revs[0].isHead)
        XCTAssertEqual(revs[0].shortId, "aaaa")
        XCTAssertEqual(revs[1].parent, "rev-1-aaaa")
        XCTAssertEqual(revs[1].origin, "rollback")
        XCTAssertTrue(revs[1].isHead)
        XCTAssertTrue(revs[1].resumable)
    }

    @MainActor
    func testCloudSandboxSurfacesWithRemoteOriginAndTrackedState() {
        let model = AppModel()
        model.storedSandboxes = [
            StoredSandbox(id: "local-1", name: "local", snapshotName: "ubuntu", location: .local),
            StoredSandbox(id: "cloud-snap-x", name: "cloud x", snapshotName: "snap-x", location: .remote),
        ]
        // A cloud sandbox tracks its own run state, independent of the daemon.
        model.cloudSandboxStates["cloud-snap-x"] = .running
        XCTAssertEqual(model.sandbox(id: "cloud-snap-x")?.location, .remote)
        XCTAssertEqual(model.sandbox(id: "cloud-snap-x")?.state, .running)
        // The local sandbox is stopped (no active daemon sandbox).
        XCTAssertEqual(model.sandbox(id: "local-1")?.location, .local)
        XCTAssertEqual(model.sandbox(id: "local-1")?.state, .stopped)
        // A failed cloud run surfaces its own reason, not the daemon status.
        model.cloudSandboxStates["cloud-snap-x"] = .failed
        model.cloudSandboxReasons["cloud-snap-x"] = "Protocol fixture — needs a real snapshot."
        XCTAssertEqual(model.sandbox(id: "cloud-snap-x")?.state, .failed)
        XCTAssertEqual(model.sandbox(id: "cloud-snap-x")?.reason, "Protocol fixture — needs a real snapshot.")
    }

    // MARK: - Interactive terminal command safety (M30.3)

    func testInteractiveCommandSingleQuotesAdversarialPaths() throws {
        // A run path laden with shell metacharacters must be neutralized, not
        // executed: it appears exactly once, wrapped in single quotes, and the
        // dangerous substring never appears unquoted as host shell code.
        let evil = "/tmp/ws'; touch /tmp/pwned; echo $(whoami) `id`"
        let command = try InteractiveTerminalCommand.shellCommand(
            chmPath: "/usr/local/bin/chm",
            runPath: evil,
            socketPath: "/tmp/chm.sock",
            lockPath: nil,
            workdir: "/work"
        )
        // The connect invocation carries the path single-quoted (embedded quote
        // becomes the `'\''` close/escape/reopen sequence).
        XCTAssertTrue(
            command.contains("connect '/tmp/ws'\\''; touch /tmp/pwned; echo $(whoami) `id`'"),
            "the adversarial path must be single-quoted as one argument: \(command)"
        )
        // The injection never appears at a top-level (unquoted) command
        // position — it would only run if it were `&&`/`;`-joined outside the
        // quotes, which correct single-quoting prevents.
        XCTAssertFalse(
            command.contains("&& touch /tmp/pwned"),
            "the payload must not reach an unquoted command position"
        )
        XCTAssertEqual(
            command.components(separatedBy: "touch /tmp/pwned").count - 1, 1,
            "the payload appears exactly once (inside the quoted argument)"
        )
    }

    func testInteractiveCommandRejectsControlCharacters() {
        // A newline in a path breaks single-quote + AppleScript-literal
        // composition, so it is refused rather than quoted.
        XCTAssertThrowsError(
            try InteractiveTerminalCommand.shellCommand(
                chmPath: "/usr/local/bin/chm",
                runPath: "/tmp/ws\nactivate\ndo script \"rm -rf ~\"",
                socketPath: "/tmp/chm.sock",
                lockPath: nil,
                workdir: "/work"
            )
        ) { error in
            guard case InteractiveTerminalCommand.BuildError.invalidPath = error else {
                return XCTFail("expected invalidPath, got \(error)")
            }
        }
    }

    func testAppleScriptStringEscapesQuotesAndBackslashes() {
        // The AppleScript literal wrapper must escape backslash then quote, so a
        // crafted command string cannot terminate the `do script "…"` literal.
        XCTAssertEqual(
            InteractiveTerminalCommand.appleScriptString(#"a"b\c"#),
            #""a\"b\\c""#
        )
    }

    // MARK: - Branch surfacing (M27 Phase 4)

    func testDecodesPlaneBranchesFromChmBranchesJSON() throws {
        let json = """
        {"branches":[
          {"branch_id":"branch-1","owner":"dev","name":"laptop-main",
           "head_snapshot_id":"snap-6150377c50aa","review_status":"pending"},
          {"branch_id":"branch-2","owner":"dev","name":"acl-demo",
           "head_snapshot_id":"snap-d9a9a1529717",
           "page_acls":[{"audience":"runner-x"}]}
        ]}
        """
        let list = try JSONDecoder().decode(PlaneBranchList.self, from: Data(json.utf8))
        XCTAssertEqual(list.branches.count, 2)
        let main = list.branches[0]
        XCTAssertEqual(main.name, "laptop-main")
        XCTAssertEqual(main.shortHead, "6150377c50aa")
        XCTAssertEqual(main.reviewLabel, "pending")
        XCTAssertEqual(main.aclCount, 0)
        // A branch with no review gate reads as "open"; ACLs are counted.
        let acl = list.branches[1]
        XCTAssertEqual(acl.reviewLabel, "open")
        XCTAssertEqual(acl.aclCount, 1)
    }
}
