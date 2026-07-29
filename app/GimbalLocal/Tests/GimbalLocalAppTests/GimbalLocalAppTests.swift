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

    func testDecodesEgressPolicyAndDerivesAllowListMode() throws {
        // The shape `chm firewall show --json` emits.
        let json = """
        {"source":"local","default":"deny","allow":["api.github.com:443"],"deny":[],
         "label":"local","restrictive":true,"path":"/ws/egress-policy.json"}
        """
        let policy = try JSONDecoder().decode(EgressPolicy.self, from: Data(json.utf8))

        XCTAssertEqual(policy.source, "local")
        XCTAssertEqual(policy.defaultStance, "deny")
        XCTAssertEqual(policy.allow, ["api.github.com:443"])
        XCTAssertTrue(policy.restrictive)
        XCTAssertEqual(policy.mode, .allowList)
        XCTAssertFalse(policy.isControlPlaneBound)
    }

    func testEgressPolicyModeDerivation() {
        let open = EgressPolicy(source: "none", defaultStance: "allow", allow: [], deny: [],
                                label: nil, restrictive: false, path: nil)
        XCTAssertEqual(open.mode, .open)
        XCTAssertEqual(EgressPolicy.unrestricted.mode, .open)

        let offline = EgressPolicy(source: "local", defaultStance: "deny", allow: [], deny: [],
                                   label: "local", restrictive: true, path: nil)
        XCTAssertEqual(offline.mode, .noNetwork)

        let bound = EgressPolicy(source: "control-plane", defaultStance: "deny",
                                 allow: ["x:443"], deny: [], label: "sha256:abc",
                                 restrictive: true, path: nil)
        XCTAssertEqual(bound.mode, .allowList)
        XCTAssertTrue(bound.isControlPlaneBound)
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
    func testEngineIndicatorReflectsLiveConnectSessionWhenDaemonIdle() {
        // An app-launched sandbox runs via `chm connect` (its own VM, tracked by
        // a session lock) that the daemon can't see. The engine bar must reflect
        // it as running instead of "idle" when the daemon slot reads idle (#61).
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let s = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        // Daemon reports idle (its single VM slot is empty)...
        model.status = SandboxStatus(state: .idle, name: nil, uptimeSeconds: nil, consoleBytes: nil, reason: nil, message: nil)
        // ...but the session registry knows this sandbox has a live VM.
        model.liveLocalSessionIDs = [s.id]

        XCTAssertEqual(model.sandbox(id: s.id)?.state, .running)
        XCTAssertEqual(model.engineIndicator.tone, .active, "a live connect session must not read idle")
        XCTAssertEqual(model.engineIndicator.label, "Sandbox running")

        // When the session ends, the engine falls back to the daemon's idle.
        model.liveLocalSessionIDs = []
        XCTAssertEqual(model.engineIndicator.tone, .ready)
    }

    @MainActor
    func testSlotHolderGuardsTheSingleVMSlot() {
        // The single HVF slot: while one sandbox holds a live session, launching
        // another must be refused. slotHolder reports the occupant (#71).
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let a = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        let b = model.createSandbox(fromSnapshotNamed: "ubuntu")!

        // No live sessions -> the slot is free for either.
        XCTAssertNil(model.slotHolder(excluding: a.id))
        XCTAssertNil(model.slotHolder(excluding: b.id))

        // A is live: launching B is blocked by A (the slot holder), but A itself
        // is not blocked by its own session.
        model.liveLocalSessionIDs = [a.id]
        XCTAssertEqual(model.slotHolder(excluding: b.id)?.id, a.id)
        XCTAssertNil(model.slotHolder(excluding: a.id), "a sandbox never blocks itself")
    }

    @MainActor
    func testLiveSessionRegistryDrivesSandboxState() {
        // The registry is authoritative for local liveness, independent of the
        // daemon and of which console the app is tracking (#71).
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let s = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        XCTAssertEqual(model.sandbox(id: s.id)?.state, .stopped)

        model.liveLocalSessionIDs = [s.id]
        XCTAssertEqual(model.sandbox(id: s.id)?.state, .running)
        XCTAssertTrue(model.hasLiveLocalSandbox)
    }

    @MainActor
    func testReconcileSessionsScansRealLocksAndReapsDeadOnes() throws {
        // Exercise the REAL scan/reap path against on-disk lock files: a lock
        // owned by this (live) process is detected; a lock owned by a dead PID is
        // not counted and is reaped. This is the ground truth behind liveness
        // across app restarts (#71) — not a preset flag.
        let model = AppModel()
        model.snapshots = [SnapshotSummary(name: "ubuntu", path: "/u", vcpus: 1, ramMib: 1024)]
        let liveSb = model.createSandbox(fromSnapshotNamed: "ubuntu")!
        let deadSb = model.createSandbox(fromSnapshotNamed: "ubuntu")!

        // A guaranteed-dead PID: run /usr/bin/true and wait for it to exit.
        let corpse = Process()
        corpse.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try corpse.run()
        corpse.waitUntilExit()
        let deadPID = corpse.processIdentifier

        let livePID = ProcessInfo.processInfo.processIdentifier
        let liveLock = model.sessionLockPath(for: liveSb.id)
        let deadLock = model.sessionLockPath(for: deadSb.id)
        try "\(livePID)".write(toFile: liveLock, atomically: true, encoding: .utf8)
        try "\(deadPID)".write(toFile: deadLock, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: liveLock) }

        model.reconcileSessions()

        XCTAssertTrue(model.liveLocalSessionIDs.contains(liveSb.id), "a live lock owner is detected")
        XCTAssertFalse(model.liveLocalSessionIDs.contains(deadSb.id), "a dead lock owner is not counted")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: deadLock),
            "a dead session's lock is reaped"
        )
        XCTAssertEqual(model.sandbox(id: liveSb.id)?.state, .running)
        XCTAssertEqual(model.sandbox(id: deadSb.id)?.state, .stopped)
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

    func testSaneGlobalDefaultsHaveProtectiveCaps() {
        // Out of the box, a runaway can't exhaust the host: disk + console are
        // capped and limits are on; the firewall is ON in default-deny mode
        // (M31.2) so a new sandbox has no public egress until allow-listed. Host
        // loopback/LAN are always blocked by the reserved-address guard (M31.1).
        let d = GlobalDefaults.sane
        XCTAssertTrue(d.limits.enabled)
        XCTAssertEqual(d.limits.maxDiskMb, 8192)
        XCTAssertEqual(d.limits.maxConsoleMb, 64)
        XCTAssertTrue(d.firewall.enabled)
        XCTAssertEqual(d.firewall.mode, .allowlist)
        XCTAssertTrue(d.firewall.allow.isEmpty)
    }

    func testGlobalDefaultsCodableRoundtrips() {
        let d = GlobalDefaults(
            limits: DefaultLimits(enabled: true, maxVcpus: 4, maxMemoryMb: 4096,
                                  maxDiskMb: 2048, maxWallSeconds: 3600, maxConsoleMb: 32,
                                  maxConnections: 128, maxBandwidthKbps: 5000),
            firewall: DefaultFirewall(enabled: true, mode: .allowlist, allow: ["github.com:443"])
        )
        let data = try! JSONEncoder().encode(d)
        let back = try! JSONDecoder().decode(GlobalDefaults.self, from: data)
        XCTAssertEqual(back, d)
    }

    @MainActor
    func testGlobalDefaultsPersistAcrossModelInstances() {
        let a = AppModel()
        a.globalDefaults.limits.maxDiskMb = 1234
        a.globalDefaults.firewall.enabled = true
        a.globalDefaults.firewall.mode = .noNetwork
        a.saveGlobalDefaults()

        let b = AppModel()
        b.loadGlobalDefaults()
        XCTAssertEqual(b.globalDefaults.limits.maxDiskMb, 1234)
        XCTAssertTrue(b.globalDefaults.firewall.enabled)
        XCTAssertEqual(b.globalDefaults.firewall.mode, .noNetwork)

        // Restore the sane defaults so this test doesn't leak into others.
        b.globalDefaults = .sane
        b.saveGlobalDefaults()
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
        // because the user is working inside it. Post-reconcile, the session
        // registry holds it live (what the grace period / lock scan produces).
        model.interactiveSandboxID = s.id
        model.activeLocalSandboxID = s.id
        model.liveLocalSessionIDs = [s.id]
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

    func testCloudSnapshotVanillaItsLpiIsRestorableHere() throws {
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
        XCTAssertTrue(s.restorableOnHVF,
                      "a vanilla its-lpi capture runs on the userspace GICv3")
        XCTAssertEqual(s.originLabel, "captured on Lima KVM")
        XCTAssertEqual(s.ramMib, 2048)
    }

    /// An interrupt routing we have no path for at all stays cloud-only, and the
    /// reason names the mode rather than prescribing a GICv2M recapture.
    func testCloudSnapshotUnknownGicModeIsNotRestorable() {
        let s = CloudSnapshot(
            id: "snap-odd", status: "available", kind: "full",
            sourceKind: nil, gicMode: "gic-v4-vlpi", originSubstrate: nil,
            vcpus: 1, ramMib: 1024, compatibility: "runnable", hasLocalCopy: false
        )
        XCTAssertFalse(s.restorableOnHVF)
        XCTAssertFalse(s.likelyBootable)
        XCTAssertEqual(s.notBootableReason,
                       "Interrupt routing `gic-v4-vlpi` is not one this Mac can rehydrate")
    }

    /// The plane refusing to release a bundle is a *different* statement from
    /// this Mac being unable to run it, and the UI must not conflate them.
    func testPlaneRefusalIsReportedSeparatelyFromLocalCapability() {
        let s = CloudSnapshot(
            id: "snap-gated", status: "available", kind: "full",
            sourceKind: nil, gicMode: "its-lpi", originSubstrate: nil,
            vcpus: 1, ramMib: 1024, compatibility: "incompatible", hasLocalCopy: false
        )
        XCTAssertTrue(s.restorableOnHVF, "we can run it")
        XCTAssertFalse(s.planeWillRelease, "the plane will not hand it over")
        XCTAssertFalse(s.likelyBootable)
        XCTAssertEqual(s.notBootableReason,
                       "The control plane classifies this as incompatible, so it will not release it")
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

    func testInteractiveCommandEndsSessionInsteadOfHostShell() throws {
        // When chm exits (guest shut down / suspended), the terminal must not
        // fall through to an interactive host shell in the workspace dir — where
        // an `ls`/`rm` would hit the Mac. The command prints an end notice and
        // exits the shell, on any chm exit status (`;`, not `&&`).
        let command = try InteractiveTerminalCommand.shellCommand(
            chmPath: "/usr/local/bin/chm",
            runPath: "/tmp/ws",
            socketPath: "/tmp/chm.sock",
            lockPath: nil,
            workdir: "/work"
        )
        XCTAssertTrue(command.hasSuffix("; exit"), "session must exit the shell: \(command)")
        XCTAssertTrue(
            command.contains("; echo '-- Sandbox session ended."),
            "an end-of-session notice must be shown before exit: \(command)"
        )
        // The chm invocation is reached with `&&` but the teardown uses `;` so it
        // runs regardless of how chm exits.
        XCTAssertTrue(command.contains("--idle-exit 0; echo "), "teardown must be ;-joined: \(command)")
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

    // MARK: - Branch surfacing (M27 Phase 4)

    func testCloudSnapshotFlagsFixturesWithoutDiskImages() {
        let base = { (hasDisk: Bool) in
            CloudSnapshot(
                id: "snap-x", status: "available", kind: "full",
                sourceKind: "local-lima", gicMode: "gicv2m-message-spi",
                originSubstrate: nil, vcpus: 1, ramMib: 1024,
                compatibility: "runnable", hasLocalCopy: false, hasDiskImage: hasDisk
            )
        }
        // A real snapshot (ships a disk) is bootable.
        let real = base(true)
        XCTAssertTrue(real.likelyBootable)
        XCTAssertNil(real.notBootableReason)
        // A fixture (runnable + gicv2m, but no disk image) is caught pre-flight.
        let fixture = base(false)
        XCTAssertFalse(fixture.likelyBootable)
        XCTAssertEqual(fixture.notBootableReason,
                       "No disk image — a protocol fixture, not a bootable snapshot")
    }

    func testParsesDiskImagePresenceFromManifestChecksumTree() {
        let json = """
        [{"snapshot_id":"snap-real","status":"available","kind":"full",
          "manifest":{"gic_mode":"gicv2m-message-spi","compatibility_status":"runnable",
            "memory_bytes":1073741824,"vcpu_count":1,
            "checksum_tree":{"state.json":"a","snapshot/memory-ranges":"b","disks/_disk0.raw":"c"}}},
         {"snapshot_id":"snap-fixture","status":"available","kind":"full",
          "manifest":{"gic_mode":"gicv2m-message-spi","compatibility_status":"runnable",
            "memory_bytes":1073741824,"vcpu_count":1,
            "checksum_tree":{"state.json":"a","snapshot/memory-ranges":"b"}}}]
        """
        let snaps = CloudControlClient.parseSnapshots(Data(json.utf8))
        XCTAssertEqual(snaps.count, 2)
        XCTAssertTrue(snaps.first { $0.id == "snap-real" }!.hasDiskImage)
        XCTAssertTrue(snaps.first { $0.id == "snap-real" }!.likelyBootable)
        XCTAssertFalse(snaps.first { $0.id == "snap-fixture" }!.hasDiskImage)
        XCTAssertFalse(snaps.first { $0.id == "snap-fixture" }!.likelyBootable)
    }

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

// MARK: - Console input encoding

/// `chm ctl input` decodes `\n`, `\t`, `\xNN` and `\\`, so a line typed by a user
/// has to be escaped or it arrives at the guest as something else entirely.
final class ConsoleInputEncodingTests: XCTestCase {
    func testAPlainLineGetsAnExplicitReturn() {
        // `chm ctl input TEXT` sends TEXT as-is with no trailing newline, so the
        // Return has to be part of the payload.
        XCTAssertEqual(ChmClient.encodeLine("uname -m"), "uname -m\\n")
    }

    func testAnEmptyLineIsJustAReturn() {
        XCTAssertEqual(ChmClient.encodeLine(""), "\\n")
    }

    func testReturnCanBeSuppressed() {
        XCTAssertEqual(ChmClient.encodeLine("partial", pressReturn: false), "partial")
    }

    func testABackslashInTheUsersTextSurvivesVerbatim() {
        // The bug this guards: unescaped, `printf 'a\nb'` would reach the guest
        // as two lines and the command would be mangled.
        XCTAssertEqual(
            ChmClient.encodeLine(#"printf 'a\nb'"#),
            #"printf 'a\\nb'\n"#
        )
    }

    func testAHexEscapeInTheUsersTextIsNotReinterpreted() {
        XCTAssertEqual(ChmClient.encodeLine(#"echo \x41"#), #"echo \\x41\n"#)
    }

    func testControlKeysCarryTheirHexEscapes() {
        XCTAssertEqual(ConsoleKey.interrupt.wireText, "\\x03")
        XCTAssertEqual(ConsoleKey.endOfFile.wireText, "\\x04")
        XCTAssertEqual(ConsoleKey.clearLine.wireText, "\\x15")
        XCTAssertEqual(ConsoleKey.returnKey.wireText, "\\n")
    }
}
