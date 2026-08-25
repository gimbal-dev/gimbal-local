// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

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
            workdir: "/work",
            cadence: .everyFiveMinutes
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
            workdir: "/work",
            cadence: .off
        )
        XCTAssertTrue(command.hasSuffix("; exit"), "session must exit the shell: \(command)")
        XCTAssertTrue(
            command.contains("; echo '-- Sandbox session ended."),
            "an end-of-session notice must be shown before exit: \(command)"
        )
        // The chm invocation is reached with `&&` but the teardown uses `;` so it
        // runs regardless of how chm exits.
        // Asserted against the notice rather than "whatever flag is last", so
        // adding a flag to the connect invocation does not silently retarget
        // this at a different property.
        XCTAssertFalse(
            command.contains("&& echo '-- Sandbox session ended."),
            "teardown must not be &&-joined, or it is skipped when chm fails: \(command)"
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
                workdir: "/work",
                cadence: .everyMinute
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

    // MARK: - Security posture (V6.1)

    /// Verbatim output of `chm ctl posture` against a daemon started with
    /// `CHM_ALLOW_LOCAL_EGRESS=1`, captured 2026-07-31. Not hand-written: the
    /// splice that injects `source`/`assessed` is a string edit on the opening
    /// brace, so a fixture typed from memory would not exercise it.
    private static let daemonPostureJSON = """
    {
      "source": "daemon",
      "assessed": "library-root",
      "workspace": "/tmp/gimbal-test/v61/lib",
      "weakened": 1,
      "controls": [
        {"invariant":"I10","control":"host-network isolation","state":"weakened","detail":"CHM_ALLOW_LOCAL_EGRESS is set — the guest can reach loopback, your LAN and link-local addresses including 169.254.169.254"},
        {"invariant":"I12","control":"credential custody","state":"not-applicable","detail":"no proxy rules; the guest holds whatever credentials it was given"},
        {"invariant":"I1","control":"no host FS passthrough","state":"active","detail":"structural — the device model wires only block/net/rng"}
      ]
    }
    """

    func testDecodesDaemonPostureIncludingItsProvenance() throws {
        let result = CommandResult(output: Self.daemonPostureJSON, status: 1)
        let report = try XCTUnwrap(ChmClient.decodePosture(result))

        XCTAssertTrue(report.isFromDaemon, "must be attributed to the daemon")
        XCTAssertEqual(report.scopeDescription, "the snapshot library (no sandbox running)")
        XCTAssertEqual(report.weakened, 1)
        XCTAssertEqual(report.controls.count, 3)
        XCTAssertEqual(report.weakenedControls.map(\.invariant), ["I10"])
        XCTAssertTrue(
            report.weakenedControls[0].detail.contains("CHM_ALLOW_LOCAL_EGRESS"),
            "the detail must name what weakened it, or the panel cannot be acted on"
        )
    }

    /// The trap: `chm posture` exits **1** when a control is weakened. Treating
    /// non-zero as failure would blank the panel in precisely the case it
    /// exists for — a green-looking empty state over a weakened sandbox.
    func testAWeakenedExitStatusIsAResultNotAFailure() throws {
        let report = try XCTUnwrap(
            ChmClient.decodePosture(CommandResult(output: Self.daemonPostureJSON, status: 1))
        )
        XCTAssertEqual(report.weakened, 1)
    }

    /// A daemon that predates the verb answers `error<TAB>unknown command`, and
    /// so does any other non-JSON. That must decode to nil so the caller falls
    /// back to a local read rather than reporting a hard error.
    func testUnknownDaemonVerbFallsThroughRatherThanErroring() {
        XCTAssertNil(ChmClient.decodePosture(
            CommandResult(output: "error\\tunknown command `posture-json`\\n", status: 0)
        ))
        XCTAssertNil(ChmClient.decodePosture(
            CommandResult(output: "chm ctl: cannot connect to daemon", status: 2)
        ))
    }

    /// Plain `chm posture --json` carries no `source`, so it must NOT claim to
    /// be the daemon's. The panel says whose environment it read.
    func testLocalPostureIsNotAttributedToTheDaemon() throws {
        let json = """
        {"workspace":"/tmp/ws","weakened":0,"controls":[
          {"invariant":"I10","control":"host-network isolation","state":"active","detail":"denied before policy is consulted"}
        ]}
        """
        let report = try XCTUnwrap(ChmClient.decodePosture(CommandResult(output: json, status: 0)))
        XCTAssertFalse(report.isFromDaemon)
        XCTAssertNil(report.scopeDescription)
        XCTAssertTrue(report.weakenedControls.isEmpty)
    }

    /// A state this build does not recognise must read as weakened, never as
    /// active. Failing towards alarm is the only safe direction here: showing
    /// green for something we do not understand is the exact failure mode the
    /// posture command exists to prevent.
    func testAnUnrecognisedStateFailsTowardsAlarm() throws {
        let json = """
        {"workspace":"/tmp/ws","weakened":0,"controls":[
          {"invariant":"I99","control":"future control","state":"partially-on","detail":"from a newer chm"}
        ]}
        """
        let report = try XCTUnwrap(ChmClient.decodePosture(CommandResult(output: json, status: 0)))
        XCTAssertEqual(report.controls[0].state, .weakened)
    }

    // MARK: - Credential proxy (V6.2)

    /// Verbatim `chm proxy check --host api.github.com --path /user --control
    /// --json`, captured 2026-07-31 against the real endpoint with a real
    /// token. 200 injected, 401 not.
    private static let checkProvesInjectionJSON = """
    {"host":"api.github.com","port":443,"path":"/user","address":"20.26.156.210:443",
     "disposition":"INJECT Authorization (github-api)","intercepted":true,"reachable":true,
     "origin_status":"HTTP/1.1 200 OK","tls":"TLSv1_3","error":null,
     "audit":[{"destination":"api.github.com [20.26.156.210]:443","rule":"github-api",
       "detail":"HEAD /user — Authorization attached","injected":true},
      {"destination":"api.github.com [20.26.156.210]:443","rule":"github-api",
       "detail":"upstream TLS TLSv1_3","injected":false}],
     "control":{"status":"HTTP/1.1 401 Unauthorized","differs":true,"proves_injection":true}}
    """

    /// The same command against `/` — an endpoint that answers 200 either way.
    /// Captured in the same session. This run is green and proves nothing.
    private static let checkProvesNothingJSON = """
    {"host":"api.github.com","port":443,"path":"/","address":"20.26.156.210:443",
     "disposition":"INJECT Authorization (github-api)","intercepted":true,"reachable":true,
     "origin_status":"HTTP/1.1 200 OK","tls":"TLSv1_3","error":null,
     "audit":[{"destination":"api.github.com [20.26.156.210]:443","rule":"github-api",
       "detail":"HEAD / — Authorization attached","injected":true}],
     "control":{"status":"HTTP/1.1 200 OK","differs":false,"proves_injection":false}}
    """

    private func decodeCheck(_ json: String) throws -> ProxyCheckResult {
        try JSONDecoder().decode(ProxyCheckResult.self, from: XCTUnwrap(json.data(using: .utf8)))
    }

    func testADifferingControlProvesTheCredentialArrived() throws {
        let result = try decodeCheck(Self.checkProvesInjectionJSON)
        XCTAssertEqual(result.verdict, .provesInjection(without: "HTTP/1.1 401 Unauthorized"))
        XCTAssertEqual(result.audit.filter(\.injected).count, 1)
    }

    /// The case that matters most. This run is reachable, intercepted, and
    /// returns 200 — every naive success signal is green — yet it proves
    /// nothing, because the origin answers identically without the credential.
    /// A UI keying off `reachable` would show a tick even if injection were
    /// completely broken.
    func testAMatchingControlIsReportedAsProvingNothing() throws {
        let result = try decodeCheck(Self.checkProvesNothingJSON)
        XCTAssertTrue(result.reachable)
        XCTAssertTrue(result.intercepted)
        XCTAssertEqual(result.originStatus, "HTTP/1.1 200 OK")
        guard case let .inconclusive(why) = result.verdict else {
            return XCTFail("expected inconclusive, got \(result.verdict)")
        }
        XCTAssertTrue(why.contains("with and without"), "must say why it proved nothing: \(why)")
    }

    func testAnUnreachableHostCarriesItsError() throws {
        let json = """
        {"host":"nope.invalid","port":443,"path":"/","address":null,
         "disposition":"PASS-THROUGH (no rule)","intercepted":false,"reachable":false,
         "origin_status":null,"tls":null,"error":"connect timed out","audit":[],"control":null}
        """
        XCTAssertEqual(try decodeCheck(json).verdict, .unreachable("connect timed out"))
    }

    /// A rule with no resolvable credential still intercepts, so the request
    /// goes out unauthenticated instead of failing. That has to be visible.
    func testARuleWithNoCredentialIsFlaggedAsWillFail() throws {
        let json = """
        {"configured":true,"origin":"/ws/proxy-rules.json","label":"L",
         "rules":[
           {"name":"gh","hosts":"api.github.com","header":"Authorization",
            "source":"env:GH_TOKEN","credential":"missing"},
           {"name":"ok","hosts":"a.example.com,b.example.com","header":"X-Key",
            "source":"exec:mint.sh","credential":"on-demand"}],
         "passthrough":["pinned.example.com"]}
        """
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertEqual(config.rulesMissingCredentials.map(\.name), ["gh"])
        XCTAssertEqual(config.passthroughHosts, ["pinned.example.com"])
        XCTAssertEqual(config.rules[1].hostList, ["a.example.com", "b.example.com"])
        // `on-demand` is the strongest arrangement, not a warning: nothing is
        // minted until a request arrives, so there is no standing token.
        XCTAssertFalse(config.rules[1].willFailToInject)
    }

    func testNoProxyConfigurationDecodesWithoutRules() throws {
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self,
            from: XCTUnwrap(#"{"configured":false,"rules":[]}"#.data(using: .utf8))
        )
        XCTAssertFalse(config.configured)
        XCTAssertTrue(config.passthroughHosts.isEmpty)
    }

    func testTheCaFingerprintIsLiftedFromTheCommandPreamble() {
        let output = """
        # sha256 9f2b1c0daa77
        # `chm proxy ca <WORKSPACE_DIR> --for-guest` prints an installer to
        -----BEGIN CERTIFICATE-----
        """
        XCTAssertEqual(ChmClient.fingerprint(fromCaOutput: output), "9f2b1c0daa77")
        XCTAssertNil(ChmClient.fingerprint(fromCaOutput: "no preamble here"))
    }

    /// Verbatim `chm ctl proxy` against a daemon holding the token, captured
    /// while the same rule read `missing` from a local `chm proxy show`.
    func testTheDaemonsProxyAnswerIsMarkedAsSuch() throws {
        let json = """
        {
          "source": "daemon",
          "assessed": "library-root",
        "configured":true,"origin":"/tmp/gimbal-test/v62lib/proxy-rules.json",        "label":"GitHub API for the agent sandbox",        "rules":[{"name":"github-api","hosts":"api.github.com","header":"Authorization",        "source":"env:V62_GH_TOKEN","credential":"present"}],        "passthrough":["pinned.example.com"]}
        """
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self,
            from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertTrue(config.isFromDaemon)
        XCTAssertEqual(config.assessed, "library-root")
        XCTAssertTrue(config.rulesMissingCredentials.isEmpty)
    }

    /// The local read has no `source`, and must not claim to be the daemon's.
    func testALocalProxyAnswerIsNotMistakenForTheDaemons() throws {
        let json = #"{"configured":true,"origin":"/x.json","label":null,"#
            + #""rules":[{"name":"r","hosts":"h","header":"Authorization","#
            + #""source":"env:T","credential":"missing"}],"passthrough":[]}"#
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self,
            from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertFalse(config.isFromDaemon)
        XCTAssertNil(config.assessed)
        // The rule really is broken *in this process* — the panel still says so
        // in the card. What must not happen is the sidebar raising an alarm
        // sourced from the wrong environment.
        XCTAssertEqual(config.rulesMissingCredentials.count, 1)
    }

    /// An older daemon answers `error\tunknown command`, which must fall
    /// through to the local read rather than blanking the panel.
    func testAnUnknownDaemonCommandDoesNotDecodeAsAProxyConfiguration() {
        XCTAssertNil(
            ChmClient.decodeProxy(CommandResult(output: "error\tunknown command", status: 0))
        )
        // A non-zero status is not a proxy report either, even if the body
        // happens to parse: `proxy show` exits 0 or it has nothing to say.
        XCTAssertNil(
            ChmClient.decodeProxy(
                CommandResult(output: #"{"configured":false,"rules":[]}"#, status: 1)
            )
        )
    }

    /// Verbatim `chm ctl proxy` while a sandbox was running from a library whose
    /// *root* held the rules — the exact shape that made the panel read "No
    /// credential proxy configured" and look like a bug in the panel.
    func testARunningSandboxWithNoRulesIsALiveFindingNotAPlaceholder() throws {
        let json = """
        {
          "source": "daemon",
          "assessed": "running-vm",
          "scope_dir": "/tmp/gimbal-test/v62lib/graviton-agent",
        "configured":false,"rules":[]}
        """
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self,
            from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertFalse(config.configured)
        XCTAssertTrue(config.describesRunningVm)
        // The directory is the actionable part: rules left in the library root
        // are read by nothing, because a guest's workspace is its own folder.
        XCTAssertEqual(config.scopeDir, "/tmp/gimbal-test/v62lib/graviton-agent")
    }

    /// An idle daemon reports the library root, which is *not* a live finding:
    /// nothing has been assessed, so the same words would overclaim.
    func testAnIdleLibraryRootIsNotReportedAsALiveSandbox() throws {
        let json = """
        {"source":"daemon","assessed":"library-root",
         "scope_dir":"/tmp/gimbal-test/v62lib","configured":false,"rules":[]}
        """
        let config = try JSONDecoder().decode(
            ProxyConfiguration.self,
            from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertTrue(config.isFromDaemon)
        XCTAssertFalse(config.describesRunningVm)
    }

    /// Verbatim `chm ctl proxy ca` against the running guest. Measured at the
    /// same moment the app's own `chm proxy ca <library-root>` returned
    /// `898b834b…` — install that one and the guest trusts a CA nothing signs
    /// with, while the installer still reports success.
    func testTheCaComesFromTheProcessThatWillSignWithIt() throws {
        let json = #"{"source":"daemon","assessed":"running-vm","#
            + #""scope_dir":"/tmp/gimbal-test/v62lib/graviton-agent","present":true,"#
            + #""sha256":"79f85a28f5fabdf07634b9bef19b91ebfaa0a31abc43fc75fedf005bb28a2d33","#
            + #""pem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n","#
            + #""installer":"set -e\nsudo tee /usr/local/share/ca-certificates/x.crt\n"}"#
        let ca = try XCTUnwrap(ChmClient.decodeCa(CommandResult(output: json, status: 0)))
        XCTAssertTrue(ca.isFromDaemon)
        XCTAssertEqual(
            ca.fingerprint,
            "79f85a28f5fabdf07634b9bef19b91ebfaa0a31abc43fc75fedf005bb28a2d33"
        )
        XCTAssertEqual(ca.scopeDir, "/tmp/gimbal-test/v62lib/graviton-agent")
        XCTAssertTrue(ca.installScript.contains("sudo tee"))
    }

    /// Before a proxy has ever run there is no CA. That must not decode as an
    /// installable one: offering the button would mint a trust anchor the guest
    /// would then carry for no reason.
    func testAnAbsentCaIsNotOfferedForInstallation() {
        XCTAssertNil(
            ChmClient.decodeCa(
                CommandResult(
                    output: #"{"source":"daemon","assessed":"running-vm","present":false}"#,
                    status: 0
                )
            )
        )
        // An older daemon that does not know the verb must fall through too.
        XCTAssertNil(
            ChmClient.decodeCa(CommandResult(output: "error\tunknown command", status: 0))
        )
    }

    /// The checked transfer has to survive the decoder, and its absence has to be
    /// distinguishable — the two delivery paths are not equivalent, and the app
    /// says so in the log when it falls back.
    func testTheCheckedTransferSurvivesDecodingAndItsAbsenceIsVisible() throws {
        let withLines = """
        {"source":"daemon","present":true,"sha256":"aa","pem":"p","installer":"set -e\\n",\
        "install_lines":["rm -f /tmp/gimbal-ca.b64","printf %s 'c2V0' >> /tmp/gimbal-ca.b64",\
        "CS=$(sha256sum /tmp/gimbal-ca.b64 | cut -d' ' -f1); if [ \\"$CS\\" = \\"bb\\" ]; \
        then base64 -d /tmp/gimbal-ca.b64 > /tmp/gimbal-ca.sh && bash /tmp/gimbal-ca.sh; \
        else echo \\"TRANSFER CORRUPT\\"; fi"]}
        """
        let ca = try XCTUnwrap(ChmClient.decodeCa(CommandResult(output: withLines, status: 0)))
        XCTAssertEqual(ca.installLines.count, 3)
        XCTAssertTrue(ca.installLines.last?.contains("TRANSFER CORRUPT") ?? false)

        // A daemon predating the checked transfer still yields an installable
        // CA, but with no lines -- which is what makes the fallback sayable
        // rather than silent.
        let old = #"{"source":"daemon","present":true,"sha256":"aa","pem":"p","installer":"x"}"#
        let legacy = try XCTUnwrap(ChmClient.decodeCa(CommandResult(output: old, status: 0)))
        XCTAssertTrue(legacy.installLines.isEmpty)
    }

    // MARK: - Activity / audit trail (V6.3)

    /// The counts are only meaningful if the page can tell "none" from "not
    /// recorded", so the model must carry that distinction rather than let the
    /// view infer it from an empty array.
    func testAnEmptyTrailIsNotEvidenceOfAQuietSandbox() throws {
        let legacy = """
        {"source":"daemon","assessed":"running-vm","scope_dir":"/w","present":true,\
        "path":"/w/audit.jsonl","total":2,"records_allow_egress":false,"truncated":false,\
        "records":[{"event":"session-start","ts":"2026-08-01T10:00:00.000Z","vcpus":2},\
        {"event":"egress-deny","ts":"2026-08-01T10:00:01.000Z","domain":"tcp",\
        "target":"1.2.3.4:443","rule":"deny","policy":"sha256:aa"}]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(legacy.data(using: .utf8))
        )
        XCTAssertTrue(trail.present)
        XCTAssertTrue(trail.isFromDaemon)
        XCTAssertFalse(
            trail.recordsAllowEgress,
            "a denial-only trail must not be read as proof nothing left"
        )
        XCTAssertEqual(trail.count(.allowed), 0)
        XCTAssertEqual(trail.count(.denied), 1)
        // session-start is context, not a decision, and must not be counted as
        // one in any of the four buckets.
        XCTAssertNil(trail.records[0].kind)
    }

    /// The four dispositions have to survive the wire, including the two that
    /// live on a `proxy` event rather than an `egress-*` one.
    func testEachDispositionDecodesToItsOwnBucket() throws {
        let json = """
        {"source":"daemon","present":true,"total":4,"records_allow_egress":true,\
        "truncated":false,"records":[\
        {"event":"egress-allow","ts":"t","domain":"tcp","target":"a:443","rule":"r",\
        "policy":"sha256:aa"},\
        {"event":"egress-deny","ts":"t","domain":"tcp","target":"b:443","rule":"d",\
        "policy":"sha256:aa"},\
        {"event":"proxy","ts":"t","destination":"api.github.com:443","disposition":"inject",\
        "rule":"gh"},\
        {"event":"proxy","ts":"t","destination":"example.com:443","disposition":"relay"}]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertEqual(trail.count(.allowed), 1)
        XCTAssertEqual(trail.count(.denied), 1)
        XCTAssertEqual(trail.count(.injected), 1)
        XCTAssertEqual(trail.count(.relayed), 1)
        XCTAssertEqual(trail.records[2].subject, "api.github.com:443")
        XCTAssertEqual(trail.policyDigests, ["sha256:aa"])
    }

    /// An unfamiliar event must not blank the page. The trail is append-only and
    /// written by whichever `chm` was running, so a strict decode would let one
    /// future record type erase the whole history a reader came to check.
    func testAnUnknownEventStillDecodes() throws {
        let json = """
        {"present":true,"total":1,"records_allow_egress":true,"truncated":false,\
        "records":[{"event":"something-new-in-v7","ts":"t","weird":123}]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertEqual(trail.records.count, 1)
        XCTAssertEqual(trail.records[0].event, "something-new-in-v7")
        XCTAssertNil(trail.records[0].kind)
    }

    /// Exact totals come from the summary, because the per-flow lines are capped
    /// and the counters behind the summary are not.
    func testTheSummaryCarriesTotalsThatOutliveTheCappedDetail() throws {
        let json = """
        {"present":true,"total":2,"records_allow_egress":true,"truncated":true,\
        "records":[{"event":"egress-allow","ts":"t","domain":"tcp","target":"a:443",\
        "rule":"r","policy":"sha256:aa"},\
        {"event":"egress-summary","ts":"t","allowed":9000,"denied":3,\
        "distinct_allowed":512,"distinct_denied":3,"truncated":true}]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertTrue(trail.truncated)
        let summary = try XCTUnwrap(trail.summary)
        XCTAssertEqual(summary.allowed, 9000)
        XCTAssertEqual(
            trail.count(.allowed), 1,
            "one line survived the cap, so the line count must not be mistaken for the total"
        )
    }

    /// Two policy hashes in one trail means the rules changed mid-session, and
    /// the newest must not be presented as though it governed the older calls.
    func testAPolicyChangeMidTrailIsVisible() throws {
        let json = """
        {"present":true,"total":2,"records_allow_egress":true,"truncated":false,\
        "records":[{"event":"egress-allow","ts":"t","domain":"tcp","target":"a:443",\
        "rule":"r","policy":"sha256:aa"},\
        {"event":"egress-deny","ts":"t","domain":"tcp","target":"b:443","rule":"d",\
        "policy":"sha256:bb"}]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertEqual(trail.policyDigests, ["sha256:aa", "sha256:bb"])
    }

    /// Repeated identical records must stay distinct: two denials of the same
    /// host a second apart are two facts, and collapsing them would hide a
    /// retry loop behind a single row.
    func testIdenticalRecordsAreNotCollapsed() throws {
        let one = #"{"event":"egress-deny","ts":"t","domain":"tcp","target":"a:443","rule":"d"}"#
        let json = """
        {"present":true,"total":2,"records_allow_egress":false,"truncated":false,\
        "records":[\(one),\(one)]}
        """
        let trail = try JSONDecoder().decode(
            AuditTrail.self, from: XCTUnwrap(json.data(using: .utf8))
        )
        XCTAssertEqual(trail.records.count, 2)
        XCTAssertNotEqual(trail.records[0].id, trail.records[1].id)
    }
}

// MARK: - Local-only mode (V8.2)

final class LocalOnlyModeTests: XCTestCase {

    /// The setting has to actually stop the app reaching for a control plane,
    /// not merely hide the section that shows one. A cosmetic toggle would
    /// leave the app making requests the user explicitly asked it not to make.
    @MainActor
    func testLocalOnlyStopsTheAppReachingForAControlPlane() async {
        let model = AppModel()
        model.cloudSnapshots = [
            CloudSnapshot(
                id: "left-over",
                status: "available",
                kind: "full",
                sourceKind: "cloud-runner",
                gicMode: "its-lpi",
                originSubstrate: "linux-kvm",
                vcpus: 2,
                ramMib: 2048,
                compatibility: "runnable",
                hasLocalCopy: false
            )
        ]

        model.localOnly = true
        await model.refreshAll()

        XCTAssertTrue(model.cloudSnapshots.isEmpty, "stale cloud state must not survive the toggle")
        XCTAssertTrue(model.branches.isEmpty)
        guard case let .offline(reason) = model.cloud.state else {
            return XCTFail("local-only must report the plane as offline")
        }
        XCTAssertEqual(reason, "local-only mode", "the reason must name the cause, not guess at a network fault")
    }

    /// Hiding the section the selection lives in would strand the detail pane
    /// on a page the sidebar can no longer reach.
    @MainActor
    func testTurningOnLocalOnlyMovesTheUserOffTheCloudPage() {
        let model = AppModel()
        model.selection = .cloudHome

        model.localOnly = true
        model.saveLocalOnly()

        XCTAssertEqual(model.selection, .sandboxesHome)
    }

    /// Turning it off must not move the user, or the setting would be
    /// destructive in the harmless direction.
    @MainActor
    func testTurningOffLocalOnlyLeavesTheSelectionAlone() {
        let model = AppModel()
        model.selection = .securityHome

        model.localOnly = false
        model.saveLocalOnly()

        XCTAssertEqual(model.selection, .securityHome)
    }
}

/// #174 — the app can turn the continuous-snapshot cadence on.
///
/// Before this, `CHM_SNAPSHOT_INTERVAL_SECS` was the only way to enable it, so
/// the app's timeline only ever filled from manual suspends and the app had no
/// way to say otherwise.
final class SnapshotCadenceTests: XCTestCase {
    func testAFirstLaunchIsOff() throws {
        // An absent key reads as 0, which is also `.off`. That is the right
        // answer while off is the default, and the doc comment on `stored`
        // records where the distinction goes if the default ever changes — a
        // presence check today could not change any answer, and this test
        // deliberately does not claim one is there.
        let store = try throwawayDefaults()
        XCTAssertEqual(SnapshotCadence.stored(in: store, key: "cadence"), .off)

        store.set(SnapshotCadence.everyMinute.seconds, forKey: "cadence")
        XCTAssertEqual(SnapshotCadence.stored(in: store, key: "cadence"), .everyMinute)

        store.set(0, forKey: "cadence")
        XCTAssertEqual(SnapshotCadence.stored(in: store, key: "cadence"), .off)
    }

    func testAnUnknownStoredValueFallsBackToOff() throws {
        // A cadence written by a newer build must not resolve to some nearby
        // value: freezing someone's guest on a cadence they never chose is a
        // worse answer than not freezing it at all.
        let store = try throwawayDefaults()
        store.set(37, forKey: "cadence")
        XCTAssertEqual(SnapshotCadence.stored(in: store, key: "cadence"), .off)
    }

    func testEveryCadenceRoundTrips() throws {
        let store = try throwawayDefaults()
        for cadence in SnapshotCadence.allCases {
            store.set(cadence.seconds, forKey: "cadence")
            XCTAssertEqual(
                SnapshotCadence.stored(in: store, key: "cadence"), cadence,
                "\(cadence.label) must survive a round trip through UserDefaults"
            )
        }
    }

    func testTheFlagIsPassedEvenWhenTheCadenceIsOff() throws {
        // The load-bearing case. Omitting the flag when the user chose "off"
        // would defer to `CHM_SNAPSHOT_INTERVAL_SECS` — an environment they
        // never set — and hand them the cadence they just declined.
        let off = try InteractiveTerminalCommand.shellCommand(
            chmPath: "/usr/local/bin/chm",
            runPath: "/tmp/ws",
            socketPath: "/tmp/chm.sock",
            lockPath: nil,
            workdir: "/work",
            cadence: .off
        )
        XCTAssertTrue(
            off.contains("--snapshot-every 0"),
            "off must be stated, not left to the environment: \(off)"
        )

        let on = try InteractiveTerminalCommand.shellCommand(
            chmPath: "/usr/local/bin/chm",
            runPath: "/tmp/ws",
            socketPath: "/tmp/chm.sock",
            lockPath: nil,
            workdir: "/work",
            cadence: .everyFiveMinutes
        )
        XCTAssertTrue(
            on.contains("--snapshot-every 300"),
            "a chosen cadence must reach chm: \(on)"
        )
    }

    func testTheEmptyStateHintMovesWithTheSetting() {
        // The hint used to say ending a session was the only way points appear.
        // That is true only while the cadence is off, so the sentence has to
        // come from the cadence rather than be a literal in a view.
        let off = SnapshotCadence.off.howPointsArrive
        XCTAssertTrue(off.contains("Settings"), "off must say where to turn it on: \(off)")

        let on = SnapshotCadence.everyFifteenSeconds.howPointsArrive
        XCTAssertFalse(
            on.lowercased().contains("turn on"),
            "an enabled cadence must not tell you to enable it: \(on)"
        )
        XCTAssertTrue(
            on.contains(SnapshotCadence.everyFifteenSeconds.label.lowercased()),
            "an enabled cadence must say how often: \(on)"
        )
    }

    func testTheAutoMarkerIsReadFromTheOriginChmWrote() {
        // chm suffixes the entry point with `-auto` when the cadence took the
        // point. Both revision types must read it the same way, which is why
        // it lives on one protocol.
        func summary(_ id: String, _ origin: String) -> RevisionSummary {
            RevisionSummary(
                id: id, parent: nil, baseImage: "img", createdAtMs: 1_754_000_000_000,
                origin: origin, label: nil, resumable: true, isHead: false
            )
        }
        let auto = summary("rev-1", "connect-auto")
        let manual = summary("rev-2", "daemon")
        XCTAssertTrue(auto.isAutomatic)
        XCTAssertEqual(auto.originEntryPoint, "connect")
        XCTAssertFalse(manual.isAutomatic)
        XCTAssertEqual(manual.originEntryPoint, "daemon")

        let subtitle = LineageCard.revisionSubtitle(auto, createdAt: auto.createdAt)
        XCTAssertTrue(subtitle.contains("via connect"), subtitle)
        XCTAssertTrue(subtitle.contains("(auto)"), "an automatic point must be marked: \(subtitle)")
        XCTAssertFalse(
            subtitle.contains("connect-auto"),
            "the raw suffix must not leak into the UI: \(subtitle)"
        )
    }
}

/// Guards on the wiring, not the values.
///
/// Every assertion above reads the *output* of a function. That is
/// structurally blind to a call site that stops calling it — this repo has now
/// been caught by exactly that four times (V9.5c, V9.11a M4, #222, #242). The
/// `shellCommand` half is a compile error by construction, because `cadence`
/// has no default. The Settings half cannot be, so it is read out of the
/// source.
final class SnapshotCadenceWiringTests: XCTestCase {
    private func source(_ file: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // GimbalLocalAppTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // GimbalLocal
            .appendingPathComponent("Sources/GimbalLocalApp/\(file)")
        return try String(contentsOf: root, encoding: .utf8)
    }

    func testTheSettingsPickerPersistsWhatItChanges() throws {
        // #142 was exactly this: a setting the user changed, that did not
        // survive a relaunch. A Picker bound to a @Published property looks
        // completely correct and persists nothing.
        let settings = try source("SettingsView.swift")
        XCTAssertTrue(
            settings.contains("$model.snapshotCadence"),
            "the picker must be bound to the model"
        )
        // Assembled from parts: a literal needle would match this assertion's
        // own text if the guard and the source ever shared a file (#241).
        let onChange = "onChange(of: model." + "snapshotCadence)"
        XCTAssertTrue(settings.contains(onChange), "the picker must persist on change")
        XCTAssertTrue(
            settings.contains("model.saveSnapshot" + "Cadence()"),
            "the change must reach the save"
        )
    }

    func testTheStorageKeyIsWrittenOnce() throws {
        // Read and write happen in different places, and the read is in a
        // @Published initializer that cannot see `self`. A restated literal
        // with a typo in one of them means the setting silently never persists.
        let model = try source("AppModel.swift")
        XCTAssertFalse(
            model.contains("\"" + SnapshotCadence.defaultsKey + "\""),
            "the key must come from SnapshotCadence.defaultsKey, not a literal"
        )
        XCTAssertEqual(
            model.components(separatedBy: "SnapshotCadence.defaultsKey").count - 1, 2,
            "both the read and the write must use the shared key"
        )
    }
}

/// The local-only default (#publish). A public download has no control plane,
/// so first launch must not reach for one.
///
/// The load-bearing case is `an_explicit_false_is_honoured`: `UserDefaults.bool`
/// answers `false` for an absent key, so a naive read cannot tell "switched off"
/// from "never chosen" — and defaulting on without testing presence would
/// silently re-enable the control plane for everyone who deliberately turned it
/// off.
final class LocalOnlyDefaultTests: XCTestCase {
    func test_a_fresh_install_is_local_only() throws {
        let d = try throwawayDefaults()
        d.removeObject(forKey: "gimbal.localOnly")
        XCTAssertTrue(
            AppModel.storedLocalOnly(in: d),
            "a first launch must not reach for a control plane it cannot have")
    }

    func test_an_explicit_false_is_honoured() throws {
        let d = try throwawayDefaults()
        d.set(false, forKey: "gimbal.localOnly")
        XCTAssertFalse(
            AppModel.storedLocalOnly(in: d),
            "a user who turned local-only off must stay off across launches")
    }

    func test_an_explicit_true_is_honoured() throws {
        let d = try throwawayDefaults()
        d.set(true, forKey: "gimbal.localOnly")
        XCTAssertTrue(AppModel.storedLocalOnly(in: d))
    }
}

/// Guards for the in-guest user-namespace row the daemon can now report (#363).
///
/// `PostureControl.State` maps every unrecognised string to `.weakened` on
/// purpose -- failing towards alarm is the only safe direction for a security
/// panel. That default is exactly why a new *known* state has to be taught to
/// the app in the same change that starts emitting it: shipping the Rust half
/// alone would paint an orange "Weakened" row over a report whose actual
/// content is "I did not look".
final class PostureUnmeasuredTests: XCTestCase {
    private func control(state: String) throws -> PostureControl {
        let json = """
        {"invariant":"#363","control":"in-guest user namespaces",
         "state":"\(state)","detail":"a detail long enough to be real"}
        """
        return try JSONDecoder().decode(PostureControl.self, from: Data(json.utf8))
    }

    func testUnmeasuredDecodesAsItselfRatherThanAsAnAlarm() throws {
        let c = try control(state: "unmeasured")
        XCTAssertEqual(c.state, .unmeasured,
                       "the panel would alarm over a check that was skipped")
    }

    /// The fallback is load-bearing and must survive the new case being added.
    func testAnUnknownStateStillFailsTowardsAlarm() throws {
        let c = try control(state: "something-we-have-never-heard-of")
        XCTAssertEqual(c.state, .weakened,
                       "an unrecognised state must never read as fine")
    }

    /// The exit-code neutrality of the Rust side has to hold here too, or the
    /// two halves disagree about whether anything is wrong.
    func testUnmeasuredIsNotCountedAsWeakened() throws {
        let report = PostureReport(
            workspace: "/w",
            weakened: 0,
            controls: [try control(state: "unmeasured"),
                       try control(state: "active")])
        XCTAssertTrue(report.weakenedControls.isEmpty,
                      "a skipped check was counted as a weakened one")
    }

    /// Every presentation switch is exhaustive, so a missing case is a compile
    /// error -- but a case filled in with a copy of its neighbour's values
    /// compiles fine and renders the row as something it is not.
    func testUnmeasuredIsDistinguishableOnScreen() {
        XCTAssertEqual(PostureControl.State.unmeasured.label, "Not measured")
        XCTAssertNotEqual(PostureControl.State.unmeasured.symbol,
                          PostureControl.State.weakened.symbol)
        XCTAssertNotEqual(PostureControl.State.unmeasured.label,
                          PostureControl.State.notApplicable.label)
    }

    /// Sorted above the green rows: "we did not look" is not bad news, but it
    /// is the thing a reader needs to notice.
    func testUnmeasuredSortsAboveActive() {
        XCTAssertLessThan(PostureControl.State.unmeasured.sortRank,
                          PostureControl.State.active.sortRank)
        XCTAssertLessThan(PostureControl.State.weakened.sortRank,
                          PostureControl.State.unmeasured.sortRank)
    }
}
