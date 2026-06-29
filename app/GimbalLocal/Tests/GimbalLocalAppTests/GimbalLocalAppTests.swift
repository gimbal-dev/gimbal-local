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
}
