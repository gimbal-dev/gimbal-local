// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest

@testable import GimbalLocalApp

/// The app writes specs and builds the command that starts them; `chm` decides
/// what a spec *means*. These tests cover the app's half only — anything about
/// validation rules belongs in `chm/src/spec.rs`, deliberately, because two
/// implementations of one rule drift.
final class SandboxSpecDocumentTests: XCTestCase {
    private func image(
        name: String = "ubuntu-cold",
        path: String = "/images/ubuntu-cold",
        vcpus: Int? = nil,
        ramMib: Int? = nil
    ) -> LocalImage {
        LocalImage(
            name: name,
            path: path,
            kernelPath: "\(path)/Image",
            initramfsPath: nil,
            diskPaths: ["\(path)/rootfs.img"],
            cmdline: nil,
            vcpus: vcpus,
            ramMib: ramMib
        )
    }

    func testDescribingCarriesTheImageAndItsSizing() throws {
        var options = ColdBootTerminalCommand.Options()
        options.vcpus = 4
        options.ramMib = 4096
        options.seconds = 600

        let doc = SandboxSpecDocument.describing(image: image(), options: options)
        XCTAssertEqual(doc.specVersion, 1)
        XCTAssertEqual(doc.image?.kernel, "/images/ubuntu-cold/Image")
        XCTAssertEqual(doc.image?.disks, ["/images/ubuntu-cold/rootfs.img"])
        XCTAssertEqual(doc.resourceLimits?.cpu?.vcpus, 4)
        XCTAssertEqual(doc.resourceLimits?.memory?.ram, "4096mb")
        XCTAssertEqual(doc.resourceLimits?.timeout?.wallClock, "600s")
        XCTAssertEqual(doc.hostRequirements?.hypervisor, "cloud-hypervisor")
    }

    /// The manifest's own sizing must survive into the spec. Dropping it would
    /// make "describe this image" quietly change the machine it describes.
    func testImageManifestSizingIsCarriedWhenNoOptionOverridesIt() {
        let doc = SandboxSpecDocument.describing(
            image: image(vcpus: 2, ramMib: 2048),
            options: ColdBootTerminalCommand.Options()
        )
        XCTAssertEqual(doc.resourceLimits?.cpu?.vcpus, 2)
        XCTAssertEqual(doc.resourceLimits?.memory?.ram, "2048mb")
    }

    /// A sandbox nobody configured must not come out of this with a network.
    func testAnUnconfiguredSpecIsNetworklessAndDefaultDeny() {
        let doc = SandboxSpecDocument.describing(
            image: image(),
            options: ColdBootTerminalCommand.Options()
        )
        XCTAssertEqual(doc.networkPolicy?.enabled, false)
        XCTAssertEqual(doc.networkPolicy?.defaultAction, "deny")
        XCTAssertNil(doc.networkPolicy?.egress)
    }

    /// `host:port` is how the rest of the tree speaks; the spec separates them.
    /// Passing the joined form through as a hostname would compile to a rule
    /// that can never match — coverage in appearance, none in fact.
    func testEgressHostsAreSplitIntoDomainAndPort() {
        var options = ColdBootTerminalCommand.Options()
        options.net = true
        options.egressAllow = ["api.github.com:443", "ports.ubuntu.com:80"]

        let doc = SandboxSpecDocument.describing(image: image(), options: options)
        XCTAssertEqual(doc.networkPolicy?.egress?.count, 2)
        XCTAssertEqual(doc.networkPolicy?.egress?.first?.domains, ["api.github.com"])
        XCTAssertEqual(doc.networkPolicy?.egress?.first?.ports, [443])
        XCTAssertEqual(doc.networkPolicy?.egress?.last?.domains, ["ports.ubuntu.com"])
        XCTAssertEqual(doc.networkPolicy?.egress?.last?.ports, [80])
    }

    func testEncodedIsPrettySortedAndNewlineTerminated() throws {
        let data = try SandboxSpecDocument.describing(
            image: image(),
            options: ColdBootTerminalCommand.Options()
        ).encoded()
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.hasSuffix("\n"))
        XCTAssertTrue(text.contains("\"specVersion\" : 1"))
        // Slashes must not be escaped: a spec is meant to be read, and
        // `\/images\/ubuntu` is not.
        XCTAssertFalse(text.contains("\\/"))
    }

    func testWriteRefusesToClobberEditsUnlessAsked() throws {
        let dir = NSTemporaryDirectory() + "spec-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let doc = SandboxSpecDocument.describing(
            image: image(path: dir), options: ColdBootTerminalCommand.Options())
        let path = try doc.write(into: dir)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        XCTAssertTrue(SandboxSpecDocument.exists(in: dir))

        XCTAssertThrowsError(try doc.write(into: dir)) { error in
            XCTAssertEqual(error as? SandboxSpecDocument.SpecError, .alreadyExists(path))
        }
        XCTAssertNoThrow(try doc.write(into: dir, overwrite: true))

        let back = try SandboxSpecDocument.read(from: dir)
        XCTAssertEqual(back, doc)
    }

    /// The spec route is the whole point of the de-duplication: one flag, not
    /// eleven, so a flag `chm` gains or renames costs no change here.
    func testSpecCommandNamesOneFlagAndQuotesItsPaths() throws {
        let command = try ColdBootTerminalCommand.specShellCommand(
            chmPath: "/usr/local/bin/chm",
            specDirectory: "/images/my sandbox",
            workdir: "/tmp"
        )
        XCTAssertTrue(command.contains("create --spec"))
        XCTAssertTrue(command.contains("'/images/my sandbox'"))
        XCTAssertFalse(command.contains("--kernel"), "the spec carries this, not the app")
        XCTAssertFalse(command.contains("--cpus"))
        XCTAssertFalse(command.contains("--egress-allow"))
    }

    /// Invariant I5: a path must never break out of the shell word it sits in.
    /// Asked of `/bin/sh` itself rather than by pattern-matching the string,
    /// because the property is "the shell parses it back unchanged" (V8.1).
    func testSpecCommandRefusesControlCharactersInPaths() {
        XCTAssertThrowsError(
            try ColdBootTerminalCommand.specShellCommand(
                chmPath: "/usr/local/bin/chm",
                specDirectory: "/images/evil\u{0}dir",
                workdir: "/tmp"
            ))
        XCTAssertThrowsError(
            try ColdBootTerminalCommand.specShellCommand(
                chmPath: "/usr/local/bin/chm",
                specDirectory: "/images/evil\ndir",
                workdir: "/tmp"
            ))
    }

    // MARK: - Reading chm's verdict

    func testValidationTrustsTheExitStatusNotTheProse() {
        let ok = SpecValidation.parse(exitCode: 0, output: "/w/sandbox.json: ok")
        XCTAssertTrue(ok.ok)
        XCTAssertTrue(ok.problems.isEmpty)
    }

    func testValidationSurfacesEveryProblemChmReported() {
        let output = """
            /w/sandbox.json: 2 problem(s)
              - `securityModules` is part of the agent compute spec but this build does not \
            implement it. See #184.
              - networkPolicy.defaultAction: `maybe` is not `allow` or `deny`
            """
        let verdict = SpecValidation.parse(exitCode: 1, output: output)
        XCTAssertFalse(verdict.ok)
        XCTAssertEqual(verdict.problems.count, 2)
        XCTAssertTrue(verdict.problems[0].contains("securityModules"))
        XCTAssertTrue(verdict.problems[1].contains("defaultAction"))
    }

    /// A refusal we cannot parse is still a refusal. Reporting "valid" because
    /// the reason was unreadable is the worst available reading of a non-zero
    /// exit, and it is the one a naive parser gives you.
    func testAnUnparseableRefusalIsStillARefusal() {
        let verdict = SpecValidation.parse(exitCode: 1, output: "chm: no such file")
        XCTAssertFalse(verdict.ok)
        XCTAssertEqual(verdict.problems, ["chm: no such file"])
    }
}

/// The one thing unit tests on either side of the boundary cannot establish:
/// that a spec the **app** writes is a spec **chm** accepts.
///
/// Both halves can be internally consistent and still disagree about a field
/// name, and the disagreement would only appear when someone pressed the button.
/// Skipped unless `CHM_PATH` names a built binary, so it never blocks the gate
/// on a machine that has not built the Rust side.
final class SandboxSpecCrossBoundaryProbe: XCTestCase {
    func testAppWrittenSpecIsAcceptedByChm() throws {
        guard let chm = ProcessInfo.processInfo.environment["CHM_PATH"],
            FileManager.default.isExecutableFile(atPath: chm)
        else {
            throw XCTSkip("set CHM_PATH to a built chm to cross-check the spec format")
        }

        let dir = NSTemporaryDirectory() + "spec-xcheck-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }

        var options = ColdBootTerminalCommand.Options()
        options.net = true
        options.egressAllow = ["api.github.com:443"]
        options.vcpus = 2
        options.ramMib = 2048
        options.seconds = 300

        let image = LocalImage(
            name: "xcheck",
            path: dir,
            kernelPath: "\(dir)/Image",
            initramfsPath: nil,
            diskPaths: ["\(dir)/rootfs.img"],
            cmdline: "console=ttyAMA0",
            vcpus: nil,
            ramMib: nil
        )
        try SandboxSpecDocument.describing(image: image, options: options).write(into: dir)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: chm)
        process.arguments = ["spec", "validate", dir]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()

        XCTAssertEqual(
            process.terminationStatus, 0,
            "chm refused a spec the app wrote:\n\(output)")

        // And the app must be able to read chm's own starter back, so the two
        // are interchangeable rather than merely compatible in one direction.
        let initDir = NSTemporaryDirectory() + "spec-init-\(UUID().uuidString)"
        let initProcess = Process()
        initProcess.executableURL = URL(fileURLWithPath: chm)
        initProcess.arguments = ["spec", "init", initDir]
        initProcess.standardOutput = Pipe()
        try initProcess.run()
        initProcess.waitUntilExit()
        defer { try? FileManager.default.removeItem(atPath: initDir) }
        XCTAssertNoThrow(
            try SandboxSpecDocument.read(from: initDir),
            "the app could not read a spec chm wrote")
    }
}
