// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest
@testable import GimbalLocalApp

/// Prints the command the app would actually run for a real image directory, so
/// a human (or a hardware smoke test) can execute exactly the app's own output
/// rather than a hand-written approximation. Not part of the normal suite.
final class ColdBootHardwareProbe: XCTestCase {
    func testEmitTheRealCommand() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["GIMBAL_PROBE"] == "1")
        let root = ProcessInfo.processInfo.environment["GIMBAL_IMAGES"] ?? ""
        let entries = LocalImageLibrary.scan(
            root: root,
            probeKernel: LocalImageLibrary.chmProber(
                chmPath: ProcessInfo.processInfo.environment["CHM_PATH"] ?? "chm"
            )
        )
        for e in entries {
            if let image = e.image {
                var opts = ColdBootTerminalCommand.Options()
                opts.seconds = Int(ProcessInfo.processInfo.environment["GIMBAL_PROBE_SECONDS"] ?? "0") ?? 0
                let cmd = try ColdBootTerminalCommand.shellCommand(
                    chmPath: ProcessInfo.processInfo.environment["CHM_PATH"] ?? "chm",
                    image: image, options: opts,
                    workdir: FileManager.default.currentDirectoryPath
                )
                print("OK   \(e.name): \(cmd)")
            } else {
                print("SKIP \(e.name): \(e.rejection?.reason ?? "?")")
            }
        }
    }
}

/// Scans a real directory with the app's own discovery code. Skipped unless
/// `GIMBAL_PROBE_DIR` names one, so it never runs in the normal gate.
final class LocalImageScanProbe: XCTestCase {
    func testScanRealDirectory() throws {
        guard let root = ProcessInfo.processInfo.environment["GIMBAL_PROBE_DIR"] else {
            throw XCTSkip("set GIMBAL_PROBE_DIR to scan a real image directory")
        }
        let entries = LocalImageLibrary.scan(
            root: root,
            probeKernel: LocalImageLibrary.chmProber(
                chmPath: ProcessInfo.processInfo.environment["CHM_PATH"] ?? "chm"
            )
        )
        print("PROBE_SCAN root=\(root) entries=\(entries.count)")
        for entry in entries {
            if let rejection = entry.rejection {
                print("PROBE_SCAN   refused \(entry.name): \(rejection.reason)")
            } else if let image = entry.image {
                print("PROBE_SCAN   accepted \(entry.name) kernel=\(image.kernelPath) disks=\(image.diskPaths.count)")
            }
        }
    }
}
