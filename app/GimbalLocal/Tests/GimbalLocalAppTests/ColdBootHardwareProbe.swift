// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest
@testable import GimbalLocalApp

/// Prints the command the app would actually run for a real image directory, so
/// a human (or a hardware smoke test) can execute exactly the app's own output
/// rather than a hand-written approximation. Not part of the normal suite.
final class ColdBootHardwareProbe: XCTestCase {
    func testEmitTheRealCommand() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["GIMBAL_PROBE"] == "1")
        let root = ProcessInfo.processInfo.environment["GIMBAL_IMAGES"] ?? ""
        let entries = LocalImageLibrary.scan(root: root)
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
