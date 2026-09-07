// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import XCTest
@testable import GimbalLocalApp

/// #440: `runRaw` and `run` waited for the child to exit before reading the pipe
/// they had given it. A pipe holds 64 KiB. Past that the child blocks in `write`
/// waiting for a reader while the app blocks in `waitUntilExit` waiting for the
/// child, and because both sit inside a continuation the `await` never returns
/// and the UI freezes with nothing to report.
///
/// These drive the real `ChmClient` methods against a stand-in child rather than
/// a copy of their bodies. A copy would keep passing after the product was
/// reordered back, which is the one thing this must not do. `chmPath` is just
/// "the program to run", so pointing it at `/bin/sh` exercises the transport
/// exactly as `chm` would.
final class ChmClientTransportTests: XCTestCase {
    private func settings(running program: String) -> AppSettings {
        AppSettings(
            chmPath: program,
            libraryPath: "/unused",
            localImagesPath: "/unused",
            socketPath: "/unused/chm.sock",
            controlPlaneURL: "http://127.0.0.1:8080"
        )
    }

    /// Well past one 64 KiB pipe buffer, so the deadlock is reached rather than
    /// approached. Bounded and exact, so a short read is unambiguous.
    ///
    /// `head -c` rather than `printf 'x%.0s' $(seq …)`: the latter emitted one
    /// byte more than its argument count at this size, and a producer whose own
    /// length is a surprise is no way to measure somebody else's read.
    private static let bytes = 1_048_576
    private static let script =
        "head -c \(ChmClientTransportTests.bytes) /dev/zero | tr '\\0' x"

    func testRunRawReadsMoreThanOnePipeBufferOfOutput() async {
        let result = await ChmClient().runRaw(
            settings: settings(running: "/bin/sh"),
            args: ["-c", Self.script]
        )

        // A short read here is the pipe buffer, not the command. In the app the
        // child is still blocked in write() and this never returns at all.
        XCTAssertEqual(
            result.output.count,
            Self.bytes,
            "runRaw returned \(result.output.count) of \(Self.bytes) bytes (#440)"
        )
        XCTAssertEqual(result.status, 0, "and the child's status is still collected")
    }

    func testRunReadsMoreThanOnePipeBufferOfOutput() async throws {
        // `run` appends `--socket`, which /bin/sh takes as another argument and
        // ignores after `-c`. The point is the transport, not the argv.
        let result = try await ChmClient().run(
            settings: settings(running: "/bin/sh"),
            args: ["-c", Self.script]
        )

        // This is the path the whole UI uses, so the hang was the app freezing
        // on an ordinary command.
        XCTAssertEqual(
            result.output.count,
            Self.bytes,
            "run returned \(result.output.count) of \(Self.bytes) bytes (#440)"
        )
        XCTAssertEqual(result.status, 0)
    }

    /// The ordering only matters past the buffer, so a small reply must keep
    /// working exactly as before. Without this the fix could be "always returns
    /// something eventually" rather than "returns the right thing".
    func testASmallReplyIsUnchanged() async {
        let result = await ChmClient().runRaw(
            settings: settings(running: "/bin/sh"),
            args: ["-c", "printf hello; printf ' world' 1>&2"]
        )

        XCTAssertEqual(result.output, "hello world", "stdout and stderr still combine, in order")
        XCTAssertEqual(result.status, 0)
    }

    /// A non-zero exit is reported, not thrown, and its output still arrives.
    func testANonZeroExitIsReportedWithItsOutput() async {
        let result = await ChmClient().runRaw(
            settings: settings(running: "/bin/sh"),
            args: ["-c", "printf nope 1>&2; exit 3"]
        )

        XCTAssertEqual(result.status, 3)
        XCTAssertEqual(result.output, "nope")
    }
}
