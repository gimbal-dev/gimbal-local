// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest
@testable import GimbalLocalApp

/// V8.1/V8.3 — bring-your-own images and cold boot from the app.
///
/// These are the first sandboxes in this app that need nothing captured on a
/// KVM host and no control plane, so the discovery policy and the command
/// builder are the whole feature. Both are pure, so both are tested directly
/// rather than through a live filesystem or a live Terminal.
final class LocalImageTests: XCTestCase {
    private func classify(_ entries: [String], manifest: String? = nil) -> LocalImageLibrary.Entry {
        LocalImageLibrary.classify(
            name: "img",
            path: "/images/img",
            entries: entries,
            manifestJSON: manifest.map { Data($0.utf8) }
        )
    }

    // MARK: - Discovery

    func testABareKernelIsEnoughToBeAnImage() {
        let e = classify(["Image"])
        XCTAssertEqual(e.image?.kernelPath, "/images/img/Image")
        XCTAssertNil(e.rejection)
        XCTAssertNil(e.image?.initramfsPath)
        XCTAssertEqual(e.image?.diskPaths, [])
    }

    func testConventionFindsInitramfsAndRootDisk() {
        let e = classify(["Image", "initramfs", "rootfs.img", "notes.txt"])
        XCTAssertEqual(e.image?.initramfsPath, "/images/img/initramfs")
        XCTAssertEqual(e.image?.diskPaths, ["/images/img/rootfs.img"])
    }

    /// The failure this prevents is the expensive one: a distro `vmlinuz` is
    /// gzip, boots to nothing, and looks like a hypervisor bug rather than a
    /// wrong file. Naming it costs one branch.
    func testACompressedKernelIsRefusedByNameRatherThanBooted() {
        let e = classify(["vmlinuz", "rootfs.img"])
        XCTAssertNil(e.image)
        XCTAssertEqual(e.rejection, .kernelIsCompressed("vmlinuz"))
        XCTAssertTrue(e.rejection!.reason.contains("gunzip"))
    }

    func testAManifestNamedKernelThatIsAlsoGzipIsStillRefused() {
        let e = classify(["Image.gz"], manifest: #"{"kernel":"Image.gz"}"#)
        XCTAssertEqual(e.rejection, .kernelIsCompressed("Image.gz"))
    }

    func testADirectoryWithNoKernelIsRefusedWithAUsableReason() {
        let e = classify(["rootfs.img", "README"])
        XCTAssertEqual(e.rejection, .noKernel)
        XCTAssertTrue(e.rejection!.reason.contains("image.json"))
    }

    func testAManifestWinsOverConvention() {
        let e = classify(
            ["Image", "custom-kernel", "rootfs.img", "data.img"],
            manifest: #"{"kernel":"custom-kernel","disks":["data.img"],"cmdline":"console=ttyAMA0","vcpus":2,"ram_mib":2048}"#
        )
        XCTAssertEqual(e.image?.kernelPath, "/images/img/custom-kernel")
        XCTAssertEqual(e.image?.diskPaths, ["/images/img/data.img"])
        XCTAssertEqual(e.image?.cmdline, "console=ttyAMA0")
        XCTAssertEqual(e.image?.vcpus, 2)
        XCTAssertEqual(e.image?.ramMib, 2048)
    }

    /// A typo in a manifest must be an error, not a silent fallback to
    /// convention -- otherwise it boots the wrong disk and says nothing.
    func testAManifestNamingAMissingFileIsAnErrorNotAFallback() {
        XCTAssertEqual(classify(["Image"], manifest: #"{"kernel":"nope"}"#).rejection, .missingFile("nope"))
        XCTAssertEqual(
            classify(["Image", "rootfs.img"], manifest: #"{"disks":["gone.img"]}"#).rejection,
            .missingFile("gone.img")
        )
    }

    func testAnUnparseableManifestFallsBackToConventionRatherThanFailing() {
        let e = classify(["Image", "rootfs.img"], manifest: "{ not json")
        XCTAssertEqual(e.image?.kernelPath, "/images/img/Image")
    }

    /// Found by cold-booting a real image: `chm` opens disks no-follow (M30.1,
    /// so a bundle cannot substitute a symlink to redirect guest writes onto a
    /// host file), and a symlinked disk therefore dies ~25s into a boot with
    /// `Too many levels of symbolic links`. That reads like a broken image. The
    /// app names it up front and names the remedy -- and deliberately does not
    /// resolve the link itself, which would defeat the control.
    func testASymlinkedDiskIsNamedUpFrontRatherThanFailingMidBoot() {
        let e = LocalImageLibrary.classify(
            name: "img", path: "/images/img",
            entries: ["Image", "rootfs.img"], manifestJSON: nil,
            isSymlink: { $0 == "rootfs.img" }
        )
        XCTAssertNil(e.image)
        XCTAssertEqual(e.rejection, .symlinkedDisk("rootfs.img"))
        XCTAssertTrue(e.rejection!.reason.contains("cp -c"), "must name the remedy, not just the fault")
    }

    func testASymlinkedDiskNamedByAManifestIsAlsoCaught() {
        let e = LocalImageLibrary.classify(
            name: "img", path: "/images/img",
            entries: ["Image", "data.img"],
            manifestJSON: Data(#"{"disks":["data.img"]}"#.utf8),
            isSymlink: { $0 == "data.img" }
        )
        XCTAssertEqual(e.rejection, .symlinkedDisk("data.img"))
    }

    /// A symlinked *kernel* is fine -- chm reads it normally, and the boot this
    /// was verified against used one. Refusing it would be cargo-culting the
    /// disk rule onto a path where it does not apply.
    func testASymlinkedKernelIsAccepted() {
        let e = LocalImageLibrary.classify(
            name: "img", path: "/images/img",
            entries: ["Image"], manifestJSON: nil,
            isSymlink: { $0 == "Image" }
        )
        XCTAssertEqual(e.image?.kernelPath, "/images/img/Image")
        XCTAssertNil(e.rejection)
    }

    // MARK: - Command building

    private let image = LocalImage(
        name: "ubuntu",
        path: "/images/ubuntu",
        kernelPath: "/images/ubuntu/Image",
        initramfsPath: "/images/ubuntu/initramfs",
        diskPaths: ["/images/ubuntu/rootfs.img", "/images/ubuntu/data.img"],
        cmdline: "console=ttyAMA0 root=/dev/vda1",
        vcpus: 2,
        ramMib: 2048
    )

    func testBuildsACompleteColdBootInvocation() throws {
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: image, options: .init(), workdir: "/work"
        )
        XCTAssertTrue(cmd.contains("'/bin/chm' create --kernel '/images/ubuntu/Image'"))
        XCTAssertTrue(cmd.contains("--initramfs '/images/ubuntu/initramfs'"))
        XCTAssertTrue(cmd.contains("--disk '/images/ubuntu/rootfs.img' --disk '/images/ubuntu/data.img'"))
        XCTAssertTrue(cmd.contains("--cmdline 'console=ttyAMA0 root=/dev/vda1'"))
        XCTAssertTrue(cmd.contains("--cpus 2"))
        XCTAssertTrue(cmd.contains("--memory 2048"))
    }

    /// An image that names no command line must not be given one.
    ///
    /// `chm create` deliberately never appends to an explicit `--cmdline`, so
    /// inventing one here does not add a default -- it *replaces* the real one,
    /// silently dropping `earlycon`, `panic=1` and the guest's wall clock. A
    /// guest booting at the Unix epoch fails every TLS handshake with
    /// "certificate is not yet valid", and this is the one path where nobody
    /// ever reads the command line to find out why.
    func testAnImageThatNamesNoCommandLineIsNotGivenOne() throws {
        let bare = LocalImage(
            name: "container",
            path: "/images/container",
            kernelPath: "/images/container/Image",
            initramfsPath: "/images/container/initramfs",
            diskPaths: [],
            cmdline: nil,
            vcpus: 2,
            ramMib: 3008
        )
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: bare, options: .init(), workdir: "/work"
        )
        XCTAssertFalse(cmd.contains("--cmdline"), "invented a command line: \(cmd)")
        // Still a complete invocation otherwise, or this would pass by being broken.
        XCTAssertTrue(cmd.contains("--kernel '/images/container/Image'"))
        XCTAssertTrue(cmd.contains("--memory 3008"))
    }

    /// A timer expiring mid-write is a power cut on a writable disk, and it has
    /// corrupted a rootfs here before. An interactive window must run until the
    /// user ends it.
    func testAnInteractiveColdBootHasNoWallClockDeadlineByDefault() throws {
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: image, options: .init(), workdir: "/work"
        )
        XCTAssertTrue(cmd.contains("--seconds 0"))
    }

    /// Nothing we did not ask for. A NIC and egress are opt-in, so an image
    /// launched with defaults reaches nothing -- the same deny-all posture the
    /// rest of the tree gets (docs/security-model.md §1a).
    func testDefaultsAttachNoNicAndNoEgress() throws {
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: image, options: .init(), workdir: "/work"
        )
        XCTAssertFalse(cmd.contains("--net"))
        XCTAssertFalse(cmd.contains("--egress-allow"))
    }

    func testOptionsOverrideTheManifest() throws {
        var opts = ColdBootTerminalCommand.Options()
        opts.vcpus = 4
        opts.ramMib = 512
        opts.net = true
        opts.egressAllow = ["api.github.com:443"]
        opts.seconds = 90
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: image, options: opts, workdir: "/work"
        )
        XCTAssertTrue(cmd.contains("--cpus 4"))
        XCTAssertTrue(cmd.contains("--memory 512"))
        XCTAssertTrue(cmd.contains("--net"))
        XCTAssertTrue(cmd.contains("--egress-allow 'api.github.com:443'"))
        XCTAssertTrue(cmd.contains("--seconds 90"))
        XCTAssertFalse(cmd.contains("--cpus 2"))
    }

    // MARK: - Injection (invariant I5)

    /// The app launches host commands, so a path must never become host code.
    ///
    /// String-matching the quoted form would be a weak test — a metacharacter
    /// legitimately *appears* inside the quotes, so asserting it is absent is
    /// asserting the wrong thing (my first version of this test failed for
    /// exactly that reason). The real property is that `sh` parses the quoted
    /// word back to exactly the original string, so this asks the real shell
    /// rather than asserting about the spelling.
    func testAdversarialPathsSurviveTheRealShellAsExactlyThemselves() throws {
        let hostile = [
            "/i/Image'; touch /tmp/gimbal-pwned; echo '",
            "/i/$(id)",
            "/i/`id`",
            "/i/a b\tc",
            "/i/x\"y",
            "/i/*",
            "/i/a&&b||c;d",
            "/i/back\\slash",
        ]
        for raw in hostile {
            let quoted = InteractiveTerminalCommand.shellQuote(raw)
            let sh = Process()
            sh.executableURL = URL(fileURLWithPath: "/bin/sh")
            sh.arguments = ["-c", "printf %s \(quoted)"]
            let pipe = Pipe()
            sh.standardOutput = pipe
            sh.standardError = Pipe()
            try sh.run()
            let out = pipe.fileHandleForReading.readDataToEndOfFile()
            sh.waitUntilExit()
            XCTAssertEqual(sh.terminationStatus, 0, raw.debugDescription)
            XCTAssertEqual(
                String(decoding: out, as: UTF8.self), raw,
                "sh must parse the quoted word back to exactly the original: \(raw.debugDescription)"
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: "/tmp/gimbal-pwned"),
            "the injected command must never have executed"
        )

        // And the builder embeds precisely that quoting for a real image path.
        let evil = LocalImage(
            name: "evil", path: "/i", kernelPath: hostile[0],
            initramfsPath: nil, diskPaths: [], cmdline: nil, vcpus: nil, ramMib: nil
        )
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: evil, options: .init(), workdir: "/work"
        )
        XCTAssertTrue(cmd.contains("--kernel " + InteractiveTerminalCommand.shellQuote(hostile[0])))
    }

    func testControlCharactersAreRefusedRatherThanQuoted() {
        for bad in ["/i/Im\nage", "/i/Im\u{0}age", "/i/Im\u{1b}age"] {
            let img = LocalImage(
                name: "x", path: "/i", kernelPath: bad, initramfsPath: nil,
                diskPaths: [], cmdline: nil, vcpus: nil, ramMib: nil
            )
            XCTAssertThrowsError(
                try ColdBootTerminalCommand.shellCommand(
                    chmPath: "/bin/chm", image: img, options: .init(), workdir: "/work"
                ),
                "control characters must be refused, not escaped: \(bad.debugDescription)"
            )
        }
    }

    func testEveryInterpolatedPositionIsScreened() {
        let bad = "/i/x\ny"
        var cases: [ColdBootTerminalCommand.Options] = []
        var rules = ColdBootTerminalCommand.Options(); rules.proxyRules = bad
        var ws = ColdBootTerminalCommand.Options(); ws.workspace = bad
        var cmdline = ColdBootTerminalCommand.Options(); cmdline.cmdline = bad
        cases = [rules, ws, cmdline]
        for opts in cases {
            XCTAssertThrowsError(
                try ColdBootTerminalCommand.shellCommand(
                    chmPath: "/bin/chm", image: image, options: opts, workdir: "/work"
                )
            )
        }
    }

    func testMalformedEgressHostsAreRefused() {
        for bad in ["api.github.com:443; rm -rf /", "$(id)", "`id`", "a b", "", "hôst:443"] {
            XCTAssertFalse(
                ColdBootTerminalCommand.isCleanEgressHost(bad),
                "\(bad.debugDescription) must not be accepted as an egress host"
            )
            var opts = ColdBootTerminalCommand.Options()
            opts.egressAllow = [bad]
            XCTAssertThrowsError(
                try ColdBootTerminalCommand.shellCommand(
                    chmPath: "/bin/chm", image: image, options: opts, workdir: "/work"
                )
            )
        }
    }

    func testRealEgressHostsAreAccepted() {
        for good in ["api.github.com:443", "registry.npmjs.org:443", "127.0.0.1:8080", "[::1]:443", "host_name:22"] {
            XCTAssertTrue(ColdBootTerminalCommand.isCleanEgressHost(good), good)
        }
    }

    /// The window must not drop the user back to an interactive host shell
    /// sitting in a workspace, where a stray `rm` hits the Mac and not the
    /// (now gone) guest. Same reasoning as the connect builder.
    func testTheSessionEndsRatherThanFallingBackToAHostShell() throws {
        let cmd = try ColdBootTerminalCommand.shellCommand(
            chmPath: "/bin/chm", image: image, options: .init(), workdir: "/work"
        )
        XCTAssertTrue(cmd.hasSuffix("; exit"))
        XCTAssertTrue(cmd.contains("Cold boot ended"))
    }
}
