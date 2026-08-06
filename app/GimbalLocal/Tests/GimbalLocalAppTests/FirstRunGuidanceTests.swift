// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import XCTest
@testable import GimbalLocalApp

/// What the app says, and what it *lets you press*, when you have nothing yet.
final class FirstRunGuidanceTests: XCTestCase {
    private func bootable(_ name: String) -> LocalImageLibrary.Entry {
        LocalImageLibrary.Entry(
            name: name,
            image: LocalImage(
                name: name,
                path: "/images/\(name)",
                kernelPath: "/images/\(name)/Image",
                initramfsPath: nil,
                diskPaths: [],
                cmdline: nil,
                vcpus: nil,
                ramMib: nil
            ),
            rejection: nil
        )
    }

    private func refused(
        _ name: String,
        _ r: LocalImage.Rejection = .noKernel
    ) -> LocalImageLibrary.Entry {
        LocalImageLibrary.Entry(name: name, image: nil, rejection: r)
    }

    private func evaluate(
        snapshots: Bool = false,
        images: [LocalImageLibrary.Entry] = []
    ) -> FirstRunGuidance.State {
        FirstRunGuidance.evaluate(
            hasSnapshots: snapshots, localImages: images, imagesPath: "~/gimbal/images"
        )
    }

    /// The bug this replaces: "New sandbox" was disabled whenever the snapshot
    /// library was empty, which greyed out cold boot — the one path that needs
    /// no snapshot, no KVM host and no control plane. A user who had done
    /// exactly the right thing found the button dead.
    func testALocalImageIsEnoughToStartWithNoSnapshotsAnywhere() {
        let g = evaluate(snapshots: false, images: [bootable("ubuntu")])
        XCTAssertTrue(
            g.canStartSomething,
            "a bootable local image must enable New sandbox without any snapshot"
        )
    }

    func testASnapshotIsStillEnoughOnItsOwn() {
        XCTAssertTrue(evaluate(snapshots: true).canStartSomething)
    }

    /// A first run with genuinely nothing has to teach three things, none of
    /// which is guessable: what an image is, where we are looking, and how to
    /// change that.
    func testTheTrueEmptyStateTeachesLayoutLocationAndHowToChangeIt() {
        let g = evaluate()
        XCTAssertFalse(g.canStartSomething)
        XCTAssertTrue(g.detail.contains("Image"), "must name the kernel file")
        XCTAssertTrue(g.detail.contains("arm64"), "must say which architecture")
        XCTAssertTrue(g.detail.contains("~/gimbal/images"), "must say where it looks")
        XCTAssertTrue(g.detail.contains("Settings"), "must say how to change that")
        XCTAssertTrue(g.rejections.isEmpty)
    }

    /// Someone with a folder that did not work has already tried, and
    /// `LocalImageLibrary` knows exactly why. Surfacing that only after a failed
    /// launch attempt wastes the best explanation the app has.
    func testAFolderThatCannotBootExplainsItselfUpFront() {
        let g = evaluate(images: [refused("ubuntu", .kernelIsCompressed("vmlinuz"))])
        XCTAssertFalse(g.canStartSomething)
        XCTAssertEqual(g.rejections.count, 1)
        XCTAssertEqual(g.rejections[0].name, "ubuntu")
        XCTAssertTrue(
            g.rejections[0].reason.contains("gunzip"),
            "the remedy the library already knows must reach the empty state"
        )
        XCTAssertTrue(g.detail.contains("~/gimbal/images"))
    }

    /// A rejection is worth showing even when something else works — otherwise
    /// a broken folder is silently invisible and the user never learns why the
    /// image they added is missing from the list.
    func testRejectionsAreStillReportedWhenSomethingElseCanBoot() {
        let g = evaluate(images: [bootable("good"), refused("bad", .symlinkedDisk("d.img"))])
        XCTAssertTrue(g.canStartSomething)
        XCTAssertEqual(g.rejections.map(\.name), ["bad"])
        XCTAssertTrue(g.rejections[0].reason.contains("cp -c"))
    }

    func testTheCountAndNounAgreeForOneAndForMany() {
        XCTAssertTrue(evaluate(images: [refused("a")]).detail.contains("1 folder"))
        let many = evaluate(images: [refused("a"), refused("b")])
        XCTAssertTrue(many.detail.contains("2 folders"))
    }

    /// The menu row and the empty-state paragraph legitimately differ in
    /// length, but not in substance. If someone changes the accepted kernel in
    /// one place, this fails rather than letting the two surfaces disagree.
    func testTheShortAndLongLayoutDescriptionsAgreeOnTheKernel() {
        let short = FirstRunGuidance.layoutOneLine(imagesPath: "~/img")
        // The facts, not the formatting — the two surfaces render differently.
        for fact in ["uncompressed", "arm64", "Image"] {
            XCTAssertTrue(short.contains(fact), "menu row must state \(fact)")
            XCTAssertTrue(
                FirstRunGuidance.layoutHelp.contains(fact),
                "empty state must state \(fact)"
            )
        }
        XCTAssertTrue(short.contains("~/img"), "menu row must say where to put it")
    }

    /// A menu renders a runtime string verbatim — SwiftUI only parses markdown
    /// out of string *literals* — so backticks meant for the empty state show up
    /// as literal characters in a menu row. Verified on screen before fixing.
    func testTextBoundForAMenuCarriesNoMarkdown() {
        XCTAssertFalse(
            FirstRunGuidance.layoutOneLine(imagesPath: "~/img").contains("`"),
            "the menu one-liner must be plain prose"
        )
        let reason = LocalImage.Rejection.kernelIsCompressed("vmlinuz").reason
        XCTAssertTrue(reason.contains("`"), "reasons stay markdown for the empty state")
        XCTAssertFalse(FirstRunGuidance.plain(reason).contains("`"))
        XCTAssertTrue(
            FirstRunGuidance.plain(reason).contains("gunzip"),
            "stripping emphasis must not lose the remedy"
        )
    }

    /// The welcome banner must name the route that works on a Mac alone.
    ///
    /// It shipped saying only *"create a sandbox from a snapshot image"* — the
    /// exact sentence #175 removed from the empty state, because a snapshot is
    /// captured on a KVM host and someone whose only machine is this Mac cannot
    /// make one. Naming the snapshot route is fine and true; naming *only* it
    /// tells a first-run user to go and do the one thing they cannot do.
    func testTheWelcomeBannerNamesTheRouteThatNeedsNoKvmHost() {
        let welcome = FirstRunGuidance.welcome.lowercased()
        XCTAssertTrue(
            welcome.contains("cold-boot") || welcome.contains("cold boot"),
            "the banner must name cold boot — it is the only route that works "
                + "on a Mac that has never had a KVM host or a control plane"
        )
        XCTAssertTrue(
            welcome.contains("snapshot"),
            "the banner should still name the snapshot route; it is real"
        )
    }

    /// The banner text must come from `FirstRunGuidance`, not a literal.
    ///
    /// This is the shape of the bug, not just an instance of it: #175 fixed the
    /// wording in the empty state and the banner kept its own hardcoded copy,
    /// so the corrected sentence and the uncorrected one rendered on the same
    /// screen — with the wrong one on top, and still rendering long after the
    /// empty state had been replaced by a sandbox list.
    ///
    /// Asserting the *content* of `welcome` cannot see that: a re-hardcoded
    /// literal in the view would leave `welcome` perfectly correct and unused.
    /// So this reads the view's own source, the way `testImageLibraryAgreesWithChm`
    /// reads `chm`'s.
    func testTheBannerRendersTheSharedCopyRatherThanItsOwn() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // GimbalLocalAppTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // GimbalLocal
            .deletingLastPathComponent()  // app
            .deletingLastPathComponent()  // repo root
        let source = try String(
            contentsOf: repo.appending(
                path: "app/GimbalLocal/Sources/GimbalLocalApp/SandboxesView.swift"
            ),
            encoding: .utf8
        )

        guard let banner = source.range(of: "private struct WelcomeBanner") else {
            return XCTFail("WelcomeBanner was renamed; this guard no longer covers it")
        }
        let body = String(source[banner.lowerBound...].prefix(1200))

        XCTAssertTrue(
            body.contains("FirstRunGuidance.welcome"),
            "the welcome banner must render the shared copy, or the next "
                + "correction will land in one place and be contradicted in the other"
        )
        XCTAssertFalse(
            body.contains("Create a sandbox from a snapshot image"),
            "the snapshot-only sentence is back in the banner"
        )
    }
}
