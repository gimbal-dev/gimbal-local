// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Turning a stack of layers into one root filesystem.
//!
//! Layers apply in order, each one able to add, replace or delete what the
//! layers below it put there. The rules are OverlayFS's, because that is what a
//! container runtime uses and what image authors build against:
//!
//! * a later entry at the same path **replaces** the earlier one,
//! * `.wh.name` **deletes** `name` from everything below,
//! * `.wh..wh..opq` in a directory **clears** that directory's lower contents
//!   while keeping the directory itself.
//!
//! Every entry crosses [`super::entry::decide`] on the way in. The applier
//! never inspects a path itself — one place decides what is safe, and this
//! walks the verdicts. Two implementations of that rule would eventually
//! disagree, and the disagreement would be a traversal.

use super::entry::{EntryKind, Refusal, Verdict};
use super::initramfs::Rootfs;
use super::targz::Layer;

/// What happened while applying layers, so the build can report it rather than
/// leaving the user to wonder what an image contained.
#[derive(Debug, Default)]
pub struct Report {
    /// Entries we refused, with the reason. These are the security-relevant
    /// ones and are printed.
    pub refused: Vec<Refusal>,
    /// Changes we made rather than refused — currently stripped setuid bits.
    pub sanitised: Vec<Refusal>,
    /// Device nodes, FIFOs and sockets the tar reader saw and skipped.
    pub skipped_nodes: Vec<String>,
    /// Files deleted by a whiteout, counted rather than listed: a large image
    /// whiteouts hundreds of paths as a matter of course and listing them buries
    /// the refusals, which are the lines that matter.
    pub whiteouts: usize,
    /// Directories cleared by an opaque marker.
    pub opaques: usize,
    /// Directory entries that named an existing symlink to a directory, and
    /// were therefore *not* applied.
    ///
    /// Counted rather than listed, and reported, because it is the one thing
    /// here that changes what the image contains without anything being wrong:
    /// a `.deb` that ships `./bin/` on a usr-merge base means `/usr/bin`, and
    /// applying it literally would destroy the alias every other file depends
    /// on.
    pub aliased_dirs: usize,
}

impl Report {
    /// Did anything happen that a user should see before booting this?
    pub fn has_findings(&self) -> bool {
        !self.refused.is_empty()
            || !self.sanitised.is_empty()
            || !self.skipped_nodes.is_empty()
            || self.aliased_dirs > 0
    }

    /// What to print on the console, one line per category that actually
    /// happened.
    ///
    /// #304: the console used to answer `has_findings()` with a single "see
    /// BUILD.txt for what was refused", which for `node:22-slim` — eleven
    /// stripped setuid bits and **zero** refusals — named the one category that
    /// was empty. Three things with very different weights had been carefully
    /// separated in this struct and then flattened again on the way out.
    ///
    /// So they are reported apart, and a stripped setuid bit is reported by its
    /// *consequence* rather than its count: `su` and `passwd` not elevating is
    /// the thing a user needs to know, and it is knowable here without opening
    /// a file.
    pub fn console_findings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.refused.is_empty() {
            out.push(format!(
                "REFUSED {} entr{} from this image — see BUILD.txt before booting it.",
                self.refused.len(),
                if self.refused.len() == 1 { "y" } else { "ies" }
            ));
        }
        if !self.sanitised.is_empty() {
            out.push(format!(
                "Stripped {} setuid/setgid bit{} ({}) — those will not elevate in this guest.",
                self.sanitised.len(),
                if self.sanitised.len() == 1 { "" } else { "s" },
                name_a_few(&self.sanitised)
            ));
        }
        if !self.skipped_nodes.is_empty() {
            out.push(format!(
                "Skipped {} device node/FIFO entr{} an initramfs does not carry.",
                self.skipped_nodes.len(),
                if self.skipped_nodes.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ));
        }
        if self.aliased_dirs > 0 {
            out.push(format!(
                "Redirected {} director{} through a usr-merge symlink \
                 (e.g. `bin` -> `usr/bin`) rather than replacing it.",
                self.aliased_dirs,
                if self.aliased_dirs == 1 { "y" } else { "ies" }
            ));
        }
        out
    }
}

/// Name up to three of them by basename, then say how many more. Enough to
/// recognise what was touched without turning a console line into the file it
/// is summarising.
///
/// Recognisable ones first, deliberately. Taken in tar order, `node:22-slim`
/// yields "chage, chfn, chsh, and 8 others" — alphabetically honest and
/// useless, because the point of naming any of them is that the reader pictures
/// the consequence, and nobody has ever run `chage`. The same eleven bits
/// described as "su, passwd, mount" say what actually changed about the guest.
fn name_a_few(items: &[Refusal]) -> String {
    let mut names: Vec<&str> = items
        .iter()
        .filter_map(|r| match r {
            Refusal::SuidStripped { path, .. } => {
                Some(path.rsplit('/').next().unwrap_or(path.as_str()))
            }
            _ => None,
        })
        .collect();
    // By recognisability rank, then alphabetically so the message is stable and
    // reproducible for the same image.
    names.sort_by_key(|n| (WELL_KNOWN.iter().position(|w| w == n).unwrap_or(usize::MAX), *n));
    match names.len() {
        0 => "see BUILD.txt".to_string(),
        1..=3 => names.join(", "),
        n => format!("{}, and {} others", names[..3].join(", "), n - 3),
    }
}

/// setuid binaries whose absence a user will actually notice, so they lead the
/// summary. Not a security classification — purely which names carry meaning at
/// a glance.
/// Ordered by how much the name tells a reader, not alphabetically: sorting
/// these by name puts `gpasswd` first, which is the same failure as `chage` in
/// a smaller costume.
const WELL_KNOWN: &[&str] = &["su", "sudo", "passwd", "mount", "umount", "newgrp", "gpasswd"];

/// Apply layers, bottom-first, to a fresh root filesystem.
pub fn apply(layers: &[Layer]) -> (Rootfs, Report) {
    let mut fs = Rootfs::new();
    let mut report = Report::default();
    for layer in layers {
        for node in &layer.skipped {
            report
                .skipped_nodes
                .push(format!("`{}` is a {}", node.path, node.kind));
        }
        for e in &layer.entries {
            match super::entry::decide(&e.raw) {
                Verdict::Accept { path, kind, notes } => {
                    report.sanitised.extend(notes);

                    // Follow any symlink the rootfs already has in this path's
                    // parents, and refuse to overwrite a directory *alias*
                    // with a real directory.
                    //
                    // This is the usr-merge rule, and it is not theoretical.
                    // Ubuntu's `iproute2` ships `./bin/`, `./bin/ip`,
                    // `./sbin/` and `./sbin/bridge` — because dpkg does this
                    // aliasing itself, so the package never had to. Applied
                    // literally, the directory entries replace `bin ->
                    // usr/bin` and `sbin -> usr/sbin`, and every one of the
                    // ~1400 programs that used to be reachable through them
                    // stops being. Measured: the guest that resulted booted to
                    // `Kernel panic - not syncing: No working init found`,
                    // having tried `/sbin/init` and `/bin/sh` and found
                    // neither.
                    //
                    // Resolving here rather than at write time also closes the
                    // silent-drop half of the same class: cpio entries are
                    // unpacked in sorted order, so a file written through a
                    // symlink whose target has not been created yet is
                    // discarded by the kernel without a word.
                    let path = fs.resolve_parents(&path);
                    if matches!(kind, EntryKind::Directory { .. })
                        && matches!(fs.kind_of(&path), Some(EntryKind::Symlink { .. }))
                    {
                        report.aliased_dirs += 1;
                        continue;
                    }

                    // A hardlink is a second *name* for content already in the
                    // archive, and it stays one: cpio expresses that with a
                    // shared `ino`, and `write_cpio` does the grouping.
                    //
                    // Resolving it to a copy here looks harmless and is not.
                    // busybox is a single binary hardlinked ~400 times, so
                    // copying turned a 1.8 MiB layer into a 467 MiB initramfs
                    // the guest could not fit in RAM. Measured, not predicted.
                    //
                    // The target is verified to exist *now*, so a link to
                    // nothing is refused at the layer that introduced it rather
                    // than becoming a zero-byte command later.
                    if let EntryKind::Hardlink { target } = &kind {
                        let src = fs.resolve_parents(target.trim_start_matches("./"));
                        if fs.contains(&src) {
                            fs.insert(path, EntryKind::Hardlink { target: src }, Vec::new());
                        } else {
                            report.refused.push(Refusal::HardlinkEscape {
                                path,
                                target: target.clone(),
                            });
                        }
                        continue;
                    }
                    fs.insert(path, kind, e.data.clone());
                }
                Verdict::Whiteout { path } => {
                    let path = fs.resolve_parents(&path);
                    fs.whiteout(&path);
                    report.whiteouts += 1;
                }
                Verdict::Opaque { dir } => {
                    let dir = fs.resolve_parents(&dir);
                    fs.opaque(&dir);
                    report.opaques += 1;
                }
                Verdict::ArchiveRoot => {}
                Verdict::Reject(r) => report.refused.push(r),
            }
        }
    }
    fs.materialize_parents();
    (fs, report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::entry::RawEntry;
    use crate::oci::targz::TarEntry;

    fn file(path: &str, body: &str) -> TarEntry {
        TarEntry {
            raw: RawEntry {
                path: path.to_string(),
                kind: EntryKind::File {
                    mode: 0o644,
                    size: body.len() as u64,
                },
            },
            data: body.as_bytes().to_vec(),
        }
    }

    fn dir(path: &str) -> TarEntry {
        TarEntry {
            raw: RawEntry {
                path: path.to_string(),
                kind: EntryKind::Directory { mode: 0o755 },
            },
            data: Vec::new(),
        }
    }

    fn symlink(path: &str, target: &str) -> TarEntry {
        TarEntry {
            raw: RawEntry {
                path: path.to_string(),
                kind: EntryKind::Symlink {
                    target: target.to_string(),
                },
            },
            data: Vec::new(),
        }
    }

    /// Regression for a guest that panicked with `No working init found`.
    ///
    /// Ubuntu's `iproute2` ships `./bin/`, `./bin/ip`, `./sbin/` and
    /// `./sbin/bridge`, because dpkg does usr-merge aliasing itself and the
    /// package never had to. Applied literally on top of a base whose `bin` is
    /// a symlink to `usr/bin`, the directory entry replaces the symlink and
    /// every program reachable through it disappears at once -- `/bin/sh`
    /// included, which is why the kernel had nothing left to run.
    #[test]
    fn a_deb_that_ships_bin_does_not_destroy_the_usr_merge_symlink() {
        let base = layer(vec![
            symlink("bin", "usr/bin"),
            dir("usr"),
            dir("usr/bin"),
            file("usr/bin/sh", "#!/bin/sh\n"),
        ]);
        let iproute2 = layer(vec![dir("bin"), file("bin/ip", "ELF")]);
        let (fs, report) = apply(&[base, iproute2]);

        assert!(
            matches!(fs.kind_of("bin"), Some(EntryKind::Symlink { .. })),
            "`bin` stopped being a symlink, so everything under /bin is gone"
        );
        assert!(
            fs.contains("usr/bin/sh"),
            "/bin/sh is no longer reachable, and the kernel panics"
        );
        assert!(
            fs.contains("usr/bin/ip"),
            "`bin/ip` was not redirected through the alias: {:?}",
            fs.paths().collect::<Vec<_>>()
        );
        assert!(!fs.contains("bin/ip"), "`ip` was written through a symlink");
        assert_eq!(report.aliased_dirs, 1, "the redirection was not reported");
    }

    /// The redirection must not become a way to write outside the tree, and it
    /// must not fire on the ordinary case. A layer replacing a symlink with a
    /// *file* is a legitimate thing an image does and is left alone.
    #[test]
    fn replacing_a_symlink_with_a_file_is_still_allowed() {
        let base = layer(vec![symlink("bin", "usr/bin"), dir("usr"), dir("usr/bin")]);
        let upper = layer(vec![file("bin", "not a directory")]);
        let (fs, report) = apply(&[base, upper]);
        assert!(
            matches!(fs.kind_of("bin"), Some(EntryKind::File { .. })),
            "an explicit replacement was swallowed by the alias rule"
        );
        assert_eq!(report.aliased_dirs, 0);
    }

    fn layer(entries: Vec<TarEntry>) -> Layer {
        Layer {
            entries,
            skipped: Vec::new(),
        }
    }

    #[test]
    fn a_later_layer_replaces_a_file_from_an_earlier_one() {
        let (fs, _) = apply(&[
            layer(vec![file("etc/os-release", "base")]),
            layer(vec![file("etc/os-release", "patched")]),
        ]);
        assert_eq!(fs.get("etc/os-release").unwrap().data, b"patched");
    }

    #[test]
    fn a_whiteout_deletes_the_file_below_it() {
        let (fs, r) = apply(&[
            layer(vec![file("usr/bin/curl", "x")]),
            layer(vec![file("usr/bin/.wh.curl", "")]),
        ]);
        assert!(!fs.contains("usr/bin/curl"));
        assert!(
            !fs.contains("usr/bin/.wh.curl"),
            "the marker is not content"
        );
        assert_eq!(r.whiteouts, 1);
    }

    /// The distinction that is easy to get backwards: opaque keeps the
    /// directory and clears its contents; a whiteout removes the directory and
    /// its whole subtree.
    #[test]
    fn an_opaque_marker_clears_contents_but_keeps_the_directory() {
        let (fs, r) = apply(&[
            layer(vec![dir("var/cache"), file("var/cache/a", "1")]),
            layer(vec![file("var/cache/.wh..wh..opq", "")]),
        ]);
        assert!(fs.contains("var/cache"), "the directory itself survives");
        assert!(!fs.contains("var/cache/a"));
        assert_eq!(r.opaques, 1);
    }

    #[test]
    fn a_whiteout_of_a_directory_takes_its_whole_subtree() {
        let (fs, _) = apply(&[
            layer(vec![dir("opt/app"), file("opt/app/deep/file", "1")]),
            layer(vec![file("opt/.wh.app", "")]),
        ]);
        assert!(!fs.contains("opt/app"));
        assert!(!fs.contains("opt/app/deep/file"));
    }

    /// The applier must not let a traversal through, and must say so rather
    /// than dropping it quietly — a refusal nobody sees is the failure shape
    /// this repo keeps finding.
    #[test]
    fn a_traversing_entry_is_refused_and_reported() {
        let (fs, r) = apply(&[layer(vec![file("../../etc/passwd", "pwned")])]);
        assert_eq!(fs.len(), 0);
        assert_eq!(r.refused.len(), 1);
        assert!(r.has_findings());
    }

    /// The link stays a link. Copying is what turned a 1.8 MiB busybox layer
    /// into a 467 MiB initramfs, so this asserts the *representation*, not just
    /// that the path exists.
    #[test]
    fn a_hardlink_stays_a_link_rather_than_becoming_a_copy() {
        let (fs, r) = apply(&[layer(vec![
            file("bin/busybox", "ELF"),
            TarEntry {
                raw: RawEntry {
                    path: "bin/ls".to_string(),
                    kind: EntryKind::Hardlink {
                        target: "bin/busybox".to_string(),
                    },
                },
                data: Vec::new(),
            },
        ])]);
        assert!(matches!(
            fs.get("bin/ls").unwrap().kind,
            EntryKind::Hardlink { .. }
        ));
        assert!(fs.get("bin/ls").unwrap().data.is_empty(), "no second copy");
        assert!(r.refused.is_empty());
    }

    /// The size claim, asserted rather than described: N links to one binary
    /// must cost one binary, not N.
    #[test]
    fn many_links_to_one_binary_cost_one_binary() {
        let body = "X".repeat(4096);
        let mut entries = vec![file("bin/busybox", &body)];
        for n in 0..50 {
            entries.push(TarEntry {
                raw: RawEntry {
                    path: format!("bin/cmd{n}"),
                    kind: EntryKind::Hardlink {
                        target: "bin/busybox".to_string(),
                    },
                },
                data: Vec::new(),
            });
        }
        let (fs, _) = apply(&[layer(entries)]);
        assert_eq!(
            fs.content_bytes(),
            4096,
            "51 names, one copy of the content"
        );
    }

    /// A hardlink to something not in the archive cannot be resolved to a copy,
    /// and inventing an empty file would produce a rootfs quietly missing a
    /// binary — busybox images are almost entirely hardlinks, so this would be
    /// a whole toolbox of zero-byte commands.
    #[test]
    fn a_hardlink_to_nothing_is_refused_not_invented() {
        let (fs, r) = apply(&[layer(vec![TarEntry {
            raw: RawEntry {
                path: "bin/ls".to_string(),
                kind: EntryKind::Hardlink {
                    target: "bin/nowhere".to_string(),
                },
            },
            data: Vec::new(),
        }])]);
        assert!(!fs.contains("bin/ls"));
        assert_eq!(r.refused.len(), 1);
    }

    #[test]
    fn parents_are_materialized_so_cpio_can_unpack_it() {
        let (fs, _) = apply(&[layer(vec![file("usr/lib/aarch64/libc.so", "x")])]);
        for p in ["usr", "usr/lib", "usr/lib/aarch64"] {
            assert!(fs.contains(p), "missing parent {p}");
        }
    }

    #[test]
    fn a_setuid_bit_is_stripped_and_reported_rather_than_refused() {
        let (fs, r) = apply(&[layer(vec![TarEntry {
            raw: RawEntry {
                path: "usr/bin/sudo".to_string(),
                kind: EntryKind::File {
                    mode: 0o4755,
                    size: 1,
                },
            },
            data: b"x".to_vec(),
        }])]);
        assert!(fs.contains("usr/bin/sudo"), "the file is still built");
        assert_eq!(r.sanitised.len(), 1);
        assert!(r.refused.is_empty());
        assert!(r.has_findings());
    }

    /// #304: `node:22-slim` -- the image a new user is most likely to try --
    /// produced eleven stripped setuid bits and **zero** refusals, and the
    /// console announced "see BUILD.txt for what was refused". It named the one
    /// category that was empty.
    ///
    /// So the guard is that the summary reports the category that actually
    /// happened, and carries the consequence rather than a count: `su` and
    /// `passwd` not elevating is the fact a user needs, and it is knowable here
    /// without opening a file.
    #[test]
    fn the_console_summary_names_what_happened_and_not_what_did_not() {
        // In `node:22-slim`'s own tar order, so the guard sees what the tester
        // saw: the recognisable names arrive last and must still lead.
        let mut r = Report::default();
        for f in ["usr/bin/chsh", "usr/bin/mount", "usr/bin/passwd", "usr/bin/su"] {
            r.sanitised.push(Refusal::SuidStripped {
                path: f.to_string(),
                mode: 0o4755,
            });
        }

        let lines = r.console_findings();
        assert_eq!(lines.len(), 1, "one category happened, so one line: {lines:?}");
        let line = &lines[0];

        assert!(
            !line.to_lowercase().contains("refus"),
            "nothing was refused; saying so is the whole bug: {line}"
        );
        assert!(line.contains('4'), "the count is stated: {line}");
        for named in ["su", "passwd", "mount"] {
            assert!(line.contains(named), "{named} is named: {line}");
        }
        assert!(
            line.contains("and 1 other"),
            "the tail is counted, not listed: {line}"
        );
        assert!(
            !line.contains("chsh"),
            "`chsh` is the forgettable one and must not displace a name that \
             carries the consequence: {line}"
        );
        assert!(
            line.contains("(su, passwd, mount,"),
            "ranked by what the name tells a reader, not alphabetically -- \
             sorting by name puts `gpasswd` first and teaches nobody: {line}"
        );
        assert!(
            line.contains("not elevate"),
            "the consequence is stated, not just the fact: {line}"
        );
    }

    /// The loud category stays loud, and stays separate. A refusal is a dropped
    /// entry and is worth stopping for; a stripped bit is routine. Flattening
    /// them is what produced #304, so they must not share a line again.
    #[test]
    fn a_refusal_is_reported_apart_from_a_stripped_bit() {
        let mut r = Report::default();
        r.refused.push(Refusal::Traversal("../etc/passwd".to_string()));
        r.sanitised.push(Refusal::SuidStripped {
            path: "usr/bin/su".to_string(),
            mode: 0o4755,
        });
        r.skipped_nodes.push("`dev/null` is a device".to_string());

        let lines = r.console_findings();
        assert_eq!(lines.len(), 3, "three categories, three lines: {lines:?}");
        assert!(lines[0].contains("REFUSED"), "{:?}", lines[0]);
        assert!(lines[1].contains("setuid"), "{:?}", lines[1]);
        assert!(lines[2].contains("Skipped"), "{:?}", lines[2]);

        assert!(
            Report::default().console_findings().is_empty(),
            "a clean image says nothing at all"
        );
    }

    #[test]
    fn a_skipped_device_node_is_carried_into_the_report() {
        let l = Layer {
            entries: Vec::new(),
            skipped: vec![crate::oci::targz::SkippedNode {
                path: "dev/null".to_string(),
                kind: "character device",
            }],
        };
        let (_, r) = apply(&[l]);
        assert_eq!(r.skipped_nodes.len(), 1);
        assert!(r.has_findings());
    }

    /// A clean image should produce a clean report, or every build prints
    /// findings and the real ones stop being read.
    #[test]
    fn an_ordinary_image_reports_nothing() {
        let (_, r) = apply(&[layer(vec![dir("etc"), file("etc/hostname", "box")])]);
        assert!(!r.has_findings());
    }

    /// Real layers open with an entry for the archive root. Reporting it as a
    /// refusal made every busybox build print a line that looked like a
    /// security finding and was not.
    #[test]
    fn the_archive_root_entry_is_not_a_finding() {
        for root in [".", "./", ""] {
            let (fs, r) = apply(&[layer(vec![dir(root), file("etc/hostname", "b")])]);
            assert!(r.refused.is_empty(), "`{root}` reported as a refusal");
            assert!(!r.has_findings(), "`{root}` produced a finding");
            assert!(fs.contains("etc/hostname"));
        }
    }
}
