// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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
}

impl Report {
    /// Did anything happen that a user should see before booting this?
    pub fn has_findings(&self) -> bool {
        !self.refused.is_empty() || !self.sanitised.is_empty() || !self.skipped_nodes.is_empty()
    }
}

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
                        let src = target.trim_start_matches("./").to_string();
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
                    fs.whiteout(&path);
                    report.whiteouts += 1;
                }
                Verdict::Opaque { dir } => {
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
