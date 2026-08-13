// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! What a layer entry is allowed to do to the rootfs we are building.
//!
//! # Why this is a pure function
//!
//! A container image is **untrusted content pulled off the internet**, and
//! layer unpacking is the classic path-traversal surface: `../` components,
//! absolute paths, symlinks pointing out of the root, hardlinks to host files,
//! device nodes, setuid bits. #153 names this as non-negotiable, and it is the
//! same threat as a rehydrated snapshot wearing a friendlier file format.
//!
//! So the decision is separated from the extraction. Nothing here opens,
//! creates or writes a file: every entry becomes a [`Verdict`] by string and
//! integer inspection alone. That means each attack is an ordinary unit test
//! with no temporary directory, no privileges and no cleanup — and a test can
//! assert the *reason* we refused, not merely that something failed.
//!
//! It also means the policy is readable in one place. A reviewer asking "can a
//! malicious image write outside the rootfs?" reads this file, rather than
//! trying to prove a negative across extraction code interleaved with IO.
//!
//! # Why we do not use a tar crate's built-in protection
//!
//! Crates that unpack tar generally offer a "safe" mode. Taking one would make
//! the security policy *theirs*, changing under us on a version bump, and
//! phrased as errors we cannot explain to a user. The rules below are ours,
//! and each one is here because of a specific attack.

use std::fmt;

/// An OCI whiteout marker: `.wh.<name>` deletes `<name>` from the accumulated
/// rootfs when a later layer is applied over an earlier one.
pub const WHITEOUT_PREFIX: &str = ".wh.";

/// The opaque-directory marker: `.wh..wh..opq` inside a directory means "every
/// entry this directory had in lower layers is gone", not merely the ones
/// individually whited out.
pub const OPAQUE_MARKER: &str = ".wh..wh..opq";

/// The kind of thing a layer entry describes, reduced to what we can safely
/// reproduce. Anything not representable here is refused rather than
/// approximated — an image that needs a block device is an image we cannot
/// honestly build, and silently dropping the node would produce a rootfs that
/// differs from what the author declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File {
        mode: u32,
        size: u64,
    },
    Directory {
        mode: u32,
    },
    Symlink {
        target: String,
    },
    /// A hardlink to an earlier entry in the same archive.
    Hardlink {
        target: String,
    },
}

/// A layer entry as read off the wire, before any judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEntry {
    pub path: String,
    pub kind: EntryKind,
}

/// Why an entry was refused. Each variant exists because of a specific attack
/// or a specific thing we cannot reproduce, and carries enough detail to name
/// the offending path in a message a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `../` escaping the rootfs, in the entry path itself.
    Traversal(String),
    /// An absolute path. Tar stores relative paths; an absolute one is either
    /// a broken writer or an attempt to land on a host path.
    Absolute(String),
    /// A symlink whose target resolves outside the rootfs. This is the subtle
    /// one: the *entry* path is innocent, and the escape only happens when
    /// something later writes through the link.
    SymlinkEscape { path: String, target: String },
    /// A hardlink pointing outside the rootfs — the same escape without the
    /// indirection, and worse, because it shares the inode immediately.
    HardlinkEscape { path: String, target: String },
    /// setuid/setgid on an extracted file. These bits mean nothing to us while
    /// the rootfs is data on the host, but they *do* mean something once the
    /// guest treats it as a filesystem, so they are stripped rather than
    /// carried, and the caller is told.
    SuidStripped { path: String, mode: u32 },
    /// An empty path, or one that normalises to nothing.
    Empty,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Traversal(p) => {
                write!(f, "`{p}` escapes the image root with `..`")
            }
            Self::Absolute(p) => write!(f, "`{p}` is an absolute path"),
            Self::SymlinkEscape { path, target } => write!(
                f,
                "`{path}` is a symlink to `{target}`, which is outside the image root"
            ),
            Self::HardlinkEscape { path, target } => write!(
                f,
                "`{path}` is a hardlink to `{target}`, which is outside the image root"
            ),
            Self::SuidStripped { path, mode } => write!(
                f,
                "`{path}` had mode {mode:o} (setuid/setgid); the bit was removed"
            ),
            Self::Empty => write!(f, "an entry with an empty path"),
        }
    }
}

/// What to do with one layer entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The archive's own root (`.` or `./`). Real layers begin with one and it
    /// carries no content, so it is a no-op — reported as neither an
    /// acceptance nor a refusal. Treating it as a refusal made every busybox
    /// build print `an entry with an empty path`, which is alarming, wrong,
    /// and trains a reader to skim the line the real refusals appear on.
    ArchiveRoot,
    /// Write it, at this normalised path, with these (possibly sanitised)
    /// attributes. `notes` carries what we changed rather than refused —
    /// currently only stripped setuid bits.
    Accept {
        path: String,
        kind: EntryKind,
        notes: Vec<Refusal>,
    },
    /// Delete `path` from the rootfs accumulated so far.
    Whiteout { path: String },
    /// Every lower-layer entry under `dir` is gone.
    Opaque { dir: String },
    /// Refuse, for this reason.
    Reject(Refusal),
}

/// Normalise a tar path to a rootfs-relative path, or explain why it cannot be
/// one.
///
/// Handles the cases a real registry actually produces (`./usr/bin`, trailing
/// slashes, doubled separators) and the ones an attacker produces (`../`,
/// `/etc/passwd`, `a/../../b`). Interior `..` is resolved rather than banned
/// outright, because `a/b/../c` is legitimate and equals `a/c`; what is banned
/// is a `..` that would pop *above* the root, which is the actual escape.
pub fn normalize(path: &str) -> Result<String, Refusal> {
    if path.is_empty() {
        return Err(Refusal::Empty);
    }
    if path.starts_with('/') {
        return Err(Refusal::Absolute(path.to_string()));
    }
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(Refusal::Traversal(path.to_string()));
                }
            }
            p => out.push(p),
        }
    }
    if out.is_empty() {
        return Err(Refusal::Empty);
    }
    Ok(out.join("/"))
}

/// Does `target`, interpreted from the directory containing `link_path`, stay
/// inside the rootfs?
///
/// An absolute target (`/etc/passwd`) is *fine* and stays inside, because it is
/// resolved by the guest kernel against the guest's own root — it is not a host
/// path. What is not fine is a relative target with enough `..` to climb out of
/// the image root, because that one is resolved by *us*, on the host, at
/// extraction time.
///
/// This asymmetry is the whole point and is easy to get backwards.
pub fn symlink_stays_inside(link_path: &str, target: &str) -> bool {
    if target.starts_with('/') {
        return true;
    }
    // Depth of the directory holding the link.
    let mut depth = link_path.split('/').count().saturating_sub(1);
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            _ => depth += 1,
        }
    }
    true
}

/// The setuid and setgid bits.
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

/// Judge one entry.
///
/// Order matters. Whiteouts are recognised *before* the entry is treated as
/// content, because a whiteout is an instruction rather than a file — but only
/// after normalisation, so `.wh.` cannot be smuggled in behind a traversal.
pub fn decide(entry: &RawEntry) -> Verdict {
    // The archive root, before normalisation can reduce it to "empty".
    let trimmed = entry.path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return Verdict::ArchiveRoot;
    }
    let path = match normalize(&entry.path) {
        Ok(p) => p,
        Err(r) => return Verdict::Reject(r),
    };

    let (dir, base) = match path.rsplit_once('/') {
        Some((d, b)) => (d, b),
        None => ("", path.as_str()),
    };

    if base == OPAQUE_MARKER {
        return Verdict::Opaque {
            dir: dir.to_string(),
        };
    }
    if let Some(name) = base.strip_prefix(WHITEOUT_PREFIX) {
        if name.is_empty() {
            return Verdict::Reject(Refusal::Empty);
        }
        let victim = if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        };
        return Verdict::Whiteout { path: victim };
    }

    let mut notes = Vec::new();
    let kind = match &entry.kind {
        EntryKind::Symlink { target } => {
            if !symlink_stays_inside(&path, target) {
                return Verdict::Reject(Refusal::SymlinkEscape {
                    path,
                    target: target.clone(),
                });
            }
            EntryKind::Symlink {
                target: target.clone(),
            }
        }
        EntryKind::Hardlink { target } => match normalize(target) {
            Ok(t) => EntryKind::Hardlink { target: t },
            Err(_) => {
                return Verdict::Reject(Refusal::HardlinkEscape {
                    path,
                    target: target.clone(),
                })
            }
        },
        EntryKind::File { mode, size } => {
            let cleaned = mode & !(S_ISUID | S_ISGID);
            if cleaned != *mode {
                notes.push(Refusal::SuidStripped {
                    path: path.clone(),
                    mode: *mode,
                });
            }
            EntryKind::File {
                mode: cleaned,
                size: *size,
            }
        }
        EntryKind::Directory { mode } => EntryKind::Directory {
            mode: mode & !(S_ISUID | S_ISGID),
        },
    };

    Verdict::Accept { path, kind, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> RawEntry {
        RawEntry {
            path: path.to_string(),
            kind: EntryKind::File {
                mode: 0o644,
                size: 0,
            },
        }
    }

    fn link(path: &str, target: &str) -> RawEntry {
        RawEntry {
            path: path.to_string(),
            kind: EntryKind::Symlink {
                target: target.to_string(),
            },
        }
    }

    #[test]
    fn ordinary_paths_normalise() {
        assert_eq!(normalize("usr/bin/env").unwrap(), "usr/bin/env");
        assert_eq!(normalize("./usr/bin/env").unwrap(), "usr/bin/env");
        assert_eq!(normalize("usr//bin/").unwrap(), "usr/bin");
        assert_eq!(normalize("a/b/../c").unwrap(), "a/c");
    }

    #[test]
    fn traversal_is_refused_however_it_is_spelled() {
        for p in [
            "../etc/passwd",
            "./../etc/passwd",
            "a/../../etc/passwd",
            "a/b/../../../etc/passwd",
            "..",
        ] {
            assert!(
                matches!(normalize(p), Err(Refusal::Traversal(_))),
                "{p} should be refused as traversal"
            );
        }
    }

    #[test]
    fn absolute_paths_are_refused() {
        assert!(matches!(
            normalize("/etc/passwd"),
            Err(Refusal::Absolute(_))
        ));
        assert!(matches!(decide(&file("/etc/passwd")), Verdict::Reject(_)));
    }

    #[test]
    fn a_relative_symlink_that_climbs_out_is_refused() {
        let v = decide(&link("usr/bin/x", "../../../../etc/passwd"));
        assert!(
            matches!(v, Verdict::Reject(Refusal::SymlinkEscape { .. })),
            "got {v:?}"
        );
    }

    /// The asymmetry that is easy to get backwards: an *absolute* symlink
    /// target is resolved by the guest kernel against the guest's own root, so
    /// it cannot reach a host file and must be allowed — `/usr/bin/python3` ->
    /// `/usr/bin/python3.12` is in essentially every image.
    #[test]
    fn an_absolute_symlink_target_is_allowed_because_the_guest_resolves_it() {
        let v = decide(&link("usr/bin/python3", "/usr/bin/python3.12"));
        assert!(matches!(v, Verdict::Accept { .. }), "got {v:?}");
    }

    #[test]
    fn a_relative_symlink_inside_the_root_is_allowed() {
        assert!(symlink_stays_inside("usr/bin/x", "../lib/y"));
        assert!(symlink_stays_inside("usr/bin/x", "./y"));
        assert!(symlink_stays_inside("a/b/c/d", "../../e"));
        assert!(!symlink_stays_inside("a/b", "../../e"));
    }

    #[test]
    fn a_hardlink_out_of_the_root_is_refused() {
        let v = decide(&RawEntry {
            path: "x".to_string(),
            kind: EntryKind::Hardlink {
                target: "../../etc/shadow".to_string(),
            },
        });
        assert!(
            matches!(v, Verdict::Reject(Refusal::HardlinkEscape { .. })),
            "got {v:?}"
        );
    }

    #[test]
    fn setuid_is_stripped_and_reported_rather_than_refused() {
        let v = decide(&RawEntry {
            path: "usr/bin/sudo".to_string(),
            kind: EntryKind::File {
                mode: 0o4755,
                size: 10,
            },
        });
        match v {
            Verdict::Accept { kind, notes, .. } => {
                assert_eq!(
                    kind,
                    EntryKind::File {
                        mode: 0o755,
                        size: 10
                    }
                );
                assert!(matches!(notes.as_slice(), [Refusal::SuidStripped { .. }]));
            }
            other => panic!("expected accept-with-note, got {other:?}"),
        }
    }

    #[test]
    fn whiteouts_become_deletions_not_files() {
        assert_eq!(
            decide(&file("usr/bin/.wh.oldtool")),
            Verdict::Whiteout {
                path: "usr/bin/oldtool".to_string()
            }
        );
        assert_eq!(
            decide(&file(".wh.top")),
            Verdict::Whiteout {
                path: "top".to_string()
            }
        );
    }

    #[test]
    fn an_opaque_marker_clears_the_whole_directory() {
        assert_eq!(
            decide(&file("var/cache/.wh..wh..opq")),
            Verdict::Opaque {
                dir: "var/cache".to_string()
            }
        );
    }

    /// A whiteout is an *instruction*, so it must not become a way to smuggle a
    /// path past the traversal check: normalisation happens first.
    #[test]
    fn a_whiteout_cannot_carry_a_traversal() {
        assert!(matches!(
            decide(&file("../.wh.passwd")),
            Verdict::Reject(Refusal::Traversal(_))
        ));
    }

    #[test]
    fn an_empty_whiteout_name_is_refused() {
        assert!(matches!(
            decide(&file("usr/.wh.")),
            Verdict::Reject(Refusal::Empty)
        ));
    }

    #[test]
    fn refusals_name_the_path_they_are_about() {
        let msg = Refusal::SymlinkEscape {
            path: "a/b".to_string(),
            target: "../../c".to_string(),
        }
        .to_string();
        assert!(msg.contains("a/b"), "{msg}");
        assert!(msg.contains("../../c"), "{msg}");
    }
}
