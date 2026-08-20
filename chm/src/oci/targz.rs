// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Reading a layer: gzip, then tar.
//!
//! # Why the tar reader is in-tree
//!
//! Layer content is untrusted (see [`super::entry`]), and the parser is the
//! first thing the attacker's bytes touch. A tar reader is 512-byte headers
//! with octal fields and two extension formats; that is a small, well-specified
//! amount of code, and writing it here means every bound check and every
//! "malformed header" decision is reviewable in this repository rather than
//! inherited from a dependency's release notes.
//!
//! It also keeps the crate's dependency posture: `flate2` is already vendored
//! in this workspace, so gzip costs nothing new, while no `tar` crate is.
//!
//! # What it handles
//!
//! - **ustar** — the ordinary case, including the `prefix` field that lets a
//!   long path be split across two header fields.
//! - **PAX** (`typeflag` `x`) — the modern long-path carrier. GNU tar and every
//!   registry builder emit these for paths over 100 bytes, so an image with a
//!   deep `node_modules` tree is not an edge case, it is Tuesday.
//! - **GNU long name/link** (`L`/`K`) — the older carrier, still produced by
//!   some builders.
//!
//! Device nodes, FIFOs and sockets are *reported*, not silently skipped, so the
//! caller can tell the user what an image asked for and did not get.

use std::io::Read;

use super::entry::{EntryKind, RawEntry};

/// A tar block. The format is defined in these units and every offset below is
/// easier to read against it.
const BLOCK: usize = 512;

/// One entry, with its content already read into memory.
///
/// Layers are compressed streams that cannot be seeked, and the whole rootfs is
/// going into a cpio image in memory anyway, so buffering per entry costs
/// nothing extra and keeps the reader a simple forward scan.
#[derive(Debug)]
pub struct TarEntry {
    pub raw: RawEntry,
    pub data: Vec<u8>,
}

/// Something an image asked for that we will not build. Kept separate from
/// [`super::entry::Refusal`] because this is a *format* judgement made while
/// parsing, before policy has an opinion.
#[derive(Debug)]
pub struct SkippedNode {
    pub path: String,
    pub kind: &'static str,
}

/// The result of reading one layer.
#[derive(Debug)]
pub struct Layer {
    pub entries: Vec<TarEntry>,
    /// Device nodes, FIFOs and sockets found in the archive. Reported rather
    /// than dropped, because "your image contains /dev/console and we did not
    /// create it" is something the user may need to know.
    pub skipped: Vec<SkippedNode>,
}

/// Parse an octal field, tolerating the several ways tar writers terminate one
/// (NUL, space, or neither) and the GNU base-256 extension for sizes that do
/// not fit.
fn octal(field: &[u8]) -> Option<u64> {
    // GNU base-256: high bit set in the first byte, remainder is big-endian.
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = u64::from(field[0] & 0x7f);
        for b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(*b))?;
        }
        return Some(v);
    }
    let s = field
        .iter()
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect::<String>();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s.trim(), 8).ok()
}

/// Read a NUL-terminated string field.
fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// How many bytes of padding follow `size` bytes of content.
fn padding(size: u64) -> usize {
    let rem = (size % BLOCK as u64) as usize;
    if rem == 0 {
        0
    } else {
        BLOCK - rem
    }
}

/// Extract `path=` from a PAX extended header record block.
///
/// PAX records are `"<len> <key>=<value>\n"`, where `<len>` counts the whole
/// record including itself. We only care about `path` and `linkpath`.
fn pax_field(data: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let mut rest = text.as_ref();
    while let Some(sp) = rest.find(' ') {
        let len: usize = rest[..sp].parse().ok()?;
        if len == 0 || len > rest.len() {
            return None;
        }
        let record = &rest[sp + 1..len];
        if let Some((k, v)) = record.split_once('=')
            && k == key
        {
            return Some(v.trim_end_matches('\n').to_string());
        }
        rest = &rest[len..];
    }
    None
}

/// A single layer's worth of decompressed tar, parsed.
///
/// `read` is consumed to end-of-stream. A truncated archive is not an error:
/// tar's terminator is two zero blocks, and real layers are sometimes simply
/// cut there, so the reader stops cleanly at the first zero header.
pub fn read_layer(mut read: impl Read, limit_bytes: u64) -> Result<Layer, String> {
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut header = [0u8; BLOCK];
    // Carried across headers by the L/K/x extension records.
    let mut next_path: Option<String> = None;
    let mut next_link: Option<String> = None;
    let mut total: u64 = 0;

    loop {
        if !read_exact_or_eof(&mut read, &mut header)? {
            break;
        }
        if header.iter().all(|b| *b == 0) {
            break;
        }

        let size = octal(&header[124..136]).ok_or("tar: unreadable size field")?;
        total = total.saturating_add(size);
        if total > limit_bytes {
            return Err(format!(
                "layer expands to more than {} MiB, which is past the limit for one image \
                 (a decompression bomb looks exactly like this)",
                limit_bytes / (1024 * 1024)
            ));
        }

        let typeflag = header[156];
        let mut body = vec![0u8; usize::try_from(size).map_err(|_| "tar: entry too large")?];
        read.read_exact(&mut body)
            .map_err(|e| format!("tar: short read on entry body: {e}"))?;
        let pad = padding(size);
        if pad > 0 {
            let mut sink = vec![0u8; pad];
            read.read_exact(&mut sink)
                .map_err(|e| format!("tar: short read on padding: {e}"))?;
        }

        match typeflag {
            // GNU long name / long link: the *next* header's name comes from
            // this entry's body.
            b'L' => {
                next_path = Some(cstr(&body));
                continue;
            }
            b'K' => {
                next_link = Some(cstr(&body));
                continue;
            }
            // PAX extended header, per-entry (x) or global (g). Global records
            // are ignored: they carry archive metadata, not paths we need.
            b'x' => {
                if let Some(p) = pax_field(&body, "path") {
                    next_path = Some(p);
                }
                if let Some(l) = pax_field(&body, "linkpath") {
                    next_link = Some(l);
                }
                continue;
            }
            b'g' => continue,
            _ => {}
        }

        let name = next_path.take().unwrap_or_else(|| {
            let prefix = cstr(&header[345..500]);
            let base = cstr(&header[0..100]);
            if prefix.is_empty() {
                base
            } else {
                format!("{prefix}/{base}")
            }
        });
        let linkname = next_link.take().unwrap_or_else(|| cstr(&header[157..257]));
        let mode = u32::try_from(octal(&header[100..108]).unwrap_or(0o644)).unwrap_or(0o644);

        let kind = match typeflag {
            b'0' | b'\0' | b'7' => EntryKind::File { mode, size },
            b'5' => EntryKind::Directory { mode },
            b'2' => EntryKind::Symlink { target: linkname },
            b'1' => EntryKind::Hardlink { target: linkname },
            other => {
                skipped.push(SkippedNode {
                    path: name,
                    kind: match other {
                        b'3' => "character device",
                        b'4' => "block device",
                        b'6' => "FIFO",
                        _ => "unsupported entry type",
                    },
                });
                continue;
            }
        };

        entries.push(TarEntry {
            raw: RawEntry { path: name, kind },
            data: body,
        });
    }

    Ok(Layer { entries, skipped })
}

/// Fill `buf`, returning `false` at a clean end of stream.
fn read_exact_or_eof(mut read: impl Read, buf: &mut [u8]) -> Result<bool, String> {
    let mut filled = 0;
    while filled < buf.len() {
        match read.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err("tar: stream ended mid-header".to_string());
            }
            Ok(n) => filled += n,
            Err(e) => return Err(format!("tar: read failed: {e}")),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tar header. Enough of a writer to test the reader without
    /// shipping one.
    fn header(name: &str, size: u64, typeflag: u8, link: &str, mode: u32) -> Vec<u8> {
        let mut h = vec![0u8; BLOCK];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        let m = format!("{mode:07o}\0");
        h[100..108].copy_from_slice(m.as_bytes());
        let s = format!("{size:011o}\0");
        h[124..136].copy_from_slice(s.as_bytes());
        h[156] = typeflag;
        if !link.is_empty() {
            h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        }
        h[257..262].copy_from_slice(b"ustar");
        // Checksum: spaces, then the octal sum. The reader does not verify it,
        // but writing it keeps the fixtures honest tar.
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        let c = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(c.as_bytes());
        h
    }

    fn entry(name: &str, body: &[u8]) -> Vec<u8> {
        let mut v = header(name, body.len() as u64, b'0', "", 0o644);
        v.extend_from_slice(body);
        v.extend(std::iter::repeat_n(0u8, padding(body.len() as u64)));
        v
    }

    #[test]
    fn reads_a_plain_file_entry() {
        let tar = entry("hello.txt", b"world");
        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].raw.path, "hello.txt");
        assert_eq!(l.entries[0].data, b"world");
    }

    #[test]
    fn stops_at_the_zero_terminator_without_complaining() {
        let mut tar = entry("a", b"x");
        tar.extend(std::iter::repeat_n(0u8, BLOCK * 2));
        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert_eq!(l.entries.len(), 1);
    }

    /// A path over 100 bytes cannot fit the ustar name field, so builders emit
    /// a PAX record. `node_modules` trees hit this constantly.
    #[test]
    fn a_pax_long_path_is_used_in_place_of_the_truncated_name() {
        let long = format!("usr/lib/{}/deep/file.js", "a".repeat(120));
        let record = format!(" path={long}\n");
        let record = format!("{}{record}", record.len() + 2);
        let mut tar = header(
            "truncated-name",
            record.len() as u64,
            b'x',
            "",
            0o644,
        );
        tar.extend_from_slice(record.as_bytes());
        tar.extend(std::iter::repeat_n(0u8, padding(record.len() as u64)));
        tar.extend(entry("truncated-name", b"z"));

        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].raw.path, long);
    }

    #[test]
    fn a_gnu_long_name_is_used_in_place_of_the_truncated_name() {
        let long = format!("var/{}/x", "b".repeat(150));
        let mut body = long.clone().into_bytes();
        body.push(0);
        let mut tar = header("././@LongLink", body.len() as u64, b'L', "", 0o644);
        tar.extend_from_slice(&body);
        tar.extend(std::iter::repeat_n(0u8, padding(body.len() as u64)));
        tar.extend(entry("truncated", b"q"));

        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert_eq!(l.entries[0].raw.path, long);
    }

    #[test]
    fn the_ustar_prefix_field_is_joined_to_the_name() {
        let mut h = header("file", 0, b'0', "", 0o644);
        let prefix = b"deep/prefix/dir";
        h[345..345 + prefix.len()].copy_from_slice(prefix);
        let l = read_layer(&h[..], 1 << 20).unwrap();
        assert_eq!(l.entries[0].raw.path, "deep/prefix/dir/file");
    }

    #[test]
    fn symlinks_and_hardlinks_carry_their_targets() {
        let mut tar = header("link", 0, b'2', "target", 0o777);
        tar.extend(header("hard", 0, b'1', "orig", 0o644));
        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert_eq!(
            l.entries[0].raw.kind,
            EntryKind::Symlink {
                target: "target".to_string()
            }
        );
        assert_eq!(
            l.entries[1].raw.kind,
            EntryKind::Hardlink {
                target: "orig".to_string()
            }
        );
    }

    #[test]
    fn device_nodes_are_reported_not_silently_dropped() {
        let tar = header("dev/console", 0, b'3', "", 0o600);
        let l = read_layer(&tar[..], 1 << 20).unwrap();
        assert!(l.entries.is_empty());
        assert_eq!(l.skipped.len(), 1);
        assert_eq!(l.skipped[0].path, "dev/console");
        assert_eq!(l.skipped[0].kind, "character device");
    }

    /// A layer whose *decompressed* size is enormous is the classic zip-bomb
    /// shape. The limit is enforced on the running total, not per entry, so a
    /// million small files is caught too.
    #[test]
    fn a_decompression_bomb_is_refused_by_total_size() {
        let mut tar = Vec::new();
        for i in 0..4 {
            tar.extend(entry(&format!("f{i}"), &vec![0u8; 4096]));
        }
        let err = read_layer(&tar[..], 8192).unwrap_err();
        assert!(err.contains("decompression bomb"), "{err}");
    }

    #[test]
    fn octal_handles_the_gnu_base256_extension() {
        let mut f = [0u8; 12];
        f[0] = 0x80;
        f[11] = 0x2a;
        assert_eq!(octal(&f), Some(42));
    }

    #[test]
    fn a_header_cut_in_half_is_an_error_not_a_silent_stop() {
        let tar = [1u8; 200];
        assert!(read_layer(&tar[..], 1 << 20).is_err());
    }
}
