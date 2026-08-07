//! Recognising the kernel files distros actually ship.
//!
//! The arm64 boot protocol wants an uncompressed `Image` — 64-byte header,
//! `ARM\x64` at offset `0x38`. Almost nothing you can download is that. What a
//! distro ships as `vmlinuz` on arm64 is one of:
//!
//! - an **EFI zboot** image: a compressed `Image` wrapped in the container
//!   Linux 6.1 added in `drivers/firmware/efi/libstub/zboot.c`, with `MZ` at 0
//!   and `zimg` at 4. This is what current Alpine, Debian and Fedora arm64
//!   kernels are.
//! - a plain **gzip** stream, which older arm64 packages and several distros
//!   still use.
//!
//! Before this module both were refused, and the zboot refusal named *"an x86
//! bzImage or a vmlinux ELF"* — two things it is not. That is worse than an
//! unhelpful message: it sends someone looking for an architecture problem
//! they do not have, on the very first command of the "I have no images yet"
//! path.
//!
//! # Why decode rather than explain
//!
//! Explaining is cheap and was the tempting half-measure. But the remedy is
//! `gunzip` for one form and *"parse a 32-byte header, slice at the offset it
//! gives you, then gunzip"* for the other — and the second one is a thing we
//! can simply do. The header is self-describing and the payload is an ordinary
//! compressed stream; there is no unpacking of the kernel's own logic here, no
//! relocation, no EFI. It is a container with a documented shape.
//!
//! # Codec by magic bytes, never by the declared type
//!
//! The zboot header carries a `compression_type` string, and this module reads
//! the payload's own magic instead. That is the same rule the OCI puller
//! follows for layers, for the same reason: a producer's label is a claim about
//! the bytes, and the bytes are right there. The declared string is used only
//! to make a refusal say something useful when the magic is one we cannot
//! handle.

use std::borrow::Cow;
use std::io::Read;
use std::str;

use flate2::read::GzDecoder;
use zstd::stream::copy_decode;

/// Offset of the arm64 image magic within the 64-byte kernel header.
pub const ARM64_MAGIC_OFFSET: usize = 0x38;
pub const ARM64_MAGIC: [u8; 4] = *b"ARM\x64";

/// Offsets within the EFI zboot header.
///
/// Measured against a real `vmlinuz-virt` rather than transcribed from the
/// struct definition — an earlier reading of `linux_efi_zboot_header` put
/// `zimg` at offset 8, and the file says 4:
///
/// ```text
/// 00000000: 4d5a 0000 7a69 6d67 70c9 0000 72a7 8b00  MZ..zimgp...r...
/// 00000010: 0000 0000 0000 0000 677a 6970 0000 0000  ........gzip....
/// ```
const ZBOOT_ZIMG_OFFSET: usize = 4;
const ZBOOT_PAYLOAD_OFFSET: usize = 8;
const ZBOOT_PAYLOAD_SIZE: usize = 12;
const ZBOOT_COMPRESSION_OFFSET: usize = 0x18;
const ZBOOT_COMPRESSION_LEN: usize = 32;
/// Enough bytes to hold everything above.
const ZBOOT_HEADER_LEN: usize = ZBOOT_COMPRESSION_OFFSET + ZBOOT_COMPRESSION_LEN;

/// What a candidate kernel file turned out to be.
///
/// Carried separately from the decoded bytes so a caller can *say* what it
/// accepted. A line reporting that a compressed kernel was unpacked is the
/// difference between a command that looks like it ignored your file and one
/// that tells you what it did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelForm {
    /// Already an uncompressed arm64 `Image`; nothing to do.
    Raw,
    /// An EFI zboot container, with the compression its header declared.
    Zboot { declared: String },
    /// A bare compressed stream, with the codec its magic bytes identified.
    Compressed { codec: &'static str },
}

impl KernelForm {
    /// One line describing what was found, for a caller that wants to report it.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Raw => "uncompressed arm64 Image".to_string(),
            Self::Zboot { declared } => format!("EFI zboot image ({declared}), decompressed"),
            Self::Compressed { codec } => format!("{codec}-compressed Image, decompressed"),
        }
    }

    /// Did this need unpacking to become a bootable `Image`?
    #[must_use]
    pub fn was_compressed(&self) -> bool {
        !matches!(self, Self::Raw)
    }
}

/// Turn whatever the user pointed at into an uncompressed arm64 `Image`.
///
/// Borrows for the already-uncompressed case, which is the common one and the
/// one where copying a 30 MiB buffer would be pure waste.
///
/// `label` names the file in any error, so the caller keeps control of how the
/// path is presented.
///
/// # Errors
///
/// When the file is not an arm64 kernel in any recognised wrapping. The error
/// names what the bytes actually are — an ELF, an x86 bzImage, a zboot image in
/// a codec we do not carry — because the previous message named two formats by
/// guess and cost a user the wrong investigation.
pub fn decode<'a>(data: &'a [u8], label: &str) -> Result<(Cow<'a, [u8]>, KernelForm), String> {
    if data.len() < 64 {
        return Err(format!("`{label}` is too small to be a kernel"));
    }

    if has_arm64_magic(data) {
        return Ok((Cow::Borrowed(data), KernelForm::Raw));
    }

    if let Some(payload) = zboot_payload(data, label)? {
        let declared = zboot_declared_compression(data);
        let out = inflate(payload, label, &declared)?;
        verify_arm64(&out, label, "the zboot payload")?;
        return Ok((Cow::Owned(out), KernelForm::Zboot { declared }));
    }

    if let Some(codec) = codec_of(data) {
        let out = inflate(data, label, codec)?;
        verify_arm64(&out, label, "the decompressed kernel")?;
        return Ok((Cow::Owned(out), KernelForm::Compressed { codec }));
    }

    Err(unrecognised(data, label))
}

/// Does this buffer already carry the arm64 `Image` magic?
fn has_arm64_magic(data: &[u8]) -> bool {
    data.len() >= ARM64_MAGIC_OFFSET + 4
        && data[ARM64_MAGIC_OFFSET..ARM64_MAGIC_OFFSET + 4] == ARM64_MAGIC
}

/// The compressed payload inside an EFI zboot container, if this is one.
///
/// Returns `Ok(None)` when the file is simply not zboot, and an error when it
/// *is* zboot and the header does not describe a payload inside the file — a
/// truncated download is far more likely than a malicious one here, and either
/// way slicing out of bounds is not the way to find out.
fn zboot_payload<'a>(data: &'a [u8], label: &str) -> Result<Option<&'a [u8]>, String> {
    if data.len() < ZBOOT_HEADER_LEN
        || &data[..2] != b"MZ"
        || &data[ZBOOT_ZIMG_OFFSET..ZBOOT_ZIMG_OFFSET + 4] != b"zimg"
    {
        return Ok(None);
    }

    let offset = le_u32(data, ZBOOT_PAYLOAD_OFFSET) as usize;
    let size = le_u32(data, ZBOOT_PAYLOAD_SIZE) as usize;
    let end = offset.checked_add(size).ok_or_else(|| {
        format!("`{label}` is an EFI zboot image whose header describes an impossible payload")
    })?;
    if size == 0 || end > data.len() {
        return Err(format!(
            "`{label}` is an EFI zboot image, but its header points at a payload of \
             {size} bytes at offset {offset:#x} and the file is only {} bytes. \
             The download is probably truncated.",
            data.len()
        ));
    }
    Ok(Some(&data[offset..end]))
}

/// The compression type the zboot header declares.
///
/// Only ever used to make an error message specific; the codec actually used is
/// chosen from the payload's magic bytes.
fn zboot_declared_compression(data: &[u8]) -> String {
    let field = &data[ZBOOT_COMPRESSION_OFFSET..ZBOOT_COMPRESSION_OFFSET + ZBOOT_COMPRESSION_LEN];
    let text = field.split(|b| *b == 0).next().unwrap_or(&[]);
    match str::from_utf8(text) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => "unnamed compression".to_string(),
    }
}

/// Which codec these bytes start with, if it is one we recognise at all.
///
/// The unsupported ones are recognised deliberately: a kernel compressed with
/// xz should be told it is xz, not told it is unidentifiable.
fn codec_of(data: &[u8]) -> Option<&'static str> {
    let starts = |m: &[u8]| data.len() >= m.len() && &data[..m.len()] == m;
    if starts(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if starts(&[0x04, 0x22, 0x4d, 0x18]) {
        Some("lz4")
    } else if starts(&[0x89, b'L', b'Z', b'O']) {
        Some("lzo")
    } else if starts(&[0x5d, 0x00, 0x00]) {
        Some("lzma")
    } else {
        None
    }
}

/// Decompress a payload with whichever codec its own bytes identify.
fn inflate(payload: &[u8], label: &str, declared: &str) -> Result<Vec<u8>, String> {
    let codec = codec_of(payload).ok_or_else(|| {
        format!(
            "`{label}` declares `{declared}` compression, and its payload does not begin with \
             any compressed-stream magic this build recognises."
        )
    })?;

    let mut out = Vec::new();
    match codec {
        "gzip" => GzDecoder::new(payload)
            .read_to_end(&mut out)
            .map(|_| ())
            .map_err(|e| format!("`{label}`: the gzip payload did not decompress: {e}")),
        "zstd" => copy_decode(payload, &mut out)
            .map_err(|e| format!("`{label}`: the zstd payload did not decompress: {e}")),
        other => Err(format!(
            "`{label}` is compressed with {other}, which this build cannot decompress. \
             Decompress it yourself and pass the resulting `Image`."
        )),
    }?;
    Ok(out)
}

/// A decompressed payload has to actually be an arm64 kernel.
///
/// Without this a wrapper around an x86 kernel would unpack cleanly and be
/// accepted, and the failure would move to a guest that produces no console
/// output — the exact failure the original magic check exists to prevent, just
/// one layer further in.
fn verify_arm64(out: &[u8], label: &str, what: &str) -> Result<(), String> {
    if has_arm64_magic(out) {
        return Ok(());
    }
    Err(format!(
        "`{label}` unpacked, but {what} is not an arm64 Image — no `ARM\\x64` at offset {ARM64_MAGIC_OFFSET:#x}. \
         A kernel for another architecture will not boot on this Mac."
    ))
}

/// Name what the file actually is, having ruled out every form we accept.
///
/// The point of this function is that it never says "an x86 bzImage or a
/// vmlinux ELF" about a file that is neither.
fn unrecognised(data: &[u8], label: &str) -> String {
    let what = if data.starts_with(b"\x7fELF") {
        "an ELF object — probably a `vmlinux`, which is the unstripped kernel and not a bootable Image"
    } else if data.len() > 0x206 && &data[0x202..0x206] == b"HdrS" {
        "an x86 bzImage, which will not boot on this Mac"
    } else if data.starts_with(b"MZ") {
        "a PE/COFF binary that is not an EFI zboot image (no `zimg` marker)"
    } else if data.starts_with(b"!<arch>\n") {
        "an ar archive — a `.deb` package rather than the kernel inside it"
    } else {
        "not a kernel image in any form this build recognises"
    };
    format!(
        "`{label}` is {what}.\nExpected an arm64 `Image` (`ARM\\x64` at {ARM64_MAGIC_OFFSET:#x}), \
         an EFI zboot image, or a gzip/zstd-compressed Image."
    )
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes in range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A minimal but structurally real arm64 Image.
    fn arm64_image(len: usize) -> Vec<u8> {
        let mut v = vec![0_u8; len.max(64)];
        v[ARM64_MAGIC_OFFSET..ARM64_MAGIC_OFFSET + 4].copy_from_slice(&ARM64_MAGIC);
        v
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Wrap a payload the way `zboot.c` does.
    fn zboot(payload: &[u8], declared: &str) -> Vec<u8> {
        let offset = 0x100_usize;
        let mut v = vec![0_u8; offset];
        v[..2].copy_from_slice(b"MZ");
        v[ZBOOT_ZIMG_OFFSET..ZBOOT_ZIMG_OFFSET + 4].copy_from_slice(b"zimg");
        v[ZBOOT_PAYLOAD_OFFSET..ZBOOT_PAYLOAD_OFFSET + 4]
            .copy_from_slice(&(offset as u32).to_le_bytes());
        v[ZBOOT_PAYLOAD_SIZE..ZBOOT_PAYLOAD_SIZE + 4]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        v[ZBOOT_COMPRESSION_OFFSET..ZBOOT_COMPRESSION_OFFSET + declared.len()]
            .copy_from_slice(declared.as_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn an_uncompressed_image_is_passed_through_without_copying() {
        let img = arm64_image(4096);
        let (out, form) = decode(&img, "Image").unwrap();
        assert_eq!(form, KernelForm::Raw);
        assert!(matches!(out, Cow::Borrowed(_)), "a raw Image was copied");
        assert_eq!(out.len(), img.len());
    }

    #[test]
    fn a_zboot_image_is_unwrapped_to_the_kernel_inside_it() {
        let inner = arm64_image(9000);
        let file = zboot(&gzip(&inner), "gzip");
        // The bug this closes: the wrapper itself has no arm64 magic.
        assert!(!has_arm64_magic(&file));

        let (out, form) = decode(&file, "vmlinuz-virt").unwrap();
        assert_eq!(
            form,
            KernelForm::Zboot {
                declared: "gzip".into()
            }
        );
        assert_eq!(
            &out[..],
            &inner[..],
            "the unwrapped bytes are not the kernel"
        );
        assert!(form.was_compressed());
    }

    #[test]
    fn a_plainly_gzipped_image_is_accepted_too() {
        let inner = arm64_image(4096);
        let gz = gzip(&inner);
        let (out, form) = decode(&gz, "Image.gz").unwrap();
        assert_eq!(form, KernelForm::Compressed { codec: "gzip" });
        assert_eq!(&out[..], &inner[..]);
    }

    /// The codec comes from the payload, not from what the header claims.
    ///
    /// A producer's label is a claim about bytes that are right in front of us.
    /// Trusting it here would make a mislabelled image fail as "corrupt".
    #[test]
    fn the_declared_compression_does_not_choose_the_codec() {
        let inner = arm64_image(4096);
        let file = zboot(&gzip(&inner), "lz4");
        let (out, form) = decode(&file, "vmlinuz").unwrap();
        assert_eq!(&out[..], &inner[..]);
        assert_eq!(
            form,
            KernelForm::Zboot {
                declared: "lz4".into()
            }
        );
    }

    /// Unpacking must not be mistaken for validating.
    #[test]
    fn a_wrapper_around_a_foreign_kernel_is_still_refused() {
        let mut foreign = vec![0_u8; 4096];
        foreign[0x202..0x206].copy_from_slice(b"HdrS");
        let e = decode(&zboot(&gzip(&foreign), "gzip"), "vmlinuz").unwrap_err();
        assert!(e.contains("not an arm64 Image"), "{e}");
        assert!(e.contains("zboot payload"), "{e}");
    }

    #[test]
    fn a_truncated_zboot_download_is_named_as_such() {
        let mut file = zboot(&gzip(&arm64_image(9000)), "gzip");
        // Relative to the real length: a fixed cut-off looks like a truncation
        // and is not one, because a mostly-zero image gzips to a few dozen
        // bytes and the whole payload survives.
        file.truncate(file.len() - 1);
        let e = decode(&file, "vmlinuz").unwrap_err();
        assert!(e.contains("truncated"), "{e}");
    }

    /// The whole point of the issue: stop naming formats the file is not.
    #[test]
    fn a_refusal_names_what_the_file_actually_is() {
        let mut elf = vec![0_u8; 4096];
        elf[..4].copy_from_slice(b"\x7fELF");
        let e = decode(&elf, "vmlinux").unwrap_err();
        assert!(e.contains("ELF"), "{e}");
        assert!(
            !e.contains("bzImage"),
            "an ELF was described as a bzImage: {e}"
        );

        let mut bz = vec![0_u8; 4096];
        bz[0x202..0x206].copy_from_slice(b"HdrS");
        let e = decode(&bz, "bzImage").unwrap_err();
        assert!(e.contains("x86 bzImage"), "{e}");
        assert!(!e.contains("ELF"), "a bzImage was described as an ELF: {e}");

        let mut deb = vec![0_u8; 4096];
        deb[..8].copy_from_slice(b"!<arch>\n");
        let e = decode(&deb, "linux-image.deb").unwrap_err();
        assert!(e.contains(".deb"), "{e}");
    }

    /// A codec we cannot handle is named, not called unidentifiable.
    #[test]
    fn an_unsupported_codec_is_named() {
        let mut xz = vec![0_u8; 4096];
        xz[..6].copy_from_slice(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]);
        let e = decode(&xz, "vmlinuz").unwrap_err();
        assert!(e.contains("xz"), "{e}");
    }

    #[test]
    fn a_pe_binary_without_the_zimg_marker_is_not_called_zboot() {
        let mut pe = vec![0_u8; 4096];
        pe[..2].copy_from_slice(b"MZ");
        let e = decode(&pe, "something.efi").unwrap_err();
        assert!(e.contains("zimg"), "{e}");
    }
}
