// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! State-CDN memory-plane consumer (M27 Phase 2).
//!
//! The control plane stores a checkpoint's guest RAM in a **content-addressed,
//! per-tenant-encrypted, deduped chunk store** — "a CDN for live compute state."
//! This module is the Mac's *consumer* of that plane: it fetches a memory ref's
//! page map, pulls each non-zero page's chunk, decrypts it (AES-256-GCM under the
//! tenant key delivered in the resume assignment), and reassembles the flat
//! `memory-ranges` image `chm resume` restores from. Zero pages carry no chunk
//! and are left as the file's natural zero fill.
//!
//! **Scope / honesty (see `docs/state-cdn-memory-plane.md`).** This is
//! *CDN-backed resume by reconstruction*: it materializes the working set from
//! the CDN before the guest runs. It does **not** yet demand-fault only the
//! *touched* pages while the guest runs — true postcopy needs HVF stage-2 fault
//! interception (macOS has no `userfaultfd`), which is a tracked follow-up. So
//! the runner advertises `supports_offload_daemon` (it can consume the CDN) but
//! not `supports_postcopy` (it does not demand-fault).

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::Deserialize;

/// One page of the memory ref, as returned by `GET /state-cdn/memory-ref`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StatePage {
    pub offset: u64,
    pub length: usize,
    #[serde(default)]
    pub store_key: String,
    #[serde(default)]
    pub encrypted: bool,
    /// Hex-encoded 12-byte AES-GCM nonce (present for an encrypted page).
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub zero: bool,
}

#[derive(Debug, Deserialize)]
struct MemoryRefRecord {
    #[serde(default)]
    total_size: u64,
}

#[derive(Debug, Deserialize)]
struct MemoryRefMap {
    #[serde(default)]
    ref_: Option<MemoryRefRecord>,
    pages: Vec<StatePage>,
}

/// What a reconstruction moved: total bytes, and how many pages were fetched vs
/// filled as zero (proof of the CDN's zero-page elision + dedup).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReconstructStats {
    pub total_bytes: u64,
    pub pages: usize,
    pub fetched_pages: usize,
    pub zero_pages: usize,
    pub decrypted_pages: usize,
}

/// Reconstruct a memory ref's flat RAM image from the state CDN into `out`.
///
/// `endpoint` is the `state_cdn_endpoint`, `token` the resume capability token,
/// and `tenant_key` the 32-byte AES-256 key (from `daemon.tenant_key_b64`) for
/// encrypted refs. Returns the movement stats.
pub(crate) fn reconstruct(
    endpoint: &str,
    memory_ref: &str,
    token: &str,
    tenant_key: Option<&[u8; 32]>,
    out: &Path,
) -> Result<ReconstructStats, String> {
    let map = fetch_page_map(endpoint, memory_ref, token)?;
    // Prefer the record's declared size; fall back to the page map's extent so a
    // trailing zero page still sizes the image correctly.
    let extent = map
        .pages
        .iter()
        .map(|p| p.offset + p.length as u64)
        .max()
        .unwrap_or(0);
    let total = map.ref_.as_ref().map_or(0, |r| r.total_size).max(extent);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)
        .map_err(|e| format!("create {}: {e}", out.display()))?;
    if total > 0 {
        file.set_len(total)
            .map_err(|e| format!("size {}: {e}", out.display()))?;
    }

    let mut stats = ReconstructStats {
        total_bytes: total,
        pages: map.pages.len(),
        ..Default::default()
    };
    for page in &map.pages {
        if page.zero || page.store_key.is_empty() {
            // Zero-page elision: nothing stored; the file is already zero-filled.
            stats.zero_pages += 1;
            continue;
        }
        let raw = fetch_chunk(endpoint, memory_ref, &page.store_key, token)?;
        let plain = if page.encrypted {
            let key = tenant_key.ok_or_else(|| {
                "page is encrypted but no tenant key was provided (daemon.tenant_key_b64)"
                    .to_string()
            })?;
            stats.decrypted_pages += 1;
            decrypt_page(&raw, key, &page.nonce)?
        } else {
            raw
        };
        if plain.len() != page.length {
            return Err(format!(
                "page at offset {} decrypted to {} bytes, expected {}",
                page.offset,
                plain.len(),
                page.length
            ));
        }
        file.write_all_at(&plain, page.offset)
            .map_err(|e| format!("write page at {}: {e}", page.offset))?;
        stats.fetched_pages += 1;
    }
    Ok(stats)
}

/// Decrypt one AES-256-GCM page: `raw` is ciphertext‖tag, `nonce_hex` the
/// hex-encoded 12-byte nonce from the page map, `key` the 32-byte tenant key.
pub(crate) fn decrypt_page(
    raw: &[u8],
    key: &[u8; 32],
    nonce_hex: &str,
) -> Result<Vec<u8>, String> {
    let nonce_bytes = hex_decode(nonce_hex)?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("nonce must be 12 bytes, got {}", nonce_bytes.len()))?;
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| "invalid AES-256 key".to_string())?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = raw.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "AES-256-GCM authentication failed (wrong key/nonce/ciphertext)".to_string())?;
    Ok(plain.to_vec())
}

/// Fetch + parse a ref's page map (`GET /state-cdn/memory-ref`).
fn fetch_page_map(endpoint: &str, memory_ref: &str, token: &str) -> Result<MemoryRefMap, String> {
    let url = format!(
        "{}/state-cdn/memory-ref?ref={}&token={}",
        endpoint.trim_end_matches('/'),
        url_encode(memory_ref),
        url_encode(token)
    );
    let out = curl_get(&url)?;
    // `MemoryRefMapResponse` names the record field `ref`; alias it to `ref_`.
    let mut value: serde_json::Value =
        serde_json::from_slice(&out).map_err(|e| format!("parse memory-ref map: {e}"))?;
    if let Some(obj) = value.as_object_mut()
        && let Some(r) = obj.remove("ref")
    {
        obj.insert("ref_".to_string(), r);
    }
    serde_json::from_value(value).map_err(|e| format!("decode memory-ref map: {e}"))
}

/// Fetch one raw chunk (`GET /state-cdn/chunk`), returning its bytes.
fn fetch_chunk(endpoint: &str, memory_ref: &str, key: &str, token: &str) -> Result<Vec<u8>, String> {
    let url = format!(
        "{}/state-cdn/chunk?ref={}&key={}&token={}",
        endpoint.trim_end_matches('/'),
        url_encode(memory_ref),
        url_encode(key),
        url_encode(token)
    );
    curl_get(&url)
}

/// GET `url` with curl, returning the raw body bytes (fails on 4xx/5xx via `-f`).
fn curl_get(url: &str) -> Result<Vec<u8>, String> {
    let out = Command::new("curl")
        .args(["-fsS", "--max-time", "1200"])
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "state-cdn fetch failed (curl exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Decode a base64 (standard alphabet, `=`-padded) string — the tenant key is
/// delivered as `daemon.tenant_key_b64`. Kept dependency-free.
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 character {:?}", c as char)),
        }
    }
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for quad in s.chunks(4) {
        let pad = quad.iter().filter(|&&b| b == b'=').count();
        let mut acc = 0u32;
        for &c in quad {
            acc = (acc << 6) | if c == b'=' { 0 } else { val(c)? };
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

/// Decode a lowercase/uppercase hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

/// Minimal percent-encoding for the query-parameter values we pass (`:`, `+`,
/// `/`, `=`, `&`, space). The ref/key/token are otherwise URL-safe.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `chm state-cdn <subcommand>` — the offload-daemon consumer CLI.
pub fn state_cdn_main(raw: &[String]) -> ExitCode {
    match raw.first().map(String::as_str) {
        Some("reconstruct") => match cmd_reconstruct(&raw[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm state-cdn reconstruct: {e}");
                ExitCode::FAILURE
            }
        },
        Some("-h") | Some("--help") | None => {
            print!("{}", state_cdn_usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("chm state-cdn: unknown subcommand `{other}`\n\n{}", state_cdn_usage());
            ExitCode::FAILURE
        }
    }
}

fn state_cdn_usage() -> String {
    "chm state-cdn — consume the control plane's memory plane (Phase 2)\n\
     \n\
     USAGE:\n    \
         chm state-cdn reconstruct --endpoint URL --ref REF --token TOK \\\n                                 \
         --out FILE [--tenant-key-b64 KEY]\n\
     \n\
     Fetches a memory ref's page map, pulls + decrypts each non-zero page from\n    \
     the state CDN, and reassembles the flat memory-ranges image at FILE. The\n    \
     endpoint/ref/token/tenant-key come from a postcopy resume assignment's CDN\n    \
     fields. This is CDN-backed resume by reconstruction; it does not yet\n    \
     demand-fault only the touched working set (see docs/state-cdn-memory-plane.md).\n"
        .to_string()
}

fn cmd_reconstruct(raw: &[String]) -> Result<(), String> {
    let mut endpoint = None;
    let mut memory_ref = None;
    let mut token = None;
    let mut out = None;
    let mut tenant_key_b64: Option<String> = None;
    let mut i = 0;
    while i < raw.len() {
        let take = |i: &mut usize, flag: &str| -> Result<String, String> {
            *i += 1;
            raw.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
        };
        match raw[i].as_str() {
            "--endpoint" => endpoint = Some(take(&mut i, "--endpoint")?),
            "--ref" => memory_ref = Some(take(&mut i, "--ref")?),
            "--token" => token = Some(take(&mut i, "--token")?),
            "--out" => out = Some(take(&mut i, "--out")?),
            "--tenant-key-b64" => tenant_key_b64 = Some(take(&mut i, "--tenant-key-b64")?),
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let endpoint = endpoint.ok_or("--endpoint is required")?;
    let memory_ref = memory_ref.ok_or("--ref is required")?;
    let token = token.ok_or("--token is required")?;
    let out = out.ok_or("--out is required")?;

    let tenant_key = match tenant_key_b64 {
        Some(b64) => {
            let bytes = base64_decode(&b64)?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("tenant key must be 32 bytes, got {}", bytes.len()))?;
            Some(arr)
        }
        None => None,
    };

    let stats = reconstruct(
        &endpoint,
        &memory_ref,
        &token,
        tenant_key.as_ref(),
        Path::new(&out),
    )?;
    println!(
        "reconstructed {} bytes to {out}\n  \
         pages    {} ({} fetched, {} zero-elided)\n  \
         decrypt  {} page(s) AES-256-GCM",
        stats.total_bytes, stats.pages, stats.fetched_pages, stats.zero_pages, stats.decrypted_pages
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    #[test]
    fn base64_decode_roundtrips_known_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // A 32-byte key round-trips to exactly 32 bytes.
        let key = base64_decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn hex_decode_parses_a_nonce() {
        assert_eq!(hex_decode("000102030405060708090a0b").unwrap().len(), 12);
        hex_decode("0g").unwrap_err();
        hex_decode("abc").unwrap_err();
    }

    #[test]
    fn decrypt_page_recovers_plaintext_sealed_the_plane_way() {
        // Seal a page exactly as the plane does (AES-256-GCM, 12-byte nonce,
        // ciphertext‖tag) and prove our consumer decrypts it byte-for-byte.
        let key = [7u8; 32];
        let nonce_bytes = [1u8; 12];
        let plaintext = b"a guest RAM page's worth of bytes".to_vec();

        let unbound = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let sealing = LessSafeKey::new(unbound);
        let mut sealed = plaintext.clone();
        sealing
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut sealed,
            )
            .unwrap();

        let nonce_hex = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let recovered = decrypt_page(&sealed, &key, &nonce_hex).unwrap();
        assert_eq!(recovered, plaintext);

        // A wrong key fails authentication (not silently mis-decrypts).
        decrypt_page(&sealed, &[9u8; 32], &nonce_hex).unwrap_err();
    }

    #[test]
    fn url_encode_escapes_ref_and_token_specials() {
        assert_eq!(url_encode("sha256:abc+/="), "sha256%3Aabc%2B%2F%3D");
        assert_eq!(url_encode("plain-ref_1.0~"), "plain-ref_1.0~");
    }
}
