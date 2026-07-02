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

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitCode, Stdio};
use std::thread;

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
    cache_dir: Option<&Path>,
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
        // Persist the raw ciphertext chunk so this node can serve it to LAN
        // peers as a peer cache (opaque without the tenant key — see `serve`).
        if let Some(cache) = cache_dir {
            write_cached_chunk(cache, memory_ref, &page.store_key, &raw)?;
        }
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

/// Decode a percent-encoded query value (inverse of [`url_encode`]).
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Map a `ref` + `store_key` to a cache file path. Sanitized so a content
/// address (`sha256:…`) is a safe single filename segment.
fn cache_path(cache: &Path, memory_ref: &str, key: &str) -> PathBuf {
    cache.join(sanitize(memory_ref)).join(sanitize(key))
}

/// Reduce a ref/key to a filesystem-safe segment (keep alnum/`-`/`.`, else `_`).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

/// Write a raw (still-encrypted) chunk into the peer cache.
fn write_cached_chunk(cache: &Path, memory_ref: &str, key: &str, bytes: &[u8]) -> Result<(), String> {
    let path = cache_path(cache, memory_ref, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create cache dir {}: {e}", parent.display()))?;
    }
    fs::write(&path, bytes).map_err(|e| format!("cache chunk {}: {e}", path.display()))
}

// --- Peer cache: serve cached chunks to LAN peers -------------------------
//
// A puller in the same locality is routed here by the plane's
// `GET /state-cdn/source`. We serve only the **ciphertext** chunks we hold — a
// peer without the tenant key (delivered separately by a legit resume) cannot
// read them, so peer serving is an optimization, never an authorization bypass.

/// Parse a `k1=v1&k2=v2` query string into decoded pairs.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

/// Route one peer-cache HTTP request to `(status, content_type, body)`. Pure
/// (only reads the cache), so it is unit-tested without a socket.
fn route_peer_request(method: &str, target: &str, cache: &Path) -> (u16, &'static str, Vec<u8>) {
    if method != "GET" {
        return (405, "text/plain", b"method not allowed\n".to_vec());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/healthz" => (200, "text/plain", b"ok\n".to_vec()),
        "/state-cdn/chunk" => {
            let params = parse_query(query);
            let get = |k: &str| params.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.as_str());
            let (Some(memory_ref), Some(key)) = (get("ref"), get("key")) else {
                return (400, "text/plain", b"missing ref or key\n".to_vec());
            };
            match fs::read(cache_path(cache, memory_ref, key)) {
                Ok(bytes) => (200, "application/octet-stream", bytes),
                Err(_) => (404, "text/plain", b"chunk not in this peer cache\n".to_vec()),
            }
        }
        _ => (404, "text/plain", b"not found\n".to_vec()),
    }
}

/// Read one request off `stream`, route it, and write the response.
fn handle_peer_conn(stream: &mut TcpStream, cache: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Drain the remaining request headers (a GET carries no body).
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (code, ctype, body) = route_peer_request(method, target, cache);
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Run the peer-cache HTTP server on `addr`, serving chunks from `cache`.
fn serve_peer_cache(cache: &Path, addr: &str) -> Result<(), String> {
    let listener =
        TcpListener::bind(addr).map_err(|e| format!("bind peer cache on {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_or_else(|_| addr.to_string(), |a| a.to_string());
    eprintln!(
        "chm state-cdn serve: peer cache on http://{bound} serving chunks from {}",
        cache.display()
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let cache = cache.to_path_buf();
        thread::spawn(move || {
            let _ = handle_peer_conn(&mut stream, &cache);
        });
    }
    Ok(())
}

/// POST a JSON body to `url` via curl, returning the response bytes.
fn curl_post_json(url: &str, body: &str) -> Result<Vec<u8>, String> {
    let out = Command::new("curl")
        .args(["-fsS", "--max-time", "60", "-X", "POST"])
        .args(["-H", "content-type: application/json"])
        .args(["--data-binary", body])
        .arg(url)
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "POST {url} failed (curl exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// `chm state-cdn <subcommand>` — the offload-daemon consumer CLI.
pub fn state_cdn_main(raw: &[String]) -> ExitCode {
    let run = |r: Result<(), String>, ctx: &str| match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm state-cdn {ctx}: {e}");
            ExitCode::FAILURE
        }
    };
    match raw.first().map(String::as_str) {
        Some("reconstruct") => run(cmd_reconstruct(&raw[1..]), "reconstruct"),
        Some("serve") => run(cmd_serve(&raw[1..]), "serve"),
        Some("register-peer") => run(cmd_register_peer(&raw[1..]), "register-peer"),
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
    "chm state-cdn — consume + peer-serve the control plane's memory plane (Phase 2)\n\
     \n\
     USAGE:\n    \
         chm state-cdn reconstruct --endpoint URL --ref REF --token TOK \\\n                                 \
         --out FILE [--tenant-key-b64 KEY] [--cache DIR]\n    \
         chm state-cdn serve --cache DIR [--addr HOST:PORT]\n    \
         chm state-cdn register-peer --api URL --endpoint URL --locality LOC \\\n                                    \
         [--ref REF]... [--owner WHO]\n\
     \n\
     reconstruct  fetch a ref's page map, pull + decrypt each non-zero page, and\n                 \
         reassemble the flat memory-ranges image at FILE. --cache also keeps the\n                 \
         raw ciphertext chunks so this node can peer-serve them.\n    \
     serve        run a peer-cache HTTP server over --cache: GET /state-cdn/chunk\n                 \
         returns a held (opaque ciphertext) chunk, else 404.\n    \
     register-peer  advertise this node as a peer cache to the plane, so LAN\n                 \
         pullers in --locality are routed here for the refs it holds.\n\
     \n\
     endpoint/ref/token/tenant-key come from a postcopy resume assignment. This is\n    \
     CDN-backed resume by reconstruction; it does not yet demand-fault only the\n    \
     touched working set (see docs/state-cdn-memory-plane.md).\n"
        .to_string()
}

fn cmd_reconstruct(raw: &[String]) -> Result<(), String> {
    let mut endpoint = None;
    let mut memory_ref = None;
    let mut token = None;
    let mut out = None;
    let mut tenant_key_b64: Option<String> = None;
    let mut cache: Option<String> = None;
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
            "--cache" => cache = Some(take(&mut i, "--cache")?),
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

    let cache_path = cache.as_ref().map(PathBuf::from);
    let stats = reconstruct(
        &endpoint,
        &memory_ref,
        &token,
        tenant_key.as_ref(),
        Path::new(&out),
        cache_path.as_deref(),
    )?;
    println!(
        "reconstructed {} bytes to {out}\n  \
         pages    {} ({} fetched, {} zero-elided)\n  \
         decrypt  {} page(s) AES-256-GCM{}",
        stats.total_bytes,
        stats.pages,
        stats.fetched_pages,
        stats.zero_pages,
        stats.decrypted_pages,
        cache.map(|c| format!("\n  cache    {} chunk(s) kept in {c}", stats.fetched_pages)).unwrap_or_default()
    );
    Ok(())
}

fn cmd_serve(raw: &[String]) -> Result<(), String> {
    let mut cache = None;
    let mut addr = "127.0.0.1:9700".to_string();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--cache" => {
                i += 1;
                cache = Some(raw.get(i).cloned().ok_or("--cache needs a value")?);
            }
            "--addr" => {
                i += 1;
                addr = raw.get(i).cloned().ok_or("--addr needs a value")?;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let cache = cache.ok_or("--cache DIR is required")?;
    serve_peer_cache(Path::new(&cache), &addr)
}

fn cmd_register_peer(raw: &[String]) -> Result<(), String> {
    let mut api = None;
    let mut endpoint = None;
    let mut locality = None;
    let mut owner = None;
    let mut refs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let take = |i: &mut usize, flag: &str| -> Result<String, String> {
            *i += 1;
            raw.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
        };
        match raw[i].as_str() {
            "--api" => api = Some(take(&mut i, "--api")?),
            "--endpoint" => endpoint = Some(take(&mut i, "--endpoint")?),
            "--locality" => locality = Some(take(&mut i, "--locality")?),
            "--owner" => owner = Some(take(&mut i, "--owner")?),
            "--ref" => refs.push(take(&mut i, "--ref")?),
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let api = api
        .or_else(|| env::var("GCTL_API").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let endpoint = endpoint.ok_or("--endpoint URL is required")?;
    let locality = locality.ok_or("--locality is required")?;

    let mut body = serde_json::json!({
        "endpoint": endpoint,
        "locality": locality,
        "refs": refs,
        "requested_by": "chm-state-cdn",
    });
    if let Some(o) = owner {
        body["owner"] = serde_json::json!(o);
    }
    let url = format!("{}/peer-caches", api.trim_end_matches('/'));
    let resp = curl_post_json(&url, &serde_json::to_string(&body).unwrap())?;
    let parsed: serde_json::Value = serde_json::from_slice(&resp).unwrap_or(serde_json::Value::Null);
    let peer_id = parsed
        .pointer("/peer_cache/peer_id")
        .or_else(|| parsed.get("peer_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(registered)");
    println!(
        "registered peer cache {peer_id} at {endpoint} (locality {locality}, {} ref(s))",
        refs.len()
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

    #[test]
    fn url_decode_inverts_encode() {
        for s in ["sha256:abc+/=", "plain", "a b&c=d"] {
            assert_eq!(url_decode(&url_encode(s)), s);
        }
    }

    #[test]
    fn cache_path_sanitizes_content_addresses() {
        let p = cache_path(Path::new("/cache"), "sha256:aa/bb", "sha256:cc");
        assert_eq!(p, Path::new("/cache/sha256_aa_bb/sha256_cc"));
    }

    #[test]
    fn peer_cache_serves_held_chunks_and_404s_misses() {
        let cache = env::temp_dir().join(format!("chm-peer-{}", process::id()));
        let _ = fs::remove_dir_all(&cache);
        let memory_ref = "sha256:deadbeef";
        let key = "sha256:cafe";
        write_cached_chunk(&cache, memory_ref, key, b"ciphertext-bytes").unwrap();

        // A held chunk is served verbatim (opaque ciphertext).
        let target = format!(
            "/state-cdn/chunk?ref={}&key={}",
            url_encode(memory_ref),
            url_encode(key)
        );
        let (code, ctype, body) = route_peer_request("GET", &target, &cache);
        assert_eq!(code, 200);
        assert_eq!(ctype, "application/octet-stream");
        assert_eq!(body, b"ciphertext-bytes");

        // A miss is 404 (the puller falls back to origin), a POST is 405, and a
        // missing param is 400 — never a 500.
        let miss = format!("/state-cdn/chunk?ref={}&key=sha256:absent", url_encode(memory_ref));
        assert_eq!(route_peer_request("GET", &miss, &cache).0, 404);
        assert_eq!(route_peer_request("POST", &target, &cache).0, 405);
        assert_eq!(route_peer_request("GET", "/state-cdn/chunk?ref=x", &cache).0, 400);
        assert_eq!(route_peer_request("GET", "/healthz", &cache).0, 200);

        let _ = fs::remove_dir_all(&cache);
    }
}
