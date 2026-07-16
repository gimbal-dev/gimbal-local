// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `chm runner` — drive local runs THROUGH the gctl control plane.
//!
//! This makes the Mac a real **runner**: instead of sourcing a snapshot out of
//! band and doing a one-off `chm run`, it registers with the control plane,
//! is *assigned* a runnable snapshot, pulls + verifies the bundle, runs it on
//! HVF, and reports state back. The control plane stays the source of truth for
//! leases, cost, cleanup, provenance, the `gic_mode` gate, and audit; `chm`
//! never overrides the gate and never decides on its own that a snapshot is
//! runnable (see `docs/runner-contract.md` in gimbal-cloud-control).
//!
//! Transport is plain HTTP via `curl` (matching this crate's existing shell-out
//! pattern in `cloud.rs`, and avoiding a heavyweight async HTTP dependency for
//! what is a local control plane). Responses are parsed with `serde_json`. The
//! non-network logic — download-URI resolution, `chm_command` substitution,
//! checksum verification, and error classification — is factored into pure
//! functions with unit tests.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, thread};

use serde_json::{Value, json};

use crate::audit;
use crate::policy;
use crate::signing::{DetachedSignature, TrustStore};

/// Default control-plane base URL (overridable via `GCTL_API`).
const DEFAULT_API: &str = "http://127.0.0.1:8080";

/// Heartbeat cadence. The plane flips a runner `offline` after 90s without a
/// heartbeat, so stay comfortably inside that window.
const HEARTBEAT_SECS: u64 = 30;

/// A thin control-plane HTTP client backed by `curl`.
pub(crate) struct ControlPlane {
    api: String,
}

/// The outcome of one HTTP call: the status code plus the parsed JSON body
/// (`Value::Null` when the body was empty or not JSON).
struct HttpResponse {
    status: u16,
    body: Value,
}

impl ControlPlane {
    fn new(api: &str) -> Self {
        let api = api.trim_end_matches('/').to_string();
        Self { api }
    }

    fn from_env_or(api: Option<String>) -> Self {
        let api = api
            .or_else(|| env::var("GCTL_API").ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_API.to_string());
        Self::new(&api)
    }

    /// Perform an HTTP request, sending `body` as JSON when present. Returns the
    /// status code and parsed body. Shape errors (curl missing, network down)
    /// surface as `Err`; HTTP error *statuses* (4xx/5xx) are returned as `Ok`
    /// so callers can branch on them (e.g. 422 → recapture guidance).
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<HttpResponse, String> {
        let url = format!("{}{}", self.api, path);
        // `-w` appends a marker line carrying the status so we can split it off
        // the body without a temp file.
        let mut cmd = Command::new("curl");
        cmd.arg("-sS")
            .args(["-X", method])
            .args(["-H", "content-type: application/json"])
            .args(["--max-time", "120"])
            .arg("-w")
            .arg("\n__CHM_HTTP_STATUS__:%{http_code}")
            .arg(&url);
        if body.is_some() {
            cmd.args(["--data-binary", "@-"]);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
        if let Some(body) = body {
            let payload = serde_json::to_vec(body).map_err(|e| format!("encode body: {e}"))?;
            child
                .stdin
                .take()
                .ok_or("curl stdin unavailable")?
                .write_all(&payload)
                .map_err(|e| format!("write curl body: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("run curl: {e}"))?;
        if !out.status.success() && out.stdout.is_empty() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("curl {method} {url} failed: {}", err.trim()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        parse_http_response(&stdout)
    }

    fn register(&self, req: &Value) -> Result<Value, String> {
        let resp = self.request("POST", "/runners", Some(req))?;
        ok_or_http_err(resp, "register runner")
    }

    fn heartbeat(&self, runner_id: &str, status: &str) -> Result<(), String> {
        let path = format!("/runners/{runner_id}/heartbeat");
        let _ = self.request("POST", &path, Some(&json!({ "status": status })))?;
        Ok(())
    }

    fn create_sandbox(&self, owner: &str, name: &str) -> Result<String, String> {
        let resp = self.request(
            "POST",
            "/sandboxes",
            Some(&json!({ "owner": owner, "name": name })),
        )?;
        let body = ok_or_http_err(resp, "create sandbox")?;
        body.get("sandbox_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "create sandbox: response had no sandbox_id".to_string())
    }

    fn assign_run(&self, runner_id: &str, req: &Value) -> Result<Value, String> {
        let path = format!("/runners/{runner_id}/assign-run");
        let resp = self.request("POST", &path, Some(req))?;
        // The gic_mode gate: a snapshot that exists but is not runnable
        // (its-lpi / unknown) is refused with 422. Surface the recapture
        // guidance and never retry as-is or self-declare it runnable.
        if resp.status == 422 {
            return Err(format!(
                "control plane refused this snapshot as not runnable (HTTP 422): {}.\n\
                 This is the gic_mode gate — recapture the snapshot with CH_GIC_V2M=1 \
                 (gicv2m-message-spi). chm must not override the gate.",
                http_error_message(&resp.body)
            ));
        }
        ok_or_http_err(resp, "assign-run")
    }

    fn mark_local_copy(&self, snapshot_id: &str, req: &Value) -> Result<(), String> {
        let path = format!("/snapshots/{snapshot_id}/mark-local-copy");
        let resp = self.request("POST", &path, Some(req))?;
        ok_or_http_err(resp, "mark-local-copy").map(|_| ())
    }

    fn report_state(&self, sandbox_id: &str, state: &str) -> Result<(), String> {
        let path = format!("/sandboxes/{sandbox_id}/report-state");
        let resp = self.request(
            "POST",
            &path,
            Some(&json!({ "state": state, "requested_by": "chm-runner" })),
        )?;
        ok_or_http_err(resp, "report-state").map(|_| ())
    }

    /// Report a policy enforcement/consumption decision to the plane's audit
    /// trail (M28). Best-effort: an audit hiccup must never fail the run, so a
    /// transport/HTTP error is logged and swallowed.
    fn report_policy_decision(&self, sandbox_id: &str, req: &Value) {
        let path = format!("/sandboxes/{sandbox_id}/report-policy-decision");
        match self.request("POST", &path, Some(req)) {
            Ok(resp) if resp.status < 300 => {}
            Ok(resp) => eprintln!(
                "chm runner: note: report-policy-decision HTTP {} ({})",
                resp.status,
                http_error_message(&resp.body)
            ),
            Err(e) => eprintln!("chm runner: note: report-policy-decision failed: {e}"),
        }
    }

    fn push_artifacts(&self, sandbox_id: &str, req: &Value) -> Result<(), String> {
        let path = format!("/sandboxes/{sandbox_id}/push-artifacts");
        let resp = self.request("POST", &path, Some(req))?;
        ok_or_http_err(resp, "push-artifacts").map(|_| ())
    }

    /// Commit a local checkpoint as a new content-addressed revision on `branch`
    /// (Phase 4). The plane ingests `bundle_dir` into its CAS, dedups against
    /// existing chunks, and advances the branch head. Returns the
    /// `CommitRevisionResponse` (branch, revision, dedup stats).
    fn commit_revision(&self, req: &Value) -> Result<Value, String> {
        let resp = self.request("POST", "/revisions/commit", Some(req))?;
        ok_or_http_err(resp, "revisions/commit")
    }

    /// List branches (their heads + review status). Used to resolve a branch
    /// *name* to its id for the id-addressed pull endpoint.
    fn list_branches(&self) -> Result<Value, String> {
        let resp = self.request("GET", "/branches", None)?;
        ok_or_http_err(resp, "branches")
    }

    /// Merge the `from` branch's head into the target branch (review-gated:
    /// merging an unapproved source into a review-required target is refused).
    fn merge_branch(&self, target_id: &str, req: &Value) -> Result<Value, String> {
        let path = format!("/branches/{target_id}/merge");
        let resp = self.request("POST", &path, Some(req))?;
        if resp.status == 400 {
            return Err(format!(
                "merge refused (HTTP 400): {}. A review-required target only accepts \
                 an approved source — set the source `approved` first with \
                 `chm branches review`.",
                http_error_message(&resp.body)
            ));
        }
        ok_or_http_err(resp, "branches/merge")
    }

    /// Set a branch's review status (`pending` / `approved` / `rejected`).
    fn review_branch(&self, branch_id: &str, req: &Value) -> Result<Value, String> {
        let path = format!("/branches/{branch_id}/review");
        let resp = self.request("POST", &path, Some(req))?;
        ok_or_http_err(resp, "branches/review")
    }

    /// Fetch a sandbox's effective policy compiled for a substrate
    /// (`GET /sandboxes/{id}/policy?substrate=`). Used by `chm policy show`.
    fn effective_policy(&self, sandbox_id: &str, substrate: &str) -> Result<Value, String> {
        let path = format!("/sandboxes/{sandbox_id}/policy?substrate={substrate}");
        let resp = self.request("GET", &path, None)?;
        ok_or_http_err(resp, "effective-policy")
    }

    /// Pull a branch head (or an explicit revision) back to a resume assignment
    /// (Phase 4). The response's `assignment` is a standard `AssignRunResponse`,
    /// so the bundle materializes through the same path a normal resume uses.
    fn pull_branch(&self, branch_id: &str, req: &Value) -> Result<Value, String> {
        let path = format!("/branches/{branch_id}/pull");
        let resp = self.request("POST", &path, Some(req))?;
        if resp.status == 422 {
            return Err(format!(
                "control plane refused this revision as not runnable (HTTP 422): {}.\n\
                 The gic_mode gate is preserved end-to-end — an its-lpi lineage is \
                 refused exactly as on a normal resume.",
                http_error_message(&resp.body)
            ));
        }
        ok_or_http_err(resp, "branches/pull")
    }
}

/// Split curl's `body\n__CHM_HTTP_STATUS__:<code>` output into a parsed body and
/// status code.
fn parse_http_response(raw: &str) -> Result<HttpResponse, String> {
    let marker = "__CHM_HTTP_STATUS__:";
    let idx = raw
        .rfind(marker)
        .ok_or_else(|| "curl output missing status marker".to_string())?;
    let status: u16 = raw[idx + marker.len()..]
        .trim()
        .parse()
        .map_err(|e| format!("parse http status: {e}"))?;
    let body_str = raw[..idx].trim_end_matches('\n');
    let body = if body_str.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body_str).unwrap_or(Value::Null)
    };
    Ok(HttpResponse { status, body })
}

/// Return the body on a 2xx status, else a formatted error carrying the status
/// and any `{"error": …}` message.
fn ok_or_http_err(resp: HttpResponse, ctx: &str) -> Result<Value, String> {
    if (200..300).contains(&resp.status) {
        Ok(resp.body)
    } else {
        Err(format!(
            "{ctx}: HTTP {} — {}",
            resp.status,
            http_error_message(&resp.body)
        ))
    }
}

/// Extract a human message from an error body (`{"error": "..."}`), falling back
/// to the compact JSON.
fn http_error_message(body: &Value) -> String {
    body.get("error").and_then(Value::as_str).map_or_else(
        || {
            if body.is_null() {
                "(no body)".to_string()
            } else {
                body.to_string()
            }
        },
        str::to_string,
    )
}

/// Resolve a `file://` `download_uri` to a local directory path. On this Mac the
/// object store is local, so the URI is a `file://` path we read directly.
/// Networked (`http(s)://`) stores are handled separately by `http_download`.
fn download_uri_to_path(uri: &str) -> Result<PathBuf, String> {
    if let Some(rest) = uri.strip_prefix("file://") {
        // file:///abs/path → /abs/path (three slashes ⇒ empty host).
        Ok(PathBuf::from(rest))
    } else {
        Err(format!("download_uri {uri} is not a local file:// locator"))
    }
}

/// Turn the plane's `chm_command` (e.g. `chm run <SNAPSHOT_DIR> --idle-exit 0`)
/// into the argument vector to pass to `chm`, substituting the local snapshot
/// directory for the `<SNAPSHOT_DIR>` placeholder and dropping the leading
/// `chm`. The command is authoritative; we only fill the placeholder.
fn chm_command_args(chm_command: &str, snapshot_dir: &Path) -> Result<Vec<String>, String> {
    let dir = snapshot_dir.to_string_lossy().into_owned();
    let mut tokens = chm_command.split_whitespace();
    match tokens.next() {
        Some("chm") => {}
        Some(other) => {
            return Err(format!(
                "chm_command should start with `chm`, got `{other}`"
            ));
        }
        None => return Err("chm_command is empty".to_string()),
    }
    let args: Vec<String> = tokens
        .map(|t| {
            if t == "<SNAPSHOT_DIR>" {
                dir.clone()
            } else {
                t.to_string()
            }
        })
        .collect();
    if args.is_empty() {
        return Err("chm_command has no subcommand after `chm`".to_string());
    }
    Ok(args)
}

/// Materialize a snapshot bundle into `cache` from the assignment's
/// `download_uri`, verifying every file against `checksum_tree`. Files are stored
/// **content-addressed** in a shared CAS (keyed by sha256, a sibling of the
/// per-snapshot cache dirs) and hard-linked into the cache, so a base layer
/// shared across snapshots — e.g. a checkpoint and its parent's multi-GiB disk —
/// is fetched and stored **once**. Returns the count served from the cache
/// (deduped) rather than fetched.
///
/// `download_uri` may be a local `file://` object store (a copy) or a networked
/// `http(s)://` one (streamed via curl). Each object is fetched from
/// `<download_uri>/<relpath>` and verified before it enters the CAS. Both the
/// object relpath and its checksum are untrusted (the manifest is unsigned until
/// M30.4): the relpath is confined under the cache root, the checksum is required
/// to be a canonical sha256 hex digest before it is used as a CAS path, and even
/// a CAS hit is re-hashed before it is linked in, so a tampered manifest can
/// neither escape the cache nor select an unverified/host file.
fn materialize_bundle(
    download_uri: &str,
    checksum_tree: &BTreeMap<String, String>,
    cache: &Path,
    token: Option<&str>,
) -> Result<usize, String> {
    if checksum_tree.is_empty() {
        return Err("manifest.checksum_tree is empty; refusing to trust the bundle".to_string());
    }
    let cas = cas_dir_for(cache);
    fs::create_dir_all(&cas).map_err(|e| format!("create CAS {}: {e}", cas.display()))?;
    let mut deduped = 0usize;
    for (rel, want) in checksum_tree {
        // The manifest is not yet signed (M30.4), so its relpaths are untrusted:
        // confine every one under the cache root before writing, or a crafted
        // key like `../../../etc/...` would escape the bundle on ingest (M30.1).
        let dest = confined_join(cache, rel)?;
        let want = want.to_lowercase();
        // The checksum VALUE is equally untrusted, and we use it as a CAS path
        // component (`cas.join(want)`). A value like "/etc/passwd" or
        // "../../secret" would make `blob` point at a host file that a dedup hit
        // then links into the guest-visible cache (M30.8). Accept only a real
        // fixed-length sha256 hex digest, which is a single safe path segment.
        if !is_sha256_hex(&want) {
            return Err(format!(
                "refusing bundle object {rel:?}: checksum {want:?} is not a \
                 64-char hex sha256 (possible tampered manifest)"
            ));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let blob = cas.join(&want);
        if blob.is_file() {
            // Dedup hit: re-hash the cached blob before trusting it. The CAS is a
            // shared, on-disk store; a blob could have been corrupted or poisoned
            // out of band since it was ingested, so verifying it here (not just at
            // first fetch) keeps a hit from linking unverified bytes into a guest
            // (M30.8). A mismatch drops the bad blob and falls through to a fresh
            // fetch + verify.
            let got = sha256_file(&blob)?;
            if got.eq_ignore_ascii_case(&want) {
                link_or_copy(&blob, &dest)?;
                deduped += 1;
                continue;
            }
            let _ = fs::remove_file(&blob);
        }
        // Miss (or an evicted poisoned hit): fetch the object, verify it, then
        // promote it into the CAS.
        fetch_object(download_uri, rel, &dest, token)?;
        let got = sha256_file(&dest)?;
        if !got.eq_ignore_ascii_case(&want) {
            let _ = fs::remove_file(&dest);
            return Err(format!("checksum mismatch for {rel}: expected {want}, got {got}"));
        }
        let _ = fs::hard_link(&dest, &blob).or_else(|_| fs::copy(&dest, &blob).map(|_| ()));
    }
    Ok(deduped)
}

/// Whether `s` is a canonical lowercase sha256 hex digest: exactly 64 chars,
/// each `0-9` or `a-f`. Used to gate the untrusted manifest checksum before it
/// is ever used as a content-addressed store path component, so a crafted value
/// cannot traverse out of the CAS to select a host file (M30.8).
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The content-addressed store (sha256 → blob) for a given snapshot cache: a
/// `.cas` sibling of the per-snapshot cache dirs, so it is shared across pulls.
fn cas_dir_for(cache: &Path) -> PathBuf {
    cache.parent().unwrap_or(cache).join(".cas")
}

/// Join an untrusted bundle-relative path onto `root`, refusing to let it escape.
///
/// Bundle manifests are not yet signed (M30.4), so a `checksum_tree` key is
/// attacker-influenced input. Reject absolute paths, Windows prefixes, root/
/// current-dir components, and any `..` (parent) component, so a crafted key
/// (`../../../etc/cron.d/x`) cannot make `chm` write outside the cache on ingest
/// (M30.1, invariant I2). Only plain relative path segments are allowed.
fn confined_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let relp = Path::new(rel);
    let mut out = root.to_path_buf();
    let mut any = false;
    for comp in relp.components() {
        match comp {
            Component::Normal(seg) => {
                out.push(seg);
                any = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "refusing bundle path {rel:?}: it escapes the bundle root (possible tampered manifest)"
                ));
            }
        }
    }
    if !any {
        return Err(format!("refusing empty bundle path {rel:?}"));
    }
    Ok(out)
}

/// Fetch one bundle object (`<download_uri>/<relpath>`) into `dest`. Supports a
/// local `file://` object store (a copy) and a networked `http(s)://` store
/// (streamed via curl, with an optional bearer token).
fn fetch_object(
    download_uri: &str,
    relpath: &str,
    dest: &Path,
    token: Option<&str>,
) -> Result<(), String> {
    if download_uri.starts_with("file://") {
        let src = download_uri_to_path(download_uri)?.join(relpath);
        fs::copy(&src, dest)
            .map(|_| ())
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dest.display()))
    } else if download_uri.starts_with("http://") || download_uri.starts_with("https://") {
        http_download(&object_url(download_uri, relpath), dest, token)
    } else {
        Err(format!(
            "unsupported download_uri scheme: {download_uri} (expected file:// or http(s)://)"
        ))
    }
}

/// Join a bundle base URL and a bundle-relative path into an object URL.
fn object_url(base: &str, relpath: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), relpath.trim_start_matches('/'))
}

/// Stream an object over HTTP(S) into `dest` via curl (`-f` fails on 4xx/5xx;
/// `-o` streams straight to disk so a multi-GiB image is never buffered in RAM).
fn http_download(url: &str, dest: &Path, token: Option<&str>) -> Result<(), String> {
    let mut cmd = Command::new("curl");
    cmd.args(["-fsS", "--max-time", "1200"]);
    if let Some(tok) = token {
        cmd.arg("-H").arg(format!("authorization: Bearer {tok}"));
    }
    cmd.arg("-o").arg(dest).arg(url);
    let status = cmd.status().map_err(|e| format!("spawn curl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        let _ = fs::remove_file(dest);
        Err(format!(
            "curl failed (exit {}) fetching {url}",
            status.code().unwrap_or(-1)
        ))
    }
}

/// Link `src` into `dest`, falling back to a copy across filesystems.
fn link_or_copy(src: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        let _ = fs::remove_file(dest);
    }
    fs::hard_link(src, dest)
        .or_else(|_| fs::copy(src, dest).map(|_| ()))
        .map_err(|e| format!("link {} -> {}: {e}", src.display(), dest.display()))
}

/// sha256 a file via `shasum -a 256` (always present on macOS), returning the
/// lowercase hex digest.
fn sha256_file(path: &Path) -> Result<String, String> {
    let out = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|e| format!("run shasum on {}: {e}", path.display()))?;
    if !out.status.success() {
        return Err(format!(
            "shasum {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_shasum_output(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("could not parse shasum output for {}", path.display()))
}

/// Parse `<hex>  <path>` (shasum format) into the digest.
fn parse_shasum_output(out: &str) -> Option<String> {
    out.split_whitespace().next().map(|s| s.to_lowercase())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The capabilities this chm build honestly supports today.
fn capabilities() -> Value {
    json!({
        "chm_version": env!("CARGO_PKG_VERSION"),
        // Message-SPI delivery on HVF — the baseline cold-boot path.
        "supports_gic_v2m": true,
        // `chm resume <DIR>` rehydrates a live checkpoint (Phase 1).
        "supports_resume": true,
        // The execution substrate this runner restores on. The plane routes
        // only `apple-hvf`-restorable checkpoints (message-SPI) to us.
        "substrate": "apple-hvf",
        // `chm fork` branches a revision; block devices run on copy-on-write
        // overlays over a shared read-only base.
        "supports_fork": true,
        "supports_cow_overlay": true,
        // `chm push` commits a local checkpoint as a content-addressed revision
        // and `chm pull` rehydrates a branch head back to a resume (Phase 4).
        "supports_commit": true,
        // `chm state-cdn reconstruct` consumes the state-CDN memory plane: it
        // pulls a checkpoint's encrypted, content-addressed RAM chunks and
        // reassembles the image before resume (Phase 2, CDN-backed resume).
        // NOTE: not `supports_postcopy` — chm reconstructs the working set
        // eagerly and does not yet demand-fault only touched pages (that needs
        // HVF stage-2 fault interception; see docs/state-cdn-memory-plane.md).
        "supports_offload_daemon": true,
        // `chm state-cdn serve` serves held (ciphertext) chunks to LAN peers.
        "supports_peer_cache": true,
        // chm consumes the plane's per-sandbox policy: it parses the compiled
        // `enforcement.chm_profile`, verifies the `policy_digest` teleported
        // intact, and surfaces it (M28.1). Egress enforcement lands with the
        // userspace NAT (M28.2/M28.3).
        "supports_policy": true,
    })
}

/// Options for `chm runner run`.
struct RunOpts {
    snapshot_id: String,
    api: Option<String>,
    owner: String,
    /// Resume/continue an existing plane sandbox (e.g. the one a cloud runner
    /// suspended) instead of creating a fresh one. This is what makes the hero
    /// loop *the same session* rather than a copy.
    sandbox: Option<String>,
    /// Exercise the protocol through mark-local-copy but do NOT execute the
    /// workload (useful for the synthetic fixture / CI, which cannot restore a
    /// real VM). The sandbox is left `assigned` — honest, since nothing ran.
    skip_run: bool,
}

pub fn runner_main(raw: &[String]) -> ExitCode {
    match raw.first().map(String::as_str) {
        Some("register") => match cmd_register(&raw[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm runner register: {e}");
                ExitCode::FAILURE
            }
        },
        Some("run") => match parse_run_opts(&raw[1..]) {
            Ok(opts) => match cmd_run(&opts) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("chm runner run: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("chm runner run: {e}\n\n{}", runner_usage());
                ExitCode::FAILURE
            }
        },
        Some("-h") | Some("--help") | None => {
            print!("{}", runner_usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("chm runner: unknown subcommand `{other}`\n\n{}", runner_usage());
            ExitCode::FAILURE
        }
    }
}

fn runner_usage() -> String {
    "chm runner — drive local runs through the gctl control plane\n\
     \n\
     USAGE:\n    \
         chm runner register [--api URL] [--owner WHO]\n    \
         chm runner run <SNAPSHOT_ID> [--api URL] [--owner WHO] [--sandbox ID] [--skip-run]\n\
     \n\
     The control plane base URL comes from --api, else $GCTL_API, else \
     http://127.0.0.1:8080.\n    \
         --sandbox ID resume/continue an existing plane sandbox (the hero loop —\n                 \
         same session) instead of creating a fresh one.\n    \
         --skip-run   exercise the protocol through mark-local-copy without\n                 \
         executing the workload (for the synthetic fixture / CI).\n"
        .to_string()
}

fn cmd_register(raw: &[String]) -> Result<(), String> {
    let mut api = None;
    let mut owner = default_owner();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--api" => {
                i += 1;
                api = Some(raw.get(i).ok_or("--api needs a value")?.clone());
            }
            "--owner" => {
                i += 1;
                owner = raw.get(i).ok_or("--owner needs a value")?.clone();
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let cp = ControlPlane::from_env_or(api);
    let runner_id = do_register(&cp, &owner)?;
    println!("{runner_id}");
    Ok(())
}

fn parse_run_opts(raw: &[String]) -> Result<RunOpts, String> {
    let mut snapshot_id = None;
    let mut api = None;
    let mut owner = default_owner();
    let mut sandbox = None;
    let mut skip_run = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--api" => {
                i += 1;
                api = Some(raw.get(i).ok_or("--api needs a value")?.clone());
            }
            "--owner" => {
                i += 1;
                owner = raw.get(i).ok_or("--owner needs a value")?.clone();
            }
            "--sandbox" => {
                i += 1;
                sandbox = Some(raw.get(i).ok_or("--sandbox needs a value")?.clone());
            }
            "--skip-run" => skip_run = true,
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            other => {
                if snapshot_id.is_some() {
                    return Err(format!("unexpected extra argument `{other}`"));
                }
                snapshot_id = Some(other.to_string());
            }
        }
        i += 1;
    }
    Ok(RunOpts {
        snapshot_id: snapshot_id.ok_or("missing <SNAPSHOT_ID>")?,
        api,
        owner,
        sandbox,
        skip_run,
    })
}

fn default_owner() -> String {
    env::var("USER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "chm-runner".to_string())
}

fn do_register(cp: &ControlPlane, owner: &str) -> Result<String, String> {
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mac.local".to_string());
    let req = json!({
        "owner": owner,
        "hostname": hostname,
        "platform": "darwin",
        "arch": "arm64",
        "gimbal_local_version": format!("chm-{}", env!("CARGO_PKG_VERSION")),
        "capabilities": capabilities(),
    });
    let runner = cp.register(&req)?;
    runner
        .get("runner_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "register: response had no runner_id".to_string())
}

/// Start a background thread that heartbeats until the returned flag is set.
fn spawn_heartbeat(cp_api: String, runner_id: String) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    thread::spawn(move || {
        let cp = ControlPlane::new(&cp_api);
        while !stop_thread.load(Ordering::Acquire) {
            // Sleep in short slices so a stop is observed promptly.
            for _ in 0..(HEARTBEAT_SECS * 10) {
                if stop_thread.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = cp.heartbeat(&runner_id, "online");
        }
    });
    stop
}

fn cmd_run(opts: &RunOpts) -> Result<(), String> {
    let cp = ControlPlane::from_env_or(opts.api.clone());
    eprintln!("chm runner: control plane {}", cp.api);

    // 1. Register + start heartbeating (so a long run doesn't flip us offline).
    let runner_id = do_register(&cp, &opts.owner)?;
    eprintln!("chm runner: registered as {runner_id}");
    let hb_stop = spawn_heartbeat(cp.api.clone(), runner_id.clone());

    // Ensure the heartbeat thread is stopped on every exit path.
    let result = run_assignment(&cp, &runner_id, opts);
    hb_stop.store(true, Ordering::Release);
    result
}

fn run_assignment(cp: &ControlPlane, runner_id: &str, opts: &RunOpts) -> Result<(), String> {
    // 2. Resume an existing plane sandbox (the hero loop — same session) or
    //    create a fresh one so state reporting has something to drive.
    let sandbox_id = match &opts.sandbox {
        Some(id) => {
            eprintln!("chm runner: continuing existing sandbox {id}");
            id.clone()
        }
        None => {
            let name = format!("chm-run-{}-{}", opts.snapshot_id, now_secs());
            let id = cp.create_sandbox(&opts.owner, &name)?;
            eprintln!("chm runner: sandbox {id}");
            id
        }
    };

    // 3. Ask for work. 422 ⇒ the gic_mode gate refused it (surfaced verbatim).
    let assign = cp.assign_run(
        runner_id,
        &json!({
            "snapshot_id": opts.snapshot_id,
            "sandbox_id": sandbox_id,
            "requested_by": "chm-runner",
        }),
    )?;

    let download_uri = assign
        .get("download_uri")
        .and_then(Value::as_str)
        .ok_or("assign-run: no download_uri")?;
    let chm_command = assign
        .get("chm_command")
        .and_then(Value::as_str)
        .ok_or("assign-run: no chm_command")?;
    let kind = assign.get("kind").and_then(Value::as_str).unwrap_or("cold");
    let (checksum_tree, provenance) = trusted_checksum_tree(&assign)?;
    eprintln!(
        "chm runner: assigned {} (kind={kind}, {} file(s) to verify, manifest {provenance})",
        opts.snapshot_id,
        checksum_tree.len()
    );

    // Sandbox policy (Pillar ③, M28.1): if the plane bound a policy, parse the
    // compiled profile and verify the `policy_digest` teleported intact. A
    // present-but-unverifiable policy is fatal (we must not run a governed
    // sandbox ungoverned); an unbound sandbox is unaffected. Egress is not yet
    // enforced on the datapath — that is M28.2/M28.3.
    match policy::parse_and_verify(&assign) {
        Ok(Some(governed)) => {
            eprintln!("chm runner: {}", governed.summary());
            // Hand the egress profile down to the `chm run` subprocess (which
            // actually boots the VM) so its userspace NAT enforces the
            // allow-list at the DNS resolve + host connect (M28.3). The digest
            // was just verified, so the child can trust this value.
            let egress = &governed.profile.egress;
            let egress_json = json!({
                "digest": governed.digest,
                "default": egress.default,
                "allow": egress.allow,
                "deny": egress.deny,
            });
            // SAFETY: single-threaded runner setup; the value is consumed by the
            // child `chm run` we spawn later in this function.
            unsafe {
                env::set_var("CHM_EGRESS_POLICY", egress_json.to_string());
            }
            cp.report_policy_decision(
                &sandbox_id,
                &json!({
                    "substrate": "apple-hvf",
                    "domain": "policy",
                    "action": "received",
                    "target": governed.digest,
                    "detail": format!(
                        "chm_profile parsed; digest teleport {}",
                        if governed.digest_recomputed { "verified" } else { "reference-checked" }
                    ),
                    "requested_by": "chm-runner",
                }),
            );

            // Filesystem policy (M28.5). chm has no host-filesystem passthrough
            // (a deliberate security invariant — see docs/security-model.md), so
            // a requested host mount cannot be honored. Refuse it loudly and
            // report the decision rather than silently running the sandbox in an
            // unexpected configuration. The guest runs confined, without the
            // host directory — the safe direction (no host exposure). The fs
            // ro/rw scopes describe guest-internal paths chm cannot police from
            // outside, so they are surfaced (in the summary) but not enforced.
            for (source, target, mode, durable) in governed.requested_mounts() {
                eprintln!(
                    "chm runner: WARNING: policy requests host mount {source} -> \
                     {target} ({mode}{}) — REFUSED: chm has no host-filesystem \
                     passthrough; the sandbox runs without it",
                    if durable { ", durable" } else { "" }
                );
                cp.report_policy_decision(
                    &sandbox_id,
                    &json!({
                        "substrate": "apple-hvf",
                        "domain": "fs",
                        "action": "mount-refused",
                        "target": format!("{source}:{target}"),
                        "detail": format!(
                            "no host-FS passthrough on apple-hvf; mount not honored \
                             (mode={mode}, durable={durable})"
                        ),
                        "requested_by": "chm-runner",
                    }),
                );
            }
        }
        Ok(None) => {}
        Err(e) => {
            cp.report_state(&sandbox_id, "error").ok();
            return Err(format!("policy verification failed: {e}"));
        }
    }

    // Resume-side provenance + gic gate. A cloud-origin checkpoint carries
    // `manifest.origin_substrate` (where it ran) and `manifest.gic_mode`. HVF can
    // only restore message-based-SPI (GICv2M) checkpoints, so re-verify the gate
    // locally as defense in depth — the plane already gated on ingest, but we
    // never restore a checkpoint the Mac cannot deliver interrupts for.
    let manifest = assign.get("manifest").cloned().unwrap_or(Value::Null);
    let gic_mode = manifest
        .get("gic_mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let origin_substrate = manifest.get("origin_substrate").and_then(Value::as_str);
    if kind == "resume" {
        if let Some(os) = origin_substrate {
            eprintln!(
                "chm runner: cross-substrate resume — checkpoint ran on `{os}`, \
                 resuming on `apple-hvf` (ran-in-cloud → resumed-local)"
            );
        }
        if !gic_mode.is_empty() && !hvf_restorable(gic_mode) {
            cp.report_state(&sandbox_id, "error").ok();
            return Err(format!(
                "checkpoint gic_mode `{gic_mode}` is not HVF-restorable — only \
                 `gicv2m-message-spi` resumes on apple-hvf; this checkpoint stays \
                 cloud-only (recapture with CH_GIC_V2M=1 to make it Mac-restorable)"
            ));
        }
    }

    // 4. Materialize + verify the bundle into a local runner cache. Content-
    //    addressed: base layers shared across snapshots (e.g. a big base disk)
    //    are fetched + stored once. `download_uri` may be file:// or http(s)://.
    let cache = runner_cache_dir(&opts.snapshot_id);
    let _ = fs::remove_dir_all(&cache);
    let token = assign.get("capability_token").and_then(Value::as_str);
    let deduped = materialize_bundle(download_uri, &checksum_tree, &cache, token)?;
    if deduped > 0 {
        eprintln!(
            "chm runner: materialized + verified {} file(s) ({deduped} shared from cache) at {}",
            checksum_tree.len(),
            cache.display()
        );
    } else {
        eprintln!(
            "chm runner: materialized + verified {} file(s) at {}",
            checksum_tree.len(),
            cache.display()
        );
    }

    // Audit the trust decisions (M29) to the same per-workspace trail the child
    // `chm run` will append its session lifecycle to: reaching this point means
    // the manifest provenance was accepted and every bundle object re-hashed to
    // its checksum.
    let ingest_audit = audit::AuditLog::open(&cache);
    ingest_audit.verify("manifest", true, &provenance);
    ingest_audit.verify(
        "bundle-checksums",
        true,
        &format!("{} object(s) verified", checksum_tree.len()),
    );

    // Prove continuity: read the mid-flight marker the cloud session embedded
    // (a `gimbal-marker.json` sidecar, or the `GIMBLMK1` frame at the head of
    // `snapshot/memory-ranges`). It carries the state the cloud run reached, so a
    // successful resume demonstrably continues *past* this point.
    if let Some(marker) = read_flight_marker(&cache) {
        let when = marker
            .written_at
            .map(|w| format!(" (written {w})"))
            .unwrap_or_default();
        eprintln!(
            "chm runner: mid-flight marker from the cloud session: {:?}{when} — \
             a resume continues the session beyond this point",
            marker.value
        );
    }

    // 5. Confirm the verified local copy to the plane.
    cp.mark_local_copy(
        &opts.snapshot_id,
        &json!({ "runner_id": runner_id, "local_uri": format!("file://{}", cache.display()), "verified": true }),
    )?;
    eprintln!("chm runner: marked verified local copy");

    if opts.skip_run {
        eprintln!(
            "chm runner: --skip-run — protocol exercised through mark-local-copy; \
             leaving sandbox `assigned` (nothing was executed)."
        );
        return Ok(());
    }

    // Pre-flight: only a real cloud-hypervisor snapshot can boot on HVF. A
    // protocol fixture pulls + verifies but has no `snapshots` state, so fail it
    // here with an honest, actionable message rather than exec'ing `chm` and
    // surfacing a cryptic parser error.
    if let Err(reason) = snapshot_is_bootable(&cache) {
        cp.report_state(&sandbox_id, "error").ok();
        return Err(reason);
    }

    // 6. Run the workload and report state honestly.
    let args = chm_command_args(chm_command, &cache)?;
    if kind == "resume" && args.first().map(String::as_str) != Some("resume") {
        eprintln!("chm runner: note: kind=resume but chm_command is `{chm_command}`");
    }
    if kind == "resume" {
        // A resume drives the sandbox through `resuming` before it is live.
        cp.report_state(&sandbox_id, "resuming")?;
    }
    cp.report_state(&sandbox_id, "running-local")?;
    eprintln!("chm runner: running-local — exec chm {}", args.join(" "));

    let exec = run_chm(&args);
    // A clean exit that left a checkpoint behind is a *suspend*, not a plain
    // stop: report `suspended` and push the checkpoint (the plane opens a
    // resumable child). Otherwise it stopped or errored.
    let suspended = matches!(&exec, Ok(0)) && checkpoint_present(&cache);
    let (final_state, artifact_kind, note) = if suspended {
        ("suspended", "checkpoint", "suspended — checkpoint saved".to_string())
    } else {
        match &exec {
            Ok(code) if *code == 0 => ("stopped", "run-output", "workload exited 0".to_string()),
            Ok(code) => ("error", "run-output", format!("workload exited {code}")),
            Err(e) => ("error", "run-output", format!("failed to launch workload: {e}")),
        }
    };
    cp.report_state(&sandbox_id, final_state)?;
    eprintln!("chm runner: reported {final_state} ({note})");

    // 7. Push artifacts (idempotent). A saved checkpoint is pushed as a
    //    `checkpoint` artifact so the plane can resume from it later.
    cp.push_artifacts(
        &sandbox_id,
        &json!({
            "runner_id": runner_id,
            "local_path": cache.display().to_string(),
            "kind": artifact_kind,
            "requested_by": "chm-runner",
            "idempotency_key": format!("{sandbox_id}-{artifact_kind}"),
        }),
    )?;
    eprintln!("chm runner: pushed artifacts (kind={artifact_kind})");

    if final_state == "error" {
        return Err(format!("workload did not complete cleanly: {note}"));
    }
    Ok(())
}

/// Execute `chm <args>` by re-invoking this signed binary (so it carries the
/// hypervisor entitlement), streaming its console straight through.
fn run_chm(args: &[String]) -> Result<i32, String> {
    let exe = env::current_exe().map_err(|e| format!("resolve current exe: {e}"))?;
    let status = Command::new(exe)
        .args(args)
        .status()
        .map_err(|e| format!("spawn chm: {e}"))?;
    Ok(status.code().unwrap_or(-1))
}

// ---------------------------------------------------------------------------
// Phase 4 — commit / push / pull ("git for live compute")
//
// `chm push` commits a local checkpoint as a content-addressed revision on a
// branch (the plane dedups it into its CAS and advances the branch head);
// `chm pull` resolves a branch head back to a resume assignment and materializes
// it, so a session committed on one machine rehydrates on any other.
// ---------------------------------------------------------------------------

/// Options for `chm push`.
struct PushOpts {
    checkpoint: PathBuf,
    branch: String,
    api: Option<String>,
    owner: String,
    message: Option<String>,
    sandbox: Option<String>,
    parent: Option<String>,
}

/// Options for `chm pull`.
struct PullOpts {
    branch: String,
    to: PathBuf,
    api: Option<String>,
    owner: String,
    revision: Option<String>,
    locality: Option<String>,
    resume: bool,
}

pub fn push_main(raw: &[String]) -> ExitCode {
    if matches!(raw.first().map(String::as_str), Some("-h") | Some("--help")) {
        print!("{}", push_usage());
        return ExitCode::SUCCESS;
    }
    match parse_push_opts(raw).and_then(|o| cmd_push(&o)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm push: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `chm policy show --sandbox ID [--substrate S] [--json]` — fetch a sandbox's
/// effective policy from the plane, verify the digest, and print the governed
/// summary. The read-only operator view of Pillar ③ governance (M28.1).
pub fn policy_main(raw: &[String]) -> ExitCode {
    match raw.first().map(String::as_str) {
        Some("show") => match cmd_policy_show(&raw[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm policy show: {e}");
                ExitCode::FAILURE
            }
        },
        Some("-h") | Some("--help") | None => {
            print!(
                "chm policy — inspect the control plane's per-sandbox governance\n\
                 \n\
                 USAGE:\n    \
                     chm policy show --sandbox ID [--substrate apple-hvf] [--json] [--api URL]\n\
                 \n\
                 Fetches the sandbox's effective policy, verifies the policy_digest,\n    \
                 and prints the compiled egress/fs posture chm would enforce.\n"
            );
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("chm policy: unknown subcommand `{other}`");
            ExitCode::FAILURE
        }
    }
}

fn cmd_policy_show(raw: &[String]) -> Result<(), String> {
    let mut api = None;
    let mut sandbox = None;
    let mut substrate = "apple-hvf".to_string();
    let mut as_json = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--api" => api = Some(take_value(raw, &mut i, "--api")?),
            "--sandbox" => sandbox = Some(take_value(raw, &mut i, "--sandbox")?),
            "--substrate" => substrate = take_value(raw, &mut i, "--substrate")?,
            "--json" => as_json = true,
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let sandbox = sandbox.ok_or("--sandbox ID is required")?;
    let cp = ControlPlane::from_env_or(api);
    let effective = cp.effective_policy(&sandbox, &substrate)?;

    let restricted = effective.get("restricted").and_then(Value::as_bool).unwrap_or(false);
    if !restricted {
        if as_json {
            println!("{}", json!({ "sandbox_id": sandbox, "restricted": false }));
        } else {
            println!("sandbox {sandbox} is unrestricted (no policy bound)");
        }
        return Ok(());
    }
    // The effective-policy response carries the same fields an assignment does
    // (policy, policy_digest, enforcement), so reuse the teleport verifier.
    match policy::parse_and_verify(&effective)? {
        Some(governed) => {
            if as_json {
                println!(
                    "{}",
                    json!({
                        "sandbox_id": sandbox,
                        "restricted": true,
                        "policy_digest": governed.digest,
                        "digest_verified": governed.digest_recomputed,
                        "egress_rule_count": governed.egress_rule_count,
                        "enforcement": effective.get("enforcement").cloned().unwrap_or(Value::Null),
                    })
                );
            } else {
                println!("sandbox {sandbox}: {}", governed.summary());
            }
        }
        None => println!("sandbox {sandbox} reports restricted but carries no enforcement block"),
    }
    Ok(())
}

pub fn branches_main(raw: &[String]) -> ExitCode {
    // `chm branches [merge|review] …`; with no subcommand it lists.
    match raw.first().map(String::as_str) {
        Some("merge") => {
            return match cmd_branch_merge(&raw[1..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("chm branches merge: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Some("review") => {
            return match cmd_branch_review(&raw[1..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("chm branches review: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }
    let mut api = None;
    let mut owner: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "-h" | "--help" => {
                print!(
                    "chm branches — list + drive revision branches on the control plane\n\
                     \n\
                     USAGE:\n    \
                         chm branches [--json] [--owner WHO] [--api URL]\n    \
                         chm branches review --branch NAME --status STATUS [--owner WHO]\n    \
                         chm branches merge --target NAME --from NAME [--owner WHO]\n\
                     \n\
                     STATUS is pending | approved | rejected. A merge into a review-\n    \
                     required target needs the source approved first.\n"
                );
                return ExitCode::SUCCESS;
            }
            "--json" => as_json = true,
            "--owner" => match take_value(raw, &mut i, "--owner") {
                Ok(v) => owner = Some(v),
                Err(e) => {
                    eprintln!("chm branches: {e}");
                    return ExitCode::FAILURE;
                }
            },
            "--api" => match take_value(raw, &mut i, "--api") {
                Ok(v) => api = Some(v),
                Err(e) => {
                    eprintln!("chm branches: {e}");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("chm branches: unknown argument `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    match cmd_branches(api, owner.as_deref(), as_json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm branches: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_branch_review(raw: &[String]) -> Result<(), String> {
    let mut api = None;
    let mut branch = None;
    let mut status = None;
    let mut owner = default_owner();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--api" => api = Some(take_value(raw, &mut i, "--api")?),
            "--branch" => branch = Some(take_value(raw, &mut i, "--branch")?),
            "--status" => status = Some(take_value(raw, &mut i, "--status")?),
            "--owner" => owner = take_value(raw, &mut i, "--owner")?,
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let branch = branch.ok_or("--branch NAME is required")?;
    let status = status.ok_or("--status STATUS is required (pending|approved|rejected)")?;
    if !matches!(status.as_str(), "pending" | "approved" | "rejected") {
        return Err(format!("invalid --status `{status}` (pending|approved|rejected)"));
    }
    let cp = ControlPlane::from_env_or(api);
    let branch_id = resolve_branch_id(&cp, &owner, &branch)?;
    cp.review_branch(
        &branch_id,
        &json!({ "status": status, "requested_by": "chm-branches" }),
    )?;
    println!("branch `{branch}` review status set to `{status}`");
    Ok(())
}

fn cmd_branch_merge(raw: &[String]) -> Result<(), String> {
    let mut api = None;
    let mut target = None;
    let mut from = None;
    let mut owner = default_owner();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--api" => api = Some(take_value(raw, &mut i, "--api")?),
            "--target" => target = Some(take_value(raw, &mut i, "--target")?),
            "--from" | "--source" => from = Some(take_value(raw, &mut i, "--from")?),
            "--owner" => owner = take_value(raw, &mut i, "--owner")?,
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    let target = target.ok_or("--target NAME is required")?;
    let from = from.ok_or("--from NAME is required")?;
    let cp = ControlPlane::from_env_or(api);
    let target_id = resolve_branch_id(&cp, &owner, &target)?;
    let resp = cp.merge_branch(
        &target_id,
        &json!({ "owner": owner, "from": from, "requested_by": "chm-branches" }),
    )?;
    let ff = resp.get("fast_forward").and_then(Value::as_bool).unwrap_or(false);
    let new_head = resp
        .get("new_head_snapshot_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    println!(
        "merged `{from}` into `{target}` ({}) — new head {new_head}",
        if ff { "fast-forward" } else { "adopted source head" }
    );
    Ok(())
}

fn cmd_branches(api: Option<String>, owner: Option<&str>, as_json: bool) -> Result<(), String> {
    let cp = ControlPlane::from_env_or(api);
    let body = cp.list_branches()?;
    let mut branches = body
        .get("branches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(owner) = owner {
        branches.retain(|b| b.get("owner").and_then(Value::as_str) == Some(owner));
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "branches": branches }))
                .map_err(|e| format!("encode json: {e}"))?
        );
    } else {
        print!("{}", format_branches_table(&branches));
    }
    Ok(())
}

/// Render a branch list as an aligned table: name, review status, head revision,
/// ACL count, owner. Pure for testability.
fn format_branches_table(branches: &[Value]) -> String {
    if branches.is_empty() {
        return "(no branches)\n".to_string();
    }
    let mut out = String::from("BRANCH                REVIEW     HEAD                 ACLS  OWNER\n");
    for b in branches {
        let name = b.get("name").and_then(Value::as_str).unwrap_or("?");
        let review = b
            .get("review_status")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        let head = b
            .get("head_snapshot_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("(empty)");
        let acls = b
            .get("page_acls")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let owner = b.get("owner").and_then(Value::as_str).unwrap_or("?");
        out.push_str(&format!(
            "{name:<21} {review:<10} {head:<20} {acls:<5} {owner}\n"
        ));
    }
    out
}

pub fn pull_main(raw: &[String]) -> ExitCode {
    if matches!(raw.first().map(String::as_str), Some("-h") | Some("--help")) {
        print!("{}", pull_usage());
        return ExitCode::SUCCESS;
    }
    match parse_pull_opts(raw).and_then(|o| cmd_pull(&o)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm pull: {e}");
            ExitCode::FAILURE
        }
    }
}

fn push_usage() -> String {
    "chm push — commit a local checkpoint as a revision on a branch (Phase 4)\n\
     \n\
     USAGE:\n    \
         chm push <CHECKPOINT_DIR> --branch NAME [--message M] [--api URL]\n                     \
         [--owner WHO] [--sandbox ID] [--parent SNAPSHOT_ID]\n\
     \n\
     CHECKPOINT_DIR is a chm snapshot/checkpoint directory (has state.json). The\n    \
     control plane ingests it into its content-addressed store, dedups against\n    \
     existing chunks, and advances the branch head. URL: --api, else $GCTL_API,\n    \
     else http://127.0.0.1:8080.\n"
        .to_string()
}

fn pull_usage() -> String {
    "chm pull — rehydrate a branch head (or revision) to a local resume (Phase 4)\n\
     \n\
     USAGE:\n    \
         chm pull --branch NAME --to DIR [--revision SNAPSHOT_ID] [--resume]\n                     \
         [--api URL] [--owner WHO] [--locality LOC]\n\
     \n\
     Resolves the branch head (or --revision) to a resume assignment and\n    \
     materializes the verified bundle into DIR. With --resume it then runs\n    \
     `chm resume DIR`; otherwise it prints DIR so you can resume when ready.\n"
        .to_string()
}

fn parse_push_opts(raw: &[String]) -> Result<PushOpts, String> {
    let mut checkpoint = None;
    let mut branch = None;
    let mut api = None;
    let mut owner = default_owner();
    let mut message = None;
    let mut sandbox = None;
    let mut parent = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--branch" => branch = Some(take_value(raw, &mut i, "--branch")?),
            "--api" => api = Some(take_value(raw, &mut i, "--api")?),
            "--owner" => owner = take_value(raw, &mut i, "--owner")?,
            "--message" | "-m" => message = Some(take_value(raw, &mut i, "--message")?),
            "--sandbox" => sandbox = Some(take_value(raw, &mut i, "--sandbox")?),
            "--parent" => parent = Some(take_value(raw, &mut i, "--parent")?),
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            pos => {
                if checkpoint.is_some() {
                    return Err(format!("unexpected argument `{pos}`"));
                }
                checkpoint = Some(PathBuf::from(pos));
            }
        }
        i += 1;
    }
    Ok(PushOpts {
        checkpoint: checkpoint.ok_or("a CHECKPOINT_DIR is required")?,
        branch: branch.ok_or("--branch NAME is required")?,
        api,
        owner,
        message,
        sandbox,
        parent,
    })
}

fn parse_pull_opts(raw: &[String]) -> Result<PullOpts, String> {
    let mut branch = None;
    let mut to = None;
    let mut api = None;
    let mut owner = default_owner();
    let mut revision = None;
    let mut locality = None;
    let mut resume = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--branch" => branch = Some(take_value(raw, &mut i, "--branch")?),
            "--to" => to = Some(PathBuf::from(take_value(raw, &mut i, "--to")?)),
            "--api" => api = Some(take_value(raw, &mut i, "--api")?),
            "--owner" => owner = take_value(raw, &mut i, "--owner")?,
            "--revision" => revision = Some(take_value(raw, &mut i, "--revision")?),
            "--locality" => locality = Some(take_value(raw, &mut i, "--locality")?),
            "--resume" => resume = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }
    Ok(PullOpts {
        branch: branch.ok_or("--branch NAME is required")?,
        to: to.ok_or("--to DIR is required")?,
        api,
        owner,
        revision,
        locality,
        resume,
    })
}

/// Advance `i` and return the value following a flag, erroring if absent.
fn take_value(raw: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    raw.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn cmd_push(opts: &PushOpts) -> Result<(), String> {
    let cp = ControlPlane::from_env_or(opts.api.clone());
    eprintln!("chm push: control plane {}", cp.api);

    // The plane ingests the bundle from this path on its own host, so make it
    // absolute — a co-located dev plane (:8080 on this Mac) resolves it directly.
    let bundle_dir = fs::canonicalize(&opts.checkpoint)
        .map_err(|e| format!("checkpoint dir {}: {e}", opts.checkpoint.display()))?;
    if !bundle_dir.join("state.json").is_file() {
        return Err(format!(
            "{} is not a chm snapshot/checkpoint (no state.json)",
            bundle_dir.display()
        ));
    }

    let mut req = json!({
        "branch": opts.branch,
        "owner": opts.owner,
        "bundle_dir": bundle_dir.display().to_string(),
        "requested_by": "chm-push",
        "idempotency_key": format!("push-{}-{}", opts.branch, now_secs()),
    });
    if let Some(m) = &opts.message {
        req["message"] = json!(m);
    }
    if let Some(s) = &opts.sandbox {
        req["sandbox_id"] = json!(s);
    }
    if let Some(p) = &opts.parent {
        req["parent_snapshot_id"] = json!(p);
    }

    let resp = cp.commit_revision(&req)?;
    println!("{}", format_commit_result(&opts.branch, &resp));
    Ok(())
}

fn cmd_pull(opts: &PullOpts) -> Result<(), String> {
    let cp = ControlPlane::from_env_or(opts.api.clone());
    eprintln!("chm pull: control plane {}", cp.api);

    let runner_id = do_register(&cp, &opts.owner)?;
    let branch_id = resolve_branch_id(&cp, &opts.owner, &opts.branch)?;

    let mut req = json!({
        "owner": opts.owner,
        "runner_id": runner_id,
        "requested_by": "chm-pull",
        "idempotency_key": format!("pull-{}-{}", opts.branch, now_secs()),
    });
    if let Some(rev) = &opts.revision {
        req["snapshot_id"] = json!(rev);
    }
    if let Some(loc) = &opts.locality {
        req["locality"] = json!(loc);
    }

    let resp = cp.pull_branch(&branch_id, &req)?;
    let snapshot_id = resp.get("snapshot_id").and_then(Value::as_str).unwrap_or("?");
    let acl = resp.get("acl_applied").and_then(Value::as_bool).unwrap_or(false);
    eprintln!(
        "chm pull: branch `{}` → revision {snapshot_id}{}",
        opts.branch,
        if acl { " (page-ACL scoped token)" } else { "" }
    );
    if let Some(src) = resp.get("chunk_source").and_then(|s| s.get("source")).and_then(Value::as_str)
    {
        eprintln!("chm pull: chunk source: {src}");
    }

    let assign = resp
        .get("assignment")
        .filter(|a| !a.is_null())
        .ok_or("pull: response carried no resume assignment")?;
    materialize_assignment_to(assign, &opts.to)?;

    if opts.resume {
        eprintln!("chm pull: resuming — exec chm resume {}", opts.to.display());
        let code = run_chm(&["resume".to_string(), opts.to.display().to_string()])?;
        if code != 0 {
            return Err(format!("chm resume exited {code}"));
        }
    } else {
        println!("{}", opts.to.display());
        eprintln!(
            "chm pull: ready — resume it with:  chm resume {}",
            opts.to.display()
        );
    }
    Ok(())
}

/// Resolve a branch *name* to its id via the branch list. If several branches
/// share the name, the one owned by `owner` wins; a unique name matches
/// regardless of owner.
fn resolve_branch_id(cp: &ControlPlane, owner: &str, name: &str) -> Result<String, String> {
    let body = cp.list_branches()?;
    let branches = body
        .get("branches")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    branch_id_by_name(&branches, owner, name).ok_or_else(|| {
        format!("no branch named `{name}` on the control plane (commit to it first with `chm push`)")
    })
}

/// Pick a branch id by name: a unique name matches outright; ambiguous names are
/// disambiguated by `owner`.
fn branch_id_by_name(branches: &[Value], owner: &str, name: &str) -> Option<String> {
    let named: Vec<&Value> = branches
        .iter()
        .filter(|b| b.get("name").and_then(Value::as_str) == Some(name))
        .collect();
    let chosen = match named.as_slice() {
        [] => return None,
        [only] => *only,
        many => *many
            .iter()
            .find(|b| b.get("owner").and_then(Value::as_str) == Some(owner))
            .unwrap_or(&many[0]),
    };
    chosen
        .get("branch_id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Materialize a pull's resume assignment into `dest`: re-verify the gic gate
/// (defense in depth — its-lpi never restores on HVF), then content-address the
/// bundle through the same CAS path a normal resume uses.
fn materialize_assignment_to(assign: &Value, dest: &Path) -> Result<(), String> {
    let download_uri = assign
        .get("download_uri")
        .and_then(Value::as_str)
        .ok_or("pull assignment: no download_uri")?;
    let (checksum_tree, provenance) = trusted_checksum_tree(assign)?;

    let manifest = assign.get("manifest").cloned().unwrap_or(Value::Null);
    let gic_mode = manifest
        .get("gic_mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !gic_mode.is_empty() && !hvf_restorable(gic_mode) {
        return Err(format!(
            "revision gic_mode `{gic_mode}` is not HVF-restorable — only \
             `gicv2m-message-spi` resumes on apple-hvf (recapture with CH_GIC_V2M=1)"
        ));
    }

    let _ = fs::remove_dir_all(dest);
    let token = assign.get("capability_token").and_then(Value::as_str);
    let deduped = materialize_bundle(download_uri, &checksum_tree, dest, token)?;
    eprintln!(
        "chm pull: materialized + verified {} file(s){} at {} [manifest {provenance}]",
        checksum_tree.len(),
        if deduped > 0 {
            format!(" ({deduped} shared from cache)")
        } else {
            String::new()
        },
        dest.display()
    );
    Ok(())
}

/// Format a `CommitRevisionResponse` into a human summary (branch head, new
/// revision id, and the content-addressed dedup stats).
fn format_commit_result(branch_name: &str, resp: &Value) -> String {
    let head = resp
        .pointer("/branch/head_snapshot_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let rev = resp
        .pointer("/revision/snapshot_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let stats = resp.get("stats").cloned().unwrap_or(Value::Null);
    let stored = stats.get("stored_bytes").and_then(Value::as_i64).unwrap_or(0);
    let total = stats.get("total_bytes").and_then(Value::as_i64).unwrap_or(0);
    let deduped = stats.get("deduped_pages").and_then(Value::as_i64).unwrap_or(0);
    let zero = stats.get("zero_pages").and_then(Value::as_i64).unwrap_or(0);
    let ratio = stats
        .get("working_set_ratio")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    format!(
        "committed revision {rev} on branch `{branch_name}`\n  \
         head    {head}\n  \
         stored  {stored} / {total} bytes ({:.1}% working set)\n  \
         dedup   {deduped} page(s) deduped, {zero} zero page(s)",
        ratio * 100.0
    )
}

/// HVF (Apple's managed GIC) can only deliver message-based SPIs, so it can only
/// restore checkpoints captured `gicv2m-message-spi`. Everything else (notably
/// `its-lpi`) stays cloud-only.
fn hvf_restorable(gic_mode: &str) -> bool {
    gic_mode == "gicv2m-message-spi"
}

/// Whether a run left a resumable checkpoint in the workspace (the `chm`
/// checkpoint manifest). Used to report a `suspended` state vs a plain `stopped`.
fn checkpoint_present(dir: &Path) -> bool {
    dir.join(".chm-checkpoint").join("checkpoint.json").is_file()
}

/// A real cloud-hypervisor snapshot's `state.json` carries a top-level
/// `snapshots` state tree (parsed by `hypervisor::hvf::rehydrate`). A protocol
/// fixture verifies + pulls but lacks it, so it cannot boot. Check before exec so
/// a fixture fails with an honest message instead of a cryptic parser error.
fn snapshot_is_bootable(dir: &Path) -> Result<(), String> {
    let state = dir.join("state.json");
    let bytes =
        fs::read(&state).map_err(|e| format!("read {}: {e}", state.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {}: {e}", state.display()))?;
    let has_snapshots = value.get("snapshots").is_some_and(|s| !s.is_null());
    if has_snapshots {
        Ok(())
    } else {
        Err("pulled + verified OK, but state.json has no `snapshots` state — this is a \
             protocol fixture, not a bootable cloud-hypervisor snapshot. It cannot run on \
             HVF; a real-KVM capture is required to make it runnable here."
            .to_string())
    }
}

/// The mid-flight marker a cloud runner embeds to prove session continuity: the
/// live state the cloud session had reached at checkpoint time.
struct FlightMarker {
    value: String,
    written_at: Option<String>,
}

/// Read the mid-flight marker from a checkpoint bundle. Prefer the
/// `gimbal-marker.json` sidecar; fall back to the `GIMBLMK1` frame at the head of
/// `snapshot/memory-ranges`.
fn read_flight_marker(dir: &Path) -> Option<FlightMarker> {
    if let Ok(bytes) = fs::read(dir.join("gimbal-marker.json"))
        && let Ok(v) = serde_json::from_slice::<Value>(&bytes)
        && let Some(value) = v.get("value").and_then(Value::as_str)
    {
        return Some(FlightMarker {
            value: value.to_string(),
            written_at: v
                .get("written_at")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    let mem = fs::read(dir.join("snapshot").join("memory-ranges")).ok()?;
    parse_gimbl_marker(&mem).map(|value| FlightMarker {
        value,
        written_at: None,
    })
}

/// Parse a `GIMBLMK1` + big-endian u32 length + UTF-8 payload frame from the head
/// of a buffer. Returns the payload if the magic and length are well-formed.
fn parse_gimbl_marker(bytes: &[u8]) -> Option<String> {
    const MAGIC: &[u8] = b"GIMBLMK1";
    if bytes.len() < 12 || &bytes[..8] != MAGIC {
        return None;
    }
    let len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let end = 12usize.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[12..end]).into_owned())
}

fn runner_cache_dir(snapshot_id: &str) -> PathBuf {
    let base = env::var_os("CHM_RUNNER_CACHE").map_or_else(
        || env::temp_dir().join("chm-runner-cache"),
        PathBuf::from,
    );
    base.join(snapshot_id)
}

/// Read `manifest.checksum_tree` from an assign-run response into a map.
fn parse_checksum_tree(assign: &Value) -> Result<BTreeMap<String, String>, String> {
    let manifest = assign
        .get("manifest")
        .ok_or("assign-run: manifest.checksum_tree missing")?;
    checksum_tree_from_manifest(manifest)
}

/// Extract + validate a `checksum_tree` from a manifest object.
fn checksum_tree_from_manifest(manifest: &Value) -> Result<BTreeMap<String, String>, String> {
    let tree = manifest
        .get("checksum_tree")
        .and_then(Value::as_object)
        .ok_or("manifest.checksum_tree missing")?;
    let mut out = BTreeMap::new();
    for (k, v) in tree {
        let digest = v
            .as_str()
            .ok_or_else(|| format!("checksum_tree[{k}] is not a string"))?;
        out.insert(k.clone(), digest.to_string());
    }
    Ok(out)
}

/// The trust store configured for this host, if any: `CHM_TRUST_STORE` points at
/// a JSON `{ "keys": { "<id>": "<hex pubkey>" } }`. `None` means no trust root is
/// configured, so bundles are accepted unsigned (back-compat during the gctl
/// signing rollout — M30.4). An empty store counts as no trust root.
fn resolve_trust_store() -> Result<Option<TrustStore>, String> {
    match env::var("CHM_TRUST_STORE") {
        Ok(p) if !p.is_empty() => {
            let store = TrustStore::load(Path::new(&p))?;
            Ok((!store.is_empty()).then_some(store))
        }
        _ => Ok(None),
    }
}

/// The `checksum_tree` to trust for a bundle, gated on manifest *authenticity*
/// (M30.4). Returns the tree plus a human provenance note.
///
/// When a trust root is configured, the assignment MUST carry a signed manifest:
/// `manifest_canonical` (the exact bytes gctl signed) and `manifest_signature`
/// (`{alg,key_id,sig}`). The signature is verified against the trust store and
/// the *signed* manifest's `checksum_tree` is used — so a tampered bundle whose
/// loose `manifest.checksum_tree` was recomputed cannot be trusted. A missing or
/// invalid signature **fails closed**. Without a trust root, the unsigned
/// `manifest.checksum_tree` is used so existing (pre-signing) flows keep working.
fn trusted_checksum_tree(assign: &Value) -> Result<(BTreeMap<String, String>, String), String> {
    authenticate_checksum_tree(assign, resolve_trust_store()?)
}

/// The authenticity gate proper, with the trust store passed in (so it is
/// testable without touching process env). See [`trusted_checksum_tree`].
fn authenticate_checksum_tree(
    assign: &Value,
    trust: Option<TrustStore>,
) -> Result<(BTreeMap<String, String>, String), String> {
    let Some(store) = trust else {
        return Ok((
            parse_checksum_tree(assign)?,
            "unsigned (no trust root configured)".to_string(),
        ));
    };
    let canonical = assign.get("manifest_canonical").and_then(Value::as_str).ok_or(
        "a trust root is configured (CHM_TRUST_STORE) but this bundle carries no \
         signed manifest_canonical — refusing to run an unsigned bundle (fail closed)",
    )?;
    let sig_val = assign.get("manifest_signature").ok_or(
        "a trust root is configured but this bundle carries no manifest_signature — \
         refusing to run an unsigned bundle (fail closed)",
    )?;
    let sig: DetachedSignature = serde_json::from_value(sig_val.clone())
        .map_err(|e| format!("parse manifest_signature: {e}"))?;
    store.verify(canonical.as_bytes(), &sig)?;
    let manifest: Value =
        serde_json::from_str(canonical).map_err(|e| format!("parse signed manifest: {e}"))?;
    let tree = checksum_tree_from_manifest(&manifest)?;
    Ok((tree, format!("verified (Ed25519 key id {})", sig.key_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    /// Build an owned `Vec<String>` args list from string literals.
    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn branch_id_resolves_unique_name_and_disambiguates_by_owner() {
        let branches = json!([
            { "branch_id": "b-1", "name": "laptop-main", "owner": "dev" },
            { "branch_id": "b-2", "name": "feature", "owner": "dev" },
            { "branch_id": "b-3", "name": "feature", "owner": "alice" }
        ]);
        let list = branches.as_array().unwrap();
        // A unique name matches regardless of the requesting owner.
        assert_eq!(
            branch_id_by_name(list, "someone-else", "laptop-main").as_deref(),
            Some("b-1")
        );
        // An ambiguous name is disambiguated by owner.
        assert_eq!(branch_id_by_name(list, "alice", "feature").as_deref(), Some("b-3"));
        assert_eq!(branch_id_by_name(list, "dev", "feature").as_deref(), Some("b-2"));
        // No match returns None.
        assert_eq!(branch_id_by_name(list, "dev", "nope"), None);
    }

    #[test]
    fn format_commit_result_reports_dedup_stats() {
        // Mirrors the live 0-byte re-commit: identical content stores nothing.
        let resp = json!({
            "branch": { "head_snapshot_id": "snap-head" },
            "revision": { "snapshot_id": "snap-rev" },
            "stats": {
                "total_bytes": 2097152, "stored_bytes": 0,
                "deduped_pages": 4, "zero_pages": 4, "working_set_ratio": 0.0
            }
        });
        let out = format_commit_result("laptop-main", &resp);
        assert!(out.contains("revision snap-rev on branch `laptop-main`"), "{out}");
        assert!(out.contains("head    snap-head"), "{out}");
        assert!(out.contains("stored  0 / 2097152 bytes (0.0% working set)"), "{out}");
        assert!(out.contains("4 page(s) deduped, 4 zero page(s)"), "{out}");
    }

    #[test]
    fn parse_push_opts_requires_dir_and_branch() {
        let opts = parse_push_opts(&s(&[
            "/tmp/ckpt", "--branch", "laptop-main", "--message", "hi", "--parent", "snap-p",
        ]))
        .unwrap();
        assert_eq!(opts.checkpoint, PathBuf::from("/tmp/ckpt"));
        assert_eq!(opts.branch, "laptop-main");
        assert_eq!(opts.message.as_deref(), Some("hi"));
        assert_eq!(opts.parent.as_deref(), Some("snap-p"));
        // Missing --branch is an error; a stray second positional is rejected.
        assert!(parse_push_opts(&s(&["/tmp/ckpt"])).is_err());
        assert!(parse_push_opts(&s(&["/tmp/a", "/tmp/b", "--branch", "x"])).is_err());
    }

    #[test]
    fn parse_pull_opts_requires_branch_and_to() {
        let opts =
            parse_pull_opts(&s(&["--branch", "feature", "--to", "/tmp/out", "--resume"])).unwrap();
        assert_eq!(opts.branch, "feature");
        assert_eq!(opts.to, PathBuf::from("/tmp/out"));
        assert!(opts.resume);
        assert!(parse_pull_opts(&s(&["--branch", "feature"])).is_err());
        assert!(parse_pull_opts(&s(&["--to", "/tmp/out"])).is_err());
    }

    #[test]
    fn capabilities_advertise_commit() {
        assert_eq!(capabilities()["supports_commit"], json!(true));
    }

    #[test]
    fn format_branches_table_renders_rows_and_empty() {
        assert_eq!(format_branches_table(&[]), "(no branches)\n");
        let branches = json!([
            { "name": "laptop-main", "review_status": "pending",
              "head_snapshot_id": "snap-6150377c50aa", "owner": "dev" },
            { "name": "acl-demo", "head_snapshot_id": "snap-d9a9a1529717",
              "owner": "dev", "page_acls": [ { "audience": "r1" } ] }
        ]);
        let out = format_branches_table(branches.as_array().unwrap());
        assert!(out.contains("BRANCH"), "{out}");
        assert!(out.contains("laptop-main"), "{out}");
        assert!(out.contains("pending"), "{out}");
        assert!(out.contains("snap-6150377c50aa"), "{out}");
        // acl-demo has no review status (shows '-') and 1 acl.
        let acl_line = out.lines().find(|l| l.contains("acl-demo")).unwrap();
        assert!(acl_line.contains(" - "), "no-review shows dash: {acl_line}");
        assert!(acl_line.contains(" 1 "), "acl count shown: {acl_line}");
    }

    #[test]
    fn parses_status_and_body() {
        let raw = "{\"runner_id\":\"r1\"}\n__CHM_HTTP_STATUS__:200";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body["runner_id"], "r1");
    }

    #[test]
    fn confined_join_accepts_plain_relative_paths() {
        let root = Path::new("/tmp/cache");
        assert_eq!(
            confined_join(root, "snapshot/memory-ranges").unwrap(),
            root.join("snapshot/memory-ranges")
        );
        assert_eq!(
            confined_join(root, "./disks/_disk0.raw").unwrap(),
            root.join("disks/_disk0.raw")
        );
    }

    #[test]
    fn confined_join_rejects_traversal_and_absolute() {
        let root = Path::new("/tmp/cache");
        // Zip-slip: a `..`-escaping manifest key must not write outside the cache.
        for bad in [
            "../../../etc/cron.d/x",
            "snapshot/../../escape",
            "/etc/passwd",
            "",
        ] {
            assert!(
                confined_join(root, bad).is_err(),
                "must reject bundle path {bad:?}"
            );
        }
    }

    #[test]
    fn parses_empty_body_with_status() {
        let raw = "\n__CHM_HTTP_STATUS__:204";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_null());
    }

    #[test]
    fn http_error_prefers_error_field() {
        let body = json!({ "error": "not found" });
        assert_eq!(http_error_message(&body), "not found");
        assert_eq!(http_error_message(&Value::Null), "(no body)");
    }

    #[test]
    fn ok_or_http_err_branches_on_status() {
        let ok = HttpResponse { status: 201, body: json!({"a":1}) };
        ok_or_http_err(ok, "x").unwrap();
        let bad = HttpResponse { status: 422, body: json!({"error":"its-lpi"}) };
        let e = ok_or_http_err(bad, "assign").unwrap_err();
        assert!(e.contains("422") && e.contains("its-lpi"));
    }

    #[test]
    fn file_uri_resolves_to_abs_path() {
        assert_eq!(
            download_uri_to_path("file:///Users/x/objects/snap").unwrap(),
            PathBuf::from("/Users/x/objects/snap")
        );
        download_uri_to_path("https://cdn/snap").unwrap_err();
    }

    #[test]
    fn substitutes_snapshot_dir_and_drops_chm() {
        let args = chm_command_args("chm run <SNAPSHOT_DIR> --idle-exit 0", Path::new("/tmp/s")).unwrap();
        assert_eq!(args, vec!["run", "/tmp/s", "--idle-exit", "0"]);
        // resume kind
        let args = chm_command_args("chm resume <SNAPSHOT_DIR>", Path::new("/c")).unwrap();
        assert_eq!(args, vec!["resume", "/c"]);
        // guards
        chm_command_args("qemu run x", Path::new("/c")).unwrap_err();
        chm_command_args("chm", Path::new("/c")).unwrap_err();
    }

    #[test]
    fn parse_shasum_takes_first_field_lowercased() {
        assert_eq!(
            parse_shasum_output("ABCD1234  /path/to/file\n").unwrap(),
            "abcd1234"
        );
        assert_eq!(parse_shasum_output(""), None);
    }

    #[test]
    fn object_url_joins_base_and_relpath() {
        assert_eq!(
            object_url("https://cdn.example/snap", "snapshot/mem"),
            "https://cdn.example/snap/snapshot/mem"
        );
        // Redundant slashes are normalised at the join.
        assert_eq!(
            object_url("https://cdn.example/snap/", "/state.json"),
            "https://cdn.example/snap/state.json"
        );
    }

    #[test]
    fn materialize_verifies_and_dedups_shared_blobs() {
        let root = env::temp_dir().join(format!("chm-cp-mat-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        // A local file:// object store with two files.
        let store = root.join("store");
        fs::create_dir_all(store.join("snapshot")).unwrap();
        fs::write(store.join("state.json"), b"hello").unwrap();
        fs::write(store.join("snapshot/mem"), b"world").unwrap();
        let uri = format!("file://{}", store.display());
        // sha256("hello"), sha256("world")
        let mut tree = BTreeMap::new();
        tree.insert(
            "state.json".to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
        );
        tree.insert(
            "snapshot/mem".to_string(),
            "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7".to_string(),
        );

        // First snapshot: everything fetched (0 deduped), bytes correct.
        let cache_a = root.join("snap-a");
        assert_eq!(materialize_bundle(&uri, &tree, &cache_a, None).unwrap(), 0);
        assert_eq!(fs::read(cache_a.join("state.json")).unwrap(), b"hello");
        assert_eq!(fs::read(cache_a.join("snapshot/mem")).unwrap(), b"world");

        // Second snapshot sharing the same blobs: fully served from the CAS.
        let cache_b = root.join("snap-b");
        assert_eq!(
            materialize_bundle(&uri, &tree, &cache_b, None).unwrap(),
            tree.len()
        );
        assert_eq!(fs::read(cache_b.join("state.json")).unwrap(), b"hello");

        // A wrong digest is rejected; an empty tree is refused.
        let mut bad = tree.clone();
        bad.insert("state.json".to_string(), "00".repeat(32));
        materialize_bundle(&uri, &bad, &root.join("snap-c"), None).unwrap_err();
        materialize_bundle(&uri, &BTreeMap::new(), &root.join("snap-d"), None).unwrap_err();
        // An unsupported scheme is refused.
        fetch_object("ftp://x/y", "z", &root.join("z"), None).unwrap_err();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn materialize_rejects_non_digest_checksums() {
        // The checksum value is used as a CAS path component. A crafted value that
        // is not a plain sha256 hex digest — an absolute path, a traversal, a
        // wrong length, or non-hex — must be refused before it can select or
        // expose a host file (M30.8).
        let root = env::temp_dir().join(format!("chm-cp-badck-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = root.join("store");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("state.json"), b"hello").unwrap();
        let uri = format!("file://{}", store.display());

        for evil in [
            "/etc/passwd",
            "../../../../etc/passwd",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b98", // 62 chars
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824ff", // 66
            "zzf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // non-hex
        ] {
            let mut tree = BTreeMap::new();
            tree.insert("state.json".to_string(), evil.to_string());
            let err = materialize_bundle(&uri, &tree, &root.join("out"), None).unwrap_err();
            assert!(
                err.contains("not a") || err.contains("hex sha256"),
                "checksum {evil:?} must be rejected as a non-digest, got: {err}"
            );
            let _ = fs::remove_dir_all(root.join("out"));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn materialize_rehashes_a_poisoned_cache_hit() {
        // A CAS blob that has been corrupted/poisoned out of band (its bytes no
        // longer match the digest that names it) must not be linked into a guest
        // on a dedup hit — it is re-hashed, discarded on mismatch, and re-fetched
        // from the verified source instead (M30.8).
        let root = env::temp_dir().join(format!("chm-cp-poison-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = root.join("store");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("state.json"), b"hello").unwrap();
        let uri = format!("file://{}", store.display());
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"; // sha256("hello")

        // Pre-poison the CAS: a blob named with the valid digest but holding attacker bytes.
        let cache = root.join("snap");
        let cas = cas_dir_for(&cache);
        fs::create_dir_all(&cas).unwrap();
        fs::write(cas.join(digest), b"POISONED-not-hello").unwrap();

        let mut tree = BTreeMap::new();
        tree.insert("state.json".to_string(), digest.to_string());
        // Must succeed by re-fetching the real bytes, not by trusting the poison.
        materialize_bundle(&uri, &tree, &cache, None).unwrap();
        assert_eq!(
            fs::read(cache.join("state.json")).unwrap(),
            b"hello",
            "the poisoned cache hit must be re-hashed and replaced with verified bytes"
        );
        // The CAS blob is now the correct content.
        assert_eq!(fs::read(cas.join(digest)).unwrap(), b"hello");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_checksum_tree_reads_manifest() {
        let assign = json!({
            "manifest": { "checksum_tree": { "state.json": "abc", "snapshot/mem": "def" } }
        });
        let tree = parse_checksum_tree(&assign).unwrap();
        assert_eq!(tree.get("state.json").map(String::as_str), Some("abc"));
        assert_eq!(tree.len(), 2);
        parse_checksum_tree(&json!({})).unwrap_err();
    }

    #[test]
    fn authenticity_gate_allows_unsigned_without_a_trust_root() {
        // No trust root configured => the unsigned manifest.checksum_tree is used
        // (back-compat during the gctl signing rollout).
        let assign = json!({
            "manifest": { "checksum_tree": { "state.json": "abc" } }
        });
        let (tree, note) = authenticate_checksum_tree(&assign, None).unwrap();
        assert_eq!(tree.get("state.json").map(String::as_str), Some("abc"));
        assert!(note.contains("unsigned"), "note: {note}");
    }

    #[test]
    fn authenticity_gate_fails_closed_when_trust_set_but_bundle_unsigned() {
        // A trust root is configured but the bundle carries no signature: refuse.
        let (_pkcs8, pub_hex) = crate::signing::generate_keypair().unwrap();
        let mut store = TrustStore::default();
        store.insert_hex("gctl-2026", &pub_hex);
        let assign = json!({
            "manifest": { "checksum_tree": { "state.json": "abc" } }
        });
        let err = authenticate_checksum_tree(&assign, Some(store)).unwrap_err();
        assert!(err.contains("fail closed"), "must fail closed, got: {err}");
    }

    #[test]
    fn authenticity_gate_verifies_a_signed_bundle_and_uses_its_tree() {
        // With a trust root and a valid signature, the SIGNED manifest's
        // checksum_tree is trusted (not the loose one) and provenance is recorded.
        let (pkcs8, pub_hex) = crate::signing::generate_keypair().unwrap();
        let mut store = TrustStore::default();
        store.insert_hex("gctl-2026", &pub_hex);

        let canonical = r#"{"version":1,"checksum_tree":{"state.json":"deadbeef"}}"#;
        let sig = crate::signing::sign(&pkcs8, "gctl-2026", canonical.as_bytes()).unwrap();
        let assign = json!({
            // A loose (untrusted) manifest that disagrees — must be ignored.
            "manifest": { "checksum_tree": { "state.json": "00" } },
            "manifest_canonical": canonical,
            "manifest_signature": { "alg": sig.alg, "key_id": sig.key_id, "sig": sig.sig },
        });
        let (tree, note) = authenticate_checksum_tree(&assign, Some(store)).unwrap();
        assert_eq!(
            tree.get("state.json").map(String::as_str),
            Some("deadbeef"),
            "the signed manifest's tree is trusted, not the loose one"
        );
        assert!(note.contains("verified") && note.contains("gctl-2026"), "note: {note}");
    }

    #[test]
    fn authenticity_gate_rejects_a_tampered_signed_manifest() {
        // The signature was made over the original bytes; altering the canonical
        // manifest after signing must fail verification.
        let (pkcs8, pub_hex) = crate::signing::generate_keypair().unwrap();
        let mut store = TrustStore::default();
        store.insert_hex("k", &pub_hex);
        let signed = r#"{"checksum_tree":{"state.json":"deadbeef"}}"#;
        let sig = crate::signing::sign(&pkcs8, "k", signed.as_bytes()).unwrap();
        let tampered = r#"{"checksum_tree":{"state.json":"evildigest"}}"#;
        let assign = json!({
            "manifest_canonical": tampered,
            "manifest_signature": { "alg": sig.alg, "key_id": sig.key_id, "sig": sig.sig },
        });
        authenticate_checksum_tree(&assign, Some(store))
            .expect_err("a tampered signed manifest must be rejected");
    }

    #[test]
    fn only_message_spi_is_hvf_restorable() {
        assert!(hvf_restorable("gicv2m-message-spi"));
        assert!(!hvf_restorable("its-lpi"));
        assert!(!hvf_restorable(""));
    }

    #[test]
    fn checkpoint_present_detects_a_saved_checkpoint() {
        let dir = env::temp_dir().join(format!("chm-cp-ckpt-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(!checkpoint_present(&dir), "no checkpoint yet");
        fs::create_dir_all(dir.join(".chm-checkpoint")).unwrap();
        fs::write(dir.join(".chm-checkpoint").join("checkpoint.json"), b"{}").unwrap();
        assert!(checkpoint_present(&dir), "a run that suspended left a checkpoint");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootable_gate_distinguishes_real_snapshot_from_fixture() {
        let dir = env::temp_dir().join(format!("chm-cp-boot-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // A protocol fixture: no `snapshots` state.
        fs::write(
            dir.join("state.json"),
            br#"{"config":{},"devices":[],"interrupt_routing":"message-spi"}"#,
        )
        .unwrap();
        snapshot_is_bootable(&dir).unwrap_err();
        // A real snapshot: has a `snapshots` state tree.
        fs::write(
            dir.join("state.json"),
            br#"{"snapshots":{"device-manager":{}},"snapshot_data":{}}"#,
        )
        .unwrap();
        snapshot_is_bootable(&dir).unwrap();
        // A null `snapshots` is treated as a fixture.
        fs::write(dir.join("state.json"), br#"{"snapshots":null}"#).unwrap();
        snapshot_is_bootable(&dir).unwrap_err();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn advertises_apple_hvf_substrate() {
        let caps = capabilities();
        assert_eq!(caps.get("substrate").and_then(Value::as_str), Some("apple-hvf"));
        assert_eq!(caps.get("supports_resume").and_then(Value::as_bool), Some(true));
        assert_eq!(caps.get("supports_fork").and_then(Value::as_bool), Some(true));
        assert_eq!(
            caps.get("supports_cow_overlay").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn parses_gimbl_marker_frame() {
        let mut buf = b"GIMBLMK1".to_vec();
        let payload = b"cloud-run proof @ T0";
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&[0u8; 16]); // trailing RAM after the frame
        assert_eq!(parse_gimbl_marker(&buf).as_deref(), Some("cloud-run proof @ T0"));
        // Guards: wrong magic, truncated length.
        assert_eq!(parse_gimbl_marker(b"NOPEMAGIC...."), None);
        let mut bad = b"GIMBLMK1".to_vec();
        bad.extend_from_slice(&999u32.to_be_bytes());
        bad.extend_from_slice(b"short");
        assert_eq!(parse_gimbl_marker(&bad), None);
    }

    #[test]
    fn reads_flight_marker_sidecar_then_falls_back() {
        let dir = env::temp_dir().join(format!("chm-cp-marker-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("snapshot")).unwrap();
        // Sidecar wins.
        fs::write(
            dir.join("gimbal-marker.json"),
            br#"{"value":"from-sidecar","written_at":"T1","origin_substrate":"linux-kvm"}"#,
        )
        .unwrap();
        let m = read_flight_marker(&dir).unwrap();
        assert_eq!(m.value, "from-sidecar");
        assert_eq!(m.written_at.as_deref(), Some("T1"));
        // Remove sidecar → fall back to the GIMBLMK1 frame in memory-ranges.
        fs::remove_file(dir.join("gimbal-marker.json")).unwrap();
        let mut mem = b"GIMBLMK1".to_vec();
        let p = b"from-ram-head";
        mem.extend_from_slice(&(p.len() as u32).to_be_bytes());
        mem.extend_from_slice(p);
        fs::write(dir.join("snapshot").join("memory-ranges"), &mem).unwrap();
        assert_eq!(read_flight_marker(&dir).unwrap().value, "from-ram-head");
        let _ = fs::remove_dir_all(&dir);
    }
}
