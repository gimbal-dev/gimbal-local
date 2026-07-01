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

    fn push_artifacts(&self, sandbox_id: &str, req: &Value) -> Result<(), String> {
        let path = format!("/sandboxes/{sandbox_id}/push-artifacts");
        let resp = self.request("POST", &path, Some(req))?;
        ok_or_http_err(resp, "push-artifacts").map(|_| ())
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

/// Resolve an assignment's `download_uri` to a local directory path. On this Mac
/// the object store is local, so the URI is a `file://` path we read directly.
/// A non-`file://` locator is unsupported here (would need a real download).
fn download_uri_to_path(uri: &str) -> Result<PathBuf, String> {
    if let Some(rest) = uri.strip_prefix("file://") {
        // file:///abs/path → /abs/path (three slashes ⇒ empty host).
        Ok(PathBuf::from(rest))
    } else {
        Err(format!(
            "download_uri {uri} is not a local file:// locator; \
             networked object stores are not supported by this runner yet"
        ))
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

/// Verify every file in `checksum_tree` exists under `dir` with a matching
/// sha256. Keys are bundle-relative paths; values are lowercase hex digests.
fn verify_checksums(dir: &Path, checksum_tree: &BTreeMap<String, String>) -> Result<(), String> {
    if checksum_tree.is_empty() {
        return Err("manifest.checksum_tree is empty; refusing to trust the bundle".to_string());
    }
    for (rel, want) in checksum_tree {
        let path = dir.join(rel);
        let got = sha256_file(&path)?;
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!(
                "checksum mismatch for {rel}: expected {want}, got {got}"
            ));
        }
    }
    Ok(())
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

/// Copy a snapshot bundle tree from `src` into `dst` (the local runner cache),
/// so the runner holds a verified local copy independent of the object store.
fn copy_bundle(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", src.display()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| format!("stat {}: {e}", from.display()))?;
        if ft.is_dir() {
            copy_bundle(&from, &to)?;
        } else {
            fs::copy(&from, &to)
                .map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))?;
        }
    }
    Ok(())
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
    let checksum_tree = parse_checksum_tree(&assign)?;
    eprintln!(
        "chm runner: assigned {} (kind={kind}, {} file(s) to verify)",
        opts.snapshot_id,
        checksum_tree.len()
    );

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

    // 4. Pull + verify the bundle into a local runner cache.
    let src = download_uri_to_path(download_uri)?;
    let cache = runner_cache_dir(&opts.snapshot_id);
    let _ = fs::remove_dir_all(&cache);
    copy_bundle(&src, &cache)?;
    verify_checksums(&cache, &checksum_tree)?;
    eprintln!("chm runner: verified {} against manifest.checksum_tree", cache.display());

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
    let (final_state, note) = match &exec {
        Ok(code) if *code == 0 => ("stopped", "workload exited 0".to_string()),
        Ok(code) => ("error", format!("workload exited {code}")),
        Err(e) => ("error", format!("failed to launch workload: {e}")),
    };
    cp.report_state(&sandbox_id, final_state)?;
    eprintln!("chm runner: reported {final_state} ({note})");

    // 7. Push run artifacts (idempotent).
    cp.push_artifacts(
        &sandbox_id,
        &json!({
            "runner_id": runner_id,
            "local_path": cache.display().to_string(),
            "kind": "run-output",
            "requested_by": "chm-runner",
            "idempotency_key": format!("{sandbox_id}-run-output"),
        }),
    )?;
    eprintln!("chm runner: pushed artifacts");

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

/// HVF (Apple's managed GIC) can only deliver message-based SPIs, so it can only
/// restore checkpoints captured `gicv2m-message-spi`. Everything else (notably
/// `its-lpi`) stays cloud-only.
fn hvf_restorable(gic_mode: &str) -> bool {
    gic_mode == "gicv2m-message-spi"
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
    let tree = assign
        .get("manifest")
        .and_then(|m| m.get("checksum_tree"))
        .and_then(Value::as_object)
        .ok_or("assign-run: manifest.checksum_tree missing")?;
    let mut out = BTreeMap::new();
    for (k, v) in tree {
        let digest = v
            .as_str()
            .ok_or_else(|| format!("checksum_tree[{k}] is not a string"))?;
        out.insert(k.clone(), digest.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn parses_status_and_body() {
        let raw = "{\"runner_id\":\"r1\"}\n__CHM_HTTP_STATUS__:200";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body["runner_id"], "r1");
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
    fn verify_checksums_matches_real_files() {
        let dir = env::temp_dir().join(format!("chm-cp-test-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("snapshot")).unwrap();
        fs::write(dir.join("state.json"), b"hello").unwrap();
        fs::write(dir.join("snapshot/mem"), b"world").unwrap();
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
        verify_checksums(&dir, &tree).unwrap();
        // A wrong digest fails.
        tree.insert("state.json".to_string(), "00".repeat(32));
        verify_checksums(&dir, &tree).unwrap_err();
        // An empty tree is refused.
        verify_checksums(&dir, &BTreeMap::new()).unwrap_err();
        let _ = fs::remove_dir_all(&dir);
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
    fn only_message_spi_is_hvf_restorable() {
        assert!(hvf_restorable("gicv2m-message-spi"));
        assert!(!hvf_restorable("its-lpi"));
        assert!(!hvf_restorable(""));
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
