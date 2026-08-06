// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Talking to an OCI registry.
//!
//! # Why `curl`
//!
//! This crate already reaches the network by shelling out to `curl`
//! ([`crate::control_plane`] says so in its own module docs), and `curl` is on
//! every macOS install with the system trust store already wired up. The
//! alternative is a vendored HTTP+TLS client stack whose only job is four GETs.
//!
//! This is emphatically **not** the dependency #153's open question is about.
//! The question there is whether to depend on *container tooling* — docker,
//! podman, skopeo — which would mean the product that exists to remove the need
//! for a Linux container runtime requires one to build an image. `curl` is not
//! that. Nothing here needs a daemon, a VM, or a package the user must install.
//!
//! # The parts that are pure
//!
//! The two things most likely to be wrong — picking `linux/arm64` out of a
//! multi-architecture index, and reading the token challenge out of a `401` —
//! are pure functions over text, tested below with the real shapes Docker Hub
//! and GHCR return. The IO around them is a thin wrapper.

use std::process::Command;

use ring::digest::{digest as sha256_of, SHA256};
use serde_json::Value;

use super::reference::Reference;

/// Media types we accept when asking for a manifest. Sending all of them is
/// what makes a registry hand back the modern OCI type when it has one and the
/// Docker type when it does not.
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json,\
application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json,\
application/vnd.docker.distribution.manifest.v2+json";

/// The architecture a guest on this product can run. Apple Silicon runs arm64
/// guests; pulling an amd64 image would produce a rootfs of binaries the guest
/// cannot execute, and the failure would appear as `exec format error` deep
/// into boot rather than at pull time.
pub const WANT_ARCH: &str = "arm64";
pub const WANT_OS: &str = "linux";

/// A `Bearer` challenge parsed out of a `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Read the token endpoint out of a registry's 401.
///
/// Registries do not agree on the order or the quoting of these parameters, and
/// GHCR omits `scope` while Docker Hub includes it, so this is written to take
/// the parameters it recognises and ignore the rest rather than to match a
/// shape.
pub fn parse_challenge(header: &str) -> Option<Challenge> {
    let rest = header.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            "scope" => scope = Some(v),
            _ => {}
        }
    }
    Some(Challenge {
        realm: realm?,
        service,
        scope,
    })
}

/// Is this manifest a multi-architecture index rather than a single image?
pub fn is_index(manifest: &Value) -> bool {
    manifest.get("manifests").is_some_and(Value::is_array)
}

/// Choose the `linux/arm64` entry from a multi-architecture index.
///
/// Returns the digest to fetch next, or an error naming what the image *does*
/// offer — because "this image has no arm64 build" is a thing the user can act
/// on, and an unexplained 404 is not.
pub fn pick_arm64(index: &Value) -> Result<String, String> {
    let entries = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or("manifest index has no `manifests` array")?;
    let mut offered = Vec::new();
    for m in entries {
        let plat = m.get("platform");
        let os = plat.and_then(|p| p.get("os")).and_then(Value::as_str);
        let arch = plat.and_then(|p| p.get("architecture")).and_then(Value::as_str);
        // Attestation manifests carry `unknown/unknown` and must be skipped, or
        // a `docker buildx` image resolves to a signature blob instead of a
        // root filesystem.
        if os == Some("unknown") || arch == Some("unknown") {
            continue;
        }
        if let (Some(o), Some(a)) = (os, arch) {
            offered.push(format!("{o}/{a}"));
            if o == WANT_OS && a == WANT_ARCH {
                let variant = plat
                    .and_then(|p| p.get("variant"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // v8 is the only arm64 variant a Mac can run; an unspecified
                // variant is the common and correct case.
                if variant.is_empty() || variant == "v8" {
                    return m
                        .get("digest")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| "arm64 entry has no digest".to_string());
                }
            }
        }
    }
    Err(format!(
        "this image has no {WANT_OS}/{WANT_ARCH} build (it offers {}). \
         Apple Silicon runs arm64 guests, so an amd64-only image cannot be booted here.",
        if offered.is_empty() {
            "nothing recognisable".to_string()
        } else {
            offered.join(", ")
        }
    ))
}

/// One layer: what to fetch, and how it is compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerRef {
    pub digest: String,
    pub media_type: String,
}

impl LayerRef {
    /// Can this build read this layer?
    ///
    /// zstd layers are a real and growing thing (`docker buildx` emits them on
    /// request) and this build cannot read one. Refusing by name at pull time is
    /// the difference between "rebuild your image with gzip" and a tar parse
    /// error that reads like corruption.
    pub fn readable(&self) -> Result<(), String> {
        let m = &self.media_type;
        if m.contains("zstd") {
            return Err(format!(
                "this image has zstd-compressed layers (`{m}`), which this build cannot read.                  Rebuild it with gzip layers, or pull a different tag."
            ));
        }
        if m.contains("foreign") {
            return Err(format!(
                "this image has a foreign/non-distributable layer (`{m}`), which the registry                  will not serve. That is usually a Windows base image."
            ));
        }
        Ok(())
    }
}

/// The layers of a single-architecture manifest, outermost last.
pub fn layer_specs(manifest: &Value) -> Result<Vec<LayerRef>, String> {
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("manifest has no `layers` array")?;
    layers
        .iter()
        .map(|l| {
            let digest = l
                .get("digest")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| "a layer has no digest".to_string())?;
            let media_type = l
                .get("mediaType")
                .and_then(Value::as_str)
                .unwrap_or("application/vnd.oci.image.layer.v1.tar+gzip")
                .to_string();
            Ok(LayerRef { digest, media_type })
        })
        .collect()
}

/// The config blob's digest, which carries `Entrypoint`, `Cmd` and `Env`.
pub fn config_digest(manifest: &Value) -> Option<String> {
    manifest
        .get("config")?
        .get("digest")?
        .as_str()
        .map(str::to_string)
}

/// What a container image says it should run, and in what environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
}

impl ImageConfig {
    /// The command the generated `init` should hand over to.
    ///
    /// Follows the container rule — `Entrypoint` then `Cmd` appended — and
    /// falls back to a shell, because a sandbox someone can type into is more
    /// useful than one that runs an image's default server and exits.
    pub fn boot_command(&self) -> String {
        let mut parts = self.entrypoint.clone();
        parts.extend(self.cmd.iter().cloned());
        if parts.is_empty() {
            return "/bin/sh".to_string();
        }
        parts.join(" ")
    }
}

/// Read the parts of an image config we act on.
pub fn parse_config(config: &Value) -> ImageConfig {
    let c = config.get("config").unwrap_or(config);
    let list = |k: &str| -> Vec<String> {
        c.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    ImageConfig {
        entrypoint: list("Entrypoint"),
        cmd: list("Cmd"),
        env: list("Env"),
        workdir: c
            .get("WorkingDir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    }
}

/// A registry session: holds the bearer token once obtained.
pub struct Registry {
    reference: Reference,
    token: Option<String>,
}

/// One HTTP response, reduced to what we use.
struct Response {
    status: u32,
    body: Vec<u8>,
    www_authenticate: Option<String>,
}

impl Registry {
    pub fn new(reference: Reference) -> Self {
        Self {
            reference,
            token: None,
        }
    }

    fn get(&self, url: &str, accept: Option<&str>) -> Result<Response, String> {
        let mut cmd = Command::new("curl");
        cmd.arg("-sS")
            .arg("-L") // registries redirect blobs to object storage
            .args(["--max-time", "600"])
            .arg("-D")
            .arg("-") // headers to stdout, ahead of the body
            .arg(url);
        if let Some(a) = accept {
            cmd.args(["-H", &format!("Accept: {a}")]);
        }
        if let Some(t) = &self.token {
            cmd.args(["-H", &format!("Authorization: Bearer {t}")]);
        }
        let out = cmd
            .output()
            .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
        if !out.status.success() && out.stdout.is_empty() {
            return Err(format!(
                "curl GET {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        split_headers_and_body(&out.stdout)
    }

    /// Obtain a bearer token for this repository, if the registry wants one.
    ///
    /// Anonymous pulls are the norm for public images, and the token endpoint
    /// issues an anonymous token happily; this is a formality the registry
    /// insists on rather than a credential step.
    fn authenticate(&mut self, challenge: &Challenge) -> Result<(), String> {
        let mut url = format!("{}?", challenge.realm);
        if let Some(s) = &challenge.service {
            url.push_str(&format!("service={}&", url_escape(s)));
        }
        let scope = challenge.scope.clone().unwrap_or_else(|| {
            format!("repository:{}:pull", self.reference.repository)
        });
        url.push_str(&format!("scope={}", url_escape(&scope)));

        let saved = self.token.take();
        let resp = self.get(&url, None);
        self.token = saved;
        let resp = resp?;
        if resp.status != 200 {
            return Err(format!(
                "the registry would not issue a pull token ({}). \
                 A private image needs credentials this build does not yet carry.",
                resp.status
            ));
        }
        let v: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| format!("token response was not JSON: {e}"))?;
        let tok = v
            .get("token")
            .or_else(|| v.get("access_token"))
            .and_then(Value::as_str)
            .ok_or("token response carried no token")?;
        self.token = Some(tok.to_string());
        Ok(())
    }

    /// GET a URL, performing the token dance once if challenged.
    fn get_authed(&mut self, url: &str, accept: Option<&str>) -> Result<Vec<u8>, String> {
        let resp = self.get(url, accept)?;
        if resp.status == 401 {
            let challenge = resp
                .www_authenticate
                .as_deref()
                .and_then(parse_challenge)
                .ok_or_else(|| {
                    format!("{url} needs authentication but did not say how")
                })?;
            self.authenticate(&challenge)?;
            let retry = self.get(url, accept)?;
            if retry.status != 200 {
                return Err(http_error(&self.reference, retry.status, &retry.body));
            }
            return Ok(retry.body);
        }
        if resp.status != 200 {
            return Err(http_error(&self.reference, resp.status, &resp.body));
        }
        Ok(resp.body)
    }

    /// Fetch the manifest, following a multi-architecture index to the arm64
    /// image.
    pub fn manifest(&mut self) -> Result<Value, String> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.registry, self.reference.repository, self.reference.reference
        );
        let body = self.get_authed(&url, Some(ACCEPT))?;
        let v: Value =
            serde_json::from_slice(&body).map_err(|e| format!("manifest was not JSON: {e}"))?;
        if !is_index(&v) {
            return Ok(v);
        }
        let digest = pick_arm64(&v)?;
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.registry, self.reference.repository, digest
        );
        let body = self.get_authed(&url, Some(ACCEPT))?;
        serde_json::from_slice(&body).map_err(|e| format!("arm64 manifest was not JSON: {e}"))
    }

    /// Fetch a blob and **verify its digest before returning it**.
    ///
    /// This is the point #153 makes about reusing the CAS hardening rather than
    /// growing a second weaker path: content addressed by `sha256:` is only
    /// content-addressed if something checks. A registry that has been
    /// compromised, an intercepting proxy, or a truncated download all show up
    /// here and nowhere else — the tar reader would happily unpack a corrupted
    /// layer and the guest would boot subtly wrong.
    pub fn blob(&mut self, digest: &str) -> Result<Vec<u8>, String> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            self.reference.registry, self.reference.repository, digest
        );
        let body = self.get_authed(&url, None)?;
        verify_digest(digest, &body)?;
        Ok(body)
    }
}

/// Check that `data` really is what `digest` claims.
pub fn verify_digest(digest: &str, data: &[u8]) -> Result<(), String> {
    let want = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("`{digest}` is not a sha256 digest"))?;
    let got = sha256_of(&SHA256, data);
    let got_hex: String = got.as_ref().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    if got_hex != want {
        return Err(format!(
            "content does not match its digest: expected sha256:{want}, got sha256:{got_hex}. \
             The download was corrupted or tampered with; nothing was unpacked."
        ));
    }
    Ok(())
}

/// Turn a registry error status into something a user can act on.
fn http_error(reference: &Reference, status: u32, body: &[u8]) -> String {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    let hint = match status {
        401 | 403 => " — the image may be private, and this build pulls anonymously",
        404 => " — check the name and tag",
        _ => "",
    };
    let short = if detail.len() > 200 {
        &detail[..200]
    } else {
        detail
    };
    format!("{} returned HTTP {status}{hint}: {short}", reference.display())
}

/// Split curl's `-D -` output into status, headers we care about, and body.
///
/// Handles the several header blocks a redirect chain produces by taking the
/// last one: `-L` follows the redirect, and the interesting status is the
/// final response, not the 307 that got us there.
fn split_headers_and_body(raw: &[u8]) -> Result<Response, String> {
    let mut rest = raw;
    let mut status;
    let mut www = None;
    loop {
        let end = find_header_end(rest).ok_or("no HTTP header block in curl output")?;
        let head = String::from_utf8_lossy(&rest[..end]).into_owned();
        let mut line_status = 0;
        for (i, line) in head.lines().enumerate() {
            if i == 0 {
                line_status = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("www-authenticate")
            {
                www = Some(v.trim().to_string());
            }
        }
        status = line_status;
        rest = &rest[end..];
        // A 1xx or a redirect is followed by another header block.
        if !starts_with_http(rest) {
            break;
        }
        www = None;
    }
    Ok(Response {
        status,
        body: rest.to_vec(),
        www_authenticate: www,
    })
}

fn starts_with_http(b: &[u8]) -> bool {
    b.starts_with(b"HTTP/")
}

/// Offset just past the blank line ending a header block, handling both CRLF
/// and bare LF.
fn find_header_end(b: &[u8]) -> Option<usize> {
    let crlf = b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
    let lf = b.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(c)) => Some(a.min(c)),
        (a, c) => a.or(c),
    }
}

/// Percent-escape a query-parameter value.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_docker_hub_challenge_is_parsed() {
        let h = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull""#;
        let c = parse_challenge(h).unwrap();
        assert_eq!(c.realm, "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:library/ubuntu:pull"));
    }

    /// GHCR omits `scope`, so a parser that required all three fields would
    /// fail on half the registries people use.
    #[test]
    fn a_challenge_without_scope_is_still_usable() {
        let h = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#;
        let c = parse_challenge(h).unwrap();
        assert_eq!(c.realm, "https://ghcr.io/token");
        assert_eq!(c.scope, None);
    }

    #[test]
    fn a_non_bearer_challenge_is_not_mistaken_for_one() {
        assert!(parse_challenge("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn an_index_is_told_apart_from_a_manifest() {
        assert!(is_index(&json!({"manifests": []})));
        assert!(!is_index(&json!({"layers": []})));
    }

    #[test]
    fn arm64_is_picked_out_of_a_multi_arch_index() {
        let idx = json!({"manifests": [
            {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}}
        ]});
        assert_eq!(pick_arm64(&idx).unwrap(), "sha256:arm");
    }

    /// `docker buildx` attaches attestation manifests with `unknown/unknown`.
    ///
    /// The skip does **not** change which manifest is selected — `unknown` can
    /// never equal `arm64`, so selection is safe without it. Its real job is
    /// the refusal message: a user told their image "offers unknown/unknown"
    /// is being pointed at a platform that does not exist. A mutation test
    /// proved the old assertion here could not fail, which made it a guard
    /// reporting safety it was not providing.
    #[test]
    fn attestation_manifests_are_skipped() {
        let idx = json!({"manifests": [
            {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}},
            {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}}
        ]});
        assert_eq!(pick_arm64(&idx).unwrap(), "sha256:arm");

        // The load-bearing half: an image with no arm64 build must not name a
        // platform the user could never have asked for.
        let amd_only = json!({"manifests": [
            {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}},
            {"digest": "sha256:a", "platform": {"os": "linux", "architecture": "amd64"}}
        ]});
        let e = pick_arm64(&amd_only).unwrap_err();
        assert!(e.contains("linux/amd64"), "{e}");
        assert!(!e.contains("unknown"), "offered a platform that is not one: {e}");
    }

    #[test]
    fn an_amd64_only_image_is_refused_by_name() {
        let idx = json!({"manifests": [
            {"digest": "sha256:a", "platform": {"os": "linux", "architecture": "amd64"}}
        ]});
        let e = pick_arm64(&idx).unwrap_err();
        assert!(e.contains("linux/amd64"), "{e}");
        assert!(e.contains("Apple Silicon"), "{e}");
    }

    #[test]
    fn an_arm64_variant_we_cannot_run_is_not_chosen() {
        let idx = json!({"manifests": [
            {"digest": "sha256:v7", "platform":
                {"os": "linux", "architecture": "arm", "variant": "v7"}}
        ]});
        assert!(pick_arm64(&idx).is_err());
    }

    #[test]
    fn layer_and_config_digests_are_read_in_order() {
        let m = json!({
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": "sha256:l1"}, {"digest": "sha256:l2"}]
        });
        let specs = layer_specs(&m).unwrap();
        assert_eq!(specs[0].digest, "sha256:l1");
        assert_eq!(specs[1].digest, "sha256:l2");
        assert_eq!(config_digest(&m).as_deref(), Some("sha256:cfg"));
    }

    /// A zstd layer must be named at pull time. Letting it reach the tar reader
    /// produces "unreadable size field", which reads as a corrupt download and
    /// sends the user looking in entirely the wrong place.
    #[test]
    fn a_zstd_layer_is_refused_by_name_before_it_is_parsed() {
        let m = json!({"layers": [
            {"digest": "sha256:z",
             "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd"}
        ]});
        let specs = layer_specs(&m).unwrap();
        let e = specs[0].readable().unwrap_err();
        assert!(e.contains("zstd"), "{e}");
        assert!(e.contains("Rebuild it with gzip"), "{e}");
    }

    #[test]
    fn an_ordinary_gzip_layer_is_readable() {
        let m = json!({"layers": [
            {"digest": "sha256:g",
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"}
        ]});
        layer_specs(&m).unwrap()[0].readable().unwrap();
    }

    #[test]
    fn entrypoint_and_cmd_combine_the_way_a_runtime_would() {
        let c = parse_config(&json!({"config": {
            "Entrypoint": ["/usr/bin/tini", "--"],
            "Cmd": ["node", "app.js"],
            "Env": ["PATH=/usr/bin"],
            "WorkingDir": "/srv"
        }}));
        assert_eq!(c.boot_command(), "/usr/bin/tini -- node app.js");
        assert_eq!(c.env, vec!["PATH=/usr/bin"]);
        assert_eq!(c.workdir.as_deref(), Some("/srv"));
    }

    /// An image with no entrypoint should give the user a shell, not nothing.
    #[test]
    fn an_image_with_no_command_falls_back_to_a_shell() {
        assert_eq!(parse_config(&json!({})).boot_command(), "/bin/sh");
    }

    #[test]
    fn a_digest_that_does_not_match_its_content_is_refused() {
        let data = b"hello";
        let real = ring::digest::digest(&ring::digest::SHA256, data);
        let hex: String = real.as_ref().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        verify_digest(&format!("sha256:{hex}"), data).unwrap();
        let e = verify_digest(&format!("sha256:{}", "0".repeat(64)), data).unwrap_err();
        assert!(e.contains("nothing was unpacked"), "{e}");
    }

    #[test]
    fn headers_and_body_are_split() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"a\":1}";
        let r = split_headers_and_body(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{\"a\":1}");
    }

    /// `-L` follows redirects, so curl emits several header blocks. The status
    /// that matters is the last one — treating the 307 as the answer would make
    /// every blob download look like a failure.
    #[test]
    fn a_redirect_chain_reports_the_final_status() {
        let raw = b"HTTP/1.1 307 Temporary Redirect\r\nlocation: https://s3/x\r\n\r\nHTTP/1.1 200 OK\r\n\r\nBODY";
        let r = split_headers_and_body(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"BODY");
    }

    #[test]
    fn a_401_challenge_survives_the_split() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer realm=\"https://auth/token\",service=\"reg\"\r\n\r\n";
        let r = split_headers_and_body(raw).unwrap();
        assert_eq!(r.status, 401);
        let c = parse_challenge(r.www_authenticate.as_deref().unwrap()).unwrap();
        assert_eq!(c.realm, "https://auth/token");
    }

    #[test]
    fn url_escaping_covers_the_characters_a_scope_contains() {
        assert_eq!(
            url_escape("repository:library/ubuntu:pull"),
            "repository%3Alibrary%2Fubuntu%3Apull"
        );
    }

    #[test]
    fn a_404_names_the_image_and_suggests_the_check() {
        let r = super::super::reference::parse("ghcr.io/a/b:v1").unwrap();
        let m = http_error(&r, 404, b"not found");
        assert!(m.contains("ghcr.io/a/b:v1"), "{m}");
        assert!(m.contains("check the name and tag"), "{m}");
    }
}
