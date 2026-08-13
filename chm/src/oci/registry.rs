// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

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

use std::fmt;
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
/// A platform to select from a multi-architecture image index.
///
/// `variant` is `None` when the caller did not name one, which is not the same
/// as `Some("")`: an unnamed variant matches any entry, while a named one must
/// match exactly. That distinction is the whole reason this type exists —
/// selecting on `os`/`architecture` alone cannot tell `linux/arm64/v8` from
/// `linux/arm64/v9`, so an image publishing both is unaddressable (#207).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub variant: Option<String>,
}

impl Platform {
    /// The default: what this host can actually boot.
    pub fn host() -> Self {
        Self {
            os: WANT_OS.to_string(),
            arch: WANT_ARCH.to_string(),
            variant: None,
        }
    }

    /// Does an index entry's `platform` object satisfy this request?
    fn matches(&self, os: &str, arch: &str, variant: &str) -> bool {
        if os != self.os || arch != self.arch {
            return false;
        }
        match self.variant.as_deref() {
            // The caller named a variant: it must match exactly.
            Some(want) => variant == want,
            // The caller did not. Accept an unspecified variant (the common and
            // correct case) and v8, which is what an Apple Silicon Mac runs.
            // A v9-only image is deliberately *not* taken by default -- it is
            // reachable with `--platform linux/arm64/v9`, which is a choice the
            // operator makes rather than one made silently on their behalf.
            None => variant.is_empty() || variant == "v8",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// Parse an `os/arch[/variant]` platform string, refusing one this host cannot
/// boot.
///
/// **The refusal is the point.** Accepting `linux/amd64` here would pull real
/// layers, unpack a real rootfs and write a real image directory — and produce
/// something that can never boot on Apple Silicon. A flag whose job is to make
/// the platform explicit must not be the flag that quietly builds an artifact
/// the tool cannot run; that is the exact false-sell shape this codebase keeps
/// finding. So the check happens before a single byte is fetched.
pub fn parse_platform(s: &str) -> Result<Platform, String> {
    let parts: Vec<&str> = s.split('/').collect();
    let (os, arch, variant) = match parts.as_slice() {
        [os, arch] => (*os, *arch, None),
        [os, arch, variant] => (*os, *arch, Some((*variant).to_string())),
        _ => {
            return Err(format!(
                "`{s}` is not a platform. Expected `os/arch` or `os/arch/variant`, \
                 for example `{WANT_OS}/{WANT_ARCH}` or `{WANT_OS}/{WANT_ARCH}/v8`."
            ));
        }
    };
    if os.is_empty() || arch.is_empty() || variant.as_deref() == Some("") {
        return Err(format!(
            "`{s}` has an empty component. Expected `os/arch` or `os/arch/variant`."
        ));
    }
    if os != WANT_OS || arch != WANT_ARCH {
        return Err(format!(
            "`{s}` cannot boot here. This is an Apple Silicon host running Linux \
             guests under Hypervisor.framework, so the only platform it can start \
             is {WANT_OS}/{WANT_ARCH}. Building a {os}/{arch} image would produce a \
             directory that looks complete and can never run."
        ));
    }
    Ok(Platform {
        os: os.to_string(),
        arch: arch.to_string(),
        variant,
    })
}

/// Pick the manifest digest for `want` out of a multi-architecture index.
pub fn pick_platform(index: &Value, want: &Platform) -> Result<String, String> {
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
            let variant = plat
                .and_then(|p| p.get("variant"))
                .and_then(Value::as_str)
                .unwrap_or("");
            offered.push(if variant.is_empty() {
                format!("{o}/{a}")
            } else {
                format!("{o}/{a}/{variant}")
            });
            if want.matches(o, a, variant) {
                return m
                    .get("digest")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("the {want} entry has no digest"));
            }
        }
    }
    Err(format!(
        "this image has no {want} build (it offers {}). \
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
    /// Refusing by name at pull time is the difference between a remedy the
    /// user can act on and a tar parse error that reads like corruption.
    ///
    /// zstd used to be refused here. It is read now (#206), and deliberately
    /// **not** by trusting this media type — see `read_blob`, which sniffs the
    /// magic bytes instead, because registries mislabel layers often enough
    /// that the declared type is a hint rather than a fact.
    pub fn readable(&self) -> Result<(), String> {
        let m = &self.media_type;
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

    /// Fetch the manifest, following a multi-architecture index to `want`.
    pub fn manifest(&mut self, want: &Platform) -> Result<Value, String> {
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
        let digest = pick_platform(&v, want)?;
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reference.registry, self.reference.repository, digest
        );
        let body = self.get_authed(&url, Some(ACCEPT))?;
        serde_json::from_slice(&body).map_err(|e| format!("the {want} manifest was not JSON: {e}"))
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
        assert_eq!(
            pick_platform(&idx, &Platform::host()).unwrap(),
            "sha256:arm"
        );
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
        assert_eq!(
            pick_platform(&idx, &Platform::host()).unwrap(),
            "sha256:arm"
        );

        // The load-bearing half: an image with no arm64 build must not name a
        // platform the user could never have asked for.
        let amd_only = json!({"manifests": [
            {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}},
            {"digest": "sha256:a", "platform": {"os": "linux", "architecture": "amd64"}}
        ]});
        let e = pick_platform(&amd_only, &Platform::host()).unwrap_err();
        assert!(e.contains("linux/amd64"), "{e}");
        assert!(!e.contains("unknown"), "offered a platform that is not one: {e}");
    }

    #[test]
    fn an_amd64_only_image_is_refused_by_name() {
        let idx = json!({"manifests": [
            {"digest": "sha256:a", "platform": {"os": "linux", "architecture": "amd64"}}
        ]});
        let e = pick_platform(&idx, &Platform::host()).unwrap_err();
        assert!(e.contains("linux/amd64"), "{e}");
        assert!(e.contains("Apple Silicon"), "{e}");
    }

    #[test]
    fn an_arm64_variant_we_cannot_run_is_not_chosen() {
        let idx = json!({"manifests": [
            {"digest": "sha256:v7", "platform":
                {"os": "linux", "architecture": "arm", "variant": "v7"}}
        ]});
        assert!(pick_platform(&idx, &Platform::host()).is_err());
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

    /// zstd layers are read now (#206), so the pull-time refusal that used to
    /// name them must be gone -- otherwise the codec support is unreachable and
    /// the feature is a false sell.
    ///
    /// Note what is *not* asserted here: that `readable()` recognises zstd. It
    /// deliberately does not care. The declared `mediaType` is a hint -- this
    /// registry client already sniffs gzip magic rather than trusting it,
    /// because layers are mislabelled often -- so the codec decision lives in
    /// `read_blob` where the bytes are, and this only has to stop refusing.
    #[test]
    fn a_zstd_layer_is_no_longer_refused_at_pull_time() {
        for mt in [
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.docker.image.rootfs.diff.tar.zstd",
        ] {
            let m = json!({"layers": [{"digest": "sha256:z", "mediaType": mt}]});
            layer_specs(&m).unwrap()[0]
                .readable()
                .unwrap_or_else(|e| panic!("`{mt}` must be pullable now: {e}"));
        }
    }

    /// A foreign layer is still refused, so the change above narrowed the
    /// refusal rather than deleting it.
    #[test]
    fn a_foreign_layer_is_still_refused_by_name() {
        let m = json!({"layers": [
            {"digest": "sha256:f",
             "mediaType": "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"}
        ]});
        let e = layer_specs(&m).unwrap()[0].readable().unwrap_err();
        assert!(e.contains("foreign"), "{e}");
        assert!(e.contains("Windows base image"), "{e}");
    }

    /// `--platform` exists to make the choice explicit; it must not become the
    /// flag that quietly builds an artifact this host can never boot.
    #[test]
    fn a_platform_this_host_cannot_boot_is_refused_before_anything_is_fetched() {
        for bad in [
            "linux/amd64",
            "windows/arm64",
            "linux/riscv64",
            "darwin/arm64",
        ] {
            let e = parse_platform(bad).unwrap_err();
            assert!(
                e.contains("cannot boot here") && e.contains("linux/arm64"),
                "`{bad}` must be refused with the reason and the supported value, got: {e}"
            );
        }
    }

    #[test]
    fn a_platform_that_is_not_a_platform_says_what_the_shape_is() {
        for bad in [
            "arm64",
            "",
            "linux/arm64/v8/extra",
            "linux/",
            "/arm64",
            "linux/arm64/",
        ] {
            let e = parse_platform(bad).unwrap_err();
            assert!(
                e.contains("os/arch"),
                "`{bad}` must be refused with the expected shape, got: {e}"
            );
        }
    }

    /// The point of the flag: an image publishing several arm64 variants is
    /// addressable, and a named variant must match *exactly* rather than
    /// falling back to the default's v8-or-unspecified rule.
    #[test]
    fn a_named_variant_selects_that_variant_and_only_that_variant() {
        let idx = json!({"manifests": [
            {"digest": "sha256:v8",
             "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
            {"digest": "sha256:v9",
             "platform": {"os": "linux", "architecture": "arm64", "variant": "v9"}}
        ]});
        let v9 = parse_platform("linux/arm64/v9").unwrap();
        assert_eq!(pick_platform(&idx, &v9).unwrap(), "sha256:v9");
        let v8 = parse_platform("linux/arm64/v8").unwrap();
        assert_eq!(pick_platform(&idx, &v8).unwrap(), "sha256:v8");

        // Without a variant the default takes v8 and leaves v9 alone: running
        // ARMv9 code is a choice the operator makes, not one made for them.
        assert_eq!(pick_platform(&idx, &Platform::host()).unwrap(), "sha256:v8");
    }

    /// A variant that is not offered must be refused by name, and the refusal
    /// must list variants -- saying an image "offers linux/arm64" when the ask
    /// was `linux/arm64/v9` is a message that reads like a bug in the tool.
    #[test]
    fn an_unavailable_variant_is_refused_listing_the_variants_that_exist() {
        let idx = json!({"manifests": [
            {"digest": "sha256:v8",
             "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}}
        ]});
        let v9 = parse_platform("linux/arm64/v9").unwrap();
        let e = pick_platform(&idx, &v9).unwrap_err();
        assert!(e.contains("no linux/arm64/v9 build"), "{e}");
        assert!(
            e.contains("linux/arm64/v8"),
            "the offer list must name variants: {e}"
        );
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
