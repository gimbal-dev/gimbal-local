// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Working out what `ubuntu:24.04` actually means.
//!
//! Container references carry a great deal of defaulting that everyone has
//! internalised and nobody has written down in one place: a bare name means
//! Docker Hub, a single-segment name on Docker Hub means the `library/`
//! namespace, no tag means `:latest`, and the registry *hostname* is only the
//! first segment when that segment looks like a host (contains a dot or a
//! colon, or is exactly `localhost`) — which is why `ubuntu/nginx` is a Docker
//! Hub user's repository and `ghcr.io/nginx` is not.
//!
//! Getting this wrong produces a confusing 404 from a registry the user never
//! mentioned, so it is parsed here as a pure function with the cases written
//! out as tests.

/// Docker Hub's registry endpoint. Note it is *not* `docker.io`, which does not
/// serve the v2 API — a redirect nobody expects the first time.
pub const DOCKER_HUB: &str = "registry-1.docker.io";

/// A fully-resolved image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host, e.g. `registry-1.docker.io` or `ghcr.io`.
    pub registry: String,
    /// Repository path, e.g. `library/ubuntu`.
    pub repository: String,
    /// Either a tag (`24.04`) or a digest (`sha256:...`).
    pub reference: String,
    /// True when [`Self::reference`] is a content digest rather than a tag,
    /// which means the pull is reproducible and needs no tag resolution.
    pub by_digest: bool,
}

impl Reference {
    /// How the user would write this back out.
    pub fn display(&self) -> String {
        let sep = if self.by_digest { "@" } else { ":" };
        format!(
            "{}/{}{}{}",
            self.registry, self.repository, sep, self.reference
        )
    }
}

/// Does this look like a registry host rather than the first path segment of a
/// repository?
fn is_host(segment: &str) -> bool {
    segment == "localhost" || segment.contains('.') || segment.contains(':')
}

/// Parse a reference, applying the defaults everyone assumes.
pub fn parse(input: &str) -> Result<Reference, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("empty image reference".to_string());
    }

    // Split the digest first: a digest contains ':' and would otherwise be
    // mistaken for a tag or a port.
    let (name_and_tag, digest) = match input.split_once('@') {
        Some((n, d)) => (n, Some(d.to_string())),
        None => (input, None),
    };

    let (registry, remainder) = match name_and_tag.split_once('/') {
        Some((first, rest)) if is_host(first) => (first.to_string(), rest.to_string()),
        _ => (DOCKER_HUB.to_string(), name_and_tag.to_string()),
    };

    let (repository, tag) = if digest.is_some() {
        (remainder, None)
    } else {
        // A ':' after the last '/' is a tag. Before it, it would be a port,
        // but the port lives in the registry we already split off.
        match remainder.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), Some(t.to_string())),
            _ => (remainder, None),
        }
    };

    if repository.is_empty() {
        return Err(format!("`{input}` has no repository name"));
    }

    // Docker Hub puts official images in `library/`.
    let repository = if registry == DOCKER_HUB && !repository.contains('/') {
        format!("library/{repository}")
    } else {
        repository
    };

    let (reference, by_digest) = match digest {
        Some(d) => {
            if !d.starts_with("sha256:") || d.len() != "sha256:".len() + 64 {
                return Err(format!(
                    "`{d}` is not a sha256 digest (expected `sha256:` and 64 hex characters)"
                ));
            }
            (d, true)
        }
        None => (tag.unwrap_or_else(|| "latest".to_string()), false),
    };

    Ok(Reference {
        registry,
        repository,
        reference,
        by_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_means_docker_hub_library_latest() {
        let r = parse("ubuntu").unwrap();
        assert_eq!(r.registry, DOCKER_HUB);
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.reference, "latest");
        assert!(!r.by_digest);
    }

    #[test]
    fn a_tag_is_honoured() {
        let r = parse("ubuntu:24.04").unwrap();
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.reference, "24.04");
    }

    /// The rule that surprises people: a first segment without a dot is a
    /// Docker Hub *user*, not a registry.
    #[test]
    fn a_dotless_first_segment_is_a_user_not_a_registry() {
        let r = parse("bitnami/nginx:1.25").unwrap();
        assert_eq!(r.registry, DOCKER_HUB);
        assert_eq!(r.repository, "bitnami/nginx");
        assert_eq!(r.reference, "1.25");
    }

    #[test]
    fn a_dotted_first_segment_is_a_registry() {
        let r = parse("ghcr.io/nebuk89/thing:v2").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "nebuk89/thing");
        assert_eq!(r.reference, "v2");
    }

    #[test]
    fn localhost_and_a_port_are_registries() {
        assert_eq!(parse("localhost/x").unwrap().registry, "localhost");
        assert_eq!(
            parse("localhost:5000/x:t").unwrap().registry,
            "localhost:5000"
        );
        assert_eq!(parse("localhost:5000/x:t").unwrap().repository, "x");
        assert_eq!(parse("localhost:5000/x:t").unwrap().reference, "t");
    }

    /// A port in the registry must not be mistaken for a tag, and a tag must
    /// not be mistaken for a port.
    #[test]
    fn a_registry_port_is_not_a_tag() {
        let r = parse("reg.example.com:5000/team/app").unwrap();
        assert_eq!(r.registry, "reg.example.com:5000");
        assert_eq!(r.repository, "team/app");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn a_digest_reference_is_recognised_and_validated() {
        let d = format!("sha256:{}", "a".repeat(64));
        let r = parse(&format!("ubuntu@{d}")).unwrap();
        assert!(r.by_digest);
        assert_eq!(r.reference, d);

        assert!(parse("ubuntu@sha256:short").is_err());
        assert!(parse("ubuntu@md5:abc").is_err());
    }

    #[test]
    fn an_empty_reference_is_refused() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for s in ["ubuntu:24.04", "ghcr.io/a/b:v1", "localhost:5000/x:t"] {
            let a = parse(s).unwrap();
            let b = parse(&a.display()).unwrap();
            assert_eq!(a, b, "{s}");
        }
    }
}
