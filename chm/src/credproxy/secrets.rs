// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! Where a credential comes from.
//!
//! The most valuable source here is [`SecretSource::Exec`]. It runs a command to
//! mint a credential at the moment a request to a matching destination actually
//! shows up, which is what removes the standing token from the system entirely:
//! if the job never calls the host, no credential is ever created, so there is
//! no window in which one is sitting around waiting to be stolen.
//!
//! Everything in this module goes out of its way not to let a secret escape by
//! accident — `Secret` redacts itself in `Debug` output, and it is never included
//! in an error message, a log line, or an audit record.

use std::path::PathBuf;
use std::process::Command;
use std::ptr::write_volatile;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fmt, fs};

/// A resolved credential.
///
/// The redacting `Debug` is the point: this type ends up inside `Rule`, which is
/// cloned, logged, and carried through the proxy, and a derived `Debug` anywhere
/// in that chain would print the secret.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl Drop for Secret {
    /// Best-effort scrub of the backing buffer.
    ///
    /// This cannot promise the value is gone — a `String` may have been copied
    /// when it grew, and the allocator may not return the page — but it removes
    /// the trivially recoverable copy, and it costs nothing.
    fn drop(&mut self) {
        // SAFETY: overwriting the bytes of a `String` we own and are about to
        // drop. The buffer stays valid UTF-8 (spaces) for the duration.
        unsafe {
            for b in self.0.as_bytes_mut() {
                write_volatile(b, 0x20);
            }
        }
    }
}

/// Where the proxy gets the credential for a rule.
#[derive(Clone)]
pub(crate) enum SecretSource {
    /// Read from an environment variable of the `chm` process.
    ///
    /// Simplest, and the right thing for a value the operator already holds. The
    /// variable is read from the proxy's own environment, which the guest has no
    /// access to.
    Env { name: String },
    /// Read from a file on the host.
    File { path: PathBuf },
    /// Run a command and take its standard output as the credential.
    ///
    /// This is the on-demand minting path. `ttl` bounds how long a minted value
    /// is reused before the command is run again.
    Exec {
        command: Vec<String>,
        ttl: Duration,
        cache: Arc<Mutex<Option<(Secret, Instant)>>>,
    },
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Describes the source without ever touching the value.
        f.write_str(&self.describe())
    }
}

impl SecretSource {
    /// Builds a source from the mutually exclusive fields of a rule document.
    pub(crate) fn from_doc(
        env: &Option<String>,
        file: &Option<String>,
        exec: &Option<Vec<String>>,
        ttl_secs: Option<u64>,
    ) -> Result<Self, String> {
        let present = [env.is_some(), file.is_some(), exec.is_some()]
            .iter()
            .filter(|p| **p)
            .count();
        if present == 0 {
            return Err("needs a secret source: one of 'env', 'file', or 'exec'".into());
        }
        if present > 1 {
            return Err(
                "has more than one secret source; use exactly one of 'env', 'file', or 'exec'"
                    .into(),
            );
        }
        if ttl_secs.is_some() && exec.is_none() {
            return Err("'ttl_secs' only applies to an 'exec' secret".into());
        }

        if let Some(name) = env {
            if name.trim().is_empty() {
                return Err("'env' is empty".into());
            }
            return Ok(SecretSource::Env { name: name.clone() });
        }
        if let Some(path) = file {
            if path.trim().is_empty() {
                return Err("'file' is empty".into());
            }
            return Ok(SecretSource::File {
                path: PathBuf::from(path),
            });
        }
        let command = exec.clone().unwrap_or_default();
        if command.is_empty() {
            return Err("'exec' is an empty command".into());
        }
        Ok(SecretSource::Exec {
            command,
            ttl: Duration::from_secs(ttl_secs.unwrap_or(300)),
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// A human description that never contains the secret itself.
    pub(crate) fn describe(&self) -> String {
        match self {
            SecretSource::Env { name } => format!("env:{name}"),
            SecretSource::File { path } => format!("file:{}", path.display()),
            SecretSource::Exec { command, ttl, .. } => {
                format!("exec:{} (ttl {}s)", command[0], ttl.as_secs())
            }
        }
    }

    /// Whether this source can produce a credential right now.
    ///
    /// Used by `chm proxy show` so an operator can see a missing token before a
    /// job fails on it, without printing the value.
    pub(crate) fn availability(&self) -> Availability {
        match self {
            SecretSource::Env { name } => match env::var(name) {
                Ok(v) if !v.trim().is_empty() => Availability::Present,
                Ok(_) => Availability::Empty,
                Err(_) => Availability::Missing,
            },
            SecretSource::File { path } => match fs::read_to_string(path) {
                Ok(v) if !v.trim().is_empty() => Availability::Present,
                Ok(_) => Availability::Empty,
                Err(_) => Availability::Missing,
            },
            // Deliberately not run. Probing a mint-on-demand source would create
            // exactly the standing credential this design avoids.
            SecretSource::Exec { .. } => Availability::OnDemand,
        }
    }

    /// Produces the credential.
    pub(crate) fn resolve(&self) -> Result<Secret, String> {
        let secret = match self {
            SecretSource::Env { name } => {
                let raw = env::var(name)
                    .map_err(|_| format!("environment variable {name} is not set"))?;
                Secret::new(raw.trim())
            }
            SecretSource::File { path } => {
                let raw = fs::read_to_string(path)
                    .map_err(|e| format!("could not read {}: {e}", path.display()))?;
                Secret::new(raw.trim())
            }
            SecretSource::Exec {
                command,
                ttl,
                cache,
            } => return self.resolve_exec(command, *ttl, cache),
        };
        if secret.is_empty() {
            return Err(format!("{} produced an empty credential", self.describe()));
        }
        Ok(secret)
    }

    fn resolve_exec(
        &self,
        command: &[String],
        ttl: Duration,
        cache: &Arc<Mutex<Option<(Secret, Instant)>>>,
    ) -> Result<Secret, String> {
        let now = Instant::now();
        {
            let held = cache.lock().expect("secret cache");
            if let Some((secret, minted)) = held.as_ref()
                && now.duration_since(*minted) < ttl
            {
                return Ok(secret.clone());
            }
        }

        let output = Command::new(&command[0])
            .args(&command[1..])
            .output()
            .map_err(|e| format!("could not run {}: {e}", command[0]))?;
        if !output.status.success() {
            // stderr can legitimately explain the failure, but it can also echo
            // the credential, so only the exit status is surfaced.
            return Err(format!(
                "{} exited with {} while minting a credential",
                command[0], output.status
            ));
        }
        let value = String::from_utf8(output.stdout)
            .map_err(|_| format!("{} produced non-UTF-8 output", command[0]))?;
        let secret = Secret::new(value.trim());
        if secret.is_empty() {
            return Err(format!("{} produced an empty credential", command[0]));
        }

        *cache.lock().expect("secret cache") = Some((secret.clone(), now));
        Ok(secret)
    }
}

/// Whether a credential is ready, without revealing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Availability {
    Present,
    Empty,
    Missing,
    OnDemand,
}

impl Availability {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Availability::Present => "present",
            Availability::Empty => "empty",
            Availability::Missing => "missing",
            Availability::OnDemand => "on-demand",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_redact_themselves_in_debug_output() {
        let s = Secret::new("ghp_averyrealtoken");
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains("ghp_"),
            "Debug leaked the secret: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn a_source_describes_itself_without_the_value() {
        let src = SecretSource::from_doc(&Some("MY_TOKEN".into()), &None, &None, None).unwrap();
        assert_eq!(format!("{src:?}"), "env:MY_TOKEN");
    }

    #[test]
    fn exactly_one_source_is_required() {
        let none = SecretSource::from_doc(&None, &None, &None, None).unwrap_err();
        assert!(none.contains("needs a secret source"), "{none}");

        let both =
            SecretSource::from_doc(&Some("A".into()), &Some("/b".into()), &None, None).unwrap_err();
        assert!(both.contains("more than one"), "{both}");
    }

    #[test]
    fn ttl_without_exec_is_a_config_error() {
        let err = SecretSource::from_doc(&Some("A".into()), &None, &None, Some(60)).unwrap_err();
        assert!(err.contains("only applies to an 'exec'"), "{err}");
    }

    #[test]
    fn a_file_secret_is_read_and_trimmed() {
        let path = std::env::temp_dir().join(format!("chm-secret-{}", std::process::id()));
        fs::write(&path, "  tok-from-file\n").unwrap();
        let src = SecretSource::from_doc(
            &None,
            &Some(path.to_string_lossy().to_string()),
            &None,
            None,
        )
        .unwrap();
        assert_eq!(src.availability(), Availability::Present);
        assert_eq!(src.resolve().unwrap().expose(), "tok-from-file");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_reports_missing_rather_than_panicking() {
        let src =
            SecretSource::from_doc(&None, &Some("/nonexistent/chm/secret".into()), &None, None)
                .unwrap();
        assert_eq!(src.availability(), Availability::Missing);
        assert!(src.resolve().is_err());
    }

    #[test]
    fn exec_mints_on_demand_and_then_reuses_within_its_ttl() {
        // A command whose output changes every call, so a second identical value
        // proves the cache was used rather than the command re-run.
        let src = SecretSource::from_doc(
            &None,
            &None,
            &Some(vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()]),
            Some(300),
        )
        .unwrap();

        // Not run until something asks for it.
        assert_eq!(src.availability(), Availability::OnDemand);

        let first = src.resolve().expect("mint");
        let second = src.resolve().expect("mint again");
        assert_eq!(first.expose(), second.expose(), "should have been cached");
        assert!(!first.expose().is_empty());
    }

    #[test]
    fn an_expired_exec_secret_is_minted_again() {
        let src = SecretSource::from_doc(
            &None,
            &None,
            &Some(vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()]),
            Some(0),
        )
        .unwrap();
        let first = src.resolve().expect("mint");
        std::thread::sleep(Duration::from_millis(5));
        let second = src.resolve().expect("mint again");
        assert_ne!(
            first.expose(),
            second.expose(),
            "a zero TTL must re-mint every time"
        );
    }

    #[test]
    fn a_failing_mint_command_does_not_leak_its_stderr() {
        let src = SecretSource::from_doc(
            &None,
            &None,
            &Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo ghp_leaked >&2; exit 3".into(),
            ]),
            None,
        )
        .unwrap();
        let err = src.resolve().unwrap_err();
        assert!(!err.contains("ghp_leaked"), "error leaked stderr: {err}");
        assert!(err.contains("exited with"), "{err}");
    }

    #[test]
    fn an_empty_credential_is_an_error_not_an_empty_header() {
        let src = SecretSource::from_doc(
            &None,
            &None,
            &Some(vec!["/bin/sh".into(), "-c".into(), "echo ''".into()]),
            None,
        )
        .unwrap();
        assert!(src.resolve().unwrap_err().contains("empty credential"));
    }
}
