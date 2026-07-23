// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Snapshot manifest signing + verification (M30.4).
//!
//! **Integrity** — does the bundle match its manifest? — is handled by
//! [`crate::control_plane`]'s `materialize_bundle`, which re-hashes every object
//! against the manifest `checksum_tree`. This module adds **authenticity**: proof
//! that the manifest *itself* came from a trusted signer, so a tampered bundle
//! whose `checksum_tree` was simply recomputed to match its altered contents is
//! rejected rather than trusted.
//!
//! ## The contract (the seam gimbal-cloud-control implements on the signing side)
//!
//! - The bundle ships a manifest document whose **raw bytes are the signed
//!   payload**. The signature covers the literal bytes, so signer and verifier
//!   need not agree on a canonical JSON encoding — a cross-language hazard this
//!   deliberately avoids.
//! - A **detached signature** accompanies it:
//!   `{ "alg": "ed25519", "key_id": "<id>", "sig": "<hex>" }`, an Ed25519
//!   signature over the manifest bytes.
//! - The verifier holds a **trust store**: `key_id -> ed25519 public key (hex)`,
//!   a map so keys can be **rotated** (add the new key id, keep the old until
//!   re-signed). Verification looks the key up by id, checks the signature over
//!   the manifest bytes, and only then does the caller trust `checksum_tree` and
//!   record provenance.
//!
//! Ed25519 is used via `ring` (already vendored for the memory-plane AES-GCM), so
//! this adds no new dependency. Keys and signatures are hex, matching the sha256
//! digests already used across the bundle format.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// The only signature algorithm the contract defines today.
pub const SIG_ALG: &str = "ed25519";
/// Ed25519 public keys are 32 bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The environment switch that turns on the fail-closed signing posture.
pub const REQUIRE_SIGNED_ENV: &str = "CHM_REQUIRE_SIGNED";

/// Whether the operator demands **fail-closed** authenticity enforcement on the
/// control-plane ingest path (M31.5). Setting [`REQUIRE_SIGNED_ENV`] flips two
/// defaults from advisory to mandatory:
///
///  1. **Signature is required.** A bundle that cannot be authenticated — no
///     trust root configured, or an unsigned / invalid manifest — is refused
///     rather than accepted unsigned.
///  2. **The policy-digest recompute is enforced.** A governed sandbox whose
///     policy document does not independently re-hash to its stated digest is
///     refused rather than merely logged.
///
/// Default (unset) preserves back-compat during the gctl signing rollout (#36):
/// unsigned bundles are still accepted, and a recompute drift is advisory. This
/// posture governs the **plane** paths only — a local `chm run <dir>` rehydrating
/// a stock snapshot never routes through it, so the rehydration dream is
/// unaffected. Presence-based to match the other `CHM_*` switches: any value
/// (e.g. `CHM_REQUIRE_SIGNED=1`) enables it; unset it to disable.
pub fn require_signed_posture() -> bool {
    env::var_os(REQUIRE_SIGNED_ENV).is_some()
}

/// Lowercase-hex encode a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode a hex string (either case). Returns `None` on odd length or a
/// non-hex character.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// A detached signature envelope accompanying a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedSignature {
    /// Signature algorithm; only [`SIG_ALG`] is accepted.
    pub alg: String,
    /// Which trusted key produced the signature (enables rotation).
    pub key_id: String,
    /// The signature bytes, hex-encoded.
    pub sig: String,
}

impl DetachedSignature {
    /// Parse a detached signature from its JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("parse signature: {e}"))
    }

    /// Serialize to canonical JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        // Field order is fixed by the struct; keys are ASCII, so this is stable.
        serde_json::to_vec(self).expect("serialize detached signature")
    }
}

/// A set of trusted Ed25519 public keys, keyed by key id so keys can be rotated.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    /// `key_id -> ed25519 public key`, hex (32 bytes).
    pub keys: BTreeMap<String, String>,
}

impl TrustStore {
    /// Load a trust store from a JSON file (`{ "keys": { "id": "<hex>" } }`).
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read(path).map_err(|e| format!("read trust store {}: {e}", path.display()))?;
        let store: TrustStore =
            serde_json::from_slice(&raw).map_err(|e| format!("parse trust store: {e}"))?;
        store.validate()?;
        Ok(store)
    }

    /// Reject malformed keys up front so verification failures are unambiguous.
    fn validate(&self) -> Result<(), String> {
        for (id, hex) in &self.keys {
            let bytes = from_hex(hex).ok_or_else(|| format!("trusted key {id:?} is not hex"))?;
            if bytes.len() != ED25519_PUBLIC_KEY_LEN {
                return Err(format!(
                    "trusted key {id:?} is {} bytes, expected {ED25519_PUBLIC_KEY_LEN}",
                    bytes.len()
                ));
            }
        }
        Ok(())
    }

    /// Whether the store holds no keys (i.e. no trust root is configured).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Add or replace a trusted key.
    pub fn insert_hex(&mut self, key_id: &str, pubkey_hex: &str) {
        self.keys.insert(key_id.to_string(), pubkey_hex.to_string());
    }

    /// Verify `sig` over `msg` using the trusted key named by `sig.key_id`.
    /// Errors on an unsupported algorithm, an unknown key id, a malformed key or
    /// signature, or a failed cryptographic check.
    pub fn verify(&self, msg: &[u8], sig: &DetachedSignature) -> Result<(), String> {
        if !sig.alg.eq_ignore_ascii_case(SIG_ALG) {
            return Err(format!("unsupported signature algorithm {:?}", sig.alg));
        }
        let pub_hex = self
            .keys
            .get(&sig.key_id)
            .ok_or_else(|| format!("no trusted key with id {:?} (rotation or wrong signer?)", sig.key_id))?;
        let pubkey = from_hex(pub_hex).ok_or("trusted public key is not hex")?;
        let sig_bytes = from_hex(&sig.sig).ok_or("signature is not hex")?;
        UnparsedPublicKey::new(&signature::ED25519, pubkey)
            .verify(msg, &sig_bytes)
            .map_err(|_| "manifest signature is invalid (not from this trusted key)".to_string())
    }
}

/// Generate a fresh Ed25519 keypair. Returns `(pkcs8 private key, public key
/// hex)`. Used by the local signer, tests, and as gctl's reference.
pub fn generate_keypair() -> Result<(Vec<u8>, String), String> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "Ed25519 keygen failed")?;
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "generated key did not parse".to_string())?;
    let pub_hex = to_hex(kp.public_key().as_ref());
    Ok((pkcs8.as_ref().to_vec(), pub_hex))
}

/// Sign `msg` with a pkcs8 Ed25519 private key, producing a detached signature
/// tagged with `key_id`.
pub fn sign(pkcs8: &[u8], key_id: &str, msg: &[u8]) -> Result<DetachedSignature, String> {
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| "invalid pkcs8 Ed25519 key")?;
    let sig = kp.sign(msg);
    Ok(DetachedSignature {
        alg: SIG_ALG.to_string(),
        key_id: key_id.to_string(),
        sig: to_hex(sig.as_ref()),
    })
}

// --- CLI: `chm manifest keygen|sign|verify` ---------------------------------
//
// A local signer + verifier: the reference implementation of the contract, so
// signing is testable end to end and gimbal-cloud-control has a concrete target
// to match. Verification here is the same code the ingest path uses.

/// The detached-signature filename convention: `<manifest>.sig`.
fn sig_path_for(manifest: &Path) -> PathBuf {
    let mut s = manifest.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

pub(crate) fn manifest_main(raw: &[String]) -> ExitCode {
    let result = match raw.first().map(String::as_str) {
        Some("keygen") => manifest_keygen(&raw[1..]),
        Some("sign") => manifest_sign(&raw[1..]),
        Some("verify") => manifest_verify(&raw[1..]),
        _ => {
            eprintln!(
                "usage: chm manifest <command>\n\
                 \n\
                 Sign and verify snapshot manifests (M30.4). The signature covers\n\
                 the manifest file's raw bytes; a detached `<manifest>.sig` holds\n\
                 the Ed25519 signature + signing key id.\n\
                 \n\
                 commands:\n    \
                   keygen --out <dir> [--id <key-id>]   generate an Ed25519 keypair\n                                        \
                    (writes <dir>/<id>.pkcs8 + a trust\n                                        \
                    store <dir>/<id>.trust.json)\n    \
                   sign <manifest.json> --key <pkcs8> --id <key-id>\n                                        \
                    write <manifest.json>.sig\n    \
                   verify <manifest.json> --trust <store.json> [--sig <file>]\n                                        \
                    verify the signature against a trust store"
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm manifest: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read a `--flag value` option from an argument list.
fn opt<'a>(raw: &'a [String], name: &str) -> Option<&'a str> {
    raw.iter()
        .position(|a| a == name)
        .and_then(|i| raw.get(i + 1))
        .map(String::as_str)
}

/// The first positional argument: one that is neither a `--flag` nor the value
/// immediately following a `--flag`.
fn first_positional(raw: &[String]) -> Option<&str> {
    let mut skip_value = false;
    for a in raw {
        if skip_value {
            skip_value = false;
            continue;
        }
        if a.starts_with("--") {
            skip_value = true;
            continue;
        }
        return Some(a.as_str());
    }
    None
}

fn manifest_keygen(raw: &[String]) -> Result<(), String> {
    let out = opt(raw, "--out").ok_or("usage: chm manifest keygen --out <dir> [--id <key-id>]")?;
    let key_id = opt(raw, "--id").unwrap_or("local-1");
    let dir = Path::new(out);
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let (pkcs8, pub_hex) = generate_keypair()?;
    let pkcs8_path = dir.join(format!("{key_id}.pkcs8"));
    fs::write(&pkcs8_path, &pkcs8).map_err(|e| format!("write {}: {e}", pkcs8_path.display()))?;
    // Lock the private key down to the owner.
    set_private_mode(&pkcs8_path);

    let mut store = TrustStore::default();
    store.insert_hex(key_id, &pub_hex);
    let store_path = dir.join(format!("{key_id}.trust.json"));
    let store_json =
        serde_json::to_vec_pretty(&store).map_err(|e| format!("serialize trust store: {e}"))?;
    fs::write(&store_path, store_json)
        .map_err(|e| format!("write {}: {e}", store_path.display()))?;

    println!("key id:       {key_id}");
    println!("private key:  {} (keep secret)", pkcs8_path.display());
    println!("public key:   {pub_hex}");
    println!("trust store:  {}", store_path.display());
    Ok(())
}

fn manifest_sign(raw: &[String]) -> Result<(), String> {
    let manifest = first_positional(raw)
        .ok_or("usage: chm manifest sign <manifest.json> --key <pkcs8> --id <key-id>")?;
    let key = opt(raw, "--key").ok_or("--key <pkcs8> is required")?;
    let key_id = opt(raw, "--id").ok_or("--id <key-id> is required")?;

    let manifest_path = Path::new(manifest);
    let bytes = fs::read(manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let pkcs8 = fs::read(key).map_err(|e| format!("read key {key}: {e}"))?;
    let sig = sign(&pkcs8, key_id, &bytes)?;
    let sig_path = sig_path_for(manifest_path);
    fs::write(&sig_path, sig.to_json())
        .map_err(|e| format!("write {}: {e}", sig_path.display()))?;
    println!("signed {} -> {} (key id {key_id})", manifest_path.display(), sig_path.display());
    Ok(())
}

fn manifest_verify(raw: &[String]) -> Result<(), String> {
    let manifest = first_positional(raw)
        .ok_or("usage: chm manifest verify <manifest.json> --trust <store.json> [--sig <file>]")?;
    let trust = opt(raw, "--trust").ok_or("--trust <store.json> is required")?;

    let manifest_path = Path::new(manifest);
    let bytes = fs::read(manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let sig_path = opt(raw, "--sig")
        .map_or_else(|| sig_path_for(manifest_path), PathBuf::from);
    let sig_bytes =
        fs::read(&sig_path).map_err(|e| format!("read signature {}: {e}", sig_path.display()))?;
    let sig = DetachedSignature::from_json(&sig_bytes)?;
    let store = TrustStore::load(Path::new(trust))?;
    store.verify(&bytes, &sig)?;
    println!(
        "OK: {} is authentic (signed by key id {})",
        manifest_path.display(),
        sig.key_id
    );
    Ok(())
}

/// Best-effort `chmod 600` on a freshly written private key.
fn set_private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_and_rejects_malformed() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa1, 0xff]), "000fa1ff");
        assert_eq!(from_hex("000fa1ff").unwrap(), vec![0x00, 0x0f, 0xa1, 0xff]);
        assert_eq!(from_hex("ABCDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
        assert!(from_hex("abc").is_none(), "odd length rejected");
        assert!(from_hex("zz").is_none(), "non-hex rejected");
    }

    fn store_with(key_id: &str, pub_hex: &str) -> TrustStore {
        let mut s = TrustStore::default();
        s.insert_hex(key_id, pub_hex);
        s
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let store = store_with("gctl-2026", &pub_hex);
        let msg = br#"{"version":1,"checksum_tree":{"state.json":"ab"}}"#;
        let sig = sign(&pkcs8, "gctl-2026", msg).unwrap();
        assert_eq!(sig.alg, SIG_ALG);
        store.verify(msg, &sig).expect("a valid signature verifies");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let store = store_with("k1", &pub_hex);
        let sig = sign(&pkcs8, "k1", b"original manifest").unwrap();
        store
            .verify(b"tampered manifest", &sig)
            .expect_err("a modified payload must fail verification");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (pkcs8_a, _pub_a) = generate_keypair().unwrap();
        let (_pkcs8_b, pub_b) = generate_keypair().unwrap();
        // Trust key B, but sign with key A's private key under B's id.
        let store = store_with("k", &pub_b);
        let sig = sign(&pkcs8_a, "k", b"payload").unwrap();
        store
            .verify(b"payload", &sig)
            .expect_err("a signature from an untrusted key must fail");
    }

    #[test]
    fn unknown_key_id_is_rejected() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let store = store_with("trusted-id", &pub_hex);
        let sig = sign(&pkcs8, "some-other-id", b"payload").unwrap();
        let err = store.verify(b"payload", &sig).unwrap_err();
        assert!(err.contains("no trusted key"), "got: {err}");
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let (_pkcs8, pub_hex) = generate_keypair().unwrap();
        let store = store_with("k", &pub_hex);
        let sig = DetachedSignature {
            alg: "rsa".into(),
            key_id: "k".into(),
            sig: "00".into(),
        };
        let err = store.verify(b"payload", &sig).unwrap_err();
        assert!(err.contains("unsupported signature algorithm"), "got: {err}");
    }

    #[test]
    fn trust_store_rejects_a_bad_key_length() {
        let mut s = TrustStore::default();
        s.insert_hex("short", "aabbcc"); // 3 bytes, not 32
        s.validate().expect_err("a wrong-length key must be rejected on load");
    }

    #[test]
    fn detached_signature_json_roundtrips() {
        let sig = DetachedSignature {
            alg: SIG_ALG.into(),
            key_id: "gctl-2026".into(),
            sig: "deadbeef".into(),
        };
        let json = sig.to_json();
        let back = DetachedSignature::from_json(&json).unwrap();
        assert_eq!(back.alg, sig.alg);
        assert_eq!(back.key_id, sig.key_id);
        assert_eq!(back.sig, sig.sig);
    }
}
