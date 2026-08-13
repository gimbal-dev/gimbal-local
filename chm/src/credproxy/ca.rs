// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! The proxy's certificate authority.
//!
//! To attach a credential to an outbound HTTPS request the proxy has to see the
//! request head, which means terminating TLS for that destination. That in turn
//! means the guest must trust a CA the proxy controls.
//!
//! Two properties keep that from being a blanket "trust everything" grant:
//!
//! * The CA is per-workspace and generated locally. It is not a shared secret
//!   across machines, and it never leaves the host.
//! * Interception is opt-in per host. A destination with no injection rule is
//!   relayed as opaque bytes and its TLS session is end-to-end between the guest
//!   and the origin — the proxy never mints a certificate for it and could not
//!   read it if it wanted to.
//!
//! See `docs/credential-proxy.md` for the full argument.

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

use super::der::{self, oids};

/// How long a minted leaf certificate is valid.
///
/// Short, because leaves are cheap to mint and are re-minted on demand. There is
/// no revocation path for them, so a short life is the only expiry control.
const LEAF_VALIDITY_SECS: i64 = 7 * 24 * 60 * 60;

/// How long the CA itself is valid. Long enough not to be an operational
/// nuisance, short enough that a workspace does not carry a decade-old key.
const CA_VALIDITY_SECS: i64 = 2 * 365 * 24 * 60 * 60;

/// Clock skew allowance on `notBefore`, so a guest whose clock is slightly
/// behind the host does not reject a freshly minted certificate.
const BACKDATE_SECS: i64 = 3600;

const CA_KEY_FILE: &str = "proxy-ca.key";
const CA_CERT_FILE: &str = "proxy-ca.crt";

/// A minted server certificate and the private key that goes with it.
#[derive(Clone)]
pub(crate) struct Leaf {
    /// The leaf certificate, DER.
    pub(crate) cert_der: Vec<u8>,
    /// The leaf private key, PKCS#8 DER.
    pub(crate) key_pkcs8: Vec<u8>,
    /// The issuing CA certificate, DER. Sent alongside the leaf so a guest that
    /// has the CA by name can still build the chain.
    pub(crate) ca_der: Vec<u8>,
}

/// The workspace-local certificate authority used for intercepted destinations.
pub(crate) struct ProxyCa {
    key_pkcs8: Vec<u8>,
    cert_der: Vec<u8>,
    /// The CA's `Name`, reused verbatim as each leaf's issuer.
    subject_der: Vec<u8>,
    /// The CA's subject key identifier, which becomes each leaf's authority key
    /// identifier so guest TLS stacks can build the chain by key rather than
    /// relying on name matching alone.
    ski: Vec<u8>,
    leaves: Mutex<HashMap<String, Arc<Leaf>>>,
    rng: SystemRandom,
}

impl ProxyCa {
    /// Loads the workspace CA, generating it on first use.
    ///
    /// The key is written `0600` and the directory `0700`. A CA that anyone on
    /// the host can read is a CA that can impersonate every intercepted host to
    /// the guest, so this is enforced rather than assumed: an existing key with
    /// looser permissions is tightened on load.
    pub(crate) fn load_or_create(dir: &Path) -> io::Result<Arc<Self>> {
        fs::create_dir_all(dir)?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);

        if key_path.exists() && cert_path.exists() {
            let key = fs::read(&key_path)?;
            let pem = fs::read_to_string(&cert_path)?;
            let cert = pem_decode(&pem, "CERTIFICATE")
                .ok_or_else(|| bad(format!("{} is not a PEM certificate", cert_path.display())))?;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
            return Self::from_parts(key, cert);
        }

        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| bad("could not generate a CA key"))?
            .as_ref()
            .to_vec();
        let pair = keypair(&key, &rng)?;
        let cert = self_signed_ca(&pair, &rng)?;

        write_private(&key_path, &key)?;
        fs::write(&cert_path, pem_encode(&cert, "CERTIFICATE"))?;

        Self::from_parts(key, cert)
    }

    /// Loads the workspace CA if it already exists, without creating one.
    ///
    /// Separate from [`Self::load_or_create`] because a caller that only wants
    /// to *report* the CA — "what will the guest have to trust?" — must not
    /// bring a trust anchor into existence as a side effect of asking, least of
    /// all in a directory it does not own.
    pub(crate) fn load_existing(dir: &Path) -> io::Result<Option<Arc<Self>>> {
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);
        if !key_path.exists() || !cert_path.exists() {
            return Ok(None);
        }
        let key = fs::read(&key_path)?;
        let pem = fs::read_to_string(&cert_path)?;
        let cert = pem_decode(&pem, "CERTIFICATE")
            .ok_or_else(|| bad(format!("{} is not a PEM certificate", cert_path.display())))?;
        Self::from_parts(key, cert).map(Some)
    }

    /// Builds an in-memory CA that is never written to disk.
    ///
    /// Used by tests, and by `chm proxy test`, so exercising the proxy never
    /// leaves a stray trust anchor behind.
    pub(crate) fn ephemeral() -> io::Result<Arc<Self>> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| bad("could not generate a CA key"))?
            .as_ref()
            .to_vec();
        let pair = keypair(&key, &rng)?;
        let cert = self_signed_ca(&pair, &rng)?;
        Self::from_parts(key, cert)
    }

    fn from_parts(key_pkcs8: Vec<u8>, cert_der: Vec<u8>) -> io::Result<Arc<Self>> {
        let rng = SystemRandom::new();
        let pair = keypair(&key_pkcs8, &rng)?;
        let ski = key_id(pair.public_key().as_ref());
        Ok(Arc::new(Self {
            key_pkcs8,
            subject_der: ca_name(),
            cert_der,
            ski,
            leaves: Mutex::new(HashMap::new()),
            rng,
        }))
    }

    /// The CA certificate in DER form.
    pub(crate) fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The CA certificate as PEM, for installing into a guest trust store.
    pub(crate) fn cert_pem(&self) -> String {
        pem_encode(&self.cert_der, "CERTIFICATE")
    }

    /// The CA's SHA-256 fingerprint, for display and for the audit log.
    ///
    /// The full digest, not a prefix: this is the value a user compares against
    /// `openssl x509 -fingerprint -sha256` inside the guest to confirm they
    /// installed the certificate this proxy is actually using, and a truncated
    /// one cannot be compared without knowing it was truncated.
    pub(crate) fn fingerprint(&self) -> String {
        digest(&SHA256, &self.cert_der)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Returns a server certificate for `host`, minting and caching one if this
    /// is the first request for that destination.
    pub(crate) fn leaf_for(&self, host: &str) -> io::Result<Arc<Leaf>> {
        let key = host.to_ascii_lowercase();
        if let Some(hit) = self.leaves.lock().expect("leaf cache").get(&key) {
            return Ok(Arc::clone(hit));
        }

        let leaf_key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.rng)
            .map_err(|_| bad("could not generate a leaf key"))?
            .as_ref()
            .to_vec();
        let leaf_pair = keypair(&leaf_key, &self.rng)?;
        let ca_pair = keypair(&self.key_pkcs8, &self.rng)?;

        let cert_der = self.sign_leaf(&key, leaf_pair.public_key().as_ref(), &ca_pair)?;
        let leaf = Arc::new(Leaf {
            cert_der,
            key_pkcs8: leaf_key,
            ca_der: self.cert_der.clone(),
        });

        self.leaves
            .lock()
            .expect("leaf cache")
            .insert(key, Arc::clone(&leaf));
        Ok(leaf)
    }

    fn sign_leaf(
        &self,
        host: &str,
        leaf_public: &[u8],
        ca_pair: &EcdsaKeyPair,
    ) -> io::Result<Vec<u8>> {
        let now = unix_now();
        let tbs = der::seq(&[
            der::explicit(0, &der::uint_small(2)), // v3
            der::uint(&random_serial(&self.rng)?),
            sig_alg(),
            self.subject_der.clone(),
            validity(now - BACKDATE_SECS, now + LEAF_VALIDITY_SECS),
            subject_cn(host),
            spki(leaf_public),
            der::explicit(
                3,
                &der::seq(&[
                    extension(oids::BASIC_CONSTRAINTS, true, &der::seq(&[])),
                    // digitalSignature only: bit 0, so seven unused trailing bits.
                    extension(oids::KEY_USAGE, true, &der::bit_string_bits(7, &[0x80])),
                    extension(
                        oids::EXT_KEY_USAGE,
                        false,
                        &der::seq(&[der::oid(oids::SERVER_AUTH)]),
                    ),
                    extension(oids::SUBJECT_ALT_NAME, false, &san(host)),
                    extension(
                        oids::SUBJECT_KEY_ID,
                        false,
                        &der::octet_string(&key_id(leaf_public)),
                    ),
                    extension(
                        oids::AUTHORITY_KEY_ID,
                        false,
                        &der::seq(&[der::tlv(der::context_primitive(0), &self.ski)]),
                    ),
                ]),
            ),
        ]);
        finish(&tbs, ca_pair, &self.rng)
    }
}

/// Builds the self-signed CA certificate.
fn self_signed_ca(pair: &EcdsaKeyPair, rng: &SystemRandom) -> io::Result<Vec<u8>> {
    let now = unix_now();
    let name = ca_name();
    let ski = key_id(pair.public_key().as_ref());
    let tbs = der::seq(&[
        der::explicit(0, &der::uint_small(2)),
        der::uint(&random_serial(rng)?),
        sig_alg(),
        name.clone(),
        validity(now - BACKDATE_SECS, now + CA_VALIDITY_SECS),
        name,
        spki(pair.public_key().as_ref()),
        der::explicit(
            3,
            &der::seq(&[
                // CA:TRUE with pathLenConstraint 0 — this CA may only issue end
                // entity certificates, never another CA.
                extension(
                    oids::BASIC_CONSTRAINTS,
                    true,
                    &der::seq(&[der::boolean(true), der::uint_small(0)]),
                ),
                // keyCertSign | cRLSign: bits 5 and 6, so one unused trailing bit.
                extension(oids::KEY_USAGE, true, &der::bit_string_bits(1, &[0x06])),
                extension(oids::SUBJECT_KEY_ID, false, &der::octet_string(&ski)),
            ]),
        ),
    ]);
    finish(&tbs, pair, rng)
}

/// Signs a TBSCertificate and wraps it into a complete Certificate.
fn finish(tbs: &[u8], pair: &EcdsaKeyPair, rng: &SystemRandom) -> io::Result<Vec<u8>> {
    let sig = pair
        .sign(rng, tbs)
        .map_err(|_| bad("could not sign a certificate"))?;
    Ok(der::seq(&[
        tbs.to_vec(),
        sig_alg(),
        der::bit_string(sig.as_ref()),
    ]))
}

fn sig_alg() -> Vec<u8> {
    // ecdsa-with-SHA256 takes no parameters; emitting a NULL here is a common
    // interop bug, so the SEQUENCE deliberately holds only the OID.
    der::seq(&[der::oid(oids::ECDSA_SHA256)])
}

fn spki(public_point: &[u8]) -> Vec<u8> {
    der::seq(&[
        der::seq(&[der::oid(oids::EC_PUBLIC_KEY), der::oid(oids::PRIME256V1)]),
        der::bit_string(public_point),
    ])
}

fn validity(not_before: i64, not_after: i64) -> Vec<u8> {
    der::seq(&[der::utc_time(not_before), der::utc_time(not_after)])
}

fn ca_name() -> Vec<u8> {
    rdn_sequence(&[
        (oids::ORGANIZATION, "Gimbal Local"),
        (oids::COMMON_NAME, "Gimbal Local credential proxy CA"),
    ])
}

fn subject_cn(host: &str) -> Vec<u8> {
    // A CN longer than 64 characters is invalid; SAN is what actually gets
    // matched, so a long host name is simply omitted from the subject.
    if host.len() <= 64 {
        rdn_sequence(&[(oids::COMMON_NAME, host)])
    } else {
        der::seq(&[])
    }
}

fn rdn_sequence(attrs: &[(&[u8], &str)]) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = attrs
        .iter()
        .map(|(oid, value)| der::set(&[der::seq(&[der::oid(oid), der::utf8_string(value)])]))
        .collect();
    der::seq(&rdns)
}

/// Builds a SubjectAltName holding either a dNSName or an iPAddress.
fn san(host: &str) -> Vec<u8> {
    let entry = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => der::tlv(der::context_primitive(7), &v4.octets()),
        Ok(IpAddr::V6(v6)) => der::tlv(der::context_primitive(7), &v6.octets()),
        Err(_) => der::tlv(der::context_primitive(2), host.as_bytes()),
    };
    der::seq(&[entry])
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der::oid(oid)];
    // `critical` defaults to FALSE, and DER forbids encoding a DEFAULT value.
    if critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::octet_string(value));
    der::seq(&parts)
}

/// Derives a key identifier from a public key.
///
/// RFC 5280 suggests SHA-1 of the public key bits but explicitly allows other
/// methods, so this uses a truncated SHA-256 and keeps SHA-1 out of the build.
/// The value only has to be consistent between the CA's SKI and each leaf's AKI,
/// which it is.
fn key_id(public_point: &[u8]) -> Vec<u8> {
    digest(&SHA256, public_point).as_ref()[..20].to_vec()
}

fn random_serial(rng: &SystemRandom) -> io::Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes)
        .map_err(|_| bad("could not read random bytes for a serial number"))?;
    // Keep the value positive; a negative serial is a certificate-lint failure
    // and some stacks reject it outright.
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    Ok(bytes.to_vec())
}

fn keypair(pkcs8: &[u8], rng: &SystemRandom) -> io::Result<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, rng)
        .map_err(|_| bad("stored CA key is not a valid P-256 PKCS#8 key"))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    // `mode` only applies at creation, so an existing looser file is tightened.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub(crate) fn pem_encode(der_bytes: &[u8], label: &str) -> String {
    let b64 = super::base64::encode(der_bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub(crate) fn pem_decode(pem: &str, label: &str) -> Option<Vec<u8>> {
    pem_decode_all(pem, label).into_iter().next()
}

/// Extracts every block with the given label. Used for the CA certificate and
/// for the host's root bundle, which holds well over a hundred.
pub(crate) fn pem_decode_all(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if line == begin {
            body = Some(String::new());
        } else if line == end {
            if let Some(b) = body.take()
                && let Some(bytes) = super::base64::decode(&b)
            {
                out.push(bytes);
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_round_trips_through_pem() {
        let ca = ProxyCa::ephemeral().expect("ca");
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let back = pem_decode(&pem, "CERTIFICATE").expect("decode");
        assert_eq!(back, ca.cert_der());
    }

    #[test]
    fn leaves_are_cached_per_host() {
        let ca = ProxyCa::ephemeral().expect("ca");
        let a = ca.leaf_for("github.com").expect("leaf");
        let b = ca.leaf_for("GITHUB.COM").expect("leaf");
        let c = ca.leaf_for("api.github.com").expect("leaf");
        // Case-insensitive hit on the cache, so the same certificate comes back.
        assert_eq!(a.cert_der, b.cert_der);
        assert_ne!(a.cert_der, c.cert_der);
    }

    #[test]
    fn leaf_carries_the_hostname_in_its_san() {
        let ca = ProxyCa::ephemeral().expect("ca");
        let leaf = ca.leaf_for("api.example.com").expect("leaf");
        // The SAN dNSName is stored as raw bytes, so a substring search over the
        // DER is a sufficient smoke test; `openssl x509` is the real check and
        // runs in the certificate test binary.
        let needle = b"api.example.com";
        assert!(leaf.cert_der.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn ip_literals_become_ip_sans_not_dns_sans() {
        let ca = ProxyCa::ephemeral().expect("ca");
        let leaf = ca.leaf_for("192.0.2.7").expect("leaf");
        // iPAddress [7] with a four byte payload.
        let needle = [0x87u8, 0x04, 192, 0, 2, 7];
        assert!(leaf.cert_der.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn a_reloaded_ca_keeps_its_identity() {
        let dir = std::env::temp_dir().join(format!("chm-ca-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = ProxyCa::load_or_create(&dir).expect("create");
        let second = ProxyCa::load_or_create(&dir).expect("reload");
        assert_eq!(first.cert_der(), second.cert_der());
        assert_eq!(first.fingerprint(), second.fingerprint());

        let mode = fs::metadata(dir.join(CA_KEY_FILE))
            .expect("key")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "CA key must not be group/world readable"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod openssl_tests {
    use std::process::Command;

    use super::*;

    /// Validates our hand-written X.509 against an independent implementation.
    ///
    /// The encoder in `der.rs` is ours, so "rustls accepted it" would only prove
    /// our two pieces of code agree with each other. OpenSSL is the outside
    /// opinion. Skipped, not failed, where `openssl` is unavailable.
    #[test]
    fn openssl_parses_and_chains_what_we_mint() {
        let Ok(probe) = Command::new("openssl").arg("version").output() else {
            eprintln!("skipping: no openssl on PATH");
            return;
        };
        if !probe.status.success() {
            eprintln!("skipping: openssl is not usable");
            return;
        }

        let dir = std::env::temp_dir().join(format!("chm-x509-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("tmp");
        let ca = ProxyCa::ephemeral().expect("ca");
        let leaf = ca.leaf_for("api.github.com").expect("leaf");

        let ca_pem = dir.join("ca.pem");
        let leaf_pem = dir.join("leaf.pem");
        fs::write(&ca_pem, ca.cert_pem()).expect("write ca");
        fs::write(&leaf_pem, pem_encode(&leaf.cert_der, "CERTIFICATE")).expect("write leaf");

        let text = Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&leaf_pem)
            .args(["-noout", "-text"])
            .output()
            .expect("openssl x509");
        let rendered = String::from_utf8_lossy(&text.stdout).to_string();
        assert!(
            text.status.success(),
            "openssl could not parse our leaf: {}",
            String::from_utf8_lossy(&text.stderr)
        );
        assert!(
            rendered.contains("DNS:api.github.com"),
            "missing SAN:\n{rendered}"
        );
        assert!(
            rendered.contains("CA:FALSE"),
            "leaf must not be a CA:\n{rendered}"
        );
        assert!(
            rendered.contains("TLS Web Server Authentication"),
            "missing serverAuth EKU:\n{rendered}"
        );
        assert!(
            rendered.contains("ecdsa-with-SHA256"),
            "unexpected signature algorithm:\n{rendered}"
        );

        // The real assertion: OpenSSL independently verifies the signature chain
        // from our leaf up to our CA.
        let verify = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(&ca_pem)
            .arg(&leaf_pem)
            .output()
            .expect("openssl verify");
        assert!(
            verify.status.success(),
            "openssl verify rejected our chain: {}{}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
