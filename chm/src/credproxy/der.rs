// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! A minimal DER writer, sized for exactly one job: emitting the X.509 v3
//! certificates the credential proxy mints for itself.
//!
//! We write DER by hand rather than depending on a certificate-generation crate
//! because the proxy is the one component in the system that holds every
//! remote-call secret. Its dependency surface is a security property, so paying
//! ~200 lines of encoder to avoid pulling four transitive crates into that
//! component is a deliberate trade. See `docs/credential-proxy.md`.
//!
//! Scope note: this module only *writes* DER. It never parses attacker-supplied
//! DER, which is where the genuinely dangerous bugs in ASN.1 code live. Every
//! value encoded here originates from this process.

/// Universal tag numbers, ORed with the constructed bit where applicable.
pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_UTF8_STRING: u8 = 0x0c;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_SET: u8 = 0x31;

/// A context-specific constructed tag, e.g. `[0] EXPLICIT` in an ASN.1 module.
pub(crate) const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// A context-specific primitive tag, used for `GeneralName` choices such as
/// `dNSName [2] IA5String` and `iPAddress [7] OCTET STRING`.
pub(crate) const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// Encodes a DER length in the shortest legal form.
///
/// DER (unlike BER) requires the definite, minimal-length encoding, so a length
/// below 128 must use the single-byte short form and anything larger must use
/// the long form with no leading zero bytes.
fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Emits a complete tag-length-value triple.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    push_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Wraps already-encoded elements in a SEQUENCE.
pub(crate) fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &elements.concat())
}

/// Wraps already-encoded elements in a SET.
pub(crate) fn set(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SET, &elements.concat())
}

/// Wraps an already-encoded element in an explicit context tag.
pub(crate) fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(context(n), inner)
}

/// Encodes a non-negative INTEGER from big-endian magnitude bytes.
///
/// DER integers are signed and minimally encoded, so a leading zero byte is
/// prepended when the high bit would otherwise mark the value negative, and
/// redundant leading zeroes are stripped.
pub(crate) fn uint(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(magnitude.len());
    let trimmed = &magnitude[first..];
    let mut value = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() {
        value.push(0);
    } else {
        if trimmed[0] & 0x80 != 0 {
            value.push(0);
        }
        value.extend_from_slice(trimmed);
    }
    tlv(TAG_INTEGER, &value)
}

/// Encodes a small non-negative INTEGER.
pub(crate) fn uint_small(v: u32) -> Vec<u8> {
    uint(&v.to_be_bytes())
}

/// Encodes a BOOLEAN. DER mandates `0xff` for true, not merely "non-zero".
pub(crate) fn boolean(v: bool) -> Vec<u8> {
    tlv(TAG_BOOLEAN, &[if v { 0xff } else { 0x00 }])
}

/// Encodes a BIT STRING whose content is a whole number of bytes.
pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    bit_string_bits(0, bytes)
}

/// Encodes a BIT STRING with an explicit count of unused trailing bits.
///
/// Needed for `KeyUsage`, which is an ASN.1 NamedBitList: DER requires trailing
/// zero bits to be dropped, so the encoding of "digitalSignature only" is one
/// byte with seven unused bits rather than a full two-byte field.
pub(crate) fn bit_string_bits(unused: u8, bytes: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(bytes.len() + 1);
    value.push(unused);
    value.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &value)
}

/// Encodes an OBJECT IDENTIFIER from its pre-encoded content bytes.
///
/// The OIDs we need are fixed and few, so they live as constants in `oid` rather
/// than being assembled from arc numbers at runtime.
pub(crate) fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(TAG_OID, encoded)
}

pub(crate) fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, bytes)
}

pub(crate) fn utf8_string(s: &str) -> Vec<u8> {
    tlv(TAG_UTF8_STRING, s.as_bytes())
}

/// Encodes a UTCTime as `YYMMDDHHMMSSZ`.
///
/// UTCTime only covers 1950-2049. That is fine for certificates this proxy mints
/// (leaves live for days, the CA for a few years) and it is what essentially
/// every real-world CA emits for such dates, so it is the best-tested path
/// through guest TLS stacks.
pub(crate) fn utc_time(unix_secs: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_secs);
    let text = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, mo, d, h, mi, s);
    tlv(TAG_UTC_TIME, text.as_bytes())
}

/// Converts a Unix timestamp to a civil UTC date/time.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, which is exact for the
/// whole proleptic Gregorian range and avoids a date-library dependency.
fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);

    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };

    (
        year,
        m,
        d,
        (secs_of_day / 3600) as u32,
        ((secs_of_day % 3600) / 60) as u32,
        (secs_of_day % 60) as u32,
    )
}

/// The fixed OIDs this module needs, as their DER content bytes.
pub(crate) mod oids {
    /// `1.2.840.10045.2.1` id-ecPublicKey
    pub(crate) const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// `1.2.840.10045.3.1.7` prime256v1 (NIST P-256)
    pub(crate) const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// `1.2.840.10045.4.3.2` ecdsa-with-SHA256
    pub(crate) const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// `2.5.4.3` commonName
    pub(crate) const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// `2.5.4.10` organizationName
    pub(crate) const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    /// `2.5.29.14` subjectKeyIdentifier
    pub(crate) const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    /// `2.5.29.15` keyUsage
    pub(crate) const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// `2.5.29.17` subjectAltName
    pub(crate) const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// `2.5.29.19` basicConstraints
    pub(crate) const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// `2.5.29.35` authorityKeyIdentifier
    pub(crate) const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    /// `2.5.29.37` extKeyUsage
    pub(crate) const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// `1.3.6.1.5.5.7.3.1` id-kp-serverAuth
    pub(crate) const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths_use_minimal_form() {
        assert_eq!(tlv(TAG_OCTET_STRING, &[0u8; 3]), vec![0x04, 0x03, 0, 0, 0]);

        let long = tlv(TAG_OCTET_STRING, &[0u8; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);

        let longer = tlv(TAG_OCTET_STRING, &[0u8; 300]);
        assert_eq!(&longer[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn integers_are_signed_and_minimal() {
        // High bit set: needs a leading zero so it is not read as negative.
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        // Redundant leading zeroes are stripped.
        assert_eq!(uint(&[0x00, 0x00, 0x2a]), vec![0x02, 0x01, 0x2a]);
        // Zero still needs one content byte.
        assert_eq!(uint(&[0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(uint_small(2), vec![0x02, 0x01, 0x02]);
    }

    #[test]
    fn boolean_true_is_all_ones() {
        assert_eq!(boolean(true), vec![0x01, 0x01, 0xff]);
        assert_eq!(boolean(false), vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn bit_string_records_zero_unused_bits() {
        assert_eq!(bit_string(&[0xab]), vec![0x03, 0x02, 0x00, 0xab]);
    }

    #[test]
    fn utc_time_matches_known_instants() {
        // 2026-07-30T09:41:00Z
        assert_eq!(&utc_time(1_785_404_460)[2..], b"260730094100Z");
        // The Unix epoch itself.
        assert_eq!(&utc_time(0)[2..], b"700101000000Z");
        // A leap day, to exercise the era arithmetic.
        assert_eq!(&utc_time(1_709_164_800)[2..], b"240229000000Z");
    }

    #[test]
    fn sequences_nest() {
        let inner = seq(&[uint_small(1), uint_small(2)]);
        assert_eq!(inner, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        let outer = explicit(0, &inner);
        assert_eq!(outer[0], 0xa0);
        assert_eq!(outer[1], 8);
    }
}
