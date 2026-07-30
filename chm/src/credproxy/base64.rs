// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//
//! Standard base64, used for PEM bodies and for HTTP Basic credentials.
//!
//! Small enough not to be worth a dependency in the component that holds every
//! secret, and the encoder is on the hot path for credential injection.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes standard base64, ignoring ASCII whitespace.
///
/// Returns `None` on any invalid character or a truncated final group, rather
/// than silently producing partial output.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None; // data after padding
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, never real data.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    if padding > 2 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4648_vectors() {
        for (raw, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw.as_bytes()), encoded, "encoding {raw:?}");
            assert_eq!(
                decode(encoded).as_deref(),
                Some(raw.as_bytes()),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn round_trips_arbitrary_bytes() {
        let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_eq!(decode(&encode(&bytes)).as_deref(), Some(&bytes[..]));
    }

    #[test]
    fn tolerates_the_line_wrapping_pem_uses() {
        let wrapped = "Zm9v\nYmFy\n";
        assert_eq!(decode(wrapped).as_deref(), Some(&b"foobar"[..]));
    }

    #[test]
    fn rejects_junk() {
        assert!(decode("Zm9v!").is_none());
        assert!(decode("Zm==9v").is_none());
    }
}
