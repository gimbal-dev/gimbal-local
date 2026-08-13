// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! HTTP/1.1 head parsing, credential injection, and message framing.
//!
//! The proxy only ever needs to modify the *head* of a request. Bodies are
//! relayed byte for byte. But it does have to know where each message ends, or
//! it could not find the head of the next one on a reused connection — which is
//! how a request could slip past injection unseen.
//!
//! Framing is therefore parsed strictly rather than leniently. In particular a
//! message carrying both `Content-Length` and `Transfer-Encoding` is refused
//! outright: that ambiguity is the request-smuggling primitive, and a proxy that
//! guesses differently from the origin it forwards to is exactly the bug.
//!
//! Only HTTP/1.1 is handled. The proxy advertises `http/1.1` alone in ALPN, so a
//! guest client that would prefer HTTP/2 negotiates down rather than arriving
//! with framing this module cannot read.

use std::fmt;
use std::str::from_utf8;

/// The largest request or response head the proxy will buffer.
///
/// A head is held entirely in memory to be rewritten, so it needs a bound. This
/// is comfortably above anything real (large cookie jars, long auth headers) and
/// well below anything that would matter for memory.
pub(crate) const MAX_HEAD: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// The head is not complete yet; read more bytes and try again.
    Incomplete,
    /// The head is malformed, or is framed in a way the proxy refuses to guess
    /// about. The connection is torn down.
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Incomplete => f.write_str("incomplete"),
            ParseError::Malformed(why) => write!(f, "{why}"),
        }
    }
}

/// A parsed request head. Header order and spelling are preserved so the
/// re-emitted head is as close to the original as possible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(String, String)>,
    /// Total bytes of the head, including the terminating blank line.
    pub(crate) len: usize,
}

impl RequestHead {
    /// Parse a request head from the front of `buf`.
    ///
    /// Returns [`ParseError::Incomplete`] while the terminating blank line has
    /// not arrived, so a caller can keep reading. Anything actively wrong is
    /// [`ParseError::Malformed`] and must end the connection: this is the one
    /// place a guest's bytes are interpreted, and a permissive parser here is
    /// how request smuggling gets in.
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let Some(end) = find_head_end(buf) else {
            // Bound the wait. Without this a guest could hold a connection open
            // forever by never sending the blank line.
            if buf.len() > MAX_HEAD {
                return Err(ParseError::Malformed(format!(
                    "request head would exceed {MAX_HEAD} bytes"
                )));
            }
            return Err(ParseError::Incomplete);
        };
        if end > MAX_HEAD {
            return Err(ParseError::Malformed(format!(
                "request head would exceed {MAX_HEAD} bytes"
            )));
        }

        let text = from_utf8(&buf[..end])
            .map_err(|_| ParseError::Malformed("request head is not valid UTF-8".into()))?;
        let mut lines = text.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| ParseError::Malformed("empty request".into()))?;
        let mut parts = request_line.split(' ');
        let (Some(method), Some(target), Some(version)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(ParseError::Malformed(format!(
                "malformed request line {request_line:?}"
            )));
        };
        if parts.next().is_some() {
            return Err(ParseError::Malformed(
                "request line has trailing content".into(),
            ));
        }
        if !version.starts_with("HTTP/1.") {
            return Err(ParseError::Malformed(format!(
                "unsupported version {version:?}"
            )));
        }

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                // Obsolete line folding (RFC 7230 §3.2.4). Deleted from the
                // standard precisely because implementations disagree about it,
                // which is what makes it a smuggling primitive.
                return Err(ParseError::Malformed(
                    "obsolete header line folding is not accepted".into(),
                ));
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(ParseError::Malformed(format!(
                    "header line without a colon: {line:?}"
                )));
            };
            if name.is_empty() || name.chars().any(|c| c == ' ' || c == '\t') {
                // Whitespace before the colon is another smuggling primitive:
                // some parsers strip it, some do not.
                return Err(ParseError::Malformed(format!(
                    "malformed header name {name:?}"
                )));
            }
            headers.push((name.to_string(), value.trim().to_string()));
        }

        Ok(Self {
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
            headers,
            len: end,
        })
    }

    /// The first value for `name`, case-insensitively.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How this request frames its body.
    pub(crate) fn body_mode(&self) -> Result<BodyMode, ParseError> {
        body_mode(&self.headers)
    }

    /// Re-emit the head with `overrides` applied.
    ///
    /// Every existing copy of an overridden header is dropped before the new one
    /// is appended. Replacing only the first would leave a guest's own copy on
    /// the wire beside ours, and which one an origin honours is not something we
    /// get to decide.
    pub(crate) fn render_with(&self, overrides: &[(String, String)]) -> Vec<u8> {
        let mut out = String::with_capacity(self.len + 128);
        out.push_str(&self.method);
        out.push(' ');
        out.push_str(&self.target);
        out.push(' ');
        out.push_str(&self.version);
        out.push_str("\r\n");
        for (name, value) in &self.headers {
            if overrides.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                continue;
            }
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        for (name, value) in overrides {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

/// Offset just past the blank line ending a head, if it has arrived.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Where a message body ends.
///
/// `UntilClose` exists only as a name for the response case we deliberately do
/// not handle: the proxy relays responses as opaque bytes, so it never needs to
/// find the end of one. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyMode {
    /// No body at all.
    Empty,
    /// Exactly `n` bytes follow the head.
    Length(u64),
    /// Chunked transfer coding; the end is found by scanning.
    Chunked,
}

/// How a request head frames its body.
///
/// Requests only. A request with neither framing header has no body, which is
/// unambiguous — unlike a response, where the same absence means "read until the
/// connection closes" and would force us to parse responses too.
fn body_mode(headers: &[(String, String)]) -> Result<BodyMode, ParseError> {
    let transfer_encoding: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    let content_lengths: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();

    if !transfer_encoding.is_empty() && !content_lengths.is_empty() {
        // The request-smuggling primitive. Refuse rather than pick a side.
        return Err(ParseError::Malformed(
            "message has both Content-Length and Transfer-Encoding".into(),
        ));
    }

    if let Some(te) = transfer_encoding.first() {
        if transfer_encoding.len() > 1 {
            return Err(ParseError::Malformed(
                "multiple Transfer-Encoding headers".into(),
            ));
        }
        let last = te.rsplit(',').next().unwrap_or("").trim();
        if !last.eq_ignore_ascii_case("chunked") {
            return Err(ParseError::Malformed(format!(
                "unsupported Transfer-Encoding {te:?}"
            )));
        }
        return Ok(BodyMode::Chunked);
    }

    if let Some(first) = content_lengths.first() {
        let parsed: u64 = first
            .trim()
            .parse()
            .map_err(|_| ParseError::Malformed(format!("bad Content-Length {first:?}")))?;
        // Duplicate Content-Length headers are only legal if identical.
        if content_lengths
            .iter()
            .any(|v| v.trim().parse::<u64>().ok() != Some(parsed))
        {
            return Err(ParseError::Malformed(
                "conflicting Content-Length headers".into(),
            ));
        }
        return Ok(BodyMode::Length(parsed));
    }

    Ok(BodyMode::Empty)
}

/// Consumes a chunked body incrementally, reporting when it ends.
///
/// The proxy does not rewrite chunked data, so this only has to find the
/// terminating zero-length chunk and its trailer section.
#[derive(Debug, Default)]
pub(crate) struct ChunkedScanner {
    state: ChunkState,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ChunkState {
    #[default]
    Size,
    /// Remaining data bytes, then the CRLF that follows them.
    Data(u64),
    DataCrLf(u8),
    /// Inside the trailer section after the final zero chunk.
    Trailer {
        /// How many consecutive CRLF-terminated empty lines have been seen.
        blank: bool,
        column: usize,
    },
    Done,
}

impl ChunkedScanner {
    /// Feeds bytes, returning how many were consumed as part of this body.
    ///
    /// Any remainder belongs to the next message. Returns an error on a
    /// malformed chunk header rather than resynchronising, since a proxy that
    /// guesses here is a proxy that can be desynchronised on purpose.
    pub(crate) fn consume(&mut self, buf: &[u8]) -> Result<usize, ParseError> {
        let mut i = 0usize;
        let mut size_digits;
        let mut size_acc: u64;
        let mut in_extension;

        loop {
            if i >= buf.len() {
                return Ok(i);
            }
            match self.state {
                ChunkState::Done => return Ok(i),
                ChunkState::Size => {
                    // Re-scan the size line from wherever we are; the accumulator
                    // lives in locals because a size line is short and always
                    // arrives within one buffer in practice. If it does not, the
                    // caller retains the unconsumed bytes and we start again.
                    let start = i;
                    size_acc = 0;
                    size_digits = 0;
                    in_extension = false;
                    loop {
                        if i >= buf.len() {
                            // Incomplete size line: consume nothing so the caller
                            // can retry with more bytes.
                            return Ok(start);
                        }
                        let b = buf[i];
                        if b == b'\r' {
                            if i + 1 >= buf.len() {
                                return Ok(start);
                            }
                            if buf[i + 1] != b'\n' {
                                return Err(ParseError::Malformed("bad chunk size line".into()));
                            }
                            i += 2;
                            break;
                        }
                        if b == b';' {
                            in_extension = true;
                        } else if !in_extension {
                            let d = match b {
                                b'0'..=b'9' => b - b'0',
                                b'a'..=b'f' => b - b'a' + 10,
                                b'A'..=b'F' => b - b'A' + 10,
                                _ => {
                                    return Err(ParseError::Malformed(format!(
                                        "bad chunk size byte {b:#04x}"
                                    )));
                                }
                            };
                            size_digits += 1;
                            if size_digits > 16 {
                                return Err(ParseError::Malformed("chunk size too long".into()));
                            }
                            size_acc = (size_acc << 4) | d as u64;
                        }
                        i += 1;
                    }
                    if size_digits == 0 {
                        return Err(ParseError::Malformed(
                            "chunk size line has no digits".into(),
                        ));
                    }
                    self.state = if size_acc == 0 {
                        ChunkState::Trailer {
                            blank: true,
                            column: 0,
                        }
                    } else {
                        ChunkState::Data(size_acc)
                    };
                }
                ChunkState::Data(remaining) => {
                    let take = remaining.min((buf.len() - i) as u64) as usize;
                    i += take;
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        ChunkState::DataCrLf(0)
                    } else {
                        ChunkState::Data(left)
                    };
                }
                ChunkState::DataCrLf(seen) => {
                    let expect = if seen == 0 { b'\r' } else { b'\n' };
                    if buf[i] != expect {
                        return Err(ParseError::Malformed(
                            "chunk data not CRLF terminated".into(),
                        ));
                    }
                    i += 1;
                    self.state = if seen == 0 {
                        ChunkState::DataCrLf(1)
                    } else {
                        ChunkState::Size
                    };
                }
                ChunkState::Trailer { blank, column } => {
                    // Scan to the end of the trailer section, which terminates
                    // with an empty line.
                    let b = buf[i];
                    i += 1;
                    if b == b'\n' {
                        if blank && column == 0 {
                            self.state = ChunkState::Done;
                        } else {
                            self.state = ChunkState::Trailer {
                                blank: true,
                                column: 0,
                            };
                        }
                    } else if b == b'\r' {
                        self.state = ChunkState::Trailer { blank, column };
                    } else {
                        self.state = ChunkState::Trailer {
                            blank: false,
                            column: column + 1,
                        };
                    }
                }
            }
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str) -> Result<RequestHead, ParseError> {
        RequestHead::parse(text.as_bytes())
    }

    #[test]
    fn a_partial_head_asks_for_more_rather_than_failing() {
        assert_eq!(
            req("GET / HTTP/1.1\r\nHost: a\r\n"),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn parses_a_normal_request() {
        let h = req("GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\nUser-Agent: git/2.43\r\n\r\n")
            .expect("parse");
        assert_eq!(h.method, "GET");
        assert_eq!(h.target, "/repo.git/info/refs?service=git-upload-pack");
        assert_eq!(h.header("host"), Some("github.com"));
        assert_eq!(h.body_mode(), Ok(BodyMode::Empty));
    }

    #[test]
    fn injection_replaces_every_copy_of_the_managed_header() {
        // A guest sending two Authorization headers must not get one of its own
        // through alongside the injected one.
        let h = req("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer guest1\r\nAccept: */*\r\nauthorization: Bearer guest2\r\n\r\n")
            .expect("parse");
        let out = h.render_with(&[("Authorization".into(), "Bearer real".into())]);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("guest1"), "{text}");
        assert!(!text.contains("guest2"), "{text}");
        assert_eq!(text.matches("uthorization").count(), 1, "{text}");
        assert!(text.contains("Authorization: Bearer real\r\n"), "{text}");
        // Untouched headers survive in order.
        assert!(text.contains("Host: a\r\nAccept: */*\r\n"), "{text}");
    }

    #[test]
    fn both_content_length_and_transfer_encoding_is_refused() {
        let h = req(
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .expect("head parses");
        match h.body_mode() {
            Err(ParseError::Malformed(why)) => assert!(why.contains("both"), "{why}"),
            other => panic!("smuggling framing must be refused, got {other:?}"),
        }
    }

    #[test]
    fn conflicting_content_lengths_are_refused() {
        let h = req("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
            .expect("head parses");
        assert!(matches!(h.body_mode(), Err(ParseError::Malformed(_))));
    }

    #[test]
    fn obsolete_folding_is_refused() {
        let err = req("GET / HTTP/1.1\r\nHost: a\r\n  continued\r\n\r\n").unwrap_err();
        assert!(
            matches!(err, ParseError::Malformed(ref w) if w.contains("folding")),
            "{err:?}"
        );
    }

    #[test]
    fn an_oversized_head_is_bounded() {
        let mut text = String::from("GET / HTTP/1.1\r\n");
        while text.len() < MAX_HEAD + 16 {
            text.push_str("X-Pad: ....................................................\r\n");
        }
        let err = RequestHead::parse(text.as_bytes()).unwrap_err();
        assert!(
            matches!(err, ParseError::Malformed(ref w) if w.contains("exceed")),
            "{err:?}"
        );
    }

    #[test]
    fn chunked_scanner_finds_the_end_of_a_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nGET /next HTTP/1.1\r\n";
        let mut s = ChunkedScanner::default();
        let used = s.consume(body).expect("scan");
        assert!(s.is_done());
        assert_eq!(&body[used..], b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn chunked_scanner_survives_arbitrary_fragmentation() {
        let body: &[u8] = b"4\r\nabcd\r\n1\r\nz\r\n0\r\n\r\nTAIL";
        for split in 1..body.len() {
            let mut s = ChunkedScanner::default();
            let mut pending: Vec<u8> = Vec::new();
            let mut consumed_total = 0usize;
            for part in [&body[..split], &body[split..]] {
                pending.extend_from_slice(part);
                let used = s.consume(&pending).expect("scan");
                pending.drain(..used);
                consumed_total += used;
                if s.is_done() {
                    break;
                }
            }
            assert!(s.is_done(), "not done for split at {split}");
            assert_eq!(
                &body[consumed_total..],
                b"TAIL",
                "wrong boundary for split at {split}"
            );
        }
    }

    #[test]
    fn chunked_scanner_handles_extensions_and_trailers() {
        let body = b"3;name=value\r\nabc\r\n0\r\nX-Checksum: deadbeef\r\n\r\nREST";
        let mut s = ChunkedScanner::default();
        let used = s.consume(body).expect("scan");
        assert!(s.is_done());
        assert_eq!(&body[used..], b"REST");
    }

    #[test]
    fn chunked_scanner_rejects_a_bad_size_line() {
        let mut s = ChunkedScanner::default();
        assert!(s.consume(b"zz\r\nabc\r\n").is_err());
    }
}
