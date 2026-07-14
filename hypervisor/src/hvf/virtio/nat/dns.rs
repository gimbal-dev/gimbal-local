//! A minimal DNS server for the userspace NAT: it parses the guest's query,
//! lets the egress policy judge the name, resolves permitted names through the
//! host resolver, and synthesizes an answer. This is deliberately small — it
//! serves A-record lookups (the demo surface) and returns an explicit, honest
//! failure for everything else rather than silently dropping it.
//!
//! Enforcing at the DNS layer is half of the egress gate: a denied name is
//! never resolved, so the guest cannot even learn the address to dial.

use std::net::Ipv4Addr;

/// DNS record type A (IPv4 address).
pub const QTYPE_A: u16 = 1;
/// DNS record type AAAA (IPv6 address) — out of V0 scope; answered with NoData.
pub const QTYPE_AAAA: u16 = 28;

const HEADER_LEN: usize = 12;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

/// A parsed DNS query (first question only, which is all a stub resolver needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction id, echoed in the response.
    pub id: u16,
    /// Recursion-desired bit from the request flags, echoed back.
    pub recursion_desired: bool,
    /// The queried name, lowercased, without a trailing dot.
    pub name: String,
    /// The query type (A / AAAA / ...).
    pub qtype: u16,
    /// The query class (normally 1 = IN).
    pub qclass: u16,
}

/// What the caller decided should happen to a query.
pub enum Outcome {
    /// Resolved A records to return.
    Answers(Vec<Ipv4Addr>),
    /// The name is not permitted by policy — answer REFUSED.
    Refused,
    /// The name resolved to nothing usable (e.g. AAAA in a v4-only NAT, or an
    /// allowed name with no A records) — answer NOERROR with no answers.
    NoData,
    /// The name does not exist upstream — answer NXDOMAIN.
    NxDomain,
}

/// Parse a DNS query message. Returns `None` if it is not a well-formed
/// single-question query (QR=0, QDCOUNT>=1) we can answer.
pub fn parse_query(msg: &[u8]) -> Option<Query> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 0 {
        return None; // a response, not a query
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let recursion_desired = (flags >> 8) & 1 == 1;

    let (name, next) = read_name(msg, HEADER_LEN)?;
    if next + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
    let qclass = u16::from_be_bytes([msg[next + 2], msg[next + 3]]);
    Some(Query {
        id,
        recursion_desired,
        name,
        qtype,
        qclass,
    })
}

/// Read a DNS name starting at `off`, following at most one level of compression
/// pointers. Returns the lowercased dotted name and the offset just past the
/// name in the *linear* question (pointers don't advance the linear cursor past
/// their two bytes). For a query the name is never compressed, but we tolerate
/// it defensively.
fn read_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut linear_end = off;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 128 {
            return None; // malformed / loop
        }
        let len = *msg.get(off)? as usize;
        if len == 0 {
            if !jumped {
                linear_end = off + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer.
            let b2 = *msg.get(off + 1)? as usize;
            let ptr = ((len & 0x3f) << 8) | b2;
            if !jumped {
                linear_end = off + 2;
            }
            jumped = true;
            off = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return None; // reserved label type
        }
        let start = off + 1;
        let end = start + len;
        let label = msg.get(start..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off = end;
        if !jumped {
            linear_end = off;
        }
    }
    Some((labels.join("."), linear_end))
}

/// Encode a dotted name as DNS labels (uncompressed), terminated by a zero byte.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        out.push(n as u8);
        out.extend_from_slice(&bytes[..n]);
    }
    out.push(0);
}

/// Build a DNS response for `query` and `outcome`. The question is echoed and
/// answers (if any) are appended with a fixed TTL.
pub fn build_response(query: &Query, outcome: &Outcome) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&query.id.to_be_bytes());

    let (rcode, answers): (u8, &[Ipv4Addr]) = match outcome {
        Outcome::Answers(a) if !a.is_empty() => (0, a.as_slice()),
        Outcome::Answers(_) | Outcome::NoData => (0, &[]),
        Outcome::Refused => (RCODE_REFUSED, &[]),
        Outcome::NxDomain => (RCODE_NXDOMAIN, &[]),
    };

    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=echo, RA=1, Z=0, RCODE.
    let mut flags: u16 = 0x8000; // QR
    if query.recursion_desired {
        flags |= 0x0100; // RD
    }
    flags |= 0x0080; // RA
    flags |= rcode as u16;
    msg.extend_from_slice(&flags.to_be_bytes());

    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section (echoed).
    encode_name(&query.name, &mut msg);
    msg.extend_from_slice(&query.qtype.to_be_bytes());
    msg.extend_from_slice(&query.qclass.to_be_bytes());

    // Answer section: one A record per address, pointing at the question name.
    for ip in answers {
        // Name compression pointer to the question at offset 12.
        msg.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // class IN
        msg.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        msg.extend_from_slice(&ip.octets());
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw A-record query for `name` with id 0x1234, RD set.
    fn a_query(name: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
        encode_name(name, &mut m);
        m.extend_from_slice(&QTYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn parses_a_query() {
        let q = parse_query(&a_query("api.github.com")).expect("parse");
        assert_eq!(q.id, 0x1234);
        assert!(q.recursion_desired);
        assert_eq!(q.name, "api.github.com");
        assert_eq!(q.qtype, QTYPE_A);
        assert_eq!(q.qclass, 1);
    }

    #[test]
    fn lowercases_the_name() {
        let q = parse_query(&a_query("API.GitHub.COM")).expect("parse");
        assert_eq!(q.name, "api.github.com");
    }

    #[test]
    fn rejects_a_response_message() {
        let mut m = a_query("x.test");
        m[2] = 0x81; // set QR
        assert!(parse_query(&m).is_none());
    }

    #[test]
    fn rejects_truncated_message() {
        assert!(parse_query(&[0u8; 4]).is_none());
    }

    #[test]
    fn builds_answer_records() {
        let q = parse_query(&a_query("api.github.com")).unwrap();
        let ips = vec![Ipv4Addr::new(140, 82, 112, 6), Ipv4Addr::new(140, 82, 113, 6)];
        let resp = build_response(&q, &Outcome::Answers(ips.clone()));
        // Header echoes id, sets QR + RA, rcode 0.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234);
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(resp[3] & 0x0f, 0, "rcode NOERROR");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 2, "ANCOUNT=2");
        // Round-trips back to a parseable question.
        let (name, _) = read_name(&resp, HEADER_LEN).unwrap();
        assert_eq!(name, "api.github.com");
    }

    #[test]
    fn refused_sets_rcode_5_and_no_answers() {
        let q = parse_query(&a_query("evil.test")).unwrap();
        let resp = build_response(&q, &Outcome::Refused);
        assert_eq!(resp[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
    }

    #[test]
    fn nodata_is_noerror_no_answers() {
        let q = parse_query(&a_query("v6only.test")).unwrap();
        let resp = build_response(&q, &Outcome::NoData);
        assert_eq!(resp[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }
}
