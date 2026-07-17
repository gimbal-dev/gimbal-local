// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Reserved / special-use IPv4 ranges the guest must not reach through the NAT
//! (M31.1).
//!
//! The userspace NAT relays a permitted flow through a real host socket, so
//! whatever the guest dials, `chm` dials *on the host*. Without this guard a
//! guest could reach the host's own networks — loopback, the private LAN, and
//! the link-local cloud-metadata endpoint `169.254.169.254` — which is a
//! host-boundary break independent of any filesystem isolation. The NAT denies a
//! connect to any of these ranges (and refuses to hand out a DNS answer that
//! resolves into one) *independently of and before* the egress policy, so even an
//! allow-all policy can only reach public destinations. A deliberate opt-in
//! (`--allow-local-egress`) lifts the guard for users who really do want
//! localhost access.

use std::net::Ipv4Addr;

/// True when `ip` is a reserved / special-use address the guest must not reach
/// (unless local egress was explicitly opted in). Covers, in IPv4 terms:
///
/// - loopback `127.0.0.0/8`
/// - RFC1918 private `10/8`, `172.16/12`, `192.168/16`
/// - link-local `169.254.0.0/16` (incl. the cloud metadata IP `169.254.169.254`)
/// - "this host" `0.0.0.0/8` and the unspecified address
/// - CGNAT / shared `100.64.0.0/10`
/// - IETF protocol assignments `192.0.0.0/24`
/// - benchmarking `198.18.0.0/15`
/// - documentation `192.0.2/24`, `198.51.100/24`, `203.0.113/24`
/// - multicast `224.0.0.0/4`, reserved `240.0.0.0/4`, and broadcast
pub fn is_reserved_egress_ip(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || a == 0 // 0.0.0.0/8 "this host"
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT/shared
        || (a == 192 && b == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking
        || a >= 240 // 240.0.0.0/4 reserved (incl. 255.255.255.255)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_allowed() {
        for s in [
            "140.82.112.6", // github.com
            "8.8.8.8",      // public DNS
            "1.1.1.1",
            "93.184.216.34", // example.com
            "13.107.42.14",
        ] {
            assert!(!is_reserved_egress_ip(ip(s)), "{s} should be public");
        }
    }

    #[test]
    fn host_internal_addresses_are_reserved() {
        for s in [
            "127.0.0.1",       // loopback
            "127.0.0.53",      // systemd-resolved / local resolver
            "10.0.0.5",        // RFC1918
            "172.16.0.1",      // RFC1918
            "172.31.255.254",  // RFC1918 upper edge
            "192.168.1.1",     // RFC1918 / typical router
            "169.254.169.254", // cloud metadata
            "169.254.0.1",     // link-local
            "0.0.0.0",         // unspecified
            "0.1.2.3",         // 0/8
            "100.64.0.1",      // CGNAT
            "100.127.255.255", // CGNAT upper edge
            "198.18.0.1",      // benchmarking
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(is_reserved_egress_ip(ip(s)), "{s} should be reserved");
        }
    }

    #[test]
    fn cgnat_boundaries() {
        assert!(!is_reserved_egress_ip(ip("100.63.255.255")), "just below CGNAT");
        assert!(is_reserved_egress_ip(ip("100.64.0.0")), "CGNAT start");
        assert!(is_reserved_egress_ip(ip("100.127.255.255")), "CGNAT end");
        assert!(!is_reserved_egress_ip(ip("100.128.0.0")), "just above CGNAT");
    }
}
