// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The join between the NAT and the proxy.
//!
//! The NAT asks one question per admitted flow — *should this go somewhere else
//! first?* — and this module answers it from the rule set. Everything that makes
//! the answer interesting (which hosts are worth intercepting, which credential
//! belongs to which destination, where that credential comes from) stays on this
//! side of the line. The hypervisor crate receives an address and some opaque
//! bytes, and could not leak a secret if it tried.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hypervisor::hvf::virtio::nat::{Divert, InterceptDecider};

use super::rules::{Destination, Disposition, RuleSet};
use super::server::RunningProxy;

/// Answers the NAT's divert question from a [`RuleSet`].
#[derive(Debug)]
pub struct RuleDecider {
    rules: RuleSet,
    proxy: SocketAddr,
}

impl RuleDecider {
    pub fn new(rules: RuleSet, proxy: SocketAddr) -> Self {
        Self { rules, proxy }
    }

    /// Build a decider for a running proxy, or `None` when no rule would ever
    /// intercept anything — so a rule file that only lists pass-throughs costs
    /// the data path nothing.
    pub fn for_proxy(rules: RuleSet, proxy: &RunningProxy) -> Option<Arc<dyn InterceptDecider>> {
        if rules.intercept_patterns().is_empty() {
            return None;
        }
        Some(Arc::new(Self::new(rules, proxy.addr)))
    }
}

impl InterceptDecider for RuleDecider {
    fn divert(&self, ip: Ipv4Addr, port: u16, host: Option<&str>) -> Option<Divert> {
        // A flow is only worth diverting if a rule would actually inject into
        // it. Anything else is left alone: routing a flow through the process
        // that holds the credentials, for no reason, is pure added risk.
        //
        // The decision is made on the destination the NAT admitted. The guest's
        // own claims about where it is going arrive later, inside the TLS
        // session, and are never consulted — see `server::intercept`.
        let dest = Destination::new(host.map(str::to_string), Some(ip.into()), port);
        match self.rules.decide(&dest) {
            Disposition::Inject(_) => Some(Divert {
                addr: self.proxy,
                preamble: super::server::preamble_bytes(ip.into(), port, host),
            }),
            Disposition::PassThrough(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> RuleSet {
        RuleSet::parse(json).expect("rules")
    }

    fn decider(json: &str) -> RuleDecider {
        RuleDecider::new(rules(json), SocketAddr::from(([127, 0, 0, 1], 9999)))
    }

    #[test]
    fn a_matching_host_is_diverted_with_its_true_destination() {
        let d = decider(
            r#"{"version":1,"rules":[{"name":"gh","hosts":["api.github.com"],
                "scheme":"bearer","env":"T"}]}"#,
        );
        let out = d
            .divert(Ipv4Addr::new(140, 82, 121, 6), 443, Some("api.github.com"))
            .expect("should divert");
        assert_eq!(out.addr, SocketAddr::from(([127, 0, 0, 1], 9999)));
        assert_eq!(
            String::from_utf8(out.preamble).unwrap(),
            "GIMBAL-PROXY/1 140.82.121.6 443 api.github.com\n"
        );
    }

    #[test]
    fn an_unlisted_host_is_left_alone() {
        let d = decider(
            r#"{"version":1,"rules":[{"name":"gh","hosts":["api.github.com"],
                "scheme":"bearer","env":"T"}]}"#,
        );
        assert!(
            d.divert(Ipv4Addr::new(1, 2, 3, 4), 443, Some("example.com"))
                .is_none()
        );
    }

    #[test]
    fn a_guest_that_skipped_dns_is_judged_on_the_address_alone() {
        // No hostname to match against, so a hostname rule cannot fire. The flow
        // must go direct rather than being intercepted on a guess.
        let d = decider(
            r#"{"version":1,"rules":[{"name":"gh","hosts":["api.github.com"],
                "scheme":"bearer","env":"T"}]}"#,
        );
        assert!(
            d.divert(Ipv4Addr::new(140, 82, 121, 6), 443, None)
                .is_none()
        );
    }

    #[test]
    fn a_ruleset_that_can_never_inject_installs_no_hook_at_all() {
        // A rules file with only pass-throughs must leave the data path exactly
        // as it was: no divert, no proxy, no per-flow work.
        let rs = rules(r#"{"version":1,"passthrough":["pinned.example.com"],"rules":[]}"#);
        assert!(rs.intercept_patterns().is_empty());
    }
}
