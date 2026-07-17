//! The egress policy the userspace NAT enforces: a default action plus an
//! allow/deny list of `host[:port]` rules. This is the hypervisor-side mirror
//! of the control-plane `chm_profile.egress` that `chm` verifies (digest
//! teleport, M28.1) and hands down when it builds the net device.
//!
//! The policy is consulted at the two authoritative points the NAT mediates:
//!
//!  * **DNS resolve** — by hostname, before the host resolver is asked.
//!  * **TCP connect** — by resolved IP + port, before a host socket is opened.
//!
//! Because `chm` is the process that would open the host socket, a `Deny`
//! decision is enforced simply by *not opening it*: default-deny is unbypassable
//! from inside the guest, which has no other route off the box.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The outcome of an egress decision, carrying the matched rule for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permit the flow; `rule` is the allow entry (or `"default-allow"`) that
    /// matched.
    Allow { rule: String },
    /// Refuse the flow; `rule` is the deny entry (or `"default-deny"`) that
    /// matched.
    Deny { rule: String },
}

impl Decision {
    /// Whether this decision permits the flow.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// The matched rule string (for audit reporting).
    pub fn rule(&self) -> &str {
        match self {
            Decision::Allow { rule } | Decision::Deny { rule } => rule,
        }
    }
}

/// How a rule matches a hostname or IP literal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostMatch {
    /// `*` — matches any host.
    Any,
    /// An exact hostname, compared case-insensitively without the trailing dot.
    Exact(String),
    /// `*.example.com` — matches that domain and any subdomain of it.
    Suffix(String),
    /// A literal IPv4 address.
    Ip(Ipv4Addr),
}

impl HostMatch {
    fn parse(host: &str) -> Self {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h == "*" || h.is_empty() {
            HostMatch::Any
        } else if let Some(rest) = h.strip_prefix("*.") {
            HostMatch::Suffix(rest.to_string())
        } else if let Ok(ip) = h.parse::<Ipv4Addr>() {
            HostMatch::Ip(ip)
        } else {
            HostMatch::Exact(h)
        }
    }

    fn matches_host(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        match self {
            HostMatch::Any => true,
            HostMatch::Exact(e) => *e == h,
            HostMatch::Suffix(dom) => h == *dom || h.ends_with(&format!(".{dom}")),
            HostMatch::Ip(_) => false,
        }
    }

    fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        match self {
            HostMatch::Any => true,
            HostMatch::Ip(rule_ip) => *rule_ip == ip,
            // Hostname rules never match a bare IP: the resolved host must be
            // supplied (via the resolve cache) to match those.
            HostMatch::Exact(_) | HostMatch::Suffix(_) => false,
        }
    }
}

/// A single `host[:port]` allow/deny rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    host: HostMatch,
    /// `None` matches any port.
    port: Option<u16>,
    /// The original text, echoed back in [`Decision`] for audit.
    raw: String,
}

impl Rule {
    /// Parse a rule of the form `host`, `host:port`, or `*:port`. IPv6 literals
    /// are out of V0 scope and parsed as an opaque host (never matched).
    fn parse(raw: &str) -> Self {
        let text = raw.trim();
        let (host, port) = match text.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => {
                (h, p.parse::<u16>().ok())
            }
            _ => (text, None),
        };
        Rule {
            host: HostMatch::parse(host),
            port,
            raw: text.to_string(),
        }
    }

    fn port_matches(&self, port: u16) -> bool {
        self.port.is_none_or(|p| p == port)
    }
}

/// A short-lived cache mapping resolved IPv4 addresses back to the hostname the
/// guest asked for, so a TCP connect (which sees only an IP) can be judged
/// against hostname allow-list rules.
#[derive(Debug, Default, Clone)]
struct ResolveCache {
    entries: HashMap<Ipv4Addr, (String, Instant)>,
    ttl: Option<Duration>,
}

impl ResolveCache {
    fn record(&mut self, ip: Ipv4Addr, host: &str, now: Instant) {
        self.entries.insert(ip, (host.to_ascii_lowercase(), now));
    }

    fn lookup(&self, ip: Ipv4Addr, now: Instant) -> Option<&str> {
        self.entries.get(&ip).and_then(|(host, at)| match self.ttl {
            Some(ttl) if now.duration_since(*at) > ttl => None,
            _ => Some(host.as_str()),
        })
    }
}

/// The egress allow-list the NAT enforces.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    default_allow: bool,
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    resolve_cache: ResolveCache,
    /// A human label for the governing policy (e.g. the digest), for tracing.
    label: String,
    /// When false (the default), connects to reserved / host-internal address
    /// ranges (loopback, private LAN, link-local metadata, …) are denied
    /// *regardless* of the allow/deny rules — the guest must not reach the host's
    /// own networks (M31.1). The `--allow-local-egress` opt-in sets this true.
    allow_local_egress: bool,
}

impl EgressPolicy {
    /// An unrestricted policy: every flow is allowed. This is the M28.2 default
    /// (real networking, no gate) until `chm` supplies a real profile (M28.3).
    /// Note this is still subject to the reserved-address guard (M31.1) unless
    /// local egress is explicitly opted in.
    pub fn allow_all() -> Self {
        Self {
            default_allow: true,
            allow: Vec::new(),
            deny: Vec::new(),
            resolve_cache: ResolveCache::default(),
            label: "allow-all".to_string(),
            allow_local_egress: false,
        }
    }

    /// Build a policy from a control-plane `chm_profile.egress`: `default` is
    /// `"allow"`/`"deny"`, and `allow`/`deny` are `host[:port]` strings.
    pub fn from_profile(
        default: &str,
        allow: &[String],
        deny: &[String],
        label: impl Into<String>,
    ) -> Self {
        Self {
            default_allow: !default.eq_ignore_ascii_case("deny"),
            allow: allow.iter().map(|r| Rule::parse(r)).collect(),
            deny: deny.iter().map(|r| Rule::parse(r)).collect(),
            resolve_cache: ResolveCache {
                entries: HashMap::new(),
                ttl: Some(Duration::from_secs(600)),
            },
            label: label.into(),
            allow_local_egress: false,
        }
    }

    /// Opt the guest into reaching reserved / host-internal address ranges
    /// (loopback, private LAN, link-local). Off by default (M31.1).
    pub fn set_allow_local_egress(&mut self, allow: bool) {
        self.allow_local_egress = allow;
    }

    /// Whether reserved / host-internal egress has been explicitly opted in.
    pub fn allow_local_egress(&self) -> bool {
        self.allow_local_egress
    }

    /// Whether this policy actually restricts anything (a default-allow policy
    /// with no deny rules is a no-op the caller can skip enforcing).
    pub fn is_restrictive(&self) -> bool {
        !self.default_allow || !self.deny.is_empty()
    }

    /// The governing label (digest or `"allow-all"`), for tracing/audit.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Remember that `host` resolved to `ip`, so a later connect to `ip` can be
    /// judged against hostname rules.
    pub fn record_resolution(&mut self, host: &str, ip: Ipv4Addr) {
        self.resolve_cache.record(ip, host, Instant::now());
    }

    /// Decide a DNS resolution request for `host`. Deny rules win over allow
    /// rules; an unmatched host falls to the default action. A denied name is
    /// never resolved, so the guest cannot learn the address at all.
    pub fn decide_dns(&self, host: &str) -> Decision {
        // DNS is judged by name only; port is irrelevant, so match any port.
        if let Some(rule) = self.deny.iter().find(|r| r.host.matches_host(host)) {
            return Decision::Deny {
                rule: format!("deny {}", rule.raw),
            };
        }
        if let Some(rule) = self.allow.iter().find(|r| r.host.matches_host(host)) {
            return Decision::Allow {
                rule: format!("allow {}", rule.raw),
            };
        }
        self.default_decision()
    }

    /// Decide a TCP connect to `ip:port`. If the IP was resolved from a name in
    /// the cache, hostname rules are matched too; otherwise only IP-literal
    /// rules (and the default) apply — so a guest that skips DNS and dials a raw
    /// IP is judged by the default action, which is `deny` under a locked-down
    /// policy.
    pub fn decide_connect(&self, ip: Ipv4Addr, port: u16) -> Decision {
        let host = self.resolve_cache.lookup(ip, Instant::now()).map(str::to_string);

        // Deny rules first — an explicit deny always wins.
        for rule in &self.deny {
            if rule.port_matches(port)
                && (rule.host.matches_ip(ip)
                    || host.as_deref().is_some_and(|h| rule.host.matches_host(h)))
            {
                return Decision::Deny {
                    rule: format!("deny {}", rule.raw),
                };
            }
        }

        // Reserved-address guard (M31.1): the NAT relays through a host socket, so
        // a connect to a host-internal range would reach the Mac's own networks.
        // Deny it unless local egress was explicitly opted in, or the *trusted
        // policy* names this exact IP with an **IP-literal** allow rule. A
        // hostname allow rule that merely resolved to a reserved IP does NOT lift
        // the guard — that is exactly the DNS-rebinding vector — so an allow-all
        // default and a rebound allow-listed name are both refused.
        if !self.allow_local_egress && super::reserved::is_reserved_egress_ip(ip) {
            let explicit_ip_allow = self
                .allow
                .iter()
                .any(|rule| rule.port_matches(port) && rule.host.matches_ip(ip));
            if !explicit_ip_allow {
                return Decision::Deny {
                    rule: "reserved-address".to_string(),
                };
            }
        }

        for rule in &self.allow {
            if rule.port_matches(port)
                && (rule.host.matches_ip(ip)
                    || host.as_deref().is_some_and(|h| rule.host.matches_host(h)))
            {
                return Decision::Allow {
                    rule: format!("allow {}", rule.raw),
                };
            }
        }
        self.default_decision()
    }

    fn default_decision(&self) -> Decision {
        if self.default_allow {
            Decision::Allow {
                rule: "default-allow".to_string(),
            }
        } else {
            Decision::Deny {
                rule: "default-deny".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_permits_everything() {
        let p = EgressPolicy::allow_all();
        assert!(!p.is_restrictive());
        assert!(p.decide_dns("evil.example.com").is_allow());
        assert!(p.decide_connect(Ipv4Addr::new(1, 2, 3, 4), 443).is_allow());
    }

    #[test]
    fn default_deny_blocks_unlisted_names() {
        let p = EgressPolicy::from_profile("deny", &["api.github.com:443".into()], &[], "t");
        assert!(p.is_restrictive());
        assert!(p.decide_dns("api.github.com").is_allow());
        let d = p.decide_dns("evil.example.com");
        assert!(!d.is_allow());
        assert_eq!(d.rule(), "default-deny");
    }

    #[test]
    fn allow_rule_is_port_scoped() {
        let p = EgressPolicy::from_profile("deny", &["api.github.com:443".into()], &[], "t");
        // Same host, wrong port -> falls through to default-deny.
        let ip = Ipv4Addr::new(140, 82, 112, 6);
        let mut p2 = p;
        p2.record_resolution("api.github.com", ip);
        assert!(p2.decide_connect(ip, 443).is_allow());
        assert!(!p2.decide_connect(ip, 80).is_allow());
    }

    #[test]
    fn connect_by_ip_matches_resolved_hostname() {
        let mut p = EgressPolicy::from_profile("deny", &["api.github.com".into()], &[], "t");
        let ip = Ipv4Addr::new(140, 82, 112, 6);
        // Before resolution, a bare-IP connect under default-deny is refused.
        assert!(!p.decide_connect(ip, 443).is_allow());
        // After the guest resolves the allowed name, the IP connect is allowed.
        p.record_resolution("api.github.com", ip);
        assert!(p.decide_connect(ip, 443).is_allow());
    }

    #[test]
    fn reserved_addresses_are_denied_even_under_allow_all() {
        // The reserved-address guard (M31.1) applies before the policy: an
        // allow-all default still cannot reach the host's own networks.
        let p = EgressPolicy::allow_all();
        for host_internal in [
            Ipv4Addr::new(127, 0, 0, 1),         // loopback
            Ipv4Addr::new(10, 0, 0, 5),          // private
            Ipv4Addr::new(192, 168, 1, 1),       // private / router
            Ipv4Addr::new(169, 254, 169, 254),   // cloud metadata
        ] {
            let d = p.decide_connect(host_internal, 443);
            assert!(!d.is_allow(), "{host_internal} must be denied under allow-all");
            assert_eq!(d.rule(), "reserved-address");
        }
        // A public destination is still allowed.
        assert!(p.decide_connect(Ipv4Addr::new(140, 82, 112, 6), 443).is_allow());
    }

    #[test]
    fn reserved_guard_closes_dns_rebinding() {
        // An allow-listed name whose DNS answer rebinds to a loopback/private IP
        // must NOT authorise the connect: the reserved check runs before the
        // hostname match.
        let mut p = EgressPolicy::from_profile("deny", &["trusted.example.com".into()], &[], "t");
        let rebound = Ipv4Addr::new(127, 0, 0, 1);
        p.record_resolution("trusted.example.com", rebound);
        let d = p.decide_connect(rebound, 443);
        assert!(!d.is_allow(), "a rebound reserved IP must be refused despite the allow rule");
        assert_eq!(d.rule(), "reserved-address");
    }

    #[test]
    fn allow_local_egress_opt_in_permits_reserved() {
        let mut p = EgressPolicy::allow_all();
        assert!(!p.decide_connect(Ipv4Addr::new(127, 0, 0, 1), 443).is_allow());
        p.set_allow_local_egress(true);
        assert!(
            p.decide_connect(Ipv4Addr::new(127, 0, 0, 1), 443).is_allow(),
            "the explicit opt-in must lift the reserved-address guard"
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = EgressPolicy::from_profile(
            "allow",
            &["*".into()],
            &["blocked.example.com".into()],
            "t",
        );
        assert!(p.decide_dns("anything.test").is_allow());
        assert!(!p.decide_dns("blocked.example.com").is_allow());
    }

    #[test]
    fn suffix_wildcard_matches_subdomains() {
        let p = EgressPolicy::from_profile("deny", &["*.github.com".into()], &[], "t");
        assert!(p.decide_dns("api.github.com").is_allow());
        assert!(p.decide_dns("github.com").is_allow());
        assert!(!p.decide_dns("github.com.evil.test").is_allow());
        assert!(!p.decide_dns("notgithub.com").is_allow());
    }

    #[test]
    fn ip_literal_rule_matches_connect() {
        let p = EgressPolicy::from_profile("deny", &["10.0.0.5:22".into()], &[], "t");
        assert!(p.decide_connect(Ipv4Addr::new(10, 0, 0, 5), 22).is_allow());
        assert!(!p.decide_connect(Ipv4Addr::new(10, 0, 0, 6), 22).is_allow());
    }

    #[test]
    fn hostname_rule_ignores_bare_ip_connect() {
        // A hostname allow must NOT leak into a bare-IP connect the guest never
        // resolved through us.
        let p = EgressPolicy::from_profile("deny", &["api.github.com:443".into()], &[], "t");
        assert!(!p.decide_connect(Ipv4Addr::new(140, 82, 112, 6), 443).is_allow());
    }
}
