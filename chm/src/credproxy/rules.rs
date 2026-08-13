// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//
//! Which destinations get a credential attached, and what gets attached.
//!
//! # Telling "inject here" from "pass through"
//!
//! This is the question that decides how much of the guest's traffic the proxy
//! can read, so it is answered narrowly and explicitly:
//!
//! * A destination is intercepted **only** if a rule names it. There is no
//!   wildcard default, no "intercept everything and decide later".
//! * A destination with no rule is relayed as opaque bytes. Its TLS session is
//!   end to end between the guest and the origin; the proxy never mints a
//!   certificate for it and cannot read it.
//! * `passthrough` entries override rules, so a cert-pinned subdomain caught by
//!   a wildcard can be excluded without giving up the wildcard. Pass-through
//!   wins, mirroring the deny-wins precedence the egress firewall already uses.
//!
//! # Matching on the destination, never on what the guest said
//!
//! A rule matches the *connection's* destination — the address the NAT dialled,
//! and the hostname the NAT itself resolved for it. The guest's `Host:` header
//! and its TLS SNI are never used to select a credential. If they were, anything
//! in the sandbox could address a request to an allowlisted name, have the
//! credential attached, and route it wherever it liked.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use super::secrets::SecretSource;

/// How a credential is rendered into a header value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// `Authorization: Bearer <secret>`
    Bearer,
    /// `Authorization: Basic base64(<username>:<secret>)` — what git over HTTPS
    /// expects, and what a forge token is normally presented as.
    Basic { username: String },
    /// A literal template with `{secret}` substituted, for APIs that want their
    /// own header shape (`X-API-Key: <secret>`, `token <secret>`, and so on).
    Template { template: String },
}

impl Scheme {
    /// Renders the header value for a secret.
    fn render(&self, secret: &str) -> String {
        match self {
            Scheme::Bearer => format!("Bearer {secret}"),
            Scheme::Basic { username } => {
                let pair = format!("{username}:{secret}");
                format!("Basic {}", super::base64::encode(pair.as_bytes()))
            }
            Scheme::Template { template } => template.replace("{secret}", secret),
        }
    }
}

/// A destination pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostPattern {
    /// An exact hostname, compared case-insensitively.
    Exact(String),
    /// `*.example.com`, which matches `example.com` and any subdomain of it.
    Suffix(String),
    /// A literal IP address, for destinations reached without DNS.
    Ip(IpAddr),
}

/// Which list a host pattern came from. Only affects the wording of a
/// rejection: both lists refuse the same patterns, but for opposite reasons,
/// and a message naming the wrong list sends the reader to the wrong line.
#[derive(Clone, Copy)]
enum PatternUse {
    Injection,
    Passthrough,
}

impl HostPattern {
    fn parse(raw: &str) -> Result<Self, String> {
        Self::parse_in(raw, PatternUse::Injection)
    }

    fn parse_in(raw: &str, used_for: PatternUse) -> Result<Self, String> {
        let raw = raw.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return Err("empty host pattern".into());
        }
        if raw == "*" {
            // Deliberately refused. A rule that intercepts everything would put
            // the proxy in the middle of all guest TLS, which is exactly the
            // blast radius this design exists to avoid.
            //
            // The same refusal applies to `passthrough`, for a different
            // reason: an exclusion list that excludes everything silently
            // disables every rule above it, so a file that looks configured
            // injects nothing. Both are refused, but saying "injection host"
            // about a passthrough entry sends the reader to the wrong line.
            return Err(match used_for {
                PatternUse::Injection => {
                    "'*' is not allowed as an injection host: interception must name its destinations"
                        .into()
                }
                PatternUse::Passthrough => {
                    "'*' is not allowed in 'passthrough': it would exclude every host and \
                     silently disable every rule. Remove the rules you do not want, or list \
                     the hosts to exclude."
                        .to_string()
                }
            });
        }
        if let Some(rest) = raw.strip_prefix("*.") {
            if rest.is_empty() || !rest.contains('.') {
                return Err(format!(
                    "'{raw}' is too broad: a wildcard needs at least two labels, e.g. '*.example.com'"
                ));
            }
            return Ok(HostPattern::Suffix(rest.to_string()));
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Ok(HostPattern::Ip(ip));
        }
        if raw.contains('*') {
            return Err(format!(
                "'{raw}': wildcards are only supported as a leading '*.' label"
            ));
        }
        Ok(HostPattern::Exact(raw))
    }

    fn matches(&self, dest: &Destination) -> bool {
        match self {
            HostPattern::Exact(want) => dest.host.as_deref().is_some_and(|h| h == want),
            HostPattern::Suffix(suffix) => dest.host.as_deref().is_some_and(|h| {
                h == suffix || h.strip_suffix(suffix).is_some_and(|p| p.ends_with('.'))
            }),
            HostPattern::Ip(want) => dest.ip == Some(*want),
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => write!(f, "{h}"),
            HostPattern::Suffix(s) => write!(f, "*.{s}"),
            HostPattern::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// The destination of a connection, as the NAT saw it.
///
/// `host` is the name the NAT's own DNS server resolved to `ip`, not anything
/// the guest asserted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Destination {
    pub(crate) host: Option<String>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) port: u16,
}

impl Destination {
    pub(crate) fn new(host: Option<String>, ip: Option<IpAddr>, port: u16) -> Self {
        Self {
            host: host.map(|h| h.trim_end_matches('.').to_ascii_lowercase()),
            ip,
            port,
        }
    }

    /// The name to put in a minted certificate and to send as SNI upstream.
    pub(crate) fn tls_name(&self) -> Option<String> {
        self.host
            .clone()
            .or_else(|| self.ip.map(|ip| ip.to_string()))
    }

    pub(crate) fn describe(&self) -> String {
        match (&self.host, self.ip) {
            (Some(h), Some(ip)) => format!("{h} [{ip}]:{}", self.port),
            (Some(h), None) => format!("{h}:{}", self.port),
            (None, Some(ip)) => format!("{ip}:{}", self.port),
            (None, None) => format!("<unknown>:{}", self.port),
        }
    }
}

/// One injection rule.
#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) name: String,
    pub(crate) hosts: Vec<HostPattern>,
    pub(crate) ports: Vec<u16>,
    pub(crate) header: String,
    pub(crate) scheme: Scheme,
    pub(crate) secret: SecretSource,
    /// Whether this credential may be attached over cleartext HTTP.
    ///
    /// Off by default: attaching a secret to a plaintext request puts it on the
    /// wire in the clear, which defeats the point of keeping it off the guest.
    pub(crate) allow_cleartext: bool,
}

impl Rule {
    fn matches(&self, dest: &Destination) -> bool {
        self.ports.contains(&dest.port) && self.hosts.iter().any(|h| h.matches(dest))
    }

    /// Renders the header this rule attaches, given a resolved secret.
    pub(crate) fn render(&self, secret: &str) -> (String, String) {
        (self.header.clone(), self.scheme.render(secret))
    }
}

/// What the proxy should do with a connection.
#[derive(Clone, Debug)]
pub(crate) enum Disposition {
    /// Terminate TLS and attach the rule's credential.
    Inject(Rule),
    /// Relay bytes without looking at them.
    PassThrough(PassReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PassReason {
    /// No rule names this destination.
    NoRule,
    /// A rule would have matched, but an explicit `passthrough` entry wins.
    ExplicitlyExcluded,
    /// A rule matched but only permits injection over TLS.
    CleartextRefused,
}

impl PassReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PassReason::NoRule => "no-rule",
            PassReason::ExplicitlyExcluded => "passthrough-list",
            PassReason::CleartextRefused => "cleartext-refused",
        }
    }
}

/// What [`RuleSet::implied_egress_allow`] derived: entries to widen the
/// allow-list with, and hosts it could not represent.
#[derive(Clone, Debug, Default)]
pub(crate) struct ImpliedEgress {
    /// `host:port` entries in [`EgressPolicy`] syntax.
    pub(crate) allow: Vec<String>,
    /// Rule hosts that produced no entry, each already annotated with its rule
    /// name so the caller can say which rule is not covered.
    pub(crate) skipped: Vec<String>,
}

/// The full set of injection rules for a workspace.
#[derive(Clone, Debug, Default)]
pub(crate) struct RuleSet {    pub(crate) rules: Vec<Rule>,
    pub(crate) passthrough: Vec<HostPattern>,
    pub(crate) label: Option<String>,
}

impl RuleSet {
    /// Every hostname pattern that could be intercepted.
    ///
    /// The NAT uses this to decide which flows to divert at all, so a
    /// destination with no rule is never even routed through the proxy.
    pub(crate) fn intercept_patterns(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for rule in &self.rules {
            for host in &rule.hosts {
                let text = host.to_string();
                if !seen.contains(&text) {
                    seen.push(text);
                }
            }
        }
        seen
    }

    /// Decides what to do with a connection to `dest`.
    /// The egress allow-list entries these rules imply, one per host × port,
    /// plus a list of hosts that had to be skipped.
    ///
    /// **Why this exists (V8.7).** Naming a host in an injection rule *is* the
    /// intent to reach it, but interception and the firewall are enforced by
    /// different subsystems: the NAT decides the connect before it ever consults
    /// the interception hook, so under a default-deny policy the flow was refused
    /// before the proxy could see it. The configuration was right and the guest
    /// was blocked anyway.
    ///
    /// Entries render in exactly the syntax [`EgressPolicy`] parses: `host:port`,
    /// `*.suffix:port`, or `ip:port`. The port is always explicit, so widening
    /// for an injection rule on 443 does not also open 22 on the same name.
    ///
    /// **`passthrough` is deliberately not consulted.** It withholds the
    /// *credential*, not the destination — the reachability is implied by the
    /// rule pattern the entry sits inside, and a passthrough host is one the
    /// operator expects the guest to reach without a secret attached.
    ///
    /// IPv6 rule hosts are returned as skips rather than entries: the egress
    /// policy parses IPv4 literals only, so an IPv6 entry would compile to an
    /// exact-hostname match that can never fire. Emitting one would look like
    /// coverage and provide none.
    pub(crate) fn implied_egress_allow(&self) -> ImpliedEgress {
        let mut allow: Vec<String> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        for rule in &self.rules {
            for host in &rule.hosts {
                if matches!(host, HostPattern::Ip(IpAddr::V6(_))) {
                    let note = format!("{} (rule '{}')", host, rule.name);
                    if !skipped.contains(&note) {
                        skipped.push(note);
                    }
                    continue;
                }
                for port in &rule.ports {
                    let entry = format!("{host}:{port}");
                    if !allow.contains(&entry) {
                        allow.push(entry);
                    }
                }
            }
        }
        ImpliedEgress { allow, skipped }
    }

    pub(crate) fn decide(&self, dest: &Destination) -> Disposition {
        if self.passthrough.iter().any(|p| p.matches(dest)) {
            return Disposition::PassThrough(PassReason::ExplicitlyExcluded);
        }
        let Some(rule) = self.rules.iter().find(|r| r.matches(dest)) else {
            return Disposition::PassThrough(PassReason::NoRule);
        };
        // Port 80 carries no confidentiality, so a credential only goes out over
        // it if the rule opted in explicitly.
        if dest.port == 80 && !rule.allow_cleartext {
            return Disposition::PassThrough(PassReason::CleartextRefused);
        }
        Disposition::Inject(rule.clone())
    }

    /// Parses a rule document.
    ///
    /// The document is JSON so it can be authored by hand, checked in, or handed
    /// down by the control plane in the same shape as the egress policy.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let doc: RuleSetDoc =
            serde_json::from_str(text).map_err(|e| format!("not valid rule JSON: {e}"))?;
        doc.compile()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleSetDoc {
    #[serde(default = "one")]
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) rules: Vec<RuleDoc>,
    #[serde(default)]
    pub(crate) passthrough: Vec<String>,
}

fn one() -> u32 {
    1
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDoc {
    pub(crate) name: String,
    pub(crate) hosts: Vec<String>,
    #[serde(default)]
    pub(crate) ports: Vec<u16>,
    #[serde(default)]
    pub(crate) header: Option<String>,
    /// `bearer` (default), `basic`, or `template`.
    #[serde(default)]
    pub(crate) scheme: Option<String>,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) template: Option<String>,
    /// Exactly one of `env`, `file`, or `exec` must be present.
    #[serde(default)]
    pub(crate) env: Option<String>,
    #[serde(default)]
    pub(crate) file: Option<String>,
    #[serde(default)]
    pub(crate) exec: Option<Vec<String>>,
    /// Cache lifetime for an `exec` secret, in seconds.
    #[serde(default)]
    pub(crate) ttl_secs: Option<u64>,
    #[serde(default)]
    pub(crate) allow_cleartext: Option<bool>,
}

impl RuleSetDoc {
    fn compile(self) -> Result<RuleSet, String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported rule document version {} (this build understands version 1)",
                self.version
            ));
        }

        let mut names: BTreeMap<String, ()> = BTreeMap::new();
        let mut rules = Vec::with_capacity(self.rules.len());
        for doc in self.rules {
            if doc.name.trim().is_empty() {
                return Err("every rule needs a name so the audit log can identify it".into());
            }
            if names.insert(doc.name.clone(), ()).is_some() {
                return Err(format!("duplicate rule name '{}'", doc.name));
            }
            rules.push(doc.compile()?);
        }

        let passthrough = self
            .passthrough
            .iter()
            .map(|p| {
                HostPattern::parse_in(p, PatternUse::Passthrough)
                    .map_err(|e| format!("passthrough: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RuleSet {
            rules,
            passthrough,
            label: self.label,
        })
    }
}

impl RuleDoc {
    fn compile(self) -> Result<Rule, String> {
        let where_ = format!("rule '{}'", self.name);
        if self.hosts.is_empty() {
            return Err(format!("{where_}: needs at least one host"));
        }
        let hosts = self
            .hosts
            .iter()
            .map(|h| HostPattern::parse(h).map_err(|e| format!("{where_}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        let ports = if self.ports.is_empty() {
            vec![443]
        } else {
            self.ports.clone()
        };

        let scheme = match self.scheme.as_deref().unwrap_or("bearer") {
            "bearer" => Scheme::Bearer,
            "basic" => Scheme::Basic {
                // Forge tokens are conventionally presented with a placeholder
                // username, which is why this default exists.
                username: self
                    .username
                    .clone()
                    .unwrap_or_else(|| "x-access-token".to_string()),
            },
            "template" => {
                let template = self.template.clone().ok_or_else(|| {
                    format!("{where_}: scheme 'template' needs a 'template' field")
                })?;
                if !template.contains("{secret}") {
                    return Err(format!(
                        "{where_}: template has no '{{secret}}' placeholder, so nothing would be injected"
                    ));
                }
                Scheme::Template { template }
            }
            other => {
                return Err(format!(
                    "{where_}: unknown scheme '{other}' (expected bearer, basic, or template)"
                ));
            }
        };

        let secret = SecretSource::from_doc(&self.env, &self.file, &self.exec, self.ttl_secs)
            .map_err(|e| format!("{where_}: {e}"))?;

        let header = self
            .header
            .clone()
            .unwrap_or_else(|| "Authorization".to_string());
        if header.trim().is_empty() || !header.bytes().all(is_token_byte) {
            return Err(format!("{where_}: '{header}' is not a valid header name"));
        }

        Ok(Rule {
            name: self.name,
            hosts,
            ports,
            header,
            scheme,
            secret,
            allow_cleartext: self.allow_cleartext.unwrap_or(false),
        })
    }
}

/// RFC 9110 token characters, which is what a header field name may contain.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(host: &str, port: u16) -> Destination {
        Destination::new(
            Some(host.to_string()),
            Some("93.184.216.34".parse().unwrap()),
            port,
        )
    }

    fn ruleset(json: &str) -> RuleSet {
        RuleSet::parse(json).expect("rules should parse")
    }

    const GITHUB: &str = r#"{
      "version": 1,
      "rules": [{
        "name": "github",
        "hosts": ["github.com", "*.github.com"],
        "scheme": "basic",
        "env": "GIMBAL_GITHUB_TOKEN"
      }]
    }"#;

    #[test]
    fn a_named_host_is_intercepted_and_anything_else_passes_through() {
        let rs = ruleset(GITHUB);
        assert!(matches!(
            rs.decide(&dest("github.com", 443)),
            Disposition::Inject(_)
        ));
        assert!(matches!(
            rs.decide(&dest("api.github.com", 443)),
            Disposition::Inject(_)
        ));
        match rs.decide(&dest("example.com", 443)) {
            Disposition::PassThrough(PassReason::NoRule) => {}
            other => panic!("unrelated hosts must not be intercepted, got {other:?}"),
        }
    }

    #[test]
    fn a_wildcard_does_not_match_a_lookalike_suffix() {
        let rs = ruleset(GITHUB);
        // The classic bug: 'notgithub.com' ends with 'github.com' as a string
        // but is a different domain.
        match rs.decide(&dest("notgithub.com", 443)) {
            Disposition::PassThrough(PassReason::NoRule) => {}
            other => panic!("suffix matching must respect label boundaries, got {other:?}"),
        }
    }

    #[test]
    fn a_wildcard_passthrough_is_refused_and_says_which_list_it_came_from() {
        // Both lists refuse '*', but for opposite reasons: an injection
        // wildcard would intercept all guest TLS, while a passthrough wildcard
        // would silently disable every rule above it. A reader who gets the
        // injection wording for a passthrough entry looks at the wrong line.
        let err = RuleSet::parse(
            r#"{
              "version": 1,
              "rules": [{"name": "gh", "hosts": ["api.github.com"], "env": "T"}],
              "passthrough": ["*"]
            }"#,
        )
        .expect_err("'*' must not be accepted as a passthrough entry");
        assert!(err.contains("passthrough"), "{err}");
        assert!(
            !err.contains("injection host"),
            "passthrough rejection must not blame injection: {err}"
        );
    }

    #[test]
    fn a_wildcard_injection_host_is_still_refused_as_before() {
        let err = RuleSet::parse(
            r#"{"version": 1, "rules": [{"name": "all", "hosts": ["*"], "env": "T"}]}"#,
        )
        .expect_err("'*' must not be accepted as an injection host");
        assert!(err.contains("injection host"), "{err}");
    }

    #[test]
    fn passthrough_overrides_a_matching_rule() {
        let rs = ruleset(
            r#"{
              "version": 1,
              "rules": [{"name":"gh","hosts":["*.github.com"],"env":"T"}],
              "passthrough": ["codeload.github.com"]
            }"#,
        );
        assert!(matches!(
            rs.decide(&dest("api.github.com", 443)),
            Disposition::Inject(_)
        ));
        match rs.decide(&dest("codeload.github.com", 443)) {
            Disposition::PassThrough(PassReason::ExplicitlyExcluded) => {}
            other => panic!("passthrough must win over a rule, got {other:?}"),
        }
    }

    #[test]
    fn cleartext_is_refused_unless_the_rule_opts_in() {
        let rs = ruleset(
            r#"{"version":1,"rules":[{"name":"gh","hosts":["gh.internal"],"ports":[80],"env":"T"}]}"#,
        );
        match rs.decide(&dest("gh.internal", 80)) {
            Disposition::PassThrough(PassReason::CleartextRefused) => {}
            other => panic!("must not put a secret on the wire in clear, got {other:?}"),
        }

        let opted_in = ruleset(
            r#"{"version":1,"rules":[{"name":"gh","hosts":["gh.internal"],"ports":[80],"env":"T","allow_cleartext":true}]}"#,
        );
        assert!(matches!(
            opted_in.decide(&dest("gh.internal", 80)),
            Disposition::Inject(_)
        ));
    }

    #[test]
    fn a_rule_only_applies_on_its_ports() {
        let rs = ruleset(GITHUB);
        match rs.decide(&dest("github.com", 22)) {
            Disposition::PassThrough(PassReason::NoRule) => {}
            other => panic!("port 22 has no rule, got {other:?}"),
        }
    }

    #[test]
    fn intercept_everything_is_refused() {
        let err =
            RuleSet::parse(r#"{"version":1,"rules":[{"name":"all","hosts":["*"],"env":"T"}]}"#)
                .expect_err("'*' must be refused");
        assert!(err.contains("must name its destinations"), "{err}");

        let broad =
            RuleSet::parse(r#"{"version":1,"rules":[{"name":"tld","hosts":["*.com"],"env":"T"}]}"#)
                .expect_err("a single-label wildcard must be refused");
        assert!(broad.contains("too broad"), "{broad}");
    }

    #[test]
    fn schemes_render_the_shapes_real_services_expect() {
        assert_eq!(Scheme::Bearer.render("tok"), "Bearer tok");
        assert_eq!(
            Scheme::Basic {
                username: "x-access-token".into()
            }
            .render("tok"),
            // base64("x-access-token:tok")
            format!(
                "Basic {}",
                super::super::base64::encode(b"x-access-token:tok")
            )
        );
        assert_eq!(
            Scheme::Template {
                template: "token {secret}".into()
            }
            .render("tok"),
            "token tok"
        );
    }

    #[test]
    fn a_template_without_a_placeholder_is_rejected() {
        let err = RuleSet::parse(
            r#"{"version":1,"rules":[{"name":"x","hosts":["a.example.com"],"scheme":"template","template":"nope","env":"T"}]}"#,
        )
        .expect_err("a template that injects nothing is a mistake, not a config");
        assert!(err.contains("placeholder"), "{err}");
    }

    #[test]
    fn ip_rules_match_only_the_literal_address() {
        let rs =
            ruleset(r#"{"version":1,"rules":[{"name":"ip","hosts":["203.0.113.9"],"env":"T"}]}"#);
        let d = Destination::new(None, Some("203.0.113.9".parse().unwrap()), 443);
        assert!(matches!(rs.decide(&d), Disposition::Inject(_)));
        let other = Destination::new(None, Some("203.0.113.10".parse().unwrap()), 443);
        assert!(matches!(rs.decide(&other), Disposition::PassThrough(_)));
    }

    #[test]
    fn rules_need_unique_names_for_the_audit_log() {
        let err = RuleSet::parse(
            r#"{"version":1,"rules":[
                 {"name":"dup","hosts":["a.example.com"],"env":"T"},
                 {"name":"dup","hosts":["b.example.com"],"env":"T"}]}"#,
        )
        .expect_err("duplicate names must be refused");
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn unknown_fields_are_refused_rather_than_silently_ignored() {
        // A typo in a security policy must be loud.
        let err = RuleSet::parse(
            r#"{"version":1,"rules":[{"name":"x","hosts":["a.example.com"],"env":"T","allowcleartext":true}]}"#,
        )
        .expect_err("typos must not be ignored");
        assert!(
            err.contains("allowcleartext") || err.contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn implied_egress_names_every_host_and_port_the_rules_use() {
        let rs = ruleset(
            r#"{"rules":[
                 {"name":"gh","hosts":["api.github.com","*.githubusercontent.com"],
                  "env":"T"},
                 {"name":"reg","hosts":["registry.npmjs.org"],"ports":[443,80],
                  "env":"T"}
               ]}"#,
        );
        let implied = rs.implied_egress_allow();
        assert_eq!(
            implied.allow,
            vec![
                "api.github.com:443",
                "*.githubusercontent.com:443",
                "registry.npmjs.org:443",
                "registry.npmjs.org:80",
            ]
        );
        assert!(implied.skipped.is_empty());
    }

    #[test]
    fn implied_egress_entries_parse_as_egress_rules() {
        // The entries only help if the firewall understands them, so assert
        // against the real policy rather than the string shape.
        let rs = ruleset(
            r#"{"rules":[{"name":"gh","hosts":["api.github.com","*.githubusercontent.com",
                          "203.0.113.7"],"env":"T"}]}"#,
        );
        let mut policy =
            hypervisor::hvf::virtio::nat::EgressPolicy::from_profile("deny", &[], &[], "t");
        policy.allow_implied(&rs.implied_egress_allow().allow, "test");
        assert!(policy.decide_dns("api.github.com").is_allow());
        assert!(policy.decide_dns("raw.githubusercontent.com").is_allow());
        assert!(!policy.decide_dns("evil.test").is_allow());
        assert!(policy
            .decide_connect("203.0.113.7".parse().unwrap(), 443)
            .is_allow());
    }

    #[test]
    fn a_ports_list_does_not_widen_beyond_the_ports_named() {
        let rs = ruleset(r#"{"rules":[{"name":"gh","hosts":["api.github.com"],"env":"T"}]}"#);
        let mut policy =
            hypervisor::hvf::virtio::nat::EgressPolicy::from_profile("deny", &[], &[], "t");
        policy.allow_implied(&rs.implied_egress_allow().allow, "test");
        policy.record_resolution("api.github.com", "140.82.112.6".parse().unwrap());
        assert!(policy
            .decide_connect("140.82.112.6".parse().unwrap(), 443)
            .is_allow());
        // An injection rule on 443 must not also open SSH on the same name.
        assert!(!policy
            .decide_connect("140.82.112.6".parse().unwrap(), 22)
            .is_allow());
    }

    #[test]
    fn an_ipv6_rule_host_is_skipped_rather_than_silently_dead() {
        // The egress policy parses IPv4 literals only, so an IPv6 entry would
        // compile to an exact-hostname match that can never fire. Reporting a
        // skip is honest; emitting one would look like coverage.
        let rs = ruleset(
            r#"{"rules":[{"name":"six","hosts":["2001:db8::1","api.github.com"],"env":"T"}]}"#,
        );
        let implied = rs.implied_egress_allow();
        assert_eq!(implied.allow, vec!["api.github.com:443"]);
        assert_eq!(implied.skipped.len(), 1);
        assert!(implied.skipped[0].contains("2001:db8::1"), "{:?}", implied.skipped);
        assert!(implied.skipped[0].contains("six"), "{:?}", implied.skipped);
    }

    #[test]
    fn passthrough_hosts_are_not_treated_as_reachability_intent() {
        // `passthrough` withholds the credential, not the destination. It must
        // not add entries of its own -- reachability comes from the rule pattern
        // it sits inside, and inventing one here would widen for a host no rule
        // names.
        let rs = ruleset(
            r#"{"rules":[{"name":"gh","hosts":["*.github.com"],"env":"T"}],
                "passthrough":["gist.github.com"]}"#,
        );
        assert_eq!(rs.implied_egress_allow().allow, vec!["*.github.com:443"]);
    }

    #[test]
    fn no_rules_implies_no_widening() {
        assert!(RuleSet::default().implied_egress_allow().allow.is_empty());
    }

    #[test]
    fn a_host_named_by_two_rules_is_implied_once() {
        let rs = ruleset(
            r#"{"rules":[{"name":"a","hosts":["api.github.com"],"env":"T"},
                         {"name":"b","hosts":["api.github.com"],"env":"T"}]}"#,
        );
        assert_eq!(rs.implied_egress_allow().allow, vec!["api.github.com:443"]);
    }
}
