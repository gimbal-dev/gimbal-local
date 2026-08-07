# The credential proxy

> The developer's repo problem is a **credentials** problem, not a filesystem
> problem. A sandbox that can authenticate to GitHub can clone the repo itself.
> The question is how it authenticates without ever holding the credential.

`chm` answers that by putting a proxy in front of the guest's network. The job
makes its normal outbound call with no secret. Right as the request leaves the
machine, the proxy rewrites the headers to add the credential. The upstream
service sees an authenticated request. **The guest never saw the secret.**

The secret lives only in `chm`.

---

## 1. How it works

```
   guest                    chm (host)                        origin
  ───────                  ────────────                      ────────
  GET /user      ──▶  NAT: which flow is this?
  (no credential)          │
                           ├─ no rule ──────────────▶  relayed opaquely,
                           │                            end-to-end TLS,
                           │                            chm cannot read it
                           │
                           └─ rule matches
                                  │
                              credential proxy
                                  ├ terminate TLS with a leaf we mint
                                  ├ parse the request head
                                  ├ attach Authorization: Bearer …
                                  └ open a verified TLS connection ──▶ GET /user
                                                                       Authorization: …
```

Four things happen, in this order:

1. **The guest makes a normal request** to some host, with no credential (or a
   harmless placeholder).
2. **The NAT decides whether to divert it.** `chm` *is* the guest's entire
   network — the userspace NAT opens every host socket — so this decision cannot
   be bypassed from inside the sandbox and needs no guest configuration.
3. **The proxy checks the destination.** If a rule matches, it injects the real
   credential in whatever form that host expects.
4. **The proxy opens its own verified connection upstream** and forwards the
   request. The response streams straight back, untouched.

From the guest's point of view nothing changed. It just works.

### The one thing the guest must be told

To rewrite headers inside TLS, the proxy has to terminate TLS, which means the
guest must trust a certificate the proxy mints. That is the single piece of
guest-side setup:

```console
$ chm proxy ca ./my-workspace --for-guest
```

This prints a self-contained shell block to paste into the guest console. It
installs the certificate and then reports, separately, what each kind of client
will actually do with it:

```
system store: trusted
node:         configured (/etc/gimbal/proxy-ca.crt)
installed:    82ea8085…
expected:     82ea8085…
this shell:   . /etc/gimbal/proxy-ca.env
```

**Scope:** the proxy only ever mints a leaf for a host that a rule already
names — everything else is relayed with the origin's own certificate, so the
CA's reach is exactly the allow-list.

### Node does not read the system trust store

Installing the CA where `curl`, `git` and `apt` look does **not** configure
Node, which carries its own compiled-in root list and consults
`NODE_EXTRA_CA_CERTS` for anything else. Measured in one guest, seconds apart,
with the CA verified in the system store:

| | |
| --- | --- |
| `node` | `fail SELF_SIGNED_CERT_IN_CHAIN` |
| `NODE_EXTRA_CA_CERTS=… node` | `ok status=403` |

The 403 is the proof, not a problem: the handshake completed and the request
reached GitHub, which rejected the deliberately fake token the probe rule
attached. **A coding agent is a Node program**, so an installer that stopped at
the system store shipped a guest where `curl` worked and the agent did not.

Two consequences worth knowing:

- **A script cannot export into the shell that ran it.** The certificate is
  written with a one-line `/etc/gimbal/proxy-ca.env` beside it, and the
  installer prints `. /etc/gimbal/proxy-ca.env` for the shell you are in.
  `/etc/profile.d` covers later *login* shells — which a container guest's
  `/bin/sh` is not.
- **Node ignores an unreadable or unparseable `NODE_EXTRA_CA_CERTS` silently.**
  So the installer has Node itself parse the file and reports `NOT LOADED` if
  it cannot — a failure that otherwise has no symptom at all until a request
  fails for an unrelated-looking reason.

### A container guest has none of the usual furniture

Measured on `node:22-slim`: no `sudo`, no `openssl`, no
`update-ca-certificates`, and none of `/usr/local/share/ca-certificates`,
`/usr/share/ca-certificates` or `/etc/ssl/certs`. An earlier installer opened
with `sudo tee`, so **every line of it failed** — on exactly the kind of image
these docs recommend for running an agent. It now uses `sudo` only if it is
both needed and present, creates what it needs, and degrades to a named
outcome (`installed, unverified (no openssl here)`) rather than either failing
or claiming a trust it did not verify.

Two things the trust-store check has to be, learned by getting both wrong:

- **It must ask the question the guest will ask.** An earlier version re-read
  the file it had just written and reported matching fingerprints on a guest
  where `update-ca-certificates` had segfaulted and the CA never reached
  `/etc/ssl/certs`. A check that cannot fail is not evidence. The installer now
  links the certificate by hand when the helper fails, and says `NOT TRUSTED`
  when it still cannot verify.
- **It must survive the console.** Gimbal Local's *Install CA in guest* button
  types this at a serial line, and typing it line by line does not work:
  `update-ca-certificates` takes seconds, so every line behind it sits in the
  tty input queue, gets echoed, and never runs. So the app sends the script as
  base64 in short appends — nothing is ever typed at a busy shell — and the
  guest hashes what it received against a digest computed host-side *before*
  running any of it. A dropped character is then `TRANSFER CORRUPT`, named at
  the moment it happens, rather than a corrupt certificate that surfaces later
  as an unexplained TLS error.

---

## 2. Two kinds of secrets

Not every secret is the same, and the split decides where it should live.

| | **Remote-call secrets** | **On-machine secrets** |
| --- | --- | --- |
| What | Credentials whose whole purpose is to authenticate an outbound request — a GitHub token, a cloud key, a registry login, a webhook signing key. | Secrets that must genuinely be present to do local work — a key that decrypts a file, a signing key a local tool invokes. |
| Does the guest need to hold it? | **No.** It only needs the call to come out authenticated. | **Yes.** The work is not a network call, so there is no network edge to handle it at. |
| Where it belongs | **The proxy.** | The guest, with their own protections. |

The proxy shrinks the first bucket to **zero on the guest**. Naming the split is
the point: it lets us push as many secrets as possible out of "on the machine"
and into "injected at transport time", and be honest about the remainder.

---

## 3. Configuring it

A rules file — `<workspace>/proxy-rules.json`, `CHM_PROXY_RULES` (a path *or* the
document itself), or `--proxy-rules FILE` on `chm run`:

```json
{
  "version": 1,
  "label": "coding-agent egress",
  "passthrough": ["pinned.example.com"],
  "rules": [
    {
      "name": "github-api",
      "hosts": ["api.github.com"],
      "scheme": "bearer",
      "exec": ["gh", "auth", "token"],
      "ttl_secs": 300
    },
    {
      "name": "github-git",
      "hosts": ["github.com"],
      "scheme": "basic",
      "username": "x-access-token",
      "env": "GH_TOKEN"
    }
  ]
}
```

```console
$ chm proxy show ./my-workspace
credential proxy: coding-agent egress (from ./my-workspace/proxy-rules.json)
  github-api → api.github.com
      injects Authorization from exec:gh (ttl 300s) [on-demand]
  github-git → github.com
      injects Authorization from env:GH_TOKEN [present]
  never intercepted: pinned.example.com

Everything not listed above is relayed end-to-end; the proxy cannot read it.
```

`show` never reads a credential value — an `exec` source is reported as
`on-demand` rather than being run.

### Rule fields

| Field | Meaning |
| --- | --- |
| `name` | Identifies the rule in logs and audit records. |
| `hosts` | Exact names (`api.github.com`) or wildcards with **at least two labels** (`*.example.com`). `*` and `*.com` are refused as too broad. |
| `ports` | Defaults to `[443]`. |
| `header` | Defaults to `Authorization`. |
| `scheme` | `bearer`, `basic` (with `username`), or `template` (with `template`, where `{secret}` is substituted). |
| `env` / `file` / `exec` | Exactly one. Where the credential comes from. |
| `ttl_secs` | For `exec` only: how long a minted credential is reused. |
| `allow_cleartext` | Permit injection on a non-TLS port. Off by default. |

### Credential sources

- **`env`** — read from `chm`'s own environment.
- **`file`** — read from a file, trimmed.
- **`exec`** — run a command and use its stdout.

`exec` is the best of the three, and the reason is in the user-facing behaviour:
**nothing runs until a request to a matching destination actually arrives.** If
the job never calls GitHub, no token is ever minted. There is no standing
credential sitting around waiting to be stolen. `ttl_secs` bounds reuse.

A failing `exec` reports only its exit status — never its stderr, which can echo
the credential it failed to produce.

---

## 4. Choosing what to intercept

**Interception is opt-in per host and never a wildcard.** A flow with no matching
rule is relayed as opaque bytes: the proxy does not terminate its TLS, does not
parse it, and cannot read it. This is deliberate — routing traffic through the
one process that holds every credential, for no reason, is pure added risk.

The order of decisions:

1. **`passthrough` wins.** Listed here, a host is never intercepted even if a
   rule would match. This mirrors the firewall's deny-wins house style and is how
   you exclude a certificate-pinned subdomain without giving up a wildcard.
2. **A matching rule intercepts.**
3. **Anything else is relayed.**

Two cases are worth calling out because they look like they should intercept and
do not:

- **A guest that skipped DNS** and dialled a raw IP supplies no hostname, so a
  hostname rule cannot fire. The flow goes direct rather than being intercepted
  on a guess.
- **A rules file with only `passthrough` entries** installs no hook at all — the
  data path is exactly as it was, with no per-flow work.

### A rule makes its host reachable

Naming a host in a rule *is* the intent to reach it, so the egress allow-list is
widened to match and you do not have to say it twice:

```console
$ chm create --proxy-rules ./rules.json ...      # note: no --egress-allow
chm: [proxy] egress widened for api.github.com:443 — implied by the injection
     rules in --rules ./rules.json
```

The widening is narrow on purpose:

- **Only the rule's own `host:port` pairs.** A rule on 443 does not also open 22
  on the same name.
- **Appended to `allow`, and deny is matched first**, so this can never overrule
  a refusal you wrote.
- **`passthrough` is not consulted.** It withholds the *credential*, not the
  destination; reachability comes from the rule pattern it sits inside.
- **IPv6 rule hosts are skipped and reported**, not emitted. The egress matcher
  parses IPv4 literals only, so an IPv6 entry would compile to an exact-hostname
  match that can never fire — which would look like coverage and provide none.
- **The reserved-address guard is untouched.** Only an explicit IP-literal allow
  lifts it, and an implied entry gets no special standing, so a rule host that
  resolves to `127.0.0.1` is still refused.

Every implied entry carries its provenance into the decision it produces, so an
operator reading an audit trail later can tell what wrote it:

```
allow api.github.com:443 (implied by credential rule 'github')
```

**The same authority must have written both halves.** Rule sources and egress
sources mirror each other exactly — a flag, an environment variable, or a file in
the workspace — and the environment layer is the control plane's channel. The
widening therefore applies only when the rules and the policy came from the same
authority. This is what stops a `proxy-rules.json` that merely *happens* to be in
a workspace directory from reopening a host that a governed, digest-pinned policy
deliberately closed. It is refused in both directions: the rule is "the same
authority wrote both halves", not "one side is trusted". A policy that could not
be resolved at all is never widened, because that is precisely the case where we
cannot tell what was meant to govern the run.

---

## 5. What stops the guest from stealing the credential

**The credential is chosen by the destination the NAT admitted — never by
anything the guest says.** Not the `Host` header, not the TLS SNI. A guest that
connects to `attacker.test` and claims `Host: api.github.com` gets
`attacker.test`'s disposition, which is "no rule, relay it". There is a test for
exactly this.

The rest of the hardening, and why each is there:

| Property | Why |
| --- | --- |
| Every existing copy of the managed header is dropped before ours is appended. | Replacing only the first would leave the guest's own copy on the wire beside ours, and which one an origin honours is not ours to decide. |
| A request with **both** `Content-Length` and `Transfer-Encoding` is refused. | That ambiguity is *the* request-smuggling primitive. |
| Obsolete header line folding is refused. | Removed from the standard because implementations disagree — same class of bug. |
| Request heads are bounded at 64 KiB. | A guest cannot hold a connection open forever by never sending the blank line. |
| Cleartext (port 80) gets no credential unless `allow_cleartext` is set. | Attaching a secret to a plaintext request puts it on the wire in the clear, defeating the point. |
| A missing credential **fails the connection**. | The alternative is silently letting the request go out unauthenticated, which looks like it worked. |
| Upstream verification is never relaxed. | Interception changes who the *guest* trusts, not who the *proxy* trusts. Origins are fully validated against the host trust store. |
| Upstream connects to the IP the NAT already admitted. | Stops DNS moving underneath the policy decision between admit and connect. |
| ALPN advertises `http/1.1` only. | Keeps the proxy out of HTTP/2 framing entirely. |
| `Secret` redacts itself in `Debug` and zeroes on drop. | Rules are cloned and logged throughout; a credential must not ride along. |

---

## 6. The honest limitations

**The proxy authenticates the destination, not the caller.** Anything running in
the guest can route a request through it and get the credential attached, so an
attacker with code execution can still make *authorized calls during the job*.
What they cannot do is take a reusable secret away with them. This is why the
credential should be short-lived, tightly scoped, and per-job — the `exec` source
exists to make that the easy path.

**Full control of the guest gets you nothing durable.** A compromised job cannot
exfiltrate a credential that was never on the guest. That is the property being
bought, and it is worth being precise that it is that property and not
"the job cannot misuse the credential".

**The guest trusts a proxy CA.** Narrowly: only hosts a rule names ever see a
minted certificate. But the CA private key is on the host, and the proxy is now
the thing holding the secrets, so it is the component to harden.

**The two TLS legs have deliberately different rules.**

| Leg | Versions | Why |
| --- | --- | --- |
| guest → proxy | **1.3 only** | We mint the certificate and the peer is a client in a sandbox we booted. There is no legacy party to accommodate. |
| proxy → origin | 1.3 preferred, **1.2 accepted** | The origin is not ours to choose. |

That asymmetry exists because of a measurement, not a preference. Surveying
eleven hosts a coding agent actually depends on (2026-07-31):

| | TLS 1.3 |
| --- | --- |
| github.com, api.github.com, codeload.github.com | yes |
| pypi.org, files.pythonhosted.org | yes |
| crates.io, static.crates.io | yes |
| ghcr.io, registry-1.docker.io, proxy.golang.org | yes |
| **registry.npmjs.org** | **no — TLS 1.2 only** |

npm is the sole outlier, and it is the one a coding agent needs most. Refusing to
inject there would not have made anything safer: the guest would simply have
reached npm down the pass-through path instead, at the same origin over the same
TLS 1.2, only without the credential *and* without the audit record. rustls's
TLS 1.2 is a narrow profile — ECDHE + AEAD only, no CBC, no static RSA, no
renegotiation, no compression.

So 1.2 is permitted upstream but never silent: **the negotiated version is
recorded per connection**, and a live test (`live_injection_works_against_a_tls_1_2_only_origin`)
holds the npm case down. Enabling rustls's `tls12` feature relaxes nothing on its
own — every TLS config in this workspace names its acceptable versions
explicitly, including `vm-migration`'s, which stays 1.3-only.

**Responses are relayed without being parsed.** Knowing where a response ends
requires full response framing, and partial or heuristic parsing is worse than
none. The consequence is visible in the audit trail: it records the request
method and target, but **no status code**.

**The decision trail is durable, and separate from the live one.** The proxy
keeps a bounded in-memory ring for `CHM_PROXY_LOG`, which is a debugging aid and
dies with the process. Since V6.3 every decision also fans out to the workspace's
`audit.jsonl` as a `proxy` record carrying the destination, the disposition
(`inject` / `relay`) and the rule that decided it — so the question "did my
credential go out, and to where" survives the sandbox stopping.

One deliberate exception: `chm proxy check` opens **real** connections, but they
are the operator's, not the guest's, and the guest may not even be running. That
path takes a disabled log on purpose, so a diagnostic never puts decisions the
sandbox did not take into the record used to judge it.

**No HTTP/2.** Clients negotiate down to HTTP/1.1 via ALPN.

---

## 7. Seeing what it did

```console
$ CHM_PROXY_LOG=1 chm run ./snapshot
[proxy] t=1785405143 api.github.com [20.26.156.210]:443 github-api HEAD /user — Authorization attached
[proxy] t=1785405143 api.github.com [20.26.156.210]:443 github-api upstream TLS TLSv1_3
[proxy] t=1785405144 registry.npmjs.org [2606:4700::6810:222]:443 - relayed opaquely (no-rule)
```

A request whose `Host` header disagrees with the destination the NAT admitted is
recorded as `[Host claims …]`. It changes nothing — the credential was chosen
from the destination — but a guest asking one host for another host's content is
worth being able to see afterwards.

`chm posture` reports it as a security control:

```console
$ chm posture ./my-workspace
  [on ] I12    credential custody
            credentials injected at the proxy for api.github.com, github.com
            — never present in the guest
```

A rule with `allow_cleartext` reports as **weakened**, because a credential may
then leave unencrypted. No rules at all reports as **n/a**, not weakened — a
sandbox with no injected credentials is strictly safer than one with them.

### Proving it works, before trusting it with anything

`chm proxy check` sends a real request through a real proxy to a real host:

```console
$ chm proxy check --host api.github.com --path /user --rules ./proxy-rules.json
api.github.com:443/user → 20.26.156.210:443
  disposition: INJECT Authorization (github-api)
  origin said: HTTP/1.1 200 OK
  guest tls:   TLSv1_3
  reachable:   yes
  audit:       api.github.com [20.26.156.210]:443 github-api HEAD /user — Authorization attached [injected]
  audit:       api.github.com [20.26.156.210]:443 github-api upstream TLS TLSv1_3
```

On an intercepted flow the handshake `check` makes terminates on *us*, so
`guest tls` is what the guest sees; the origin-facing version arrives in the
audit line. On a relayed flow the handshake reaches the origin itself, and the
line is labelled `origin tls` accordingly.

Pick a `--path` whose answer differs with and without a credential, and the check
becomes conclusive rather than merely reassuring. `/user` on `api.github.com` is
`401` unauthenticated and `200` with a valid token, so the same command against a
rules file with no rules is the control:

```console
$ chm proxy check --host api.github.com --path /user --rules ./no-rules.json
api.github.com:443/user → 20.26.156.210:443
  disposition: PASS-THROUGH (no-rule)
  origin said: HTTP/1.1 401 Unauthorized
  origin tls:  TLSv1_3
  reachable:   yes
  audit:       api.github.com [20.26.156.210]:443 - relayed opaquely (no-rule)
```

Identical request bytes. The only difference is the proxy.

---

## 8. Where the code lives

| Piece | File |
| --- | --- |
| The inject-vs-relay decision | `chm/src/credproxy/rules.rs` |
| Credential sources, on-demand minting | `chm/src/credproxy/secrets.rs` |
| CA + per-host leaf minting | `chm/src/credproxy/ca.rs` |
| Request parsing, framing, injection | `chm/src/credproxy/http.rs` |
| TLS termination, verified upstream, relay | `chm/src/credproxy/server.rs` |
| The NAT ⇄ proxy join | `chm/src/credproxy/nat.rs` |
| `chm proxy` | `chm/src/credproxy/cli.rs` |
| The NAT's side of the hook | `hypervisor/src/hvf/virtio/nat/mod.rs` (`InterceptDecider`) |

The `hypervisor` crate holds **no credential knowledge at all**. `InterceptDecider`
hands it an address and some opaque bytes to send first; it never learns why a
flow is diverted or what will be attached. It could not leak a secret it never
receives.

X.509 is generated in-tree (`der.rs`) rather than pulling in `rcgen`, because the
dependency surface of the one component that holds every secret is itself a
security property. The encoder only *writes* DER — it never parses
attacker-supplied ASN.1, which is where the dangerous bugs in that area live —
and what it mints is checked against OpenSSL in
`ca.rs::openssl_tests::openssl_parses_and_chains_what_we_mint`.

---

## See also

- [`networking.md`](networking.md) — the userspace NAT and egress allow-list.
- [`security-model.md`](security-model.md) — invariants and the default posture.
- [`environment-variables.md`](environment-variables.md) — `CHM_PROXY_*`.
