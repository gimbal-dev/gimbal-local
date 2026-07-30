# Sandbox networking & egress control

This is the human guide to how a rehydrated guest reaches the network on your
Mac, and how the control plane's egress allow-list follows a sandbox down and is
enforced locally. For the design/rationale and the staged plan, see
[`network-policy-plan.md`](network-policy-plan.md); this doc is about **what the
product does today and how to use it**.

## The one-paragraph version

A snapshot brought down from the cloud has **no tap and no bridge** — no
layer-2 access to your Mac's network. Its only link is a virtio-net device that
`chm` terminates in a **userspace NAT** — a small TCP/IP stack inside `chm` that
answers the guest's DNS, accepts its TCP connections, and relays them out through
ordinary host sockets. Because `chm` is the process opening every socket, it is
also the **enforcement point**: the control plane's per-sandbox egress allow-list
is checked at the moment a name is resolved and a connection is dialed, and a
denied flow is enforced simply by *not opening the socket*.

> **Host-network boundary (enforced — M31.1).** The NAT relays through a real
> host socket, so a guest's connection would otherwise reach the host's own
> networks. A **reserved-address guard** now denies any flow to loopback
> (`127.0.0.1`), private LAN, or link-local (incl. the cloud metadata IP
> `169.254.169.254`) — **regardless of the egress policy**, so even the allow-all
> default and a DNS-rebound allow-listed name cannot reach the host. Only an
> explicit IP-literal allow rule in your policy, or `--allow-local-egress`
> (`CHM_ALLOW_LOCAL_EGRESS=1`), lifts it. For **public** egress: `chm` itself is
> allow-all when no policy is bound, but the Gimbal Local app now defaults new
> sandboxes to firewall-on **default-deny** (M31.2) — so a sandbox created through
> the app has no public egress until you allow-list what it needs. See
> [`security-model.md`](security-model.md#m31--network-host-isolation--the-reserved-address-boundary).

```
guest ──virtio-net──▶ chm userspace NAT ──host socket──▶ public internet
                          │                              (host loopback / LAN /
                          ├─ reserved-address guard         metadata are denied
                          │  (M31.1, always on)             by the guard)
                          └─ egress policy
                             checked at DNS resolve + TCP connect
```

## What works today

| Capability | Status |
| --- | --- |
| Outbound IPv4 **TCP** (e.g. HTTPS) | ✅ real, via connection-proxy NAT |
| **DNS** (A-record lookups) | ✅ resolved through the host resolver |
| **Egress allow-list enforcement** | ✅ at DNS resolve **and** TCP connect, *when a policy is bound* |
| Default posture | ⚠️ **allow-all to the public internet** when no policy is bound; default-deny only once a policy sets it |
| Host-network isolation (loopback / LAN / metadata) | ✅ **enforced** by the reserved-address guard, regardless of policy (M31.1) |
| Denial visibility | ✅ each blocked flow is logged to the console + audit trail once |
| UDP beyond DNS, IPv6, inbound/listen, ICMP to real hosts | ⛔ out of V0 scope (answered-empty or denied, never silently broken) |

The guest keeps the static address capture-side cloud-init gave it
(`192.168.249.2/24`, gateway `192.168.249.1`); the NAT owns the gateway address.

## How the policy gets there

1. **In the cloud**, the control plane authors a per-sandbox `SandboxPolicy`
   (an egress `default` action plus `allow`/`deny` lists of `host[:port]`) and
   content-addresses it as a `policy_digest`.
2. **On assignment**, every run/resume the plane hands `chm` carries the compiled
   `enforcement.chm_profile` and the `policy_digest`.
3. **`chm` verifies the teleport**: it recomputes the digest from the received
   profile byte-for-byte and refuses to run a governed sandbox if it does not
   match (see `chm policy show --sandbox <id>`).
4. **`chm` hands the profile down** to the subprocess that actually boots the VM
   (via the `CHM_EGRESS_POLICY` environment variable), where the NAT enforces it.

You can inspect the policy the plane compiled for a sandbox:

```console
$ chm policy show --sandbox sbx-aa2539e692da
governed by sha256:147f… · egress default=deny, 1 rule(s) · fs 0 ro / 1 rw · digest verified
  egress: deny by default
    allow api.github.com:443
```

### Bringing a cloud policy down (`chm policy bind`)

Steps 2–4 above describe a full plane **assignment** — the runner re-execs `chm`
with the profile in its environment. But you often want the cloud's policy to
govern a sandbox you are running locally, outside an assignment: you brought the
snapshot down and you are iterating on it on the Mac. `chm policy bind` is that
path. It fetches the sandbox's effective policy, verifies the digest through the
**same** `parse_and_verify` path (and the same fail-closed
[`CHM_REQUIRE_SIGNED`](security-model.md) posture) the runner uses, then writes
the workspace's `egress-policy.json` **labelled with the plane's digest**:

```console
$ chm policy bind --sandbox sbx-11d5f919687f ./my-sandbox
chm policy bind: governed by sha256:f857c2f0… · egress default=deny, 3 rule(s) · fs 1 ro / 1 rw · digest verified
  wrote ./my-sandbox/egress-policy.json — the same digest now governs this local sandbox
```

Because the digest is the policy's **label**, it is what the NAT reports on every
console `DENY` line and what lands in the durable audit trail — so a refusal on
this Mac is attributable to the exact policy the control plane issued. Binding is
an enforcement action, so an unverifiable policy is refused outright rather than
written in a degraded form.

### Locally, with no control plane

The same enforcement is available to a self-served (no-`gctl`) user, authored
locally with **`chm firewall`**. It writes a per-workspace `egress-policy.json`
(the same shape as the cloud `chm_profile.egress`), which the NAT reads on the
next start — no plane, no digest, same gate:

```console
$ chm firewall set ./my-sandbox --default deny --allow api.github.com:443
wrote ./my-sandbox/egress-policy.json — egress default=deny · 1 allow / 0 deny rule(s)
$ chm firewall show ./my-sandbox
./my-sandbox [local]  egress default=deny · 1 allow / 0 deny rule(s)
$ chm firewall clear ./my-sandbox        # back to unrestricted egress
```

`chm run` / `chm resume` / `chm connect` also accept a one-shot
`--egress-policy <file>` override. `chm` resolves the effective policy in priority
order: the **`--egress-policy` flag** › the **`CHM_EGRESS_POLICY`** binding (what
the cloud runner sets) › the per-workspace **`egress-policy.json`**. So a
control-plane binding always wins over a local file, and the Gimbal Local app's
per-sandbox **Connectivity** control is a thin client of `chm firewall`.

## What enforcement looks like

With a default-deny policy that allows only `api.github.com:443`, a guest that
tries to reach anything else is stopped at the gate. Denials are logged to the
guest's console stream:

```
chm: virtio-net _net0 governed by egress policy sha256:147f… (default-deny enforced at the NAT)
chm: [egress] DENY dns evil.example.com (default-deny) — sandbox policy sha256:147f…
chm: [egress] DENY tcp 93.184.216.34:80 (default-deny) — sandbox policy sha256:147f…
```

- A **denied DNS name** is never resolved, so the guest cannot even learn the
  address.
- A **denied TCP connect** is refused (the guest sees a connection reset); `chm`
  never opens a host socket for it.
- An **allowed** destination connects and transfers normally.

A guest that skips DNS and dials a raw IP is judged by the same rules: under
default-deny, an IP the guest never resolved through us matches no allow rule and
is refused.

## Enabling the live path (capture requirement)

Enforcement is exercised end-to-end by an in-tree test that drives a guest TCP/IP
stack through the NAT to a real host socket (`hypervisor` crate,
`hvf::virtio::nat` — an allow-listed destination connects, an unlisted one is
refused). To run the **guest-side** demo you need a snapshot that was captured
**with a network device**: the captures in the current corpus were taken without
`--net`, so their guests have no NIC.

### Capturing a net-enabled snapshot

The capture pipeline (`scripts/hvf/capture-arm-snapshot.sh`) boots a throwaway
Ubuntu guest under cloud-hypervisor and snapshots it. To make its snapshot carry
a usable virtio-net device, two things must change in that boot:

1. **Give cloud-hypervisor a NIC.** Add a `--net` device to the boot command. When
   run privileged (the capture already boots under `sudo`), cloud-hypervisor
   auto-creates the backing tap:

   ```
   --net tap=,mac=12:34:56:78:9a:bc
   ```

   The tap needs no real uplink — the guest only has to *have* the NIC and
   configure it, so the device state lands in the snapshot. On the Mac, `chm`'s
   userspace NAT provides the actual connectivity.

2. **Configure the guest statically to match the NAT.** Add a netplan file to the
   NoCloud seed's `write_files` so the guest comes up on the address the NAT
   presents:

   ```yaml
   - path: /etc/netplan/50-chm.yaml
     permissions: '0644'
     content: |
       network:
         version: 2
         ethernets:
           enp0s1:              # the virtio-net iface name; verify in the guest
             addresses: [192.168.249.2/24]
             routes:
               - to: default
                 via: 192.168.249.1
             nameservers:
               addresses: [192.168.249.1]
   ```

   (and `netplan apply` in `runcmd` before the readiness marker).

The gateway/nameserver `192.168.249.1` and guest `192.168.249.2/24` are the
addresses the NAT hard-codes today.

### Running the demo

Both halves of the proof are scripted, so they are repeatable rather than a
one-off screenshot. Each one boots the guest, drives real `curl` probes over the
serial console, and **asserts** the outcome — including that the allow-listed
host really does work, without which "nothing gets out" would be trivially
satisfied by a broken network.

#### 1. Allow-list enforcement (no control plane needed)

```console
$ scripts/hvf/egress-allowlist-demo.sh
egress-demo: PASS
  - example.com (allow-listed)          -> HTTP 200
  - neverssl.com (not allow-listed)     -> refused at the DNS gate
  - 34.223.124.45 (raw IP, DNS bypassed) -> refused at the TCP-connect gate
  - both denials audited under policy 'm28.4-allowlist-demo'
```

The third probe is the load-bearing one. A guest that **hardcodes an IP address**
never touches the DNS gate at all — but `chm` is the process that calls
`connect()`, so default-deny means the host socket is simply never opened. There
is no path around it from inside the guest. `curl`'s exit codes make the two
gates distinguishable: `6` = could not resolve (DNS gate), `7` = failed to
connect (connect gate).

#### 2. The policy-digest teleport (needs a plane)

```console
$ scripts/hvf/policy-teleport-demo.sh
policy-teleport: binding the plane's policy for sbx-11d5f919687f to snapshots/ch-arm-stock-its-net
chm policy bind: governed by sha256:f857c2f0… · egress default=deny, 3 rule(s) · digest verified
policy-teleport: PASS
  the control plane's policy sha256:f857c2f0…
  governed a microVM on this Mac:
    - api.github.com (plane allow-list)  -> HTTP 200
    - example.com (not allow-listed)     -> refused at the DNS gate
    - 169.254.169.254 (plane deny rule)  -> refused at the TCP-connect gate
  every refusal audited under the plane's digest
```

The script derives its probes from whatever policy the plane actually authored,
and skips (rather than fails) when no plane or no policy-bound sandbox is
reachable. Three properties matter here:

- The **plane's allow rule** let real traffic out — the policy is live, not inert.
- A host the plane did **not** allow-list was refused, so the allow-list is closed.
- The plane's **explicit deny of the cloud metadata service** (`169.254.169.254`)
  fired **by name** — the console line reads `(deny 169.254.169.254)`, not
  `(default-deny)` — proving that specific cloud-authored rule travelled intact,
  not merely the default stance. This is the highest-value rule to prove: IMDS is
  how a compromised agent reaches for cloud credentials.

And the durable record ties it together:

```console
$ chm audit show snapshots/ch-arm-stock-its-net
… egress-DENY  dns example.com (default-deny) policy=sha256:f857c2f0…
… egress-DENY  tcp 169.254.169.254:80 (deny 169.254.169.254) policy=sha256:f857c2f0…
```

One content-addressed policy, authored in the cloud, enforced on the Mac, and
named in the audit trail on both sides.

## Getting credentials in without putting them in the guest

Because `chm` *is* the guest's whole network, it is also the one place every
outbound call must pass through — which makes it the natural place to attach a
credential. A rule names a destination; the proxy terminates TLS for that
destination only, adds the `Authorization` header as the request leaves, and
opens its own fully-verified connection upstream. The guest sends no secret and
never holds one.

This is the answer to "how does the developer's repo get into the sandbox": it
is a credentials problem, not a filesystem problem, and a sandbox that can
authenticate to GitHub can clone the repo itself. See
[`credential-proxy.md`](credential-proxy.md).

Nothing is intercepted unless a rule names it. A flow with no rule is relayed as
opaque bytes exactly as before, and a rules file with only `passthrough` entries
installs no hook in the data path at all.

## Scope & non-goals

- **No host filesystem passthrough.** There is deliberately no virtiofs/9p/shared
  folder path (see [`security-model.md`](security-model.md)); networking is the
  only egress surface, and it is fully mediated. If a policy requests a host
  **mount**, `chm` refuses it loudly (a `fs / mount-refused` decision reported to
  the plane) and runs the sandbox without it, rather than silently changing the
  environment. The policy's `fs` read-only/read-write scopes describe
  guest-internal paths that `chm` cannot police from outside the guest, so they
  are surfaced but not gated.
- **V0 is IPv4 TCP + DNS.** Other protocols are denied or answered-empty rather
  than partially working — a clear, honest boundary.
