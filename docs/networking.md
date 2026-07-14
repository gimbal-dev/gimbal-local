# Sandbox networking & egress control

This is the human guide to how a rehydrated guest reaches the network on your
Mac, and how the control plane's egress allow-list follows a sandbox down and is
enforced locally. For the design/rationale and the staged plan, see
[`network-policy-plan.md`](network-policy-plan.md); this doc is about **what the
product does today and how to use it**.

## The one-paragraph version

A snapshot brought down from the cloud has **no tap, no bridge, and no route to
your Mac's network**. Its only link is a virtio-net device that `chm` terminates
in a **userspace NAT** — a small TCP/IP stack inside `chm` that answers the
guest's DNS, accepts its TCP connections, and relays them out through ordinary
host sockets. Because `chm` is the process opening every socket, it is also the
**enforcement point**: the control plane's per-sandbox egress allow-list is
checked at the moment a name is resolved and a connection is dialed, and a denied
flow is enforced simply by *not opening the socket*. The guest cannot get around
this — there is no other way off the box.

```
guest ──virtio-net──▶ chm userspace NAT ──host socket──▶ internet
                          │
                          └─ egress policy (from the control plane)
                             checked at DNS resolve + TCP connect
```

## What works today

| Capability | Status |
| --- | --- |
| Outbound IPv4 **TCP** (e.g. HTTPS) | ✅ real, via connection-proxy NAT |
| **DNS** (A-record lookups) | ✅ resolved through the host resolver |
| **Egress allow-list enforcement** | ✅ at DNS resolve **and** TCP connect |
| Default-deny (`can't get out` unless allow-listed) | ✅ enforced by not dialing |
| Denial visibility | ✅ each blocked flow is logged to the console once |
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
`--net`, so their guests have no NIC. A net-enabled capture must:

- boot cloud-hypervisor with a `--net` device, and
- configure the guest statically as `192.168.249.2/24`, gateway `192.168.249.1`
  (the address the NAT presents).

Once such a snapshot exists, resuming it under a default-deny+allow-list policy
demonstrates the full loop: *the plane sets an allow-list for sandbox N, it
follows the sandbox down, and the guest provably can't get out except to the
allow-list.*

## Scope & non-goals

- **No host filesystem passthrough.** There is deliberately no virtiofs/9p/shared
  folder path (see [`security-model.md`](security-model.md)); networking is the
  only egress surface, and it is fully mediated.
- **V0 is IPv4 TCP + DNS.** Other protocols are denied or answered-empty rather
  than partially working — a clear, honest boundary.
