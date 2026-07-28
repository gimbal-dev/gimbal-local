# Gimbal Local — security model & hardening plan (M30)

Gimbal Local brings a snapshot **down from the cloud** and runs it on a personal
Mac. The whole point is to run **someone else's compute** — increasingly an
**autonomous coding agent** — inside a sandbox on your machine. That inverts the
usual trust assumption: the workload is not something you wrote and vetted, it is
untrusted (potentially *hostile*) code, and the snapshot bundle that carries it
is untrusted input from the network.

This doc is the threat model, the security **invariants** we hold, and the
hardening plan that closes the gaps found in the first security review. It is the
umbrella for milestone **M30 · Security hardening (hostile-agent readiness)** and
takes priority over the remaining feature milestones (it precedes M27).

> Status is honest: some invariants **hold today**, several controls are
> **being hardened** under M30, and the "hostile-agent production ready" bar is
> **not yet met** — this is a promising prototype with a written path to that bar,
> not a finished hostile sandbox.

---

## 1. Threat model

### Assets we protect

1. **The host Mac** — its filesystem, credentials, and other processes.
2. **Other sandboxes** — one sandbox must not read or corrupt another's state.
3. **The user's trust in provenance** — "this is the snapshot my cloud produced,"
   not something a network attacker swapped in.
4. **The control-plane relationship** — leases, cost, and audit integrity.

### Adversaries

- **A hostile guest workload** — the code *inside* the sandbox is adversarial
  (this is the coding-agent case) and actively tries to break out of the VM,
  reach the host filesystem, or affect other sandboxes.
- **A malicious snapshot bundle** — the bundle (`state.json`, `disks/`,
  `memory-ranges`, manifest) is crafted to make **`chm`** (the code *outside* the
  VM, on the host) touch host files it should not, by way of symlinks, `..`
  escapes, or absolute disk paths.
- **A local co-tenant process** — another unprivileged process on the same Mac
  that tries to drive the daemon (start/stop/console/shutdown) or hijack its
  socket.
- **A network / supply-chain attacker** — tampers with a bundle in transit or at
  rest in the object store.

### Trust boundaries

```
                    signed manifest (M30.4)
   cloud / capture ───────────────────────────▶  chm materialize  (untrusted bundle)
                                                         │  verify + confine (M30.1)
   local user ── ctl (peer-cred, M30.2) ──▶ chm serve ──┤
                                                         ▼
   app (Process args, M30.3) ─────────────────▶  chm connect / run
                                                         │  HVF boundary (trusted)
                                                         ▼
                                                   guest workload  (hostile)
```

- **guest ↔ host** — enforced by Apple Hypervisor.framework. We **trust the
  platform's VM boundary**; a hypervisor-level escape is out of scope (see §4).
- **bundle ↔ `chm`** — the bundle is **untrusted input**. Every file access `chm`
  makes into a bundle is a place a malicious bundle can attack the host. This is
  the highest-value boundary we own (M30.1, M30.4).
- **ctl client ↔ daemon** — a local IPC boundary; today anyone who can reach the
  socket can drive the VM (M30.2).
- **app ↔ `chm`** — the app must launch `chm` without letting any interpolated
  value become host shell code (M30.3).

### Out of scope (documented assumptions)

- **HVF / Apple silicon hypervisor escapes.** We rely on the platform VM
  boundary; if HVF is broken, so are we. We minimise our own attack surface but
  do not re-implement the CPU/memory isolation.
- **Escape-response posture.** A guest-level compromise — a hostile agent
  breaking out of its own userspace into the *guest kernel* — is assumed
  **contained by the HVF VM boundary**: the guest is a real hardware-isolated VM,
  not a shared-kernel container, so an in-guest attacker cannot reach host files,
  other sandboxes, or the daemon *through the VM*. The escape we actively defend
  is the **bundle-driven host-file** path — a crafted snapshot / manifest / disk
  reaching a host file before or around the VM — closed by bundle confinement
  (M30.1), the CAS digest gate (M30.8), and the no-host-FS invariant (I1). A break
  of HVF itself (first bullet) defeats this assumption.
- **Side channels** (timing, cache, Spectre-class) between guest and host.
- **Physical access / a compromised macOS account** running as the user.
- **The control plane's own security** — owned by `gimbal-cloud-control`; we
  consume its trust root (M30.4) but do not audit its internals here.
- **The cloud/KVM capture path and its harness** (M31.4). Everything in this
  document — bundle confinement, the reserved-address network guard, resource
  limits, the audit trail — governs the **macOS / HVF runtime in this repo**. The
  *capture* side (producing a snapshot on a Linux/KVM host, e.g. the BYO EC2
  harness in [`aws-byo-setup.md`](aws-byo-setup.md)) runs **outside this
  repository** and is **not** covered by these guarantees:
  - the capture host holds EC2/S3 credentials and can reach the cloud
    instance-metadata endpoint (`169.254.169.254`), so a workload captured there
    is only as isolated as that host and its IAM policy make it;
  - the network guarantees (I10 / M31.1) apply to the local NAT datapath, not to
    how the guest reached the network while it was being captured on KVM;
  - a snapshot is trusted on the Mac only via the signed-manifest chain (M30.4);
    the capture harness itself must be audited in its own repo.
  Treat a snapshot as trustworthy only to the extent you trust the host that
  captured it and the signature over its manifest.

---

## 2. Security invariants

These are the properties we commit to. Each has an enforcement mechanism and a
test/guard so a regression is caught, not discovered.

| # | Invariant | Enforced by | Status |
| --- | --- | --- | --- |
| I1 | **No host filesystem passthrough.** A guest never gets a virtiofs/9p/shared-folder mount of a host directory. The only guest storage is virtio-blk over a bundle-owned image + a private overlay. | Device model wires only block/net/rng (virtio-fs/9p classify as `Unsupported`); a behavioural test + `make security-check` guard fail if that regresses. | **Holds today** (M30.5) |
| I2 | **Bundles are confined.** Every file `chm` opens for a bundle resolves to a real path **under the bundle root** — no symlink is followed out, no `..` escapes. | `symlink_metadata` rejection + path confinement + `O_NOFOLLOW` opens. | **Holds today** (M30.1) |
| I3 | **Overlays are private.** Writable overlays/checkpoints are created by `chm` in a fresh `0700` dir it owns, refusing a symlinked overlay/dir shipped in the bundle. | Private `0700` overlay dir + no-follow overlay opens. | **Holds today** (M30.1) |
| I4 | **The daemon is local-and-owner-only.** Only the same-uid user can drive the control socket; the socket lives in a private `0700` dir with `0600` perms and validates peer credentials. | Private socket dir + `0600` perms + `getpeereid` peer-uid check. | **Holds today** (M30.2) |
| I5 | **The app never builds host shell code from data.** Snapshot/sandbox names and paths never become shell tokens. | Centralised single-quote builder + control-char rejection; adversarial-input tests. | **Holds today** (M30.3) |
| I6 | **Only verified, provenance-known snapshots run.** A bundle is checksum-verified **and** signature-verified against a trusted key before import or run; provenance is recorded. | Ed25519 signed-manifest verification with a `CHM_TRUST_STORE` trust root; fails closed when configured, and `CHM_REQUIRE_SIGNED` makes fail-closed the default (M31.5). | **Verification + fail-closed posture hold** (M30.4/M31.5); gctl signing pending (#36) |
| I7 | **Undeliverable snapshots are never mis-run.** A capture whose virtio completions route through the GIC ITS as LPIs is rehydrated onto the userspace GICv3, which can deliver them; it is never run on the managed GIC, which cannot. | `routes_completions_as_lpis` routes both `chm run` and `chm serve`; `CHM_ALLOW_ITS_LPI=1` is a diagnostic-only override. | **Holds today** (V2.1 — was "refused", now "routed and run") |
| I8 | **The content store cannot select a host file.** A manifest checksum is only ever used as a CAS path after it is validated as a canonical sha256 hex digest, and every CAS object (including cache hits) is re-hashed before it is linked into a guest. | Digest-shape gate + re-hash on hit in `materialize_bundle`. | **Holds today** (M30.8) |
| I9 | **A governed session's egress is enforced on every NIC and fails closed.** The resolved policy applies to all virtio-net NICs, and a session whose policy source is present but unresolvable denies all egress rather than running open. | Per-NIC policy clone + `EgressResolution::FailClosed` deny-all. | **Holds today** (M30.9) |
| I10 | **A guest cannot reach the host's own networks.** No sandbox flow reaches loopback, RFC1918 LAN, link-local (incl. `169.254.169.254`), or other special-use ranges, regardless of policy or DNS answers, unless local egress is explicitly opted in or the trusted policy names the exact IP. | Reserved-address guard in the NAT: `decide_connect` denies reserved IPs before the allow rules (IP-literal allow or `--allow-local-egress` excepted); DNS answers resolving into reserved ranges are dropped. | **Holds today** (M31.1) |

---

## 3. Findings → hardening plan (the M30 work)

The review graded eight areas. Each maps to an M30 issue, prioritised P0
(exploitable now / quick, correctness-preserving), P1 (trust model), P2
(defence-in-depth).

### M30.1 · Bundle file isolation — symlinks & path traversal  **[P0, engine]**

**Status: shipped.** Symlinked disk bases and overlays are rejected, disk +
overlay opens use `O_NOFOLLOW`, the overlay dir is created private `0700`, and
`materialize_bundle` confines every manifest relpath under the cache root.

**Finding.** Host file isolation is breakable via symlinks in `disks/` /
`.chm-overlays/`, because the run path tests `Path::exists()` / `is_file()`
(which **follow** symlinks) and overlays are created *inside* the bundle
directory the snapshot controls.

**Verified.** The workspace/fork model deliberately symlinks a *trusted* base
(our own image) — that is fine — but a **downloaded bundle** could ship a
`disks/rootfs.raw → /etc/passwd` symlink or a `state.json` disk path of
`../../../../etc/…`, and nothing currently rejects it.

**Plan.**
- When materialising a bundle, **reject symlinks**: `symlink_metadata()` every
  entry and refuse any that is a symlink (a downloaded bundle has no legitimate
  symlinks). Distinguish this from our *own* workspace base-links, which point at
  a canonicalised trusted image root.
- **Canonicalise** every bundle-relative path (disk images from `state.json`,
  `memory-ranges`, manifest entries) and require the resolved path to stay
  **under the bundle root**; reject `..` escapes and absolute paths that leave it.
- Use **no-follow opens** (`O_NOFOLLOW` via `OpenOptionsExt.custom_flags`) for
  bundle files so a swap-in TOCTOU can't redirect an open.
- Create writable **overlays in a fresh private `0700` runtime dir** `chm` owns
  (e.g. under its own state dir), **not** in the bundle's `.chm-overlays`, so an
  attacker who controls the bundle can't pre-seed or symlink overlay targets.
- Fix the `remove_file`-then-`bind`/create TOCTOU on any predictable path.

**Tests.** A malicious-bundle fixture (symlinked disk, `..`-escaping disk path,
absolute path) must be rejected; a legitimate bundle + our own workspace links
must still run.

### M30.2 · Daemon control hardening — socket auth  **[P0, daemon]**

**Status: shipped.** The socket is bound `0600` in a private `0700`
`<tmp>/gimbal-local/` dir, and `handle_conn` rejects any peer whose uid is not
the daemon's own (`getpeereid`). Proven live: dir `drwx------`, socket
`srw-------`, same-uid `ctl` admitted.

**Finding.** The control daemon is not hardened: a predictable socket, no auth,
no peer check.

**Verified.** `serve.rs default_socket()` = `env::temp_dir().join("chm.sock")` —
a predictable path in a world-traversable temp dir; `UnixListener::bind` sets no
permissions and the accept loop performs **no peer credential check** before
honouring `start` / `stop` / `console` / `shutdown`.

**Plan.**
- Put the socket in a **private per-user `0700` directory** (e.g. under
  `$XDG_RUNTIME_DIR` / `~/Library/Application Support/gimbal-local/run/`), not
  `$TMPDIR`.
- `chmod` the socket to **`0600`** after bind.
- **Validate peer credentials** — `getpeereid(2)` (macOS `LOCAL_PEERCRED`) on
  each accepted connection; reject any client whose uid ≠ the daemon's uid before
  processing a command.
- Harden the `remove_file`-before-`bind` step against a symlink swap.

**Tests.** Peer-uid mismatch is rejected; same-uid client still works; socket
perms are `0600` in a private dir.

### M30.3 · App command safety — no shell strings  **[P0, app]**

**Status: shipped.** Terminal command building moved to a pure
`InteractiveTerminalCommand` builder that single-quotes every interpolated value
and rejects control characters, with adversarial-input tests.

**Finding.** Host command injection via the snapshot name in the Terminal
command.

**Verified.** The specific **snapshot-name interpolation was already removed**
last session (the echo line no longer includes it, and the run path is now a
UUID-based workspace path the app controls, not a user-set name). The residual
risk is the **pattern**: `openInteractiveTerminal` still assembles a `&&`-joined
**shell string** run through `osascript`, relying on `shellQuote` at the shell
layer *and* AppleScript escaping at the outer layer.

**Plan.**
- Prefer launching **`chm connect` directly with a `Process` argument vector**
  (no shell) wherever an interactive Terminal window is not strictly required;
  for the Terminal-UX path, keep interpolation to app-controlled values and
  ensure robust quoting at **both** the AppleScript and shell layers.
- Never interpolate a user-settable name into any command string.

**Tests.** An adversarial name/path (quotes, `;`, `$( )`, newlines) round-trips
as literal argv with no host execution.

### M30.4 · Signed snapshot manifest + verification  **[P1, chm + app + gctl]**

**Status: verification side shipped; gctl signing side pending.** `chm` can now
verify a signed manifest and **fails closed** when a trust root is configured but
a bundle is unsigned/invalid. The remaining half — gctl producing + signing
manifests in production — is tracked cross-repo (#36).

**Finding.** Snapshot trust was missing — bundle contents and `state.json` were
trusted after only a checksum. `materialize_bundle` verifies each object against
`manifest.checksum_tree` (integrity — detects corruption) but there was **no
signature** (authenticity), so a tampered bundle with a recomputed
`checksum_tree` passed.

**The contract (implemented on the verification side; gctl matches on signing).**
- **Algorithm:** Ed25519 (via the already-vendored `ring`, no new dependency).
  Public keys and signatures are lowercase hex.
- **Signed payload = the manifest's raw bytes.** The signature covers the literal
  manifest document, so signer and verifier need not agree on a canonical JSON
  encoding (a cross-language hazard). An assignment carries:
  - `manifest_canonical` — the exact manifest bytes gctl signed (a JSON string
    with `checksum_tree` + runtime metadata: substrate, gic_mode, origin, sizes);
  - `manifest_signature` — `{ "alg": "ed25519", "key_id": "<id>", "sig": "<hex>" }`.
- **Trust store:** `CHM_TRUST_STORE` points at a JSON `{ "keys": { "<id>":
  "<hex pubkey>" } }`. It is a **map keyed by id so keys rotate** — add the new
  key id, keep the old until everything is re-signed.
- **Verification order:** verify the signature over `manifest_canonical` against
  the trusted key named by `key_id`, then use **that signed manifest's**
  `checksum_tree` (never the loose, unsigned one) for `materialize_bundle`, which
  re-hashes every object — including CAS cache hits (M30.8) — before use.
- **Fail closed:** with a trust root configured, a missing/invalid signature or
  unknown key id is refused. Without a trust root, the unsigned `checksum_tree`
  is used so pre-signing flows keep working during rollout.
- **Fail-closed posture (`CHM_REQUIRE_SIGNED`, M31.5):** setting it makes
  verification *mandatory* on the plane ingest path — a bundle that cannot be
  authenticated (no trust root, or an unsigned/invalid manifest) is refused
  rather than accepted unsigned, and the independent **policy-digest recompute**
  becomes enforced (a governed policy whose doc does not re-hash to its stated
  digest is refused, not just logged). Local `chm run <dir>` rehydration never
  routes through this gate, so the stock-snapshot path is unaffected.
- **Reference implementation + local signer:** `chm manifest keygen | sign |
  verify` produces and checks exactly this format, so the contract is testable
  end to end and gctl has a concrete target.

**Remaining (cross-repo, #36).** gctl produces + signs canonical manifests and
publishes its public keys; the app surfaces only `chm`-verified provenance. One
trust root, key ids + rotation.

### M30.5 · No-host-FS-passthrough invariant + CI guard  **[P1, docs + test]**

**Status: shipped.** The device model already turns virtio-fs/9p into
`Unsupported` (refused at build); a behavioural test asserts that, and
`scripts/security/no-host-fs-passthrough.sh` (`make security-check`) fails if
host-FS wiring tokens appear without a `SECURITY-REVIEWED-FS-SHARE` marker.

**Finding.** "No ordinary host FS sharing" is true by design but implicit.

**Plan (done).** Make I1 **explicit**: document it here, add a behavioural test
(`host_fs_passthrough_device_types_are_unsupported`), and add a repo guard that
**fails** if `virtiofs`/`9p`/shared-folder/host-mount wiring appears in the HVF
device model without a paired security review — so the invariant can't silently
regress.

### M30.6 · Per-sandbox resource limits  **[P2, engine]**

**Status: core shipped.** A declarative limits document (`--limits` flag,
`CHM_LIMITS` env, or a per-workspace `limits.json`, authored with `chm limits
set`) bounds a sandbox's resources, enforced in the run loop:

- **Admission control (launch gate):** a snapshot whose vCPU or RAM shape exceeds
  the `max_vcpus` / `max_memory_mb` ceiling is refused — a snapshot's shape is
  fixed, so this is a gate, not a throttle.
- **Runtime caps (monitor):** the console loop stops the guest cleanly when the
  disk overlay (`max_disk_mb`, measured by actual allocated blocks so a sparse
  CoW file does not false-trip) or console output (`max_console_mb`) grows past
  the cap, and folds `max_wall_seconds` into the wall-clock stop. A trip is a
  clean external stop, so live state is still checkpointed.
- **App defaults:** Gimbal Local ships sane global defaults (an 8 GiB disk +
  64 MiB console cap on by default) applied to every new sandbox's workspace, so
  a runaway can't exhaust the host out of the box.
- **Network caps (NAT datapath):** `max_connections` bounds the concurrent
  outbound TCP flows the guest may hold open (a SYN over the cap is refused like
  a policy denial and audited as `connection-limit`, so a permitted destination
  can't be used to exhaust host sockets), and `max_bandwidth_kbps` bounds
  sustained egress throughput via a token bucket that *throttles* (TCP
  backpressure slows the guest) rather than dropping. The cap applies to every
  NIC, matching the per-NIC fail-closed egress policy (M30.9).

Verified end to end: a guest running `dd if=/dev/zero` was stopped after ~64 MiB
against a 64 MiB cap; the NAT connection and bandwidth caps are proven by the
two-stack relay test (a real guest smoltcp stack moving bytes through the NAT to
a real localhost server) — an over-limit SYN is refused, and a tightly-capped
flow moves dramatically fewer bytes than an unthrottled one over the same window.

### M30.2 daemon follow-up · runtime-dir ownership  **[P1, daemon] — shipped**

**Finding (2026-07 review).** The socket dir is created private `0700` with a
`0600` socket + peer-uid check, but a **pre-existing** runtime directory was not
fully validated. **Fixed (#66).** `ensure_private_runtime_dir` now, when the
runtime dir already exists, rejects it outright if it is owned by another UID (a
directory planted by another user in the shared temp root must not host the
control socket) and tightens a self-owned directory back to `0700` if its
permissions were left loose, so group/other can never interpose. Symlinks at the
path are still refused. Covered by a unit test.

### M30.3 app follow-up · direct argv launch  **[P2, app] — shipped**

**Finding (2026-07 review).** The central single-quoting builder is safe, but it
still composed a shell/AppleScript string with two escaping layers. **Fixed
(#67).** The interactive `chm connect` command is now delivered to `osascript`
as an `argv` parameter (`on run argv` ... `do script (item 1 of argv)`) instead
of being interpolated into the AppleScript source, eliminating the
AppleScript-literal escaping layer — a path can no longer break out of the
script text into host code. Terminal.app's `do script` still requires a command
*string* for `chm` itself, so the single-quote + control-char rejection remains
(now the only layer). Verified live that a command with shell metacharacters and
`$(...)` passes through argv verbatim, unexecuted.

### M29 · Audit trail — durable session + egress log  **[P2, chm] — shipped**

**Status: shipped.** A per-workspace append-only `audit.jsonl` records the
security-relevant history of a sandbox, independent of the console scrollback
(which the guest can flood). Each line is a self-contained JSON object stamped
with a UTC timestamp:

- **`session-start` / `session-stop`** — written by the run loop for every
  `chm run` / `resume` / `connect`, capturing the resume-vs-cold mode, the
  vCPU/RAM shape, the resolved limits summary, the governing egress label, and
  the stop outcome + duration.
- **`egress-deny`** — the userspace NAT's denied outbound flows, drained off the
  net-service thread and recorded once per unique `(domain, target, rule)` so a
  guest retrying a blocked host in a loop leaves one line, not thousands. This is
  the "what did the sandbox try to reach that we blocked" signal.
- **`verify`** — the runner's bundle-trust decisions (manifest provenance +
  per-object checksum re-hash, M30.4/M30.8) recorded to the same trail the child
  session appends to, so a cloud-run session's log carries verify → start →
  deny → stop end to end.

Writes are best-effort (an audit failure never crashes or stalls the run) and use
`O_APPEND`, so the vCPU and net-service threads interleave records safely without
a shared lock. Read it back with `chm audit show <WORKSPACE_DIR> [--json]`.
Verified live: a real HVF resume session recorded start + stop records that
`chm audit show` renders back.

### M30.7 · Threat model + hardening checklist  **[P0, docs]**

**Finding.** Not production-ready as a hostile sandbox; needs a written threat
model + checklist.

**Plan.** *This document.* It defines the model, the invariants, and the
per-area plan, and is the acceptance surface for M30. The checklist below is the
"done" bar.

### M30.8 · CAS digest hardening — content-store path safety  **[P0, chm]**

**Status: shipped.** `materialize_bundle` now validates every manifest checksum
is a canonical 64-char lowercase sha256 hex digest before it is used as a
content-addressed-store path, and re-hashes every CAS object on a dedup hit (not
only at first fetch) before linking it in.

**Finding (2026-07 review).** The content-addressed store keyed blobs by the
manifest checksum value used directly as a path (`cas.join(want)`), lower-cased
but otherwise unvalidated. A crafted checksum — an absolute path (`/etc/passwd`)
or a `..` traversal — made the blob path point at a **host file**, and a dedup
hit then hard-linked that host file into the guest-visible cache **without
re-hashing**. This is a host-file read exposure from an unsigned bundle manifest
(the checksum-value analogue of the M30.1 relpath-confinement fix).

**Plan (done).**
- Reject any checksum that is not exactly `[0-9a-f]{64}` before it is used as a
  path component, so it is always a single safe segment (no absolute path, no
  `..`, no separators).
- Re-hash CAS objects on **every** dedup hit; a blob whose bytes no longer match
  its digest (corrupted or poisoned out of band) is discarded and re-fetched
  from the verified source, never linked into a guest.

**Tests.** Adversarial checksums (absolute path, traversal, wrong length,
non-hex) are refused; a poisoned cache hit is re-hashed, dropped, and replaced
with verified bytes.

### M30.9 · Egress policy on every NIC + fail-closed  **[P0, engine]**

**Status: shipped.** The resolved egress policy is applied to **every**
virtio-net NIC, and a governed session that cannot resolve its policy fails
closed (deny-all) instead of running open.

**Finding (2026-07 review).** The policy was moved into the first NIC with
`net_policy.take()`, so a snapshot with a second NIC left that NIC unrestricted —
a path straight around the allow-list. Separately, "no policy source" and "a
source was specified but failed to load" both collapsed to `None`, so a governed
session whose policy file went missing/malformed booted wide open.

**Plan (done).**
- Derive `Clone` on `EgressPolicy`; hand every NIC a clone of the single
  resolved policy so all interfaces enforce the same allow-list.
- Resolve to an explicit `EgressResolution` (Unrestricted / Policy / FailClosed):
  a source that is present but unreadable/malformed **fails closed** with a
  deny-all policy rather than silently disabling the firewall.

**Tests.** The per-NIC clone still enforces the deny; the fail-closed policy
denies every destination; a missing/malformed source resolves to FailClosed.

**Remaining.** Requiring the HVF path for untrusted sessions and rejecting
multi-NIC snapshots outright (vs. governing them) are follow-ups tracked with
M30.4/M30.6.

### M31 · Network host-isolation — the reserved-address boundary  **[P0, engine]**

**Status: M31.1 shipped; M31.2-M31.5 open.** A second adversarial review
(2026-07-16) found that the egress boundary M28/M30.9 built is only a *policy*
gate; it did not stop a guest from reaching the **host's own networks**. The
userspace NAT relays a permitted flow through an ordinary host socket, so
whatever the guest dials, `chm` dials on the host — including:

- **loopback** (`127.0.0.0/8`, `::1`) — localhost databases, dev servers, other
  local tooling;
- **RFC1918 / private LAN** (`10/8`, `172.16/12`, `192.168/16`) — routers, NAS,
  other machines on your network;
- **link-local** (`169.254.0.0/16`), including the cloud **metadata endpoint**
  `169.254.169.254`;
- other special-use ranges (`0/8` "this host", CGNAT `100.64/10`, multicast
  `224/4`, reserved `240/4`).

This is a host-boundary break independent of filesystem isolation, and it is
reachable **by default**: networking is allow-all when no policy is bound (the
shipping default), and the app's global firewall ships disabled. Even in
allow-list mode it is bypassable by **DNS rebinding** — a permitted hostname
whose authoritative DNS answers `127.0.0.1` / a private IP is cached and then
authorises the connect to that reserved IP (`policy.rs` matches the resolved
name at connect time).

**Plan.**

- **M31.1 (P0, #75) — reserved-address guard. SHIPPED.** The NAT denies any
  connect whose destination IP falls in a special-use / non-public range,
  **independently of and before** the egress policy, so even allow-all cannot
  reach host-internal networks. The *resolved* IP is checked at connect time (a
  hostname allow-match never authorises a reserved IP → DNS rebinding closed),
  DNS answers resolving into reserved ranges are dropped, and an IP-literal allow
  rule in the *trusted* policy (or `--allow-local-egress` / `CHM_ALLOW_LOCAL_EGRESS`)
  is the only way to reach them. Proven by unit tests (the reserved predicate,
  the policy decision, DNS rebinding) and an end-to-end relay test: under
  allow-all a real guest stack cannot reach a localhost echo server.
- **M31.2 (P1) — safe default posture. SHIPPED.** With the guard always-on,
  allow-all is a safe floor (public egress only, never the host). The app's global
  default now ships the firewall **on in default-deny (allow-list) mode**, so a
  new sandbox has no public egress until the user allow-lists what it needs; the
  Settings copy makes the always-on host/LAN/metadata block explicit. (`chm` still
  warns when a restrictive policy is bound; an unbound run is public-egress with
  the host guard on.)
- **M31.3 (P1) — honest network docs.** Correct `networking.md` and the invariant
  table so claims match enforcement (allow-all default; the NAT relays via host
  sockets; the reserved-address guard is the real host boundary).
- **M31.4 (P2) — cloud/KVM path boundary. DOCUMENTED.** The network guarantees
  apply to the macOS userspace-NAT path only. The cloud/KVM capture path's
  isolation depends on the **external EC2 capture harness** (outside this repo)
  with EC2/S3 permissions and a reachable instance-metadata endpoint. This
  boundary is now stated explicitly in §1 "Out of scope" and in the BYO capture
  runbook; auditing the harness itself is tracked cross-repo.
- **M31.5 (P1) — signing default + digest recompute. SHIPPED (posture).** Signing
  still fails *open* when neither `CHM_TRUST_STORE` nor `CHM_REQUIRE_SIGNED` is
  set (by-design back-compat, #36). Setting **`CHM_REQUIRE_SIGNED`** now flips the
  default to fail-closed: the plane ingest path refuses any bundle it cannot
  authenticate (no trust root, or unsigned/invalid manifest), and the
  policy-digest recompute — previously advisory — is **enforced** (a governed
  policy whose doc does not re-hash to its stated digest is refused). The
  operator-set posture is the shipped half; gctl signing production manifests
  (#36) is the remaining cross-repo half.

---

## 4. Hardening checklist (the "hostile-agent ready" bar)

- [x] **File boundary** — bundles confined (symlink-reject, path-confine,
      `O_NOFOLLOW`), overlays in a private `0700` dir (M30.1, shipped).
- [x] **Daemon auth** — private `0600` socket in a `0700` dir, peer-cred check
      (M30.2, shipped).
- [x] **No shell strings** built from data in the app; centralised quoting +
      control-char rejection (M30.3, shipped).
- [ ] **Snapshot signing** — signed manifest, verified against a trusted key,
      provenance recorded (M30.4).
- [ ] **Trust root** — one root: app trusts the cloud/capture public keys; cloud
      signs; local verifies before exposing "Run" (M30.4).
- [x] **No host FS passthrough** — invariant documented, behavioural test +
      `make security-check` guard (M30.5, shipped).
- [x] **Resource limits** — per-sandbox vCPU/mem/disk/console/wall ceilings plus
      NAT connection-count + bandwidth caps (M30.6, shipped).
- [x] **Network policy** — egress allow/deny enforced on the local datapath: a
      default-deny allow-list applied to every NIC, fail-closed, plus NAT
      connection/bandwidth caps (M28 + M30.9). The live in-guest demo (#52) is
      pending only a net-enabled snapshot; enforcement already ships.
- [x] **Audit logs** — session start/stop, denied egress, and bundle-verify
      decisions recorded to a durable per-workspace `audit.jsonl` (M29, shipped).
- [x] **Network host-isolation** — a guest cannot reach loopback / private LAN /
      link-local (incl. `169.254.169.254`) regardless of policy or DNS answers,
      unless explicitly opted in (M31.1, shipped). Closes the critical gap found
      by the 2026-07-16 review.
- [ ] **Update / signing chain** — the app + `chm` binaries themselves are signed
      and updated over a verified channel (macOS notarisation + release signing).
- [x] **Escape-response assumptions** — documented (§1 "Out of scope"): a guest
      escape is assumed contained by the HVF VM boundary; the actively-defended
      escape is the bundle-driven host-file path, closed by M30.1 / M30.8 / I1.

---

## 5. How this sits with the feature milestones

- **Overlaps M28 (pillar ③).** M28 is the *policy* layer — the plane authors a
  `SandboxPolicy` (egress + fs scopes) and Gimbal Local enforces it. M30 is the
  *trust + isolation* layer beneath it: even with **no** policy, a bundle must
  not escape the host and the daemon must not be hijackable. M30's network item
  and M28's firewall enforcement are the same datapath, built once.
- **Overlaps M26 provenance.** M26 surfaces `source_kind` / `origin_substrate`;
  M30.4 makes that provenance **cryptographically verified**, not just displayed.
- **Precedence.** M30's P0 items (M30.1–M30.3) are correctness-preserving
  hardening of code that already exists and ship **before** M27. M30.4 is
  cross-repo and tracks the gctl signing contract like M27/M28 track their
  contracts.

Tracked as GitHub milestone **M30** with one issue per area above.
