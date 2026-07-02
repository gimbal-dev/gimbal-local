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
- **Side channels** (timing, cache, Spectre-class) between guest and host.
- **Physical access / a compromised macOS account** running as the user.
- **The control plane's own security** — owned by `gimbal-cloud-control`; we
  consume its trust root (M30.4) but do not audit its internals here.

---

## 2. Security invariants

These are the properties we commit to. Each has an enforcement mechanism and a
test/guard so a regression is caught, not discovered.

| # | Invariant | Enforced by | Status |
| --- | --- | --- | --- |
| I1 | **No host filesystem passthrough.** A guest never gets a virtiofs/9p/shared-folder mount of a host directory. The only guest storage is virtio-blk over a bundle-owned image + a private overlay. | Device model ships only block/rng/net; a CI guard fails if virtiofs/9p/shared-folder appears without review. | **Holds today**; guard is M30.5 |
| I2 | **Bundles are confined.** Every file `chm` opens for a bundle resolves to a real path **under the bundle root** — no symlink is followed out, no `..` escapes. | `symlink_metadata` rejection + path confinement + `O_NOFOLLOW` opens. | **Holds today** (M30.1) |
| I3 | **Overlays are private.** Writable overlays/checkpoints are created by `chm` in a fresh `0700` dir it owns, refusing a symlinked overlay/dir shipped in the bundle. | Private `0700` overlay dir + no-follow overlay opens. | **Holds today** (M30.1) |
| I4 | **The daemon is local-and-owner-only.** Only the same-uid user can drive the control socket; the socket lives in a private `0700` dir with `0600` perms and validates peer credentials. | Private socket dir + `0600` perms + `getpeereid` peer-uid check. | **Holds today** (M30.2) |
| I5 | **The app never builds host shell code from data.** Snapshot/sandbox names and paths never become shell tokens. | Centralised single-quote builder + control-char rejection; adversarial-input tests. | **Holds today** (M30.3) |
| I6 | **Only verified, provenance-known snapshots run.** A bundle is checksum-verified **and** signature-verified against a trusted key before import or run; provenance is recorded. | Signed manifest + verification against the cloud trust root. | **Not yet** (M30.4) |
| I7 | **Undeliverable snapshots are refused, not mis-run.** ITS/LPI snapshots fail loudly at the load guard and the `assign-run` 422 gate. | `its_lpi_guard` + plane gate. | **Holds today** |

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

**Finding.** Snapshot trust is missing — bundle contents and `state.json` are
trusted after only a checksum.

**Verified.** `materialize_bundle` verifies each object against
`manifest.checksum_tree` (integrity — detects corruption) but there is **no
signature** (authenticity — nothing proves the manifest itself came from the
cloud). A tampered bundle with a matching recomputed `checksum_tree` passes.

**Plan (cross-repo with gctl).**
- Define a **signed manifest**: the manifest hashes every file **plus** runtime
  metadata (substrate, gic_mode, origin, sizes), and carries a **signature** over
  that manifest, produced by the cloud/capture signing key.
- `chm` (and the app before it exposes "Run") **verify the signature** against a
  trusted public key, then verify `checksum_tree`, then record provenance.
- gctl owns producing + signing the manifest; Gimbal Local owns verification.

### M30.5 · No-host-FS-passthrough invariant + CI guard  **[P1, docs + test]**

**Finding.** "No ordinary host FS sharing" is true by design but implicit.

**Plan.** Make I1 **explicit**: document it here (done) and add a repo guard (a
test / CI grep) that **fails** if `virtiofs`, `9p`, `virtio-fs`, or a
shared-folder / host-mount device path appears in the device model without a
paired security review. So the invariant can't silently regress.

### M30.6 · Per-sandbox resource limits  **[P2, engine]**

**Finding (from area 8).** A hostile sandbox has no declared resource ceiling.

**Plan.** Bound per-sandbox vCPU / memory / disk-overlay growth (the snapshot's
own vCPU+RAM shape is the baseline; cap overlay size + wall-clock where the
runner drives it) so a runaway guest can't exhaust host resources. Small MVP;
integrates with the M28 policy object later.

### M30.7 · Threat model + hardening checklist  **[P0, docs]**

**Finding.** Not production-ready as a hostile sandbox; needs a written threat
model + checklist.

**Plan.** *This document.* It defines the model, the invariants, and the
per-area plan, and is the acceptance surface for M30. The checklist below is the
"done" bar.

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
- [ ] **No host FS passthrough** — invariant documented + CI-guarded (M30.5).
- [ ] **Resource limits** — per-sandbox vCPU/mem/disk ceilings (M30.6).
- [ ] **Network policy** — egress allow/deny enforced on the local datapath
      (converges with **M28**; the firewall half of pillar ③).
- [ ] **Audit logs** — start/stop/verify/deny decisions recorded (converges with
      **M29** telemetry).
- [ ] **Update / signing chain** — the app + `chm` binaries themselves are signed
      and updated over a verified channel (macOS notarisation + release signing).
- [ ] **Escape-response assumptions** — documented: a guest escape is assumed
      contained by HVF; a bundle-driven host-file escape is the boundary M30.1
      closes.

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
