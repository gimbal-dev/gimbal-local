# State-CDN memory plane — the Mac consumer (M27 Phase 2)

The control plane stores a checkpoint's guest RAM not as one file but as a
**content-addressed, per-tenant-encrypted, deduped chunk store** — "a CDN for
live compute state." This doc covers the Mac side: how `chm` **consumes** that
plane, what is real today, and the one honest gap (true demand-fault postcopy)
with its plan.

Companion to the control-plane spec
([`state-substrate.md`](https://github.com/gimbal-dev/gimbal-cloud-control/blob/main/docs/state-substrate.md))
and the runner contract's Phase-2 handoff.

---

## What the plane serves

A suspend ingests the checkpoint's RAM into a chunk store (256 KiB pages;
all-zero pages elided; identical plaintext deduped **within** a tenant via
convergent AES-256-GCM, opaque **across** tenants). A resume on an
offload-capable runner returns the CDN fields on the assignment:

```jsonc
{ "memory_mode": "postcopy",
  "state_cdn_endpoint": "http://…", "memory_ref": "sha256:…",
  "capability_token": "…",              // token-gated, ref-scoped, ~10 min TTL
  "daemon": { "namespace": "tenant", "encrypted": true, "chunk_size": 262144,
              "page_count": 8, "total_size": 2097152,
              "tenant_key_b64": "…" } }  // the 32-byte AES-256 data key
```

Two token-gated routes back it:

- `GET /state-cdn/memory-ref?ref=&token=` → the ordered page map
  (`offset`, `length`, `store_key`, `encrypted`, `nonce`, `zero`).
- `GET /state-cdn/chunk?ref=&key=&token=` → one raw chunk (ciphertext‖tag for a
  tenant ref).

---

## What `chm` does today — CDN-backed resume by reconstruction

`chm/src/state_cdn.rs` is the real consumer, exposed as:

```
chm state-cdn reconstruct --endpoint URL --ref REF --token TOK \
    --tenant-key-b64 KEY --out memory-ranges
```

It:

1. fetches the **page map**;
2. for each non-zero page, fetches its **chunk** and **decrypts** it
   (AES-256-GCM, 12-byte nonce from the page map, tenant key from the assignment)
   — a wrong key fails authentication rather than yielding garbage;
3. leaves **zero pages** as the file's natural zero fill (no fetch);
4. writes each page at its offset, reassembling the flat `memory-ranges` image
   `chm resume` restores from.

So a checkpoint's RAM travels as encrypted, deduped, content-addressed chunks and
is rebuilt on the Mac. The runner advertises **`supports_offload_daemon`**.

### Per-page-range ACL honoring

A branch can grant a runner only a **subset of pages** (`page_acls`). On such a
pull the plane mints a **scoped** capability token (`acl_applied: true`); the
token still reads the whole page map, but an out-of-scope chunk fetch is refused
**403**. `reconstruct` honors the grant: a 403 marks the page **ACL-denied** and
leaves it zero (a least-privilege image), rather than failing the run. Proven
live: a page-0-only token reconstructs 1 fetched + **3 ACL-denied** pages; a full
token fetches all 4.

### Proven live (`$0`, local `:8080` plane)

Against a real tenant-encrypted ref (`sha256:b2b6576f…`, 8 pages / 2 MiB):

| Check | Result |
| --- | --- |
| Reconstruct | 2 097 152 bytes, **4 pages fetched + AES-256-GCM-decrypted, 4 zero-elided** |
| Determinism | two runs → identical `sha256` (`e0def239…`) |
| Auth | a wrong tenant key → **`AES-256-GCM authentication failed`**, not silent garbage |
| ACL | a page-0-only scoped token → **1 fetched, 3 ACL-denied**, run still succeeds |

Unit tests seal a page exactly as the plane does and prove `chm` decrypts it
byte-for-byte, plus base64/hex/URL-encoding vectors.

---

## The honest gap — true demand-fault postcopy is **not** done

`supports_postcopy` means *demand-fault only the touched working set* — the guest
starts and pages fault in lazily as it accesses them, so a resume moves only what
the session actually uses. **`chm` does not do this yet, and does not claim it.**
It reconstructs the working set **eagerly** before the guest runs. Concretely:

- `chm` advertises `supports_offload_daemon` (it consumes the CDN) but **not**
  `supports_postcopy` (it does not demand-fault). The plane only sends CDN fields
  when a runner advertises **both**, so in production `chm` currently takes the
  file-backed Phase-1 path; `chm state-cdn reconstruct` is the proven building
  block for when demand-fault lands.

### Why it is hard on HVF (and the plan)

The Linux/KVM offload daemon demand-faults with `userfaultfd`. **macOS has no
`userfaultfd`**, and today `chm` maps all guest RAM up front
(`mmap(MAP_ANON)` + read the flat image, then `hv_vm_map`), so a guest access to
an un-fetched page never traps to the VMM. True postcopy on HVF needs
stage-2 fault interception:

1. Map guest RAM **no-access** (or unmapped) instead of pre-populating it.
2. Catch the guest's stage-2 abort as a VM exit, read the faulting **IPA**.
3. Fetch + decrypt that page from the CDN, `hv_vm_map`/`hv_vm_protect` it in,
   re-enter — the HVF analogue of `userfaultfd`.
4. A background thread pre-fetches likely-next pages so the guest rarely blocks.

This is a real, bounded VMM change (the vcpu-run loop gains a fault handler and
the memory model gains a lazy backing), gated on hardware testing. Until it
lands, `chm` stays honest: CDN consumption is real; the touched-working-set
*optimization* is tracked, not faked.

---

## Peer cache — LAN-local chunk sourcing

`reconstruct --cache DIR` also keeps each fetched **ciphertext** chunk, and
`chm state-cdn serve --cache DIR` runs a small HTTP server exposing
`GET /state-cdn/chunk?ref=&key=` over them. `chm state-cdn register-peer` then
advertises the node to the plane (`POST /peer-caches`) with its endpoint +
locality, so `GET /state-cdn/source` routes a same-locality puller here instead
of the origin.

Serving is safe without a token check **for full-access refs**: the chunks are
opaque ciphertext, so only a puller that already holds the tenant key (from its
own legit resume) can decrypt them.

**What that argument depends on — and a bug that broke it.** "Opaque
ciphertext" only holds if the server can serve nothing *but* cache contents.
In every release up to and including **v0.2.1** it could not. `sanitize()` folds
`/` to `_`, which kills multi-segment traversal, but it keeps `.` — so a `ref`
of `..` survived as a whole path segment and `Path::join` stepped one level out
of the cache.
`GET /state-cdn/chunk?ref=..&key=secret.txt` returned any file named
`[A-Za-z0-9.-]+` sitting *beside* the cache directory: plaintext, unauthenticated,
200. Measured before and after the fix against a real socket with a decoy file:

| | `ref=..&key=secret.txt` |
| --- | --- |
| before | `HTTP 200` — file contents returned |
| after | `HTTP 404 chunk not in this peer cache` |

The default bind is loopback (`127.0.0.1:9700`), so reaching it needed
`--addr` on a routable interface. `cache_path` now appends a single plain
filename component per segment and refuses anything else — `.`, `..`, absolute
paths, empty — so the containment this section's argument assumes is now
enforced rather than implied. A refused path and a genuine miss both return
404, so the endpoint never confirms what does or does not exist off-cache.

The endpoint is still deliberately **unauthenticated**: bind it only to an
interface you would be willing to hand every ciphertext chunk on.

**Honest boundary — page-range ACLs + peers.** A peer serves any chunk it holds,
so it does not itself enforce a *page-range ACL*: a puller scoped to a subset of
pages that reached this peer directly could fetch an out-of-scope chunk it would
be refused (403) at origin. So an **ACL-restricted ref must be sourced from
origin**, where the scope is enforced — which is exactly what `reconstruct` does
(it fetches from the assignment's `state_cdn_endpoint`, never a peer). Making
peers enforce scopes too needs a plane-defined peer-token contract (local
public-key verification, or forward-validation to origin) and is a tracked
follow-up. Proven live: a peer served byte-identical chunks (the served bytes'
`sha256` equals the content-address `store_key`), and a different locality fell
back to origin.

---

## Where this sits

- **Pillar ②** (branching filesystem + lazy load): the memory plane is the
  "lazy load" half. `chm push`/`pull` (Phase 4) already move revisions; this adds
  consuming their memory from the CDN.
- **Provenance/trust:** chunks are encrypted and content-addressed; a wrong key
  is rejected. Signed-manifest verification (M30.4) will extend this to
  authenticity of the ref itself.
