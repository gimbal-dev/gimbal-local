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

### Proven live (`$0`, local `:8080` plane)

Against a real tenant-encrypted ref (`sha256:b2b6576f…`, 8 pages / 2 MiB):

| Check | Result |
| --- | --- |
| Reconstruct | 2 097 152 bytes, **4 pages fetched + AES-256-GCM-decrypted, 4 zero-elided** |
| Determinism | two runs → identical `sha256` (`e0def239…`) |
| Auth | a wrong tenant key → **`AES-256-GCM authentication failed`**, not silent garbage |

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

## Where this sits

- **Pillar ②** (branching filesystem + lazy load): the memory plane is the
  "lazy load" half. `chm push`/`pull` (Phase 4) already move revisions; this adds
  consuming their memory from the CDN.
- **Provenance/trust:** chunks are encrypted and content-addressed; a wrong key
  is rejected. Signed-manifest verification (M30.4) will extend this to
  authenticity of the ref itself.
