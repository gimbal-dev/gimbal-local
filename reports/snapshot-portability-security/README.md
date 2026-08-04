# Gimbal Local snapshot portability and security audit

**Date:** 2026-07-30  
**Target:** `gimbal-dev/gimbal-local` at `f635e0f66`  
**Host validation:** Apple Silicon, macOS 26.5.2  
**Scope:** cloud-origin Cloud Hypervisor snapshot portability, hostile-agent
security, and coding-agent product readiness

## Verdict

> **The narrow dream is real; the product claim is not yet real.**

Gimbal Local genuinely resumes vanilla AWS Graviton Cloud Hypervisor snapshots
on Apple Hypervisor.framework. All three supplied captures independently
restored real disk devices and produced fresh login prompts after delayed host
input. This is live resumed execution, not a stub or console replay.

The larger promise—**securely run portable cloud coding-agent sessions
locally**—is still a prototype. The supplied guests have no NIC, one vCPU,
953 MiB usable RAM, an 8 GiB image whose 2.4 GB guest filesystem is 74% full,
and no development toolchain.
Snapshot authenticity is not enforced by default, local `chm run` verifies no
manifest, tar ingestion is manual, the real network path has not been proven on
a cloud capture, and no macOS CI executes the HVF path.

| Question | Score | Answer |
| --- | ---: | --- |
| Does a cloud snapshot really resume locally? | **8/10** | **Yes.** Three independent Graviton captures passed live interaction. |
| Is cloud-to-local delivery secure by default? | **3/10** | **No.** Provenance, archive intake, and local-run authenticity are incomplete. |
| Can these snapshots host a coding agent? | **1/10** | **No.** No NIC, insufficient resources, and missing toolchain. |
| Is the engine ready for a purpose-built agent image? | **5/10** | Promising, but the real net path, CPU fidelity, and hostile-console handling need proof/hardening. |
| Is this operationally mature? | **3/10** | No Apple-Silicon CI, no automated real-snapshot fixture, and ten focused tests remain ignored. |

## What was directly verified

| Evidence | Result |
| --- | --- |
| Repository identity | ✅ `origin` is `https://github.com/gimbal-dev/gimbal-local.git` |
| Build and entitlement | ✅ `chm` built on arm64 macOS and carried `com.apple.security.hypervisor` |
| Structural host-FS guard | ✅ `make security-check` passed |
| HVF integration test binary | ✅ Compiled with `hvf,kvm-snapshot` |
| Focused Rust tests | ✅ 207 passed, 0 failed, 10 ignored |
| Archive member safety | ✅ Seven expected regular files/directories per archive; no traversal, links, or devices |
| Snapshot 1 | ✅ Userspace GICv3, two block devices, RNG, fresh login prompts |
| Snapshot 2 | ✅ Userspace GICv3, two block devices, RNG, fresh login prompts |
| Snapshot 3 | ✅ Userspace GICv3, two block devices, RNG, fresh login prompts |
| Real cloud NIC path | ❌ Captures contain `net = null` |
| Signed provenance | ❌ No signatures or trust root |
| Automated macOS/HVF CI | ❌ No macOS runner |

The exemplary surface is the **KVM-to-HVF rehydration engine**. Its userspace
GICv3 correctly handles vanilla ITS/LPI routing that Apple's managed GIC cannot,
and the disk mappings were restored without modifying repository code or
snapshot metadata.

## Risk matrix

Risk score = impact (1-4) + exposure (1-3) + product-blocking (0-2) +
evidence-gap (0-1).

| Surface | Risk | Portability | Utility | Security | Evidence | Classification |
| --- | ---: | :---: | :---: | :---: | :---: | --- |
| <a href="#agent-image">Agent image and resources</a> | 🔴 **10** | ✅ | ❌ | ⚠️ | ✅ | 🧑 Human/image team |
| <a href="#intake">Archive intake and provenance</a> | 🔴 **9** | ⚠️ | ⚠️ | ❌ | ✅ | 🧑 Cross-repo decision |
| <a href="#network">Real snapshot networking</a> | 🔴 **9** | ⚠️ | ❌ | ⚠️ | ❌ | 🧑 Capture + engine |
| <a href="#ci">HVF verification and CI</a> | 🟠 **8** | ⚠️ | ⚠️ | ⚠️ | ❌ | 🧑 Infrastructure |
| <a href="#cpu">CPU/timer fidelity</a> | 🟠 **7** | ⚠️ | ⚠️ | ⚠️ | ✅ | 🧑 Architecture |
| <a href="#state-cdn">State-CDN peer cache</a> | 🟠 **7** | ✅ | ✅ | ❌ | ✅ | 🤖 Agent-fixable |
| <a href="#control-plane">External control-plane dependency</a> | 🟠 **7** | ⚠️ | ⚠️ | ❌ | ⚠️ | 🧑 Cross-repo |
| <a href="#posture">Posture/status semantics</a> | 🟡 **6** | ✅ | ⚠️ | ⚠️ | ✅ | 🤖 Agent-fixable |
| <a href="#isolation">Host isolation and limits</a> | 🟡 **5** | ✅ | ✅ | ⚠️ | ✅ | Mixed |
| <a href="#console">Untrusted console output</a> | 🟡 **4** | ✅ | ✅ | ⚠️ | ✅ | 🤖 Agent-fixable |
| <a href="#rehydration">Core rehydration</a> | 🟢 **2** | ✅ | ⚠️ | ✅ | ✅ | Exemplary |

<a id="rehydration"></a>
## Core rehydration: real

`chm` parses the Cloud Hypervisor `state.json`, maps `memory-ranges` privately,
restores vCPU/GIC state, reconstructs the virtio device tree, and calls Apple's
Hypervisor.framework. The supplied vanilla snapshots automatically selected
the userspace GICv3 path and restored:

- `_disk0`: 8 GiB root disk
- `_disk1`: cloud-init seed
- `__rng`: virtio RNG

A newline sent five seconds after launch produced new `ch-snap login:` prompts
for every capture. This proves guest execution continued after restore.

**Verdict:** no gaslighting here. The hard hypervisor-translation claim holds.

---

<a id="agent-image"></a>
## Coding-agent image and resources: not real

All three archives are the same weak capture shape:

- 1 vCPU
- 1 GiB RAM (953 MiB usable in the guest)
- 8 GiB root-disk image, but only a 2.4 GB guest filesystem is provisioned;
  that filesystem is documented as 74% full with 634 MB free
- no NIC or routes
- no `gcc`, `make`, `node`, `npm`, `go`, or `cargo`

The repository itself admits this in
[`docs/roadmap.md`](../../docs/roadmap.md#L203-L225). These are demo VMs, not
coding-agent sessions. A real product needs a purpose-built image, a minimum
resource contract, and a capture with at least one NIC and multiple vCPUs.

**Verdict:** describing the current artifacts as coding-agent sandboxes would
be fiction. The internal roadmap is honest; the top-level pitch is ahead of it.

---

<a id="intake"></a>
## Archive intake and provenance: unsafe workflow gap

The product's actual handoff artifact is `.tar.zst`, but the repository has no
hardened importer. `chm run` only accepts an already-extracted directory and
reads `state.json` plus `snapshot/memory-ranges`
([`chm/src/imp.rs`](../../chm/src/imp.rs#L70-L100)). Users must choose and run
an external tar extractor before the repository's path-confinement controls
apply.

The three supplied archives were structurally safe, but carried no signature.
The cloud ingest path accepts unsigned manifests when no trust store is
configured
([`control_plane.rs`](../../chm/src/control_plane.rs#L1980-L2039)), and local
`chm run` performs no integrity or authenticity check at all. The signing
implementation is sound but opt-in; the producer-side trust root remains in
the external `gimbal-cloud-control` repository.

**Required bar:**

1. A first-party importer that validates archive paths/types, extracts into a
   private staging directory, verifies every digest, verifies a signed
   manifest, then atomically promotes the bundle.
2. Local `chm run` must reject externally sourced snapshots lacking verified
   provenance, with an explicit developer override for trusted local fixtures.
3. Ship and rotate a trust root with the control plane; stop treating I6 as
   “not applicable.”

---

<a id="network"></a>
## Networking and egress: code exists, product proof does not

The userspace NAT, DNS, reserved-address guard, policy engine, and credential
proxy are substantial implementations. However, the supplied real-cloud
captures contain `net = null`; the repository explicitly says the NAT and
egress policy have never been exercised against a real cloud capture
([`docs/roadmap.md`](../../docs/roadmap.md#L211-L224)).

Direct `chm run` also resolves to unrestricted public-internet egress when no
policy exists
([`chm/src/imp.rs`](../../chm/src/imp.rs#L702-L745)). Reserved host/LAN ranges
remain blocked, which is a valuable default, but a hostile coding agent can
still exfiltrate anything present in the guest.

**Verdict:** “network stack implemented” is true. “Cloud coding agent can use it
securely” is unproven.

---

<a id="cpu"></a>
## CPU and timer fidelity: bounded, not transparent

The captures advertise AArch32 at EL0 because Graviton supports it; Apple
Silicon does not. `CHM_STRICT_AARCH32=1` correctly refused all three snapshots.
The default warns and runs because the measured Ubuntu guest contains no
32-bit binaries. Executing one later would permanently wedge the vCPU.

The captures also predate upstream counter metadata commit `69637dde6`, so
`chm` cannot authenticate their counter frequency. The repository's
`CNTVOFF` synthesis fixes the measured 5.08x Graviton-to-Apple clock mismatch,
but these particular archives do not self-describe the required rate. `CTR_EL0`
also differs in DIC semantics, leaving a documented latent I-cache-maintenance
risk.

**Verdict:** portability is workload-conditional, not “arbitrary arm64
snapshot” compatibility.

---

<a id="isolation"></a>
## Host isolation: strong prototype foundations

Implemented controls that held up under code review:

- no virtio-fs/9p/shared-folder device support;
- private copy-on-write RAM mapping;
- no-follow disk/overlay opens and confined bundle paths;
- private overlay directories;
- same-UID daemon socket authorization;
- reserved-address network guard;
- resource ceilings for CPU, RAM, overlays, console, and NAT sockets;
- authenticated AES-GCM state-CDN chunks;
- destination-bound credential injection with verified upstream TLS.

These are real controls, not documents. The remaining problem is that they do
not compensate for unauthenticated inputs, unrestricted public egress, or a
missing safe archive entry point.

---

<a id="state-cdn"></a>
## Security finding: state-CDN peer-cache path traversal

**Severity:** Medium security / High product risk  
**Confidence:** High  
**Location:** [`chm/src/state_cdn.rs`](../../chm/src/state_cdn.rs#L358-L418)

The LAN peer-cache endpoint reads a file at:

```text
cache / sanitize(ref) / sanitize(key)
```

`sanitize("..")` remains `..` for either attacker-controlled segment. A
request such as:

```text
GET /state-cdn/chunk?ref=..&key=<safe-filename>
```

reads and returns a file from the cache directory's parent. Setting both
segments to `..` normalizes to the grandparent directory, but `fs::read` cannot
turn that directory target into an arbitrary grandparent file because slashes
inside either segment become `_`. The confirmed disclosure primitive is
therefore any single safe-named file in the cache parent's directory. It is
network reachable whenever the peer cache binds a routable address.

**Fix:** validate each value as a non-empty single segment, reject `.`/`..`, and
confine the final path before read. Add traversal regression tests for both
query parameters.

---

<a id="console"></a>
## Security finding: hostile guest output reaches the terminal

**Severity:** Low  
**Confidence:** High  
**Location:** [`chm/src/console_filter.rs`](../../chm/src/console_filter.rs#L23-L81)

The console filter removes one cosmetic kernel line and otherwise forwards raw
guest bytes. An untrusted guest can emit ANSI/OSC terminal-control sequences or
prompt-injection text to a human/agent consumer. This audit captured output to
a file and stripped controls before inspection.

**Fix:** provide an agent/non-TTY mode that escapes C0/C1, CSI, and OSC
sequences; reserve raw output for an explicitly interactive TTY.

---

<a id="control-plane"></a>
## Control plane: critical half lives elsewhere

The local repository contains the control-plane client, not the server that
assigns, signs, and distributes production bundles. The signing producer and
trust-root rollout are therefore not verifiable here. The state-CDN is
reconstruction, not demand-paged postcopy.

**Verdict:** a secure cloud-to-local claim cannot be closed by this repository
alone. It requires a cross-repo threat model and end-to-end signed fixture.

---

<a id="ci"></a>
## Verification and CI: manual heroics, not a safety net

The HVF test suite is gated to Apple-Silicon macOS, but every repository CI
runner is Linux. Real snapshot tests are environment-gated or ignored, and the
Make target compiles them with `--no-run`. The three supplied snapshots were
external and the prior “acid test” evidence was prose.

This audit reproduced the acid test, which raises confidence in the engine but
does not solve regression risk.

**Required bar:**

- Apple-Silicon CI or a dedicated hardware runner;
- a legally distributable, minimized snapshot fixture;
- automated live-console challenge/response;
- net-enabled, multi-vCPU cloud capture in the matrix;
- signed-manifest negative tests at the real import/run boundary.

---

<a id="posture"></a>
## Where status language becomes misleading

This is not wholesale gaslighting. The deep documents are unusually candid.
The problem is **layering**:

| Claim/status | Reality |
| --- | --- |
| README: milestones are “all hardware-verified” | No macOS CI; some network claims are synthetic/local only |
| README: M28 default-deny allow-list | Direct `chm run` without a policy allows public egress |
| `chm posture`: `weakened: 0` | Signature verification and egress allow-list are labeled “not-applicable” |
| Security invariant I6: only verified snapshots run | Local run verifies no manifest; cloud verification is opt-in |
| “A vanilla snapshot just works safely” | It runs, but strict AArch32 compatibility refuses it and provenance is unknown |
| Coding-agent sandbox framing | Current real captures cannot network or build software |

The most misleading artifact is `chm posture`: exit code 0 means “not weaker
than our chosen defaults,” not “safe for hostile-agent execution.” That is a
policy report, not a security gate, despite language that invites callers to
use it as one.

## Recommended sequence

1. **P0 — close the real trust boundary:** first-party safe importer, mandatory
   signed provenance, and local-run verification.
2. **P0 — produce the actual workload:** net-enabled 2+ vCPU agent image with
   sufficient disk/RAM and toolchain.
3. **P0 — prove network behavior:** run clone/package/API workflows from a real
   cloud capture under default-deny and credential injection.
4. **P1 — fix concrete vulnerabilities:** state-CDN traversal and hostile
   console sanitization.
5. **P1 — make claims executable:** Apple-Silicon CI and a signed portable
   fixture with challenge/response.
6. **P1 — redefine posture:** add a hostile-agent profile where missing
   signatures, unrestricted public egress, and unresolved AArch32 compatibility
   fail the gate.
7. **P2 — tighten compatibility contract:** require modern counter metadata and
   document supported CPU-feature deltas as an import-time decision.

## Methodology and evidence

The audit used:

- static code and document review at `f635e0f66`;
- independent security-specialist review;
- Git history and repository identity;
- archive header inspection before extraction;
- SHA-256 hashes of archives and extracted payloads;
- private extraction outside the repository;
- signed `chm` build on Apple Silicon;
- bounded, captured, control-sanitized HVF execution;
- 207 focused Rust tests, the HVF compile target, and the structural security
  guard.

Raw guest disks and console streams are intentionally not committed. Rerunnable
static discovery and sanitized validation summaries are in
[`artifacts/`](artifacts/).
