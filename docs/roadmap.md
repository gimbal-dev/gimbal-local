# Gimbal Local — roadmap & milestones

Gimbal Local rehydrates Cloud Hypervisor arm64 / KVM snapshots onto Apple
Hypervisor.framework (HVF), so a workload captured in the cloud can be brought
down and run — or resumed *past where it left off* — on an Apple-silicon Mac.

Companion to [`macos-local-runtime.md`](macos-local-runtime.md) (the
architecture): read that for *how* the port works, this for *where it is going*.

**Start at [§0, the goal ledger](#0-the-goal-ledger--what-the-local-ship-means)**
if you want to know what we are building toward. §1 onward is how much of it is
true and how we got here.

---

## 0. The goal ledger — what the local ship means

Re-baselined **2026-08-04**, after V8.4 merged. This is the definition of done
for the **local standalone ship**: a product that needs no control plane. It
supersedes ad-hoc milestone tracking as the answer to *"are we building the
right thing?"*.

Goals marked **★** are new in this baseline — either named for the first time,
or adopted after reading what Cloudflare shipped in
[Cloudflare Computer](https://blog.cloudflare.com/cloudflare-computer/)
(2026-08-03) and its Containers platform.

### The ship goals

| # | Goal | State | Evidence, or what is missing |
| --- | --- | --- | --- |
| **G1** | **Real Cloud Hypervisor locally, plus BYO images by path** — not simulated | ✅ **done** | Stock upstream, unforked, Graviton2 captures, no flags (V1.5 acid test). BYO image directories with typed refusals (V8.3). Cold boot of a stock kernel with no snapshot in the path (V5.4). |
| **G2** | **Snapshot as changes happen — time travel** | 🟡 **half** | Have: live checkpoints incl. SMP (V5.6), fork/CoW lineage, `revisions`, `rollback`, auto-prune to 5 resumable. Missing: **nothing snapshots on its own.** Every checkpoint is a manual suspend, so there is no timeline to travel along. |
| **G3** | **Runs Copilot for real, safely isolated** | ✅ **done** | V7.1: Copilot CLI installed, authenticated, wrote and ran JS, on a cold-booted guest, holding **no credential** — verified by hashing, not by trusting the agent. |
| **G4** | **Network controls** | ✅ **done, with gaps** | Default-deny-able egress allow-list, userspace NAT, reserved-address guard (I10), per-NIC fail-closed, egress audit trail (V6.3). Gaps are G17/G20 below. |
| **G5** | **Off-box credentials** | ✅ **done** | Injected at the network edge; guest never holds one (V5.2, I12). In-app rule builder with no field that can hold a token (V8.5). |
| **G6** | **Create local images — from vanilla *or from containers*** | 🟡 **half** | Vanilla: done (cold boot, BYO). **Containers: nothing.** No OCI/Docker→rootfs path exists anywhere in the tree. |
| **G7** | **A consistent CLI with all features** | 🟡 **partial** | 24 subcommands; the app now drives **19** of them. But **7 are absent from `chm --help`** — including `create`, the flagship cold-boot path. The app is ahead of the CLI's own discoverability. |
| **G8** | **Snapshot management** | 🟡 **partial** | Have: lineage, fork, rollback, bounded growth. Missing: **delete, garbage-collect, disk-usage reporting, rename, export/import.** Nothing reclaims a snapshot you no longer want. |

### Goals we already held, stated explicitly

| # | Goal | State | Evidence, or what is missing |
| --- | --- | --- | --- |
| **G9** | **Every claim carries its evidence** — the app never asserts a control it has not checked | ✅ **done** | V6.5 capability honesty; `chm posture` exits non-zero when anything is weakened; the proxy page names which process answered. |
| **G10** | **A build someone else can actually run** | 🔴 **not started** | Everything is verified against `target/debug/chm` in a git checkout with a manual re-sign. #144 / V8.6. **This is the single hardest blocker on the word "ship".** |
| **G11** | **Resource ceilings by default** | ✅ **done** | M30.6 + V4.2: an unconfigured workspace resolves to a real baseline, not unbounded. |
| **G12** | **Signed provenance / trust root** | 🟡 **half** | Ed25519 signed-manifest verification and a reference signer exist on the `chm` side (M30.4). The unified trust root is cross-repo. |
| **G13** | **Observability — what a session cost, did, and reached** | 🟡 **half** | Egress audit is real and shown (V6.3). There is **no unified per-session record** of what the sandbox did. |
| **G14** | **Cloud round-trip** | 🟡 **half** | Cross-substrate mobility is proven. Signed-manifest contract is not. **Deliberately out of scope for the local ship** — it is the only thing gated on another team. |

### ★ New goals — the sandbox contract

The theme these share: **we can start a sandbox, but we cannot describe one.**
Cloud Hypervisor's own contract is a VM config; ours is a pile of CLI flags.
Cloudflare's product is weaker than ours on the thing we are best at (see
below), and stronger on exactly this.

| # | Goal | State | Why it is a goal |
| --- | --- | --- | --- |
| **G15 ★** | **A declarative sandbox spec** — one document that says what a sandbox *is*: image, sizing, egress policy, credential rules, env, entrypoint, lifetime | 🔴 | Today this is ~10 argv flags across two entry points, and the app reimplements the assembly. A spec makes a sandbox reproducible, diffable, and shareable — and is the natural unit for the control plane later. Cloudflare has this (`wrangler.jsonc` + `Container` class fields). |
| **G16 ★** | **`exec` into a running sandbox** — run a command, get stdout/stderr/exit code | 🔴 | `chm ctl input` types characters at a console and you scrape the screen. There is **no way to run a command and learn whether it succeeded.** This is the single biggest ergonomic gap for driving an agent, and it is what every automation will want first. Cloudflare's `ctx.container.exec()` returns `{stdout, stderr, exitCode, pid, kill()}`. |
| **G17 ★** | **Runtime-mutable network policy** — change egress rules on a live sandbox | 🔴 | Ours is fixed at start; changing it means restarting the guest, which throws away the work. Cloudflare changes allow/deny lists on a running container without dropping connections. Directly serves G4. |
| **G18 ★** | **Idle sleep with activity reset, and a graceful stop** | 🟡 | `--idle-exit` defaults to **10 seconds** of console silence, and `--max-seconds` is a **power cut on a writable disk**. Cloudflare's `sleepAfter` defaults to 10 minutes, resets on activity, and calls a stop hook. Ours should suspend to a checkpoint rather than kill — which is G2's mechanism, reused. |
| **G19 ★** | **Named sizing tiers** | 🔴 | `--cpus 2 --memory 2048` is a guess every time. Named tiers make sizing a decision someone can be right about, and give the docs something to reference. |
| **G20 ★** | **Ingress — reach a service inside the sandbox** | 🔴 | The NAT is egress-only. An agent that starts a dev server on :3000 has no way to be reached. Cloudflare exposes `containerFetch`/`getTcpPort`. **Must be opt-in and per-port**, or it is a hole in the isolation we spent M30/M31 building. |
| **G21 ★** | **MCP surface** — drive a sandbox as an MCP server | 🔴 | Not adopted from Cloudflare: their docs mention MCP **nowhere**. It is our own bet, and G15+G16 are its prerequisites — an MCP tool call is exactly "start a sandbox from a spec" plus "exec in it and tell me what happened". |
| **G22 ★** | **Env vars and entrypoint at start** | 🔴 | No way to pass configuration into a guest without baking it into the image. Cheap, and G15 needs the fields anyway. |
| **G23 ★** | **An agent paper trail** | 🟡 | We record what *left* the sandbox (V6.3). We do not record what the agent *did* inside it. Cloudflare claims "a clear paper trail showing what the agent did" but documents no API for it — so this is a goal we would be defining, not copying. |

### What the research changed, and what it confirmed

Reading the Cloudflare product against ours produced one genuine surprise, and
it went in our favour:

- **They have no VM snapshots at all.** No checkpoint, no fork, no resume. Their
  `sleepAfter` is a **cold stop that discards the container disk**; persistence
  is a SQLite filesystem in a Durable Object, FUSE-mounted back in. So *"sleep"*
  there means *"stop and cold-start later"*. **G2 — snapshot-as-you-go with real
  time travel — is not a catch-up feature. It is the thing we have that the
  nearest comparable product does not.** That is an argument for prioritising it
  rather than the contract work, and it reverses the instinct.
- **Their credential design is architecturally identical to ours** — a handler
  outside the sandbox holds the secret, the guest makes a plain request, the
  header is attached on the way out. Independent convergence on V5.2/I12 is the
  strongest evidence we have that the design is right.
- **They describe container isolation as "a Linux VM"** but publish no
  hypervisor detail, no seccomp/capability claims, and no statement of what a
  guest can attempt. Our 12 invariants and `chm posture` are a **stronger
  security story, stated more precisely** — G9 is a real differentiator, not
  housekeeping.
- **`@cloudflare/computer` is explicitly preview-only**, and its `docs/` are
  stated by its own README to be "forward-looking — read for intent, not as
  description of the code today". Treat its API as a signal of direction, not a
  shipped bar.

---

## 0a. How milestones ladder into the goals

### The last ten, and which goal each served

Reverse chronological, all merged and hardware-verified:

| # | Milestone | Merged | Serves |
| --- | --- | --- | --- |
| 1 | **V8.4 + credential builder** — settings persist; a rule builder with no field that can hold a token; `chm` is the authority on whether a rule is valid (#147) | 08-04 | G5, G9 |
| 2 | **V8.3 · Bring-your-own images** — an image directory with typed refusals; the symlink rule found by using it (#146) | 08-03 | **G1** |
| 3 | **V8.2 · Local-only mode** — stops the app *reaching* for a control plane, not just hiding it (#146) | 08-03 | G14 boundary |
| 4 | **V8.1 · Cold boot from the app** — the app's most basic capability stops depending on infrastructure the user may not have (#146) | 08-03 | **G1** |
| 5 | **V7.1 · A coding agent works inside the sandbox** — Copilot CLI installed, authenticated, wrote and ran JS, holding no credential (#141) | 08-03 | **G3**, G5 |
| 6 | **Icache-elision warning** — a capture whose kernel elided `ic ivau` is named rather than mysteriously SIGILL-ing (#140) | 08-03 | G9 |
| 7 | **Overlay drift refusal** — refuse to resume a checkpoint whose disk moved on under it (#139) | 08-03 | **G2**, G8 |
| 8 | **Retire the managed GIC** — one interrupt backend; retiring it exposed three real defects it had been hiding (#138) | 08-03 | G1 |
| 9 | **Cold boot: SMP, disk, NIC, RTC** — a cold guest gets real hardware, on more than one core (#133–#137) | 08-03 | **G1**, G6 |
| 10 | **V6.1–V6.5 · The app tells the whole truth** — posture, credential proxy, egress audit, capability honesty, each claim carrying its evidence (#129–#132) | 07-31 | **G9**, G4, G13 |

### What is outstanding, against the local ship

Ordered by what actually blocks the word *"ship"*. **V9 is new** — it is the
track the goal ledger creates.

| | Milestone | Goal | Why now | Size |
| --- | --- | --- | --- | --- |
| **V8.6** (#144) | **A build someone else can run** — signed `.app` that finds its own `chm`, and an honest statement of what it needs | G10 | Nothing else on this list matters if the answer to *"can I have it?"* is *"clone the repo and re-sign the binary"*. **The one true blocker.** | M |
| **V9.1 ★** (#148) | **Continuous snapshots** — checkpoint on a cadence and on meaningful events, keep a browsable timeline, restore any point | **G2** | The capability the nearest comparable product does not have at all. The primitives all exist (SMP checkpoint, lineage, prune, drift detection); what is missing is something that *decides when*. | L |
| **V9.2 ★** (#149) | **`chm exec`** — run a command in a running sandbox, get stdout/stderr/exit code | **G16** | Everything that automates this product needs it, and today the only answer is to type at a console and scrape it. Cheapest large win on the list. | M |
| **V8.7** (#145) | **Proxy rules imply egress allowance** | G4, G5 | Naming a host in an injection rule *is* the intent to reach it. Found by using V7.1 in anger. | S |
| **V9.3 ★** (#150) | **The sandbox spec** — one declarative document: image, sizing, egress, credentials, env, entrypoint, lifetime | **G15** | Makes a sandbox reproducible and diffable, removes the app's duplicate flag assembly, and is the unit the control plane will want. | L |
| **V9.4 ★** (#151) | **CLI completeness** — the 7 subcommands missing from `chm --help`, `create` first | **G7** | The app drives 19 of 24 commands; the CLI does not document 7 of its own. Nearly free. | S |
| **V9.5 ★** (#152) | **Snapshot lifecycle** — delete, GC, disk usage, rename | **G8** | Nothing reclaims a snapshot. Disk grows monotonically until someone finds the directory. | M |
| **V8.5** (#143) | **A first-run empty state that teaches** (image half; credentials half shipped in #147) | G9 | The discovery rejections already carry the vocabulary. | S |
| **V9.6 ★** (#154) | **Graceful stop + idle sleep that suspends** | **G18** | `--max-seconds` is a power cut on a writable disk. Should suspend to a checkpoint — which is V9.1's mechanism, reused. | S |
| **V9.7 ★** (#153) | **Containers → image** — build a bootable rootfs from an OCI image | **G6** | The half of "create local images" that does not exist. Turns the whole container ecosystem into sandbox images. | L |
| **V9.8 ★** (#156) | **Runtime-mutable egress policy** | **G17** | Change what a sandbox may reach without throwing away its work. | M |
| **V9.9 ★** (#155) | **Opt-in ingress** — reach a named port inside a sandbox | **G20** | An agent that starts a dev server cannot be reached. Must be per-port and opt-in or it undoes M30/M31. | M |
| **V9.10 ★** (in #150) | **Env + entrypoint at start** | **G22** | Cheap; V9.3 needs the fields anyway. | S |
| **V9.11 ★** (in #150) | **Named sizing tiers** | **G19** | Makes sizing a decision someone can be right about. | S |
| **V9.12 ★** (#157) | **MCP server surface** | **G21** | Depends on V9.2 and V9.3. An MCP tool call *is* "start from a spec" + "exec and report". | L |
| **V9.13 ★** | **Session record** — what the sandbox did, not just what left it | G13, G23 | We audit egress. We do not audit the session. | M |
| V3.x | Cloud round-trip: signed manifest, `pull → verify → run` | G14 | **Deliberately after the local ship.** Cross-repo. | — |

**The order is deliberate and one item is deliberately out of position.** V9.1
(continuous snapshots) sits above the cheaper wins because the research found it
is the capability the nearest comparable product does not have *at all* — their
sleep is a cold stop that discards the disk. Building the contract features
first would be competing on their ground with a later start.

---

## 1. The dream, and how much of it is true

> **A Cloud Hypervisor snapshot from the cloud is brought down and rehydrated on
> a Mac, where it runs as a secure local sandbox — and a coding agent works
> inside it.**

Four sentences, in dependency order. This is the honest score:

| | | |
| --- | --- | --- |
| **1. A vanilla cloud snapshot runs on a Mac.** | ✅ **true, hardware-proven** | Stock upstream, unforked, Graviton2-captured, **no flags and no environment variables**, through all three entry points (`chm run`, `chm serve`, the app). |
| **2. It is a *secure* sandbox.** | ✅ **true, and it is enforced rather than asserted** | 12 invariants, default-on posture, `chm posture` reports what is actually in force and exits non-zero if anything is weakened. |
| **3. It round-trips with the cloud.** | 🟡 **half true** | Cross-substrate mobility is proven (a cloud session resumed on HVF *past its marker*). The signed-manifest contract (V3) is not finished, and it is cross-repo. |
| **4. A coding agent works inside it.** | ✅ **true, hardware-proven 2026-08-03** | The **GitHub Copilot CLI installed, authenticated, and wrote and ran a JavaScript app** inside a Gimbal Local guest — and did it **holding no credential**, which was attached at the network edge. The route is the cold-booted guest V6.8 predicted would be immune: `npm` installs and runs with no SIGILL. Verified independently of the agent's own claim, and the real token's sha256 appears nowhere in the guest. §5 has the transcript. |

**What changed the shape of the plan:** V1–V4 were about making it *work*. That
part is done. What remains is making it a *product* — evidence for the parts we
built and now proved end-to-end (V5.1 ✅), an image worth running (V5.3 ✅), and
a UI that shows any of it (V6.1–V6.3, V6.5 ✅).

**And one thing changed the shape of the *architecture*.** Cold boot (V5.4/#101)
was planned as a convenience — a fresh sandbox without needing a capture. V6.8
made it **load-bearing**: it is now the only path on which a code-generating
workload is sound, which is to say the only path to sentence 4. Everything a
rehydrated capture inherits from its capture host, a cold-booted guest reads
from this Mac. **That prediction has now been tested rather than argued**: V7.1
ran on exactly that path and `npm` never faulted once.

**Three of the four sentences are now true and hardware-proven.** The one that
is not — round-tripping with the cloud — is the one that needs another team.

### The consequence nobody planned for: this thing can ship on its own

The dream sentence is about the cloud, and for a year that framed everything. But
add up what is actually true and a **second, smaller product falls out of it that
needs no cloud at all**:

- it cold-boots a stock Linux kernel into a real Ubuntu rootfs with disk, NIC and
  SMP, from files on this Mac (V5.4);
- that guest is a *secure* sandbox — 12 invariants, default-deny egress, a
  posture command that exits non-zero when anything is weakened (V4);
- credentials attach at the network edge, so the guest never holds one (V5.2);
- and a coding agent runs inside it and writes working code (V7.1) — **on the
  cold-boot path, with nothing captured anywhere**.

Every one of those was proved on hardware **without a control plane in the path**.
The cloud round-trip is the *bigger* product and still the destination; it is also
the only part gated on another team. Continuing to ship the local half behind it
would be holding a finished thing hostage to an unfinished one.

So **V8 is a deliberate decoupling**: make the local app a product that stands up
on its own, with the cloud as an additive feature rather than a load-bearing
dependency. It is not a retreat from the dream — the same binary, the same
engine, the same invariants — it is admitting that a working thing should be
allowed to ship. §5a has the detail.

| | | |
| --- | --- | --- |
| **5. It is useful with no cloud at all.** | ✅ **true, hardware-proven 2026-08-04** | Bring-your-own images cold-boot from the app with no snapshot, no KVM host and no control plane; local-only mode hides *and stops calling* the cloud half. V8.1–V8.3. |

---

## 2. What is actually blocking us — one place

Everything below is ordered by *what kind* of blocker it is, because they need
very different things from us.

### ✅ Blocker A (CLOSED 2026-07-31) — we had no capture with a NIC

It was the single highest-value gap in the plan, because it was the only one
where the code already existed and only the evidence was missing.

**Closed by the gimbal cloud round-2 capture.** `graviton-vanilla-2cpu-net`
rehydrates on Apple silicon with a working virtio-net NIC, and from inside that
guest `curl https://api.github.com/zen` returns `HTTP 200` and `git clone` over
HTTPS succeeds. The record of *why* this was hard is kept below, because the
constraint it describes is structural and still true — we consume captures, we
cannot make them.

The userspace NAT, the egress allow-list and the V5.2 credential proxy were all
built and all tested against the real internet *from the host side*, but **none
of them had ever met a real cloud capture**, because every capture we held was
taken with `net = None` — `ip -br link` inside a live rehydrated guest showed
loopback and nothing else. No `git clone`, no `npm install`, no API call.

**Why we cannot just make one on the Mac.** Cloud Hypervisor snapshots are
produced by Cloud Hypervisor running on Linux/KVM. The Mac is the *consumer* in
this architecture — deliberately, that is the entire product. Apple silicon
cannot run arm64 KVM, so it cannot manufacture the artifact it is designed to
receive. Something else has to produce it.

**What we actually need is not AWS.** It is *an arm64 Linux box with KVM that
can create a **VGICv3** device* — `/dev/kvm` alone is not enough, because the
capture path creates a VGICv3. Three ways to get one:

| Route | Effort | Status | Notes |
| --- | --- | --- | --- |
| **AWS Graviton bare-metal** | ~an afternoon, costs money per hour | **credentials already work** (`chm-aws` profile authenticates today) | Documented end to end in [`aws-byo-setup.md`](aws-byo-setup.md) — quota, bucket, security group, launch, capture, stop spending. |
| **Raspberry Pi 5** | one-off hardware, then free | plan written, untried | [`raspberry-pi-offbox-plan.md`](raspberry-pi-offbox-plan.md). **Pi 5 only** — Pi 4 commonly exposes GICv2 and would need a whole new VGICv2 ingest path. Proves "a physically separate Linux/KVM arm64 box", which de-risks the cloud milestone without retiring it. |
| **gimbal cloud runs it for us** | none of ours | the ask is written | [`graviton-capture-request.md`](graviton-capture-request.md) — rounds 1 and 2 delivered; **round 3 (the minimal agent image) is the live ask**. |

**Any of the three unblocks V5.1 and V1.6** — gimbal cloud is the one that
delivered. They were not alternatives in value, only in cost: AWS gives the most faithful artifact, the Pi gives the fastest
independent one.

### ✅ Blocker B — CLOSED 2026-07-30: the agent image is built and persisted

**Corrected 2026-07-30.** This was previously written as "the image is 74 % full,
so a toolchain does not fit". That was wrong, and testing it rather than
asserting it took about twenty minutes:

```console
# grow into the 4.5 GiB that was already inside the disk file
$ sudo sgdisk -e /dev/vda && sudo partx -u /dev/vda
$ sudo growpart /dev/vda 1 && sudo partx -u /dev/vda && sudo resize2fs /dev/vda1
/dev/vda1       6.8G  1.8G  5.0G  26% /        # was 2.4G / 633M / 74%

# install a real toolchain over the NIC V5.1 proved
$ sudo apt-get install -y --no-install-recommends build-essential
$ cc --version && printf 'int main(void){return 0;}' >/tmp/t.c && cc /tmp/t.c -o /tmp/t && /tmp/t
cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
BUILD_OK
```

The 4.5 GiB past the end of the GPT was usable all along — the backup GPT header
just had to be moved to the end of the device first, which is why `growpart`
refused. And `build-essential` fits in 633 MB even without growing (703 packages,
94 % full). **So building an agent image locally is not blocked by anything.**

**The real blocker was that the result could not be persisted**, and it was our
code rather than a cloud dependency. Checkpoint capture was hardcoded to
single-vCPU:

```rust
// chm/src/imp.rs
let want_capture = want_checkpoint && n == 1 && id == 0;
```

…and the two captures we hold split the requirements exactly wrong:

| Capture | vCPUs | NIC | Can install a toolchain | Can checkpoint |
| --- | --- | --- | --- | --- |
| `graviton-vanilla-1cpu` | 1 | ❌ | ❌ no network | ✅ |
| `graviton-vanilla-2cpu-net` | 2 | ✅ | ✅ **proved** | ❌ silently no-ops |

Neither did both. Two ways out were identified, and **V5.6 shipped the durable
one the same day**, so no capture round-trip was needed at all:

1. Ask for a `graviton-vanilla-1cpu-net` capture — one line on their side, no
   code on ours. Kept as a nice-to-have, **not** taken.
2. **Lift checkpoint capture to SMP (V5.6)** — the durable fix, because it
   unblocks fork/branch/push/rollback for every multi-vCPU sandbox rather than
   just this one. **This is what shipped.**

`--checkpoint` also used to **fail silently** on a multi-vCPU snapshot; a
refused checkpoint now says why and cold-boots.

**The result, measured on a rehydrated 2-vCPU guest:**

```console
$ cc --version | head -1
cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
$ git --version
git version 2.43.0
$ df -h / | tail -1
/dev/vda1       6.8G  2.2G  4.6G  33% /
$ printf 'int main(void){return 7;}' >/tmp/r.c && cc /tmp/r.c -o /tmp/r; /tmp/r; echo "RESUMED_BUILD=$?"
RESUMED_BUILD=7
```

That compile happened **after** the checkpoint was resumed, not before it was
taken — so the toolchain is genuinely part of the image, not a live session.

**One hazard this surfaced, now documented:** guest RAM is restored from the
snapshot on every run, so a run that writes to disk but does not end in a
checkpoint comes back with a kernel whose cached filesystem view no longer
matches the overlay — the files are there, and the resumed guest cannot see
them. RAM and disk have to be captured together, which is exactly what a
checkpoint does.

The minimal-rootfs capture (round 3, §9–§12) is still worth having — smaller,
reproducible from a manifest, far less attack surface — but it is an
**optimisation, not a prerequisite**. It is no longer what stands between us and
an agent sandbox.

**Side finding, now closed — and the cause was not the one it looked like:**
`apt-get update` rejected repository metadata with `Release file … is not valid
yet`, skipping `noble-updates` and `noble-security`. The obvious suspect was the
`0.197×` rate, but the symptom survived rate correction: the real cause was that
a restored guest woke believing it was the *instant of capture*, measured **5
hours stale**, so signed metadata published since then was genuinely in its
future. Fixed in V5.5 by advancing the counter over the elapsed wall time.
**After the fix, on the same capture, `apt-get update` fetched 37.7 MB with zero
errors.**

### 🟢 Blocker D (ROUTED AROUND 2026-08-03) — a rehydrated Graviton guest cannot JIT

The newest blocker, and the only one that is a property of the *capture host*
rather than of anything we build. `CTR_EL0.DIC` is set on Graviton2 and clear on
Apple silicon; Linux reads it **once at boot** and, when set, patches `ic ivau`
out of the routine behind `__sync_icache_dcache()` — the code that runs whenever
userspace makes a page executable. Those NOPs are baked into the kernel text
inside the snapshot, so **nothing can repair them at rehydrate time.**

Measured: the `mmap(RW) → write → mprotect(RX) → call` sequence every JIT
performs returns stale instructions **955 times in 1000**; the same test with an
explicit `ic ivau` is **0 in 1000**. `node --version` works, `npm --version`
dies with `Illegal instruction` about 2 runs in 15.

**Two ways out, and only one is ours:**

| Route | Ours? | Notes |
| --- | --- | --- |
| **Cold boot (V5.4/#101)** | ✅ **yes, and taken** | The kernel reads *this Mac's* `CTR_EL0`, sees `DIC = 0`, keeps its maintenance. Immune by construction. **Proven 2026-08-03**: `npm i -g @github/copilot` installed 3 packages on a cold-booted guest with no fault, and the Copilot CLI then ran. |
| A capture host reporting `DIC = 0` | ❌ theirs | Unknown whether Graviton3/4 do. Worth asking gimbal cloud, but we no longer depend on it. |

The blocker itself is **not fixed and cannot be** — a rehydrated Graviton guest
still cannot JIT soundly, which is why the guard stays. What changed is that the
capability it blocked no longer needs that path. `chm` warns at load,
`CHM_STRICT_ICACHE=1` refuses, and `chm posture` reports it. Full detail in §7c
and [`cpu-feature-deltas.md`](cpu-feature-deltas.md).

### 🟠 Blocker C — cross-repo, not ours to close

V3.1 and V3.3 need `gctl` changes. Our side of V3.1 is already corrected.

### ✅ Not blocked — we can start today

**Nothing on the critical path.** V5.4 finished with a real rootfs and V7.1 ran
on it, so every milestone that needed only us is shipped. What remains —
**V6.4 and V3** — is the off-box round-trip, and it needs the control plane.

The best local work now is ergonomics found while running V7.1 for real:
proxy-rule hosts should imply egress allowance (naming a host in a rule is an
explicit statement of intent, and requiring it twice fails closed but
confusingly), `chm proxy show --workspace` does not honour its own flag, and a
`--seconds` expiry should attempt a graceful shutdown rather than acting as a
power cut on a guest with a writable disk.

---

## 3. The spine

| | Milestone | Pillar | Status |
| --- | --- | --- | --- |
| **V1** | Make a real cloud snapshot run | ① | ✅ **complete** — acid test passed, clock fixed, CPU deltas audited |
| **V2** | Vanilla everywhere in the product | ①③ | ✅ **complete** — CLI, daemon and app all run vanilla, flagless |
| **V3** | Cloud control plane on the vanilla contract | ②④ | 🟠 partly blocked cross-repo (#21, #36) |
| **V4** | Security with sane defaults | ③ | ✅ **complete** — threat model, default posture, `chm posture` |
| **V5** | The coding-agent sandbox | ①③ | ✅ **complete** — V5.1, V5.2, V5.3, V5.5, V5.6 and now **V5.4** all shipped. Cold create-from-image boots a stock kernel with a real disk, NIC and SMP into a **real Ubuntu rootfs**, no snapshot and no KVM host in the path |
| **V6** | The app tells the whole truth | ③④ | 🟢 **V6.1, V6.2, V6.3 and V6.5 shipped** — security panel, credential-proxy UI, egress audit and capability honesty are all in the app. **V6.4 (off-box round-trip) remains**, and it is the one that needs the control plane |
| **V6.8** | Why a rehydrated guest cannot JIT | ① | ✅ **root-caused, guarded, documented** — and it is what makes V5.4 a prerequisite for V7 rather than a nicety |
| **V7** | The agent acceptance run | ①③ | ✅ **V7.1 done 2026-08-03** — the Copilot CLI installed, authenticated **holding no credential**, and wrote and ran a JS app, on a cold-booted guest. §5 has the transcript. Merged to main as `894e86f80` (#141) |
| **V8** | **A local app that ships on its own** | ①③ | 🟢 **V8.1, V8.2, V8.3 shipped 2026-08-04** — cold boot and BYO images from the app, and a local-only mode that actually stops calling a control plane. V8.4–V8.6 remain; none is blocked. §5a |

**Recommended order of attack — re-prioritised 2026-08-04 around shipping the
local app.** The previous ordering put V6.4/V3 at the top, which is correct by
*value* and wrong by *what we can do*: it is the one item gated on another team,
and everything behind it was finished. V8 is what unblocks a release.

1. ~~**V5.1**~~ — ✅ done. gimbal cloud delivered the capture; the guest reaches
   the real internet and clones from GitHub. Blocker A is closed.
2. ~~**V5.3**~~ — ✅ done, and it never needed the cloud. Built locally on the
   round-2 capture and persisted with V5.6 SMP checkpointing.
3. ~~**V6.1–V6.3**~~ — ✅ done. The local half of the UI needed nobody, and
   shipping it found nine instances of one bug class.
4. ~~**V5.4 — finish cold boot (rootfs)**~~ — ✅ done. Promoted to the top by
   V6.8: it was no longer "a fresh sandbox without a capture", it was *the only
   substrate on which an agent workload is sound*.
5. ~~**V7.1**~~ — ✅ done, on that cold-booted guest. See §5.
6. ~~**V8.1–V8.3**~~ — ✅ done. The app can now start a guest from files on this
   Mac, and local-only mode makes the cloud half genuinely optional.
7. **V8.4–V8.6 — finish the local MVP.** Persist settings, make the empty state
   teach, ship a build someone can run. **Top of the queue**; blocked on nobody.
8. **V6.4 / V3** — the off-box round-trip, once the contract lands. Still the
   larger prize, still the one thing that needs somebody else. Moving it below
   V8 is not a demotion — it is refusing to let it gate a finished product.

---

## 4. The vision it serves (V0)

The end state, shared with the control plane
([Gimbal Cloud](https://github.com/gimbal-dev/gimbal-cloud-control)), is four
capabilities:

1. **Run either side, restart either side.** Start a session in the cloud, resume
   it on the Mac *past the point it reached*, and back. Local vs remote is an
   implementation detail.
2. **Snapshots as a branching filesystem, with lazy rehydration.** Content-
   addressed revisions that fork/branch like git, and a resume that demand-faults
   only the working set instead of copying whole images.
3. **Consistent filesystem + network (firewall) policy.** A per-sandbox policy —
   what it can *reach* and what it can *touch* — authored once in the plane and
   enforced identically wherever the sandbox runs.
4. **Unified logging, insights & cost.** One place for what a session cost, did,
   and reached, regardless of where it ran.

**The one rule that ties it together:** the control plane (`gctl`) is the single
source of truth; `chm`-on-HVF (Mac) and cloud-hypervisor-on-KVM (cloud) are
**symmetric workers** speaking the same
[runner contract](https://github.com/gimbal-dev/gimbal-cloud-control/blob/main/docs/runner-contract.md).
A capability that only works on one substrate is not done.

### The line: what Gimbal Local owns

Gimbal Local owns everything on the Mac — the **app** (`app/GimbalLocal`), the
**engine + daemon** (`chm`, `hypervisor/src/hvf/`), and the thin **runner client**
that calls the plane when one exists. The control plane owns the server on the
far side of the runner contract: leases, cost, cleanup, snapshot provenance, the
`gic_mode` compatibility gate, and audit. The Mac is a *worker*, not a second
source of truth.

---

## 5. Milestone detail

### V1 · Make a real cloud snapshot run ✅

The milestone that proves the vision. **V1.5 passed on 2026-07-28** — see
[`graviton-acid-test-results.md`](graviton-acid-test-results.md). V1.1 was
answered as a side effect, and V1.3 — the hard problem — is now solved: **V1 is complete.**

| | Task | Status / blocked on |
| --- | --- | --- |
| V1.1 | Establish what `CNTFRQ_EL0` an HVF guest actually sees. | ✅ **Done.** No bare-metal payload needed after all: the guest's own dmesg in the RAM image states it. Mac/HVF = **24 000 000 Hz**; Graviton2 = **121 875 000 Hz**. Confirmed three independent ways (boot log, a measured 5.080× dilation vs 5.078125 predicted, and `CNTVCT`÷rate cross-checked against cloud-init's timestamps). |
| V1.2 | Guard the HVF rehydrate path against a frequency mismatch: parse the clock block, compare against the host, say so loudly. (#104) | ✅ **Done.** Ships on both the CLI and daemon paths. Warns by default and still runs — deliberately diverging from KVM, because a dilated guest is genuinely useful and refusing would mean no cloud snapshot ever starts on a Mac. `CHM_STRICT_CNTFRQ=1` opts in to the KVM rejection. A capture predating `69637dde6` carries no clock block, so the guard reports that it cannot verify rather than guessing. |
| V1.3 | **Fix the 5.08&times; dilation.** (#108) Apple exposes `hv_vcpu_set_vtimer_offset` — an *offset*, never a *rate* — but the offset is ours to move. Holding `CNTVCT_guest = base + (now - base_host) * guest_hz / host_hz` and re-stepping the offset onto that curve at every guest entry synthesizes the rate. `121875000/24000000` reduces to exactly `325/64`, so u128 integer math accumulates **zero drift**. Originally enabled explicitly with `CHM_GUEST_CNTFRQ=<Hz>`; on by default since V5.5, from the frequency the capture records. | ✅ **Done — measured 1.000&times;, down from 5.081&times;.** Guest `sleep 5` takes 5.00 s of host wall clock (was 25.40 s); three consecutive runs at 1.001 / 1.000 / 1.000. Boot-to-shell also halved, 2.19 s &rarr; 1.09 s. Instrument: `scripts/hvf/measure-clock-dilation.py`, validated by first reproducing the known 5.08&times; baseline. |
| V1.4 | Audit the rest of the bug class: MPIDR/affinity layout, `ID_AA64*` feature registers, cache topology, GIC `IIDR` — anywhere a guest probed the *capture* host and cached the answer. | ✅ **Done 2026-07-29 — and it found a new bug.** 238 captured registers replayed against a real HVF vCPU: 105 restored, 133 refused, 0 clamped. Every `ID_AA64*`/`MIDR`/`MPIDR` restores exactly, which is *why* a Graviton guest runs here at all. The bug is the inverse of the one we went looking for: `ID_AA64PFR0_EL1.EL0 = 2` (AArch32 at EL0) is restored **faithfully**, so the guest still believes it can run 32-bit binaries — and executing one **permanently wedges the vCPU**, verified against a control that the shell survives. Warned at load; `CHM_STRICT_AARCH32=1` refuses. Also: `CTR_EL0.DIC` differs in exactly one bit (latent, stressed without fault) and the `DC ZVA` block size is identical (hazard closed). Instrument: `chm sysregs`. Full report: [`cpu-feature-deltas.md`](cpu-feature-deltas.md). |
| V1.5 | **THE ACID TEST** — rehydrate a genuine vanilla Graviton capture (#105). | ✅ **PASSED 2026-07-28.** Three Graviton2 captures, all restored, all reached an interactive login shell, no code changes. |
| V1.6 | **Round 2 capture.** Round 1 exposed two bugs in our own request: it pinned `CH_VERSION=v52.0`, which predates the clock block entirely, and the captures fired mid-cloud-init so the guest restarts its getty ~113 s after resume. Both fixed in the request. | gimbal cloud |

The capture we need, precisely: [`graviton-capture-request.md`](graviton-capture-request.md).

### V2 · Vanilla everywhere in the product ✅

| | Task | Blocked on |
| --- | --- | --- |
| V2.1 | Wire the userspace GIC into `chm serve` (#102). Factor the ~525-line `run_usgic` engine so CLI and daemon share it, checkpoint/resume included. | ✅ **Done.** `run_usgic_engine(cfg, loaded, supervise)` is shared by both entry points. The daemon reaches an interactive shell on a vanilla Graviton capture (`ubuntu@ch-snap:~$`, `uname -a` → `6.8.0-136-generic aarch64`), Stop → Start round-trips live guest RAM (a bash variable set before the stop echoed back after it), and checkpoints interoperate in both directions with the CLI's. Adds a `chm ctl input` command, because the daemon's console was read-only and a resumed guest emits nothing until typed at. |
| V2.2 | The SwiftUI app opens, runs, stops and resumes a vanilla snapshot end to end. | ✅ **Done (#114).** Two things were in the way and both are fixed: the app's restorability gate still demanded `gicv2m-message-spi`, so it refused snapshots the runner would happily run (it now mirrors `hvf_restorable`, and separates "this Mac can restore it" from "the plane will release it"); and the console was read-only, which is fatal for a vanilla capture because it resumes at a login prompt and emits nothing until typed at. Input now goes through `chm ctl input`. **Hardware evidence:** from the app, no flags, no environment variables, against a vanilla ITS/LPI Graviton capture — logged in as `ubuntu`, `uname -m` → `aarch64`. Stop wrote a real checkpoint (1 GiB `memory-ranges`); resuming it came back already at `ubuntu@ch-snap:~$` with an in-RAM-only marker intact, so live state genuinely survives Stop → Start. |
| V2.3 | ~~Retire `CHM_USERSPACE_GIC=1`~~ **done as auto-routing.** Both `chm run` and `chm serve` ask `routes_completions_as_lpis()` and send ITS/LPI captures to the userspace GICv3 with no flag, so a vanilla Graviton snapshot reaches a shell with zero environment variables. Only bundles the managed GIC would have refused outright change path. **The three vestigial forcing mechanisms are now gone (#115):** `HvfVcpu::new` no longer reads the variable to seed `UserGic::enabled` (a library crate letting a process-global change per-vCPU interrupt semantics — a vCPU could have come up trapping ICC registers with no distributor behind them), and the runner no longer sets it on the child (belt-and-braces that would have hidden an auto-routing regression). It survives only as a genuine A/B override on `chm run`/`chm serve`. **Still open:** whether the userspace GIC should also take *GICv2M* captures, so there is one path rather than a routing decision. | V1.5 |

### V3 · Cloud control plane on the vanilla contract 🟠

| | Task | Blocked on |
| --- | --- | --- |
| V3.1 | `gctl` should stop gating on GIC mode entirely: as of V2.1 a vanilla ITS/LPI capture runs under **both** `chm run` and `chm serve`, so an `assign-run` 422 on `gic_mode: its-lpi` now refuses bundles we can run. Our side of the earlier confusion is corrected in `d8511789d`. | gctl |
| V3.2 | One-command `pull → verify → run`, fail-closed. | V3.3 |
| V3.3 | Signed snapshot manifest + verification, unified trust root (#36). | gctl |

### V4 · Security with sane defaults ✅

| | Task | Status |
| --- | --- | --- |
| V4.1 | Threat model + hardening checklist umbrella (#39). A rehydrated snapshot is untrusted code with a device model attached. | ✅ **Done.** [`security-model.md`](security-model.md) carries the threat model, invariants I1–I10 and the checklist; §1a now adds **the default posture** — what is true of a run with no flags, no env and no config — including a written argument for the two controls that are deliberately *not* default-on. Made executable as `chm posture`, which resolves the same sources the run path resolves, reports every control with how it was decided, and exits non-zero if anything is weakened. A checklist in a document says what we intended; a control you believe is on but is not is worse than one you know is off. |
| V4.2 | Make egress allow-list, reserved-address guard and CoW isolation the **default** posture with a documented opt-out (#20). | ✅ **Done.** Audited what was actually on out of the box rather than assuming: the reserved-address guard (I10) and CoW/overlay confinement (I2/I3) were already default-on, but **resource ceilings were not** — an unconfigured workspace resolved to *unbounded*. Now resolves to a `chm` baseline (≤64 vCPU, RAM ≤ host physical, overlay ≤64 GiB, console ≤1 GiB, ≤128 NAT sockets) with `CHM_LIMITS=none` as the documented opt-out. Verified the acid test still passes under the new ceilings. Egress stays open-to-the-internet by design — §1a argues why default-deny would be the worse security outcome. |

### V5 · The coding-agent sandbox — measured gap list **[the current thrust]**

V1–V4 deliver the sentence *"a vanilla Cloud Hypervisor snapshot from the cloud
just works on my Mac, safely."* That sentence is true. It is **not** the same as
*"a developer's coding agent runs in this sandbox"*, and the difference was
measured rather than assumed, inside a live rehydrated `graviton-1` guest on
2026-07-30:

| what a coding agent needs | measured | gap |
| --- | --- | --- |
| 64-bit userspace | `aarch64`, **2382 ELF binaries, 0 of them 32-bit**, no `armhf` multiarch | ✅ none — the V1.4 AArch32 wedge is effectively unreachable |
| **network** | `ip -br link` → **loopback only**, no routes; the capture config says `net = None` | 🔴 **blocker.** No `git clone`, no `npm install`, no API call. We *built* the userspace NAT and egress policy but have never run them against a real cloud capture |
| **CPU / RAM / disk** | 1 vCPU · 953 MiB · 2.4 GB disk, **74 % full, 634 MB free** | 🔴 **blocker.** A demo VM, not a build environment |
| **toolchain** | `git` ✅ `python3` ✅ `curl` ✅ — `gcc` `make` `node` `npm` `go` `cargo` **all missing** | 🟡 an *image* problem, not a hypervisor problem: needs a purpose-built agent image, not stock Ubuntu cloud |
| **developer's code in / out** | credential-injecting egress proxy (V5.2) | ✅ **answered without touching I1.** The repo does not need to be *passed in*: the sandbox authenticates and clones it. The credential is attached at the network edge and is never present in the guest, so a compromised job cannot carry one out. Remaining caveat: this covers *remote-call* secrets; a secret a local tool must actually read still has to live in the guest |
| **fresh sandbox from an image** | every start is a rehydrate | 🟡 #101 |

| | Task | Status |
| --- | --- | --- |
| V5.1 | **Capture with a NIC and 2+ vCPU**, and prove the NAT, the egress policy *and* the V5.2 credential proxy on a real cloud snapshot. | ✅ **Done — 2026-07-31.** gimbal cloud delivered round 2 (`graviton-vanilla-1cpu`, `graviton-vanilla-2cpu-net`; CH v54.0.0 @ `9ea9019d29af`, post-`69637dde6`, captured after cloud-init, `cntfrq: 121875000` recorded in **both** clock blocks). B rehydrated on Apple silicon with `ens3 UP 192.168.249.2/24`, `nproc`=2, virtio-net at `1af4:1041`. **From inside the guest: `curl https://api.github.com/zen` → `HTTP 200`, and `git clone` of a public repo over HTTPS succeeded.** The userspace NAT's DNS responder answers on the gateway. First cloud capture ever to make a network call here. Two real bugs found — see below. |
| V5.2 | **How a developer's repo enters the sandbox — answered, and shipped.** The decision was that this is a *credentials* problem, not a filesystem one: a sandbox that can authenticate to GitHub clones the repo itself, so I1 stands untouched. A TLS-terminating egress proxy attaches the credential as the request leaves for a rule-named destination; the guest never holds a secret. Proven live against api.github.com (200 with the rule, 401 without, identical request bytes) and against registry.npmjs.org. New invariant **I12**; `chm proxy show/ca/check`; [`credential-proxy.md`](credential-proxy.md). | ✅ done |
| V5.3 | **A purpose-built agent image.** ✅ **Done 2026-07-30, and it never needed the cloud.** Built locally on the round-2 NIC capture: grew the root partition (the 4.5 GiB past the GPT was usable once `sgdisk -e` moved the backup header) from 2.4 G/633 M free to **6.8 G/4.6 G free**, installed `build-essential` + `git` over the V5.1 NIC, and persisted the result with the SMP checkpointing from V5.6. Verified by resuming the checkpoint and compiling a *new* C program inside the rehydrated guest: `cc 13.3.0`, `git 2.43.0`, 703 packages, exit code 7 from a binary built after resume. A minimal reproducible rootfs ([`graviton-capture-request.md`](graviton-capture-request.md) §9–§12) is still wanted — smaller, manifest-built, less attack surface — but as an *optimisation*. | ✅ done |
| V5.5 | **SMP counter coherence.** Found by V5.1 — the first 2-vCPU capture we have ever held. The vtimer offset was **per-vCPU**, seeded on each vCPU's own thread at its own `mach_absolute_time()`, so the offsets differed permanently; rate correction then re-stepped each one on guest *entry*, at cadences that differ wildly between cores (**measured: cpu0 117,950 re-steps vs cpu1 521** — cpu1 sits in `WFI`). Linux treats `CNTVCT_EL0` as one system-wide clocksource, and `arch_sys_counter` is **56-bit**, so `clocksource_delta()` turns a read one tick behind into `2^56` ticks &asymp; **18.7 guest-years** forward — which is why bounded skew was never an acceptable target. **Measured in-guest with a pinned two-thread ping-pong that establishes strict happens-before between reads: 19,992 of 40,000 ordered samples went backwards uncorrected (guest `date`: July 2101), 19,996 of 40,000 corrected, max 128 ms backwards, RCU stalls, guest wedge.** Fixed by a VM-global `VtimerClock`: one offset shared by every vCPU, moved only by a stop-the-world barrier that abandons the step rather than publish under a running vCPU. | &#9989; **Done — 0 of 40,000 backwards on both paths, `sleep 20` = 20.01 s wall, uptime +20.02 s, correction now on by default at a measured 2.8% of wall time.** |
| V5.6 | **SMP checkpoint capture.** ✅ **Done 2026-07-30.** Capture was gated `n == 1 && id == 0`, so `--checkpoint` silently did nothing on a multi-vCPU guest — no suspend/resume, and no fork/branch/push/rollback, for any SMP sandbox. Each vCPU now captures itself on its owning thread and the orchestrator assembles one checkpoint and dumps RAM once. The blocking constraint turned out not to exist: the guest-RAM mappings are owned by `prepared` on the orchestrator thread and outlive the vCPU threads, so the dump never needed to happen on the boot CPU. `CheckpointState` gained a per-vCPU `usgic_cpus`, because `UsgicCheckpoint` mixes one VM-global distributor with three per-vCPU models — restoring vCPU 0's onto every core would have handed secondaries the boot CPU's PPI config and in-flight interrupts. | ✅ done |
| V5.4 | Cold create-from-image (#101) so a fresh sandbox does not require a pre-existing capture. | ✅ **a stock Ubuntu 6.8 arm64 kernel cold-boots to an interactive shell on HVF, 2026-08-03** — `chm create --kernel --initramfs`, no snapshot and no KVM host anywhere in the path; guest timekeeping measured at 3.00 s per 3 s. Found four more instances of the bug class plus the OS-lock trap. **Cold virtio landed 2026-08-03**: `--disk` and `--net` over a new virtio-mmio transport, verified against a stock kernel — sector-accurate disk reads, a guest write landing in the host file, and an HTTP 301 from api.github.com with port-specific egress denial. **SMP cold boot landed 2026-08-03**: `--cpus N` brings up secondary cores via PSCI `CPU_ON`, verified at 1/2/4 vCPU with user time, per-core timer PPIs and IPIs on every core. **Cold rootfs landed 2026-08-03**: a real 8 GiB Ubuntu 24.04 arm64 root on GPT, named by PARTUUID so the guest is not hostage to device probe order, plus a PL031 RTC so its clock is real and TLS works. V7.1 then ran the Copilot CLI on it. **Complete.** |

### V6 · The app tells the whole truth

**The problem, stated plainly: `chm` has 22 subcommands and the app drives 8.**
Everything we have built to make a local sandbox *trustworthy* — the security
posture, the egress audit trail, the credential proxy shipped in V5.2 — is
reachable only by someone who knows to type it. A person evaluating whether to
run untrusted code on their Mac cannot see any of it.

That is not a cosmetic gap. The pitch is "cloud snapshots run locally **in a
secure way**", and right now the app can only demonstrate the first half. A
control that nobody can see is, for most users, a control that does not exist.

The same is true of the **off-box** half. The dream — *bring a cloud snapshot
down and rehydrate it here* — is `chm pull`, and it is CLI-only. The app's Cloud
tab today counts what the control plane has (`runners`, `snapshots`,
`sandboxes`, running cost); it cannot *move* anything.

#### The audit

| `chm` capability | In the app? | Why it matters that it isn't |
| --- | --- | --- |
| `run` / `ctl` / `fork` / `revisions` / `rollback` / `branches` / `workspace` / `limits` / `firewall` / `runner` | ✅ yes | The local lifecycle is well covered. |
| **`posture`** | ✅ **yes (V6.1)** | 12 security invariants, including I12 shipped today. The single most important thing to surface, and the only place a user learns what is *weakened*. |
| **`proxy`** (`show` / `ca` / `check`) | ✅ **yes (V6.2)** | Rules, what is *not* intercepted, the CA the guest must trust, and a test button that runs a control. All four answered by the process that actually injects. |
| **`audit`** | ❌ **no** | What did this sandbox actually reach? Answering that in a UI is most of the value of having recorded it. |
| **`policy`** | ❌ **no** | `firewall` is wired but the control-plane egress policy behind it is not shown, so a governed session looks identical to an ungoverned one. |
| **`pull` / `push`** | ❌ **no** | *This is the dream, and it is CLI-only.* |
| **`cloud`** | 🟡 read-only | Counts and cost, no actions. |
| **`state-cdn`** | ❌ **no** | The off-box memory plane is invisible; there is no way to see whether a rehydrate streamed pages or read them locally. |
| `manifest` / `sysregs` / `serve` / `connect` | — | Diagnostics. CLI is the right home; a "copy diagnostics" affordance is enough. |

| | Task | Size |
| --- | --- | --- |
| V6.1 | **Security panel.** ✅ **Done 2026-07-31.** Every control rendered with its invariant, state and the sentence naming what weakened it; weakened rows sort first, are outlined orange, and the count shows in the sidebar so you do not have to navigate to see it. The milestone turned on a bug that would have made the panel actively harmful: posture resolves from the environment of whichever process computes it, and the app is not the process running the guest — attach to a daemon started with `CHM_ALLOW_LOCAL_EGRESS=1` and a naive panel shows green. Measured, on the shipped build: the app's own environment yields `weakened: 0`, the daemon yields `weakened: 1`. Fixed by adding a `posture-json` verb to the daemon (`chm ctl posture`) so it answers for itself; when it cannot, the panel falls back to a local read **and says so** in a banner rather than implying the two are interchangeable. | M |
| V6.2 | **Credential proxy UI.** ✅ **Done 2026-07-31.** Rules, their destinations, where each credential comes from (never its value), what is deliberately *not* intercepted, the CA the guest must trust, and a **test-this-rule** button that always runs the control. Measured through the UI: the same request returned `HTTP/1.1 401 Unauthorized` without injection and `HTTP/1.1 200 OK` with it — the guest sent nothing and the origin still authenticated it. Against `/` (an endpoint that answers the same either way) the same button says **“This run proved nothing”**, so it is capable of failing. The milestone was mostly a hunt for one bug class: an answer computed in the wrong process. It was found four times, each on hardware — see below. | M |
| V6.3 | **Egress + audit view.** ✅ **Done 2026-07-31.** The policy in force with its content hash, and a decision log — allowed, denied, injected, relayed — per sandbox. The milestone turned on the same bug class as V6.1–V6.2, twice: the durable trail **discarded every allowed event**, so it could only answer "what was blocked"; and the reader could only find a trail while the guest was still running, which is the one moment nobody is reading it. Measured on the 2-vCPU Graviton capture: two `curl` commands produced **19 distinct outbound flows**, eight of them to Ubuntu/Canonical services nobody asked for, two over plaintext HTTP. Under the old code that session's trail was a single line. | M |
| V6.4 | **Off-box round-trip.** `pull` a cloud snapshot and `push` a local one, with progress, from the Cloud tab. This is the dream expressed as a button. Includes surfacing `state-cdn` so a streamed rehydrate is legible as such. | L |
| V6.5 | **Capability honesty.** ✅ **Done 2026-08-03.** One place that states what this build can and cannot do — HVF backend, vanilla-snapshot support, the V5 gap list — so nobody has to infer it from whether a thing crashed. Every claim carries the grade of evidence behind it, because "we created a VM two seconds ago" and "someone wrote this down" are not the same sentence and must not look alike. Building it turned up a **ninth** instance of the bug class, and this one had been in the tree since the port began: `is_available()` answered a question about the machine with a compile-time constant. | S |

##### The four provenance bugs (V6.1–V6.2)

Credential availability, posture and the CA all resolve from **whichever process
computes them**. Three processes exist: the app, subprocesses it spawns (which
inherit its environment), and `chm serve` (which runs the guest, and may have
been started by anyone). Only the last one describes the sandbox. Each was
measured with both answers taken at the same moment:

| Surface | The app's answer | The daemon's answer | What the wrong answer would have caused |
| --- | --- | --- | --- |
| `posture` (V6.1) | `weakened: 0` | `weakened: 1` | A green security panel over a sandbox with local egress allowed. |
| `proxy show` | `credential: missing` | `present` | An alarm about the wrong environment — or, inverted, a green panel while every request leaves unauthenticated. |
| `proxy check` | `PASS-THROUGH`, 401 | `INJECT`, 200 vs 401 control | A test button that can never exercise the injection it exists to test. |
| `proxy ca` | `898b834b…` (library root) | `79f85a28…` (the running guest's workspace) | **The worst of the four.** Install the app's CA and the guest trusts a certificate nothing signs with — and because the installer compared what it wrote against the fingerprint it was handed, it would have reported success while every intercepted connection failed a certificate check. |

Each is fixed the same way: a daemon verb (`chm ctl posture` / `proxy` /
`proxy check` / `proxy ca`) that splices `source` and `assessed` into the body,
so one decoder handles both shapes. Where the daemon cannot be reached the panel
falls back to a local read **and says so**; the sidebar badge stays grey, because
an alarm sourced from the wrong process is worse than no alarm — it trains the
reader to ignore it.

A fifth instance of the same class was found in the guest, not the host: the CA
installer verified the certificate by re-reading **the file it had just
written**, which is true by construction. On a rehydrated Graviton guest
`update-ca-certificates` segfaults, the CA never reached `/etc/ssl/certs`, and
the script still printed matching fingerprints. It now verifies with `openssl
verify -CApath /etc/ssl/certs`, falls back to linking the hash by hand when the
helper is broken, and can print `NOT TRUSTED`. Measured after the fix on the
same guest: `trusted:` matched `expected:` and `openssl verify` exited 0 — via
the fallback, because the segfault is still there.

##### And a sixth, in the delivery rather than the answer

Clicking *Install CA in guest* for the first time — it had been shipped
untested — showed the correct script arriving and then doing nothing. The app
typed it one line at a time, 60 ms apart; `update-ca-certificates` takes
seconds, so the four verification lines behind it sat in the tty input queue,
were echoed, and never ran. The console showed the script's own text where its
output belonged, and the panel truthfully reported the script sent. No fixed
delay can fix that, because it would have to be as long as the slowest command
in the script and nothing knows what that is.

The script now crosses as base64 in short `printf` appends — nothing is ever
typed at a shell that is busy — and the guest hashes what it received against a
digest computed host-side **before running any of it**, so loss is named
(`TRANSFER CORRUPT`) at the moment it happens. That check also settled a
question the console could not: the captured lines come back with their leading
characters missing, which looks exactly like dropped input, but on the
successful run the digest matched — so every chunk had arrived byte-perfect and
the truncation is console rendering, not loss.

**Measured end to end on a live guest**, by clicking the button: `trusted:
45339c91c1785f8c63da3b8be0a10b5db1fe31c82e04d349c1b69a7397ef2372` equal to
`expected:`, equal to the fingerprint on the panel, equal to the CA the running
proxy signs with.

##### A seventh and an eighth, in what the record could answer (V6.3)

The durable trail was written only on refusal — `if !ev.allowed`. A sandbox that
reached two hundred permitted hosts produced an **empty file**, byte-identical
to one that never opened a socket. The two are opposite conclusions from the
same evidence, and the reassuring one is the one a reader reaches for, so the
record was not merely incomplete: it was misleading in the direction that
matters.

That is not hypothetical. The real trail left behind by the V5.1 session — the
one that fetched 37.7 MB with `apt-get` and cloned a repo from GitHub over
HTTPS — contains **three lines, all denials**. Read at face value it says the
sandbox barely touched the network.

Allows are now recorded, deduplicated per distinct flow so a retry loop cannot
flood the file, and capped at 512 distinct flows per session — with a
`truncated` flag, because an incomplete record that says so is usable and one
that silently stops is not. A per-session summary carries the exact totals,
which the deduplicated lines cannot: the measured run below logged **one**
denial and summarised **four**, so the guest had retried three times and the
log alone would have understated it.

The eighth was in the fix. The trail is durable precisely so it outlives the
process — and the moment a sandbox stops is exactly when someone sits down to
read what it did. But the daemon resolved "no VM running" to the library root,
which is not a workspace and can never hold a trail, so a stopped sandbox
reported `present: false` while 21 records sat in its directory. The panel would
have rendered "no trail recorded yet" over a full history. It now reports
`no-sandbox-in-scope` and names the sandboxes that *do* have one.

**Measured on hardware**, `graviton-2cpu-net` (the 2-vCPU NIC capture), two
`curl` commands issued at the guest console, both `200`:

| | |
| --- | --- |
| Flows recorded | **19 allowed, 1 denied** — 10 DNS, 10 TCP |
| Asked for by hand | 2 (`api.github.com`, `example.com`) |
| Unrequested | 8 — `changelogs.ubuntu.com`, `cdn.fwupd.org`, `contracts.canonical.com`, `motd.ubuntu.com`, `ntp.ubuntu.com`, `ports.ubuntu.com`, `livepatch.canonical.com`, `esm.ubuntu.com` |
| Plaintext | 2 connections on port 80 |
| Session summary | `allowed: 25 (19 distinct) · denied: 4 (1 distinct)` |
| Under the old code | **1 line** |

The panel refuses to round any of this off. A trail with no allow event renders
`Allowed` as **—**, never `0`, above a sentence saying the absence was never
recorded rather than never happened; a filter with no matches says so *about the
filter*; and repeated identical records stay separate rows, so three denials of
the same host at 11:58, 12:11 and 12:18 read as three attempts and not one.

**Ordering note.** V6.1–V6.3 are all local and can ship without a cloud
dependency. V6.4 needs the control plane, so it goes last.

##### A ninth, in the oldest line of the backend (V6.5)

The other eight were bugs written during this port. The ninth was there from
the first commit that created the HVF backend, and nothing had ever asked it a
question it could get wrong:

```rust
/// HVF is available on Apple Silicon Macs with the hypervisor entitlement.
pub fn is_available() -> Result<bool> { Ok(cfg!(target_os = "macos")) }
```

The doc comment describes a property of the running machine. The body is a
constant baked in at compile time. It never touched Hypervisor.framework, and
it returned `true` for an Intel Mac — there was no `target_arch` check — and,
far more often, for a binary that `hv_vm_create` would refuse outright with
`HV_DENIED`, because a plain `cargo build` in this repo strips the
`com.apple.security.hypervisor` entitlement. Every developer build in this tree
was a binary that HVF rejects and `is_available()` called available. It is not
dead code: `hypervisor::new()` picks the backend with it.

The distinction the fix draws is the whole milestone. `is_available()` now
answers only the question it can answer — *was this compiled for arm64 macOS* —
and says so. A new `probe_availability()` answers the other one the only way it
can be answered, by creating a VM and destroying it, and returns the decoded
`hv_return_t` when the answer is no.

Proving that gap is real took one binary and two files:

| | `codesign`ed by `scripts/build-chm.sh` | same build, `--remove-signature` |
| --- | --- | --- |
| `is_available()` | `true` | `true` |
| `probe_availability()` | ok | `HV_DENIED` |
| Panel says | `hvf: yes (probed)` | `hvf: no (probed)`, naming the fix |

Same source, same compiler, opposite truths — and only the probe can tell them
apart.

Two rules fell out of it and are enforced in `chm/src/capability.rs`. Every
claim carries an `Evidence` grade — `probed` (done just now) beats `observed`
(happening as you read this) beats `recorded` (read out of the capture) beats
`built` (compiled in) beats `documented` (a human asserted it, nothing checks
it) — because otherwise a written-down sentence borrows the credibility of the
probe sitting next to it. And a snapshot preflight may report only *"nothing I
checked refuses this"*; never *"supported"*, never *"will boot"*. Unchecked must
not round up to working.

The diagnostic must also not perturb what it measures. `hv_vm_create` is
process-global, so probing while a guest runs would contend with it: with a VM
up the panel reports `observed` and says why it did not probe; otherwise it
spawns a child. The child is the more honest test anyway, since the entitlement
lives on the **file**, not in the asking process's memory.

**Measured on hardware**, against `graviton-2cpu-net` — the real 2-vCPU
Graviton2 capture:

| | |
| --- | --- |
| Preflight | 8 checks, none refuse it; **1 will not run as captured** |
| The one | `121875000 Hz` captured against this host's `24000000 Hz` — ratio `325/64`, a 5.08× dilation, reported `degraded` rather than passed |
| Truncate `memory-ranges` by 700 MB | `no`, *"short by 700 MiB"*, exit 1 |
| A v52.0 capture (no `clock` block) | `unknown` — names commit `69637dde6` and the dilation it cannot rule out |
| Panel, no snapshot | 2 measured, 4 written down, of 9 claims |

The last two rows are the point. A capture that predates the counter-frequency
commit cannot say what rate it ran at, so the honest verdict is `unknown` and
not a pass — and the truncated capture is refused *before* anything is opened,
which the runner also does, but only after side effects.

One claim in the module was wrong when first written, and it was a claim about
not overclaiming: the truncation finding said resuming would hand the guest
zeroes for its own memory. Tested, the runner refuses it too. The text now says
what was measured — the preflight says it first, and without side effects.

### V7 · The acceptance test — a real agent doing real work

**One test, end to end, with nothing stubbed:**

> Start an image. Install the Copilot CLI inside it. Give it a GitHub
> credential **through the proxy, so the credential never enters the guest**.
> Then have the Copilot CLI write a hello-world JavaScript app — and run it.

This is the whole thesis in a single run, and it is deliberately the *last*
milestone because it is the only one that cannot be passed by any individual
piece working. Every layer has to hold simultaneously:

| What it proves | Layer under test |
| --- | --- |
| The guest boots, stays up, and its clock is sane enough for TLS and `npm` | V1/V2 rehydration, V5.5 clock coherence |
| `npm i -g @github/copilot` completes | egress, DNS, NAT, sustained throughput |
| The CLI authenticates to GitHub | **V5.2 credential proxy** — and `chm proxy check` must show the credential was *injected at the edge*, never present in the guest |
| The CLI reaches the model endpoint and streams | long-lived TLS through the proxy, no MITM breakage |
| `node hello.js` prints | the toolchain actually runs — the AArch32 caveat does not bite a 64-bit Node |
| Nothing was weakened to make it work | `chm ctl posture` before **and after**, both clean |

**The acceptance bar is deliberately hostile to a nice demo:**

1. **No credential in the guest.** Grep the guest's environment, shell history,
   `~/.config`, and process table for the token. Zero hits, or the milestone
   fails. This is the V5.2 claim and it is worth nothing unless it is checked
   adversarially.
2. **Posture clean throughout.** If it only works with
   `CHM_ALLOW_LOCAL_EGRESS=1`, it did not work.
3. **The JS app must execute**, not merely be written. A file on disk proves
   the model replied; a printed line proves the sandbox is a working computer.
4. **Transcript recorded** — every proxy decision (`allowed` / `denied` /
   `injected`) for the whole run, so the claim is auditable rather than
   asserted.

| | Task | Size |
| --- | --- | --- |
| V7.1 | **Agent acceptance run.** The scenario above, start to finish, on real hardware, with the adversarial checks above and a recorded transcript. | ✅ **done 2026-08-03** |

**Achieved 2026-08-03, on a cold-booted guest** — no snapshot, no KVM host,
nothing captured anywhere in the path. The measured run:

- `npm i -g @github/copilot` → `added 3 packages in 12s`. **No SIGILL**: a cold
  guest reads this Mac's own `CTR_EL0`, sees `DIC = 0` and keeps its `ic ivau`,
  so it is immune to V6.8 by construction. The prediction held.
- **GitHub Copilot CLI 1.0.77** installed and answering.
- The CLI wrote `hello.js` and ran it → **`COLD BOOT HVF`**.
- Verified independently of the agent's own claim: `cat` showed
  `console.log("COLD BOOT HVF");`, and a separate `node ~/hello/hello.js`
  printed the same. The JavaScript really executes.
- **The guest never held a credential.** It was attached at the network edge by
  the V5.2 proxy, and `curl https://api.github.com/user` from inside returned
  200 with no token present.
- `chm posture` reported *"No control is weakened from its default"*, exit 0.

**Adversarial check, done by hashing rather than reading.** The real token was
sha256'd host-side, the guest hashed every token-shaped string on its filesystem
and in its environment, and the two lists were compared — so nothing was ever
printed. **The real token's hash appears nowhere.** Exactly two token-shaped
strings exist in the guest: our own placeholder (in `.bash_history`, where we
typed it), and a string-table fragment inside the Copilot CLI's own prebuilt
`runtime.node`, which is a token-*prefix* table and not a credential.

Three real defects had to be closed to get here, and all three are worth more
than the milestone: a missing PL031 RTC (TLS cannot work if the clock is a
kernel build constant), a lost virtio kick racing the re-arm (§10a), and the
discovery that credential injection must cover the Copilot API hosts and not
just the `api.github.com` token exchange.

**Depends on:** V6.2 (the CA install into the guest is the fiddliest step and
should be a button before it is a test), M32.1 (agent workload readiness), and
ideally V5.4/#101 so the run can start from a *cold* image rather than a cloud
capture. It does **not** depend on the cloud control plane.

---


---

## 5a. V8 · A local app that ships on its own

**Why this track exists.** Every capability the local app needs is finished and
hardware-proven; the only unfinished part of the dream is the cloud round-trip,
and it is the only part that needs another team. V8 decouples the two so the
local half can ship. The engine, the invariants and the binary are unchanged —
what changes is that the control plane becomes **additive rather than
load-bearing**.

### V8.1 · Cold boot from the app ✅ (2026-08-04)

**#101, finally, from the UI.** Before this, every sandbox in the app began with
something captured on a KVM host: a library snapshot, or a bundle brought down
from a control plane. `chm create` — the cold-boot path V5.4 built — was
CLI-only, so the app's most basic capability, *start a Linux guest*, depended on
infrastructure the user may not have. `New sandbox` now offers **Cold boot from a
local image** alongside the snapshot list.

**The design question, and why the obvious answer was wrong.** The instinct was
to add a cold-create route to the daemon, and that is a substantial refactor:
`serve.rs::scan_library` only recognises directories holding a `state.json`,
`start_vm` starts a library entry *by name*, and `create.rs::run` is one 437-line
function that owns console I/O. But the app **already** runs guests as
subprocesses — `chm connect` in a Terminal.app window — and that is not a legacy
wart, it is correct: `hv_vm_create` is process-global, so **one HVF VM per
process** is a platform constraint, and the daemon owns a single VM slot. Routing
cold boots through the daemon would have serialised them behind whatever it was
already running, for a much larger diff. The subprocess is the right shape.

So V8.1 is a second command builder beside the audited connect one, under the
same invariant I5 discipline: every interpolated value single-quoted, every path
screened for control characters, egress hosts screened by shape as a second
layer.

**Verified on hardware, running the command the app's own builder emitted** — not
a hand-written approximation:

```console
chm create: 2 vCPU, 2048 MiB, kernel ~/gimbal-images/ubuntu-cold/Image
  virtio-blk  0x0010000000..0x0010000200  (SPI 35)
  built in   30.9 ms
[    0.685821] EXT4-fs (vda1): mounted filesystem … r/w with ordered data mode
[    0.690764] Run /sbin/init as init process
ubuntu@ch-snap:~$ V81_MARK=aarch64/2/ch-snap
ubuntu@ch-snap:~$ byo cold boot
67108864 bytes (67 MB, 64 MiB) copied, 0.233179 s, 288 MB/s
V81_RTC=2026-08-03T20:07:55      # host 21:08:28 BST — correct, no intervention
V81_DONE=0
```

No snapshot, no KVM host, no control plane anywhere in that path.

### V8.2 · Local-only mode ✅ (2026-08-04)

A switch that hides the Cloud sidebar section, the control-plane status dot and
the Control plane settings tab. **Off by default** — hiding a feature you have is
worse than showing one you have not set up yet.

Two decisions that are the actual content of this milestone:

1. **It stops the app *reaching* for a control plane, not just displaying one.**
   `refreshAll` would otherwise have kept polling every cycle for state nobody
   can see. A user who says "local only" is making a statement about network
   behaviour, and a toggle that only rearranges pixels would be a cosmetic lie.
   Stale cloud state is cleared on the way, and the offline reason names the
   cause (`local-only mode`) rather than implying a network fault.
2. **The switch is not on the Control plane tab.** That was the obvious home for
   it and it is a trap: enabling it would hide the pane holding the switch that
   turns it off. It lives on a new always-visible General tab.

Turning it on while the Cloud page is selected also moves the selection, or the
detail pane strands on a page the sidebar can no longer reach.

### V8.3 · Bring-your-own images ✅ (2026-08-04)

A settings path pointing at a directory of images. Each subdirectory holds an
uncompressed arm64 `Image`, optionally an initramfs and raw disks, optionally an
`image.json` naming them. A manifest beats convention — someone who wrote one
meant it — but a manifest naming a file that is not present is an **error**, not
a silent fallback, or a typo would quietly boot the wrong disk.

**The refusals are the feature.** An image directory the app cannot use says why,
in terms that name the remedy:

| Refused | Reason given |
| --- | --- |
| `vmlinuz`, `Image.gz`, `zImage` | gzip-compressed; cold boot needs an uncompressed arm64 Image (gunzip it first) |
| a disk that is a **symlink** | disks are opened no-follow, so a link cannot redirect guest writes onto a host file — use `cp -c` (an APFS clone is instant and costs no space) |
| a manifest naming a missing file | named in `image.json` but not in the directory |
| no kernel at all | expected an `Image`, or an `image.json` naming one |

**The symlink rule was found by using it, not by reading the code.** The first
real cold boot died 25 seconds in with `Too many levels of symbolic links`, which
reads like a broken image. It is not: `FileBackend::open` uses
`open_rw_create_nofollow` **on purpose** (M30.1 — a bundle must not be able to
substitute a symlink for a disk and redirect guest writes onto a host file). The
app therefore **does not resolve the link itself**; laundering it in the UI would
defeat the control everywhere it applies. It names it at discovery time instead.
A symlinked *kernel* stays accepted, because the rule does not apply there — and
the verified boot above used one.

### Still open in V8 — none of it blocked

**V8.4 shipped 2026-08-04** (#147): `SettingsStore` persists `AppSettings`, a
saved path is validated on load rather than trusted, and unknown keys survive a
downgrade. The credentials half of V8.5 shipped alongside it — an empty state
that teaches the model in three steps, and a rule builder whose `Source` type
has **no case that carries a value**, so there is no field a token can be typed
into. Save is gated on a real `chm` verdict, never on the app's own validation.

| | Milestone | Why | Size |
| --- | --- | --- | --- |
| **V8.5** (#143) | **An empty state that teaches** — *image half only* | The credentials half is done. A first-run user with no images still sees an empty list; the discovery rejections already carry the vocabulary. | S |
| **V8.6** (#144) | **A build someone else can run** | Everything is verified against `target/debug/chm` in a git checkout with a re-sign step. A local MVP means a signed `.app` that finds its own `chm`, and an honest statement of what it needs (HVF entitlement, an image). **[§0a](#0a-how-milestones-ladder-into-the-goals) ranks this the one true blocker on the word "ship".** | M |
| **V8.7** (#145) | **Proxy rules should imply egress allowance** | Naming a host in a credential-injection rule *is* the intent to reach it; requiring it again in `--egress-allow` fails closed but confusingly. Found by using V7.1 in anger. `create.rs:822`. | S |

**V9 is the track that follows** — see
[§0a](#0a-how-milestones-ladder-into-the-goals). It exists because the
2026-08-04 goal re-baseline found two things V8 was never scoped to cover:
nothing snapshots on its own (so there is no timeline to travel along), and
there is no way to run a command in a running sandbox and learn whether it
worked.


## 6. Shipped & proven — how we got here

The port was built as a long series of hardware-proven milestones (`M1`–`M24`),
then the cloud-integration work that followed. Grouped by theme:

### The merged ledger, V1 → V8 (PRs #88–#146)

Reconciled 2026-08-04 across git history, merged PRs, the session plan and the
issue tracker, so the record is what *shipped* rather than what was planned.

| PR | Landed | What it actually changed |
| --- | --- | --- |
| #89, #90 | 07-23 | Userspace GIC: SMP resume with cross-core IPIs; VM-global distributor + SPI affinity routing. |
| #91 | 07-23 | NAT accepts the guest's offloaded checksums, so external egress works at all. |
| #92 | 07-27 | M28.4 allow-list egress demo + policy-digest teleport. |
| #93, #96, #97, #100 | 07-27 | The performance pass the Docker benchmark forced: I/O bottlenecks, receive coalescing + NAT off the vCPU thread (1.62×), RAM populated off the critical path, startup latency instrumented **and then fixed by what the instrument found**. |
| #103, #106 | 07-28 | The correction that reshaped everything: **vanilla is the supported capture shape**, and a replan on a vanilla-first spine. |
| #107 | 07-28 | **The Graviton acid test passed** — and exposed the 5.08× clock dilation. |
| #109, #111 | 07-28 | Roadmap trued up; stop silently keeping a stale overlay bitmap over a truncated overlay. |
| #112 | 07-28 | **The 5.08× dilation fixed** (`325/64` reduces exactly, so u128 math drifts zero) and the rootfs corruption it caused. |
| #113, #114 | 07-28/29 | Vanilla runs from the **daemon** (#102), then from the **app** — flagless on both. Sentence 1 of the dream became true through all three entry points. |
| #115, #116 | 07-29 | Retired three vestigial userspace-GIC forcing mechanisms — including a *library* crate letting a process-global env var change per-vCPU interrupt semantics. |
| #117 | 07-29 | V1.4 CPU feature delta audit (`chm sysregs`), V4.1 threat model, V4.2 secure defaults, `chm posture`. Found the **inverse** bug it went looking for: `ID_AA64PFR0_EL1` restores *perfectly*, so a 32-bit binary permanently wedges the vCPU. |
| #118, #120 | 07-30 | Measured the coding-agent gap rather than assuming it; re-laid the roadmap around what actually blocks. |
| #119 | 07-30 | **V5.2 — credentials at the network edge.** The guest never holds one. `200` with a rule, `401` without, against production `api.github.com`. |
| #123 | 07-30 | **V5.1 — Blocker A closed.** First capture with a NIC and 2 vCPU; `curl https://api.github.com/zen` → 200 and `git clone` from inside a rehydrated Graviton guest. |
| #124, #125, #128 | 07-30 | Capture request round 3; **corrected Blocker B** — the agent image was never blocked on the cloud, and testing that took ~20 minutes. |
| #126 | 07-30 | **V5.6 — multi-vCPU checkpoints.** `--checkpoint` had been *silently doing nothing* on SMP guests. The constraint that made it look hard did not exist. |
| #127 | 07-30 | **V5.5 — a coherent, current guest clock.** Two independent bugs; 19,992/40,000 backwards `CNTVCT_EL0` reads → **0/40,000**. |
| #129–#132 | 07-31/08-03 | **V6.1, V6.2, V6.3, V6.5** — the local half of the UI: security panel, credential-proxy UI, egress audit, and capability honesty (every claim carries its evidence). |
| #133, #134 | 08-03 | **`arch` builds on macOS** — the blocker #101 named — then a **stock Linux kernel cold-boots on HVF**. |
| #135, #137 | 08-03 | A cold-booted guest gets a real disk and a real NIC; then more than one vCPU. |
| #138 | 08-03 | Retired the managed-GIC runtime path. One interrupt backend. |
| #139 | 08-03 | **V6.7** — refuse to resume a checkpoint whose disk moved on. The failure that cost a day: a wedged kernel gets captured over the last good checkpoint, so every later resume starts wedged. |
| #140 | 08-03 | **V6.8** — why `npm` dies on a rehydrated Graviton guest. `CTR_EL0.DIC`, filed one severity too low by V1.4. 955/1000 stale → 0/1000. Makes cold boot a **prerequisite**, not a nicety. |
| #141 | 08-03 | **V7.1 — the final smoke test.** Copilot CLI installed, authenticated holding no credential, wrote and ran a JS app on a cold-booted guest. Merged `894e86f80`. Carried the **lost virtio kick** fix, which refuted `overlay-extent-writes` after it survived six clean A/B tests. |
| #146 | 08-04 | **V8.1–V8.3** — cold boot and BYO images from the app; local-only mode that actually stops calling a control plane; and `chm proxy show --workspace` fixed (it silently ate its own flag's value). |

**What this ledger is for.** Two milestones in it were *wrong when written* and
only corrected by measuring — Blocker B ("the image does not fit": it did) and
`overlay-extent-writes` (six clean A/B tests, still false). Keeping the record of
what changed our minds is the point; a ledger of only the wins would teach
nothing.


### The in-tree HVF port — hardware-proven

| Area | Milestones | Result |
| --- | --- | --- |
| CPU & backend | M1, M3, M20 | Real in-tree HVF backend; KVM→HVF register/system-register translation; SMP resume runs every vCPU of a multi-core snapshot concurrently. |
| Interrupts & GIC | M2, M10–M14 | Host→guest interrupt delivery; a user-space ITS translation engine; message-based SPI (GICv2M) delivery, with live virtio completion routed as message-SPIs. |
| Devices | M5, M17, M18 | PL011 serial console (interactive login), virtio-blk with copy-on-write overlays, and virtio-net with a real host datapath. |
| Snapshots | M15, M16 | A real SPI-routed cloud snapshot rehydrates on HVF and services real virtio I/O, resuming a settled guest to a usable login prompt. |
| Guard rails | M13, M19 | A load-time guard rejects ITS/LPI snapshots the managed GIC cannot deliver (boundary **R1**). The managed GIC limit is real, but a userspace-GICv3 path that *can* deliver LPIs is now proven (M-USGIC / #81), so R1 is a current-default, not a permanent platform limit. |

### Tooling & app

| Milestone | Result |
| --- | --- |
| M7, M8 | The standalone `chm` binary and the `chm serve` daemon + `chm ctl` client (machine-readable local state). |
| M22 | The bring-your-own-AWS capture loop (`chm cloud …`) — local-managed slice. |
| M23 | **Gimbal Local**, the native SwiftUI desktop app over `chm serve`/`ctl`. |

### Live local lifecycle primitives (M25) ✅

- **Suspend / resume** — `chm resume` restores a live checkpoint; a suspend
  captures a memory + device + fs checkpoint on idle and on graceful stop
  (checkpoint-everywhere).
- **Fork lineage** — `chm fork` branches a revision (Image → Revision → Sandbox,
  where *suspend = commit* and *fork = branch*); see
  [`gimbal-local-fork-model.md`](gimbal-local-fork-model.md).
- **Revision store + rollback** — `.chm-revisions/` keeps the lineage (RAM-pruned
  to the newest N); `chm revisions` / `chm rollback`, surfaced as a Revision
  history card in the app.
- **Per-sandbox workspaces** — `chm workspace <image> <ws>` shares an image's
  read-only base but isolates each sandbox's overlays + checkpoints.

### The control-plane runner + M26 — faithful cloud rehydration ✅

`chm runner` makes the Mac a **runner** for the plane, and milestone **M26
(complete)** delivers the whole cloud→local loop:

| # | What | Status |
| --- | --- | --- |
| #15 | Cloud Snapshots tab — browse the plane, bring one down | ✅ |
| #16 | Unified local/cloud sandboxes (origin is an implementation detail) | ✅ |
| #17 | Runner fetches from a `file://` **or** `http(s)://` object store | ✅ |
| #3 | Provenance surfaced + content-addressed cache dedup | ✅ |
| #18 | Real-snapshot fidelity on HVF — booted Ubuntu 24.04 | ✅ **proven** |
| #19 | **Cross-substrate session mobility (the hero loop)** | ✅ **proven** |

The headline proof (**Pillar ①**): a session that ran on `linux-kvm` in the
cloud, was checkpointed, and **resumed on `apple-hvf` past its mid-flight
marker** — booting to an interactive login prompt, with the 1 GiB RAM + 8 GiB
disk + device/vCPU state restored, the `gic_mode` gate re-verified locally, and
the runner cache deduping repeat pulls content-addressed (a 9 GB re-pull served
from cache in 0.077 s).

---

### Why a vanilla capture runs here at all

The **userspace GICv3** (M-USGIC): a software distributor / redistributor / ITS
and a trapped CPU interface, delivering the LPIs Apple's managed GIC cannot,
while HVF still executes the vCPUs. It is a real interrupt controller, not a
compatibility shim. Both `chm run` and `chm serve` ask
`routes_completions_as_lpis()` and route ITS/LPI captures to it **with no flag**.

Locally captured fixtures additionally demonstrate virtio disk, virtio net + NAT
egress, SMP and checkpoint/resume, at **247 ms** start-to-ready against Docker
Sandbox's **12.73 s** on the same host.

### The three problems that blocked the crossing — all closed

1. ~~**We have never rehydrated a real cloud snapshot.**~~ **Done, 2026-07-28.**
   Three vanilla Graviton2 captures restored and ran an interactive shell. Full
   evidence in [`graviton-acid-test-results.md`](graviton-acid-test-results.md).
2. ~~**The guest's clock runs 5.08× slow across the cloud→Mac boundary** (#104,
   #108).~~ **Fixed, and measured at 1.000×.** Graviton2 presents `CNTFRQ_EL0 =
   121 875 000 Hz` against Apple silicon's `24 000 000 Hz`, and a Linux guest
   caches the rate at boot. Apple exposes a vtimer *offset*, never a *rate* — but
   the offset is ours to move, so re-stepping it onto `base + (now - base_host) ×
   guest_hz / host_hz` at every guest entry synthesizes the rate. `325/64`
   reduces exactly, so u128 math drifts zero.
3. ~~**`chm serve` rejects vanilla** (#102).~~ **Fixed in V2.1**, and V2.2 took
   it the rest of the way into the app.

---

## 7. Deferred, deliberately


- **#101 · cold create-from-image.** Every start is a full snapshot rehydrate.
  Reframed from a perf problem to a capability/onboarding gap — warm resume is
  247 ms and a cold path would be slower. **Foundation landed 2026-08-03; the
  blocker it was waiting on turned out not to exist** — see below.
- **`GITS_*` MMIO.** Not exercised on the resume path; a guest that re-programs
  its ITS *while running* is untested. No fixture does this.
- **memfd page-sharing (#4/M25 perf ceiling), postcopy (#5), fork/wake-on-traffic (#6).**

#### A tenth, in this document (#101)

The other nine instances of the bug class were in code. The tenth was here, in
the plan, and it had stopped work for a month.

This roadmap recorded that cold boot needed a port of `arch` — a 1325-line
aarch64 FDT generator — because *"the arch crate does not build on macOS at
all"*. The measurement behind that was real: `--no-default-features` gave 9
errors, `--features kvm` gave 48. Both numbers were correct and neither was the
question. With no features, `hypervisor` compiles with no backend at all, so its
enums are empty and every `match` on them is non-exhaustive; with `kvm`,
`kvm-ioctls` cannot build on macOS by construction. Nobody had tried
`--features hypervisor/hvf,hypervisor/kvm-snapshot` — the combination in this
repo's own Makefile:

| Command | Errors |
| --- | --- |
| `cargo build -p arch --no-default-features` | 10 |
| `cargo build -p arch --features kvm` | 48 (in `kvm-ioctls`) |
| `cargo build -p arch --features hypervisor/hvf,hypervisor/kvm-snapshot` | **0** |

`arch` builds on macOS, its tests pass, and `linux-loader` builds clean too. The
port that was blocking #101 was never needed.

It rotted because nothing built it. `make clippy` covered `chm` and
`hypervisor`; `arch` was in neither, so it could break — or, as it turned out,
quietly work — without anyone finding out. It is in the lint and test gates now.

The same audit found `make test-hvf` ended at `--no-run`: it built 30 HVF
integration tests and ran none of them. A gate that cannot fail is not a gate.
It now signs the test binary (every `cargo build` strips the entitlement, so an
unsigned run fails all 27 with `HV_DENIED`, which reads like a broken backend
and is not) and runs it with `--test-threads=1`, because `hv_vm_create` is
process-global and a concurrent second VM returns `HV_BUSY`. **27 pass.**

##### What actually landed

`arch` gained an `hvf` feature, so the incantation is one flag. The userspace
GIC had no `Vgic` impl — the trait the FDT writer needs to describe an interrupt
controller — because a rehydrated guest arrives with a device tree already in
its RAM and nothing on this side had ever had to write one. `ColdBootGic` is
that description: the canonical arm64 GIC window, distributor at the top and
redistributors growing *downward*, which is what the kernel expects and the
opposite of the ordering the managed GIC forces on the rehydrate path.

It deliberately does **not** implement the save/restore half of `Vgic`. It holds
no interrupt state — that lives in `softgic` — so `state()` and
`save_data_tables()` return errors naming where the state really is. The
tempting empty-`Ok` would produce a snapshot that restores cleanly with every
pending interrupt missing.

Writing those errors surfaced one more instance in miniature: wrapping the
explanation in the existing `GicError::CreateGic` variant *discarded* it at the
display boundary, so a caller would have been told `Failed creating GIC device`
when nothing was being created. Hence `GicError::Unsupported(String)`, which
renders its own text.

**Measured**, on this Mac, in `arch/tests/cold_boot_fdt.rs` — a real device tree
built and then read back with an independent parser rather than the writer that
produced it:

| | |
| --- | --- |
| FDT magic + header `totalsize` | valid, matches the blob |
| `/intc` | `arm,gic-v3`, dist `0x08ff_0000`+`0x1_0000`, redist `0x08fb_0000`+`0x4_0000` — exactly what `ColdBootGic` reports |
| `/cpus` | `cpu@0`, `cpu@1`, `enable-method = "psci"` |
| `/memory@40000000` | base and size as allocated |
| `/pl011@9000000` | the console a cold guest would print to |
| `/timer`, `/psci`, `/apb-pclk` | `arm,armv8-timer`, `arm,psci-0.2`/`hvc`, 24 MHz |
| Tree size, 1–32 vCPUs | inside `FDT_MAX_SIZE` |

More of the boot path already existed than the plan assumed: `setup_regs`
implements the Linux/PSCI protocol (`PC` = entry, `x0` = FDT, EL1h/DAIF), the
`EC_HVC64` exit handles PSCI, and `Pl011` is implemented. What remains for a
kernel that actually boots is wiring, not a port: load an arm64 `Image` into
guest RAM, write the tree at `FDT_START`, construct virtio devices cold rather
than from captured state, and add the `create` verb.

#### The wiring, and what booting a real kernel found (#101, 2026-08-03)

`chm create --kernel <Image> --initramfs <cpio.gz>` boots a **stock Ubuntu
6.8.0-31-generic arm64 kernel** on Hypervisor.framework to an interactive shell.
No snapshot, no KVM host, no capture — the kernel came off `ports.ubuntu.com`.

```
uname -a   : Linux (none) 6.8.0-31-generic ... aarch64 GNU/Linux
clocksource: arch_sys_counter
 11:  95  GICv3  27 Level   arch_timer
 13:   0  GICv3  33 Edge    uart-pl011
uptime delta over a 3s sleep: 0.09 -> 3.09
```

That last line is the one worth reading twice: 3.00 s of guest time for 3 s of
wall clock, from a guest reading Apple's own `CNTFRQ_EL0` with no rate
correction in the path at all.

##### Four more instances of the bug class, in one run

This is the strongest instance yet, and it has a single root cause worth stating
plainly:

> **The userspace GIC and the PSCI dispatch had only ever served a guest that
> had already discovered them.** A rehydrated guest probed its interrupt
> controller and its firmware on a KVM host *before* it was captured, and never
> re-probes on resume. So every register that exists purely to be *discovered*
> was free to be wrong — and all of it was.

| # | Register / call | Wrong answer | Right answer | What it cost |
| --- | --- | --- | --- | --- |
| 11 | `PSCI_VERSION` (0x84000000) | 0 (catch-all) → reads as v0.0 | `0x0001_0000` (v1.0) | `Conflicting PSCI version detected`; PSCI disabled outright, so `CPU_ON` became unreachable however correctly it was implemented |
| 12 | `GICD_PIDR2` @ 0xFFE8 | 0 | `0x30` | `no distributor detected, giving up` → and the architected timer hangs off the GIC, so `sched_clock: 64 bits at 1000 Hz` — the jiffies fallback |
| 13 | `GICR_TYPER` affinity / `Last`, `GICR_PIDR2` | cpu 0 and `Last` on *every* redistributor | per-CPU affinity; `Last` only on the final frame | latent: `gic_iterate_rdists` stops at the first `Last`, so secondary cores find no redistributor |
| 14 | `GICD_ICFGR` / `GICR_ICFGR` **read** | 0 (write stored, read unhandled) | the stored config | `gic_configure_irq` **verifies its own write** and returns -EINVAL; no `request_irq` for the PL011, so no tty. printk still worked — its console path is polled — so the guest ran perfectly and had nowhere to write |

Instance 14 is the sharpest: a fully working Linux system, with an init process
executing and a shell running, producing **not one byte** of userspace output.
The failure was a register that had only ever been written to, in a model whose
guests had always configured their interrupts somewhere else.

A fifth was not a discovery register but the same shape of gap. Linux's
`clear_os_lock()` writes `OSDLR_EL1` and `OSLAR_EL1` on every CPU during
`debug_monitors_init`. Hypervisor.framework implements neither, so both trap —
and the vCPU died on the first one, ~30 ms in, with a fully booted kernel.
`handle_debug_sysreg_trap` handles them **by name**, and deliberately not with a
blanket "ignore unknown MSR": each register is enumerated, and only the write
that requests the state we actually provide is accepted. A guest that asks to
*set* the OS lock still gets a hard error naming the register, because silently
swallowing a system-register write is the most expensive lie a hypervisor can
tell — the guest believes it changed the machine, the machine did not change,
and the divergence surfaces arbitrarily far away.

##### How the cold path is built

- **vm-memory owns the RAM.** `GuestMemoryMmap::from_ranges` allocates it, so
  `linux-loader`'s PE loader and `arch`'s `create_fdt` / `write_fdt_to_memory`
  work **unmodified** — no adapter, no raw-pointer juggling. `GuestRam` was
  deliberately *not* extended: it is snapshot-file-specific (`map_file` only),
  and a cold boot has different ownership.
- **Cold boot uses the userspace GIC**, not Apple's managed one, for two
  guest-facing reasons: `hv_gic_create` fixes a non-canonical MMIO layout the
  tree would then have to agree with, and the managed GIC cannot deliver LPIs to
  a non-nested EL1 guest — so future virtio-pci would hit the known wall.
- **No clock correction.** `VtimerClock::new(0, 0, host_counter_hz())`. A cold
  guest reads Apple's own `CNTFRQ_EL0`, so there is nothing to correct and the
  V5.5 stepper never runs. The measured 3.00 s above is that, working.
- **The initramfs goes at the top of RAM**, page-aligned down, not just after the
  kernel: `image_size` covers BSS that is not in the file, so "just after the
  file" is *inside* the kernel's own memory.
- **`read_arm64_header` detects gzip and says `gunzip`.** A distro `vmlinuz` on
  arm64 is a gzip stream, and `linux-loader`'s `InvalidImageMagicNumber` sends
  you hunting a corrupt download instead.
- **`scripts/hvf/mkinitramfs.py`** writes the newc archive directly, because
  macOS `cpio` cannot create device nodes without root — and an initramfs with
  no `/dev/console` gives init no stdout at all, which looks exactly like a
  silent hang. (It is also, independently, how instance 14 was found.)

##### What is verified, and by what

| Claim | Evidence |
| --- | --- |
| A stock kernel cold-boots to userspace | `Run /init as init process` → BusyBox `ash` prompt |
| The GIC delivers | `arch_timer` 95 interrupts taken on GICv3 PPI 27 |
| Guest timekeeping is right | 3 s sleep measured as 3.00 s of guest uptime |
| The IRQ trigger config takes | `Setting trigger mode ... failed` count: 1 → **0** |
| The discovery registers | 5 unit tests in `softgic.rs` |
| The OS-lock and PSCI paths | 2 bare-metal guests in `hvf_boot.rs`, on real HVF |
| The image builder | 10 tests in `coldboot.rs` against a synthetic `Image` |

##### Still not done

SMP cold boot is unwired — PSCI `CPU_ON` returns `NOT_SUPPORTED` **by design**,
so a kernel that asks logs a failed secondary rather than hanging. That, and a
rootfs image, are the remainder of #101.

#### Cold virtio: a disk and a NIC for a guest that was never captured (2026-08-03)

A kernel and a shell is a demo. A **disk** and a **NIC** is a sandbox. Cold boot
needed both, and neither existed: every virtio device in this tree was
`virtio-pci`, reconstructed from a snapshot's `state.json`.

##### Why virtio-mmio, when virtio-pci already worked

The device *model* is the expensive part and it is already correct — queue
draining, notification re-arming, and the RX/TX asymmetry in the net path each
took measurement to get right. The **transport** is the cheap part. So the work
was to separate them rather than to write a second device.

Choosing `virtio-mmio` over `virtio-pci` for the cold path removes a synthetic
PCIe host bridge, an ECAM window, BAR programming, MSI-X tables and ITS
translation — and `arch`'s FDT writer *already* emitted `virtio_mmio@` nodes for
`DeviceType::Virtio(n)`, so the device-tree half was free.

`hypervisor/src/hvf/virtio/devcore.rs` now holds the transport-independent
`DeviceCore`; `pci.rs` and `mmio.rs` each contribute only their own register
layout. A cold guest's disk I/O runs through **exactly** the code a rehydrated
guest's does. The extraction was proven behaviour-preserving before the new
transport was written: 191 hypervisor tests before, 191 after.

##### What the driver actually demanded

| | virtio-pci (restore) | virtio-mmio (cold) |
| --- | --- | --- |
| features | replayed from the snapshot | negotiated with the driver |
| queue addresses | restored, never written | programmed by the driver |
| queue size | restored | driver picks, `<= QUEUE_NUM_MAX` |
| interrupts | MSI-X vector → LPI | one wired SPI, level status |

Four things Linux requires that a reading of the spec alone does not stress, each
now a test:

- **`VIRTIO_F_VERSION_1` must be offered.** A v2 transport without it is rejected
  outright, so `VirtioMmioDevice::new` force-adds bit 32 whatever the device says.
- **`QueueReady` must read back.** The probe writes it, then reads it, and does
  not trust the queue until it agrees.
- **A notify for a queue whose `ready` is false must be ignored.** The driver
  programs six address halves in any order; walking a half-named ring reads
  garbage GPAs.
- **Ring features come from `driver_features`, not what the device offered.** A
  driver is free to decline `EVENT_IDX`.

##### Ordering is a contract, not a detail

Disks are placed before the NIC. Linux names virtio-blk devices in probe order
and probes `virtio_mmio` nodes in **address** order, so a NIC placed first
renames `/dev/vda` to `/dev/vdb` — and `root=/dev/vda` stops meaning anything.
That ordering is asserted by a test rather than left to the reader.

A related trap sits in the FDT writer and is easy to get backwards:
`create_virtio_node` writes `dev_info.irq()` **verbatim** (SPI-relative), while
`create_serial_node` subtracts `IRQ_BASE` (absolute INTID). Same struct field,
two different conventions.

##### Measured, on a stock Ubuntu 6.8.0-31 arm64 kernel

Disk — an 8 MiB raw image with known magic at sectors 0, 1 and 4095:

```
major minor  #blocks  name
 253        0       8192 vda
   C H M - V I R T I O - B L K - S E C T O R - 0 0 0 0 0 0 0 0 0 0     <- sector 0
   C H M - V I R T I O - B L K - S E C T O R - 0 0 0 0 0 0 4 0 9 5     <- sector 4095
 14:          7     GICv3  34 Edge      virtio0
```

and the guest's write came back **out of the host file**, not out of its own page
cache — `host sector 7: b'FINAL-VERIFY-WRITE-FROM-COLD-GUEST'`. The interrupt
count is the point: completions are delivered on SPI 34, not polled.

Network — the userspace NAT, DNS responder and egress policy, meeting a cold
guest for the first time:

```
2: eth0: <BROADCAST,MULTICAST> link/ether 02:00:00:00:00:02
64 bytes from 192.168.249.1: seq=0 ttl=64 time=0.126 ms
Name: api.github.com   Address: 20.26.156.210
HTTP/1.1 301 Moved Permanently
Location: https://api.github.com/zen
```

A real HTTP response from the public internet, inside a guest that was never
captured anywhere.

##### The egress posture held, at two layers

`--net` defaults to deny-all, the same posture as every other entry point
(`docs/security-model.md` §1a); `--egress-allow host:port` is the only way out,
and passing it *without* `--net` is a parse error rather than a reassuring no-op.

Running with `--egress-allow api.github.com:80` produced two refusals worth
recording, because they are different mechanisms:

```
[egress] DENY dns example.com (default-deny)
[egress] DENY tcp 93.184.216.34:80 (default-deny)
```

The first is the DNS responder refusing to resolve a name the policy does not
allow. The second is the same host refused **by raw IP**, so containment does not
depend on the guest choosing to use our resolver. Enforcement is also
port-specific: the allowed `:80` request succeeded, GitHub answered `301` to
`https://`, and the follow-up to `:443` was denied by the same policy.

##### One honest note on method

The first run reported empty reads and a write that never reached the host file,
which looks exactly like a broken device. It was not: the test initramfs had no
`/dev/vda` node, and busybox `dd` had quietly created a *regular file* of that
name in tmpfs. The 3 interrupts observed were the kernel's own partition scan —
which is to say the device had been working the whole time and the test was
measuring itself. `mount -t devtmpfs` fixed it. Worth recording because
"completes but moves no data" is a plausible enough hypothesis to have sent a
day into the queue code.

---

#### Cold SMP: bringing up secondary cores on a guest with no capture (2026-08-03)

`chm create --cpus N` now boots a stock Ubuntu 6.8 arm64 kernel onto **N real
vCPUs**, with PSCI `CPU_ON`, per-core timers and cross-core IPIs. Measured at
1, 2 and 4 vCPUs.

Every piece of this — the PSCI coordinator, the per-vCPU checkpoint models, the
SGI router — already existed for the **restore** path. None of it worked cold,
and the reason is the same each time: **a rehydrated guest never discovers its
hardware.** It wakes with the GIC already probed, the redistributor already
matched to its core, and every base register already latched. A cold guest does
all of that from scratch, and the discovery path was where the bugs were.

Four bugs, in the order the guest hit them.

**1. Each vCPU could only see its own redistributor frame.** The MMIO decode
was `ipa >= gicr_base && ipa < gicr_base + 0x20000` — the running core's frame
alone. But `gic_iterate_rdists` runs on the **boot CPU** and walks *every*
frame in the region reading `GICR_TYPER` until it finds the `Last` bit. On real
hardware every frame is visible to every core. So the boot CPU data-aborted on
frame 1: `Internal error: Oops: 0000000096000007` in `gic_iterate_rdists`,
before a secondary had even been asked for.

The redistributors are now one shared `Arc<Vec<Mutex<Redistributor>>>` with a
per-vCPU `redist_index`; `redist_frame(ipa)` recovers the region base and
returns `(frame, offset)` for any address in it. `Default` is a single frame,
so the single-vCPU and restore paths are byte-identical.

**2. A secondary started at EL0.** `setup_regs` — which sets `PSTATE` to EL1h
with `DAIF` masked — only ran for the boot CPU, because a secondary has no
entry point until `CPU_ON` names one. HVF resets a fresh vCPU to EL0, so the
secondary's first instruction fetch aborted from a lower EL (`EC=0x20`) and
vectored to `VBAR_EL1 = 0`. PSCI defines the entry state for a core brought up
by `CPU_ON`: highest implemented non-secure EL, interrupts masked. A parked
vCPU is now put there at creation.

**3. `GICR_TYPER` was truncated to 32 bits — and this is the one that mattered
most.** The register models are 32-bit, and `usgic_mmio` returned `u32`. Linux
reads `GICR_TYPER` as **one doubleword**, and the affinity it matches against
its own `MPIDR_EL1` lives in **bits [63:32]**. Folded onto the low word, every
frame reported affinity 0 — so the boot CPU (affinity 0) always found itself,
and no secondary ever could. The symptom was a silent whole-guest hang, with
`gic_populate_rdist` spinning on a core with no console.

Accesses now carry their width: a doubleword splits into the two word halves
the models already implement (`GICR_TYPER` at `+0x8`/`+0xC`, `GICR_PROPBASER`
at `+0x70`/`+0x74`, `GICD_IROUTER`). This was invisible on the restore path for
the same reason as the other three: the guest reads `GICR_TYPER` exactly once,
during discovery.

**4. PSCI returned `NOT_SUPPORTED`.** `ColdVmOps::psci_vcpu_on` was hardcoded
`Ok(-1)`. `PsciCoordinator` gained a `cold()` constructor — vCPU 0 online
because the boot protocol started it there, every secondary off until the
kernel asks — and `create.rs` grew the N-thread setup/go handshake the restore
path already used, since HVF binds a vCPU to its creating thread.

**Measured, on the signed binary, with a stock Ubuntu 6.8.0-31 kernel:**

| | 1 vCPU | 2 vCPU | 4 vCPU |
| --- | --- | --- | --- |
| `/sys/devices/system/cpu/online` | `0` | `0-1` | `0-3` |
| user jiffies after saturating every core | 9 | 11 / 11 | 11 / 11 / 12 / 11 |
| `arch_timer` PPI 27, per core | 193 | 127 / 96 | 222 / 197 / 182 / 201 |
| IPI0 rescheduling, per core | 0 | 27 / 39 | 21 / 10 / 22 / 20 |
| IPI1 function call, per core | 0 | 154 / 199 | 222 / 218 / 64 / 72 |

Non-zero user time on *every* core is the load-bearing number: it proves the
secondaries execute work, not merely that they exist. Non-zero IPI rows in both
directions prove cross-vCPU SGI delivery. `arch_timer` on every core proves
per-core PPI delivery through the right redistributor frame.

Composed with the virtio work: `--cpus 2 --disk --net` reads the host disk
magic, pings the NAT gateway at 0.17 ms, and shows virtio SPIs 34/35 alongside
per-core timers and IPIs.

**Regression, not just progress.** The shared-redistributor and access-width
changes are on the *restore* path too, so a 2-vCPU Graviton2 capture was
re-run: 2 cores online, IPI0 1743/1961 and IPI1 3030/7006. Unchanged.

## 7a. V6.6 — one interrupt backend

**Shipped.** The Apple managed-GIC runtime path is retired. `chm run` and
`chm serve` no longer choose between two GIC backends, because there is only
one: the userspace GICv3.

### Why retire rather than fix

Measured, not argued. All three captures we hold route to the userspace GICv3
today; nothing routes managed. `classify_routing` returns `DeliverableSpi` — the
only managed route left — when a VM wires **zero** MSI-X devices, and a real
cloud-hypervisor arm64 VM always wires virtio-blk/net through MSI-X to the ITS.
GICv2M captures were already refused outright. So the managed path was reachable
only by a VM with no virtio devices at all.

It also could not be fixed into relevance:

- **It cannot deliver an LPI.** Apple's ICH List Registers are EL2/nested-only
  (`HV_UNSUPPORTED`), and `hv_gic_*` exposes no `GICR_PROPBASER`,
  `GICR_PENDBASER` or ITS. A stock capture's disk and net completions arrive as
  LPIs, so the guest restores and then stalls on its first I/O.
- **It cannot cold-boot.** `hv_gic_create` returns `HV_BAD_ARGUMENT` unless the
  redistributors sit *above* the distributor, which is not the layout Linux
  expects.
- **It has no shared `VtimerClock`.** Both `attach_clock` call sites are
  userspace, so the V5.5 counter-coherence fix never applied to it.
- **The performance A/B is unmeasurable.** There is no workload both backends
  can run: an ITS/LPI capture stalls on managed by construction, and cold boot
  cannot use managed at all.

The evidence survives. `hypervisor/src/hvf/gic.rs` and the managed-GIC tests in
`hypervisor/tests/hvf_boot.rs` still drive Apple's GIC directly on hardware —
that measurement *is* the justification for building a userspace GIC, so it is
kept as a test rather than as a runtime path a user can select.

### Retiring it widened the contract rather than narrowing it

The usgic restore path never consulted the ITS config, and `UsgicMsiSink`
already delivers both SPIs and LPIs. Every capture the managed path could have
run, the userspace path runs.

### Three real defects the dead path was hiding

Removing it made the compiler point at code nothing called any more — and each
one turned out to be a guard the *surviving* path had never had:

| Guard | What was wrong |
| --- | --- |
| **Session-liveness lock** | `chm connect --session-lock` writes the file the app scans to reconcile which sandboxes are live. It was acquired only inside `resume_smp` (managed), so for every real capture the file was never written. |
| **Run-progress watchdog** | Bounds how long a vCPU can stay wedged inside one `hv_vcpu_run` (#78/#60). Every vCPU has always bumped `run_gen`; on the userspace path nobody read it. |
| **Session lifecycle audit (M29)** | `session-start` / `session-stop` were written only on the managed path. A real capture's audit log had denied-egress records but no session boundaries — proven by absence: `~/graviton-r2/b`'s log contained **zero** `session-start` lines across its whole history until this fix wrote one. |

All three now run on the userspace path, and `session-stop` is written on the
error path too — a session that ended because a vCPU failed is exactly the one
an operator needs a durable record of. The credential proxy is now also held for
the session and `stop()`ped at teardown, so the daemon does not leak an accept
loop per VM.

### Honesty fixes that came with it

- `chm capabilities` reported **`[no] Cold boot from an image`** while we ship
  cold boot with disk, NIC and 4-way SMP. Now `[yes] … (built)` — `Built`, not
  `Observed`, because nothing probes it while building the report and
  `Observed` means "already happening".
- Posture invariant **I7** was `Active`/`Weakened` on `CHM_ALLOW_ITS_LPI`. That
  variable now selects nothing, so I7 is structural. The row is kept, not
  dropped: `CHM_ALLOW_ITS_LPI=1 chm posture` reports no weakened control.
- `CHM_ALLOW_ITS_LPI` and `CHM_USERSPACE_GIC` are removed from the env-var
  reference, and the "do not confuse the two variables" section of
  `hvf-compatible-snapshots.md` is replaced by "there is only one backend now".

### Verified live

Real 2-vCPU Graviton2 capture rehydrated to a login shell; cold boot at
`--cpus 2 --disk --net` read the host disk magic, pinged the NAT gateway at
0.24 ms, and showed per-core `arch_timer` plus virtio SPIs 34/35 and IPIs on
both cores. Session lock observed written with a live PID and removed on exit;
watchdog observed forcing exits on both cores at its 30 ms cadence.

Net: **1,048 lines deleted, 170 added.**

## 7b. V6.7 — the resume wedge, and what it is not

While rebuilding the agent image a guest wedged: `rcu_preempt kthread timer
wakeup didn't happen for 60013 jiffies`, `Possible timer handling issue on
cpu=1`, then silence. It recurred, and on one occasion a `kworker` was
`blocked for more than 245 seconds` — an I/O that never completed.

This landed immediately after V6.6 retired the managed GIC and moved the run
watchdog onto the surviving path, so the first duty was to find out whether we
had broken something. **We had not**, and saying so required disproving three
plausible explanations rather than one.

### The elimination

Every row is a run on real hardware, counting only kernel-emitted stall lines
(`^\[ *[0-9]+\.[0-9]+\] rcu:`).

| Hypothesis | Test | Result |
| --- | --- | --- |
| The new run watchdog cancels `hv_vcpu_run` and the vtimer is not redelivered | 4-way CPU burn, 50 s, watchdog **on** | **0 stalls** |
| …then it must need a checkpoint resume to show | Same image resumed from a checkpoint, watchdog **off** via `CHM_DISABLE_RUN_WATCHDOG=1` | **Reproduced identically** — watchdog cleared outright |
| The resume-time counter jump (V5.5 §8b) buries the guest in missed ticks | `CHM_FORCE_RESUME_ADVANCE_S=3600` on an image that had just resumed clean, holding elapsed time constant | **0 stalls**, guest healthy, wall clock correct |
| It is simply how long the checkpoint sat on disk | Same image, ~1 min gap vs ~5 min gap | Short **clean**; long **clean** once the jump was isolated |
| Disk-heavy work loses a virtio completion | 600 MB `dd … conv=fsync` on the pristine capture | **0 stalls, 0 hung tasks**, 165 MB/s |
| Idle guests stop getting timer wakeups | Idle 200 s, watchdog on | **0 stalls** |

Two things fell out of this that were worth the trouble on their own.

**A guard, because one cause is now understood.** A session that writes to disk
and exits *without* `--checkpoint` leaves guest RAM describing a filesystem that
has moved underneath it. The guest then serves RAM-only work normally and wedges
the moment it touches the diverged tree — and the teardown capture writes that
**hung** kernel over the last good checkpoint, so every later resume starts
wedged. Checkpoints now record the overlay identity they were taken against and
resume refuses a mismatch, naming the two recoveries. `CHM_ALLOW_OVERLAY_DRIFT=1`
overrides.

**A knob, because the obvious experiment was not available.** The counter jump
on resume is normally a function of how long the checkpoint sat on disk, so
waiting cannot separate the two. `CHM_FORCE_RESUME_ADVANCE_S` varies the jump
while holding elapsed time constant, and is what turned a one-hour experiment
into a three-minute one — and disproved the leading hypothesis.

### What is still open

The surviving correlation is narrow and specific: **every wedge happened on a
root filesystem that had been `growpart`/`resize2fs`d to fill the virtual disk;
the un-resized pristine capture is clean under idle, CPU burn, 600 MB of
`fsync`ed writes, checkpoint/resume and a forced one-hour counter jump.** That
points at how the CoW overlay handles writes to the region past the original
filesystem extent, not at interrupts or timekeeping. It is not yet proven, and
it is the next thing to test.

**Resolved 2026-08-03, and the answer was none of the above — see §10a.** The
same signature (`jbd2`, `ext4lazyinit` and kworkers "blocked for more than 122
seconds") reproduced on a **cold-booted** guest with no CoW overlay in the path
at all, which refutes `overlay-extent-writes` outright. The cause was a lost
virtio kick racing the notification re-arm: an interrupt bug after all, just not
in the interrupt controller. The correlation with resized roots was real but
incidental — a bigger filesystem means more journal traffic, which means more
chances to lose the race.

**Worth keeping as method.** A correlation that survives six clean A/B tests can
still be a coincidence, and the thing that finally broke it open was noticing
`chm` itself sitting at 2.3% CPU in state `S`. An *idle* device with a *blocked*
guest is not slow I/O; it is a notification that never arrived. One `ps` reading
was worth more than the whole correlation table.

Also found, and unrelated: on a rehydrated Graviton2 guest `node --version`
returns `v22.23.2` but `npm --version` dies with **`Illegal instruction (core
dumped)`**. `node` barely JITs and `npm` JITs heavily, which is the workload
[`cpu-feature-deltas.md`](cpu-feature-deltas.md) predicted would stress the one
`CTR_EL0` bit (DIC) that differs between the capture host and Apple silicon —
recorded there as latent and *"stressed without fault"*. It now has a fault.

## 7c. V6.8 — why npm dies on a rehydrated Graviton guest

`node --version` printed `v22.23.2`. `npm --version` printed
`Illegal instruction (core dumped)`. Same binary, same guest, seconds apart.

The cause is one bit, and it was already written down. V1.4's audit recorded
`CTR_EL0.DIC` as the single bit differing between the capture host and Apple
silicon, filed it as latent, and predicted it would bite *kernel* code patching.
It was stressed there — module load, ftrace, jump labels — and did not fire. The
audit then concluded userspace was safe, for a reason that is true but not
sufficient: the guest applies Neoverse-N1 erratum 1542419, traps EL0 `CTR_EL0`
reads and reports `DIC = 0`, so a userspace JIT does issue `ic ivau`.

**Userspace being told the truth is not enough, because part of the maintenance
is the kernel's job.** `__sync_icache_dcache()` runs when userspace makes a page
executable, and it is backed by `caches_clean_inval_pou()` — the function Linux
alternative-patched `ic ivau` out of, at boot, on a host that reported
`DIC = 1`. Those NOPs are baked into the kernel text inside the snapshot.

### Measured

Executing freshly written code and checking whether the value returned is the
one just written (`scripts/hvf/icache-coherency-probe.py`, rerunnable in any
guest, no compiler required):

| probe | stale |
| --- | --- |
| same page rewritten, no maintenance | 1997 / 2000 |
| same page rewritten, explicit `ic ivau` | **0 / 2000** |
| **`mmap(RW)` → write → `mprotect(RX)` → call** | **955 / 1000** |
| as above, plus explicit `ic ivau` | **0 / 1000** |

Row 3 is the JIT path and must be 0 on a sound kernel. Rows 2 and 4 show the
hardware and the instruction both work; only the kernel's elided copy is wrong.

### How it was found, and one wrong turn worth recording

The first hypothesis was this exact bit, and an in-guest probe appeared to
**disprove** it: userspace reads `DIC = 0`, so JITs do the right thing. That was
a correct measurement of the wrong half, and treating it as decisive would have
closed the investigation on a true fact and a false conclusion.

What reopened it was refusing to stop at a clean single result. A statistical
bisect showed the fault was *intermittent* — and that pinning to one vCPU made
it **worse**, 10/15 versus 2/15. A cross-vCPU coherency problem improves under
pinning. Staying on one core instead maximises the chance that core's I-cache
still holds the stale line, which is the signature of a missing invalidate
rather than a missing broadcast. Only then did the kernel half come into view.

| variant | failures |
| --- | --- |
| `npm --version` | 2/15 |
| `npm --version`, `taskset -c 0` | 10/15 |
| `--predictable` (single-threaded V8) | 2/15 |
| `--jitless` | **0/15** |

### Shipped

`icache_dic_guard` warns at load on both the `run` and `serve` paths, and
`CHM_STRICT_ICACHE=1` refuses. It mirrors `aarch32_guard`: nothing can be
repaired at rehydrate time, and refusing by default would block every Graviton
capture over a hazard that only affects workloads generating code at runtime.
`chm posture` reports it.

### What actually fixes it

- **Cold boot.** A kernel that boots here reads this Mac's own `CTR_EL0`, sees
  `DIC = 0`, and keeps its `ic ivau`. Immune by construction — which makes the
  cold-boot path (V5.4 / #101) load-bearing for agent workloads, not just a
  convenience.
- **A capture host reporting `DIC = 0`.** This is a property of the capture
  host, not the workload. Graviton2 is Neoverse-N1 and reports 1. Worth asking
  gimbal cloud what Graviton3/4 report before assuming a newer instance helps.

### Consequence for V7

`v7-agent-acceptance` runs the Copilot CLI, which is a Node/npm workload, so it
inherits this. It should run on a cold-booted guest, or on a capture from
`DIC = 0` hardware — not on a rehydrated Graviton2 capture.


## 8. Historical milestone detail (M25–M32)

The sections below are the **previous** milestone structure, kept for the shipped
detail and rationale they record. The V1–V4 spine above supersedes them as the
plan; where the two disagree, V1–V4 is current.

### M25 · Live local lifecycle — suspend · resume · fork

The Mac runs, suspends, resumes, and forks microVMs entirely locally. The engine
is complete:

- **Suspend / resume** live checkpoints, and **checkpoint-everywhere** (idle,
  graceful stop, daemon stop).
- **`chm fork`** branches a revision (shared read-only base + copied live state).
- **Local revision store + rollback** — `.chm-revisions/` keeps the suspend /
  fork / rollback lineage (RAM-pruned to the newest N so the graph survives),
  `chm revisions` / `chm rollback`, and a Revision history card in the app.
- **`chm workspace <image> <ws>`** — a per-sandbox workspace that shares an
  image's read-only base but keeps its own overlays + checkpoints, so N sandboxes
  from one image diverge independently.
- The runner advertises `supports_fork` / `supports_cow_overlay`.
- **Per-sandbox workspaces are wired through the app** — each sandbox runs in its
  own workspace (shared read-only base, isolated overlays + checkpoints) via both
  the interactive terminal and the daemon; several run concurrently (one VM per
  process). `chm fork` shares the base RAM read-only (file-level CoW). The runner
  reports `suspended` + pushes a `checkpoint` artifact when a run leaves one.

**Residual (one deferred perf optimisation, not dangling work):**

- **Runtime memory page-sharing (memfd CoW).** Fork already shares the base RAM
  *file* read-only (copy-on-write at the file level) and diverges on the next
  suspend. Sharing live pages between *concurrently running* VMs via a private
  memfd is a deeper HVF memory-management optimisation — a documented perf
  ceiling, tracked for later; correctness and isolation are complete without it.

### M30 · Security hardening — hostile-agent readiness

**The immediate priority — it precedes M27.** Gimbal Local runs *untrusted*
compute (increasingly an autonomous coding agent) from an *untrusted* snapshot
bundle, on a personal Mac. A first security review found real gaps; M30 closes
them. Full model + plan: [`security-model.md`](security-model.md).

- **M30.1 (#33, P0) — shipped.** Bundle file isolation: reject symlinked disk
  bases + overlays, `O_NOFOLLOW` opens, a private `0700` overlay dir, and
  manifest relpath confinement in `materialize_bundle`.
- **M30.2 (#34, P0) — shipped.** Daemon socket hardening: private `0700` dir,
  `0600` socket, and a peer-uid (`getpeereid`) check before
  start/stop/console/shutdown. Follow-up #66 shipped: a pre-existing runtime dir
  is rejected unless the current user owns it, and self-owned dirs left too open
  are tightened back to `0700`.
- **M30.3 (#35, P0) — shipped.** App command safety: a pure, single-quoting
  `InteractiveTerminalCommand` builder that rejects control characters (the
  snapshot-name vector was already removed). Follow-up #67 shipped: the command
  is handed to `osascript` as an `argv` parameter, dropping the AppleScript
  string-literal escaping layer.
- **M30.4 (#36, P1) — verification shipped.** Ed25519 signed-manifest
  verification in `chm` (trust store via `CHM_TRUST_STORE`, key ids + rotation),
  fail-closed when configured, plus a `chm manifest keygen|sign|verify` reference
  signer. gctl producing + signing production manifests is the remaining
  cross-repo half (#36).
- **M30.5 (#37, P1) — shipped.** The **no host-FS-passthrough** invariant is
  explicit: a behavioural test proves virtio-fs/9p classify as `Unsupported`,
  and `make security-check` fails if host-FS wiring appears without review.
- **M30.6 (#38, P2) — shipped.** Per-sandbox resource limits: a launch
  gate (vCPU/mem ceiling) + a run-loop monitor that stops a runaway on disk
  overlay / console / wall-clock caps, plus NAT `max_connections` /
  `max_bandwidth_kbps` caps enforced on the egress datapath (over-limit SYN
  refused + audited; bandwidth throttled via token-bucket backpressure).
  Authored with `chm limits` and applied to new sandboxes by the app's sane
  global defaults.
- **M30.7 (#39)** — the threat model + hardening checklist (this doc set).
- **M30.8 (P0) — shipped.** CAS digest hardening: a manifest checksum is
  validated as a canonical sha256 hex digest before it is used as a
  content-store path, and every CAS object (including cache hits) is re-hashed
  before linking, so a tampered manifest cannot select or expose a host file.
- **M30.9 (P0) — shipped.** Egress enforced on **every** NIC (not just the
  first) and fail-closed: a governed session whose policy cannot be resolved
  denies all egress rather than booting open.

M30 is the *trust + isolation* layer beneath the feature pillars: even with **no**
policy, a bundle must not escape the host and the daemon must not be hijackable.
Its network item converges with M28's firewall enforcement (same datapath); its
signing item makes M26's displayed provenance cryptographically verified.

### M31 · Network host-isolation — the reserved-address boundary

**The new critical priority** (2026-07-16 adversarial review). M28/M30.9 built a
*policy* gate on egress, but the userspace NAT still relays a permitted flow
through a real host socket — so a guest can reach the **host's own networks**
(loopback, private LAN, link-local `169.254.169.254` metadata), reachable
**by default** (allow-all when no policy is bound; the app firewall ships off),
and bypassable in allow-list mode via **DNS rebinding**. This is a host-boundary
break even without filesystem access. Full findings + plan:
[`security-model.md`](security-model.md#m31--network-host-isolation--the-reserved-address-boundary).

- **M31.1 (P0, #75)** — reserved-address guard in the NAT: deny loopback / RFC1918 /
  link-local / other special-use ranges independently of the policy, re-check the
  *resolved* IP at connect (closes DNS rebinding), drop DNS answers resolving into
  reserved ranges, with an explicit opt-in for deliberate localhost access.
  **Shipped.**
- **M31.2 (P1)** — safe default posture: the app ships the firewall on in
  default-deny (allow-list) mode, so a new sandbox has no public egress until
  allow-listed (host/LAN always blocked by M31.1). **Shipped.**
- **M31.3 (P1)** — correct the overstated network docs to match enforcement.
- **M31.4 (P2)** — document the cloud/KVM path + external capture-harness
  boundary (security-model § "Out of scope" + the BYO capture runbook).
  **Shipped.**
- **M31.5 (P1)** — signing fail-closed default + digest recompute enforcement
  (folds into #36). **Posture shipped** (`CHM_REQUIRE_SIGNED`); gctl-signed
  production manifests are the remaining half.



Pillar ②'s deep, plane-coupled half:

- **`chm commit` / `push` / `pull`** (#7) — **shipped (core loop).** `chm push`
  commits a local checkpoint as a content-addressed revision on a branch (the
  plane dedups it into its CAS and advances the head); `chm pull` rehydrates a
  branch head (or explicit revision) back to a local resume. Proven live on the
  `:8080` dev plane: a re-commit of already-present content stored **0 bytes**.
- **Branch review + merge** (#7) — **shipped.** `chm branches review`/`merge`
  drive the plane's review gate (an unapproved source into a review-required
  target is refused; approve → merge); the app's Branches section has a review
  picker + a merge menu. Proven live: gate refused then merged after approval.
- **Page-range ACL honoring** (#7) — **shipped.** A scoped pull's out-of-scope
  chunk 403s; `chm state-cdn reconstruct` skips those pages (least-privilege
  image) rather than failing. Proven live: a page-0-only token → 1 fetched, 3
  ACL-denied.
- **Peer cache** (#7) — **shipped.** `chm state-cdn serve` runs a peer-cache HTTP
  server over the reconstructed (ciphertext) chunks and `register-peer` advertises
  it; the plane routes same-locality pullers here. Proven live: a peer served
  byte-identical chunks and a different locality fell back to origin. A peer
  serves opaque ciphertext without a token check, so ACL-restricted refs are
  sourced from origin (where the scope is enforced); peer scope-enforcement is a
  documented follow-up.
- **Postcopy memory plane** (#5) — **consumer shipped; demand-fault deferred.**
  `chm state-cdn reconstruct` pulls a checkpoint's encrypted, content-addressed
  RAM chunks from the state CDN, decrypts them (AES-256-GCM per-tenant), and
  reassembles the memory image — proven live decrypting real tenant chunks. It
  advertises `supports_offload_daemon`. True *demand-fault* postcopy (fetch only
  the touched working set) needs HVF stage-2 fault interception (no `userfaultfd`
  on macOS) and is the tracked next step — see
  [`state-cdn-memory-plane.md`](state-cdn-memory-plane.md).
- **Disk plane**: lazy blocks over the same content-addressed store.

Back-compat means Gimbal Local always degrades to the M25 file-backed path, so it
is never *stuck* — just not yet demand-faulting the working set.

### M28 · Consistent sandbox controls — filesystem + network/firewall

Pillar ③ (#20) — **the product must-have, now planned:
[`network-policy-plan.md`](network-policy-plan.md).** The plane authors a
per-sandbox `SandboxPolicy` (egress allow/deny + fs read/write scopes + mounts),
content-addressed so it teleports *with* the session; every `assign-run`/resume
carries the compiled `enforcement.chm_profile` + `policy_digest`. Gimbal Local is
**one of the two enforcers**.

**The key realisation:** `chm` already mediates 100% of the guest's network (one
`NetResponder` seam; no tap/bridge/host route). Replacing the current echo stub
with a **userspace NAT** — a TCP/IP stack that relays the guest's flows through
host sockets `chm` opens — makes networking *real* **and** makes enforcement
*authoritative* in one stroke: because `chm` is the process that dials,
default-deny is literally "don't open the socket," and the guest has no path
around us. Same model as gVisor/slirp/passt.

Staged: **M28.1** policy plumbing + digest teleport (#49, no datapath change,
shipped) → **M28.2** userspace egress NAT (#50, the hard engine work — shipped:
real IPv4 TCP + DNS through a smoltcp NAT, proven by an in-CI relay test) →
**M28.3** the allow-list gate at DNS + TCP-connect (#51, shipped: the verified
`chm_profile` teleports through `CHM_EGRESS_POLICY` into the NAT, which refuses
unlisted DNS names and TCP connects and logs each denial) → **M28.4** the demo +
teleport proof (#52, shipped: two scripted hardware proofs — a default-deny
allow-list refused at BOTH the DNS gate and, for a hardcoded IP, the TCP-connect
gate; and `chm policy bind` bringing a plane-authored policy down so the cloud's
digest governs a local sandbox and names every audited denial) → **M28.5** fs scopes (#53, shipped: requested host mounts
are refused loudly — no host-FS passthrough — and reported to the plane). The
demo it must land: the plane sets *allow-list only for sandbox N*, it follows the
sandbox down, and the guest **provably can't get out** except to the allow-list.
**That demo now runs, on real hardware, from a script.** The net-enabled capture
that used to block it exists (`GUEST_NET=1` in the capture harness), so
`scripts/hvf/egress-allowlist-demo.sh` and `scripts/hvf/policy-teleport-demo.sh`
prove enforcement and the digest teleport end-to-end on a rehydrated stock ITS
snapshot. See [`networking.md`](networking.md) for the runbook.

### M29 · Observability & cost — logging, insights, both sides

Pillar ④. **Local audit trail shipped:** every sandbox writes a durable,
append-only `audit.jsonl` (session start/stop with shape + outcome, denied
egress flows, and bundle-verify decisions), readable with `chm audit show`, so an
operator can review what a sandbox did independent of the guest-floodable
console. The remaining half is the shared telemetry/cost contract: local
sandboxes emit the **same** structured usage events (cpu-seconds, wall-time,
memory, bytes faulted) through the runner's report-state / push-artifacts path,
so insights and cost accounting are uniform regardless of where a session ran.
The app already reads the plane's read-only cost/health panel; the rest waits on
the gctl telemetry/cost event contract.

### M32 · Agent workloads + benchmark vs Docker (#76)

With the local runtime and host-isolation complete, the next thrust is putting
**real agents/workloads to work inside gimbal microVMs** and measuring how the
platform compares to the incumbent (Docker Desktop's Linux VM) on the same Mac.

- **M32.1 — agent workload readiness.** Prove a representative dev/agent loop runs
  end to end inside a gimbal sandbox: clone a repo, install deps, build, run
  tests, and (nested) `docker build` inside the guest. Shake out anything the
  guest image lacks (container runtime, disk headroom, DNS/egress allow-list for
  package registries under the new default-deny). This is the "actually put an
  agent to work" proof.
- **M32.2 — benchmark vs Docker sandboxes. Harness shipped + first result
  recorded (`scripts/bench/`, `RESULTS.md`).** A reproducible harness runs the
  **same** inner workload inside a Docker Desktop container and a gimbal microVM
  on the same Mac, N trials, and aggregates to markdown with mean ± stddev + a
  gimbal/Docker ratio. The gimbal side runs the workload inside the stock demo
  snapshot via a PTY-driven integration test (`microvm_xz_benchmark`), so it
  needs no special snapshot. **First real result (Apple M3, matched 1 vCPU / 1
  GiB, single-threaded `xz` compression):** gimbal 23.67 ± 0.82 s vs Docker
  23.17 ± 0.83 s — **gimbal is 1.02x Docker (~2% slower, within noise)**, at or
  better than the ~1.03–1.09x microVM prior-art band. Warm-checkpoint resume +
  teardown adds only ~5 s.
  - *Two findings surfaced:* the stock demo guest has **no C toolchain** (so a
    real compile benchmark needs a toolchain-provisioned snapshot, M32.1), and a
    **post-CPU-burst input wedge** where a second command after a long silent
    compute does not wake the parked vCPU (filed as #78; the benchmark runs each
    trial in a fresh session to sidestep it).
  - *Still future:* multi-vCPU / parallel builds, and IO/network-heavy workloads
    (where microVMs historically lose ~17–20%) to exercise the CoW overlay + NAT.

**On the "snapshot dependency":** gimbal only *rehydrates a snapshot* — there is
no boot-from-scratch path — so the microVM you build in **is** a snapshot; it is a
one-time "provision a Docker/toolchain guest, then capture it" step (local-doable
on a KVM host), not an external blocker. If the build inputs are **baked into the
guest image**, the build runs **offline** and needs no network / net-enabled
snapshot (#52); network is only needed for realistic pull-at-build-time runs.

Both parts are local-doable and do not depend on the control plane. They also
stress the security posture (egress allow-list vs. registries; disk/console caps
vs. real builds), so they double as end-to-end validation of M30/M31.

---

## 9. Standing platform boundaries

- **R1 — ITS/LPI is no longer a wall; it is a solved problem with one gap.**
  Apple's *managed* GIC (`hv_gic`) delivers message-based SPIs only, with no
  ITS/LPI path. The **userspace GICv3** (M-USGIC) removes that limit: a stock
  ITS/LPI capture rehydrates onto a software GIC that delivers LPIs, with disk,
  net, SMP and checkpoint/resume all hardware-proven. **Vanilla is now the
  recommended capture shape.** The remaining gap is that `chm serve` has not been
  wired to it yet (#102), so the daemon still requires a `gicv2m-message-spi`
  capture. See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md).
- **Counter frequency is a hard, unfixable-at-restore part of the compatibility
  contract.** A guest caches `CNTFRQ_EL0` at boot and never re-reads it. Apple
  presents HVF guests **24 000 000 Hz** and offers no way to change it —
  `hv_vcpu_set_vtimer_offset` sets an *offset*, never a *rate*. **Measured
  2026-07-28:** an AWS Graviton2 guest (`121 875 000 Hz`) resumed on Apple silicon
  runs **5.08× slow** in wall-clock terms — correct, self-consistent, and living
  in dilated time. It presents as sluggishness, not as a clock fault, which makes
  it the most dangerous failure mode we have. The HVF path does not yet check
  (#104). See [`graviton-acid-test-results.md`](graviton-acid-test-results.md) §4
  for every mitigation considered and why each one is or is not available.
- **arm64 KVM capacity.** Producing real snapshots needs a genuine arm64 `/dev/kvm`
  host (a Lima nested-KVM guest for $0, or Graviton bare metal); the Mac itself
  can only *run* snapshots, never capture them.

---

## 10a. The lost virtio kick (2026-08-03)

The bug that had been hiding behind `overlay-extent-writes` since V6.7, found
while running V7.1 and fixed in the same session.

**The symptom** was familiar: `jbd2/vda1-8`, `ext4lazyinit` and several
`kworker`s all "blocked for more than 122 seconds". **The datum that broke it
open was new**: this time it happened on a *cold-booted* guest, which has no CoW
overlay at all — so the standing theory could not be right. And `ps` showed
`chm` at **2.3% CPU in state `S`**. An idle device with a blocked guest is not
slow I/O. It is a notification that never arrived.

**The mechanism.** `VIRTIO_F_EVENT_IDX` is edge-triggered, not level-triggered:

```
vring_need_event(event, new, old) = (u16)(new - event - 1) < (u16)(new - old)
```

It fires only when the published index falls inside the window `(old, new]`. So
an event index that is **too old suppresses kicks just as effectively as one
that is too new** — which is the part that is easy to get wrong, because "stale"
intuitively sounds like it would cause *spurious* kicks rather than none.

The device's only writer of `avail_event` published a **fresh read of
`avail.idx`**:

1. `pop()` returns `None`; the device has consumed up to N.
2. The driver appends entry N, sets `avail.idx = N+1`, reads `avail_event`, sees
   a stale value, and decides **not to kick**.
3. The device re-reads `avail.idx` — now `N+1` — and publishes it, promising
   *"do not kick until you pass N+1"* for an entry **it never consumed**.
4. Nothing ever wakes the device. The guest blocks forever.

**Both halves of the fix are required.** Publish `next_avail`, the device's own
cursor, which can never run ahead of what was actually consumed, so the first
unseen submission always kicks. And because the driver may *already* have made
its no-kick decision, only the device can notice: after arming, re-check for
pending work and drain again. **The order matters** — arm, then re-check; the
reverse reopens the same window.

`VIRTIO_BLK_F_FLUSH` did not cause this. It exposed it, by turning every ext4
journal commit into another request and widening the window — which is why a
durability improvement looked like a regression.

**Very likely the same bug as the historical V6.7 resume wedges**: identical
signature, identical code path, and the resized-root correlation is explained as
"more filesystem, more journal traffic, more chances to lose the race".

### Method notes

- **A test can encode a bug.** `arm_notification_points_avail_event_at_current_idx`
  asserted precisely the broken behaviour, and had passed since it was written.
  It was replaced, not adjusted.
- **Check whether the emulator is busy before assuming the guest is waiting on
  it.** One `ps` reading discriminated "slow" from "asleep", which no amount of
  guest-side logging would have.
- A correlation surviving six clean A/B tests is still not a cause.

---

## 10. How this is tracked

Progress lives in the
[GitHub issues](https://github.com/gimbal-dev/gimbal-local/issues), mapped to the
V1–V4 spine:

| Milestone | Issues |
| --- | --- |
| V1.2 counter-frequency guard | ~~#104~~ shipped |
| V1.3 counter-rate synthesis | ~~#108~~ shipped |
| V1.5 the acid test | ~~#105~~ passed |
| V2.1 `chm serve` + userspace GIC | ~~#102~~ shipped |
| V2.2 the app on vanilla | ~~#114~~ shipped |
| V2.3 retire the forcing env var | ~~#115~~ shipped |
| V5.4 / V8.1 cold create-from-image | ~~#101~~ **shipped** — the engine in #134/#135/#137, the app in #146 |
| V3 cloud contract / signing / postcopy | #21, #36, #5 |
| V4 security umbrella / defaults | #39, #20 |
| **V8 local MVP (V8.4–V8.7)** | #142, #143, #144, #145 |
| Deferred | #4, #6 |

The four pillars remain the capability contract (#21); a pillar is only "done"
when it holds for a **vanilla** snapshot on both substrates.

**Two release lines, deliberately.** *Gimbal Local* (V8) ships on the Mac alone
and is gated on nobody. *Gimbal* (V3/V6.4 — the cloud round-trip) is the larger
product and is gated on the control plane. Keeping them separate is what stops a
finished thing waiting on an unfinished one; it does **not** fork the codebase —
same binary, same engine, same invariants, one additive feature switched off.
