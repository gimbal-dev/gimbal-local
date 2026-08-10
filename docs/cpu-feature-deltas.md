# CPU feature deltas: what a Graviton guest still believes on Apple silicon

**Milestone V1.4.** Measured 2026-07-29 on an Apple M3, against the three vanilla
AWS Graviton2 captures in `snapshots/graviton-{1,2,3}`.

---

## Why this audit exists

A guest probes its host's identity and feature registers **once, at boot**, and
caches the answers — in kernel data structures, in cpu capability bitmaps that
get patched into the kernel's own instruction stream, in glibc's ifunc dispatch
tables. Rehydrating that guest somewhere else does not re-run those probes. If
the new host answers differently, the guest is running on beliefs that are no
longer true.

We were bitten by exactly this once already. `CNTFRQ_EL0` reads 121 875 000 Hz on
Graviton2 and 24 000 000 Hz on Apple silicon; Linux caches it at boot as
`arch_timer_rate` and never re-reads it; the result was a guest whose clock ran
**5.08× slow**. It was found by accident, months in.

`CNTFRQ_EL0` is not special. It is one register in a family, and the rest had
never been audited. This document is that audit.

## The mechanism that makes it invisible

`HvfVcpu::set_state` restores every system register except `MPIDR_EL1`
best-effort:

```rust
let _ = self.set_sysreg(id, v);
```

That is deliberate and correct — a register that is read-only on this core must
not abort an otherwise good restore — but it is **silent**. A value the capture
host chose is dropped with no diagnostic.

`chm sysregs` makes it measurable. It replays a capture's registers against a
real HVF vCPU and reports, per register, whether this Mac reproduces the captured
value, clamps it, or refuses it outright. The probe is non-destructive (each
register's pre-probe value is read back and rewritten) and runs against a VM with
**no guest RAM mapped**, so it completes in milliseconds.

```console
$ chm sysregs snapshots/graviton-1          # divergent registers only
$ chm sysregs snapshots/graviton-1 --all    # every register
$ chm sysregs snapshots/graviton-1 --json   # machine-readable
```

## The shape of the result

| | count |
| --- | --- |
| registers captured | 238 |
| **restored faithfully** | **105** |
| **refused by HVF** | **133** |
| clamped (write taken, reads back different) | 0 |
| …of the refusals, whose captured value was `0` | 46 |
| …so registers carrying real state that is lost | **87** |

HVF is binary about this: it takes a register or it does not. Nothing is
silently truncated.

### What is reproduced — and why the project works at all

Every AArch64 identity and feature register is restored **exactly**:

| register | Graviton2 value | fate |
| --- | --- | --- |
| `MIDR_EL1` | `0x413fd0c1` (Neoverse-N1) | restored |
| `MPIDR_EL1` | `0x80000000` | restored |
| `ID_AA64PFR0_EL1` | `0x1100000011111112` | restored |
| `ID_AA64PFR1_EL1` | `0x20` | restored |
| `ID_AA64ISAR0_EL1` | `0x100010211120` | restored |
| `ID_AA64ISAR1_EL1` | `0x100001` | restored |
| `ID_AA64MMFR0/1/2_EL1` | `0x101125` / `0x10212122` / `0x100000000000011` | restored — and `MMFR0` is [Finding 6](#finding-6--asid-width-unrelated-processes-share-tlb-contexts-) |
| `ID_AA64DFR0/1_EL1` | `0x10305408` / `0x0` | restored |

This is the finding that explains the whole project: **HVF genuinely lets us
spoof CPU identity.** A guest that booted on a Neoverse-N1 keeps believing it is
on a Neoverse-N1, with the same ISA and MMU features, which is why a Graviton
snapshot runs on an M3 at all rather than dying on the first unsupported
instruction.

---

## Finding 1 — 32-bit userspace wedges the vCPU 🔴

**This is the one that matters, and it is the inverse of the bug we went looking
for: the guest is not harmed by a register we failed to reproduce, it is harmed
by one we reproduced perfectly.**

`ID_AA64PFR0_EL1.EL0` (bits 3:0) says which execution states EL0 supports: `1` =
AArch64 only, `2` = AArch64 **and AArch32**. Graviton2's value is `2`, and HVF
accepts the write, so it is restored faithfully. Apple silicon implements **no
AArch32 at any exception level**.

The guest kernel latched `ARM64_HAS_32BIT_EL0` when it booted on Graviton, and
the captured guest kernel (`6.8.0-136-generic`) is built with `CONFIG_COMPAT=y`.
So it will happily
accept a 32-bit binary.

### Measured

A 96-byte hand-assembled static AArch32 ELF (`mov r7,#1; mov r0,#42; svc #0`),
executed in a rehydrated `graviton-1` guest:

```console
ubuntu@ch-snap:~$ /tmp/a32; echo A32_EXIT=$?
                       ← nothing. ever. no exit code, no error, no prompt.
```

The guest never executes another instruction. Every subsequent keystroke is
swallowed.

**Control** — a deliberately malformed ELF (32-bit class claiming `EM_AARCH64`)
that the kernel must reject before any AArch32 state is entered:

```console
ubuntu@ch-snap:~$ /tmp/ctl; echo CTRL_EXIT=$?
-bash: /tmp/ctl: cannot execute binary file: Exec format error
CTRL_EXIT=126
ubuntu@ch-snap:~$ echo CTRL_SURVIVED=yes
CTRL_SURVIVED=yes
```

So the wedge is specific to entering AArch32 state, not to malformed files.

**It is the vCPU, not the task.** Backgrounding the binary so the shell is not
blocked in `wait()` changes nothing:

```console
ubuntu@ch-snap:~$ /tmp/a32 & echo BG_STARTED=$!
[1] 1069
BG_STARTED=1069
ubuntu@ch-snap:~$
                       ← and that is the last thing the guest ever prints.
```

The mechanism is an illegal exception return: the kernel writes
`SPSR_EL1.M[4] = 1` to drop to EL0 in AArch32, and on a core that implements no
AArch32 that exception return cannot be architecturally completed.

### What we do about it

**Nothing can be fixed at rehydrate time.** Rewriting `ID_AA64PFR0_EL1` after
resume would change nothing — the capability was latched during the *capture
host's* boot, long before we saw the snapshot.

So `chm` warns at load, on both the CLI and daemon paths:

```
chm: warning: this snapshot's guest believes it can run 32-bit binaries, and
this Mac cannot. […] Measured on hardware: executing a 32-bit binary permanently
wedges the vCPU — the entire guest stops, not just that process, and it cannot
be recovered.
```

`CHM_STRICT_AARCH32=1` refuses to start instead, for anyone running unknown or
untrusted workloads.

### How reachable is it, really?

Asserting "a stock image never does this" is not evidence, so it was counted.
In a rehydrated `graviton-1` guest:

| measurement | result |
| --- | --- |
| ELF binaries under `/usr/bin /usr/sbin /bin /sbin /usr/lib` | **2382, all 64-bit** |
| …of which AArch32 (`ELF 32-bit`) | **0** |
| `dpkg --print-foreign-architectures` | **empty** — no `armhf` multiarch |

So there is not one 32-bit binary in the image, and `apt` **cannot** install one
without a deliberate `dpkg --add-architecture armhf` first. Every runtime a
coding-agent or CI workload would use on arm64 — Python, Node, Go, Rust, Java,
gcc — is 64-bit. Reaching this bug takes three deliberate steps that nothing
does by accident.

It is also **specific to Graviton2**. Neoverse-N1 implements AArch32 at EL0 and
Graviton2 enables it; later Neoverse cores (Graviton3/4) drop AArch32 entirely,
so a capture from those hosts would set `ID_AA64PFR0_EL1.EL0 = 1` and the
divergence would not exist. This is a legacy-silicon artifact, not a permanent
property of cloud captures.

**Verdict: real, unrecoverable, and effectively unreachable.** It stays warned
rather than refused because refusing would block every Graviton2 capture over a
hazard nothing triggers. `CHM_STRICT_AARCH32=1` is there for anyone running
genuinely untrusted guests who would rather not carry the risk at all.

It was worth finding regardless: it is a reproducible unrecoverable hang
reachable from ordinary unprivileged userspace, and it was invisible before this
audit.

---

## Finding 2 — `CTR_EL0.DIC`: one bit, and it breaks every JIT 🔴

`CTR_EL0` is refused by HVF, so the guest observes Apple's value. Reading it
required a three-instruction guest at EL1: macOS traps `mrs ctr_el0` from EL0
with `SIGILL`, and `hv_vcpu_get_sys_reg` returns `HV_BAD_ARGUMENT` for it. That
probe is now the `hvf_host_cache_identity_registers` test.

| field | Graviton2 `0xb444c004` | Apple M3 `0x9444c004` |
| --- | --- | --- |
| `DminLine` | 64 B | 64 B |
| `IminLine` | 64 B | 64 B |
| `CWG` / `ERG` | 64 B / 64 B | 64 B / 64 B |
| `L1Ip` | PIPT | PIPT |
| `IDC` | 1 | 1 |
| **`DIC`** (bit 29) | **1** | **0** |

**Exactly one bit differs.** Every field that governs cache-maintenance stride is
bit-for-bit identical, so all maintenance-by-VA loops in the guest step correctly.

`DIC = 1` means "instruction cache invalidation to the PoU is not required for
data-to-instruction coherence". The guest kernel read that at boot on Graviton
and **patched `ic ivau` out of `caches_clean_inval_pou`**. On Apple, where
`DIC = 0`, that is architecturally unsound — kernel-side runtime code patching
(module load, BPF JIT, ftrace, kprobes, static keys) could fetch stale
instructions.

**Stressed kernel-side, and it did not fire.** In a rehydrated guest:
`modprobe dummy` / `rmmod` cycled three times, jump-label patching via
`/sys/kernel/tracing/events/sched/sched_switch/enable`, and 126 lines of ftrace
output captured — all clean, no fault, no `Oops`, guest healthy afterwards.

That made it look latent. **It is not.** The elision was stressed from the wrong
side: the exposed caller is not module load, it is `__sync_icache_dcache()`,
which `caches_clean_inval_pou()` backs and which runs whenever **userspace**
makes a page executable. That is the JIT path.

### Measured 2026-08-03 — it bites userspace JITs

Guest userspace does read the register correctly, exactly as predicted below: an
in-guest EL0 read returns `0x9444c00a`, `DIC = 0`, because `MIDR_EL1` is
restored faithfully so the guest applies Neoverse-N1 erratum 1542419, traps EL0
`CTR_EL0`, and hides `DIC`. **Userspace being told the truth is not enough**,
because part of the maintenance is the kernel's job.

A four-way probe in a rehydrated guest, executing freshly written code and
checking whether the value returned is the one just written:

| probe | stale executions |
| --- | --- |
| same page, rewritten, no maintenance | 1997 / 2000 |
| same page, rewritten, explicit `ic ivau` | **0 / 2000** |
| **`mmap(RW)` → write → `mprotect(RX)` → call** | **955 / 1000** |
| same, plus explicit `ic ivau` | **0 / 1000** |

Row 3 is what every JIT does, and it is precisely the case
`__sync_icache_dcache()` exists to make safe; on a sound kernel it is 0. Rows 2
and 4 show the hardware and the EL0 maintenance instruction both work — only the
kernel's elided copy is wrong.

The user-visible symptom, on Node 22.23.2:

| command | result |
| --- | --- |
| `node --version` | `v22.23.2` |
| hot loop, 8 M iterations (TurboFan) | correct |
| 200 × `new Function` | correct |
| `npm --version` | **`Illegal instruction (core dumped)`, 2/15 runs** |
| `npm --version`, pinned with `taskset -c 0` | **10/15 runs** |
| `npm --version` under `node --jitless` | 0/15 |

**Re-measured 2026-08-08, and the rate above understates it badly.** The 2/15
figure was taken on a guest built for this investigation. On a plain rehydrated
`graviton-vanilla-2cpu-net` capture running Node 22.11.0 — the path a user
actually takes — `npm --version` failed **10 times out of 10**. Under
`NODE_OPTIONS=--jitless` the same command succeeded **5 times out of 5**.

| | rate |
| --- | --- |
| `npm --version`, untreated, rehydrated Graviton guest | **10/10 failed** |
| `npm --version`, `NODE_OPTIONS=--jitless` | **5/5 succeeded** |

So treat the intermittency in the table above as an artifact of one guest, not
as the expected experience: for Node tooling on a rehydrated capture, assume it
does not work until the JIT is off.

```sh
echo 'export NODE_OPTIONS=--jitless' | sudo tee /etc/profile.d/jitless.sh
```

That is the mitigation `chm`'s own warning now hands you, because it is the only
one that can be applied from inside the guest. It costs interpreter-speed
JavaScript, which for `npm install` and the Copilot CLI is a trade worth making.

Pinning making it **worse** is the confirmation: a cross-vCPU coherency problem
would improve when the work stays on one core. Staying on one core instead
maximises the chance that core's I-cache still holds the *stale* line, which is
the signature of missing invalidation rather than missing broadcast.

### Measured 2026-08-10, RETRACTED 2026-08-11 — "non-JIT workloads are unaffected" was wrong, and so was its replacement ⚠️

This section used to claim that DIC also explained the userspace crashes a
rehydrated guest suffers under ordinary IO load. **That attribution is false.**
The observation was real and is kept below because it is what led to the actual
root cause; the *explanation* is retracted, and the finding it belongs to is
[Finding 6](#finding-6--asid-width-unrelated-processes-share-tlb-contexts-).

The observation, unchanged. Load: four `dd`/`sync`/`rm` loops churning the page
cache, plus two spinners, on `graviton-vanilla-2cpu-net`. Cold-boot control: the
same script, same host, same `chm` binary, on a cold-booted guest.

| | cold-booted | rehydrated |
| --- | --- | --- |
| load average reached | **9.3** | 4.7 |
| crashes | **0** | **35** |

The crashes are not JITs and not one signal: `Segmentation fault` ×13,
`stack smashing detected` ×10, `Aborted` ×8, `Bus error` ×3,
`Illegal instruction` ×1. The victims were `rm`, `dd` and `sync`.

The reasoning that read this as DIC was: `__sync_icache_dcache()` runs on every
`execve` and every shared-library mapping, so a page written by the loader (or
recycled by the page cache) and then executed is the same hazard as a JIT
buffer. That is a true statement about the kernel and a false explanation of
these crashes.

#### Four measurements killed it

| # | Test | Result |
| --- | --- | --- |
| 1 | Perform the maintenance host-side for the guest (invalidate every DMA destination as virtio-blk completes), instrumented | **1,277,598 invalidations / 266 MiB** in one short run, and the crash count did not move |
| 2 | Prove the primitive rather than assume it: guest runs a routine, host overwrites it through the host mapping + `sys_icache_invalidate`, guest calls again | guest sees the **new** code — so the null in row 1 disconfirms the *hypothesis*, not the mechanism |
| 3 | Run the identical load entirely in `tmpfs` — zero virtio-blk data traffic | **27 crashes**. Removing the I/O path did not help |
| 4 | Re-run the cold-boot control with the *same* tmpfs load at load average **9.23** | **0 crashes** — so it is rehydration-specific, just not I-cache |

Row 2 is the one that makes the rest mean anything: without it, row 1 reads as
"the fix never reached the case" rather than "the hypothesis is wrong".

The signal composition argued against DIC all along and was misread: **18 of the
35 are glibc data-integrity aborts** (stack smashing, malloc tcache) and exactly
**1** is SIGILL. A stale instruction fetch presents as SIGILL. It does not
present as a valid, correctly-executed code path discovering that its stack
canary has been overwritten. That is memory belonging to another address space.

Also worth recording: **the cold-boot control in the original run was not a
control.** `agent-glibc4` is kernel + initramfs with **no disk**, so the
"cold boot crashes zero" figure was measured with the load writing to a RAM
filesystem and issuing zero virtio-blk requests. Row 4 above is the control that
should have existed.

#### What survives

- DIC is real, and the 955/1000 `mprotect(RX)` measurement above stands. It
  explains JIT and self-modifying-code failures — `npm`, Java, .NET.
- **`NODE_OPTIONS=--jitless` still does not cover a native binary**, for the
  reason given above.
- **Cold boot is still the only complete answer** for a rehydrated capture — now
  for two independent reasons rather than one.
- Nothing can be repaired at rehydrate time: the NOPs are baked into the kernel
  text inside the snapshot. `chm` warns at load and `CHM_STRICT_ICACHE=1`
  refuses (`icache_dic_guard`).

---

## Finding 6 — ASID width: unrelated processes share TLB contexts 🔴

**This is the cause of the crashes Finding 2 wrongly claimed.** It is the same
*class* of bug — a CPU feature the guest kernel latched at boot on the capture
host, faithfully restored, and wrong here — but a different register, and a
worse failure mode: it corrupts memory rather than killing a fetch.

### Measured

| | value | `ASIDBits` | width |
| --- | --- | --- | --- |
| Graviton2 capture, `ID_AA64MMFR0_EL1` | `0x101125` | 2 | **16-bit** |
| This Mac (Apple silicon) | `0xf100002` | 0 | **8-bit** |

The guest confirms it latched the capture host's width, in its own words:

```
$ dmesg | grep -i asid
ASID allocator initialised with 32768 entries
```

32768 = 2¹⁵, i.e. a 16-bit ASID space (bit 15 is the generation flag). A guest
booted on this Mac says `256 entries`.

The host's value could not be read with `hv_vcpu_get_sys_reg` — HVF refuses
`ID_AA64MMFR0_EL1` with `0xfae94003`, exactly as it refuses `CTR_EL0`, `DCZID`
and `CLIDR`. It was measured by executing a 7-instruction guest that `mrs`-es the
register and stores it to MMIO (`hvf_host_mmu_feature_register` in
`hypervisor/tests/hvf_boot.rs`, which pins this host at 8 bits so a future part
that changes it fails a test rather than passing a guard silently).

### Why it corrupts memory

The TLB tags each entry with the ASID of the address space that created it, and
compares **only the bits the hardware implements**. The guest allocates context
ids across a 16-bit space; the hardware compares 8. Two processes whose ASIDs
differ only above bit 7 — say `0x0142` and `0x0242` — are indistinguishable to
the TLB, so one can hit an entry created by the other and read and write its
pages.

It needs more than 256 live address spaces to bite, which is why an idle guest
looks perfect and a guest under fork pressure falls apart.

Kernel mappings are global (TTBR1, `nG = 0`) and carry no ASID, which is exactly
why **the guest never oopses while its userspace dies** — the observation that
made this look like a userspace-only problem such as a stale I-cache.

### What we do about it

`chm` warns at load (`asid_width_guard`); `CHM_STRICT_ASID=1` refuses to start.
There is no in-guest workaround: the width was latched before the snapshot was
taken, and lowering the process count reduces the collision rate without
removing it.

Two things fix it properly:

- **Cold boot.** The guest reads this Mac's own 8-bit width. Correct by
  construction.
- **A capture taken with the width already capped.** Route established
  2026-08-10 by reading Linux v6.8 — the capture guest's own kernel version —
  rather than by recollection:

  | route | verdict |
  | --- | --- |
  | `idreg-override` on the guest command line | **dead, twice over.** `id_aa64mmfr0` is not in the descriptor table in `arch/arm64/kernel/idreg-override.c` at all; and `get_cpu_asid_bits()` in `arch/arm64/mm/context.c` uses `read_cpuid()` — a raw `MRS` — which bypasses the sanitised registers the override mechanism feeds. |
  | `KVM_SET_ONE_REG` on `ID_AA64MMFR0_EL1` before the vCPU runs | **viable.** `ID_WRITABLE(ID_AA64MMFR0_EL1, …)` in `arch/arm64/kvm/sys_regs.c` masks out only `RES0` and the `TGRANx_2` fields, so `ASIDBits` is writable; `cpufeature.c` marks it `FTR_LOWER_SAFE`, so lowering `2 → 0` passes `arm64_check_features`. Needs host kernel ≥ 6.7, and a VMM that issues the write — cloud-hypervisor has no such path today (`vmm/src/cpu.rs` only *reads* the register, for the PA range). |

  Written up as a capture-side ask in
  [`graviton-capture-request.md` §13](./graviton-capture-request.md); tracked as
  issue #279. **It only ever applies to captures not yet taken** — every capture
  already held keeps its 16-bit belief permanently.

A runtime mitigation would mean trapping `TTBR0_EL1` writes and flushing the TLB
on every context switch. Correct, brutally slow, and not known to be expressible
under HVF. Unexplored.

---

## Finding 3 — `DC ZVA` block size: hazard closed ✅

`dc zva` zeroes the **hardware's** block regardless of what software believes. If
a guest cached a 64-byte block and the host's were 128, every `dc zva` in glibc's
`memset` would clobber 64 bytes past the intended range — silent memory
corruption. `DCZID_EL0` is not in the capture at all, so the guest's belief came
from Graviton and could not be checked against anything.

Measured directly on both sides:

| | `DCZID_EL0` | block | behavioural check |
| --- | --- | --- | --- |
| Apple M3 host (EL0) | `0x4` | 64 B | one `dc zva` zeroed exactly 64 bytes |
| rehydrated guest | `0x4` | 64 B | — |

Identical, and `DP = 0` so `DC ZVA` is permitted. **No exposure.**

Note that `hw.cachelinesize: 128` on macOS is *not* comparable — that is the
P-core L1 line, whereas `CTR_EL0.DminLine` is the minimum across all caches.
Comparing those two is how this started out looking like a bug.

---

## Finding 4 — the AArch32 ID block: refused, and harmless ✅

Twenty registers at `S3_0_C0_C{1,2,3}_*` — `ID_PFR0/1`, `ID_DFR0`, `ID_MMFR0-3`,
`ID_ISAR0-6`, `ID_MMFR4/5`, `ID_PFR2` — describe **AArch32** capabilities. HVF
refuses all of them, consistently with Apple having no AArch32.

Harmless in itself: a guest only consults them to decide what 32-bit userspace
can do, and per Finding 1 no 32-bit userspace can run here anyway. Listed for
completeness, and because 20 of the 22 non-zero identity-space refusals are these.

## Finding 5 — `REVIDR_EL1`, `CLIDR_EL1`, `CCSIDR_EL1`: cosmetic ✅

Refused. `REVIDR_EL1` is a silicon revision; the register that actually selects
erratum workarounds is `MIDR_EL1`, which is restored faithfully. `CLIDR_EL1` and
`CCSIDR_EL1` describe the cache hierarchy, but the geometry maintenance actually
uses comes from `CTR_EL0` (Finding 2), which matches.

---

## Summary

| # | Register | Verdict |
| --- | --- | --- |
| 1 | `ID_AA64PFR0_EL1.EL0` | 🔴 **Real bug.** 32-bit exec permanently wedges the vCPU. Warned at load; `CHM_STRICT_AARCH32=1` refuses. |
| 2 | `CTR_EL0.DIC` | 🔴 The guest kernel elided `ic ivau`, so JITs in the guest execute stale code (955/1000 measured). Warned at load; `CHM_STRICT_ICACHE=1` refuses. Cold boot is immune. **Scope narrowed 2026-08-11**: it does *not* explain the crashes under ordinary IO load — that is #6. |
| 3 | `DCZID_EL0` | ✅ Identical. Hazard closed by measurement. |
| 4 | AArch32 ID block (20 regs) | ✅ Refused, harmless. |
| 5 | `REVIDR`/`CLIDR`/`CCSIDR` | ✅ Cosmetic. |
| 6 | `ID_AA64MMFR0_EL1.ASIDBits` | 🔴 **Real bug.** Guest uses 16-bit ASIDs, this Mac compares 8, so past ~256 live address spaces unrelated processes share TLB entries and corrupt each other. 27-30 processes killed in 16 min vs 0 cold-booted. Warned at load; `CHM_STRICT_ASID=1` refuses. Cold boot is immune. |
| — | `CNTFRQ_EL0` | ✅ Known; corrected at runtime (V1.2/V1.3). |
| — | all `ID_AA64*`, `MIDR`, `MPIDR` | ✅ Restored exactly — the reason this project works. |

## Reproducing

```console
$ chm sysregs snapshots/graviton-1              # the audit, with analysis notes
$ cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
      --test hvf_boot -- --exact hvf_host_cache_identity_registers --nocapture
$ cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
      --test hvf_boot -- --exact hvf_host_mmu_feature_register --nocapture
```

The first test reads `CTR_EL0`, `DCZID_EL0` and `CLIDR_EL1` from inside a
minimal HVF guest and asserts the *invariants this document's safety argument
rests on* — not the literal values — so a future Apple part with different cache
geometry fails loudly instead of quietly invalidating what is written here. The
second does the same for `ID_AA64MMFR0_EL1`, pinning this host at 8-bit ASIDs;
both registers have to be read from inside a guest because
`hv_vcpu_get_sys_reg` refuses them.
