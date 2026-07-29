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
| `ID_AA64MMFR0/1/2_EL1` | `0x101125` / `0x10212122` / `0x100000000000011` | restored |
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

**In practice the exposure is narrow.** A stock arm64 Ubuntu image ships no
32-bit userspace and never execs one. 64-bit workloads are wholly unaffected.
But it is a real, reproducible, unrecoverable hang reachable from ordinary
unprivileged userspace, and it was invisible before this audit.

---

## Finding 2 — `CTR_EL0.DIC`: one bit, latent 🟡

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

**Stressed, and it did not fire.** In a rehydrated guest: `modprobe dummy` /
`rmmod` cycled three times, jump-label patching via
`/sys/kernel/tracing/events/sched/sched_switch/enable`, and 126 lines of ftrace
output captured — all clean, no fault, no `Oops`, guest healthy afterwards.

So this is recorded as a latent unsoundness rather than an active bug. Note that
guest **userspace** is not exposed at all: because `MIDR_EL1` is restored
faithfully, the guest applies Neoverse-N1 erratum 1542419, which traps EL0
`CTR_EL0` reads and hides `DIC` — so userspace JITs issue `ic ivau` correctly.
(That erratum handling is also why an in-guest EL0 read returns `0x9444c00a`
rather than the raw `0x9444c004`.)

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
| 2 | `CTR_EL0.DIC` | 🟡 Latent unsoundness in kernel code patching. Stressed without fault. Userspace unaffected. |
| 3 | `DCZID_EL0` | ✅ Identical. Hazard closed by measurement. |
| 4 | AArch32 ID block (20 regs) | ✅ Refused, harmless. |
| 5 | `REVIDR`/`CLIDR`/`CCSIDR` | ✅ Cosmetic. |
| — | `CNTFRQ_EL0` | ✅ Known; corrected at runtime (V1.2/V1.3). |
| — | all `ID_AA64*`, `MIDR`, `MPIDR` | ✅ Restored exactly — the reason this project works. |

## Reproducing

```console
$ chm sysregs snapshots/graviton-1              # the audit, with analysis notes
$ cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
      --test hvf_boot -- --exact hvf_host_cache_identity_registers --nocapture
```

The test reads `CTR_EL0`, `DCZID_EL0` and `CLIDR_EL1` from inside a minimal HVF
guest and asserts the *invariants this document's safety argument rests on* —
not the literal values — so a future Apple part with different cache geometry
fails loudly instead of quietly invalidating what is written here.
