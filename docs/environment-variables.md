# The `chm` environment variables

`chm` has no debugger. You cannot attach `lldb` to a guest vCPU mid-flight: the
interesting state lives inside `hv_vcpu_run`, and the interesting failures are
things that happened forty milliseconds ago in another thread. So the diagnostic
surface is a set of `CHM_TRACE_*` switches that make the hypervisor narrate
itself, plus a smaller set of behavioural overrides for A/B-ing a suspected bug
against a known-good path.

This is not leftover scaffolding. The 5.08× guest clock dilation — the single
biggest bug in the project's history — was found by turning on `CHM_TRACE_EXIT`
and `CHM_TRACE_VTIMER` and reading the resulting stream. Each switch costs one
`env::var_os` at a cold-path boundary.

**None of these are needed to run a snapshot.** `chm run <dir>` needs no
environment at all. Everything below is for when something is wrong, or when you
are proving something is right.

---

## Tracing

Set any of these to any value (`=1` by convention) to enable. Output goes to
stderr, so `2> trace.log` separates it from guest console output.

| Variable | What it prints | Reach for it when |
| --- | --- | --- |
| `CHM_TRACE_EXIT` | Every vCPU exit: `[exit] t=<ns> vcpu N reason=R ec=0xEC pc=0x… ipa=0x…`. `reason=1` exception, `reason=2` vtimer; `ec=0x18` is an MSR/MRS trap, `ec=0x1` a WFI/WFE. | The guest is stuck and you need to know *where*. A healthy idle loop is a repeating `0x18, 0x18, 0x1 (WFI), reason=2 (vtimer)`. A tight non-WFI loop is a spin. |
| `CHM_TRACE_VTIMER` | Virtual timer arming and firing, plus the shared counter clock's stepper: steps taken/abandoned and the share of wall time spent stopped, every 5s. | Time in the guest is wrong — running fast, slow, or jumping — or the clock correction is costing more than it should. |
| `CHM_TRACE_VTIMER_WFI` | Every WFI park, with the guest counter and the timer deadline it parked against. | A guest that idles and never wakes. Very heavy: it perturbs the timing it observes. |
| `CHM_TRACE_ABORT` | Data/instruction aborts with the faulting IPA. | The guest touched an address the device model does not decode. Almost always a missing or misplaced MMIO region. |
| `CHM_TRACE_HVC` | Hypercalls (PSCI: `CPU_ON`, `CPU_OFF`, `SYSTEM_OFF`, …). | SMP will not come up, or the guest will not shut down. |
| `CHM_TRACE_MMIO` | Every virtio-PCI MMIO access — register, offset, value. | A device is being configured wrongly, or not at all. Verbose. |
| `CHM_TRACE_REDIST` | Every software-GIC redistributor access — which core, which frame, which offset. | A secondary core hangs during GIC discovery. Frames other than the running core's are normal: `gic_iterate_rdists` walks them all. |
| `CHM_TRACE_NOTIFY` | Virtqueue kicks from the guest. | The guest submitted work but nothing happened — this tells you whether it kicked. |
| `CHM_TRACE_DRAIN` | The device-side drain of a virtqueue. | You saw the kick (above) but the request was not serviced. |
| `CHM_TRACE_MSI` | MSI-X writes and their translation to interrupts. | Completions are not reaching the guest. |
| `CHM_TRACE_ITS` | GIC ITS command queue processing — `MAPD`, `MAPTI`, `INV`, `INT`. | LPI delivery is broken; a device's interrupt never arrives. |
| `CHM_TRACE_DEBUGREG` | Self-hosted debug system registers HVF does not implement (`OSDLR_EL1`, `OSLAR_EL1`, `OSLSR_EL1`, `DBGPRCR_EL1`), each as `[dbgreg] vcpu N read/write NAME val=0x…`. | A cold-booting guest dies in `debug_monitors_init` with `unhandled sysreg trap ESR=0x…`. Decode `ESR` bits [24:0] as op0/op1/CRn/CRm/op2 to name the register the guest wanted and we do not answer. |
| `CHM_TRACE_USGIC` | The userspace GICv3: distributor/redistributor register access, pending-state changes, injection. | The hardest class of bug in this codebase. Pair with `CHM_TRACE_EXIT`. |
| `CHM_TRACE_NET` | virtio-net frames in and out of the device. | Networking is silent. Confirms whether the guest is even transmitting. |
| `CHM_TRACE_NAT` | NAT flow decisions: connect/allow/deny, per-flow lifecycle. | Egress is being refused and you need to know by which rule — the reserved-address guard, the allow-list, or a connection cap. |
| `CHM_TRACE_INPUT` | Bytes written into the guest console. | Keystrokes are not reaching the guest. Distinguishes "not delivered" from "delivered and ignored". |
| `CHM_TRACE_WATCHDOG` | The run watchdog's liveness sampling. | A run is being killed and you want to see what the watchdog saw. |
| `CHM_TRACE_TIMING` | `[startup] <elapsed> <label>` for each startup phase. | Start-up is slow and you want the phase, not a guess. |

## Behavioural overrides

These **change what `chm` does**, so they are for bisecting a bug against a
known-good path, not for normal operation.

| Variable | Effect | Why it exists |
| --- | --- | --- |
| `CHM_DISABLE_SPI_1_OF_N_FALLBACK=1` | Disable 1-of-N SPI target-selection fallback. | Isolating an interrupt-affinity bug. |
| `CHM_SERIAL_SPI=<n>` | Override the serial console's SPI INTID. | A capture whose device/IRQ ordering differs from what we infer. |
| `CHM_GUEST_CNTFRQ=<Hz>` | Override the guest counter rate the VM-global clock synthesizes. | Not normally needed: a capture including upstream `69637dde6` records its own frequency and is corrected automatically. Set it for an older capture that records none, or `0` to decline the correction and accept the dilation. See [`hvf-compatible-snapshots.md`](hvf-compatible-snapshots.md#how-the-correction-works). |
| `CHM_VTIMER_STEP_MS=<ms>` | How often the shared counter clock steps forward (default 20). | Trades stop-the-world barrier overhead against the guest's worst-case clock error: 5 ms is 26.9% of wall time for 4 ms error, 20 ms is 2.8% for 16 ms, 50 ms is 0.8% for 40 ms. |
| `CHM_DEBUG_VTIMER=1` | One line per accepted offset step: host tick, curve target, old and new offset, and how far the guest's counter jumped. | Checking that the correction is stepping as expected. 50 lines/s at the default period — far lighter than it once was, when it sat on the guest-entry path. |
| `CHM_STRICT_CNTFRQ=1` | Refuse to run on a frequency mismatch instead of warning. | KVM's posture. We warn by default because a dilated guest is still useful; this opts into strictness. |
| `CHM_STRICT_AARCH32=1` | Refuse a snapshot whose guest believes it can run 32-bit binaries. | See [`cpu-feature-deltas.md`](cpu-feature-deltas.md) — such a guest wedges its vCPU if it ever execs one. Warn-only by default. |
| `CHM_STRICT_ICACHE=1` | Refuse a snapshot whose guest kernel elided `ic ivau`. | See [`cpu-feature-deltas.md`](cpu-feature-deltas.md) — a capture from `CTR_EL0.DIC = 1` hardware runs JITs that intermittently execute stale code (955/1000 measured). Warn-only by default; a cold-booted guest is immune. |
| `CHM_EAGER_RAM=1` | Populate guest RAM eagerly rather than mapping the snapshot file. | Ruling out a lazy-mapping interaction. Slower to start. |
| `CHM_NO_RAM_WILLNEED=1` | Skip the `madvise(MADV_WILLNEED)` prefault. | Measuring what the prefault is actually buying. |
| `CHM_FULL_BARRIER=1` | Opt back into the full media barrier on virtio-blk flush. | Comparing durability posture against throughput. |
| `CHM_RAW_CONSOLE=1` | Disable console filtering; pass guest bytes through untouched. | The filter is suspected of eating something. |
| `CHM_DISABLE_RUN_WATCHDOG=1` | Disable the run watchdog. | Long single-step debugging sessions the watchdog would otherwise cut short. |
| `CHM_FORCE_RESUME_ADVANCE_S=<n>` | Force the resume-time guest counter jump to `n` seconds instead of the real elapsed time. | Attributing a resume-time stall. The jump is normally a function of how long the checkpoint sat on disk, so waiting cannot separate "the jump was large" from "a lot of time passed"; this varies one and holds the other. |
| `CHM_ALLOW_OVERLAY_DRIFT=1` | Resume even though the disk overlays changed after the checkpoint's RAM was captured. | Deliberately pairing a remembered filesystem with a different one. Expect the guest to wedge — see below. |
| `CHM_MAX_RESUMABLE_REVISIONS=<n>` | How many checkpoint revisions stay resumable before older ones are pruned. | Each revision carries a complete RAM image, though consecutive ones share most of their extents (V9.1a), so the incremental cost is a measured 2–13 MiB rather than the 2.8 GiB the image measures. Shared extents are only freed when the last revision using them goes, so this still bounds the store — see `chm revisions <dir> --usage`, which reports what deleting a revision would actually reclaim. Pinned revisions (`chm revisions <dir> pin <id>`) sit outside this budget, so pinning one does not shorten the window of recent history. |
| `CHM_SNAPSHOT_INTERVAL_SECS=<n>` | Checkpoint the *running* guest every `n` seconds, without stopping it. Off by default. | Long agent sessions, where a session that ends badly should not be a session whose work is gone. Each checkpoint freezes the guest while it captures RAM — **measured 0.9–2.1 s for a 2 GiB guest on an M-series Mac**, costing 2–13 MiB of disk, since V9.1a writes each snapshot as a delta against the last. `chm` reports the freeze it actually measured every time, so the interval is a trade you make on your own numbers. See `docs/continuous-snapshots.md`. |

### Why overlay drift is refused rather than warned about

Guest RAM holds the kernel's page cache, inode cache and journal head for the
filesystem it had mounted. Resume restores that RAM but reattaches whatever the
overlay holds **now**, so a session that writes to disk and exits *without*
`--checkpoint` leaves the next resume describing blocks that have moved.

The failure is not a clean error. The guest comes up, serves RAM-only work
normally, and then wedges the first time it touches the diverged part of the
tree — `rcu_preempt kthread timer wakeup didn't happen for 60006 jiffies`, then
silence. It is also self-perpetuating: capturing at teardown writes that *hung*
kernel over the last good checkpoint, so every later resume starts wedged. That
is why the check refuses up front instead of warning and continuing.

## Policy and control-plane bindings

These are **not** debug switches. They carry configuration, usually set by the
runner or an operator. See [`security-model.md`](security-model.md) §1a for the
default posture.

| Variable | Effect |
| --- | --- |
| `CHM_LIMITS` | A JSON limits document, or `none` to opt out of the default ceilings entirely. Highest precedence after `--limits`. |
| `CHM_EGRESS_POLICY` | A JSON egress-policy document handed down by the control plane. Overrides the workspace `egress-policy.json`. |
| `CHM_ALLOW_LOCAL_EGRESS=1` | **Weakens I10.** Lets the guest reach loopback, your LAN, link-local and `169.254.169.254`. Only for deliberately testing against a local service. |
| `CHM_TRUST_STORE` | Path to the trusted public keys used to verify a signed snapshot manifest. |
| `CHM_REQUIRE_SIGNED=1` | Fail closed: refuse any bundle that cannot be signature-verified. |
| `CHM_RUNNER_CACHE` | Base directory for the runner's content-addressed bundle cache. |
| `CHM_PROXY_RULES` | Credential-proxy rules: either a path to a JSON document or the document itself, so a launcher holding rules in memory need not write them to disk. Overrides `<workspace>/proxy-rules.json`. See [`credential-proxy.md`](credential-proxy.md). |
| `CHM_PROXY_CA_BUNDLE` | Path to the PEM trust anchors the proxy verifies *origins* against. Defaults to `/etc/ssl/cert.pem` (128 roots). This never affects what the guest trusts. |
| `CHM_PROXY_LOG=1` | Print every proxy decision — injected, relayed, or failed — to stderr as it happens. Not a debug-only switch in spirit: it is how you see what a job actually reached. |

`chm posture <workspace>` prints which of the policy variables are in effect and
what they have done, so you do not have to reason about precedence by hand.

---

## Worked example: a guest that will not boot

```console
$ CHM_TRACE_EXIT=1 CHM_TRACE_ABORT=1 chm run snapshots/foo 2> trace.log
$ tail -20 trace.log
```

Read the last few exits before it stopped.

- Repeating `ec=0x1` (WFI) with `reason=2` (vtimer) between them — **that is a
  healthy idle guest**, not a hang. It is waiting for input. Press return.
- The same `pc=` over and over with no WFI — a spin. Something the guest is
  polling for is never becoming true; usually an interrupt that was never
  delivered, so add `CHM_TRACE_USGIC=1` or `CHM_TRACE_ITS=1`.
- An abort at an `ipa=` outside every device window — the guest is touching an
  address the device model does not decode.
- Exits stop entirely — the vCPU is wedged rather than looping. If the guest just
  ran a 32-bit binary, see [`cpu-feature-deltas.md`](cpu-feature-deltas.md).
