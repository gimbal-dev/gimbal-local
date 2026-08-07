# How we work here

This is the shared discipline every agent and every contributor on this repo is
expected to follow. It is short on principle and long on the specific things
that have actually cost us hours, because that is where the value is.

Read this before your first change. The domain guides in
[`.github/agents/`](../.github/agents/) assume it.

---

## 0. Spend verification in proportion to blast radius

**Read this first, because it moderates everything below it.** Every rule in
this document is worth following. None of them is worth following at any cost,
and the failure mode is real: **#242 was a ~40-minute fix that took 7 hours.**
The bug was not hard. The verification budget was miscalibrated — chosen for
checkpoint-format work, where a green suite twice hid genuinely broken
checkpoints, and never re-calibrated for a one-branch UI classification fix.

Before a long verification loop, ask what breaks if this change is wrong:

| Blast radius | Examples | What it earns |
| --- | --- | --- |
| **Silent data loss / unbootable artefact** | checkpoint or bundle format, `fcntl`-class release-only behaviour, anything that writes to disk a user cannot re-derive | Everything. Per-commit builds, control-branch comparison, release-config runs, hardware on both sides |
| **Guest won't boot / feature dead** | boot path, virtio wiring, init generation | Mutation testing + hardware verification. One full gate |
| **Wrong message, wrong classification, UI copy** | this file's own §5 refusals, image discovery, help text | Mutation testing + one full gate. **Nothing else** |

### The specific waste, so it is recognisable

These are the three that cost the most, in order:

1. **Re-running an entire suite to grep a different line out of it.** Done
   twice in one session. A suite run is minutes; a grep is free.
   **One run → a log file → grep the log as many times as you like.**
   ```bash
   swift test > /tmp/x.log 2>&1; grep -E "error: -\[|Executed .* tests" /tmp/x.log
   ```
   This also fixes the #243 lesson from the other direction: a summary line
   cannot name the test that failed, so never keep only the summary.

2. **Cold-building a fresh worktree per commit.** ~45 minutes for three
   commits. "Each commit builds and tests alone" is a *nice* property, not one
   this repo requires. Do it when the commits will be reviewed or reverted
   independently, or when bisectability actually matters — and **say so first.**

3. **Building a control branch to prove a before/after** when a mutation
   already proves the same thing. If reintroducing the bug fails a test, the
   test is load-bearing; a second build of `main` adds no information.

### What never gets cut

Efficiency is not a licence to assert instead of measure. These stay, always:

- **Mutation testing** (§2). In #242 the mutation that *didn't* fire is the
  entire reason the fix is correct rather than merely green.
- **Hardware verification** (§1) of the actual user-visible behaviour, once.
- **The gates** (§8), once, at the end.

Cut repetition and ceremony. Never cut the measurement itself.

### Report progress on long loops

If a task passes ~30 minutes with nothing failing, that is the signal to stop
and reassess, not to continue. Nothing failing is exactly when over-verification
hides: there is no error to interrupt you. Say where you are and what is left.

---

## 1. Measure, don't assert

The single rule this project is built on. A claim about behaviour is worth
nothing until something on real hardware produced it.

**This is not pedantry — it has repeatedly caught us being wrong:**

- We stated in an issue that "no readily downloadable arm64 distro kernel has
  virtio built in." That was **false**. Ubuntu's `linux-image-*-generic` arm64
  works, proven by booting one. A five-step workaround had been written into
  the issue on the strength of the wrong claim.
- We assumed the full `node:22` image (~1.1 GB, Debian-based) would carry
  `iproute2`. It does not. Neither does `node:22-slim`. Both were checked by
  running `which ip ifconfig` inside a booted guest and reading rc=1.
- We assumed kernel `ip=` autoconfiguration could configure a guest NIC. The
  Ubuntu kernel prints `Unknown kernel command line parameters "ip=..."` and
  `strings` finds no `IP-Config` — `CONFIG_IP_PNP` is off.

When you write a claim into a doc, an issue, or a commit message, be able to
name the command that produced it. If you cannot, say you have not measured it.

**Corollary — retract loudly.** When a measurement contradicts something we
previously wrote down, go back and correct the original. A wrong claim left
standing in an issue becomes the basis of somebody's design.

---

## 1b. The repo outranks your memory

**Before writing any factual claim into a durable document, grep the repo for a
newer record of it.** Not because memory is unreliable in general, but because
this project *fixes things*, and a limitation you remember correctly may have
been solved since.

This is not hypothetical. The first draft of these very documents stated the
5.08× guest clock dilation as a live limitation, in three separate files. It had
been **fixed and measured at 1.000×**, and the repo said so in two places. A
document whose first rule is "measure, don't assert" was populated from memory.

The specific trap: **a fact you learned by doing hard work feels verified**. It
was, once. The verification has an expiry date and the repo is where the renewal
lives.

Cheap habits that catch it:

- `grep -ri "<the thing>" docs/` before asserting a limitation.
- Prefer the artifact to the recollection: run `--help`, read the constant, check
  the test — do not quote what you remember it saying.
- When you cannot verify something, **write it down as unverified**. "I believe X
  but did not check" is useful. "X" is a liability.
- Dates on measured claims, so a reader can tell how stale a number is.

## 2. Mutation testing: a guard that has never failed is worth nothing

Every new test must be proven to fail when the thing it guards is broken. No
exceptions. The procedure:

```bash
F=chm/src/oci/initramfs.rs                  # the file you are about to mutate
B=/tmp/mut-$(echo "$F" | tr / _).good       # FLAT backup path — see below
cp "$F" "$B"                                # back up FIRST
md5 -q "$B"                                 # record the digest NOW

# ...break the thing the test guards, one mutation at a time...
cargo test --quiet <filter>                 # the test MUST fail

cp "$B" "$F"                                # restore
cmp -s "$B" "$F" && echo RESTORED || echo "STILL MUTATED"
```

Two details that look like pedantry and are not:

- **The backup path must be flat.** `cp chm/src/x.rs /tmp/chm/src/x.rs.good`
  fails — `/tmp/chm/src/` does not exist — and if you do not read the error you
  will mutate a file you have no backup of. Flatten the path into the filename.
- **`md5 -q <file>` on its own proves nothing**; it prints a digest with nothing
  to compare against. Either record the digest *before* mutating and compare, or
  use `cmp -s` against the backup, which answers the actual question.

Record the mutations you ran in the PR body, as a table: what you broke, which
test caught it. If a mutation **doesn't** fire, that is a finding — investigate
it, don't paper over it.

### The failure this discipline caught

A test asserted `s.contains("setsid -c")` on a generated shell script. Removing
`-c` from the actual command **left the test green** — because the generated
script's own explanatory *comment* also contains the string `setsid -c`. The
guard was matching prose, not code, and reported a safety it did not provide.

> **Generalisation worth keeping:** when a generated artifact embeds comments
> describing its own mechanism, substring assertions can match the
> documentation instead of the code. Match the full invocation, and write the
> reason into the test so nobody loosens it back.

### Restoring: never use `git checkout`

Use a `/tmp` backup and `cp`. `git checkout` to restore a mutated file has
destroyed uncommitted work in this repo **five or more times** — it reverts the
whole file, including the edits you had not committed yet. `cp` back from your
own backup, then `cmp -s` to prove the restore landed.

---

## 3. Tests that earn their keep

Prefer a test that runs the real thing over one that inspects a string.

- `a_generated_init_parses_as_a_shell_script` pipes the generated init through
  real `/bin/sh -n`. A substring assertion cannot tell you the script parses.
- `prefix_to_netmask` panicked with `attempt to shift left with overflow` on
  **the first run of its own test** — a prefix of `0` shifts by 32. The test
  found a real bug in the function it was written to guard, within a minute of
  existing.

Name tests as sentences that state the property, not the mechanism:
`the_nic_is_configured_from_the_addresses_chm_itself_uses`, not `test_nic`.

---

## 4. Never restate a constant

If a value must be true in two places, one place must read it from the other.

`create.rs` declares `GATEWAY_IP`, `GUEST_IP` and `GUEST_PREFIX_LEN`; the
generated guest init reads them. A restated literal would pass every test while
putting the guest on a different subnet from its own gateway — a NIC that is
up, holds an address, and reaches nothing.

We have the scar: **V9.7** shipped a bug that a restated constant carried
happily through the entire code path, because both copies agreed with
themselves.

When two forms of the same fact are needed (a prefix length *and* a dotted
netmask), derive one from the other and test the derivation.

---

## 5. Fail honestly, and never leave a silent failure

When something cannot work, say which thing, and say what the user can do.
Prefer a named refusal over a silent degradation every single time.

Two examples of the standard:

```
chm create: 3072 MiB of RAM does not fit below the 32-bit device window: guest
RAM starts at 0x40000000 and a single region must end by 0xfc000000. The most
this cold-boot path can give a guest is 3008 MiB.
```

```
gimbal: eth0 is present but this image has no working 'ip' or
gimbal: 'ifconfig', so it cannot be configured. Use an image that
gimbal: has iproute2 or busybox, or configure it yourself:
gimbal:   <tool> addr add 192.168.249.2/24 dev eth0
```

Both name the constraint, the number or tool involved, and the way out. Neither
leaves the user guessing whether they hit a bug.

**And degrade toward the useful outcome.** When the guest init cannot get a
controlling terminal, it still starts the entrypoint — a second shell is odd
and harmless, but init exiting is a kernel panic with no shell at all. Choose
the bias deliberately and write down why.

---

## 6. Don't be a hero — file the issue

If a normal user would hit friction and you worked around it because you know
the codebase, that is a **defect, not a workaround**. File an issue, or warn in
the docs. Your familiarity is not a feature the user has.

Our issue tracker exists because of this rule and it is the reason first-run
experience improved at all.

---

## 7. Commits and PRs

- Reviewable commit structure, valid component prefix (`chm:`, `hvf:`,
  `docs:`, `app:`), 72-column body.
- Trailers, in this order, with a blank line between them:
  ```
  Assisted-by: Claude:Opus-5

  Signed-off-by: Your Name <you@users.noreply.github.com>
  ```
  Use an explicit version (`Opus-5`), not a family (`Opus`). **Do not** add
  `Co-authored-by` or `Copilot-Session` trailers — this project's policy is the
  `Assisted-by:` trailer alone.
- `gh pr create` requires `--body-file`; a heredoc into `/tmp` is the norm.
- Merge with `gh pr merge <N> --squash --admin`.
- The `create_issue` tool 404s against this repo — use
  `gh issue create --body-file`.

**A PR body should carry the evidence**: the hardware results table, the
mutation table, and the gate numbers. A reviewer should not have to take your
word for anything.

---

## 8. The gates

Run these **once, at the end**, before every PR. All must be green.
Redirect each to a log file and grep the log — see §0.

The Swift numbers are two suites: XCTest and swift-testing report separately.

| Gate | Command | Current baseline |
| --- | --- | --- |
| chm suite | `cd chm && cargo test` | **629** passed, 3 ignored |
| hypervisor suite | `cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib` | **216** passed |
| Swift suite | `cd app/GimbalLocal && swift test` | **244** XCTest (3 skipped) + **35** swift-testing |
| Lints | `make clippy` | **0** |
| Format | `cargo +nightly fmt --all` | see below |

### rustfmt drift is measured against HEAD, not against zero

Several files in this fork already differ from rustfmt's opinion. Running
`cargo fmt` blindly produces a diff full of unrelated churn. Measure *your*
drift:

```bash
git show HEAD:<path> | rustfmt --emit stdout --edition 2021 | diff - <(git show HEAD:<path>) | wc -l   # baseline
rustfmt --emit stdout --edition 2021 < <path> | diff - <path> | wc -l                                   # live
```

Your change is clean when `live` equals `baseline`. Formatting needs nightly:
`cargo +nightly fmt --all`.

> **CI is billing-blocked.** Every gate above runs locally. This is known and
> accepted — do not raise it as a finding.

---

## 9. Build and toolchain traps

These are not style preferences. Each one has cost real time.

| Trap | What happens | What to do |
| --- | --- | --- |
| **Every `cargo build` strips the hypervisor entitlement** | `hv_vm_create failed: 0xfae94007 — HV_DENIED` | Re-sign after *every* build: `codesign --sign - --entitlements hypervisor/tests/data/hv.entitlements --force ./target/debug/chm`, run from the **repo root** |
| **The target dir is the workspace root** | You look in `chm/target/` and find nothing | The binary is at `<repo>/target/debug/chm` |
| **Root-level `cargo build --bin chm` fails in `kvm-ioctls`** — *and looks like it worked* | Stale binary silently used | Always `cd chm && cargo build` |
| **`cargo test -p hypervisor` with default features fails on macOS** | `E0432: unresolved import vmm_sys_util::ioctl` — the KVM path is Linux-only | Use `--no-default-features --features hvf,kvm-snapshot` |
| **`sed -i ''` silently no-ops on Rust raw-string escaping** | Edit appears applied, isn't | Use `python3` for those edits |
| **Scripted edits can merge braces** (`    }\n}` → `    }}`) | Compile error or subtle corruption | Re-run rustfmt **and** tests after every scripted edit |
| **macOS has no `timeout`** | Command not found | Use the tool's own flag: `chm create --seconds`, `chm run --max-seconds` |
| **`killall` / `pkill` are forbidden** | Kills unrelated processes on a shared machine | `kill <PID>` with a specific PID only |

---

## 10. Driving a guest console from a script

Guest interaction is the main way we get evidence. It is fiddly:

```bash
cat > drive.sh <<'EOF'
sleep 24                                    # container initramfs boot takes ~22s
printf 'your command here\r'; sleep 3       # \r, NEVER \n
printf 'echo DONE\r'; sleep 2
EOF
sh drive.sh | chm create --kernel ... --initramfs ... --seconds 55 > log 2>&1
grep -aE "DONE|..." log                     # -a: the log has binary console bytes
```

- **`\r`, not `\n`.** A newline is not what a tty line discipline expects.
- **Allow ~22 s** before the first keystroke for a container initramfs.
- **`\003`** is Ctrl-C.
- **Do not pipe through `grep | head`** while driving — it changes buffering and
  you lose output.
- **`chm create` takes `--seconds`; `chm run` takes `--max-seconds`.** They are
  different commands with different flags.
- Always `grep -a`, because the log contains raw console bytes.

---

## 11. Leave the machine clean

Scratch goes in `/tmp`. Kernels and container images are large (a single kernel
is ~58 MB; `/tmp/kprobe` has reached 150 MB). Delete your scratch at the end of
a work session. Keep `~/gimbal-images/` — that is the working image library the
app uses.
