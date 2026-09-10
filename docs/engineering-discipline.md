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

### 1c. A fact about the outside world cannot be guarded from inside the repo

The rule above says to date a measured claim. This is what to do when dating it
is not enough, because the claim is about something that changes without anyone
touching the repo.

`docs/project-state.md` carries a grouped list of every open issue. That is an
assertion about GitHub, so no `cargo test` can check it. It rotted twice:

- [#368](https://github.com/gimbal-dev/gimbal-local/issues/368) was filed when a
  hand-built list had gone **completely** stale — every issue on it had closed.
- The refresh that closed #368 rotted in turn. Measured 2026-09-08: of the 31
  issues it named, **12 were closed and one open issue was missing**. 42% wrong,
  in 19 days.

The second rot is the instructive one. **The page was internally consistent the
whole time** — it claimed 31 and listed 31, every link well-formed, every group
sensible. Any checker that stayed inside the repo would have passed it, on every
run, while it decayed.

> **Generalisation:** *internal consistency is not truth. A document that
> asserts something only an external system knows needs a checker that leaves
> the repo and asks, and it needs to be a gate rather than a habit — because the
> first refresh was done carefully by someone who knew all this, and it rotted
> anyway.*

The shape that works here is a pair, and both halves are needed:

| Half | Where | Catches |
| --- | --- | --- |
| Ask the outside world | `scripts/check-docs.sh`, wired to `make check-docs` | The list disagreeing with GitHub |
| Keep the asker aimed | `hygiene.rs::the_state_page_still_matches_the_checker_that_sweeps_it` | The page being reformatted so the checker silently sweeps the wrong region |

The second half is easy to skip and is the one that fails quietly. A checker
that navigates a document by literal headings stops checking the moment those
headings move, and it keeps exiting 0 while it does. So the guard reads the
checker's own needles out of the script rather than restating them, which makes
editing either file alone a failure.

Note also what the checker does when it **cannot** reach GitHub: it exits `2`,
distinct from `1` for real drift. A checker that reports success because it
could not run is the silent failure of §5 wearing a green tick.

**The same rot lives in `.github/agents/*.md`, in a different shape.** Those
files carry per-issue status rows — a table naming an issue and marking it
`Open`. An audit on 2026-09-08 found **ten wrong across six of the eight
files**, and the damage is worse than a stale list: the agent file told a
reader to plan around defects that had already been fixed, so the reader
designs a workaround for a bug that no longer exists. `check-docs.sh` now
checks those rows against GitHub too, and refuses (exit 2) if the agents
directory ever moves out from under it.

**Aim an external checker with a narrow needle, and measure the false
positives before you keep it.** The first version of that status check matched
any line pairing an issue number with the word `Open`. It immediately produced
**eight false positives** in `docs/roadmap.md`, where `Open` belongs to the
**Open terminal** button name and is not a status at all. Tightened to a table
*cell* — `| Open` — it matched exactly the three genuinely stale rows and
nothing else.

> **Generalisation:** *a guard that cries wolf on correct prose gets switched
> off, so a needle's false-positive count is part of whether it works, not a
> detail. Measure it against both a known-bad tree and the known-good one.*

The same reasoning splits the gate-count guard in two. `docs/` keeps narrative
history — "827 tests stayed green", "all 514 tests pass" — which is a record of
a past measurement and must not be flagged, so there the needle is a **bolded**
count. The agent files keep no such history and restate counts as comments on
commands (`swift test # 216 passing`), so there the needle is looser. One
needle across both trees cannot be right.

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

### Mutating a function is not mutating its call site

**Nine recorded instances in this repo**, and the most expensive of them was the
product's own entry point: `chm vanilla export A B` printed usage and refused
*every time it had ever been run*, while 827 tests stayed green — because every
test called the exporter directly and nothing crossed the argument parser.

An assertion about an outcome is structurally blind to a path that is no longer
taken. So the mutation that matters is often not "break the function" but
**"stop calling it"**:

```rust
install_modules(&mut rootfs, None)?;   // was: bundled.as_ref(), image.rs:774
LocalImage.scan(root:, probeKernel:)   // Swift: hand it a stub prober
```

Prefer making the mutation *impossible* over catching it. Both of these are
better than another guard:

- **Remove the default argument value.** A parameter defaulting to `0` or `nil`
  lets a dropped call site compile; without the default it is a compile error.
  `LocalImage.scan` (`LocalImage.swift:212`) takes `probeKernel` with **no**
  default for exactly this reason. Note that its neighbour `classify` keeps one
  — it is a pure function over explicit inputs, so a stub there is a legitimate
  test affordance rather than a dropped production path. The rule is about the
  call site that ships, not about defaults in general.
- **Change the arity.** `hypervisor/src/compat.rs:60` declares `fcntl`
  variadic; reverting it to a fixed third parameter is now `E0061`, because the
  guards at `:287` and `:296` call it with two arguments. That declaration is
  load-bearing: on Apple arm64 a variadic argument goes on the stack while a
  fixed one goes in a register, so the wrong shape silently never set
  `O_NONBLOCK` and hung every release build.

Where neither is available, add a source-reading guard that pins the call site —
and know that it covers something different from the outcome tests. That is what
a mutation pair proves: break the function and the outcome tests fire; break the
call site and only the source guard does.

#### One of N call sites can be unreachable from your fixture

The refinement that cost a real hole in a real guard. `checkpoint::rollback`
calls `archive_head` **twice**: site 1 runs only when the rollback target *is*
HEAD, site 2 on the ordinary path. The guard rolled back to HEAD, so it
exercised site 1 and could never reach site 2 — and site 2 is the one that
matters more, because its very next statement is `copy_tree(&target, &dir)`,
which overwrites the HEAD that just failed to be preserved.

Mutation reported it: ignoring the failure at site 2 left the suite green.

> **Generalisation:** *"the guard drives the function" is not the same claim as
> "the guard drives this call to the function". Count the call sites, then ask
> which one your fixture can actually reach.* The cure was a second guard whose
> fixture writes two checkpoints, so the older is archived and the newer is
> HEAD, which reaches site 2 exclusively.

#### A fixture that does not create the failure it names

Sibling failure, same investigation. `archive_head` had two error arms, one for
`fs::rename` and one for `fs::create_dir_all`, each with its own delete. The
guard failed the rename by setting the store to mode `0500`, and reported the
`create_dir_all` delete as covered. It was not:

**`fs::create_dir_all` succeeds on a directory that already exists, whatever its
mode.** The second arm was never entered, so mutating it was silent.

> **Generalisation:** *a fixture is a claim that a specific failure happens. If
> you have not seen the error, you have not established the arm is reachable —
> you have established that the test passes.* The cure was to loop the guard
> over both arms, the second making the store path a **regular file** so
> `create_dir_all` genuinely fails.

### A guard whose body recomputes the answer cannot fail

The strongest lesson on the vanilla-export stream, and the hardest to see by
reading.

`the_exported_counter_advances_at_the_guests_frequency` restated the product's
arithmetic in the test body and asserted against its own restatement. The
function it named was **never called**. Four independent defects left it green.

> **Generalisation:** *a test that recomputes the value it is checking is a
> mirror of the product with none of the product's code in it — it agrees with
> itself in every world.*

The cure is three things together, and dropping any one of them brings the
mirror back:

1. **Drive the real function.** If the function's name does not appear as a call
   in the test body, the test is about arithmetic, not about the product.
2. **Choose the inputs independently.** Inputs derived from the same expression
   as the expectation are the mirror wearing a disguise.
3. **Source the constants from the committed fixture**, never retyped. See §4.

### A source-reading needle can silently relocate

The sharper version of the same family. A guard that reads its own file with
`include_str!` and navigates by `split(needle).nth(1)` is only correct while the
occurrence it means is the one it lands on. Both halves of that can move:

- **The needle can match itself.** A file that reads its own source contains the
  assertion text too, so the literal in `split("…")` is one of its own matches.
  Assemble the needle from parts — `format!("let mut tally = {}::default();",
  "EgressTally")` — so it cannot.
- **The needle can occur in the test module.** A production line and three test
  uses of the same string means `.nth(1)` is correct *only* because production
  happens to come first. Rename or move the production line and the guard
  silently starts inspecting test code, with the suite still green — it reports
  on a region that is not the one it names.

The cure is an assertion, not a cleverer search:

```rust
let spawn = format!("let mut tally = {}::default();", "EgressTally");
assert_eq!(
    src.matches(&spawn).count(), 1,
    "…or this guard reads a region that is not the loop"
);
let body = src.split(&spawn).nth(1)…
```

That fails loudly in **both** directions: an occurrence removed from the site
that matters, and an occurrence added somewhere that does not.

> **Generalisation:** *a needle appearing in more than one place cannot detect
> its removal from the one that matters.* Uniqueness is part of the guard, so
> assert it.

The same guard has a second failure mode once you *bound* the region it reads.
Narrowing a whole-file scrape to "the dispatch table only" is usually right — it
is how you stop a guard false-positiving on unrelated code — but a bounding bug
that closes the region early leaves the guard reading a prefix of what it names,
silently.

> **Generalisation:** *a source-reading guard is only as good as the region it
> reads.* Mutate at **both ends** of that region, not just in the middle. A
> mid-table mutation fires whether the bound is right or wrong; only a mutation
> against the **last** entry can tell you the region reaches the end.

### Reading a mutation result: SILENT has three causes, not one

A mutation that does not fire is a finding. But it is not automatically a hole
in the guard, and treating it as one sends you rewriting a test that was fine.
Ask these in order, because the first two are cheaper and more common:

1. **Did the mutation apply?** `str.replace` no-ops on an absent needle. Worse,
   `replace(old, new, 1)` applies to the *first* occurrence only. A guard here
   reported SILENT because its needle appeared **five** times in the file and
   only one was mutated; the assertion under test still saw an intact copy.
   Make the harness print the occurrence count and assert it changed.
2. **Did the guard run?** A `cargo test` filter list that does not name the test
   reports a clean run and a green suite. That happened here: the cycle-guard
   mutation looked fire-proof for a whole cycle because the filter never
   selected it. Print the test count, and check the mutation run selected what
   you think it selected.
3. **Only then: is the guard weak?** If the mutation truly applied and the guard
   truly ran, now you have a finding worth acting on.

> **Generalisation:** *SILENT is a claim about your harness before it is a claim
> about your test.* Two of the three causes are in the tooling.

**And FIRES has causes too — check the failure is the one you provoked.** A
mutation of `scripts/check-docs.sh` was run by copying the script to `/tmp` and
editing the copy. It exited `2`, which is what the guard under test should
produce, so it looked proven. It was not: the script derives `ROOT` from its own
location, so from `/tmp` it had failed much earlier, on `cannot read
//docs/project-state.md`, and never reached the new code at all. **Read the
failure message, not just the exit status**, and mutate in place with a backup
rather than in a copy that changes the program's idea of where it lives.

### A hang is the fire, and it has to be timed out to be seen

Not every broken guard fails an assertion. `ChmClient.runRaw` waited on the
child process before draining its pipe; a reply larger than the ~64 KiB pipe
buffer blocks the child on write and the parent on wait, and neither moves
again. Reverting the fix does not turn the suite red. The suite **never
returns** — the first such run held the tool for 500 s and had to be killed.

A harness with no timeout cannot distinguish "the guard did not fire" from "the
guard is still running", so it will eventually record the wrong one:

```python
try:
    r = subprocess.run(CMD, cwd=..., capture_output=True, text=True, timeout=180)
except subprocess.TimeoutExpired:
    restore()
    print(f"{mid}: TIMED OUT after 180s -- FIRES (deadlock: the test never returned)")
```

> **Generalisation:** *for anything with a pipe, a lock, or a wait in it, the
> expected fire is a timeout, so the harness needs a deadline before it can
> observe one.*

Stranded children clean themselves up here, which is worth knowing before you
go hunting: when the killed test process drops the read end of the pipe, the
blocked writer takes `SIGPIPE` and dies. Measured `0` leftovers afterwards.

### An assertion implied by a stronger one cannot fail

Found by mutating this repo's own doc guard.
`the_state_page_still_matches_the_checker_that_sweeps_it` opened with
`doc.contains("scripts/check-docs.sh")` and closed with
`doc.contains("`./scripts/check-docs.sh`")`. The second needle *contains* the
first, so the first could never fail while the second passed. It read like two
checks and was one, and the mutation that should have caught it was silent.

> **Generalisation:** *when two assertions in the same test check needles where
> one is a substring of the other, the looser one is decoration.* Delete it, or
> make it check something the stricter one does not. Leave a comment saying
> which, or it will be added back as an "obvious" safety net.

### A test producer whose own length surprises you

The megabyte guard for the pipe deadlock first failed at `1048577 != 1048576`.
The product was correct — a full megabyte arrived where 65536 used to. The
**test's own data generator** was wrong: `printf 'x%.0s' $(seq 1 1048576)` emits
one byte more than its argument count at that size, though it is exact at 10.

Replaced with `head -c 1048576 /dev/zero | tr '\0' x`, which is exactly the
requested length.

> **Generalisation:** *a producer whose own length is a surprise is no way to
> measure somebody else's read.* When a test that measures a size is off by a
> small amount, suspect the fixture before the product, and measure the fixture
> on its own.

### A mutation harness with hardcoded backup paths goes stale

A helper script that restores from fixed paths (`/tmp/create.rs.good`) is
restoring whatever was there when you *last* refreshed it — which silently
reverts every edit you have made since. Re-copy the backups immediately before
any mutation run, and check the digests. A harness that quietly undoes your work
is worse than mutating by hand.

Two more one-liners that have each cost a run here:

- Prose **wraps.** A guard reading a `.md` file must flatten whitespace before
  searching, or a reinstated claim that happens to break across a newline sails
  straight past the substring search.
- **`sed -n 'l'` inserts its own line-wrap backslashes.** It wraps at the
  terminal width and marks the wrap with a `\`, which is indistinguishable from
  a `\` that is really in the file — and in Rust source, trailing backslashes
  are load-bearing. Three needle attempts were built here against a line
  splitting that did not exist. **Read exact line content with `python3` and
  `repr()`**, which settled the same question in one command.

### Restoring: never use `git checkout`

Use a `/tmp` backup and `cp`. `git checkout` to restore a mutated file has
destroyed uncommitted work in this repo **five or more times** — it reverts the
whole file, including the edits you had not committed yet. `cp` back from your
own backup, then `cmp -s` to prove the restore landed.

---

## 2b. Enforce the rule, don't only write it down

The rule about `git checkout` was already in this document, in bold, with the
count of times it had destroyed work. It went on destroying work. A rule an
agent has to remember is a rule an agent can forget, and a document that is
read once at session start competes with everything that arrives afterwards.

So the rules that have actually cost time here now live in `.github/hooks/`,
where the runtime enforces them. `.github/hooks/README.md` describes each one.
The short version: the harness refuses `git checkout` of a path, `git restore`,
`git reset --hard`, `git clean -f`, `pkill`, `killall`, and
`cargo fmt --check <path>`; it asks before a mutating AWS command; it asks for a
rubber-duck pass after a compaction; and it refuses one stop when source files
changed and no gate command ran.

### The contract, measured rather than read

Every claim below came from running a real session against Copilot CLI 1.0.74
on macOS and reading what happened, not from documentation:

- Repo hooks load from `.github/hooks/*.json`, and only after folder trust. In
  prompt mode they additionally need `GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS`.
- `preToolUse` receives `toolArgs.command`. Returning
  `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` blocks the
  command and hands the reason to the agent word for word.
- `agentStop` returning `{"decision": "block", "reason": "..."}` refuses the
  stop and makes the agent continue.
- `sessionStart` and `postToolUse` returning `{"additionalContext": "..."}`
  reach the model.
- Hook commands run in the session directory, so scripts must be located with
  `git rev-parse --show-toplevel`, not a relative path.

To test a hook change without touching your own configuration, point
`COPILOT_HOME` at a throwaway directory whose `config.json` trusts this repo.

### What makes an enforced rule survive contact

- **Fail open.** A `preToolUse` hook that errors denies the tool call, so a
  crash in a guard script blocks every command the agent tries. Every script
  here prints `{}` and exits 0 on any failure path. The completion gate does the
  same: a malformed payload lets the agent stop. A gate that can trap the agent
  is worse than no gate.
- **Block once.** The stop gate refuses a single stop per session and never
  fights a forced continuation. The runtime gives up after eight consecutive
  blocks anyway; a gate that has to be overridden is a gate that gets deleted.
- **Count the false positives, in a table.** Each script carries a case list of
  inputs it must act on *and* inputs it must ignore, run by `make check-harness`.
  The `git clean` rule matched `git clean --dry-run` on its first run, because
  `--dry-run` contains a `-d`. Only the quiet cases could have found that.
- **Say where the instruction comes from.** Context injected through
  `additionalContext` arrives inside a tool result, which is exactly where a
  prompt injection would arrive. A test notice that told the agent to repeat a
  passphrase was correctly refused as an injection attempt. Notices must name
  the file they come from and the reason they exist, or a careful agent will
  ignore them and an incautious one will obey anything.
- **Check the mechanism with something only the mechanism does.** The obvious
  way to ask whether the harness is live is to try a `git checkout` of a path
  and see it refused. That check passes with the harness switched off, because
  the rule is in this document too and the agent refuses on its own judgement.
  Measured: a worktree with no `.github/hooks` at all still refused it. Use
  `cargo fmt -- --check <path>` instead, which an agent has no reason to
  refuse, and look for the literal words `Denied by preToolUse hook`. When a
  rule is written down *and* enforced, an observed refusal does not tell you
  which one acted. Pick a probe the prose does not cover.

The same principle covers the procedures rather than the prohibitions:
`.github/skills/` holds `mutation-proof`, `measure-formatting-drift`, and
`ship-a-change`, so the recipe is loaded when it is needed instead of being
remembered from a document read an hour earlier.

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

| Gate | Command |
| --- | --- |
| chm suite | `cd chm && cargo test` |
| hypervisor suite | `cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot --lib` |
| Swift suite | `cd app/GimbalLocal && swift test` |
| Lints | `make clippy` |
| Docs | `make check-docs` |
| Format | `cargo +nightly fmt --all` |

**The expected counts are deliberately not written here.** They live in one
place, the gate table in
[`project-state.md`](project-state.md#the-gates-and-their-current-numbers), for
the reason given in §4: a number restated in a second file goes stale in the
second file. This table used to carry its own baseline and it did exactly that
— it still read `629` / `216` / `244` when the suites were at `1111` / `343` /
`273`, which is not a harmless slip. A newcomer comparing a real run against a
stale baseline concludes they have broken something, or "fixes" a regression
that never happened.

Compare your run against `project-state.md`, and if it disagrees, work out which
of the two is wrong before you change any code.

### Debug is not evidence about release

Every gate above is a **debug** gate. That is a real limitation, not a
technicality: the first signed release **hung on every boot**, and correct
tests for the behaviour existed and passed the whole time — in debug, where
the garbage `fcntl` read off the stack happened to be a zero.

| `fn fcntl(fd, cmd, arg: i32)` | result |
| --- | --- |
| `opt-level=0` | `flags=0x0` — benign, tests pass |
| `opt-level=s` | `flags=0x4000c0` — garbage, every vCPU parks |

```bash
make test-release      # chm + hypervisor + app, all in release
```

Run it **before any milestone that claims a gate**, not only before a release.
Finding a release-only failure at release time is the worst possible moment:
highest pressure, least slack. `scripts/release-macos.sh` runs the same suites
itself, so a release still cannot ship on debug-only evidence.

Green in release as of 08-07: chm **629**, hypervisor **216**, app **244**
(#214).

### rustfmt drift is measured against HEAD, not against zero

Several files in this fork already differ from rustfmt's opinion. Running
`cargo fmt` blindly produces a diff full of unrelated churn. Measure *your*
drift by stashing, so both sides are produced by the identical command:

```bash
cargo +nightly fmt --all --check | grep -c '^[+-]'   # live
git stash -q && cargo +nightly fmt --all --check | grep -c '^[+-]' && git stash pop -q   # baseline
```

Your change is clean when `live` equals `baseline`. To find *which* lines are
yours, save both diffs and compare their sorted `^[+-]` lines.

**Do not measure this per file with a bare `rustfmt <path>`.** Two traps, and
the second is silent:

- **`cargo fmt -- --check <path>` does not check `<path>`.** `cargo fmt`
  formats the package's own targets and passes the trailing arguments to
  rustfmt, so the path you named is simply not what gets examined. It exits 0
  and prints nothing, which reads exactly like "no drift". Measured: a file
  deliberately mangled to `fn f(){let _x=1;` scored **0** through
  `cargo +nightly fmt -- --edition 2024 --check <path>` and **10** through
  `rustfmt` invoked directly on the same file. A whole drift measurement was
  taken and believed on the strength of that zero. If you want one file, invoke
  `rustfmt` itself.
- `--edition 2024` is required. Under an older edition the parse differs and so
  does the verdict.
- **rustfmt formats submodules too.** Point it at a file with `mod foo;`
  declarations — `hypervisor/src/hvf/mod.rs` is the obvious one — and the output
  covers the whole subtree, so the count is not about your file at all. Stable
  rustfmt rejects `--skip-children` outright (`Unrecognized option`) *after* you
  have already believed a number. Nightly accepts it, but only together with
  `--unstable-features`; **without that flag rustfmt errors out and `| wc -l`
  then counts the error message**, returning 1 on both sides of a comparison and
  reporting a clean result for anything.

  ```bash
  rustfmt +nightly --unstable-features --skip-children --edition 2024 --check <file>
  ```

- **The baseline must live inside the tree.** `.rustfmt.toml` sits at the repo
  root and rustfmt discovers it by walking up from *the file's own location*, so
  a HEAD baseline written to `/tmp` is formatted under rustfmt's defaults while
  the live file is formatted under this repo's `group_imports` and
  `imports_granularity`. Measured: the byte-identical `chm/src/firewall.rs`
  scored **39 in place and 25 as a `/tmp` copy**. Both settings are
  import-related, which is why the manufactured hunks are always `use std::…`
  regrouping at the top of a file — a long way from wherever you edited.

  Write the baseline somewhere like `chm/src/.fmtbase/` so it discovers the same
  config, and delete it before committing. Note that scratch `.rs` files left
  inside `chm/src` are picked up by `hygiene.rs`, which scans that tree.

  This one is worth being loud about: a baseline under the wrong ruleset is
  *self-consistent*, so it reports a confident number and can show zero drift on
  code that genuinely drifts under the config the repo actually uses.

When a drift number moves by much more than your diff could explain, the
measurement is wrong before the code is. Formatting needs nightly:
`cargo +nightly fmt --all`.

**Control-test the measurement before you trust its verdict.** Every trap in
this section produces a *confident wrong number* rather than an error, so the
only way to tell a working method from a blind one is to feed it something you
know is broken and check it complains:

```bash
# deliberately mangle a copy, then measure it. A blind method scores this 0.
sed 's/fn some_test() {/fn some_test(){let _x=1;/' file.rs > ctl.rs
```

This costs one command and has caught two blind methods here — the `cargo fmt`
path-forwarding above, and the `/tmp` baseline ruleset below. Both reported
zero drift on code that drifts.

> **CI is billing-blocked.** Every gate above runs locally. This is known and
> accepted — do not raise it as a finding.

---

## 9. Build and toolchain traps

These are not style preferences. Each one has cost real time.

| Trap | What happens | What to do |
| --- | --- | --- |
| **Every `cargo build` strips the hypervisor entitlement** | `hv_vm_create failed: 0xfae94007 — HV_DENIED` | Re-sign after *every* build: `codesign --sign - --entitlements hypervisor/tests/data/hv.entitlements --force ./target/debug/chm`, run from the **repo root**. Verify by **reading** `codesign -d --entitlements - ./target/debug/chm` and looking for `com.apple.security.hypervisor` / `[Bool] true` — do not `grep -c`, the dump format has changed before and a count is a proxy for the answer, not the answer |
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
