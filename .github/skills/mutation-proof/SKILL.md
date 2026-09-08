---
name: mutation-proof
description: "Prove a test, guard, check script, or assertion actually fails when the thing it guards is broken. Use whenever you add or change a test, a hygiene guard, a lint, a CI check, or any assertion, and before claiming a check works. Triggers on: added a test, wrote a guard, does this test work, mutation test, prove the check fires, is this assertion doing anything."
---

# Mutation-proof a guard

A guard that has never failed is worth nothing. Before you claim a check works,
break the thing it checks and watch it fail.

## Procedure

1. Run the guard on the unmodified tree. Record that it passes.
2. Break the thing the guard exists to catch. Change the real file, not a copy.
   Back it up first: `cp <file> /tmp/<file>.bak`.
3. Run the guard again. Record the exact failure message, not just the exit
   status.
4. Restore: `cp /tmp/<file>.bak <file>`, then `md5 -q` both to check they match.
5. Repeat for every distinct thing the guard claims to catch. One mutation per
   claim.
6. Add at least one negative control: a change the guard must *not* flag. A
   guard that fires on everything is the same as no guard.
7. Put the table in the pull request body: mutation, expected, observed.

## Reading the result

A mutation that produces **SILENT** has three possible causes, in this order:

1. The mutation never applied. Diff the file and check.
2. The guard never ran. Check it was in the command you ran, and that an
   earlier failure did not stop the run first.
3. Only then is the guard weak.

A mutation that produces **FIRES** has causes too, and they are not all good:

- It may have fired on the mutation.
- It may have fired on something else entirely. Read the message. A check
  script that derives its own root path will fail early and loudly in a `/tmp`
  copy, long before it reaches the code you changed, and that failure looks
  exactly like success.

**Read the failure message, not the exit status.** Mutate in place with a
backup, not in a copy somewhere else.

## Traps that have caught people here

- **An assertion implied by a stronger one can never fail.** Asserting a
  document contains `scripts/check-docs.sh` is dead code when you already
  assert it contains the same path in backticks. Delete it, and leave a
  comment so nobody re-adds it.
- **A check a typo can switch off is not a check.** If the guard looks for a
  phrase and silently skips when the phrase is absent, then rewording the
  phrase disables it while it still exits 0. Make the phrase required: absent
  means hard failure.
- **A measurement method is itself a guard.** Before you trust a tool that
  reports zero problems, feed it a known-broken input and check it reports a
  problem. See the `measure-formatting-drift` skill for the case where this
  rule was learned.
- **False positives are part of correctness.** A guard that cries wolf gets
  switched off. Count them, and tighten the pattern until the count is zero.

## Where the guards live

`chm/src/hygiene.rs` holds the checks that bind a document to the thing it
documents, using `include_str!`. `scripts/check-docs.sh` holds the checks that
have to leave the repository and ask GitHub, because internal consistency is
not truth: a page can list exactly as many issues as it claims and still be
badly wrong.

The harness in `.github/hooks/` follows the same rule. Every hook script has a
`--selftest` that runs a case table containing both the inputs it must act on
and the inputs it must ignore. Run them all with `make check-harness`.
