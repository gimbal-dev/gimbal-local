---
name: measure-formatting-drift
description: "Measure whether a Rust change added rustfmt drift in this repo, without believing a false zero. Use before committing Rust, when a formatting check reports no problems, or when asked whether a file is rustfmt-clean. Triggers on: is this formatted, rustfmt check, cargo fmt, formatting drift, fmt clean, did I add drift."
---

# Measure formatting drift

Several files in this fork already differ from rustfmt's opinion. The standard
is **do not add drift**, not reach zero. So every measurement is a comparison
against HEAD, never against nothing.

The full reasoning, with the measured numbers behind each trap, is in
`docs/engineering-discipline.md` under "rustfmt drift is measured against HEAD".
Read it before you argue with a result. This skill is the recipe.

## Whole-tree, the reliable way

```bash
cargo +nightly fmt --all --check | grep -c '^[+-]'                                   # live
git stash -q && cargo +nightly fmt --all --check | grep -c '^[+-]' && git stash pop -q  # baseline
```

Clean means live equals baseline.

## One file

`cargo fmt -- --check <path>` **does not check that path**. It formats the
package's own targets and ignores the trailing path, so it prints nothing and
exits 0 on a file that is badly mangled. A drift measurement was taken and
believed on the strength of that zero, and a wrong claim shipped.

Invoke `rustfmt` itself, put the baseline inside the tree so it finds the repo
`.rustfmt.toml`, and delete the scratch directory before committing:

```bash
mkdir -p chm/src/.fmtbase
git show HEAD:chm/src/<file>.rs > chm/src/.fmtbase/base.rs
cp chm/src/<file>.rs chm/src/.fmtbase/live.rs
RF="rustfmt +nightly --unstable-features --skip-children --edition 2024 --check"
$RF chm/src/.fmtbase/base.rs 2>/dev/null | grep -c '^Diff in'
$RF chm/src/.fmtbase/live.rs 2>/dev/null | grep -c '^Diff in'
rm -rf chm/src/.fmtbase
```

Every flag earns its place:

- `--edition 2024`, because the parse and the verdict change without it.
- `--skip-children`, because rustfmt otherwise formats every `mod` a file
  declares and counts the whole subtree.
- `--unstable-features`, because without it rustfmt rejects `--skip-children`,
  and a naive `| wc -l` then counts the error message and reports 1 on both
  sides of the comparison.
- A baseline **inside** `chm/src`, because rustfmt finds `.rustfmt.toml` by
  walking up from the file, so a `/tmp` baseline is measured under rustfmt's
  defaults instead of this repo's import rules. It is self-consistent, so it
  produces a confident number that is simply wrong.
- `rm -rf` at the end, because `hygiene.rs` scans `chm/src` and will pick up
  stray `.rs` files.

## Control-test before you trust a zero

Every trap here produces a confident wrong number rather than an error, so the
only way to tell a working method from a blind one is to feed it something you
know is broken:

```bash
sed 's/fn \([a-z_]*\)() {/fn \1(){let _x=1;/' chm/src/<file>.rs > chm/src/.fmtbase/ctl.rs
$RF chm/src/.fmtbase/ctl.rs 2>/dev/null | grep -c '^Diff in'   # must be well above zero
```

If the control scores zero, the method is blind. Fix the method before you
report anything about the code.

Formatting the tree needs nightly: `cargo +nightly fmt --all`.
