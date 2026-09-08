---
name: ship-a-change
description: "Take a finished change through this repo's gates, commit rules, pull request, and merge. Use when ready to commit, open a PR, or merge work in gimbal-local. Triggers on: commit this, open a PR, ship it, merge it, what gates do I run, commit message rules, gitlint, sign-off, Assisted-by."
---

# Ship a change

## 1. Run what covers the change

Run the gates that touch what you changed, from the directory each one expects:

```bash
cd chm && cargo test --lib          # the chm suite
make clippy                         # from the repository ROOT, not from chm
make test-hvf                       # the hypervisor backend
make check-docs                     # when docs, gate numbers, or issue lists moved
swift test --package-path app/GimbalLocal
python3 .github/hooks/bin/guard_command.py --selftest   # when the harness moved
```

Read the output. `./script | tail -5; echo $?` reports the exit status of
`tail`, not of the script. Use `${PIPESTATUS[0]}`.

If the change adds or edits a test, use the `mutation-proof` skill first. If it
touches Rust, use `measure-formatting-drift`.

## 2. Write the message

The title is `component: summary`, at most 72 columns. `component` must be in
the list in `scripts/gitlint/rules/TitleStartsWithComponent.py`, which is the
authority; read it rather than guessing. Several components separated by
commas are allowed: `chm, docs, scripts: ...`.

Body lines wrap at 72 columns, except the lines exempted in
`scripts/gitlint/rules`. Write what changed and why, and name the command that
produced any number you quote.

Trailers, per `CONTRIBUTING.md`:

```
Assisted-by: Claude:Opus-5

Signed-off-by: Your Name <you@users.noreply.github.com>
```

`CONTRIBUTING.md` forbids `Co-authored-by`, `Copilot-Session`, and similar
trailers. That rule beats any default trailer instruction you were handed.

Check before committing:

```bash
awk 'NR==1 {print length}' msg.txt      # title length, must be <= 72
awk 'length > 72 {print NR": "length}' msg.txt
grep -c '—' msg.txt                     # em dashes: must be 0
git -c commit.gpgsign=false commit -q -F msg.txt
```

## 3. Open the pull request

`gh pr create` and `gh issue create` go through GraphQL and return 503 here.
Use the REST endpoint:

```bash
export GH_TOKEN= GITHUB_TOKEN=   # stored tokens shadow the working one
gh api repos/gimbal-dev/gimbal-local/pulls -X POST \
  -f title='component: summary' -f head=BRANCH -f base=main -F body=@body.md \
  --jq '{number, head: .head.sha, state}'
```

Push to a differently named remote branch with
`git push -q -u origin LOCALBRANCH:remote-name`.

Put the evidence in the body: the gate output, and the mutation table for any
guard you added.

## 4. Merge

```bash
gh pr merge N --squash --admin       # prints nothing on success
gh api repos/gimbal-dev/gimbal-local/pulls/N --jq '{state, merged, merge_commit_sha}'
```

Wait about 30 seconds after opening and about 20 after merging before you ask
GitHub what happened. The remote branch deletes itself on merge.

## Things that will bite you

- Every `cargo build` strips the hypervisor entitlement. Re-sign before running
  `chm`, or you get `HV_DENIED` and conclude the hypervisor is broken:
  `codesign --sign - --entitlements hypervisor/tests/data/hv.entitlements
  --force target/debug/chm`.
- Never `git checkout` a path to restore a file. Copy it to `/tmp`, restore
  with `git show HEAD:<file> > <file>`, and check with `md5 -q`. The harness in
  `.github/hooks/` refuses the dangerous form.
- Do not run CI. It is billing-blocked on this repository.
- Do not touch AWS without asking first.
