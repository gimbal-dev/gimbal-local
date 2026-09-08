#!/usr/bin/env bash
#
# Measure docs/project-state.md's open-issue list against GitHub.
#
# Why this script exists, and why a unit test could not replace it:
#
# The grouped issue list in docs/project-state.md asserts a fact about the
# outside world -- which issues are open right now. Nothing inside the repo
# knows that, so no `cargo test` can check it. Left unchecked it rots, and it
# has rotted twice:
#
#   * #368 was filed because the list had been assembled by hand and *every*
#     issue on it had since closed.
#   * The refresh that closed #368 rotted in turn. Measured 2026-09-08: of the
#     31 issues it named, 12 were closed and one open issue (#410) was missing.
#     42% wrong.
#
# The second rot is the interesting one, because the list was *internally*
# consistent the whole time -- it claimed 31 and listed 31. A guard that only
# counted would have passed it. Internal consistency is not truth, so the
# check has to leave the repo and ask.
#
# Exit status is the point: 0 when the doc matches GitHub, 1 when it drifts,
# and 2 when the check could not be run at all. A checker that cannot reach
# GitHub must NOT report success -- that is the silent-failure mode this
# project refuses (docs/engineering-discipline.md section 5).
#
# Usage:  ./scripts/check-docs.sh            # check, print any drift
#         ./scripts/check-docs.sh --list     # just print what gh says is open
#
# Note for this machine: stored GH_TOKEN/GITHUB_TOKEN env vars can shadow the
# working `gh` credential. If gh fails to authenticate, retry with
# `env -u GH_TOKEN -u GITHUB_TOKEN ./scripts/check-docs.sh`. The script does
# not unset them for you, because on a normal machine that token is the one
# thing making `gh` work.

set -uo pipefail

REPO="gimbal-dev/gimbal-local"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC="$ROOT/docs/project-state.md"
SECTION_START='^## The open issue list, grouped'

die() { echo "check-docs: $*" >&2; exit 2; }

command -v gh >/dev/null 2>&1 || die "the gh CLI is not installed, so the list cannot be checked"
[ -r "$DOC" ] || die "cannot read $DOC"

# Ask GitHub first. `select(.pull_request == null)` matters: the issues
# endpoint returns pull requests too, and counting those would inflate the
# real number and produce drift that is not there.
if ! gh api "repos/$REPO/issues?state=open&per_page=100" \
        --jq '.[] | select(.pull_request == null) | .number' 2>/tmp/check-docs-gh.err \
        | sort -un > /tmp/check-docs-gh.txt; then
    die "gh could not list open issues: $(head -3 /tmp/check-docs-gh.err | tr '\n' ' ')"
fi

# An empty answer means the query failed in a way gh did not report as an
# error. Treating that as "the doc lists too many" would be a confident lie.
[ -s /tmp/check-docs-gh.txt ] || die "gh returned no open issues at all, which is not credible -- refusing to compare"

if [ "${1:-}" = "--list" ]; then
    tr '\n' ' ' < /tmp/check-docs-gh.txt; echo
    exit 0
fi

# Read the doc's claim. Only the grouped section counts: issue numbers appear
# elsewhere in the page as historical citations, and folding those in would
# report drift that does not exist.
awk "/$SECTION_START/,/^## Where to read next/" "$DOC" \
    | grep -o 'issues/[0-9]*' | grep -o '[0-9]*' | sort -un > /tmp/check-docs-doc.txt

[ -s /tmp/check-docs-doc.txt ] || die "found no issue links in the grouped section -- has the section been renamed?"

listed=$(wc -l < /tmp/check-docs-doc.txt | tr -d ' ')
actual=$(wc -l < /tmp/check-docs-gh.txt | tr -d ' ')

# The doc also states its own count in prose. A mismatch between the stated
# count and the number of links is a hand-edit slip, and it is worth naming
# separately from real drift because the cure is different.
#
# The count is REQUIRED, not optional. An earlier version of this script
# skipped the comparison when it could not find the phrase, which meant any
# reformatting of that sentence silently switched off a check while the script
# still exited 0. A check that can be disabled by a typo is not a check.
claimed=$(grep -o '\*\*[0-9]\+ remain open\*\*' "$DOC" | grep -o '[0-9]\+' | head -1)
[ -n "$claimed" ] || die "the page no longer states '**N remain open**', so its own count cannot be checked -- restore that phrasing or update this script deliberately"

rc=0

if [ "$claimed" != "$listed" ]; then
    echo "MISCOUNT: the page says '**$claimed remain open**' but links $listed issues."
    rc=1
fi

closed_but_listed=$(comm -23 /tmp/check-docs-doc.txt /tmp/check-docs-gh.txt | tr '\n' ' ' | sed 's/ *$//')
open_but_missing=$(comm -13 /tmp/check-docs-doc.txt /tmp/check-docs-gh.txt | tr '\n' ' ' | sed 's/ *$//')

if [ -n "$closed_but_listed" ]; then
    echo "STALE: listed as open, but closed on GitHub: $closed_but_listed"
    rc=1
fi

if [ -n "$open_but_missing" ]; then
    echo "MISSING: open on GitHub, but absent from the page: $open_but_missing"
    rc=1
fi

# A second, separate rot, in different files and a different shape.
#
# The eight .github/agents/*.md files carry per-issue status claims -- a table
# row naming an issue and marking it Open. Those rot the same way the grouped
# list does, and on 2026-09-08 an audit found ten of them wrong across six
# files, including bugs the agent file told you to work around that had in fact
# been fixed months earlier. An agent reading that file plans around a defect
# that no longer exists.
#
# The needle is a table cell holding the standalone word "Open" on a line that
# also cites an issue. It has to be that narrow. A first attempt matched any
# line pairing an issue with the word "Open" and immediately produced eight
# false positives in docs/roadmap.md, where "Open" is part of the **Open
# terminal** button name rather than a status. A guard that cries wolf on
# correct prose teaches the next reader to switch it off. Measured against the
# pre-audit files the tightened needle matched exactly the three stale rows,
# and against the repaired tree it matches nothing.
# If that tree moves, `grep -r` finds nothing and this check quietly passes,
# which is precisely the silent-failure mode above. Refuse instead.
AGENTS_DIR="$ROOT/.github/agents"
ls "$AGENTS_DIR"/*.md >/dev/null 2>&1 || \
    die "no .github/agents/*.md found -- the per-issue status check would sweep nothing; update AGENTS_DIR deliberately"

status_bad=""
while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file=${hit%%:*}; rest=${hit#*:}; lineno=${rest%%:*}; text=${rest#*:}
    # sort -u: a linked citation carries the number twice, once in the link
    # text and once in the URL, and would otherwise be reported twice.
    for n in $(printf '%s' "$text" | grep -oE '#[0-9]{2,}|issues/[0-9]+' | grep -oE '[0-9]+' | sort -un); do
        grep -qx "$n" /tmp/check-docs-gh.txt || \
            status_bad="$status_bad $(basename "$file"):$lineno(#$n)"
    done
done < <(grep -rnE '#[0-9]{2,}|issues/[0-9]+' \
             "$ROOT/docs" "$ROOT/.github/agents" --include='*.md' 2>/dev/null \
         | grep -E '\| *Open\b')

if [ -n "$status_bad" ]; then
    echo "CLOSED-BUT-CALLED-OPEN:${status_bad}"
    echo "  Those lines mark an issue Open that GitHub reports closed."
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "docs/project-state.md matches GitHub: $actual open issues, all named."
else
    echo
    echo "docs/project-state.md is $listed entries against $actual actually open."
    echo "Refresh the grouped list, and update both the count and the sweep date."
fi

exit "$rc"
