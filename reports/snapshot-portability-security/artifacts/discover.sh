#!/usr/bin/env bash
# Usage: ./discover.sh <path-to-target-codebase>
# Output: artifacts/raw-discovery.json
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path-to-target-codebase>" >&2
    exit 2
fi

TARGET="$(cd "$1" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/raw-discovery.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

collect_matches() {
    local output="$1"
    local pattern="$2"
    shift 2
    if command -v rg >/dev/null 2>&1; then
        (
            cd "$TARGET"
            rg --json --line-number \
                --glob '!target/**' \
                --glob '!vendor/**' \
                --glob '!node_modules/**' \
                "$pattern" "$@" || true
        ) | jq -s '
            [.[] | select(.type == "match") | {
                path: .data.path.text,
                line: .data.line_number,
                text: (.data.lines.text | sub("\n$"; ""))
            }]
        ' > "$TMP/$output"
    else
        (
            cd "$TARGET"
            grep -RInE \
                --exclude-dir=target \
                --exclude-dir=vendor \
                --exclude-dir=node_modules \
                -- "$pattern" "$@" || true
        ) | jq -R -s '
            split("\n")
            | map(select(length > 0))
            | map(capture("^(?<path>.*?):(?<line>[0-9]+):(?<text>.*)$"))
            | map(.line |= tonumber)
        ' > "$TMP/$output"
    fi
}

# Product claims and explicit caveats.
collect_matches claims.json \
    'secure|hardware-verified|hostile-agent|not yet met|no NIC|net = None|trust root|default-deny|allow-all' \
    README.md docs

# Runtime trust boundaries and security-sensitive defaults.
collect_matches security.json \
    'CHM_TRUST_STORE|CHM_REQUIRE_SIGNED|EgressResolution|cache_path|sanitize|O_NOFOLLOW|peer_uid|allow-local-egress|ConsoleFilter' \
    chm/src hypervisor/src/hvf

# Portability implementation and unsupported surfaces.
collect_matches portability.json \
    'rehydrate|userspace GIC|ITS/LPI|CNTFRQ|AArch32|Unsupported|not implemented|untested|placeholder' \
    chm/src hypervisor/src/hvf docs/hvf-compatible-snapshots.md docs/cpu-feature-deltas.md

# Test and CI evidence.
collect_matches verification.json \
    'CH_SNAPSHOT_DIR|#\[ignore|runs-on:|test-hvf|no-run|real_cloud|stock_its' \
    .github/workflows hypervisor/tests Makefile

REMOTE="$(git -C "$TARGET" remote get-url origin 2>/dev/null || true)"
HEAD="$(git -C "$TARGET" rev-parse HEAD)"
BRANCH="$(git -C "$TARGET" branch --show-current)"

jq -n \
    --arg target "$TARGET" \
    --arg remote "$REMOTE" \
    --arg head "$HEAD" \
    --arg branch "$BRANCH" \
    --slurpfile claims "$TMP/claims.json" \
    --slurpfile security "$TMP/security.json" \
    --slurpfile portability "$TMP/portability.json" \
    --slurpfile verification "$TMP/verification.json" \
    '{
        target: $target,
        repository: {
            remote: $remote,
            head: $head,
            branch: $branch
        },
        generated_at: (now | todate),
        claims: $claims[0],
        security_surfaces: $security[0],
        portability_surfaces: $portability[0],
        verification_surfaces: $verification[0],
        counts: {
            claims: ($claims[0] | length),
            security_surfaces: ($security[0] | length),
            portability_surfaces: ($portability[0] | length),
            verification_surfaces: ($verification[0] | length)
        }
    }' > "$OUT"

echo "$OUT"
