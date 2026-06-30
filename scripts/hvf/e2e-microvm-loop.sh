#!/usr/bin/env bash
#
# e2e-microvm-loop.sh — run the full local sandbox loop as an automated test:
# boot a real HVF-compatible snapshot, log in over a PTY, write a file inside
# the guest, `ls` it back, and assert there are no ext4/IO errors.
#
# This wraps the `#[ignore]`d integration test `chm/tests/e2e_microvm_loop.rs`
# so a single command exercises (and guards) the rehydrate→connect→use loop.
#
# Usage:
#   scripts/hvf/e2e-microvm-loop.sh [SNAPSHOT_DIR]
#
# SNAPSHOT_DIR defaults to $CHM_E2E_SNAPSHOT, then to ./snapshots/ch-arm-v2m-demo.
# The snapshot directory must hold state.json + snapshot/ + disks/ (a bundle
# captured by scripts/hvf/capture-on-mac.sh).
set -euo pipefail

cd "$(dirname "$0")/../.."

SNAP="${1:-${CHM_E2E_SNAPSHOT:-snapshots/ch-arm-v2m-demo}}"
if [ ! -d "$SNAP" ]; then
    echo "e2e-microvm-loop: snapshot dir not found: $SNAP" >&2
    echo "  capture one with scripts/hvf/capture-on-mac.sh, or pass a path." >&2
    exit 1
fi
SNAP="$(cd "$SNAP" && pwd)"
if [ ! -s "$SNAP/state.json" ]; then
    echo "e2e-microvm-loop: $SNAP has no state.json (not a snapshot bundle)" >&2
    exit 1
fi
if [ ! -d "$SNAP/disks" ]; then
    echo "e2e-microvm-loop: WARNING — $SNAP has no disks/; the guest will fall" >&2
    echo "  back to a zero overlay and the loop is expected to fail on disk I/O." >&2
fi

export CHM_E2E_SNAPSHOT="$SNAP"

# Start from clean copy-on-write overlays (the test does this too; belt + braces).
rm -rf "$SNAP/.chm-overlays"/* 2>/dev/null || true

echo "e2e-microvm-loop: snapshot = $SNAP"
echo "e2e-microvm-loop: running the boot → login → write → ls loop..."

# The test copies and ad-hoc-signs the cargo-built `chm` itself, so no separate
# signing step is needed here. `--ignored` opts the heavy test in; `--nocapture`
# streams its progress.
exec cargo test -p cloud-hypervisor-mac --test e2e_microvm_loop -- \
    --ignored --nocapture --exact microvm_boots_logs_in_writes_and_lists_a_file
