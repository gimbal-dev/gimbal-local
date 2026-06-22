#!/usr/bin/env bash
#
# Build and code-sign the `chm` (Cloud Hypervisor for macOS) binary.
#
# Hypervisor.framework refuses to create a VM unless the executable carries the
# `com.apple.security.hypervisor` entitlement, so every build of `chm` must be
# re-signed before it can run. This wraps both steps.
#
# Usage:
#   scripts/build-chm.sh [--release]
#
# The signed binary path is printed on success; run it with, e.g.:
#   "$(scripts/build-chm.sh)" run /path/to/ch-snapshot
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="debug"
CARGO_PROFILE_FLAG=()
if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
    CARGO_PROFILE_FLAG=(--release)
fi

ENTITLEMENTS="hypervisor/tests/data/hv.entitlements"

# Build only this crate; it target-gates its Hypervisor.framework dependency to
# Apple Silicon, so this must be run on an arm64 Mac. The `${arr[@]+"${arr[@]}"}`
# form expands safely even when the array is empty under `set -u` (bash 3.2).
cargo build -p cloud-hypervisor-mac --bin chm \
    ${CARGO_PROFILE_FLAG[@]+"${CARGO_PROFILE_FLAG[@]}"} >&2

BIN="target/${PROFILE}/chm"
if [[ ! -x "$BIN" ]]; then
    echo "build-chm.sh: expected binary not found at $BIN" >&2
    exit 1
fi

codesign --sign - --entitlements "$ENTITLEMENTS" --force "$BIN" >&2

echo "$BIN"
