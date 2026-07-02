#!/usr/bin/env bash
# Copyright © 2024 Cloud Hypervisor contributors
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#
# Security guard for invariant I1 (docs/security-model.md, M30.5):
# **no host filesystem passthrough**. Gimbal Local runs untrusted, potentially
# hostile guest workloads; a guest must never receive a virtiofs/9p/shared-folder
# mount of a host directory. The only guest storage is virtio-blk over a
# bundle-owned image plus a private copy-on-write overlay.
#
# This guard fails the build if host-FS-passthrough wiring appears in the HVF
# device model without a deliberate security review. If such support is ever
# added intentionally, it must be paired with a threat-model update and the exact
# reviewed line annotated with the marker below, so the addition cannot land
# silently:
#
#     // SECURITY-REVIEWED-FS-SHARE: <reason / ticket>
#
# Run directly or via `make security-check`.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Scope: the macOS HVF device model — the only place a guest device is wired.
scan_dir="$repo_root/hypervisor/src/hvf"

# Real host-FS-passthrough wiring tokens (code identifiers / virtio constants),
# not hyphenated prose — so device wiring is caught but doc comments are not.
pattern='virtiofs|virtiofsd|virtio_fs|VIRTIO_ID_FS|VIRTIO_TYPE_FS|9pfs|VIRTIO_ID_9P|VIRTIO_TYPE_9P|p9_trans|shared[_-]?folder|host[_-]?mount|mount_host'

# Grep the device model, dropping any line carrying the reviewed-exception marker.
hits="$(grep -rInE "$pattern" "$scan_dir" 2>/dev/null | grep -v 'SECURITY-REVIEWED-FS-SHARE' || true)"
if [ -n "$hits" ]; then
    echo "error: possible host-filesystem passthrough in the HVF device model" >&2
    echo "       (security invariant I1 — see docs/security-model.md, M30.5)." >&2
    echo "" >&2
    echo "$hits" >&2
    echo "" >&2
    echo "If this is an intentional, security-reviewed change, annotate the" >&2
    echo "exact line(s) with '// SECURITY-REVIEWED-FS-SHARE: <reason>' and" >&2
    echo "update docs/security-model.md." >&2
    exit 1
fi

echo "no-host-fs-passthrough: OK (device model wires only block/net/rng)"
