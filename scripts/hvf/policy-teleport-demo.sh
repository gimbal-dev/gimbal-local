#!/usr/bin/env bash
# M28.4 — the policy-digest teleport proof.
#
# The allow-list demo (egress-allowlist-demo.sh) proves a LOCALLY authored
# policy is enforced. This proves the other half of the story: a policy authored
# in the CONTROL PLANE, for a sandbox that lives in the cloud, comes DOWN to this
# Mac and governs a local microVM — with the plane's policy digest as the
# identity on every refusal.
#
# The chain it exercises end to end:
#
#   plane policy_digest
#     -> chm policy bind   (fetch + verify the digest, same path the runner uses)
#     -> <workspace>/egress-policy.json labelled with that digest
#     -> the userspace NAT's DNS + TCP-connect gates
#     -> console DENY lines + the durable audit trail, both naming the digest
#
# Requires a reachable control plane with at least one policy-bound sandbox.
# Skips (exit 0) rather than failing when there isn't one, so it is safe to run
# unconditionally.
#
# Usage: scripts/hvf/policy-teleport-demo.sh [SNAPSHOT_DIR]
#   CHM_API      control plane base URL (default http://127.0.0.1:8080)
#   CHM_SANDBOX  sandbox to bind from   (default: first restricted one found)

set -euo pipefail

cd "$(dirname "$0")/../.."

SNAP="${1:-snapshots/ch-arm-stock-its-net}"
CHM="./target/debug/chm"
API="${CHM_API:-http://127.0.0.1:8080}"
LOG="$(mktemp -t chm-teleport-demo)"
# A host that no realistic sandbox policy allow-lists, used to prove the
# allow-list is closed rather than merely present.
OUTSIDE_HOST="example.com"
# The cloud instance metadata service. A policy that names this in its deny list
# is the highest-value rule to prove, because a compromised agent reaching IMDS
# is how cloud credentials leak.
IMDS_IP="169.254.169.254"

skip() { echo "policy-teleport: SKIP — $*"; exit 0; }
fail() { echo "policy-teleport: FAIL — $*" >&2; echo "--- console log: $LOG"; exit 1; }

# --- Preflight ---------------------------------------------------------------
[ -x "$CHM" ] || skip "$CHM not built (run: cargo build -p gimbal-local --bin chm)"
[ -d "$SNAP" ] || skip "snapshot $SNAP not present"
[ -f "$SNAP/config.json" ] && grep -q '_net' "$SNAP/config.json" 2>/dev/null \
    || grep -qa '_net' "$SNAP/state.json" 2>/dev/null \
    || skip "$SNAP has no virtio-net device — a policy can only be proven on a net-enabled snapshot"

curl -fsS -m 5 "$API/healthz" >/dev/null 2>&1 \
    || skip "no control plane reachable at $API — the teleport needs a plane to teleport FROM"

# --- Find a policy-bound sandbox ---------------------------------------------
SANDBOX="${CHM_SANDBOX:-}"
if [ -z "$SANDBOX" ]; then
    for id in $(curl -fsS -m 10 "$API/sandboxes" 2>/dev/null \
                | tr ',' '\n' | grep -o 'sbx-[0-9a-f]*' | sort -u); do
        if curl -fsS -m 10 "$API/sandboxes/$id/policy?substrate=apple-hvf" 2>/dev/null \
           | grep -q '"restricted":[[:space:]]*true'; then
            SANDBOX="$id"
            break
        fi
    done
fi
[ -n "$SANDBOX" ] || skip "no policy-bound sandbox on $API — bind a policy in the plane first"

# --- The teleport ------------------------------------------------------------
echo "policy-teleport: binding the plane's policy for $SANDBOX to $SNAP"
BIND_OUT="$("$CHM" policy bind --sandbox "$SANDBOX" --api "$API" "$SNAP" 2>&1)" \
    || fail "chm policy bind failed:\n$BIND_OUT"
echo "$BIND_OUT"

DIGEST="$(grep -o 'sha256:[0-9a-f]\{64\}' "$SNAP/egress-policy.json" | head -1)"
[ -n "$DIGEST" ] || fail "the bound policy is not labelled with a sha256 digest"

# Derive the allow probe from the policy itself, so this proves whatever the
# plane actually authored rather than a hardcoded expectation.
ALLOW_HOST="$(grep -o '"[A-Za-z0-9.-]*\.[A-Za-z]\{2,\}:443"' "$SNAP/egress-policy.json" \
              | head -1 | tr -d '":' | sed 's/443$//')"
[ -n "$ALLOW_HOST" ] || skip "the bound policy allow-lists no https hostname to probe"
grep -q "\"$IMDS_IP\"" "$SNAP/egress-policy.json" && PROBE_IMDS=1 || PROBE_IMDS=0

echo "policy-teleport: probing under digest $DIGEST"
echo "  allow-listed by the plane : $ALLOW_HOST"
echo "  not allow-listed          : $OUTSIDE_HOST"
[ "$PROBE_IMDS" = 1 ] && echo "  explicitly denied         : $IMDS_IP (cloud metadata)"

rm -f "$SNAP/audit.jsonl"
rm -rf "${SNAP:?}/.chm-overlays/"* 2>/dev/null || true

(
  sleep 18
  printf 'echo TELEPORT_READY\r'
  sleep 3
  printf 'curl -sS -m 15 -o /dev/null -w "ALLOWED_HTTP=%%{http_code}\\n" https://%s/ || echo ALLOWED_RC=$?\r' "$ALLOW_HOST"
  sleep 18
  printf 'curl -sS -m 12 -o /dev/null -w "OUTSIDE_HTTP=%%{http_code}\\n" http://%s/ || echo OUTSIDE_RC=$?\r' "$OUTSIDE_HOST"
  sleep 15
  if [ "$PROBE_IMDS" = 1 ]; then
    printf 'curl -sS -m 12 -o /dev/null -w "IMDS_HTTP=%%{http_code}\\n" http://%s/latest/meta-data/ || echo IMDS_RC=$?\r' "$IMDS_IP"
    sleep 15
  fi
  printf '\x01x'
) | CHM_USERSPACE_GIC=1 "$CHM" run "$SNAP" --idle-exit 0 --max-seconds 100 2>&1 \
  | tr -d '\000' > "$LOG" || true

# --- Assert ------------------------------------------------------------------
have() { grep -aq "$1" "$LOG"; }

have 'TELEPORT_READY' \
    || fail "the guest never reached a shell — the run did not get far enough to prove anything"

# 1. The plane's allow rule must actually let traffic through, or "nothing gets
#    out" would be trivially true and the proof vacuous.
have 'ALLOWED_HTTP=200' \
    || fail "$ALLOW_HOST is allow-listed by the plane but did NOT return HTTP 200"

# 2. Anything the plane did not allow-list must be refused, under the plane's
#    digest — this is the teleport actually biting.
have 'OUTSIDE_RC=6' \
    || fail "$OUTSIDE_HOST is not allow-listed but was not refused at the DNS gate (expected curl rc 6)"
have "\[egress\] DENY dns $OUTSIDE_HOST.*$DIGEST" \
    || fail "the $OUTSIDE_HOST denial did not name the plane's digest $DIGEST"

# 3. An explicit deny rule must fire BY NAME, proving the specific cloud-authored
#    rule travelled — not just the default-deny stance.
if [ "$PROBE_IMDS" = 1 ]; then
    have 'IMDS_RC=7' \
        || fail "$IMDS_IP is explicitly denied but was not refused at the connect gate (expected curl rc 7)"
    have "\[egress\] DENY tcp $IMDS_IP:80 (deny $IMDS_IP)" \
        || fail "the $IMDS_IP refusal did not cite the plane's explicit deny rule"
fi

# 4. The durable record must carry the digest, so a refusal on this Mac is
#    attributable to the exact policy the control plane issued.
AUDIT="$("$CHM" audit show "$SNAP" 2>/dev/null || true)"
echo "$AUDIT" | grep -q "egress-DENY.*policy=$DIGEST" \
    || fail "the audit trail does not name the plane's policy digest"

echo "policy-teleport: PASS"
echo "  the control plane's policy $DIGEST"
echo "  governed a microVM on this Mac:"
echo "    - $ALLOW_HOST (plane allow-list)     -> HTTP 200"
echo "    - $OUTSIDE_HOST (not allow-listed)   -> refused at the DNS gate"
[ "$PROBE_IMDS" = 1 ] && \
echo "    - $IMDS_IP (plane deny rule)  -> refused at the TCP-connect gate"
echo "  every refusal audited under the plane's digest"
