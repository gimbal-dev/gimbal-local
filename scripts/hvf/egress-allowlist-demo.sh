#!/usr/bin/env bash
#
# egress-allowlist-demo.sh — M28.4: prove a sandbox's allow-list egress policy
# is ENFORCED on the Mac, against a real rehydrated guest with real networking.
#
# The demo binds a default-deny policy with a single allowed host, resumes a
# net-enabled snapshot, and drives three probes inside the guest:
#
#   1. ALLOWED  — curl the allow-listed host        => expect HTTP 200
#   2. DENIED   — curl a non-allowed host by NAME   => expect refusal at the
#                 DNS gate (curl exit 6, "could not resolve host")
#   3. RAW-IP   — curl a non-allowed host by literal IP, bypassing DNS entirely
#                 => expect refusal at the TCP-connect gate (curl exit 7)
#
# Probe 3 is the load-bearing one: it proves the guest cannot escape by
# hardcoding an address, because `chm` is the process that opens the host
# socket. Default-deny means "we never call connect()", so there is no path
# around the gate from inside the guest.
#
# Each refusal must also appear on the console as a `chm: [egress] DENY` line
# AND in the durable audit trail naming the governing policy.
#
# Usage:
#   scripts/hvf/egress-allowlist-demo.sh [SNAPSHOT_DIR]
#
# SNAPSHOT_DIR defaults to $CHM_NET_SNAPSHOT, then ./snapshots/ch-arm-stock-its-net.
# It must be a net-enabled capture (GUEST_NET=1 in scripts/hvf/capture-on-mac.sh).
#
# Requires a signed ./target/debug/chm (scripts/build-chm.sh).
set -uo pipefail

cd "$(dirname "$0")/../.."

SNAP="${1:-${CHM_NET_SNAPSHOT:-snapshots/ch-arm-stock-its-net}}"
CHM="${CHM_BIN:-./target/debug/chm}"

# The host we permit, and a host we do not. Both must be reachable from the Mac
# for the demo to be meaningful (otherwise "denied" proves nothing).
ALLOW_HOST="${ALLOW_HOST:-example.com}"
DENY_HOST="${DENY_HOST:-neverssl.com}"
POLICY_LABEL="${POLICY_LABEL:-m28.4-allowlist-demo}"

fail() { echo "egress-demo: FAIL — $*" >&2; exit 1; }

[ -d "$SNAP" ] || fail "snapshot dir not found: $SNAP (capture one with GUEST_NET=1 scripts/hvf/capture-on-mac.sh)"
[ -s "$SNAP/state.json" ] || fail "$SNAP has no state.json (not a snapshot bundle)"
[ -x "$CHM" ] || fail "no chm binary at $CHM (run scripts/build-chm.sh)"
grep -q '_net' "$SNAP/state.json" || fail "$SNAP has no virtio-net device; this demo needs a net-enabled capture"

# Resolve the denied host on the HOST side, so the guest can dial it by literal
# IP without needing DNS. This is what makes probe 3 a real bypass attempt.
DENY_IP="$(dig +short "$DENY_HOST" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)"
[ -n "$DENY_IP" ] || fail "could not resolve $DENY_HOST on the host; pick a different DENY_HOST"

echo "egress-demo: snapshot   = $SNAP"
echo "egress-demo: policy     = default-deny, allow $ALLOW_HOST  (label $POLICY_LABEL)"
echo "egress-demo: denied host= $DENY_HOST ($DENY_IP)"
echo

# --- Author the policy -------------------------------------------------------
# `chm firewall set` writes <workspace>/egress-policy.json, which `chm run`
# resolves and hands to the userspace NAT. No control plane needed ($0 repro);
# a cloud assignment binds the same shape via CHM_EGRESS_POLICY.
"$CHM" firewall set "$SNAP" \
    --default deny --allow "$ALLOW_HOST" --label "$POLICY_LABEL" >/dev/null \
    || fail "could not author the policy"
"$CHM" firewall show "$SNAP" || fail "could not read back the policy"
echo

# Start from clean copy-on-write overlays so the run is reproducible.
rm -rf "${SNAP:?}/.chm-overlays"/* 2>/dev/null || true

LOG="$(mktemp -t egress-demo)"
trap 'rm -f "$LOG"' EXIT

# --- Drive the guest ---------------------------------------------------------
# The guest resumes to an interactive shell, so the probes are typed onto its
# serial console. Timings are generous: each curl must be allowed to hit its own
# timeout (a denied flow fails fast, an allowed one needs a real round trip).
# `\x01x` is chm's Ctrl-A x quit escape.
echo "egress-demo: resuming the guest and running the probes (~75s)..."
(
    sleep 18
    printf 'echo DEMO_READY\r'
    sleep 3
    printf 'curl -sS -m 12 -o /dev/null -w "ALLOWED_HTTP=%%{http_code}\\n" http://%s/ || echo ALLOWED_CURL_RC=$?\r' "$ALLOW_HOST"
    sleep 15
    printf 'curl -sS -m 12 -o /dev/null -w "DENIED_HTTP=%%{http_code}\\n" http://%s/ || echo DENIED_CURL_RC=$?\r' "$DENY_HOST"
    sleep 15
    printf 'curl -sS -m 12 -o /dev/null -w "RAWIP_HTTP=%%{http_code}\\n" http://%s/ || echo RAWIP_CURL_RC=$?\r' "$DENY_IP"
    sleep 15
    printf '\x01x'
) | CHM_USERSPACE_GIC=1 "$CHM" run "$SNAP" --idle-exit 0 --max-seconds 90 2>&1 \
    | tr -d '\000' > "$LOG"

echo
echo "egress-demo: --- guest + enforcement output ---"
grep -aE 'DEMO_READY|ALLOWED_HTTP|DENIED_HTTP|RAWIP_HTTP|_CURL_RC|\[egress\] DENY' "$LOG" || true
echo "egress-demo: -----------------------------------"
echo

# --- Assert ------------------------------------------------------------------
have() { grep -aq "$1" "$LOG"; }

have 'DEMO_READY' \
    || fail "the guest never reached a shell — the run did not get far enough to prove anything"

# 1. The allow-listed host must actually work. Without this the whole demo is
#    vacuous: "nothing gets out" is trivially satisfiable by a broken network.
have 'ALLOWED_HTTP=200' \
    || fail "the allow-listed host $ALLOW_HOST did NOT return HTTP 200 (allow rule not honoured)"

# 2. The denied host must be refused at the DNS gate. curl exit 6 = could not
#    resolve host, i.e. the NAT refused to answer the lookup.
have 'DENIED_CURL_RC=6' \
    || fail "$DENY_HOST was not refused at the DNS gate (expected curl rc 6)"
have "\[egress\] DENY dns $DENY_HOST" \
    || fail "no console DENY line for the $DENY_HOST DNS lookup"

# 3. The raw-IP dial must be refused at the TCP-connect gate. curl exit 7 =
#    failed to connect, i.e. chm never opened a host socket for it.
have 'RAWIP_CURL_RC=7' \
    || fail "the raw-IP dial to $DENY_IP was not refused at the connect gate (expected curl rc 7)"
have "\[egress\] DENY tcp $DENY_IP:80" \
    || fail "no console DENY line for the raw-IP connect to $DENY_IP"

# 4. The denials must be durably recorded AND name the governing policy, so a
#    refusal on the Mac can be tied back to the exact policy that caused it.
AUDIT="$("$CHM" audit show "$SNAP" 2>/dev/null || true)"
echo "$AUDIT" | grep -q "egress-DENY.*dns $DENY_HOST" \
    || fail "the DNS denial is not in the audit trail"
echo "$AUDIT" | grep -q "egress-DENY.*tcp $DENY_IP:80" \
    || fail "the raw-IP connect denial is not in the audit trail"
echo "$AUDIT" | grep -q "egress-DENY.*policy=$POLICY_LABEL" \
    || fail "the audit trail does not name the governing policy ($POLICY_LABEL)"

echo "egress-demo: PASS"
echo "  - $ALLOW_HOST (allow-listed)          -> HTTP 200"
echo "  - $DENY_HOST  (not allow-listed)      -> refused at the DNS gate"
echo "  - $DENY_IP    (raw IP, DNS bypassed)  -> refused at the TCP-connect gate"
echo "  - both denials audited under policy '$POLICY_LABEL'"
