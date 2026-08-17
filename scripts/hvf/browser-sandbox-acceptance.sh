#!/usr/bin/env bash
#
# browser-sandbox-acceptance.sh -- V11.3 (#332), the acceptance gate for the
# browser sandbox epic (#329).
#
# The claim under test:
#
#   An agent gets a browser and nothing else. It reaches that browser over CDP
#   from the host, drives a real page load through the userspace NAT, and has
#   no other way in or out of the guest.
#
# Four checks, and the last three are the ones that make the first mean
# something:
#
#   A. HAPPY PATH   Playwright connectOverCDP -> render, evaluate, screenshot,
#                   and load an allow-listed page off the real internet.
#   B. INGRESS      The only path in is the port that was exposed. The guest's
#                   own address is NOT reachable from the host, so it is the
#                   ingress mapping granting access and not host routing.
#   C. EGRESS       A destination outside the profile is refused, the browser
#                   sees a navigation error rather than a blank page, and the
#                   refusal is on the console naming the governing policy.
#   D. NO CREDS     No credential-injection rule is in play. A browser that can
#                   be steered to an injection host would make authenticated
#                   requests on the agent's behalf: right for a coding agent,
#                   wrong for a browser sandbox.
#
# Usage:
#   scripts/hvf/browser-sandbox-acceptance.sh [IMAGE_DIR]
#
# IMAGE_DIR defaults to $CHM_BROWSER_IMAGE, then ~/gimbal-images/browser. Build
# one with:  chm image build --browser -o ~/gimbal-images/browser
#
# Requires a signed chm (scripts/build-chm.sh) and playwright-core on the host:
#   npm i playwright-core     # no browser download needed, the browser is in the VM
#
# Env:
#   CHM_BIN            path to chm            (default ./target/debug/chm)
#   NODE_PATH          where playwright-core lives, if not resolvable from cwd
#   ALLOW_HOST         allow-listed host      (default example.com)
#   DENY_HOST          host outside the policy(default neverssl.com)

set -uo pipefail

cd "$(dirname "$0")/../.."
REPO="$PWD"

CHM="${CHM_BIN:-./target/debug/chm}"
IMAGE_DIR="${1:-${CHM_BROWSER_IMAGE:-$HOME/gimbal-images/browser}}"
ALLOW_HOST="${ALLOW_HOST:-example.com}"
DENY_HOST="${DENY_HOST:-neverssl.com}"

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/browser-acceptance.XXXXXX")"
CONSOLE="$RUN_DIR/console.log"
# The audit trail needs somewhere to live, and it is the durable half of check
# C's evidence -- the console is a stream nobody is watching once the guest is
# gone.
WORKSPACE="$RUN_DIR/workspace"
mkdir -p "$WORKSPACE"
DRIVER_OUT="$RUN_DIR/driver.log"
VM_PID=""

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf '        %s\n' "$1"; }
FAILURES=0

cleanup() {
  if [ -n "$VM_PID" ] && kill -0 "$VM_PID" 2>/dev/null; then
    kill "$VM_PID" 2>/dev/null
    # Give the guest a moment to go down before the next run wants the single
    # process-global HVF slot back.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$VM_PID" 2>/dev/null || break
      sleep 1
    done
  fi
  echo
  echo "artifacts: $RUN_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight. Every one of these is a thing that has produced a confusing
# failure at least once, so each is named rather than left to fail obscurely.
# ---------------------------------------------------------------------------

echo "V11.3 browser sandbox acceptance (#332)"
echo

[ -x "$CHM" ] || { echo "no chm at $CHM -- run scripts/build-chm.sh" >&2; exit 2; }

# Every cargo build strips the hypervisor entitlement, and the guest then dies
# with HV_DENIED, which reads like a broken image rather than an unsigned tool.
if ! codesign -d --entitlements - "$CHM" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
  echo "$CHM carries no hypervisor entitlement -- re-sign it:" >&2
  echo "  codesign --sign - --entitlements hypervisor/tests/data/hv.entitlements --force $CHM" >&2
  exit 2
fi

for f in Image rootfs.img; do
  [ -f "$IMAGE_DIR/$f" ] || {
    echo "no $f in $IMAGE_DIR -- build one with:" >&2
    echo "  $CHM image build --browser -o $IMAGE_DIR" >&2
    exit 2
  }
done

command -v node >/dev/null || { echo "node is not on PATH" >&2; exit 2; }
if ! node -e 'require.resolve("playwright-core")' 2>/dev/null; then
  echo "playwright-core is not resolvable -- npm i playwright-core, or set NODE_PATH" >&2
  exit 2
fi

# The CDP port is the browser module's to define. Reading it here rather than
# restating it means a change to the constant cannot leave this gate testing a
# port nothing listens on, which is the exact shape of the app/engine drift
# this repo has hit repeatedly (#242, #225).
#
# Measured limit, so nobody reads more into this than it carries: against a
# PREBUILT image the port is already patched into the guest forwarder, so
# drifting this constant and restating the literal here still passes. Mutating
# it proved that. What the read buys is that the script cannot silently test a
# different port than the tree builds -- it does not verify the image on disk
# was built from this tree. Provenance of $IMAGE_DIR is the operator's to know.
CDP_PORT="$(sed -n 's/^pub const CDP_PORT: u16 = \([0-9]*\);.*/\1/p' chm/src/oci/browser.rs)"
[ -n "$CDP_PORT" ] || { echo "could not read CDP_PORT from chm/src/oci/browser.rs" >&2; exit 2; }
READY_MARKER="$(sed -n 's/^pub const READY_MARKER: &str = "\(.*\)";$/\1/p' chm/src/oci/browser.rs)"
[ -n "$READY_MARKER" ] || { echo "could not read READY_MARKER from chm/src/oci/browser.rs" >&2; exit 2; }

info "chm         $CHM"
info "image       $IMAGE_DIR"
info "CDP port    $CDP_PORT (read from chm/src/oci/browser.rs)"
info "allowed     $ALLOW_HOST"
info "denied      $DENY_HOST"
echo

# ---------------------------------------------------------------------------
# Boot. --seconds 0 because the default 30s deadline tore down an early
# concurrency run mid-flight and presented as 96/96 connection failures.
# ---------------------------------------------------------------------------

"$CHM" create \
  --kernel "$IMAGE_DIR/Image" \
  --disk "$IMAGE_DIR/rootfs.img" \
  --cpus 2 \
  --memory 2048 \
  --net \
  --expose "$CDP_PORT" \
  --egress-allow "$ALLOW_HOST:443" \
  --workspace "$WORKSPACE" \
  --seconds 0 \
  >"$CONSOLE" 2>&1 </dev/null &
VM_PID=$!

# The host port is chosen by the OS, so it has to be read back off the console
# rather than assumed. That line is also check B's evidence that the listener
# is loopback-only.
HOST_PORT=""
for _ in $(seq 1 90); do
  kill -0 "$VM_PID" 2>/dev/null || break
  HOST_PORT="$(sed -n "s/^chm: ingress 127\.0\.0\.1:\([0-9]*\) -> guest .*:$CDP_PORT .*/\1/p" "$CONSOLE" | head -1)"
  [ -n "$HOST_PORT" ] && break
  sleep 1
done

if [ -z "$HOST_PORT" ]; then
  fail "ingress never announced a host port for guest $CDP_PORT"
  tail -20 "$CONSOLE"
  exit 1
fi
pass "ingress mapped 127.0.0.1:$HOST_PORT -> guest:$CDP_PORT"

GUEST_IP="$(sed -n "s/^chm: ingress 127\.0\.0\.1:$HOST_PORT -> guest \([0-9.]*\):$CDP_PORT .*/\1/p" "$CONSOLE" | head -1)"

# The browser announces its own readiness. Waiting for that marker rather than
# polling the port means a slow start is not confused with a failed one.
READY=no
for _ in $(seq 1 120); do
  kill -0 "$VM_PID" 2>/dev/null || break
  grep -qF "$READY_MARKER" "$CONSOLE" && { READY=yes; break; }
  grep -qF 'gimbal-browser: FAILED:' "$CONSOLE" && break
  sleep 1
done

if [ "$READY" != yes ]; then
  fail "the browser never reported itself ready"
  grep -F 'gimbal-browser' "$CONSOLE" | tail -10
  exit 1
fi
pass "browser reported ready ($(grep -oF "$READY_MARKER" -m1 "$CONSOLE" >/dev/null && grep -F "$READY_MARKER" "$CONSOLE" | head -1 | sed "s/.*$READY_MARKER//"))"
echo

# ---------------------------------------------------------------------------
# A. The happy path, and C's browser-visible half, in one session.
# ---------------------------------------------------------------------------

echo "A. Playwright drives the browser"
node "$REPO/scripts/hvf/browser-cdp-drive.mjs" \
  "$HOST_PORT" "https://$ALLOW_HOST/" "https://$DENY_HOST/" >"$DRIVER_OUT" 2>&1
DRIVER_RC=$?

read_key() { sed -n "s/^$1=//p" "$DRIVER_OUT" | head -1; }

if [ "$(read_key VERDICT)" = ok ]; then
  pass "connectOverCDP -> $(read_key VERSION)"
  pass "rendered in-guest: $(read_key LOCAL_DOM)"
  pass "screenshot $(read_key SHOT_BYTES) bytes, PNG signature present"
  pass "loaded https://$ALLOW_HOST/ -> \"$(read_key ALLOWED_TITLE)\" ($(read_key ALLOWED_BODY_CHARS) chars, $(read_key ALLOWED_MS) ms)"
else
  fail "the driver did not reach a verdict (rc=$DRIVER_RC)"
  sed 's/^/        /' "$DRIVER_OUT"
fi
echo

# ---------------------------------------------------------------------------
# B. Exposure is the only way in.
# ---------------------------------------------------------------------------

echo "B. the only path in is the exposed port"

if [ -n "$GUEST_IP" ]; then
  if nc -z -G 3 -w 3 "$GUEST_IP" "$CDP_PORT" 2>/dev/null; then
    fail "the guest address $GUEST_IP:$CDP_PORT answered the host directly"
    info "ingress is then not the thing granting access, and --expose is decorative"
  else
    pass "guest $GUEST_IP:$CDP_PORT is unreachable from the host"
  fi
else
  fail "could not read the guest address off the ingress line"
fi

# A port that was never exposed must have no host listener at all. Picking the
# CDP port + 1 keeps this honest: it is the neighbour of a port that IS mapped,
# so a range-mapping bug would show up here rather than hide.
UNEXPOSED=$((CDP_PORT + 1))
if nc -z -G 2 -w 2 127.0.0.1 "$UNEXPOSED" 2>/dev/null; then
  fail "127.0.0.1:$UNEXPOSED answered, but nothing exposed guest port $UNEXPOSED"
else
  pass "unexposed guest port $UNEXPOSED has no host listener"
fi

# The mapping is loopback-only, so it is not reachable from another machine on
# the network. chm says so on the console; check it said it.
if grep -q "^chm: ingress 127\.0\.0\.1:$HOST_PORT .*(loopback only)" "$CONSOLE"; then
  pass "the host listener is bound loopback-only"
else
  fail "the ingress line does not claim a loopback-only binding"
fi
echo

# ---------------------------------------------------------------------------
# C. Fail-closed egress, from both ends.
# ---------------------------------------------------------------------------

echo "C. egress stays fail-closed"

case "$(read_key DENIED_RESULT)" in
  refused)
    pass "the browser was refused https://$DENY_HOST/"
    info "$(read_key DENIED_ERROR)"
    ;;
  loaded)
    fail "the browser loaded https://$DENY_HOST/, which the policy does not permit"
    ;;
  *)
    fail "no result recorded for the denied destination"
    ;;
esac

# The browser's error alone is not proof the policy did it -- a site can be
# down. The console line is what names our gate as the cause.
if grep -qE "^chm: \[egress\] DENY .*$DENY_HOST" "$CONSOLE"; then
  pass "chm logged the refusal: $(grep -E "^chm: \[egress\] DENY .*$DENY_HOST" "$CONSOLE" | head -1 | sed 's/^chm: //')"
else
  fail "no [egress] DENY line for $DENY_HOST on the console"
  info "without it, the failed navigation could just be a site being down"
fi

if grep -qE "^chm: \[egress\] DENY .*$ALLOW_HOST" "$CONSOLE"; then
  fail "$ALLOW_HOST was denied despite being allow-listed"
else
  pass "no refusal recorded for the allow-listed $ALLOW_HOST"
fi

# The console is a stream someone has to be watching. #332 asks for the refusal
# to survive in the audit trail, which is what answers "what did this sandbox
# reach?" after the guest is gone. Read it as JSON so this asserts the recorded
# event rather than a sentence that may be reworded.
AUDIT_JSON="$("$CHM" audit show "$WORKSPACE" --json 2>/dev/null || true)"
if printf '%s\n' "$AUDIT_JSON" | grep -q 'no audit trail yet'; then
  fail "the run left no audit trail in $WORKSPACE"
  info "egress decisions on this path would be unanswerable once the guest stops"
elif printf '%s\n' "$AUDIT_JSON" \
  | grep '"event":"egress-deny"' | grep -q "$DENY_HOST"; then
  pass "the refusal is recorded as an egress-deny audit event"
else
  fail "no egress-deny audit event naming $DENY_HOST"
  info "the console said it; the durable record did not"
fi
echo

# ---------------------------------------------------------------------------
# D. No credentials anywhere near this browser.
# ---------------------------------------------------------------------------

echo "D. the credential proxy is not in play"

# A proxy decision is recorded as a `proxy` audit event whenever one is taken,
# so an empty set is the positive evidence that nothing was injected -- stronger
# than the absence of a console line, which is also what a silent proxy looks
# like.
if printf '%s\n' "$AUDIT_JSON" | grep -q '"event":"proxy"'; then
  fail "credential-proxy decisions recorded on a browser sandbox"
  printf '%s\n' "$AUDIT_JSON" | grep '"event":"proxy"' | head -5 | sed 's/^/        /'
elif printf '%s\n' "$AUDIT_JSON" | grep -q 'no audit trail yet'; then
  # Silence from a trail that does not exist is not evidence. Check C has
  # already failed this run, and claiming a pass here would report a safety
  # property nothing observed.
  fail "no audit trail, so nothing can say whether the proxy ran"
else
  pass "no credential-proxy decision was taken on this run"
fi

if grep -qiE 'disposition: inject|credential rule' "$CONSOLE"; then
  fail "credential-proxy activity on the console"
  grep -iE 'disposition: inject|credential rule' "$CONSOLE" | head -5 | sed 's/^/        /'
else
  pass "no credential rules and no injection on this run"
fi
echo

# ---------------------------------------------------------------------------

if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mV11.3 ACCEPTED\033[0m -- an agent drove a browser it cannot otherwise touch.\n'
  exit 0
fi

printf '\033[31mV11.3 REFUSED\033[0m -- %d check(s) failed.\n' "$FAILURES"
exit 1
