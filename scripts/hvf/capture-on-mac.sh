#!/usr/bin/env bash
#
# capture-on-mac.sh — capture a real cloud-hypervisor arm64 KVM snapshot
# entirely on an Apple Silicon Mac, using Lima nested virtualization.
#
# What it does:
#   1. Verifies this is an M3+ Mac on macOS 15+ (nested-virt prerequisites).
#   2. Installs Lima (via Homebrew) if it is missing.
#   3. Starts the `lima-arm-kvm.yaml` guest, which exposes /dev/kvm nested.
#   4. Runs capture-arm-snapshot.sh INSIDE that guest, where cloud-hypervisor
#      boots a throwaway Ubuntu VM and snapshots it.
#   5. Copies the resulting snapshot back to the Mac.
#
# Output lands in $OUT_DIR (default: ./ch-arm-snapshot on the Mac).
#
# Usage:
#   scripts/hvf/capture-on-mac.sh            # capture, leave the VM running
#   KEEP_VM=0 scripts/hvf/capture-on-mac.sh  # capture, then stop the Lima VM

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="${VM_NAME:-arm-kvm}"
TEMPLATE="$HERE/lima-arm-kvm.yaml"
OUT_DIR="${OUT_DIR:-$PWD/ch-arm-snapshot}"
KEEP_VM="${KEEP_VM:-1}"
USE_LOCAL_CH="${USE_LOCAL_CH:-1}"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

log()  { printf '\033[1;35m[mac]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mac] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- prerequisites --------------------------------------------------------- #
[ "$(uname -s)" = "Darwin" ] || die "run this on macOS"
[ "$(uname -m)" = "arm64" ]  || die "run this on Apple Silicon"

CHIP="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
case "$CHIP" in
  *"M1"*|*"M2"*)
    die "$CHIP has NO nested virtualization. Nested /dev/kvm needs Apple M3 or \
later. Use the cloud fallback (an ARM *.metal instance) with capture-arm-snapshot.sh." ;;
  *) log "chip: $CHIP" ;;
esac

OS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
[ "$OS_MAJOR" -ge 15 ] || die "macOS 15 (Sequoia) or newer is required for nested \
virtualization; this is $(sw_vers -productVersion)."

# --- Lima ------------------------------------------------------------------ #
if ! command -v limactl >/dev/null 2>&1; then
  command -v brew >/dev/null 2>&1 || die "Homebrew not found; install Lima manually."
  log "installing Lima via Homebrew"
  brew install lima
fi
log "lima: $(limactl --version)"

mkdir -p /tmp/lima "$OUT_DIR"
GUEST_OUT="/tmp/lima/ch-arm-snapshot"
GUEST_WORK="/var/tmp/ch-arm-snapshot-work"

# --- start the nested-KVM guest -------------------------------------------- #
if limactl list --quiet 2>/dev/null | grep -qx "$VM_NAME"; then
  log "Lima VM '$VM_NAME' already exists; ensuring it is started"
  limactl start "$VM_NAME"
else
  log "creating + starting Lima VM '$VM_NAME' (nested virtualization)"
  limactl start --name="$VM_NAME" --tty=false "$TEMPLATE"
fi

log "verifying nested /dev/kvm inside the guest"
if ! limactl shell "$VM_NAME" test -e /dev/kvm; then
  die "nested /dev/kvm did not appear inside the guest. See the probe hint above."
fi
log "nested /dev/kvm is present ✓ — this M3 really can host KVM."

CH_BIN_ENV=()
if [ "$USE_LOCAL_CH" = "1" ]; then
  GUEST_REPO="${LIMA_REPO:-$REPO_ROOT}"
  GUEST_TARGET="$GUEST_WORK/ch-target"
  log "building this fork's Linux/aarch64 cloud-hypervisor inside Lima"
  limactl shell "$VM_NAME" env GUEST_REPO="$GUEST_REPO" GUEST_TARGET="$GUEST_TARGET" bash -s <<'EOS'
set -euo pipefail
[ -d "$GUEST_REPO" ] || { echo "repo not visible inside Lima: $GUEST_REPO" >&2; exit 1; }
need_apt=()
command -v curl >/dev/null 2>&1 || need_apt+=(curl)
command -v cc >/dev/null 2>&1 || need_apt+=(build-essential)
command -v pkg-config >/dev/null 2>&1 || need_apt+=(pkg-config)
pkg-config --exists openssl 2>/dev/null || need_apt+=(libssl-dev)
pkg-config --exists libcap-ng 2>/dev/null || need_apt+=(libcap-ng-dev)
pkg-config --exists libseccomp 2>/dev/null || need_apt+=(libseccomp-dev)
if [ "${#need_apt[@]}" -gt 0 ]; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need_apt[@]}"
fi
if ! command -v cargo >/dev/null 2>&1 || ! cargo --version | grep -Eq 'cargo 1\.(8[9-9]|9[0-9])|cargo [2-9]\.'; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  . "$HOME/.cargo/env"
fi
cargo build --manifest-path "$GUEST_REPO/Cargo.toml" --target-dir "$GUEST_TARGET" \
  -p cloud-hypervisor --bin cloud-hypervisor --bin ch-remote
EOS
  CH_BIN_ENV=(CH_BIN="$GUEST_TARGET/debug/cloud-hypervisor" CHREMOTE_BIN="$GUEST_TARGET/debug/ch-remote")
fi

# --- run the capture inside the guest -------------------------------------- #
# Guard against a previously-interrupted run leaving a cloud-hypervisor guest
# alive inside Lima. If it is still holding ./cloud-hypervisor open, the next
# capture fails with "Text file busy" when it tries to refresh the binary. This
# is exactly what stranded earlier attempts, so clear it pre-emptively.
log "clearing any stale capture processes inside Lima"
limactl shell "$VM_NAME" sh -lc '
  pids=$(ps -eo pid,args | grep -E "ch-arm-snapshot-work|cloud-hypervisor|ch-remote" | grep -v grep | awk "{print \$1}")
  if [ -n "$pids" ]; then
    echo "killing stale: $pids"
    kill $pids 2>/dev/null || true
    sleep 2
    for p in $pids; do kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true; done
  fi
' || true


log "running capture-arm-snapshot.sh inside the guest (this downloads ~600MB \
and boots a real Ubuntu guest; expect several minutes)"
limactl shell "$VM_NAME" env OUT_DIR="$GUEST_OUT" WORK_DIR="$GUEST_WORK" \
  CH_GIC_V2M="${CH_GIC_V2M:-0}" GUEST_CPUS="${GUEST_CPUS:-1}" GUEST_NET="${GUEST_NET:-0}" \
  "${CH_BIN_ENV[@]}" \
  bash -s < "$HERE/capture-arm-snapshot.sh"

# --- collect the artifact -------------------------------------------------- #
# /tmp/lima is a writable shared mount, so the output is already on the Mac.
# The exported disks can be large but are sparse; macOS `cp` preserves the holes
# when writing to APFS, so the on-disk footprint stays close to the used size.
if [ -d "$GUEST_OUT" ]; then
  log "copying snapshot from the shared mount to $OUT_DIR"
  cp -Rc "$GUEST_OUT/snapshot" "$OUT_DIR/" 2>/dev/null || cp -R "$GUEST_OUT/snapshot" "$OUT_DIR/"
  cp "$GUEST_OUT/state.json" "$OUT_DIR/state.json"
  if [ -d "$GUEST_OUT/disks" ]; then
    mkdir -p "$OUT_DIR/disks"
    # Copy each disk preserving sparseness (clone on APFS when possible).
    for d in "$GUEST_OUT/disks"/*; do
      [ -e "$d" ] || continue
      cp -c "$d" "$OUT_DIR/disks/" 2>/dev/null || cp "$d" "$OUT_DIR/disks/"
    done
  else
    warn "no disks/ in the captured output — the guest will fall back to a \
zero overlay and may hit I/O errors after resume."
  fi
else
  die "expected output at $GUEST_OUT (shared mount) but it is missing."
fi

[ -s "$OUT_DIR/state.json" ] || die "no state.json in $OUT_DIR"
log "captured snapshot on the Mac:"
ls -lh "$OUT_DIR" | sed 's/^/    /'
if [ -d "$OUT_DIR/disks" ]; then
  log "exported disks (apparent / actual on APFS):"
  for d in "$OUT_DIR/disks"/*; do
    [ -e "$d" ] || continue
    printf '    %s  apparent=%s actual=%s\n' "$(basename "$d")" \
      "$(ls -lh "$d" | awk '{print $5}')" "$(du -h "$d" | awk '{print $1}')"
  done
fi

if [ "$KEEP_VM" = "0" ]; then
  log "stopping Lima VM '$VM_NAME' (KEEP_VM=0)"
  limactl stop "$VM_NAME"
fi

log "DONE. Real arm64 KVM snapshot is at: $OUT_DIR"
log "  state.json (registers + GIC blob): $OUT_DIR/state.json"
log "  full snapshot + memory          : $OUT_DIR/snapshot/"
log "  guest disks (COW base images)   : $OUT_DIR/disks/"
