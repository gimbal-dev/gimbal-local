#!/usr/bin/env bash
#
# capture-arm-snapshot.sh — produce a REAL cloud-hypervisor arm64 KVM snapshot.
#
# Runs INSIDE any aarch64 Linux host that exposes /dev/kvm:
#   * a Lima nested-virtualization guest on an Apple M3+ Mac (see capture-on-mac.sh)
#   * an AWS Graviton *.metal instance, Oracle BM.Standard.A1, or any ARM bare metal
#
# It boots a throwaway Ubuntu guest under cloud-hypervisor, lets it reach
# userspace (so the GICv3 distributor/redistributors and vCPU registers hold
# real state), then `pause`s and `snapshot`s it. The snapshot directory
# contains `state.json` — which serializes every vCPU's `VcpuKvmState`
# (kvm_regs + the system-register kvm_one_reg list) AND the GIC
# `Gicv3ItsState { dist, rdist, icc, gicd_ctlr }` — exactly the input the
# macOS Hypervisor.framework port's KVM->HVF translator consumes.
#
# Output (under $OUT_DIR, default ./ch-arm-snapshot):
#   snapshot/                full cloud-hypervisor snapshot (state.json + memory)
#   state.json               copied out for convenience (the small fixture)
#   ch-arm-snapshot.tar.zst  the whole snapshot, compressed, ready to copy out
#
# Everything is overridable by environment variable; see the CONFIG block.
# If CH_BIN/CHREMOTE_BIN are set, those binaries are used instead of downloading
# upstream release binaries. Use that for HVF-compatible GICv2M captures from
# this fork; upstream binaries do not understand this fork's CH_GIC_V2M patch.

set -euo pipefail

# --------------------------------- CONFIG ---------------------------------- #
CH_VERSION="${CH_VERSION:-v52.0}"
CH_URL="${CH_URL:-https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static-aarch64}"
CHREMOTE_URL="${CHREMOTE_URL:-https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/ch-remote-static-aarch64}"
CH_BIN="${CH_BIN:-}"
CHREMOTE_BIN="${CHREMOTE_BIN:-}"
# AArch64 EDK2 UEFI firmware from cloud-hypervisor's edk2 fork (boots cloud images).
FW_URL="${FW_URL:-https://github.com/cloud-hypervisor/edk2/releases/latest/download/CLOUDHV_EFI.fd}"
# Ubuntu 24.04 (noble) arm64 cloud image — a real distro guest.
IMG_URL="${IMG_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img}"

GUEST_CPUS="${GUEST_CPUS:-1}"
GUEST_MEM_MB="${GUEST_MEM_MB:-1024}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"   # seconds to wait for the in-guest marker
CH_GIC_V2M="${CH_GIC_V2M:-1}"         # 1 = HVF-compatible message-SPI capture
REUSE_GUEST_RAW="${REUSE_GUEST_RAW:-0}" # 1 = reuse cached guest.raw; default fresh
# NOTE: default is a *fresh* guest.raw on every capture. Reusing a cached disk is
# what previously baked a chatty `chm-heartbeat` service into the snapshot, which
# then floods the serial console after an HVF resume. Keep this 0 unless you have
# a specific reason and know the cached disk is clean.

WORK_DIR="${WORK_DIR:-$HOME/.cache/ch-arm-snapshot}"
OUT_DIR="${OUT_DIR:-$PWD/ch-arm-snapshot}"
# --------------------------------------------------------------------------- #

log()  { printf '\033[1;36m[capture]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[capture]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[capture] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -m)" = "aarch64" ] || die "must run on aarch64 (this is $(uname -m))"
[ -e /dev/kvm ] || die "/dev/kvm is missing — this host has no (nested) KVM. \
On an M3+ Mac use capture-on-mac.sh; in the cloud use an ARM *.metal instance."
[ -r /dev/kvm ] && [ -w /dev/kvm ] || \
  warn "/dev/kvm is not read/writable by $(id -un); will use sudo for the VM."

KVM_PREFIX=()
if ! { [ -r /dev/kvm ] && [ -w /dev/kvm ]; }; then KVM_PREFIX=(sudo); fi

# --- dependencies ---------------------------------------------------------- #
need_apt=()
command -v qemu-img    >/dev/null 2>&1 || need_apt+=(qemu-utils)
command -v cloud-localds >/dev/null 2>&1 || need_apt+=(cloud-image-utils)
command -v curl        >/dev/null 2>&1 || need_apt+=(curl)
command -v zstd        >/dev/null 2>&1 || need_apt+=(zstd)
if [ "${#need_apt[@]}" -gt 0 ]; then
  log "installing host deps: ${need_apt[*]}"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need_apt[@]}"
fi

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

fetch() { # url dest
  local url="$1" dest="$2"
  if [ -s "$dest" ]; then log "have $(basename "$dest") (cached)"; return; fi
  log "downloading $(basename "$dest")"
  curl --fail --location --progress-bar --output "$dest.part" "$url"
  mv "$dest.part" "$dest"
}

if [ -n "$CH_BIN" ]; then
  [ -x "$CH_BIN" ] || die "CH_BIN is set but not executable: $CH_BIN"
  log "using cloud-hypervisor from CH_BIN=$CH_BIN"
  cp "$CH_BIN" cloud-hypervisor
else
  warn "using upstream cloud-hypervisor release; CH_GIC_V2M requires this fork's patched binary"
  fetch "$CH_URL" cloud-hypervisor
fi

if [ -n "$CHREMOTE_BIN" ]; then
  [ -x "$CHREMOTE_BIN" ] || die "CHREMOTE_BIN is set but not executable: $CHREMOTE_BIN"
  log "using ch-remote from CHREMOTE_BIN=$CHREMOTE_BIN"
  cp "$CHREMOTE_BIN" ch-remote
else
  fetch "$CHREMOTE_URL" ch-remote
fi
fetch "$FW_URL"      CLOUDHV_EFI.fd
fetch "$IMG_URL"     noble-arm64.img
chmod +x cloud-hypervisor ch-remote

# --- build the guest disk + a NoCloud seed (autologin, no network needed) --- #
if [ "$REUSE_GUEST_RAW" != "1" ] || [ ! -s guest.raw ]; then
  log "converting cloud image to fresh raw guest disk"
  rm -f guest.raw
  qemu-img convert -O raw noble-arm64.img guest.raw
  qemu-img resize -f raw guest.raw 8G >/dev/null
else
  log "reusing cached guest.raw (REUSE_GUEST_RAW=1)"
fi

MARKER="CH_SNAPSHOT_READY_$$"
log "building NoCloud seed (marker=$MARKER)"
rm -f seed.img
cat > user-data <<EOF
#cloud-config
password: ubuntu
chpasswd: { expire: false }
ssh_pwauth: true
write_files:
  - path: /etc/systemd/system/serial-getty@ttyAMA0.service.d/autologin.conf
    permissions: '0644'
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin ubuntu --noclear %I $TERM
# No datasource network wait; just announce readiness on the serial console so
# the host knows the guest fully booted and the GIC/vCPU state is "interesting".
runcmd:
  - [ systemctl, daemon-reload ]
  - [ sh, -c, "systemctl disable --now chm-heartbeat.service chm-heartbeat.timer 2>/dev/null || true" ]
  - [ sh, -c, "rm -f /etc/systemd/system/chm-heartbeat.service /etc/systemd/system/chm-heartbeat.timer /lib/systemd/system/chm-heartbeat.service /lib/systemd/system/chm-heartbeat.timer" ]
  - [ systemctl, daemon-reload ]
  - [ systemctl, restart, serial-getty@ttyAMA0.service ]
  - [ sh, -c, "echo $MARKER > /dev/ttyAMA0" ]
EOF
cat > meta-data <<EOF
instance-id: ch-snap-$$
local-hostname: ch-snap
EOF
cloud-localds seed.img user-data meta-data

# --- boot under cloud-hypervisor ------------------------------------------- #
API_SOCK="$WORK_DIR/ch.sock"
SERIAL_LOG="$WORK_DIR/serial.log"
rm -f "$API_SOCK" "$SERIAL_LOG"
: > "$SERIAL_LOG"

CH_PID=""
cleanup() {
  if [ -n "$CH_PID" ] && kill -0 "$CH_PID" 2>/dev/null; then
    log "shutting the guest down"
    "${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" shutdown-vmm 2>/dev/null || true
    sleep 1
    kill "$CH_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log "booting guest (${GUEST_CPUS} vCPU, ${GUEST_MEM_MB} MiB) under cloud-hypervisor"
log "GIC capture mode: CH_GIC_V2M=${CH_GIC_V2M} (1 means message-SPI, not ITS/LPI)"
CH_ENV=(env "CH_GIC_V2M=$CH_GIC_V2M")
if [ "${#KVM_PREFIX[@]}" -gt 0 ]; then
  CH_ENV=(sudo env "CH_GIC_V2M=$CH_GIC_V2M")
fi
"${CH_ENV[@]}" ./cloud-hypervisor \
  --api-socket "$API_SOCK" \
  --firmware ./CLOUDHV_EFI.fd \
  --disk path=guest.raw --disk path=seed.img,readonly=on \
  --cpus "boot=${GUEST_CPUS}" \
  --memory "size=${GUEST_MEM_MB}M" \
  --serial "file=$SERIAL_LOG" \
  --console off \
  >"$WORK_DIR/ch.stdout" 2>"$WORK_DIR/ch.stderr" &
CH_PID=$!

# --- wait for the guest to reach userspace --------------------------------- #
log "waiting up to ${BOOT_TIMEOUT}s for the guest to finish booting"
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
booted=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$CH_PID" 2>/dev/null; then
    warn "cloud-hypervisor exited early; stderr:"; cat "$WORK_DIR/ch.stderr" >&2
    die "guest VMM died before snapshot"
  fi
  if grep -q "$MARKER" "$SERIAL_LOG" 2>/dev/null; then booted=1; break; fi
  # Fallback: cloud-init has FULLY finished. This is the only other signal that
  # is safe to snapshot on, because the "finished" banner is printed after
  # `modules:final` completes — i.e. after our runcmd has run, restarted the
  # getty, and echoed $MARKER. A bare "Reached target ..." is NOT safe:
  # cloud-init.target / multi-user.target are reached BEFORE cloud-final runs the
  # runcmd, so snapshotting then can catch the guest mid getty-restart and wedge
  # the captured state on resume.
  if grep -qE "Cloud-init v.* finished" "$SERIAL_LOG" 2>/dev/null; then
    booted=1; break
  fi
  sleep 2
done
if [ "$booted" -eq 1 ]; then
  log "guest is up; letting it settle for 5s"
  sleep 5
else
  warn "boot marker not seen in ${BOOT_TIMEOUT}s — snapshotting anyway \
(kernel + GIC are almost certainly live). Check $SERIAL_LOG if restore misbehaves."
fi

# --- pause + snapshot ------------------------------------------------------ #
SNAP_DIR="$OUT_DIR/snapshot"
rm -rf "$SNAP_DIR"; mkdir -p "$SNAP_DIR"

log "pausing the guest"
"${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" pause

log "taking the snapshot -> $SNAP_DIR"
"${KVM_PREFIX[@]}" ./ch-remote --api-socket "$API_SOCK" snapshot "file://$SNAP_DIR"

# cloud-hypervisor writes files owned by root when we used sudo; make them ours.
if [ "${#KVM_PREFIX[@]}" -gt 0 ]; then sudo chown -R "$(id -u):$(id -g)" "$SNAP_DIR"; fi

[ -s "$SNAP_DIR/state.json" ] || die "snapshot produced no state.json"
cp "$SNAP_DIR/state.json" "$OUT_DIR/state.json"

log "snapshot contents:"
ls -lh "$SNAP_DIR" | sed 's/^/    /'

# --- export the guest disks so the snapshot is self-contained --------------- #
# A CH snapshot references its disks by host path but does NOT embed them. chm
# needs the real disk content to rehydrate a guest that does post-resume I/O, so
# export each disk under <OUT_DIR>/disks/<device-id>.raw — the id (e.g. _disk0)
# is exactly the device-node name chm's shipped_backing() looks for. chm reads
# these through a per-run copy-on-write overlay, so the exported base stays
# pristine and every resume is consistent with the restored RAM. The guest is
# still paused here, so the disks match the memory image instant-for-instant.
DISKS_DIR="$OUT_DIR/disks"
rm -rf "$DISKS_DIR"; mkdir -p "$DISKS_DIR"
python3 - "$SNAP_DIR/config.json" <<'PY' | while IFS="$(printf '\t')" read -r id src; do
import json, sys
cfg = json.load(open(sys.argv[1]))
for d in cfg.get("disks", []):
    print(f"{d['id']}\t{d['path']}")
PY
  case "$src" in
    /*) abs="$src" ;;
    *)  abs="$WORK_DIR/$src" ;;
  esac
  if [ -f "$abs" ]; then
    log "exporting disk $id <- $abs"
    cp --sparse=always "$abs" "$DISKS_DIR/$id.raw"
  else
    warn "disk source for $id not found at $abs; skipping \
(guest will fall back to a zero overlay for this disk)"
  fi
done
if [ "${#KVM_PREFIX[@]}" -gt 0 ]; then
  sudo chown -R "$(id -u):$(id -g)" "$DISKS_DIR" 2>/dev/null || true
fi
log "exported disks:"
ls -lh "$DISKS_DIR" | sed 's/^/    /'

# Quick sanity: confirm the artifact really carries KVM vCPU + GIC state.
if grep -q '"core_regs"' "$SNAP_DIR/state.json" 2>/dev/null; then
  log "state.json carries vCPU core_regs ✓"
fi
if grep -qiE '"(gicd_ctlr|rdist|dist)"' "$SNAP_DIR/state.json" 2>/dev/null; then
  log "state.json carries GIC distributor/redistributor state ✓"
fi
ITS_ENABLED="$(python3 - "$SNAP_DIR/state.json" <<'PY'
import json
import sys

try:
    root = json.load(open(sys.argv[1]))
    state = root["snapshots"]["device-manager"]["snapshots"]["gic-v3-its"]["snapshot_data"]["state"]
    kvm = json.loads(state)["Kvm"]
    print("1" if (int(kvm.get("its_ctlr", 0)) & 1) else "0")
except Exception:
    print("0")
PY
)"
if [ "$ITS_ENABLED" = "1" ]; then
  warn "snapshot has an enabled ITS; this is not HVF-compatible"
  warn "ensure CH_BIN points to this fork's patched cloud-hypervisor binary"
else
  log "GITS_CTLR.Enabled is clear ✓ — HVF-compatible message-SPI interrupt mode"
fi

# --- package --------------------------------------------------------------- #
# A complete, self-contained bundle: RAM/device snapshot + the disk images. The
# disks dominate the size, so default to a fast zstd level (override with
# ZSTD_LEVEL). Set PACKAGE_TARBALL=0 to skip packaging entirely when you only
# need the on-disk <OUT_DIR>/{snapshot,disks,state.json} layout (chm uses that
# directly; the tarball is for off-box sharing).
if [ "${PACKAGE_TARBALL:-1}" = "1" ]; then
  TARBALL="$OUT_DIR/ch-arm-snapshot.tar.zst"
  ZSTD_LEVEL="${ZSTD_LEVEL:-6}"
  log "packaging -> $TARBALL (zstd -$ZSTD_LEVEL, includes disks)"
  tar -C "$OUT_DIR" -c snapshot disks state.json | zstd -q "-$ZSTD_LEVEL" -o "$TARBALL" -f
  log "  tarball           : $TARBALL  ($(wc -c < "$TARBALL") bytes)"
fi

log "DONE."
log "  full snapshot dir : $SNAP_DIR"
log "  disks dir         : $DISKS_DIR"
log "  state.json        : $OUT_DIR/state.json  ($(wc -c < "$OUT_DIR/state.json") bytes)"
log ""
log "Copy the <OUT_DIR> tree (or the tarball) back to the Mac; chm reads the"
log "snapshot/, disks/ and state.json directly."
