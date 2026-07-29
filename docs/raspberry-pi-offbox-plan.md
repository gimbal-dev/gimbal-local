# Raspberry Pi off-box Linux/KVM snapshot plan

This is the fallback plan while AWS bare-metal quota is blocked.

The goal is narrower than the AWS milestone but still valuable:

```text
Raspberry Pi Linux/KVM host -> cloud-hypervisor snapshot -> local Mac chm
```

This proves the snapshot was produced on a physically separate Linux/KVM arm64
box, not by nested KVM on the Mac. It does **not** retire the real-cloud
milestone; it de-risks it.

## Honest compatibility gate

The current capture path needs a KVM host that can create a **VGICv3** device.
`/dev/kvm` alone is not enough.

Raspberry Pi guidance:

| Board | Expected fit | Why |
| --- | --- | --- |
| Raspberry Pi 5 | Best candidate | arm64 CPU, likely enough performance, possible KVM/VGICv3 with the right 64-bit kernel |
| Raspberry Pi 4 | High risk / probably no-go for this repo today | commonly exposes GICv2/VGICv2, while the current KVM capture code creates VGICv3 |

If the board cannot run a VGICv3 KVM guest, stop. The next choice is either:

1. use a different arm64 Linux box with VGICv3; or
2. add a separate VGICv2 snapshot ingest/translation path, which is a real new
   engineering milestone, not a setup tweak.

## Hardware setup

Recommended:

- Raspberry Pi 5, 8 GB or better;
- 64-bit Raspberry Pi OS or Ubuntu Server arm64;
- active cooling;
- wired Ethernet;
- SSD or fast USB storage, not a tiny SD card;
- at least 20 GB free disk space.

## Step 1: Prepare the Pi

On the Pi:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cloud-image-utils \
  curl \
  git \
  jq \
  pkg-config \
  qemu-system-arm \
  qemu-utils \
  zstd
```

Confirm it is a 64-bit arm64 host:

```bash
uname -m
```

Expected:

```text
aarch64
```

Confirm KVM exists:

```bash
test -e /dev/kvm && echo "KVM is present"
ls -l /dev/kvm
```

If `/dev/kvm` is missing, stop and fix the Pi kernel/OS first.

## Step 2: Check VGICv3 before spending time

Run this on the Pi:

```bash
timeout 5s sudo qemu-system-aarch64 \
  -accel kvm \
  -machine virt,gic-version=3 \
  -cpu host \
  -m 256M \
  -nographic \
  -nodefaults \
  -S
```

Interpretation:

- exit code `124` from `timeout` usually means QEMU started and waited: good;
- an immediate error mentioning KVM, GICv3, VGIC, or unsupported machine config
  means this Pi is not suitable for the current capture path.

Optional debug:

```bash
dmesg | grep -Ei 'kvm|gic|vgic' | tail -80
```

## Step 3: Copy the capture script to the Pi

From the Mac, in this repo:

```bash
export PI_HOST=pi@raspberrypi.local

scp scripts/hvf/capture-arm-snapshot.sh "$PI_HOST:/tmp/capture-arm-snapshot.sh"
```

## Step 4: Capture a first off-box snapshot

On the Mac, run the script remotely:

```bash
ssh "$PI_HOST" \
  'CH_GIC_V2M=0 GUEST_CPUS=1 GUEST_MEM_MB=1024 OUT_DIR=$HOME/ch-arm-snapshot bash /tmp/capture-arm-snapshot.sh'
```

`CH_GIC_V2M=0` is the vanilla shape: stock upstream ITS/LPI routing, no fork.
It is the script default; the remote command keeps it explicit so the capture
mode is obvious in the logs. Run the result on the Mac with no flags — `chm`
reads the capture and routes ITS/LPI bundles to its software GICv3, which
delivers the LPIs Apple's managed GIC cannot.

`CH_GIC_V2M=1` produces the legacy GICv2M/message-SPI shape. Nothing requires
it any more — `chm run`, `chm serve` and the app all take vanilla captures — so
it is kept only as a regression fixture for the managed-GIC path. It is this
fork's patch, so it also needs `CH_BIN`/`CHREMOTE_BIN`.

## Step 5: Copy the snapshot back to the Mac

```bash
mkdir -p ./snapshots/pi-offbox

rsync -avz \
  "$PI_HOST:~/ch-arm-snapshot/snapshot/" \
  ./snapshots/pi-offbox/
```

The expected local shape is:

```text
snapshots/pi-offbox/
  state.json
  memory-ranges
  config.json
```

## Step 6: Rehydrate locally

Build the Mac runtime:

```bash
bash scripts/build-chm.sh
```

Run the Pi-produced snapshot:

```bash
target/debug/chm run ./snapshots/pi-offbox --max-seconds 30 --idle-exit 0
```

Pass condition for the first proof:

- `chm` accepts the snapshot without the ITS/LPI guard rejecting it;
- the restored guest reaches serial output or a login prompt;
- no unsupported GIC/vCPU translation error appears.

## Step 7: Stretch proofs

After the single-vCPU boot proof:

1. Repeat with `GUEST_CPUS=2` to verify off-box SMP snapshot resume.
2. Repeat with the net capture workload once the Pi path is stable.
3. Add a small `chm remote capture ssh` wrapper so the Mac can copy the script,
   run capture, rsync the snapshot, and invoke `chm run` in one command.

## What this retires

This retires the "only captured inside nested Lima on the Mac" concern.

It does **not** retire the "real cloud" claim. AWS/Oracle still matter because
the dream is cloud snapshot mobility, but the Pi path is the fastest honest
next proof while AWS quota is blocked.
