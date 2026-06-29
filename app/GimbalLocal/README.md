# Gimbal Local

Gimbal Local is the native macOS desktop shell for `chm`: a Docker
Desktop-style dashboard for local Cloud Hypervisor sandboxes rehydrated on
Apple Hypervisor.framework.

It intentionally remains a thin app over the runtime:

- `chm serve` owns the local daemon and one running VM.
- `chm ctl list/status/start/console/stop/shutdown` is the local app contract.
- `gimbal-cloud-control` is optional; when `gctl server` is running, the app
  reads `/healthz`, `/runners`, `/snapshots`, `/sandboxes`, and `/cost/running`.

## Run from source

```sh
swift run --package-path app/GimbalLocal GimbalLocal
```

The default `chm` path is discovered from the repo root as `target/debug/chm`.
You can override paths before launching:

```sh
CHM_PATH=/absolute/path/to/chm \
GIMBAL_LIBRARY=/absolute/path/to/snapshots \
swift run --package-path app/GimbalLocal GimbalLocal
```

## Build a clickable app bundle

```sh
APP=$(./scripts/build-gimbal-local-app.sh)
open "$APP"
```

The packaging script builds and signs `chm`, builds the SwiftUI executable, and
creates `target/GimbalLocal.app`.

## Current M23 surface

- Start/shutdown a local `chm serve` daemon.
- Configure `chm`, snapshot library, socket, and control-plane URL.
- List local snapshot sandboxes from `chm ctl list --json`.
- Start/stop a selected sandbox and attach to its serial console.
- Show local daemon/VM state from `chm ctl status --json`.
- Show optional cloud-control health, runner count, snapshot count, sandbox
  count, and cost summary when `gimbal-cloud-control` is reachable.
