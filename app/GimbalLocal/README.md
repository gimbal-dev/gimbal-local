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

- Polished macOS dashboard with a glass-card layout, hero launch area, status
  pills, premium sidebar, and terminal-styled console/activity panes.
- Auto-start `chm serve` on launch when the local daemon is not reachable, and
  create the configured snapshot library folder if needed.
- Focus on creating and managing sandboxes; the local engine is background
  plumbing surfaced only as an always-visible status bar at the bottom of the
  window (a small colour icon for the engine and the optional control plane).
- Move all engine tweaks into a dedicated Settings window (⌘,): configure `chm`,
  snapshot library, socket, and control-plane URL, and start/restart/shut down
  the local engine — including a one-click restart when it becomes unresponsive.
- Menu bar extra so the app stays useful with the main window closed: lists the
  three most recently active sandboxes with "See more", "Shut Down Engine", and
  "Open Main App".
- List local snapshot sandboxes from `chm ctl list --json`.
- Start/stop a selected sandbox and follow its serial console as an explicit
  read-only live stream. Keyboard input is not wired through the app yet; use
  **Connect to session** to open Terminal.app with an interactive `chm run`
  serial session for the selected sandbox.
- Show local daemon/VM state from `chm ctl status --json`.
- Surface immediate start failures, including unsupported ITS/LPI snapshots,
  directly in the sandbox state and console panels.
- Show optional cloud-control health, runner count, snapshot count, sandbox
  count, and cost summary when `gimbal-cloud-control` is reachable.
