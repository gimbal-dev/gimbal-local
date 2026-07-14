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

## Current surface

- Split navigation: a **Sandboxes** page and a **Snapshots** page, each with its
  own sidebar section and main view. The app opens on Sandboxes.
- **Sandboxes** are instances; **Snapshots** are the image templates you launch
  them from. The UI is built around N sandboxes and N snapshots — you can launch
  several sandboxes from the same image. Each sandbox carries a location badge
  (Local today, Remote planned) so location stays an implementation detail.
- The Sandboxes page leads with **New sandbox** when empty; each sandbox card and
  detail view make **Open terminal** (work *inside* the sandbox) the primary
  action. The read-only serial console is secondary — a collapsed expander in the
  sandbox detail, not the main surface.
- A dismissible welcome banner appears on first run and can be closed for good.
- Auto-start `chm serve` on launch when the local daemon is not reachable, and
  create the configured snapshot library folder if needed.
- The local engine is background plumbing surfaced only as an always-visible
  status bar at the bottom of the window, which also carries the **only**
  control-plane indicator. All engine and control-plane details live in the
  Settings window (⌘,): Engine, Runtime paths, and Control plane tabs.
- Menu bar extra so the app stays useful with the main window closed: lists
  recent sandboxes, "See all…", "Shut Down Engine", and "Open Main App".
- Start/stop sandboxes via `chm ctl`, and open an interactive session with
  `chm connect`. Surfaces start failures (including unsupported ITS/LPI
  snapshots) in the sandbox detail.
- **Connectivity** control in the sandbox detail: a per-sandbox outbound network
  firewall with **Open / No network / Allow-list** postures (`host:port` rules).
  It is a client of `chm firewall`, which writes the sandbox workspace's
  `egress-policy.json`; the userspace NAT enforces it on the next start — no
  control plane required. A control-plane-bound policy is shown read-only.
- Shows optional cloud-control health, runner/snapshot/sandbox counts, and cost
  summary in the Control plane settings tab when `gimbal-cloud-control` is
  reachable.

### Source layout

| File | Responsibility |
| --- | --- |
| `GimbalLocalApp.swift` | App entry, windows, menus, menu-bar extra, Dock icon. |
| `ContentView.swift` | Split-view shell: sidebar, detail router, bottom status bar. |
| `SandboxesView.swift` | Sandboxes page, sandbox cards, and the work-inside detail. |
| `SnapshotsView.swift` | Snapshots page, image cards, and snapshot detail. |
| `SettingsView.swift` | Engine / Runtime / Control plane settings tabs. |
| `DesignSystem.swift` | Theme, shared atoms, the rounded app-icon view, badges. |
| `AppModel.swift` | State + orchestration over `chm`. |
| `Models.swift` | `Sandbox`, `SnapshotSummary`, status/overview, navigation types. |
| `ChmClient.swift` / `CloudControlClient.swift` | `chm` and control-plane I/O. |
