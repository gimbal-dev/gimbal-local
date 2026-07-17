# Maintainers

Gimbal Local is a macOS-focused fork of
[Cloud Hypervisor](https://www.cloudhypervisor.org/). It is maintained as its own
project (the macOS / Apple Hypervisor.framework runtime) and does **not** track
upstream for merge-back.

## Gimbal Local maintainers

The macOS runtime — `chm`, the `hypervisor/src/hvf/` backend, and the
`app/GimbalLocal/` desktop app:

- Ben De St Paer-Gotch — [@nebuk89](https://github.com/nebuk89)

## Upstream Cloud Hypervisor

The Linux/KVM VMM crates this project forks from (kept in-tree only to build the
patched `cloud-hypervisor` binary used to *capture* HVF-compatible snapshots) are
maintained by the upstream Cloud Hypervisor project:

- Sebastien Boeuf - @sboeuf
- Robert Bradford - @rbradford
- Bo Chen - @likebreath
- Samuel Ortiz - @sameo
- Wei Liu - @liuw
- Michael Zhao - @michael2012z

See [`CREDITS.md`](CREDITS.md) for the projects and contributors the upstream
code is based on.
