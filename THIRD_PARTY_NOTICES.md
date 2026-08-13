# Third-party notices

Gimbal Local includes and builds on third-party open-source software. This file
summarises the major upstream notices; individual files retain their own SPDX
identifiers and copyright notices.

## Cloud Hypervisor

Gimbal Local is derived from Cloud Hypervisor:

- Project: <https://www.cloudhypervisor.org/>
- Source: <https://github.com/cloud-hypervisor/cloud-hypervisor>
- Licence: Apache-2.0 AND BSD-3-Clause, with per-file SPDX identifiers

The current upstream baseline is recorded in `UPSTREAM-CHANGES.md`.

## Inherited Cloud Hypervisor credit chain

Cloud Hypervisor itself credits and incorporates work from the rust-vmm,
Firecracker, and crosvm projects. Gimbal Local preserves that inherited credit
chain in `CREDITS.md`.

## Rust dependencies

Rust crate dependencies are resolved through Cargo and recorded in `Cargo.lock`.
Their licence metadata is not rewritten here; distribution tooling should keep
third-party crate licence notices with any binary distribution.

## Apple platform frameworks

The macOS app and HVF backend use Apple platform APIs, including
Hypervisor.framework and SwiftUI. Apple, macOS, and related marks belong to
Apple Inc.
