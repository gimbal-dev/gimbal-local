# Cloud Hypervisor for macOS — local-runtime convenience targets.
#
# These wrap the `chm` standalone executable (Apple Silicon only). The binary
# must be code-signed with the hypervisor entitlement before it can create a
# VM; `scripts/build-chm.sh` does the build + sign and prints the path.

CHM_BIN := target/debug/chm
SOCKET  ?= $${TMPDIR:-/tmp}/chm.sock

.PHONY: help chm chm-run chm-serve clippy fmt test-hvf

help:
	@echo "Cloud Hypervisor for macOS — make targets:"
	@echo "  make chm                      Build + code-sign the chm binary"
	@echo "  make chm-run DIR=<snapshot>   Resume a snapshot, stream console"
	@echo "  make chm-serve DIR=<library>  Run the daemon over a snapshot library"
	@echo "  make clippy                   Lint chm + hvf hypervisor configs"
	@echo "  make fmt                      Format (nightly rustfmt)"
	@echo "  make test-hvf                 Build hvf_boot integration tests (no-run)"

# Build and code-sign chm; prints the signed binary path on stdout.
chm:
	@./scripts/build-chm.sh

chm-run: chm
	@test -n "$(DIR)" || { echo "usage: make chm-run DIR=/path/to/ch-snapshot"; exit 2; }
	@$(CHM_BIN) run "$(DIR)"

chm-serve: chm
	@test -n "$(DIR)" || { echo "usage: make chm-serve DIR=/path/to/library"; exit 2; }
	@$(CHM_BIN) serve "$(DIR)" --socket "$(SOCKET)"

clippy:
	cargo clippy -p cloud-hypervisor-mac --bin chm
	cargo clippy -p hypervisor --no-default-features --features hvf,kvm-snapshot

fmt:
	cargo +nightly fmt --all

test-hvf:
	cargo test -p hypervisor --no-default-features --features hvf,kvm-snapshot \
		--test hvf_boot --no-run
