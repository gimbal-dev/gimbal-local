# Cloud Hypervisor for macOS — local-runtime convenience targets.
#
# These wrap the `chm` standalone executable (Apple Silicon only). The binary
# must be code-signed with the hypervisor entitlement before it can create a
# VM; `scripts/build-chm.sh` does the build + sign and prints the path.

CHM_BIN := target/debug/chm
SOCKET  ?= $${TMPDIR:-/tmp}/gimbal-local/chm.sock

.PHONY: help chm chm-run chm-serve clippy fmt test-hvf security-check

help:
	@echo "Cloud Hypervisor for macOS — make targets:"
	@echo "  make chm                      Build + code-sign the chm binary"
	@echo "  make chm-run DIR=<snapshot>   Resume a snapshot, stream console"
	@echo "  make chm-serve DIR=<library>  Run the daemon over a snapshot library"
	@echo "  make clippy                   Lint chm + hvf + arch configs"
	@echo "  make security-check           Enforce the no-host-FS-passthrough guard"
	@echo "  make fmt                      Format (nightly rustfmt)"
	@echo "  make test-hvf                 Run hvf_boot tests (signs, runs serially)"

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
	cargo clippy -p gimbal-local --bin chm
	cargo clippy -p hypervisor --no-default-features --features hvf,kvm-snapshot
	cargo clippy -p arch --features hvf --all-targets

# Security invariant I1 (docs/security-model.md): fail if host-filesystem
# passthrough (virtiofs/9p/shared-folder) appears in the device model.
security-check:
	@./scripts/security/no-host-fs-passthrough.sh

fmt:
	cargo +nightly fmt --all

# The HVF integration tests create real VMs, so they need two things a plain
# `cargo test` does not give them:
#
#   1. The hypervisor entitlement. Every `cargo build` strips it, so the test
#      binary must be re-signed after it is built or every test fails with
#      HV_DENIED — which reads like a broken backend and is not.
#   2. Serial execution. `hv_vm_create` is process-global; a second concurrent
#      VM returns HV_BUSY, so the default thread pool fails most of the suite.
#
# This target used to stop at `--no-run`, which built the tests and ran none of
# them. A gate that cannot fail is not a gate.
test-hvf:
	@set -e; \
	bin=$$(cargo test -p hypervisor --no-default-features \
		--features hvf,kvm-snapshot --test hvf_boot --no-run \
		--message-format=json 2>/dev/null \
		| python3 -c "import sys,json;\
[print(m['executable']) for m in (json.loads(l) for l in sys.stdin if l.startswith('{'))\
 if m.get('profile',{}).get('test') and m.get('executable')]" | tail -1); \
	test -n "$$bin" || { echo "could not locate the hvf_boot test binary"; exit 1; }; \
	codesign --sign - --entitlements hypervisor/tests/data/hv.entitlements \
		--force "$$bin" >/dev/null 2>&1; \
	"$$bin" --test-threads=1
