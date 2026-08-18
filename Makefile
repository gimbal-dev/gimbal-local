# Cloud Hypervisor for macOS — local-runtime convenience targets.
#
# These wrap the `chm` standalone executable (Apple Silicon only). The binary
# must be code-signed with the hypervisor entitlement before it can create a
# VM; `scripts/build-chm.sh` does the build + sign and prints the path.

CHM_BIN := target/debug/chm
SOCKET  ?= $${TMPDIR:-/tmp}/gimbal-local/chm.sock

.PHONY: help chm chm-run chm-serve clippy fmt test-hvf test-release security-check

help:
	@echo "Cloud Hypervisor for macOS — make targets:"
	@echo "  make chm                      Build + code-sign the chm binary"
	@echo "  make chm-run DIR=<snapshot>   Resume a snapshot, stream console"
	@echo "  make chm-serve DIR=<library>  Run the daemon over a snapshot library"
	@echo "  make clippy                   Lint chm + hvf + arch configs"
	@echo "  make security-check           Enforce the no-host-FS-passthrough guard"
	@echo "  make fmt                      Format (nightly rustfmt)"
	@echo "  make test-hvf                 Run the HVF gate (signed hvf_boot + lib tests)"
	@echo "  make test-release             Run every suite in RELEASE configuration"

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

# Every suite, in the configuration we actually ship.
#
# This target exists because of a shipped bug, not a preference. The first
# signed release hung on *every* boot: `fcntl` was declared with a fixed third
# argument, and on Apple arm64 variadic arguments go on the stack while fixed
# ones go in registers, so `O_NONBLOCK` was never set and every vCPU parked
# before one guest instruction. Correct tests for that behaviour existed and
# passed the whole time — in debug, where the garbage happened to be a zero.
#
#   fn fcntl(fd, cmd, arg: i32)   opt-level=0 -> flags=0x0        (benign)
#                                 opt-level=s -> flags=0x4000c0   (garbage)
#
# A suite that has only ever run in one configuration reports safety it does
# not provide for any other. `scripts/release-macos.sh` runs these before it
# builds anything, so a release cannot ship on debug-only evidence again — but
# finding a release-only failure *at release time* is the worst moment for it:
# highest pressure, least slack. This makes the configuration one command away.
#
# Run it before any milestone that claims a gate, not only before a release.
test-release:
	@set -e; \
	echo "==> chm, release"; \
	(cd chm && cargo test --release); \
	echo "==> hypervisor, release (hvf,kvm-snapshot)"; \
	cargo test -p hypervisor --release --no-default-features \
		--features hvf,kvm-snapshot --lib; \
	echo "==> app, release"; \
	swift test -c release --package-path app/GimbalLocal; \
	echo; echo "All suites green in release configuration."

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
#
# It then ran only the `hvf_boot` integration binary, which is the same disease
# one layer up: the HVF unit tests were silently outside the gate. Those are not
# incidental — `snapshot_sys_reg_tests` is what holds the #257 cure, the register
# list whose *order* is the restore write order. Swapping CNTV_CVAL and CNTV_CTL
# leaves all 35 integration tests green, so anyone measuring a mutation with this
# target alone would conclude the invariant was unguarded. That misreading
# happened, on that exact invariant. The lib suite is therefore part of the gate,
# not a thing to remember to run beside it.
#
# `hvf_boot.rs::the_hvf_gate_runs_the_hypervisor_unit_tests` holds this target to
# that. It lives in the integration suite on purpose: a guard placed in the lib
# suite would be silenced by the very change it exists to catch.
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
	"$$bin" --test-threads=1; \
	echo "==> hypervisor unit tests (hvf,kvm-snapshot)"; \
	cargo test -p hypervisor --no-default-features \
		--features hvf,kvm-snapshot --lib
