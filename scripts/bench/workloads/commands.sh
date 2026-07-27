#!/usr/bin/env bash
# commands.sh — the single source of truth for the M32.2 I/O + network inner
# commands.
#
# The CPU workloads (xz/gzip) could be duplicated safely because they are one
# short pipeline. The I/O and network workloads are longer, and a benchmark that
# runs *slightly* different commands in each runtime is worse than no benchmark
# at all. So the exact command string is defined ONCE here and consumed by both
# sides:
#
#   * Docker  — `workloads/diskwrite.sh` / `workloads/netget.sh` source this file
#     and run "$BENCH_INNER_CMD".
#   * gimbal  — `run-gimbal-io.sh` sources this file and exports the same string
#     as `BENCH_CMD`, which the `microvm_xz_benchmark` integration test inlines
#     over the guest console.
#
# Both runtimes therefore execute a byte-identical shell command; the only
# variable is the runtime underneath it.
#
# Usage:  bench_command <workload>   -> echoes the command string
#
# Tunables (env): BENCH_DISK_MB, BENCH_DISK_PATH, BENCH_URL.

# Disk-write: fixed-size sequential write to the guest/container filesystem,
# fsync'd so the cost lands on the actual block device rather than the page
# cache. This is the CoW-overlay stress: on gimbal every first write to a block
# must copy-up through the overlay, which is exactly the path we want measured.
# `dd` is present in every minimal userland, so no extra tooling is needed.
bench_cmd_diskwrite() {
    local mb="${BENCH_DISK_MB:-256}"
    local path="${BENCH_DISK_PATH:-/tmp/gimbal-bench.dat}"
    printf 'dd if=/dev/zero of=%s bs=1M count=%s conv=fsync && sync && rm -f %s' \
        "$path" "$mb" "$path"
}

# Network-get: pull a fixed-size payload over HTTP from a server on the host.
# A host-local server (rather than the public internet) keeps the ISP link out
# of the measurement, so what is timed is the runtime's own network datapath --
# gimbal's userspace NAT versus Docker's virtual network stack.
bench_cmd_netget() {
    local url="${BENCH_URL:?set BENCH_URL to the host payload URL}"
    printf 'curl -s -f -m 300 -o /dev/null %s' "$url"
}

# Fsync-heavy: many *small* synchronous writes -- the access pattern of package
# installs, git checkouts and databases, and the one that punishes a copy-on-write
# overlay hardest. Deliberately moves almost no data (a few hundred KiB), so any
# large gap between runtimes is per-flush overhead rather than throughput.
bench_cmd_fsyncsmall() {
    local count="${BENCH_FSYNC_COUNT:-200}"
    local path="${BENCH_DISK_PATH:-/tmp/gimbal-bench-sync.dat}"
    printf 'dd if=/dev/zero of=%s bs=4k count=%s oflag=dsync && rm -f %s' \
        "$path" "$count" "$path"
}

bench_command() {
    case "${1:-}" in
        diskwrite) bench_cmd_diskwrite ;;
        fsyncsmall) bench_cmd_fsyncsmall ;;
        netget)    bench_cmd_netget ;;
        *) echo "bench_command: unknown workload '${1:-}'" >&2; return 1 ;;
    esac
}
