# Userspace-GIC experiment fixtures (Path A / M-USGIC)

Bare-metal arm64 guest blobs for the HVF userspace-CPU-interface experiment in
`hvf_boot.rs`. They prove that, with **no** Apple managed GIC, the VMM can trap
the GICv3 CPU-interface system registers (`ICC_*_EL1`, EC=0x18) and deliver an
**LPI** (INTID >= 8192) — the interrupt class the managed GIC cannot deliver.

- `icc_probe.S` / `icc_probe.bin` — reads `ICC_SRE_EL1`, then `ICC_IAR1_EL1`;
  used by `hvf_probe_icc_cpu_interface_trap_without_managed_gic` to show
  `ICC_IAR1_EL1` traps to the VMM as EC=0x18.
- `lpi_deliver.S` / `lpi_deliver.bin` — waits, then its IRQ handler acknowledges
  two host-injected LPIs (8192, 8193) via `ICC_IAR1_EL1`/`ICC_EOIR1_EL1`; used by
  `hvf_userspace_gic_delivers_an_lpi`.

Regenerate a `.bin` from its `.S` on Apple Silicon:

```sh
clang -c -target arm64-apple-macos11 -o /tmp/g.o hypervisor/tests/data/lpi_deliver.S
otool -t /tmp/g.o | awk 'NF>1 && $1 ~ /^[0-9a-f]{16}$/ {for(i=2;i<=NF;i++) print $i}' \
  | python3 -c 'import sys;\
b=bytearray();\
[b.extend(int(w,16).to_bytes(4,"little")) for w in sys.stdin.read().split() if len(w)==8];\
open("hypervisor/tests/data/lpi_deliver.bin","wb").write(b)'
```
