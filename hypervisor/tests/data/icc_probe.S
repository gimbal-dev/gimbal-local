// No-managed-GIC ICC_* CPU-interface trap probe.
// Loaded flat at RAM_BASE (0x40000000); PC starts at offset 0.
// Marker MMIO at 0x09000000: every 32-bit store there is trapped+recorded.
.text
.global _start
_start:
    // SP = 0x4000F000
    movz x0, #0x4000, lsl #16
    movk x0, #0xF000
    mov  sp, x0
    // VBAR_EL1 = 0x40001000
    movz x1, #0x4000, lsl #16
    movk x1, #0x1000
    msr  VBAR_EL1, x1
    isb
    // marker base
    movz x19, #0x0900, lsl #16
    // START = 0xAA000000
    movz w0, #0xAA00, lsl #16
    str  w0, [x19]
    // read ICC_SRE_EL1 (does even a READ trap/fault with no managed GIC?)
    mrs  x0, ICC_SRE_EL1
    movz w2, #0xB000, lsl #16
    orr  w0, w0, w2
    str  w0, [x19]
    // try to enable the sysreg interface: ICC_SRE_EL1.SRE = 1
    mov  x0, #1
    msr  ICC_SRE_EL1, x0
    isb
    // about-to-read-IAR marker
    movz w0, #0xCC00, lsl #16
    str  w0, [x19]
    // read ICC_IAR1_EL1 (acknowledge highest-priority IRQ)
    mrs  x0, ICC_IAR1_EL1
    movz w2, #0xD000, lsl #16
    orr  w0, w0, w2
    str  w0, [x19]
    // DONE = 0xEE000000
    movz w0, #0xEE00, lsl #16
    str  w0, [x19]
    // PSCI SYSTEM_OFF (0x84000008)
    mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0
0:  b 0b

// --- exception vectors at 0x1000 ---
.org 0x1000
    b sync_h        // Cur EL SP0 sync
.org 0x1200
    b sync_h        // Cur EL SPx sync
.org 0x1280
    b sync_h        // Cur EL SPx IRQ

.org 0x1800
sync_h:
    movz x19, #0x0900, lsl #16
    movz w1, #0xFA00, lsl #16     // fault sentinel
    str  w1, [x19]
    mrs  x0, ESR_EL1
    str  w0, [x19]               // raw ESR
    mrs  x0, FAR_EL1
    str  w0, [x19]               // raw FAR
    mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0
1:  b 1b
