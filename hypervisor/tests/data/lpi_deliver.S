// Userspace-GIC LPI delivery demo (two interrupts, no wfi). No managed GIC.
// The guest waits by polling a scratch MMIO address (each write exits to the
// host, so the host can inject) rather than wfi -- avoiding the unrelated HVF
// wfi-park issue. The host queues LPI 8192 and 8193; the CPU interface keeps the
// raw IRQ line asserted while pending is non-empty, so the guest drains both
// back-to-back (IAR/record/EOIR/eret) and powers off after the second. Proves
// active/pending transitions + no spurious re-trigger on Apple HVF.
.text
.global _start
_start:
    movz x0, #0x4000, lsl #16
    movk x0, #0xF000
    mov  sp, x0
    movz x1, #0x4000, lsl #16
    movk x1, #0x1000
    msr  VBAR_EL1, x1
    isb
    mov  x0, #1
    msr  ICC_SRE_EL1, x0
    isb
    mov  x0, #0xF0
    msr  ICC_PMR_EL1, x0
    mov  x0, #1
    msr  ICC_IGRPEN1_EL1, x0
    isb
    mov  x20, #0                   // interrupt counter (preserved across IRQ)
    movz x21, #0x0800, lsl #16      // scratch MMIO poll address 0x08000000
    movz x19, #0x0900, lsl #16      // marker MMIO 0x09000000
    movz w0, #0x1100, lsl #16       // READY 0x11000000
    str  w0, [x19]
    msr  DAIFClr, #2
0:  str  wzr, [x21]                // poll: MMIO write -> exit to host; loop
    b 0b

.org 0x1000
    b sync_h                       // 0x000
.org 0x1200
    b sync_h                       // 0x200 Cur EL SPx sync
.org 0x1280
    b irq_h                        // 0x280 Cur EL SPx IRQ

.org 0x1700
sync_h:
    movz x19, #0x0900, lsl #16
    movz w1, #0xFA00, lsl #16
    str  w1, [x19]
    mrs  x0, ESR_EL1
    str  w0, [x19]
    mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0
1:  b 1b

.org 0x1800
irq_h:
    mrs  x0, ICC_IAR1_EL1          // trap -> injected INTID
    movz x19, #0x0900, lsl #16
    str  w0, [x19]                 // record it
    msr  ICC_EOIR1_EL1, x0         // trap -> EOI
    add  x20, x20, #1
    cmp  x20, #2
    b.ge 2f
    eret                           // return to poll loop; 2nd LPI still pending
2:  mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0                        // PSCI off after the 2nd
1:  b 1b
