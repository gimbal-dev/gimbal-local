// Software-GIC virtual-timer (PPI 27) delivery. No managed GIC. The guest
// enables PPI 27 in its redistributor (GICR MMIO -> hvf::softgic), arms CNTV,
// and waits. HVF surfaces HV_EXIT_REASON_VTIMER_ACTIVATED when the timer fires;
// the VMM injects PPI 27 through the software GIC; the guest's IRQ handler reads
// ICC_IAR1_EL1 (== 27), records it, disables CNTV, EOIs and powers off. Proves
// the scheduler-tick path a real guest needs, with no managed GIC.
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
    // GICR_WAKER (RD_base 0x08010000 + 0x14): clear ProcessorSleep.
    movz x4, #0x0801, lsl #16
    str  wzr, [x4, #0x14]
    // GICR SGI frame (0x08020000) ISENABLER0 (+0x100): enable PPI 27.
    movz x3, #0x0802, lsl #16
    mov  w0, #1
    lsl  w0, w0, #27
    str  w0, [x3, #0x100]
    dsb  sy
    // Arm CNTV: TVAL = 0x8000 ticks, CTL.enable = 1.
    movz x0, #0x8000
    msr  CNTV_TVAL_EL0, x0
    mov  x0, #1
    msr  CNTV_CTL_EL0, x0
    isb
    movz x19, #0x0900, lsl #16
    movz w0, #0x1100, lsl #16       // READY
    str  w0, [x19]
    msr  DAIFClr, #2
    movz x21, #0x0c00, lsl #16      // scratch poll
0:  str  wzr, [x21]
    b 0b

.org 0x1000
    b sync_h
.org 0x1200
    b sync_h
.org 0x1280
    b irq_h
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
    mrs  x0, ICC_IAR1_EL1          // expect PPI 27
    movz x19, #0x0900, lsl #16
    str  w0, [x19]
    msr  CNTV_CTL_EL0, xzr         // disable CNTV so it cannot re-fire
    msr  ICC_EOIR1_EL1, x0
    mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0
1:  b 1b
