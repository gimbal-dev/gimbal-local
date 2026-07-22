// Software-GIC SPI delivery: the guest enables SPI 32 by programming the
// distributor over MMIO (GICD_CTLR + GICD_ISENABLER1, serviced by hvf::softgic,
// no managed GIC), signals READY, and waits. The host asserts SPI 32; the
// distributor (enabled) forwards it to the CPU interface; the guest's IRQ
// handler reads ICC_IAR1_EL1 (== 32), records it, EOIs and powers off. Proves
// the guest-MMIO-config -> distributor -> CPU-interface pipeline end to end.
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
    // Distributor @ 0x08000000.
    movz x2, #0x0800, lsl #16
    mov  w0, #0x12                  // GICD_CTLR: EnableGrp1 | ARE_NS
    str  w0, [x2]
    mov  w0, #1                     // GICD_ISENABLER1 bit0 -> enable INTID 32
    str  w0, [x2, #0x104]
    dsb  sy
    movz x19, #0x0900, lsl #16
    movz w0, #0x1100, lsl #16       // READY
    str  w0, [x19]
    msr  DAIFClr, #2
    movz x21, #0x0c00, lsl #16      // scratch poll (yield to host)
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
    mrs  x0, ICC_IAR1_EL1
    movz x19, #0x0900, lsl #16
    str  w0, [x19]
    msr  ICC_EOIR1_EL1, x0
    mov  x0, #8
    movk x0, #0x8400, lsl #16
    hvc  #0
1:  b 1b
