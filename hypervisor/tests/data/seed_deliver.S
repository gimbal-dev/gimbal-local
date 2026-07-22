// Seeded-software-GIC SPI delivery: a guest with NO managed GIC that NEVER
// programs the distributor. Its interrupt configuration comes entirely from the
// host seeding the software GIC from a REAL captured KVM snapshot dump
// (`dist_to_hvf`/`redist_to_hvf` -> `usgic_seed_gic`) — exactly the resume case,
// where a rehydrated guest inherits its GIC state and does not re-program it.
//
// The guest only brings up the CPU interface (ICC_SRE/PMR/IGRPEN1), signals
// READY, unmasks IRQs, and polls a scratch MMIO address to yield to the host.
// The host asserts a seeded-enabled SPI; the software distributor forwards it
// (because the SEED marked it enabled), the guest's IRQ handler reads
// ICC_IAR1_EL1, records the INTID, EOIs, and powers off.
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
    // NB: NO distributor programming here — the seed is the only source of the
    // enable/priority/group/route state.
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
