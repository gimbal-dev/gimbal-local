// nicfg — bring up eth0 with no tools in the guest.
//
// Configuring an interface is an ioctl, and no shell builtin makes one. A
// container rootfs is under no obligation to ship `ip` or `ifconfig`, and the
// mainstream ones increasingly do not: node:22 and node:22-slim have neither.
// So chm carries this.
//
// Freestanding: raw syscalls, no libc, no relocations, no dynamic loader.
//
// Rebuild (from the repo root) after changing anything here:
//
//   SYSROOT=$(rustc --print sysroot)
//   clang --target=aarch64-unknown-linux-gnu -c chm/src/oci/nicfg.S -o /tmp/nicfg.o
//   "$SYSROOT"/lib/rustlib/*/bin/rust-lld -flavor gnu -static -e _start \
//       -o /tmp/nicfg /tmp/nicfg.o
//   "$SYSROOT"/lib/rustlib/*/bin/rust-objcopy --strip-all /tmp/nicfg \
//       chm/src/oci/nicfg.bin
//
// `nicfg::tests::the_binary_is_reproducible_from_the_source` re-runs exactly
// this and fails if the checked-in binary is not what the source assembles to.

.equ NR_ioctl,  29
.equ NR_exit,   93
.equ NR_socket, 198

.equ AF_INET,    2
.equ SOCK_DGRAM, 2

.equ SIOCADDRT,      0x890B
.equ SIOCGIFFLAGS,   0x8913
.equ SIOCSIFFLAGS,   0x8914
.equ SIOCSIFADDR,    0x8916
.equ SIOCSIFNETMASK, 0x891C

.equ IFF_UP,      0x1
.equ IFF_RUNNING, 0x40

// Exit codes. Distinct so the init script can say which step failed rather
// than reporting a generic failure.
.equ E_SOCKET, 10
.equ E_ADDR,   11
.equ E_MASK,   12
.equ E_GFLAGS, 13
.equ E_SFLAGS, 14
.equ E_ROUTE,  15

.text
.global _start
_start:
    mov     x0, #AF_INET
    mov     x1, #SOCK_DGRAM
    mov     x2, #0
    mov     x8, #NR_socket
    svc     #0
    tbnz    x0, #63, .Lfail_socket
    mov     x19, x0                     // x19 = fd, held across every ioctl

    adr     x2, ifr_addr
    mov     x1, #SIOCSIFADDR
    bl      .Lioctl
    tbnz    x0, #63, .Lfail_addr

    // The netmask is a separate ioctl. Setting the address alone leaves the
    // kernel to assume a classful mask, which is not the /24 chm hands out.
    adr     x2, ifr_mask
    mov     x1, #SIOCSIFNETMASK
    bl      .Lioctl
    tbnz    x0, #63, .Lfail_mask

    // Read the current flags before setting: overwriting them would clear
    // whatever the kernel already set on the device.
    adr     x20, ifr_flags
    mov     x2, x20
    mov     x1, #SIOCGIFFLAGS
    bl      .Lioctl
    tbnz    x0, #63, .Lfail_gflags

    ldrh    w1, [x20, #16]
    mov     w2, #(IFF_UP | IFF_RUNNING)
    orr     w1, w1, w2
    strh    w1, [x20, #16]

    mov     x2, x20
    mov     x1, #SIOCSIFFLAGS
    bl      .Lioctl
    tbnz    x0, #63, .Lfail_sflags

    adr     x2, rtent
    mov     x1, #SIOCADDRT
    bl      .Lioctl
    tbnz    x0, #63, .Lfail_route

    mov     x0, #0
    b       .Lexit

.Lioctl:
    mov     x0, x19
    mov     x8, #NR_ioctl
    svc     #0
    ret

.Lfail_socket: mov x0, #E_SOCKET ; b .Lexit
.Lfail_addr:   mov x0, #E_ADDR   ; b .Lexit
.Lfail_mask:   mov x0, #E_MASK   ; b .Lexit
.Lfail_gflags: mov x0, #E_GFLAGS ; b .Lexit
.Lfail_sflags: mov x0, #E_SFLAGS ; b .Lexit
.Lfail_route:  mov x0, #E_ROUTE  ; b .Lexit
.Lexit:
    mov     x8, #NR_exit
    svc     #0

// Writable, because SIOCGIFFLAGS writes into ifr_flags.
.data
.balign 8

// struct ifreq { char ifr_name[16]; union { struct sockaddr; short flags; }; }
// The address words are sentinels; chm rewrites them from its own constants so
// the guest address is never restated in two places.
ifr_addr:
    .ascii "eth0"
    .zero  12
    .hword AF_INET
    .hword 0
    .word  0xC0DE0001        // guest address
    .zero  16                // sin_zero(8) + the rest of the 24-byte union
ifr_mask:
    .ascii "eth0"
    .zero  12
    .hword AF_INET
    .hword 0
    .word  0xC0DE0002        // netmask
    .zero  16                // sin_zero(8) + the rest of the 24-byte union
ifr_flags:
    .ascii "eth0"
    .zero  12
    .zero  24

// struct rtentry — default route via the gateway.
rtent:
    .quad  0                 // rt_pad1
    .hword AF_INET           // rt_dst = 0.0.0.0
    .zero  14
    .hword AF_INET           // rt_gateway
    .hword 0
    .word  0xC0DE0003        // gateway address
    .zero  8
    .hword AF_INET           // rt_genmask = 0.0.0.0
    .zero  14
    .hword 0x0003            // rt_flags = RTF_UP | RTF_GATEWAY
    .hword 0                 // rt_pad2
    .zero  60                // rt_pad3 .. rt_irtt
