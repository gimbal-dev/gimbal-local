// cdpfwd -- relay the one CDP port from the guest's NIC address to its own
// loopback, and nothing else.
//
// Chromium 151's DevTools endpoint binds 127.0.0.1 and there is no switch to
// move it: `strings headless_shell | grep -x 'remote-debugging-[a-z]*'` lists
// `remote-debugging-pipe` and `remote-debugging-port`, and no
// `remote-debugging-address`. chm's ingress dials the guest at its NIC address,
// so the two never meet. This closes that gap and is deliberately the smallest
// thing that can: it forwards bytes and understands nothing.
//
// What it will not do, structurally rather than by promise:
//
//   * It never creates a process. There is no clone, fork, execve or execveat
//     in it -- `cdpfwd::tests::the_syscall_vocabulary_is_exactly_the_allow_list`
//     decodes every syscall number out of the shipped bytes and fails if one
//     appears that is not on the list below.
//   * It never opens a file. There is no openat either, for the same reason.
//   * It reads no configuration. It ignores argv entirely, and both the address
//     and the port are constants patched in from chm's own single source of
//     truth before the image is written.
//   * It binds one address and one port. Not a wildcard: the guest's NIC
//     address only, so nothing already inside the guest gains a path it did not
//     have, and the only reach added is the host's -- which is exactly what
//     `--expose` authorised.
//
// Concurrency: one process, one thread, non-blocking sockets and a
// level-triggered epoll over a fixed table of MAX_SLOTS connections. One page
// load opens ~80 connections and #330 measured the NAT to 96, so the table is
// 128 -- 257 descriptors against a default RLIMIT_NOFILE of 1024. When the
// table is full the listener's epoll interest is set to zero rather than
// accepting and dropping, so back-pressure is the kernel's own backlog and
// there is no busy-wait and no spin. There is no idle timeout: a CDP WebSocket
// is legitimately idle for minutes.
//
// Freestanding, and with no linker at all: the ELF header and program headers
// below are part of the source, the whole program is one section, and the build
// is `clang -c` plus `objcopy -O binary`. That is not cleverness for its own
// sake. `rust-lld` is absent from a Homebrew rust install -- measured, see #340
// -- so the `nicfg`/`modload` "the binary came from the source beside it" guards
// silently skip on that toolchain, and a guard that never runs is worth
// nothing. An assembler encodes an instruction one way; this rebuilds and
// compares byte for byte anywhere clang exists.
//
// Rebuild (from the repo root) after changing anything here:
//
//   SYSROOT=$(rustc --print sysroot)
//   clang --target=aarch64-unknown-linux-gnu -c chm/src/oci/cdpfwd.S \
//       -o /tmp/cdpfwd.o
//   "$SYSROOT"/lib/rustlib/*/bin/rust-objcopy -O binary --only-section=.text \
//       /tmp/cdpfwd.o chm/src/oci/cdpfwd.bin
//
// `cdpfwd::tests::the_binary_is_reproducible_from_the_source` re-runs exactly
// this and fails if the checked-in binary is not what the source assembles to.

// ---------------------------------------------------------------------------
// Syscall numbers (asm-generic/unistd.h, which is what aarch64 uses).
//
// This list is the program's entire vocabulary, and it is checked against the
// shipped bytes rather than against this comment.
// ---------------------------------------------------------------------------
.equ NR_epoll_create1, 20
.equ NR_epoll_ctl,     21
.equ NR_epoll_pwait,   22
.equ NR_close,         57
.equ NR_write,         64
.equ NR_exit_group,    94
.equ NR_socket,        198
.equ NR_bind,          200
.equ NR_listen,        201
.equ NR_connect,       203
.equ NR_sendto,        206
.equ NR_recvfrom,      207
.equ NR_setsockopt,    208
.equ NR_shutdown,      210
.equ NR_accept4,       242

.equ AF_INET,       2
.equ SOCK_STREAM,   1
.equ SOCK_NONBLOCK, 2048            // O_NONBLOCK
.equ SOL_SOCKET,    1
.equ SO_REUSEADDR,  2
.equ IPPROTO_TCP,   6
.equ TCP_NODELAY,   1
.equ MSG_NOSIGNAL,  0x4000
.equ SHUT_WR,       1
.equ BACKLOG,       128

.equ EPOLL_CTL_ADD, 1
.equ EPOLL_CTL_MOD, 3
.equ EPOLLIN,       0x001
.equ EPOLLOUT,      0x004
.equ EPOLLERR,      0x008
.equ EPOLLHUP,      0x010

// Retryable, as opposed to fatal for the connection. ENOTCONN appears when a
// write is attempted while the upstream connect is still in flight, which is
// ordinary rather than an error.
.equ EAGAIN,   11
.equ EINTR,    4
.equ ENOTCONN, 107
.equ EINPROGRESS, 115

.equ STDERR, 2

// Exit codes, distinct so the launcher can say which step failed rather than
// reporting a generic failure.
.equ E_EPOLL,  10
.equ E_SOCKET, 11
.equ E_BIND,   12
.equ E_LISTEN, 13
.equ E_WAIT,   14

// ---------------------------------------------------------------------------
// Memory. The second PT_LOAD below is zero-filled by the kernel; nothing here
// is in the file. Every base is a single MOVZ immediate on purpose -- an
// address the assembler cannot form in one instruction is an address that
// needs a literal pool, and this program has no relocations to spend.
// ---------------------------------------------------------------------------
.equ MAX_SLOTS,  128
.equ MAX_EVENTS, 64
.equ BUF_CAP,    16384
.equ SLOT_SIZE,  32

.equ EV_BUF, 0x110000                   // MAX_EVENTS * 16
.equ SLOTS,  0x120000                   // MAX_SLOTS * SLOT_SIZE
.equ BUFS,   0x130000                   // MAX_SLOTS * 2 * BUF_CAP
.equ BSS_BASE, EV_BUF
.equ BSS_SIZE, (BUFS + MAX_SLOTS * 2 * BUF_CAP) - EV_BUF

// A slot. `fd_a` is -1 when the slot is free, and that is the only liveness
// test: an epoll batch can carry two events for a connection that the first of
// them tore down, so the second must find the slot empty and leave.
//
//   +0  fd_a   client, the side that dialled in
//   +4  fd_b   upstream, 127.0.0.1
//   +8  a2b head, +12 a2b tail      client -> upstream
//   +16 b2a head, +20 b2a tail      upstream -> client
//   +24 flags
//   +28 mask_a (hword), +30 mask_b (hword)
.equ S_FD_A,  0
.equ S_FD_B,  4
.equ S_HEAD0, 8
.equ S_HEAD1, 16
.equ S_FLAGS, 24
.equ S_MASK,  28

// Flag bits. The read-closed and write-shut bits are indexed by side so the
// relay logic is symmetric and there is only one copy of it.
.equ F_RC_A,  1                         // 1 << side
.equ F_WS_A,  4                         // 4 << side
.equ F_DEAD,  16

.equ BASE, 0x10000
.equ LISTENER_TAG, -1

.text
.global _start

// ---------------------------------------------------------------------------
// The ELF the kernel is handed. Two segments, so text is never writable and
// the buffers are never executable.
// ---------------------------------------------------------------------------
image_start:
    .byte 0x7f, 'E', 'L', 'F'
    .byte 2                             // ELFCLASS64
    .byte 1                             // ELFDATA2LSB
    .byte 1                             // EV_CURRENT
    .byte 0                             // ELFOSABI_NONE
    .quad 0                             // e_ident padding
    .hword 2                            // e_type = ET_EXEC
    .hword 183                          // e_machine = EM_AARCH64
    .word 1                             // e_version
    .quad BASE + (_start - image_start) // e_entry
    .quad phdr - image_start            // e_phoff -- a file offset, not a vaddr
    .quad 0                             // e_shoff
    .word 0                             // e_flags
    .hword 64                           // e_ehsize
    .hword 56                           // e_phentsize
    .hword 2                            // e_phnum
    .hword 0                            // e_shentsize
    .hword 0                            // e_shnum
    .hword 0                            // e_shstrndx
phdr:
    .word 1                             // PT_LOAD
    .word 5                             // PF_R | PF_X
    .quad 0                             // p_offset
    .quad BASE                          // p_vaddr
    .quad BASE                          // p_paddr
    .quad image_end - image_start       // p_filesz
    .quad image_end - image_start       // p_memsz
    .quad 0x10000                       // p_align
    .word 1                             // PT_LOAD
    .word 6                             // PF_R | PF_W
    .quad 0                             // p_offset; filesz 0, so only the
    .quad BSS_BASE                      // congruence with p_align matters
    .quad BSS_BASE
    .quad 0
    .quad BSS_SIZE
    .quad 0x10000

// ---------------------------------------------------------------------------
// x19 = epoll fd, x20 = listening fd, w21 = 1 while the listener is armed.
// ---------------------------------------------------------------------------
_start:
    mov     x0, #0
    mov     x8, #NR_epoll_create1
    svc     #0
    tbnz    x0, #63, .Lfail_epoll
    mov     x19, x0

    mov     x0, #AF_INET
    mov     x1, #(SOCK_STREAM | SOCK_NONBLOCK)
    mov     x2, #0
    mov     x8, #NR_socket
    svc     #0
    tbnz    x0, #63, .Lfail_socket
    mov     x20, x0

    // SO_REUSEADDR so a restart is not blocked by a lingering TIME_WAIT. It
    // does not widen anything: two listening sockets still cannot share an
    // address, which is why the bind below is the guest's NIC address and not
    // a wildcard.
    mov     x0, x20
    mov     x1, #SOL_SOCKET
    mov     x2, #SO_REUSEADDR
    adr     x3, int_one
    mov     x4, #4
    mov     x8, #NR_setsockopt
    svc     #0

    mov     x0, x20
    adr     x1, listen_sa
    mov     x2, #16
    mov     x8, #NR_bind
    svc     #0
    tbnz    x0, #63, .Lfail_bind

    mov     x0, x20
    mov     x1, #BACKLOG
    mov     x8, #NR_listen
    svc     #0
    tbnz    x0, #63, .Lfail_listen

    // Every slot free.
    mov     x9, #SLOTS
    mov     x10, #MAX_SLOTS
    mov     w11, #-1
.Linit:
    str     w11, [x9, #S_FD_A]
    add     x9, x9, #SLOT_SIZE
    subs    x10, x10, #1
    b.ne    .Linit

    mov     x0, x20
    mov     w1, #EPOLLIN
    mov     x2, #LISTENER_TAG
    mov     w3, #EPOLL_CTL_ADD
    bl      ep_ctl
    mov     w21, #1

// ---------------------------------------------------------------------------
// The loop. Accepts are deferred to the end of each batch: a slot freed by an
// early event must not be handed to a new connection while a later event in the
// same batch still names it.
// ---------------------------------------------------------------------------
.Lwait:
    mov     x0, x19
    mov     x1, #EV_BUF
    mov     x2, #MAX_EVENTS
    mov     w3, #-1                     // block; there is nothing to poll for
    mov     x4, #0
    mov     x5, #8
    mov     x8, #NR_epoll_pwait
    svc     #0
    cmn     x0, #EINTR
    b.eq    .Lwait
    tbnz    x0, #63, .Lfail_wait
    mov     x25, x0                     // events returned
    mov     x26, #0                     // index
    mov     w28, #0                     // did the listener fire

.Lev:
    cmp     x26, x25
    b.ge    .Lev_done
    mov     x9, #EV_BUF
    add     x9, x9, x26, lsl #4         // sizeof(struct epoll_event) is 16 on
    ldr     w27, [x9]                   // aarch64: it is packed only on x86_64
    ldr     x11, [x9, #8]
    cmn     x11, #1
    b.ne    .Lslot_ev
    mov     w28, #1
    b       .Lnext_ev

.Lslot_ev:
    lsr     x24, x11, #1                // slot index
    and     w23, w11, #1                // side: 0 = client, 1 = upstream
    mov     x22, #SLOTS
    add     x22, x22, x24, lsl #5
    ldr     w12, [x22, #S_FD_A]
    cmn     w12, #1
    b.eq    .Lnext_ev                   // torn down earlier in this batch

    tst     w27, #EPOLLERR
    b.eq    .Lev_in
    ldr     w12, [x22, #S_FLAGS]
    orr     w12, w12, #F_DEAD
    str     w12, [x22, #S_FLAGS]
    b       .Lev_progress

.Lev_in:
    tst     w27, #EPOLLIN
    b.eq    .Lev_out
    mov     x0, x22
    mov     x1, x23
    mov     x2, x24
    bl      do_read
.Lev_out:
    tst     w27, #EPOLLOUT
    b.eq    .Lev_hup
    mov     x0, x22
    mov     x1, x23
    mov     x2, x24
    bl      do_write
.Lev_hup:
    tst     w27, #EPOLLHUP
    b.eq    .Lev_progress
    // This side is gone in both directions, so what was queued for it can
    // never be delivered. Say so by dropping it rather than waiting on a
    // writability that will not come.
    ldr     w12, [x22, #S_FLAGS]
    mov     w13, #F_RC_A
    lsl     w13, w13, w23
    orr     w12, w12, w13
    str     w12, [x22, #S_FLAGS]
    eor     w13, w23, #1
    add     x14, x22, x13, lsl #3
    str     wzr, [x14, #S_HEAD0]
    str     wzr, [x14, #(S_HEAD0 + 4)]

.Lev_progress:
    mov     x0, x22
    mov     x1, x24
    bl      slot_progress

.Lnext_ev:
    add     x26, x26, #1
    b       .Lev

.Lev_done:
    cbz     w28, .Lwait
    bl      do_accept
    b       .Lwait

// ---------------------------------------------------------------------------
// epoll_ctl(epfd, op=w3, fd=x0, {events=w1, data=x2})
// ---------------------------------------------------------------------------
ep_ctl:
    sub     sp, sp, #16
    str     w1, [sp]
    str     x2, [sp, #8]
    mov     x2, x0
    mov     x0, x19
    mov     x1, x3
    mov     x3, sp
    mov     x8, #NR_epoll_ctl
    svc     #0
    add     sp, sp, #16
    ret

// ---------------------------------------------------------------------------
// do_read(slot = x0, side = x1, idx = x2)
//
// Reads from this side into the buffer flowing away from it. Buffer index and
// side are the same number, which is why there is one copy of this rather than
// two mirrored ones.
// ---------------------------------------------------------------------------
do_read:
    mov     x9, x0
    mov     x10, x1
    add     x11, x9, x10, lsl #3        // &head for this direction
    ldr     w12, [x11, #S_HEAD0]        // head
    ldr     w13, [x11, #(S_HEAD0 + 4)]  // tail
    mov     w14, #BUF_CAP
    cmp     w13, w14
    b.ge    .Lread_out                  // full; epoll will not have asked
    mov     x15, #BUFS
    add     x15, x15, x2, lsl #15
    add     x15, x15, x10, lsl #14      // buffer base
    ldr     w0, [x9, x10, lsl #2]       // fd
    add     x1, x15, x13
    sub     w2, w14, w13
    mov     x3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x8, #NR_recvfrom
    svc     #0
    cmp     x0, #0
    b.gt    .Lread_got
    b.eq    .Lread_eof
    cmn     x0, #EAGAIN
    b.eq    .Lread_out
    cmn     x0, #EINTR
    b.eq    .Lread_out
    ldr     w12, [x9, #S_FLAGS]
    orr     w12, w12, #F_DEAD
    str     w12, [x9, #S_FLAGS]
    ret
.Lread_got:
    add     w13, w13, w0
    str     w13, [x11, #(S_HEAD0 + 4)]
    ret
.Lread_eof:
    // A half-close, not a teardown: the peer may still be waiting for the
    // reply to what it already sent.
    ldr     w12, [x9, #S_FLAGS]
    mov     w14, #F_RC_A
    lsl     w14, w14, w10
    orr     w12, w12, w14
    str     w12, [x9, #S_FLAGS]
.Lread_out:
    ret

// ---------------------------------------------------------------------------
// do_write(slot = x0, side = x1, idx = x2)
//
// Writes to this side from the buffer flowing towards it, which is the other
// direction's buffer.
// ---------------------------------------------------------------------------
do_write:
    mov     x9, x0
    mov     x10, x1
    eor     x16, x10, #1                // the buffer aimed at this side
    add     x11, x9, x16, lsl #3
    ldr     w12, [x11, #S_HEAD0]
    ldr     w13, [x11, #(S_HEAD0 + 4)]
    cmp     w12, w13
    b.ge    .Lwrite_out                 // nothing queued
    mov     x15, #BUFS
    add     x15, x15, x2, lsl #15
    add     x15, x15, x16, lsl #14
    ldr     w0, [x9, x10, lsl #2]
    add     x1, x15, x12
    sub     w2, w13, w12
    mov     x3, #MSG_NOSIGNAL           // no SIGPIPE, so no signal disposition
    mov     x4, #0                      // to get wrong in a freestanding image
    mov     x5, #0
    mov     x8, #NR_sendto
    svc     #0
    cmp     x0, #0
    b.gt    .Lwrite_sent
    cmn     x0, #EAGAIN
    b.eq    .Lwrite_out
    cmn     x0, #EINTR
    b.eq    .Lwrite_out
    cmn     x0, #ENOTCONN
    b.eq    .Lwrite_out                 // upstream connect still in flight
    ldr     w12, [x9, #S_FLAGS]
    orr     w12, w12, #F_DEAD
    str     w12, [x9, #S_FLAGS]
    ret
.Lwrite_sent:
    add     w12, w12, w0
    cmp     w12, w13
    b.lt    .Lwrite_part
    // Drained: rewind rather than carry an offset forward, so a long-lived
    // connection does not walk off the end of a linear buffer.
    str     wzr, [x11, #S_HEAD0]
    str     wzr, [x11, #(S_HEAD0 + 4)]
    ret
.Lwrite_part:
    str     w12, [x11, #S_HEAD0]
.Lwrite_out:
    ret

// ---------------------------------------------------------------------------
// slot_progress(slot = x0, idx = x1)
//
// Everything that is true of a connection after an event: drain what can be
// drained, propagate a half-close, tear down when both directions are done,
// and otherwise ask epoll for exactly what is still wanted.
// ---------------------------------------------------------------------------
slot_progress:
    stp     x29, x30, [sp, #-32]!
    stp     x22, x23, [sp, #16]         // x19-x21 are the epoll fd, the
    mov     x29, sp                     // listening fd and its armed flag, and
    mov     x22, x0                     // stay that way everywhere
    mov     x23, x1

    // Opportunistic: a read that just landed can usually go straight out, and
    // waiting for a second epoll round would double the latency of every CDP
    // message for no gain.
    mov     x0, x22
    mov     x1, #1
    mov     x2, x23
    bl      do_write
    mov     x0, x22
    mov     x1, #0
    mov     x2, x23
    bl      do_write

    ldr     w9, [x22, #S_FLAGS]
    tst     w9, #F_DEAD
    b.ne    .Lprog_close

    // Half-close: side read-closed and its queue drained means the other side
    // has seen everything there will ever be, so tell it so.
    mov     x10, #0
.Lprog_hc:
    mov     w11, #F_RC_A
    lsl     w11, w11, w10
    ldr     w9, [x22, #S_FLAGS]
    tst     w9, w11
    b.eq    .Lprog_hc_next
    add     x12, x22, x10, lsl #3
    ldr     w13, [x12, #S_HEAD0]
    ldr     w14, [x12, #(S_HEAD0 + 4)]
    cmp     w13, w14
    b.ne    .Lprog_hc_next
    eor     x15, x10, #1                // shut writing on the *other* side
    mov     w11, #F_WS_A
    lsl     w11, w11, w15
    tst     w9, w11
    b.ne    .Lprog_hc_next
    orr     w9, w9, w11
    str     w9, [x22, #S_FLAGS]
    ldr     w0, [x22, x15, lsl #2]
    mov     x1, #SHUT_WR
    mov     x8, #NR_shutdown
    svc     #0
.Lprog_hc_next:
    add     x10, x10, #1
    cmp     x10, #2
    b.lt    .Lprog_hc

    // Done when neither side can send anything more and nothing is queued.
    ldr     w9, [x22, #S_FLAGS]
    and     w10, w9, #(F_RC_A | (F_RC_A << 1))
    cmp     w10, #(F_RC_A | (F_RC_A << 1))
    b.ne    .Lprog_mask
    ldr     w13, [x22, #S_HEAD0]
    ldr     w14, [x22, #(S_HEAD0 + 4)]
    cmp     w13, w14
    b.ne    .Lprog_mask
    ldr     w13, [x22, #S_HEAD1]
    ldr     w14, [x22, #(S_HEAD1 + 4)]
    cmp     w13, w14
    b.ne    .Lprog_mask

.Lprog_close:
    ldr     w0, [x22, #S_FD_A]
    mov     x8, #NR_close
    svc     #0
    ldr     w0, [x22, #S_FD_B]
    mov     x8, #NR_close
    svc     #0
    mov     w9, #-1
    str     w9, [x22, #S_FD_A]
    ldp     x22, x23, [sp, #16]
    ldp     x29, x30, [sp], #32
    // A slot came free, so the listener can be armed again if the table full
    // condition had disarmed it.
    cbnz    w21, .Lprog_ret
    mov     x0, x20
    mov     w1, #EPOLLIN
    mov     x2, #LISTENER_TAG
    mov     w3, #EPOLL_CTL_MOD
    mov     w21, #1
    b       ep_ctl
.Lprog_ret:
    ret

.Lprog_mask:
    mov     x10, #0
.Lprog_mask_loop:
    ldr     w9, [x22, #S_FLAGS]
    mov     w12, #0
    // Read from this side while it has not ended and its queue has room.
    mov     w11, #F_RC_A
    lsl     w11, w11, w10
    tst     w9, w11
    b.ne    .Lprog_no_in
    add     x13, x22, x10, lsl #3
    ldr     w14, [x13, #(S_HEAD0 + 4)]
    cmp     w14, #BUF_CAP
    b.ge    .Lprog_no_in
    orr     w12, w12, #EPOLLIN
.Lprog_no_in:
    // Write to this side while anything is queued for it.
    eor     x15, x10, #1
    add     x13, x22, x15, lsl #3
    ldr     w14, [x13, #S_HEAD0]
    ldr     w16, [x13, #(S_HEAD0 + 4)]
    cmp     w14, w16
    b.ge    .Lprog_no_out
    orr     w12, w12, #EPOLLOUT
.Lprog_no_out:
    add     x13, x22, x10, lsl #1
    ldrh    w14, [x13, #S_MASK]
    cmp     w14, w12
    b.eq    .Lprog_mask_next
    strh    w12, [x13, #S_MASK]
    ldr     w0, [x22, x10, lsl #2]
    mov     w1, w12
    orr     x2, x10, x23, lsl #1
    mov     w3, #EPOLL_CTL_MOD
    stp     x10, x11, [sp, #-16]!
    bl      ep_ctl
    ldp     x10, x11, [sp], #16
.Lprog_mask_next:
    add     x10, x10, #1
    cmp     x10, #2
    b.lt    .Lprog_mask_loop

    ldp     x22, x23, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

// ---------------------------------------------------------------------------
// do_accept()
//
// Drains the backlog into free slots. When there is no free slot the listener
// is disarmed instead of accepting and closing: a connection left in the
// kernel's backlog is one the client can still make progress on, and a
// connection accepted and dropped is one it cannot.
// ---------------------------------------------------------------------------
do_accept:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
.Lacc_loop:
    // First free slot, or none.
    mov     x9, #SLOTS
    mov     x10, #0
.Lacc_find:
    ldr     w11, [x9, #S_FD_A]
    cmn     w11, #1
    b.eq    .Lacc_found
    add     x9, x9, #SLOT_SIZE
    add     x10, x10, #1
    cmp     x10, #MAX_SLOTS
    b.lt    .Lacc_find
    // Full.
    mov     x0, x20
    mov     w1, #0
    mov     x2, #LISTENER_TAG
    mov     w3, #EPOLL_CTL_MOD
    mov     w21, #0
    bl      ep_ctl
    b       .Lacc_out

.Lacc_found:
    str     x9, [sp, #16]               // slot ptr survives the syscalls
    mov     x0, x20
    mov     x1, #0
    mov     x2, #0
    mov     x3, #SOCK_NONBLOCK
    mov     x8, #NR_accept4
    svc     #0
    tbnz    x0, #63, .Lacc_out          // EAGAIN: the backlog is empty
    mov     x12, x0                     // client fd

    mov     x0, #AF_INET
    mov     x1, #(SOCK_STREAM | SOCK_NONBLOCK)
    mov     x2, #0
    mov     x8, #NR_socket
    svc     #0
    tbnz    x0, #63, .Lacc_drop_client
    mov     x13, x0                     // upstream fd

    // CDP is many small messages; Nagle would add 40 ms to the thing whose
    // whole job is latency.
    mov     x0, x12
    bl      set_nodelay
    mov     x0, x13
    bl      set_nodelay

    mov     x0, x13
    adr     x1, upstream_sa
    mov     x2, #16
    mov     x8, #NR_connect
    svc     #0
    tbz     x0, #63, .Lacc_wire
    cmn     x0, #EINPROGRESS
    b.eq    .Lacc_wire
    // Nothing is listening on loopback yet, or it refused. Drop this one and
    // keep serving; the browser may still be starting.
    mov     x0, x13
    mov     x8, #NR_close
    svc     #0
.Lacc_drop_client:
    mov     x0, x12
    mov     x8, #NR_close
    svc     #0
    b       .Lacc_loop

.Lacc_wire:
    ldr     x9, [sp, #16]
    mov     x10, #SLOTS
    sub     x10, x9, x10
    lsr     x10, x10, #5                // slot index
    str     w12, [x9, #S_FD_A]
    str     w13, [x9, #S_FD_B]
    str     wzr, [x9, #S_HEAD0]
    str     wzr, [x9, #(S_HEAD0 + 4)]
    str     wzr, [x9, #S_HEAD1]
    str     wzr, [x9, #(S_HEAD1 + 4)]
    str     wzr, [x9, #S_FLAGS]
    mov     w14, #EPOLLIN
    strh    w14, [x9, #S_MASK]
    mov     w14, #(EPOLLIN | EPOLLOUT)
    strh    w14, [x9, #(S_MASK + 2)]

    mov     x0, x12
    mov     w1, #EPOLLIN
    lsl     x2, x10, #1
    mov     w3, #EPOLL_CTL_ADD
    stp     x10, x13, [sp, #-16]!
    bl      ep_ctl
    ldp     x10, x13, [sp], #16
    mov     x0, x13
    mov     w1, #(EPOLLIN | EPOLLOUT)   // OUT so a completed connect is heard
    lsl     x2, x10, #1
    orr     x2, x2, #1
    mov     w3, #EPOLL_CTL_ADD
    bl      ep_ctl
    b       .Lacc_loop

.Lacc_out:
    ldp     x29, x30, [sp], #32
    ret

// set_nodelay(fd = x0)
set_nodelay:
    mov     x1, #IPPROTO_TCP
    mov     x2, #TCP_NODELAY
    adr     x3, int_one
    mov     x4, #4
    mov     x8, #NR_setsockopt
    svc     #0
    ret

// ---------------------------------------------------------------------------
// Failure. One line naming the step, then a distinct status. A forwarder that
// died silently would look exactly like a browser that never answered.
// ---------------------------------------------------------------------------
.Lfail_epoll:
    adr     x1, m_epoll
    mov     x2, #(m_socket - m_epoll)
    mov     x9, #E_EPOLL
    b       .Lfail
.Lfail_socket:
    adr     x1, m_socket
    mov     x2, #(m_bind - m_socket)
    mov     x9, #E_SOCKET
    b       .Lfail
.Lfail_bind:
    adr     x1, m_bind
    mov     x2, #(m_listen - m_bind)
    mov     x9, #E_BIND
    b       .Lfail
.Lfail_listen:
    adr     x1, m_listen
    mov     x2, #(m_wait - m_listen)
    mov     x9, #E_LISTEN
    b       .Lfail
.Lfail_wait:
    adr     x1, m_wait
    mov     x2, #(m_end - m_wait)
    mov     x9, #E_WAIT
.Lfail:
    mov     x0, #STDERR
    mov     x8, #NR_write
    svc     #0
    mov     x0, x9
    mov     x8, #NR_exit_group
    svc     #0

// ---------------------------------------------------------------------------
// Data. The two sockaddrs carry sentinels rather than numbers: the address and
// the port live in chm (`create::GUEST_IP`, `browser::CDP_PORT`) and a second
// copy here would be a copy that can drift. `cdpfwd::forwarder` rewrites them
// and refuses if a sentinel is not found exactly once.
// ---------------------------------------------------------------------------
.balign 8
int_one:
    .word 1

listen_sa:
    .hword AF_INET
    .hword 0xDEC0                       // sin_port sentinel, patched
    .word 0xC0DE0001                    // sin_addr sentinel, patched
    .quad 0

upstream_sa:
    .hword AF_INET
    .hword 0xDEC1                       // sin_port sentinel, patched
    .word 0x0100007F                    // 127.0.0.1, and never anything else
    .quad 0

m_epoll:
    .ascii "gimbal-cdpfwd: epoll_create1 failed\n"
m_socket:
    .ascii "gimbal-cdpfwd: socket failed\n"
m_bind:
    .ascii "gimbal-cdpfwd: bind failed (no guest address? needs --net)\n"
m_listen:
    .ascii "gimbal-cdpfwd: listen failed\n"
m_wait:
    .ascii "gimbal-cdpfwd: epoll_pwait failed\n"
m_end:
image_end:
