// modload — insert kernel modules, for guests that have no tool to do it with.
//
// Loading a module is a syscall (finit_module) and no shell builtin makes one.
// A container rootfs is under no obligation to ship `insmod` or `modprobe`, and
// the mainstream ones do not: measured, node:22-slim (Debian) has neither and
// no /lib/modules at all. That is the image the agent story needs, so a loader
// that assumes busybox would fail on exactly the case that matters.
//
// Takes module paths on argv, in load order, and inserts each one. Exits with
// the number that failed, so 0 means every module is in. A module that is
// already loaded (EEXIST) counts as success — it is, the module is present.
//
// Freestanding: raw syscalls, no libc, no relocations, no dynamic loader.
//
// Rebuild (from the repo root) after changing anything here:
//
//   SYSROOT=$(rustc --print sysroot)
//   clang --target=aarch64-unknown-linux-gnu -c chm/src/oci/modload.S -o /tmp/modload.o
//   "$SYSROOT"/lib/rustlib/*/bin/rust-lld -flavor gnu -static -e _start \
//       -o /tmp/modload /tmp/modload.o
//   "$SYSROOT"/lib/rustlib/*/bin/rust-objcopy --strip-all /tmp/modload \
//       chm/src/oci/modload.bin
//
// `modload::tests::the_binary_is_reproducible_from_the_source` re-runs exactly
// this and fails if the checked-in binary is not what the source assembles to.

.equ NR_openat,       56
.equ NR_close,        57
.equ NR_write,        64
.equ NR_exit,         93
.equ NR_finit_module, 273

.equ AT_FDCWD,  -100
.equ O_RDONLY,  0
.equ STDERR,    2

// finit_module returns -EEXIST when the module is already in. That is not a
// failure: the caller asked for it to be loaded and it is loaded.
.equ EEXIST, 17

.text
.global _start
_start:
    ldr     x19, [sp]                   // argc
    add     x20, sp, #8                 // &argv[0]
    mov     x21, #1                     // index; argv[0] is our own name
    mov     x22, #0                     // failures

.Lloop:
    cmp     x21, x19
    b.ge    .Ldone
    ldr     x23, [x20, x21, lsl #3]     // argv[i] — the module path

    mov     x0, #AT_FDCWD
    mov     x1, x23
    mov     x2, #O_RDONLY
    mov     x3, #0
    mov     x8, #NR_openat
    svc     #0
    tbnz    x0, #63, .Lfailed           // could not open it at all
    mov     x24, x0                     // fd

    // finit_module(fd, "", 0). The empty string is the module's parameters;
    // it must be a valid pointer, not NULL.
    mov     x0, x24
    adr     x1, no_params
    mov     x2, #0
    mov     x8, #NR_finit_module
    svc     #0
    mov     x25, x0                     // hold the result across close()

    mov     x0, x24
    mov     x8, #NR_close
    svc     #0

    tbz     x25, #63, .Lnext            // >= 0: loaded
    cmn     x25, #EEXIST                // == -EEXIST: already loaded, fine
    b.eq    .Lnext

.Lfailed:
    add     x22, x22, #1
    // Say which module failed. A count alone would leave the init reporting
    // that something did not load without being able to say what, which is
    // the silence this program exists to remove.
    mov     x0, #STDERR
    adr     x1, prefix
    mov     x2, #(prefix_end - prefix)
    mov     x8, #NR_write
    svc     #0
    mov     x2, #0                      // strlen(path)
.Lstrlen:
    ldrb    w3, [x23, x2]
    cbz     w3, .Lwrite_path
    add     x2, x2, #1
    b       .Lstrlen
.Lwrite_path:
    mov     x0, #STDERR
    mov     x1, x23
    mov     x8, #NR_write
    svc     #0
    mov     x0, #STDERR
    adr     x1, newline
    mov     x2, #1
    mov     x8, #NR_write
    svc     #0

.Lnext:
    add     x21, x21, #1
    b       .Lloop

.Ldone:
    mov     x0, x22
    mov     x8, #NR_exit
    svc     #0

.section .rodata
.balign 8
no_params:
    .byte 0
prefix:
    .ascii "gimbal: could not load "
prefix_end:
newline:
    .ascii "\n"
