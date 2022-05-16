---

title: Meet-4 -> More Advanced Kernel-ROP
author: th3f0x
styles:
  style: gruvbox-dark

---

## Overview

- [Overview](#overview)
- [Challenges](#challenges)
- [KPTI](#kpti)
- [Misc Tips](#misc-tips)
- [Home Assignment](#home-assignment)
- [Links](#links)

---

## Challenges

- khop (from BSides Noida CTF 2021)
  - Files: `khop.zip`

---

## KPTI

KPTI, abbreviated for Kernel page-table isolation, is a feature which separates
user-space and kernel-space page tables entirely, instead of using just one set
of page tables that contains both user-space and kernel-space addresses. One
set of page tables includes both kernel-space and user-space addresses same as
before, but it is only used when the system is running in kernel mode. The
second set of page tables for use in user mode contains a copy of user-space
and a minimal set of kernel-space addresses. It can be enabled/disabled by
adding kpti=1 or nopti under -append option.

> This feature is very unique to the kernel and was introduced to prevent
> meltdown in Linux kernel

---

## Misc Tips

- Getting a `mov rdi, rax` gadget:
  ```asm
  pop rdx ; ret
  8 // so that next comparison gadget sets the `equal` flag, so any further `jne <...>` don't execute
  cmp rdx, 8 ; jne <...> ; pop rbx ; pop rbp ; ret
  <dummy rbx>
  <dummy rbp>
  mov rdi, rax ; jne <...> ; pop rbx ; pop rbp ; ret
  <dummy rbx>
  <dummy rbp>
  ```

- Bypassing KPTI
  - Using a signal handler(hacky way, but works). We can just add a signal handler to it which calls
    get_shell() by simply inserting this line in to main:
    ```c
    signal(SIGSEGV, get_shell)
    ```

  - Using a KPTI trampoline. We use the function
    `swapgs_restore_regs_and_return_to_usermode` to execute code, which swaps
    the page tables and does the swaps and iretq for us. Note that we still
    need to add the required values on the stack for the iretq call. These can
    be pushed to kernel stack after address of this function. This function looks like:
    ```asm
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rax
    pop     rcx
    pop     rdx
    pop     rsi
    mov     rdi, rsp
    mov     rsp, qword ptr gs:unk_6004
    push    qword ptr [rdi+30h]
    push    qword ptr [rdi+28h]
    push    qword ptr [rdi+20h]
    push    qword ptr [rdi+18h]
    push    qword ptr [rdi+10h]
    push    qword ptr [rdi]
    push    rax
    jmp     short loc_FFFFFFFF81200F89
    ```
    Here, we can jump right after all the `pop` instructions in order to avoid
    enlargening of the rop-chain. This address is usually:
    `swapgs_restore_regs_and_return_to_usermode + 22`. This function still does a few pops afterwards (for RAX and RDI), so we need to push dummy values for them anyway.

---

## Home Assignment

- Try to read some portions from the [links](#links)
- Try challenge yourself
- Try to solve the challenge `kernel-rop` without reading the [Good blog series on kernel exploitation - Part 2](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-2/)
  in the [Links](#links) section, which basically serves as a writeup for the
  challenge. Read the post only after trying out the challenge yourself.
  - Files: `kernel-rop-bf9c106d45917343.tar.xz`
  - NOTE: Remove `kaslr` from `run.sh` in the `-append` flag and `+smap` from the `-cpu` flag for this time.
---

## Links

- [Good blog series on kernel exploitation - Part 2](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-2/)
- [Linux Kernel Exploitation compilation](https://github.com/xairy/linux-kernel-exploitation)
