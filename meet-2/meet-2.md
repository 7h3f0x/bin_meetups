---

title: Meet-2 -> Basic Exloitation Techniques
author: th3f0x
styles:
  style: gruvbox-dark

---

## Overview

- [Overview](#overview)
- [Address Protection](#address-protection)
- [Userspace Memory Access Mitigations](#userspace-memory-access-mitigations)
- [Challenges](#challenges)
- [Misc Tips](#misc-tips)
- [Home Assignment](#home-assignment)
- [Links](#links)

---

## Address Protection

- This bans kernel using memory address starting from 0. The reason is quite
simple, the NULL pointer dereference will also try to read address 0.

- We can check the minimum address mappable by

```sh
cat /proc/sys/vm/mmap_min_addr
```

---

## Userspace Memory Access Mitigations

> SMEP: Supervisor Mode Execution Prevention

This feature marks all the userland pages in the page table as non-executable
when the process is in kernel-mode. In the kernel, this is enabled by setting
the 20th bit of Control Register CR4. On boot, it can be enabled by adding
`+smep` to `-cpu`, and disabled by adding `nosmep` to `-append`

> SMAP: Supervisor Mode Access Prevention

Complementing SMEP, this feature marks all the userland pages in the page table
as non-accessible when the process is in kernel-mode, which means they cannot
be read or written as well. In the kernel, this is enabled by setting the 21st
bit of Control Register CR4. On boot, it can be enabled by adding `+smap` to
`-cpu`, and disabled by adding `nosmap` to `-append`

---

## Challenges

- Lab 5 (from [How2Kernel](https://github.com/R3x/How2Kernel) Repository)
  - Files: `https://github.com/R3x/How2Kernel/Lab5`

- suscall (from BSides Noida CTF 2021)
  - Files: `suscall.tar.gz`

---

## Misc Tips

- To get an exact address from `mmap`, use the `MAP_FIXED` flag in the `flags` field.

```
MAP_FIXED
Don't  interpret  addr  as  a hint: place the mapping at exactly that address.```
```

Note that mmap will fail in case the `addr` value is something that cannot be mapped as the starting address, `mmap` will fail and return `-1`

- These systems are very minimal and don't have the C standard libary (the
  libc.so files). So we need to make the exploit statically linked
  ```sh
  <compiler of choice> -static exploit.c
  ```

- To get the binary on the target system (on the remote, since we can inject
  our binary simply by modifying the initramfs file for local testing), we
  generally don't have access to networking, so we use base64 to safely
  transport binary data to target and then decode it on the target machine:

  ```sh
  # on our machine
  base64 <exploit> | xclip -sel clip

  # on target machine
  cd /tmp
  cat > a.txt << EOF
  <paste data here>
  EOF
  base64 -d a.txt > a.out
  chmod +x a.out
  ./a.out
  # get root shell ;)
  ```

- To get the smallest binary sizes(since the regular libc is optimised for
  performance and not size), use `musl`:
  ```sh
  musl-gcc -static exploit.c # uses the musl libc
  ```

---

## Home Assignment

- Try to read some portions from the [links](#links)
- Try both challenges yourself
- Solve Labs 1-4 yourself (from [How2Kernel](https://github.com/R3x/How2Kernel))
  - First 3 labs are just practice for writing kernel modules
  - 4th lab is similar to last week's `Baby Kernel` Challenge. Maybe try writing an exploit instead of using provided client

---

## Links

- [Good blog series on kernel exploitation](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)
- [Kernel Challenges Basic Info](https://web.archive.org/web/20191019131252/http://www.auxy.xyz/modern%20binary%20exploitation/2019/06/10/Linux-Exp-Tutorial.html)
