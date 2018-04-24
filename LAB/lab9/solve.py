#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

io = process("./playfmt")
elf = ELF("./playfmt")


