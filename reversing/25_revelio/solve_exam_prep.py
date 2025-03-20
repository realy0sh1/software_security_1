#!/usr/bin/env python3

import pwn
import socket
import threading
import string

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

port = 1024
conn = pwn.remote('127.0.0.1', port)

# flag_1
# flag is 26 chars long
s = [b for b in b'Caput Draconis']
# flip endieness as stored in little endian
v3 = pwn.p64(0x2D37451D18150F26) + pwn.p16(0x50E) + pwn.p64(0x1C15091C16011A30) + pwn.p64(0xB1D021617267F06)
v3 = [b for b in v3]
# vs[i] = flag ^ s[i mod 14]
# flag = v3[i] ^ s[i mod 14]
flag_1 = b''
for i in range(26):
    flag_1 += pwn.p8(v3[i]^s[i%14], endianness='big')

#b'enemies_of_the_heir_beware'
conn.sendlineafter(b'Enter flag 1: ', flag_1)

# flag_2
# v3 has 416 bytes
# we had pointers to chars, as pointer is 1 byte but char 2bytes as UTF-16
v3 = bytes.fromhex('1E20000000000000 2020000000000000 222000000000000024200000000000002620000000000000282000000000000020200000000000002A200000000000002C200000000000002E20000000000000302000000000000032200000000000003420000000000000362000000000000038200000000000003A200000000000003C200000000000003E2000000000000028200000000000002C20000000000000402000000000000042200000000000002420000000000000442000000000000046200000000000002620000000000000482000000000000022200000000000003E2000000000000030200000000000004A200000000000004620000000000000362000000000000048200000000000003A200000000000003C2000000000000042200000000000004C200000000000004C2000000000000034200000000000004E200000000000001E2000000000000032200000000000004A200000000000005020000000000000402000000000000044200000000000004E200000000000002A2000000000000038200000000000002E200000000000005020000000000000')
# the following chars were stored in UTF-16LE
v3 = b'ptvyerzbnqmujwxkshlidgafco' # 26 chars
# as the pointers are messeed up we effectively have this string:
v3 = b'pt vy er tz bn qm uj wx ks rb hl yi de gv sq ad jg xk lf fu cp ma oh ic zw no'
# when we read fist char, we take 2nd
# so other way around, as we want grffinrdoq, we take jellybean

# as we want grffinrdoq at the end, we need to take the char before it
# jellybeans
flag_2 = b'jellybeans'
conn.sendlineafter(b'Enter flag 2: ', flag_2)

# flag_3
"""
struct node {
    char name;
    node *left_child;
    node *right_child;
}
"""
flag_3 = b'LRRLRLRL'
conn.sendlineafter(b'Enter flag 3: ', flag_3)

conn.interactive()