#!/usr/bin/env python3

import pwn
import itertools

exe = pwn.ELF("./rev")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/revelio') /bin/bash
# 3) gdb -p "$(pgrep -n rev)"


conn = pwn.remote('tasks.ws24.softsec.rub.de', 32810)
#conn = pwn.remote('127.0.0.1', 1024)


# FLAG 1

# s="Caput Draconis"
#          stored at rbp-0x40 | stored at rbp-0x38 | stored at rbp-0x38-2 | stored at rbp-0x2E
# target = 0x2D37451D18150F26 | 0x091C16011A30050E | 0x1C15 091C16011A30  | 0x0B1D021617267F06
#for pos in len(inputflag):
#    assert: (inputflag[pos] xor s[pos % 14]) == target[pos]
# => flag = target[pos] xor s[pos %14]
target = [0x26,0x0F,0x15,0x18,0x1D,0x45,0x37,0x2D,
        0x0E,0x05,0x30,0x1A,0x01,0x16,0x1C,0x09,
        0x15,0x1C,
        0x06,0x7F,0x26,0x17,0x16,0x02,0x1D,0x0B]
s =  list(b'Caput Draconis')
flag_1 = b''
for pos in range(26):
    flag_1 += bytes.fromhex(hex(target[pos] ^ s[pos%14])[2:])
#print(f'flag_1: {flag_1}')
conn.recvuntil(b"Enter flag 1:")
#b'enemies_of_the_heir_beware'
conn.sendline(flag_1)


# FLAG 2

# in UTF-16LE (26 chars => 52 bytes)
# 26 chars as hex string: (stored as little endien so swap bytes 2byte-wise)
"7000 7400 76007900650072007A0062006E0071006D0075006A00770078006B00730068006C006900640067006100660063006F00"
"p t vyerzbnqmujwxkshlidgafco" 
# there are 52 pointers in the array
# each pointer points to a 2 Byte UTF16-little-endien char as shown below
# effectively we have this string (tranlated pointer to corresponding char)
target = b'pt by er tz bn qm uj wx ks rb hl yi de gv sq ad jg xk lf fu cp ma oh ic zw no'
# if we want 2nd char in pack, we need to choose first one in input_flag:
flag_2 = b'jellybeans'
# this way j => g (in total we get: grffinrdoq)
conn.recvuntil(b"Enter flag 2:")
#b'jellybeans'
conn.sendline(flag_2)


# FLAG 3

# key must be: b'alohomora'
# input is 8 byte long (either L or R)
# path = flag: LRRLRLRL
flag_3 = b'LRRLRLRL'
conn.recvuntil(b"Enter flag 3:")
#b'LRRLRLRL'
conn.sendline(flag_3)

conn.interactive()
