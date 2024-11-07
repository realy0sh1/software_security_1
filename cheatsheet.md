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
- Show C-source code by pressing F5


## objdump: quick peek at disassembly
- dump binary with:
```
objdump -M intel -d ./my_binary
```


## masm/nasm/yasm: assembler
- TODO: figure out, what to use


## gcc: compiler
- switch to intel syntax, add at top of asm file fizzbuzz.s:
```
.intel_syntax noprefix
.globl do_fizzbuzz ;#.global _start # do this if "main" and not called from c

do_fizzbuzz:
	push rbp
	push rbx
	push rdx
	xor rcx, rcx
	
	loop:
		xor r10, r10
		mov r10b, 3
```
- cmpile asm to elf (can be executed, e.g. in gdb)
```
gcc -Wl,-N -ffreestanding -nostdlib -static fizzbuzz.s -o fizzbuzz.elf
```
-look at elf
```
objdump -M intel -d ./fizzbuzz.elf
```
- run elf
```
gdb ./fizzbuzz.elf
```
- extract shell code as bytes
```
objcopy --dump-section .text=fizzbuzz.raw fizzbuzz.elf
```
- call from main.c
```
#include <stdio.h>
#include <stdint.h>

extern int do_fizzbuzz(uint32_t* b);

int main(){
	uint32_t a[2048];
	int res;
	
	for (int i = 0; i < 2048; i++)
	{
		a[i] = i+1;
	}
	res = do_fizzbuzz(a);
	for (int i = 0; i < 16; i++)
	{
		printf("%x\n", a[i]);
	}
	printf("res: %d\n", res);
	return res;
}
```
- compile c with
```
gcc main.c fizzbuzz.s -o main
```


## gdb + pwndbg: Debugging and Dynamic Analysis
- cheat sheet: https://pwndbg.re/CheatSheet.pdf
- install gdb + pwndebug (or gef)
```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
- allow root to use it, add /root/.gdbinit
```
source /home/timniklas/pwndbg/gdbinit.py
add-auto-load-safe-path /home/timniklas/.gdbinit
```
- open binary directly in gdb
 ```
gdb ./my_binary
 ```
- attach gdb to running process: get newest process id of process cat and debug
```
sudo -E gdb -p $(pgrep -n vuln)
```
- print (20 entries) of stack
```
stack 20
```
- show memory at rsi
```
telescope $rsi 20
```
- print a value
```
p/x $rsi
```
- run program (and interact with it) 
```
r
```
- start and break at the main function (does the initialization)
```
start
```
- start at the very first instruction and break (all registers zero)
```
starti
```
- continue (until the end/breakpoint)
```
c
```
- step a single instruction
```
si
```
- find all commands that are related to another command (e.g. similar to step)
```
apropos step
```
- press enter to repeat same command
- step out of a function (runs until the return of the function)
```
fin
```
- next instruction (skip calls, meaning execute call and stop after wards)
```
ni
```
- set break points (break on the functino "read")
```
b read
```
- break on address
```
b *Ox55...555
b *main+10
```
- gdb will turn off ASLR if we start programm with gdb
- if we attach gdb to a programm, ASLR is on => addresses change => breakpoints will not work
- get address of system() libc
```
p system
```
- get symbol (function) of address
```
info symbol 0x79ac90a29d90
```
- show next 10 instructions starting at address
```
x/10i 0x747a03e2a3e5
```
- disassemble function
```
disassemble <function_name>
```
- create breakpoint at fork()
```
catch fork
```
- decide if gdb should follow the child or parent on fork
```
set follow-fork-mode child
```
- allow gdb to keep control of both parent and child
```
set detach-on-fork off
```

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
#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33311)
conn = pwn.process([exe.path])

pwn.gdb.attach(conn)

conn.interactive()
exit()
```
```python
form pwn import *

context.terminal

context.terminal = ['/bin/sh']
tube = gdb.debug('./vuln')

tube.write(b'A'*40)

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
- change freely: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11

- fastcall: rdi, rsi, rdx, rcx, r8, r9, stack
- syscall: rdi, rsi, rdx


## x86 (amd64) instruction set
- https://treeniks.github.io/x86-64-simplified/prefix.html


## find ROP gadgets
- https://github.com/sashs/Ropper
- install ropper
```
sudo pip install capstone
sudo pip install filebytes
sudo pip install keystone-engine
pip install ropper
```
- find gadgets
```
ropper --file ./vuln
ropper --file ./vuln --search syscall
ropper --file ./vuln --inst-count 2 --type rop
ropper --file ./vuln --search "mov rdi, e?x" --inst-count 2 --type rop

ropper --file ./vuln --search "pop rdi; ret;" 

ropper --file ./vuln --semantic "rdi+=rax"
```
- find all gadgets interactively
```
ropper
file vuln
```
- exclude stuff
```
badbytes 0a
```
- find specific ones
```
search /1/ pop rdi
```


# extract linker to run other libc locally
- get container id
```
docker ps
```
- get correct linker (in addition to the already provided libc)
```
docker exec -it c93ecb781483 /bin/bash
cd /lib/x86_64-linux-gnu

ld-linux-x86-64.so.2

docker cp c93ecb781483:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_02/10_echo
```
- setup pwndbg
```
- use pwninit to get it working (cargo install pwninit)
```
- verify that it worked
```
LD_DEBUG=libs ./vuln_patched
```

# gind how many bits aslr system has
- find out how many bits are randomized with aslr 
```
sudo cat /proc/sys/vm/mmap_rnd_bits
```


# found out how far we can go with the overflow until we reach the return address
- get a non repeating string with python 
- paste it in the input, then use cyclic_find to get the length
```
cyclic(128)
cyclic_find(0x<address>)
```


# ROP chain trick if PIE-disabled
- if pie is off, we can write into "data" with the ropchain, then we can read from this well known address
```python
chain = b''.join([
	pwn.p64(0x4013d5), # pop rdi; ret;
	pwn.p64(0x48a000), # => rdi = "/bin/sh";
	pwn.p64(0x401001), # pop rax; ret;
	b'/bin/sh\0'
	pwn.p64(0x442b30) # mov [rdi], rax; ret;
	pwn.p64(binary.symbols['system'])
])
```


# One_gadget
- install
```
sudo gem install one_gadget
```

- 