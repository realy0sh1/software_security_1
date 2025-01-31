# Cheatsheet binary exploitation
- scoreboard: 

## IDA: reverse engineering and binary analysis
- on sciebo: https://ruhr-uni-bochum.sciebo.de/s/HtOsjEyOgeYjLOd
- my key is in my keepass and needs to be saved in installation directory
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
objdump -M intel -D ./vuln
```


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
- create breakpoint in gdb if SIGINT signal handler triggers
```
handler SIGINT stop apss
```
- see all signals
```
kill -l
```
- send signal to program (that runs inside gdb)
```
kill -SIGINT $(pgrep signal-example)
```
- search a 8 bytes in stack in gdb
```
search -t qword 0xdeadbead
```
- show heap:
```
heap
```
- show fastbins:
```
fastbins
```
- get got of libc using pwndbg:
```
got -p libc
```
- get address of function
```
info address win
```


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
- basic usage with docker setup for exam
```python
import pwn

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33267)
#conn = pwn.remote('127.0.0.1', 1024)

# wait for user input (in this time, connect gdb)
pwn.pause()

def call_secret():
    conn.sendlineafter(b'> ', b'42')
    conn.sendlineafter(b'Index: ', b'0')


call_secret()

conn.interactive()
```
- basic usage for CTF in general (use pwninit to setup library)
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

# find how many bits aslr system has
- find out how many bits are randomized with aslr 
```
sudo cat /proc/sys/vm/mmap_rnd_bits
```



# IDA
- 'F5' to decompile
- 'Tab' to switch between assembly and pseudocode
- 'Space' to swtich between graph view and linear view
- 'N' to rename things
- 'Y' to retype things
- 'x' to find cross references
- '/' to comment
- rightclick on value to change int->char etc
- mark -> edit -> export data (get hexstring from raw bytes)
- add (local) types, rightclick -> add type -> c code (then retype from char to phonebook pointer) 
```
struct phonebook_entry {
	char data[0x70];
}
```


# Heap: actual malloc code
- https://elixir.bootlin.com/glibc/glibc-2.36.9000/source/malloc/malloc.c


# docker debug setup
```
 docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'
```

# Heap
- 10 fastbins with sizes: 16, 24, 32, 40, 48, 56, 64, 72, 80 and 88.
- the house of exploits: https://seclists.org/bugtraq/2005/Oct/118
- main arena is in libc:
```
p main_arena
```
- size of malloc() is always multiple of 16 Bytes (and we need 8 Bytes of Chunk header)
- in unsorted list (double linked list) there are pointer to main arena

### get main_arena offset
- get main arena position via gdb (not in debug symbols)
- get libc base and pointer of main_arena (subtract to get offset to main_arena)
```
vmmap
p &main_arena
```

## get got of libc
```
got -p libc
```

### practically disable tchache
- option 1: malloc stuff that is bigger than tcache or fastbin entries
- option 2: 
	- tcache has 7 entries per size
	- malloc 8 things
	- free 7 things (cache full)
	- free 8th thing => in fastbin (or unsorted if fastbin full, this way disable fastbin as well)
	- malloc 7 things (tcache empty now)
	- malloc 8-th thing (we get it from fastbin (or unsorted))

## get vtable
```
objdump -t ./vuln | c++filt | grep vtable
```



## python virtual environment
```
python3 -m venv softsec_venv
source softsec_venv/bin/activate
pip3 install pwn
```
