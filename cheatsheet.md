# Cheatsheet binary exploitation


### x86 (amd64) instruction set
- https://treeniks.github.io/x86-64-simplified/prefix.html


### x86 64bit registers
- restore: rbx, rbp, r12, r13, r14, r15, rsp
- change freely: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11

- fastcall: rdi, rsi, rdx, rcx, r8, r9, stack
- syscall: rdi, rsi, rdx


### python virtual environment
```
python3 -m venv softsec_venv
source softsec_venv/bin/activate
pip3 install pwn
```


### python conversions
- bytes with number to int
```
b = b'AC12'
i = int(b, 16)

b = b'112'
i = int(b, 10)
```

- raw bytes to int
```
pwn.u64(b)

i = b'\x00'
int.from_bytes(i, 'little')
```

- int to bytes
```
i = 0xAC12
b = pwn.p64(i)
b = pwn.p64(i, endien="big")
```


### objdump: quick peek at disassembly
- dump binary with:
```
objdump -M intel -d ./my_binary
objdump -M intel -D ./vuln
```


## checksec
- use checksec to find out which security features binary has
```
checksec --file=my_binary
```


### manpage: get info about libc and syscalls
- get information about libc
```
man 3 gets
```


### get info about syscalls
- https://syscalls.mebeim.net/?table=x86/64/x64/latest
```
man 2 open
```


### extract linker from docker to run other libc locally
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


### gcc and asm files
- for shellcode use pwntools in python instead, as more convenient
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


### find how many bits aslr system has
- find out how many bits are randomized with aslr 
```
sudo cat /proc/sys/vm/mmap_rnd_bits
```