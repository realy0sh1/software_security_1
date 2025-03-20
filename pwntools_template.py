#!/usr/bin/env python3

import pwn
import socket
import threading

# this is required on gnome to start gdb
pwn.context.terminal = ['gnome-terminal', '--']


pwn.context.arch = 'amd64'

# pwninit
exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")

port = 1024
#conn = pwn.remote('tasks.ws24.softsec.rub.de', port)
conn = pwn.process([exe.path])

pwn.gdb.attach(conn, gdbscript="""
set detach-on-fork off
set follow-fork-mode child
""")

pwn.pause()

# do stuff


conn.interactive()
