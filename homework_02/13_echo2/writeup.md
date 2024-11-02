# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "coalmine"
- story:  no story :/

## Setup
- setup correct libc
```
docker compose up
docker ps
docker exec -it 5dbd2b6fed26 /bin/bash
cd /lib/x86_64-linux-gnu
docker cp 5dbd2b6fed26:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_02/13_echo2
pwninit
```
- verify that it worked
```
LD_DEBUG=libs ./vuln_patched
```

## Exploit
- we can write arbitrary fmt string of length n, by writing last byte first and then do it in 0(n)


```
#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33311)
conn = pwn.process([exe.path])

pwn.gdb.attach(conn)


def set_format_string(fmt):
    for byte in fmt:
        print(byte)






set_format_string(b'%1$llx\n%2$llx\n%3$llx\n%4$llx\n')


```