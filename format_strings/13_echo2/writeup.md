# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "echo2"
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
- we can override local stack, by using a pointer on the stack that points to another stack pointer
- flag 
```
softsec{uEiZ1qCHPGTzmv0TFtiVTJuYpd9T5cglTQnaGcqx1TDbYX2Z1RjnJJ-PdMI0v5qT}
```