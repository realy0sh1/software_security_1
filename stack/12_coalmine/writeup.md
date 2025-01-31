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
docker exec -it 2685955ff290 /bin/bash
cd /lib/x86_64-linux-gnu
docker cp 2685955ff290:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_02/12_coalmine
pwninit
```
- verify that it worked
```
LD_DEBUG=libs ./vuln_patched
```

## Exploit
- fork return 0 on child (pid on parent) and keeps entire memory, including the stack canary and aslr offsets
- child writes up to 256 bytes into buffer => we override stack canary
- once we have done that we can override return address to get aslr
- then deploy a rop chain (child return => triggers rop chain :)
- once we guessed correct offset, we cat a "You made it back alive :)" message back from the parent process
- flag
```
softsec{uN9VP2sD2O5GGDo2xnZ5yt9jzSoHq953Pr-ZF2C6cFjqYDhz1cSXaTi6J1XHjmFy}
```