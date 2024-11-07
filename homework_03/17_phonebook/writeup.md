# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "phonebook"
- story: We're releasing our new phone book soon. Can you test the software for us?
- Hint: Don't be confused by the presence of dynamic memory allocation (on the heap, via malloc/calloc and free) in this task — you don't need to understand anything about the heap yet. 

## Setup
- setup correct libc
```
docker compose up
docker ps
docker exec -it 934b5fd7fb33 /bin/bash
cd /lib/x86_64-linux-gnu
docker cp 934b5fd7fb33:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_03/17_phonebook
pwninit
```
- verify that it worked
```
LD_DEBUG=libs ./vuln_patched
```

## Exploit
- just change rsp to new location
- flag
```
softsec{lDi9IPjZyjLAgx6SpI1mliM1RdU1pL-16ujk0FPtLArOemYjZQcbd7m5rDgpSbEx}
```