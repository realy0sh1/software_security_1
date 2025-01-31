# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "tarzan"
- story: There is a technique called Stack Pivoting which Tarzan, the King of the Jungle, needs to master. Could you help him make a ROPe swing to a nicer buffer and exploit it?
- Hint: You have the location of the big buffer which has plenty of space for a better exploit than the smaller buffer. Use stack pivoting to jump there.
- Hint: Stack pivoting gadgets include leave; ret, pop rsp; ret, and xchg , rsp; ret. ropper should be able to help you find them.
- Hint: Remember to use the correct offset to compute the address of libc from the leak. 

## Setup
- setup correct libc
```
docker compose up
docker ps
docker exec -it 3ddab9b8e9dc /bin/bash
cd /lib/x86_64-linux-gnu
docker cp 3ddab9b8e9dc:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_03/15_tarzan
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