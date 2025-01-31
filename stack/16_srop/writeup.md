# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "srop"
- story: Sometimes, you only have very few gadgets to write your ROP chain with. Luckily, a single system call is enough to set all registers. If you set up the stack correctly, the rt_sigreturn syscall (number 0xf, which is normally used to return from a signal handler) is able to set essentially all general-purpose registers, including rip. This is called sigreturn-oriented programming (SROP). It even has a Wikipedia article! Can you spawn a shell (e.g., with execve("/bin/sh", NULL, NULL))? You may have to chain two syscall gadgets to do that!
- Hint: pwntools also has some tooling for this: https://docs.pwntools.com/en/stable/rop/srop.html

## Exploit
- get all gadgets with ropper
- on the stack a 200Byte buffer gets allocated, but we can write 0x200 = 512 bytes => buffer overflow
- use SIGRETURN syscall to set registers for syscall that gets us shell :)
- flag
```
softsec{r4RIvsnkHPSL4LZFy45hQDtZ8xcdFOrb5ade-wwwgKgkFz-5C77sI-Oj7_st7xWY}
```