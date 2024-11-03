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
- we have a pointer to 
```
00:0000│  5d4d1621ad68 (__do_global_dtors_aux_fini_array_entry) —▸ 0x556dabacb2c0 (__do_global_dtors_aux) ◂— endbr64 
```
- http://www.secureroot.com/security/advisories/9768329857.html
- input argument 22 has the value: 5d4d1621ad68
```
info symbol 5d4d1621ad68
```
```
__do_global_dtors_aux_fini_array_entry in section .fini_array of /home/timniklas/Code/software_security_1/homework_02/13_echo2/vuln_patched
```
- show the bytes at that address
```
x/1xg 5d4d1621ad68
```
```
0x5d4d1621ad68:	0x00005d4d162182c0
```
- figure out what is there usually
```
telescope 0x0000556dabacb2c0
```
```
00:0000│  0x556dabacb2c0 (__do_global_dtors_aux) ◂— endbr64 
01:0008│  0x556dabacb2c8 (__do_global_dtors_aux+8) ◂— add byte ptr [rax], al
02:0010│  0x556dabacb2d0 (__do_global_dtors_aux+16) ◂— cmp eax, 0x2d22 /* '="-' */
```
- that means we can override the pointer and point to our ROP chain. On exit(), our ropchain is called.

- the address is similar to main+135, which is: 0x5d4d 1621|8187
-                                               0x5d4d 1621|ad68
-   address of ssize_t fmt_len                  0x5d4d|1621|b050
- this means we only have to overrid the lower 2 Bytes = 2^16 = 65536, which should be possible
- lets try this out: when calling exit, call main again



- input 15 has pointer to main()

##############################

- new idea
    - on stack are addresses from the stack/heap/code (everything we meight need)
    - we can override the last two bytes of that address to have an arbitrary address on the stack
    - then we can reference that input parameter and write to arbitrary memory




    0x0000000000001469: add rsp, 0x18; pop rbx; pop rbp; ret; 


    softsec{uEiZ1qCHPGTzmv0TFtiVTJuYpd9T5cglTQnaGcqx1TDbYX2Z1RjnJJ-PdMI0v5qT}