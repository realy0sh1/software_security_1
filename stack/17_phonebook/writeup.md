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
- check security features
```
checksec ./vuln
```
```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```
- in the function phonebook_edit() is a buffer overflow as name is a 80-Byte buffer, but entry->name is only 64 bytes
- the address of the buffer (stack) is leaked (via phone number)

- GOAL: entry->name must point to stack (e.g. return address), then we can write to stack
- 1) write stack pointer of our choice into global phonebook pointer
    -> create a entry
    -> edit entry, change name and also overflow to change entry->next (= stack position of our choice) and entry->prev (= null)
    -> delete entry, then the global phonebook struct points to stack (thinks that there is a valid entry)
- 2) via phonebook_show (set index = 0), we can print the number and name
- 3) write ropchain
    -> using phonebook_edit, we can write 80Bytes
    -> ideally we have pointer to return address of main(), then we can write a rop chain there (right after the canary)

```
00:0000│ rcx rdi rsp 0x7ffe21cdfbe0 ◂— 0x4c /* 'L' */ <-- we get pointer to here
01:0008│             0x7ffe21cdfbe8 ◂— 0
02:0010│             0x7ffe21cdfbf0 ◂— 0
03:0018│             0x7ffe21cdfbf8 ◂— 0x97adc7197e0e2600 <-- canary, do not touch
04:0020│             0x7ffe21cdfc00 ◂— 0

05:0028│             0x7ffe21cdfc08 —▸ 0x7ffe21cdfd38 —▸ 0x7ffe21ce2022 ◂— '/home...' <- start phone number (don't care)
06:0030│             0x7ffe21cdfc10 ◂— 1
07:0038│             0x7ffe21cdfc18 ◂— 0
08:0040│             0x7ffe21cdfc20 —▸ 0x7ffe21cdfd48 —▸ 0x7ffe21ce2071 ◂— 'SHELL=...'

09:0048│             0x7ffe21cdfc28 —▸ 0x7fc0d357824a ◂— mov edi, eax   <-- start name, this leaks libc pointer :))) via phonebook_show, after that we start writing ropchain here, which gets immediately executed :)))
0a:0050│             0x7ffe21cdfc30 ◂— 0
0b:0058│             0x7ffe21cdfc38 —▸ 0x598c4ec7c657 (main) ◂— push r13
0c:0060│             0x7ffe21cdfc40 ◂— 0x100000000
0d:0068│             0x7ffe21cdfc48 —▸ 0x7ffe21cdfd38 —▸ 0x7ffe21ce2022 ◂— '/home/...'
0e:0070│             0x7ffe21cdfc50 —▸ 0x7ffe21cdfd38 —▸ 0x7ffe21ce2022 ◂— '/home/...'
0f:0078│             0x7ffe21cdfc58 ◂— 0x89732705510870eb
10:0080│             0x7ffe21cdfc60 ◂— 0

11:0088│             0x7ffe21cdfc68 —▸ 0x7ffe21cdfd48 —▸ 0x7ffe21ce2071 ◂— 'SHELL=/bin/bash'
12:0090│             0x7ffe21cdfc70 —▸ 0x598c4ec7eda0       <-- end of entry

13:0098│             0x7ffe21cdfc78 —▸ 0x7fc0d3766020 (_rtld_global) —▸ 0x7fc0d37672e0 —▸ 0x598c4ec7b000 ◂— 0x10102464c457f
14:00a0│             0x7ffe21cdfc80 ◂— 0x768f649ea96a70eb
15:00a8│             0x7ffe21cdfc88 ◂— 0x76f281aa550e70eb
16:00b0│             0x7ffe21cdfc90 ◂— 0
... ↓                2 skipped
19:00c8│             0x7ffe21cdfca8 —▸ 0x7ffe21cdfd38 —▸ 0x7ffe21ce2022 ◂— '/home/timniklas/Code/software_security_1/homework_03/17_phonebook/vuln_patched'
1a:00d0│             0x7ffe21cdfcb0 —▸ 0x7ffe21cdfd38 —▸ 0x7ffe21ce2022 ◂— '/home/timniklas/Code/software_security_1/homework_03/17_phonebook/vuln_patched'
1b:00d8│             0x7ffe21cdfcb8 ◂— 0x97adc7197e0e2600
1c:00e0│             0x7ffe21cdfcc0 ◂— 0xd /* '\r' */
1d:00e8│             0x7ffe21cdfcc8 —▸ 0x7fc0d3578305 (__libc_start_main+133) ◂— mov r15, qword ptr [rip + 0x1aac6c]
1e:00f0│             0x7ffe21cdfcd0 —▸ 0x598c4ec7c657 (main) ◂— push r13
1f:00f8│             0x7ffe21cdfcd8 —▸ 0x598c4ec7eda0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x598c4ec7c0e0 (__do_global_dtors_aux) ◂— endbr64 
20:0100│             0x7ffe21cdfce0 ◂— 0

```

- flag:
```
softsec{jSPy9VL4U-CZBw9ezXsjt_A799Y6zkR7u9Ac4zp57sHqKRn60nODlXwv7OP8TxgT}
```