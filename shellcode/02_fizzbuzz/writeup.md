# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "fizzbuzz"
- story: In this task, you'll need to write some shellcode that will solve a variant of the famous FizzBuzz problem. You'll receive a pointer to an array of 2048 unsigned 32-bit integers in rdi. Replace all values that are divisible only by 3 with zero, those that are only divisible by 5 with one, and those that are divisible by both with two. All remaining numbers should be replaced with three.
Then, return cleanly from your shellcode. If you correctly fizzbuzz-ed all the numbers, you'll receive the flag. 
- start local instance
```
cd /home/timniklas/Code/software_security_1/homework_01/02_fizzbuzz
docker build -t fizzbuzz .
echo 'flag{fake_flag}' > flag
docker run --rm --mount "type=bind,src=$(pwd)/flag,dst=/flag" --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 1024:1024 -ti fizzbuzz
```
- connect to machine (do it once to see what happens, but I have an exploit in exploit.py)
```
nc 127.0.0.1 1024
```
- i can provide the program with shellcode that kindly will be executed for me
- in the register rdi is a pointer to the array
- i automated the attack:
```python
#!/usr/bin/env python3

import pwn

pwn.context.arch = 'amd64'
conn = pwn.remote('tasks.ws24.softsec.rub.de', 32862)
'''
i want somthing like the following in assembly
p=0
while(p<2048) {
     if (elements[i] % 15 == 0) {
        elements[i] = 2;
    } else if (elements[i] % 3 == 0) {
        elements[i] = 0;
    } else if (elements[i] % 5 == 0) {
        elements[i] = 1;
    } else {
        elements[i] = 3;
    }
    p += 1;
}
'''
shellcode = pwn.asm('''
    xor rcx, rcx;           # rcx is loop var running from 0...2047                    
while_start:
    cmp rcx, 2048;
    jae while_exit;         # if rcx >= (above or equal), exit  
    
    mov r10d, 2;   # r10d (32-bit) has the new value that will replace previous  
    xor edx, edx;  # zero in edx for division we divide 64-bit / 32-bit = 32-bit                                   
    mov eax, [rdi + rcx*4]; # copy array element to eax (32bit)
    mov r11d, 15;
    div r11d;      # edx:eax/15 = eax Remainder edx
    cmp edx, 0;
    je replace;    # replace with value 2 if remainder 0                   

    mov r10d, 0; 
    xor edx, edx; 
    mov eax, [rdi + rcx*4];
    mov r11d, 3;
    div r11d;
    cmp edx, 0;
    je replace; # replace with value 0

    mov r10d, 1;  
    xor edx, edx;    
    mov eax, [rdi + rcx*4];
    mov r11d, 5;
    div r11d;
    cmp edx, 0;
    je replace; # replace with value 1

    mov r10d, 3; # else replace with 3
    je replace;                        

replace:
    mov [rdi + rcx*4], r10d   
    inc rcx;
    jmp while_start;
while_exit:
    ret       
''')

print(shellcode.hex())
conn.recvuntil(b'please enter your (hex-encoded) shellcode, at most 4096 bytes:')
conn.sendline(shellcode.hex().encode())
conn.interactive()
```
- i got the following flag:
```
softsec{jqCF9ssJUHNbQN425vd73x0f4g1gFI7L7ANl7ABxE1i3ZqWWpKWLhqF4-G3U3lVB}
```
