# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "quiz"
- connect to machine
```
nc tasks.ws24.softsec.rub.de 32781
```
- I answered as follows:
```
Welcome to our quiz! You have 120 seconds to answer all questions!
Reverse Engineering (RE) is the process of analyzing a system to:
 (1) extract its components and their interrelationships, and create representations of it in another form or at a lower level.
 (2) identify its components and their interrelationships, and create representations of it in another form or at a higher level.
 (3) identify its components and their interrelationships, and create representations of and execute it as a level code.
 (4) hide its components and their interrelationships in complex operations, and make it difficult to create the representations of it in another form or at a higher level.
> 2

How is the number 1337 stored in memory (as a 32-bit value)?
 (1) 00000539
 (2) 37130000
 (3) 39050000
 (4) 00001337
> 3

What is the name of the well-known debugger from the GNU project?
 (1) windbg
 (2) ida
 (3) gdb
 (4) lldb
> 3

Which of these is the architecture that considers code as being the same as data
 (1) Le Corbusier architecture
 (2) von Neumann architecture
 (3) Harvard architecture
 (4) Turing architecture
> 2

What is the Linux utility that helps track down which syscalls were invoked by a program?
 (1) sysctl
 (2) strings
 (3) strace
 (4) ltrace
> 3

Which syscall do you use for executing programs
 (1) execl
 (2) kexec_file_load
 (3) execve
 (4) sysinfo
> 3

What idiom represents the same as multiplying a number by 2.
 (1) jmp rax
 (2) shl rax, 1
 (3) xor rax, 2
 (4) mov rax, 2
> 2

When you find a bug lying around in a big company that your government runs. What would be the ethical response to this?
 (1) Try to find a contact for responsible disclosure
 (2) Blackmail the manufacturer
 (3) Sell online
 (4) Give to your university professor for free (<3)
> 1

How are integer arguments passed to functions in Linux on x86_64?
 (1) all arguments are pushed on the stack
 (2) rax / rbx / rcx / rdx, and the rest on the stack
 (3) rdi / rsi / rdx / rcx / r8 / r9, and the rest on the stack
 (4) rcx / rdx / r8 / r9, and the rest on the stack
> 3

Consider `int foo = INT_MAX`. What would be the value of foo if you add 1 to foo?
 (1) 0
 (2) -2147483648
 (3) 2147483647
 (4) undefined
> 2

What is the mechanism's name that ensures the stack does not contain code?
 (1) ASLR
 (2) NX
 (3) mprotect
 (4) Stack canary
> 2

How are arguments passed to system calls in Linux on x86_64?
 (1) rax / rbx / rcx / rdx
 (2) rcx / rdx / r8 / r9, and the rest on the stack
 (3) rdi / rsi / rdx / rcx / r8 / r9
 (4) rdi / rsi / rdx / r10 / r8 / r9
> 4

Congratulations, here is your flag: softsec{j15BtCW5dS1M2o1iGEu8BwYST4NnpqpLIpNgLJ8FVB7q-rd9-4WaC3g1-KiUehwN}
```
- flag
```
softsec{j15BtCW5dS1M2o1iGEu8BwYST4NnpqpLIpNgLJ8FVB7q-rd9-4WaC3g1-KiUehwN}
```