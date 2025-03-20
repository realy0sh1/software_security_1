# GDB + pwndbg
- gdb will turn off ASLR if we start programm with gdb
- if we attach gdb to a programm, ASLR is on => addresses change => breakpoints will not work


### attack to program
- via: gdb -p
```
podman exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'
```


### open binary directly in gdb
 ```
gdb ./my_binary
 ```


### run program (and interact with it) 
```
r
```
- start and break at the main function (does the initialization)
```
start
```
- start at the very first instruction and break (all registers zero)
```
starti
```
- continue (until the end/breakpoint)
```
c
```
- step a single instruction
```
s
```
- execute next instruction (entire call if call)
```
n
```
- step out of a function (runs until the return of the function)
```
fin
```


### show stack
- print (20 entries) of stack
```
stack 20
```


### show heap:
- entire heap
```
heap
```
- show fastbins
```
fastbins
```


### show data at addresses
- at address
```
telescope 0x747a03e2a3e5
```
- at rsi
```
telescope $rsi 20
p/x $rsi
```
- show next 10 instructions starting at address
```
x/10i 0x747a03e2a3e5
```


### address -> function
- get symbol (function) of address
```
info symbol 0x79ac90a29d90
```


### function -> address
- get address of system() function directly
```
p system
```
- get (more) information about function
```
info address win
```


### get virtual memory map
```
vmmap
```


### get got of libc
- also possible to get via IDA
```
got -p libc
```
- got of vuln via:
```
got
```

### get main_arena offset
- main_arena is in libc (but not in debug symbols)
- get libc base and pointer of main_arena (subtract to get offset to main_arena)
```
vmmap
p &main_arena
```


### find c vars
- find address of c var "bug"
```
info variables bug
info address bug
```


### disassemble function
```
disassemble <function_name>
```


### set break points 
- break on the functino "read"
```
b read
```
- break on address
```
b *Ox55...555
b *main+10
```


### handle forking
- create breakpoint at fork()
```
catch fork
```
- decide if gdb should follow the child or parent on fork
```
set follow-fork-mode child
```
- allow gdb to keep control of both parent and child
```
set detach-on-fork off
```


### install gdb + pwndebug
```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
- allow root to use it, add /root/.gdbinit
```
source /home/timniklas/pwndbg/gdbinit.py
add-auto-load-safe-path /home/timniklas/.gdbinit
```


### online chat sheet
- cheat sheet: https://pwndbg.re/CheatSheet.pdf
