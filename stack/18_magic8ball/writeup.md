# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "magic8ball"
- story: he Magic 8 Ball will answer all of your questions... maybe.


This binary comes with a shadow stack to protect control-flow integrity (or rather, an emulation layer that simulates the shadow stack). In essence, this means that every ret has to go to the call from which it came.
You may want to look into jump- and call-oriented programming to solve this.

Hint: Unfortunately, this means that you won't be able to debug the binary while it is running. Linux only allows one debugger per process, and the shadow stack emulation takes up that slot.
You can run the binary without shadow stack emulation by removing the /sbin/cfi --shadowstack from the command line in the Dockerfile.
Then, you won't be able to see any CFI violations, but you will be able to debug the binary as usual.

Note: /sbin/cfi also supports a --trace flag, which will report all instructions that the binary executes, but this is likely to be very verbose.

Hint: In ropper, you can use type jop to restrict the list of gadgets to only those that end in jmp or ret. 


## Exploit
- the struct has a 40 Byte char array and after that an 8 Byte function pointer 
- we can overflow the char array and thus also override the function pointer. In addition we can write a rop/call-chain onto the stack as we can write 400 Bytes :)
- as we have a shadow stack, we can never return but only call, call, call (that is why we get the first call for free :)
- we have libc, so our goal is to call system. Before that we need to put the pointer to the string "\bin\sh\x00" into rdi first.
- just use a gadget that reads rdi from our buffer (easy :)
- find call gadgets with ropper
```
ropper
file libc.so.6
help
type jop
gadgets
```
- flag
```
softsec{mKPkTEz6fNVMdy67cdotw3AUSY85Itm38VlWSm-5pUutq3LodrsDWGav71mHyFbb}
```