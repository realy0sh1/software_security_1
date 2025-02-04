# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "tinyalloc"
- story: I wrote a tiny little allocator.
    - Don't worry, you don't need to read all of the allocator code, I tried not to put any bugs there (though there probably are some left unintentionally — if you do find bugs in the allocator, please let me know).
    - For this allocator, gdb-tools.py provides the inspect-heap and inspect-freelist commands. They work (almost) like the pwndbg commands you may be used to.
    - There is probably no one canonical way to break this. For some inspiration: my solution uses consolidation with a fake top chunk and an analogue to the (ancient) House of Force technique.
    - Remember that the offset between libc and libtinyalloc is constant on Linux, it does not change with ASLR (this is bad, by the way). If you think you have everything else working, but the offset you get locally is wrong, try a few pages (0x1000 bytes) in either direction. (0x4000 on server)
    - Remember that libc only has partial RELRO. In pwndbg, you can view the libc GOT using got -p libc. If you're not sure what to write, try overwriting everything and seeing where it crashes! You may need to fix some entries before you find something that is useful! 


# idea:
- override strlen GOT in libc at: libc.address + 0x1d2080 with system
- call strlen on string: "head /flag" 
- when we malloc we can write 1 Byte more (off-by-one error)

# House of Force:
- overflow into top chunk and change it size to huge value
- then we can malloc and get pointers to memory beyond heap
    - 1. malloc huge value (ignore)
    - 2. malloc value of choice, this pointer now start e.g. at .GOT as we ignore 1.


# flag:
```
softsec{tgM4zgYUbmCghpz-clhUmAr-FkhyhZIeiaVFfFp23yrz5zSqJURdtx541OQBSeKD}
```