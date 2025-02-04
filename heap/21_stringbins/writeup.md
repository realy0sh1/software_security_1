# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "stringbins"
- story: We've turned off the tcaches. But at least this time you get to struggle with safe linking (https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/). This is glibc 2.36 from Debian Bookworm. 

# setup
- start container
```
docker compose -f debug.yml up
```
- get gdb shell
```
docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/stringbins') /bin/bash
```
```
gdb -p "$(pgrep -n vuln)"
```


# overview
- alloc()
    - we get the pointer from malloc printed :)
    - alloc() zero's out the memory, then we can write arbitrary chars into memory :)
    - strings_p is array of all allocated strings
    - strings_l is array of all corresponding lengths
- print()
    - we can give an index in array and we get string printed
    - !! if we can write arbitrary pointer into array strings_p, we can read 1 Byte arbitrary memory :)
- list()
    - we get pointer to all strings printed (all heap chunks used)
- dealloc()
    - we can free() a pointer from strings_p as often as we want (nothing changed else) => we have UAF :)
- change()
    - 

# ideas:
- return => write ropchain onto stack => shell :)
- just assume I manage to return an arbitrary pointer from malloc() (still 16 Bytes aligned) => do stack address
- then i could write a ropchain onto stack with change()
- i need:
    - libc pointer ()
    - stack pointer (i get it via change(), is printed :)
    - heap pointer (i get it via alloc(), is printed :)
    - 


- list() prints all (heap) chunk addresses. that means we now address form *next pointer in struct as it is chunk_address + 8 => that means we can use arbitrary pointers in next as we can caluclate back safe-linking

# guide:
    - 1) ALLOC: malloc memory, leak pointer to chunk
    - 2) CHANGE: leak stack pointer
    - 3) DEALLOC: free that memory (we still get pointer to there)
    - 4) CHANGE: write arbitrary data into chunk, override *next (reverse safe-linking via pointer from LIST) (note: new pointer needs to be 16-Bytes aligned). point to stack
    - 5) ALLOC: get pointer to stack, write there non zero
    - 6) PRINT: the pointer to stack, this will print stack (until zero byte) and leak libc address :)
    - 7) get pointer to stack again (starting at return address) and write ropchain to stack, then return, done :)
    


- idea: points to: strings_p, then use change() to write stack addresses into strings_p, then leak libc, then use change() to write into arbitrary stack address
- it is enough to leak one malloc pointer as everything deterministic => we also have strings_p address :)

# guide:
    - 1) 


-flag
```
softsec{pGI_5EUHNrhbhYFjB0Uz83rXpmucvUhvX2aD92mQN6zNQ-fYDxcTwmpAFFczpSr3}
```
