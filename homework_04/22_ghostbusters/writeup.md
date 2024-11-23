# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "ghostbusters"
- story: You may have seen our phonebook, but who you gonna call? The Ghostbusters are having some trouble with their loadout system. Could you help them to find a way to unspook the loadout system? I heard that there is a legend about a "House of Spirit" (https://seclists.org/bugtraq/2005/Oct/118) that may be related to the spooky things that have been happening.


# The House of Spirit exploit (write fake chunk on stack and put into fastbin)
- can be used to leverage a heap or stack overflow
- first step is to pass a (desired) pointer to free()
- this can lead to linking an arbitrary address into a fastbin
- we need to have access 8 Byte before where our pointer points to to manipulate the length field
- make sure that no bits are set (size is multiple of 8)


# Startup
```
docker compose -f debug.yml up
docker exec -ti $(docker ps --quiet --filter 'ancestor=softsec/ghostbusters') /bin/bash
gdb -p "$(pgrep -n vuln)"
```


# overview
- we get a stack and libc pointers for free :)
- "A"dd
    - first it prints (heap) address that malloc() returns
    - mallocs equipment_t struct and adds pointer to equipment_list
    - inventory can store 5 equiments, we can still create malloc() if needed, but pointer is just printed and not stored in equipment
- "V"iew
    - 
- "U"pdate
    - 
- "D"elete
    - we can give a pointer to delete and free() is called on it!!!!!
    - 
- "G"hostbuster profile
    - change name to 0x68 here
- "E"nd
    - returns => if we can override return address with ropchain we are done (already have libc)


# ideas 
- we always malloc 96 Bytes (104 = 0x68 chunk size)
- we have a stack pointer, find place where 0x68 is stored
- we call Delete (free()) on that pointer => added to fastbinss
- we create an equipment
- if we can write an (arbitrary) stack pointer into the equipment list, then we can use update to directly write the ropchain and we are done
- right above the equipment list is a ghostbuster_t struct with a name field
- we can set the name to the length 0x68
- then we can call free on the equipment list
- then we call malloc() to get a pointer to equipment list and override it with a stackpointer of our choice
- then we call update to write an ropchain at a destination of our choice 


# flag
```
softsec{tt95jn61vJojzizhLHRuCH5Me0iPpqHd6iVVoniKSF5X83II9L1z-C5zDtMuQbBy}
```