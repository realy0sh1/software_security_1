# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "ragnarok"
- story: The House of Einherjar is (https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_einherjar/) one of my favorite heap exploitation techniques, because it shows how even tiny mistakes (an overflow of a single null byte, e.g., at the end of a string, into the next chunk) can lead to full RIP control.
    - Make sure to fill up the tcache first if it gets in the way. In other places, the tcache might come in useful.
    - You may find it useful to overwrite GOT entries in libc, which only has partial RELRO.


# Overview
- we can malloc (create warrior) of size: 128 - 1024 and write data into it via fgets (until newline)
- stored in global warriors array
- inspect warrior allows to leak heap values, as we can give a size, eventhough actual size may be smaller
- rename_warrior has an off-by-one error and one nullbyte is written beyond chunk

