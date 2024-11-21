# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "tinytcash"
- story: Can you shuffle around the tca{sh,che}? 
    - Note: Newer versions of glibc use safe linking (i.e., pointer mangling) on the tcache entries, while this one does not. Think about how that might make exploiting this task easier on this version of glibc!
    - This is glibc 2.31 from Debian Bullseye. This is an older version than the one that we typically use (2.36, from Debian Bookworm). Make sure you don't accidentally use the libc or loader from another task.
    - use: https://elixir.bootlin.com/glibc/glibc-2.31.9000/source
    - calls to malloc end up here: https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3022
    - calls to free end up here: https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3086


# overview:
- no pie => win() function is at well known position (0x401810) (via 'p win' in gdb)
- i can override the .got of printf() (0x403870) to win() (0x401810) as no RELRO
- attack overview
    - 1) "create" account 1 (malloc() for log 1)
    - 2) "create" account 2 (malloc() for log 2)
    - 3) "widthdraw" 0 from account 1 (free() for log 1)
    - 4) "wdithdraw" 0 from account 2 (free() for log 2)
    - => now 8 Byte tcache has two entries:
        - log2 with log2.next = log1
        - log1 with log1.next = NULL
    - 5) "deposit" account 2 with deposit = 0x403870 (.got of printf)
        - overrites log2.next = 0x403870
    - 6) "create" account 3 
        - malloc() for log reuses log2
    - 7) "create" account 4
        - malloc() returns pointer 0x403870 (.got of printf)
    - 8) "deposit" account 4 with desposit = 0x401810 (pointer to win())



# details of functions 
- there is a win function, that we must call
- there is a log_event function
    - we can write 8 Bytes (+ 1 Byte type) at the start of where log points to
    - we can free log by widthdrawing all money => use after free
    - now we can override 8 Bytes (+1 fixed) of the tcache entry, which convenietly is the *next pointer.
    - if a have a stack address, i can set return value of malloc to stack address, then log_event can override a return address for me:)
- there is a read_name function
- we can:
    - create an account: 
        - new linked list entry is created and put as new head
        - we can set a custom string as account identifier (0x40 bytes), char by char, so without a null byte (if we can proint name, we can read heap memory after that)
    - deposit:
        - we can deposit money into an account, by providing account name, then the account name gets printed => we meight leak pointer from stack :)
    - withdraw: 
        - if we withdraw money from account, we log the withdraw in the account via log_event
        - if we withdraw money and balance is zero afterwards, we free the log (only!) from the account => now we hava a UseAfterFree !!!!!, as the log pointer is still in account struct :)
    - transfer: 
        - transfer money and log in/out of accounts

- i would only need to leak a value from main and override a return address with win() function

- flag
```
softsec{jzJGPmu0-qss94i6C01KQVFFOrrJIGqGN7tunUJX3VAbEtd9_nh3UMNhU_HlKkFz}
```