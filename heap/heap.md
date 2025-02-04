# Heap
- 10 fastbins with sizes: 16, 24, 32, 40, 48, 56, 64, 72, 80 and 88.
- the house of exploits: https://seclists.org/bugtraq/2005/Oct/118
- actual malloc code: https://elixir.bootlin.com/glibc/glibc-2.36.9000/source/malloc/malloc.c


### Trick: practically disable tchache
- option 1: malloc stuff that is bigger than tcache or fastbin entries
- option 2: 
	- tcache has 7 entries per size
	- malloc 8 things
	- free 7 things (cache full)
	- free 8th thing => in fastbin (or unsorted if fastbin full, this way disable fastbin as well)
	- malloc 7 things (tcache empty now)
	- malloc 8-th thing (we get it from fastbin (or unsorted))


### Trick: leak main_arena pointer
- in unsorted list (double linked list) there are pointer to main arena

